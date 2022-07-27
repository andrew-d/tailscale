// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || freebsd
// +build darwin freebsd

package routetable

import (
	"bufio"
	"fmt"
	"net"
	"net/netip"
	"runtime"
	"sort"
	"strings"
	"syscall"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"tailscale.com/net/interfaces"
	"tailscale.com/types/logger"
)

type routeEntrySys struct {
	// GatewayInterface is the name of the interface specified as a gateway
	// for this route, if any.
	GatewayInterface string
	// GatewayIdx is the index of the interface specified as a gateway for
	// this route, if any.
	GatewayIdx int
	// GatewayAddr is the link-layer address of the gateway for this route,
	// if any.
	GatewayAddr string
	// Flags contains a string representation of common flags for this
	// route.
	Flags []string
	// RawFlags contains the raw flags that were returned by the operating
	// system for this route.
	RawFlags int
}

func (r routeEntrySys) Format(f fmt.State, verb rune) {
	logger.ArgWriter(func(w *bufio.Writer) {
		var pstart bool
		pr := func(format string, args ...any) {
			if pstart {
				fmt.Fprintf(w, ", "+format, args...)
			} else {
				fmt.Fprintf(w, format, args...)
				pstart = true
			}
		}

		w.WriteString("{")
		if r.GatewayInterface != "" {
			pr("GatewayInterface: %s", r.GatewayInterface)
		}
		if r.GatewayIdx > 0 {
			pr("GatewayIdx: %d", r.GatewayIdx)
		}
		if r.GatewayAddr != "" {
			pr("GatewayAddr: %s", r.GatewayAddr)
		}
		pr("Flags: %v", r.Flags)

		w.WriteString("}")
	}).Format(f, verb)
}

// ipFromRMAddr returns a netip.Addr converted from one of the
// route.Inet{4,6}Addr types.
func ipFromRMAddr(ifs map[int]interfaces.Interface, addr any) netip.Addr {
	switch v := addr.(type) {
	case *route.Inet4Addr:
		return netip.AddrFrom4(v.IP)

	case *route.Inet6Addr:
		ip := netip.AddrFrom16(v.IP)
		if v.ZoneID != 0 {
			if iif, ok := ifs[v.ZoneID]; ok {
				ip = ip.WithZone(iif.Name)
			} else {
				ip = ip.WithZone(fmt.Sprint(v.ZoneID))
			}
		}

		return ip
	}

	return netip.Addr{}
}

// populateGateway populates gateway fields on a routeEntry/routeEntrySys.
func populateGateway(re *routeEntry, reSys *routeEntrySys, ifs map[int]interfaces.Interface, addr any) {
	// If the address type has a valid IP, use that.
	if ip := ipFromRMAddr(ifs, addr); ip.IsValid() {
		re.Gateway = ip
		return
	}

	switch v := addr.(type) {
	case *route.LinkAddr:
		reSys.GatewayIdx = v.Index
		if iif, ok := ifs[v.Index]; ok {
			reSys.GatewayInterface = iif.Name
		}
		var sb strings.Builder
		for i, x := range v.Addr {
			if i != 0 {
				sb.WriteByte(':')
			}
			fmt.Fprintf(&sb, "%02x", x)
		}
		reSys.GatewayAddr = sb.String()
	}
}

// populateDestination populates the 'Dst' field on a routeEntry based on the
// RouteMessage's destination and netmask fields.
func populateDestination(re *routeEntry, ifs map[int]interfaces.Interface, rm *route.RouteMessage) {
	dst := rm.Addrs[unix.RTAX_DST]
	if dst == nil {
		return
	}

	ip := ipFromRMAddr(ifs, dst)
	if !ip.IsValid() {
		return
	}

	if ip.Is4() {
		re.Family = 4
	} else {
		re.Family = 6
	}
	re.Dst = routeDestination{
		Prefix: netip.PrefixFrom(ip, 32), // default if nothing more specific
	}

	// If the RTF_HOST flag is set, then this is a host route and there's
	// no netmask in this RouteMessage.
	if rm.Flags&unix.RTF_HOST != 0 {
		return
	}

	// As above if there's no netmask in the list of addrs
	if len(rm.Addrs) < unix.RTAX_NETMASK || rm.Addrs[unix.RTAX_NETMASK] == nil {
		return
	}

	nm := ipFromRMAddr(ifs, rm.Addrs[unix.RTAX_NETMASK])
	if !ip.IsValid() {
		return
	}

	// Count the number of bits in the netmask IP and use that to make our prefix.
	ones, _ /* bits */ := net.IPMask(nm.AsSlice()).Size()

	// Print this ourselves instead of using netip.Prefix so that we don't
	// lose the zone (since netip.Prefix strips that).
	//
	// NOTE(andrew): this doesn't print the same values as the 'netstat' tool
	// for some addresses on macOS, and I have no idea why. Specifically,
	// 'netstat -rn' will show something like:
	//    ff00::/8   ::1      UmCI     lo0
	//
	// But we will get:
	//    destination=ff00::/40 [...]
	//
	// The netmask that we get back from FetchRIB has 32 more bits in it
	// than netstat prints, but only for multicast routes.
	//
	// For consistency's sake, we're going to do the same here so that we
	// get the same values as netstat returns.
	if runtime.GOOS == "darwin" && ip.Is6() && ip.IsMulticast() && ones > 32 {
		ones -= 32
	}
	re.Dst = routeDestination{
		Prefix: netip.PrefixFrom(ip, ones),
		Zone:   ip.Zone(),
	}
}

// routeEntryFromMsg returns a routeEntryFromMsg from a single route.Message
// returned by the operating system.
func routeEntryFromMsg(ifsByIdx map[int]interfaces.Interface, msg route.Message) (routeEntry, bool) {
	rm, ok := msg.(*route.RouteMessage)
	if !ok {
		return routeEntry{}, false
	}

	// Ignore things that we don't understand
	if rm.Version < 3 || rm.Version > 5 {
		return routeEntry{}, false
	}
	if rm.Type != rmExpectedType {
		return routeEntry{}, false
	}
	if len(rm.Addrs) < unix.RTAX_GATEWAY {
		return routeEntry{}, false
	}

	if rm.Flags&skipFlags != 0 {
		return routeEntry{}, false
	}

	reSys := routeEntrySys{
		RawFlags: rm.Flags,
	}
	for fv, fs := range flags {
		if rm.Flags&fv == fv {
			reSys.Flags = append(reSys.Flags, fs)
		}
	}
	sort.Strings(reSys.Flags)

	re := routeEntry{
		Sys: reSys,
	}
	hasFlag := func(f int) bool { return rm.Flags&f != 0 }
	switch {
	case hasFlag(unix.RTF_LOCAL):
		re.Type = routeTypeLocal
	case hasFlag(unix.RTF_BROADCAST):
		re.Type = routeTypeBroadcast
	case hasFlag(unix.RTF_MULTICAST):
		re.Type = routeTypeMulticast

	// From the manpage: "host entry (net otherwise)"
	case !hasFlag(unix.RTF_HOST):
		re.Type = routeTypeUnicast

	default:
		re.Type = routeTypeOther
	}
	populateDestination(&re, ifsByIdx, rm)
	if unix.RTAX_GATEWAY < len(rm.Addrs) {
		populateGateway(&re, &reSys, ifsByIdx, rm.Addrs[unix.RTAX_GATEWAY])
	}

	if outif, ok := ifsByIdx[rm.Index]; ok {
		re.Interface = outif.Name
	}
	return re, true
}

// getRouteTable returns route entries from the system route table, limited to
// at most 'max' results.
func getRouteTable(max int) ([]routeEntry, error) {
	// Fetching the list of interfaces can race with fetching our route
	// table, but we do it anyway since it's helpful for debugging.
	ifs, err := interfaces.GetList()
	if err != nil {
		return nil, err
	}

	ifsByIdx := make(map[int]interfaces.Interface)
	for _, iif := range ifs {
		ifsByIdx[iif.Index] = iif
	}

	rib, err := route.FetchRIB(syscall.AF_UNSPEC, ribType, 0)
	if err != nil {
		return nil, err
	}
	msgs, err := route.ParseRIB(parseType, rib)
	if err != nil {
		return nil, err
	}

	var ret []routeEntry
	for _, m := range msgs {
		re, ok := routeEntryFromMsg(ifsByIdx, m)
		if ok {
			ret = append(ret, re)
			if len(ret) == max {
				break
			}
		}
	}
	return ret, nil
}
