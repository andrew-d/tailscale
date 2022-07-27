// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package routetable

import (
	"fmt"
	"strings"

	"github.com/tailscale/netlink"
	"golang.org/x/sys/unix"
	"tailscale.com/net/interfaces"
)

type routeEntry struct {
	Family  int
	Type    int
	Table   int
	Dst     string
	Src     string
	Device  string
	Gateway string
	Proto   netlink.RouteProtocol
	Metric  int
}

func (re routeEntry) String() string {
	var sb strings.Builder

	switch re.Family {
	case netlink.FAMILY_V4:
		fmt.Fprint(&sb, "{Kind: IPv4")
	case netlink.FAMILY_V6:
		fmt.Fprint(&sb, "{Kind: IPv6")
	default:
		fmt.Fprintf(&sb, "{Kind: unknown(%d)", re.Family)
	}
	if re.Type != unix.RTN_UNICAST { // match 'ip route' behaviour
		fmt.Fprintf(&sb, ", Type: %s", typeName(re.Type))
	}
	fmt.Fprintf(&sb, ", Dst: %s", re.Dst)
	if re.Device != "" {
		fmt.Fprintf(&sb, ", Device: %s", re.Device)
	}
	if re.Table != unix.RT_TABLE_MAIN { // match 'ip route' behaviour
		fmt.Fprintf(&sb, ", Table: %s", tableName(re.Table))
	}
	if re.Proto != unix.RTPROT_BOOT { // match 'ip route' behaviour
		fmt.Fprintf(&sb, ", Proto: %s", re.Proto)
	}
	if re.Src != "" {
		fmt.Fprintf(&sb, ", Src: %s", re.Src)
	}
	if re.Gateway != "" {
		fmt.Fprintf(&sb, ", Gateway: %s", re.Gateway)
	}
	if re.Metric != 0 {
		fmt.Fprintf(&sb, ", Metric: %d", re.Metric)
	}
	fmt.Fprint(&sb, "}")

	return sb.String()
}

func typeName(t int) string {
	switch t {
	case unix.RTN_UNSPEC:
		return "none"
	case unix.RTN_UNICAST:
		return "unicast"
	case unix.RTN_LOCAL:
		return "local"
	case unix.RTN_BROADCAST:
		return "broadcast"
	case unix.RTN_ANYCAST:
		return "anycast"
	case unix.RTN_MULTICAST:
		return "multicast"
	case unix.RTN_BLACKHOLE:
		return "blackhole"
	case unix.RTN_UNREACHABLE:
		return "unreachable"
	case unix.RTN_PROHIBIT:
		return "prohibit"
	case unix.RTN_THROW:
		return "throw"
	case unix.RTN_NAT:
		return "nat"
	case unix.RTN_XRESOLVE:
		return "xresolve"
	default:
		return fmt.Sprint(t)
	}
}

func tableName(t int) string {
	switch t {
	case unix.RT_TABLE_DEFAULT:
		return "default"
	case unix.RT_TABLE_MAIN:
		return "main"
	case unix.RT_TABLE_LOCAL:
		return "local"
	default:
		return fmt.Sprint(t)
	}
}

func getRouteTable() ([]routeEntry, error) {
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

	filter := &netlink.Route{}
	routes, err := netlink.RouteListFiltered(netlink.FAMILY_ALL, filter, netlink.RT_FILTER_TABLE)
	if err != nil {
		return nil, err
	}

	var ret []routeEntry
	for _, route := range routes {
		if route.Family != netlink.FAMILY_V4 && route.Family != netlink.FAMILY_V6 {
			continue
		}

		var src, dst string
		if route.Dst != nil {
			dst = route.Dst.String()
		} else {
			dst = "default"
		}
		if route.Src != nil {
			src = route.Src.String()
		}

		re := routeEntry{
			Family: route.Family,
			Type:   route.Type,
			Table:  route.Table,
			Proto:  route.Protocol,
			Dst:    dst,
			Src:    src,
			Metric: route.Priority,
		}

		if gw := route.Gw; gw != nil {
			re.Gateway = gw.String()
		}
		if outif, ok := ifsByIdx[route.LinkIndex]; ok {
			re.Device = outif.Name
		}
		ret = append(ret, re)
	}
	return ret, nil
}
