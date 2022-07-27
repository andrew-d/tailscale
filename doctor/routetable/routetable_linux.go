// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package routetable

import (
	"bufio"
	"fmt"
	"net/netip"
	"strconv"

	"github.com/tailscale/netlink"
	"golang.org/x/sys/unix"
	"tailscale.com/net/interfaces"
	"tailscale.com/net/netaddr"
	"tailscale.com/types/logger"
)

// routeEntrySys is the structure that makes up the Sys field of the
// routeEntry structure.
type routeEntrySys struct {
	// Type is the raw type of the route.
	Type int
	// Table is the routing table index of this route.
	Table int
	// Src is the source of the route (if any)
	Src netip.Addr
	// Proto describes the source of the route--i.e. what caused this route
	// to be added to the route table.
	Proto netlink.RouteProtocol
	// Priority is the route's priority.
	Priority int
	// Scope is the route's scope
	Scope int
	// InputInterfaceIdx is the input interface index.
	InputInterfaceIdx int
	// InputInterfaceName is the input interface name (if available).
	InputInterfaceName string
}

func (r routeEntrySys) Format(f fmt.State, verb rune) {
	logger.ArgWriter(func(w *bufio.Writer) {
		// TODO(andrew): should we skip printing anything if type is unicast?
		fmt.Fprintf(w, "{Type: %s", r.TypeName())

		// Match 'ip route' behaviour when printing these fields
		if r.Table != unix.RT_TABLE_MAIN {
			fmt.Fprintf(w, ", Table: %s", r.TableName())
		}
		if r.Proto != unix.RTPROT_BOOT {
			fmt.Fprintf(w, ", Proto: %s", r.Proto)
		}

		if r.Src.IsValid() {
			fmt.Fprintf(w, ", Src: %s", r.Src)
		}
		if r.Priority != 0 {
			fmt.Fprintf(w, ", Priority: %d", r.Priority)
		}
		if r.Scope != unix.RT_SCOPE_UNIVERSE {
			fmt.Fprintf(w, ", Scope: %s", r.ScopeName())
		}
		if r.InputInterfaceName != "" {
			fmt.Fprintf(w, ", InputInterfaceName: %s", r.InputInterfaceName)
		} else if r.InputInterfaceIdx != 0 {
			fmt.Fprintf(w, ", InputInterfaceIdx: %d", r.InputInterfaceIdx)
		}
		w.WriteString("}")
	}).Format(f, verb)
}

// TypeName returns the string representation of this route's Type.
func (r routeEntrySys) TypeName() string {
	switch r.Type {
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
		return strconv.Itoa(r.Type)
	}
}

// TableName returns the string representation of this route's Table.
func (r routeEntrySys) TableName() string {
	switch r.Table {
	case unix.RT_TABLE_DEFAULT:
		return "default"
	case unix.RT_TABLE_MAIN:
		return "main"
	case unix.RT_TABLE_LOCAL:
		return "local"
	default:
		return strconv.Itoa(r.Table)
	}
}

// ScopeName returns the string representation of this route's Scope.
func (r routeEntrySys) ScopeName() string {
	switch r.Scope {
	case unix.RT_SCOPE_UNIVERSE:
		return "global"
	case unix.RT_SCOPE_NOWHERE:
		return "nowhere"
	case unix.RT_SCOPE_HOST:
		return "host"
	case unix.RT_SCOPE_LINK:
		return "link"
	case unix.RT_SCOPE_SITE:
		return "site"
	default:
		return strconv.Itoa(r.Scope)
	}
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

		re := routeEntry{}
		if route.Family == netlink.FAMILY_V4 {
			re.Family = 4
		} else {
			re.Family = 6
		}
		switch route.Type {
		case unix.RTN_UNSPEC:
			re.Type = routeTypeUnspecified
		case unix.RTN_UNICAST:
			re.Type = routeTypeUnicast
		case unix.RTN_LOCAL:
			re.Type = routeTypeLocal
		case unix.RTN_BROADCAST:
			re.Type = routeTypeBroadcast
		case unix.RTN_MULTICAST:
			re.Type = routeTypeMulticast
		default:
			re.Type = routeTypeOther
		}
		if route.Dst != nil {
			if d, ok := netaddr.FromStdIPNet(route.Dst); ok {
				re.Dst = routeDestination{Prefix: d}
			}
		} else if route.Family == netlink.FAMILY_V4 {
			re.Dst = routeDestination{Prefix: netip.PrefixFrom(netip.IPv4Unspecified(), 0)}
		} else {
			re.Dst = routeDestination{Prefix: netip.PrefixFrom(netip.IPv6Unspecified(), 0)}
		}
		if gw := route.Gw; gw != nil {
			if gwa, ok := netip.AddrFromSlice(gw); ok {
				re.Gateway = gwa
			}
		}
		if outif, ok := ifsByIdx[route.LinkIndex]; ok {
			re.Interface = outif.Name
		} else if route.LinkIndex > 0 {
			re.Interface = fmt.Sprintf("link#%d", route.LinkIndex)
		}
		reSys := routeEntrySys{
			Type:              route.Type,
			Table:             route.Table,
			Proto:             route.Protocol,
			Priority:          route.Priority,
			Scope:             int(route.Scope),
			InputInterfaceIdx: route.ILinkIndex,
		}
		if src, ok := netip.AddrFromSlice(route.Src); ok {
			reSys.Src = src
		}
		if iif, ok := ifsByIdx[route.ILinkIndex]; ok {
			reSys.InputInterfaceName = iif.Name
		}

		re.Sys = reSys
		ret = append(ret, re)

		// Stop after we've reached the maximum number of routes
		if len(ret) == max {
			break
		}
	}
	return ret, nil
}
