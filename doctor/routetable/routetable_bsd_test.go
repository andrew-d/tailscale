// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build darwin || freebsd
// +build darwin freebsd

package routetable

import (
	"fmt"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"testing"

	"golang.org/x/net/route"
	"golang.org/x/sys/unix"
	"tailscale.com/net/interfaces"
)

func TestRouteEntryFromMsg(t *testing.T) {
	ifs := map[int]interfaces.Interface{
		1: {
			Interface: &net.Interface{
				Name: "iface0",
			},
		},
		2: {
			Interface: &net.Interface{
				Name: "tailscale0",
			},
		},
	}

	ip4 := func(s string) *route.Inet4Addr {
		ip := netip.MustParseAddr(s)
		return &route.Inet4Addr{IP: ip.As4()}
	}
	ip6 := func(s string) *route.Inet6Addr {
		ip := netip.MustParseAddr(s)
		return &route.Inet6Addr{IP: ip.As16()}
	}
	ip6zone := func(s string, idx int) *route.Inet6Addr {
		ip := netip.MustParseAddr(s)
		return &route.Inet6Addr{IP: ip.As16(), ZoneID: idx}
	}
	link := func(idx int, addr string) *route.LinkAddr {
		if _, found := ifs[idx]; !found {
			panic("index not found")
		}

		ret := &route.LinkAddr{
			Index: idx,
		}
		if addr != "" {
			ret.Addr = make([]byte, 6)
			fmt.Sscanf(addr, "%02x:%02x:%02x:%02x:%02x:%02x",
				&ret.Addr[0],
				&ret.Addr[1],
				&ret.Addr[2],
				&ret.Addr[3],
				&ret.Addr[4],
				&ret.Addr[5],
			)
		}
		return ret
	}

	type testCase struct {
		name string
		msg  *route.RouteMessage
		want routeEntry
		fail bool
	}

	testCases := []testCase{
		{
			name: "BasicIPv4",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip4("1.2.3.4"),       // dst
					ip4("1.2.3.1"),       // gateway
					ip4("255.255.255.0"), // netmask
				},
			},
			want: routeEntry{
				Family:      unix.AF_INET,
				Dst:         "1.2.3.4/24",
				GatewayAddr: "1.2.3.1",
			},
		},
		{
			name: "BasicIPv6",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip6("fd7a:115c:a1e0::"), // dst
					ip6("1234::"),           // gateway
					ip6("ffff:ffff:ffff::"), // netmask
				},
			},
			want: routeEntry{
				Family:      unix.AF_INET6,
				Dst:         "fd7a:115c:a1e0::/48",
				GatewayAddr: "1234::",
			},
		},
		{
			name: "IPv6WithZone",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip6zone("fe80::", 2),         // dst
					ip6("1234::"),                // gateway
					ip6("ffff:ffff:ffff:ffff::"), // netmask
				},
			},
			want: routeEntry{
				Family:      unix.AF_INET6,
				Dst:         "fe80::%tailscale0/64",
				GatewayAddr: "1234::",
			},
		},
		{
			name: "IPv6WithUnknownZone",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip6zone("fe80::", 4),         // dst
					ip6("1234::"),                // gateway
					ip6("ffff:ffff:ffff:ffff::"), // netmask
				},
			},
			want: routeEntry{
				Family:      unix.AF_INET6,
				Dst:         "fe80::%4/64",
				GatewayAddr: "1234::",
			},
		},
		{
			name: "DefaultIPv4",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip4("0.0.0.0"), // dst
					ip4("1.2.3.4"), // gateway
					ip4("0.0.0.0"), // netmask
				},
			},
			want: routeEntry{
				Family:      unix.AF_INET,
				Dst:         "default",
				GatewayAddr: "1.2.3.4",
			},
		},
		{
			name: "DefaultIPv6",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip6("0::"),    // dst
					ip6("1234::"), // gateway
					ip6("0::"),    // netmask
				},
			},
			want: routeEntry{
				Family:      unix.AF_INET6,
				Dst:         "default",
				GatewayAddr: "1234::",
			},
		},
		{
			name: "ShortAddrs",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip4("1.2.3.4"), // dst
				},
			},
			want: routeEntry{
				Family: unix.AF_INET,
				Dst:    "1.2.3.4",
			},
		},
		{
			name: "TailscaleIPv4",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip4("100.64.0.0"), // dst
					link(2, ""),
					ip4("255.192.0.0"), // netmask
				},
			},
			want: routeEntry{
				Family:     unix.AF_INET,
				Dst:        "100.64.0.0/10",
				GatewayIf:  "tailscale0",
				GatewayIdx: 2,
			},
		},
		{
			name: "Flags",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip4("1.2.3.4"),       // dst
					ip4("1.2.3.1"),       // gateway
					ip4("255.255.255.0"), // netmask
				},
				Flags: unix.RTF_STATIC | unix.RTF_GATEWAY | unix.RTF_UP,
			},
			want: routeEntry{
				Family:      unix.AF_INET,
				Dst:         "1.2.3.4/24",
				GatewayAddr: "1.2.3.1",
				Flags:       []string{"gateway", "static", "up"},
				rawFlags:    unix.RTF_STATIC | unix.RTF_GATEWAY | unix.RTF_UP,
			},
		},
		{
			name: "SkipNoAddrs",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs:   []route.Addr{},
			},
			fail: true,
		},
		{
			name: "SkipBadVersion",
			msg: &route.RouteMessage{
				Version: 1,
			},
			fail: true,
		},
		{
			name: "SkipBadType",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType + 1,
			},
			fail: true,
		},
		{
			name: "OutputIface",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Index:   1,
				Addrs: []route.Addr{
					ip4("1.2.3.4"), // dst
				},
			},
			want: routeEntry{
				Family:   unix.AF_INET,
				Dst:      "1.2.3.4",
				OutputIf: "iface0",
			},
		},
		{
			name: "GatewayMAC",
			msg: &route.RouteMessage{
				Version: 3,
				Type:    rmExpectedType,
				Addrs: []route.Addr{
					ip4("100.64.0.0"), // dst
					link(1, "01:02:03:04:05:06"),
					ip4("255.192.0.0"), // netmask
				},
			},
			want: routeEntry{
				Family:      unix.AF_INET,
				Dst:         "100.64.0.0/10",
				GatewayIf:   "iface0",
				GatewayIdx:  1,
				GatewayAddr: "01:02:03:04:05:06",
			},
		},
	}

	if runtime.GOOS == "darwin" {
		testCases = append(testCases,
			testCase{
				name: "SkipFlags",
				msg: &route.RouteMessage{
					Version: 3,
					Type:    rmExpectedType,
					Addrs: []route.Addr{
						ip4("1.2.3.4"),       // dst
						ip4("1.2.3.1"),       // gateway
						ip4("255.255.255.0"), // netmask
					},
					Flags: unix.RTF_UP | skipFlags,
				},
				fail: true,
			},
			testCase{
				name: "NetmaskAdjust",
				msg: &route.RouteMessage{
					Version: 3,
					Type:    rmExpectedType,
					Addrs: []route.Addr{
						ip6("ff00::"),           // dst
						ip6("1234::"),           // gateway
						ip6("ffff:ffff:ff00::"), // netmask
					},
				},
				want: routeEntry{
					Family:      unix.AF_INET6,
					Dst:         "ff00::/8",
					GatewayAddr: "1234::",
				},
			},
		)
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			re, ok := routeEntryFromMsg(ifs, tc.msg)
			if wantOk := !tc.fail; ok != wantOk {
				t.Fatalf("ok = %v; want %v", ok, wantOk)
			}

			if !reflect.DeepEqual(re, tc.want) {
				t.Fatalf("routeEntry = %+v; want %+v", re, tc.want)
			}
		})
	}
}

func TestRouteEntryFormatting(t *testing.T) {
	testCases := []struct {
		re   routeEntry
		want string
	}{
		{
			re: routeEntry{
				Family:    unix.AF_INET,
				Dst:       "1.2.3.0/24",
				GatewayIf: "en0",
				OutputIf:  "en0",
				Flags:     []string{"static", "up"},
			},
			want: `{Kind: IPv4, Dst: 1.2.3.0/24, GatewayIf: en0, OutputIf: en0, Flags: [static up]}`,
		},
		{
			re: routeEntry{
				Family:     unix.AF_INET6,
				Dst:        "fd7a:115c:a1e0::/24",
				GatewayIdx: 3,
				OutputIf:   "en0",
				Flags:      []string{"static", "up"},
			},
			want: `{Kind: IPv6, Dst: fd7a:115c:a1e0::/24, GatewayIdx: 3, OutputIf: en0, Flags: [static up]}`,
		},
	}
	for _, tc := range testCases {
		t.Run("", func(t *testing.T) {
			got := tc.re.String()
			if got != tc.want {
				t.Fatalf("routeEntry.String() = %q; want %q", got, tc.want)
			}
		})
	}
}

func TestGetRouteTable(t *testing.T) {
	routes, err := getRouteTable(MaxRoutes)
	if err != nil {
		t.Fatal(err)
	}

	// Basic assertion: we have at least one 'default' route
	var (
		hasDefault bool
	)
	for _, route := range routes {
		if route.Dst == "default" {
			hasDefault = true
		}
	}
	if !hasDefault {
		t.Errorf("expected at least one default route; routes=%v", routes)
	}
}
