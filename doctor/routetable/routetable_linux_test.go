// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build linux
// +build linux

package routetable

import (
	"testing"

	"github.com/tailscale/netlink"
	"golang.org/x/sys/unix"
)

func TestGetRouteTable(t *testing.T) {
	routes, err := getRouteTable()
	if err != nil {
		t.Fatal(err)
	}

	// Basic assertion: we have at least one 'default' route in the main table
	var (
		hasDefault bool
	)
	for _, route := range routes {
		if route.Dst == "default" && route.Table == unix.RT_TABLE_MAIN {
			hasDefault = true
		}
	}
	if !hasDefault {
		t.Errorf("expected at least one default route; routes=%v", routes)
	}
}

func TestRouteEntryFormatting(t *testing.T) {
	testCases := []struct {
		re   routeEntry
		want string
	}{
		{
			re: routeEntry{
				Family:  netlink.FAMILY_V4,
				Type:    unix.RTN_ANYCAST,
				Dst:     "100.64.0.0/10",
				Device:  "tailscale0",
				Table:   52,
				Proto:   unix.RTPROT_STATIC,
				Src:     "1.2.3.4",
				Gateway: "1.2.3.1",
				Metric:  555,
			},
			want: `{Kind: IPv4, Type: anycast, Dst: 100.64.0.0/10, Device: tailscale0, Table: 52, Proto: static, Src: 1.2.3.4, Gateway: 1.2.3.1, Metric: 555}`,
		},
		{
			re: routeEntry{
				Family:  netlink.FAMILY_V4,
				Type:    unix.RTN_UNICAST,
				Dst:     "1.2.3.0/24",
				Table:   unix.RT_TABLE_MAIN,
				Proto:   unix.RTPROT_BOOT,
				Gateway: "1.2.3.1",
			},
			want: `{Kind: IPv4, Dst: 1.2.3.0/24, Gateway: 1.2.3.1}`,
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
