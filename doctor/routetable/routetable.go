// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package routetable provides a doctor.Check that dumps the current system's
// route table to the log.
package routetable

import (
	"bufio"
	"context"
	"fmt"
	"net/netip"
	"strconv"

	"tailscale.com/types/logger"
)

// MaxRoutes is the maximum number of routes that will be displayed.
const MaxRoutes = 1000

// Check implements the doctor.Check interface.
type Check struct{}

func (c Check) Name() string {
	return "routetable"
}

func (c Check) Run(_ context.Context, log logger.Logf) error {
	rs, err := getRouteTable(MaxRoutes)
	if err != nil {
		return err
	}
	for _, r := range rs {
		log("%s", r)
	}
	return nil
}

// routeEntry contains common cross-platform fields describing an entry in the
// system route table.
type routeEntry struct {
	// Family is the IP family of the route; it will be either 4 or 6.
	Family int
	// Type is the type of this route.
	Type routeType
	// Dst is the destination of the route.
	Dst routeDestination
	// Gatewayis the gateway address specified for this route.
	// This value will be invalid (where !r.Gateway.IsValid()) in cases
	// where there is no gateway address for this route.
	Gateway netip.Addr
	// Interface is the name of the network interface to use when sending
	// packets that match this route. This field can be empty.
	Interface string
	// Sys contains platform-specific information about this route.
	Sys any
}

func (r routeEntry) Format(f fmt.State, verb rune) {
	logger.ArgWriter(func(w *bufio.Writer) {
		switch r.Family {
		case 4:
			fmt.Fprintf(w, "{Family: IPv4")
		case 6:
			fmt.Fprintf(w, "{Family: IPv6")
		default:
			fmt.Fprintf(w, "{Family: unknown(%d)", r.Family)
		}

		// Match 'ip route' and other tools by not printing the route
		// type if it's a unicast route.
		if r.Type != routeTypeUnicast {
			fmt.Fprintf(w, ", Type: %s", r.Type)
		}

		if r.Dst.IsValid() {
			fmt.Fprintf(w, ", Dst: %s", r.Dst)
		} else {
			w.WriteString(", Dst: invalid")
		}

		if r.Gateway.IsValid() {
			fmt.Fprintf(w, ", Gateway: %s", r.Gateway)
		}

		if r.Interface != "" {
			fmt.Fprintf(w, ", Interface: %s", r.Interface)
		}

		if r.Sys != nil {
			var formatVerb string
			switch {
			case f.Flag('#'):
				formatVerb = "%#v"
			case f.Flag('+'):
				formatVerb = "%+v"
			default:
				formatVerb = "%v"
			}
			fmt.Fprintf(w, ", Sys: "+formatVerb, r.Sys)
		}

		w.WriteString("}")
	}).Format(f, verb)
}

// routeDestination is the destination of a route.
//
// This is similar to net/netip.Prefix, but also contains an optional IPv6
// zone.
type routeDestination struct {
	netip.Prefix
	Zone string
}

func (r routeDestination) String() string {
	ip := r.Prefix.Addr()
	if r.Zone != "" {
		ip = ip.WithZone(r.Zone)
	}
	return ip.String() + "/" + strconv.Itoa(r.Prefix.Bits())
}

// routeType describes the type of a route.
type routeType int

const (
	// An unspecified route type
	routeTypeUnspecified routeType = iota
	// The destination of this route is an address that belongs to this
	// system.
	routeTypeLocal
	// The destination of this route is a "regular" address--one that
	// neither belongs to this host, nor is a broadcast/multicast/etc.
	// address.
	routeTypeUnicast
	// The destination of this route is a broadcast address.
	routeTypeBroadcast
	// The destination of this route is a multicast address.
	routeTypeMulticast
	// The route is of some other valid type; see the Sys field for the
	// OS-provided route information to determine the exact type.
	routeTypeOther
)

func (r routeType) String() string {
	switch r {
	case routeTypeUnspecified:
		return "unspecified"
	case routeTypeLocal:
		return "local"
	case routeTypeUnicast:
		return "unicast"
	case routeTypeBroadcast:
		return "broadcast"
	case routeTypeMulticast:
		return "multicast"
	case routeTypeOther:
		return "other"
	default:
		return "invalid"
	}
}
