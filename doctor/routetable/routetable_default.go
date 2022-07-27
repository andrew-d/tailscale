// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

//go:build !linux && !darwin && !freebsd

package routetable

import (
	"fmt"
	"runtime"
)

type routeEntry struct{}

var errUnsupported = fmt.Errorf("cannot get route table on platform %q", runtime.GOOS)

func getRouteTable(max int) ([]routeEntry, error) {
	return nil, errUnsupported
}
