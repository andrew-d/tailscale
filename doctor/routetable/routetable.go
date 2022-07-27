// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package routetable

import (
	"context"

	"tailscale.com/types/logger"
)

type Check struct{}

func (c Check) Name() string {
	return "routetable"
}

func (c Check) Run(_ context.Context, log logger.Logf) error {
	rs, err := getRouteTable()
	if err != nil {
		return err
	}
	for _, r := range rs {
		log("%s", r)
	}
	return nil
}
