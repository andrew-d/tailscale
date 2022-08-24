// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package linuxfw

import (
	"testing"
	"unsafe"

	"tailscale.com/util/linuxfw/linuxfwtest"
)

func TestSizes(t *testing.T) {
	linuxfwtest.TestSizes(t, &linuxfwtest.SizeInfo{
		SizeofSocklen: unsafe.Sizeof(sockLen(0)),
	})
}
