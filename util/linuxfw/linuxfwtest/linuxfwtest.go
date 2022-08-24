// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

// Package linuxfwtest contains tests for the linuxfw package. Go does not
// support cgo in tests, and we don't want the main package to have a cgo
// dependency, so we put all the tests here and call them from the main package
// in tests intead.
package linuxfwtest

import (
	"testing"
	"unsafe"
)

/*
#include <sys/socket.h>  // socket()
*/
import "C"

type SizeInfo struct {
	SizeofSocklen uintptr
}

func TestSizes(t *testing.T, si *SizeInfo) {
	want := unsafe.Sizeof(C.socklen_t(0))
	if want != si.SizeofSocklen {
		t.Errorf("sockLen has wrong size; want=%d got=%d", want, si.SizeofSocklen)
	}
}
