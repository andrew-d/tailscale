// Copyright (c) 2022 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package doctor

import (
	"context"
	"fmt"
	"sync"
	"testing"

	"tailscale.com/types/logger"
)

func TestRunChecks(t *testing.T) {
	var (
		mu    sync.Mutex
		lines []string
	)
	logf := func(format string, args ...any) {
		mu.Lock()
		defer mu.Unlock()
		lines = append(lines, fmt.Sprintf(format, args...))
	}

	ctx := context.Background()
	RunChecks(ctx, logf,
		testCheck1{},
		CheckFunc("testcheck2", func(_ context.Context, log logger.Logf) error {
			log("check 2")
			return nil
		}),
	)

	mu.Lock()
	defer mu.Unlock()
	assertContains(t, lines, "testcheck1: check 1")
	assertContains(t, lines, "testcheck2: check 2")
}

type testCheck1 struct{}

func (t testCheck1) Name() string { return "testcheck1" }
func (t testCheck1) Run(_ context.Context, log logger.Logf) error {
	log("check 1")
	return nil
}

func assertContains[T comparable](t *testing.T, arr []T, val T) {
	t.Helper()
	var found bool
	for _, v := range arr {
		if val == v {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected list to contain element %v", val)
	}
}
