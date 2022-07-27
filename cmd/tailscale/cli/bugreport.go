// Copyright (c) 2021 Tailscale Inc & AUTHORS All rights reserved.
// Use of this source code is governed by a BSD-style
// license that can be found in the LICENSE file.

package cli

import (
	"context"
	"errors"
	"flag"

	"github.com/peterbourgon/ff/v3/ffcli"
)

var bugReportCmd = &ffcli.Command{
	Name:       "bugreport",
	Exec:       runBugReport,
	ShortHelp:  "Print a shareable identifier to help diagnose issues",
	ShortUsage: "bugreport [note]",
	FlagSet: (func() *flag.FlagSet {
		fs := newFlagSet("doctor")
		fs.BoolVar(&bugReportArgs.doctor, "doctor", false, "run additional in-depth checks")
		return fs
	})(),
}

var bugReportArgs struct {
	doctor bool
}

func runBugReport(ctx context.Context, args []string) error {
	var note string
	switch len(args) {
	case 0:
	case 1:
		note = args[0]
	default:
		return errors.New("unknown argumets")
	}
	logMarker, err := localClient.BugReport(ctx, note, bugReportArgs.doctor)
	if err != nil {
		return err
	}
	outln(logMarker)
	return nil
}
