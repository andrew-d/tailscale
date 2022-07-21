package dhcpinfo

import (
	"context"
	"testing"
)

func TestDNSServers(t *testing.T) {
	s, err := DNSServers(context.Background())
	if err != nil {
		t.Fatal(err)
	}

	if len(s) < 1 {
		t.Error("expected non-zero number of servers; got 0")
	}

	t.Logf("DNSServers(): %+v", s)
}
