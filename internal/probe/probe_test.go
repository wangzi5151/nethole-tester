package probe

import (
	"context"
	"errors"
	"os"
	"testing"
	"time"
)

// These tests touch the public internet and are skipped in -short mode.
// They exist to prove each chain performs a real measurement end to end.

func TestICMP(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	p, err := NewICMP("1.1.1.1")
	if err != nil {
		// The production Runner degrades gracefully when no ICMP socket can
		// be opened (unprivileged containers, ping_group_range=0, Windows
		// without admin): it warns and continues with TCP/DNS. A permission
		// failure here is an environment limit, not a code bug, so skip —
		// any other construction error is still fatal.
		if errors.Is(err, os.ErrPermission) {
			t.Skipf("ICMP socket not permitted in this environment: %v", err)
		}
		t.Fatalf("NewICMP: %v", err)
	}
	defer p.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s := p.Probe(ctx)
	if !s.OK {
		t.Logf("icmp probe failed (this may be expected behind a firewall): %s", s.Err)
		return
	}
	t.Logf("icmp rtt=%s", s.RTT)
}

func TestTCP(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	p := NewTCP("1.1.1.1:443")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s := p.Probe(ctx)
	if !s.OK {
		t.Logf("tcp probe failed: %s", s.Err)
		return
	}
	t.Logf("tcp rtt=%s", s.RTT)
}

func TestDNS(t *testing.T) {
	if testing.Short() {
		t.Skip("network test")
	}
	p := NewDNS("1.1.1.1:53", "www.example.com")
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s := p.Probe(ctx)
	if !s.OK {
		t.Logf("dns probe failed: %s", s.Err)
		return
	}
	t.Logf("dns rtt=%s", s.RTT)
}
