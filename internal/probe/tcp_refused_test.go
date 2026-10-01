package probe

import (
	"context"
	"testing"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/model"
)

// Dials a port that is (almost) certainly closed on loopback and asserts the
// sample is flagged as refused rather than generic loss.
func TestTCPConnRefusedFlagged(t *testing.T) {
	p := NewTCP("127.0.0.1:1") // tcpmux: never open in practice
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	s := p.Probe(ctx)
	if s.Kind != model.KindTCP {
		t.Fatalf("kind = %s, want tcp", s.Kind)
	}
	if s.OK {
		t.Skip("127.0.0.1:1 unexpectedly open; cannot test refused path here")
	}
	if !s.ConnRefused {
		t.Fatalf("expected ConnRefused=true, got err=%q", s.Err)
	}
}
