// Package probe implements the three independent, high-precision measurement
// chains used by NetHole-Tester: ICMP echo, TCP SYN handshake and recursive
// DNS. Each Prober is bound to a single target so that probes can run fully in
// parallel without sharing mutable socket state.
package probe

import (
	"context"
	"errors"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/model"
)

// ErrTimeout is returned when a probe produced no reply before its deadline.
var ErrTimeout = errors.New("probe timeout (no reply)")

// Prober measures one target of one kind.
type Prober interface {
	// Kind reports which chain this prober belongs to.
	Kind() model.Kind
	// Target is the human readable target (host, host:port or resolver).
	Target() string
	// Probe performs exactly one measurement. A non-nil context timeout should
	// abort the measurement and be reported as a failed Sample, never a panic.
	Probe(ctx context.Context) model.Sample
	// Close releases any socket held by the prober.
	Close() error
}

// deadline returns the context deadline or now+fallback when none is set.
func deadline(ctx context.Context, fallback time.Duration) time.Time {
	if d, ok := ctx.Deadline(); ok {
		return d
	}
	return time.Now().Add(fallback)
}
