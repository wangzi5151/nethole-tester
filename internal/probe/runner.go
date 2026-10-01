package probe

import (
	"context"
	"fmt"
	"math/rand"
	"sync"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/config"
	"github.com/wangzi5151/nethole-tester/internal/model"
)

// Runner schedules all probers in parallel and multiplexes every Sample onto a
// single channel. Each (prober,target) pair runs in its own goroutine with an
// independent context timeout so one stalled chain can never delay the others.
type Runner struct {
	cfg     config.Config
	probers []Prober
	out     chan model.Sample
	wg      sync.WaitGroup
}

// NewRunner builds probers from a configuration. It returns an error only when a
// chain cannot be initialised at all (e.g. no ICMP socket available) — a later,
// transient probe failure is reported per-sample instead.
func NewRunner(cfg config.Config) (*Runner, error) {
	var probers []Prober
	for _, t := range cfg.ICMPTargets {
		p, err := NewICMP(t)
		if err != nil {
			return nil, fmt.Errorf("icmp prober %s: %w", t, err)
		}
		probers = append(probers, p)
	}
	for _, t := range cfg.TCPTargets {
		probers = append(probers, NewTCP(t))
	}
	for _, s := range cfg.DNSServers {
		probers = append(probers, NewDNS(s, cfg.DNSName))
	}
	if len(probers) == 0 {
		return nil, fmt.Errorf("no probers configured")
	}
	return &Runner{
		cfg:     cfg,
		probers: probers,
		out:     make(chan model.Sample, 4096),
	}, nil
}

// Samples returns the multiplexed sample stream. The channel is closed after
// Run's context is cancelled and all probers have stopped.
func (r *Runner) Samples() <-chan model.Sample { return r.out }

// Run starts every probe loop. It returns immediately; use the context to stop.
func (r *Runner) Run(ctx context.Context) {
	for _, p := range r.probers {
		r.wg.Add(1)
		go r.loop(ctx, p)
	}
	go func() {
		r.wg.Wait()
		close(r.out)
	}()
}

func (r *Runner) loop(ctx context.Context, p Prober) {
	defer r.wg.Done()

	// Small random offset so the three chains never fire in lockstep.
	if j := r.cfg.Interval; j > 1 {
		select {
		case <-ctx.Done():
			return
		case <-time.After(time.Duration(rand.Int63n(int64(j)))):
		}
	}

	ticker := time.NewTicker(r.cfg.Interval)
	defer ticker.Stop()

	for {
		pctx, cancel := context.WithTimeout(ctx, r.cfg.Timeout)
		s := p.Probe(pctx)
		cancel()

		select {
		case r.out <- s:
		case <-ctx.Done():
			return
		}

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
	}
}

// Close releases every prober's socket. Safe to call once after Run stops.
func (r *Runner) Close() {
	for _, p := range r.probers {
		_ = p.Close()
	}
}

// Targets returns a snapshot of all configured targets, grouped by kind.
func (r *Runner) Targets() map[model.Kind][]string {
	m := map[model.Kind][]string{}
	for _, p := range r.probers {
		m[p.Kind()] = append(m[p.Kind()], p.Target())
	}
	return m
}
