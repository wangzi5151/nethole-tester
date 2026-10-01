package probe

import (
	"context"
	"fmt"
	"math/rand"
	"runtime"
	"strings"
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
	warns   []string
	out     chan model.Sample
	wg      sync.WaitGroup
}

// NewRunner builds probers from a configuration.
//
// An ICMP chain that cannot be initialised (e.g. on Windows without admin
// rights, where neither raw nor unprivileged ICMP sockets exist) is skipped
// with a warning instead of aborting the whole run — TCP and DNS chains still
// produce useful evidence. Call Warnings to surface those notes to the user.
// It returns an error only when no chain can be initialised at all.
func NewRunner(cfg config.Config) (*Runner, error) {
	var probers []Prober
	var warns []string
	for _, t := range cfg.ICMPTargets {
		p, err := NewICMP(t)
		if err != nil {
			hint := ""
			if runtime.GOOS == "windows" {
				hint = "; on Windows, ICMP probing requires Administrator — re-run elevated to enable it"
			}
			warns = append(warns, fmt.Sprintf("icmp prober %s unavailable (%v), continuing with TCP/DNS only%s", t, err, hint))
			continue
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
		if len(warns) > 0 {
			return nil, fmt.Errorf("no probers could be initialised: %s", strings.Join(warns, "; "))
		}
		return nil, fmt.Errorf("no probers configured")
	}
	return &Runner{
		cfg:     cfg,
		probers: probers,
		warns:   warns,
		out:     make(chan model.Sample, 4096),
	}, nil
}

// Warnings returns non-fatal notes collected while building probers
// (e.g. a skipped ICMP chain). Print them so the user knows what is missing.
func (r *Runner) Warnings() []string { return r.warns }

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
