package probe

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/model"
)

// tcpProber measures a TCP three-way handshake (SYN -> SYN/ACK) to host:port.
// It never sends application data, so it stays a lightweight, compliant probe.
type tcpProber struct {
	target string
}

// NewTCP creates a TCP-SYN prober for a host:port target.
func NewTCP(target string) Prober { return &tcpProber{target: target} }

func (p *tcpProber) Kind() model.Kind { return model.KindTCP }
func (p *tcpProber) Target() string   { return p.target }
func (p *tcpProber) Close() error     { return nil }

// Probe dials the target and measures the handshake time.
func (p *tcpProber) Probe(ctx context.Context) model.Sample {
	d := net.Dialer{}
	start := time.Now()
	conn, err := d.DialContext(ctx, "tcp", p.target)
	rtt := time.Since(start)
	if err != nil {
		s := model.NewSample(model.KindTCP, p.target, 0, err)
		// A refused connection means the host is up but the port is closed:
		// flag it so the detector does not mistake a wrong target for a
		// network outage. Errno comparison is locale-independent, unlike
		// matching the (possibly localised) error string.
		s.ConnRefused = isConnRefused(err)
		return s
	}
	_ = conn.Close()
	return model.NewSample(model.KindTCP, p.target, rtt, nil)
}

// isConnRefused reports whether err is an ECONNREFUSED from a dial.
func isConnRefused(err error) bool {
	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		return false
	}
	var sysErr *os.SyscallError
	if errors.As(opErr.Err, &sysErr) {
		return sysErr.Err == syscall.ECONNREFUSED
	}
	if errno, ok := opErr.Err.(syscall.Errno); ok {
		return errno == syscall.ECONNREFUSED
	}
	return false
}
