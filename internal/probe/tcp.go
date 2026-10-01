package probe

import (
	"context"
	"net"
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
		return model.NewSample(model.KindTCP, p.target, 0, err)
	}
	_ = conn.Close()
	return model.NewSample(model.KindTCP, p.target, rtt, nil)
}
