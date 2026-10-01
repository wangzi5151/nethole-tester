package probe

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"

	"github.com/wangzi5151/nethole-tester/internal/model"
)

// icmpProber owns a dedicated ICMP socket for a single target. A mutex
// serialises probes on the socket, which is required to match replies to the
// correct sequence number.
type icmpProber struct {
	target string
	ip     net.IP
	conn   *icmp.PacketConn
	raw    bool // true when using a privileged "ip4:icmp" socket
	id     int
	seq    int
	mu     sync.Mutex
}

// NewICMP creates an ICMP prober for target (an IP or hostname). It prefers a
// raw socket and transparently falls back to an unprivileged "udp4" datagram
// socket, which is what makes this work on Android/Termux without root.
func NewICMP(target string) (Prober, error) {
	ip := net.ParseIP(target)
	if ip == nil {
		addrs, err := net.LookupIP(target)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			if v4 := a.To4(); v4 != nil {
				ip = v4
				break
			}
		}
		if ip == nil {
			ip = addrs[0]
		}
	}
	// udp4 ping sockets reject 16-byte-mapped addresses with "invalid argument",
	// so normalise to the 4-byte form whenever possible.
	if v4 := ip.To4(); v4 != nil {
		ip = v4
	}
	var (
		conn *icmp.PacketConn
		raw  bool
		err  error
	)
	if conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
		raw = true
	} else if conn, err = icmp.ListenPacket("udp4", "0.0.0.0"); err != nil {
		return nil, err
	}
	return &icmpProber{
		target: target,
		ip:     ip,
		conn:   conn,
		raw:    raw,
		id:     os.Getpid() & 0xffff,
	}, nil
}

func (p *icmpProber) Kind() model.Kind { return model.KindICMP }
func (p *icmpProber) Target() string   { return p.target }
func (p *icmpProber) Close() error     { return p.conn.Close() }

// Probe sends one echo request and waits for the matching reply.
func (p *icmpProber) Probe(ctx context.Context) model.Sample {
	p.mu.Lock()
	defer p.mu.Unlock()

	p.seq = (p.seq + 1) & 0xffff
	body := &icmp.Echo{
		ID:   p.id,
		Seq:  p.seq,
		Data: []byte("nethole"),
	}
	msg := icmp.Message{Type: ipv4.ICMPTypeEcho, Code: 0, Body: body}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return model.NewSample(model.KindICMP, p.target, 0, err)
	}

	// Privileged raw sockets expect *net.IPAddr; unprivileged ping sockets
	// (udp4) expect *net.UDPAddr. Mixing them yields EINVAL on write.
	var dst net.Addr
	if p.raw {
		dst = &net.IPAddr{IP: p.ip}
	} else {
		dst = &net.UDPAddr{IP: p.ip}
	}
	start := time.Now()
	if _, err := p.conn.WriteTo(wb, dst); err != nil {
		return model.NewSample(model.KindICMP, p.target, 0, err)
	}

	dl := deadline(ctx, 2*time.Second)
	rb := make([]byte, 1500)
	for {
		if err := p.conn.SetReadDeadline(dl); err != nil {
			return model.NewSample(model.KindICMP, p.target, 0, err)
		}
		n, _, err := p.conn.ReadFrom(rb)
		if err != nil {
			return model.NewSample(model.KindICMP, p.target, 0, ErrTimeout)
		}
		m := parseICMPReply(rb[:n], p.raw)
		if m == nil || m.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := m.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		// On a raw socket we can verify the ID; on udp4 the kernel rewrites it
		// to the socket's local port, so only the sequence is meaningful.
		if p.raw && echo.ID != p.id {
			continue
		}
		return model.NewSample(model.KindICMP, p.target, time.Since(start), nil)
	}
}

// parseICMPReply normalises raw and unprivileged replies into an icmp.Message.
// Raw sockets prepend the IPv4 header; udp4 sockets do not.
func parseICMPReply(b []byte, raw bool) *icmp.Message {
	if raw {
		if len(b) < 20 || b[0]>>4 != 4 || b[9] != 1 { // IPv4 + ICMP protocol
			return nil
		}
		ihl := int(b[0]&0x0f) * 4
		if ihl < 20 || ihl > len(b) {
			return nil
		}
		b = b[ihl:]
	}
	m, err := icmp.ParseMessage(1, b)
	if err != nil {
		return nil
	}
	return m
}
