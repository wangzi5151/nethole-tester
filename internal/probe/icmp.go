package probe

import (
	"context"
	"net"
	"os"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"

	"github.com/wangzi5151/nethole-tester/internal/model"
)

// icmpProber owns a dedicated ICMP socket for a single target. A mutex
// serialises probes on the socket, which is required to match replies to the
// correct sequence number. Both IPv4 and IPv6 targets are supported.
type icmpProber struct {
	target string
	ip     net.IP
	conn   *icmp.PacketConn
	raw    bool // true when using a privileged raw socket
	v6     bool
	id     int
	seq    int
	mu     sync.Mutex
}

// NewICMP creates an ICMP prober for target (an IP or hostname). It prefers a
// raw socket and transparently falls back to an unprivileged "udp4"/"udp6"
// datagram socket, which is what makes this work on Android/Termux without
// root. IPv4 is preferred when a hostname has both A and AAAA records.
func NewICMP(target string) (Prober, error) {
	var ip4, ip6 net.IP
	if ip := net.ParseIP(target); ip != nil {
		if v4 := ip.To4(); v4 != nil {
			ip4 = v4
		} else {
			ip6 = ip
		}
	} else {
		addrs, err := net.LookupIP(target)
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			if v4 := a.To4(); v4 != nil && ip4 == nil {
				ip4 = v4
			} else if a.To4() == nil && ip6 == nil {
				ip6 = a
			}
		}
	}

	var (
		conn *icmp.PacketConn
		raw  bool
		v6   bool
		err  error
	)
	switch {
	case ip4 != nil:
		if conn, err = icmp.ListenPacket("ip4:icmp", "0.0.0.0"); err == nil {
			raw = true
		} else if conn, err = icmp.ListenPacket("udp4", "0.0.0.0"); err != nil {
			return nil, err
		}
	case ip6 != nil:
		v6 = true
		if conn, err = icmp.ListenPacket("ip6:ipv6-icmp", "::"); err == nil {
			raw = true
		} else if conn, err = icmp.ListenPacket("udp6", "::"); err != nil {
			return nil, err
		}
	default:
		return nil, &net.DNSError{Name: target, Err: "no IP address"}
	}

	ip := ip4
	if v6 {
		ip = ip6
	}
	return &icmpProber{
		target: target,
		ip:     ip,
		conn:   conn,
		raw:    raw,
		v6:     v6,
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
	body := &icmp.Echo{ID: p.id, Seq: p.seq, Data: []byte("nethole")}

	msgType := icmp.Type(ipv4.ICMPTypeEcho)
	if p.v6 {
		msgType = ipv6.ICMPTypeEchoRequest
	}
	msg := icmp.Message{Type: msgType, Code: 0, Body: body}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return model.NewSample(model.KindICMP, p.target, 0, err)
	}

	// Privileged raw sockets expect *net.IPAddr; unprivileged ping sockets
	// (udp4/udp6) expect *net.UDPAddr. Mixing them yields EINVAL on write.
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
		m := parseICMPReply(rb[:n], p.v6)
		if m == nil {
			continue
		}
		if p.v6 {
			if m.Type != ipv6.ICMPTypeEchoReply {
				continue
			}
		} else if m.Type != ipv4.ICMPTypeEchoReply {
			continue
		}
		echo, ok := m.Body.(*icmp.Echo)
		if !ok {
			continue
		}
		// On a raw socket we can verify the ID; on udp4/udp6 the kernel
		// rewrites it to the socket's local port, so only seq is meaningful.
		if p.raw && echo.ID != p.id {
			continue
		}
		return model.NewSample(model.KindICMP, p.target, time.Since(start), nil)
	}
}

// parseICMPReply normalises raw and unprivileged replies into an icmp.Message.
// Raw sockets may prepend the IP header (IPv4 always on most systems, IPv6
// rarely), so we detect and strip it by the version nibble. ICMP message types
// never begin with nibble 4 or 6, so this is unambiguous.
func parseICMPReply(b []byte, v6 bool) *icmp.Message {
	if v6 {
		if len(b) >= 40 && b[0]>>4 == 6 {
			b = b[40:]
		}
	} else if len(b) >= 20 && b[0]>>4 == 4 {
		ihl := int(b[0]&0x0f) * 4
		if ihl >= 20 && ihl <= len(b) {
			b = b[ihl:]
		}
	}
	proto := 1
	if v6 {
		proto = 58
	}
	m, err := icmp.ParseMessage(proto, b)
	if err != nil {
		return nil
	}
	return m
}
