package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"strings"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/model"
)

// dnsProber sends a single recursive A query directly to one resolver and
// measures the round trip. The query is built by hand (RFC 1035) so there is no
// resolver cache in the path and we can see the raw RCODE.
type dnsProber struct {
	server string // host:port
	name   string // query name
}

// NewDNS creates a DNS prober for a resolver (host:port) and query name.
func NewDNS(server, name string) Prober {
	if !strings.Contains(server, ":") {
		server += ":53"
	}
	return &dnsProber{server: server, name: name}
}

func (p *dnsProber) Kind() model.Kind { return model.KindDNS }
func (p *dnsProber) Target() string   { return p.server }
func (p *dnsProber) Close() error     { return nil }

// Probe performs one recursive DNS lookup and measures its latency.
func (p *dnsProber) Probe(ctx context.Context) model.Sample {
	id := uint16(rand.Intn(1 << 16))
	query := buildDNSQuery(id, p.name)

	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "udp", p.server)
	if err != nil {
		return model.NewSample(model.KindDNS, p.server, 0, err)
	}
	defer conn.Close()

	start := time.Now()
	if _, err := conn.Write(query); err != nil {
		return model.NewSample(model.KindDNS, p.server, 0, err)
	}
	if err := conn.SetReadDeadline(deadline(ctx, 2*time.Second)); err != nil {
		return model.NewSample(model.KindDNS, p.server, 0, err)
	}
	rb := make([]byte, 1500)
	n, err := conn.Read(rb)
	rtt := time.Since(start)
	if err != nil {
		return model.NewSample(model.KindDNS, p.server, 0, ErrTimeout)
	}
	if err := validateDNSResponse(rb[:n], id); err != nil {
		return model.NewSample(model.KindDNS, p.server, 0, err)
	}
	// A valid response (including NXDOMAIN) proves the resolver answered, so
	// the sample counts as successful reachability.
	return model.NewSample(model.KindDNS, p.server, rtt, nil)
}

// buildDNSQuery encodes a standard recursive A/IN query.
func buildDNSQuery(id uint16, name string) []byte {
	b := make([]byte, 0, 64)
	b = append(b, byte(id>>8), byte(id))
	b = append(b, 0x01, 0x00) // RD=1
	b = append(b, 0, 1, 0, 0, 0, 0, 0, 0)
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		if len(label) == 0 || len(label) > 63 {
			continue
		}
		b = append(b, byte(len(label)))
		b = append(b, label...)
	}
	b = append(b, 0)    // end of QNAME
	b = append(b, 0, 1) // QTYPE = A
	b = append(b, 0, 1) // QCLASS = IN
	return b
}

// validateDNSResponse checks the transaction ID and reserved header bits.
func validateDNSResponse(b []byte, id uint16) error {
	if len(b) < 12 {
		return fmt.Errorf("dns: short response (%d bytes)", len(b))
	}
	if binary.BigEndian.Uint16(b[0:2]) != id {
		return fmt.Errorf("dns: transaction id mismatch (spoof/cross-talk)")
	}
	if b[2]&0x80 == 0 {
		return fmt.Errorf("dns: response bit not set")
	}
	return nil
}
