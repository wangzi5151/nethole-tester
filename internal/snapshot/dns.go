package snapshot

import (
	"context"
	"net"
	"strings"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/config"
)

// dnsCheck resolves the configured name against each configured resolver
// directly (bypassing any system cache) and records the answers or errors.
func dnsCheck(ctx context.Context, cfg config.Config) map[string]string {
	out := map[string]string{}
	ctx, cancel := context.WithTimeout(ctx, 2500*time.Millisecond)
	defer cancel()

	servers := cfg.DNSServers
	if len(servers) == 0 {
		servers = []string{"1.1.1.1:53"}
	}
	for _, server := range servers {
		server := server
		r := &net.Resolver{
			PreferGo: true,
			Dial: func(ctx context.Context, network, _ string) (net.Conn, error) {
				d := net.Dialer{Timeout: 1500 * time.Millisecond}
				return d.DialContext(ctx, "udp", server)
			},
		}
		key := server + " -> " + cfg.DNSName
		addrs, err := r.LookupHost(ctx, cfg.DNSName)
		if err != nil {
			out[key] = "ERROR: " + err.Error()
			continue
		}
		out[key] = strings.Join(addrs, ", ")
	}
	return out
}
