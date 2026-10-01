package snapshot

import (
	"context"
	"os/exec"
	"strings"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/config"
)

// traceroute runs whichever of mtr/traceroute/tracepath is installed. It never
// shells out to anything but those fixed, read-only diagnostics (no user input
// reaches the shell), keeping the tool compliant and safe.
func traceroute(ctx context.Context, cfg config.Config) (string, string) {
	target := "1.1.1.1"
	if len(cfg.ICMPTargets) > 0 {
		target = cfg.ICMPTargets[0]
	}
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()

	type candidate struct {
		bin  string
		args []string
	}
	candidates := []candidate{
		{"mtr", []string{"-rwzc5", "-m", "12", target}},
		{"traceroute", []string{"-n", "-m", "12", "-w", "1", target}},
		{"tracepath", []string{"-n", "-m", "12", target}},
	}
	for _, c := range candidates {
		path := findTool(c.bin)
		if path == "" {
			continue
		}
		out, err := exec.CommandContext(ctx, path, c.args...).CombinedOutput()
		txt := strings.TrimRight(string(out), "\n")
		if txt != "" {
			return txt, "via " + c.bin
		}
		if err != nil {
			return "", c.bin + " failed: " + err.Error()
		}
	}
	return "", "no traceroute tool found (install mtr or traceroute for hop evidence)"
}
