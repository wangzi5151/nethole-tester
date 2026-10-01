package snapshot

import (
	"os"
	"os/exec"
	"strings"
)

// arpTable reads the local ARP/neighbour table. On Linux (including Android) it
// comes straight from /proc/net/arp; elsewhere it falls back to `arp -a`.
func arpTable() (string, string) {
	if b, err := os.ReadFile("/proc/net/arp"); err == nil {
		txt := strings.TrimRight(string(b), "\n")
		if txt != "" {
			return txt, "from /proc/net/arp"
		}
	}
	if path := findTool("arp"); path != "" {
		if out, err := exec.Command(path, "-a").CombinedOutput(); err == nil {
			if txt := strings.TrimRight(string(out), "\n"); txt != "" {
				return txt, "via arp -a"
			}
		}
	}
	return "", "ARP table unavailable on this platform"
}
