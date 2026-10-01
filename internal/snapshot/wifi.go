package snapshot

import (
	"context"
	"os"
	"os/exec"
	"runtime"
	"strings"
	"time"
)

// wifiInfo collects Wi-Fi signal / link quality when the platform exposes it.
// Android restrictions mean this is frequently unavailable in Termux without
// root; that is reported as a note rather than an error.
func wifiInfo(ctx context.Context) (string, string) {
	ctx, cancel := context.WithTimeout(ctx, 4*time.Second)
	defer cancel()

	if runtime.GOOS == "linux" {
		if b, err := os.ReadFile("/proc/net/wireless"); err == nil {
			txt := strings.TrimSpace(string(b))
			if len(strings.Split(txt, "\n")) > 2 {
				return txt, "from /proc/net/wireless"
			}
		}
		if path := findTool("iwconfig"); path != "" {
			if out, err := exec.CommandContext(ctx, path).CombinedOutput(); err == nil {
				if txt := strings.TrimSpace(string(out)); txt != "" {
					return txt, "via iwconfig"
				}
			}
		}
	}

	// Android specific hints (may require permissions; best effort).
	if runtime.GOOS == "android" {
		for _, args := range [][]string{
			{"wifi", "status"},
			{"wifi", "list-networks"},
		} {
			if path := findTool("cmd"); path != "" {
				if out, err := exec.CommandContext(ctx, path, args...).CombinedOutput(); err == nil {
					if txt := strings.TrimSpace(string(out)); txt != "" {
						return txt, "via cmd " + strings.Join(args, " ")
					}
				}
			}
		}
	}

	switch runtime.GOOS {
	case "darwin":
		if path := findTool("airport"); path != "" {
			if out, err := exec.CommandContext(ctx, path, "-I").CombinedOutput(); err == nil {
				return strings.TrimSpace(string(out)), "via airport -I"
			}
		}
	case "windows":
		if path := findTool("netsh"); path != "" {
			if out, err := exec.CommandContext(ctx, path, "wlan", "show", "interfaces").CombinedOutput(); err == nil {
				return strings.TrimSpace(string(out)), "via netsh wlan"
			}
		}
	}
	return "", "Wi-Fi signal not readable on this platform/session"
}
