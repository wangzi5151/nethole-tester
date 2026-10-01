package snapshot

import (
	"os"
	"path/filepath"
	"strings"
)

// findTool locates an executable without calling os/exec.LookPath.
//
// Why not LookPath: on Android/Termux the kernel seccomp policy can return
// SIGSYS for the faccessat2 syscall that Go's LookPath uses, killing the whole
// process. Scanning PATH with os.Stat avoids that path entirely, and because we
// then launch tools with an absolute path, exec.Command never calls LookPath
// either.
func findTool(name string) string {
	if strings.ContainsRune(name, os.PathSeparator) {
		if isExecutable(name) {
			return name
		}
		return ""
	}
	for _, dir := range filepath.SplitList(os.Getenv("PATH")) {
		if dir == "" {
			continue
		}
		if p := filepath.Join(dir, name); isExecutable(p) {
			return p
		}
	}
	// Common fallbacks, including Termux and Android system paths.
	for _, dir := range []string{
		"/data/data/com.termux/files/usr/bin",
		"/system/bin", "/system/xbin", "/vendor/bin",
		"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin",
	} {
		if p := filepath.Join(dir, name); isExecutable(p) {
			return p
		}
	}
	return ""
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	return info.Mode()&0o111 != 0
}
