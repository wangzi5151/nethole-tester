package snapshot

import (
	"os"
	"path/filepath"
	"runtime"
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
	candidates := []string{name}
	if runtime.GOOS == "windows" && !hasWindowsExt(name) {
		// Windows executables carry an extension (netsh.exe, arp.exe,
		// tracert.exe); joining dir + bare name never matches a real file.
		candidates = []string{name + ".exe", name + ".cmd", name + ".bat", name + ".com"}
	}
	dirs := filepath.SplitList(os.Getenv("PATH"))
	// Common fallbacks, including Termux and Android system paths.
	dirs = append(dirs,
		"/data/data/com.termux/files/usr/bin",
		"/system/bin", "/system/xbin", "/vendor/bin",
		"/usr/bin", "/usr/sbin", "/bin", "/sbin", "/usr/local/bin",
	)
	for _, dir := range dirs {
		if dir == "" {
			continue
		}
		for _, cand := range candidates {
			if p := filepath.Join(dir, cand); isExecutable(p) {
				return p
			}
		}
	}
	return ""
}

func hasWindowsExt(name string) bool {
	lower := strings.ToLower(name)
	for _, ext := range []string{".exe", ".cmd", ".bat", ".com", ".ps1"} {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func isExecutable(path string) bool {
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}
	if runtime.GOOS == "windows" {
		// Windows has no exec-bit concept (Go never sets 0o111 there);
		// existing as a non-directory is the closest equivalent.
		return true
	}
	return info.Mode()&0o111 != 0
}
