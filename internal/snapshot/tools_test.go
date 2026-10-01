package snapshot

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestHasWindowsExt(t *testing.T) {
	cases := map[string]bool{
		"netsh":       false,
		"netsh.exe":   true,
		"arp.CMD":     true,
		"tracert.bat": true,
		"foo.ps1":     true,
		"weird.exex":  false,
	}
	for name, want := range cases {
		if got := hasWindowsExt(name); got != want {
			t.Errorf("hasWindowsExt(%q) = %v, want %v", name, got, want)
		}
	}
}

func TestFindToolAbsolutePath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("absolute-path probe uses unix test binary")
	}
	// findTool must accept an explicit path containing a separator.
	sh := "/bin/sh"
	if _, err := os.Stat(sh); err != nil {
		t.Skip("no /bin/sh on this system")
	}
	if got := findTool(sh); got != sh {
		t.Errorf("findTool(%q) = %q, want %q", sh, got, sh)
	}
	if got := findTool(filepath.Join(t.TempDir(), "no-such-tool")); got != "" {
		t.Errorf("findTool(missing) = %q, want empty", got)
	}
}

func TestFindToolOnPath(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("PATH probe assumes unix layout")
	}
	// "sh" should be discoverable via PATH or the fallback dirs.
	if got := findTool("sh"); got == "" {
		t.Error("findTool(sh) = empty, want a path")
	}
}
