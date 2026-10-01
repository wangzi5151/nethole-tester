package storage

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestRotationCapsFiles(t *testing.T) {
	path := filepath.Join(t.TempDir(), "samples.jsonl")
	r, err := NewRotator(path, 1, 3)
	if err != nil {
		t.Fatal(err)
	}
	// Force tiny rotations regardless of the MiB-based constructor.
	r.maxBytes = 120
	line := []byte("0123456789012345678901234567890123456789") // 40 bytes
	for i := 0; i < 60; i++ {
		if err := r.WriteLine(line); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}

	for i := 1; i <= 3; i++ {
		p := fmt.Sprintf("%s.%d", path, i)
		if _, err := os.Stat(p); err != nil {
			t.Fatalf("expected rotated file %s: %v", p, err)
		}
	}
	if _, err := os.Stat(path + ".4"); err == nil {
		t.Fatal("rotation kept more files than maxFiles")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("active file missing after rotation: %v", err)
	}
}

func TestWriteLineNoRotation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "e.jsonl")
	r, err := NewRotator(path, 8, 5)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	for i := 0; i < 10; i++ {
		if err := r.WriteLine([]byte("x")); err != nil {
			t.Fatal(err)
		}
	}
	info, _ := os.Stat(path)
	if info.Size() != 20 { // 10 lines of "x\n"
		t.Fatalf("size = %d, want 20", info.Size())
	}
}
