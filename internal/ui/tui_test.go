package ui

import "testing"

func TestLossStripRefused(t *testing.T) {
	// ok, lost, refused, ok, refused
	lost := []bool{false, true, true, false, true}
	refused := []bool{false, false, true, false, true}
	got := lossStrip(lost, refused, 40)
	want := "·█×·×"
	if got != want {
		t.Fatalf("lossStrip = %q, want %q", got, want)
	}
	if got := lossStrip(nil, nil, 40); got != "" {
		t.Fatalf("lossStrip(nil) = %q, want empty", got)
	}
	// width clipping keeps the tail of both series in lockstep
	got = lossStrip(lost, refused, 2)
	if got != "·×" {
		t.Fatalf("lossStrip clipped = %q, want %q", got, "·×")
	}
}
