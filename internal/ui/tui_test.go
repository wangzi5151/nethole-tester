package ui

import (
	"testing"

	"github.com/wangzi5151/nethole-tester/internal/model"
)

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

func TestLiveStatsHelpers(t *testing.T) {
	m := Model{
		total: 100,
		loss:  1,
		rtts: map[model.Kind][]float64{
			model.KindICMP: {10, 20, 30, 40, 50},
		},
		losses: map[model.Kind][]bool{
			model.KindICMP: {false, true, false},
		},
		refused: map[model.Kind][]bool{
			model.KindICMP: {false, false, true},
		},
	}
	if got := m.availability(); got != 99 {
		t.Fatalf("availability = %v, want 99", got)
	}
	if got := m.avgRTT(model.KindICMP); got != 30 {
		t.Fatalf("avgRTT = %v, want 30", got)
	}
	if got := m.p95RTT(model.KindICMP); got != 50 {
		t.Fatalf("p95RTT = %v, want 50", got)
	}
	// One genuine loss out of two attempted probes; the refused one is neutral.
	if got := m.recentLossPct(model.KindICMP); got != 50 {
		t.Fatalf("recentLossPct = %v, want 50", got)
	}
}
