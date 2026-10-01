package analyze

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/model"
)

func mkSamples() []model.Sample {
	base := time.Now()
	var out []model.Sample
	for i := 0; i < 100; i++ {
		s := model.Sample{Time: base.Add(time.Duration(i) * time.Second), Kind: model.KindICMP, Target: "1.1.1.1", OK: true}
		s.RTTms = float64(i % 50)
		out = append(out, s)
	}
	out[10].OK = false
	out[10].RTTms = 0
	return out
}

func TestAnalyze(t *testing.T) {
	a := Analyze(mkSamples(), nil)
	ks := a.Kinds[model.KindICMP]
	if ks == nil {
		t.Fatal("missing icmp stats")
	}
	if ks.Total != 100 || ks.Loss != 1 || ks.OK != 99 {
		t.Fatalf("unexpected counts: %+v", ks)
	}
	if ks.MaxMs < ks.P50Ms {
		t.Fatal("max should be >= p50")
	}
	if a.Duration <= 0 {
		t.Fatal("duration not computed")
	}
}

func TestSparklineWidth(t *testing.T) {
	vals := make([]float64, 200)
	for i := range vals {
		vals[i] = float64(i)
	}
	if got := len([]rune(Sparkline(vals, 56))); got != 56 {
		t.Fatalf("sparkline width = %d, want 56", got)
	}
}

func TestLossBarsShortInput(t *testing.T) {
	ss := []model.Sample{{OK: true}, {OK: false}, {OK: false}}
	got := LossBars(ss, 56)
	if len([]rune(got)) != 3 {
		t.Fatalf("short loss bar length = %d, want 3", len([]rune(got)))
	}
}

func TestRefusedNotCountedAsLoss(t *testing.T) {
	base := time.Now()
	var ss []model.Sample
	for i := 0; i < 5; i++ {
		ss = append(ss, model.Sample{Time: base, Kind: model.KindTCP, Target: "h:1", OK: false, ConnRefused: true})
	}
	ss = append(ss, model.Sample{Time: base, Kind: model.KindTCP, Target: "h:1", OK: true, RTTms: 5})
	a := Analyze(ss, nil)
	ks := a.Kinds[model.KindTCP]
	if ks.Refused != 5 {
		t.Fatalf("Refused = %d, want 5", ks.Refused)
	}
	if ks.Loss != 0 {
		t.Fatalf("Loss = %d, want 0 (refused is not loss)", ks.Loss)
	}
	if ks.LossPct != 0 {
		t.Fatalf("LossPct = %v, want 0", ks.LossPct)
	}
}

func TestIncidentsMergeOverlapping(t *testing.T) {
	base := time.Now()
	mk := func(kind model.Kind, off int) model.HoleEvent {
		return model.HoleEvent{
			RunID: "r", ID: int64(off + 1), Kind: kind, Target: string(kind),
			Start: base.Add(time.Duration(off) * time.Second),
			End:   base.Add(time.Duration(off+1) * time.Second),
		}
	}
	// Three chains firing around the same instant -> one incident.
	same := []model.HoleEvent{mk(model.KindICMP, 0), mk(model.KindTCP, 0), mk(model.KindDNS, 1)}
	if got := Incidents(same, time.Second); len(got) != 1 {
		t.Fatalf("overlapping events -> %d incidents, want 1", len(got))
	} else if len(got[0].Kinds) != 3 {
		t.Fatalf("incident merged %d kinds, want 3", len(got[0].Kinds))
	}
	// Widely separated events -> two incidents.
	sep := []model.HoleEvent{mk(model.KindICMP, 0), mk(model.KindICMP, 30)}
	if got := Incidents(sep, time.Second); len(got) != 2 {
		t.Fatalf("separated events -> %d incidents, want 2", len(got))
	}
}

func TestLoadEventsDedupesCheckpoints(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/events.jsonl"
	// Same (run,id) written three times as a live event is checkpointed.
	lines := `{"run":"r","id":1,"kind":"icmp","start":"2026-01-01T00:00:00Z","end":"2026-01-01T00:00:00Z","samples":1,"loss_count":1}
{"run":"r","id":1,"kind":"icmp","start":"2026-01-01T00:00:00Z","end":"2026-01-01T00:00:03Z","samples":4,"loss_count":4}
{"run":"r","id":1,"kind":"icmp","start":"2026-01-01T00:00:00Z","end":"2026-01-01T00:00:05Z","samples":6,"loss_count":6}
`
	if err := os.WriteFile(path, []byte(lines), 0o644); err != nil {
		t.Fatal(err)
	}
	evs, err := LoadEvents(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(evs) != 1 {
		t.Fatalf("got %d events, want 1 (deduped)", len(evs))
	}
	if evs[0].Samples != 6 || evs[0].LossCount != 6 {
		t.Fatalf("dedupe kept wrong record: %+v", evs[0])
	}
}

func TestWriteCSVHasBOM(t *testing.T) {
	var b bytes.Buffer
	if err := WriteCSV(&b, mkSamples()); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(b.String(), "\ufeff") {
		t.Fatal("csv missing UTF-8 BOM (Excel compatibility)")
	}
	if !strings.Contains(b.String(), "timestamp,kind,target,ok,rtt_ms,error") {
		t.Fatal("csv missing header")
	}
}
