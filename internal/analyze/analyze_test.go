package analyze

import (
	"bytes"
	"fmt"
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

func TestRTTsStayChronological(t *testing.T) {
	base := time.Now()
	vals := []float64{10, 5, 20, 8, 12}
	var ss []model.Sample
	for i, v := range vals {
		ss = append(ss, model.Sample{
			Time: base.Add(time.Duration(i) * time.Second), Kind: model.KindICMP,
			Target: "1.1.1.1", OK: true, RTTms: v,
		})
	}
	a := Analyze(ss, nil)
	ks := a.Kinds[model.KindICMP]
	if len(ks.RTTs) != len(vals) {
		t.Fatalf("RTT series length = %d, want %d", len(ks.RTTs), len(vals))
	}
	for i, want := range vals {
		if ks.RTTs[i] != want {
			t.Fatalf("RTT[%d] = %v, want %v (series must stay chronological)", i, ks.RTTs[i], want)
		}
	}
}

func TestAvailabilityAndQuality(t *testing.T) {
	base := time.Now()
	var ss []model.Sample
	for i := 0; i < 999; i++ {
		ss = append(ss, model.Sample{Time: base.Add(time.Duration(i) * time.Second), Kind: model.KindICMP, Target: "1.1.1.1", OK: true, RTTms: 30})
	}
	ss = append(ss, model.Sample{Time: base.Add(1000 * time.Second), Kind: model.KindICMP, Target: "1.1.1.1", OK: false})
	a := Analyze(ss, nil)
	if a.AvailabilityPct < 99.89 || a.AvailabilityPct > 99.91 {
		t.Fatalf("AvailabilityPct = %v, want ~99.9", a.AvailabilityPct)
	}
	if a.Grade != "A" || a.QualityScore < 90 {
		t.Fatalf("grade=%s score=%d, want A/>=90", a.Grade, a.QualityScore)
	}
}

func TestPerTargetStats(t *testing.T) {
	base := time.Now()
	var ss []model.Sample
	for i := 0; i < 10; i++ {
		ss = append(ss, model.Sample{Time: base, Kind: model.KindICMP, Target: "good", OK: true, RTTms: 20})
		ss = append(ss, model.Sample{Time: base, Kind: model.KindICMP, Target: "bad", OK: i < 4, RTTms: 20})
	}
	a := Analyze(ss, nil)
	if len(a.Targets) != 2 {
		t.Fatalf("targets = %d, want 2", len(a.Targets))
	}
	if len(TargetsOfKind(a, model.KindICMP)) != 2 {
		t.Fatal("TargetsOfKind did not return both targets")
	}
	for _, ts := range a.Targets {
		if ts.Target == "bad" && ts.LossPct != 60 {
			t.Fatalf("bad target loss = %v, want 60", ts.LossPct)
		}
	}
}

func TestLoadSamplesReadsRotatedOldestFirst(t *testing.T) {
	dir := t.TempDir()
	base := dir + "/samples.jsonl"
	line := func(sec int, target string) string {
		return fmt.Sprintf("{\"t\":\"2026-01-01T00:00:%02dZ\",\"kind\":\"icmp\",\"target\":%q,\"rtt_ms\":1,\"ok\":true}\n", sec, target)
	}
	if err := os.WriteFile(base+".2", []byte(line(1, "oldest")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base+".1", []byte(line(2, "middle")), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base, []byte(line(3, "newest")), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadSamples(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 {
		t.Fatalf("loaded %d samples, want 3", len(got))
	}
	for i, want := range []string{"oldest", "middle", "newest"} {
		if got[i].Target != want {
			t.Fatalf("sample[%d].Target = %q, want %q", i, got[i].Target, want)
		}
	}
}

func TestQualityScoreBands(t *testing.T) {
	cases := []struct {
		avail, p95, jitter float64
		grade              string
	}{
		{100, 30, 5, "A"},
		{99.9, 120, 30, "A"},
		{99, 100, 20, "C"},
		{96, 250, 80, "F"},
		{60, 500, 200, "F"},
	}
	for _, c := range cases {
		score, grade := qualityScore(c.avail, c.p95, c.jitter)
		if grade != c.grade {
			t.Errorf("qualityScore(%v,%v,%v) = %d/%s, want grade %s", c.avail, c.p95, c.jitter, score, grade, c.grade)
		}
	}
}

func TestEventsCSVIncludesTarget(t *testing.T) {
	var b bytes.Buffer
	err := WriteEventsCSV(&b, []model.HoleEvent{{
		ID: 1, Kind: model.KindTCP, Target: "example:443", Severity: model.SevWarn,
	}})
	if err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if !strings.Contains(out, "id,start,end,duration_s,kind,target,severity") {
		t.Fatalf("events csv header missing target column: %q", out)
	}
	if !strings.Contains(out, "example:443") {
		t.Fatal("events csv missing target value")
	}
}

func TestLoadEventsDedupesAcrossRotatedFiles(t *testing.T) {
	dir := t.TempDir()
	base := dir + "/events.jsonl"
	old := `{"run":"r","id":1,"kind":"icmp","target":"a","start":"2026-01-01T00:00:00Z","end":"2026-01-01T00:00:01Z","samples":1,"loss_count":1}
`
	newer := `{"run":"r","id":1,"kind":"icmp","target":"a","start":"2026-01-01T00:00:00Z","end":"2026-01-01T00:00:04Z","samples":4,"loss_count":4}
{"run":"r","id":2,"kind":"dns","target":"b","start":"2026-01-01T00:01:00Z","end":"2026-01-01T00:01:02Z","samples":2,"loss_count":2}
`
	if err := os.WriteFile(base+".1", []byte(old), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(base, []byte(newer), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := LoadEvents(base)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("loaded %d events, want 2", len(got))
	}
	if got[0].Samples != 4 || got[0].LossCount != 4 {
		t.Fatalf("dedupe across rotation kept %+v, want the more complete record", got[0])
	}
}

func TestAnalyzeEventsOnlyWindow(t *testing.T) {
	base := time.Now()
	a := Analyze(nil, []model.HoleEvent{{
		ID: 1, Kind: model.KindICMP, Start: base, End: base.Add(5 * time.Second),
	}})
	if a.Start.IsZero() || a.Duration != 5*time.Second {
		t.Fatalf("events-only window = %v..%v (%v), want 5s", a.Start, a.End, a.Duration)
	}
}
