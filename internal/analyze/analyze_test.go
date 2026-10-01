package analyze

import (
	"bytes"
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
