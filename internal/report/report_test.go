package report

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/analyze"
	"github.com/wangzi5151/nethole-tester/internal/model"
)

func TestHTMLIsOfflineAndSelfContained(t *testing.T) {
	a := analyze.Analyze([]model.Sample{
		{Kind: model.KindICMP, Target: "1.1.1.1", OK: true, RTTms: 12},
		{Kind: model.KindDNS, Target: "1.1.1.1:53", OK: false},
	}, nil)

	var b bytes.Buffer
	if err := WriteHTML(&b, a); err != nil {
		t.Fatal(err)
	}
	html := b.String()

	for _, bad := range []string{"http://", "https://", "<script src", "google-analytics", "cdn."} {
		if strings.Contains(html, bad) {
			t.Fatalf("report must be offline, found %q", bad)
		}
	}
	if !strings.Contains(html, "var DATA =") {
		t.Fatal("report missing embedded data")
	}
}

func TestPercentZeroNotBlank(t *testing.T) {
	a := analyze.Analyze([]model.Sample{
		{Kind: model.KindICMP, Target: "1.1.1.1", OK: true, RTTms: 5},
	}, nil)
	if got := percent(a); got != "0%" {
		t.Fatalf("percent with no loss = %q, want %q", got, "0%")
	}
}

func TestComplaintContainsEvidence(t *testing.T) {
	a := analyze.Analyze([]model.Sample{
		{Kind: model.KindICMP, Target: "1.1.1.1", OK: false},
	}, []model.HoleEvent{{
		ID: 1, Kind: model.KindICMP, Severity: model.SevWarn,
		Reason: "test hole",
	}})
	var b bytes.Buffer
	WriteComplaint(&b, a, Meta{Operator: "ACME ISP"})
	out := b.String()
	if !strings.Contains(out, "ACME ISP") || !strings.Contains(out, "test hole") {
		t.Fatal("complaint missing meta or evidence")
	}
}

func TestHTMLContainsQualityTargetsAndEvents(t *testing.T) {
	base := time.Now()
	a := analyze.Analyze([]model.Sample{
		{Time: base, Kind: model.KindICMP, Target: "1.1.1.1", OK: true, RTTms: 20},
		{Time: base, Kind: model.KindICMP, Target: "1.1.1.1", OK: false},
		{Time: base, Kind: model.KindTCP, Target: "example:443", OK: true, RTTms: 40},
	}, []model.HoleEvent{{
		ID: 7, Kind: model.KindICMP, Target: "1.1.1.1", Severity: model.SevWarn,
		Start: base, End: base.Add(time.Second), Reason: "loss burst",
	}})

	var b bytes.Buffer
	if err := WriteHTML(&b, a); err != nil {
		t.Fatal(err)
	}
	html := b.String()
	for _, want := range []string{"quality_score", "availability_pct", "targets", "loss burst", "各目标明细"} {
		if !strings.Contains(html, want) {
			t.Fatalf("HTML report missing %q", want)
		}
	}
}

func TestBuildSummaryJSON(t *testing.T) {
	a := analyze.Analyze([]model.Sample{
		{Kind: model.KindICMP, Target: "1.1.1.1", OK: true, RTTms: 12},
	}, nil)
	s := BuildSummary(a)
	if s.Grade == "" || s.QualityScore <= 0 {
		t.Fatalf("summary missing quality: %+v", s)
	}
	if len(s.Kinds) != 1 || len(s.Targets) != 1 {
		t.Fatalf("summary kinds/targets = %d/%d, want 1/1", len(s.Kinds), len(s.Targets))
	}
	var b bytes.Buffer
	if err := WriteSummaryJSON(&b, s); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"availability_pct"`) {
		t.Fatal("summary JSON missing availability_pct")
	}
}
