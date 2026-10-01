package report

import (
	"bytes"
	"strings"
	"testing"

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
