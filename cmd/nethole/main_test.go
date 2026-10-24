package main

import (
	"testing"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/analyze"
	"github.com/wangzi5151/nethole-tester/internal/model"
)

func testAnalysis(loss int) *analyze.Analysis {
	base := time.Now()
	ss := make([]model.Sample, 0, 100)
	for i := 0; i < 100; i++ {
		s := model.Sample{Time: base, Kind: model.KindICMP, Target: "1.1.1.1", OK: i >= loss, RTTms: 20}
		ss = append(ss, s)
	}
	return analyze.Analyze(ss, nil)
}

func TestEvaluateCheckDisabledByDefault(t *testing.T) {
	a := testAnalysis(10)
	if got := evaluateCheck(a, -1, -1, 0, 0); len(got) != 0 {
		t.Fatalf("disabled thresholds produced failures: %v", got)
	}
}

func TestEvaluateCheckThresholds(t *testing.T) {
	a := testAnalysis(10) // 10% loss
	got := evaluateCheck(a, 5, 0, 0, 0)
	if len(got) != 1 {
		t.Fatalf("failures = %v, want one loss failure", got)
	}
	if got := evaluateCheck(a, 5, 0, 99, 0); len(got) != 2 {
		t.Fatalf("failures = %v, want loss + quality failures", got)
	}
	// A generous threshold must pass.
	if got := evaluateCheck(a, 20, 10, 1, 1000); len(got) != 0 {
		t.Fatalf("generous thresholds failed: %v", got)
	}
}

func TestSplitList(t *testing.T) {
	got := splitList(" a, b ,, c ")
	if len(got) != 3 || got[0] != "a" || got[2] != "c" {
		t.Fatalf("splitList = %#v", got)
	}
}
