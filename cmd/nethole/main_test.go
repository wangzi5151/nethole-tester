package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/analyze"
	"github.com/wangzi5151/nethole-tester/internal/config"
	"github.com/wangzi5151/nethole-tester/internal/model"
	"github.com/wangzi5151/nethole-tester/internal/ui"
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

func TestQuickCustomBuildsRequestedArgs(t *testing.T) {
	input := strings.Join([]string{
		"mobile5g", // preset
		"3m",       // duration
		"500ms",    // interval
		"/tmp/out", // out dir
		"",         // trailing newline from the last prompt
	}, "\n")
	var out bytes.Buffer
	args, err := quickCustom(bufio.NewReader(strings.NewReader(input)), &out)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"--preset=mobile5g", "--duration=3m0s", "--interval=500ms", "--out=/tmp/out"}
	if len(args) != len(want) {
		t.Fatalf("args = %#v, want %#v", args, want)
	}
	for i := range want {
		if args[i] != want[i] {
			t.Fatalf("args[%d] = %q, want %q", i, args[i], want[i])
		}
	}
}

func TestQuickCustomRejectsBadValues(t *testing.T) {
	cases := []string{
		"bogus\n10m\n1s\n./out\n",
		"dorm\nnope\n1s\n./out\n",
		"dorm\n-5m\n1s\n./out\n",
		"dorm\n10m\n50ms\n./out\n",
	}
	for _, in := range cases {
		if _, err := quickCustom(bufio.NewReader(strings.NewReader(in)), io.Discard); err == nil {
			t.Fatalf("quickCustom(%q) accepted invalid input", in)
		}
	}
}

func TestDrainFramesDoesNotBlock(t *testing.T) {
	frames := make(chan ui.Frame, 1)
	done := make(chan struct{})
	go func() {
		drainFrames(frames)
		close(done)
	}()
	for i := 0; i < 1000; i++ {
		frames <- ui.Frame{}
	}
	close(frames)
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("drainFrames did not drain and exit")
	}
}

func writeTestRun(t *testing.T, dir string) (samplesPath, eventsPath string) {
	t.Helper()
	samplesPath = filepath.Join(dir, "samples.jsonl")
	eventsPath = filepath.Join(dir, "events.jsonl")
	b, err := json.Marshal(model.Sample{
		Time: time.Now(), Kind: model.KindICMP, Target: "1.1.1.1", OK: true, RTTms: 12,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(samplesPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(eventsPath, nil, 0o644); err != nil {
		t.Fatal(err)
	}
	return samplesPath, eventsPath
}

func TestFinishWritesAllReports(t *testing.T) {
	dir := t.TempDir()
	samplesPath, eventsPath := writeTestRun(t, dir)
	cfg := config.Config{OutDir: dir, SamplesOut: samplesPath, EventsOut: eventsPath}

	if err := finish(cfg); err != nil {
		t.Fatalf("finish: %v", err)
	}
	for _, name := range []string{"report.html", "samples.csv", "events.csv", "complaint.txt"} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("missing %s: %v", name, err)
		}
		if info.Size() == 0 {
			t.Fatalf("%s is empty", name)
		}
	}
}

func TestFinishReportsWriteErrors(t *testing.T) {
	dir := t.TempDir()
	samplesPath, eventsPath := writeTestRun(t, dir)

	// A regular file cannot be used as the output directory, so every report
	// create call fails with ENOTDIR. finish must surface that as an error.
	blocked := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(blocked, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{OutDir: blocked, SamplesOut: samplesPath, EventsOut: eventsPath}
	if err := finish(cfg); err == nil {
		t.Fatal("finish succeeded even though reports could not be written")
	}
}
