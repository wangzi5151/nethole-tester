// Package analyze turns raw JSONL logs into statistics, ASCII charts, CSV
// exports and correlation hints. Everything runs locally; nothing is uploaded.
package analyze

import (
	"bufio"
	"encoding/json"
	"math"
	"os"
	"sort"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/model"
)

// KindStats aggregates one probe chain.
type KindStats struct {
	Kind     model.Kind
	Targets  []string
	Total    int
	OK       int
	Loss     int
	LossPct  float64
	MinMs    float64
	AvgMs    float64
	P50Ms    float64
	P95Ms    float64
	P99Ms    float64
	MaxMs    float64
	JitterMs float64
	RTTs     []float64
}

// Analysis is the full local analysis result.
type Analysis struct {
	Start        time.Time
	End          time.Time
	Duration     time.Duration
	TotalSamples int
	Kinds        map[model.Kind]*KindStats
	Events       []model.HoleEvent
	HoleDuration time.Duration
	// Samples keeps the ordered stream so charts can show loss over time.
	Samples []model.Sample
}

// LoadSamples reads a JSONL samples file. A missing file is not an error.
func LoadSamples(path string) ([]model.Sample, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []model.Sample
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var s model.Sample
		if err := json.Unmarshal(line, &s); err != nil {
			continue // skip a torn line rather than fail the whole report
		}
		out = append(out, s)
	}
	return out, sc.Err()
}

// LoadEvents reads a JSONL events file. A missing file is not an error.
func LoadEvents(path string) ([]model.HoleEvent, error) {
	f, err := os.Open(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	defer f.Close()

	var out []model.HoleEvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for sc.Scan() {
		line := sc.Bytes()
		if len(line) == 0 {
			continue
		}
		var e model.HoleEvent
		if err := json.Unmarshal(line, &e); err != nil {
			continue
		}
		out = append(out, e)
	}
	return out, sc.Err()
}

// Analyze computes statistics from samples and events.
func Analyze(samples []model.Sample, events []model.HoleEvent) *Analysis {
	a := &Analysis{
		Kinds:   map[model.Kind]*KindStats{},
		Events:  events,
		Samples: samples,
	}
	for _, s := range samples {
		if a.Start.IsZero() || s.Time.Before(a.Start) {
			a.Start = s.Time
		}
		if s.Time.After(a.End) {
			a.End = s.Time
		}
		ks := a.Kinds[s.Kind]
		if ks == nil {
			ks = &KindStats{Kind: s.Kind}
			a.Kinds[s.Kind] = ks
		}
		ks.Total++
		if !contains(ks.Targets, s.Target) {
			ks.Targets = append(ks.Targets, s.Target)
		}
		if s.OK {
			ks.OK++
			ks.RTTs = append(ks.RTTs, s.RTTms)
		} else {
			ks.Loss++
		}
	}
	a.TotalSamples = len(samples)
	if !a.Start.IsZero() {
		a.Duration = a.End.Sub(a.Start)
	}
	for _, ks := range a.Kinds {
		ks.finalize()
	}
	for _, e := range events {
		a.HoleDuration += e.Duration()
	}
	return a
}

func (ks *KindStats) finalize() {
	if ks.Total > 0 {
		ks.LossPct = float64(ks.Loss) / float64(ks.Total) * 100
	}
	if len(ks.RTTs) == 0 {
		return
	}
	sort.Float64s(ks.RTTs)
	n := len(ks.RTTs)
	ks.MinMs = ks.RTTs[0]
	ks.MaxMs = ks.RTTs[n-1]
	ks.P50Ms = percentile(ks.RTTs, 50)
	ks.P95Ms = percentile(ks.RTTs, 95)
	ks.P99Ms = percentile(ks.RTTs, 99)
	var sum float64
	for _, v := range ks.RTTs {
		sum += v
	}
	ks.AvgMs = sum / float64(n)
	var variance float64
	for _, v := range ks.RTTs {
		d := v - ks.AvgMs
		variance += d * d
	}
	ks.JitterMs = math.Sqrt(variance / float64(n))
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	idx := int(math.Round(p / 100 * float64(len(sorted)-1)))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func contains(xs []string, x string) bool {
	for _, v := range xs {
		if v == x {
			return true
		}
	}
	return false
}

// SortedKinds returns kinds in canonical order.
func SortedKinds(m map[model.Kind]*KindStats) []model.Kind {
	var out []model.Kind
	for _, k := range model.AllKinds {
		if _, ok := m[k]; ok {
			out = append(out, k)
		}
	}
	return out
}
