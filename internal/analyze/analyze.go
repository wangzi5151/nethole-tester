// Package analyze turns raw JSONL logs into statistics, ASCII charts, CSV
// exports and correlation hints. Everything runs locally; nothing is uploaded.
package analyze

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"sort"
	"strings"
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
	// Incidents merges overlapping events across chains into real outages.
	Incidents    []Incident
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

	var (
		out   []model.HoleEvent
		index = map[string]int{} // run#id -> position, for checkpoint de-dup
	)
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
		// A live event is written on start and then checkpointed, so the same
		// (run,id) can appear several times. Keep the most complete record.
		key := fmt.Sprintf("%s#%d", e.RunID, e.ID)
		if idx, ok := index[key]; ok {
			if e.End.After(out[idx].End) {
				out[idx].End = e.End
			}
			if e.Samples > out[idx].Samples {
				out[idx].Samples = e.Samples
			}
			if e.LossCount > out[idx].LossCount {
				out[idx].LossCount = e.LossCount
			}
			if e.MaxRTTms > out[idx].MaxRTTms {
				out[idx].MaxRTTms = e.MaxRTTms
			}
			if out[idx].Snapshot == nil && e.Snapshot != nil {
				out[idx].Snapshot = e.Snapshot
			}
			continue
		}
		index[key] = len(out)
		out = append(out, e)
	}
	return out, sc.Err()
}

// Incident groups hole events that overlap in time (across probe chains and
// targets) into a single real-world outage, so one disconnect does not inflate
// the report with three near-identical rows.
type Incident struct {
	Start    time.Time
	End      time.Time
	Kinds    []model.Kind
	Targets  []string
	Severity model.Severity
	Events   []model.HoleEvent
}

// Duration returns the incident span.
func (in Incident) Duration() time.Duration { return in.End.Sub(in.Start) }

// KindsLabel renders a compact "ICMP-Ping+TCP-SYN" label for a kind set.
func KindsLabel(kinds []model.Kind) string {
	parts := make([]string, 0, len(kinds))
	for _, k := range kinds {
		parts = append(parts, k.Label())
	}
	return strings.Join(parts, "+")
}

// Incidents clusters events whose gaps are no larger than gap.
func Incidents(events []model.HoleEvent, gap time.Duration) []Incident {
	sorted := append([]model.HoleEvent(nil), events...)
	sort.SliceStable(sorted, func(i, j int) bool { return sorted[i].Start.Before(sorted[j].Start) })

	var out []Incident
	for _, e := range sorted {
		if n := len(out); n > 0 && !e.Start.After(out[n-1].End.Add(gap)) {
			in := &out[n-1]
			if e.End.After(in.End) {
				in.End = e.End
			}
			in.Kinds = appendKind(in.Kinds, e.Kind)
			in.Targets = appendUnique(in.Targets, e.Target)
			in.Events = append(in.Events, e)
			if sevRank(e.Severity) > sevRank(in.Severity) {
				in.Severity = e.Severity
			}
			continue
		}
		out = append(out, Incident{
			Start:    e.Start,
			End:      e.End,
			Kinds:    []model.Kind{e.Kind},
			Targets:  nonEmpty(e.Target),
			Severity: e.Severity,
			Events:   []model.HoleEvent{e},
		})
	}
	return out
}

func appendKind(xs []model.Kind, k model.Kind) []model.Kind {
	for _, v := range xs {
		if v == k {
			return xs
		}
	}
	return append(xs, k)
}

func appendUnique(xs []string, s string) []string {
	if s == "" {
		return xs
	}
	for _, v := range xs {
		if v == s {
			return xs
		}
	}
	return append(xs, s)
}

func nonEmpty(s string) []string {
	if s == "" {
		return nil
	}
	return []string{s}
}

func sevRank(s model.Severity) int {
	switch s {
	case model.SevCritical:
		return 3
	case model.SevWarn:
		return 2
	case model.SevInfo:
		return 1
	}
	return 0
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
	// Cluster overlapping events so three chains firing at once count as one
	// outage, and report downtime from the merged spans (no double counting).
	a.Incidents = Incidents(events, 3*time.Second)
	for _, in := range a.Incidents {
		a.HoleDuration += in.Duration()
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
