// Package analyze turns raw JSONL logs into statistics, ASCII charts, CSV
// exports and correlation hints. Everything runs locally; nothing is uploaded.
package analyze

import (
	"bufio"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/model"
)

// KindStats aggregates one probe chain.
type KindStats struct {
	Kind    model.Kind
	Targets []string
	Total   int
	OK      int
	Loss    int
	Refused int // TCP connection refused: host up, port closed (not loss)
	LossPct float64
	// RTTs is chronological (insertion order), not sorted. This keeps the
	// trend sparkline honest; percentile helpers sort a private copy.
	RTTs []float64
	RTTStats
}

// RTTStats is the latency summary shared by per-chain and per-target stats.
type RTTStats struct {
	N        int
	MinMs    float64
	AvgMs    float64
	P50Ms    float64
	P95Ms    float64
	P99Ms    float64
	MaxMs    float64
	JitterMs float64
}

// TargetStat aggregates one (chain,target) pair. This is what lets the report
// say "only this destination is bad" instead of blaming the whole uplink.
type TargetStat struct {
	Kind    model.Kind
	Target  string
	Total   int
	OK      int
	Loss    int
	Refused int
	LossPct float64
	RTTs    []float64
	RTTStats
}

// Analysis is the full local analysis result.
type Analysis struct {
	Start        time.Time
	End          time.Time
	Duration     time.Duration
	TotalSamples int
	Kinds        map[model.Kind]*KindStats
	Targets      []*TargetStat
	Events       []model.HoleEvent
	// Incidents merges overlapping events across chains into real outages.
	Incidents    []Incident
	HoleDuration time.Duration
	// Samples keeps the ordered stream so charts can show loss over time.
	Samples []model.Sample

	// Aggregate quality figures (refused connections are excluded from the
	// loss denominator, exactly like KindStats.LossPct).
	OK              int
	Loss            int
	Refused         int
	LossPct         float64
	AvailabilityPct float64
	P95Ms           float64
	P99Ms           float64
	MaxMs           float64
	JitterMs        float64
	QualityScore    int
	Grade           string
}

// logFiles returns the active JSONL file plus its rotated ancestors, oldest
// first. Rotation names files "<path>.1", "<path>.2", ... and the reporter must
// read them too, otherwise a 24x7 run silently loses all but the newest chunk.
func logFiles(path string) []string {
	matches, _ := filepath.Glob(path + ".*")
	type rotatedFile struct {
		path string
		n    int
	}
	var rotated []rotatedFile
	for _, m := range matches {
		n, err := strconv.Atoi(strings.TrimPrefix(m, path+"."))
		if err != nil || n <= 0 {
			continue
		}
		rotated = append(rotated, rotatedFile{path: m, n: n})
	}
	sort.Slice(rotated, func(i, j int) bool { return rotated[i].n > rotated[j].n })
	out := make([]string, 0, len(rotated)+1)
	for _, f := range rotated {
		out = append(out, f.path)
	}
	return append(out, path)
}

// eachLine streams every non-empty line of the active log and its rotated
// ancestors. Missing files are skipped rather than treated as errors.
func eachLine(path string, fn func([]byte)) error {
	for _, p := range logFiles(path) {
		f, err := os.Open(p)
		if err != nil {
			if os.IsNotExist(err) {
				continue
			}
			return err
		}
		sc := bufio.NewScanner(f)
		sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
		for sc.Scan() {
			if line := sc.Bytes(); len(line) > 0 {
				fn(line)
			}
		}
		err = sc.Err()
		_ = f.Close()
		if err != nil {
			return err
		}
	}
	return nil
}

// LoadSamples reads a JSONL samples file (including rotated chunks). A missing
// file is not an error.
func LoadSamples(path string) ([]model.Sample, error) {
	var out []model.Sample
	err := eachLine(path, func(line []byte) {
		var s model.Sample
		if err := json.Unmarshal(line, &s); err != nil {
			return // skip a torn line rather than fail the whole report
		}
		out = append(out, s)
	})
	return out, err
}

// LoadEvents reads a JSONL events file (including rotated chunks). A missing
// file is not an error.
func LoadEvents(path string) ([]model.HoleEvent, error) {
	var (
		out   []model.HoleEvent
		index = map[string]int{} // run#id -> position, for checkpoint de-dup
	)
	err := eachLine(path, func(line []byte) {
		var e model.HoleEvent
		if err := json.Unmarshal(line, &e); err != nil {
			return
		}
		// A live event is written on start and then checkpointed, so the same
		// (run,id) can appear several times. Keep the most complete record.
		// Legacy logs without a RunID fall back to the start timestamp so
		// different runs do not collide on ID alone.
		key := fmt.Sprintf("%s#%d", e.RunID, e.ID)
		if e.RunID == "" {
			key = fmt.Sprintf("%s#%d", e.Start.UTC().Format(time.RFC3339Nano), e.ID)
		}
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
			return
		}
		index[key] = len(out)
		out = append(out, e)
	})
	return out, err
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
	targetMap := map[string]*TargetStat{}
	var allRTTs []float64

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

		key := string(s.Kind) + "|" + s.Target
		ts := targetMap[key]
		if ts == nil {
			ts = &TargetStat{Kind: s.Kind, Target: s.Target}
			targetMap[key] = ts
		}
		ts.Total++

		switch {
		case s.OK:
			ks.OK++
			ks.RTTs = append(ks.RTTs, s.RTTms)
			ts.OK++
			ts.RTTs = append(ts.RTTs, s.RTTms)
			a.OK++
			allRTTs = append(allRTTs, s.RTTms)
		case s.ConnRefused:
			// Host is reachable, only the port is closed: not packet loss.
			ks.Refused++
			ts.Refused++
			a.Refused++
		default:
			ks.Loss++
			ts.Loss++
			a.Loss++
		}
	}
	a.TotalSamples = len(samples)
	if a.Start.IsZero() && len(events) > 0 {
		// Events-only logs (e.g. rotated samples but surviving events) still
		// deserve a sensible report window.
		a.Start, a.End = events[0].Start, events[0].End
		for _, e := range events {
			if e.Start.Before(a.Start) {
				a.Start = e.Start
			}
			if e.End.After(a.End) {
				a.End = e.End
			}
		}
	}
	if !a.Start.IsZero() {
		a.Duration = a.End.Sub(a.Start)
	}
	for _, ks := range a.Kinds {
		ks.finalize()
	}
	for _, ts := range targetMap {
		ts.finalize()
		a.Targets = append(a.Targets, ts)
	}
	sort.SliceStable(a.Targets, func(i, j int) bool {
		ri, rj := kindRank(a.Targets[i].Kind), kindRank(a.Targets[j].Kind)
		if ri != rj {
			return ri < rj
		}
		return a.Targets[i].Target < a.Targets[j].Target
	})

	// Cluster overlapping events so three chains firing at once count as one
	// outage, and report downtime from the merged spans (no double counting).
	a.Incidents = Incidents(events, 3*time.Second)
	for _, in := range a.Incidents {
		a.HoleDuration += in.Duration()
	}

	if attempted := a.OK + a.Loss; attempted > 0 {
		a.LossPct = float64(a.Loss) / float64(attempted) * 100
		a.AvailabilityPct = 100 - a.LossPct
		st := computeRTTStats(allRTTs)
		a.P95Ms = st.P95Ms
		a.P99Ms = st.P99Ms
		a.MaxMs = st.MaxMs
		a.JitterMs = st.JitterMs
		a.QualityScore, a.Grade = qualityScore(a.AvailabilityPct, st.P95Ms, st.JitterMs)
	} else {
		// Nothing measurable reached the network (e.g. every TCP target
		// refused). Availability is undefined; do not invent a score.
		a.AvailabilityPct = 100
		a.Grade = "n/a"
	}
	return a
}

// qualityScore turns availability, tail latency and jitter into a deliberately
// simple, reproducible 0-100 heuristic. It is a summary aid, not a diagnosis.
//
// Loss is weighted aggressively on purpose: this tool exists to catch
// stability problems, and even 1% packet loss ruins gaming / calls. The
// availability component is 60 points, decaying to zero at 3% loss; latency is
// 25 points (50ms ideal, 400ms worst); jitter is 15 points (0ms ideal, 150ms
// worst).
func qualityScore(availabilityPct, p95Ms, jitterMs float64) (int, string) {
	lossPct := 100 - availabilityPct
	avail := clamp01(1 - lossPct/3)        // 0% loss -> 1.0, 3% loss -> 0.0
	latency := clamp01(1 - (p95Ms-50)/350) // 50ms -> 1.0, 400ms -> 0.0
	jitter := clamp01(1 - jitterMs/150)    // 0ms -> 1.0, 150ms -> 0.0
	score := int(math.Round(avail*60 + latency*25 + jitter*15))
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score, gradeFor(score)
}

func gradeFor(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 75:
		return "B"
	case score >= 60:
		return "C"
	case score >= 40:
		return "D"
	default:
		return "F"
	}
}

func clamp01(v float64) float64 {
	if v < 0 {
		return 0
	}
	if v > 1 {
		return 1
	}
	return v
}

func kindRank(k model.Kind) int {
	for i, v := range model.AllKinds {
		if v == k {
			return i
		}
	}
	return len(model.AllKinds)
}

func (ks *KindStats) finalize() {
	// Loss is measured only over probes that actually reached the network
	// (refused connections are a target config issue, not packet loss).
	if attempted := ks.OK + ks.Loss; attempted > 0 {
		ks.LossPct = float64(ks.Loss) / float64(attempted) * 100
	}
	ks.RTTStats = computeRTTStats(ks.RTTs)
}

func (ts *TargetStat) finalize() {
	if attempted := ts.OK + ts.Loss; attempted > 0 {
		ts.LossPct = float64(ts.Loss) / float64(attempted) * 100
	}
	ts.RTTStats = computeRTTStats(ts.RTTs)
}

// computeRTTStats sorts a copy so the caller's chronological series (used for
// sparklines) is never reordered.
func computeRTTStats(rtts []float64) RTTStats {
	if len(rtts) == 0 {
		return RTTStats{}
	}
	sorted := append([]float64(nil), rtts...)
	sort.Float64s(sorted)
	n := len(sorted)
	st := RTTStats{
		N:     n,
		MinMs: sorted[0],
		MaxMs: sorted[n-1],
		P50Ms: percentile(sorted, 50),
		P95Ms: percentile(sorted, 95),
		P99Ms: percentile(sorted, 99),
	}
	var sum float64
	for _, v := range sorted {
		sum += v
	}
	st.AvgMs = sum / float64(n)
	var variance float64
	for _, v := range sorted {
		d := v - st.AvgMs
		variance += d * d
	}
	st.JitterMs = math.Sqrt(variance / float64(n))
	return st
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

// TargetsOfKind returns the per-target stats for one chain, in target order.
func TargetsOfKind(a *Analysis, k model.Kind) []*TargetStat {
	var out []*TargetStat
	for _, ts := range a.Targets {
		if ts.Kind == k {
			out = append(out, ts)
		}
	}
	return out
}
