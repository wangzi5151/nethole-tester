package report

import (
	"encoding/json"
	"io"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/analyze"
)

// Summary is a stable, machine-readable representation of one analysis. It is
// what `nethole check --json` emits so CI / scripts never have to scrape the
// human-oriented text report.
type Summary struct {
	Generated       string          `json:"generated"`
	Start           string          `json:"start"`
	End             string          `json:"end"`
	DurationS       float64         `json:"duration_s"`
	Samples         int             `json:"samples"`
	OK              int             `json:"ok"`
	Loss            int             `json:"loss"`
	Refused         int             `json:"refused"`
	LossPct         float64         `json:"loss_pct"`
	AvailabilityPct float64         `json:"availability_pct"`
	QualityScore    int             `json:"quality_score"`
	Grade           string          `json:"grade"`
	P95Ms           float64         `json:"p95_ms"`
	P99Ms           float64         `json:"p99_ms"`
	MaxMs           float64         `json:"max_ms"`
	JitterMs        float64         `json:"jitter_ms"`
	Holes           int             `json:"holes"`
	Incidents       int             `json:"incidents"`
	HoleDurationS   float64         `json:"hole_duration_s"`
	Kinds           []SummaryKind   `json:"kinds"`
	Targets         []SummaryTarget `json:"targets"`
	Events          []SummaryEvent  `json:"events"`
	Hints           []string        `json:"hints"`
}

// SummaryKind is the per-chain slice of a Summary.
type SummaryKind struct {
	Kind     string   `json:"kind"`
	Label    string   `json:"label"`
	Targets  []string `json:"targets"`
	Samples  int      `json:"samples"`
	OK       int      `json:"ok"`
	Loss     int      `json:"loss"`
	Refused  int      `json:"refused"`
	LossPct  float64  `json:"loss_pct"`
	AvgMs    float64  `json:"avg_ms"`
	P50Ms    float64  `json:"p50_ms"`
	P95Ms    float64  `json:"p95_ms"`
	P99Ms    float64  `json:"p99_ms"`
	MaxMs    float64  `json:"max_ms"`
	JitterMs float64  `json:"jitter_ms"`
}

// SummaryTarget is the per-destination slice of a Summary.
type SummaryTarget struct {
	Kind     string  `json:"kind"`
	Target   string  `json:"target"`
	Samples  int     `json:"samples"`
	OK       int     `json:"ok"`
	Loss     int     `json:"loss"`
	Refused  int     `json:"refused"`
	LossPct  float64 `json:"loss_pct"`
	AvgMs    float64 `json:"avg_ms"`
	P95Ms    float64 `json:"p95_ms"`
	MaxMs    float64 `json:"max_ms"`
	JitterMs float64 `json:"jitter_ms"`
}

// SummaryEvent is one hole event with a stable RFC3339 timestamp.
type SummaryEvent struct {
	ID        int64   `json:"id"`
	Start     string  `json:"start"`
	End       string  `json:"end"`
	DurationS float64 `json:"duration_s"`
	Kind      string  `json:"kind"`
	Target    string  `json:"target,omitempty"`
	Severity  string  `json:"severity"`
	Reason    string  `json:"reason"`
}

// BuildSummary converts an Analysis into the stable summary shape.
func BuildSummary(a *analyze.Analysis) Summary {
	s := Summary{
		Generated:       time.Now().Format(time.RFC3339),
		DurationS:       a.Duration.Seconds(),
		Samples:         a.TotalSamples,
		OK:              a.OK,
		Loss:            a.Loss,
		Refused:         a.Refused,
		LossPct:         a.LossPct,
		AvailabilityPct: a.AvailabilityPct,
		QualityScore:    a.QualityScore,
		Grade:           a.Grade,
		P95Ms:           a.P95Ms,
		P99Ms:           a.P99Ms,
		MaxMs:           a.MaxMs,
		JitterMs:        a.JitterMs,
		Holes:           len(a.Events),
		Incidents:       len(a.Incidents),
		HoleDurationS:   a.HoleDuration.Seconds(),
		Hints:           analyze.Hints(a),
	}
	if !a.Start.IsZero() {
		s.Start = a.Start.Format(time.RFC3339)
	}
	if !a.End.IsZero() {
		s.End = a.End.Format(time.RFC3339)
	}
	for _, k := range analyze.SortedKinds(a.Kinds) {
		ks := a.Kinds[k]
		s.Kinds = append(s.Kinds, SummaryKind{
			Kind:     string(k),
			Label:    k.Label(),
			Targets:  ks.Targets,
			Samples:  ks.Total,
			OK:       ks.OK,
			Loss:     ks.Loss,
			Refused:  ks.Refused,
			LossPct:  ks.LossPct,
			AvgMs:    ks.AvgMs,
			P50Ms:    ks.P50Ms,
			P95Ms:    ks.P95Ms,
			P99Ms:    ks.P99Ms,
			MaxMs:    ks.MaxMs,
			JitterMs: ks.JitterMs,
		})
	}
	for _, t := range a.Targets {
		s.Targets = append(s.Targets, SummaryTarget{
			Kind:     string(t.Kind),
			Target:   t.Target,
			Samples:  t.Total,
			OK:       t.OK,
			Loss:     t.Loss,
			Refused:  t.Refused,
			LossPct:  t.LossPct,
			AvgMs:    t.AvgMs,
			P95Ms:    t.P95Ms,
			MaxMs:    t.MaxMs,
			JitterMs: t.JitterMs,
		})
	}
	for _, e := range a.Events {
		s.Events = append(s.Events, SummaryEvent{
			ID:        e.ID,
			Start:     e.Start.Format(time.RFC3339),
			End:       e.End.Format(time.RFC3339),
			DurationS: e.Duration().Seconds(),
			Kind:      string(e.Kind),
			Target:    e.Target,
			Severity:  string(e.Severity),
			Reason:    e.Reason,
		})
	}
	return s
}

// WriteSummaryJSON writes an indented summary. JSON encoding escapes HTML
// characters by default, so this is safe to embed anywhere.
func WriteSummaryJSON(w io.Writer, s Summary) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(s)
}
