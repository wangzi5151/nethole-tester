package report

import (
	"encoding/json"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/analyze"
	"github.com/wangzi5151/nethole-tester/internal/model"
)

// maxPointsPerSeries caps how many points are embedded so a multi-day run still
// produces a small, fast HTML file. Points are bucket-averaged, loss preserved.
const maxPointsPerSeries = 2000

type htmlPoint struct {
	T float64 `json:"t"`
	Y float64 `json:"y"` // <0 marks a lost bucket (line gap)
}

type htmlSeries struct {
	Name   string      `json:"name"`
	Color  string      `json:"color"`
	Points []htmlPoint `json:"points"`
}

type htmlEvent struct {
	Start  string  `json:"start"`
	DurS   float64 `json:"dur_s"`
	Kind   string  `json:"kind"`
	Target string  `json:"target,omitempty"`
	Sev    string  `json:"sev"`
	Why    string  `json:"why"`
}

type htmlTarget struct {
	Kind    string  `json:"kind"`
	Target  string  `json:"target"`
	Samples int     `json:"samples"`
	Loss    int     `json:"loss"`
	LossPct float64 `json:"loss_pct"`
	AvgMs   float64 `json:"avg_ms"`
	P95Ms   float64 `json:"p95_ms"`
	MaxMs   float64 `json:"max_ms"`
}

type htmlData struct {
	Generated       string       `json:"generated"`
	DurationS       float64      `json:"duration_s"`
	Total           int          `json:"total"`
	OK              int          `json:"ok"`
	Loss            int          `json:"loss"`
	Refused         int          `json:"refused"`
	LossPct         float64      `json:"loss_pct"`
	AvailabilityPct float64      `json:"availability_pct"`
	QualityScore    int          `json:"quality_score"`
	Grade           string       `json:"grade"`
	P95Ms           float64      `json:"p95_ms"`
	JitterMs        float64      `json:"jitter_ms"`
	Holes           int          `json:"holes"`
	Incidents       int          `json:"incidents"`
	HoleDurS        float64      `json:"hole_dur_s"`
	Series          []htmlSeries `json:"series"`
	Events          []htmlEvent  `json:"events"`
	IncidentList    []htmlEvent  `json:"incident_list"`
	Targets         []htmlTarget `json:"targets"`
	Hints           []string     `json:"hints"`
}

var seriesColors = map[model.Kind]string{
	model.KindICMP: "#3ddc84",
	model.KindTCP:  "#4aa8ff",
	model.KindDNS:  "#ffb74d",
}

// WriteHTML renders a fully offline, interactive report to w.
func WriteHTML(w io.Writer, a *analyze.Analysis) error {
	data := buildHTMLData(a)
	payload, err := json.Marshal(data)
	if err != nil {
		return err
	}

	sum := summaryString(a)
	page := strings.NewReplacer(
		"{{GENERATED}}", time.Now().Format("2006-01-02 15:04:05"),
		"{{SUMMARY}}", sum,
		"{{DATA}}", string(payload),
	).Replace(htmlTemplate)

	_, err = io.WriteString(w, page)
	return err
}

func buildHTMLData(a *analyze.Analysis) htmlData {
	d := htmlData{
		Generated:       time.Now().Format("2006-01-02 15:04:05"),
		DurationS:       a.Duration.Seconds(),
		Total:           a.TotalSamples,
		OK:              a.OK,
		Loss:            a.Loss,
		Refused:         a.Refused,
		LossPct:         a.LossPct,
		AvailabilityPct: a.AvailabilityPct,
		QualityScore:    a.QualityScore,
		Grade:           a.Grade,
		P95Ms:           a.P95Ms,
		JitterMs:        a.JitterMs,
		Holes:           len(a.Events),
		Incidents:       len(a.Incidents),
		HoleDurS:        a.HoleDuration.Seconds(),
		Hints:           analyze.Hints(a),
	}
	for _, k := range analyze.SortedKinds(a.Kinds) {
		d.Series = append(d.Series, htmlSeries{
			Name:   k.Label(),
			Color:  seriesColors[k],
			Points: downsample(a, k),
		})
	}
	for _, e := range a.Events {
		d.Events = append(d.Events, htmlEvent{
			Start:  e.Start.Format("2006-01-02 15:04:05"),
			DurS:   e.Duration().Seconds(),
			Kind:   e.Kind.Label(),
			Target: e.Target,
			Sev:    string(e.Severity),
			Why:    e.Reason,
		})
	}
	for _, in := range a.Incidents {
		d.IncidentList = append(d.IncidentList, htmlEvent{
			Start:  in.Start.Format("2006-01-02 15:04:05"),
			DurS:   in.Duration().Seconds(),
			Kind:   analyze.KindsLabel(in.Kinds),
			Target: strings.Join(in.Targets, ", "),
			Sev:    string(in.Severity),
			Why:    analyze.IncidentReason(in),
		})
	}
	for _, t := range a.Targets {
		d.Targets = append(d.Targets, htmlTarget{
			Kind:    t.Kind.Label(),
			Target:  t.Target,
			Samples: t.Total,
			Loss:    t.Loss,
			LossPct: t.LossPct,
			AvgMs:   t.AvgMs,
			P95Ms:   t.P95Ms,
			MaxMs:   t.MaxMs,
		})
	}
	return d
}

func downsample(a *analyze.Analysis, k model.Kind) []htmlPoint {
	var raw []model.Sample
	for _, s := range a.Samples {
		// Refused connections carry no network signal (host up, port closed):
		// drop them so they neither render as loss gaps nor dilute buckets.
		if s.Kind == k && !s.ConnRefused {
			raw = append(raw, s)
		}
	}
	if len(raw) == 0 {
		return nil
	}
	if a.Start.IsZero() {
		a.Start = raw[0].Time
	}
	toPoint := func(s model.Sample) htmlPoint {
		y := s.RTTms
		if !s.OK {
			y = -1
		}
		return htmlPoint{T: s.Time.Sub(a.Start).Seconds(), Y: y}
	}
	if len(raw) <= maxPointsPerSeries {
		out := make([]htmlPoint, 0, len(raw))
		for _, s := range raw {
			out = append(out, toPoint(s))
		}
		return out
	}

	buckets := maxPointsPerSeries
	step := float64(len(raw)) / float64(buckets)
	out := make([]htmlPoint, 0, buckets)
	for i := 0; i < buckets; i++ {
		lo := int(float64(i) * step)
		hi := int(float64(i+1) * step)
		if hi > len(raw) {
			hi = len(raw)
		}
		if hi <= lo {
			hi = lo + 1
		}
		var sum float64
		okN := 0
		t := raw[lo].Time.Sub(a.Start).Seconds()
		for _, s := range raw[lo:hi] {
			if s.OK {
				sum += s.RTTms
				okN++
			}
		}
		y := -1.0
		if okN > 0 {
			y = sum / float64(okN)
		}
		out = append(out, htmlPoint{T: t, Y: y})
	}
	return out
}

func summaryString(a *analyze.Analysis) string {
	var sb strings.Builder
	sb.WriteString("<div class='cards'>")
	card := func(label, value, sub string) {
		sb.WriteString("<div class='card'><div class='v'>" + value + "</div><div class='l'>" + label + "</div><div class='s'>" + sub + "</div></div>")
	}
	card("监控时长 Duration", a.Duration.Round(time.Second).String(), a.Start.Format("01-02 15:04")+" ~ "+a.End.Format("01-02 15:04"))
	card("采样 Samples", itoa(a.TotalSamples), "成功 "+itoa(a.OK)+" · 丢包 "+itoa(a.Loss))
	quality := "综合质量评分 n/a"
	if a.Grade != "n/a" {
		quality = "综合质量评分 " + itoa(a.QualityScore) + "/100 (" + a.Grade + ")"
	}
	card("可用率 Availability", availabilityPercent(a), quality)
	card("网洞 Holes", itoa(len(a.Incidents)), "合并自 "+itoa(len(a.Events))+" 条 · 累计 "+a.HoleDuration.Round(time.Second).String())
	sb.WriteString("</div>")
	return sb.String()
}

// percent returns the share of attempted probes that failed (0% = no loss).
func percent(a *analyze.Analysis) string {
	return ratioPercent(a.Loss, a.OK+a.Loss)
}

// availabilityPercent returns the share of attempted probes that succeeded.
func availabilityPercent(a *analyze.Analysis) string {
	return ratioPercent(a.OK, a.OK+a.Loss)
}

func ratioPercent(part, total int) string {
	if total == 0 {
		return "n/a"
	}
	s := strconv.FormatFloat(float64(part)/float64(total)*100, 'f', 3, 64)
	s = strings.TrimRight(s, "0")
	s = strings.TrimRight(s, ".")
	if s == "" {
		s = "0"
	}
	return s + "%"
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
