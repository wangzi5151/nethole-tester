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
	Start string  `json:"start"`
	DurS  float64 `json:"dur_s"`
	Kind  string  `json:"kind"`
	Sev   string  `json:"sev"`
	Why   string  `json:"why"`
}

type htmlData struct {
	Generated string       `json:"generated"`
	DurationS float64      `json:"duration_s"`
	Total     int          `json:"total"`
	OK        int          `json:"ok"`
	Loss      int          `json:"loss"`
	LossPct   float64      `json:"loss_pct"`
	Holes     int          `json:"holes"`
	Incidents int          `json:"incidents"`
	HoleDurS  float64      `json:"hole_dur_s"`
	Series    []htmlSeries `json:"series"`
	Events    []htmlEvent  `json:"events"`
	Hints     []string     `json:"hints"`
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
		Generated: time.Now().Format("2006-01-02 15:04:05"),
		DurationS: a.Duration.Seconds(),
		Total:     a.TotalSamples,
		Holes:     len(a.Events),
		Incidents: len(a.Incidents),
		HoleDurS:  a.HoleDuration.Seconds(),
		Hints:     analyze.Hints(a),
	}
	for _, ks := range a.Kinds {
		d.OK += ks.OK
		d.Loss += ks.Loss
	}
	if d.Total > 0 {
		d.LossPct = float64(d.Loss) / float64(d.Total) * 100
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
			Start: e.Start.Format("2006-01-02 15:04:05"),
			DurS:  e.Duration().Seconds(),
			Kind:  e.Kind.Label(),
			Sev:   string(e.Severity),
			Why:   e.Reason,
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
	card("采样 Samples", itoa(a.TotalSamples), "三条链路并行")
	card("网洞 Holes", itoa(len(a.Incidents)), "合并自 "+itoa(len(a.Events))+" 条 · 累计 "+a.HoleDuration.Round(time.Second).String())
	card("异常占比 Bad", percent(a), "丢包+超时")
	sb.WriteString("</div>")
	return sb.String()
}

func percent(a *analyze.Analysis) string {
	// Loss is measured only over probes that actually reached the network,
	// mirroring KindStats.LossPct (refused connections are a target config
	// issue, not packet loss).
	ok, bad := 0, 0
	for _, ks := range a.Kinds {
		ok += ks.OK
		bad += ks.Loss
	}
	if ok+bad == 0 {
		return "0%"
	}
	s := strconv.FormatFloat(float64(bad)/float64(ok+bad)*100, 'f', 2, 64)
	// Trim trailing zeros of the fraction only; a bare integer like "0" must
	// stay "0" (naive TrimRight would turn it into an empty string).
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
