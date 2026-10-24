// Package ui provides the bubbletea-powered live terminal dashboard.
package ui

import (
	"fmt"
	"sort"
	"strings"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"

	"github.com/wangzi5151/nethole-tester/internal/analyze"
	"github.com/wangzi5151/nethole-tester/internal/config"
	"github.com/wangzi5151/nethole-tester/internal/detect"
	"github.com/wangzi5151/nethole-tester/internal/model"
)

// Frame is a non-blocking status update pushed from the engine to the UI.
type Frame struct {
	Sample    model.Sample
	Update    detect.Update
	Activity  bool // Update is meaningful (hole started/ended)
	HoleCount int
	LossCount int
	Total     int
	Elapsed   time.Duration
	Done      bool
}

const ringSize = 64

// Model is the bubbletea model.
type Model struct {
	cfg    config.Config
	start  time.Time
	frames <-chan Frame

	width, height int

	rtts   map[model.Kind][]float64
	losses map[model.Kind][]bool
	// refused tracks TCP "connection refused" per chain in lockstep with
	// losses: the host is up but the port is closed, so it renders as ×
	// (neutral), never as a loss block.
	refused map[model.Kind][]bool
	last    map[string]model.Sample

	total, loss, holes int
	events             []model.HoleEvent
	elapsed            time.Duration
	done               bool
}

// New creates the dashboard model. frames must be closed when the run ends.
func New(cfg config.Config, frames <-chan Frame) Model {
	return Model{
		cfg:     cfg,
		start:   time.Now(),
		frames:  frames,
		rtts:    map[model.Kind][]float64{},
		losses:  map[model.Kind][]bool{},
		refused: map[model.Kind][]bool{},
		last:    map[string]model.Sample{},
	}
}

type frameMsg Frame

func waitForFrame(ch <-chan Frame) tea.Cmd {
	return func() tea.Msg {
		f, ok := <-ch
		if !ok {
			return frameMsg(Frame{Done: true})
		}
		return frameMsg(f)
	}
}

// Init implements tea.Model.
func (m Model) Init() tea.Cmd { return waitForFrame(m.frames) }

// Update implements tea.Model.
func (m Model) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.WindowSizeMsg:
		m.width, m.height = msg.Width, msg.Height
		return m, nil
	case tea.KeyMsg:
		switch msg.String() {
		case "q", "esc", "ctrl+c":
			m.done = true
			return m, tea.Quit
		}
		return m, nil
	case frameMsg:
		f := Frame(msg)
		if f.Done {
			m.done = true
			return m, tea.Quit
		}
		m.apply(f)
		return m, waitForFrame(m.frames)
	}
	return m, nil
}

func (m *Model) apply(f Frame) {
	m.elapsed = f.Elapsed
	m.total = f.Total
	m.loss = f.LossCount
	m.holes = f.HoleCount

	s := f.Sample
	m.last[string(s.Kind)+"|"+s.Target] = s
	m.losses[s.Kind] = appendCappedBool(m.losses[s.Kind], !s.OK, ringSize)
	m.refused[s.Kind] = appendCappedBool(m.refused[s.Kind], s.ConnRefused, ringSize)
	if s.OK {
		m.rtts[s.Kind] = appendCappedFloat(m.rtts[s.Kind], s.RTTms, ringSize)
	}

	if f.Update.Event.ID != 0 {
		if f.Update.Started {
			m.events = append([]model.HoleEvent{f.Update.Event}, m.events...)
			if len(m.events) > 6 {
				m.events = m.events[:6]
			}
		} else {
			// Ended and progress updates keep the live duration accurate.
			for i := range m.events {
				if m.events[i].ID == f.Update.Event.ID {
					m.events[i] = f.Update.Event
					break
				}
			}
		}
	}
}

// View implements tea.Model.
func (m Model) View() string {
	var b strings.Builder

	titleStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("42"))
	dim := lipgloss.NewStyle().Foreground(lipgloss.Color("240"))
	bad := lipgloss.NewStyle().Foreground(lipgloss.Color("203")).Bold(true)

	b.WriteString(titleStyle.Render(" NetHole-Tester "))
	b.WriteString(dim.Render(" 网络隐形断流探测器 / invisible-drop detector"))
	b.WriteString("\n")
	fmt.Fprintf(&b, " preset=%s  interval=%s  elapsed=%s", m.cfg.Name, m.cfg.Interval, m.elapsed.Round(time.Second))
	if m.cfg.Duration > 0 {
		fmt.Fprintf(&b, "/%s", m.cfg.Duration.Round(time.Second))
	}
	fmt.Fprintf(&b, "  holes=")
	if m.holes > 0 {
		b.WriteString(bad.Render(fmt.Sprintf("%d", m.holes)))
	} else {
		b.WriteString("0")
	}
	fmt.Fprintf(&b, "  samples=%d  lost=%d\n", m.total, m.loss)
	fmt.Fprintf(&b, " live availability=%.2f%%  recent p95=%.1fms\n", m.availability(), m.p95All())
	b.WriteString(dim.Render(strings.Repeat("─", clamp(m.width, 40, 100))) + "\n")

	chartW := clamp((m.width-34)/2, 10, 32)
	for _, k := range m.cfg.Kinds() {
		spark := analyze.Sparkline(m.rtts[k], chartW)
		strip := lossStrip(m.losses[k], m.refused[k], chartW)
		lastTxt := "waiting…"
		alert := false
		if s, ok := m.lastSample(k); ok {
			switch {
			case s.OK:
				lastTxt = fmt.Sprintf("%.1fms", s.RTTms)
			case s.ConnRefused:
				lastTxt, alert = "REFUSED", true
			default:
				lastTxt, alert = "TIMEOUT", true
			}
		}
		lastTxt = padRight(lastTxt, 9)
		if alert {
			lastTxt = bad.Render(lastTxt)
		}
		avgTxt, p95Txt, lossTxt := "—", "—", "—"
		if len(m.rtts[k]) > 0 {
			avgTxt = fmt.Sprintf("%.1fms", m.avgRTT(k))
			p95Txt = fmt.Sprintf("%.1fms", m.p95RTT(k))
		}
		if len(m.losses[k]) > 0 {
			lossTxt = fmt.Sprintf("%.1f%%", m.recentLossPct(k))
		}
		fmt.Fprintf(&b, " %-10s %s  avg %7s  p95 %7s  loss %6s\n",
			k.Label(), lastTxt, avgTxt, p95Txt, lossTxt)
		fmt.Fprintf(&b, "   trend %s  pkt %s\n", spark, dim.Render(strip))
	}
	b.WriteString(dim.Render(strings.Repeat("─", clamp(m.width, 40, 100))) + "\n")

	if len(m.events) == 0 {
		b.WriteString(dim.Render(" 暂无网洞事件，一切正常 / no holes yet") + "\n")
	} else {
		b.WriteString(" 最近网洞 / recent holes:\n")
		for _, e := range m.events {
			sev := dim
			if e.Severity == model.SevCritical {
				sev = bad
			}
			fmt.Fprintf(&b, "  %s %-9s %6.1fs  %s\n",
				sev.Render(e.Start.Format("15:04:05")), e.Kind.Label(), e.Duration().Seconds(), truncate(e.Reason, 52))
		}
	}
	b.WriteString("\n")
	b.WriteString(dim.Render(" [q] 停止并导出报告 / stop & export  ·  Ctrl+C 退出"))
	b.WriteString("\n")
	return b.String()
}

func (m Model) avgRTT(k model.Kind) float64 {
	xs := m.rtts[k]
	if len(xs) == 0 {
		return 0
	}
	var sum float64
	for _, v := range xs {
		sum += v
	}
	return sum / float64(len(xs))
}

func (m Model) p95RTT(k model.Kind) float64 { return percentile95(m.rtts[k]) }

func (m Model) p95All() float64 {
	var all []float64
	for _, xs := range m.rtts {
		all = append(all, xs...)
	}
	return percentile95(all)
}

// recentLossPct uses the ring buffer, excluding refused probes (host up, port
// closed) so the live number matches the final analysis definition of loss.
func (m Model) recentLossPct(k model.Kind) float64 {
	lost := m.losses[k]
	if len(lost) == 0 {
		return 0
	}
	total, bad := 0, 0
	for i, l := range lost {
		if i < len(m.refused[k]) && m.refused[k][i] {
			continue
		}
		total++
		if l {
			bad++
		}
	}
	if total == 0 {
		return 0
	}
	return float64(bad) / float64(total) * 100
}

func (m Model) availability() float64 {
	if m.total == 0 {
		return 100
	}
	return float64(m.total-m.loss) / float64(m.total) * 100
}

func percentile95(xs []float64) float64 {
	if len(xs) == 0 {
		return 0
	}
	sorted := append([]float64(nil), xs...)
	sort.Float64s(sorted)
	idx := int(float64(len(sorted)-1)*0.95 + 0.5)
	if idx >= len(sorted) {
		idx = len(sorted) - 1
	}
	return sorted[idx]
}

func (m Model) lastSample(k model.Kind) (model.Sample, bool) {
	var best model.Sample
	found := false
	for _, s := range m.last {
		if s.Kind != k {
			continue
		}
		if !found || s.Time.After(best.Time) {
			best = s
			found = true
		}
	}
	return best, found
}

// lossStrip renders the recent per-sample history: █ lost, × refused
// (host reachable, port closed — neutral, not packet loss), · ok.
func lossStrip(lost, refused []bool, width int) string {
	if len(lost) == 0 {
		return ""
	}
	if len(lost) > width {
		lost = lost[len(lost)-width:]
	}
	if len(refused) > width {
		refused = refused[len(refused)-width:]
	}
	var b strings.Builder
	for i, l := range lost {
		switch {
		case i < len(refused) && refused[i]:
			b.WriteRune('×')
		case l:
			b.WriteRune('█')
		default:
			b.WriteRune('·')
		}
	}
	return b.String()
}

func appendCappedFloat(xs []float64, v float64, n int) []float64 {
	xs = append(xs, v)
	if len(xs) > n {
		xs = xs[len(xs)-n:]
	}
	return xs
}

func appendCappedBool(xs []bool, v bool, n int) []bool {
	xs = append(xs, v)
	if len(xs) > n {
		xs = xs[len(xs)-n:]
	}
	return xs
}

func clamp(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}

func padRight(s string, n int) string {
	for len([]rune(s)) < n {
		s += " "
	}
	return s
}

func truncate(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n-1]) + "…"
}
