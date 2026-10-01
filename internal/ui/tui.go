// Package ui provides the bubbletea-powered live terminal dashboard.
package ui

import (
	"fmt"
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
	last   map[string]model.Sample

	total, loss, holes int
	events             []model.HoleEvent
	elapsed            time.Duration
	done               bool
}

// New creates the dashboard model. frames must be closed when the run ends.
func New(cfg config.Config, frames <-chan Frame) Model {
	return Model{
		cfg:    cfg,
		start:  time.Now(),
		frames: frames,
		rtts:   map[model.Kind][]float64{},
		losses: map[model.Kind][]bool{},
		last:   map[string]model.Sample{},
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
	if s.OK {
		m.rtts[s.Kind] = appendCappedFloat(m.rtts[s.Kind], s.RTTms, ringSize)
	}

	if f.Activity && f.Update.Event.ID != 0 {
		if f.Update.Started {
			m.events = append([]model.HoleEvent{f.Update.Event}, m.events...)
			if len(m.events) > 6 {
				m.events = m.events[:6]
			}
		} else if f.Update.Ended && len(m.events) > 0 {
			// Update the matching in-memory event with its final duration.
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
	fmt.Fprintf(&b, " preset=%s  interval=%s  elapsed=%s  holes=", m.cfg.Name, m.cfg.Interval, m.elapsed.Round(time.Second))
	if m.holes > 0 {
		b.WriteString(bad.Render(fmt.Sprintf("%d", m.holes)))
	} else {
		b.WriteString("0")
	}
	fmt.Fprintf(&b, "  samples=%d  lost=%d\n", m.total, m.loss)
	b.WriteString(dim.Render(strings.Repeat("─", clamp(m.width, 40, 100))) + "\n")

	for _, k := range m.cfg.Kinds() {
		spark := analyze.Sparkline(m.rtts[k], 40)
		lossStrip := lossStrip(m.losses[k], 40)
		lastTxt := "waiting…"
		if s, ok := m.lastSample(k); ok {
			switch {
			case s.OK:
				lastTxt = fmt.Sprintf("%6.1fms", s.RTTms)
			case s.ConnRefused:
				lastTxt = bad.Render("  REFUSED")
			default:
				lastTxt = bad.Render("  TIMEOUT")
			}
		}
		fmt.Fprintf(&b, " %-10s %s  %s  %s\n", k.Label(), padRight(lastTxt, 12), spark, dim.Render(lossStrip))
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

func lossStrip(xs []bool, width int) string {
	if len(xs) == 0 {
		return ""
	}
	if len(xs) > width {
		xs = xs[len(xs)-width:]
	}
	var b strings.Builder
	for _, lost := range xs {
		if lost {
			b.WriteRune('█')
		} else {
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
