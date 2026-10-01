package analyze

import (
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/model"
)

var sparkBlocks = []rune("▁▂▃▄▅▆▇█")
var lossBlocks = []rune("·░▒▓█")

// Sparkline downsamples values into width buckets and renders a unicode
// block trend. Empty input returns an empty string.
func Sparkline(vals []float64, width int) string {
	if len(vals) == 0 || width <= 0 {
		return ""
	}
	buckets := bucketize(vals, width)
	min, max := buckets[0], buckets[0]
	for _, v := range buckets {
		if v < min {
			min = v
		}
		if v > max {
			max = v
		}
	}
	var b strings.Builder
	for _, v := range buckets {
		idx := 0
		if max > min {
			idx = int((v - min) / (max - min) * float64(len(sparkBlocks)-1))
		}
		if idx < 0 {
			idx = 0
		}
		if idx >= len(sparkBlocks) {
			idx = len(sparkBlocks) - 1
		}
		b.WriteRune(sparkBlocks[idx])
	}
	return b.String()
}

// LossBars renders per-bucket loss ratios as a density strip.
func LossBars(samples []model.Sample, width int) string {
	if len(samples) == 0 || width <= 0 {
		return ""
	}
	// Fewer samples than columns: one character per sample is far more honest
	// than stretching each sample across many buckets.
	if len(samples) <= width {
		var b strings.Builder
		for _, s := range samples {
			if s.OK {
				b.WriteRune(lossBlocks[0])
			} else {
				b.WriteRune(lossBlocks[len(lossBlocks)-1])
			}
		}
		return b.String()
	}
	step := float64(len(samples)) / float64(width)
	var b strings.Builder
	for i := 0; i < width; i++ {
		lo := int(float64(i) * step)
		hi := int(float64(i+1) * step)
		if hi > len(samples) {
			hi = len(samples)
		}
		if hi <= lo {
			b.WriteRune(lossBlocks[0])
			continue
		}
		lost, total := 0, 0
		for _, s := range samples[lo:hi] {
			total++
			if !s.OK {
				lost++
			}
		}
		idx := 0
		if total > 0 {
			idx = int(float64(lost) / float64(total) * float64(len(lossBlocks)-1))
		}
		if idx >= len(lossBlocks) {
			idx = len(lossBlocks) - 1
		}
		b.WriteRune(lossBlocks[idx])
	}
	return b.String()
}

func bucketize(vals []float64, width int) []float64 {
	if width >= len(vals) {
		return vals
	}
	out := make([]float64, width)
	step := float64(len(vals)) / float64(width)
	for i := 0; i < width; i++ {
		lo := int(float64(i) * step)
		hi := int(float64(i+1) * step)
		if hi > len(vals) {
			hi = len(vals)
		}
		if hi <= lo {
			hi = lo + 1
			if hi > len(vals) {
				hi = len(vals)
			}
		}
		var sum float64
		for _, v := range vals[lo:hi] {
			sum += v
		}
		out[i] = sum / float64(hi-lo)
	}
	return out
}

// RenderText writes the human-readable analysis to w.
func RenderText(w io.Writer, a *Analysis) {
	fmt.Fprintln(w, "================================================================")
	fmt.Fprintln(w, " NetHole-Tester  本地分析报告 / Local Analysis")
	fmt.Fprintln(w, "================================================================")
	if !a.Start.IsZero() {
		fmt.Fprintf(w, " 时间段 Window : %s  ->  %s\n", a.Start.Format("2006-01-02 15:04:05"), a.End.Format("2006-01-02 15:04:05"))
	}
	fmt.Fprintf(w, " 持续 Duration : %s\n", a.Duration.Round(time.Millisecond))
	fmt.Fprintf(w, " 样本 Samples  : %d\n", a.TotalSamples)
	fmt.Fprintf(w, " 网洞 Holes    : %d  (累计 %s)\n", len(a.Events), a.HoleDuration.Round(time.Millisecond))
	fmt.Fprintln(w)

	for _, k := range SortedKinds(a.Kinds) {
		ks := a.Kinds[k]
		fmt.Fprintf(w, "[%s]  %s\n", k.Label(), strings.Join(ks.Targets, ", "))
		lossColor := ""
		if ks.LossPct > 5 {
			lossColor = "  <-- 丢包偏高 / high loss"
		}
		fmt.Fprintf(w, "  包 Packets : %d ok / %d lost  (%.2f%% loss)%s\n", ks.OK, ks.Loss, ks.LossPct, lossColor)
		fmt.Fprintf(w, "  延迟 RTT ms: min %.1f  avg %.1f  p50 %.1f  p95 %.1f  p99 %.1f  max %.1f  (jitter %.1f)\n",
			ks.MinMs, ks.AvgMs, ks.P50Ms, ks.P95Ms, ks.P99Ms, ks.MaxMs, ks.JitterMs)
		fmt.Fprintf(w, "  趋势 Trend : %s\n", Sparkline(ks.RTTs, 56))
		fmt.Fprintf(w, "  丢包 Loss  : %s   (· good  ░▒▓█ bad)\n", LossBars(samplesOfKind(a, k), 56))
		fmt.Fprintln(w)
	}

	if len(a.Events) > 0 {
		fmt.Fprintln(w, "-- 网洞事件 / Hole events -------------------------------")
		for i, e := range a.Events {
			fmt.Fprintf(w, "  #%-3d %s  %-8s %-8s %6.2fs  %s\n",
				i+1,
				e.Start.Format("15:04:05"),
				e.Kind.Label(),
				e.Severity,
				e.Duration().Seconds(),
				e.Reason)
		}
		fmt.Fprintln(w)
	}
}

func samplesOfKind(a *Analysis, k model.Kind) []model.Sample {
	if len(a.Samples) == 0 {
		return nil
	}
	out := make([]model.Sample, 0, 64)
	for _, s := range a.Samples {
		if s.Kind == k {
			out = append(out, s)
		}
	}
	return out
}
