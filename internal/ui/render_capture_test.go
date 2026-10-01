package ui

import (
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/config"
	"github.com/wangzi5151/nethole-tester/internal/detect"
	"github.com/wangzi5151/nethole-tester/internal/model"
)

// TestRenderCapture prints one fully-populated dashboard frame. It is used to
// generate the documentation screenshots and doubles as a smoke test that View
// never panics on realistic input. Safe to keep in the repo.
func TestRenderCapture(t *testing.T) {
	cfg, _ := config.Preset(config.PresetDorm, "out")
	m := New(cfg, nil)
	m.width = 96

	t0 := time.Now()
	total, loss := 0, 0
	for i := 0; i < 64; i++ {
		// ICMP: stable ~34ms with one spike and one loss burst.
		icmpOK := true
		rtt := 30 + 6*math.Sin(float64(i)/4)
		if i == 18 {
			rtt = 480
		}
		if i >= 40 && i <= 42 {
			icmpOK = false
		}
		s := model.Sample{Time: t0.Add(time.Duration(i) * time.Second), Kind: model.KindICMP, Target: "223.5.5.5"}
		if icmpOK {
			s.OK = true
			s.RTTms = rtt
		}
		total++
		if !icmpOK {
			loss++
		}
		m.apply(Frame{Sample: s, Total: total, LossCount: loss, HoleCount: 1, Elapsed: time.Duration(i) * time.Second})

		// TCP: mostly fine, steady.
		st := model.Sample{Time: s.Time, Kind: model.KindTCP, Target: "www.baidu.com:443", OK: true, RTTms: 42 + 4*math.Sin(float64(i)/3)}
		total++
		m.apply(Frame{Sample: st, Total: total, LossCount: loss, HoleCount: 1, Elapsed: time.Duration(i) * time.Second})

		// DNS.
		sd := model.Sample{Time: s.Time, Kind: model.KindDNS, Target: "223.5.5.5:53", OK: true, RTTms: 25 + 3*math.Sin(float64(i)/5)}
		total++
		m.apply(Frame{Sample: sd, Total: total, LossCount: loss, HoleCount: 1, Elapsed: time.Duration(i) * time.Second})
	}

	ev := model.HoleEvent{
		ID: 1, Start: t0.Add(19 * time.Second), End: t0.Add(35*time.Second),
		Kind: model.KindICMP, Severity: model.SevWarn, Reason: "latency spike 480ms on 223.5.5.5 (baseline 32ms)",
	}
	m.apply(Frame{
		Sample:    model.Sample{Time: ev.End, Kind: model.KindICMP, Target: "223.5.5.5", OK: true, RTTms: 33},
		Update:    detect.Update{Event: ev, Started: true},
		Activity:  true,
		Total:     160, LossCount: 3,
		HoleCount: 1, Elapsed: 35 * time.Second,
	})
	m.apply(Frame{
		Sample: model.Sample{Time: t0.Add(41 * time.Second), Kind: model.KindICMP, Target: "223.5.5.5"},
		Update: detect.Update{Event: model.HoleEvent{
			ID: 2, Start: t0.Add(40 * time.Second), End: t0.Add(43 * time.Second),
			Kind: model.KindICMP, Severity: model.SevWarn, Reason: "3 consecutive probe failures on 223.5.5.5",
		}, Started: true},
		Activity: true, Total: 192, LossCount: 3, HoleCount: 2, Elapsed: 43 * time.Second,
	})
	m.holes = 2

	fmt.Println("<<<TUI-START>>>")
	fmt.Print(m.View())
	fmt.Println("<<<TUI-END>>>")
}
