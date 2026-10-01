// Package detect turns a stream of samples into HoleEvents. It is deliberately
// stateful per (kind,target) so a single flaky chain cannot mask a clean one.
package detect

import (
	"fmt"

	"github.com/wangzi5151/nethole-tester/internal/config"
	"github.com/wangzi5151/nethole-tester/internal/model"
)

// Update describes a state transition produced by Observe. Main uses Started to
// fire an evidence snapshot and Ended to persist the completed event.
type Update struct {
	Event   model.HoleEvent
	Started bool
	Ended   bool
}

type state struct {
	kind    model.Kind
	target  string
	base    []float64 // ring of recent successful RTTs (ms)
	baseIdx int
	loss    int // consecutive failed probes
	active  *model.HoleEvent
}

// Detector applies thresholds to incoming samples.
type Detector struct {
	th     config.Thresholds
	states map[string]*state
	nextID int64
}

// New creates a Detector with the supplied thresholds.
func New(th config.Thresholds) *Detector {
	return &Detector{th: th, states: map[string]*state{}}
}

func (d *Detector) state(s model.Sample) *state {
	key := string(s.Kind) + "|" + s.Target
	st := d.states[key]
	if st == nil {
		st = &state{
			kind:   s.Kind,
			target: s.Target,
			base:   make([]float64, 0, d.th.BaselineWindow),
		}
		d.states[key] = st
	}
	return st
}

// Observe feeds one sample and reports whether a hole just started or ended.
func (d *Detector) Observe(s model.Sample) (Update, bool) {
	st := d.state(s)

	if !s.OK {
		return d.onFailure(st, s), true
	}
	return d.onSuccess(st, s), true
}

func (d *Detector) onFailure(st *state, s model.Sample) Update {
	st.loss++
	if st.active == nil {
		if st.loss >= d.th.LossBurst {
			sev := model.SevWarn
			if s.Kind == model.KindTCP {
				sev = model.SevCritical
			}
			if st.loss >= d.th.LossBurst*2 {
				sev = model.SevCritical
			}
			ev := &model.HoleEvent{
				ID:        d.newID(),
				Start:     s.Time,
				End:       s.Time,
				Kind:      st.kind,
				Target:    st.target,
				Reason:    fmt.Sprintf("%d consecutive probe failures on %s", st.loss, st.target),
				Severity:  sev,
				Samples:   1,
				LossCount: 1,
				MaxRTTms:  0,
			}
			st.active = ev
			return Update{Event: *ev, Started: true}
		}
		return Update{}
	}

	// Hole already open: extend it.
	st.active.End = s.Time
	st.active.Samples++
	st.active.LossCount++
	if st.loss >= d.th.LossBurst*2 {
		st.active.Severity = model.SevCritical
	}
	return Update{Event: *st.active}
}

func (d *Detector) onSuccess(st *state, s model.Sample) Update {
	st.loss = 0

	if st.active != nil {
		// Recover the event on the first healthy sample.
		st.active.End = s.Time
		st.active.Samples++
		if s.RTTms > st.active.MaxRTTms {
			st.active.MaxRTTms = s.RTTms
		}
		ev := st.active
		st.active = nil
		return Update{Event: *ev, Ended: true}
	}

	baseline := st.average()
	spike := d.isSpike(s.RTTms, baseline)
	if !spike {
		// Only feed healthy samples into the baseline, otherwise a spike
		// would poison the very reference used to detect it.
		st.push(s.RTTms)
	}

	if spike {
		ev := &model.HoleEvent{
			ID:       d.newID(),
			Start:    s.Time,
			End:      s.Time,
			Kind:     st.kind,
			Target:   st.target,
			Reason:   fmt.Sprintf("latency spike %.0fms on %s (baseline %.0fms)", s.RTTms, st.target, baseline),
			Severity: model.SevWarn,
			Samples:  1,
			MaxRTTms: s.RTTms,
		}
		if s.RTTms-baseline > 2*d.th.LatencySpikeMs {
			ev.Severity = model.SevCritical
		}
		st.active = ev
		return Update{Event: *ev, Started: true}
	}
	return Update{}
}

func (d *Detector) isSpike(rtt, baseline float64) bool {
	if rtt < d.th.SpikeFloorMs {
		return false
	}
	return rtt-baseline > d.th.LatencySpikeMs
}

// Flush closes any still-open events and returns them. Call it when the sample
// stream ends, otherwise a blackhole that persists until shutdown would never
// be written to disk.
func (d *Detector) Flush() []model.HoleEvent {
	var out []model.HoleEvent
	for _, st := range d.states {
		if st.active != nil {
			ev := *st.active
			st.active = nil
			out = append(out, ev)
		}
	}
	return out
}

func (d *Detector) newID() int64 {
	d.nextID++
	return d.nextID
}

func (st *state) average() float64 {
	if len(st.base) == 0 {
		return 0
	}
	var sum float64
	for _, v := range st.base {
		sum += v
	}
	return sum / float64(len(st.base))
}

func (st *state) push(v float64) {
	if len(st.base) < cap(st.base) {
		st.base = append(st.base, v)
		return
	}
	st.base[st.baseIdx%len(st.base)] = v
	st.baseIdx++
}
