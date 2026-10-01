package probe

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/config"
	"github.com/wangzi5151/nethole-tester/internal/model"
)

type fakeProber struct {
	kind   model.Kind
	target string
	calls  int32
}

func (f *fakeProber) Kind() model.Kind { return f.kind }
func (f *fakeProber) Target() string   { return f.target }
func (f *fakeProber) Close() error     { return nil }
func (f *fakeProber) Probe(context.Context) model.Sample {
	atomic.AddInt32(&f.calls, 1)
	return model.NewSample(f.kind, f.target, 2*time.Millisecond, nil)
}

func TestRunnerStreamsAndCloses(t *testing.T) {
	fp := &fakeProber{kind: model.KindTCP, target: "example:443"}
	r := &Runner{
		cfg:     config.Config{Interval: 20 * time.Millisecond, Timeout: time.Second},
		probers: []Prober{fp},
		out:     make(chan model.Sample, 8),
	}
	ctx, cancel := context.WithCancel(context.Background())
	r.Run(ctx)

	got := 0
	deadline := time.After(3 * time.Second)
	for got < 5 {
		select {
		case s, ok := <-r.Samples():
			if !ok {
				t.Fatalf("channel closed after %d samples", got)
			}
			if s.Kind != model.KindTCP {
				t.Fatalf("unexpected kind %s", s.Kind)
			}
			got++
		case <-deadline:
			t.Fatalf("only received %d samples", got)
		}
	}
	cancel()
	// The stream must close once the context is cancelled.
	select {
	case _, ok := <-r.Samples():
		for ok {
			_, ok = <-r.Samples()
		}
	case <-time.After(3 * time.Second):
		t.Fatal("samples channel did not close after cancel")
	}
	if atomic.LoadInt32(&fp.calls) < 5 {
		t.Fatal("prober was not called enough")
	}
}
