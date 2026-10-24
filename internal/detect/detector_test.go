package detect

import (
	"testing"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/config"
	"github.com/wangzi5151/nethole-tester/internal/model"
)

func sample(ok bool, rttMs float64) model.Sample {
	s := model.Sample{
		Time:   time.Now(),
		Kind:   model.KindICMP,
		Target: "1.1.1.1",
		OK:     ok,
	}
	if ok {
		s.RTT = time.Duration(rttMs * float64(time.Millisecond))
		s.RTTms = rttMs
	}
	return s
}

func TestLossBurstStartsAndEnds(t *testing.T) {
	th := config.DefaultThresholds()
	th.LossBurst = 3
	d := New(th)

	for i := 0; i < 2; i++ {
		if u := d.Observe(sample(false, 0)); u.Started {
			t.Fatalf("event started too early at loss %d", i+1)
		}
	}
	u := d.Observe(sample(false, 0))
	if !u.Started {
		t.Fatal("expected hole to start after 3 consecutive losses")
	}
	if u.Event.Severity == "" {
		t.Fatal("event missing severity")
	}
	u = d.Observe(sample(true, 20))
	if !u.Ended {
		t.Fatal("expected hole to end on first healthy sample")
	}
	if u.Event.Duration() < 0 {
		t.Fatal("negative duration")
	}
}

func TestLatencySpike(t *testing.T) {
	th := config.DefaultThresholds()
	th.LatencySpikeMs = 200
	th.SpikeFloorMs = 250
	d := New(th)

	for i := 0; i < 5; i++ {
		d.Observe(sample(true, 30))
	}
	u := d.Observe(sample(true, 600))
	if !u.Started {
		t.Fatal("expected latency spike event")
	}
}

func TestFlushPersistsActive(t *testing.T) {
	th := config.DefaultThresholds()
	th.LossBurst = 2
	d := New(th)
	d.Observe(sample(false, 0))
	d.Observe(sample(false, 0))

	flushed := d.Flush()
	if len(flushed) != 1 {
		t.Fatalf("expected 1 flushed event, got %d", len(flushed))
	}
	if len(d.Flush()) != 0 {
		t.Fatal("flush should be idempotent")
	}
}

func TestConnRefusedNeverOpensHole(t *testing.T) {
	th := config.DefaultThresholds()
	th.LossBurst = 3
	d := New(th)

	refused := func() model.Sample {
		s := sample(false, 0)
		s.Kind = model.KindTCP
		s.ConnRefused = true
		return s
	}
	// Even a long streak of refused probes must not open a hole event:
	// the host is reachable, only the port is closed.
	for i := 0; i < 10; i++ {
		if u := d.Observe(refused()); u.Started || u.Ended {
			t.Fatalf("refused sample must not drive hole state (iter %d)", i)
		}
	}
	if got := len(d.Flush()); got != 0 {
		t.Fatalf("expected no flushed events, got %d", got)
	}
	// A refused streak must not poison later loss accounting either.
	for i := 0; i < 3; i++ {
		d.Observe(refused())
	}
	tcpLoss := sample(false, 0)
	tcpLoss.Kind = model.KindTCP
	for i := 0; i < 2; i++ {
		if u := d.Observe(tcpLoss); u.Started {
			t.Fatalf("hole started too early at genuine loss %d", i+1)
		}
	}
	if u := d.Observe(tcpLoss); !u.Started {
		t.Fatal("genuine losses after refused streak should still open a hole")
	}
}

func TestNoSpikeBeforeWarmup(t *testing.T) {
	th := config.DefaultThresholds()
	th.SpikeWarmup = 5
	d := New(th)

	// A cold-start outlier must not be reported as a hole.
	if u := d.Observe(sample(true, 900)); u.Started {
		t.Fatal("spike fired before the baseline was warmed up")
	}
	for i := 0; i < 4; i++ {
		d.Observe(sample(true, 30))
	}
	// Exactly at the warm-up boundary a normal sample is still not a spike.
	if u := d.Observe(sample(true, 30)); u.Started {
		t.Fatal("normal sample should not start a hole")
	}
	// Once armed, a real outlier fires.
	if u := d.Observe(sample(true, 1000)); !u.Started {
		t.Fatal("expected a spike after warm-up")
	}
}

func TestSustainedSpikeStaysOneEvent(t *testing.T) {
	th := config.DefaultThresholds()
	th.LatencySpikeMs = 200
	th.SpikeFloorMs = 250
	d := New(th)

	for i := 0; i < 5; i++ {
		d.Observe(sample(true, 30))
	}
	u := d.Observe(sample(true, 600))
	if !u.Started {
		t.Fatal("expected spike event to start")
	}
	id := u.Event.ID

	// Still elevated: the event must stay open and keep growing.
	u = d.Observe(sample(true, 650))
	if u.Started || u.Ended {
		t.Fatalf("elevated sample should be a progress update, got started=%v ended=%v", u.Started, u.Ended)
	}
	if u.Event.ID != id || u.Event.Samples != 2 {
		t.Fatalf("progress update = id %d samples %d, want id %d samples 2", u.Event.ID, u.Event.Samples, id)
	}
	u = d.Observe(sample(true, 700))
	if u.Ended || u.Event.Samples != 3 {
		t.Fatalf("second elevated sample: ended=%v samples=%d", u.Ended, u.Event.Samples)
	}

	// Recovery closes exactly one event with the full duration.
	u = d.Observe(sample(true, 32))
	if !u.Ended || u.Event.ID != id {
		t.Fatalf("recovery should end event %d, got ended=%v id=%d", id, u.Ended, u.Event.ID)
	}
	if u.Event.Samples != 4 {
		t.Fatalf("closed event samples = %d, want 4", u.Event.Samples)
	}
	if u.Event.MaxRTTms != 700 {
		t.Fatalf("closed event max = %v, want 700", u.Event.MaxRTTms)
	}
}

func TestLossBurstCoversWholeBurst(t *testing.T) {
	th := config.DefaultThresholds()
	th.LossBurst = 3
	d := New(th)
	start := time.Now()
	for i := 0; i < 3; i++ {
		s := sample(false, 0)
		s.Time = start.Add(time.Duration(i) * time.Second)
		u := d.Observe(s)
		if i < 2 && u.Event.ID != 0 {
			t.Fatal("event started before threshold")
		}
		if i == 2 {
			if !u.Started {
				t.Fatal("expected event to start")
			}
			if !u.Event.Start.Equal(start) {
				t.Fatalf("event start = %v, want first failure %v", u.Event.Start, start)
			}
			if u.Event.LossCount != 3 || u.Event.Samples != 3 {
				t.Fatalf("event loss/samples = %d/%d, want 3/3", u.Event.LossCount, u.Event.Samples)
			}
		}
	}
}
