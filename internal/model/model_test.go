package model

import (
	"errors"
	"testing"
	"time"
)

func TestKindLabel(t *testing.T) {
	cases := map[Kind]string{
		KindICMP:        "ICMP-Ping",
		KindTCP:         "TCP-SYN",
		KindDNS:         "DNS-Query",
		Kind("carrier"): "carrier", // unknown kinds fall back to their raw value
	}
	for k, want := range cases {
		if got := k.Label(); got != want {
			t.Fatalf("Kind(%q).Label() = %q, want %q", k, got, want)
		}
	}
	if len(AllKinds) != 3 || AllKinds[0] != KindICMP || AllKinds[1] != KindTCP || AllKinds[2] != KindDNS {
		t.Fatalf("AllKinds = %v, want canonical [icmp tcp dns] order", AllKinds)
	}
}

func TestNewSampleSuccess(t *testing.T) {
	s := NewSample(KindTCP, "1.1.1.1:443", 1500*time.Microsecond, nil)
	if !s.OK || s.Err != "" {
		t.Fatalf("successful sample = %+v", s)
	}
	if s.RTTms != 1.5 {
		t.Fatalf("RTTms = %v, want 1.5 (microsecond precision preserved)", s.RTTms)
	}
	if s.Time.IsZero() {
		t.Fatal("sample timestamp not set")
	}
	if s.ConnRefused {
		t.Fatal("successful sample marked conn_refused")
	}
}

func TestNewSampleFailure(t *testing.T) {
	s := NewSample(KindDNS, "1.1.1.1:53", 0, errors.New("timeout"))
	if s.OK {
		t.Fatal("failed sample marked OK")
	}
	if s.Err != "timeout" {
		t.Fatalf("Err = %q, want the probe error text", s.Err)
	}
}

func TestHoleEventDuration(t *testing.T) {
	start := time.Unix(1_700_000_000, 0)
	e := HoleEvent{Start: start, End: start.Add(2500 * time.Millisecond)}
	if got := e.Duration(); got != 2500*time.Millisecond {
		t.Fatalf("Duration = %s, want 2.5s", got)
	}
}
