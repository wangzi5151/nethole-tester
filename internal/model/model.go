// Package model holds the shared, dependency-free data types used across
// NetHole-Tester. Keeping every core type here avoids import cycles between
// the probe, detector, snapshot, storage, analyze and report packages.
package model

import "time"

// Kind identifies an independent probe chain.
type Kind string

const (
	KindICMP Kind = "icmp" // ICMP echo (raw or unprivileged udp4)
	KindTCP  Kind = "tcp"  // TCP SYN handshake to 80/443
	KindDNS  Kind = "dns"  // Recursive DNS query
)

// AllKinds is the canonical ordered list of probe chains.
var AllKinds = []Kind{KindICMP, KindTCP, KindDNS}

// Label returns a human friendly name for terminal / report output.
func (k Kind) Label() string {
	switch k {
	case KindICMP:
		return "ICMP-Ping"
	case KindTCP:
		return "TCP-SYN"
	case KindDNS:
		return "DNS-Query"
	default:
		return string(k)
	}
}

// Sample is a single probe result carrying a high precision timestamp.
// RTT is exported in JSON as rtt_ms (float, millisecond resolution) so the
// file format stays portable and easy to chart from any language.
type Sample struct {
	Time   time.Time     `json:"t"`
	Kind   Kind          `json:"kind"`
	Target string        `json:"target"`
	RTT    time.Duration `json:"-"`
	RTTms  float64       `json:"rtt_ms"`
	OK     bool          `json:"ok"`
	Err    string        `json:"err,omitempty"`
	// ConnRefused marks a TCP dial rejected by the target (ECONNREFUSED):
	// the host is reachable but the port is closed. This is a target
	// configuration problem, not a network hole, so the detector ignores
	// it for loss accounting (see analyze.Hints for the user-facing note).
	ConnRefused bool `json:"conn_refused,omitempty"`
}

// NewSample builds a Sample from an RTT measurement.
func NewSample(kind Kind, target string, rtt time.Duration, err error) Sample {
	s := Sample{
		Time:   time.Now(),
		Kind:   kind,
		Target: target,
		RTT:    rtt,
		RTTms:  float64(rtt.Microseconds()) / 1000.0,
		OK:     err == nil,
	}
	if err != nil {
		s.Err = err.Error()
	}
	return s
}

// Severity ranks how bad a hole event is.
type Severity string

const (
	SevInfo     Severity = "info"
	SevWarn     Severity = "warn"
	SevCritical Severity = "critical"
)

// HoleEvent is a detected "network hole": an interval where the connection was
// up but behaving badly (latency spike, packet loss burst, or TCP blackhole).
//
// RunID scopes the otherwise per-process ID so a log file appended across many
// runs can be de-duplicated unambiguously.
type HoleEvent struct {
	RunID     string    `json:"run,omitempty"`
	ID        int64     `json:"id"`
	Start     time.Time `json:"start"`
	End       time.Time `json:"end"`
	Kind      Kind      `json:"kind"`
	Target    string    `json:"target,omitempty"`
	Reason    string    `json:"reason"`
	Severity  Severity  `json:"severity"`
	Samples   int       `json:"samples"`
	LossCount int       `json:"loss_count"`
	MaxRTTms  float64   `json:"max_rtt_ms"`
	Snapshot  *Snapshot `json:"snapshot,omitempty"`
}

// Duration returns how long the hole lasted.
func (e HoleEvent) Duration() time.Duration { return e.End.Sub(e.Start) }

// Snapshot is the evidence captured automatically the instant a hole is seen.
// Every field is best-effort: tools may be missing on some platforms, in which
// case the field explains why it is empty instead of failing the whole capture.
type Snapshot struct {
	Time       time.Time         `json:"time"`
	Traceroute string            `json:"traceroute,omitempty"`
	DNS        map[string]string `json:"dns,omitempty"`
	ARP        string            `json:"arp,omitempty"`
	Wifi       string            `json:"wifi,omitempty"`
	Notes      []string          `json:"notes,omitempty"`
}
