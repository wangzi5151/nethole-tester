// Package config defines runtime configuration, thresholds and the three
// built-in presets (dorm broadband, mobile 4G/5G, Raspberry Pi 24x7).
package config

import (
	"fmt"
	"path/filepath"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/model"
)

// Thresholds control when an interval of bad connectivity is promoted to a
// HoleEvent (a "network hole").
type Thresholds struct {
	// LatencySpikeMs marks a latency sample as anomalous if it exceeds the
	// rolling baseline by this many milliseconds (and is at least SpikeFloorMs).
	LatencySpikeMs float64 `json:"latency_spike_ms"`
	SpikeFloorMs   float64 `json:"spike_floor_ms"`
	// LossBurst is the number of consecutive failed probes required to fire a
	// loss event.
	LossBurst int `json:"loss_burst"`
	// TCPTimeout is when a TCP handshake is considered a blackhole.
	TCPTimeout   time.Duration `json:"-"`
	TCPTimeoutMs int64         `json:"tcp_timeout_ms"`
	// BaselineWindow is the number of recent successful samples used to compute
	// the rolling latency baseline per chain.
	BaselineWindow int `json:"baseline_window"`
}

// DefaultThresholds returns the conservative defaults shipped to users.
func DefaultThresholds() Thresholds {
	t := Thresholds{
		LatencySpikeMs: 200,
		SpikeFloorMs:   250,
		LossBurst:      3,
		TCPTimeout:     2 * time.Second,
		BaselineWindow: 20,
	}
	t.sync()
	return t
}

func (t *Thresholds) sync() { t.TCPTimeoutMs = t.TCPTimeout.Milliseconds() }

// Config is the full runtime configuration for one monitoring run.
type Config struct {
	Name       string        `json:"name"`
	Interval   time.Duration `json:"-"`
	IntervalMs int64         `json:"interval_ms"`
	Duration   time.Duration `json:"-"`
	DurationS  int64         `json:"duration_s"`
	Timeout    time.Duration `json:"-"`
	TimeoutMs  int64         `json:"timeout_ms"`

	ICMPTargets []string `json:"icmp_targets"`
	TCPTargets  []string `json:"tcp_targets"`
	DNSServers  []string `json:"dns_servers"`
	DNSName     string   `json:"dns_name"`

	Thresholds Thresholds `json:"thresholds"`

	OutDir      string `json:"out_dir"`
	MaxLogMB    int    `json:"max_log_mb"`
	MaxLogFiles int    `json:"max_log_files"`

	EnableSnapshot bool `json:"enable_snapshot"`
	Headless       bool `json:"headless"`
	NoColor        bool `json:"no_color"`

	SamplesOut string `json:"samples_out,omitempty"`
	EventsOut  string `json:"events_out,omitempty"`
}

// Sync recomputes the millisecond mirror fields and applies sane defaults.
func (c *Config) Sync() {
	if c.Interval <= 0 {
		c.Interval = time.Second
	}
	if c.Timeout <= 0 {
		c.Timeout = 1200 * time.Millisecond
	}
	if c.Thresholds.TCPTimeout <= 0 {
		c.Thresholds.TCPTimeout = 2 * time.Second
	}
	if c.Thresholds.BaselineWindow <= 0 {
		c.Thresholds.BaselineWindow = 20
	}
	if c.MaxLogMB <= 0 {
		c.MaxLogMB = 8
	}
	if c.MaxLogFiles <= 0 {
		c.MaxLogFiles = 5
	}
	if c.DNSName == "" {
		c.DNSName = "www.example.com"
	}
	if len(c.ICMPTargets) == 0 {
		c.ICMPTargets = []string{"1.1.1.1"}
	}
	if len(c.TCPTargets) == 0 {
		c.TCPTargets = []string{"1.1.1.1:443", "www.google.com:443"}
	}
	if len(c.DNSServers) == 0 {
		c.DNSServers = []string{"1.1.1.1:53", "8.8.8.8:53"}
	}
	c.IntervalMs = c.Interval.Milliseconds()
	c.DurationS = int64(c.Duration.Seconds())
	c.TimeoutMs = c.Timeout.Milliseconds()
	c.Thresholds.sync()
	if c.SamplesOut == "" && c.OutDir != "" {
		c.SamplesOut = filepath.Join(c.OutDir, "samples.jsonl")
	}
	if c.EventsOut == "" && c.OutDir != "" {
		c.EventsOut = filepath.Join(c.OutDir, "events.jsonl")
	}
}

// PresetName identifies a built-in profile.
type PresetName string

const (
	PresetDorm   PresetName = "dorm"     // 宿舍宽带模式
	PresetMobile PresetName = "mobile5g" // 手机 4G/5G 移动网络模式
	PresetPi     PresetName = "pi24x7"   // 树莓派 7x24 监控模式
)

// Preset returns a fully populated Config for a named profile.
func Preset(name PresetName, outDir string) (Config, error) {
	c := Config{
		Name:           string(name),
		OutDir:         outDir,
		EnableSnapshot: true,
		Thresholds:     DefaultThresholds(),
	}
	switch name {
	case PresetDorm, "":
		// Dorm broadband: shared uplink, buffer-bloat prone. Probe often enough
		// to catch 1-3s stalls but keep the load trivial.
		c.Name = string(PresetDorm)
		c.Interval = time.Second
		c.Timeout = 1500 * time.Millisecond
		c.ICMPTargets = []string{"223.5.5.5", "1.1.1.1"}
		c.TCPTargets = []string{"www.baidu.com:443", "1.1.1.1:443"}
		c.DNSServers = []string{"223.5.5.5:53", "119.29.29.29:53"}
		c.DNSName = "www.bilibili.com"
		c.Thresholds.LatencySpikeMs = 200
		c.Thresholds.LossBurst = 3
	case PresetMobile:
		// Mobile networks are jittery by nature; tolerate more latency but still
		// flag hard stalls and TCP blackholes.
		c.Name = string(PresetMobile)
		c.Interval = time.Second
		c.Timeout = 2 * time.Second
		c.ICMPTargets = []string{"1.1.1.1", "8.8.8.8"}
		c.TCPTargets = []string{"1.1.1.1:443", "www.cloudflare.com:443"}
		c.DNSServers = []string{"1.1.1.1:53", "8.8.8.8:53"}
		c.DNSName = "www.example.com"
		c.Thresholds.LatencySpikeMs = 350
		c.Thresholds.SpikeFloorMs = 400
		c.Thresholds.LossBurst = 4
	case PresetPi:
		// Raspberry Pi 24x7: slow cadence, tiny footprint, aggressive rotation.
		c.Name = string(PresetPi)
		c.Interval = 3 * time.Second
		c.Duration = 24 * time.Hour
		c.Timeout = 2 * time.Second
		c.ICMPTargets = []string{"1.1.1.1"}
		c.TCPTargets = []string{"1.1.1.1:443", "8.8.8.8:443"}
		c.DNSServers = []string{"1.1.1.1:53"}
		c.DNSName = "www.example.com"
		c.MaxLogMB = 4
		c.MaxLogFiles = 8
		c.Thresholds.LossBurst = 3
	default:
		return c, fmt.Errorf("unknown preset %q (want dorm|mobile5g|pi24x7)", name)
	}
	c.Sync()
	return c, nil
}

// Validate performs light sanity checks before a run starts.
func (c *Config) Validate() error {
	if c.Interval < 200*time.Millisecond {
		return fmt.Errorf("interval %s is too aggressive; minimum 200ms to avoid flooding", c.Interval)
	}
	if c.Timeout > 5*time.Second {
		return fmt.Errorf("timeout %s is too large; maximum 5s", c.Timeout)
	}
	if len(c.ICMPTargets)+len(c.TCPTargets)+len(c.DNSServers) == 0 {
		return fmt.Errorf("no probe targets configured")
	}
	return nil
}

// Kinds returns the set of probe chains implied by this configuration.
func (c *Config) Kinds() []model.Kind {
	var k []model.Kind
	if len(c.ICMPTargets) > 0 {
		k = append(k, model.KindICMP)
	}
	if len(c.TCPTargets) > 0 {
		k = append(k, model.KindTCP)
	}
	if len(c.DNSServers) > 0 {
		k = append(k, model.KindDNS)
	}
	return k
}
