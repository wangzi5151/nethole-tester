package config

import (
	"testing"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/model"
)

func TestPresetKnownNames(t *testing.T) {
	for _, name := range []PresetName{PresetDorm, PresetMobile, PresetPi} {
		cfg, err := Preset(name, "/tmp/out")
		if err != nil {
			t.Fatalf("Preset(%q): %v", name, err)
		}
		if cfg.Name != string(name) {
			t.Fatalf("Preset(%q).Name = %q", name, cfg.Name)
		}
		if err := cfg.Validate(); err != nil {
			t.Fatalf("Preset(%q) does not validate: %v", name, err)
		}
		if len(cfg.ICMPTargets) == 0 || len(cfg.TCPTargets) == 0 || len(cfg.DNSServers) == 0 {
			t.Fatalf("Preset(%q) is missing a probe chain: %+v", name, cfg)
		}
		if cfg.SamplesOut == "" || cfg.EventsOut == "" {
			t.Fatalf("Preset(%q) did not derive log paths from OutDir", name)
		}
	}
}

func TestPresetEmptyNameIsDorm(t *testing.T) {
	cfg, err := Preset("", "/tmp/out")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Name != string(PresetDorm) {
		t.Fatalf("empty preset name = %q, want dorm", cfg.Name)
	}
}

func TestPresetUnknownNameFails(t *testing.T) {
	if _, err := Preset("bogus", "/tmp/out"); err == nil {
		t.Fatal("unknown preset was accepted")
	}
}

func TestPresetPiIsLowCadence(t *testing.T) {
	cfg, err := Preset(PresetPi, "/tmp/out")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Interval < 3*time.Second {
		t.Fatalf("pi24x7 interval = %s, want >= 3s for low footprint", cfg.Interval)
	}
	if cfg.MaxLogMB != 4 || cfg.MaxLogFiles != 8 {
		t.Fatalf("pi24x7 rotation = %dMB x %d files, want 4MB x 8", cfg.MaxLogMB, cfg.MaxLogFiles)
	}
}

func TestSyncAppliesDefaults(t *testing.T) {
	var cfg Config
	cfg.OutDir = "/tmp/out"
	cfg.Sync()
	if cfg.Interval != time.Second || cfg.Timeout != 1200*time.Millisecond {
		t.Fatalf("Sync timing defaults = %s/%s", cfg.Interval, cfg.Timeout)
	}
	if cfg.DNSName == "" || len(cfg.ICMPTargets) == 0 || len(cfg.TCPTargets) == 0 || len(cfg.DNSServers) == 0 {
		t.Fatalf("Sync target defaults missing: %+v", cfg)
	}
	// The millisecond mirror fields must agree with the durations, since the
	// JSON config dump is what users and tooling read.
	if cfg.IntervalMs != cfg.Interval.Milliseconds() || cfg.TimeoutMs != cfg.Timeout.Milliseconds() {
		t.Fatalf("Sync mirrors out of sync: %+v", cfg)
	}
	if cfg.Thresholds.TCPTimeoutMs != cfg.Thresholds.TCPTimeout.Milliseconds() {
		t.Fatalf("threshold mirror out of sync: %+v", cfg.Thresholds)
	}
}

func TestValidateRejectsBadValues(t *testing.T) {
	base, err := Preset(PresetDorm, "/tmp/out")
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]func(*Config){
		"interval too aggressive": func(c *Config) { c.Interval = 100 * time.Millisecond },
		"timeout too large":       func(c *Config) { c.Timeout = 6 * time.Second },
		"negative duration":       func(c *Config) { c.Duration = -time.Minute },
		"zero loss burst":         func(c *Config) { c.Thresholds.LossBurst = 0 },
		"negative loss burst":     func(c *Config) { c.Thresholds.LossBurst = -2 },
		"negative spike":          func(c *Config) { c.Thresholds.LatencySpikeMs = -1 },
		"negative spike floor":    func(c *Config) { c.Thresholds.SpikeFloorMs = -1 },
		"no targets": func(c *Config) {
			c.ICMPTargets, c.TCPTargets, c.DNSServers = nil, nil, nil
		},
	}
	for name, mutate := range cases {
		cfg := base
		mutate(&cfg)
		if err := cfg.Validate(); err == nil {
			t.Fatalf("Validate accepted %s", name)
		}
	}
	if err := base.Validate(); err != nil {
		t.Fatalf("Validate rejected the unmutated preset: %v", err)
	}
}

func TestKindsReflectConfiguredChains(t *testing.T) {
	cfg, err := Preset(PresetDorm, "/tmp/out")
	if err != nil {
		t.Fatal(err)
	}
	kinds := cfg.Kinds()
	if len(kinds) != 3 || kinds[0] != model.KindICMP || kinds[1] != model.KindTCP || kinds[2] != model.KindDNS {
		t.Fatalf("Kinds = %v, want [icmp tcp dns]", kinds)
	}
	cfg.ICMPTargets = nil
	if kinds := cfg.Kinds(); len(kinds) != 2 || kinds[0] != model.KindTCP {
		t.Fatalf("Kinds without ICMP = %v, want [tcp dns]", kinds)
	}
}

func TestDefaultThresholdsAreConservative(t *testing.T) {
	th := DefaultThresholds()
	if th.LossBurst < 2 {
		t.Fatalf("default LossBurst = %d, want >= 2 so one dropped probe is not a hole", th.LossBurst)
	}
	if th.TCPTimeoutMs != th.TCPTimeout.Milliseconds() || th.TCPTimeout <= 0 {
		t.Fatalf("default TCP timeout mirror broken: %+v", th)
	}
}
