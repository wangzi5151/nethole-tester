// Command nethole is the NetHole-Tester entry point: a pure-Go, single-binary
// network quality monitor that catches intermittent, "invisible" outages.
//
// Privacy: this program makes only the probes you configure (ICMP/TCP/DNS) and
// writes results to local files. It contains no telemetry, no analytics, no
// update pings and no hidden callbacks of any kind.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	tea "github.com/charmbracelet/bubbletea"
	"golang.org/x/term"

	"github.com/wangzi5151/nethole-tester/internal/analyze"
	"github.com/wangzi5151/nethole-tester/internal/config"
	"github.com/wangzi5151/nethole-tester/internal/detect"
	"github.com/wangzi5151/nethole-tester/internal/model"
	"github.com/wangzi5151/nethole-tester/internal/probe"
	"github.com/wangzi5151/nethole-tester/internal/report"
	"github.com/wangzi5151/nethole-tester/internal/snapshot"
	"github.com/wangzi5151/nethole-tester/internal/storage"
	"github.com/wangzi5151/nethole-tester/internal/ui"
)

// Build-time metadata, injected with -ldflags by the Makefile.
var (
	version = "dev"
	commit  = "none"
	date    = "unknown"
)

// exitError lets a command request a specific process exit code (used by
// `nethole check` so CI can fail a build without printing an ugly "error:").
type exitError struct {
	code int
	msg  string
}

func (e *exitError) Error() string { return e.msg }

func main() {
	if err := run(os.Args[1:]); err != nil {
		var ee *exitError
		if errors.As(err, &ee) {
			if ee.msg != "" {
				fmt.Fprintln(os.Stderr, ee.msg)
			}
			os.Exit(ee.code)
		}
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	cmd := "quick"
	if len(args) > 0 {
		cmd = args[0]
		args = args[1:]
	}
	switch cmd {
	case "quick":
		return quickMode()
	case "run", "monitor":
		return runCmd(args)
	case "report", "export":
		return reportCmd(args)
	case "check":
		return checkCmd(args)
	case "version", "-v", "--version":
		fmt.Printf("NetHole-Tester %s (commit %s, built %s)\n", version, commit, date)
		return nil
	case "help", "-h", "--help":
		usage()
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", cmd)
	}
}

func usage() {
	fmt.Print(`NetHole-Tester - 抓住那些"网没断但就是卡"的瞬间

用法 Usage:
  nethole                      新手快速模式 (interactive quick start)
  nethole run [flags]          持续监控 (live monitoring)
  nethole report [flags]       从日志生成本地报告 / complaint / html / csv
  nethole check [flags]        检查已有日志并按阈值返回退出码 (CI-friendly)
  nethole version              版本信息

运行示例 Examples:
  nethole run --preset=dorm --duration=10m
  nethole run --preset=pi24x7 --headless --out=/var/log/nethole
  nethole report --in=./nethole-out --complaint
  nethole check --in=./nethole-out --max-loss=1 --max-holes=0 --json

常用参数 (run):
  --preset=dorm|mobile5g|pi24x7   配置预设
  --duration=10m                  运行时长, 0=直到 Ctrl+C
  --interval=1s                   每条链路的探测间隔 (>=200ms)
  --out=./nethole-out             输出目录
  --headless                      无 TUI, 适合后台/服务
  --spike-ms=200                  延迟突跳阈值(ms)
  --loss-burst=3                  连续丢包阈值
  --icmp=1.1.1.1,223.5.5.5        ICMP 目标
  --tcp=1.1.1.1:443,...           TCP 目标
  --dns=1.1.1.1:53,...            DNS 服务器

常用参数 (check):
  --in=./nethole-out              日志目录
  --json                          输出机器可读 JSON 摘要
  --max-loss=1.0                  丢包率超过该百分比则失败 (-1 关闭)
  --max-holes=0                   合并网洞超过该数量则失败 (-1 关闭)
  --min-score=80                  质量评分低于该值则失败 (0 关闭)
  --max-p95=200                   p95 延迟超过该毫秒数则失败 (0 关闭)
`)
}

// ---------------------------------------------------------------------------
// quick mode
// ---------------------------------------------------------------------------

func quickMode() error {
	fmt.Println()
	fmt.Println("  ┌──────────────────────────────────────────────┐")
	fmt.Println("  │        NetHole-Tester  新手快速模式          │")
	fmt.Println("  │   网络“没断但随机卡”? 现在开始抓证据。      │")
	fmt.Println("  └──────────────────────────────────────────────┘")
	fmt.Println()
	fmt.Println("  请选择模式 / choose a mode:")
	fmt.Println("    1) 宿舍宽带模式    (推荐先测 10 分钟)")
	fmt.Println("    2) 手机 4G/5G 模式 (测 5 分钟)")
	fmt.Println("    3) 树莓派 7x24 监控 (后台长测 1 小时)")
	fmt.Println("    0) 自定义参数")
	fmt.Println()
	fmt.Print("  输入数字后回车 (直接回车 = 1): ")

	// Keep one reader so custom-mode prompts continue on the same buffered
	// stream instead of discarding whatever was read ahead.
	in := bufio.NewReader(os.Stdin)

	// Read a whole line so EOF / empty input / piped stdin all behave sanely.
	line, _ := in.ReadString('\n')
	line = strings.TrimSpace(line)
	if line == "" {
		line = "1"
	}

	var (
		preset   config.PresetName
		duration time.Duration
	)
	switch line {
	case "1":
		preset, duration = config.PresetDorm, 10*time.Minute
	case "2":
		preset, duration = config.PresetMobile, 5*time.Minute
	case "3":
		preset, duration = config.PresetPi, time.Hour
	case "0":
		args, err := quickCustom(in, os.Stdout)
		if err != nil {
			return err
		}
		fmt.Println("\n  正在以自定义参数启动... (按 q 可提前停止并生成报告)")
		fmt.Println()
		time.Sleep(700 * time.Millisecond)
		return runCmd(args)
	default:
		return fmt.Errorf("无效选择 %q", line)
	}

	out := "./nethole-out"
	fmt.Printf("\n  即将以 [%s] 模式运行 %s，结果保存到 %s\n", preset, duration, out)
	fmt.Println("  正在启动... (按 q 可提前停止并生成报告)")
	fmt.Println()
	time.Sleep(700 * time.Millisecond)

	args := []string{"--preset=" + string(preset), "--duration=" + duration.String(), "--out=" + out}
	return runCmd(args)
}

// promptQuick prints a prompt and returns the trimmed answer, falling back to
// def when the user just presses enter (or stdin ends).
func promptQuick(r *bufio.Reader, w io.Writer, label, def string) string {
	if def != "" {
		fmt.Fprintf(w, "  %s [回车=%s]: ", label, def)
	} else {
		fmt.Fprintf(w, "  %s: ", label)
	}
	line, _ := r.ReadString('\n')
	if line = strings.TrimSpace(line); line == "" {
		return def
	}
	return line
}

// quickCustom interactively collects the most useful `nethole run` flags.
// Selecting "0) 自定义参数" used to fall straight through to the defaults,
// so this prompts for real values instead.
func quickCustom(r *bufio.Reader, w io.Writer) ([]string, error) {
	fmt.Fprintln(w)
	fmt.Fprintln(w, "  自定义参数 / custom settings (直接回车使用方括号内的默认值)")

	preset := promptQuick(r, w, "预设 preset (dorm|mobile5g|pi24x7)", string(config.PresetDorm))
	switch config.PresetName(preset) {
	case config.PresetDorm, config.PresetMobile, config.PresetPi:
	default:
		return nil, fmt.Errorf("无效预设 %q (可选 dorm|mobile5g|pi24x7)", preset)
	}

	durStr := promptQuick(r, w, "运行时长 duration (如 10m；0 = 直到 Ctrl+C)", "10m")
	duration, err := time.ParseDuration(durStr)
	if err != nil || duration < 0 {
		return nil, fmt.Errorf("无效时长 %q (需 >= 0)", durStr)
	}

	intervalStr := promptQuick(r, w, "探测间隔 interval (如 1s，最小 200ms)", "1s")
	interval, err := time.ParseDuration(intervalStr)
	if err != nil || interval < 200*time.Millisecond {
		return nil, fmt.Errorf("无效间隔 %q (需 >= 200ms)", intervalStr)
	}

	out := promptQuick(r, w, "输出目录 out", "./nethole-out")

	return []string{
		"--preset=" + preset,
		"--duration=" + duration.String(),
		"--interval=" + interval.String(),
		"--out=" + out,
	}, nil
}

// ---------------------------------------------------------------------------
// run command
// ---------------------------------------------------------------------------

func runCmd(args []string) error {
	fs := flag.NewFlagSet("run", flag.ContinueOnError)
	preset := fs.String("preset", "dorm", "preset: dorm|mobile5g|pi24x7")
	duration := fs.Duration("duration", 0, "run duration, 0 = until Ctrl+C")
	interval := fs.Duration("interval", 0, "probe interval override")
	out := fs.String("out", "./nethole-out", "output directory")
	icmpT := fs.String("icmp", "", "comma separated ICMP targets")
	tcpT := fs.String("tcp", "", "comma separated TCP targets")
	dnsS := fs.String("dns", "", "comma separated DNS servers")
	dnsName := fs.String("dns-name", "", "DNS query name")
	spike := fs.Float64("spike-ms", 0, "latency spike threshold in ms")
	lossBurst := fs.Int("loss-burst", 0, "consecutive loss threshold")
	headless := fs.Bool("headless", false, "disable the live TUI")
	noSnap := fs.Bool("no-snapshot", false, "disable evidence snapshots")
	if err := fs.Parse(args); err != nil {
		return err
	}
	// Negative overrides used to be silently ignored (only > 0 values were
	// applied), so `--duration=-5m` quietly ran with the preset duration.
	// Reject them, mirroring quickCustom's input validation.
	if *duration < 0 || *interval < 0 || *spike < 0 || *lossBurst < 0 {
		return fmt.Errorf("negative values are not allowed: --duration=%s --interval=%s --spike-ms=%v --loss-burst=%d",
			*duration, *interval, *spike, *lossBurst)
	}

	cfg, err := config.Preset(config.PresetName(*preset), *out)
	if err != nil {
		return err
	}
	if *duration > 0 {
		cfg.Duration = *duration
	}
	if *interval > 0 {
		cfg.Interval = *interval
	}
	if *icmpT != "" {
		cfg.ICMPTargets = splitList(*icmpT)
	}
	if *tcpT != "" {
		cfg.TCPTargets = splitList(*tcpT)
	}
	if *dnsS != "" {
		cfg.DNSServers = splitList(*dnsS)
	}
	if *dnsName != "" {
		cfg.DNSName = *dnsName
	}
	if *spike > 0 {
		cfg.Thresholds.LatencySpikeMs = *spike
	}
	if *lossBurst > 0 {
		cfg.Thresholds.LossBurst = *lossBurst
	}
	if *noSnap {
		cfg.EnableSnapshot = false
	}
	cfg.Headless = *headless || !term.IsTerminal(int(os.Stdout.Fd()))
	cfg.Sync()
	if err := cfg.Validate(); err != nil {
		return err
	}
	return execute(cfg)
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// execute runs the full monitoring pipeline.
func execute(cfg config.Config) error {
	if err := os.MkdirAll(cfg.OutDir, 0o755); err != nil {
		return err
	}

	runner, err := probe.NewRunner(cfg)
	if err != nil {
		return err
	}
	for _, w := range runner.Warnings() {
		fmt.Fprintln(os.Stderr, "warn:", w)
	}
	store, err := storage.New(cfg.SamplesOut, cfg.EventsOut, cfg.MaxLogMB, cfg.MaxLogFiles)
	if err != nil {
		return err
	}
	det := detect.New(cfg.Thresholds)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if cfg.Duration > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, cfg.Duration)
		defer cancel()
	}

	frames := make(chan ui.Frame, 256)
	start := time.Now()

	runner.Run(ctx)
	engineDone := make(chan struct{})
	go func() {
		defer close(engineDone)
		defer close(frames)
		runEngine(ctx, cfg, runner, store, det, frames, start)
	}()

	var uiErr error
	if cfg.Headless {
		// No TUI consumes frames, so drain (and discard) them. Otherwise the
		// engine blocks on the channel once its buffer fills and probes stall.
		go drainFrames(frames)
		fmt.Printf("NetHole-Tester running headless: preset=%s interval=%s out=%s\n", cfg.Name, cfg.Interval, cfg.OutDir)
		fmt.Println("Press Ctrl+C to stop.")
		<-ctx.Done()
	} else {
		p := tea.NewProgram(ui.New(cfg, frames), tea.WithAltScreen())
		if _, err := p.Run(); err != nil {
			uiErr = err
		}
		stop() // ensure the engine winds down when the user quits
	}

	runner.Close()
	<-engineDone
	_ = store.Close()

	if uiErr != nil {
		return uiErr
	}
	return finish(cfg)
}

// drainFrames discards UI frames until the engine closes the channel. It is
// used in headless mode, where nothing else reads frames.
func drainFrames(frames <-chan ui.Frame) {
	for range frames {
	}
}

// liveEvent tracks an event that is currently open.
type liveEvent struct {
	ev   model.HoleEvent
	snap chan *model.Snapshot
}

// snapshotWait bounds how long an event writer waits for its evidence snapshot.
const snapshotWait = 6 * time.Second

// snapshotCooldown avoids firing three identical traceroutes when all chains
// detect the same outage within a second of each other. The first event of an
// incident keeps the evidence; siblings reuse the incident window.
const snapshotCooldown = 8 * time.Second

// runEngine is the single consumer of the probe stream. It persists every
// sample, feeds the detector, fires evidence snapshots and mirrors status to
// the UI without ever blocking the probers.
//
// Durability: an event is written to disk the moment it starts and then
// checkpointed periodically, so a `kill -9`, power loss or a blackhole that
// lasts until shutdown still leaves a recoverable record.
func runEngine(ctx context.Context, cfg config.Config, runner *probe.Runner, store *storage.Store,
	det *detect.Detector, frames chan<- ui.Frame, start time.Time) {

	runID := start.UTC().Format("20060102T150405")
	var (
		total, loss, holes int
		active             = map[int64]*liveEvent{}
		snapSem            = make(chan struct{}, 2) // limit concurrent traceroutes
		lastSnap           time.Time
		wg                 sync.WaitGroup
		samples            = runner.Samples()
		checkpoint         = time.NewTicker(5 * time.Second)
	)
	defer checkpoint.Stop()

	// persist writes an event after waiting (asynchronously) for its snapshot,
	// so the probe stream is never stalled by a slow traceroute.
	persist := func(ev model.HoleEvent, ch chan *model.Snapshot) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if ch != nil {
				select {
				case ev.Snapshot = <-ch:
				case <-time.After(snapshotWait):
				}
			}
			ev.RunID = runID
			if err := store.WriteEvent(ev); err != nil {
				fmt.Fprintln(os.Stderr, "warn: write event:", err)
			}
		}()
	}

	writeCheckpoints := func() {
		for _, le := range active {
			ev := le.ev
			ev.RunID = runID
			if err := store.WriteEvent(ev); err != nil {
				fmt.Fprintln(os.Stderr, "warn: checkpoint event:", err)
			}
		}
	}

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-checkpoint.C:
			writeCheckpoints()
		case s, ok := <-samples:
			if !ok {
				break loop
			}
			total++
			// Refused connections are a target-config issue, not loss; keep
			// the live counters consistent with the final analysis.
			if !s.OK && !s.ConnRefused {
				loss++
			}
			if err := store.WriteSample(s); err != nil {
				fmt.Fprintln(os.Stderr, "warn: write sample:", err)
			}

			upd := det.Observe(s)
			frame := ui.Frame{Sample: s, Total: total, LossCount: loss, HoleCount: holes, Elapsed: time.Since(start)}

			if upd.Event.ID != 0 {
				frame.Update = upd
				switch {
				case upd.Started:
					holes++
					frame.HoleCount = holes
					frame.Activity = true
					var ch chan *model.Snapshot
					if cfg.EnableSnapshot && time.Since(lastSnap) >= snapshotCooldown {
						ch = make(chan *model.Snapshot, 1)
						lastSnap = time.Now()
						go captureAsync(ctx, cfg, snapSem, ch, upd.Event.Target)
					}
					active[upd.Event.ID] = &liveEvent{ev: upd.Event, snap: ch}
					// Durable from the very first instant.
					ev := upd.Event
					ev.RunID = runID
					if err := store.WriteEvent(ev); err != nil {
						fmt.Fprintln(os.Stderr, "warn: write event:", err)
					}
				case upd.Ended:
					frame.Activity = true
					le := active[upd.Event.ID]
					delete(active, upd.Event.ID)
					ev := upd.Event
					if le != nil {
						persist(ev, le.snap)
					} else {
						persist(ev, nil)
					}
					frame.Update.Event = ev
				default:
					// Progress update: refresh the in-memory record used by
					// checkpoints.
					if le := active[upd.Event.ID]; le != nil {
						le.ev = upd.Event
					}
				}
			}

			if frame.Activity {
				// Never drop a transition, even if the UI is behind.
				select {
				case frames <- frame:
				case <-ctx.Done():
					break loop
				}
			} else {
				select {
				case frames <- frame:
				default: // UI slower than probes: drop the display frame, never the data
				}
			}
		}
	}

	// Persist any event still open at shutdown.
	for _, ev := range det.Flush() {
		if le := active[ev.ID]; le != nil {
			persist(ev, le.snap)
			delete(active, ev.ID)
		} else {
			persist(ev, nil)
		}
	}
	wg.Wait()
}

func captureAsync(ctx context.Context, cfg config.Config, sem chan struct{}, ch chan *model.Snapshot, traceTarget string) {
	if !cfg.EnableSnapshot {
		ch <- nil
		return
	}
	sem <- struct{}{}
	defer func() { <-sem }()
	// Snapshot must keep running even if the main context is cancelled, so it
	// gets its own short-lived background context.
	sctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	ch <- snapshot.Capture(sctx, cfg, traceTarget)
}

// finish loads what was logged and writes text/html/csv + a complaint report.
func finish(cfg config.Config) error {
	samples, err := analyze.LoadSamples(cfg.SamplesOut)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warn: cannot read samples log:", err)
	}
	events, err := analyze.LoadEvents(cfg.EventsOut)
	if err != nil {
		fmt.Fprintln(os.Stderr, "warn: cannot read events log:", err)
	}
	if len(samples) == 0 && len(events) == 0 {
		return fmt.Errorf("no data found under %s (nothing was recorded during this run)", cfg.OutDir)
	}
	a := analyze.Analyze(samples, events)

	fmt.Println()
	report.WriteText(os.Stdout, a)

	htmlPath := filepath.Join(cfg.OutDir, "report.html")
	csvPath := filepath.Join(cfg.OutDir, "samples.csv")
	evCsvPath := filepath.Join(cfg.OutDir, "events.csv")
	complaintPath := filepath.Join(cfg.OutDir, "complaint.txt")

	writes := []struct {
		name string
		path string
		fn   func(io.Writer) error
	}{
		{"HTML 报告", htmlPath, func(w io.Writer) error { return report.WriteHTML(w, a) }},
		{"CSV 数据", csvPath, func(w io.Writer) error { return analyze.WriteCSV(w, samples) }},
		{"CSV 事件", evCsvPath, func(w io.Writer) error { return analyze.WriteEventsCSV(w, events) }},
		{"申诉报告", complaintPath, func(w io.Writer) error {
			report.WriteComplaint(w, a, report.Meta{Location: "", Account: ""})
			return nil
		}},
	}

	var writeErrs []error
	for _, item := range writes {
		if err := writeReportFile(item.path, item.fn); err != nil {
			fmt.Fprintf(os.Stderr, "warn: %s 写入失败 (%s): %v\n", item.name, item.path, err)
			writeErrs = append(writeErrs, err)
		}
	}

	fmt.Println("已生成 / generated:")
	fmt.Println("  HTML 报告 :", htmlPath, " (浏览器打开, 可交互)")
	fmt.Println("  申诉报告 :", complaintPath)
	fmt.Println("  CSV 数据 :", csvPath, ",", evCsvPath)
	fmt.Println("  原始日志 :", cfg.SamplesOut, ",", cfg.EventsOut)
	if len(writeErrs) > 0 {
		return fmt.Errorf("部分报告写入失败 (%d/%d)，请检查 %s 的磁盘空间与写入权限: %w",
			len(writeErrs), len(writes), cfg.OutDir, errors.Join(writeErrs...))
	}
	return nil
}

// writeReportFile creates path, runs fn, and closes the file while preserving
// create/write/close errors so finish can report which report failed and why.
func writeReportFile(path string, fn func(io.Writer) error) error {
	f, err := os.Create(path)
	if err != nil {
		return fmt.Errorf("创建文件失败: %w", err)
	}
	if err := fn(f); err != nil {
		_ = f.Close()
		return fmt.Errorf("写入失败: %w", err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("关闭文件失败: %w", err)
	}
	return nil
}

// ---------------------------------------------------------------------------
// report command
// ---------------------------------------------------------------------------

func reportCmd(args []string) error {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	in := fs.String("in", "./nethole-out", "directory containing samples.jsonl/events.jsonl")
	outHTML := fs.String("html", "", "output html path (default <in>/report.html)")
	outCSV := fs.String("csv", "", "output csv path (default <in>/samples.csv)")
	complaint := fs.Bool("complaint", true, "also write a carrier complaint report")
	operator := fs.String("operator", "", "ISP name for the complaint report")
	account := fs.String("account", "", "broadband account")
	contact := fs.String("contact", "", "contact phone")
	location := fs.String("location", "", "installation address")
	if err := fs.Parse(args); err != nil {
		return err
	}

	samples, err := analyze.LoadSamples(filepath.Join(*in, "samples.jsonl"))
	if err != nil {
		return err
	}
	events, err := analyze.LoadEvents(filepath.Join(*in, "events.jsonl"))
	if err != nil {
		return err
	}
	if len(samples) == 0 {
		return fmt.Errorf("no samples found under %s (run 'nethole run' first)", *in)
	}
	a := analyze.Analyze(samples, events)

	report.WriteText(os.Stdout, a)

	if *outHTML == "" {
		*outHTML = filepath.Join(*in, "report.html")
	}
	// Use the same writeReportFile helper as finish(): create/write/close
	// errors must be reported, not swallowed. Previously a failed CSV or
	// complaint write (full disk, read-only directory) exited 0 silently.
	if err := writeReportFile(*outHTML, func(w io.Writer) error { return report.WriteHTML(w, a) }); err != nil {
		return fmt.Errorf("HTML 报告 写入失败 (%s): %w", *outHTML, err)
	}
	fmt.Println("HTML 报告 written:", *outHTML)

	if *outCSV == "" {
		*outCSV = filepath.Join(*in, "samples.csv")
	}
	if err := writeReportFile(*outCSV, func(w io.Writer) error { return analyze.WriteCSV(w, samples) }); err != nil {
		return fmt.Errorf("CSV 写入失败 (%s): %w", *outCSV, err)
	}
	fmt.Println("CSV written:", *outCSV)

	if *complaint {
		path := filepath.Join(*in, "complaint.txt")
		err := writeReportFile(path, func(w io.Writer) error {
			report.WriteComplaint(w, a, report.Meta{
				Operator: *operator, Account: *account, Contact: *contact, Location: *location,
			})
			return nil
		})
		if err != nil {
			return fmt.Errorf("申诉报告 写入失败 (%s): %w", path, err)
		}
		fmt.Println("申诉报告 Complaint written:", path)
	}
	return nil
}

// ---------------------------------------------------------------------------
// check command
// ---------------------------------------------------------------------------

// checkReport is the JSON envelope emitted by `nethole check --json`.
type checkReport struct {
	report.Summary
	Pass     bool     `json:"pass"`
	Failures []string `json:"failures,omitempty"`
}

// checkCmd reads an existing run and evaluates optional thresholds. It exits 0
// when every configured threshold is met and 1 otherwise, which makes it easy
// to wire into CI or a cron job. With no thresholds it acts as an inspector.
func checkCmd(args []string) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	in := fs.String("in", "./nethole-out", "directory containing samples.jsonl/events.jsonl")
	asJSON := fs.Bool("json", false, "print a machine-readable JSON summary")
	maxLoss := fs.Float64("max-loss", -1, "fail when overall loss percent is greater than this (-1 disables)")
	maxHoles := fs.Int("max-holes", -1, "fail when merged incidents exceed this count (-1 disables)")
	minScore := fs.Int("min-score", 0, "fail when quality score is below this (0 disables)")
	maxP95 := fs.Float64("max-p95", 0, "fail when overall p95 latency (ms) is greater than this (0 disables)")
	if err := fs.Parse(args); err != nil {
		return err
	}

	samples, err := analyze.LoadSamples(filepath.Join(*in, "samples.jsonl"))
	if err != nil {
		return err
	}
	events, err := analyze.LoadEvents(filepath.Join(*in, "events.jsonl"))
	if err != nil {
		return err
	}
	if len(samples) == 0 && len(events) == 0 {
		return fmt.Errorf("no data found under %s (run 'nethole run' first)", *in)
	}
	a := analyze.Analyze(samples, events)

	failures := evaluateCheck(a, *maxLoss, *maxHoles, *minScore, *maxP95)

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(checkReport{
			Summary:  report.BuildSummary(a),
			Pass:     len(failures) == 0,
			Failures: failures,
		}); err != nil {
			return err
		}
	} else {
		fmt.Printf("NetHole check: %s  samples=%d  loss=%.3f%%  availability=%.3f%%\n",
			a.Duration.Round(time.Second), a.TotalSamples, a.LossPct, a.AvailabilityPct)
		if a.Grade != "n/a" {
			fmt.Printf("quality=%d/100 (%s)  p95=%.1fms  jitter=%.1fms\n", a.QualityScore, a.Grade, a.P95Ms, a.JitterMs)
		} else {
			fmt.Println("quality=n/a (no successful samples)")
		}
		fmt.Printf("incidents=%d  raw_events=%d  hole_time=%s\n", len(a.Incidents), len(a.Events), a.HoleDuration.Round(time.Second))
	}

	if len(failures) > 0 {
		return &exitError{code: 1, msg: "check failed: " + strings.Join(failures, "; ")}
	}
	if !*asJSON {
		fmt.Println("PASS")
	}
	return nil
}

// evaluateCheck applies the optional check thresholds and returns one human
// readable message per violated threshold. Negative maxLoss/maxHoles and zero
// minScore/maxP95 disable that particular check.
func evaluateCheck(a *analyze.Analysis, maxLoss float64, maxHoles, minScore int, maxP95 float64) []string {
	var failures []string
	if maxLoss >= 0 && a.LossPct > maxLoss {
		failures = append(failures, fmt.Sprintf("loss %.3f%% > max-loss %.3f%%", a.LossPct, maxLoss))
	}
	if maxHoles >= 0 && len(a.Incidents) > maxHoles {
		failures = append(failures, fmt.Sprintf("incidents %d > max-holes %d", len(a.Incidents), maxHoles))
	}
	if minScore > 0 && a.QualityScore < minScore {
		failures = append(failures, fmt.Sprintf("quality %d < min-score %d", a.QualityScore, minScore))
	}
	if maxP95 > 0 && a.P95Ms > maxP95 {
		failures = append(failures, fmt.Sprintf("p95 %.1fms > max-p95 %.1fms", a.P95Ms, maxP95))
	}
	return failures
}
