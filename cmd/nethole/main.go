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
	"flag"
	"fmt"
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

func main() {
	if err := run(os.Args[1:]); err != nil {
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
  nethole version              版本信息

运行示例 Examples:
  nethole run --preset=dorm --duration=10m
  nethole run --preset=pi24x7 --headless --out=/var/log/nethole
  nethole report --in=./nethole-out --complaint

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

	// Read a whole line so EOF / empty input / piped stdin all behave sanely.
	line, _ := bufio.NewReader(os.Stdin).ReadString('\n')
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
		return runCmd(nil)
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

// liveEvent tracks an event that is currently open.
type liveEvent struct {
	ev   model.HoleEvent
	snap chan *model.Snapshot
}

// snapshotWait bounds how long an event writer waits for its evidence snapshot.
const snapshotWait = 6 * time.Second

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
			if !s.OK {
				loss++
			}
			if err := store.WriteSample(s); err != nil {
				fmt.Fprintln(os.Stderr, "warn: write sample:", err)
			}

			upd, has := det.Observe(s)
			frame := ui.Frame{Sample: s, Total: total, LossCount: loss, HoleCount: holes, Elapsed: time.Since(start)}

			if has && upd.Event.ID != 0 {
				frame.Update = upd
				switch {
				case upd.Started:
					holes++
					frame.HoleCount = holes
					frame.Activity = true
					ch := make(chan *model.Snapshot, 1)
					active[upd.Event.ID] = &liveEvent{ev: upd.Event, snap: ch}
					go captureAsync(ctx, cfg, snapSem, ch)
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

func captureAsync(ctx context.Context, cfg config.Config, sem chan struct{}, ch chan *model.Snapshot) {
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
	ch <- snapshot.Capture(sctx, cfg)
}

// finish loads what was logged and writes text/html/csv + a complaint report.
func finish(cfg config.Config) error {
	samples, _ := analyze.LoadSamples(cfg.SamplesOut)
	events, _ := analyze.LoadEvents(cfg.EventsOut)
	a := analyze.Analyze(samples, events)

	fmt.Println()
	report.WriteText(os.Stdout, a)

	htmlPath := filepath.Join(cfg.OutDir, "report.html")
	if f, err := os.Create(htmlPath); err == nil {
		_ = report.WriteHTML(f, a)
		_ = f.Close()
	}
	csvPath := filepath.Join(cfg.OutDir, "samples.csv")
	if f, err := os.Create(csvPath); err == nil {
		_ = analyze.WriteCSV(f, samples)
		_ = f.Close()
	}
	evCsvPath := filepath.Join(cfg.OutDir, "events.csv")
	if f, err := os.Create(evCsvPath); err == nil {
		_ = analyze.WriteEventsCSV(f, events)
		_ = f.Close()
	}
	complaintPath := filepath.Join(cfg.OutDir, "complaint.txt")
	if f, err := os.Create(complaintPath); err == nil {
		report.WriteComplaint(f, a, report.Meta{Location: "", Account: ""})
		_ = f.Close()
	}

	fmt.Println("已生成 / generated:")
	fmt.Println("  HTML 报告 :", htmlPath, " (浏览器打开, 可交互)")
	fmt.Println("  申诉报告 :", complaintPath)
	fmt.Println("  CSV 数据 :", csvPath, ",", evCsvPath)
	fmt.Println("  原始日志 :", cfg.SamplesOut, ",", cfg.EventsOut)
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
	if f, err := os.Create(*outHTML); err == nil {
		_ = report.WriteHTML(f, a)
		_ = f.Close()
		fmt.Println("HTML 报告 written:", *outHTML)
	} else {
		return err
	}

	if *outCSV == "" {
		*outCSV = filepath.Join(*in, "samples.csv")
	}
	if f, err := os.Create(*outCSV); err == nil {
		_ = analyze.WriteCSV(f, samples)
		_ = f.Close()
		fmt.Println("CSV written:", *outCSV)
	}

	if *complaint {
		path := filepath.Join(*in, "complaint.txt")
		f, err := os.Create(path)
		if err != nil {
			return err
		}
		report.WriteComplaint(f, a, report.Meta{
			Operator: *operator, Account: *account, Contact: *contact, Location: *location,
		})
		_ = f.Close()
		fmt.Println("申诉报告 Complaint written:", path)
	}
	return nil
}
