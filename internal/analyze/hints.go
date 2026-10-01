package analyze

import (
	"fmt"
	"math"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/model"
)

// Hints derives correlation clues from the analysis. These are deliberately
// phrased as possibilities, never as definitive diagnoses.
func Hints(a *Analysis) []string {
	var hints []string
	icmp := a.Kinds[model.KindICMP]
	tcp := a.Kinds[model.KindTCP]
	dns := a.Kinds[model.KindDNS]

	// 1. ICMP looks bad but everything else is fine -> ICMP is often
	// deprioritised by carriers and routers, not a real outage.
	if icmp != nil && icmp.LossPct > 10 && tcp != nil && tcp.LossPct < 2 {
		hints = append(hints, "ICMP 丢包明显但 TCP 正常：很可能是运营商/路由器对 ICMP 做了限速，并非真实断网 (ICMP is likely rate-limited, not a real outage).")
	}

	// 2. TCP handshakes failing while ping is healthy -> possible TCP
	// blackhole, carrier NAT or an overloaded port/stateful firewall.
	if tcp != nil && tcp.LossPct > 5 && icmp != nil && icmp.LossPct < 2 {
		hints = append(hints, "TCP 握手失败但 ping 正常：疑似 TCP 黑洞 / 运营商 NAT 表项耗尽 / 端口被限 (possible TCP blackhole or NAT exhaustion).")
	}

	// 3. DNS losing more than ICMP -> resolver or upstream DNS problem,
	// occasionally a sign of DNS hijacking / packet theft.
	if dns != nil && icmp != nil && dns.LossPct > icmp.LossPct+5 && dns.LossPct > 5 {
		hints = append(hints, "DNS 丢包高于其他链路：优先怀疑 DNS 服务器或上游解析异常，也可能是 DNS 被劫持/偷包 (DNS-specific loss; possible resolver hijack).")
	}

	// 4. High jitter with little loss -> typical Wi-Fi interference or a busy
	// shared channel.
	for _, ks := range a.Kinds {
		if ks.AvgMs > 0 && ks.JitterMs > ks.AvgMs*0.8 && ks.LossPct < 5 {
			hints = append(hints, fmt.Sprintf("%s 抖动(jitter)远大于均值但丢包少：符合 Wi-Fi 信道干扰/共享信道拥塞特征 (high jitter, low loss: Wi-Fi interference?).", ks.Kind.Label()))
			break
		}
	}

	// 5. Latency drifting upward across the run -> overheating fibre modem,
	// thermal throttling or growing buffer occupancy.
	for _, ks := range a.Kinds {
		if ks.AvgMs > 30 && ks.P99Ms > ks.AvgMs*3 {
			hints = append(hints, fmt.Sprintf("%s 尾部延迟(p99)极高：可能是缓冲区膨胀(bufferbloat)或设备过热降速 (possible bufferbloat / thermal throttling).", ks.Kind.Label()))
			break
		}
	}

	// 6. Periodicity of hole events -> roaming, DHCP renew, or a neighbour's
	// scheduled downloads.
	if iv, ok := periodicInterval(a.Events); ok {
		hints = append(hints, fmt.Sprintf("网洞事件大约每 %s 出现一次，具有周期性：留意 Wi-Fi 漫游、DHCP 续租或同宿舍定时下载 (periodic pattern: roaming / DHCP renew / scheduled downloads).", iv.Round(time.Second)))
	}

	// 7. TCP targets refusing connections -> the host is reachable but the
	// port is closed. This is a target configuration problem, not a network
	// outage (the detector already excludes these from hole accounting).
	var refused []string
	for _, s := range a.Samples {
		if s.Kind == model.KindTCP && s.ConnRefused && !contains(refused, s.Target) {
			refused = append(refused, s.Target)
		}
	}
	for _, t := range refused {
		hints = append(hints, fmt.Sprintf("TCP %s 连接被拒绝 (connection refused)：目标主机可达但端口未开放，请检查目标配置；这不是网络丢包，不计入网洞统计 (port closed on target, not a network hole).", t))
	}

	if len(hints) == 0 {
		hints = append(hints, "未发现明显相关性线索；若您确有卡顿体感，可延长监控时长并保留报告 (no strong correlation found; try a longer run).")
	}
	return hints
}

// periodicInterval looks for a dominant, consistent gap between hole events.
func periodicInterval(events []model.HoleEvent) (time.Duration, bool) {
	if len(events) < 3 {
		return 0, false
	}
	starts := make([]time.Time, 0, len(events))
	for _, e := range events {
		starts = append(starts, e.Start)
	}
	// events are appended in start order in practice; sort defensively.
	for i := 1; i < len(starts); i++ {
		for j := i; j > 0 && starts[j].Before(starts[j-1]); j-- {
			starts[j], starts[j-1] = starts[j-1], starts[j]
		}
	}
	var gaps []float64
	for i := 1; i < len(starts); i++ {
		gaps = append(gaps, starts[i].Sub(starts[i-1]).Seconds())
	}
	if len(gaps) < 2 {
		return 0, false
	}
	mean := 0.0
	for _, g := range gaps {
		mean += g
	}
	mean /= float64(len(gaps))
	if mean < 30 {
		return 0, false
	}
	// Consistent means most gaps fall within +/-25% of the mean.
	near := 0
	for _, g := range gaps {
		if math.Abs(g-mean)/mean < 0.25 {
			near++
		}
	}
	if near >= len(gaps)*2/3 {
		return time.Duration(mean) * time.Second, true
	}
	return 0, false
}
