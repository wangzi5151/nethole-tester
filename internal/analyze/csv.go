package analyze

import (
	"bufio"
	"fmt"
	"io"
	"strings"

	"github.com/wangzi5151/nethole-tester/internal/model"
)

// WriteCSV writes a UTF-8-BOM CSV that opens cleanly in Microsoft Excel and
// LibreOffice. Columns: timestamp, kind, target, ok, rtt_ms, error.
func WriteCSV(w io.Writer, samples []model.Sample) error {
	bw := bufio.NewWriter(w)
	if _, err := bw.WriteString("\ufeff"); err != nil {
		return err
	}
	if _, err := bw.WriteString("timestamp,kind,target,ok,rtt_ms,error\n"); err != nil {
		return err
	}
	for _, s := range samples {
		line := fmt.Sprintf("%s,%s,%s,%t,%.3f,%s\n",
			s.Time.Format("2006-01-02 15:04:05.000"),
			s.Kind, csvField(s.Target), s.OK, s.RTTms, csvField(s.Err))
		if _, err := bw.WriteString(line); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// WriteEventsCSV writes hole events for spreadsheet analysis.
func WriteEventsCSV(w io.Writer, events []model.HoleEvent) error {
	bw := bufio.NewWriter(w)
	if _, err := bw.WriteString("\ufeff"); err != nil {
		return err
	}
	if _, err := bw.WriteString("id,start,end,duration_s,kind,severity,loss_count,max_rtt_ms,reason\n"); err != nil {
		return err
	}
	for _, e := range events {
		line := fmt.Sprintf("%d,%s,%s,%.3f,%s,%s,%d,%.1f,%s\n",
			e.ID,
			e.Start.Format("2006-01-02 15:04:05.000"),
			e.End.Format("2006-01-02 15:04:05.000"),
			e.Duration().Seconds(),
			e.Kind, e.Severity, e.LossCount, e.MaxRTTms, csvField(e.Reason))
		if _, err := bw.WriteString(line); err != nil {
			return err
		}
	}
	return bw.Flush()
}

// csvField quotes a field when it contains characters that would break CSV.
func csvField(s string) string {
	if s == "" {
		return s
	}
	if strings.ContainsAny(s, ",\"\n\r") {
		return "\"" + strings.ReplaceAll(s, "\"", "\"\"") + "\""
	}
	return s
}
