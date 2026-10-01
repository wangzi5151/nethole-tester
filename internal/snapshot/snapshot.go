// Package snapshot captures the "evidence" recorded the instant a hole event
// starts: traceroute, DNS answers, the ARP table and Wi-Fi signal strength.
// Every collector is best-effort and cross-platform; a missing tool never
// aborts the capture, it simply records a note explaining the gap.
package snapshot

import (
	"context"
	"sync"
	"time"

	"github.com/wangzi5151/nethole-tester/internal/config"
	"github.com/wangzi5151/nethole-tester/internal/model"
)

// Capture gathers all evidence concurrently and returns a Snapshot. It always
// returns a non-nil result, even on total failure.
func Capture(ctx context.Context, cfg config.Config) *model.Snapshot {
	s := &model.Snapshot{
		Time: time.Now(),
		DNS:  map[string]string{},
	}

	var (
		wg    sync.WaitGroup
		mu    sync.Mutex
		notes []string
	)
	addNote := func(n string) {
		mu.Lock()
		notes = append(notes, n)
		mu.Unlock()
	}

	wg.Add(4)
	go func() { // traceroute
		defer wg.Done()
		if txt, note := traceroute(ctx, cfg); txt != "" {
			mu.Lock()
			s.Traceroute = txt
			mu.Unlock()
			if note != "" {
				addNote(note)
			}
		} else if note != "" {
			addNote(note)
		}
	}()
	go func() { // dns
		defer wg.Done()
		answers := dnsCheck(ctx, cfg)
		mu.Lock()
		for k, v := range answers {
			s.DNS[k] = v
		}
		mu.Unlock()
	}()
	go func() { // arp
		defer wg.Done()
		if txt, note := arpTable(); txt != "" {
			mu.Lock()
			s.ARP = txt
			mu.Unlock()
			if note != "" {
				addNote(note)
			}
		} else if note != "" {
			addNote(note)
		}
	}()
	go func() { // wifi
		defer wg.Done()
		if txt, note := wifiInfo(ctx); txt != "" {
			mu.Lock()
			s.Wifi = txt
			mu.Unlock()
			if note != "" {
				addNote(note)
			}
		} else if note != "" {
			addNote(note)
		}
	}()

	wg.Wait()
	mu.Lock()
	s.Notes = notes
	mu.Unlock()
	return s
}
