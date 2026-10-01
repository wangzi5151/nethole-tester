// Package storage persists samples and events as newline-delimited JSON
// (JSONL) with size-based rotation, so a Raspberry Pi can run for days without
// filling its SD card.
package storage

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"

	"github.com/wangzi5151/nethole-tester/internal/model"
)

// Rotator is an append-only, size-rotated log file.
type Rotator struct {
	mu       sync.Mutex
	path     string
	maxBytes int64
	maxFiles int
	file     *os.File
	w        *bufio.Writer
	size     int64
	lines    int64
}

// NewRotator opens (creating parent dirs) a rotating writer.
func NewRotator(path string, maxMB, maxFiles int) (*Rotator, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	r := &Rotator{
		path:     path,
		maxBytes: int64(maxMB) * 1024 * 1024,
		maxFiles: maxFiles,
	}
	if err := r.open(); err != nil {
		return nil, err
	}
	return r, nil
}

func (r *Rotator) open() error {
	f, err := os.OpenFile(r.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	info, _ := f.Stat()
	r.file = f
	r.w = bufio.NewWriterSize(f, 16*1024)
	if info != nil {
		r.size = info.Size()
	}
	return nil
}

// WriteLine appends one line and flushes it immediately (durability matters
// more than a syscall at these low probe rates).
func (r *Rotator) WriteLine(b []byte) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.size >= r.maxBytes {
		if err := r.rotate(); err != nil {
			return err
		}
	}
	n, err := r.w.Write(b)
	if err != nil {
		return err
	}
	if err := r.w.WriteByte('\n'); err != nil {
		return err
	}
	if err := r.w.Flush(); err != nil {
		return err
	}
	r.size += int64(n) + 1
	r.lines++
	return nil
}

// rotate drops the oldest file, shifts path.(i) -> path.(i+1), then moves the
// active file to path.1. The oldest must be removed BEFORE shifting, otherwise
// the shift would overwrite it with a file we want to keep.
func (r *Rotator) rotate() error {
	_ = r.w.Flush()
	_ = r.file.Close()

	_ = os.Remove(fmt.Sprintf("%s.%d", r.path, r.maxFiles))
	for i := r.maxFiles - 1; i >= 1; i-- {
		src := fmt.Sprintf("%s.%d", r.path, i)
		dst := fmt.Sprintf("%s.%d", r.path, i+1)
		_ = os.Rename(src, dst)
	}
	if err := os.Rename(r.path, r.path+".1"); err != nil && !os.IsNotExist(err) {
		return err
	}
	return r.open()
}

// Close flushes and closes the file.
func (r *Rotator) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.w != nil {
		_ = r.w.Flush()
	}
	if r.file != nil {
		return r.file.Close()
	}
	return nil
}

// Store persists samples and events.
type Store struct {
	Samples *Rotator
	Events  *Rotator
}

// New opens both logs described by the configuration paths.
func New(samplesOut, eventsOut string, maxMB, maxFiles int) (*Store, error) {
	s, err := NewRotator(samplesOut, maxMB, maxFiles)
	if err != nil {
		return nil, err
	}
	e, err := NewRotator(eventsOut, maxMB, maxFiles)
	if err != nil {
		_ = s.Close()
		return nil, err
	}
	return &Store{Samples: s, Events: e}, nil
}

// WriteSample appends a sample.
func (st *Store) WriteSample(s model.Sample) error {
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	return st.Samples.WriteLine(b)
}

// WriteEvent appends a completed hole event.
func (st *Store) WriteEvent(e model.HoleEvent) error {
	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	return st.Events.WriteLine(b)
}

// Close closes both logs.
func (st *Store) Close() error {
	err1 := st.Samples.Close()
	err2 := st.Events.Close()
	if err1 != nil {
		return err1
	}
	return err2
}
