package jobs

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sync"
	"time"
)

const outputLimit = 4 * 1024 * 1024

// maxEventListeners caps concurrent /events SSE streams per job. Each stream
// holds a goroutine and a buffered channel for its lifetime; without a cap a
// client opening many streams drains goroutines unboundedly (one job only,
// but a single host can still exhaust the process).
const maxEventListeners = 64

// outputSaveInterval bounds how often a running job's receipt is rewritten.
// A chatty child delivers many pipe chunks, and each receipt write is a temp
// file plus two directory/file syncs; doing that per chunk stalls the child on
// disk. The output file itself is written per chunk and readable through the
// page cache, and finish persists the final counters.
const outputSaveInterval = 250 * time.Millisecond

type outputWriter struct {
	mu        sync.Mutex
	owner     *Owner
	id        string
	file      *os.File
	size      int
	truncated bool
	lastSave  time.Time
	// saveInterval overrides outputSaveInterval when positive.
	saveInterval time.Duration
}

func (w *outputWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n := len(p)
	keep := n
	if keep > outputLimit-w.size {
		keep = outputLimit - w.size
		w.truncated = true
	}
	if keep > 0 {
		if _, err := w.file.Write(p[:keep]); err != nil {
			return 0, err
		}
		w.size += keep
	}
	interval := w.saveInterval
	if interval <= 0 {
		interval = outputSaveInterval
	}
	if now := time.Now(); now.Sub(w.lastSave) >= interval {
		if err := w.persistLocked(); err != nil {
			return 0, err
		}
		w.lastSave = now
	}
	return n, nil
}

// persistLocked rewrites the receipt's output counters. Callers hold w.mu.
func (w *outputWriter) persistLocked() error {
	w.owner.mu.Lock()
	defer w.owner.mu.Unlock()
	r, err := w.owner.read(w.id)
	if err != nil {
		return err
	}
	if r.OutputBytes == w.size && r.OutputTruncated == w.truncated {
		return nil
	}
	r.OutputBytes = w.size
	r.OutputTruncated = w.truncated
	if err = w.owner.save(r); err != nil {
		return err
	}
	// An event is a state change; notify once the receipt carries the new
	// counters instead of waking every watcher for each pipe chunk.
	w.owner.notify(w.id)
	return nil
}

func (w *outputWriter) finish() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if err := w.persistLocked(); err != nil {
		_ = w.file.Close()
		return "", err
	}
	if err := w.file.Sync(); err != nil {
		_ = w.file.Close()
		return "", err
	}
	if err := w.file.Close(); err != nil {
		return "", err
	}
	b, err := os.ReadFile(w.file.Name())
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}
