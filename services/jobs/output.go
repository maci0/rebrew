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
	n := len(p)
	keep := n
	if keep > outputLimit-w.size {
		keep = outputLimit - w.size
		w.truncated = true
	}
	if keep > 0 {
		if _, err := w.file.Write(p[:keep]); err != nil {
			w.mu.Unlock()
			return 0, err
		}
		w.size += keep
	}
	size, truncated := w.size, w.truncated
	interval := w.saveInterval
	if interval <= 0 {
		interval = outputSaveInterval
	}
	now := time.Now()
	due := now.Sub(w.lastSave) >= interval
	if due {
		w.lastSave = now
	}
	w.mu.Unlock()
	if due {
		if err := w.persist(size, truncated); err != nil {
			return 0, err
		}
	}
	return n, nil
}

// persist rewrites the receipt's output counters.  writeJSONAtomic's rename
// is the atomic commit point; a concurrent field update (e.g. CancelRequested
// set under o.mu) can be clobbered if it lands between the read and the
// rename, so the owner lock is still held here to serialize against those
// writers.  The writer lock is never held across it, so lock order stays
// o.mu -> (no w.mu), matching admit/Cancel/ReconcileDocker.
// Counters are monotonic, so a stale persist writes a smaller size only.
// Callers must not hold w.mu.
func (w *outputWriter) persist(size int, truncated bool) error {
	w.owner.mu.Lock()
	defer w.owner.mu.Unlock()
	r, err := w.owner.read(w.id)
	if err != nil {
		return err
	}
	if r.OutputBytes >= size && r.OutputTruncated == truncated {
		return nil
	}
	r.OutputBytes = size
	r.OutputTruncated = truncated
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
	size, truncated := w.size, w.truncated
	w.mu.Unlock()
	if err := w.persist(size, truncated); err != nil {
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
