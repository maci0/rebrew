package jobs

import (
	"crypto/sha256"
	"encoding/hex"
	"os"
	"sync"
)

const outputLimit = 4 * 1024 * 1024

type outputWriter struct {
	mu        sync.Mutex
	owner     *Owner
	id        string
	file      *os.File
	size      int
	truncated bool
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
		if err := w.file.Sync(); err != nil {
			return 0, err
		}
	}
	w.owner.mu.Lock()
	defer w.owner.mu.Unlock()
	r, err := w.owner.read(w.id)
	if err != nil {
		return 0, err
	}
	r.OutputBytes = w.size
	r.OutputTruncated = w.truncated
	if err = w.owner.save(r); err != nil {
		return 0, err
	}
	w.owner.notify(w.id)
	return n, nil
}
func (w *outputWriter) finish() (string, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
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
