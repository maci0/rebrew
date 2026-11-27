package jobs

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestOutputRetainsBoundAndReportsTruncation(t *testing.T) {
	owner, err := Open(t.TempDir(), testJobDir(t), "/bin/false")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	id := strings.Repeat("a", 64)
	if err = owner.save(Receipt{ID: id, State: "running"}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(owner.dir, id+".output"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	w := &outputWriter{owner: owner, id: id, file: f}
	payload := bytes.Repeat([]byte("x"), outputLimit+10)
	if n, err := w.Write(payload); err != nil || n != len(payload) {
		t.Fatal("bounded write failed")
	}
	digest, err := w.finish()
	if err != nil {
		t.Fatal("output digest unavailable")
	}
	sum := sha256.Sum256(payload[:outputLimit])
	if want := hex.EncodeToString(sum[:]); digest != want {
		t.Fatalf("output digest = %s, want %s", digest, want)
	}
	r, err := owner.Get(id)
	if err != nil || r.OutputBytes != outputLimit || !r.OutputTruncated {
		t.Fatal("truncation not retained")
	}
}

func TestOutputCoalescesReceiptWrites(t *testing.T) {
	owner, err := Open(t.TempDir(), testJobDir(t), "/bin/false")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	id := strings.Repeat("b", 64)
	if err = owner.save(Receipt{ID: id, State: "running"}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(owner.dir, id+".output"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	w := &outputWriter{owner: owner, id: id, file: f, saveInterval: time.Hour}
	if _, err = w.Write([]byte("first")); err != nil {
		t.Fatal(err)
	}
	r, err := owner.Get(id)
	if err != nil || r.OutputBytes != len("first") {
		t.Fatal("first write did not persist its counters")
	}
	if _, err = w.Write([]byte("second")); err != nil {
		t.Fatal(err)
	}
	r, err = owner.Get(id)
	if err != nil || r.OutputBytes != len("first") {
		t.Fatal("receipt rewritten inside the save interval")
	}
	if _, err = w.finish(); err != nil {
		t.Fatal(err)
	}
	r, err = owner.Get(id)
	if err != nil || r.OutputBytes != len("firstsecond") {
		t.Fatal("finish did not persist the final counters")
	}
}

func TestOutputFinishHashesIncrementallyWithoutReopening(t *testing.T) {
	owner, err := Open(t.TempDir(), testJobDir(t), "/bin/false")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	id := strings.Repeat("c", 64)
	if err = owner.save(Receipt{ID: id, State: "running"}); err != nil {
		t.Fatal(err)
	}
	outPath := filepath.Join(owner.dir, id+".output")
	f, err := os.OpenFile(outPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	w := &outputWriter{owner: owner, id: id, file: f, saveInterval: time.Hour}
	chunk1 := bytes.Repeat([]byte("abc"), 1024)
	chunk2 := bytes.Repeat([]byte("xyz"), 2048)
	if _, err = w.Write(chunk1); err != nil {
		t.Fatal(err)
	}
	if _, err = w.Write(chunk2); err != nil {
		t.Fatal(err)
	}
	// On Unix, unlinking the path while the open fd remains valid proves finish()
	// computes the digest incrementally instead of reopening and rereading disk.
	if runtime.GOOS != "windows" {
		if err = os.Remove(outPath); err != nil {
			t.Fatal(err)
		}
	}
	digest, err := w.finish()
	if err != nil {
		t.Fatalf("finish failed: %v", err)
	}
	h := sha256.New()
	_, _ = h.Write(chunk1)
	_, _ = h.Write(chunk2)
	if want := hex.EncodeToString(h.Sum(nil)); digest != want {
		t.Fatalf("digest = %s, want %s", digest, want)
	}
}

func TestOutputFinishEmptyDigest(t *testing.T) {
	owner, err := Open(t.TempDir(), testJobDir(t), "/bin/false")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	id := strings.Repeat("d", 64)
	if err = owner.save(Receipt{ID: id, State: "running"}); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(owner.dir, id+".output"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	w := &outputWriter{owner: owner, id: id, file: f}
	digest, err := w.finish()
	if err != nil {
		t.Fatalf("finish failed: %v", err)
	}
	empty := sha256.Sum256(nil)
	if want := hex.EncodeToString(empty[:]); digest != want {
		t.Fatalf("empty digest = %s, want %s", digest, want)
	}
}
