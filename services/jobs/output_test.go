package jobs

import (
	"bytes"
	"os"
	"path/filepath"
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
	if err != nil || len(digest) != 64 {
		t.Fatal("output digest unavailable")
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
