package jobs

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
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
