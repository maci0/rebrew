package jobs

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testAdmit(o *Owner, key, seed string) (Receipt, bool, error) {
	stage, digest, err := snapshot(o.root, o.dir)
	if err != nil {
		return Receipt{}, false, err
	}
	defer os.RemoveAll(stage)
	return o.Admit(key, seed, digest)
}

func testJobDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { makeTreeRemovable(dir) })
	return dir
}

func TestRealMatchInvocationAndIdempotentRecovery(t *testing.T) {
	root := t.TempDir()
	dir := testJobDir(t)
	if err := os.WriteFile(filepath.Join(root, "seed.c"), []byte("int f(void){return 0;}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := filepath.Abs("../../.venv/bin/rebrew")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(executable); err != nil {
		t.Skip("installed Rebrew CLI unavailable")
	}
	owner, err := Open(root, dir, executable)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = Open(root, dir, executable); err == nil {
		t.Fatal("second owner acquired store")
	}
	first, created, err := testAdmit(owner, "operation-1", "seed.c")
	if err != nil || !created {
		t.Fatalf("admit: %v", err)
	}
	deadline := time.Now().Add(30 * time.Second)
	var done Receipt
	for time.Now().Before(deadline) {
		done, err = owner.Get(first.ID)
		if err != nil {
			t.Fatal(err)
		}
		if done.ExitCode != nil {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if done.State != "uncertain" || done.ExitCode == nil {
		t.Fatal("actual Rebrew process did not finish")
	}
	original, err := os.ReadFile(filepath.Join(dir, first.ID+".original", "seed.c"))
	if err != nil || string(original) != "int f(void){return 0;}\n" {
		t.Fatal("original seed was not retained")
	}
	output, err := os.ReadFile(filepath.Join(dir, first.ID+".output"))
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(output)
	if done.OutputBytes != len(output) || done.OutputSHA256 != hex.EncodeToString(sum[:]) {
		t.Fatal("retained output differs from receipt")
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	owner, err = Open(root, dir, executable)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	replay, created, err := testAdmit(owner, "operation-1", "seed.c")
	if err != nil || created || replay.State != "uncertain" || *replay.ExitCode != *done.ExitCode {
		t.Fatal("retained receipt changed on retry")
	}
	if err = os.WriteFile(filepath.Join(root, "other.c"), []byte("new"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = testAdmit(owner, "operation-1", "seed.c"); err == nil {
		t.Fatal("changed workspace accepted")
	}
	if err = os.Remove(filepath.Join(root, "other.c")); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "seed.c"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, _, err = testAdmit(owner, "operation-1", "seed.c"); err == nil {
		t.Fatal("changed original accepted")
	}
	if _, _, err = testAdmit(owner, "operation-1", "../outside"); err == nil {
		t.Fatal("unsafe seed accepted")
	}
	if _, err = owner.Get("../../bad"); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("invalid id accepted")
	}
}

func TestSnapshotRefusesSymlink(t *testing.T) {
	root, dir := t.TempDir(), testJobDir(t)
	if err := os.WriteFile(filepath.Join(root, "seed.c"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("seed.c", filepath.Join(root, "alias.c")); err != nil {
		t.Fatal(err)
	}
	o, err := Open(root, dir, "/bin/false")
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if _, _, err = testAdmit(o, "key", "seed.c"); err == nil {
		t.Fatal("workspace symlink was accepted")
	}
}

func TestRetainedUncertainIsNotRelaunched(t *testing.T) {
	root := t.TempDir()
	dir := testJobDir(t)
	if err := os.WriteFile(filepath.Join(root, "seed.c"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	owner, err := Open(root, dir, "/bin/false")
	if err != nil {
		t.Fatal(err)
	}
	r := Receipt{ID: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", Seed: "seed.c", State: "running"}
	if err = owner.save(r); err != nil {
		t.Fatal(err)
	}
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	owner, err = Open(root, dir, "/bin/false")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	time.Sleep(25 * time.Millisecond)
	got, err := owner.Get(r.ID)
	if err != nil || got.State != "uncertain" {
		t.Fatal("unknown launch was replayed")
	}
	if _, _, err = testAdmit(owner, "different-operation", "seed.c"); err == nil {
		t.Fatal("unresolved work did not fence the workspace")
	}
}

func TestCancelProvesOnlyInProcessQueuedWorkNeverLaunched(t *testing.T) {
	owner, err := Open(t.TempDir(), testJobDir(t), "/bin/false")
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	id := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	r := Receipt{ID: id, Seed: "seed.c", State: "uncertain"}
	if err = owner.save(r); err != nil {
		t.Fatal(err)
	}
	owner.mu.Lock()
	owner.queued[id] = true
	owner.occupied = true
	owner.mu.Unlock()
	got, err := owner.Cancel(id)
	if err != nil || got.State != "cancelled" || !got.CancelRequested {
		t.Fatal("queued cancellation was not retained")
	}
	if err = owner.run(r); err == nil {
		t.Fatal("cancelled original launched")
	}
	owner.mu.Lock()
	busy := owner.occupied
	owner.mu.Unlock()
	if busy {
		t.Fatal("proven never-start work retained capacity")
	}
}

func TestNeverStartedFailureReleasesCapacity(t *testing.T) {
	root, dir := t.TempDir(), testJobDir(t)
	if err := os.WriteFile(filepath.Join(root, "seed.c"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	executable := filepath.Join(t.TempDir(), "runner")
	if err := os.WriteFile(executable, []byte("#!/bin/sh\nexit 0\n"), 0700); err != nil {
		t.Fatal(err)
	}
	owner, err := Open(root, dir, executable)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err = os.Remove(executable); err != nil {
		t.Fatal(err)
	}
	first, _, err := testAdmit(owner, "never-started", "seed.c")
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var r Receipt
	for time.Now().Before(deadline) {
		r, err = owner.Get(first.ID)
		if err != nil {
			t.Fatal(err)
		}
		if r.State == "failed" {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if r.State != "failed" || !r.NeverStarted {
		t.Fatal("never-start proof missing")
	}
	if _, created, err := testAdmit(owner, "next", "seed.c"); err != nil || !created {
		t.Fatal("proven never-start job retained capacity")
	}
}

func TestRetainedResultWorkspacePinsStoppedOutput(t *testing.T) {
	root, dir := t.TempDir(), testJobDir(t)
	if err := os.WriteFile(filepath.Join(root, "out.txt"), []byte("result"), 0600); err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("d", 64)
	first, err := retainResultWorkspace(root, dir, id)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(root, "out.txt"), []byte("later workspace change"), 0600); err != nil {
		t.Fatal(err)
	}
	second, err := retainResultWorkspace(root, dir, id)
	if err != nil || first != second {
		t.Fatal("retained result did not preserve stopped tree")
	}
	path := filepath.Join(dir, id+".result", "out.txt")
	if err = os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(path, []byte("changed retained result"), 0600); err != nil {
		t.Fatal(err)
	}
	third, err := retainResultWorkspace(root, dir, id)
	if err != nil || third == first {
		t.Fatal("changed retained result was not detected")
	}
}
