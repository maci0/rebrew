package jobs

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestCloseWaitsForCancellationStop(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake docker uses a POSIX shell script")
	}
	root, dir := t.TempDir(), testJobDir(t)
	if err := os.WriteFile(filepath.Join(root, "seed.c"), []byte("int f(void){return 0;}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	markerDir := t.TempDir()
	t.Setenv("REBREW_TEST_CANCEL_MARKER", markerDir)
	script := filepath.Join(markerDir, "docker")
	body := "#!/bin/sh\n: > \"$REBREW_TEST_CANCEL_MARKER/started\"\nwhile [ ! -e \"$REBREW_TEST_CANCEL_MARKER/release\" ]; do sleep 0.02; done\n"
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	provider := DockerProvider{Binary: script, Image: "sha256:" + strings.Repeat("a", 64)}
	owner, err := OpenDocker(root, dir, provider)
	if err != nil {
		t.Fatal(err)
	}
	release := filepath.Join(markerDir, "release")
	defer func() {
		_ = os.WriteFile(release, nil, 0600)
		_ = owner.Close()
	}()
	receipt := Receipt{
		ID:          strings.Repeat("b", 64),
		Seed:        "seed.c",
		State:       "running",
		Provider:    "docker",
		Image:       provider.Image,
		ContainerID: strings.Repeat("c", 64),
	}
	owner.mu.Lock()
	err = owner.save(receipt)
	if err == nil {
		owner.occupied = true
	}
	owner.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = owner.Cancel(receipt.ID); err != nil {
		t.Fatal(err)
	}
	started := filepath.Join(markerDir, "started")
	deadline := time.Now().Add(10 * time.Second)
	for {
		if _, err = os.Stat(started); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("cancellation stop never started")
		}
		time.Sleep(10 * time.Millisecond)
	}
	closed := make(chan error, 1)
	go func() { closed <- owner.Close() }()
	select {
	case <-closed:
		t.Fatal("Close returned while the cancellation stop was still running")
	case <-time.After(200 * time.Millisecond):
	}
	if err = os.WriteFile(release, nil, 0600); err != nil {
		t.Fatal(err)
	}
	select {
	case err = <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Close did not return after the cancellation stop finished")
	}
	if _, err = owner.Cancel(receipt.ID); err == nil {
		t.Fatal("Cancel mutated a closed owner")
	}
}
