package jobs

import (
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceDigestMatchesSnapshotWithoutTempCopy(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "nested"), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "source.c"), []byte("int f(void) { return 7; }\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "empty"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "nested", "run.sh"), []byte("#!/bin/sh\n"), 0700); err != nil {
		t.Fatal(err)
	}

	stage, want, err := snapshot(root, t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stage)
	got, err := WorkspaceDigest(root)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("digest-only walk differs from snapshot: got %s want %s", got, want)
	}

	missingTemp := filepath.Join(t.TempDir(), "missing")
	t.Setenv("TMPDIR", missingTemp)
	t.Setenv("TMP", missingTemp)
	t.Setenv("TEMP", missingTemp)
	got, err = WorkspaceDigest(root)
	if err != nil {
		t.Fatalf("digest-only walk required a temporary directory: %v", err)
	}
	if got != want {
		t.Fatalf("digest changed without a temporary copy: got %s want %s", got, want)
	}
}
