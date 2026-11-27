package jobs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceDigestAllocationBudget(t *testing.T) {
	root := t.TempDir()
	data := make([]byte, 8*1024)
	for i := range 128 {
		if err := os.WriteFile(filepath.Join(root, fmt.Sprintf("%03d.c", i)), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	allocations := testing.AllocsPerRun(5, func() {
		if _, err := WorkspaceDigest(root); err != nil {
			t.Fatal(err)
		}
	})
	const budget = 2380 // 2324 with a shared buffer, 2452 with one buffer per file.
	if allocations > budget {
		t.Fatalf("workspace digest allocated %.0f times, budget %d", allocations, budget)
	}
	t.Logf("%.0f allocations for 128 files", allocations)
}

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
