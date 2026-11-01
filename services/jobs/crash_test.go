package jobs

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestCrashHelper(t *testing.T) {
	if os.Getenv("REBREW_JOBS_TEST_HELPER") != "1" {
		return
	}
	owner, err := Open(os.Getenv("TEST_ROOT"), os.Getenv("TEST_DIR"), os.Getenv("TEST_RUNNER"))
	if err != nil {
		os.Exit(2)
	}
	r, _, err := testAdmit(owner, "crash-operation", "seed.c")
	if err != nil {
		os.Exit(3)
	}
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		state, err := owner.Get(r.ID)
		if err == nil && state.State == "running" {
			fmt.Println(r.ID)
			select {}
		}
		time.Sleep(10 * time.Millisecond)
	}
	os.Exit(4)
}

func TestKilledOwnerDoesNotRelaunchOrReleaseUnknownWork(t *testing.T) {
	root, dir := t.TempDir(), testJobDir(t)
	if err := os.WriteFile(filepath.Join(root, "seed.c"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	pidfile := filepath.Join(t.TempDir(), "child.pid")
	runner := filepath.Join(t.TempDir(), "runner")
	script := "#!/bin/sh\necho $$ > " + pidfile + "\nexec sleep 30\n"
	if err := os.WriteFile(runner, []byte(script), 0700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(os.Args[0], "-test.run=^TestCrashHelper$")
	cmd.Env = append(os.Environ(), "REBREW_JOBS_TEST_HELPER=1", "TEST_ROOT="+root, "TEST_DIR="+dir, "TEST_RUNNER="+runner)
	pipe, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err = cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if cmd.ProcessState == nil {
			_ = cmd.Process.Kill()
			_ = cmd.Wait()
		}
	}()
	var id string
	if _, err = fmt.Fscanln(pipe, &id); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	var data []byte
	for time.Now().Before(deadline) {
		data, err = os.ReadFile(pidfile)
		if err == nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if err != nil {
		t.Fatal("child did not start")
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(data)))
	if err != nil {
		t.Fatal(err)
	}
	child, err := os.FindProcess(pid)
	if err != nil {
		t.Fatal(err)
	}
	defer child.Kill()
	if err = cmd.Process.Kill(); err != nil {
		t.Fatal(err)
	}
	_ = cmd.Wait()
	owner, err := Open(root, dir, runner)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	r, err := owner.Get(id)
	if err != nil || r.State != "uncertain" {
		t.Fatal("crashed owner did not retain uncertain work")
	}
	if _, _, err = testAdmit(owner, "another", "seed.c"); err == nil {
		t.Fatal("unknown child did not fence workspace")
	}
}
