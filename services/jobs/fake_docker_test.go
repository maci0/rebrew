package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var fakeContainer = strings.Repeat("c", 64)

// fakeDockerOwner opens a Docker owner over a POSIX stand-in for the docker
// CLI and returns it with the stand-in's state directory. Every call is
// appended to <state>/calls. Create fails while <state>/create-fails exists.
// The container counts as exited once kill ran or <state>/exited exists;
// until then logs blocks and inspect reports it running.
func fakeDockerOwner(t *testing.T) (*Owner, string) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake docker uses a POSIX shell script")
	}
	root, state := t.TempDir(), t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "seed.c"), []byte("int f(void){return 0;}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REBREW_TEST_FAKE_DOCKER", state)
	script := filepath.Join(state, "docker")
	body := `#!/bin/sh
d=$REBREW_TEST_FAKE_DOCKER
echo "$@" >> "$d/calls"
case "$1" in
create) if [ -e "$d/create-fails" ]; then exit 1; fi; echo ` + fakeContainer + ` ;;
logs) [ -e "$d/exited" ] || exec sleep 600 ;;
inspect) if [ -e "$d/exited" ]; then cat "$d/exited.json"; else cat "$d/running.json"; fi ;;
kill) : > "$d/exited" ;;
esac
`
	if err := os.WriteFile(script, []byte(body), 0700); err != nil {
		t.Fatal(err)
	}
	owner, err := OpenDocker(root, testJobDir(t), DockerProvider{Binary: script, Image: "sha256:" + strings.Repeat("a", 64)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = owner.Close() })
	return owner, state
}

// fakeJob returns the job ID for key and writes the inspect rows the fake
// reports for that job's default match container.
func fakeJob(t *testing.T, owner *Owner, state, key string) string {
	t.Helper()
	sum := sha256.Sum256([]byte(key))
	job := hex.EncodeToString(sum[:])
	for name, running := range map[string]bool{"running.json": true, "exited.json": false} {
		status := "exited"
		if running {
			status = "running"
		}
		row := map[string]any{
			"ID":    fakeContainer,
			"Image": owner.docker.Image,
			"Config": map[string]any{
				"Labels":     map[string]string{"relumea.rebrew.job": job},
				"User":       processUser(),
				"WorkingDir": "/workspace",
				"Entrypoint": []string{"/opt/venv/bin/rebrew"},
				"Cmd":        jobArguments("", "seed.c", defaultMatchOptions.Generations, defaultMatchOptions.Population),
			},
			"State": map[string]any{"Running": running, "Status": status, "ExitCode": 137},
			"HostConfig": map[string]any{
				"NetworkMode": "none", "ReadonlyRootfs": true, "CapDrop": []string{"ALL"},
				"SecurityOpt": []string{"no-new-privileges"}, "PidsLimit": 128, "Memory": 1 << 30, "NanoCpus": 1000000000,
				"Ulimits": []map[string]any{{"Name": "nofile", "Soft": 1024, "Hard": 1024}},
			},
			"Mounts": []map[string]any{
				{"Type": "bind", "Source": filepath.Join(owner.dir, job+".workspace"), "Destination": "/workspace", "RW": true},
				{"Type": "bind", "Source": filepath.Join(owner.dir, job+".original"), "Destination": "/original", "RW": false},
			},
		}
		b, err := json.Marshal([]any{row})
		if err != nil {
			t.Fatal(err)
		}
		if err = os.WriteFile(filepath.Join(state, name), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return job
}

func fakeCalls(t *testing.T, state string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(state, "calls"))
	if err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	return string(b)
}

func waitWorkers(t *testing.T, owner *Owner) {
	t.Helper()
	done := make(chan struct{})
	go func() { owner.workers.Wait(); close(done) }()
	select {
	case <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("job worker did not return")
	}
}

func TestRunTimeoutStopsContainer(t *testing.T) {
	owner, state := fakeDockerOwner(t)
	owner.runTimeout = time.Millisecond
	job := fakeJob(t, owner, state, "timeout")
	if _, _, err := testAdmit(owner, "timeout", "seed.c"); err != nil {
		t.Fatal(err)
	}
	waitWorkers(t, owner)
	r, err := owner.Get(job)
	if err != nil || r.State != "finished" || !r.StopVerified {
		t.Fatalf("timed-out container was not stopped and proven: %+v, %v", r, err)
	}
	if !strings.Contains(fakeCalls(t, state), "kill --signal 9 "+fakeContainer) {
		t.Fatal("timed-out container was not killed")
	}
}

func TestCloseStopsFollowedContainer(t *testing.T) {
	owner, state := fakeDockerOwner(t)
	job := fakeJob(t, owner, state, "close")
	if _, _, err := testAdmit(owner, "close", "seed.c"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(10 * time.Second)
	for !strings.Contains(fakeCalls(t, state), "logs --follow") {
		if time.Now().After(deadline) {
			t.Fatal("job never followed its container")
		}
		time.Sleep(10 * time.Millisecond)
	}
	closed := make(chan error, 1)
	go func() { closed <- owner.Close() }()
	select {
	case err := <-closed:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Close did not return")
	}
	r, err := owner.Get(job)
	if err != nil || r.State != "finished" || !r.StopVerified {
		t.Fatalf("closing owner left the container unproven: %+v, %v", r, err)
	}
}

func TestCancelStopsUncertainContainer(t *testing.T) {
	owner, state := fakeDockerOwner(t)
	job := fakeJob(t, owner, state, "uncertain")
	owner.mu.Lock()
	err := owner.save(Receipt{ID: job, Seed: "seed.c", State: "uncertain", Provider: "docker", Image: owner.docker.Image, ContainerID: fakeContainer})
	owner.occupied = true
	owner.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = owner.Cancel(job); err != nil {
		t.Fatal(err)
	}
	waitWorkers(t, owner)
	if !strings.Contains(fakeCalls(t, state), "kill --signal 9 "+fakeContainer) {
		t.Fatal("cancel left an uncertain container running")
	}
}

func TestPreLaunchFailureReleasesSlotAndMediator(t *testing.T) {
	owner, state := fakeDockerOwner(t)
	if err := owner.ConfigureManagedCompile("https://recompile.invalid", 1, []string{"gcc"}); err != nil {
		t.Fatal(err)
	}
	job := fakeJob(t, owner, state, "no-original")
	owner.mu.Lock()
	socket, err := owner.startManagedCompile(job, "rck_secret")
	r := Receipt{ID: job, Seed: "seed.c", State: "uncertain", Provider: "docker", Image: owner.docker.Image, ManagedCompile: true, CompileSocket: socket}
	if err == nil {
		err = owner.save(r)
	}
	owner.occupied = true
	owner.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	// No retained original, so the launch fails before anything starts.
	if err = owner.run(r); err == nil {
		t.Fatal("launch without a retained original succeeded")
	}
	got, err := owner.Get(job)
	if err != nil || got.State != "failed" || !got.NeverStarted {
		t.Fatalf("pre-launch failure not recorded: %+v, %v", got, err)
	}
	owner.mu.Lock()
	busy, mediator := owner.occupied, owner.compileMediator
	owner.mu.Unlock()
	if busy || mediator != nil {
		t.Fatalf("pre-launch failure kept the slot (%v) or the compile mediator (%v)", busy, mediator != nil)
	}
}

func TestFailedCreateReleasesSlot(t *testing.T) {
	owner, state := fakeDockerOwner(t)
	if err := os.WriteFile(filepath.Join(state, "create-fails"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	job := fakeJob(t, owner, state, "create-fails")
	if _, _, err := testAdmit(owner, "create-fails", "seed.c"); err != nil {
		t.Fatal(err)
	}
	waitWorkers(t, owner)
	r, err := owner.Get(job)
	if err != nil || r.State != "failed" || !r.NeverStarted || r.ContainerID != "" {
		t.Fatalf("failed create not recorded as never started: %+v, %v", r, err)
	}
	if !strings.Contains(fakeCalls(t, state), "rm rebrew-job-"+job) {
		t.Fatal("a possibly created container was not removed by name")
	}
	if _, created, err := testAdmit(owner, "after-create-fails", "seed.c"); err != nil || !created {
		t.Fatalf("failed create kept the slot: %v", err)
	}
}

func TestFinishedJobReleasesContainerAndWorkspace(t *testing.T) {
	owner, state := fakeDockerOwner(t)
	if err := os.WriteFile(filepath.Join(state, "exited"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	job := fakeJob(t, owner, state, "finished")
	if _, _, err := testAdmit(owner, "finished", "seed.c"); err != nil {
		t.Fatal(err)
	}
	waitWorkers(t, owner)
	r, err := owner.Get(job)
	if err != nil || r.State != "finished" || r.ResultWorkspaceSHA256 == "" {
		t.Fatalf("job did not finish: %+v, %v", r, err)
	}
	if !strings.Contains(fakeCalls(t, state), "rm "+fakeContainer) {
		t.Fatal("stopped container was not removed")
	}
	if _, err = os.Lstat(filepath.Join(owner.dir, job+".workspace")); !os.IsNotExist(err) {
		t.Fatalf("working copy kept after its result was sealed: %v", err)
	}
	for _, kept := range []string{".original", ".result", ".output"} {
		if _, err = os.Lstat(filepath.Join(owner.dir, job+kept)); err != nil {
			t.Fatalf("retained evidence %s removed: %v", kept, err)
		}
	}
}

func TestReconcileReleasesContainerOnlyAfterProof(t *testing.T) {
	owner, state := fakeDockerOwner(t)
	if err := os.WriteFile(filepath.Join(state, "exited"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	job := fakeJob(t, owner, state, "lost-reply")
	workspace := filepath.Join(owner.dir, job+".workspace")
	if err := os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(workspace, "seed.c"), []byte("result"), 0600); err != nil {
		t.Fatal(err)
	}
	catalog := *owner.docker
	catalog.Kind = "catalog"
	if _, err := catalog.InspectStop(context.Background(), fakeContainer, job, filepath.Join(owner.dir, job+".original"), workspace, "seed.c"); err == nil {
		t.Fatal("foreign command accepted as stop evidence")
	}
	r := Receipt{ID: job, Seed: "seed.c", Generations: defaultMatchOptions.Generations, Population: defaultMatchOptions.Population, State: "uncertain", Provider: "docker", Image: owner.docker.Image, ContainerID: fakeContainer, ResultWorkspaceSHA256: strings.Repeat("0", 64)}
	owner.mu.Lock()
	err := owner.save(r)
	owner.occupied = true
	owner.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if _, err = owner.ReconcileDocker(context.Background(), job); err == nil {
		t.Fatal("changed result released capacity")
	}
	if strings.Contains(fakeCalls(t, state), "rm ") {
		t.Fatal("container removed without a proven settlement")
	}
	r.ResultWorkspaceSHA256 = ""
	owner.mu.Lock()
	err = owner.save(r)
	owner.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	got, err := owner.ReconcileDocker(context.Background(), job)
	if err != nil || got.State != "stopped_unsettled" || !got.StopVerified || !got.OutputIncomplete || got.ResultWorkspaceSHA256 == "" {
		t.Fatalf("exact stop was not recovered conservatively: %+v, %v", got, err)
	}
	if !strings.Contains(fakeCalls(t, state), "rm "+fakeContainer) {
		t.Fatal("reconciled container was not removed")
	}
	if _, err = os.Lstat(workspace); !os.IsNotExist(err) {
		t.Fatalf("working copy kept after reconciliation: %v", err)
	}
}
