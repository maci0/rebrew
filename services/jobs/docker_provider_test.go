package jobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestDockerProviderRealRebrewAndExactStop(t *testing.T) {
	image := os.Getenv("REBREW_TEST_DOCKER_IMAGE")
	if image == "" {
		t.Skip("explicit isolated Docker image not supplied")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	root := t.TempDir()
	if err = os.WriteFile(filepath.Join(root, "seed.c"), []byte("int f(void){return 0;}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	original := t.TempDir()
	if err = os.WriteFile(filepath.Join(original, "seed.c"), []byte("int f(void){return 0;}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(root))
	job := hex.EncodeToString(sum[:])
	provider := DockerProvider{Binary: docker, Image: image}
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	id, err := provider.Create(ctx, original, root, job, "seed.c")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = provider.Stop(context.Background(), id); _ = exec.Command(docker, "rm", id).Run() }()
	if _, err = provider.InspectStop(ctx, id, job, original, root, "seed.c"); err == nil {
		t.Fatal("created container treated as stopped execution")
	}
	if _, err = provider.InspectNeverStarted(ctx, id, job, original, root, "seed.c"); err != nil {
		t.Fatal(err)
	}
	var output bytes.Buffer
	_ = provider.Start(ctx, id, &output)
	receipt, err := provider.InspectStop(ctx, id, job, original, root, "seed.c")
	if err != nil {
		t.Fatal(err)
	}
	if receipt.ID != id || receipt.Image != image || output.Len() == 0 {
		t.Fatal("real CLI execution or stop proof missing")
	}
	if _, err = provider.InspectNeverStarted(ctx, id, job, original, root, "seed.c"); err == nil {
		t.Fatal("executed container treated as never started")
	}
	if _, err = provider.InspectStop(ctx, id, strings.Repeat("0", 64), original, root, "seed.c"); err == nil {
		t.Fatal("foreign job accepted")
	}
}

func TestDockerManagedCompileThroughSocket(t *testing.T) {
	image := os.Getenv("REBREW_TEST_COMPILE_DOCKER_IMAGE")
	if image == "" {
		t.Skip("explicit isolated compile test image not supplied")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	credential := "rck_test_owner_credential"
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credential {
			t.Error("owner credential missing")
			http.Error(w, "unauthorized", 401)
			return
		}
		if r.Method == http.MethodPost {
			if !validHex(r.Header.Get("Idempotency-Key"), 12) {
				t.Error("invalid key")
			}
			_, _ = w.Write([]byte(`{"status":"ok","artifact_url":"/api/v1/artifacts/abcdef123456.o"}`))
			return
		}
		if r.URL.Path != "/api/v1/artifacts/abcdef123456.o" {
			t.Error("foreign artifact")
		}
		digest := sha256.Sum256([]byte("object"))
		w.Header().Set("ETag", `"sha256-`+hex.EncodeToString(digest[:])+`"`)
		_, _ = w.Write([]byte("object"))
	}))
	defer upstream.Close()
	root, dir := t.TempDir(), testJobDir(t)
	if err = os.WriteFile(filepath.Join(root, "seed.c"), []byte("int f(void){return 0;}"), 0600); err != nil {
		t.Fatal(err)
	}
	o, err := OpenDocker(root, dir, DockerProvider{Binary: docker, Image: image})
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if err = o.ConfigureManagedCompile(upstream.URL, 1, []string{"gcc"}); err != nil {
		t.Fatal(err)
	}
	stage, digest, err := snapshot(root, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stage)
	r, _, err := o.AdmitManaged("managed-compile", "seed.c", digest, credential)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		v, e := o.Get(r.ID)
		if e == nil && v.ContainerID != "" {
			_ = (DockerProvider{Binary: docker, Image: image}).Stop(context.Background(), v.ContainerID)
			_ = exec.Command(docker, "rm", v.ContainerID).Run()
		}
	}()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		r, err = o.Get(r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if r.State == "finished" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if r.State != "finished" || !r.StopVerified {
		t.Fatalf("managed compile job not finished: %+v", r)
	}
	entries, err := os.ReadDir(filepath.Join(dir, r.ID+".compile", "ledger"))
	if err != nil || len(entries) != 2 {
		t.Fatalf("compile original missing: %v", err)
	}
	name := entries[0].Name()
	if name == "index.json" {
		name = entries[1].Name()
	}
	data, err := os.ReadFile(filepath.Join(dir, r.ID+".compile", "ledger", name))
	if err != nil {
		t.Fatal(err)
	}
	var original compileOriginal
	if json.Unmarshal(data, &original) != nil || len(original.Result) == 0 || original.Artifact != "/api/v1/artifacts/abcdef123456.o" || bytes.Contains(data, []byte(credential)) {
		t.Fatal("retained compile evidence invalid")
	}
	if r.ResultWorkspaceSHA256 == "" {
		t.Fatal("result workspace digest unavailable")
	}
	obj, err := os.ReadFile(filepath.Join(dir, r.ID+".result", "socket-test.o"))
	if err != nil || string(obj) != "object" {
		t.Fatal("worker did not receive authorized artifact")
	}
}

func TestDockerReconcileCancelledNeverStarted(t *testing.T) {
	image := os.Getenv("REBREW_TEST_DOCKER_IMAGE")
	if image == "" {
		t.Skip("explicit isolated Docker image not supplied")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	root, dir := t.TempDir(), testJobDir(t)
	provider := DockerProvider{Binary: docker, Image: image}
	owner, err := OpenDocker(root, dir, provider)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	sum := sha256.Sum256([]byte(root))
	job := hex.EncodeToString(sum[:])
	original, workspace := filepath.Join(dir, job+".original"), filepath.Join(dir, job+".workspace")
	if err = os.Mkdir(original, 0700); err != nil {
		t.Fatal(err)
	}
	if err = os.Mkdir(workspace, 0700); err != nil {
		t.Fatal(err)
	}
	id, err := provider.Create(context.Background(), original, workspace, job, "seed.c")
	if err != nil {
		t.Fatal(err)
	}
	defer exec.Command(docker, "rm", id).Run()
	r := Receipt{ID: job, Seed: "seed.c", Provider: "docker", Image: image, ContainerID: id, State: "uncertain", CancelRequested: true}
	if err = owner.save(r); err != nil {
		t.Fatal(err)
	}
	owner.occupied = true
	r, err = owner.ReconcileDocker(context.Background(), job)
	if err != nil || r.State != "cancelled" || !r.NeverStarted || !r.StopVerified || r.ExitCode != nil || owner.occupied {
		t.Fatalf("never-started cancellation was not proven: %+v, %v", r, err)
	}
}

func TestDockerCompileSocketMountIsReadOnly(t *testing.T) {
	image := os.Getenv("REBREW_TEST_DOCKER_IMAGE")
	if image == "" {
		t.Skip("explicit isolated Docker image not supplied")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	root, original, socket, ledger := t.TempDir(), t.TempDir(), t.TempDir(), t.TempDir()
	for _, dir := range []string{socket, ledger} {
		if err = os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	m, err := NewCompileMediator(ledger, "http://127.0.0.1:1", "rck_test", strings.Repeat("a", 64), 1, []string{"gcc"})
	if err != nil {
		t.Fatal(err)
	}
	server, listener, err := m.ServeSocket(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer listener.Close()
	sum := sha256.Sum256([]byte(root))
	job := hex.EncodeToString(sum[:])
	p := DockerProvider{Binary: docker, Image: image, CompileDir: socket}
	id, err := p.Create(context.Background(), original, root, job, "seed.c")
	if err != nil {
		t.Fatal(err)
	}
	defer exec.Command(docker, "rm", id).Run()
	if _, err = p.InspectNeverStarted(context.Background(), id, job, original, root, "seed.c"); err != nil {
		t.Fatal(err)
	}
	withoutSocket := DockerProvider{Binary: docker, Image: image}
	if _, err = withoutSocket.InspectNeverStarted(context.Background(), id, job, original, root, "seed.c"); err == nil {
		t.Fatal("unaccounted mount accepted")
	}
}

func TestDockerOwnerPersistsExactStopBeforeRelease(t *testing.T) {
	image := os.Getenv("REBREW_TEST_DOCKER_IMAGE")
	if image == "" {
		t.Skip("explicit isolated Docker image not supplied")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	root, dir := t.TempDir(), testJobDir(t)
	if err = os.WriteFile(filepath.Join(root, "seed.c"), []byte("int f(void){return 0;}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	provider := DockerProvider{Binary: docker, Image: image}
	owner, err := OpenDocker(root, dir, provider)
	if err != nil {
		t.Fatal(err)
	}
	ids := []string{}
	defer func() {
		_ = owner.Close()
		for _, job := range ids {
			r, e := owner.Get(job)
			if e == nil && r.ContainerID != "" {
				_ = provider.Stop(context.Background(), r.ContainerID)
				_ = exec.Command(docker, "rm", r.ContainerID).Run()
			}
		}
	}()
	first, created, err := testAdmit(owner, root+"-first", "seed.c")
	if err != nil || !created {
		t.Fatalf("admit: %v", err)
	}
	ids = append(ids, first.ID)
	deadline := time.Now().Add(90 * time.Second)
	var receipt Receipt
	for time.Now().Before(deadline) {
		receipt, err = owner.Get(first.ID)
		if err != nil {
			t.Fatal(err)
		}
		if receipt.State == "finished" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if receipt.State != "finished" || !receipt.StopVerified || receipt.ContainerID == "" || receipt.Image != image || receipt.ExitCode == nil || receipt.OutputSHA256 == "" || receipt.ResultWorkspaceSHA256 == "" {
		t.Fatal("no retained exact stop and output receipt")
	}
	// Model a lost final reply: retain only uncertain custody, then re-observe the exact container.
	owner.mu.Lock()
	receipt.State, receipt.StopVerified = "uncertain", false
	if err = owner.save(receipt); err != nil {
		owner.mu.Unlock()
		t.Fatal(err)
	}
	owner.occupied = true
	owner.mu.Unlock()
	resultFile := filepath.Join(dir, receipt.ID+".result", "seed.c")
	originalResult, err := os.ReadFile(resultFile)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(resultFile, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(resultFile, []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if _, err = owner.ReconcileDocker(context.Background(), receipt.ID); err == nil {
		t.Fatal("changed result released capacity")
	}
	if err = os.WriteFile(resultFile, originalResult, 0600); err != nil {
		t.Fatal(err)
	}
	if err = os.Chmod(resultFile, 0400); err != nil {
		t.Fatal(err)
	}
	recovered, err := owner.ReconcileDocker(context.Background(), receipt.ID)
	if err != nil || recovered.State != "stopped_unsettled" || !recovered.StopVerified || !recovered.OutputIncomplete {
		t.Fatal("exact stop was not recovered conservatively")
	}
	next, created, err := testAdmit(owner, root+"-second", "seed.c")
	if err != nil || !created {
		t.Fatalf("proven stopped job did not release capacity: %v", err)
	}
	ids = append(ids, next.ID)
}

func TestDockerOwnerCancellationRequiresObservedStop(t *testing.T) {
	image := os.Getenv("REBREW_TEST_SLOW_DOCKER_IMAGE")
	if image == "" {
		t.Skip("explicit slow isolated test image not supplied")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	root, dir := t.TempDir(), testJobDir(t)
	if err = os.WriteFile(filepath.Join(root, "seed.c"), []byte("int f(void){return 0;}\n"), 0600); err != nil {
		t.Fatal(err)
	}
	provider := DockerProvider{Binary: docker, Image: image}
	owner, err := OpenDocker(root, dir, provider)
	if err != nil {
		t.Fatal(err)
	}
	saved, _, err := testAdmit(owner, root+"-cancel", "seed.c")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = owner.Close()
		r, e := owner.Get(saved.ID)
		if e == nil && r.ContainerID != "" {
			_ = provider.Stop(context.Background(), r.ContainerID)
			_ = exec.Command(docker, "rm", r.ContainerID).Run()
		}
	}()
	deadline := time.Now().Add(45 * time.Second)
	var receipt Receipt
	running := false
	for time.Now().Before(deadline) {
		receipt, err = owner.Get(saved.ID)
		if err != nil {
			t.Fatal(err)
		}
		if receipt.ContainerID != "" {
			out, e := exec.Command(docker, "inspect", "--format", "{{.State.Running}}", receipt.ContainerID).Output()
			if e == nil && string(bytes.TrimSpace(out)) == "true" {
				running = true
				break
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !running {
		t.Fatal("isolated test container never reached running")
	}
	if _, err = owner.Cancel(saved.ID); err != nil {
		t.Fatal(err)
	}
	for time.Now().Before(deadline) {
		receipt, err = owner.Get(saved.ID)
		if err != nil {
			t.Fatal(err)
		}
		if receipt.State == "cancelled" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if receipt.State != "cancelled" || !receipt.CancelRequested || !receipt.StopVerified || receipt.ExitCode == nil {
		t.Fatal("cancel lacked verified physical stop")
	}
}

func TestDockerManagedAdmissionRunsPinnedContainer(t *testing.T) {
	image := os.Getenv("REBREW_TEST_DOCKER_IMAGE")
	if image == "" {
		t.Skip("explicit isolated Docker image not supplied")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	root, dir := t.TempDir(), testJobDir(t)
	if err = os.WriteFile(filepath.Join(root, "seed.c"), []byte("int f(void){return 0;}"), 0600); err != nil {
		t.Fatal(err)
	}
	o, err := OpenDocker(root, dir, DockerProvider{Binary: docker, Image: image})
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if err = o.ConfigureManagedCompile("http://127.0.0.1:1", 1, []string{"gcc"}); err != nil {
		t.Fatal(err)
	}
	stage, digest, err := snapshot(root, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stage)
	r, _, err := o.AdmitManaged("managed", "seed.c", digest, "rck_test_secret")
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		v, e := o.Get(r.ID)
		if e == nil && v.ContainerID != "" {
			_ = (DockerProvider{Binary: docker, Image: image}).Stop(context.Background(), v.ContainerID)
			_ = exec.Command(docker, "rm", v.ContainerID).Run()
		}
	}()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		r, err = o.Get(r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if r.State == "finished" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if r.State != "finished" || !r.ManagedCompile || !r.StopVerified {
		t.Fatalf("managed job did not finish with exact stop: %+v", r)
	}
}

// This opt-in test requires a disposable paired Platform/Recompile fixture.
func TestDockerManagedRealPeer(t *testing.T) {
	image, upstream, credential := os.Getenv("REBREW_TEST_COMPILE_DOCKER_IMAGE"), os.Getenv("REBREW_TEST_REAL_COMPILE_URL"), os.Getenv("REBREW_TEST_REAL_CALLER_KEY")
	if image == "" || upstream == "" || credential == "" {
		t.Skip("explicit isolated real peer fixture not supplied")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	root, dir := t.TempDir(), testJobDir(t)
	if err = os.WriteFile(filepath.Join(root, "seed.c"), []byte("int f(void){return 0;}"), 0600); err != nil {
		t.Fatal(err)
	}
	o, err := OpenDocker(root, dir, DockerProvider{Binary: docker, Image: image})
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if err = o.ConfigureManagedCompile(upstream, 1, []string{"gcc-14.2.0"}); err != nil {
		t.Fatal(err)
	}
	stage, digest, err := snapshot(root, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stage)
	r, _, err := o.AdmitManaged("real-managed-compile", "seed.c", digest, credential)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		v, e := o.Get(r.ID)
		if e == nil && v.ContainerID != "" {
			_ = (DockerProvider{Binary: docker, Image: image}).Stop(context.Background(), v.ContainerID)
			_ = exec.Command(docker, "rm", v.ContainerID).Run()
		}
	}()
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		r, err = o.Get(r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if r.State == "finished" || r.State == "uncertain" && r.ContainerID != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if r.State != "finished" || !r.StopVerified {
		intents, _ := o.CompileIntents(r.ID)
		t.Fatalf("real peer job unresolved: state=%s intents=%+v", r.State, intents)
	}
	if r.ResultWorkspaceSHA256 == "" {
		t.Fatal("result workspace digest unavailable")
	}
	obj, err := os.ReadFile(filepath.Join(dir, r.ID+".result", "socket-test.o"))
	if err != nil || len(obj) < 4 || string(obj[:4]) != "\x7fELF" {
		t.Fatal("real compiler artifact unavailable")
	}
	intents, err := o.CompileIntents(r.ID)
	if err != nil || len(intents) != 1 || intents[0].State != "result_retained" {
		t.Fatal("real compile original unavailable")
	}
}

// This opt-in test drops a real paired response after the upstream has finished.
func TestDockerManagedRealPeerLostReply(t *testing.T) {
	image, upstream, credential := os.Getenv("REBREW_TEST_COMPILE_DOCKER_IMAGE"), os.Getenv("REBREW_TEST_REAL_COMPILE_URL"), os.Getenv("REBREW_TEST_REAL_CALLER_KEY")
	if image == "" || upstream == "" || credential == "" {
		t.Skip("explicit isolated real peer fixture not supplied")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	var mu sync.Mutex
	var originalKey string
	var originalBody []byte
	calls := 0
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(io.LimitReader(r.Body, 16*1024*1024+1))
		if err != nil || len(body) > 16*1024*1024 {
			http.Error(w, "invalid", 400)
			return
		}
		mu.Lock()
		calls++
		n := calls
		key := r.Header.Get("Idempotency-Key")
		if n == 1 {
			originalKey = key
			originalBody = append([]byte(nil), body...)
		} else if key != originalKey || !bytes.Equal(body, originalBody) {
			t.Error("recovery changed original")
		}
		mu.Unlock()
		req, err := http.NewRequest(r.Method, upstream+r.URL.RequestURI(), bytes.NewReader(body))
		if err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		req.GetBody = nil
		req.Header = r.Header.Clone()
		client := &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 150 * time.Second}
		res, err := client.Do(req)
		if err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		defer res.Body.Close()
		reply, err := io.ReadAll(io.LimitReader(res.Body, 1024*1024))
		if err != nil {
			http.Error(w, "unavailable", 503)
			return
		}
		if n == 1 {
			conn, _, err := w.(http.Hijacker).Hijack()
			if err == nil {
				_ = conn.Close()
			}
			return
		}
		w.WriteHeader(res.StatusCode)
		_, _ = w.Write(reply)
	}))
	defer proxy.Close()
	root, dir := t.TempDir(), testJobDir(t)
	if err = os.WriteFile(filepath.Join(root, "seed.c"), []byte("int f(void){return 0;}"), 0600); err != nil {
		t.Fatal(err)
	}
	provider := DockerProvider{Binary: docker, Image: image}
	o, err := OpenDocker(root, dir, provider)
	if err != nil {
		t.Fatal(err)
	}
	var containerID string
	defer func() {
		if o != nil {
			_ = o.Close()
		}
		if containerID != "" {
			_ = provider.Stop(context.Background(), containerID)
			_ = exec.Command(docker, "rm", containerID).Run()
		}
	}()
	if err = o.ConfigureManagedCompile(proxy.URL, 1, []string{"gcc-14.2.0"}); err != nil {
		t.Fatal(err)
	}
	stage, digest, err := snapshot(root, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stage)
	r, _, err := o.AdmitManaged("real-managed-lost-reply", "seed.c", digest, credential)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		r, err = o.Get(r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if r.State == "uncertain" && r.ContainerID != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	containerID = r.ContainerID
	if r.State != "uncertain" || containerID == "" {
		t.Fatal("lost response did not fence job")
	}
	intents, err := o.CompileIntents(r.ID)
	if err != nil || len(intents) != 1 || intents[0].State != "unresolved" {
		t.Fatal("lost original unavailable")
	}
	if err = o.Close(); err != nil {
		t.Fatal(err)
	}
	o = nil
	o, err = OpenDocker(root, dir, provider)
	if err != nil {
		t.Fatal(err)
	}
	if err = o.ConfigureManagedCompile(proxy.URL, 1, []string{"gcc-14.2.0"}); err != nil {
		t.Fatal(err)
	}
	if err = o.ReconcileCompile(context.Background(), r.ID, intents[0].Intent, credential); err != nil {
		status, _ := o.CompileIntents(r.ID)
		t.Fatalf("same-original reconciliation failed: intents=%+v", status)
	}
	recovered, err := o.ReconcileDocker(context.Background(), r.ID)
	if err != nil || recovered.State != "stopped_unsettled" || !recovered.StopVerified || !recovered.OutputIncomplete {
		t.Fatal("exact stop recovery failed")
	}
	mu.Lock()
	total := calls
	mu.Unlock()
	if total != 2 {
		t.Fatalf("unexpected upstream dispatch count %d", total)
	}
	data, err := os.ReadFile(filepath.Join(dir, r.ID+".compile", "ledger", intents[0].Intent+".json"))
	if err != nil {
		t.Fatal("recovered evidence unavailable")
	}
	var original compileOriginal
	if json.Unmarshal(data, &original) != nil {
		t.Fatal("recovered evidence invalid")
	}
	var result struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(original.Result, &result) != nil || !validHex(result.ID, 12) {
		t.Fatal("recovered job identity invalid")
	}
	t.Logf("recovered_job=%s", result.ID)
}

// This opt-in test runs the real matching CLI on a private copy of a local test project.
func TestDockerManagedRealMatch(t *testing.T) {
	image, upstream, credential, project := os.Getenv("REBREW_TEST_MATCH_DOCKER_IMAGE"), os.Getenv("REBREW_TEST_REAL_COMPILE_URL"), os.Getenv("REBREW_TEST_REAL_CALLER_KEY"), os.Getenv("REBREW_TEST_REAL_MATCH_PROJECT")
	if image == "" || upstream == "" || credential == "" || project == "" {
		t.Skip("explicit isolated real matching fixture not supplied")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	parent, dir := t.TempDir(), testJobDir(t)
	workspace, _, err := snapshot(project, parent)
	if err != nil {
		t.Fatal(err)
	}
	config := filepath.Join(workspace, "rebrew-project.toml")
	data, err := os.ReadFile(config)
	if err != nil {
		t.Fatal(err)
	}
	old := `profile = "mingw-16.2.0"`
	base := `base_cflags = "/nologo /c /MT"`
	if !bytes.Contains(data, []byte(old)) || !bytes.Contains(data, []byte(base)) {
		t.Fatal("fixture compiler configuration changed")
	}
	data = bytes.Replace(data, []byte(old), []byte(`profile = "mingw-14.2.0"`), 1)
	data = bytes.Replace(data, []byte(base), []byte(`base_cflags = "-c"`), 1)
	data = bytes.Replace(data, []byte(`jobs = 4`), []byte(`jobs = 1`), 1)
	if err = os.WriteFile(config, data, 0600); err != nil {
		t.Fatal(err)
	}
	o, err := OpenDocker(workspace, dir, DockerProvider{Binary: docker, Image: image})
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	if err = o.ConfigureManagedCompile(upstream, 6, []string{"mingw-14.2.0"}); err != nil {
		t.Fatal(err)
	}
	stage, digest, err := snapshot(workspace, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stage)
	r, _, err := o.AdmitManagedTuned("real-matching-smoke", "src/test_waveout/fcn_00401000.c", digest, credential, MatchOptions{Generations: 1, Population: 2})
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		v, e := o.Get(r.ID)
		if e == nil && v.ContainerID != "" {
			_ = (DockerProvider{Binary: docker, Image: image}).Stop(context.Background(), v.ContainerID)
			_ = exec.Command(docker, "rm", v.ContainerID).Run()
		}
	}()
	deadline := time.Now().Add(180 * time.Second)
	for time.Now().Before(deadline) {
		r, err = o.Get(r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if r.State == "finished" || r.State == "uncertain" && r.ContainerID != "" {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if r.State != "finished" || !r.StopVerified {
		intents, _ := o.CompileIntents(r.ID)
		t.Fatalf("real matching job unresolved: state=%s intents=%+v", r.State, intents)
	}
	if r.ResultWorkspaceSHA256 == "" {
		t.Fatal("matching result workspace was not pinned")
	}
	if _, err = os.Stat(filepath.Join(dir, r.ID+".result", "output", "ga_runs", "best.c")); err != nil {
		t.Fatal("matching result source was not retained")
	}
	output, err := os.ReadFile(filepath.Join(dir, r.ID+".output"))
	if err != nil || !bytes.Contains(output, []byte(`"mode":"ga"`)) {
		t.Fatal("matching result unavailable")
	}
	var summary struct {
		Mode      string  `json:"mode"`
		Exact     bool    `json:"exact"`
		BestScore float64 `json:"best_score"`
	}
	for _, line := range bytes.Split(output, []byte("\n")) {
		if json.Unmarshal(line, &summary) == nil && summary.Mode == "ga" {
			break
		}
	}
	if summary.Mode != "ga" || r.ExitCode == nil {
		t.Fatal("matching result or exit code invalid")
	}
	if r.Generations != 1 || r.Population != 2 {
		t.Fatal("admitted match bounds changed")
	}
	intents, err := o.CompileIntents(r.ID)
	if err != nil || len(intents) == 0 {
		t.Fatal("matching did not request compilation")
	}
	success := false
	for _, intent := range intents {
		raw, e := os.ReadFile(filepath.Join(dir, r.ID+".compile", "ledger", intent.Intent+".json"))
		if e != nil {
			t.Fatal(e)
		}
		var original compileOriginal
		if json.Unmarshal(raw, &original) != nil {
			t.Fatal("invalid matching compile evidence")
		}
		var result struct {
			Status    string `json:"status"`
			ErrorCode string `json:"error_code"`
			Log       string `json:"log"`
		}
		if json.Unmarshal(original.Result, &result) == nil && result.Status == "ok" {
			success = true
		} else {
			if len(result.Log) > 500 {
				result.Log = result.Log[:500]
			}
			t.Logf("compile status=%s code=%s log=%s", result.Status, result.ErrorCode, result.Log)
		}
	}
	if !success {
		t.Fatal("matching did not complete an actual compile")
	}
	t.Logf("matching_exit=%d exact=%t score=%g retained_compiles=%d", *r.ExitCode, summary.Exact, summary.BestScore, len(intents))
}
