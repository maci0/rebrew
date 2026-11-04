package jobs

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestCompileMediatorUncertainOriginalAndAuthorizedArtifact(t *testing.T) {
	credential := "rck_fixture_secret"
	var key string
	var originalBody []byte
	var corrupt atomic.Bool
	posts := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer "+credential {
			t.Error("owner credential missing")
			http.Error(w, "no", 401)
			return
		}
		if r.Method == "POST" {
			posts++
			body, err := io.ReadAll(r.Body)
			if err != nil {
				t.Error(err)
			}
			if originalBody == nil {
				originalBody = body
			} else if !bytes.Equal(originalBody, body) {
				t.Error("original request bytes changed")
			}
			got := r.Header.Get("Idempotency-Key")
			if !validHex(got, 12) || (key != "" && key != got) {
				t.Error("original key changed")
			}
			key = got
			if posts == 1 {
				http.Error(w, "uncertain", 503)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"ok","artifact_url":"/api/v1/artifacts/abcdef123456.o"}`))
			return
		}
		if r.URL.Path != "/api/v1/artifacts/abcdef123456.o" {
			t.Error("wrong artifact")
		}
		digest := sha256.Sum256([]byte("object"))
		if corrupt.Load() {
			digest = sha256.Sum256([]byte("different"))
		}
		w.Header().Set("ETag", `"sha256-`+hex.EncodeToString(digest[:])+`"`)
		_, _ = w.Write([]byte("object"))
	}))
	defer upstream.Close()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeCompileIndex(dir, []string{}); err != nil {
		t.Fatal(err)
	}
	cap := strings.Repeat("a", 64)
	mediator, err := NewCompileMediator(dir, upstream.URL, credential, cap, 1, []string{"gcc"})
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("b", 64)
	body := `{"compiler":"gcc","source":"int x = 1 < 2;","flags":[],"filename":"a.c","emit_assembly":false}`
	send := func(method, path, capability string, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, bytes.NewBufferString(body))
		req.Header.Set("X-Rebrew-Job-Capability", capability)
		req.Header.Set("X-Rebrew-Compile-Intent", id)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		mediator.ServeHTTP(w, req)
		return w
	}
	if got := send("POST", "/api/v1/compile", "wrong", body).Code; got != 401 {
		t.Fatal(got)
	}
	if got := send("POST", "/api/v1/compile", cap, body).Code; got != 503 {
		t.Fatal(got)
	}
	if got := send("POST", "/api/v1/compile", cap, body).Code; got != 409 || posts != 1 {
		t.Fatal("implicit retry")
	}
	other := httptest.NewRequest("POST", "/api/v1/compile", strings.NewReader(body))
	other.Header.Set("X-Rebrew-Job-Capability", cap)
	other.Header.Set("X-Rebrew-Compile-Intent", strings.Repeat("f", 64))
	other.Header.Set("Content-Type", "application/json")
	blocked := httptest.NewRecorder()
	mediator.ServeHTTP(blocked, other)
	if blocked.Code != 409 || posts != 1 {
		t.Fatal("new compile crossed unresolved original")
	}
	raw, err := os.ReadFile(filepath.Join(dir, id+".json"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte(credential)) || bytes.Contains(raw, []byte(cap)) {
		t.Fatal("credential retained")
	}
	var original compileOriginal
	if json.Unmarshal(raw, &original) != nil || original.Key != key {
		t.Fatal("original missing")
	}
	if err = mediator.Reconcile(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	blocked = httptest.NewRecorder()
	other = httptest.NewRequest("POST", "/api/v1/compile", strings.NewReader(body))
	other.Header.Set("X-Rebrew-Job-Capability", cap)
	other.Header.Set("X-Rebrew-Compile-Intent", strings.Repeat("f", 64))
	other.Header.Set("Content-Type", "application/json")
	mediator.ServeHTTP(blocked, other)
	if blocked.Code != 429 || posts != 2 {
		t.Fatal("compile budget not enforced")
	}
	if got := send("GET", "/api/v1/artifacts/abcdef123456.o", cap, ""); got.Code != 200 || got.Body.String() != "object" {
		t.Fatal("artifact not delivered")
	}
	corrupt.Store(true)
	if got := send("GET", "/api/v1/artifacts/abcdef123456.o", cap, "").Code; got != 503 {
		t.Fatal("artifact with wrong digest accepted")
	}
	if got := send("GET", "/api/v1/artifacts/abcdef123457.o", cap, "").Code; got != 404 {
		t.Fatal("foreign artifact accepted")
	}
	if got := send("POST", "/api/v1/compile", cap, body).Code; got != 200 || posts != 3 {
		t.Fatal("delivery did not reauthorize")
	}
}

func TestCompileMediatorSocketRejectsUnscopedCaller(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { t.Error("unexpected upstream request") }))
	defer upstream.Close()
	ledger, socket := t.TempDir(), t.TempDir()
	for _, dir := range []string{ledger, socket} {
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
	}
	m, err := NewCompileMediator(ledger, upstream.URL, "rck_secret", strings.Repeat("c", 64), 1, []string{"gcc"})
	if err != nil {
		t.Fatal(err)
	}
	server, listener, err := m.ServeSocket(socket)
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	defer listener.Close()
	client := &http.Client{Transport: &http.Transport{DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, "unix", filepath.Join(socket, "owner.sock"))
	}}}
	defer client.CloseIdleConnections()
	resp, err := client.Post("http://rebrew-job/api/v1/compile", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatal("unscoped socket caller accepted")
	}
}

func TestManagedCompileRecoveryRequiresOriginalCredentialAndConfiguration(t *testing.T) {
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Skip("docker client unavailable")
	}
	calls := 0
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if calls == 1 {
			http.Error(w, "uncertain", 503)
			return
		}
		_, _ = w.Write([]byte(`{"status":"error"}`))
	}))
	defer upstream.Close()
	root, dir := t.TempDir(), testJobDir(t)
	p := DockerProvider{Binary: docker, Image: "sha256:" + strings.Repeat("a", 64)}
	owner, err := OpenDocker(root, dir, p)
	if err != nil {
		t.Fatal(err)
	}
	if err = owner.ConfigureManagedCompile(upstream.URL, 1, []string{"gcc"}); err != nil {
		t.Fatal(err)
	}
	job := strings.Repeat("d", 64)
	credential := "rck_original_secret"
	sum := sha256.Sum256([]byte(credential))
	socket, err := owner.startManagedCompile(job, credential)
	if err != nil {
		t.Fatal(err)
	}
	receipt := Receipt{ID: job, State: "uncertain", Provider: "docker", Image: p.Image, ManagedCompile: true, CredentialSHA256: hex.EncodeToString(sum[:]), CompileSocket: socket, ContainerID: strings.Repeat("f", 64)}
	if err = owner.save(receipt); err != nil {
		t.Fatal(err)
	}
	intent := strings.Repeat("e", 64)
	req := httptest.NewRequest("POST", "/api/v1/compile", strings.NewReader(`{"compiler":"gcc","source":"int x;","flags":[],"filename":"a.c","emit_assembly":false}`))
	req.Header.Set("X-Rebrew-Job-Capability", owner.compileMediator.capability)
	req.Header.Set("X-Rebrew-Compile-Intent", intent)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	owner.compileMediator.ServeHTTP(w, req)
	if w.Code != 503 {
		t.Fatal("expected uncertain outcome")
	}
	owner.stopManagedCompile()
	if err = owner.Close(); err != nil {
		t.Fatal(err)
	}
	owner, err = OpenDocker(root, dir, p)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	if err = owner.ConfigureManagedCompile("http://127.0.0.1:2", 1, []string{"gcc"}); err != nil {
		t.Fatal(err)
	}
	if err = owner.ReconcileCompile(context.Background(), job, intent, credential); err == nil {
		t.Fatal("changed upstream accepted")
	}
	if err = owner.ConfigureManagedCompile(upstream.URL, 1, []string{"gcc"}); err != nil {
		t.Fatal(err)
	}
	if err = owner.ReconcileCompile(context.Background(), job, intent, "wrong"); err == nil || calls != 1 {
		t.Fatal("changed credential accepted")
	}
	pending, err := owner.compilePending(job)
	if err != nil || !pending {
		t.Fatal("uncertainty lost")
	}
	statuses, err := owner.CompileIntents(job)
	if err != nil || len(statuses) != 1 || statuses[0].Intent != intent || statuses[0].State != "unresolved" {
		t.Fatal("recovery identifier unavailable")
	}
	if _, err = owner.ReconcileDocker(context.Background(), job); err == nil || !strings.Contains(err.Error(), "compile outcome unresolved") {
		t.Fatal("unresolved remote work did not fence container recovery")
	}
	if err = owner.ReconcileCompile(context.Background(), job, intent, credential); err != nil {
		t.Fatal(err)
	}
	pending, err = owner.compilePending(job)
	if err != nil || pending || calls != 2 {
		t.Fatal("reconciliation not retained")
	}
	statuses, err = owner.CompileIntents(job)
	if err != nil || len(statuses) != 1 || statuses[0].State != "result_retained" {
		t.Fatal("reconciled result unavailable")
	}
	ledger := filepath.Join(dir, job+".compile", "ledger", intent+".json")
	data, err := os.ReadFile(ledger)
	if err != nil {
		t.Fatal(err)
	}
	var retained compileOriginal
	if json.Unmarshal(data, &retained) != nil {
		t.Fatal("invalid original")
	}
	before := retained.Body
	retained.Body = []byte(`{"compiler":"gcc","source":"changed"}`)
	changed, err := json.Marshal(retained)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(ledger, changed, 0600); err != nil {
		t.Fatal(err)
	}
	if err = owner.ReconcileCompile(context.Background(), job, intent, credential); err == nil || calls != 2 {
		t.Fatal("changed request accepted")
	}
	retained.Body = before
	retained.Result = []byte(`{"status":"ok","artifact_url":"https://foreign.example/object"}`)
	data, err = json.Marshal(retained)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(ledger, data, 0600); err != nil {
		t.Fatal(err)
	}
	pending, err = owner.compilePending(job)
	if err != nil || !pending {
		t.Fatal("invalid retained result released the fence")
	}
	if _, err = owner.CompileIntents(job); err == nil {
		t.Fatal("invalid result exposed as retained")
	}
	if err = os.Remove(ledger); err != nil {
		t.Fatal(err)
	}
	pending, err = owner.compilePending(job)
	if err != nil || !pending {
		t.Fatal("missing indexed original released the fence")
	}
	if _, err = owner.CompileIntents(job); err == nil {
		t.Fatal("missing indexed original hidden from recovery")
	}
}

func TestCompileMediatorDroppedReplyNeverRetries(t *testing.T) {
	var calls atomic.Int32
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		conn, _, err := w.(http.Hijacker).Hijack()
		if err != nil {
			t.Error(err)
			return
		}
		_ = conn.Close()
	}))
	defer upstream.Close()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeCompileIndex(dir, []string{}); err != nil {
		t.Fatal(err)
	}
	cap := strings.Repeat("a", 64)
	m, err := NewCompileMediator(dir, upstream.URL, "rck_test", cap, 2, []string{"gcc"})
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/v1/compile", strings.NewReader(`{"compiler":"gcc","source":"int x;","flags":[],"filename":"a.c"}`))
	req.Header.Set("X-Rebrew-Job-Capability", cap)
	req.Header.Set("X-Rebrew-Compile-Intent", strings.Repeat("b", 64))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	m.ServeHTTP(w, req)
	if w.Code != 503 || calls.Load() != 1 {
		t.Fatalf("lost response was retried or not fenced: status=%d calls=%d", w.Code, calls.Load())
	}
}

func TestCompileMediatorRecoversOriginalBeforeIndexCommit(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte(`{"status":"error"}`)) }))
	defer upstream.Close()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeCompileIndex(dir, []string{}); err != nil {
		t.Fatal(err)
	}
	cap := strings.Repeat("a", 64)
	credential := "rck_test"
	m, err := NewCompileMediator(dir, upstream.URL, credential, cap, 2, []string{"gcc"})
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("b", 64)
	sum := sha256.Sum256([]byte(credential))
	original := compileOriginal{Intent: id, Key: "abcdef123456", Body: []byte(`{"compiler":"gcc","source":"int x;","flags":[],"filename":"a.c"}`), CredentialSHA256: hex.EncodeToString(sum[:])}
	bodySum := sha256.Sum256(original.Body)
	original.BodySHA256 = hex.EncodeToString(bodySum[:])
	if err = m.writeOriginal(original); err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest("POST", "/api/v1/compile", bytes.NewReader(original.Body))
	req.Header.Set("X-Rebrew-Job-Capability", cap)
	req.Header.Set("X-Rebrew-Compile-Intent", strings.Repeat("c", 64))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	m.ServeHTTP(w, req)
	if w.Code != 409 {
		t.Fatal("unindexed original did not fence dispatch")
	}
	if err = m.Reconcile(context.Background(), id); err != nil {
		t.Fatal(err)
	}
	ids, err := readCompileIndex(dir)
	if err != nil || len(ids) != 1 || ids[0] != id {
		t.Fatal("original index was not recovered")
	}
}

// TestReconcileCompileReleasesOwnerLockDuringUpstreamCall pins the lock scope:
// the owner lock guards custody, not a network round trip, so a status read
// must not wait for the whole replay.
func TestReconcileCompileReleasesOwnerLockDuringUpstreamCall(t *testing.T) {
	root, dir := t.TempDir(), testJobDir(t)
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	owner, err := Open(root, dir, executable)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()

	credential := "rck_reconcile_secret"
	job := strings.Repeat("d", 64)
	intent := strings.Repeat("e", 64)
	entered := make(chan struct{}, 1)
	release := make(chan struct{})
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"error"}`))
	}))
	defer upstream.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()

	base := filepath.Join(dir, job+".compile")
	ledger := filepath.Join(base, "ledger")
	if err = os.MkdirAll(ledger, 0700); err != nil {
		t.Fatal(err)
	}
	if err = writeCompileIndex(ledger, []string{intent}); err != nil {
		t.Fatal(err)
	}
	config := managedCompileConfig{Upstream: upstream.URL, Max: 1, Allowed: []string{"gcc"}}
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(filepath.Join(base, "config.json"), data, 0600); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(credential))
	body := []byte(`{"compiler":"gcc","source":"int x;","flags":[],"filename":"a.c","emit_assembly":false}`)
	bodySum := sha256.Sum256(body)
	original := compileOriginal{Intent: intent, Key: "abcdef123456", Body: body, BodySHA256: hex.EncodeToString(bodySum[:]), CredentialSHA256: hex.EncodeToString(sum[:])}
	if err = writeJSONAtomic(ledger, ".compile-", intent+".json", original); err != nil {
		t.Fatal(err)
	}

	owner.mu.Lock()
	owner.compileConfig = &config
	err = owner.save(Receipt{ID: job, State: "uncertain", ManagedCompile: true, CredentialSHA256: hex.EncodeToString(sum[:])})
	owner.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}

	reconciled := make(chan error, 1)
	go func() { reconciled <- owner.ReconcileCompile(context.Background(), job, intent, credential) }()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("replay never reached the upstream")
	}
	status := make(chan error, 1)
	start := time.Now()
	go func() { _, err := owner.Get(job); status <- err }()
	select {
	case err = <-status:
		if err != nil {
			t.Fatal(err)
		}
		if elapsed := time.Since(start); elapsed > 400*time.Millisecond {
			t.Fatalf("job status waited %s for the compile replay", elapsed)
		}
	case <-time.After(2 * time.Second):
		close(release)
		t.Fatal("job status blocked on the compile replay")
	}
	close(release)
	select {
	case err = <-reconciled:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("compile reconciliation did not finish")
	}
}
