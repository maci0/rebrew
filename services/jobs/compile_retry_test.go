package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// fakeAnswer is one scripted upstream answer.
type fakeAnswer struct {
	status     int
	retryAfter string
	body       string
}

// fakeRecompile answers POST /api/v1/compile as recompile's hosted profile
// does: a 200 answer is retained under its Idempotency-Key and read back for
// every later request with that key; a 429 or 503 is not retained. script
// holds the answers of the requests that reach it in turn; past its end every
// request compiles.
type fakeRecompile struct {
	mu       sync.Mutex
	script   []fakeAnswer
	retained map[string]fakeAnswer
	keys     []string
}

const fakeCompiled = `{"status":"ok","artifact_url":"/api/v1/artifacts/abcdef123456.o"}`

func (f *fakeRecompile) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	key := r.Header.Get("Idempotency-Key")
	f.keys = append(f.keys, key)
	a, ok := f.retained[key]
	if !ok {
		a = fakeAnswer{status: 200, body: fakeCompiled}
		if len(f.script) > 0 {
			a, f.script = f.script[0], f.script[1:]
		}
		if a.status == 200 {
			f.retained[key] = a
		}
	}
	if a.retryAfter != "" {
		w.Header().Set("Retry-After", a.retryAfter)
	}
	w.WriteHeader(a.status)
	_, _ = io.WriteString(w, a.body)
}

func (f *fakeRecompile) sentKeys() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.keys...)
}

// retryMediator is a mediator over upstream with a private ledger and budget max.
func retryMediator(t *testing.T, upstream http.Handler, max int) (*CompileMediator, string) {
	t.Helper()
	server := httptest.NewServer(upstream)
	t.Cleanup(server.Close)
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeCompileIndex(dir, []string{}); err != nil {
		t.Fatal(err)
	}
	m, err := NewCompileMediator(dir, server.URL, "rck_retry_secret", strings.Repeat("a", 64), max, []string{"gcc"})
	if err != nil {
		t.Fatal(err)
	}
	return m, dir
}

// compileIntent posts source as intent through m, as the worker does.
func compileIntent(m *CompileMediator, intent, source string) *httptest.ResponseRecorder {
	body := `{"compiler":"gcc","source":"` + source + `","flags":[],"filename":"a.c","emit_assembly":false}`
	req := httptest.NewRequest("POST", "/api/v1/compile", strings.NewReader(body))
	req.Header.Set("X-Rebrew-Job-Capability", m.capability)
	req.Header.Set("X-Rebrew-Compile-Intent", intent)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	m.ServeHTTP(w, req)
	return w
}

func retainedIntent(t *testing.T, dir, intent string) compileOriginal {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(dir, intent+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var v compileOriginal
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	return v
}

// One throttle and one capacity refusal used to fail the whole job: the
// throttled intent stayed unresolved and fenced every other intent with 409,
// and the capacity answer was retained as the intent's verdict and replayed
// under the same key to every retry. Each refusal now says no verdict, the
// retry draws a new key, and the other intents compile.
func TestCompileMediatorOneRefusalDoesNotFailTheJob(t *testing.T) {
	upstream := &fakeRecompile{retained: map[string]fakeAnswer{}, script: []fakeAnswer{
		{status: 429, retryAfter: "7", body: `{"detail":"too many failed compiles"}`},
		{status: 200, retryAfter: "5", body: `{"status":"error","error_code":"capacity","artifact_url":null,"log":""}`},
	}}
	m, dir := retryMediator(t, upstream, 3)
	a, b, c := strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64)

	throttled := compileIntent(m, a, "int a;")
	if throttled.Code != 429 || throttled.Header().Get("Retry-After") != "7" {
		t.Fatalf("throttle not relayed: %d %q", throttled.Code, throttled.Header().Get("Retry-After"))
	}
	refused := compileIntent(m, b, "int b;")
	if refused.Code != 200 || refused.Header().Get("Retry-After") != "5" || !strings.Contains(refused.Body.String(), `"capacity"`) {
		t.Fatalf("capacity not relayed: %d %q %s", refused.Code, refused.Header().Get("Retry-After"), refused.Body.String())
	}
	for _, intent := range []string{a, b} {
		if v := retainedIntent(t, dir, intent); !compileNotRun(v) {
			t.Fatalf("refusal retained as a verdict: %+v", v)
		}
	}
	for _, step := range []struct{ intent, source string }{{a, "int a;"}, {b, "int b;"}, {c, "int c;"}} {
		if w := compileIntent(m, step.intent, step.source); w.Code != 200 || w.Body.String() != fakeCompiled {
			t.Fatalf("intent %s after the refusals: %d %s", step.intent[:1], w.Code, w.Body.String())
		}
	}
	keys := upstream.sentKeys()
	seen := map[string]bool{}
	for _, key := range keys {
		if seen[key] {
			t.Fatalf("a key was sent twice: %v", keys)
		}
		seen[key] = true
	}
	if len(keys) != 5 {
		t.Fatalf("upstream requests: %v", keys)
	}
	if w := compileIntent(m, b, "int b;"); w.Code != 200 || w.Body.String() != fakeCompiled {
		t.Fatalf("retained result not replayed: %d", w.Code)
	}
	if got := upstream.sentKeys(); got[len(got)-1] != keys[3] {
		t.Fatal("replay did not read the verdict back under its own key")
	}
}

// An unresolved attempt is resent under its own key, never a new one, until
// the upstream answers it; a throttle in between says nothing about that
// attempt and keeps the key.
func TestCompileMediatorResendsUnresolvedKey(t *testing.T) {
	upstream := &fakeRecompile{retained: map[string]fakeAnswer{}, script: []fakeAnswer{
		{status: 503, retryAfter: "5", body: `{"detail":"managed compile evidence is unavailable; retry the same key"}`},
		{status: 200, body: fakeCompiled},
		{status: 429, retryAfter: "3", body: `{"detail":"rate limit"}`},
	}}
	m, dir := retryMediator(t, upstream, 2)
	a := strings.Repeat("1", 64)
	if w := compileIntent(m, a, "int a;"); w.Code != 503 || w.Header().Get("Retry-After") != "5" {
		t.Fatalf("lost settlement: %d %q", w.Code, w.Header().Get("Retry-After"))
	}
	if w := compileIntent(m, strings.Repeat("2", 64), "int b;"); w.Code != 200 {
		t.Fatalf("unresolved intent fenced another: %d", w.Code)
	}
	if w := compileIntent(m, a, "int a;"); w.Code != 429 || w.Header().Get("Retry-After") != "3" {
		t.Fatalf("throttle on resend: %d", w.Code)
	}
	if v := retainedIntent(t, dir, a); compileNotRun(v) || len(v.Result) != 0 {
		t.Fatalf("throttle settled an unresolved key: %+v", v)
	}
	if w := compileIntent(m, a, "int a;"); w.Code != 200 || w.Body.String() != fakeCompiled {
		t.Fatalf("unresolved key not reconciled: %d", w.Code)
	}
	keys := upstream.sentKeys()
	if len(keys) != 4 || keys[0] != keys[2] || keys[0] != keys[3] || keys[0] == keys[1] {
		t.Fatalf("unresolved key not resent: %v", keys)
	}
	if err := m.Reconcile(context.Background(), a); err != nil || len(upstream.sentKeys()) != 4 {
		t.Fatalf("reconcile of a retained result went upstream: %v", err)
	}
}

// The worker waits out capacity until its deadline, so one intent may be sent
// many times: each capacity refusal is relayed with its Retry-After, the next
// attempt draws a new key, and none spends the job's budget of one intent.
func TestCompileMediatorWaitingOutCapacitySpendsNoBudget(t *testing.T) {
	capacity := fakeAnswer{status: 200, retryAfter: "5", body: `{"status":"error","error_code":"capacity","artifact_url":null,"log":"managed engine at physical capacity"}`}
	upstream := &fakeRecompile{retained: map[string]fakeAnswer{}, script: []fakeAnswer{capacity, capacity, capacity, capacity, capacity}}
	m, _ := retryMediator(t, upstream, 1)
	a := strings.Repeat("1", 64)
	for range 5 {
		if w := compileIntent(m, a, "int a;"); w.Code != 200 || w.Header().Get("Retry-After") != "5" || !strings.Contains(w.Body.String(), `"capacity"`) {
			t.Fatalf("capacity not relayed: %d %q %s", w.Code, w.Header().Get("Retry-After"), w.Body.String())
		}
	}
	if w := compileIntent(m, a, "int a;"); w.Code != 200 || w.Body.String() != fakeCompiled {
		t.Fatalf("intent after the waits: %d %s", w.Code, w.Body.String())
	}
	keys := upstream.sentKeys()
	seen := map[string]bool{}
	for _, key := range keys {
		seen[key] = true
	}
	if len(keys) != 6 || len(seen) != 6 {
		t.Fatalf("each attempt needs its own key: %v", keys)
	}
}

// Recompile caps a result's log at 4 MiB; JSON escaping and the envelope make
// the answer larger than the log.
func TestCompileMediatorDeliversLargestDocumentedLog(t *testing.T) {
	const line, lineBytes = `warning C4100\r\n\"x\"\t`, 19 // JSON text, decoded UTF-8 bytes
	log := strings.Repeat(line, 4<<20/lineBytes)
	body := `{"status":"error","error_code":"toolchain_failure","artifact_url":null,"log":"` + log + `"}`
	upstream := &fakeRecompile{retained: map[string]fakeAnswer{}, script: []fakeAnswer{{status: 200, body: body}}}
	m, _ := retryMediator(t, upstream, 1)
	w := compileIntent(m, strings.Repeat("1", 64), "int a;")
	var got struct {
		Log string `json:"log"`
	}
	if w.Code != 200 || w.Body.String() != body || json.Unmarshal(w.Body.Bytes(), &got) != nil || len(got.Log) < 4<<20-lineBytes {
		t.Fatalf("large log: %d, %d bytes", w.Code, w.Body.Len())
	}
}

// A spent budget is permanent for the job, so it is not a throttle.
func TestCompileMediatorBudgetIsNotRetryable(t *testing.T) {
	upstream := &fakeRecompile{retained: map[string]fakeAnswer{}}
	m, _ := retryMediator(t, upstream, 1)
	if w := compileIntent(m, strings.Repeat("1", 64), "int a;"); w.Code != 200 {
		t.Fatal(w.Code)
	}
	w := compileIntent(m, strings.Repeat("2", 64), "int b;")
	if w.Code != http.StatusForbidden || w.Header().Get("Retry-After") != "" || len(upstream.sentKeys()) != 1 {
		t.Fatalf("budget: %d %q", w.Code, w.Header().Get("Retry-After"))
	}
}

// An intent refused without a verdict holds nothing upstream, so it does not
// fence the job's capacity; an unresolved one does until it is reconciled.
func TestCompileNotRunIntentDoesNotFenceTheJob(t *testing.T) {
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
	credential := "rck_retry_secret"
	job := strings.Repeat("d", 64)
	ledger := filepath.Join(dir, job+".compile", "ledger")
	if err = os.MkdirAll(ledger, 0700); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(credential))
	owner.mu.Lock()
	err = owner.save(Receipt{ID: job, State: "uncertain", ManagedCompile: true, CredentialSHA256: hex.EncodeToString(sum[:])})
	owner.mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	m, err := NewCompileMediator(ledger, "http://127.0.0.1:2", credential, strings.Repeat("a", 64), 2, []string{"gcc"})
	if err != nil {
		t.Fatal(err)
	}
	notRun, unresolved := strings.Repeat("1", 64), strings.Repeat("2", 64)
	body := []byte(`{"compiler":"gcc","source":"int a;","flags":[],"filename":"a.c","emit_assembly":false}`)
	bodySum := sha256.Sum256(body)
	retain := func(v compileOriginal, ids ...string) {
		t.Helper()
		v.Body, v.BodySHA256, v.CredentialSHA256 = body, hex.EncodeToString(bodySum[:]), hex.EncodeToString(sum[:])
		if err := m.writeOriginal(v); err != nil {
			t.Fatal(err)
		}
		if err := writeCompileIndex(ledger, ids); err != nil {
			t.Fatal(err)
		}
	}
	retain(compileOriginal{Intent: notRun, Key: "abcdef123456", NotRun: true, LastHTTPStatus: 200}, notRun)
	if pending, err := owner.compilePending(job); err != nil || pending {
		t.Fatalf("not-run intent fenced the job: %v %v", pending, err)
	}
	retain(compileOriginal{Intent: unresolved, Key: "abcdef654321", LastHTTPStatus: 503}, notRun, unresolved)
	if pending, err := owner.compilePending(job); err != nil || !pending {
		t.Fatal("unresolved intent released the fence")
	}
	statuses, err := owner.CompileIntents(job)
	if err != nil || len(statuses) != 2 || statuses[0].State != "not_run" || statuses[1].State != "unresolved" || statuses[1].UpstreamHTTPStatus != 503 {
		t.Fatalf("intent states: %+v %v", statuses, err)
	}
	if err = m.Reconcile(context.Background(), notRun); err != nil {
		t.Fatalf("a not-run intent needs no reconciliation: %v", err)
	}
	if err = m.Reconcile(context.Background(), unresolved); err == nil {
		t.Fatal("unreachable upstream reconciled the intent")
	}
}

// Recompile 12 can report delivery_denied or result_unavailable after settling
// a compile as billed. Neither refusal proves the key is free, even after an
// earlier ambiguous attempt, so every retry must resend that key.
func TestCompileMediatorKeepsBilledRefusalKeyAfterUnresolvedAttempt(t *testing.T) {
	for _, c := range []struct {
		status int
		code   string
	}{
		{http.StatusForbidden, "delivery_denied"},
		{http.StatusConflict, "result_unavailable"},
	} {
		refusal := fakeAnswer{status: c.status, body: `{"detail":"refused","code":"` + c.code + `"}`}
		upstream := &fakeRecompile{retained: map[string]fakeAnswer{}, script: []fakeAnswer{
			{status: http.StatusServiceUnavailable, body: `{"detail":"outcome unknown"}`},
			refusal,
			{status: http.StatusOK, body: fakeCompiled},
		}}
		m, dir := retryMediator(t, upstream, 1)
		intent := strings.Repeat("1", 64)
		for i, want := range []int{http.StatusServiceUnavailable, c.status, http.StatusOK} {
			if w := compileIntent(m, intent, "int a;"); w.Code != want {
				t.Fatalf("%s attempt %d: got %d, want %d", c.code, i, w.Code, want)
			}
		}
		keys := upstream.sentKeys()
		if len(keys) != 3 || keys[0] != keys[1] || keys[1] != keys[2] {
			t.Fatalf("%s changed a possibly billed key: %v", c.code, keys)
		}
		if v := retainedIntent(t, dir, intent); compileNotRun(v) || len(v.Result) == 0 {
			t.Fatalf("%s settled the intent without a verdict: %+v", c.code, v)
		}
	}
}

// Recompile 11 says with a code that a key can never yield a result and billed
// nothing (the admission expired): such a refusal settles even a key an earlier
// attempt left unresolved, and the next attempt draws a new key.
// settlement_pending asks for the same key, and a refusal with another code
// says nothing about the first attempt. The worker gets recompile's code.
func TestCompileMediatorBranchesOnTheRefusalCode(t *testing.T) {
	refusal := func(status int, code, retryAfter string) fakeAnswer {
		return fakeAnswer{status: status, retryAfter: retryAfter, body: `{"detail":"refused","code":"` + code + `"}`}
	}
	upstream := &fakeRecompile{retained: map[string]fakeAnswer{}, script: []fakeAnswer{
		refusal(503, "settlement_pending", "5"),
		refusal(409, "admission_expired", ""),
		{status: 200, body: fakeCompiled},
		refusal(503, "runtime_unavailable", "5"),
		refusal(409, "admission_abandoned", ""),
		{status: 200, body: fakeCompiled},
		refusal(503, "platform_unavailable", "5"),
		refusal(403, "forbidden", ""),
	}}
	m, dir := retryMediator(t, upstream, 3)
	a, b, c := strings.Repeat("1", 64), strings.Repeat("2", 64), strings.Repeat("3", 64)
	codeOf := func(w *httptest.ResponseRecorder) string {
		var body struct {
			Code string `json:"code"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		return body.Code
	}
	steps := []struct {
		intent, source string
		status         int
		code           string
	}{
		{a, "int a;", 503, "settlement_pending"},
		{a, "int a;", 409, "admission_expired"},
		{a, "int a;", 200, ""},
		{b, "int b;", 503, "runtime_unavailable"},
		{b, "int b;", 409, "admission_abandoned"},
		{b, "int b;", 200, ""},
		{c, "int c;", 503, "platform_unavailable"},
		{c, "int c;", 403, "forbidden"},
	}
	for i, s := range steps {
		w := compileIntent(m, s.intent, s.source)
		if w.Code != s.status || s.code != "" && codeOf(w) != s.code {
			t.Fatalf("step %d: %d %s", i, w.Code, w.Body.String())
		}
	}
	if v := retainedIntent(t, dir, c); compileNotRun(v) {
		t.Fatal("a forbidden refusal settled an unresolved key")
	}
	keys := upstream.sentKeys()
	if keys[0] != keys[1] || keys[1] == keys[2] || keys[3] != keys[4] || keys[4] == keys[5] || keys[6] != keys[7] {
		t.Fatalf("keys: %v", keys)
	}
	if w := compileIntent(m, c, "int c;"); w.Code != 200 || upstream.sentKeys()[8] != keys[6] {
		t.Fatalf("unresolved key not resent: %d %v", w.Code, upstream.sentKeys())
	}
}
