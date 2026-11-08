package jobs

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// CompileMediator is one job's paid compilation boundary. The credential stays
// in this owner process; the worker receives only the per-job capability.
type CompileMediator struct {
	mu                                    sync.Mutex
	dir, upstream, credential, capability string
	max                                   int
	compilers                             map[string]bool
	client                                *http.Client
}

// ServeSocket exposes the job-scoped mediator on an already private directory.
// Closing the listener stops new requests; callers must also wait for active work.
func (m *CompileMediator) ServeSocket(dir string) (*http.Server, net.Listener, error) {
	info, err := os.Stat(dir)
	if err != nil || !isPrivateDir(info) || !validHex(m.capability, 64) {
		return nil, nil, errors.New("invalid private socket directory")
	}
	capFile, err := os.OpenFile(filepath.Join(dir, "capability"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0400)
	if err != nil {
		return nil, nil, err
	}
	if _, err = capFile.WriteString(m.capability); err == nil {
		err = capFile.Sync()
	}
	if closeErr := capFile.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return nil, nil, err
	}
	listener, err := net.Listen("unix", filepath.Join(dir, "owner.sock"))
	if err != nil {
		return nil, nil, err
	}
	if err = os.Chmod(filepath.Join(dir, "owner.sock"), 0600); err != nil {
		listener.Close()
		return nil, nil, err
	}
	server := &http.Server{Handler: m, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 180 * time.Second}
	go func() { _ = server.Serve(listener) }()
	return server, listener, nil
}

type compileOriginal struct {
	Intent           string `json:"intent"`
	Key              string `json:"key"`
	Body             []byte `json:"body"`
	BodySHA256       string `json:"body_sha256"`
	Result           []byte `json:"result,omitempty"`
	ResultSHA256     string `json:"result_sha256,omitempty"`
	Artifact         string `json:"artifact,omitempty"`
	CredentialSHA256 string `json:"credential_sha256"`
	LastHTTPStatus   int    `json:"last_http_status,omitempty"`
}

type compileBody struct {
	Compiler        string   `json:"compiler"`
	Source          string   `json:"source"`
	Flags           []string `json:"flags"`
	Filename        string   `json:"filename"`
	EmitAssembly    bool     `json:"emit_assembly"`
	TrainingConsent bool     `json:"training_consent"`
}

func readCompileIndex(dir string) ([]string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return nil, err
	}
	var ids []string
	if json.Unmarshal(b, &ids) != nil || ids == nil || len(ids) > 1000 {
		return nil, errors.New("invalid compile index")
	}
	seen := make(map[string]bool, len(ids))
	for _, id := range ids {
		if !validHex(id, 64) || seen[id] {
			return nil, errors.New("invalid compile index")
		}
		seen[id] = true
	}
	return ids, nil
}

func writeCompileIndex(dir string, ids []string) error {
	return writeJSONAtomic(dir, ".index-", "index.json", ids)
}

// NewCompileMediator opens private per-job custody with a pinned action budget.
// It never writes the upstream credential or worker capability to the ledger.
func NewCompileMediator(dir, upstream, credential, capability string, max int, allowed []string) (*CompileMediator, error) {
	u, err := url.Parse(upstream)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.Scheme != "https" && !(u.Scheme == "http" && (u.Hostname() == "127.0.0.1" || u.Hostname() == "::1"))) || u.Path != "" || len(credential) < 1 || strings.ContainsAny(credential, "\r\n") || len(capability) < 32 || strings.ContainsAny(capability, "\r\n") || max < 1 || max > 1000 || len(allowed) == 0 {
		return nil, errors.New("invalid compile mediator configuration")
	}
	info, err := os.Stat(dir)
	if err != nil || !isPrivateDir(info) {
		return nil, errors.New("compile ledger must be private")
	}
	compilers := make(map[string]bool, len(allowed))
	for _, c := range allowed {
		if c == "" {
			return nil, errors.New("empty compiler pin")
		}
		compilers[c] = true
	}
	return &CompileMediator{dir: dir, upstream: upstream, credential: credential, capability: capability, max: max, compilers: compilers, client: &http.Client{Transport: &http.Transport{DisableKeepAlives: true}, Timeout: 150 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}}, nil
}

func (m *CompileMediator) writeOriginal(v compileOriginal) error {
	return writeJSONAtomic(m.dir, ".compile-", v.Intent+".json", v)
}
func (m *CompileMediator) readOriginal(id string) (compileOriginal, error) {
	var v compileOriginal
	if !validHex(id, 64) {
		return v, errors.New("invalid intent")
	}
	b, e := os.ReadFile(filepath.Join(m.dir, id+".json"))
	if e != nil {
		return v, e
	}
	if json.Unmarshal(b, &v) != nil || v.Intent != id || !validHex(v.Key, 12) {
		return v, errors.New("invalid retained intent")
	}
	bodySum := sha256.Sum256(v.Body)
	if !json.Valid(v.Body) || v.BodySHA256 != hex.EncodeToString(bodySum[:]) {
		return v, errors.New("compile original changed")
	}
	if len(v.Result) > 0 {
		sum := sha256.Sum256(v.Result)
		if v.ResultSHA256 != hex.EncodeToString(sum[:]) {
			return v, errors.New("compile result changed")
		}
	}
	sum := sha256.Sum256([]byte(m.credential))
	if v.CredentialSHA256 != hex.EncodeToString(sum[:]) {
		return v, errors.New("credential does not match original")
	}
	return v, nil
}
func (m *CompileMediator) exchange(ctx context.Context, v compileOriginal) (compileOriginal, error) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.upstream+"/api/v1/compile", bytes.NewReader(v.Body))
	if err != nil {
		return v, err
	}
	req.Header.Set("Authorization", "Bearer "+m.credential)
	// Go's transport treats Idempotency-Key as retryable when GetBody is set.
	req.GetBody = nil
	req.Header.Set("Idempotency-Key", v.Key)
	req.Header.Set("Content-Type", "application/json")
	resp, err := m.client.Do(req)
	if err != nil {
		log.Printf("level=error msg=compile_upstream_error intent=%q duration_ms=%d error=%q", v.Intent, time.Since(start).Milliseconds(), err.Error())
		return v, errors.New("compile outcome unresolved")
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024+1))
	if err != nil || len(b) > 1024*1024 || resp.StatusCode != http.StatusOK {
		v.LastHTTPStatus = resp.StatusCode
		_ = m.writeOriginal(v)
		log.Printf("level=error msg=compile_upstream_error intent=%q status=%d duration_ms=%d", v.Intent, resp.StatusCode, time.Since(start).Milliseconds())
		return v, errors.New("compile outcome unresolved")
	}
	var result struct {
		Status   string `json:"status"`
		Artifact string `json:"artifact_url"`
	}
	if json.Unmarshal(b, &result) != nil || (result.Status != "ok" && result.Status != "error") {
		log.Printf("level=error msg=compile_upstream_error intent=%q status=%d duration_ms=%d", v.Intent, resp.StatusCode, time.Since(start).Milliseconds())
		return v, errors.New("compile outcome unresolved")
	}
	if result.Status == "ok" && !validArtifact(result.Artifact) {
		return v, errors.New("compile result artifact invalid")
	}
	if result.Status == "error" && result.Artifact != "" {
		return v, errors.New("compile result artifact invalid")
	}
	if len(v.Result) != 0 && !bytes.Equal(v.Result, b) {
		return v, errors.New("compile result differs from retained original")
	}
	v.Result = append([]byte(nil), b...)
	v.LastHTTPStatus = resp.StatusCode
	resultSum := sha256.Sum256(b)
	v.ResultSHA256 = hex.EncodeToString(resultSum[:])
	v.Artifact = result.Artifact
	if err = m.writeOriginal(v); err != nil {
		return v, errors.New("compile result retention unresolved")
	}
	log.Printf("level=info msg=compile_upstream_ok intent=%q status=%d result=%q duration_ms=%d", v.Intent, resp.StatusCode, result.Status, time.Since(start).Milliseconds())
	return v, nil
}
func validArtifact(p string) bool {
	const prefix = "/api/v1/artifacts/"
	if !strings.HasPrefix(p, prefix) {
		return false
	}
	name := strings.TrimPrefix(p, prefix)
	parts := strings.Split(name, ".")
	if len(parts) != 2 || !validHex(parts[0], 12) {
		return false
	}
	return parts[1] == "obj" || parts[1] == "o" || parts[1] == "exe" || parts[1] == "ne"
}

// Reconcile repeats only an explicitly selected original key and body.
func (m *CompileMediator) Reconcile(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids, err := readCompileIndex(m.dir)
	if err != nil {
		return err
	}
	indexed := make(map[string]bool, len(ids))
	for _, known := range ids {
		indexed[known] = true
	}
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Name() == "index.json" || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		other := strings.TrimSuffix(entry.Name(), ".json")
		if !indexed[other] && other != id {
			return errors.New("another compile remains unresolved")
		}
	}
	found := false
	for _, known := range ids {
		retained, err := m.readOriginal(known)
		if err != nil {
			return err
		}
		if known != id && !compileResultValid(retained) {
			return errors.New("another compile remains unresolved")
		}
		if known == id {
			found = true
		}
	}
	v, err := m.readOriginal(id)
	if err != nil {
		return err
	}
	if !found {
		if len(ids) >= m.max {
			return errors.New("compile budget exhausted")
		}
		ids = append(ids, id)
		if err = writeCompileIndex(m.dir, ids); err != nil {
			return err
		}
	}
	if len(v.Result) > 0 {
		if !compileResultValid(v) {
			return errors.New("invalid retained result")
		}
		return nil
	}
	_, err = m.exchange(ctx, v)
	return err
}

func (m *CompileMediator) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Same single-line shape as the job server's access log so both
	// services' logs parse with one query; the compile intent is the
	// correlation key for the paid upstream call.
	start := time.Now()
	status := 0
	rec := &statusRecorder{ResponseWriter: w, status: &status, method: r.Method}
	w = rec
	defer func() {
		s := status
		if s == 0 {
			s = http.StatusOK
		}
		intent := r.Header.Get("X-Rebrew-Compile-Intent")
		if !validHex(intent, 64) {
			intent = ""
		}
		level := "info"
		if s >= 500 {
			level = "error"
		} else if s >= 400 {
			level = "warning"
		}
		// Upstream compile is the only billable path; an operator needs its own
		// RED view, separate from job-admission counters, so an upstream burn-rate
		// spike does not hide inside a global error total.
		globalMetrics.recordFor("compile", s, float64(time.Since(start).Microseconds())/1000.0)
		log.Printf("level=%s msg=http_request method=%s path=%s status=%d duration_ms=%d intent=%q trace_id=%q", level, logEscape(r.Method), logEscape(r.URL.Path), s, time.Since(start).Milliseconds(), intent, traceID(r.Header.Get("traceparent")))
	}()
	if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-Rebrew-Job-Capability")), []byte(m.capability)) != 1 {
		apiError(w, "unauthorized", 401)
		return
	}
	w.Header().Set("Cache-Control", "no-store")
	m.mu.Lock()
	defer m.mu.Unlock()
	if r.Context().Err() != nil {
		return
	}
	// POST /api/v1/compile carries the JSON compile body.  A missing or
	// wrong Content-Type is a client mistake answered 415 here, before the
	// body is read, exactly as the jobs API and `rebrew ops serve` do.
	if r.Method == http.MethodPost {
		media := r.Header.Get("Content-Type")
		if i := strings.IndexByte(media, ';'); i >= 0 {
			media = media[:i]
		}
		if strings.TrimSpace(media) != "application/json" {
			apiError(w, "Content-Type must be application/json", http.StatusUnsupportedMediaType)
			return
		}
	}
	if r.Method == http.MethodPost && r.URL.Path == "/api/v1/compile" {
		id := r.Header.Get("X-Rebrew-Compile-Intent")
		if !validHex(id, 64) {
			apiError(w, "invalid intent", 400)
			return
		}
		b, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 16*1024*1024))
		if err != nil {
			apiError(w, "invalid body", 400)
			return
		}
		var payload compileBody
		dec := json.NewDecoder(bytes.NewReader(b))
		dec.DisallowUnknownFields()
		if dec.Decode(&payload) != nil || dec.Decode(new(any)) != io.EOF || !m.compilers[payload.Compiler] || payload.TrainingConsent {
			apiError(w, "compile refused", 400)
			return
		}
		var canonical bytes.Buffer
		if json.Compact(&canonical, b) != nil {
			apiError(w, "invalid body", 400)
			return
		}
		b = canonical.Bytes()
		ids, e := readCompileIndex(m.dir)
		if e != nil {
			apiError(w, "ledger unavailable", 503)
			return
		}
		indexed := make(map[string]bool, len(ids))
		for _, known := range ids {
			indexed[known] = true
			v, err := m.readOriginal(known)
			if err != nil || !json.Valid(v.Body) || !compileResultValid(v) {
				apiError(w, "prior compile remains unresolved", 409)
				return
			}
		}
		entries, e := os.ReadDir(m.dir)
		if e != nil {
			apiError(w, "ledger unavailable", 503)
			return
		}
		for _, entry := range entries {
			if entry.Name() == "index.json" || !strings.HasSuffix(entry.Name(), ".json") {
				continue
			}
			if !indexed[strings.TrimSuffix(entry.Name(), ".json")] {
				apiError(w, "prior compile remains unresolved", 409)
				return
			}
		}
		if old, e := m.readOriginal(id); e == nil {
			if !bytes.Equal(old.Body, b) || len(old.Result) == 0 {
				apiError(w, "original unresolved or changed", 409)
				return
			}
			old, e = m.exchange(r.Context(), old)
			if e != nil {
				apiError(w, "compile outcome unresolved", 503)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(old.Result)
			log.Printf("level=info msg=compile_replayed intent=%q", id)
			return
		} else if !errors.Is(e, os.ErrNotExist) {
			apiError(w, "ledger unavailable", 503)
			return
		}
		if len(ids) >= m.max {
			w.Header().Set("Retry-After", "5")
			apiError(w, "compile budget exhausted", 429)
			return
		}
		var key [6]byte
		if _, e = rand.Read(key[:]); e != nil {
			apiError(w, "ledger unavailable", 503)
			return
		}
		sum := sha256.Sum256([]byte(m.credential))
		bodySum := sha256.Sum256(b)
		v := compileOriginal{Intent: id, Key: hex.EncodeToString(key[:]), Body: append([]byte(nil), b...), BodySHA256: hex.EncodeToString(bodySum[:]), CredentialSHA256: hex.EncodeToString(sum[:])}
		if e = m.writeOriginal(v); e != nil {
			apiError(w, "ledger unavailable", 503)
			return
		}
		ids = append(ids, id)
		if e = writeCompileIndex(m.dir, ids); e != nil {
			apiError(w, "ledger unavailable", 503)
			return
		}
		v, e = m.exchange(r.Context(), v)
		if e != nil {
			apiError(w, "compile outcome unresolved", 503)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(v.Result)
		log.Printf("level=info msg=compile_admitted intent=%q compiler=%q key=%q", v.Intent, payload.Compiler, v.Key)
		return
	}
	if r.Method == http.MethodGet && validArtifact(r.URL.Path) {
		id := r.Header.Get("X-Rebrew-Compile-Intent")
		v, err := m.readOriginal(id)
		if err != nil || v.Artifact != r.URL.Path || len(v.Result) == 0 {
			apiError(w, "not found", http.StatusNotFound)
			return
		}
		req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, m.upstream+v.Artifact, nil)
		if err != nil {
			apiError(w, "artifact unavailable", 503)
			return
		}
		req.Header.Set("Authorization", "Bearer "+m.credential)
		resp, err := m.client.Do(req)
		if err != nil {
			apiError(w, "artifact unavailable", 503)
			return
		}
		defer resp.Body.Close()
		if resp.StatusCode != 200 {
			// Upstream failures are server/upstream faults, not client
			// mistakes: forwarding a 4xx verbatim would mislabel them.
			apiError(w, "artifact unavailable", http.StatusBadGateway)
			return
		}
		body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024*1024+1))
		if err != nil || len(body) > 64*1024*1024 {
			apiError(w, "artifact unavailable", 503)
			return
		}
		digest := sha256.Sum256(body)
		if resp.Header.Get("ETag") != `"sha256-`+hex.EncodeToString(digest[:])+`"` {
			apiError(w, "artifact integrity unavailable", 503)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		_, _ = w.Write(body)
		log.Printf("level=info msg=compile_artifact_ok intent=%q bytes=%d", id, len(body))
		return
	}
	// Known path with wrong method: 405 with Allow, like the jobs API /
	// dashboard / ops on a served path, rather than 404 which would claim
	// the resource is missing.
	if r.URL.Path == "/api/v1/compile" {
		w.Header().Set("Allow", http.MethodPost)
		apiError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if validArtifact(r.URL.Path) {
		w.Header().Set("Allow", http.MethodGet)
		apiError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	apiError(w, "not found", http.StatusNotFound)
}
