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
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"slices"
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

// compileOriginal is one retained compile intent. Key is the Idempotency-Key
// of its current attempt. The intent is in one of three states:
//
//   - result retained (Result set): the upstream's verdict, replayed under Key;
//   - not run (NotRun): Key's attempt was refused without a verdict, and the
//     next attempt draws a new key (recompile keeps the refusal under Key);
//   - unresolved (neither): Key may be admitted upstream with an unknown
//     outcome, so every later attempt resends Key, which compiles and bills
//     at most once.
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
	NotRun           bool   `json:"not_run,omitempty"`
	// Attribution is the attribution header of the request that created the
	// intent, sent with every attempt, a Reconcile resend included.
	Attribution string `json:"attribution,omitempty"`
}

// maxCompileReplyBytes bounds one upstream compile answer. Recompile caps a
// result's log at 4 MiB of UTF-8 (docs/API.md, CompileResult) and retains a
// managed result of at most 16 MiB of JSON, so the log with its JSON escaping
// and the envelope fits.
const maxCompileReplyBytes = 16 << 20

// notRunCodes are the error_code values of a 200 answer that is no verdict on
// the source. Recompile retains that refusal under its Idempotency-Key, so a
// new attempt needs a new key (docs/API.md, "Reading a failed compile").
var notRunCodes = map[string]bool{
	"capacity": true, "timeout": true, "runner_unavailable": true, "publish_failed": true, "provenance_unavailable": true,
}

// maxRetryAfterDigits bounds a relayed Retry-After: delta-seconds only.
const maxRetryAfterDigits = 6

// compileAnswer is what the worker is told about one exchange: the upstream
// result on 200, else detail and the upstream's error code, and the
// upstream's Retry-After when it sent delta-seconds.
type compileAnswer struct {
	status     int
	body       []byte
	detail     string
	code       string
	retryAfter string
}

// spentKeyCodes are the error codes of a refusal that says the key can never
// yield a result, so the next attempt needs a new key (recompile 11 docs/API.md,
// "Error codes": the admission ended before dispatch, passed its payment
// deadline, has no local record or ended without a retained result, or the
// current credential may not receive the result).
var spentKeyCodes = map[string]bool{
	"admission_abandoned": true, "admission_expired": true, "admission_unrecoverable": true,
	"result_unavailable": true, "delivery_denied": true,
}

// errorCodePattern is the shape of recompile's error codes; another value is
// not relayed.
var errorCodePattern = regexp.MustCompile(`^[a-z][a-z_]{0,63}$`)

// errorCode is the `code` of a recompile error body, or "" when it has none.
func errorCode(body []byte) string {
	var refusal struct {
		Code string `json:"code"`
	}
	if json.Unmarshal(body, &refusal) != nil || !errorCodePattern.MatchString(refusal.Code) {
		return ""
	}
	return refusal.Code
}

// unresolvedAnswer is an exchange whose outcome under its key is unknown: the
// worker may retry the intent, which resends the same key.
func unresolvedAnswer(code, retryAfter string) compileAnswer {
	return compileAnswer{status: http.StatusServiceUnavailable, detail: "compile outcome unresolved", code: code, retryAfter: retryAfter}
}

// relayRetryAfter is the upstream Retry-After when it is delta-seconds, else "".
func relayRetryAfter(value string) string {
	if value == "" || len(value) > maxRetryAfterDigits || strings.Trim(value, "0123456789") != "" {
		return ""
	}
	return value
}

// attributionHeader names the Workbench work a compile is for (rebrew
// recompile_client.ATTRIBUTION_HEADER); the mediator relays it upstream.
const attributionHeader = "X-Relumea-Attribution"

// maxAttributionMemberChars is the longest attribution member rebrew's
// Attribution accepts.
const maxAttributionMemberChars = 128

// validAttribution reports whether value is the JSON object rebrew's
// Attribution writes: exactly org, project, user and job, each 1 to
// maxAttributionMemberChars printable ASCII characters.
func validAttribution(value string) bool {
	// A map, not a struct: encoding/json matches struct fields without regard
	// to case, and rebrew refuses "Org".
	var members map[string]any
	dec := json.NewDecoder(strings.NewReader(value))
	if dec.Decode(&members) != nil || dec.Decode(new(any)) != io.EOF || len(members) != 4 {
		return false
	}
	for _, name := range []string{"org", "project", "user", "job"} {
		member, ok := members[name].(string)
		if !ok || len(member) < 1 || len(member) > maxAttributionMemberChars {
			return false
		}
		for _, c := range []byte(member) {
			if c < ' ' || c > '~' {
				return false
			}
		}
	}
	return true
}

func newCompileKey() (string, error) {
	var key [6]byte
	if _, err := rand.Read(key[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(key[:]), nil
}

// compileBody is recompile's CompileRequest. The bundle fields travel only
// when the source reads project headers; the upstream checks their bounds
// and path rules, and the body is forwarded as received (compacted).
type compileBody struct {
	Compiler        string        `json:"compiler"`
	Source          string        `json:"source"`
	Flags           []string      `json:"flags"`
	Filename        string        `json:"filename"`
	EmitAssembly    bool          `json:"emit_assembly"`
	TrainingConsent bool          `json:"training_consent"`
	SourceDir       string        `json:"source_dir,omitempty"`
	Includes        []includeFile `json:"includes,omitempty"`
}

// includeFile is one header of recompile's include bundle.
type includeFile struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

// featuresPath is where recompile lists its optional request features; a
// worker asks it before it sends an include bundle.
const featuresPath = "/api/v1/features"

// maxFeaturesBytes bounds the forwarded features document (a few dozen bytes).
const maxFeaturesBytes = 64 * 1024

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

// exchange sends v's body under v.Key and records what the answer says about
// the key. fresh says no earlier exchange left v.Key unresolved, so a 4xx
// refusal proves nothing was admitted under it. A result already retained is
// never replaced: a different answer is unresolved.
func (m *CompileMediator) exchange(ctx context.Context, v compileOriginal, fresh bool) (compileOriginal, compileAnswer) {
	start := time.Now()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, m.upstream+"/api/v1/compile", bytes.NewReader(v.Body))
	if err != nil {
		return v, unresolvedAnswer("", "")
	}
	req.Header.Set("Authorization", "Bearer "+m.credential)
	// Go's transport treats Idempotency-Key as retryable when GetBody is set.
	req.GetBody = nil
	req.Header.Set("Idempotency-Key", v.Key)
	req.Header.Set("Content-Type", "application/json")
	if v.Attribution != "" {
		req.Header.Set(attributionHeader, v.Attribution)
	}
	// Continue the caller's trace across the paid upstream hop: without the
	// header the upstream span starts a new trace and the billable compile
	// cannot be found from the trace that admitted it.  Only a well-formed
	// inbound traceparent is forwarded (validTraceparent).
	if tp, _ := ctx.Value(traceparentContextKey{}).(string); validTraceparent(tp) {
		req.Header.Set("traceparent", tp)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		log.Printf("level=error msg=compile_upstream_error intent=%q duration_ms=%d trace_id=%q error=%q", v.Intent, time.Since(start).Milliseconds(), traceIDFromContext(ctx), err.Error())
		return v, unresolvedAnswer("", "")
	}
	defer resp.Body.Close()
	retryAfter := relayRetryAfter(resp.Header.Get("Retry-After"))
	failed := func(why string) {
		log.Printf("level=error msg=compile_upstream_error intent=%q status=%d reason=%q duration_ms=%d trace_id=%q", v.Intent, resp.StatusCode, why, time.Since(start).Milliseconds(), traceIDFromContext(ctx))
	}
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxCompileReplyBytes+1))
	if err != nil || len(b) > maxCompileReplyBytes || resp.StatusCode != http.StatusOK && resp.StatusCode/100 != 4 {
		// A lost or oversized answer, or a 5xx (recompile's 503s, such as
		// settlement_pending, ask for the same key): the key may be admitted,
		// so it is kept.
		v.LastHTTPStatus = resp.StatusCode
		_ = m.writeOriginal(v)
		failed("unresolved")
		code := ""
		if err == nil && len(b) <= maxCompileReplyBytes {
			code = errorCode(b)
		}
		return v, unresolvedAnswer(code, retryAfter)
	}
	if resp.StatusCode != http.StatusOK {
		// A key no exchange left unresolved was not admitted, a spent-key code
		// says the key can never yield a result, and every other 409 says it
		// yields none under it (another request's key, retained bytes that are
		// not rebuilt): the next attempt draws a new key. Any other refusal says
		// nothing about an unresolved key's first attempt, which stays.
		code := errorCode(b)
		v.LastHTTPStatus = resp.StatusCode
		if len(v.Result) == 0 && (fresh || spentKeyCodes[code] || resp.StatusCode == http.StatusConflict) {
			v.NotRun = true
		}
		if err = m.writeOriginal(v); err != nil {
			return v, compileAnswer{status: http.StatusServiceUnavailable, detail: "ledger unavailable"}
		}
		failed("refused")
		return v, compileAnswer{status: resp.StatusCode, detail: "compile refused upstream", code: code, retryAfter: retryAfter}
	}
	var result struct {
		Status    string `json:"status"`
		Artifact  string `json:"artifact_url"`
		ErrorCode string `json:"error_code"`
	}
	if json.Unmarshal(b, &result) != nil || (result.Status != "ok" && result.Status != "error") ||
		result.Status == "ok" && !validArtifact(result.Artifact) || result.Status == "error" && result.Artifact != "" {
		failed("unreadable result")
		return v, unresolvedAnswer("", retryAfter)
	}
	if len(v.Result) != 0 && !bytes.Equal(v.Result, b) {
		failed("result differs from retained original")
		return v, unresolvedAnswer("", retryAfter)
	}
	v.LastHTTPStatus = resp.StatusCode
	if result.Status == "error" && notRunCodes[result.ErrorCode] {
		v.NotRun = true
	} else {
		v.Result = append([]byte(nil), b...)
		resultSum := sha256.Sum256(b)
		v.ResultSHA256 = hex.EncodeToString(resultSum[:])
		v.Artifact = result.Artifact
	}
	if err = m.writeOriginal(v); err != nil {
		return v, compileAnswer{status: http.StatusServiceUnavailable, detail: "compile result retention unresolved"}
	}
	log.Printf("level=info msg=compile_upstream_ok intent=%q status=%d result=%q error_code=%q duration_ms=%d trace_id=%q", v.Intent, resp.StatusCode, result.Status, result.ErrorCode, time.Since(start).Milliseconds(), traceIDFromContext(ctx))
	return v, compileAnswer{status: http.StatusOK, body: b, retryAfter: retryAfter}
}

type traceparentContextKey struct{}

// traceIDFromContext is the trace id of the inbound traceparent carried on
// ctx, or "" when the caller sent none.  The compile mediator stashes the
// inbound header on the context so the upstream hop and its log lines keep
// the trace an operator pivots from.
func traceIDFromContext(ctx context.Context) string {
	tp, _ := ctx.Value(traceparentContextKey{}).(string)
	return traceID(tp)
}

// forwardFeatures answers the upstream's features document, so a worker can
// tell whether the service takes an include bundle before it sends one. The
// route is public upstream: the owner credential is not sent. An upstream
// older than the route answers 404, and so does this; anything else that is
// not a bounded JSON document is the upstream's fault (502).
func (m *CompileMediator) forwardFeatures(w http.ResponseWriter, r *http.Request) {
	req, err := http.NewRequestWithContext(r.Context(), http.MethodGet, m.upstream+featuresPath, nil)
	if err != nil {
		apiError(w, "features unavailable", http.StatusBadGateway)
		return
	}
	if tp := r.Header.Get("traceparent"); validTraceparent(tp) {
		req.Header.Set("traceparent", tp)
	}
	resp, err := m.client.Do(req)
	if err != nil {
		apiError(w, "features unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNotFound {
		apiError(w, "not found", http.StatusNotFound)
		return
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeaturesBytes+1))
	var doc struct {
		Features []string `json:"features"`
	}
	if err != nil || resp.StatusCode != http.StatusOK || len(body) > maxFeaturesBytes || json.Unmarshal(body, &doc) != nil || doc.Features == nil {
		apiError(w, "features unavailable", http.StatusBadGateway)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if r.Method != http.MethodHead {
		_ = json.NewEncoder(w).Encode(doc)
	}
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

// index counts id against the job's budget once, before its first exchange.
func (m *CompileMediator) index(ids []string, id string) error {
	if slices.Contains(ids, id) {
		return nil
	}
	if len(ids) >= m.max {
		return errBudgetExhausted
	}
	return writeCompileIndex(m.dir, append(ids, id))
}

var errBudgetExhausted = errors.New("compile budget exhausted")

// Reconcile settles one unresolved intent after its job stopped: it resends
// the intent's key and body with the original credential, which reads the
// original attempt's outcome without compiling or billing it again. The job
// keeps its capacity fenced until every intent is settled (compilePending).
// Other intents, settled or not, do not affect this one.
func (m *CompileMediator) Reconcile(ctx context.Context, id string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	ids, err := readCompileIndex(m.dir)
	if err != nil {
		return err
	}
	v, err := m.readOriginal(id)
	if err != nil {
		return err
	}
	if len(v.Result) > 0 {
		if !compileResultValid(v) {
			return errors.New("invalid retained result")
		}
		return nil
	}
	if compileNotRun(v) {
		return nil
	}
	if err = m.index(ids, id); err != nil {
		return err
	}
	if v, _ = m.exchange(ctx, v, false); len(v.Result) == 0 && !compileNotRun(v) {
		return fmt.Errorf("compile outcome unresolved (upstream status %d)", v.LastHTTPStatus)
	}
	return nil
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
	w.Header().Set("X-Content-Type-Options", "nosniff")
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
		// The traceparent of this compile request rides the context so the
		// upstream hop (exchange) and its log lines keep the inbound trace.
		r = r.WithContext(context.WithValue(r.Context(), traceparentContextKey{}, r.Header.Get("traceparent")))
		id := r.Header.Get("X-Rebrew-Compile-Intent")
		if !validHex(id, 64) {
			apiError(w, "invalid intent", 400)
			return
		}
		attribution := r.Header.Get(attributionHeader)
		if attribution != "" && !validAttribution(attribution) {
			apiError(w, "invalid attribution", 400)
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
		// Each intent stands alone: another intent's unresolved or refused
		// attempt does not hold this one back.
		v, e := m.readOriginal(id)
		fresh := false
		switch {
		case e == nil && !bytes.Equal(v.Body, b):
			apiError(w, "intent names a different compile", 409)
			return
		case e == nil && compileNotRun(v):
			// The last attempt was refused without a verdict, and recompile
			// keeps that refusal under its key: this attempt is a new key.
			if v.Key, e = newCompileKey(); e != nil {
				apiError(w, "ledger unavailable", 503)
				return
			}
			v.NotRun, v.LastHTTPStatus, fresh = false, 0, true
		case e == nil:
			// A retained result is read back under its key, which re-checks
			// delivery; an unresolved attempt is resent under its key.
		case errors.Is(e, os.ErrNotExist):
			key, err := newCompileKey()
			if err != nil {
				apiError(w, "ledger unavailable", 503)
				return
			}
			sum := sha256.Sum256([]byte(m.credential))
			bodySum := sha256.Sum256(b)
			v = compileOriginal{Intent: id, Key: key, Body: append([]byte(nil), b...), BodySHA256: hex.EncodeToString(bodySum[:]), CredentialSHA256: hex.EncodeToString(sum[:]), Attribution: attribution}
			fresh = true
		default:
			apiError(w, "ledger unavailable", 503)
			return
		}
		if !slices.Contains(ids, id) && len(ids) >= m.max {
			// Permanent for this job: a retry cannot succeed, so no Retry-After.
			apiError(w, errBudgetExhausted.Error(), http.StatusForbidden)
			return
		}
		// The key is retained before it is sent, so a crash cannot lose it.
		if fresh {
			if e = m.writeOriginal(v); e != nil {
				apiError(w, "ledger unavailable", 503)
				return
			}
		}
		if e = m.index(ids, id); e != nil {
			apiError(w, "ledger unavailable", 503)
			return
		}
		v, answer := m.exchange(r.Context(), v, fresh)
		if answer.retryAfter != "" {
			w.Header().Set("Retry-After", answer.retryAfter)
		}
		log.Printf("level=info msg=compile_answered intent=%q compiler=%q key=%q status=%d not_run=%t result_retained=%t", v.Intent, payload.Compiler, v.Key, answer.status, v.NotRun, len(v.Result) > 0)
		if answer.status != http.StatusOK {
			// Recompile's error envelope, so the worker branches on the upstream code.
			body := map[string]any{"detail": answer.detail}
			if answer.code != "" {
				body["code"] = answer.code
			}
			writeAPIError(w, answer.status, body)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(answer.body)
		return
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && validArtifact(r.URL.Path) {
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
		if tp := r.Header.Get("traceparent"); validTraceparent(tp) {
			req.Header.Set("traceparent", tp)
		}
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
		if r.Method != http.MethodHead {
			_, _ = w.Write(body)
		}
		log.Printf("level=info msg=compile_artifact_ok intent=%q bytes=%d", id, len(body))
		return
	}
	if (r.Method == http.MethodGet || r.Method == http.MethodHead) && r.URL.Path == featuresPath {
		m.forwardFeatures(w, r)
		return
	}
	// Known path with wrong method: 405 with Allow, like the jobs API /
	// dashboard / ops on a served path, rather than 404 which would claim
	// the resource is missing.  HEAD mirrors GET (RFC 9110 §9.3.2) exactly
	// as the jobs API advertises Allow: GET, HEAD on its readable routes.
	if r.URL.Path == featuresPath {
		w.Header().Set("Allow", "GET, HEAD")
		apiError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.URL.Path == "/api/v1/compile" {
		w.Header().Set("Allow", http.MethodPost)
		apiError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	if validArtifact(r.URL.Path) {
		w.Header().Set("Allow", "GET, HEAD")
		apiError(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	apiError(w, "not found", http.StatusNotFound)
}
