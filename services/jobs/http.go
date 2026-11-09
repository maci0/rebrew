package jobs

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// logEscape renders attacker-controlled text as one terminal-safe line:
// %q alone leaves \n verbatim when the probe sends it, forging a second
// log record. Escape controls and backslash, then quote.
func logEscape(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	for _, r := range s {
		switch {
		case r == '\\', r == '"':
			b.WriteByte('\\')
			b.WriteRune(r)
		case r < 0x20 || (r >= 0x7f && r < 0xa0):
			fmt.Fprintf(&b, "\\x%02x", r)
		default:
			b.WriteRune(r)
		}
	}
	return strconv.Quote(b.String())
}

var latencyBucketsMS = [4]float64{100, 1000, 10000, 60000}

type jobMetrics struct {
	mu             sync.Mutex
	requests       int64
	errors         int64
	serverErrors   int64
	clientErrors   int64
	latencyMsTotal float64
	latencyMsMax   float64
	buckets        [4]int64
	startedAt      time.Time
	// per-op availability for the two money/burn paths: a bare global error
	// counter cannot tell "compiles are failing" from "admission is busy".
	compileRequests     int64
	compileErrors       int64
	jobRequests         int64
	jobErrors           int64
	compileLatencyTotal float64
	compileLatencyMax   float64
}

var globalMetrics = &jobMetrics{startedAt: time.Now()}
var inFlight atomic.Int64

func metricsRouteOp(r *http.Request) string {
	if strings.HasPrefix(r.URL.Path, "/api/v1/compile") || strings.HasPrefix(r.URL.Path, "/api/v1/artifacts") {
		return "compile"
	}
	return "job"
}

func (m *jobMetrics) record(code int, ms float64) {
	m.recordFor("job", code, ms)
}

func (m *jobMetrics) recordFor(op string, code int, ms float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.requests++
	m.latencyMsTotal += ms
	if ms > m.latencyMsMax {
		m.latencyMsMax = ms
	}
	for i, b := range latencyBucketsMS {
		if ms <= b {
			m.buckets[i]++
			break
		}
		if i == len(latencyBucketsMS)-1 {
			m.buckets[i]++
		}
	}
	if op == "compile" {
		m.compileRequests++
		m.compileLatencyTotal += ms
		if ms > m.compileLatencyMax {
			m.compileLatencyMax = ms
		}
		if code >= 400 {
			m.compileErrors++
		}
	} else {
		m.jobRequests++
		if code >= 400 {
			m.jobErrors++
		}
	}
	if code >= 500 {
		m.serverErrors++
		m.errors++
	} else if code >= 400 {
		m.clientErrors++
		m.errors++
	}
}

func (m *jobMetrics) snapshot() (req, err, srv, cli int64, total, maxv, uptime float64, buckets [4]int64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.requests, m.errors, m.serverErrors, m.clientErrors, m.latencyMsTotal, m.latencyMsMax, time.Since(m.startedAt).Seconds(), m.buckets
}

func (m *jobMetrics) perOp() (compileReq, compileErr, jobReq, jobErr, compileTotal, compileMax float64) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return float64(m.compileRequests), float64(m.compileErrors), float64(m.jobRequests), float64(m.jobErrors), m.compileLatencyTotal, m.compileLatencyMax
}

// requestID returns the client's X-Request-ID when it is a well-formed single
// token, and otherwise mints one. Every admitted request then carries a
// non-empty correlation id in the access log that an operator can pivot on
// (a missing header previously logged request_id="" and could not be
// correlated with anything).

// traceID extracts the trace id from a W3C traceparent, or "" if absent/invalid.
func traceID(tp string) string {
	parts := strings.Split(tp, "-")
	if len(parts) != 4 || parts[0] != "00" || len(parts[1]) != 32 || len(parts[2]) != 16 {
		return ""
	}
	for _, p := range parts[1:3] {
		for _, c := range p {
			if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
				return ""
			}
		}
	}
	return parts[1]
}

// validTraceparent reports whether tp is a well-formed W3C traceparent a
// downstream call may continue.  The trace id alone (traceID) is not enough
// to forward: a truncated or non-hex header must not be re-emitted.
func validTraceparent(tp string) bool {
	parts := strings.Split(tp, "-")
	if len(parts) != 4 || parts[0] != "00" || len(parts[2]) != 16 || len(parts[3]) != 2 {
		return false
	}
	if traceID(tp) == "" || parts[1] == strings.Repeat("0", 32) || parts[2] == strings.Repeat("0", 16) {
		return false
	}
	for _, c := range parts[3] {
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return false
		}
	}
	return true
}

// jobLogContext carries the correlation ids of the HTTP request that
// admitted a job, so the asynchronous worker's lifecycle lines (started,
// finished, run errors) can be pivoted back to that request and trace.
type jobLogContext struct {
	requestID string
	traceID   string
}

type jobLogContextKey struct{}

func withJobLogContext(ctx context.Context, requestID, traceID string) context.Context {
	return context.WithValue(ctx, jobLogContextKey{}, jobLogContext{requestID: requestID, traceID: traceID})
}

func jobLogContextFrom(ctx context.Context) (requestID, traceID string) {
	if v, ok := ctx.Value(jobLogContextKey{}).(jobLogContext); ok {
		return v.requestID, v.traceID
	}
	return "", ""
}

// jobLogFields renders the correlation fields for the job lifecycle log
// lines: always request_id/trace_id keys (empty when the admission request
// carried none) so one log query matches every line of a job's life.
func jobLogFields(ctx context.Context) string {
	requestID, traceID := jobLogContextFrom(ctx)
	return fmt.Sprintf(" request_id=%q trace_id=%q", requestID, traceID)
}

func requestID(r *http.Request) string {
	id := r.Header.Get("X-Request-ID")
	if id == "" || len(id) > 128 || strings.ContainsAny(id, " \t\r\n") {
		var b [16]byte
		if _, err := rand.Read(b[:]); err != nil {
			return ""
		}
		if b[0] == 0 && b[1] == 0 && b[2] == 0 && b[3] == 0 && b[4] == 0 && b[5] == 0 && b[6] == 0 && b[7] == 0 && b[8] == 0 && b[9] == 0 && b[10] == 0 && b[11] == 0 && b[12] == 0 && b[13] == 0 && b[14] == 0 && b[15] == 0 {
			return ""
		}
		return fmt.Sprintf("%x", b)
	}
	return id
}

type statusRecorder struct {
	http.ResponseWriter
	status *int
	wrote  bool
	method string
}

// RequestMethod reports the request method so apiError can suppress a HEAD
// body; all other writers leave the method unknown and keep the body.
func (r *statusRecorder) RequestMethod() string { return r.method }

func (r *statusRecorder) WriteHeader(code int) {
	if !r.wrote {
		*r.status = code
		r.wrote = true
	}
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		*r.status = http.StatusOK
		r.wrote = true
	}
	return r.ResponseWriter.Write(b)
}

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

func (r *statusRecorder) SetWriteDeadline(t time.Time) error {
	if rc, ok := r.ResponseWriter.(interface{ SetWriteDeadline(time.Time) error }); ok {
		return rc.SetWriteDeadline(t)
	}
	return nil
}

// apiError answers one refusal in the service's single error envelope:
// {"error": detail, "code": status}.  Codes are the bare numeric status as a
// string because every documented client (and the tests) branch on the
// status line, not on a code name; detail is a fixed string safe to log,
// never an internal error.  http.Error is never used: it emits text/plain,
// which no JSON client can branch on uniformly.  A HEAD response carries the
// same headers as its GET but no body (RFC 9110 §9.3.2), matching the
// dashboard and ops servers.
func apiError(w http.ResponseWriter, detail string, status int) {
	// A statusRecorder knows the request method; a plain writer (the compile
	// mediator passes the recorder too) is probed for it.
	method := ""
	if r, ok := w.(interface{ RequestMethod() string }); ok {
		method = r.RequestMethod()
	}
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="rebrew-jobs"`)
	}
	w.WriteHeader(status)
	if method == http.MethodHead {
		return
	}
	_ = json.NewEncoder(w).Encode(map[string]any{"error": detail, "code": strconv.Itoa(status)})
}

func hostAllowed(host string) bool {
	if host == "" {
		return true
	}
	h := host
	if strings.Contains(h, ":") {
		var err error
		h, _, err = net.SplitHostPort(h)
		if err != nil {
			return false
		}
	}
	h = strings.Trim(h, "[]")
	switch strings.ToLower(h) {
	case "127.0.0.1", "localhost", "::1", "0.0.0.0", "::":
		return true
	}
	ip := net.ParseIP(h)
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return true
	}
	return false
}

func metricsAuthorized(r *http.Request, token string) bool {
	return subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) == 1
}

// Handler exposes one configured owner's local API; it is not a tenant authorization boundary.
func (o *Owner) Handler(token string) (http.Handler, error) {
	if len(token) < 32 {
		return nil, fmt.Errorf("job token must contain at least 32 bytes")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Health probes must not require auth: the orchestrator needs a
		// liveness signal that does not depend on the bearer token.  No
		// admission or credential is consulted; the owner already holds
		// the workspace seal and the job directory lock.
		if r.URL.Path == "/healthz" || r.URL.Path == "/health" {
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				apiError(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			req, errc, srv, cli, total, maxv, uptime, _ := globalMetrics.snapshot()
			avg := 0.0
			if req > 0 {
				avg = total / float64(req)
			}
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			if r.Method == http.MethodHead {
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "requests": req, "errors": errc, "server_errors": srv, "client_errors": cli, "latency_ms_avg": avg, "latency_ms_max": maxv, "uptime_seconds": uptime, "in_flight": inFlight.Load()})
			return
		}
		if r.URL.Path == "/metrics" {
			if !metricsAuthorized(r, token) {
				apiError(w, "unauthorized", http.StatusUnauthorized)
				return
			}
			if r.Method != http.MethodGet && r.Method != http.MethodHead {
				w.Header().Set("Allow", "GET, HEAD")
				apiError(w, "method not allowed", http.StatusMethodNotAllowed)
				return
			}
			req, errc, srv, cli, total, maxv, uptime, buckets := globalMetrics.snapshot()
			var b strings.Builder
			fmt.Fprintf(&b, "# HELP rebrew_jobs_requests_total Total jobs requests answered.\n# TYPE rebrew_jobs_requests_total counter\nrebrew_jobs_requests_total %d\n", req)
			fmt.Fprintf(&b, "# HELP rebrew_jobs_errors_total Total jobs requests answered with an error status.\n# TYPE rebrew_jobs_errors_total counter\nrebrew_jobs_errors_total %d\n", errc)
			fmt.Fprintf(&b, "# HELP rebrew_jobs_server_errors_total Total jobs requests answered with a 5xx status.\n# TYPE rebrew_jobs_server_errors_total counter\nrebrew_jobs_server_errors_total %d\n", srv)
			fmt.Fprintf(&b, "# HELP rebrew_jobs_client_errors_total Total jobs requests answered with a 4xx status.\n# TYPE rebrew_jobs_client_errors_total counter\nrebrew_jobs_client_errors_total %d\n", cli)
			fmt.Fprintf(&b, "# HELP rebrew_jobs_latency_ms_total Total latency of answered jobs requests, in milliseconds.\n# TYPE rebrew_jobs_latency_ms_total counter\nrebrew_jobs_latency_ms_total %.3f\n", total)
			fmt.Fprintf(&b, "# HELP rebrew_jobs_latency_ms_max Maximum latency of an answered jobs request, in milliseconds.\n# TYPE rebrew_jobs_latency_ms_max gauge\nrebrew_jobs_latency_ms_max %.3f\n", maxv)
			fmt.Fprintf(&b, "# HELP rebrew_jobs_uptime_seconds Seconds since the server started.\n# TYPE rebrew_jobs_uptime_seconds gauge\nrebrew_jobs_uptime_seconds %.3f\n", uptime)
			fmt.Fprintf(&b, "# HELP rebrew_jobs_in_flight Requests currently being handled.\n# TYPE rebrew_jobs_in_flight gauge\nrebrew_jobs_in_flight %d\n", inFlight.Load())
			b.WriteString("# HELP rebrew_jobs_latency_bucket Latency of answered jobs requests, in milliseconds (cumulative).\n# TYPE rebrew_jobs_latency_bucket histogram\n")
			var cum int64
			for i, bound := range latencyBucketsMS {
				cum += buckets[i]
				fmt.Fprintf(&b, "rebrew_jobs_latency_bucket{le=\"%v\"} %d\n", bound, cum)
			}
			fmt.Fprintf(&b, "rebrew_jobs_latency_bucket{le=\"+Inf\"} %d\n", req)
			fmt.Fprintf(&b, "rebrew_jobs_latency_count %d\n", req)
			fmt.Fprintf(&b, "rebrew_jobs_latency_sum %.3f\n", total)
			cReq, cErr, jReq, jErr, cTotal, cMax := globalMetrics.perOp()
			fmt.Fprintf(&b, "# HELP rebrew_jobs_compile_requests_total Compile-mediator requests answered.\n# TYPE rebrew_jobs_compile_requests_total counter\nrebrew_jobs_compile_requests_total %v\n", cReq)
			fmt.Fprintf(&b, "# HELP rebrew_jobs_compile_errors_total Compile-mediator requests answered with an error status.\n# TYPE rebrew_jobs_compile_errors_total counter\nrebrew_jobs_compile_errors_total %v\n", cErr)
			fmt.Fprintf(&b, "# HELP rebrew_jobs_job_requests_total Job lifecycle requests answered.\n# TYPE rebrew_jobs_job_requests_total counter\nrebrew_jobs_job_requests_total %v\n", jReq)
			fmt.Fprintf(&b, "# HELP rebrew_jobs_job_errors_total Job lifecycle requests answered with an error status.\n# TYPE rebrew_jobs_job_errors_total counter\nrebrew_jobs_job_errors_total %v\n", jErr)
			fmt.Fprintf(&b, "# HELP rebrew_jobs_compile_latency_ms_total Total latency of compile-mediator requests, in milliseconds.\n# TYPE rebrew_jobs_compile_latency_ms_total counter\nrebrew_jobs_compile_latency_ms_total %.3f\n", cTotal)
			fmt.Fprintf(&b, "# HELP rebrew_jobs_compile_latency_ms_max Maximum latency of a compile-mediator request, in milliseconds.\n# TYPE rebrew_jobs_compile_latency_ms_max gauge\nrebrew_jobs_compile_latency_ms_max %.3f\n", cMax)
			w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
			w.Header().Set("Cache-Control", "no-store")
			w.WriteHeader(http.StatusOK)
			if r.Method != http.MethodHead {
				_, _ = w.Write([]byte(b.String()))
			}
			return
		}
		if !hostAllowed(r.Host) {
			log.Printf("level=warning msg=http_host_rejected host=%s path=%s", logEscape(r.Host), logEscape(r.URL.Path))
			apiError(w, "host not allowed", http.StatusForbidden)
			return
		}
		start := time.Now()
		inFlight.Add(1)
		defer inFlight.Add(-1)
		requestID := requestID(r)
		if requestID != "" {
			w.Header().Set("X-Request-ID", requestID)
		}
		status := 0
		// Instrument only the response status that a handler actually commits;
		// the log line at the end is the single access log for the service.
		rec := &statusRecorder{ResponseWriter: w, status: &status, method: r.Method}
		w = rec
		defer func() {
			// http.Error without WriteHeader leaves the implicit 200; handlers
			// in this file always set a status before writing, but recover the
			// common cases so the log is never misleading.
			s := status
			if s == 0 {
				s = http.StatusOK
			}
			jobID := ""
			if strings.HasPrefix(r.URL.Path, "/jobs/") {
				jobID = strings.Split(strings.TrimPrefix(r.URL.Path, "/jobs/"), "/")[0]
			}
			level := "info"
			if s >= 500 {
				level = "error"
			} else if s >= 400 {
				level = "warning"
			}
			elapsed := float64(time.Since(start).Microseconds()) / 1000.0
			globalMetrics.recordFor(metricsRouteOp(r), s, elapsed)
			log.Printf("level=%s msg=http_request method=%s path=%s status=%d duration_ms=%d request_id=%q job_id=%q trace_id=%q",
				level, logEscape(r.Method), logEscape(r.URL.Path), s, time.Since(start).Milliseconds(), requestID, jobID, traceID(r.Header.Get("traceparent")))
		}()
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
			log.Printf("level=warning msg=http_unauthorized method=%s path=%s request_id=%q", logEscape(r.Method), logEscape(r.URL.Path), requestID)
			apiError(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		// Every JSON request on this service declares its media type, as
		// `rebrew ops serve` already requires on POST (415 otherwise).
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
		// POST /jobs carries the JSON admission body; the Content-Type check
		// above already refused a missing or wrong media type (415), so the
		// body here is known to be declared JSON.
		if r.Method == http.MethodPost && r.URL.Path == "/jobs" {
			var in struct {
				Key             string `json:"key"`
				Kind            string `json:"kind"`
				Seed            string `json:"seed"`
				WorkspaceSHA256 string `json:"workspace_sha256"`
				Generations     *int   `json:"generations"`
				Population      *int   `json:"population"`
			}
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 4096))
			dec.DisallowUnknownFields()
			if dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF {
				apiError(w, "invalid request", 400)
				return
			}
			credential := r.Header.Get("X-Rebrew-Compile-Credential")
			var saved Receipt
			var created bool
			var err error
			options := defaultMatchOptions
			if in.Generations != nil {
				options.Generations = *in.Generations
			}
			if in.Population != nil {
				options.Population = *in.Population
			}
			admitCtx := withJobLogContext(r.Context(), requestID, traceID(r.Header.Get("traceparent")))
			if in.Kind == "catalog" {
				if in.Seed != "" || credential != "" || in.Generations != nil || in.Population != nil {
					apiError(w, "invalid catalog request", 400)
					return
				}
				saved, created, err = o.admitContext(admitCtx, in.Key, "rebrew-project.toml", in.WorkspaceSHA256, "", defaultMatchOptions, "catalog")
			} else if in.Kind != "" && in.Kind != "match" {
				apiError(w, "invalid kind", 400)
				return
			} else if credential != "" {
				saved, created, err = o.admitContext(admitCtx, in.Key, in.Seed, in.WorkspaceSHA256, credential, options, "")
			} else {
				saved, created, err = o.admitContext(admitCtx, in.Key, in.Seed, in.WorkspaceSHA256, "", options, "")
			}
			if err != nil {
				if errors.Is(err, ErrIdempotencyConflict) {
					log.Printf("level=warning msg=job_admission_conflict request_id=%q trace_id=%q key=%q error=%q", requestID, traceID(r.Header.Get("traceparent")), in.Key, err.Error())
					apiError(w, "idempotency conflict", http.StatusConflict)
					return
				}
				if errors.Is(err, ErrOccupied) {
					log.Printf("level=warning msg=job_admission_busy request_id=%q trace_id=%q key=%q error=%q", requestID, traceID(r.Header.Get("traceparent")), in.Key, err.Error())
					w.Header().Set("Retry-After", "5")
					apiError(w, "workspace has unresolved work", http.StatusConflict)
					return
				}
				log.Printf("level=warning msg=job_admission_refused request_id=%q trace_id=%q key=%q kind=%q error=%q", requestID, traceID(r.Header.Get("traceparent")), in.Key, in.Kind, err.Error())
				apiError(w, "admission refused", 400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if created {
				w.WriteHeader(http.StatusAccepted)
			}
			_ = json.NewEncoder(w).Encode(saved)
			return
		}
		// Known collection path with wrong method: 405, like dashboard/ops on a
		// served path, rather than 404 which would claim the resource is missing.
		if r.URL.Path == "/jobs" {
			w.Header().Set("Allow", http.MethodPost)
			apiError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if !strings.HasPrefix(r.URL.Path, "/jobs/") {
			apiError(w, "not found", http.StatusNotFound)
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/jobs/"), "/")
		if len(parts) > 2 {
			apiError(w, "not found", http.StatusNotFound)
			return
		}
		id := parts[0]
		// Known job paths: /jobs/{id} (GET, HEAD), /jobs/{id}/output and
		// /jobs/{id}/compile-intents (GET, HEAD), /jobs/{id}/events (GET only:
		// a stream has no HEAD representation), /jobs/{id}/cancel|reconcile|
		// compile-reconcile (POST). Wrong method on a known shape is 405 with
		// Allow, not 404. HEAD mirrors GET headers with no body, like the
		// dashboard and ops servers.
		isGet := r.Method == http.MethodGet || r.Method == http.MethodHead
		head := r.Method == http.MethodHead
		if len(parts) == 1 && !isGet {
			w.Header().Set("Allow", "GET, HEAD")
			apiError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if len(parts) == 2 {
			switch parts[1] {
			case "events":
				if r.Method != http.MethodGet {
					w.Header().Set("Allow", http.MethodGet)
					apiError(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
			case "output", "compile-intents":
				if !isGet {
					w.Header().Set("Allow", "GET, HEAD")
					apiError(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
			case "cancel", "reconcile", "compile-reconcile":
				if r.Method != http.MethodPost {
					w.Header().Set("Allow", http.MethodPost)
					apiError(w, "method not allowed", http.StatusMethodNotAllowed)
					return
				}
			default:
				apiError(w, "not found", http.StatusNotFound)
				return
			}
		}
		if isGet && len(parts) == 2 && parts[1] == "compile-intents" {
			intents, err := o.CompileIntents(id)
			if err != nil {
				apiError(w, "managed job unavailable", 404)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if head {
				w.WriteHeader(http.StatusOK)
				return
			}
			_ = json.NewEncoder(w).Encode(intents)
			return
		}
		if r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "compile-reconcile" {
			var in struct {
				Intent string `json:"intent"`
			}
			dec := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1024))
			dec.DisallowUnknownFields()
			if dec.Decode(&in) != nil || dec.Decode(new(any)) != io.EOF || !validHex(in.Intent, 64) {
				apiError(w, "invalid request", 400)
				return
			}
			ctx, cancel := context.WithTimeout(r.Context(), 150*time.Second)
			defer cancel()
			if err := o.ReconcileCompile(ctx, id, in.Intent, r.Header.Get("X-Rebrew-Compile-Credential")); err != nil {
				if errors.Is(err, os.ErrNotExist) {
					apiError(w, "job unavailable", http.StatusNotFound)
					return
				}
				apiError(w, "compile remains unresolved", http.StatusConflict)
				return
			}
			w.WriteHeader(http.StatusNoContent)
			return
		}
		if r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "cancel" {
			saved, err := o.Cancel(id)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					apiError(w, "job unavailable", http.StatusNotFound)
					return
				}
				log.Printf("level=warning msg=job_cancel_refused request_id=%q trace_id=%q job_id=%q error=%q", requestID, traceID(r.Header.Get("traceparent")), id, err.Error())
				apiError(w, "cancel refused", 400)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(saved)
			return
		}
		if r.Method == http.MethodPost && len(parts) == 2 && parts[1] == "reconcile" {
			ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
			defer cancel()
			saved, err := o.ReconcileDocker(ctx, id)
			if err != nil {
				if errors.Is(err, os.ErrNotExist) {
					apiError(w, "job unavailable", http.StatusNotFound)
					return
				}
				apiError(w, "stop remains unresolved", http.StatusConflict)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(saved)
			return
		}
		if isGet && len(parts) == 1 {
			saved, err := o.Get(id)
			if err != nil {
				apiError(w, "job unavailable", 404)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			if head {
				w.WriteHeader(http.StatusOK)
				return
			}
			_ = json.NewEncoder(w).Encode(saved)
			return
		}
		if isGet && len(parts) == 2 && parts[1] == "output" {
			if _, err := o.Get(id); err != nil {
				apiError(w, "job unavailable", 404)
				return
			}
			file, err := os.Open(filepath.Join(o.dir, id+".output"))
			if err != nil {
				apiError(w, "output unavailable", 404)
				return
			}
			defer file.Close()
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			if head {
				w.WriteHeader(http.StatusOK)
				return
			}
			_, _ = io.Copy(w, io.LimitReader(file, outputLimit))
			return
		}
		if r.Method != http.MethodGet || len(parts) != 2 || parts[1] != "events" {
			apiError(w, "not found", http.StatusNotFound)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			apiError(w, "stream unavailable", 500)
			return
		}
		o.mu.Lock()
		saved, err := o.read(id)
		if err != nil {
			o.mu.Unlock()
			apiError(w, "job unavailable", 404)
			return
		}
		if len(o.listeners[id]) >= maxEventListeners {
			o.mu.Unlock()
			w.Header().Set("Retry-After", "5")
			apiError(w, "too many event streams", http.StatusTooManyRequests)
			return
		}
		ch := make(chan struct{}, 1)
		if o.listeners[id] == nil {
			o.listeners[id] = map[chan struct{}]bool{}
		}
		o.listeners[id][ch] = true
		o.mu.Unlock()
		defer func() {
			o.mu.Lock()
			delete(o.listeners[id], ch)
			if len(o.listeners[id]) == 0 {
				delete(o.listeners, id)
			}
			o.mu.Unlock()
		}()
		w.Header().Set("Content-Type", "text/event-stream")
		send := func(v Receipt) bool {
			b, e := json.Marshal(v)
			if e != nil {
				return false
			}
			controller := http.NewResponseController(w)
			if controller.SetWriteDeadline(time.Now().Add(5*time.Second)) != nil {
				return false
			}
			if _, e = fmt.Fprintf(w, "data: %s\n\n", b); e != nil {
				return false
			}
			flusher.Flush()
			return true
		}
		if !send(saved) {
			return
		}
		for {
			select {
			case <-r.Context().Done():
				return
			case <-ch:
				saved, err = o.Get(id)
				if err != nil || !send(saved) {
					return
				}
			}
		}
	}), nil
}
