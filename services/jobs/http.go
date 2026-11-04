package jobs

import (
	"context"
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
	"time"
)

type statusRecorder struct {
	http.ResponseWriter
	status *int
	wrote  bool
}

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
// which no JSON client can branch on uniformly.
func apiError(w http.ResponseWriter, detail string, status int) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	if status == http.StatusUnauthorized {
		w.Header().Set("WWW-Authenticate", `Bearer realm="rebrew-jobs"`)
	}
	w.WriteHeader(status)
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

// Handler exposes one configured owner's local API; it is not a tenant authorization boundary.
func (o *Owner) Handler(token string) (http.Handler, error) {
	if len(token) < 32 {
		return nil, fmt.Errorf("job token must contain at least 32 bytes")
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !hostAllowed(r.Host) {
			apiError(w, "host not allowed", http.StatusForbidden)
			return
		}
		start := time.Now()
		requestID := r.Header.Get("X-Request-ID")
		status := 0
		// Instrument only the response status that a handler actually commits;
		// the log line at the end is the single access log for the service.
		rec := &statusRecorder{ResponseWriter: w, status: &status}
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
			log.Printf("http_request method=%s path=%s status=%d duration_ms=%d request_id=%q job_id=%q",
				r.Method, r.URL.Path, s, time.Since(start).Milliseconds(), requestID, jobID)
		}()
		if subtle.ConstantTimeCompare([]byte(r.Header.Get("Authorization")), []byte("Bearer "+token)) != 1 {
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
			if in.Kind == "catalog" {
				if in.Seed != "" || credential != "" || in.Generations != nil || in.Population != nil {
					apiError(w, "invalid catalog request", 400)
					return
				}
				saved, created, err = o.AdmitCatalog(in.Key, in.WorkspaceSHA256)
			} else if in.Kind != "" && in.Kind != "match" {
				apiError(w, "invalid kind", 400)
				return
			} else if credential != "" {
				saved, created, err = o.AdmitManagedTuned(in.Key, in.Seed, in.WorkspaceSHA256, credential, options)
			} else {
				saved, created, err = o.AdmitTuned(in.Key, in.Seed, in.WorkspaceSHA256, options)
			}
			if err != nil {
				if errors.Is(err, ErrIdempotencyConflict) {
					apiError(w, "idempotency conflict", http.StatusConflict)
					return
				}
				if errors.Is(err, ErrOccupied) {
					w.Header().Set("Retry-After", "5")
					apiError(w, "workspace has unresolved work", http.StatusConflict)
					return
				}
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
		// Known job paths: /jobs/{id} (GET), /jobs/{id}/events|output|compile-intents
		// (GET), /jobs/{id}/cancel|reconcile|compile-reconcile (POST). Wrong method
		// on a known shape is 405 with Allow, not 404.
		if len(parts) == 1 && r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			apiError(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if len(parts) == 2 {
			switch parts[1] {
			case "events", "output", "compile-intents":
				if r.Method != http.MethodGet {
					w.Header().Set("Allow", http.MethodGet)
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
		if r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "compile-intents" {
			intents, err := o.CompileIntents(id)
			if err != nil {
				apiError(w, "managed job unavailable", 404)
				return
			}
			w.Header().Set("Content-Type", "application/json")
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
				apiError(w, "job unavailable", 404)
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
		if r.Method == http.MethodGet && len(parts) == 1 {
			saved, err := o.Get(id)
			if err != nil {
				apiError(w, "job unavailable", 404)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(saved)
			return
		}
		if r.Method == http.MethodGet && len(parts) == 2 && parts[1] == "output" {
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
