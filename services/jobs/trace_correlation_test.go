package jobs

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// The compile mediator is the jobs service's paid upstream hop.  The trace
// that admitted the compile must continue across it, or the billable call
// cannot be found from the trace an operator pivots from (MELT investigative
// path: access line -> trace -> upstream call).
func TestCompileMediatorForwardsTraceparentUpstream(t *testing.T) {
	credential := "rck_fixture_secret"
	var gotTraceparent string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTraceparent = r.Header.Get("traceparent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","artifact_url":"/api/v1/artifacts/abcdef123456.o"}`))
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
	body := `{"compiler":"gcc","source":"int x;","flags":[],"filename":"a.c","emit_assembly":false}`
	const tp = "00-4bf92f3577b34da6a3ce929d0e0e4736-00f067aa0ba902b7-01"
	req := httptest.NewRequest("POST", "/api/v1/compile", bytes.NewBufferString(body))
	req.Header.Set("X-Rebrew-Job-Capability", cap)
	req.Header.Set("X-Rebrew-Compile-Intent", id)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("traceparent", tp)
	w := httptest.NewRecorder()
	mediator.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("compile: %d", w.Code)
	}
	if gotTraceparent != tp {
		t.Fatalf("upstream traceparent = %q, want %q", gotTraceparent, tp)
	}
}

// A malformed traceparent must not be re-emitted upstream: forwarding
// garbage would poison the upstream trace with a header no collector can parse.
func TestCompileMediatorDropsMalformedTraceparent(t *testing.T) {
	credential := "rck_fixture_secret"
	var gotTraceparent string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotTraceparent = r.Header.Get("traceparent")
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok","artifact_url":"/api/v1/artifacts/abcdef123456.o"}`))
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
	body := `{"compiler":"gcc","source":"int x;","flags":[],"filename":"a.c","emit_assembly":false}`
	req := httptest.NewRequest("POST", "/api/v1/compile", bytes.NewBufferString(body))
	req.Header.Set("X-Rebrew-Job-Capability", cap)
	req.Header.Set("X-Rebrew-Compile-Intent", id)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("traceparent", "not-a-traceparent")
	w := httptest.NewRecorder()
	mediator.ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("compile: %d", w.Code)
	}
	if gotTraceparent != "" {
		t.Fatalf("malformed traceparent forwarded: %q", gotTraceparent)
	}
}

// The job lifecycle lines (admitted/started/finished) are the only record of
// an asynchronous job's progress; without the admission request's ids an
// operator cannot pivot from a job to the request and trace that admitted it.
func TestJobLogFieldsCarryAdmissionCorrelation(t *testing.T) {
	ctx := withJobLogContext(context.Background(), "req-1", "4bf92f3577b34da6a3ce929d0e0e4736")
	got := jobLogFields(ctx)
	if !strings.Contains(got, `request_id="req-1"`) || !strings.Contains(got, `trace_id="4bf92f3577b34da6a3ce929d0e0e4736"`) {
		t.Fatalf("jobLogFields = %q", got)
	}
	// No admission request (library Admit* entry points): the keys are still
	// present so one log query matches every lifecycle line.
	empty := jobLogFields(context.Background())
	if !strings.Contains(empty, `request_id=""`) || !strings.Contains(empty, `trace_id=""`) {
		t.Fatalf("jobLogFields empty = %q", empty)
	}
}
