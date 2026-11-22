package jobs

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// newBundleMediator serves one job's compiles against upstream.
func newBundleMediator(t *testing.T, upstream *httptest.Server) (*CompileMediator, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeCompileIndex(dir, []string{}); err != nil {
		t.Fatal(err)
	}
	capability := strings.Repeat("a", 64)
	m, err := NewCompileMediator(dir, upstream.URL, "rck_fixture_secret", capability, 2, []string{"gcc"})
	if err != nil {
		t.Fatal(err)
	}
	return m, capability
}

func mediate(m *CompileMediator, method, path, capability, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("X-Rebrew-Job-Capability", capability)
	req.Header.Set("X-Rebrew-Compile-Intent", strings.Repeat("c", 64))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	m.ServeHTTP(w, req)
	return w
}

func TestCompileMediatorForwardsIncludeBundles(t *testing.T) {
	var posted []byte
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/features":
			if r.Header.Get("Authorization") != "" {
				t.Error("the public features route received the owner credential")
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"features":["include-bundles"]}`))
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/compile":
			posted, _ = io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"status":"error","error_code":"toolchain_failure","log":"x"}`))
		default:
			http.NotFound(w, r)
		}
	}))
	defer upstream.Close()
	m, capability := newBundleMediator(t, upstream)

	if got := mediate(m, http.MethodGet, "/api/v1/features", "wrong", ""); got.Code != 401 {
		t.Fatalf("features without the job capability: %d", got.Code)
	}
	features := mediate(m, http.MethodGet, "/api/v1/features", capability, "")
	if features.Code != 200 || strings.TrimSpace(features.Body.String()) != `{"features":["include-bundles"]}` {
		t.Fatalf("features: %d %q", features.Code, features.Body.String())
	}
	if got := mediate(m, http.MethodPost, "/api/v1/features", capability, ""); got.Code != 405 || got.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST features: %d Allow=%q", got.Code, got.Header().Get("Allow"))
	}

	body := `{"compiler":"gcc","source":"#include \"a.h\"\n","flags":["-I."],"filename":"a.c",` +
		`"emit_assembly":false,"source_dir":"src","includes":[{"path":"src/a.h","content":"int a;\n"}]}`
	if got := mediate(m, http.MethodPost, "/api/v1/compile", capability, body); got.Code != 200 {
		t.Fatalf("bundle compile: %d %s", got.Code, got.Body.String())
	}
	var compact bytes.Buffer
	if err := json.Compact(&compact, []byte(body)); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(posted, compact.Bytes()) {
		t.Fatalf("upstream got %s", posted)
	}
	smuggled := `{"compiler":"gcc","source":"x","flags":[],"filename":"a.c","emit_assembly":false,` +
		`"includes":[{"path":"a.h","content":"","mode":"0777"}]}`
	if got := mediate(m, http.MethodPost, "/api/v1/compile", capability, smuggled); got.Code != 400 {
		t.Fatalf("an include with an unknown field: %d", got.Code)
	}
}

func TestCompileMediatorReportsAnOlderUpstreamHasNoFeatures(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	m, capability := newBundleMediator(t, upstream)
	if got := mediate(m, http.MethodGet, "/api/v1/features", capability, ""); got.Code != 404 {
		t.Fatalf("an upstream without the route: %d", got.Code)
	}
}

func TestCompileMediatorForwardsTheJobsCompilerRows(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.URL.Path != "/api/v1/compilers" {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "" {
			t.Error("the public compiler listing received the owner credential")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`[{"id":"gcc","execution_status":"unavailable","family":"gcc"},` +
			`{"id":"msvc-6.0","execution_status":"admitted"}]`))
	}))
	defer upstream.Close()
	m, capability := newBundleMediator(t, upstream)

	if got := mediate(m, http.MethodGet, "/api/v1/compilers", "wrong", ""); got.Code != 401 {
		t.Fatalf("listing without the job capability: %d", got.Code)
	}
	// Only the compilers this job may send: the others are no answer it can use.
	listing := mediate(m, http.MethodGet, "/api/v1/compilers", capability, "")
	if listing.Code != 200 || strings.TrimSpace(listing.Body.String()) != `[{"execution_status":"unavailable","family":"gcc","id":"gcc"}]` {
		t.Fatalf("listing: %d %q", listing.Code, listing.Body.String())
	}
	if got := mediate(m, http.MethodPost, "/api/v1/compilers", capability, ""); got.Code != 405 || got.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST listing: %d Allow=%q", got.Code, got.Header().Get("Allow"))
	}
}

func TestCompileMediatorReportsAnOlderUpstreamHasNoCompilerListing(t *testing.T) {
	upstream := httptest.NewServer(http.NotFoundHandler())
	defer upstream.Close()
	m, capability := newBundleMediator(t, upstream)
	if got := mediate(m, http.MethodGet, "/api/v1/compilers", capability, ""); got.Code != 404 {
		t.Fatalf("an upstream without the route: %d", got.Code)
	}
}
