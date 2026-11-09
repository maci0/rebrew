package jobs

import (
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

func TestCompileMediatorMethodNotAllowed(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := writeCompileIndex(dir, []string{}); err != nil {
		t.Fatal(err)
	}
	cap := strings.Repeat("a", 64)
	m, err := NewCompileMediator(dir, upstream.URL, "cred", cap, 1, []string{"gcc"})
	if err != nil {
		t.Fatal(err)
	}
	send := func(method, path string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, nil)
		req.Header.Set("X-Rebrew-Job-Capability", cap)
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		m.ServeHTTP(w, req)
		return w
	}
	if w := send(http.MethodGet, "/api/v1/compile"); w.Code != 405 || w.Header().Get("Allow") != http.MethodPost {
		t.Fatalf("GET compile: %d Allow=%q", w.Code, w.Header().Get("Allow"))
	}
	if w := send(http.MethodPost, "/api/v1/artifacts/abcdef123456.o"); w.Code != 405 || w.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("POST artifact: %d Allow=%q", w.Code, w.Header().Get("Allow"))
	}
	if w := send(http.MethodHead, "/api/v1/artifacts/abcdef123456.o"); w.Code != http.StatusNotFound || w.Body.Len() != 0 {
		t.Fatalf("HEAD artifact mirrors GET: %d body=%q", w.Code, w.Body.String())
	}
	if w := send(http.MethodGet, "/api/v1/nope"); w.Code != 404 {
		t.Fatalf("unknown path: %d", w.Code)
	}
}
