package jobs

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMetricsRequiresBearerToken(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "seed.c"), []byte("int f(void){return 0;}"), 0600); err != nil {
		t.Fatal(err)
	}
	executable, err := filepath.Abs("../../.venv/bin/rebrew")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = os.Stat(executable); err != nil {
		t.Skip("installed Rebrew CLI unavailable")
	}
	owner, err := Open(root, testJobDir(t), executable)
	if err != nil {
		t.Fatal(err)
	}
	defer owner.Close()
	token := strings.Repeat("x", 32)
	handler, err := owner.Handler(token)
	if err != nil {
		t.Fatal(err)
	}
	get := func(path, auth string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r.Host = "localhost"
		if auth != "" {
			r.Header.Set("Authorization", "Bearer "+auth)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := get("/metrics", ""); w.Code != http.StatusUnauthorized {
		t.Fatalf("unauthenticated metrics: %d", w.Code)
	}
	if w := get("/metrics", "wrong-token-wrong-token-wrong-token"); w.Code != http.StatusUnauthorized {
		t.Fatalf("wrong-token metrics: %d", w.Code)
	}
	if w := get("/metrics", token); w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "rebrew_jobs_requests_total") {
		t.Fatalf("authenticated metrics: %d %q", w.Code, w.Body.String())
	}
	for _, want := range []string{"rebrew_jobs_compile_requests_total", "rebrew_jobs_job_requests_total", "rebrew_jobs_compile_errors_total"} {
		if w := get("/metrics", token); !strings.Contains(w.Body.String(), want) {
			t.Fatalf("metrics missing per-op counter %s in %q", want, w.Body.String())
		}
	}
	if w := get("/healthz", ""); w.Code != http.StatusOK {
		t.Fatalf("healthz stays unauthenticated: %d", w.Code)
	}
}
