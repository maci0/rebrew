package jobs

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// HEAD must mirror GET on safe read endpoints (RFC 9110 §9.3.2), like the
// dashboard and ops servers which advertise Allow: GET, HEAD. Previously
// HEAD on a job resource answered 405 Allow: GET.
func TestJobHeadMirrorsGet(t *testing.T) {
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
	saved, _, err := testAdmit(owner, "head-test", "seed.c")
	if err != nil {
		t.Fatal(err)
	}
	send := func(method, path string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, path, nil)
		r.Host = "localhost"
		r.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	id := saved.ID
	// GET baseline.
	if w := send(http.MethodGet, "/jobs/"+id); w.Code != http.StatusOK || w.Body.Len() == 0 {
		t.Fatalf("GET job: %d body=%q", w.Code, w.Body.String())
	}
	// HEAD mirrors GET: same status, headers, no body.
	if w := send(http.MethodHead, "/jobs/"+id); w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("HEAD job: %d body=%q", w.Code, w.Body.String())
	} else if ct := w.Header().Get("Content-Type"); ct != "application/json" {
		t.Fatalf("HEAD job Content-Type: %q", ct)
	}
	// Wrong method still 405, now advertising GET, HEAD.
	if w := send(http.MethodPut, "/jobs/"+id); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != "GET, HEAD" {
		t.Fatalf("PUT job: %d Allow=%q", w.Code, w.Header().Get("Allow"))
	}
	// Output: HEAD mirrors GET (200 when the file exists, else 404), empty body either way.
	if w := send(http.MethodGet, "/jobs/"+id+"/output"); w.Code != http.StatusOK {
		t.Fatalf("GET output: %d", w.Code)
	}
	if w := send(http.MethodHead, "/jobs/"+id+"/output"); w.Code != http.StatusOK || w.Body.Len() != 0 {
		t.Fatalf("HEAD output: %d body=%q", w.Code, w.Body.String())
	}
	if w := send(http.MethodHead, "/jobs/"+strings.Repeat("f", 64)+"/output"); w.Code != http.StatusNotFound || w.Body.Len() != 0 {
		t.Fatalf("HEAD missing output: %d body=%q", w.Code, w.Body.String())
	}
	// Compile-intents on a non-managed job mirrors GET (404, empty body).
	if w := send(http.MethodGet, "/jobs/"+id+"/compile-intents"); w.Code != http.StatusNotFound {
		t.Fatalf("GET compile-intents: %d", w.Code)
	}
	if w := send(http.MethodHead, "/jobs/"+id+"/compile-intents"); w.Code != http.StatusNotFound || w.Body.Len() != 0 {
		t.Fatalf("HEAD compile-intents: %d body=%q", w.Code, w.Body.String())
	}
	// Events stays GET-only (a stream has no HEAD representation): 405.
	if w := send(http.MethodHead, "/jobs/"+id+"/events"); w.Code != http.StatusMethodNotAllowed || w.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("HEAD events: %d Allow=%q", w.Code, w.Header().Get("Allow"))
	}
}
