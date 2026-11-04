package jobs

import (
	"bufio"
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestHTTPAdmissionAndToken(t *testing.T) {
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
	request := func(body string, authenticated bool) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/jobs", bytes.NewBufferString(body))
		r.Host = "localhost"
		if authenticated {
			r.Header.Set("Authorization", "Bearer "+token)
		}
		w := httptest.NewRecorder()
		handler.ServeHTTP(w, r)
		return w
	}
	if w := request(`{"key":"k","seed":"seed.c"}`, false); w.Code != 401 {
		t.Fatalf("unauthenticated: %d", w.Code)
	}
	if w := request(`{"key":"k","seed":"seed.c","extra":1}`, true); w.Code != 400 {
		t.Fatalf("unknown field: %d", w.Code)
	}
	if w := request(`{"key":"k","seed":"seed.c"}`, true); w.Code != 400 {
		t.Fatalf("missing workspace digest: %d", w.Code)
	}
	stage, digest, err := snapshot(root, owner.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stage)
	if w := request(`{"key":"k","seed":"seed.c","workspace_sha256":"`+strings.Repeat("0", 64)+`"}`, true); w.Code != 400 {
		t.Fatalf("wrong workspace digest: %d", w.Code)
	}
	body := `{"key":"k","seed":"seed.c","workspace_sha256":"` + digest + `","generations":1,"population":2}`
	if w := request(`{"key":"k","seed":"seed.c","workspace_sha256":"`+digest+`","generations":0,"population":2}`, true); w.Code != 400 {
		t.Fatalf("invalid match bounds: %d", w.Code)
	}
	if err = os.WriteFile(filepath.Join(root, "seed.c"), []byte("changed"), 0600); err != nil {
		t.Fatal(err)
	}
	if w := request(body, true); w.Code != 400 {
		t.Fatalf("changed workspace accepted: %d", w.Code)
	}
	if err = os.WriteFile(filepath.Join(root, "seed.c"), []byte("int f(void){return 0;}"), 0600); err != nil {
		t.Fatal(err)
	}
	w := request(body, true)
	if w.Code != 202 {
		t.Fatalf("admission: %d", w.Code)
	}
	var receipt Receipt
	if err = json.Unmarshal(w.Body.Bytes(), &receipt); err != nil || receipt.ID == "" || receipt.Generations != 1 || receipt.Population != 2 {
		t.Fatal("receipt missing")
	}
	w = request(body, true)
	if w.Code != 200 {
		t.Fatalf("replay: %d", w.Code)
	}
	if w = request(`{"key":"k","seed":"seed.c","workspace_sha256":"`+digest+`","generations":2,"population":2}`, true); w.Code != 409 {
		t.Fatal("changed match bounds accepted on replay")
	}
}

func TestEventStreamStartsWithRetainedSnapshot(t *testing.T) {
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
	saved, _, err := testAdmit(owner, "stream-test", "seed.c")
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(handler)
	defer server.Close()
	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest(http.MethodGet, server.URL+"/jobs/"+saved.ID+"/events", nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	response, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatalf("stream: %d", response.StatusCode)
	}
	reader := bufio.NewReader(response.Body)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(line, "data: ") {
			continue
		}
		var event Receipt
		if err = json.Unmarshal([]byte(strings.TrimSpace(strings.TrimPrefix(line, "data: "))), &event); err != nil {
			t.Fatal(err)
		}
		if event.ID != saved.ID {
			t.Fatal("foreign event")
		}
		if event.ExitCode != nil {
			break
		}
	}
}
