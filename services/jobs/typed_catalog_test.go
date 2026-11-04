package jobs

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestCatalogAdmissionPinsKindAndRejectsForeignParameters(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "rebrew-project.toml"), []byte("fixture"), 0600); err != nil {
		t.Fatal(err)
	}
	o, err := Open(root, testJobDir(t), "/bin/true")
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	stage, digest, err := snapshot(root, o.dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stage)
	h, err := o.Handler(strings.Repeat("x", 32))
	if err != nil {
		t.Fatal(err)
	}
	post := func(body string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/jobs", bytes.NewBufferString(body))
		r.Host = "localhost"
		r.Header.Set("Authorization", "Bearer "+strings.Repeat("x", 32))
		r.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		return w
	}
	body := `{"key":"catalog","kind":"catalog","workspace_sha256":"` + digest + `"}`
	w := post(body)
	if w.Code != 202 {
		t.Fatalf("admission %d: %s", w.Code, w.Body.String())
	}
	var got Receipt
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil || got.Kind != "catalog" {
		t.Fatal("kind not retained")
	}
	if w = post(body); w.Code != 200 {
		t.Fatalf("replay %d", w.Code)
	}
	for _, extra := range []string{`,"seed":"rebrew-project.toml"`, `,"population":2`, `,"generations":1`} {
		if w = post(strings.TrimSuffix(body, "}") + extra + `}`); w.Code != 400 {
			t.Fatalf("accepted %s", extra)
		}
	}
	if w = post(`{"key":"catalog","kind":"unknown","workspace_sha256":"` + digest + `"}`); w.Code != 400 {
		t.Fatal("unknown kind accepted")
	}
	if w = post(`{"key":"catalog","seed":"rebrew-project.toml","workspace_sha256":"` + digest + `"}`); w.Code != 409 {
		t.Fatal("kind change accepted")
	}
	if strings.Join(jobArguments("catalog", "ignored", 100, 64), " ") != "coverage catalog --json" {
		t.Fatal("catalog arguments changed")
	}
}

func TestDockerCatalogRealCLI(t *testing.T) {
	image, project := os.Getenv("REBREW_TEST_DOCKER_IMAGE"), os.Getenv("REBREW_TEST_CATALOG_PROJECT")
	if image == "" || project == "" {
		t.Skip("isolated catalog project and image required")
	}
	docker, err := exec.LookPath("docker")
	if err != nil {
		t.Fatal(err)
	}
	dir := testJobDir(t)
	o, err := OpenDocker(project, dir, DockerProvider{Binary: docker, Image: image})
	if err != nil {
		t.Fatal(err)
	}
	defer o.Close()
	stage, digest, err := snapshot(project, dir)
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(stage)
	r, _, err := o.AdmitCatalog("actual-catalog", digest)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if r.ContainerID != "" {
			_ = exec.Command(docker, "rm", "-f", r.ContainerID).Run()
		}
	}()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		r, err = o.Get(r.ID)
		if err != nil {
			t.Fatal(err)
		}
		if r.StopVerified {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if !r.StopVerified || r.ExitCode == nil || *r.ExitCode != 0 || r.ResultWorkspaceSHA256 == "" {
		t.Fatalf("catalog did not finish safely: %+v", r)
	}
	wrong := DockerProvider{Binary: docker, Image: image, Generations: r.Generations, Population: r.Population}
	if _, err := wrong.InspectStop(context.Background(), r.ContainerID, r.ID, filepath.Join(dir, r.ID+".original"), filepath.Join(dir, r.ID+".workspace"), r.Seed); err == nil {
		t.Fatal("foreign command accepted as stop evidence")
	}
	output, err := os.ReadFile(filepath.Join(dir, r.ID+".output"))
	if err != nil {
		t.Fatal(err)
	}
	var payload map[string]any
	if json.Unmarshal(bytes.TrimSpace(output[bytes.LastIndexByte(bytes.TrimSpace(output), '\n')+1:]), &payload) != nil || len(payload) == 0 {
		t.Fatalf("missing JSON catalog output: %s", output)
	}
}
