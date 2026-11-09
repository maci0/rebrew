package jobs

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"strings"
)

type managedCompileConfig struct {
	Upstream string   `json:"upstream"`
	Max      int      `json:"max"`
	Allowed  []string `json:"allowed"`
}

type CompileIntentStatus struct {
	Intent             string `json:"intent"`
	State              string `json:"state"`
	UpstreamHTTPStatus int    `json:"upstream_http_status,omitempty"`
}

// CompileIntents exposes recovery identifiers without source or credentials.
func (o *Owner) CompileIntents(job string) ([]CompileIntentStatus, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	r, err := o.read(job)
	if err != nil || !r.ManagedCompile {
		return nil, errors.New("managed job unavailable")
	}
	dir := filepath.Join(o.dir, job+".compile", "ledger")
	ids, err := readCompileIndex(dir)
	if err != nil {
		return nil, err
	}
	indexed := make(map[string]bool, len(ids))
	for _, id := range ids {
		indexed[id] = false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	statuses := make([]CompileIntentStatus, 0)
	for _, entry := range entries {
		if entry.Name() == "index.json" || !strings.HasSuffix(entry.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			return nil, err
		}
		var v compileOriginal
		if json.Unmarshal(b, &v) != nil || !validHex(v.Intent, 64) || entry.Name() != v.Intent+".json" || !validHex(v.Key, 12) || !compileBodyValid(v) || v.CredentialSHA256 != r.CredentialSHA256 {
			return nil, errors.New("invalid compile original")
		}
		state := "unresolved"
		_, known := indexed[v.Intent]
		if known {
			indexed[v.Intent] = true
		}
		if known && compileResultValid(v) {
			state = "result_retained"
		} else if known && len(v.Result) > 0 {
			return nil, errors.New("invalid compile result")
		}
		statuses = append(statuses, CompileIntentStatus{Intent: v.Intent, State: state, UpstreamHTTPStatus: v.LastHTTPStatus})
	}
	for _, present := range indexed {
		if !present {
			return nil, errors.New("indexed compile original missing")
		}
	}
	return statuses, nil
}

func compileBodyValid(v compileOriginal) bool {
	sum := sha256.Sum256(v.Body)
	return json.Valid(v.Body) && v.BodySHA256 == hex.EncodeToString(sum[:])
}

func compileResultValid(v compileOriginal) bool {
	sum := sha256.Sum256(v.Result)
	if v.ResultSHA256 != hex.EncodeToString(sum[:]) {
		return false
	}
	var result struct {
		Status   string `json:"status"`
		Artifact string `json:"artifact_url"`
	}
	if json.Unmarshal(v.Result, &result) != nil {
		return false
	}
	return (result.Status == "ok" && validArtifact(result.Artifact) && v.Artifact == result.Artifact) || (result.Status == "error" && result.Artifact == "" && v.Artifact == "")
}

// ConfigureManagedCompile pins upstream, compiler actions and job budget before admission.
func (o *Owner) ConfigureManagedCompile(upstream string, max int, allowed []string) error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed || o.reconciling || o.compileMediator != nil || o.docker == nil {
		return errors.New("managed compile configuration unavailable")
	}
	if _, err := NewCompileMediator(o.dir, upstream, "validation", strings.Repeat("0", 64), max, allowed); err != nil {
		return err
	}
	o.compileConfig = &managedCompileConfig{Upstream: upstream, Max: max, Allowed: append([]string(nil), allowed...)}
	return nil
}
func (o *Owner) startManagedCompile(id, credential string) (string, error) {
	base := filepath.Join(o.dir, id+".compile")
	if err := os.Mkdir(base, 0700); err != nil {
		return "", err
	}
	ledger := filepath.Join(base, "ledger")
	if err := os.Mkdir(ledger, 0700); err != nil {
		return "", err
	}
	if err := writeCompileIndex(ledger, []string{}); err != nil {
		return "", err
	}
	data, err := json.Marshal(o.compileConfig)
	if err != nil {
		return "", err
	}
	f, err := os.OpenFile(filepath.Join(base, "config.json"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return "", err
	}
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return "", err
	}
	if err := syncDir(base); err != nil {
		return "", err
	}
	socket, err := os.MkdirTemp("", "rebrew-job-")
	if err != nil {
		return "", err
	}
	keep := false
	defer func() {
		if !keep {
			_ = os.RemoveAll(socket)
		}
	}()
	var cap [32]byte
	if _, err := rand.Read(cap[:]); err != nil {
		return "", err
	}
	m, err := NewCompileMediator(ledger, o.compileConfig.Upstream, credential, hex.EncodeToString(cap[:]), o.compileConfig.Max, o.compileConfig.Allowed)
	if err != nil {
		return "", err
	}
	server, listener, err := m.ServeSocket(socket)
	if err != nil {
		return "", err
	}
	o.compileMediator, o.compileServer, o.compileListener = m, server, listener
	o.compileSocket = socket
	keep = true
	return socket, nil
}

// stopManagedCompile closes the mediator's server and detaches it from the owner.
//
// It does not wait for an in-flight compile request: that request can hold
// m.mu for the full upstream timeout, so waiting here (with o.mu held) froze
// every status, cancel and admission for that long.  The caller passes the
// returned mediator to waitManagedCompileIdle after releasing o.mu.
func (o *Owner) stopManagedCompile() *CompileMediator {
	m := o.compileMediator
	if o.compileServer != nil {
		_ = o.compileServer.Close()
	}
	if o.compileListener != nil {
		_ = o.compileListener.Close()
	}
	if o.compileSocket != "" {
		_ = os.RemoveAll(o.compileSocket)
		o.compileSocket = ""
	}
	o.compileMediator, o.compileServer, o.compileListener = nil, nil, nil
	return m
}

// waitManagedCompileIdle waits for the mediator's active request to finish.
//
// Call it without o.mu.  The m.mu barrier is what proves no handler still
// writes the compile ledger after the owner released custody.
func waitManagedCompileIdle(m *CompileMediator) {
	if m == nil {
		return
	}
	m.mu.Lock()
	m.mu.Unlock()
}
func (o *Owner) compilePending(id string) (bool, error) {
	receipt, err := o.read(id)
	if err != nil || !receipt.ManagedCompile || !validHex(receipt.CredentialSHA256, 64) {
		return true, errors.New("invalid managed receipt")
	}
	dir := filepath.Join(o.dir, id+".compile", "ledger")
	ids, err := readCompileIndex(dir)
	if err != nil {
		return true, err
	}
	indexed := make(map[string]bool, len(ids))
	for _, id := range ids {
		indexed[id] = false
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return true, err
	}
	for _, e := range entries {
		if e.Name() == "index.json" || !strings.HasSuffix(e.Name(), ".json") {
			continue
		}
		b, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return true, err
		}
		var v compileOriginal
		if json.Unmarshal(b, &v) != nil || !validHex(v.Intent, 64) || e.Name() != v.Intent+".json" || !validHex(v.Key, 12) || v.CredentialSHA256 != receipt.CredentialSHA256 || !compileBodyValid(v) || !compileResultValid(v) {
			return true, nil
		}
		if _, known := indexed[v.Intent]; !known {
			return true, nil
		}
		indexed[v.Intent] = true
	}
	for _, present := range indexed {
		if !present {
			return true, nil
		}
	}
	return false, nil
}

// ReconcileCompile requires the original caller credential and explicitly replays one uncertain compile.
//
// The upstream replay runs outside o.mu.  It can take the full request
// timeout, and holding the owner lock across it froze every job status and
// event read for that long.  One reconcile at a time is still enforced, and
// the in-flight replay counts as owner work so Close waits for it before
// releasing the single-owner store.
func (o *Owner) ReconcileCompile(ctx context.Context, job, intent, credential string) error {
	o.mu.Lock()
	if o.closed {
		o.mu.Unlock()
		return errors.New("owner is closed")
	}
	r, err := o.read(job)
	if err != nil {
		o.mu.Unlock()
		return err
	}
	sum := sha256.Sum256([]byte(credential))
	if !r.ManagedCompile || r.CredentialSHA256 != hex.EncodeToString(sum[:]) || o.compileConfig == nil || o.compileMediator != nil || o.reconciling || r.State != "uncertain" {
		o.mu.Unlock()
		return errors.New("compile recovery unavailable")
	}
	data, err := os.ReadFile(filepath.Join(o.dir, job+".compile", "config.json"))
	if err != nil {
		o.mu.Unlock()
		return err
	}
	var retained managedCompileConfig
	if json.Unmarshal(data, &retained) != nil || !reflect.DeepEqual(retained, *o.compileConfig) {
		o.mu.Unlock()
		return errors.New("compile recovery configuration differs")
	}
	config := *o.compileConfig
	m, err := NewCompileMediator(filepath.Join(o.dir, job+".compile", "ledger"), config.Upstream, credential, strings.Repeat("0", 64), config.Max, config.Allowed)
	if err != nil {
		o.mu.Unlock()
		return err
	}
	o.reconciling = true
	o.workers.Add(1)
	o.mu.Unlock()
	defer func() {
		o.mu.Lock()
		o.reconciling = false
		o.mu.Unlock()
		o.workers.Done()
	}()
	return m.Reconcile(ctx, intent)
}
