// Package jobs owns durable local match invocations; it does not authorize projects.
package jobs

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

type Receipt struct {
	ID                    string `json:"id"`
	Kind                  string `json:"kind,omitempty"`
	Seed                  string `json:"seed"`
	Generations           int    `json:"generations"`
	Population            int    `json:"population"`
	SeedSHA256            string `json:"seed_sha256"`
	WorkspaceSHA256       string `json:"workspace_sha256"`
	ResultWorkspaceSHA256 string `json:"result_workspace_sha256,omitempty"`
	State                 string `json:"state"`
	CancelRequested       bool   `json:"cancel_requested"`
	ExitCode              *int   `json:"exit_code,omitempty"`
	OutputBytes           int    `json:"output_bytes"`
	OutputTruncated       bool   `json:"output_truncated"`
	OutputSHA256          string `json:"output_sha256,omitempty"`
	NeverStarted          bool   `json:"never_started"`
	Provider              string `json:"provider"`
	ContainerID           string `json:"container_id,omitempty"`
	Image                 string `json:"image,omitempty"`
	StopVerified          bool   `json:"stop_verified"`
	OutputIncomplete      bool   `json:"output_incomplete"`
	ManagedCompile        bool   `json:"managed_compile"`
	CredentialSHA256      string `json:"credential_sha256,omitempty"`
	CompileSocket         string `json:"compile_socket,omitempty"`
}

type Owner struct {
	mu                    sync.Mutex
	root, dir, executable string
	lock                  *os.File
	workers               sync.WaitGroup
	cancel                context.CancelFunc
	runCtx                context.Context
	runTimeout            time.Duration
	closed                bool
	reconciling           bool
	occupied              bool
	listeners             map[string]map[chan struct{}]bool
	queued                map[string]bool
	docker                *DockerProvider
	compileConfig         *managedCompileConfig
	compileMediator       *CompileMediator
	compileServer         *http.Server
	compileListener       net.Listener
	compileSocket         string
}

// OpenDocker selects an isolated local Docker provider without changing CLI behavior.
func OpenDocker(root, dir string, provider DockerProvider) (*Owner, error) {
	if provider.CompileDir != "" || provider.Kind != "" || provider.Generations != 0 || provider.Population != 0 {
		return nil, errors.New("compile socket is assigned by the job owner")
	}
	if err := provider.check(); err != nil {
		return nil, err
	}
	o, err := Open(root, dir, provider.Binary)
	if err != nil {
		return nil, err
	}
	o.docker = &provider
	return o, nil
}

func readSeed(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, 16*1024*1024+1))
}

// Open reserves a single-owner local store; an interrupted running receipt is never replayed.
func Open(root, dir, executable string) (*Owner, error) {
	root, err := filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	rootInfo, err := os.Stat(root)
	if err != nil || !rootInfo.IsDir() {
		return nil, errors.New("workspace must be a directory")
	}
	if !filepath.IsAbs(executable) {
		return nil, errors.New("executable must be an absolute path")
	}
	execInfo, err := os.Stat(executable)
	if err != nil || !execInfo.Mode().IsRegular() {
		return nil, errors.New("executable is unavailable")
	}
	if err = os.MkdirAll(dir, 0700); err != nil {
		return nil, err
	}
	dir, err = filepath.EvalSymlinks(dir)
	if err != nil {
		return nil, err
	}
	dirInfo, err := os.Stat(dir)
	if err != nil || !dirInfo.IsDir() || dirInfo.Mode().Perm()&0077 != 0 {
		return nil, errors.New("job directory must be private")
	}
	rel, err := filepath.Rel(root, dir)
	if err != nil || rel == "." || (rel != ".." && !strings.HasPrefix(rel, ".."+string(os.PathSeparator))) {
		return nil, errors.New("job directory must be outside workspace")
	}
	f, err := os.OpenFile(filepath.Join(dir, "owner.lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = tryLockOwner(f); err != nil {
		f.Close()
		return nil, err
	}
	ownerCtx, ownerCancel := context.WithCancel(context.Background())
	owner := &Owner{root: root, dir: dir, executable: executable, lock: f, cancel: ownerCancel, runCtx: ownerCtx, runTimeout: 10 * time.Minute, listeners: make(map[string]map[chan struct{}]bool), queued: make(map[string]bool)}
	paths, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		f.Close()
		return nil, err
	}
	for _, path := range paths {
		id := strings.TrimSuffix(filepath.Base(path), ".json")
		receipt, readErr := owner.read(id)
		if readErr != nil {
			f.Close()
			return nil, readErr
		}
		if receipt.State == "running" {
			receipt.State = "uncertain"
			if err = owner.save(receipt); err != nil {
				f.Close()
				return nil, err
			}
		}
		if receipt.State == "uncertain" {
			owner.occupied = true
		}
	}
	return owner, nil
}
func (o *Owner) Close() error {
	o.mu.Lock()
	o.closed = true
	cancel := o.cancel
	o.mu.Unlock()
	if cancel != nil {
		cancel()
	}
	o.workers.Wait()
	o.mu.Lock()
	mediator := o.stopManagedCompile()
	o.mu.Unlock()
	waitManagedCompileIdle(mediator)
	return o.lock.Close()
}

func (o *Owner) runContext() context.Context {
	if o.runCtx != nil {
		return o.runCtx
	}
	return context.Background()
}

func (o *Owner) runTimeoutOrDefault() time.Duration {
	if o.runTimeout > 0 {
		return o.runTimeout
	}
	return 10 * time.Minute
}

func (o *Owner) path(id string) string { return filepath.Join(o.dir, id+".json") }
func (o *Owner) read(id string) (Receipt, error) {
	var r Receipt
	if len(id) != 64 {
		return r, os.ErrNotExist
	}
	if _, err := hex.DecodeString(id); err != nil {
		return r, os.ErrNotExist
	}
	b, err := os.ReadFile(o.path(id))
	if err != nil {
		return r, err
	}
	if err = json.Unmarshal(b, &r); err != nil {
		return r, err
	}
	if r.ID != id {
		return r, errors.New("invalid retained job")
	}
	return r, nil
}

var (
	ErrIdempotencyConflict = errors.New("idempotency conflict")
	ErrOccupied            = errors.New("workspace has unresolved work")
)

func (o *Owner) save(r Receipt) error {
	return writeJSONAtomic(o.dir, ".job-", r.ID+".json", r)
}
func (o *Owner) Get(id string) (Receipt, error) { o.mu.Lock(); defer o.mu.Unlock(); return o.read(id) }

func (o *Owner) notify(id string) {
	for ch := range o.listeners[id] {
		select {
		case ch <- struct{}{}:
		default:
		}
	}
}

// Admit pins one seed under the workspace and durably retains intent before launch.
type MatchOptions struct {
	Generations int
	Population  int
}

var defaultMatchOptions = MatchOptions{Generations: 100, Population: 64}

func (o *Owner) Admit(key, seed, expectedWorkspaceSHA256 string) (Receipt, bool, error) {
	return o.admit(key, seed, expectedWorkspaceSHA256, "", defaultMatchOptions, "")
}

func (o *Owner) AdmitTuned(key, seed, digest string, options MatchOptions) (Receipt, bool, error) {
	return o.admit(key, seed, digest, "", options, "")
}

// AdmitManaged keeps the caller credential in memory for the isolated job only.
func (o *Owner) AdmitManaged(key, seed, expectedWorkspaceSHA256, credential string) (Receipt, bool, error) {
	if credential == "" {
		return Receipt{}, false, errors.New("managed compile credential required")
	}
	return o.admit(key, seed, expectedWorkspaceSHA256, credential, defaultMatchOptions, "")
}

func (o *Owner) AdmitManagedTuned(key, seed, digest, credential string, options MatchOptions) (Receipt, bool, error) {
	if credential == "" {
		return Receipt{}, false, errors.New("managed compile credential required")
	}
	return o.admit(key, seed, digest, credential, options, "")
}

func (o *Owner) AdmitCatalog(key, digest string) (Receipt, bool, error) {
	return o.admit(key, "rebrew-project.toml", digest, "", defaultMatchOptions, "catalog")
}

func (o *Owner) admit(key, seed, expectedWorkspaceSHA256, credential string, options MatchOptions, kind string) (Receipt, bool, error) {
	if options.Generations < 1 || options.Generations > 10000 || options.Population < 2 || options.Population > 4096 {
		return Receipt{}, false, errors.New("invalid match bounds")
	}
	if len(key) == 0 || len(key) > 256 || seed == "" || filepath.IsAbs(seed) || len(expectedWorkspaceSHA256) != 64 {
		return Receipt{}, false, errors.New("invalid request")
	}
	if _, err := hex.DecodeString(expectedWorkspaceSHA256); err != nil || strings.ToLower(expectedWorkspaceSHA256) != expectedWorkspaceSHA256 {
		return Receipt{}, false, errors.New("invalid workspace digest")
	}
	target, err := filepath.EvalSymlinks(filepath.Join(o.root, seed))
	if err != nil {
		return Receipt{}, false, err
	}
	rel, err := filepath.Rel(o.root, target)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(os.PathSeparator)) {
		return Receipt{}, false, errors.New("seed escapes workspace")
	}
	st, err := os.Stat(target)
	if err != nil || !st.Mode().IsRegular() || st.Size() > 16*1024*1024 {
		return Receipt{}, false, errors.New("seed must be a regular file")
	}
	bytes, err := readSeed(target)
	if err != nil || len(bytes) > 16*1024*1024 {
		return Receipt{}, false, errors.New("seed unavailable")
	}
	seedSum := sha256.Sum256(bytes)
	seedDigest := hex.EncodeToString(seedSum[:])
	credentialDigest := ""
	if credential != "" {
		sum := sha256.Sum256([]byte(credential))
		credentialDigest = hex.EncodeToString(sum[:])
	}
	sum := sha256.Sum256([]byte(key))
	id := hex.EncodeToString(sum[:])
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return Receipt{}, false, errors.New("owner is closed")
	}
	if credential != "" && (o.docker == nil || o.compileConfig == nil) {
		return Receipt{}, false, errors.New("managed compile unavailable")
	}
	stage, workspaceDigest, err := snapshot(o.root, o.dir)
	if err != nil {
		return Receipt{}, false, err
	}
	defer os.RemoveAll(stage)
	if workspaceDigest != expectedWorkspaceSHA256 {
		return Receipt{}, false, errors.New("workspace digest mismatch")
	}
	copyBytes, err := readSeed(filepath.Join(stage, rel))
	if err != nil {
		return Receipt{}, false, err
	}
	copySum := sha256.Sum256(copyBytes)
	if hex.EncodeToString(copySum[:]) != seedDigest {
		return Receipt{}, false, errors.New("seed changed during snapshot")
	}
	r, err := o.read(id)
	if err == nil {
		if r.Kind != kind || r.Seed != rel || r.SeedSHA256 != seedDigest || r.WorkspaceSHA256 != workspaceDigest || r.ManagedCompile != (credential != "") || r.CredentialSHA256 != credentialDigest || r.Generations != options.Generations || r.Population != options.Population {
			return Receipt{}, false, ErrIdempotencyConflict
		}
		return r, false, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return Receipt{}, false, err
	}
	if o.occupied {
		return Receipt{}, false, ErrOccupied
	}
	originalPath := filepath.Join(o.dir, id+".original")
	if _, statErr := os.Lstat(originalPath); !errors.Is(statErr, os.ErrNotExist) {
		return Receipt{}, false, errors.New("original custody already exists")
	}
	if err = os.Rename(stage, originalPath); err != nil {
		return Receipt{}, false, err
	}
	if err = sealSnapshot(originalPath); err != nil {
		return Receipt{}, false, err
	}
	directory, err := os.Open(o.dir)
	if err != nil {
		return Receipt{}, false, err
	}
	err = directory.Sync()
	directory.Close()
	if err != nil {
		return Receipt{}, false, err
	}
	r = Receipt{ID: id, Kind: kind, Seed: rel, SeedSHA256: seedDigest, WorkspaceSHA256: workspaceDigest, Generations: options.Generations, Population: options.Population, State: "uncertain", ManagedCompile: credential != "", CredentialSHA256: credentialDigest}
	if r.ManagedCompile {
		if r.CompileSocket, err = o.startManagedCompile(r.ID, credential); err != nil {
			return Receipt{}, false, err
		}
	}
	if o.docker != nil {
		r.Provider = "docker"
		r.Image = o.docker.Image
	} else {
		r.Provider = "local"
	}
	if err = o.save(r); err != nil {
		if r.ManagedCompile {
			o.stopManagedCompile()
		}
		return Receipt{}, false, err
	}
	o.occupied = true
	o.queued[r.ID] = true
	o.notify(r.ID)
	log.Printf("level=info msg=job_admitted job_id=%q kind=%q provider=%q state=%q", r.ID, r.Kind, r.Provider, r.State)
	o.workers.Add(1)
	go func() {
		defer o.workers.Done()
		if err := o.run(r); err != nil {
			// The job worker owns its lifecycle; do not swallow an outcome the
			// receipt does not already carry.
			log.Printf("level=error msg=job_run_error job_id=%q error=%q", r.ID, err.Error())
		}
	}()
	return r, true, nil
}

// Run executes an admitted job once in this process. A crash leaves uncertain custody.
func (o *Owner) run(r Receipt) error {
	o.mu.Lock()
	saved, err := o.read(r.ID)
	if err != nil {
		o.mu.Unlock()
		return err
	}
	if saved != r || saved.State != "uncertain" || saved.CancelRequested {
		o.mu.Unlock()
		return errors.New("job is not launchable")
	}
	delete(o.queued, r.ID)
	stage, snapshotDigest, err := snapshot(filepath.Join(o.dir, saved.ID+".original"), o.dir)
	if err != nil {
		o.mu.Unlock()
		return err
	}
	defer os.RemoveAll(stage)
	if snapshotDigest != saved.WorkspaceSHA256 {
		o.mu.Unlock()
		return errors.New("retained original changed")
	}
	workspace := filepath.Join(o.dir, saved.ID+".workspace")
	if _, statErr := os.Lstat(workspace); !errors.Is(statErr, os.ErrNotExist) {
		o.mu.Unlock()
		return errors.New("workspace custody already exists")
	}
	if err = os.Rename(stage, workspace); err != nil {
		o.mu.Unlock()
		return err
	}
	saved.State = "running"
	if err = o.save(saved); err != nil {
		o.mu.Unlock()
		return err
	}
	o.notify(saved.ID)
	log.Printf("level=info msg=job_started job_id=%q kind=%q provider=%q", saved.ID, saved.Kind, saved.Provider)
	o.mu.Unlock()
	if saved.Provider == "docker" {
		return o.runDocker(saved, workspace)
	}
	runCtx, runCancel := context.WithTimeout(o.runContext(), o.runTimeoutOrDefault())
	defer runCancel()
	cmd := exec.CommandContext(runCtx, o.executable, jobArguments(saved.Kind, saved.Seed, saved.Generations, saved.Population)...)
	cmd.Dir = workspace
	configureJobProcess(cmd)
	outputFile, outputErr := os.OpenFile(filepath.Join(o.dir, saved.ID+".output"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if outputErr != nil {
		return outputErr
	}
	output := &outputWriter{owner: o, id: saved.ID, file: outputFile}
	cmd.Stdout, cmd.Stderr = output, output
	seedPath, pathErr := filepath.EvalSymlinks(filepath.Join(workspace, saved.Seed))
	if pathErr == nil {
		var relative string
		relative, pathErr = filepath.Rel(workspace, seedPath)
		if pathErr == nil && relative != saved.Seed {
			pathErr = errors.New("seed path changed")
		}
	}
	var seedBytes []byte
	var readErr error
	if pathErr == nil {
		seedBytes, readErr = readSeed(seedPath)
	} else {
		readErr = pathErr
	}
	seedSum := sha256.Sum256(seedBytes)
	if readErr != nil || len(seedBytes) > 16*1024*1024 || hex.EncodeToString(seedSum[:]) != saved.SeedSHA256 {
		err = errors.New("seed changed before launch")
	} else {
		err = cmd.Run()
	}
	outputDigest, outputErr := output.finish()
	if outputErr != nil {
		return outputErr
	}
	code := 0
	if err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			code = exit.ExitCode()
		} else {
			code = -1
		}
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	current, err := o.read(saved.ID)
	if err != nil {
		return err
	}
	if current.State != "running" {
		return fmt.Errorf("retained state changed")
	}
	// A CLI exit does not prove its container or descendant processes stopped.
	current.State = "uncertain"
	if cmd.Process == nil {
		current.State = "failed"
		current.NeverStarted = true
	}
	current.ExitCode = &code
	current.OutputSHA256 = outputDigest
	if err := o.save(current); err != nil {
		return err
	}
	if current.NeverStarted {
		o.occupied = false
	}
	log.Printf("level=info msg=job_finished job_id=%q state=%q exit_code=%d provider=%q", current.ID, current.State, code, current.Provider)
	o.notify(current.ID)
	return nil
}

func (o *Owner) runDocker(saved Receipt, workspace string) error {
	if o.docker == nil || o.docker.Image != saved.Image {
		return errors.New("container provider unavailable")
	}
	provider := *o.docker
	provider.Generations, provider.Population, provider.Kind = saved.Generations, saved.Population, saved.Kind
	managedRunning := saved.ManagedCompile
	if managedRunning {
		provider.CompileDir = saved.CompileSocket
		defer func() {
			if managedRunning {
				o.mu.Lock()
				mediator := o.stopManagedCompile()
				o.mu.Unlock()
				waitManagedCompileIdle(mediator)
			}
		}()
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	id, err := provider.Create(ctx, filepath.Join(o.dir, saved.ID+".original"), workspace, saved.ID, saved.Seed)
	cancel()
	if err != nil {
		return err
	}
	o.mu.Lock()
	current, err := o.read(saved.ID)
	if err != nil || current.State != "running" {
		o.mu.Unlock()
		return errors.New("retained state changed")
	}
	current.ContainerID = id
	if err = o.save(current); err != nil {
		o.mu.Unlock()
		return err
	}
	o.notify(saved.ID)
	if current.CancelRequested {
		current.State = "uncertain"
		if err = o.save(current); err != nil {
			o.mu.Unlock()
			return err
		}
		o.notify(saved.ID)
		var mediator *CompileMediator
		if managedRunning {
			mediator = o.stopManagedCompile()
			managedRunning = false
		}
		o.mu.Unlock()
		waitManagedCompileIdle(mediator)
		inspectCtx, inspectCancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer inspectCancel()
		_, err = o.ReconcileDocker(inspectCtx, saved.ID)
		return err
	}
	f, err := os.OpenFile(filepath.Join(o.dir, saved.ID+".output"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		o.mu.Unlock()
		return err
	}
	output := &outputWriter{owner: o, id: saved.ID, file: f}
	startCtx, startCancel := context.WithTimeout(context.Background(), 15*time.Second)
	startErr := provider.StartDetached(startCtx, id)
	startCancel()
	o.mu.Unlock()
	if startErr == nil {
		followCtx, followCancel := context.WithTimeout(o.runContext(), o.runTimeoutOrDefault())
		if err := provider.Follow(followCtx, id, output); err != nil {
			// Lost-attached logs are already surfaced as incomplete output
			// via InspectStop; record loss here for operators watching logs.
			log.Printf("level=error msg=job_follow_error job_id=%q error=%q", saved.ID, err.Error())
		}
		followCancel()
	}
	digest, outputErr := output.finish()
	if outputErr != nil {
		return outputErr
	}
	inspectCtx, inspectCancel := context.WithTimeout(context.Background(), 15*time.Second)
	stop, stopErr := provider.InspectStop(inspectCtx, id, saved.ID, filepath.Join(o.dir, saved.ID+".original"), workspace, saved.Seed)
	inspectCancel()
	o.mu.Lock()
	var idle *CompileMediator
	defer func() {
		o.mu.Unlock()
		waitManagedCompileIdle(idle)
	}()
	if managedRunning {
		idle = o.stopManagedCompile()
		managedRunning = false
		pending, pendingErr := o.compilePending(saved.ID)
		if pending || pendingErr != nil {
			stopErr = errors.New("managed compile outcome unresolved")
		}
	}
	resultDigest := ""
	if stopErr == nil {
		resultDigest, stopErr = retainResultWorkspace(workspace, o.dir, saved.ID)
	}
	current, err = o.read(saved.ID)
	if err != nil || current.ContainerID != id || current.State != "running" {
		return errors.New("retained state changed")
	}
	current.OutputSHA256 = digest
	current.State = "uncertain"
	if stopErr == nil {
		current.ResultWorkspaceSHA256 = resultDigest
		current.State = "finished"
		if current.CancelRequested {
			current.State = "cancelled"
		}
		current.ExitCode = &stop.ExitCode
		current.StopVerified = true
	}
	if err = o.save(current); err != nil {
		return err
	}
	if stopErr == nil {
		o.occupied = false
	} else {
		log.Printf("level=error msg=job_stop_error job_id=%q error=%q", saved.ID, stopErr.Error())
	}
	log.Printf("level=info msg=job_finished job_id=%q state=%q exit_code=%d provider=%q", current.ID, current.State, stop.ExitCode, current.Provider)
	o.notify(saved.ID)
	return stopErr
}

// ReconcileDocker proves local container stop without claiming lost output is complete.
func (o *Owner) ReconcileDocker(ctx context.Context, id string) (Receipt, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.closed {
		return Receipt{}, errors.New("owner is closed")
	}
	r, err := o.read(id)
	if err != nil {
		return r, err
	}
	if o.docker == nil || r.Provider != "docker" || r.Image != o.docker.Image || r.State != "uncertain" || r.ContainerID == "" {
		return r, errors.New("no recoverable exact container")
	}
	provider := *o.docker
	provider.Generations, provider.Population, provider.Kind = r.Generations, r.Population, r.Kind
	if r.ManagedCompile {
		pending, pendingErr := o.compilePending(r.ID)
		if pending || pendingErr != nil {
			return r, errors.New("managed compile outcome unresolved")
		}
		provider.CompileDir = r.CompileSocket
	}
	stop, err := provider.InspectStop(ctx, r.ContainerID, r.ID, filepath.Join(o.dir, r.ID+".original"), filepath.Join(o.dir, r.ID+".workspace"), r.Seed)
	if err == nil {
		digest, err := retainResultWorkspace(filepath.Join(o.dir, r.ID+".workspace"), o.dir, r.ID)
		if err != nil {
			return r, err
		}
		if r.ResultWorkspaceSHA256 != "" && r.ResultWorkspaceSHA256 != digest {
			return r, errors.New("retained result workspace changed")
		}
		r.ResultWorkspaceSHA256 = digest
		r.State, r.StopVerified, r.OutputIncomplete = "stopped_unsettled", true, true
		r.ExitCode = &stop.ExitCode
	} else {
		if !r.CancelRequested {
			return r, err
		}
		_, err = provider.InspectNeverStarted(ctx, r.ContainerID, r.ID, filepath.Join(o.dir, r.ID+".original"), filepath.Join(o.dir, r.ID+".workspace"), r.Seed)
		if err != nil {
			return r, err
		}
		r.State, r.StopVerified, r.NeverStarted = "cancelled", true, true
	}
	if err = o.save(r); err != nil {
		return r, err
	}
	o.occupied = false
	o.notify(id)
	return r, nil
}

// Cancel records a request; it does not claim a child or its descendants stopped.
func (o *Owner) Cancel(id string) (Receipt, error) {
	o.mu.Lock()
	var idle *CompileMediator
	defer func() {
		o.mu.Unlock()
		waitManagedCompileIdle(idle)
	}()
	if o.closed {
		return Receipt{}, errors.New("owner is closed")
	}
	r, err := o.read(id)
	if err != nil {
		return r, err
	}
	r.CancelRequested = true
	if o.queued[id] && r.State == "uncertain" {
		r.State = "cancelled"
		delete(o.queued, id)
		if r.ManagedCompile {
			idle = o.stopManagedCompile()
		}
	}
	if err := o.save(r); err != nil {
		return r, err
	}
	if r.State == "cancelled" {
		o.occupied = false
	}
	o.notify(id)
	if r.State == "running" && r.Provider == "docker" && r.ContainerID != "" && o.docker != nil {
		provider, containerID := *o.docker, r.ContainerID
		// Count the stop as in-flight work so Close waits for it.  Cancel
		// holds the owner lock and rejects a closed owner, so this Add
		// always precedes Close's Wait.
		o.workers.Add(1)
		go func() {
			defer o.workers.Done()
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			if err := provider.Stop(ctx, containerID); err != nil {
				log.Printf("level=error msg=job_cancel_stop_error job_id=%q error=%q", id, err.Error())
			}
		}()
	}
	return r, nil
}
