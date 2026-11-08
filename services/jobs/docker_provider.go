package jobs

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

// DockerReceipt describes an exact no-network container, not any remote compile.
type DockerReceipt struct {
	ID       string `json:"container_id"`
	ExitCode int    `json:"exit_code"`
	Image    string `json:"image"`
}
type DockerProvider struct {
	Binary, Image, CompileDir, Kind string
	Generations, Population         int
}

func matchArguments(seed string, generations, population int) []string {
	args := []string{"match", "run", seed, "--json"}
	if generations != 0 || population != 0 {
		args = append(args, "--generations", strconv.Itoa(generations), "--pop-size", strconv.Itoa(population))
	}
	return args
}

func jobArguments(kind, seed string, generations, population int) []string {
	if kind == "catalog" {
		return []string{"coverage", "catalog", "--json"}
	}
	return matchArguments(seed, generations, population)
}

func validHex(s string, n int) bool {
	if len(s) != n {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil && strings.ToLower(s) == s
}
func (p DockerProvider) check() error {
	if p.Kind != "" && p.Kind != "match" && p.Kind != "catalog" {
		return errors.New("invalid job kind")
	}
	if !filepath.IsAbs(p.Binary) || !strings.HasPrefix(p.Image, "sha256:") || !validHex(strings.TrimPrefix(p.Image, "sha256:"), 64) {
		return errors.New("docker binary and pinned image required")
	}
	if p.CompileDir != "" && (!filepath.IsAbs(p.CompileDir) || strings.ContainsAny(p.CompileDir, ",\n\r")) {
		return errors.New("invalid compile socket directory")
	}
	if (p.Generations != 0 || p.Population != 0) && (p.Generations < 1 || p.Generations > 10000 || p.Population < 2 || p.Population > 4096) {
		return errors.New("invalid match bounds")
	}
	return nil
}

// Create allocates exactly one named, isolated container; unknown results must not be retried.
func (p DockerProvider) Create(ctx context.Context, original, workspace, id, seed string) (string, error) {
	if err := p.check(); err != nil {
		return "", err
	}
	if !validHex(id, 64) || seed == "" || filepath.IsAbs(seed) || strings.HasPrefix(filepath.Clean(seed), "..") || !filepath.IsAbs(workspace) || !filepath.IsAbs(original) || original == workspace || strings.ContainsAny(original+workspace, ",\n\r") || isRoot() {
		return "", errors.New("invalid allocation")
	}
	originalInfo, originalErr := os.Stat(original)
	if originalErr != nil || !originalInfo.IsDir() {
		return "", errors.New("original unavailable")
	}
	info, err := os.Stat(workspace)
	if err != nil || !info.IsDir() {
		return "", errors.New("workspace unavailable")
	}
	args := []string{"create", "--name", "rebrew-job-" + id, "--label", "relumea.rebrew.job=" + id, "--network", "none", "--read-only", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--pids-limit", "128", "--ulimit", "nofile=1024:1024", "--memory", "1g", "--cpus", "1", "--user", processUser(), "--tmpfs", "/tmp:rw,nosuid,nodev,noexec,size=64m", "--mount", "type=bind,src=" + workspace + ",dst=/workspace", "--mount", "type=bind,src=" + original + ",dst=/original,readonly"}
	if p.CompileDir != "" {
		info, err := os.Stat(p.CompileDir)
		if err != nil || !isPrivateDir(info) {
			return "", errors.New("compile socket directory unavailable")
		}
		args = append(args, "--mount", "type=bind,src="+p.CompileDir+",dst=/run/rebrew-job,readonly", "--env", "REBREW_RECOMPILE_URL=http://rebrew-job", "--env", "REBREW_JOB_COMPILE_SOCKET=/run/rebrew-job/owner.sock")
	}
	args = append(args, "--workdir", "/workspace", "--entrypoint", "/opt/venv/bin/rebrew", p.Image)
	args = append(args, jobArguments(p.Kind, seed, p.Generations, p.Population)...)
	out, err := exec.CommandContext(ctx, p.Binary, args...).Output()
	if err != nil {
		return "", errors.New("container creation outcome unknown")
	}
	container := strings.TrimSpace(string(out))
	if !validHex(container, 64) {
		return "", errors.New("container creation identity unknown")
	}
	return container, nil
}

// Start waits for the attached container. A lost attach response is not a stop receipt.
func (p DockerProvider) Start(ctx context.Context, id string, out io.Writer) error {
	if err := p.check(); err != nil {
		return err
	}
	if !validHex(id, 64) {
		return errors.New("invalid container identity")
	}
	cmd := exec.CommandContext(ctx, p.Binary, "start", "--attach", id)
	cmd.Stdout = out
	cmd.Stderr = out
	return cmd.Run()
}

// StartDetached completes the start request before the owner accepts a cancel.
// An error can still follow a successful start and must be reconciled.
func (p DockerProvider) StartDetached(ctx context.Context, id string) error {
	if err := p.check(); err != nil {
		return err
	}
	if !validHex(id, 64) {
		return errors.New("invalid container identity")
	}
	return exec.CommandContext(ctx, p.Binary, "start", id).Run()
}

// Follow streams the retained Docker log; successful return alone is not a stop proof.
func (p DockerProvider) Follow(ctx context.Context, id string, out io.Writer) error {
	if err := p.check(); err != nil {
		return err
	}
	if !validHex(id, 64) {
		return errors.New("invalid container identity")
	}
	cmd := exec.CommandContext(ctx, p.Binary, "logs", "--follow", id)
	cmd.Stdout, cmd.Stderr = out, out
	return cmd.Run()
}

// InspectStop verifies the exact retained ID and isolation before claiming local termination.
func (p DockerProvider) InspectStop(ctx context.Context, id, job, original, workspace, seed string) (DockerReceipt, error) {
	return p.inspect(ctx, id, job, original, workspace, seed, false)
}

// InspectNeverStarted accepts only the daemon's never-started created state.
func (p DockerProvider) InspectNeverStarted(ctx context.Context, id, job, original, workspace, seed string) (DockerReceipt, error) {
	return p.inspect(ctx, id, job, original, workspace, seed, true)
}

func (p DockerProvider) inspect(ctx context.Context, id, job, original, workspace, seed string, created bool) (DockerReceipt, error) {
	if err := p.check(); err != nil {
		return DockerReceipt{}, err
	}
	if !validHex(id, 64) || !validHex(job, 64) {
		return DockerReceipt{}, errors.New("invalid identity")
	}
	out, err := exec.CommandContext(ctx, p.Binary, "inspect", id).Output()
	if err != nil {
		return DockerReceipt{}, errors.New("container observation unavailable")
	}
	var rows []struct {
		ID, Image string
		Config    struct {
			Labels               map[string]string
			User, WorkingDir     string
			Entrypoint, Cmd, Env []string
		}
		State struct {
			Running               bool
			Status, Error         string
			StartedAt, FinishedAt string
			Pid                   int
			ExitCode              int
		}
		HostConfig struct {
			NetworkMode, PidMode, IpcMode, UsernsMode string
			ReadonlyRootfs, Privileged                bool
			CapDrop                                   []string
			SecurityOpt                               []string
			PidsLimit                                 int64
			Memory                                    int64
			NanoCpus                                  int64
			Ulimits                                   []struct {
				Name       string
				Soft, Hard int64
			}
		}
		Mounts []struct {
			Type, Source, Destination string
			RW                        bool
		}
	}
	if json.Unmarshal(out, &rows) != nil || len(rows) != 1 {
		return DockerReceipt{}, errors.New("malformed container observation")
	}
	v := rows[0]
	stateOK := !v.State.Running && v.State.Status == "exited" && v.State.Error == ""
	if created {
		stateOK = !v.State.Running && v.State.Status == "created" && v.State.Error == "" && v.State.Pid == 0 && v.State.StartedAt == "0001-01-01T00:00:00Z" && v.State.FinishedAt == "0001-01-01T00:00:00Z"
	}
	mountCount := 2
	if p.CompileDir != "" {
		mountCount = 3
	}
	if v.ID != id || v.Image != p.Image || v.Config.Labels["relumea.rebrew.job"] != job || v.Config.User != processUser() || v.Config.WorkingDir != "/workspace" || len(v.Config.Entrypoint) != 1 || v.Config.Entrypoint[0] != "/opt/venv/bin/rebrew" || strings.Join(v.Config.Cmd, "\x00") != strings.Join(jobArguments(p.Kind, seed, p.Generations, p.Population), "\x00") || !stateOK || v.HostConfig.NetworkMode != "none" || v.HostConfig.PidMode == "host" || v.HostConfig.IpcMode == "host" || v.HostConfig.UsernsMode == "host" || !v.HostConfig.ReadonlyRootfs || v.HostConfig.Privileged || len(v.HostConfig.CapDrop) != 1 || v.HostConfig.CapDrop[0] != "ALL" || v.HostConfig.PidsLimit != 128 || v.HostConfig.Memory != 1073741824 || v.HostConfig.NanoCpus != 1000000000 || len(v.Mounts) != mountCount {
		return DockerReceipt{}, errors.New("container stop or isolation is unproven")
	}
	noPrivileges := false
	for _, opt := range v.HostConfig.SecurityOpt {
		if opt == "no-new-privileges" || opt == "no-new-privileges=true" {
			noPrivileges = true
		}
	}
	if !noPrivileges {
		return DockerReceipt{}, errors.New("container security differs")
	}
	nofile := false
	for _, limit := range v.HostConfig.Ulimits {
		if limit.Name == "nofile" {
			if nofile || limit.Soft != 1024 || limit.Hard != 1024 {
				return DockerReceipt{}, errors.New("container file limit differs")
			}
			nofile = true
		}
	}
	if !nofile {
		return DockerReceipt{}, errors.New("container file limit missing")
	}
	if p.CompileDir != "" {
		foundURL, foundSocket := false, false
		for _, env := range v.Config.Env {
			if strings.HasPrefix(env, "REBREW_RECOMPILE_URL=") {
				if foundURL || env != "REBREW_RECOMPILE_URL=http://rebrew-job" {
					return DockerReceipt{}, errors.New("compile environment differs")
				}
				foundURL = true
			}
			if strings.HasPrefix(env, "REBREW_JOB_COMPILE_SOCKET=") {
				if foundSocket || env != "REBREW_JOB_COMPILE_SOCKET=/run/rebrew-job/owner.sock" {
					return DockerReceipt{}, errors.New("compile environment differs")
				}
				foundSocket = true
			}
		}
		if !foundURL || !foundSocket {
			return DockerReceipt{}, errors.New("compile environment missing")
		}
	}
	originalFound, workspaceFound, compileFound := false, false, p.CompileDir == ""
	for _, m := range v.Mounts {
		if m.Type != "bind" {
			return DockerReceipt{}, errors.New("container mount differs")
		}
		if m.Source == workspace && m.Destination == "/workspace" && m.RW {
			workspaceFound = true
		}
		if m.Source == original && m.Destination == "/original" && !m.RW {
			originalFound = true
		}
		if m.Source == p.CompileDir && m.Destination == "/run/rebrew-job" && !m.RW {
			compileFound = true
		}
	}
	if !originalFound || !workspaceFound || !compileFound {
		return DockerReceipt{}, errors.New("container mount differs")
	}
	return DockerReceipt{ID: id, ExitCode: v.State.ExitCode, Image: v.Image}, nil
}

// Stop requests termination; callers must still use InspectStop before releasing capacity.
func (p DockerProvider) Stop(ctx context.Context, id string) error {
	if err := p.check(); err != nil {
		return err
	}
	if !validHex(id, 64) {
		return errors.New("invalid container identity")
	}
	return exec.CommandContext(ctx, p.Binary, "kill", "--signal", strconv.Itoa(9), id).Run()
}
