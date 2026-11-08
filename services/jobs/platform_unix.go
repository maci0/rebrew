//go:build !windows

package jobs

import (
	"os"
	"os/exec"
	"syscall"
)

// tryLockOwner takes the non-blocking exclusive flock on the owner lock file.
// Windows has no syscall.Flock; platform_windows.go documents the fallback.
func tryLockOwner(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}

// configureJobProcess makes cmd lead its own process group and wires Cancel
// to kill the whole group. There is no process-group kill on Windows; see
// platform_windows.go for the portable fallback (kill the direct child).
func configureJobProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
