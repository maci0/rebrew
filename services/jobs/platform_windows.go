//go:build windows

package jobs

import (
	"errors"
	"os"
	"os/exec"
)

// tryLockOwner is a documented no-op on Windows: syscall.Flock does not exist
// there, and the owner lock file is held only for the integer lifetime of the
// process (Close releases it by closing the file). A second rebrew-jobs on
// the same directory can therefore start instead of failing fast; the receipt
// state machine (running→uncertain on open) still refuses to replay work.
// This mirrors file_handle_lock in src/rebrew/utils.py, which also accepts
// the reduced guarantee on Windows rather than blocking the build. Fixing
// this properly needs a LockFileEx wrapper via golang.org/x/sys/windows,
// which this module does not depend on.
func tryLockOwner(f *os.File) error {
	_ = f
	return nil
}

// configureJobProcess kills only the direct child on Cancel. Windows has no
// process groups or syscall.Kill, so the Unix sibling's group kill cannot be
// expressed; grandchildren the child spawns survive, as with subprocess
// Popen.kill in the Python service (stop_process_tree falls back to
// proc.kill() when os.killpg is absent). A future fix could use
// golang.org/x/sys/windows Job Objects to bound the tree.
func configureJobProcess(cmd *exec.Cmd) {
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return nil
		}
		if err := cmd.Process.Kill(); err != nil {
			return errors.Join(err)
		}
		return nil
	}
}
