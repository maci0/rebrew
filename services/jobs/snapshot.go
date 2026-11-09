package jobs

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const snapshotByteLimit = 256 * 1024 * 1024
const snapshotFileLimit = 10000

// WorkspaceDigest computes the same bounded full-tree digest used at admission.
// The caller must retain and submit the resulting pin as part of its intent.
func WorkspaceDigest(root string) (string, error) {
	temp, err := os.MkdirTemp("", "rebrew-digest-")
	if err != nil {
		return "", err
	}
	defer os.RemoveAll(temp)
	_, digest, err := snapshot(root, temp)
	return digest, err
}

func hashField(h hash.Hash, b []byte) {
	var size [8]byte
	binary.BigEndian.PutUint64(size[:], uint64(len(b)))
	_, _ = h.Write(size[:])
	_, _ = h.Write(b)
}

// snapshot copies regular files only. Any ambiguous or oversized input refuses admission.
func snapshot(root, dir string) (string, string, error) {
	stage, err := os.MkdirTemp(dir, ".snapshot-")
	if err != nil {
		return "", "", err
	}
	keep := false
	defer func() {
		if !keep {
			makeTreeRemovable(stage)
			_ = os.RemoveAll(stage)
		}
	}()
	h := sha256.New()
	count := 0
	var total int64
	err = filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, e := filepath.Rel(root, path)
		if e != nil {
			return e
		}
		if rel == "." {
			return nil
		}
		count++
		if count > snapshotFileLimit {
			return errors.New("workspace exceeds snapshot limits")
		}
		info, e := entry.Info()
		if e != nil {
			return e
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("workspace symlinks are not supported")
		}
		dest := filepath.Join(stage, rel)
		if info.IsDir() {
			hashField(h, []byte("d"))
			hashField(h, []byte(rel))
			return os.Mkdir(dest, 0700)
		}
		if !info.Mode().IsRegular() {
			return errors.New("workspace contains a non-regular file")
		}
		total += info.Size()
		if info.Size() < 0 || total > snapshotByteLimit {
			return errors.New("workspace exceeds snapshot limits")
		}
		f, e := os.Open(path)
		if e != nil {
			return e
		}
		// Not deferred: this closure runs once per file within one walk,
		// so defer would hold one fd per file until the walk ends.
		before, e := f.Stat()
		if e != nil || !os.SameFile(info, before) {
			_ = f.Close()
			return errors.New("workspace changed during snapshot")
		}
		out, e := os.OpenFile(dest, os.O_CREATE|os.O_EXCL|os.O_WRONLY, info.Mode().Perm()&0700|0600)
		if e != nil {
			_ = f.Close()
			return e
		}
		hashField(h, []byte("f"))
		hashField(h, []byte(rel))
		hashField(h, []byte{byte(info.Mode().Perm() & 0100)})
		var length [8]byte
		binary.BigEndian.PutUint64(length[:], uint64(info.Size()))
		_, _ = h.Write(length[:])
		written, e := io.Copy(io.MultiWriter(out, h), io.LimitReader(f, info.Size()+1))
		if e == nil {
			e = out.Sync()
		}
		if closeErr := out.Close(); e == nil {
			e = closeErr
		}
		after, statErr := f.Stat()
		if e != nil {
			_ = f.Close()
			return e
		}
		if statErr != nil || written != info.Size() || after.Size() != before.Size() || !after.ModTime().Equal(before.ModTime()) {
			_ = f.Close()
			return errors.New("workspace changed during snapshot")
		}
		return f.Close()
	})
	if err != nil {
		return "", "", err
	}
	_ = filepath.WalkDir(stage, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil || !entry.IsDir() {
			return walkErr
		}
		f, err := os.Open(path)
		if err != nil {
			return nil
		}
		if err := f.Sync(); err != nil {
			_ = f.Close()
			return nil
		}
		_ = f.Close()
		return nil
	})
	keep = true
	return stage, hex.EncodeToString(h.Sum(nil)), nil
}

func sealSnapshot(root string) error {
	return filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if info.IsDir() {
			return os.Chmod(path, 0500)
		}
		return os.Chmod(path, info.Mode().Perm()&0500)
	})
}

// makeTreeRemovable restores owner write access under a sealed tree so it can
// be deleted; file modes do not stop removal, directory modes do.
func makeTreeRemovable(root string) {
	_ = filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err == nil && entry.IsDir() {
			return os.Chmod(path, 0700)
		}
		return err
	})
}

// retainResultWorkspace seals the complete post-stop tree before capacity release.
func retainResultWorkspace(workspace, dir, id string) (string, error) {
	if !validHex(id, 64) {
		return "", errors.New("invalid result identity")
	}
	target := filepath.Join(dir, id+".result")
	info, err := os.Lstat(target)
	if err == nil {
		if !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
			return "", errors.New("invalid retained result")
		}
		stage, digest, err := snapshot(target, dir)
		if err != nil {
			return "", err
		}
		defer os.RemoveAll(stage)
		return digest, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	stage, digest, err := snapshot(workspace, dir)
	if err != nil {
		return "", err
	}
	keep := false
	defer func() {
		if !keep {
			makeTreeRemovable(stage)
			_ = os.RemoveAll(stage)
		}
	}()
	if err = sealSnapshot(stage); err != nil {
		return "", err
	}
	if err = os.Rename(stage, target); err != nil {
		return "", err
	}
	keep = true
	_ = syncDir(dir)
	return digest, nil
}
