package jobs

import (
	"encoding/json"
	"os"
	"path/filepath"
)

// syncDir best-effort fsyncs dir so a rename into it reaches disk. Opening
// a directory for fsync is not portable (Windows refuses it), so failure
// here degrades to the atomic rename alone, mirroring
// rebrew.utils._fsync_path in the Python service.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return nil
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return nil
	}
	return nil
}

// writeJSONAtomic replaces dir/name with the JSON encoding of value.
func writeJSONAtomic(dir, pattern, name string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(dir, pattern)
	if err != nil {
		return err
	}
	tmp := f.Name()
	defer os.Remove(tmp)
	if err = f.Chmod(0600); err == nil {
		_, err = f.Write(b)
	}
	if err == nil {
		err = f.Sync()
	}
	if e := f.Close(); err == nil {
		err = e
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, filepath.Join(dir, name)); err != nil {
		return err
	}
	return syncDir(dir)
}
