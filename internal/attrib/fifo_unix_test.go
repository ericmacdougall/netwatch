//go:build !windows

package attrib

import (
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestDirReaderDoesNotBlockOnFIFO(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "p"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := DirReader{Root: root}.Tail("p", 100); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO read accepted")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("FIFO open blocked")
	}
}

// A directory replaced by a FIFO (or a symlink to one) must not block List.
func TestDirReaderListDoesNotBlockOnFIFO(t *testing.T) {
	root := t.TempDir()
	if err := syscall.Mkfifo(filepath.Join(root, "d"), 0o600); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { _, err := DirReader{Root: root}.List("d", 10); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("FIFO listed as a directory")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("List blocked on a FIFO")
	}
}
