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
