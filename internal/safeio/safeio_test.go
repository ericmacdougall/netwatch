//go:build !windows

package safeio

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// within fails the test, rather than hanging the run, if fn blocks.
func within(t *testing.T, d time.Duration, fn func()) {
	t.Helper()
	done := make(chan struct{})
	go func() { defer close(done); fn() }()
	select {
	case <-done:
	case <-time.After(d):
		t.Fatalf("blocked for more than %s", d)
	}
}

func write(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReadFileCorpus(t *testing.T) {
	dir := t.TempDir()
	good := write(t, dir, "good", "hello", 0o600)
	big := write(t, dir, "big", strings.Repeat("x", 101), 0o600)
	exact := write(t, dir, "exact", strings.Repeat("x", 100), 0o600)
	wide := write(t, dir, "wide", "x", 0o644)
	link := filepath.Join(dir, "link")
	if err := os.Symlink(good, link); err != nil {
		t.Fatal(err)
	}
	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	sub := filepath.Join(dir, "sub")
	if err := os.Mkdir(sub, 0o700); err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		name string
		path string
		o    Opts
		want error // nil means success
	}{
		{"regular", good, Opts{Max: 100}, nil},
		{"exactly max", exact, Opts{Max: 100}, nil},
		{"one over max", big, Opts{Max: 100}, ErrTooLarge},
		{"symlink", link, Opts{Max: 100}, ErrNotRegular},
		{"fifo", fifo, Opts{Max: 100}, ErrNotRegular},
		{"dev zero", "/dev/zero", Opts{Max: 100}, ErrNotRegular},
		{"directory", sub, Opts{Max: 100}, ErrNotRegular},
		{"wide perm rejected", wide, Opts{Max: 100, MaxPerm: 0o600}, ErrPerm},
		{"wide perm allowed w/o check", wide, Opts{Max: 100}, nil},
		{"own file owner check", good, Opts{Max: 100, RequireOwner: true, MaxPerm: 0o600}, nil},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			within(t, 3*time.Second, func() {
				_, err := ReadFile(c.path, c.o)
				if c.want == nil && err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if c.want != nil && !errors.Is(err, c.want) {
					t.Errorf("want %v, got %v", c.want, err)
				}
			})
		})
	}

	t.Run("no cap is an error", func(t *testing.T) {
		if _, err := ReadFile(good, Opts{}); err == nil {
			t.Error("Max 0 must not mean unlimited")
		}
	})
	t.Run("foreign owner", func(t *testing.T) {
		old := selfUID
		selfUID = func() int { return os.Getuid() + 1 }
		defer func() { selfUID = old }()
		if _, err := ReadFile(good, Opts{Max: 100, RequireOwner: true}); !errors.Is(err, ErrOwner) {
			t.Errorf("want ErrOwner, got %v", err)
		}
	})
	t.Run("missing", func(t *testing.T) {
		if _, err := ReadFile(filepath.Join(dir, "nope"), Opts{Max: 1}); !errors.Is(err, os.ErrNotExist) {
			t.Errorf("want ErrNotExist, got %v", err)
		}
	})
}

func TestTailLines(t *testing.T) {
	dir := t.TempDir()
	long := strings.Repeat("L", 50)
	p := write(t, dir, "log", "one\ntwo\n"+long+"\nthree\nfour", 0o600)
	got, err := TailLines(p, 3, 10, Opts{Max: 1 << 20})
	if err != nil {
		t.Fatal(err)
	}
	// "four" has no newline but is kept; the 50-byte line is dropped.
	want := []string{"two", "three", "four"}
	if len(got) != len(want) {
		t.Fatalf("got %q", got)
	}
	for i := range want {
		if string(got[i]) != want[i] {
			t.Errorf("line %d: %q want %q", i, got[i], want[i])
		}
	}

	// A window that cuts a line: the fragment must be dropped.
	p2 := write(t, dir, "log2", "aaaaaaaaaa\nbb\ncc\n", 0o600)
	got, err = TailLines(p2, 10, 100, Opts{Max: 8})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || string(got[0]) != "bb" || string(got[1]) != "cc" {
		t.Errorf("window cut: got %q", got)
	}

	fifo := filepath.Join(dir, "fifo")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatal(err)
	}
	within(t, 3*time.Second, func() {
		if _, err := TailLines(fifo, 3, 10, Opts{Max: 100}); !errors.Is(err, ErrNotRegular) {
			t.Errorf("fifo: %v", err)
		}
	})
}

func TestWriteFileAtomic(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(dir, "mode", []byte("alert")); err != nil {
		t.Fatal(err)
	}
	if err := WriteFileAtomic(dir, "mode", []byte("pause")); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(filepath.Join(dir, "mode"))
	if string(b) != "pause" {
		t.Errorf("content %q", b)
	}
	fi, _ := os.Stat(filepath.Join(dir, "mode"))
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}
	ents, _ := os.ReadDir(dir)
	if len(ents) != 1 {
		t.Errorf("temp file left behind: %v", ents)
	}

	t.Run("bad names", func(t *testing.T) {
		for _, n := range []string{"", ".", "..", "a/b", "../x", `a\b`} {
			if WriteFileAtomic(dir, n, nil) == nil {
				t.Errorf("name %q accepted", n)
			}
		}
	})
	t.Run("world-readable dir", func(t *testing.T) {
		d := filepath.Join(t.TempDir(), "open")
		os.Mkdir(d, 0o755)
		os.Chmod(d, 0o755)
		if err := WriteFileAtomic(d, "f", []byte("x")); !errors.Is(err, ErrPerm) {
			t.Errorf("want ErrPerm, got %v", err)
		}
	})
	t.Run("foreign owned dir", func(t *testing.T) {
		old := selfUID
		selfUID = func() int { return os.Getuid() + 1 }
		defer func() { selfUID = old }()
		if err := WriteFileAtomic(dir, "f", []byte("x")); !errors.Is(err, ErrOwner) {
			t.Errorf("want ErrOwner, got %v", err)
		}
	})
	t.Run("symlinked dir", func(t *testing.T) {
		l := filepath.Join(t.TempDir(), "l")
		os.Symlink(dir, l)
		if err := WriteFileAtomic(l, "f", []byte("x")); err == nil {
			t.Error("symlinked dir accepted")
		}
	})
	t.Run("symlink at target is replaced not followed", func(t *testing.T) {
		victim := filepath.Join(t.TempDir(), "victim")
		os.WriteFile(victim, []byte("keep"), 0o600)
		os.Symlink(victim, filepath.Join(dir, "evil"))
		if err := WriteFileAtomic(dir, "evil", []byte("new")); err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(victim); string(b) != "keep" {
			t.Errorf("write followed the symlink: %q", b)
		}
	})
}

func TestOpenAppend(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "events")
	f, err := OpenAppend(p)
	if err != nil {
		t.Fatal(err)
	}
	f.WriteString("a\n")
	f.Close()
	f, _ = OpenAppend(p)
	f.WriteString("b\n")
	f.Close()
	if b, _ := os.ReadFile(p); string(b) != "a\nb\n" {
		t.Errorf("content %q", b)
	}
	if fi, _ := os.Stat(p); fi.Mode().Perm() != 0o600 {
		t.Errorf("mode %v", fi.Mode().Perm())
	}

	t.Run("symlink", func(t *testing.T) {
		victim := write(t, dir, "victim", "keep", 0o600)
		l := filepath.Join(dir, "l")
		os.Symlink(victim, l)
		if _, err := OpenAppend(l); !errors.Is(err, ErrNotRegular) {
			t.Errorf("want ErrNotRegular, got %v", err)
		}
	})
	t.Run("fifo does not block", func(t *testing.T) {
		fifo := filepath.Join(dir, "fifo")
		syscall.Mkfifo(fifo, 0o600)
		within(t, 3*time.Second, func() {
			if f, err := OpenAppend(fifo); err == nil {
				f.Close()
				t.Error("fifo accepted")
			}
		})
	})
	t.Run("foreign owner", func(t *testing.T) {
		old := selfUID
		selfUID = func() int { return os.Getuid() + 1 }
		defer func() { selfUID = old }()
		if _, err := OpenAppend(p); !errors.Is(err, ErrOwner) {
			t.Errorf("want ErrOwner, got %v", err)
		}
	})
}
