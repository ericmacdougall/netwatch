package main

import (
	"bufio"
	"bytes"
	"context"
	"io"
	"os"
	"os/signal"
	"syscall"
	"time"
)

func (a *app) cmdTail(args []string) error {
	fs := a.flags("tail")
	n := fs.Int("n", 10, "number of recent events to print first")
	noFollow := fs.Bool("no-follow", false, "print and exit")
	if err := parse(fs, args); err != nil {
		return err
	}
	path, _ := a.paths()
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return follow(ctx, path, *n, !*noFollow, a.stdout, time.Second)
}

// lastLines returns the final n lines of f, reading at most 1 MiB.
func lastLines(f *os.File, n int) ([]byte, int64, error) {
	st, err := f.Stat()
	if err != nil {
		return nil, 0, err
	}
	size := st.Size()
	start := size - 1<<20
	if start < 0 {
		start = 0
	}
	buf := make([]byte, size-start)
	if _, err := f.ReadAt(buf, start); err != nil && err != io.EOF {
		return nil, 0, err
	}
	lines := bytes.SplitAfter(buf, []byte("\n"))
	if len(lines) > 0 && len(lines[len(lines)-1]) == 0 {
		lines = lines[:len(lines)-1]
	}
	if start > 0 && len(lines) > 0 {
		lines = lines[1:] // first line is probably partial
	}
	if n >= 0 && len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return bytes.Join(lines, nil), size, nil
}

// follow prints the tail of path and then new lines as they are appended,
// reopening the file when it is rotated (it shrinks or is replaced).
func follow(ctx context.Context, path string, n int, keepGoing bool, w io.Writer, poll time.Duration) error {
	var off int64
	if f, err := os.Open(path); err == nil {
		out, size, err := lastLines(f, n)
		f.Close()
		if err != nil {
			return err
		}
		_, _ = w.Write(out)
		off = size
	} else if !os.IsNotExist(err) {
		return err
	}
	if !keepGoing {
		return nil
	}
	var lastInfo os.FileInfo
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-time.After(poll):
		}
		st, err := os.Stat(path)
		if err != nil {
			continue
		}
		if st.Size() < off || (lastInfo != nil && !os.SameFile(st, lastInfo)) {
			off = 0 // rotated
		}
		lastInfo = st
		if st.Size() == off {
			continue
		}
		f, err := os.Open(path)
		if err != nil {
			continue
		}
		if _, err := f.Seek(off, io.SeekStart); err == nil {
			r := bufio.NewReader(f)
			for {
				line, err := r.ReadBytes('\n')
				if len(line) > 0 && line[len(line)-1] == '\n' {
					_, _ = w.Write(line)
					off += int64(len(line))
				}
				if err != nil {
					break
				}
			}
		}
		f.Close()
	}
}
