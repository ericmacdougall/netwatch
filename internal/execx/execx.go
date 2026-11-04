// Package execx runs helper commands with a deadline and without flashing
// console windows on Windows.
package execx

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

// MaxOutput bounds captured stdout so a misbehaving helper cannot balloon
// netwatch's memory.
const MaxOutput = 16 << 20

type limitedBuffer struct {
	bytes.Buffer
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if room := MaxOutput - b.Len(); room < len(p) {
		if room > 0 {
			b.Buffer.Write(p[:room])
		}
		b.truncated = true
		return len(p), nil
	}
	return b.Buffer.Write(p)
}

// Output runs name with args and returns stdout. A non-zero exit is an error
// that includes the first line of stderr.
func Output(ctx context.Context, timeout time.Duration, name string, args ...string) ([]byte, error) {
	return OutputEnv(ctx, timeout, nil, name, args...)
}

// OutputEnv is Output with extra environment variables (KEY=value) added to
// the inherited environment.
func OutputEnv(ctx context.Context, timeout time.Duration, env []string, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	hide(cmd)
	// Do not wait forever for grandchildren holding the output pipes.
	cmd.WaitDelay = 2 * time.Second
	if len(env) > 0 {
		cmd.Env = append(os.Environ(), env...)
	}
	var stdout limitedBuffer
	var stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if i := strings.IndexByte(msg, '\n'); i >= 0 {
			msg = msg[:i]
		}
		if ctx.Err() == context.DeadlineExceeded {
			return stdout.Bytes(), fmt.Errorf("%s: timed out after %s", name, timeout)
		}
		if msg != "" {
			return stdout.Bytes(), fmt.Errorf("%s: %w: %s", name, err, msg)
		}
		return stdout.Bytes(), fmt.Errorf("%s: %w", name, err)
	}
	return stdout.Bytes(), nil
}

// Command returns an exec.Cmd prepared like Output's, for callers that need
// to manage the process themselves.
func Command(ctx context.Context, name string, args ...string) *exec.Cmd {
	cmd := exec.CommandContext(ctx, name, args...)
	hide(cmd)
	return cmd
}
