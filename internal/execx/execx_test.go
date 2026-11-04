package execx

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestOutputErrorsAndTimeout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("uses POSIX sh")
	}
	out, err := Output(context.Background(), 5*time.Second, "sh", "-c", "echo hi")
	if err != nil || strings.TrimSpace(string(out)) != "hi" {
		t.Fatalf("got %q %v", out, err)
	}
	_, err = Output(context.Background(), 5*time.Second, "sh", "-c", "echo boom >&2; exit 3")
	if err == nil || !strings.Contains(err.Error(), "boom") {
		t.Fatalf("want stderr in error, got %v", err)
	}
	_, err = Output(context.Background(), 100*time.Millisecond, "sh", "-c", "sleep 5")
	if err == nil || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("want timeout, got %v", err)
	}
}
