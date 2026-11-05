//go:build darwin

package resmon

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/ericmacdougall/netwatch/internal/resources"
)

// The adapter must watch the processes it is given and record a child they
// fork afterwards. The watched "Claude" here is the test process itself and
// the child is a sleep it spawns; nothing else is touched.
func TestKqWatcherRecordsChildOfWatchedProcess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	r := resources.New()
	w := NewWatcher(ctx, r, func(what string, err error) { t.Logf("%s: %v", what, err) })
	if w == nil {
		t.Fatal("no watcher on darwin")
	}
	var self resources.Proc
	if err := r.Probe(os.Getpid(), &self); err != nil {
		t.Fatal(err)
	}
	self.Exe = r.ExePath(os.Getpid())
	w.Watch([]resources.Proc{self})

	cmd := exec.Command("/bin/sleep", "5")
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = cmd.Process.Kill(); _ = cmd.Wait() }()

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		w.Watch([]resources.Proc{self}) // also settles pending records
		for _, rec := range w.Records() {
			if rec.PID == cmd.Process.Pid && rec.ClaudePID == os.Getpid() {
				return
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("child %d was not recorded; records: %+v", cmd.Process.Pid, w.Records())
}
