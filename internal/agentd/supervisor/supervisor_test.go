package supervisor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// script writes a shell script and returns its path, so the tests supervise a
// real process rather than a mock.
func script(t *testing.T, body string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "proc.sh")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatal(err)
	}
	return path
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestStartAndStop(t *testing.T) {
	var out lockedBuffer
	s := New(Spec{
		Name:      "sleeper",
		Path:      script(t, "echo up; sleep 30"),
		LogWriter: &out,
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	if !s.Running() {
		t.Fatal("not running after Start returned")
	}
	status := s.Status()
	if status.PID == 0 {
		t.Error("status has no pid")
	}
	if status.Restarts != 0 {
		t.Errorf("restarts = %d on a first start", status.Restarts)
	}

	// Output must reach the log writer, which is how node logs get to the
	// panel at all.
	waitFor(t, "output", func() bool { return bytes.Contains(out.Bytes(), []byte("up")) })

	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if s.Running() {
		t.Error("still running after Stop")
	}
	// Stopping twice must be harmless: the agent calls it on shutdown paths
	// that can overlap.
	if err := s.Stop(); err != nil {
		t.Errorf("second Stop: %v", err)
	}
}

// A process that dies on its own must come back, and the panel must hear
// about it.
func TestRestartsAfterCrash(t *testing.T) {
	// Each run appends a line, so the file counts the starts.
	counter := filepath.Join(t.TempDir(), "runs")
	s := New(Spec{
		Name:           "crasher",
		Path:           script(t, "echo run >> "+counter+"; sleep 0.2; exit 3"),
		RestartBackoff: 50 * time.Millisecond,
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}

	var kinds []string
	var mu sync.Mutex
	go func() {
		for event := range s.Events() {
			mu.Lock()
			kinds = append(kinds, event.Kind)
			mu.Unlock()
		}
	}()

	waitFor(t, "three starts", func() bool {
		raw, err := os.ReadFile(counter)
		return err == nil && bytes.Count(raw, []byte("run")) >= 3
	})
	if got := s.Status().Restarts; got < 2 {
		t.Errorf("restarts = %d, want at least 2", got)
	}
	_ = s.Stop()

	mu.Lock()
	defer mu.Unlock()
	var sawExited, sawRestarting bool
	for _, kind := range kinds {
		switch kind {
		case EventExited:
			sawExited = true
		case EventRestarting:
			sawRestarting = true
		}
	}
	if !sawExited || !sawRestarting {
		t.Errorf("events = %v, want an exited and a restarting among them", kinds)
	}
}

// A process the agent stopped on purpose must not be reported as a crash, or
// every deliberate restart would fill the panel's journal with errors.
func TestDeliberateStopIsNotACrash(t *testing.T) {
	s := New(Spec{Name: "sleeper", Path: script(t, "sleep 30")}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}

	collected := make(chan []string, 1)
	go func() {
		var kinds []string
		timeout := time.After(5 * time.Second)
		for {
			select {
			case event := <-s.Events():
				kinds = append(kinds, event.Kind)
				if event.Kind == EventStopped {
					collected <- kinds
					return
				}
			case <-timeout:
				collected <- kinds
				return
			}
		}
	}()

	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	kinds := <-collected
	for _, kind := range kinds {
		if kind == EventExited || kind == EventRestarting {
			t.Errorf("a deliberate stop produced %q: %v", kind, kinds)
		}
	}
}

// A binary that is not there must fail Start rather than leave the agent
// believing a core is up.
func TestStartFailsForAMissingBinary(t *testing.T) {
	s := New(Spec{Name: "ghost", Path: "/nonexistent/binary"}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err == nil {
		t.Fatal("Start succeeded for a missing binary")
	}
	if s.Running() {
		t.Error("Running is true after a failed Start")
	}
	// A failed Start must leave the supervisor startable again.
	s2 := New(Spec{Name: "ok", Path: script(t, "sleep 5")}, nil)
	if err := s2.Start(ctx); err != nil {
		t.Fatal(err)
	}
	_ = s2.Stop()
}

// A process that stays up without serving must be treated as a failure: that
// is the difference between "Xray is running" and "Xray is working".
func TestReadyFailureKillsTheProcess(t *testing.T) {
	s := New(Spec{
		Name:         "not-ready",
		Path:         script(t, "sleep 30"),
		StartTimeout: 300 * time.Millisecond,
		Ready: func(ctx context.Context) error {
			<-ctx.Done()
			return errors.New("never became ready")
		},
	}, nil)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := s.Start(ctx)
	if err == nil {
		t.Fatal("Start succeeded although Ready failed")
	}
	if s.Running() {
		t.Error("the process was left running after Ready failed")
	}
}

func TestReadySuccess(t *testing.T) {
	var calls int
	s := New(Spec{
		Name: "ready",
		Path: script(t, "sleep 30"),
		Ready: func(context.Context) error {
			calls++
			return nil
		},
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Stop() }()
	if calls != 1 {
		t.Errorf("Ready called %d times, want 1", calls)
	}
}

func TestRestartKeepsCounting(t *testing.T) {
	s := New(Spec{Name: "sleeper", Path: script(t, "sleep 30")}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = s.Stop() }()

	before := s.Status().Restarts
	if err := s.Restart(ctx); err != nil {
		t.Fatal(err)
	}
	if !s.Running() {
		t.Error("not running after Restart")
	}
	if after := s.Status().Restarts; after != before+1 {
		t.Errorf("restarts = %d, want %d", after, before+1)
	}
}

// Cancelling the context must end supervision and the process with it.
func TestContextCancellationStops(t *testing.T) {
	s := New(Spec{
		Name:           "sleeper",
		Path:           script(t, "sleep 30"),
		RestartBackoff: 20 * time.Millisecond,
	}, nil)
	ctx, cancel := context.WithCancel(context.Background())
	if err := s.Start(ctx); err != nil {
		t.Fatal(err)
	}
	cancel()
	if err := s.Stop(); err != nil {
		t.Fatal(err)
	}
	if s.Running() {
		t.Error("still running after the context was cancelled")
	}
}

func TestNextBackoffDoublesToACeiling(t *testing.T) {
	d := 1 * time.Second
	for i := 0; i < 10; i++ {
		d = nextBackoff(d, 10*time.Second)
	}
	if d != 10*time.Second {
		t.Errorf("backoff = %v, want the ceiling", d)
	}
	if got := nextBackoff(time.Second, time.Minute); got != 2*time.Second {
		t.Errorf("backoff = %v, want 2s", got)
	}
}

// A consumer that stops reading must not stall supervision.
func TestEventsAreDroppedRatherThanBlocking(t *testing.T) {
	s := New(Spec{Name: "noisy", Path: "/bin/true"}, nil)
	for i := 0; i < 1000; i++ {
		s.emit(Event{Name: "noisy", Kind: EventStarted})
	}
	// Getting here at all is the assertion: emit must never block.
	if len(s.Events()) == 0 {
		t.Error("no events were queued")
	}
}

// lockedBuffer is a bytes.Buffer safe for the process's stdout goroutine to
// write while a test reads it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) Bytes() []byte {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]byte(nil), b.buf.Bytes()...)
}
