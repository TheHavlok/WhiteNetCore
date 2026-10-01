// Package supervisor keeps a child process running.
//
// The agent supervises xray-core and the DNS tunnel this way: start, watch,
// restart with backoff when it dies, and tell the panel every time it had to.
// systemd supervises the agent; the agent supervises the cores. Nothing here
// knows what the process does, which is what lets one implementation serve
// both.
package supervisor

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"os/exec"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Spec describes what to run.
type Spec struct {
	// Name identifies the process in logs and events.
	Name string
	// Path is the binary, Args its arguments (without argv[0]).
	Path string
	Args []string
	// Dir is the working directory; empty means the agent's.
	Dir string
	// Env is added to the agent's environment.
	Env []string

	// Ready, when set, is what decides a start actually worked. A process
	// that exits immediately is a failure either way; Ready catches the
	// subtler case of a process that stays up without serving anything.
	Ready func(context.Context) error
	// StartTimeout bounds Ready.
	StartTimeout time.Duration
	// StopTimeout is how long the process gets after SIGTERM before SIGKILL.
	StopTimeout time.Duration

	// RestartBackoff is the delay before the first restart, doubling up to
	// RestartBackoffMax for a process that keeps dying.
	RestartBackoff    time.Duration
	RestartBackoffMax time.Duration

	// LogWriter receives the process's stdout and stderr. Nil discards them.
	LogWriter io.Writer
}

// Event is what the supervisor reports upwards, so the panel's journal says
// "xray crashed and was restarted" rather than showing a version mismatch and
// nothing else.
type Event struct {
	Name string
	// Kind is started, exited, restarting, failed or stopped.
	Kind string
	// Err is set for exited and failed.
	Err error
	// Restarts is how many times this process has been restarted since the
	// supervisor started it.
	Restarts uint32
	At       time.Time
}

// Event kinds.
const (
	EventStarted    = "started"
	EventExited     = "exited"
	EventRestarting = "restarting"
	EventFailed     = "failed"
	EventStopped    = "stopped"
)

// Status is a snapshot for the heartbeat.
type Status struct {
	Running   bool
	Restarts  uint32
	StartedAt time.Time
	LastError string
	PID       int
}

// Supervisor runs one process.
type Supervisor struct {
	spec Spec
	log  *slog.Logger
	// events is where Event values go. It is buffered and dropped on
	// overflow: a supervisor must never block on a reader that stopped
	// reading.
	events chan Event

	mu        sync.Mutex
	cmd       *exec.Cmd
	startedAt time.Time
	lastErr   error
	stopping  bool
	done      chan struct{}

	restarts atomic.Uint32
	running  atomic.Bool
}

// New returns a stopped supervisor.
func New(spec Spec, log *slog.Logger) *Supervisor {
	if log == nil {
		log = slog.Default()
	}
	if spec.StartTimeout <= 0 {
		spec.StartTimeout = 15 * time.Second
	}
	if spec.StopTimeout <= 0 {
		spec.StopTimeout = 10 * time.Second
	}
	if spec.RestartBackoff <= 0 {
		spec.RestartBackoff = 2 * time.Second
	}
	if spec.RestartBackoffMax < spec.RestartBackoff {
		spec.RestartBackoffMax = 2 * time.Minute
	}
	return &Supervisor{
		spec:   spec,
		log:    log.With("core", spec.Name),
		events: make(chan Event, 64),
	}
}

// Events is the channel of state changes. It is never closed, so a consumer
// can select on it for the lifetime of the agent.
func (s *Supervisor) Events() <-chan Event { return s.events }

// Status reports what the heartbeat needs.
func (s *Supervisor) Status() Status {
	s.mu.Lock()
	defer s.mu.Unlock()
	status := Status{
		Running:   s.running.Load(),
		Restarts:  s.restarts.Load(),
		StartedAt: s.startedAt,
	}
	if s.lastErr != nil {
		status.LastError = s.lastErr.Error()
	}
	if s.cmd != nil && s.cmd.Process != nil {
		status.PID = s.cmd.Process.Pid
	}
	return status
}

// Running reports whether the process is up.
func (s *Supervisor) Running() bool { return s.running.Load() }

// Start launches the process and keeps it running until ctx is cancelled or
// Stop is called. It returns once the first start has succeeded, so a caller
// can rely on the process being up - or learn that it is not.
func (s *Supervisor) Start(ctx context.Context) error {
	s.mu.Lock()
	if s.done != nil {
		s.mu.Unlock()
		return errors.New("supervisor: already started")
	}
	s.done = make(chan struct{})
	s.stopping = false
	done := s.done
	s.mu.Unlock()

	if err := s.startOnce(ctx); err != nil {
		s.mu.Lock()
		s.done = nil
		s.mu.Unlock()
		close(done)
		return err
	}

	go s.supervise(ctx, done)
	return nil
}

// supervise waits for the process and restarts it.
func (s *Supervisor) supervise(ctx context.Context, done chan struct{}) {
	defer close(done)

	backoff := s.spec.RestartBackoff
	for {
		s.mu.Lock()
		cmd := s.cmd
		s.mu.Unlock()
		if cmd == nil {
			return
		}

		waitErr := cmd.Wait()
		s.running.Store(false)

		s.mu.Lock()
		stopping := s.stopping
		s.lastErr = waitErr
		s.mu.Unlock()

		if stopping || ctx.Err() != nil {
			s.emit(Event{Name: s.spec.Name, Kind: EventStopped, At: time.Now()})
			return
		}

		// An exit the agent did not ask for is what the panel wants to know
		// about: it is the difference between a quiet node and a broken one.
		s.emit(Event{
			Name: s.spec.Name, Kind: EventExited, Err: waitErr,
			Restarts: s.restarts.Load(), At: time.Now(),
		})
		s.log.Warn("core exited, restarting", "error", waitErr, "backoff", backoff)

		s.emit(Event{Name: s.spec.Name, Kind: EventRestarting, Restarts: s.restarts.Load(), At: time.Now()})
		select {
		case <-ctx.Done():
			return
		case <-time.After(backoff):
		}

		s.restarts.Add(1)
		if err := s.startOnce(ctx); err != nil {
			s.lastErr = err
			s.emit(Event{
				Name: s.spec.Name, Kind: EventFailed, Err: err,
				Restarts: s.restarts.Load(), At: time.Now(),
			})
			s.log.Error("core failed to restart", "error", err)
			// Keep trying, with a longer delay each time: a node whose Xray
			// cannot start must keep trying rather than give up, because the
			// cause is often a port that will be free again shortly.
			backoff = nextBackoff(backoff, s.spec.RestartBackoffMax)
			continue
		}
		backoff = s.spec.RestartBackoff
	}
}

// nextBackoff doubles up to the ceiling.
func nextBackoff(current, max time.Duration) time.Duration {
	next := current * 2
	if next > max {
		return max
	}
	return next
}

// startOnce launches the process and waits for Ready.
func (s *Supervisor) startOnce(ctx context.Context) error {
	cmd := exec.Command(s.spec.Path, s.spec.Args...)
	cmd.Dir = s.spec.Dir
	if len(s.spec.Env) > 0 {
		cmd.Env = append(os.Environ(), s.spec.Env...)
	}
	if s.spec.LogWriter != nil {
		cmd.Stdout = s.spec.LogWriter
		cmd.Stderr = s.spec.LogWriter
	}
	// Its own process group, so stopping the agent does not leave a core
	// behind and SIGKILL reaches anything the core spawned.
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("supervisor: start %s: %w", s.spec.Name, err)
	}

	s.mu.Lock()
	s.cmd = cmd
	s.startedAt = time.Now()
	s.lastErr = nil
	s.mu.Unlock()
	s.running.Store(true)

	if s.spec.Ready != nil {
		readyCtx, cancel := context.WithTimeout(ctx, s.spec.StartTimeout)
		defer cancel()
		if err := s.spec.Ready(readyCtx); err != nil {
			// It started but is not serving. Killing it is right: leaving a
			// half-working process up would make the panel believe the node
			// is fine.
			_ = s.kill(cmd)
			s.running.Store(false)
			return fmt.Errorf("supervisor: %s did not become ready: %w", s.spec.Name, err)
		}
	}

	s.emit(Event{
		Name: s.spec.Name, Kind: EventStarted,
		Restarts: s.restarts.Load(), At: time.Now(),
	})
	s.log.Info("core started", "pid", cmd.Process.Pid, "path", s.spec.Path)
	return nil
}

// Stop ends the process and the supervision loop.
func (s *Supervisor) Stop() error {
	s.mu.Lock()
	if s.done == nil {
		s.mu.Unlock()
		return nil
	}
	s.stopping = true
	cmd := s.cmd
	done := s.done
	s.mu.Unlock()

	var err error
	if cmd != nil && cmd.Process != nil {
		err = s.terminate(cmd)
	}
	// Wait for supervise to notice; it is the only goroutine that calls
	// cmd.Wait, so returning before it does would race with it.
	select {
	case <-done:
	case <-time.After(s.spec.StopTimeout + 5*time.Second):
	}

	s.mu.Lock()
	s.cmd = nil
	s.done = nil
	s.mu.Unlock()
	s.running.Store(false)
	return err
}

// Restart stops and starts, keeping the restart counter so the panel can see
// how often a core has had to come back.
func (s *Supervisor) Restart(ctx context.Context) error {
	if err := s.Stop(); err != nil {
		s.log.Warn("stop before restart failed", "error", err)
	}
	s.restarts.Add(1)
	return s.Start(ctx)
}

// terminate asks politely, then does not.
func (s *Supervisor) terminate(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	// Signal the group: a core that spawned helpers must take them with it.
	pgid := -cmd.Process.Pid
	if err := syscall.Kill(pgid, syscall.SIGTERM); err != nil {
		// Falling back to the process alone covers the case where setting
		// the group failed.
		if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
			return fmt.Errorf("supervisor: sigterm %s: %w", s.spec.Name, err)
		}
	}

	deadline := time.After(s.spec.StopTimeout)
	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-deadline:
			s.log.Warn("core did not exit on sigterm, killing", "timeout", s.spec.StopTimeout)
			return s.kill(cmd)
		case <-ticker.C:
			if !s.running.Load() {
				return nil
			}
		}
	}
}

func (s *Supervisor) kill(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); err != nil {
		if err := cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
			return fmt.Errorf("supervisor: kill %s: %w", s.spec.Name, err)
		}
	}
	return nil
}

// emit queues an event, dropping it if nobody is keeping up. A supervisor that
// blocks on its own event channel would stop supervising, which is worse than
// losing a journal line.
func (s *Supervisor) emit(event Event) {
	select {
	case s.events <- event:
	default:
		s.log.Warn("event channel full, dropping", "kind", event.Kind)
	}
}
