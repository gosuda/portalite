package portalite

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
)

// ErrNoRelays is returned by Accept after every configured relay has failed.
var ErrNoRelays = errors.New("portalite: no relays available")

// RelayState is the lifecycle state of one independently supervised relay.
type RelayState string

const (
	RelayConnecting RelayState = "connecting"
	RelayReady      RelayState = "ready"
	RelayFailed     RelayState = "failed"
)

// RelayStatus is an immutable snapshot of one relay's externally visible state.
type RelayStatus struct {
	RelayURL  string
	PublicURL string
	State     RelayState
	Err       error
}

// ExposeConfig configures a multi-relay exposure.
type ExposeConfig struct {
	Relays   []string
	Identity Identity
}

// Exposure is a net.Listener that fans in tenant connections from all relays.
type Exposure struct {
	ctx    context.Context
	cancel context.CancelFunc
	addr   exposureAddr

	accepted chan net.Conn
	updates  chan RelayStatus

	mu           sync.RWMutex
	statuses     map[string]RelayStatus
	relayCount   int
	failedCount  int
	closing      bool
	allFailed    chan struct{}
	stateChanged chan struct{}
	failedOnce   sync.Once

	supervisors sync.WaitGroup
	cleanupMu   sync.Mutex
	cleanupErrs []error

	closeOnce       sync.Once
	closeDone       chan struct{}
	closeErr        error
	parentWatchStop chan struct{}
}

type exposureAddr struct{ address string }

func (a exposureAddr) Network() string { return "portalite" }
func (a exposureAddr) String() string  { return "portalite:" + a.address }

// Expose validates local configuration, starts all relay supervisors
// concurrently, and returns without waiting for network readiness.
func Expose(ctx context.Context, cfg ExposeConfig) (*Exposure, error) {
	return exposeWithTimings(ctx, cfg, defaultRelayTimings())
}

// exposeWithTimings is the deterministic test seam for lease scheduling and
// network deadlines. It intentionally does not widen the public configuration.
func exposeWithTimings(ctx context.Context, cfg ExposeConfig, timings relayTimings) (*Exposure, error) {
	if ctx == nil {
		return nil, errors.New("portalite: context is nil")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if cfg.Identity.Name() == "" || cfg.Identity.Address() == "" || cfg.Identity.PublicKey() == "" {
		return nil, errors.New("portalite: invalid identity")
	}
	relays, err := NormalizeRelays(append([]string(nil), cfg.Relays...))
	if err != nil {
		return nil, err
	}
	if len(relays) == 0 {
		return nil, errors.New("portalite: at least one relay is required")
	}

	supervisorList := make([]*relaySupervisor, 0, len(relays))
	for _, relayURL := range relays {
		supervisor, err := newRelaySupervisor(relayURL, cfg.Identity, timings)
		if err != nil {
			return nil, fmt.Errorf("portalite: relay %s: %w", relayURL, err)
		}
		supervisorList = append(supervisorList, supervisor)
	}

	exposureCtx, cancel := context.WithCancel(ctx)
	acceptCapacity := 2 * len(relays)
	if acceptCapacity < 1 {
		acceptCapacity = 1
	}
	e := &Exposure{
		ctx:             exposureCtx,
		cancel:          cancel,
		addr:            exposureAddr{address: cfg.Identity.Address()},
		accepted:        make(chan net.Conn, acceptCapacity),
		updates:         make(chan RelayStatus, 3*len(relays)),
		statuses:        make(map[string]RelayStatus, len(relays)),
		relayCount:      len(relays),
		allFailed:       make(chan struct{}),
		stateChanged:    make(chan struct{}),
		closeDone:       make(chan struct{}),
		parentWatchStop: make(chan struct{}),
	}

	for _, relayURL := range relays {
		status := RelayStatus{RelayURL: relayURL, State: RelayConnecting}
		e.statuses[relayURL] = status
		e.updates <- status
	}

	for _, supervisor := range supervisorList {
		e.supervisors.Add(1)
		go e.runSupervisor(supervisor)
	}
	go func() {
		select {
		case <-ctx.Done():
			_ = e.Close()
		case <-e.parentWatchStop:
		}
	}()
	return e, nil
}

func (e *Exposure) runSupervisor(supervisor *relaySupervisor) {
	defer e.supervisors.Done()
	runErr, cleanupErr := supervisor.run(e.ctx,
		func(publicURL string) { e.markReady(supervisor.relayURL, publicURL) },
		e.offer,
	)
	if cleanupErr != nil {
		e.cleanupMu.Lock()
		e.cleanupErrs = append(e.cleanupErrs, fmt.Errorf("relay %s cleanup: %w", supervisor.relayURL, cleanupErr))
		e.cleanupMu.Unlock()
	}
	if runErr != nil && e.ctx.Err() == nil {
		e.markFailed(supervisor.relayURL, runErr)
	}
}

func (e *Exposure) offer(relayCtx context.Context, conn net.Conn) bool {
	if conn == nil {
		return false
	}
	select {
	case <-relayCtx.Done():
		return false
	case <-e.ctx.Done():
		return false
	case e.accepted <- conn:
		return true
	}
}

func (e *Exposure) markReady(relayURL, publicURL string) {
	e.mu.Lock()
	status, exists := e.statuses[relayURL]
	if !exists || e.closing || e.ctx.Err() != nil || status.State == RelayFailed {
		e.mu.Unlock()
		return
	}
	status.PublicURL = publicURL
	status.Err = nil
	if status.State == RelayReady {
		e.statuses[relayURL] = status
		e.notifyStateChangedLocked()
		e.mu.Unlock()
		return
	}
	status.State = RelayReady
	e.statuses[relayURL] = status
	e.notifyStateChangedLocked()
	e.mu.Unlock()
	e.updates <- status
}

func (e *Exposure) markFailed(relayURL string, relayErr error) {
	e.mu.Lock()
	status, exists := e.statuses[relayURL]
	if !exists || e.closing || e.ctx.Err() != nil || status.State == RelayFailed {
		e.mu.Unlock()
		return
	}
	status.State = RelayFailed
	status.Err = relayErr
	e.statuses[relayURL] = status
	e.failedCount++
	e.notifyStateChangedLocked()
	allFailed := e.failedCount == e.relayCount
	e.mu.Unlock()

	e.updates <- status
	if allFailed {
		e.failedOnce.Do(func() { close(e.allFailed) })
		e.drainAccepted()
	}
}

func (e *Exposure) notifyStateChangedLocked() {
	close(e.stateChanged)
	e.stateChanged = make(chan struct{})
}

// Accept returns the next tenant TLS connection from any live relay.
func (e *Exposure) Accept() (net.Conn, error) {
	if e == nil {
		return nil, net.ErrClosed
	}
	for {
		closed, failed := e.terminalState()
		if closed {
			return nil, net.ErrClosed
		}
		if failed {
			return nil, ErrNoRelays
		}

		select {
		case <-e.ctx.Done():
			return nil, net.ErrClosed
		case <-e.allFailed:
			closed, _ = e.terminalState()
			if closed {
				return nil, net.ErrClosed
			}
			return nil, ErrNoRelays
		case conn := <-e.accepted:
			closed, failed = e.terminalState()
			if closed || failed {
				_ = conn.Close()
				if closed {
					return nil, net.ErrClosed
				}
				return nil, ErrNoRelays
			}
			return conn, nil
		}
	}
}

// WaitReady waits until at least one relay can accept tenant connections.
// It does not consume Updates. The returned statuses are sorted by relay URL.
func (e *Exposure) WaitReady(ctx context.Context) ([]RelayStatus, error) {
	if e == nil {
		return nil, net.ErrClosed
	}
	if ctx == nil {
		return nil, errors.New("portalite: context is nil")
	}
	for {
		e.mu.RLock()
		ready := make([]RelayStatus, 0, e.relayCount-e.failedCount)
		for _, status := range e.statuses {
			if status.State == RelayReady {
				ready = append(ready, status)
			}
		}
		closed := e.closing || e.ctx.Err() != nil
		failed := e.failedCount == e.relayCount
		changed := e.stateChanged
		e.mu.RUnlock()

		if len(ready) != 0 {
			sort.Slice(ready, func(i, j int) bool { return ready[i].RelayURL < ready[j].RelayURL })
			return ready, nil
		}
		if closed {
			return nil, net.ErrClosed
		}
		if failed {
			return nil, ErrNoRelays
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-e.ctx.Done():
			return nil, net.ErrClosed
		case <-changed:
		}
	}
}

func (e *Exposure) terminalState() (closed, failed bool) {
	e.mu.RLock()
	closed = e.closing || e.ctx.Err() != nil
	failed = e.failedCount == e.relayCount
	e.mu.RUnlock()
	return closed, failed
}

// Close stops every relay concurrently, waits for best-effort unregister and
// signer cleanup, drains unaccepted connections, and closes Updates.
func (e *Exposure) Close() error {
	if e == nil {
		return nil
	}
	e.closeOnce.Do(func() {
		e.mu.Lock()
		e.closing = true
		e.mu.Unlock()
		close(e.parentWatchStop)
		e.cancel()
		e.supervisors.Wait()
		e.drainAccepted()

		e.cleanupMu.Lock()
		e.closeErr = errors.Join(e.cleanupErrs...)
		e.cleanupMu.Unlock()
		close(e.updates)
		close(e.closeDone)
	})
	<-e.closeDone
	return e.closeErr
}

func (e *Exposure) drainAccepted() {
	for {
		select {
		case conn := <-e.accepted:
			if conn != nil {
				_ = conn.Close()
			}
		default:
			return
		}
	}
}

// Addr identifies the aggregate listener and its identity.
func (e *Exposure) Addr() net.Addr {
	if e == nil {
		return exposureAddr{}
	}
	return e.addr
}

// Updates returns the non-blocking relay lifecycle stream.
func (e *Exposure) Updates() <-chan RelayStatus {
	if e == nil {
		return nil
	}
	return e.updates
}

// Relays returns a defensive, canonically sorted status snapshot.
func (e *Exposure) Relays() []RelayStatus {
	if e == nil {
		return nil
	}
	e.mu.RLock()
	statuses := make([]RelayStatus, 0, len(e.statuses))
	for _, status := range e.statuses {
		statuses = append(statuses, status)
	}
	e.mu.RUnlock()
	sort.Slice(statuses, func(i, j int) bool { return statuses[i].RelayURL < statuses[j].RelayURL })
	return statuses
}
