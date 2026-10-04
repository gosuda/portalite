package portalite

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// ErrNoRelays is returned by Accept after every configured relay has failed.
var ErrNoRelays = errors.New("portalite: no relays available")

// RelayState is the lifecycle state of one independently supervised relay.
type RelayState string

const (
	RelayConnecting RelayState = "connecting"
	RelayReady      RelayState = "ready"
	RelayUDPReady   RelayState = "udp_ready"
	RelayFailed     RelayState = "failed"
)

// RelayStatus is an immutable snapshot of one relay's externally visible state.
type RelayStatus struct {
	RelayURL  string
	PublicURL string
	UDPAddr   string
	State     RelayState
	Err       error
}

// ExposeConfig configures a multi-relay exposure.
type ExposeConfig struct {
	Relays     []string
	Identity   Identity
	UDPEnabled bool

	// DisableDiscovery turns off automatic relay discovery, which is on by
	// default. While enabled, the exposure polls /discovery on its relays and
	// adds verified candidates until MaxActiveRelays is reached, so the
	// exposed relay set tracks the network instead of a frozen list.
	DisableDiscovery bool

	// MaxActiveRelays caps how many relays the exposure supervises at once.
	// Relays passed in Relays are always retained. Zero selects the default.
	MaxActiveRelays int
}

// Exposure is a net.Listener that fans in tenant connections from all relays.
type Exposure struct {
	ctx    context.Context
	cancel context.CancelFunc
	addr   exposureAddr

	accepted  chan net.Conn
	updates   chan RelayStatus
	datagrams chan DatagramFrame

	mu           sync.RWMutex
	statuses     map[string]RelayStatus
	relayCount   int
	failedCount  int
	udpEnabled   bool
	closing      bool
	allFailed    chan struct{}
	stateChanged chan struct{}
	failedOnce   sync.Once

	// rejectedRelays records relays that failed terminally, so discovery
	// never re-adds a relay this exposure already gave up on.
	rejectedRelays map[string]struct{}

	supervisors      sync.WaitGroup
	cleanupMu        sync.Mutex
	cleanupErrs      []error
	relaySupervisors map[string]*relaySupervisor

	identity Identity
	timings  relayTimings

	discoveryEnabled bool
	maxActiveRelays  int
	candidates       *discoveryCandidates
	discoveryClient  *discoveryClient
	discoveryPoll    time.Duration
	discoveryDone    sync.WaitGroup
	discoveryKick    chan struct{}

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
	// Normalize once so every derived deadline, including the discovery
	// interval, has a usable value.
	timings = timings.withDefaults()
	relays, err := NormalizeRelays(append([]string(nil), cfg.Relays...))
	if err != nil {
		return nil, err
	}
	if len(relays) == 0 {
		return nil, errors.New("portalite: at least one relay is required")
	}

	maxActiveRelays := cfg.MaxActiveRelays
	if maxActiveRelays <= 0 {
		maxActiveRelays = defaultMaxActiveRelays
	}
	if maxActiveRelays < len(relays) {
		// Explicit relays are always retained, so the cap can never sit
		// below the set the caller asked for.
		maxActiveRelays = len(relays)
	}
	discoveryEnabled := !cfg.DisableDiscovery

	exposureCtx, cancel := context.WithCancel(ctx)
	capacity := maxActiveRelays
	acceptCapacity := 2 * capacity
	if acceptCapacity < 1 {
		acceptCapacity = 1
	}
	datagramCapacity := datagramQueuePerRelay * capacity
	if datagramCapacity < 1 {
		datagramCapacity = 1
	}
	e := &Exposure{
		ctx:              exposureCtx,
		cancel:           cancel,
		addr:             exposureAddr{address: cfg.Identity.Address()},
		accepted:         make(chan net.Conn, acceptCapacity),
		updates:          make(chan RelayStatus, 4*capacity),
		datagrams:        make(chan DatagramFrame, datagramCapacity),
		statuses:         make(map[string]RelayStatus, capacity),
		udpEnabled:       cfg.UDPEnabled,
		allFailed:        make(chan struct{}),
		stateChanged:     make(chan struct{}),
		rejectedRelays:   make(map[string]struct{}),
		relaySupervisors: make(map[string]*relaySupervisor, capacity),
		identity:         cfg.Identity,
		timings:          timings,
		discoveryEnabled: discoveryEnabled,
		maxActiveRelays:  maxActiveRelays,
		discoveryPoll:    timings.discoveryPoll,
		closeDone:        make(chan struct{}),
		parentWatchStop:  make(chan struct{}),
	}
	if discoveryEnabled {
		e.candidates = newDiscoveryCandidates()
		e.discoveryClient = newDiscoveryClient(timings.requestTimeout)
		e.discoveryKick = make(chan struct{}, 1)
	}
	if err := e.addRelays(relays); err != nil {
		cancel()
		return nil, err
	}

	if discoveryEnabled {
		e.discoveryDone.Add(1)
		go e.runDiscovery()
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

// addRelays starts one supervisor per relay, skipping relays that are already
// members, already rejected, or beyond the active cap.
func (e *Exposure) addRelays(relayURLs []string) error {
	for _, relayURL := range relayURLs {
		if err := e.addRelay(relayURL); err != nil {
			return err
		}
	}
	return nil
}

func (e *Exposure) addRelay(relayURL string) error {
	supervisor, err := newRelaySupervisor(relayURL, e.identity, e.timings)
	if err != nil {
		return fmt.Errorf("portalite: relay %s: %w", relayURL, err)
	}
	supervisor.udpEnabled = e.udpEnabled

	e.mu.Lock()
	if e.closing || e.ctx.Err() != nil {
		e.mu.Unlock()
		return nil
	}
	if _, exists := e.statuses[relayURL]; exists {
		e.mu.Unlock()
		return nil
	}
	if _, rejected := e.rejectedRelays[relayURL]; rejected {
		e.mu.Unlock()
		return nil
	}
	if len(e.statuses) >= e.maxActiveRelays {
		e.mu.Unlock()
		return nil
	}
	status := RelayStatus{RelayURL: relayURL, State: RelayConnecting}
	e.statuses[relayURL] = status
	e.relaySupervisors[relayURL] = supervisor
	e.relayCount++
	// Membership grew, so a previously exhausted exposure is live again.
	e.rearmAllFailedLocked()
	e.notifyStateChangedLocked()
	// Add while holding the lock: Close sets closing under the same lock
	// before it waits, so the counter can never be incremented after Wait.
	e.supervisors.Add(1)
	e.mu.Unlock()

	e.updates <- status
	go e.runSupervisor(supervisor)
	return nil
}

// rearmAllFailedLocked restores the all-failed signal after membership grows,
// so an exposure that reported ErrNoRelays can recover.
func (e *Exposure) rearmAllFailedLocked() {
	select {
	case <-e.allFailed:
		e.allFailed = make(chan struct{})
		e.failedOnce = sync.Once{}
	default:
	}
}

// runDiscovery polls /discovery on the current membership and adopts verified
// candidates until the active cap is reached.
func (e *Exposure) runDiscovery() {
	defer e.discoveryDone.Done()
	e.refreshDiscovery()

	ticker := time.NewTicker(e.discoveryPoll)
	defer ticker.Stop()
	for {
		select {
		case <-e.ctx.Done():
			return
		case <-ticker.C:
			e.refreshDiscovery()
		case <-e.discoveryKick:
			e.refreshDiscovery()
		}
	}
}

// refreshDiscovery merges verified candidates from every current member and
// adopts as many as the cap allows. A member that cannot answer contributes
// nothing: discovery never fails the exposure.
func (e *Exposure) refreshDiscovery() {
	if e.ctx.Err() != nil {
		return
	}
	e.mu.RLock()
	seeds := discoverySeeds(e.activeRelaysLocked())
	requireUDP := e.udpEnabled
	e.mu.RUnlock()

	now := time.Now()
	for _, seed := range seeds {
		if e.ctx.Err() != nil {
			return
		}
		candidates, err := e.discoveryClient.fetch(e.ctx, seed, now)
		if err != nil {
			continue
		}
		e.candidates.merge(now, candidates)
	}
	e.adoptDiscoveredRelays(now, requireUDP)

	// Discovery has now had its say. If every member still failed and no
	// candidate was adopted, the exposure is genuinely exhausted and callers
	// should learn that instead of waiting forever.
	e.mu.RLock()
	exhausted := e.relayCount > 0 && e.failedCount >= e.relayCount &&
		!e.closing && e.ctx.Err() == nil
	e.mu.RUnlock()
	if exhausted {
		e.markExhausted()
	}
}

// adoptDiscoveredRelays starts supervisors for fresh, verified candidates.
func (e *Exposure) adoptDiscoveredRelays(now time.Time, requireUDP bool) {
	e.mu.RLock()
	active := e.activeRelaysLocked()
	e.mu.RUnlock()

	for _, relayURL := range e.candidates.selectRelays(now, active, requireUDP) {
		if e.ctx.Err() != nil {
			return
		}
		if err := e.addRelay(relayURL); err != nil {
			continue
		}
	}
}

// exhausted reports whether the exposure has given up: every member failed
// and discovery produced nothing new. The all-failed signal is the single
// authority, so discovery and non-discovery modes cannot disagree about it.
func (e *Exposure) exhausted() bool {
	return e.exhaustedSignal() != nil
}

// exhaustedSignal returns the current all-failed channel when the exposure is
// exhausted, or nil when it is still live. Callers must re-read it every
// iteration: the channel is replaced when membership grows again.
func (e *Exposure) exhaustedSignal() chan struct{} {
	e.mu.RLock()
	signal := e.allFailed
	exhausted := e.failedCount >= e.relayCount && e.relayCount > 0
	e.mu.RUnlock()
	if !exhausted {
		return nil
	}
	select {
	case <-signal:
		return signal
	default:
		return nil
	}
}

// markExhausted signals a total failure. It is the only place that closes the
// all-failed signal; rearmAllFailedLocked is the only place that reopens it.
func (e *Exposure) markExhausted() {
	e.failedOnce.Do(func() { close(e.allFailed) })
	// Wake WaitReady and WaitDatagramReady, which observe exhaustion through
	// the state-change signal rather than the all-failed channel.
	e.mu.Lock()
	e.notifyStateChangedLocked()
	e.mu.Unlock()
	e.drainAccepted()
}

// stateChangedSignal snapshots the state-change channel so a blocked caller
// can be woken when membership or relay state changes.
func (e *Exposure) stateChangedSignal() chan struct{} {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.stateChanged
}

// activeRelaysLocked snapshots current membership.
func (e *Exposure) activeRelaysLocked() map[string]struct{} {
	active := make(map[string]struct{}, len(e.statuses))
	for relayURL := range e.statuses {
		active[relayURL] = struct{}{}
	}
	for relayURL := range e.rejectedRelays {
		active[relayURL] = struct{}{}
	}
	return active
}

func (e *Exposure) runSupervisor(supervisor *relaySupervisor) {
	defer e.supervisors.Done()
	runErr, cleanupErr := supervisor.run(
		e.ctx,
		func(publicURL string) { e.markReady(supervisor.relayURL, publicURL) },
		func(udpAddr string) { e.markDatagramReady(supervisor.relayURL, udpAddr) },
		e.offer,
		e.offerDatagram,
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

func (e *Exposure) offerDatagram(relayCtx context.Context, frame DatagramFrame) bool {
	frame.Payload = append([]byte(nil), frame.Payload...)
	select {
	case <-relayCtx.Done():
		return false
	case <-e.ctx.Done():
		return false
	case e.datagrams <- frame:
		return true
	default:
		return false
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
	// A terminal failure is permanent for this relay: discovery must not
	// re-add a relay this exposure already gave up on.
	e.rejectedRelays[relayURL] = struct{}{}
	e.notifyStateChangedLocked()
	allFailed := e.failedCount >= e.relayCount
	e.mu.Unlock()

	e.updates <- status
	if !allFailed {
		return
	}
	if e.discoveryEnabled {
		// Every member is gone: refresh now instead of waiting for the poll
		// interval, so the exposure recovers as soon as a candidate exists.
		select {
		case e.discoveryKick <- struct{}{}:
		default:
		}
		return
	}
	// Without discovery, a total failure is terminal for this exposure.
	e.markExhausted()
}

func (e *Exposure) markDatagramReady(relayURL, udpAddr string) {
	e.mu.Lock()
	status, exists := e.statuses[relayURL]
	if !exists || e.closing || e.ctx.Err() != nil || status.State == RelayFailed {
		e.mu.Unlock()
		return
	}
	announce := udpAddr != "" && status.UDPAddr != udpAddr
	status.UDPAddr = udpAddr
	e.statuses[relayURL] = status
	e.notifyStateChangedLocked()
	e.mu.Unlock()
	if announce {
		status.State = RelayUDPReady
		e.updates <- status
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
		case <-e.stateChangedSignal():
			// Re-evaluate: membership or relay state changed.
			continue
		case <-e.exhaustedSignal():
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
		exhausted := e.exhaustedSignal()
		changed := e.stateChanged
		e.mu.RUnlock()

		if len(ready) != 0 {
			sort.Slice(ready, func(i, j int) bool { return ready[i].RelayURL < ready[j].RelayURL })
			return ready, nil
		}
		if closed {
			return nil, net.ErrClosed
		}
		if exhausted != nil {
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

// AcceptDatagram returns the next UDP datagram from any connected UDP relay.
func (e *Exposure) AcceptDatagram() (DatagramFrame, error) {
	if e == nil || !e.udpEnabled {
		return DatagramFrame{}, net.ErrClosed
	}
	for {
		closed, failed := e.terminalState()
		if closed {
			return DatagramFrame{}, net.ErrClosed
		}
		if failed {
			return DatagramFrame{}, ErrNoRelays
		}
		select {
		case <-e.ctx.Done():
			return DatagramFrame{}, net.ErrClosed
		case <-e.stateChangedSignal():
			// Re-evaluate: membership or relay state changed.
			continue
		case <-e.exhaustedSignal():
			closed, _ = e.terminalState()
			if closed {
				return DatagramFrame{}, net.ErrClosed
			}
			return DatagramFrame{}, ErrNoRelays
		case frame := <-e.datagrams:
			frame.Payload = append([]byte(nil), frame.Payload...)
			return frame, nil
		}
	}
}

// SendDatagram sends a response through the relay and flow identified by frame.
func (e *Exposure) SendDatagram(frame DatagramFrame) error {
	if e == nil || !e.udpEnabled {
		return net.ErrClosed
	}
	e.mu.RLock()
	supervisor := e.relaySupervisors[frame.RelayURL]
	closed := e.closing || e.ctx.Err() != nil
	failed := e.exhausted()
	e.mu.RUnlock()
	if closed {
		return net.ErrClosed
	}
	if failed {
		return ErrNoRelays
	}
	if supervisor == nil {
		return errors.New("portalite: datagram frame references an unknown relay")
	}
	frame.Payload = append([]byte(nil), frame.Payload...)
	return supervisor.sendDatagram(frame)
}

// WaitDatagramReady waits until at least one relay has an authenticated QUIC
// datagram backhaul. It does not consume Updates or AcceptDatagram.
func (e *Exposure) WaitDatagramReady(ctx context.Context) ([]RelayStatus, error) {
	if e == nil {
		return nil, net.ErrClosed
	}
	if ctx == nil {
		return nil, errors.New("portalite: context is nil")
	}
	if !e.udpEnabled {
		return nil, errors.New("portalite: UDP is not enabled")
	}
	for {
		e.mu.RLock()
		ready := make([]RelayStatus, 0, e.relayCount-e.failedCount)
		for _, status := range e.statuses {
			if status.UDPAddr != "" && status.State != RelayFailed {
				ready = append(ready, status)
			}
		}
		closed := e.closing || e.ctx.Err() != nil
		exhausted := e.exhaustedSignal()
		changed := e.stateChanged
		e.mu.RUnlock()

		if len(ready) != 0 {
			sort.Slice(ready, func(i, j int) bool { return ready[i].RelayURL < ready[j].RelayURL })
			return ready, nil
		}
		if closed {
			return nil, net.ErrClosed
		}
		if exhausted != nil {
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
	// With discovery enabled membership is dynamic: every relay failing is
	// recoverable, so Accept waits for a new candidate instead of reporting
	// a terminal ErrNoRelays.
	e.mu.RUnlock()
	failed = e.exhausted()
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
		// Discovery can still start supervisors, so it must stop before the
		// supervisor counter and the updates channel are finalized.
		e.discoveryDone.Wait()
		if e.discoveryClient != nil {
			e.discoveryClient.close()
		}
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
