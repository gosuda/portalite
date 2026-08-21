package portalite

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"time"
)

const proxyBufferSize = 32 << 10

var relayToLocalBuffers = sync.Pool{New: func() any {
	buffer := make([]byte, proxyBufferSize)
	return &buffer
}}

var localToRelayBuffers = sync.Pool{New: func() any {
	buffer := make([]byte, proxyBufferSize)
	return &buffer
}}

type proxyPair struct {
	mu     sync.Mutex
	relay  net.Conn
	local  net.Conn
	closed bool
}

func newProxyPair(relay net.Conn) *proxyPair { return &proxyPair{relay: relay} }

func (p *proxyPair) setLocal(local net.Conn) bool {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		_ = local.Close()
		return false
	}
	p.local = local
	p.mu.Unlock()
	return true
}

func (p *proxyPair) connections() (net.Conn, net.Conn) {
	p.mu.Lock()
	relay, local := p.relay, p.local
	p.mu.Unlock()
	return relay, local
}

func (p *proxyPair) close() {
	p.mu.Lock()
	if p.closed {
		p.mu.Unlock()
		return
	}
	p.closed = true
	relay, local := p.relay, p.local
	p.mu.Unlock()
	if relay != nil {
		_ = relay.Close()
	}
	if local != nil {
		_ = local.Close()
	}
}

type activeProxyPairs struct {
	mu    sync.Mutex
	pairs map[*proxyPair]struct{}
}

func (a *activeProxyPairs) add(pair *proxyPair) {
	a.mu.Lock()
	a.pairs[pair] = struct{}{}
	a.mu.Unlock()
}

func (a *activeProxyPairs) remove(pair *proxyPair) {
	a.mu.Lock()
	delete(a.pairs, pair)
	a.mu.Unlock()
}

func (a *activeProxyPairs) closeAll() {
	a.mu.Lock()
	pairs := make([]*proxyPair, 0, len(a.pairs))
	for pair := range a.pairs {
		pairs = append(pairs, pair)
	}
	a.mu.Unlock()
	for _, pair := range pairs {
		pair.close()
	}
}

// Proxy is the sole Accept consumer for exposure and copies bytes between each
// tenant connection and the validated local TCP target.
func Proxy(ctx context.Context, exposure *Exposure, target string) error {
	if exposure == nil {
		return errors.New("portalite: exposure is nil")
	}
	if ctx == nil {
		return errors.Join(errors.New("portalite: context is nil"), exposure.Close())
	}
	normalizedTarget, err := NormalizeTarget(target)
	if err != nil {
		return errors.Join(err, exposure.Close())
	}

	proxyCtx, cancel := context.WithCancel(ctx)
	active := activeProxyPairs{pairs: make(map[*proxyPair]struct{})}
	var connections sync.WaitGroup

	stopContextClose := context.AfterFunc(ctx, func() {
		cancel()
		active.closeAll()
		_ = exposure.Close()
	})

	var acceptErr error
	for {
		conn, err := exposure.Accept()
		if err != nil {
			acceptErr = err
			break
		}
		pair := newProxyPair(conn)
		active.add(pair)
		connections.Add(1)
		go func() {
			defer connections.Done()
			defer active.remove(pair)
			proxyConnection(proxyCtx, pair, normalizedTarget)
		}()
	}

	cancel()
	active.closeAll()
	closeErr := exposure.Close()
	connections.Wait()
	stopContextClose()

	if ctx.Err() != nil {
		return nil
	}
	if errors.Is(acceptErr, ErrNoRelays) {
		return errors.Join(ErrNoRelays, closeErr)
	}
	if acceptErr != nil && !errors.Is(acceptErr, net.ErrClosed) {
		return errors.Join(acceptErr, closeErr)
	}
	if acceptErr != nil {
		return errors.Join(acceptErr, closeErr)
	}
	if closeErr != nil {
		return fmt.Errorf("close exposure: %w", closeErr)
	}
	return nil
}

func proxyConnection(ctx context.Context, pair *proxyPair, target string) {
	defer pair.close()

	dialer := &net.Dialer{Timeout: 5 * time.Second}
	local, err := dialer.DialContext(ctx, "tcp", target)
	if err != nil {
		// A target failure belongs only to this public connection. In
		// particular, do not inject an HTTP response into an arbitrary stream.
		return
	}
	if !pair.setLocal(local) {
		return
	}
	relay, local := pair.connections()
	if relay == nil || local == nil {
		return
	}

	var copies sync.WaitGroup
	copies.Add(2)
	go func() {
		defer copies.Done()
		if err := copyWithPooledBuffer(local, relay, &relayToLocalBuffers); err != nil {
			pair.close()
			return
		}
		if err := halfCloseWrite(local); err != nil {
			pair.close()
		}
	}()
	go func() {
		defer copies.Done()
		if err := copyWithPooledBuffer(relay, local, &localToRelayBuffers); err != nil {
			pair.close()
			return
		}
		if err := halfCloseWrite(relay); err != nil {
			pair.close()
		}
	}()
	copies.Wait()
}

func copyWithPooledBuffer(destination io.Writer, source io.Reader, pool *sync.Pool) error {
	bufferPointer := pool.Get().(*[]byte)
	defer pool.Put(bufferPointer)
	_, err := io.CopyBuffer(destination, source, *bufferPointer)
	return err
}

func halfCloseWrite(conn net.Conn) error {
	if closeWriter, ok := conn.(interface{ CloseWrite() error }); ok {
		return closeWriter.CloseWrite()
	}
	return nil
}
