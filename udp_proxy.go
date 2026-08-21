package portalite

import (
	"context"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"
)

type udpProxyFlowKey struct {
	relayURL string
	flowID   uint32
}

type udpProxyFlow struct {
	key      udpProxyFlowKey
	conn     *net.UDPConn
	frame    DatagramFrame
	lastSeen time.Time
}

type udpProxyFlowManager struct {
	ctx      context.Context
	exposure *Exposure
	target   *net.UDPAddr

	mu     sync.Mutex
	flows  map[udpProxyFlowKey]*udpProxyFlow
	closed bool
	wg     sync.WaitGroup
}

var udpProxyBuffers = sync.Pool{New: func() any {
	buffer := make([]byte, maxUDPPayloadSize)
	return &buffer
}}

func runUDPProxy(ctx context.Context, exposure *Exposure, target string) error {
	resolved, err := net.ResolveUDPAddr("udp", target)
	if err != nil {
		return fmt.Errorf("resolve UDP target %q: %w", target, err)
	}
	if _, err := exposure.WaitDatagramReady(ctx); err != nil {
		return fmt.Errorf("wait for UDP relay: %w", err)
	}

	manager := &udpProxyFlowManager{
		ctx:      ctx,
		exposure: exposure,
		target:   resolved,
		flows:    make(map[udpProxyFlowKey]*udpProxyFlow),
	}
	manager.wg.Add(1)
	go manager.cleanupLoop()
	defer func() {
		manager.close()
		manager.wg.Wait()
	}()

	for {
		frame, err := exposure.AcceptDatagram()
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			return fmt.Errorf("accept relayed UDP datagram: %w", err)
		}
		// UDP is lossy by design. A local target or flow-capacity failure drops
		// only this datagram and leaves the remaining relay flows active.
		_ = manager.forward(frame)
	}
}

var errUDPFlowCapacity = errors.New("portalite: UDP proxy flow capacity reached")

func (m *udpProxyFlowManager) forward(frame DatagramFrame) error {
	key := udpProxyFlowKey{relayURL: frame.RelayURL, flowID: frame.FlowID}
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return net.ErrClosed
	}
	flow := m.flows[key]
	if flow == nil {
		if len(m.flows) >= defaultUDPProxyMaxFlows {
			m.mu.Unlock()
			return errUDPFlowCapacity
		}
		conn, err := net.DialUDP("udp", nil, m.target)
		if err != nil {
			m.mu.Unlock()
			return fmt.Errorf("dial local UDP target: %w", err)
		}
		flow = &udpProxyFlow{
			key:      key,
			conn:     conn,
			frame:    frame,
			lastSeen: time.Now(),
		}
		flow.frame.Payload = nil
		m.flows[key] = flow
		m.wg.Add(1)
		go m.readResponses(flow)
	} else {
		flow.frame.UDPAddr = frame.UDPAddr
		flow.lastSeen = time.Now()
	}
	conn := flow.conn
	m.mu.Unlock()

	if _, err := conn.Write(frame.Payload); err != nil {
		m.remove(flow)
		return fmt.Errorf("write local UDP target: %w", err)
	}
	return nil
}

func (m *udpProxyFlowManager) readResponses(flow *udpProxyFlow) {
	defer m.wg.Done()
	bufferPointer := udpProxyBuffers.Get().(*[]byte)
	defer udpProxyBuffers.Put(bufferPointer)
	buffer := *bufferPointer
	for {
		n, err := flow.conn.Read(buffer)
		if err != nil {
			m.remove(flow)
			return
		}
		m.mu.Lock()
		if m.closed || m.flows[flow.key] != flow {
			m.mu.Unlock()
			return
		}
		flow.lastSeen = time.Now()
		frame := flow.frame
		m.mu.Unlock()
		frame.Payload = append([]byte(nil), buffer[:n]...)
		if err := m.exposure.SendDatagram(frame); err != nil {
			if m.ctx.Err() != nil || errors.Is(err, net.ErrClosed) {
				m.remove(flow)
				return
			}
			// A reconnect can make this single response stale; keep the local flow.
		}
	}
}

func (m *udpProxyFlowManager) cleanupLoop() {
	defer m.wg.Done()
	ticker := time.NewTicker(defaultUDPFlowCleanupInterval)
	defer ticker.Stop()
	for {
		select {
		case <-m.ctx.Done():
			return
		case now := <-ticker.C:
			m.mu.Lock()
			var expired []*udpProxyFlow
			for key, flow := range m.flows {
				if now.Sub(flow.lastSeen) >= defaultUDPFlowIdleTimeout {
					delete(m.flows, key)
					expired = append(expired, flow)
				}
			}
			m.mu.Unlock()
			for _, flow := range expired {
				_ = flow.conn.Close()
			}
		}
	}
}

func (m *udpProxyFlowManager) remove(flow *udpProxyFlow) {
	m.mu.Lock()
	if m.flows[flow.key] == flow {
		delete(m.flows, flow.key)
	}
	m.mu.Unlock()
	_ = flow.conn.Close()
}

func (m *udpProxyFlowManager) close() {
	m.mu.Lock()
	if m.closed {
		m.mu.Unlock()
		return
	}
	m.closed = true
	flows := make([]*udpProxyFlow, 0, len(m.flows))
	for key, flow := range m.flows {
		delete(m.flows, key)
		flows = append(flows, flow)
	}
	m.mu.Unlock()
	for _, flow := range flows {
		_ = flow.conn.Close()
	}
}
