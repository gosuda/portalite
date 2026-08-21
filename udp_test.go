package portalite

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"testing"
	"time"
)

func TestDatagramCodecBoundaries(t *testing.T) {
	payload := []byte("payload")
	encoded, err := encodeDatagram(42, payload)
	if err != nil {
		t.Fatalf("encodeDatagram: %v", err)
	}
	payload[0] = 'X'
	frame, err := decodeDatagram(encoded)
	if err != nil {
		t.Fatalf("decodeDatagram: %v", err)
	}
	if frame.FlowID != 42 || string(frame.Payload) != "payload" {
		t.Fatalf("decoded frame = %+v", frame)
	}
	encoded[len(encoded)-1] = 'Z'
	if string(frame.Payload) != "payload" {
		t.Fatal("decoded payload aliases wire buffer")
	}
	if _, err := decodeDatagram(nil); err == nil {
		t.Fatal("DecodeDatagram accepted an empty frame")
	}
	var overflow [binary.MaxVarintLen64]byte
	n := binary.PutUvarint(overflow[:], uint64(^uint32(0))+1)
	if _, err := decodeDatagram(overflow[:n]); err == nil {
		t.Fatal("DecodeDatagram accepted an overflowing flow ID")
	}
	if _, err := encodeDatagram(1, make([]byte, maxUDPPayloadSize+1)); err == nil {
		t.Fatal("EncodeDatagram accepted an oversized UDP payload")
	}
}

func TestExposureUDPDatagramsTwoRelays(t *testing.T) {
	relayA := newFakeRelay(t, "udp-a", fakeRelayOptions{udpEnabled: true})
	defer relayA.close()
	relayB := newFakeRelay(t, "udp-b", fakeRelayOptions{udpEnabled: true})
	defer relayB.close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exposure, err := exposeWithTimings(ctx, ExposeConfig{
		Relays:     []string{relayA.url, relayB.url},
		Identity:   newTestIdentity(t),
		UDPEnabled: true,
	}, testRelayTimings())
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}
	defer exposure.Close()

	relayA.waitForQUICConn(t)
	relayB.waitForQUICConn(t)
	ready, err := exposure.WaitDatagramReady(ctx)
	if err != nil {
		t.Fatalf("WaitDatagramReady: %v", err)
	}
	if len(ready) == 0 {
		t.Fatal("WaitDatagramReady returned no relays")
	}

	relayA.sendQUICDatagram(t, 7, []byte("from-a"))
	relayB.sendQUICDatagram(t, 7, []byte("from-b"))
	seen := make(map[string]DatagramFrame)
	for len(seen) < 2 {
		frame, err := exposure.AcceptDatagram()
		if err != nil {
			t.Fatalf("AcceptDatagram: %v", err)
		}
		seen[frame.RelayURL] = frame
	}
	if string(seen[relayA.url].Payload) != "from-a" || string(seen[relayB.url].Payload) != "from-b" {
		t.Fatalf("received frames = %+v", seen)
	}

	frameA := seen[relayA.url]
	frameA.Payload = []byte("reply-a")
	if err := exposure.SendDatagram(frameA); err != nil {
		t.Fatalf("SendDatagram A: %v", err)
	}
	frameB := seen[relayB.url]
	frameB.Payload = []byte("reply-b")
	if err := exposure.SendDatagram(frameB); err != nil {
		t.Fatalf("SendDatagram B: %v", err)
	}
	if reply := relayA.receiveQUICDatagram(t); reply.FlowID != 7 || string(reply.Payload) != "reply-a" {
		t.Fatalf("relay A reply = %+v", reply)
	}
	if reply := relayB.receiveQUICDatagram(t); reply.FlowID != 7 || string(reply.Payload) != "reply-b" {
		t.Fatalf("relay B reply = %+v", reply)
	}
	if err := exposure.SendDatagram(DatagramFrame{RelayURL: "https://unknown.example", FlowID: 1}); err == nil {
		t.Fatal("SendDatagram accepted an unknown relay")
	}
}

func TestExposureUDPUnsupportedRelayIsIsolated(t *testing.T) {
	supported := newFakeRelay(t, "udp-supported", fakeRelayOptions{udpEnabled: true})
	defer supported.close()
	unsupported := newFakeRelay(t, "udp-disabled", fakeRelayOptions{})
	defer unsupported.close()
	ctx, cancel := context.WithTimeout(context.Background(), fakeRelayWait)
	defer cancel()
	exposure, err := exposeWithTimings(ctx, ExposeConfig{
		Relays:     []string{unsupported.url, supported.url},
		Identity:   newTestIdentity(t),
		UDPEnabled: true,
	}, testRelayTimings())
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}
	defer exposure.Close()

	supported.waitForQUICConn(t)
	if _, err := exposure.WaitDatagramReady(ctx); err != nil {
		t.Fatalf("WaitDatagramReady: %v", err)
	}
	unsupported.waitFor(t, "unsupported UDP relay failure", func() bool {
		for _, status := range exposure.Relays() {
			if status.RelayURL == unsupported.url {
				return status.State == RelayFailed
			}
		}
		return false
	})
	for _, status := range exposure.Relays() {
		if status.RelayURL == supported.url && status.State == RelayFailed {
			t.Fatalf("supported relay failed: %v", status.Err)
		}
	}
}

func TestExposureUDPFailureUnblocksDatagramAccept(t *testing.T) {
	relay := newFakeRelay(t, "udp-unavailable", fakeRelayOptions{})
	defer relay.close()
	ctx, cancel := context.WithTimeout(context.Background(), fakeRelayWait)
	defer cancel()
	exposure, err := exposeWithTimings(ctx, ExposeConfig{
		Relays:     []string{relay.url},
		Identity:   newTestIdentity(t),
		UDPEnabled: true,
	}, testRelayTimings())
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}
	defer exposure.Close()
	if _, err := exposure.AcceptDatagram(); !errors.Is(err, ErrNoRelays) {
		t.Fatalf("AcceptDatagram error = %v, want ErrNoRelays", err)
	}
}

func TestExposureUDPRenewReconnectsWithLatestToken(t *testing.T) {
	relay := newFakeRelay(t, "udp-renew", fakeRelayOptions{
		udpEnabled:   true,
		initialLease: 900 * time.Millisecond,
		renewedLease: 5 * time.Minute,
	})
	defer relay.close()
	ctx, cancel := context.WithTimeout(context.Background(), fakeRelayWait)
	defer cancel()
	timings := testRelayTimings()
	timings.leaseTTL = 900 * time.Millisecond
	timings.renewBefore = 300 * time.Millisecond
	exposure, err := exposeWithTimings(ctx, ExposeConfig{
		Relays:     []string{relay.url},
		Identity:   newTestIdentity(t),
		UDPEnabled: true,
	}, timings)
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}
	defer exposure.Close()

	relay.waitFor(t, "renewed QUIC token", func() bool {
		return len(relay.quicTokens) >= 2 && relay.quicTokens[len(relay.quicTokens)-1] == relay.currentToken && relay.renewCount >= 1
	})
	relay.sendQUICDatagram(t, 9, []byte("after-renew"))
	frame, err := exposure.AcceptDatagram()
	if err != nil {
		t.Fatalf("AcceptDatagram: %v", err)
	}
	if frame.FlowID != 9 || string(frame.Payload) != "after-renew" {
		t.Fatalf("renewed frame = %+v", frame)
	}
}

func TestProxyWithConfigServesTCPAndUDP(t *testing.T) {
	relay := newFakeRelay(t, "combined", fakeRelayOptions{udpEnabled: true})
	defer relay.close()
	targetHTTP, tcpTarget := newTargetServer(t)
	defer targetHTTP.Close()
	udpTarget, closeUDP := newUDPEchoTarget(t)
	defer closeUDP()

	ctx, cancel := context.WithCancel(context.Background())
	exposure, err := exposeWithTimings(ctx, ExposeConfig{
		Relays:     []string{relay.url},
		Identity:   newTestIdentity(t),
		UDPEnabled: true,
	}, testRelayTimings())
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}
	proxyDone := make(chan error, 1)
	go func() {
		proxyDone <- ProxyWithConfig(ctx, exposure, ProxyConfig{TCPTarget: tcpTarget, UDPTarget: udpTarget})
	}()

	_ = waitForReady(t, exposure, 1)
	relay.waitForQUICConn(t)
	token := relay.currentAccessToken()
	relay.waitForIdleToken(t, token, 1)
	if body := relay.requestThroughSession(t, token, "tenant.localhost", "/combined"); body != "target:/combined" {
		t.Fatalf("TCP body = %q", body)
	}
	relay.sendQUICDatagram(t, 55, []byte("udp-echo"))
	response := relay.receiveQUICDatagram(t)
	if response.FlowID != 55 || string(response.Payload) != "udp-echo" {
		t.Fatalf("UDP response = %+v", response)
	}

	cancel()
	select {
	case err := <-proxyDone:
		if err != nil {
			t.Fatalf("ProxyWithConfig shutdown: %v", err)
		}
	case <-time.After(fakeRelayWait):
		t.Fatal("ProxyWithConfig did not stop")
	}
}

func newUDPEchoTarget(t *testing.T) (string, func()) {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatalf("listen UDP echo target: %v", err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		buffer := make([]byte, maxUDPPayloadSize)
		for {
			n, address, err := conn.ReadFromUDP(buffer)
			if err != nil {
				return
			}
			_, _ = conn.WriteToUDP(buffer[:n], address)
		}
	}()
	return conn.LocalAddr().String(), func() {
		_ = conn.Close()
		<-done
	}
}

func TestProxyUDPRejectsDisabledExposure(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exposure := &Exposure{ctx: ctx, udpEnabled: false}
	if _, err := exposure.WaitDatagramReady(ctx); err == nil {
		t.Fatal("WaitDatagramReady accepted a disabled exposure")
	}
	if _, err := exposure.AcceptDatagram(); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("AcceptDatagram error = %v, want net.ErrClosed", err)
	}
}
