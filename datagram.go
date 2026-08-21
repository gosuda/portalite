package portalite

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/quic-go/quic-go"
)

const (
	maxUDPPayloadSize             = 65507
	datagramQueuePerRelay         = 256
	quicBackhaulALPN              = "portal-tunnel"
	quicBackhaulControlTimeout    = 10 * time.Second
	quicBackhaulControlBodyLimit  = 4096
	quicBackhaulKeepAlive         = 15 * time.Second
	quicBackhaulIdleTimeout       = 60 * time.Second
	defaultUDPFlowIdleTimeout     = 5 * time.Minute
	defaultUDPFlowCleanupInterval = 15 * time.Second
	defaultUDPProxyMaxFlows       = 1024
)

// DatagramFrame is one UDP datagram received from or sent through a relay.
// RelayURL and FlowID together identify the return path.
type DatagramFrame struct {
	FlowID   uint32
	Payload  []byte
	RelayURL string
	UDPAddr  string
}

var errDatagramNotReady = errors.New("portalite: datagram relay is not ready")

type quicBackhaulControlMessage struct {
	AccessToken string `json:"access_token"`
}

type quicBackhaulControlResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type quicBackhaulRejection struct {
	Code string
}

func (e *quicBackhaulRejection) Error() string {
	code := strings.TrimSpace(e.Code)
	if code == "" {
		code = "rejected"
	}
	return "QUIC backhaul rejected: " + code
}

func encodeDatagram(flowID uint32, payload []byte) ([]byte, error) {
	if len(payload) > maxUDPPayloadSize {
		return nil, fmt.Errorf("UDP payload exceeds %d bytes", maxUDPPayloadSize)
	}
	var prefix [binary.MaxVarintLen32]byte
	n := binary.PutUvarint(prefix[:], uint64(flowID))
	encoded := make([]byte, n+len(payload))
	copy(encoded, prefix[:n])
	copy(encoded[n:], payload)
	return encoded, nil
}

func decodeDatagram(data []byte) (DatagramFrame, error) {
	flowID, n := binary.Uvarint(data)
	if n <= 0 || flowID > uint64(^uint32(0)) {
		return DatagramFrame{}, errors.New("invalid datagram flow ID")
	}
	payload := data[n:]
	if len(payload) > maxUDPPayloadSize {
		return DatagramFrame{}, fmt.Errorf("UDP payload exceeds %d bytes", maxUDPPayloadSize)
	}
	return DatagramFrame{FlowID: uint32(flowID), Payload: append([]byte(nil), payload...)}, nil
}

func dialQUICBackhaul(ctx context.Context, address string, baseTLS *tls.Config, accessToken string) (*quic.Conn, error) {
	if ctx == nil {
		return nil, errors.New("QUIC backhaul context is nil")
	}
	if strings.TrimSpace(accessToken) == "" {
		return nil, errors.New("QUIC backhaul access token is required")
	}
	if _, _, err := net.SplitHostPort(address); err != nil {
		return nil, fmt.Errorf("invalid QUIC backhaul address: %w", err)
	}

	conn, err := quic.DialAddr(ctx, address, quicClientTLSConfig(baseTLS), quicClientConfig())
	if err != nil {
		return nil, fmt.Errorf("dial QUIC backhaul: %w", err)
	}
	closeWithError := func(code quic.ApplicationErrorCode, reason string) {
		_ = conn.CloseWithError(code, reason)
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		closeWithError(1, "control stream open failed")
		return nil, fmt.Errorf("open QUIC backhaul control stream: %w", err)
	}
	_ = stream.SetDeadline(time.Now().Add(quicBackhaulControlTimeout))
	if err := json.NewEncoder(stream).Encode(quicBackhaulControlMessage{AccessToken: accessToken}); err != nil {
		closeWithError(1, "control write failed")
		return nil, fmt.Errorf("write QUIC backhaul control message: %w", err)
	}
	var response quicBackhaulControlResponse
	if err := json.NewDecoder(io.LimitReader(stream, quicBackhaulControlBodyLimit)).Decode(&response); err != nil {
		closeWithError(1, "control response read failed")
		return nil, fmt.Errorf("read QUIC backhaul control response: %w", err)
	}
	_ = stream.SetDeadline(time.Time{})
	_ = stream.Close()
	if !response.OK {
		rejection := &quicBackhaulRejection{Code: response.Error}
		closeWithError(1, rejection.Error())
		return nil, rejection
	}
	return conn, nil
}

func quicClientTLSConfig(base *tls.Config) *tls.Config {
	var config *tls.Config
	if base == nil {
		config = &tls.Config{}
	} else {
		config = base.Clone()
	}
	config.NextProtos = []string{quicBackhaulALPN}
	if config.MinVersion < tls.VersionTLS13 {
		config.MinVersion = tls.VersionTLS13
	}
	return config
}

func quicClientConfig() *quic.Config {
	return &quic.Config{
		EnableDatagrams:    true,
		KeepAlivePeriod:    quicBackhaulKeepAlive,
		MaxIdleTimeout:     quicBackhaulIdleTimeout,
		MaxIncomingStreams: 16,
	}
}
