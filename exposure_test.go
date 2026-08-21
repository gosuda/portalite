package portalite

import (
	"bufio"
	"bytes"
	"context"
	stdecdsa "crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

const fakeRelayWait = 5 * time.Second

type fakeRelayOptions struct {
	initialLease         time.Duration
	renewedLease         time.Duration
	recoveredLease       time.Duration
	leaseNotFoundAtRenew int
	transientRenewAt     int
	registrationSNIPorts []int
	holdTLSHandshakeAt   int
	tlsHandshakeStarted  chan<- int
	tlsHandshakeRelease  <-chan struct{}
	signRequestStarted   chan<- string
	signRequestRelease   <-chan struct{}
	signRequestFinished  chan<- struct{}
	invalidSigner        bool
}

type fakeRelaySession struct {
	id      int
	token   string
	conn    net.Conn
	claimed bool
}

type fakeRelayRequestResult struct {
	body string
	err  error
}

type fakeRelay struct {
	name      string
	url       string
	port      int
	leaf      *x509.Certificate
	key       *stdecdsa.PrivateKey
	listener  net.Listener
	server    *http.Server
	serveDone chan error

	options fakeRelayOptions

	mu                    sync.Mutex
	changed               chan struct{}
	errors                chan error
	tlsHandshakes         int
	domainCount           int
	challengeCount        int
	registerCount         int
	renewCount            int
	challengeID           string
	challengeMessage      string
	challengeIdentity     identityRef
	currentToken          string
	leaseNotFoundSent     bool
	transientRenewSent    bool
	connectLeaseLost      bool
	connectLeaseLossCount int
	terminalConnect       bool
	signRequestHeld       bool
	nextSessionID         int
	sessions              map[int]*fakeRelaySession
	connectTokens         []string
	signTokens            []string
	unregisterTokens      []string
	closed                bool
}

type fakeSignRequest struct {
	KeyID         string `json:"key_id"`
	Algorithm     string `json:"algorithm"`
	Digest        []byte `json:"digest"`
	TimestampUnix int64  `json:"timestamp_unix"`
	Nonce         string `json:"nonce"`
}

type fakeSignResponse struct {
	KeyID     string `json:"key_id"`
	Algorithm string `json:"algorithm"`
	Signature []byte `json:"signature"`
}

func newFakeRelay(t *testing.T, name string, options fakeRelayOptions) *fakeRelay {
	t.Helper()
	if options.initialLease <= 0 {
		options.initialLease = 5 * time.Minute
	}
	if options.renewedLease <= 0 {
		options.renewedLease = 5 * time.Minute
	}
	if options.recoveredLease <= 0 {
		options.recoveredLease = 5 * time.Minute
	}

	key, err := stdecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate fake relay key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost", "*.localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create fake relay certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse fake relay certificate: %v", err)
	}
	certificate := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        leaf,
	}

	baseListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen for fake relay: %v", err)
	}
	port := baseListener.Addr().(*net.TCPAddr).Port
	relay := &fakeRelay{
		name:      name,
		url:       "https://localhost:" + strconv.Itoa(port),
		port:      port,
		leaf:      leaf,
		key:       key,
		listener:  baseListener,
		serveDone: make(chan error, 1),
		options:   options,
		changed:   make(chan struct{}),
		errors:    make(chan error, 32),
		sessions:  make(map[int]*fakeRelaySession),
	}
	tlsConfig := &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{certificate},
		NextProtos:   []string{"http/1.1"},
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) {
			relay.mu.Lock()
			relay.tlsHandshakes++
			handshake := relay.tlsHandshakes
			hold := handshake == relay.options.holdTLSHandshakeAt && relay.options.tlsHandshakeRelease != nil
			relay.signalLocked()
			relay.mu.Unlock()
			if hold {
				if relay.options.tlsHandshakeStarted != nil {
					relay.options.tlsHandshakeStarted <- handshake
				}
				<-relay.options.tlsHandshakeRelease
			}
			return nil, nil
		},
	}
	relay.server = &http.Server{Handler: relay}
	tlsListener := tls.NewListener(baseListener, tlsConfig)
	go func() {
		relay.serveDone <- relay.server.Serve(tlsListener)
	}()
	return relay
}

func (r *fakeRelay) signalLocked() {
	close(r.changed)
	r.changed = make(chan struct{})
}

func (r *fakeRelay) recordError(err error) {
	select {
	case r.errors <- err:
	default:
	}
}

func (r *fakeRelay) ServeHTTP(response http.ResponseWriter, request *http.Request) {
	if request.ProtoMajor != 1 {
		r.fail(response, http.StatusHTTPVersionNotSupported, "http11_only", "HTTP/1.1 required")
		return
	}
	switch request.URL.Path {
	case pathDomain:
		r.handleDomain(response, request)
	case pathRegisterChallenge:
		r.handleChallenge(response, request)
	case pathRegister:
		r.handleRegister(response, request)
	case pathRenew:
		r.handleRenew(response, request)
	case pathUnregister:
		r.handleUnregister(response, request)
	case pathConnect:
		r.handleConnect(response, request)
	case "/v1/sign":
		r.handleSign(response, request)
	default:
		r.recordError(fmt.Errorf("%s: unexpected path %s", r.name, request.URL.Path))
		r.fail(response, http.StatusNotFound, "not_found", "not found")
	}
}

func (r *fakeRelay) handleDomain(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet {
		r.badRequest(response, fmt.Errorf("domain method = %s", request.Method))
		return
	}
	r.mu.Lock()
	r.domainCount++
	r.signalLocked()
	r.mu.Unlock()
	r.success(response, domainResponse{ProtocolVersion: ProtocolVersion})
}

func (r *fakeRelay) handleChallenge(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		r.badRequest(response, fmt.Errorf("challenge method = %s", request.Method))
		return
	}
	var body challengeRequest
	if err := decodeFakeJSON(request, &body); err != nil {
		r.badRequest(response, fmt.Errorf("decode challenge: %w", err))
		return
	}
	if body.Identity.Name == "" || body.Identity.Address == "" || body.TTL < 1 {
		r.badRequest(response, fmt.Errorf("invalid challenge body: %+v", body))
		return
	}

	r.mu.Lock()
	r.challengeCount++
	challengeID := fmt.Sprintf("%s-challenge-%d", r.name, r.challengeCount)
	message := fmt.Sprintf("%s.localhost wants you to sign in with your Ethereum account:\n%s\n\nPortalite relay test\nNonce: %s", body.Identity.Name, body.Identity.Address, challengeID)
	r.challengeID = challengeID
	r.challengeMessage = message
	r.challengeIdentity = body.Identity
	r.signalLocked()
	r.mu.Unlock()
	r.success(response, challengeResponse{
		ChallengeID: challengeID,
		ExpiresAt:   time.Now().Add(time.Minute),
		SIWEMessage: message,
	})
}

func (r *fakeRelay) handleRegister(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		r.badRequest(response, fmt.Errorf("register method = %s", request.Method))
		return
	}
	var body registerRequest
	if err := decodeFakeJSON(request, &body); err != nil {
		r.badRequest(response, fmt.Errorf("decode register: %w", err))
		return
	}

	r.mu.Lock()
	challengeID := r.challengeID
	message := r.challengeMessage
	identity := r.challengeIdentity
	r.mu.Unlock()
	if body.ChallengeID != challengeID || body.SIWEMessage != message {
		r.badRequest(response, errors.New("register did not echo exact challenge"))
		return
	}
	if err := verifyFakeSIWESignature(body.SIWEMessage, body.SIWESignature, identity.Address); err != nil {
		r.badRequest(response, fmt.Errorf("verify SIWE signature: %w", err))
		return
	}

	r.mu.Lock()
	r.registerCount++
	registration := r.registerCount
	token := fmt.Sprintf("%s-token-%d", r.name, registration)
	r.currentToken = token
	r.connectLeaseLost = false
	leaseDuration := r.options.initialLease
	if registration > 1 {
		leaseDuration = r.options.recoveredLease
	}
	sniPort := r.port
	if len(r.options.registrationSNIPorts) > 0 {
		portIndex := registration - 1
		if portIndex >= len(r.options.registrationSNIPorts) {
			portIndex = len(r.options.registrationSNIPorts) - 1
		}
		sniPort = r.options.registrationSNIPorts[portIndex]
	}
	stale := make([]net.Conn, 0, len(r.sessions))
	if registration > 1 {
		for id, session := range r.sessions {
			stale = append(stale, session.conn)
			delete(r.sessions, id)
		}
	}
	r.signalLocked()
	r.mu.Unlock()
	for _, conn := range stale {
		_ = conn.Close()
	}

	r.success(response, registerResponse{
		Identity:    identity,
		ExpiresAt:   time.Now().Add(leaseDuration),
		AccessToken: token,
		SNIPort:     sniPort,
	})
}

func (r *fakeRelay) handleRenew(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		r.badRequest(response, fmt.Errorf("renew method = %s", request.Method))
		return
	}
	var body renewRequest
	if err := decodeFakeJSON(request, &body); err != nil {
		r.badRequest(response, fmt.Errorf("decode renew: %w", err))
		return
	}

	r.mu.Lock()
	r.renewCount++
	renewCount := r.renewCount
	currentToken := r.currentToken
	if body.AccessToken != currentToken || body.TTL < 1 {
		r.mu.Unlock()
		r.badRequest(response, fmt.Errorf("renew token/ttl mismatch: token=%q ttl=%d", body.AccessToken, body.TTL))
		return
	}
	if r.options.leaseNotFoundAtRenew > 0 && renewCount == r.options.leaseNotFoundAtRenew && !r.leaseNotFoundSent {
		r.leaseNotFoundSent = true
		r.signalLocked()
		r.mu.Unlock()
		r.fail(response, http.StatusNotFound, "lease_not_found", "lease not found")
		return
	}
	if r.options.transientRenewAt > 0 && renewCount == r.options.transientRenewAt && !r.transientRenewSent {
		r.transientRenewSent = true
		r.signalLocked()
		r.mu.Unlock()
		r.fail(response, http.StatusServiceUnavailable, "temporarily_unavailable", "try again")
		return
	}
	if r.connectLeaseLost {
		r.mu.Unlock()
		<-request.Context().Done()
		return
	}
	newToken := fmt.Sprintf("%s-renewed-%d", r.name, renewCount)
	r.currentToken = newToken
	r.signalLocked()
	r.mu.Unlock()
	r.success(response, renewResponse{
		AccessToken: newToken,
		ExpiresAt:   time.Now().Add(r.options.renewedLease),
	})
}

func (r *fakeRelay) handleUnregister(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		r.badRequest(response, fmt.Errorf("unregister method = %s", request.Method))
		return
	}
	var body unregisterRequest
	if err := decodeFakeJSON(request, &body); err != nil {
		r.badRequest(response, fmt.Errorf("decode unregister: %w", err))
		return
	}
	if body.AccessToken == "" {
		r.badRequest(response, errors.New("unregister token is empty"))
		return
	}
	r.mu.Lock()
	r.unregisterTokens = append(r.unregisterTokens, body.AccessToken)
	r.signalLocked()
	r.mu.Unlock()
	r.success(response, nil)
}

func (r *fakeRelay) handleConnect(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodGet || !headerHasToken(request.Header, "Connection", "upgrade") || !strings.EqualFold(request.Header.Get("Upgrade"), "raw") {
		r.badRequest(response, errors.New("invalid reverse upgrade request"))
		return
	}
	token := request.Header.Get(accessTokenHeader)
	r.mu.Lock()
	r.connectTokens = append(r.connectTokens, token)
	terminal := r.terminalConnect
	currentToken := r.currentToken
	leaseLost := r.connectLeaseLost && token == currentToken
	if leaseLost {
		r.connectLeaseLossCount++
	}
	r.signalLocked()
	r.mu.Unlock()
	if terminal {
		r.fail(response, http.StatusConflict, "transport_mismatch", "transport mismatch")
		return
	}
	if leaseLost || token == "" || token != currentToken {
		r.fail(response, http.StatusUnauthorized, "unauthorized", "bad access token")
		return
	}

	hijacker, ok := response.(http.Hijacker)
	if !ok {
		r.badRequest(response, errors.New("HTTP server does not support hijacking"))
		return
	}
	conn, buffered, err := hijacker.Hijack()
	if err != nil {
		r.recordError(fmt.Errorf("%s: hijack reverse session: %w", r.name, err))
		return
	}
	if _, err := buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: raw\r\n\r\n"); err != nil {
		_ = conn.Close()
		r.recordError(fmt.Errorf("%s: write upgrade response: %w", r.name, err))
		return
	}
	if err := buffered.Flush(); err != nil {
		_ = conn.Close()
		r.recordError(fmt.Errorf("%s: flush upgrade response: %w", r.name, err))
		return
	}

	r.mu.Lock()
	r.nextSessionID++
	session := &fakeRelaySession{id: r.nextSessionID, token: token, conn: conn}
	r.sessions[session.id] = session
	r.signalLocked()
	r.mu.Unlock()
}

func (r *fakeRelay) handleSign(response http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		r.badRequest(response, fmt.Errorf("sign method = %s", request.Method))
		return
	}
	var body fakeSignRequest
	if err := decodeFakeJSON(request, &body); err != nil {
		r.badRequest(response, fmt.Errorf("decode sign: %w", err))
		return
	}
	if body.KeyID != "relay-cert" || len(body.Digest) == 0 || body.TimestampUnix == 0 || body.Nonce == "" || !strings.HasPrefix(body.Algorithm, "ECDSA_") {
		r.badRequest(response, fmt.Errorf("invalid sign request: %+v", body))
		return
	}
	token := request.Header.Get(accessTokenHeader)
	r.mu.Lock()
	r.signTokens = append(r.signTokens, token)
	isProbe := bytes.Equal(body.Digest, tenantSignerProbeDigest[:])
	hold := !isProbe && !r.signRequestHeld && r.options.signRequestRelease != nil
	if hold {
		r.signRequestHeld = true
	}
	r.signalLocked()
	r.mu.Unlock()
	if hold {
		if r.options.signRequestStarted != nil {
			r.options.signRequestStarted <- token
		}
		if r.options.signRequestFinished != nil {
			defer func() { r.options.signRequestFinished <- struct{}{} }()
		}
		select {
		case <-r.options.signRequestRelease:
		case <-request.Context().Done():
			return
		}
	}
	r.mu.Lock()
	currentToken := r.currentToken
	r.mu.Unlock()
	if token == "" || token != currentToken {
		http.Error(response, `{"error":"bad access token"}`, http.StatusUnauthorized)
		return
	}
	signature, err := stdecdsa.SignASN1(rand.Reader, r.key, body.Digest)
	if err != nil {
		r.badRequest(response, fmt.Errorf("sign digest: %w", err))
		return
	}
	if r.options.invalidSigner && len(signature) != 0 {
		signature[len(signature)-1] ^= 0xff
	}
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(fakeSignResponse{
		KeyID:     body.KeyID,
		Algorithm: body.Algorithm,
		Signature: signature,
	})
}

func (r *fakeRelay) success(response http.ResponseWriter, data any) {
	var raw json.RawMessage
	if data != nil {
		encoded, err := json.Marshal(data)
		if err != nil {
			r.recordError(fmt.Errorf("%s: encode response: %w", r.name, err))
			http.Error(response, "encode response", http.StatusInternalServerError)
			return
		}
		raw = encoded
	}
	response.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(response).Encode(apiEnvelope{OK: true, Data: raw})
}

func (r *fakeRelay) fail(response http.ResponseWriter, status int, code, message string) {
	response.Header().Set("Content-Type", "application/json")
	response.WriteHeader(status)
	_ = json.NewEncoder(response).Encode(apiEnvelope{
		OK:    false,
		Error: &apiErrorBody{Code: code, Message: message},
	})
}

func (r *fakeRelay) badRequest(response http.ResponseWriter, err error) {
	r.recordError(fmt.Errorf("%s: %w", r.name, err))
	r.fail(response, http.StatusBadRequest, "bad_request", err.Error())
}

func decodeFakeJSON(request *http.Request, destination any) error {
	defer request.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(request.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	var extra any
	if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func verifyFakeSIWESignature(message, signature, expectedAddress string) error {
	normalized := strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(signature), "0x"), "0X")
	raw, err := hex.DecodeString(normalized)
	if err != nil || len(raw) != 65 {
		return errors.New("signature must be 65 hexadecimal bytes")
	}
	compact := make([]byte, 65)
	compact[0] = raw[64]
	copy(compact[1:], raw[:64])

	prefix := "\x19Ethereum Signed Message:\n" + strconv.Itoa(len(message))
	hasher := sha3.NewLegacyKeccak256()
	_, _ = io.WriteString(hasher, prefix)
	_, _ = io.WriteString(hasher, message)
	publicKey, _, err := ecdsa.RecoverCompact(compact, hasher.Sum(nil))
	if err != nil {
		return err
	}
	if !strings.EqualFold(ethereumAddress(publicKey), expectedAddress) {
		return fmt.Errorf("recovered address %s, want %s", ethereumAddress(publicKey), expectedAddress)
	}
	return nil
}

func (r *fakeRelay) waitFor(t *testing.T, description string, condition func() bool) {
	t.Helper()
	timer := time.NewTimer(fakeRelayWait)
	defer timer.Stop()
	for {
		r.mu.Lock()
		if condition() {
			r.mu.Unlock()
			return
		}
		changed := r.changed
		r.mu.Unlock()
		select {
		case err := <-r.errors:
			t.Fatalf("fake relay error while waiting for %s: %v", description, err)
		case <-changed:
		case <-timer.C:
			t.Fatalf("timed out waiting for %s", description)
		}
	}
}

func (r *fakeRelay) waitForIdleToken(t *testing.T, token string, count int) {
	t.Helper()
	r.waitFor(t, fmt.Sprintf("%d idle sessions using %s", count, token), func() bool {
		idle := 0
		for _, session := range r.sessions {
			if !session.claimed && session.token == token {
				idle++
			}
		}
		return idle >= count
	})
}

func (r *fakeRelay) currentAccessToken() string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.currentToken
}

func (r *fakeRelay) requestThroughSession(t *testing.T, token, serverName, path string) string {
	t.Helper()
	result := <-r.startRequestThroughSession(t, token, serverName, path)
	if result.err != nil {
		t.Fatalf("request through %s: %v", r.name, result.err)
	}
	return result.body
}

func (r *fakeRelay) startRequestThroughSession(t *testing.T, token, serverName, path string) <-chan fakeRelayRequestResult {
	t.Helper()
	r.waitForIdleToken(t, token, 1)

	r.mu.Lock()
	var selected *fakeRelaySession
	for _, session := range r.sessions {
		if !session.claimed && session.token == token {
			session.claimed = true
			selected = session
			break
		}
	}
	r.signalLocked()
	r.mu.Unlock()
	if selected == nil {
		t.Fatalf("no idle session for token %q", token)
	}

	result := make(chan fakeRelayRequestResult, 1)
	go func() {
		defer func() {
			_ = selected.conn.Close()
			r.mu.Lock()
			delete(r.sessions, selected.id)
			r.signalLocked()
			r.mu.Unlock()
		}()
		body, err := r.requestOnSession(selected, serverName, path)
		result <- fakeRelayRequestResult{body: body, err: err}
	}()
	return result
}

func (r *fakeRelay) requestOnSession(selected *fakeRelaySession, serverName, path string) (string, error) {
	if _, err := selected.conn.Write([]byte{markerTLS}); err != nil {
		return "", fmt.Errorf("write TLS marker: %w", err)
	}
	roots := x509.NewCertPool()
	roots.AddCert(r.leaf)
	tenant := tls.Client(selected.conn, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: serverName,
		RootCAs:    roots,
		NextProtos: []string{"http/1.1"},
	})
	if err := tenant.SetDeadline(time.Now().Add(fakeRelayWait)); err != nil {
		return "", fmt.Errorf("set tenant deadline: %w", err)
	}
	if err := tenant.Handshake(); err != nil {
		return "", fmt.Errorf("tenant TLS handshake: %w", err)
	}
	request := &http.Request{
		Method:     http.MethodGet,
		URL:        &url.URL{Path: path},
		Host:       serverName,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	request.Header.Set("Connection", "close")
	if err := request.Write(tenant); err != nil {
		return "", fmt.Errorf("write tenant HTTP request: %w", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(tenant), request)
	if err != nil {
		return "", fmt.Errorf("read tenant HTTP response: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("read tenant HTTP body: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("tenant response status = %d, body = %q", response.StatusCode, body)
	}
	return string(body), nil
}

func (r *fakeRelay) closeOneIdleAndRejectReconnect(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	var selected *fakeRelaySession
	for _, session := range r.sessions {
		if !session.claimed {
			selected = session
			break
		}
	}
	if selected == nil {
		r.mu.Unlock()
		t.Fatal("no idle reverse session to close")
	}
	r.terminalConnect = true
	delete(r.sessions, selected.id)
	r.signalLocked()
	r.mu.Unlock()
	_ = selected.conn.Close()
}

func (r *fakeRelay) closeOneIdleAndLoseConnectLease(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	if !r.transientRenewSent {
		r.mu.Unlock()
		t.Fatal("transient renew failure has not completed")
	}
	var selected *fakeRelaySession
	for _, session := range r.sessions {
		if !session.claimed {
			selected = session
			break
		}
	}
	if selected == nil {
		r.mu.Unlock()
		t.Fatal("no idle reverse session to close")
	}
	r.connectLeaseLost = true
	delete(r.sessions, selected.id)
	r.signalLocked()
	r.mu.Unlock()
	_ = selected.conn.Close()
}

func (r *fakeRelay) closeOneIdle(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	var selected *fakeRelaySession
	for _, session := range r.sessions {
		if !session.claimed {
			selected = session
			break
		}
	}
	if selected == nil {
		r.mu.Unlock()
		t.Fatal("no idle reverse session to close")
	}
	delete(r.sessions, selected.id)
	r.signalLocked()
	r.mu.Unlock()
	_ = selected.conn.Close()
}

func (r *fakeRelay) observeRemoteSessionClosures() {
	r.mu.Lock()
	sessions := make([]*fakeRelaySession, 0, len(r.sessions))
	for _, session := range r.sessions {
		if !session.claimed {
			session.claimed = true
			sessions = append(sessions, session)
		}
	}
	r.mu.Unlock()
	for _, session := range sessions {
		go func(session *fakeRelaySession) {
			_ = session.conn.SetReadDeadline(time.Now().Add(fakeRelayWait))
			var one [1]byte
			_, err := session.conn.Read(one[:])
			if err == nil {
				r.recordError(fmt.Errorf("%s: received data after shutdown on session %d", r.name, session.id))
				return
			}
			if networkError, ok := err.(net.Error); ok && networkError.Timeout() {
				r.recordError(fmt.Errorf("%s: session %d remained open after shutdown", r.name, session.id))
				return
			}
			r.mu.Lock()
			delete(r.sessions, session.id)
			r.signalLocked()
			r.mu.Unlock()
		}(session)
	}
}

func (r *fakeRelay) waitForNoSessions(t *testing.T) {
	t.Helper()
	r.waitFor(t, "all hijacked sessions to close", func() bool { return len(r.sessions) == 0 })
}

func (r *fakeRelay) assertNoErrors(t *testing.T) {
	t.Helper()
	select {
	case err := <-r.errors:
		t.Fatalf("fake relay error: %v", err)
	default:
	}
}

func (r *fakeRelay) close() {
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return
	}
	r.closed = true
	sessions := make([]net.Conn, 0, len(r.sessions))
	for id, session := range r.sessions {
		sessions = append(sessions, session.conn)
		delete(r.sessions, id)
	}
	r.signalLocked()
	r.mu.Unlock()
	for _, conn := range sessions {
		_ = conn.Close()
	}
	_ = r.server.Close()
	_ = r.listener.Close()
	select {
	case <-r.serveDone:
	case <-time.After(fakeRelayWait):
	}
}

func testRelayTimings() relayTimings {
	return relayTimings{
		leaseTTL:         time.Second,
		renewBefore:      100 * time.Millisecond,
		retryWait:        10 * time.Millisecond,
		dialTimeout:      2 * time.Second,
		handshakeTimeout: 2 * time.Second,
		requestTimeout:   2 * time.Second,
		idleTimeout:      30 * time.Second,
		shutdownTimeout:  2 * time.Second,
	}
}

func newTestIdentity(t *testing.T) Identity {
	t.Helper()
	identity, err := IdentityFromPrivateKey("tenant", "0000000000000000000000000000000000000000000000000000000000000001")
	if err != nil {
		t.Fatalf("create identity: %v", err)
	}
	return identity
}

func newTargetServer(t *testing.T) (*httptest.Server, string) {
	t.Helper()
	target := httptest.NewServer(http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(response, "target:"+request.URL.Path)
	}))
	parsed, err := url.Parse(target.URL)
	if err != nil {
		target.Close()
		t.Fatalf("parse target URL: %v", err)
	}
	return target, parsed.Host
}

func startTestProxy(t *testing.T, ctx context.Context, identity Identity, relays []string, timings relayTimings, target string) (*Exposure, <-chan error) {
	t.Helper()
	exposure, err := exposeWithTimings(ctx, ExposeConfig{Relays: relays, Identity: identity}, timings)
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}
	proxyDone := make(chan error, 1)
	go func() {
		proxyDone <- Proxy(ctx, exposure, target)
	}()
	return exposure, proxyDone
}

func waitForReady(t *testing.T, exposure *Exposure, relayCount int) map[string]RelayStatus {
	t.Helper()
	ready := make(map[string]RelayStatus, relayCount)
	timer := time.NewTimer(fakeRelayWait)
	defer timer.Stop()
	for len(ready) < relayCount {
		select {
		case status, ok := <-exposure.Updates():
			if !ok {
				t.Fatalf("updates closed after %d/%d ready relays", len(ready), relayCount)
			}
			if status.State == RelayFailed {
				t.Fatalf("relay %s failed before ready: %v", status.RelayURL, status.Err)
			}
			if status.State == RelayReady {
				ready[status.RelayURL] = status
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for %d ready relays", relayCount)
		}
	}
	return ready
}

func waitForFailed(t *testing.T, exposure *Exposure, relayURL string) RelayStatus {
	t.Helper()
	timer := time.NewTimer(fakeRelayWait)
	defer timer.Stop()
	for {
		select {
		case status, ok := <-exposure.Updates():
			if !ok {
				t.Fatalf("updates closed before failure for %s", relayURL)
			}
			if status.RelayURL == relayURL && status.State == RelayFailed {
				return status
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for relay failure: %s", relayURL)
		}
	}
}

func stopTestProxy(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Proxy after cancellation: %v", err)
		}
	case <-time.After(fakeRelayWait):
		t.Fatal("Proxy did not stop after cancellation")
	}
}

func TestExposureTwoRelaysEndToEnd(t *testing.T) {
	relayA := newFakeRelay(t, "relay-a", fakeRelayOptions{})
	defer relayA.close()
	relayB := newFakeRelay(t, "relay-b", fakeRelayOptions{})
	defer relayB.close()
	target, targetAddress := newTargetServer(t)
	defer target.Close()
	identity := newTestIdentity(t)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := false
	exposure, proxyDone := startTestProxy(t, ctx, identity, []string{relayA.url, relayB.url}, testRelayTimings(), targetAddress)
	defer func() {
		if !stopped {
			stopTestProxy(t, cancel, proxyDone)
		}
	}()

	ready := waitForReady(t, exposure, 2)
	if len(ready) != 2 {
		t.Fatalf("ready relay count = %d, want 2", len(ready))
	}
	statusA := ready[relayA.url]
	statusB := ready[relayB.url]
	urlA, err := url.Parse(statusA.PublicURL)
	if err != nil {
		t.Fatalf("parse relay A public URL: %v", err)
	}
	urlB, err := url.Parse(statusB.PublicURL)
	if err != nil {
		t.Fatalf("parse relay B public URL: %v", err)
	}
	if urlA.Port() == "" || urlB.Port() == "" || urlA.Port() == urlB.Port() {
		t.Fatalf("ready URLs must have distinct explicit ports: %q and %q", statusA.PublicURL, statusB.PublicURL)
	}
	if statusA.PublicURL != "https://tenant.localhost:"+strconv.Itoa(relayA.port) || statusB.PublicURL != "https://tenant.localhost:"+strconv.Itoa(relayB.port) {
		t.Fatalf("unexpected public URLs: %q and %q", statusA.PublicURL, statusB.PublicURL)
	}

	tokenA := relayA.currentAccessToken()
	tokenB := relayB.currentAccessToken()
	relayA.waitForIdleToken(t, tokenA, reverseSessionSlots)
	relayB.waitForIdleToken(t, tokenB, reverseSessionSlots)
	if body := relayA.requestThroughSession(t, tokenA, "tenant.localhost", "/from-a"); body != "target:/from-a" {
		t.Fatalf("relay A body = %q", body)
	}
	if body := relayB.requestThroughSession(t, tokenB, "tenant.localhost", "/from-b"); body != "target:/from-b" {
		t.Fatalf("relay B body = %q", body)
	}

	relayA.waitForIdleToken(t, tokenA, reverseSessionSlots)
	relayA.closeOneIdleAndRejectReconnect(t)
	failed := waitForFailed(t, exposure, relayA.url)
	var apiErr *APIError
	if !errors.As(failed.Err, &apiErr) || apiErr.StatusCode != http.StatusConflict || apiErr.Code != "transport_mismatch" {
		t.Fatalf("relay A failure = %#v, want 409 transport_mismatch", failed.Err)
	}
	relayA.waitFor(t, "relay A unregister", func() bool {
		return len(relayA.unregisterTokens) == 1 && relayA.unregisterTokens[0] == tokenA
	})

	relayB.waitForIdleToken(t, tokenB, 1)
	if body := relayB.requestThroughSession(t, tokenB, "tenant.localhost", "/after-a-failed"); body != "target:/after-a-failed" {
		t.Fatalf("relay B body after A failure = %q", body)
	}

	stopTestProxy(t, cancel, proxyDone)
	stopped = true
	relayB.waitFor(t, "relay B unregister", func() bool {
		return len(relayB.unregisterTokens) == 1 && relayB.unregisterTokens[0] == tokenB
	})
	relayA.observeRemoteSessionClosures()
	relayB.observeRemoteSessionClosures()
	relayA.waitForNoSessions(t)
	relayB.waitForNoSessions(t)
	relayA.assertNoErrors(t)
	relayB.assertNoErrors(t)
}

func TestExposureRenewRotatesConnectAndSignerToken(t *testing.T) {
	relay := newFakeRelay(t, "rotation", fakeRelayOptions{
		initialLease:   150 * time.Millisecond,
		renewedLease:   5 * time.Minute,
		recoveredLease: 5 * time.Minute,
	})
	defer relay.close()
	target, targetAddress := newTargetServer(t)
	defer target.Close()
	identity := newTestIdentity(t)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := false
	exposure, proxyDone := startTestProxy(t, ctx, identity, []string{relay.url}, testRelayTimings(), targetAddress)
	defer func() {
		if !stopped {
			stopTestProxy(t, cancel, proxyDone)
		}
	}()

	_ = waitForReady(t, exposure, 1)
	originalToken := relay.name + "-token-1"
	relay.waitForIdleToken(t, originalToken, reverseSessionSlots)
	relay.waitFor(t, "renewed access token", func() bool {
		return relay.renewCount >= 1 && relay.currentToken != originalToken
	})
	rotatedToken := relay.currentAccessToken()
	relay.closeOneIdle(t)
	relay.waitForIdleToken(t, rotatedToken, 1)
	if body := relay.requestThroughSession(t, rotatedToken, "tenant.localhost", "/rotated"); body != "target:/rotated" {
		t.Fatalf("rotated-token body = %q", body)
	}
	relay.waitFor(t, "rotated token at connect and signer", func() bool {
		return exposureTestContainsString(relay.connectTokens, rotatedToken) && exposureTestContainsString(relay.signTokens, rotatedToken)
	})

	stopTestProxy(t, cancel, proxyDone)
	stopped = true
	relay.waitFor(t, "latest token unregister", func() bool {
		return len(relay.unregisterTokens) == 1 && relay.unregisterTokens[0] == rotatedToken
	})
	relay.observeRemoteSessionClosures()
	relay.waitForNoSessions(t)
	relay.assertNoErrors(t)
}

func TestExposureConnectLeaseLossAfterTransientRenewRebootstrapsAndRecovers(t *testing.T) {
	relay := newFakeRelay(t, "connect-recovery", fakeRelayOptions{
		initialLease:     30 * time.Second,
		recoveredLease:   5 * time.Minute,
		transientRenewAt: 1,
	})
	defer relay.close()
	target, targetAddress := newTargetServer(t)
	defer target.Close()
	ctx, cancel := context.WithCancel(context.Background())
	stopped := false
	timings := testRelayTimings()
	timings.renewBefore = 29500 * time.Millisecond
	timings.retryWait = 500 * time.Millisecond
	timings.requestTimeout = 200 * time.Millisecond
	exposure, proxyDone := startTestProxy(t, ctx, newTestIdentity(t), []string{relay.url}, timings, targetAddress)
	defer func() {
		if !stopped {
			stopTestProxy(t, cancel, proxyDone)
		}
	}()

	_ = waitForReady(t, exposure, 1)
	originalToken := relay.name + "-token-1"
	relay.waitForIdleToken(t, originalToken, reverseSessionSlots)
	relay.waitFor(t, "transient renew failure", func() bool {
		return relay.transientRenewSent && relay.renewCount >= 1 && relay.currentToken == originalToken
	})
	relay.closeOneIdleAndLoseConnectLease(t)

	relay.waitFor(t, "full registration after explicit connect lease loss", func() bool {
		return relay.connectLeaseLossCount >= 1 &&
			relay.domainCount >= 2 &&
			relay.challengeCount >= 2 &&
			relay.registerCount >= 2
	})
	recoveredToken := relay.name + "-token-2"
	relay.waitForIdleToken(t, recoveredToken, 1)
	if body := relay.requestThroughSession(t, recoveredToken, "tenant.localhost", "/after-connect-loss"); body != "target:/after-connect-loss" {
		t.Fatalf("recovered body = %q", body)
	}
	relay.waitFor(t, "recovered token signer call", func() bool {
		return exposureTestContainsString(relay.signTokens, recoveredToken)
	})
	statuses := exposure.Relays()
	if len(statuses) != 1 || statuses[0].State != RelayReady || statuses[0].Err != nil {
		t.Fatalf("relay status after connect lease recovery = %+v, want ready without failure", statuses)
	}

	stopTestProxy(t, cancel, proxyDone)
	stopped = true
	relay.waitFor(t, "recovered lease unregister", func() bool {
		return len(relay.unregisterTokens) == 1 && relay.unregisterTokens[0] == recoveredToken
	})
	relay.observeRemoteSessionClosures()
	relay.waitForNoSessions(t)
	relay.assertNoErrors(t)
}

func TestExposureLeaseNotFoundRebootstrapsAndRecovers(t *testing.T) {
	relay := newFakeRelay(t, "recovery", fakeRelayOptions{
		initialLease:         150 * time.Millisecond,
		renewedLease:         150 * time.Millisecond,
		recoveredLease:       5 * time.Minute,
		leaseNotFoundAtRenew: 2,
	})
	defer relay.close()
	target, targetAddress := newTargetServer(t)
	defer target.Close()
	identity := newTestIdentity(t)
	ctx, cancel := context.WithCancel(context.Background())
	stopped := false
	exposure, proxyDone := startTestProxy(t, ctx, identity, []string{relay.url}, testRelayTimings(), targetAddress)
	defer func() {
		if !stopped {
			stopTestProxy(t, cancel, proxyDone)
		}
	}()

	_ = waitForReady(t, exposure, 1)
	relay.mu.Lock()
	initialHandshakes := relay.tlsHandshakes
	relay.mu.Unlock()
	relay.waitFor(t, "full registration after lease_not_found", func() bool {
		return relay.leaseNotFoundSent && relay.domainCount >= 2 && relay.challengeCount >= 2 && relay.registerCount >= 2 && relay.tlsHandshakes > initialHandshakes
	})
	recoveredToken := relay.name + "-token-2"
	relay.waitForIdleToken(t, recoveredToken, 1)
	if body := relay.requestThroughSession(t, recoveredToken, "tenant.localhost", "/recovered"); body != "target:/recovered" {
		t.Fatalf("recovered body = %q", body)
	}
	relay.waitFor(t, "recovered token signer call", func() bool {
		return exposureTestContainsString(relay.signTokens, recoveredToken)
	})

	stopTestProxy(t, cancel, proxyDone)
	stopped = true
	relay.waitFor(t, "recovered lease unregister", func() bool {
		return len(relay.unregisterTokens) == 1 && relay.unregisterTokens[0] == recoveredToken
	})
	relay.observeRemoteSessionClosures()
	relay.waitForNoSessions(t)
	relay.assertNoErrors(t)
}

func TestExposureLeaseRefreshWinsOverCanceledStalledReverseOpen(t *testing.T) {
	handshakeStarted := make(chan int, 1)
	handshakeRelease := make(chan struct{})
	var releaseHandshake sync.Once
	release := func() { releaseHandshake.Do(func() { close(handshakeRelease) }) }

	relay := newFakeRelay(t, "stalled-open-refresh", fakeRelayOptions{
		initialLease:         time.Second,
		renewedLease:         5 * time.Minute,
		recoveredLease:       5 * time.Minute,
		leaseNotFoundAtRenew: 1,
		holdTLSHandshakeAt:   4,
		tlsHandshakeStarted:  handshakeStarted,
		tlsHandshakeRelease:  handshakeRelease,
	})
	defer relay.close()
	defer release()
	target, targetAddress := newTargetServer(t)
	defer target.Close()
	ctx, cancel := context.WithCancel(context.Background())
	stopped := false
	exposure, proxyDone := startTestProxy(t, ctx, newTestIdentity(t), []string{relay.url}, testRelayTimings(), targetAddress)
	defer func() {
		if !stopped {
			stopTestProxy(t, cancel, proxyDone)
		}
	}()

	_ = waitForReady(t, exposure, 1)
	select {
	case handshake := <-handshakeStarted:
		if handshake != 4 {
			t.Fatalf("held TLS handshake = %d, want 4", handshake)
		}
	case <-time.After(fakeRelayWait):
		t.Fatal("timed out waiting for stalled reverse TLS handshake")
	}
	relay.waitFor(t, "full registration after cancellation of stalled reverse open", func() bool {
		return relay.leaseNotFoundSent && relay.domainCount >= 2 && relay.challengeCount >= 2 && relay.registerCount >= 2
	})
	recoveredToken := relay.name + "-token-2"
	relay.waitForIdleToken(t, recoveredToken, reverseSessionSlots)
	release()

	if body := relay.requestThroughSession(t, recoveredToken, "tenant.localhost", "/after-stalled-open"); body != "target:/after-stalled-open" {
		t.Fatalf("recovered body = %q", body)
	}
	statuses := exposure.Relays()
	if len(statuses) != 1 || statuses[0].State != RelayReady || statuses[0].Err != nil {
		t.Fatalf("relay status after refresh = %+v, want ready without failure", statuses)
	}
	select {
	case status := <-exposure.Updates():
		if status.State == RelayFailed {
			t.Fatalf("canceled stalled slot emitted RelayFailed: %v", status.Err)
		}
	default:
	}

	stopTestProxy(t, cancel, proxyDone)
	stopped = true
	relay.waitFor(t, "recovered lease unregister", func() bool {
		return len(relay.unregisterTokens) == 1 && relay.unregisterTokens[0] == recoveredToken
	})
	relay.observeRemoteSessionClosures()
	relay.waitForNoSessions(t)
	relay.assertNoErrors(t)
}

func TestExposureStaleSignerRequestAcrossRenewalRecovers(t *testing.T) {
	signStarted := make(chan string, 1)
	signFinished := make(chan struct{}, 1)
	signRelease := make(chan struct{})
	var releaseSign sync.Once
	release := func() { releaseSign.Do(func() { close(signRelease) }) }

	relay := newFakeRelay(t, "stale-sign", fakeRelayOptions{
		initialLease:        time.Second,
		renewedLease:        5 * time.Minute,
		recoveredLease:      5 * time.Minute,
		signRequestStarted:  signStarted,
		signRequestRelease:  signRelease,
		signRequestFinished: signFinished,
	})
	defer relay.close()
	defer release()
	target, targetAddress := newTargetServer(t)
	defer target.Close()
	ctx, cancel := context.WithCancel(context.Background())
	stopped := false
	exposure, proxyDone := startTestProxy(t, ctx, newTestIdentity(t), []string{relay.url}, testRelayTimings(), targetAddress)
	defer func() {
		if !stopped {
			stopTestProxy(t, cancel, proxyDone)
		}
	}()

	_ = waitForReady(t, exposure, 1)
	originalToken := relay.name + "-token-1"
	relay.waitForIdleToken(t, originalToken, reverseSessionSlots)
	staleRequest := relay.startRequestThroughSession(t, originalToken, "tenant.localhost", "/stale")
	select {
	case token := <-signStarted:
		if token != originalToken {
			t.Fatalf("held signer token = %q, want old token %q", token, originalToken)
		}
	case <-time.After(fakeRelayWait):
		t.Fatal("timed out waiting for held old-token sign request")
	}
	relay.waitFor(t, "successful token renewal while sign is held", func() bool {
		return relay.renewCount >= 1 && relay.currentToken != originalToken
	})
	renewedToken := relay.currentAccessToken()
	release()

	select {
	case result := <-staleRequest:
		if result.err == nil {
			t.Fatalf("old-token request unexpectedly succeeded with body %q", result.body)
		}
	case <-time.After(fakeRelayWait):
		t.Fatal("old-token request did not fail after renewal")
	}
	select {
	case <-signFinished:
	case <-time.After(fakeRelayWait):
		t.Fatal("held sign handler did not finish after release")
	}

	relay.waitForIdleToken(t, renewedToken, 1)
	if body := relay.requestThroughSession(t, renewedToken, "tenant.localhost", "/after-stale"); body != "target:/after-stale" {
		t.Fatalf("new-token body = %q", body)
	}
	relay.waitFor(t, "new token signer call", func() bool {
		return exposureTestContainsString(relay.signTokens, renewedToken)
	})
	statuses := exposure.Relays()
	if len(statuses) != 1 || statuses[0].State != RelayReady || statuses[0].Err != nil {
		t.Fatalf("relay status after stale sign = %+v, want ready without failure", statuses)
	}
	select {
	case status := <-exposure.Updates():
		if status.State == RelayFailed {
			t.Fatalf("stale signer response emitted RelayFailed: %v", status.Err)
		}
	default:
	}

	stopTestProxy(t, cancel, proxyDone)
	stopped = true
	relay.waitFor(t, "renewed token unregister", func() bool {
		return len(relay.unregisterTokens) == 1 && relay.unregisterTokens[0] == renewedToken
	})
	relay.observeRemoteSessionClosures()
	relay.waitForNoSessions(t)
	relay.assertNoErrors(t)
}

func TestExposureCloseWaitsForBoundedSignerAndCleansUp(t *testing.T) {
	signStarted := make(chan string, 1)
	signFinished := make(chan struct{}, 1)
	signRelease := make(chan struct{})
	var releaseSign sync.Once
	release := func() { releaseSign.Do(func() { close(signRelease) }) }

	relay := newFakeRelay(t, "close-stalled-sign", fakeRelayOptions{
		signRequestStarted:  signStarted,
		signRequestRelease:  signRelease,
		signRequestFinished: signFinished,
	})
	defer relay.close()
	defer release()
	timings := testRelayTimings()
	timings.requestTimeout = 3 * time.Second
	timings.handshakeTimeout = 3 * time.Second
	exposure, err := exposeWithTimings(context.Background(), ExposeConfig{
		Relays:   []string{relay.url},
		Identity: newTestIdentity(t),
	}, timings)
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}

	_ = waitForReady(t, exposure, 1)
	token := relay.currentAccessToken()
	relay.waitForIdleToken(t, token, reverseSessionSlots)
	stalledRequest := relay.startRequestThroughSession(t, token, "tenant.localhost", "/never-forwarded")
	select {
	case heldToken := <-signStarted:
		if heldToken != token {
			t.Fatalf("held signer token = %q, want %q", heldToken, token)
		}
	case <-time.After(fakeRelayWait):
		t.Fatal("timed out waiting for stalled sign request")
	}
	relay.observeRemoteSessionClosures()

	closeDone := make(chan error, 1)
	go func() { closeDone <- exposure.Close() }()
	select {
	case err := <-closeDone:
		t.Fatalf("Exposure.Close returned before tracked signer completed: %v", err)
	case <-time.After(100 * time.Millisecond):
	}
	select {
	case <-signFinished:
		t.Fatal("sign handler finished before its deliberate hold was released")
	default:
	}
	relay.waitFor(t, "unregister during stalled signer shutdown", func() bool {
		return len(relay.unregisterTokens) == 1 && relay.unregisterTokens[0] == token
	})

	release()
	select {
	case <-signFinished:
	case <-time.After(fakeRelayWait):
		t.Fatal("tracked sign handler did not finish after release")
	}
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Exposure.Close: %v", err)
		}
	case <-time.After(fakeRelayWait):
		t.Fatal("Exposure.Close did not finish after tracked signer completed")
	}

	select {
	case result := <-stalledRequest:
		if result.err == nil {
			t.Fatalf("stalled request unexpectedly succeeded with body %q", result.body)
		}
	case <-time.After(fakeRelayWait):
		t.Fatal("tenant handshake remained blocked after Exposure.Close")
	}
	relay.waitForNoSessions(t)

	relay.assertNoErrors(t)
}

func TestExposureReregistrationRefreshesStoredPublicURL(t *testing.T) {
	const (
		initialSNIPort   = 1443
		recoveredSNIPort = 2443
	)
	relay := newFakeRelay(t, "public-url-refresh", fakeRelayOptions{
		initialLease:         150 * time.Millisecond,
		renewedLease:         150 * time.Millisecond,
		recoveredLease:       5 * time.Minute,
		leaseNotFoundAtRenew: 2,
		registrationSNIPorts: []int{initialSNIPort, recoveredSNIPort},
	})
	defer relay.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exposure, err := exposeWithTimings(ctx, ExposeConfig{
		Relays:   []string{relay.url},
		Identity: newTestIdentity(t),
	}, testRelayTimings())
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}
	closed := false
	defer func() {
		if !closed {
			_ = exposure.Close()
		}
	}()

	initialURL := "https://tenant.localhost:" + strconv.Itoa(initialSNIPort)
	ready := waitForReady(t, exposure, 1)
	if got := ready[relay.url].PublicURL; got != initialURL {
		t.Fatalf("initial ready PublicURL = %q, want %q", got, initialURL)
	}

	relay.waitFor(t, "full registration with changed SNI port", func() bool {
		return relay.leaseNotFoundSent && relay.domainCount >= 2 && relay.challengeCount >= 2 && relay.registerCount >= 2
	})
	recoveredToken := relay.name + "-token-2"
	relay.waitForIdleToken(t, recoveredToken, reverseSessionSlots)

	recoveredURL := "https://tenant.localhost:" + strconv.Itoa(recoveredSNIPort)
	statusTimer := time.NewTimer(fakeRelayWait)
	statusTicker := time.NewTicker(time.Millisecond)
	defer statusTimer.Stop()
	defer statusTicker.Stop()
	for {
		statuses := exposure.Relays()
		if len(statuses) != 1 {
			t.Fatalf("Relays length = %d, want 1", len(statuses))
		}
		if statuses[0].PublicURL == recoveredURL {
			break
		}
		select {
		case <-statusTicker.C:
		case <-statusTimer.C:
			t.Fatalf("Relays PublicURL = %q, want refreshed %q", statuses[0].PublicURL, recoveredURL)
		}
	}

	relay.closeOneIdleAndRejectReconnect(t)
	var failed RelayStatus
	additionalReady := 0
	failureTimer := time.NewTimer(fakeRelayWait)
	defer failureTimer.Stop()
	for failed.State != RelayFailed {
		select {
		case status, ok := <-exposure.Updates():
			if !ok {
				t.Fatal("updates closed before terminal relay failure")
			}
			if status.RelayURL != relay.url {
				continue
			}
			switch status.State {
			case RelayReady:
				additionalReady++
			case RelayFailed:
				failed = status
			}
		case <-failureTimer.C:
			t.Fatal("timed out waiting for terminal relay failure")
		}
	}
	if additionalReady != 0 {
		t.Fatalf("additional ready updates = %d, want 0", additionalReady)
	}
	if failed.PublicURL != recoveredURL {
		t.Fatalf("failed PublicURL = %q, want latest %q", failed.PublicURL, recoveredURL)
	}
	statuses := exposure.Relays()
	if len(statuses) != 1 || statuses[0].State != RelayFailed || statuses[0].PublicURL != recoveredURL {
		t.Fatalf("final Relays = %+v, want failed status with PublicURL %q", statuses, recoveredURL)
	}

	if err := exposure.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	closed = true
	relay.observeRemoteSessionClosures()
	relay.waitForNoSessions(t)
	relay.assertNoErrors(t)
}

func exposureTestContainsString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

func TestExposureRejectsMismatchedTenantSigner(t *testing.T) {
	relay := newFakeRelay(t, "invalid-signer", fakeRelayOptions{invalidSigner: true})
	defer relay.close()
	ctx, cancel := context.WithTimeout(context.Background(), fakeRelayWait)
	defer cancel()
	exposure, err := exposeWithTimings(ctx, ExposeConfig{
		Relays:   []string{relay.url},
		Identity: newTestIdentity(t),
	}, testRelayTimings())
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}
	defer exposure.Close()

	if _, err := exposure.WaitReady(ctx); !errors.Is(err, ErrNoRelays) {
		t.Fatalf("WaitReady error = %v, want ErrNoRelays", err)
	}
	statuses := exposure.Relays()
	if len(statuses) != 1 || statuses[0].State != RelayFailed {
		t.Fatalf("relay statuses = %+v, want one failed relay", statuses)
	}
	if statuses[0].Err == nil || !strings.Contains(statuses[0].Err.Error(), "does not match relay certificate") {
		t.Fatalf("relay failure = %v, want signer mismatch", statuses[0].Err)
	}
	relay.waitFor(t, "invalid signer lease unregister", func() bool {
		return len(relay.unregisterTokens) == 1
	})
}

func TestExposureWaitReadyDoesNotConsumeUpdates(t *testing.T) {
	relay := newFakeRelay(t, "wait-ready", fakeRelayOptions{})
	defer relay.close()
	ctx, cancel := context.WithTimeout(context.Background(), fakeRelayWait)
	defer cancel()
	exposure, err := exposeWithTimings(ctx, ExposeConfig{
		Relays:   []string{relay.url},
		Identity: newTestIdentity(t),
	}, testRelayTimings())
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}
	defer exposure.Close()

	ready, err := exposure.WaitReady(ctx)
	if err != nil {
		t.Fatalf("WaitReady: %v", err)
	}
	if len(ready) != 1 || ready[0].RelayURL != relay.url || ready[0].State != RelayReady {
		t.Fatalf("WaitReady statuses = %+v", ready)
	}

	var updates []RelayStatus
	for len(updates) < 2 {
		select {
		case status := <-exposure.Updates():
			updates = append(updates, status)
		case <-ctx.Done():
			t.Fatalf("updates after WaitReady: %v", ctx.Err())
		}
	}
	if updates[0].State != RelayConnecting || updates[1].State != RelayReady {
		t.Fatalf("updates after WaitReady = %+v", updates)
	}
}
