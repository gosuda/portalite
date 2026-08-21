package portalite

import (
	"bufio"
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/gosuda/keyless_tls/keyless"
)

const reverseSessionSlots = 2

const maxReverseResponseHeadBytes int64 = 1 << 20

var tenantSignerProbeDigest = sha256.Sum256([]byte("portalite tenant signer probe"))

type relayTimings struct {
	leaseTTL         time.Duration
	renewBefore      time.Duration
	retryWait        time.Duration
	dialTimeout      time.Duration
	handshakeTimeout time.Duration
	requestTimeout   time.Duration
	idleTimeout      time.Duration
	shutdownTimeout  time.Duration
}

func defaultRelayTimings() relayTimings {
	return relayTimings{
		leaseTTL:         2 * time.Minute,
		renewBefore:      30 * time.Second,
		retryWait:        3 * time.Second,
		dialTimeout:      15 * time.Second,
		handshakeTimeout: 30 * time.Second,
		requestTimeout:   30 * time.Second,
		idleTimeout:      60 * time.Second,
		shutdownTimeout:  5 * time.Second,
	}
}

func (t relayTimings) withDefaults() relayTimings {
	d := defaultRelayTimings()
	if t.leaseTTL <= 0 {
		t.leaseTTL = d.leaseTTL
	}
	if t.renewBefore <= 0 {
		t.renewBefore = d.renewBefore
	}
	if t.retryWait <= 0 {
		t.retryWait = d.retryWait
	}
	if t.dialTimeout <= 0 {
		t.dialTimeout = d.dialTimeout
	}
	if t.handshakeTimeout <= 0 {
		t.handshakeTimeout = d.handshakeTimeout
	}
	if t.requestTimeout <= 0 {
		t.requestTimeout = d.requestTimeout
	}
	if t.idleTimeout <= 0 {
		t.idleTimeout = d.idleTimeout
	}
	if t.shutdownTimeout <= 0 {
		t.shutdownTimeout = d.shutdownTimeout
	}
	return t
}

func (t relayTimings) ttlSeconds() int {
	seconds := int((t.leaseTTL + time.Second - 1) / time.Second)
	if seconds < 1 {
		return 1
	}
	return seconds
}

type relayLease struct {
	token          string
	expiresAt      time.Time
	publicURL      string
	tlsConfig      *tls.Config
	signer         *keyless.RemoteSigner
	generation     uint64
	renewing       bool
	tokenUncertain bool
}

type relaySupervisor struct {
	relayURL       string
	authority      string
	hostname       string
	dialAddress    string
	publicHostname string
	identity       Identity
	timings        relayTimings

	controlTLS       *tls.Config
	certificateChain []byte
	controlTransport *http.Transport
	controlClient    *http.Client

	leaseMu             sync.RWMutex
	lease               relayLease
	nextLeaseGeneration uint64
	signerWG            sync.WaitGroup
}

type terminalRelayError struct{ err error }

func (e *terminalRelayError) Error() string { return e.err.Error() }
func (e *terminalRelayError) Unwrap() error { return e.err }

var errLeaseRefresh = errors.New("relay lease must be refreshed")

type malformedRelayResponseError struct{ err error }

var errControlResponseTooLarge = errors.New("relay control response body exceeds limit")

func (e *malformedRelayResponseError) Error() string { return e.err.Error() }
func (e *malformedRelayResponseError) Unwrap() error { return e.err }

var errReverseResponseHeadTooLarge = errors.New("reverse upgrade response head exceeds 1 MiB")

type reverseUpgradeError struct {
	token      string
	generation uint64
	err        error
}

func (e *reverseUpgradeError) Error() string { return e.err.Error() }
func (e *reverseUpgradeError) Unwrap() error { return e.err }

type tenantSignerError struct {
	err        error
	generation uint64
}

func (e *tenantSignerError) Error() string { return fmt.Sprintf("tenant TLS signer: %v", e.err) }
func (e *tenantSignerError) Unwrap() error { return e.err }

type signerResult struct {
	signature []byte
	err       error
}

type recordingSigner struct {
	ctx        context.Context
	signer     crypto.Signer
	inflight   *sync.WaitGroup
	generation uint64
	mu         sync.Mutex
	err        error
}

func (s *recordingSigner) Public() crypto.PublicKey { return s.signer.Public() }

func (s *recordingSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	digestCopy := append([]byte(nil), digest...)
	optsCopy := copySignerOpts(opts)
	result := make(chan signerResult, 1)
	s.inflight.Add(1)
	go func() {
		defer s.inflight.Done()
		signature, err := s.signer.Sign(nil, digestCopy, optsCopy)
		s.record(err)
		result <- signerResult{signature: signature, err: err}
	}()

	select {
	case completed := <-result:
		return completed.signature, completed.err
	case <-s.ctx.Done():
		return nil, s.ctx.Err()
	}
}

func copySignerOpts(opts crypto.SignerOpts) crypto.SignerOpts {
	if opts == nil {
		return nil
	}
	if pss, ok := opts.(*rsa.PSSOptions); ok {
		copy := *pss
		return &copy
	}
	return opts.HashFunc()
}

func (s *recordingSigner) record(err error) {
	if err == nil {
		return
	}
	s.mu.Lock()
	if s.err == nil {
		s.err = err
	}
	s.mu.Unlock()
}

func (s *recordingSigner) signingError() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.err
}

type reverseResponseHeadReader struct {
	reader    io.Reader
	remaining int64
	bounded   bool
}

func (r *reverseResponseHeadReader) Read(p []byte) (int, error) {
	if !r.bounded {
		return r.reader.Read(p)
	}
	if r.remaining == 0 {
		return 0, errReverseResponseHeadTooLarge
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	return n, err
}

func (r *reverseResponseHeadReader) disableBound() { r.bounded = false }

func newRelaySupervisor(relayURL string, identity Identity, timings relayTimings) (*relaySupervisor, error) {
	parsed, err := url.Parse(relayURL)
	if err != nil {
		return nil, fmt.Errorf("parse relay URL: %w", err)
	}
	if parsed.Host == "" || parsed.Hostname() == "" {
		return nil, errors.New("relay URL has no hostname")
	}

	port := parsed.Port()
	if port == "" {
		port = "443"
	}
	return &relaySupervisor{
		relayURL:    relayURL,
		authority:   parsed.Host,
		hostname:    parsed.Hostname(),
		dialAddress: net.JoinHostPort(parsed.Hostname(), port),
		identity:    identity,
		timings:     timings.withDefaults(),
	}, nil
}

// run owns the complete lifecycle of one relay. Its two results deliberately
// separate a terminal relay failure from best-effort shutdown failures.
func (s *relaySupervisor) run(ctx context.Context, ready func(string), offer func(context.Context, net.Conn) bool) (runErr, cleanupErr error) {
	defer func() {
		cleanupErr = s.shutdown()
	}()

	for {
		if err := ctx.Err(); err != nil {
			return err, nil
		}

		if err := s.initializeControl(ctx); err != nil {
			s.resetControl()
			if ctx.Err() != nil {
				return ctx.Err(), nil
			}
			if isTerminalRelayFailure(err) {
				return unwrapTerminalRelayError(err), nil
			}
			if !waitForRelayRetry(ctx, s.timings.retryWait) {
				return ctx.Err(), nil
			}
			continue
		}

		registered := false
		for !registered {
			if err := ctx.Err(); err != nil {
				return err, nil
			}
			err := s.registerLease(ctx)
			if err == nil {
				registered = true
				break
			}
			if ctx.Err() != nil {
				return ctx.Err(), nil
			}
			if isTerminalRelayFailure(err) {
				return unwrapTerminalRelayError(err), nil
			}
			if !waitForRelayRetry(ctx, s.timings.retryWait) {
				return ctx.Err(), nil
			}
		}

		err := s.runLease(ctx, ready, offer)
		if ctx.Err() != nil {
			return ctx.Err(), nil
		}
		if errors.Is(err, errLeaseRefresh) {
			s.discardLostLease()
			s.resetControl()
			continue
		}
		if isTerminalRelayFailure(err) {
			return unwrapTerminalRelayError(err), nil
		}
		if err != nil {
			return err, nil
		}
	}
}

func (s *relaySupervisor) initializeControl(ctx context.Context) error {
	tlsConfig, chain, leaf, err := s.bootstrapTLS(ctx)
	if err != nil {
		return classifyRelayError(err, false)
	}

	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		DialContext:         (&net.Dialer{Timeout: s.timings.dialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:   false,
		TLSClientConfig:     tlsConfig,
		TLSHandshakeTimeout: s.timings.handshakeTimeout,
		TLSNextProto:        make(map[string]func(string, *tls.Conn) http.RoundTripper),
	}
	client := &http.Client{
		Transport: transport,
		Timeout:   s.timings.requestTimeout,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	s.controlTLS = tlsConfig
	s.certificateChain = chain
	s.controlTransport = transport
	s.controlClient = client

	var domain domainResponse
	if err := s.doAPI(ctx, http.MethodGet, pathDomain, nil, &domain); err != nil {
		return classifyRelayError(err, false)
	}
	if domain.ProtocolVersion != ProtocolVersion {
		return terminalRelay(fmt.Errorf("unsupported relay protocol version %q (want %q)", domain.ProtocolVersion, ProtocolVersion))
	}

	s.publicHostname = s.identity.Name() + "." + s.hostname
	if err := leaf.VerifyHostname(s.publicHostname); err != nil {
		return terminalRelay(fmt.Errorf("relay certificate does not cover public hostname %q: %w", s.publicHostname, err))
	}
	return nil
}

func (s *relaySupervisor) bootstrapTLS(ctx context.Context) (*tls.Config, []byte, *x509.Certificate, error) {
	dialer := &net.Dialer{Timeout: s.timings.dialTimeout}
	raw, err := dialer.DialContext(ctx, "tcp", s.dialAddress)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("dial relay: %w", err)
	}
	defer raw.Close()

	local := isLocalRelayHostname(s.hostname)
	fetchConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: s.hostname,
		NextProtos: []string{"http/1.1"},
		// A local development relay is trusted only for this initial fetch;
		// its exact presented chain becomes the root set for every later call.
		InsecureSkipVerify: local, //nolint:gosec
	}
	conn := tls.Client(raw, fetchConfig)
	handshakeCtx, cancel := context.WithTimeout(ctx, s.timings.handshakeTimeout)
	err = conn.HandshakeContext(handshakeCtx)
	cancel()
	if err != nil {
		if isCertificateValidationError(err) {
			return nil, nil, nil, terminalRelay(fmt.Errorf("verify relay certificate: %w", err))
		}
		return nil, nil, nil, fmt.Errorf("TLS handshake with relay: %w", err)
	}

	peerCertificates := conn.ConnectionState().PeerCertificates
	if len(peerCertificates) == 0 {
		return nil, nil, nil, terminalRelay(errors.New("relay returned no certificates"))
	}
	var chain bytes.Buffer
	for _, certificate := range peerCertificates {
		if err := pem.Encode(&chain, &pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}); err != nil {
			return nil, nil, nil, terminalRelay(fmt.Errorf("encode relay certificate: %w", err))
		}
	}

	controlConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: s.hostname,
		NextProtos: []string{"http/1.1"},
	}
	if local {
		roots := x509.NewCertPool()
		if !roots.AppendCertsFromPEM(chain.Bytes()) {
			return nil, nil, nil, terminalRelay(errors.New("build local relay certificate pool"))
		}
		intermediates := x509.NewCertPool()
		for _, certificate := range peerCertificates[1:] {
			intermediates.AddCert(certificate)
		}
		if _, err := peerCertificates[0].Verify(x509.VerifyOptions{
			DNSName:       s.hostname,
			Roots:         roots,
			Intermediates: intermediates,
		}); err != nil {
			return nil, nil, nil, terminalRelay(fmt.Errorf("verify pinned local relay certificate: %w", err))
		}
		controlConfig.RootCAs = roots
	}

	return controlConfig, append([]byte(nil), chain.Bytes()...), peerCertificates[0], nil
}

func isLocalRelayHostname(hostname string) bool {
	if strings.EqualFold(strings.TrimSuffix(hostname, "."), "localhost") {
		return true
	}
	ip := net.ParseIP(hostname)
	return ip != nil && ip.IsLoopback()
}

func (s *relaySupervisor) registerLease(ctx context.Context) error {
	requestIdentity := identityRef{Name: s.identity.Name(), Address: s.identity.Address()}
	var challenge challengeResponse
	if err := s.doAPI(ctx, http.MethodPost, pathRegisterChallenge, challengeRequest{
		Identity: requestIdentity,
		TTL:      s.timings.ttlSeconds(),
	}, &challenge); err != nil {
		return classifyRelayError(err, false)
	}
	if strings.TrimSpace(challenge.ChallengeID) == "" {
		return terminalRelay(errors.New("register challenge has an empty challenge_id"))
	}
	if challenge.SIWEMessage == "" {
		return terminalRelay(errors.New("register challenge has an empty siwe_message"))
	}
	if !challenge.ExpiresAt.After(time.Now()) {
		return terminalRelay(errors.New("register challenge is expired"))
	}

	signature, err := s.identity.signEthereumPersonalMessage(challenge.SIWEMessage)
	if err != nil {
		return terminalRelay(fmt.Errorf("sign register challenge: %w", err))
	}

	var response registerResponse
	if err := s.doAPI(ctx, http.MethodPost, pathRegister, registerRequest{
		ChallengeID:   challenge.ChallengeID,
		SIWEMessage:   challenge.SIWEMessage,
		SIWESignature: signature,
	}, &response); err != nil {
		return classifyRelayError(err, false)
	}

	responseToken := strings.TrimSpace(response.AccessToken)
	invalid := func(err error) error {
		if responseToken != "" {
			unregisterCtx, cancel := context.WithTimeout(context.Background(), s.timings.shutdownTimeout)
			unregisterErr := s.unregisterToken(unregisterCtx, responseToken)
			cancel()
			if unregisterErr != nil {
				err = errors.Join(err, fmt.Errorf("unregister invalid lease: %w", unregisterErr))
			}
		}
		return terminalRelay(err)
	}
	if responseToken == "" {
		return invalid(errors.New("register response has an empty access_token"))
	}
	if !response.ExpiresAt.After(time.Now()) {
		return invalid(errors.New("register response lease is expired"))
	}
	if response.SNIPort < 0 || response.SNIPort > 65535 {
		return invalid(fmt.Errorf("register response has invalid sni_port %d", response.SNIPort))
	}
	responseName, err := normalizeIdentityName(response.Identity.Name)
	if err != nil {
		return invalid(fmt.Errorf("register response has invalid identity name: %w", err))
	}
	responseAddress, err := normalizeEthereumAddress(response.Identity.Address)
	if err != nil {
		return invalid(fmt.Errorf("register response has invalid identity address: %w", err))
	}
	if responseName != requestIdentity.Name || responseAddress != requestIdentity.Address {
		return invalid(errors.New("register response identity does not match requested identity"))
	}

	publicURL := "https://" + s.publicHostname
	if response.SNIPort > 0 && response.SNIPort != 443 {
		publicURL = "https://" + net.JoinHostPort(s.publicHostname, fmt.Sprint(response.SNIPort))
	}

	signer, tlsConfig, err := s.buildTenantTLS(responseToken)
	if err == nil {
		err = verifyTenantSigner(signer)
	}
	if err != nil {
		if signer != nil {
			_ = signer.Close()
		}
		unregisterCtx, cancel := context.WithTimeout(context.Background(), s.timings.shutdownTimeout)
		unregisterErr := s.unregisterToken(unregisterCtx, responseToken)
		cancel()
		if unregisterErr != nil {
			err = errors.Join(err, fmt.Errorf("unregister unusable lease: %w", unregisterErr))
		}
		return terminalRelay(fmt.Errorf("configure tenant TLS: %w", err))
	}

	s.leaseMu.Lock()
	s.nextLeaseGeneration++
	s.lease = relayLease{
		token:      responseToken,
		expiresAt:  response.ExpiresAt,
		publicURL:  publicURL,
		tlsConfig:  tlsConfig,
		signer:     signer,
		generation: s.nextLeaseGeneration,
	}
	s.leaseMu.Unlock()
	return nil
}

func (s *relaySupervisor) buildTenantTLS(initialToken string) (*keyless.RemoteSigner, *tls.Config, error) {
	signer, err := s.newRemoteSigner(func() http.Header {
		header := make(http.Header, 1)
		token := s.currentToken()
		if token == "" {
			token = initialToken
		}
		if token != "" {
			header.Set(accessTokenHeader, token)
		}
		return header
	})
	if err != nil {
		return nil, nil, err
	}

	tlsConfig, err := keyless.NewServerTLSConfig(keyless.ServerTLSConfig{
		CertPEM:    append([]byte(nil), s.certificateChain...),
		Signer:     signer,
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS12,
	})
	if err != nil {
		_ = signer.Close()
		return nil, nil, err
	}
	return signer, tlsConfig, nil
}

func verifyTenantSigner(signer crypto.Signer) error {
	if signer == nil {
		return errors.New("tenant TLS signer is nil")
	}
	signature, err := signer.Sign(rand.Reader, tenantSignerProbeDigest[:], crypto.SHA256)
	if err != nil {
		return fmt.Errorf("probe tenant TLS signer: %w", err)
	}
	switch publicKey := signer.Public().(type) {
	case *rsa.PublicKey:
		if err := rsa.VerifyPKCS1v15(publicKey, crypto.SHA256, tenantSignerProbeDigest[:], signature); err != nil {
			return fmt.Errorf("tenant TLS signer does not match relay certificate: %w", err)
		}
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(publicKey, tenantSignerProbeDigest[:], signature) {
			return errors.New("tenant TLS signer does not match relay certificate")
		}
	default:
		return fmt.Errorf("unsupported tenant TLS signer public key %T", signer.Public())
	}
	return nil
}

func (s *relaySupervisor) newRemoteSigner(headers func() http.Header) (*keyless.RemoteSigner, error) {
	return keyless.NewRemoteSigner(keyless.RemoteSignerConfig{
		Endpoint:   s.relayURL,
		ServerName: s.hostname,
		KeyID:      "relay-cert",
		RootCAPEM:  append([]byte(nil), s.certificateChain...),
		Timeout:    s.timings.requestTimeout,
		Headers:    headers,
	}, s.certificateChain)
}

func (s *relaySupervisor) runLease(ctx context.Context, ready func(string), offer func(context.Context, net.Conn) bool) error {
	leaseCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	results := make(chan error, reverseSessionSlots+1)
	var wg sync.WaitGroup
	var readyOnce sync.Once
	announceReady := func() {
		readyOnce.Do(func() { ready(s.currentPublicURL()) })
	}

	for range reverseSessionSlots {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results <- s.runReverseSlot(leaseCtx, announceReady, offer)
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		results <- s.runRenewLoop(leaseCtx)
	}()

	var firstResult error
	haveFirstResult := false
	select {
	case <-ctx.Done():
	case firstResult = <-results:
		haveFirstResult = true
	}
	cancel()
	wg.Wait()

	var workerResults [reverseSessionSlots + 1]error
	resultCount := 0
	if haveFirstResult {
		workerResults[0] = firstResult
		resultCount = 1
	}
	for resultCount < len(workerResults) {
		workerResults[resultCount] = <-results
		resultCount++
	}
	if err := ctx.Err(); err != nil {
		return err
	}

	var transient error
	refresh := false
	for _, result := range workerResults {
		if isTerminalRelayFailure(result) {
			return result
		}
		if errors.Is(result, errLeaseRefresh) {
			refresh = true
			continue
		}
		if result != nil && !errors.Is(result, context.Canceled) && transient == nil {
			transient = result
		}
	}
	if refresh {
		return errLeaseRefresh
	}
	if transient != nil {
		return transient
	}
	return context.Canceled
}

func (s *relaySupervisor) runReverseSlot(ctx context.Context, ready func(), offer func(context.Context, net.Conn) bool) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		conn, err := s.openReverseSession(ctx)
		if err != nil {
			if ctx.Err() != nil {
				return ctx.Err()
			}
			var upgradeErr *reverseUpgradeError
			if errors.As(err, &upgradeErr) && isLostLeaseError(err) &&
				s.reverseConnectRequestStale(upgradeErr.token, upgradeErr.generation) {
				if !waitForRelayRetry(ctx, s.timings.retryWait) {
					return ctx.Err()
				}
				continue
			}
			err = classifyRelayError(err, true)
			if errors.Is(err, errLeaseRefresh) || isTerminalRelayFailure(err) {
				return err
			}
			if !waitForRelayRetry(ctx, s.timings.retryWait) {
				return ctx.Err()
			}
			continue
		}

		ready()
		transferred, claimed, sessionErr := s.runReverseSession(ctx, conn, offer)
		if !transferred {
			_ = conn.Close()
		}
		if sessionErr == nil {
			continue
		}
		if ctx.Err() != nil {
			return ctx.Err()
		}
		var signerErr *tenantSignerError
		if claimed && !errors.As(sessionErr, &signerErr) {
			// A public client's TLS failure is not a relay failure and should be
			// replenished immediately rather than consuming the retry interval.
			continue
		}
		if signerErr != nil && s.signerGenerationStale(signerErr.generation) {
			// The request was pinned to a token that rotated while /v1/sign was
			// in flight. Replenish the slot instead of treating the old token's
			// response as a relay or signer failure.
			if !waitForRelayRetry(ctx, s.timings.retryWait) {
				return ctx.Err()
			}
			continue
		}
		sessionErr = classifyRelayError(sessionErr, true)
		if errors.Is(sessionErr, errLeaseRefresh) || isTerminalRelayFailure(sessionErr) {
			return sessionErr
		}
		if !waitForRelayRetry(ctx, s.timings.retryWait) {
			return ctx.Err()
		}
	}
}

func (s *relaySupervisor) openReverseSession(ctx context.Context) (net.Conn, error) {
	dialer := &net.Dialer{Timeout: s.timings.dialTimeout, KeepAlive: 30 * time.Second}
	raw, err := dialer.DialContext(ctx, "tcp", s.dialAddress)
	if err != nil {
		return nil, fmt.Errorf("dial reverse session: %w", err)
	}
	conn := tls.Client(raw, s.controlTLS.Clone())
	closeOnError := true
	defer func() {
		if closeOnError {
			_ = conn.Close()
		}
	}()
	stopContextClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer stopContextClose()

	handshakeCtx, cancel := context.WithTimeout(ctx, s.timings.handshakeTimeout)
	err = conn.HandshakeContext(handshakeCtx)
	cancel()
	if err != nil {
		return nil, fmt.Errorf("reverse TLS handshake: %w", err)
	}

	if err := conn.SetDeadline(time.Now().Add(s.timings.handshakeTimeout)); err != nil {
		return nil, fmt.Errorf("set reverse upgrade deadline: %w", err)
	}
	request := &http.Request{
		Method:     http.MethodGet,
		URL:        &url.URL{Scheme: "https", Host: s.authority, Path: pathConnect},
		Host:       s.authority,
		Proto:      "HTTP/1.1",
		ProtoMajor: 1,
		ProtoMinor: 1,
		Header:     make(http.Header),
	}
	request.Header.Set("Connection", "Upgrade")
	request.Header.Set("Upgrade", "raw")
	token, _, generation := s.currentTokenExpiryAndGeneration()
	if token == "" {
		return nil, errLeaseRefresh
	}
	request.Header.Set(accessTokenHeader, token)
	if err := request.Write(conn); err != nil {
		return nil, fmt.Errorf("write reverse upgrade request: %w", err)
	}

	headReader := &reverseResponseHeadReader{
		reader:    conn,
		remaining: maxReverseResponseHeadBytes,
		bounded:   true,
	}
	reader := bufio.NewReader(headReader)
	response, err := http.ReadResponse(reader, request)
	if err != nil {
		return nil, fmt.Errorf("read reverse upgrade response: %w", err)
	}
	headReader.disableBound()
	if response.StatusCode != http.StatusSwitchingProtocols {
		apiErr := decodeHTTPAPIError(response)
		return nil, &reverseUpgradeError{token: token, generation: generation, err: apiErr}
	}
	if response.Body != nil {
		_ = response.Body.Close()
	}
	if !headerHasToken(response.Header, "Connection", "upgrade") {
		return nil, terminalRelay(errors.New("reverse upgrade response is missing Connection: Upgrade"))
	}
	if !strings.EqualFold(strings.TrimSpace(response.Header.Get("Upgrade")), "raw") {
		return nil, terminalRelay(errors.New("reverse upgrade response is missing Upgrade: raw"))
	}
	if err := conn.SetDeadline(time.Time{}); err != nil {
		return nil, fmt.Errorf("clear reverse upgrade deadline: %w", err)
	}

	if !stopContextClose() && ctx.Err() != nil {
		return nil, ctx.Err()
	}
	closeOnError = false
	if reader.Buffered() != 0 {
		return &bufferedNetConn{Conn: conn, reader: reader}, nil
	}
	return conn, nil
}

func headerHasToken(header http.Header, name, token string) bool {
	for _, value := range header.Values(name) {
		for _, part := range strings.Split(value, ",") {
			if strings.EqualFold(strings.TrimSpace(part), token) {
				return true
			}
		}
	}
	return false
}

type bufferedNetConn struct {
	net.Conn
	reader *bufio.Reader
}

func (c *bufferedNetConn) Read(p []byte) (int, error) { return c.reader.Read(p) }

func (s *relaySupervisor) runReverseSession(ctx context.Context, conn net.Conn, offer func(context.Context, net.Conn) bool) (transferred, claimed bool, err error) {
	stopClose := context.AfterFunc(ctx, func() { _ = conn.Close() })
	defer func() {
		if !transferred {
			stopClose()
		}
	}()

	for {
		if err := conn.SetReadDeadline(time.Now().Add(s.timings.idleTimeout)); err != nil {
			return false, false, fmt.Errorf("set reverse marker deadline: %w", err)
		}
		var marker [1]byte
		if _, err := io.ReadFull(conn, marker[:]); err != nil {
			return false, false, fmt.Errorf("read reverse stream marker: %w", err)
		}
		switch marker[0] {
		case markerKeepalive:
			continue
		case markerRaw:
			return false, false, terminalRelay(errors.New("relay requested unsupported raw stream marker 0x01"))
		case markerTLS:
			if err := conn.SetDeadline(time.Time{}); err != nil {
				return false, true, fmt.Errorf("clear reverse marker deadline: %w", err)
			}
			handshakeCtx, cancel := context.WithTimeout(ctx, s.timings.handshakeTimeout)
			tlsConfig, sessionSigner, err := s.tenantTLSForSession(handshakeCtx)
			if err != nil {
				cancel()
				return false, true, err
			}
			tlsConn := tls.Server(conn, tlsConfig)
			err = tlsConn.HandshakeContext(handshakeCtx)
			cancel()
			if err != nil {
				if signerErr := sessionSigner.signingError(); signerErr != nil {
					return false, true, &tenantSignerError{
						err:        signerErr,
						generation: sessionSigner.generation,
					}
				}
				return false, true, fmt.Errorf("tenant TLS handshake: %w", err)
			}
			if !stopClose() && ctx.Err() != nil {
				_ = tlsConn.Close()
				return false, true, ctx.Err()
			}
			if !offer(ctx, tlsConn) {
				_ = tlsConn.Close()
				return false, true, ctx.Err()
			}
			return true, true, nil
		default:
			return false, false, terminalRelay(fmt.Errorf("relay sent unknown stream marker 0x%02x", marker[0]))
		}
	}
}

func (s *relaySupervisor) runRenewLoop(ctx context.Context) error {
	for {
		token, expiresAt, generation := s.currentTokenExpiryAndGeneration()
		if token == "" || !expiresAt.After(time.Now()) {
			return errLeaseRefresh
		}
		renewAt := expiresAt.Add(-s.timings.renewBefore)
		if delay := time.Until(renewAt); delay > 0 {
			if !waitForRelayRetry(ctx, delay) {
				return ctx.Err()
			}
		}

		if !s.beginRenewal(token, generation) {
			return errLeaseRefresh
		}
		var response renewResponse
		err := s.doAPI(ctx, http.MethodPost, pathRenew, renewRequest{
			AccessToken: token,
			TTL:         s.timings.ttlSeconds(),
		}, &response)
		if err != nil {
			s.endRenewal(generation)
			err = classifyRelayError(err, true)
			if errors.Is(err, errLeaseRefresh) || isTerminalRelayFailure(err) {
				return err
			}
			if !time.Now().Before(expiresAt) {
				return errLeaseRefresh
			}
			delay := s.timings.retryWait
			if remaining := time.Until(expiresAt); remaining < delay {
				delay = remaining
			}
			if delay <= 0 || !waitForRelayRetry(ctx, delay) {
				if ctx.Err() != nil {
					return ctx.Err()
				}
				return errLeaseRefresh
			}
			continue
		}

		newToken := strings.TrimSpace(response.AccessToken)
		if newToken == "" {
			return terminalRelay(errors.New("renew response has an empty access_token"))
		}
		if !response.ExpiresAt.After(time.Now()) {
			return terminalRelay(errors.New("renew response lease is expired"))
		}
		s.leaseMu.Lock()
		if s.lease.token != token || s.lease.generation != generation {
			s.leaseMu.Unlock()
			return errLeaseRefresh
		}
		s.nextLeaseGeneration++
		s.lease.token = newToken
		s.lease.expiresAt = response.ExpiresAt
		s.lease.renewing = false
		s.lease.tokenUncertain = false
		s.lease.generation = s.nextLeaseGeneration
		s.leaseMu.Unlock()
	}
}

func (s *relaySupervisor) doAPI(ctx context.Context, method, path string, body, output any) error {
	if s.controlClient == nil {
		return errors.New("relay control client is not initialized")
	}
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			return fmt.Errorf("encode relay request: %w", err)
		}
		requestBody = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(ctx, method, s.relayURL+path, requestBody)
	if err != nil {
		return fmt.Errorf("build relay request: %w", err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	request.Header.Set("Accept", "application/json")

	response, err := s.controlClient.Do(request)
	if err != nil {
		return fmt.Errorf("relay request: %w", err)
	}
	defer response.Body.Close()
	payload, err := readBoundedControlBody(response.Body)
	if err != nil {
		if response.StatusCode >= 200 && response.StatusCode < 300 {
			if errors.Is(err, errControlResponseTooLarge) {
				return &malformedRelayResponseError{err: err}
			}
			// A body read that did not complete is a transport failure, not a
			// completed malformed success response.
			return err
		}
		return &APIError{StatusCode: response.StatusCode}
	}

	var envelope apiEnvelope
	decodeErr := json.Unmarshal(payload, &envelope)
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		apiErr := &APIError{StatusCode: response.StatusCode}
		if decodeErr == nil && !envelope.OK && envelope.Error != nil {
			apiErr.Code = envelope.Error.Code
			apiErr.Message = envelope.Error.Message
		}
		return apiErr
	}
	if decodeErr != nil {
		return &malformedRelayResponseError{err: fmt.Errorf("decode successful relay response: %w", decodeErr)}
	}
	if !envelope.OK {
		apiErr := &APIError{StatusCode: response.StatusCode}
		if envelope.Error != nil {
			apiErr.Code = envelope.Error.Code
			apiErr.Message = envelope.Error.Message
		}
		return apiErr
	}
	if output != nil {
		if len(envelope.Data) == 0 || bytes.Equal(bytes.TrimSpace(envelope.Data), []byte("null")) {
			return &malformedRelayResponseError{err: errors.New("successful relay response has no data")}
		}
		if err := json.Unmarshal(envelope.Data, output); err != nil {
			return &malformedRelayResponseError{err: fmt.Errorf("decode successful relay data: %w", err)}
		}
	}
	return nil
}

func readBoundedControlBody(reader io.Reader) ([]byte, error) {
	payload, err := io.ReadAll(io.LimitReader(reader, maxControlResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read relay response: %w", err)
	}
	if int64(len(payload)) > maxControlResponseBytes {
		return nil, fmt.Errorf("%w: exceeds %d bytes", errControlResponseTooLarge, maxControlResponseBytes)
	}
	return payload, nil
}

func decodeHTTPAPIError(response *http.Response) error {
	defer response.Body.Close()
	payload, err := readBoundedControlBody(response.Body)
	apiErr := &APIError{StatusCode: response.StatusCode}
	if err != nil {
		return apiErr
	}
	var envelope apiEnvelope
	if json.Unmarshal(payload, &envelope) == nil && !envelope.OK && envelope.Error != nil {
		apiErr.Code = envelope.Error.Code
		apiErr.Message = envelope.Error.Message
	}
	return apiErr
}

func (s *relaySupervisor) unregisterToken(ctx context.Context, token string) error {
	if token == "" || s.controlClient == nil {
		return nil
	}
	return s.doAPI(ctx, http.MethodPost, pathUnregister, unregisterRequest{AccessToken: token}, nil)
}

func (s *relaySupervisor) shutdown() error {
	token := s.currentToken()
	var errs []error
	if token != "" {
		ctx, cancel := context.WithTimeout(context.Background(), s.timings.shutdownTimeout)
		if err := s.unregisterToken(ctx, token); err != nil {
			errs = append(errs, fmt.Errorf("unregister relay lease: %w", err))
		}
		cancel()
	}
	s.signerWG.Wait()
	if signer := s.clearLease(); signer != nil {
		if err := signer.Close(); err != nil {
			errs = append(errs, fmt.Errorf("close keyless signer: %w", err))
		}
	}
	s.resetControl()
	return errors.Join(errs...)
}

func (s *relaySupervisor) discardLostLease() {
	s.signerWG.Wait()
	if signer := s.clearLease(); signer != nil {
		_ = signer.Close()
	}
}

func (s *relaySupervisor) clearLease() *keyless.RemoteSigner {
	s.leaseMu.Lock()
	signer := s.lease.signer
	s.lease = relayLease{}
	s.leaseMu.Unlock()
	return signer
}

func (s *relaySupervisor) resetControl() {
	if s.controlTransport != nil {
		s.controlTransport.CloseIdleConnections()
	}
	s.controlClient = nil
	s.controlTransport = nil
	s.controlTLS = nil
	s.certificateChain = nil
	s.publicHostname = ""
}

func (s *relaySupervisor) currentToken() string {
	s.leaseMu.RLock()
	token := s.lease.token
	s.leaseMu.RUnlock()
	return token
}

func (s *relaySupervisor) currentTokenExpiryAndGeneration() (string, time.Time, uint64) {
	s.leaseMu.RLock()
	token, expiry, generation := s.lease.token, s.lease.expiresAt, s.lease.generation
	s.leaseMu.RUnlock()
	return token, expiry, generation
}

func (s *relaySupervisor) currentPublicURL() string {
	s.leaseMu.RLock()
	publicURL := s.lease.publicURL
	s.leaseMu.RUnlock()
	return publicURL
}

func (s *relaySupervisor) beginRenewal(token string, generation uint64) bool {
	s.leaseMu.Lock()
	defer s.leaseMu.Unlock()
	if s.lease.token != token || s.lease.generation != generation || s.lease.renewing {
		return false
	}
	s.lease.tokenUncertain = true
	s.lease.renewing = true
	return true
}

func (s *relaySupervisor) endRenewal(generation uint64) {
	s.leaseMu.Lock()
	if s.lease.generation == generation {
		s.lease.renewing = false
	}
	s.leaseMu.Unlock()
}

func (s *relaySupervisor) reverseConnectRequestStale(token string, generation uint64) bool {
	s.leaseMu.RLock()
	stale := s.lease.token != token || s.lease.generation != generation || s.lease.renewing
	s.leaseMu.RUnlock()
	return stale
}

func (s *relaySupervisor) signerGenerationStale(generation uint64) bool {
	s.leaseMu.RLock()
	stale := s.lease.generation != generation || s.lease.renewing || s.lease.tokenUncertain
	s.leaseMu.RUnlock()
	return stale
}

func (s *relaySupervisor) tenantTLSForSession(ctx context.Context) (*tls.Config, *recordingSigner, error) {
	s.leaseMu.RLock()
	base := s.lease.tlsConfig
	generation := s.lease.generation
	if base == nil || s.lease.token == "" {
		s.leaseMu.RUnlock()
		return nil, nil, errors.New("tenant TLS configuration is unavailable")
	}
	config := base.Clone()
	config.Certificates = append([]tls.Certificate(nil), base.Certificates...)
	s.leaseMu.RUnlock()

	if len(config.Certificates) == 0 {
		return nil, nil, errors.New("tenant TLS configuration has no certificate")
	}
	signer, ok := config.Certificates[0].PrivateKey.(crypto.Signer)
	if !ok || signer == nil {
		return nil, nil, errors.New("tenant TLS certificate has no crypto signer")
	}
	sessionSigner := &recordingSigner{
		ctx:        ctx,
		signer:     signer,
		inflight:   &s.signerWG,
		generation: generation,
	}
	config.Certificates[0].PrivateKey = sessionSigner
	return config, sessionSigner, nil
}

func classifyRelayError(err error, allowLeaseRefresh bool) error {
	if err == nil || isTerminalRelayFailure(err) || errors.Is(err, errLeaseRefresh) {
		return err
	}
	if allowLeaseRefresh && isLostLeaseError(err) {
		return errLeaseRefresh
	}
	var malformed *malformedRelayResponseError
	if errors.As(err, &malformed) {
		return terminalRelay(err)
	}
	if isCertificateValidationError(err) {
		return terminalRelay(err)
	}
	var apiErr *APIError
	if errors.As(err, &apiErr) {
		code := strings.ToLower(strings.TrimSpace(apiErr.Code))
		if apiErr.StatusCode == http.StatusHTTPVersionNotSupported || code == "http11_only" {
			return terminalRelay(err)
		}
		if apiErr.StatusCode >= 500 && apiErr.StatusCode != http.StatusHTTPVersionNotSupported {
			return err
		}
		return terminalRelay(err)
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return err
	}
	var networkError net.Error
	if errors.As(err, &networkError) {
		return err
	}
	return terminalRelay(err)
}

func isLostLeaseError(err error) bool {
	var apiErr *APIError
	if !errors.As(err, &apiErr) {
		return false
	}
	code := strings.ToLower(strings.TrimSpace(apiErr.Code))
	return code == "lease_not_found" || code == "unauthorized"
}

func isCertificateValidationError(err error) bool {
	var verificationError *tls.CertificateVerificationError
	if errors.As(err, &verificationError) {
		return true
	}
	var hostnameError x509.HostnameError
	if errors.As(err, &hostnameError) {
		return true
	}
	var authorityError x509.UnknownAuthorityError
	if errors.As(err, &authorityError) {
		return true
	}
	var invalidError x509.CertificateInvalidError
	return errors.As(err, &invalidError)
}

func terminalRelay(err error) error {
	if err == nil || isTerminalRelayFailure(err) {
		return err
	}
	return &terminalRelayError{err: err}
}

func isTerminalRelayFailure(err error) bool {
	var terminal *terminalRelayError
	return errors.As(err, &terminal)
}

func unwrapTerminalRelayError(err error) error {
	var terminal *terminalRelayError
	if errors.As(err, &terminal) {
		return terminal.err
	}
	return err
}

func waitForRelayRetry(ctx context.Context, delay time.Duration) bool {
	if delay <= 0 {
		return ctx.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}
