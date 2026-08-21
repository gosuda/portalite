package portalite

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestAPIErrorFormattingOrder(t *testing.T) {
	tests := []struct {
		name string
		err  *APIError
		want string
	}{
		{"nil", nil, ""},
		{"code and message", &APIError{StatusCode: 409, Code: " lease_not_found ", Message: " gone "}, "lease_not_found: gone"},
		{"code without message", &APIError{StatusCode: 409, Code: "unauthorized"}, "unauthorized: "},
		{"message without code", &APIError{StatusCode: 400, Message: " invalid request "}, "invalid request"},
		{"status only", &APIError{StatusCode: 503}, "api request failed with status 503"},
		{"empty", &APIError{}, "api request failed"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := test.err.Error(); got != test.want {
				t.Fatalf("Error() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestRelayDomainCompatibilityChecks(t *testing.T) {
	identity, err := IdentityFromPrivateKey("alice", scalarOnePrivateKey)
	if err != nil {
		t.Fatalf("IdentityFromPrivateKey: %v", err)
	}
	tests := []struct {
		name             string
		dnsNames         []string
		protocolVersion  string
		wantErrorContain string
	}{
		{
			name:             "protocol mismatch",
			dnsNames:         []string{"localhost", "alice.localhost"},
			protocolVersion:  "7",
			wantErrorContain: "unsupported relay protocol version",
		},
		{
			name:             "certificate misses public domain",
			dnsNames:         []string{"localhost"},
			protocolVersion:  ProtocolVersion,
			wantErrorContain: "does not cover public hostname",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			relay := newProtocolTestTLSServer(t, test.dnsNames, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet || r.URL.Path != pathDomain {
					t.Errorf("domain request = %s %s, want GET %s", r.Method, r.URL.Path, pathDomain)
					http.NotFound(w, r)
					return
				}
				protocolTestWriteOK(t, w, domainResponse{ProtocolVersion: test.protocolVersion})
			}))
			supervisor, err := newRelaySupervisor(relay.URL, identity, defaultRelayTimings())
			if err != nil {
				t.Fatalf("newRelaySupervisor: %v", err)
			}
			defer supervisor.resetControl()
			err = supervisor.initializeControl(context.Background())
			if err == nil || !strings.Contains(err.Error(), test.wantErrorContain) {
				t.Fatalf("initializeControl error = %v, want containing %q", err, test.wantErrorContain)
			}
			if !isTerminalRelayFailure(err) {
				t.Fatalf("initializeControl error %v is not terminal", err)
			}
		})
	}
}

func TestRegisterLeaseExactChallengeAndSIWEWireContract(t *testing.T) {
	identity, err := IdentityFromPrivateKey("alice", scalarOnePrivateKey)
	if err != nil {
		t.Fatalf("IdentityFromPrivateKey: %v", err)
	}
	challengeExpiry := time.Now().Add(5 * time.Minute).UTC()
	leaseExpiry := time.Now().Add(10 * time.Minute).UTC()

	var relay *protocolTestTLSServer
	relay = newProtocolTestTLSServer(t, []string{"localhost", "alice.localhost"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case pathDomain:
			if r.Method != http.MethodGet {
				t.Errorf("domain method = %s, want GET", r.Method)
			}
			protocolTestWriteOK(t, w, domainResponse{ProtocolVersion: ProtocolVersion})
		case pathRegisterChallenge:
			if r.Method != http.MethodPost {
				t.Errorf("challenge method = %s, want POST", r.Method)
			}
			body, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				t.Errorf("read challenge request: %v", readErr)
				return
			}
			want := `{"identity":{"name":"alice","address":"` + scalarOneAddress + `"},"ttl":120}`
			if string(body) != want {
				t.Errorf("challenge JSON = %s, want exact %s", body, want)
			}
			if got := r.Header.Get("Content-Type"); got != "application/json" {
				t.Errorf("challenge Content-Type = %q, want application/json", got)
			}
			if got := r.Header.Get(accessTokenHeader); got != "" {
				t.Errorf("challenge unexpectedly sent access token %q", got)
			}
			protocolTestWriteOK(t, w, challengeResponse{
				ChallengeID: "challenge-1",
				ExpiresAt:   challengeExpiry,
				SIWEMessage: fixedSIWEMessage,
			})
		case pathRegister:
			if r.Method != http.MethodPost {
				t.Errorf("register method = %s, want POST", r.Method)
			}
			body, readErr := io.ReadAll(r.Body)
			if readErr != nil {
				t.Errorf("read register request: %v", readErr)
				return
			}
			var request registerRequest
			if decodeErr := json.Unmarshal(body, &request); decodeErr != nil {
				t.Errorf("decode register request: %v", decodeErr)
				return
			}
			var fields map[string]json.RawMessage
			if decodeErr := json.Unmarshal(body, &fields); decodeErr != nil {
				t.Errorf("decode register fields: %v", decodeErr)
				return
			}
			if len(fields) != 3 || fields["challenge_id"] == nil || fields["siwe_message"] == nil || fields["siwe_signature"] == nil {
				t.Errorf("register fields = %v, want exactly challenge_id, siwe_message, siwe_signature", fields)
			}
			if request.ChallengeID != "challenge-1" {
				t.Errorf("register challenge_id = %q", request.ChallengeID)
			}
			if request.SIWEMessage != fixedSIWEMessage {
				t.Errorf("register changed exact SIWE message:\n%s", request.SIWEMessage)
			}
			assertPersonalSignatureRecovers(t, fixedSIWEMessage, request.SIWESignature, scalarOnePublicKey)
			encodedMessage, _ := json.Marshal(fixedSIWEMessage)
			want := `{"challenge_id":"challenge-1","siwe_message":` + string(encodedMessage) + `,"siwe_signature":"` + request.SIWESignature + `"}`
			if string(body) != want {
				t.Errorf("register JSON = %s, want exact %s", body, want)
			}
			if got := r.Header.Get(accessTokenHeader); got != "" {
				t.Errorf("register unexpectedly sent access token %q", got)
			}
			protocolTestWriteOK(t, w, registerResponse{
				Identity:    identityRef{Name: " ALICE ", Address: strings.ToLower(scalarOneAddress)},
				ExpiresAt:   leaseExpiry,
				AccessToken: "lease-token",
				SNIPort:     8443,
			})
		case "/v1/sign":
			if got := r.Header.Get(accessTokenHeader); got != "lease-token" {
				t.Errorf("sign access token = %q, want lease-token", got)
			}
			var request struct {
				KeyID     string `json:"key_id"`
				Algorithm string `json:"algorithm"`
				Digest    []byte `json:"digest"`
			}
			if err := json.NewDecoder(r.Body).Decode(&request); err != nil {
				t.Errorf("decode sign request: %v", err)
				return
			}
			signature, err := ecdsa.SignASN1(rand.Reader, relay.Key, request.Digest)
			if err != nil {
				t.Errorf("sign probe digest: %v", err)
				return
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(map[string]any{
				"key_id":    request.KeyID,
				"algorithm": request.Algorithm,
				"signature": signature,
			})
		default:
			http.NotFound(w, r)
		}
	}))

	supervisor, err := newRelaySupervisor(relay.URL, identity, defaultRelayTimings())
	if err != nil {
		t.Fatalf("newRelaySupervisor: %v", err)
	}
	defer supervisor.resetControl()
	if err := supervisor.initializeControl(context.Background()); err != nil {
		t.Fatalf("initializeControl: %v", err)
	}
	if err := supervisor.registerLease(context.Background()); err != nil {
		t.Fatalf("registerLease: %v", err)
	}
	if got := supervisor.currentToken(); got != "lease-token" {
		t.Fatalf("currentToken() = %q, want lease-token", got)
	}
	if got := supervisor.currentPublicURL(); got != "https://alice.localhost:8443" {
		t.Fatalf("currentPublicURL() = %q, want https://alice.localhost:8443", got)
	}
	if signer := supervisor.clearLease(); signer != nil {
		_ = signer.Close()
	}
}

func TestControlEnvelopeErrorsPreserveStatusCodeAndDetails(t *testing.T) {
	relay := newProtocolTestTLSServer(t, []string{"localhost"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/non-2xx-envelope":
			w.WriteHeader(http.StatusConflict)
			_, _ = io.WriteString(w, `{"ok":false,"error":{"code":"lease_not_found","message":"lease expired"}}`)
		case "/two-hundred-envelope-error":
			w.WriteHeader(http.StatusOK)
			_, _ = io.WriteString(w, `{"ok":false,"error":{"code":"unauthorized","message":"bad signature"}}`)
		case "/malformed-non-2xx":
			w.WriteHeader(http.StatusBadGateway)
			_, _ = io.WriteString(w, `not-json`)
		default:
			http.NotFound(w, r)
		}
	}))
	supervisor := &relaySupervisor{relayURL: relay.URL, controlClient: relay.Server.Client()}

	tests := []struct {
		path    string
		status  int
		code    string
		message string
		text    string
	}{
		{"/non-2xx-envelope", http.StatusConflict, "lease_not_found", "lease expired", "lease_not_found: lease expired"},
		{"/two-hundred-envelope-error", http.StatusOK, "unauthorized", "bad signature", "unauthorized: bad signature"},
		{"/malformed-non-2xx", http.StatusBadGateway, "", "", "api request failed with status 502"},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			err := supervisor.doAPI(context.Background(), http.MethodGet, test.path, nil, nil)
			var apiErr *APIError
			if !errors.As(err, &apiErr) {
				t.Fatalf("doAPI error = %T %v, want *APIError", err, err)
			}
			if apiErr.StatusCode != test.status || apiErr.Code != test.code || apiErr.Message != test.message {
				t.Fatalf("APIError = %#v, want status=%d code=%q message=%q", apiErr, test.status, test.code, test.message)
			}
			if err.Error() != test.text {
				t.Fatalf("error text = %q, want %q", err.Error(), test.text)
			}
		})
	}
}

func TestControlSuccessBodyReadFailuresPreserveRetryabilityBoundary(t *testing.T) {
	t.Run("network timeout remains retryable", func(t *testing.T) {
		supervisor := &relaySupervisor{
			relayURL: "https://relay.invalid",
			controlClient: &http.Client{Transport: protocolRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(&protocolTimeoutReader{}),
					Header:     make(http.Header),
				}, nil
			})},
		}

		err := supervisor.doAPI(context.Background(), http.MethodGet, "/timeout", nil, nil)
		if err == nil {
			t.Fatal("doAPI returned nil, want body read timeout")
		}
		var malformed *malformedRelayResponseError
		if errors.As(err, &malformed) {
			t.Fatalf("doAPI error = %T %v, must not classify an incomplete body as malformed", err, err)
		}
		var networkError net.Error
		if !errors.As(err, &networkError) || !networkError.Timeout() {
			t.Fatalf("doAPI error = %T %v, want preserved net timeout", err, err)
		}
		if classified := classifyRelayError(err, false); isTerminalRelayFailure(classified) {
			t.Fatalf("classifyRelayError(%v) = terminal %v, want retryable", err, classified)
		}
	})

	t.Run("completed oversized body is terminal", func(t *testing.T) {
		supervisor := &relaySupervisor{
			relayURL: "https://relay.invalid",
			controlClient: &http.Client{Transport: protocolRoundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{
					StatusCode: http.StatusOK,
					Body:       io.NopCloser(strings.NewReader(strings.Repeat("x", int(maxControlResponseBytes)+1))),
					Header:     make(http.Header),
				}, nil
			})},
		}

		err := supervisor.doAPI(context.Background(), http.MethodGet, "/oversized", nil, nil)
		var malformed *malformedRelayResponseError
		if !errors.As(err, &malformed) || !errors.Is(err, errControlResponseTooLarge) {
			t.Fatalf("doAPI error = %T %v, want oversized malformed response", err, err)
		}
		if classified := classifyRelayError(err, false); !isTerminalRelayFailure(classified) {
			t.Fatalf("classifyRelayError(%v) = %v, want terminal", err, classified)
		}
	})
}

func TestReverseUpgradeRequiresStrict101HeadersAndPreservesBufferedMarker(t *testing.T) {
	identity, err := IdentityFromPrivateKey("alice", scalarOnePrivateKey)
	if err != nil {
		t.Fatalf("IdentityFromPrivateKey: %v", err)
	}
	tests := []struct {
		name             string
		response         string
		bufferedMarker   *byte
		wantErrorContain string
	}{
		{
			name:           "valid tokenized connection and case insensitive upgrade",
			response:       "HTTP/1.1 101 Switching Protocols\r\nConnection: keep-alive, UpGrAdE\r\nUpgrade: RaW\r\n\r\n",
			bufferedMarker: protocolTestByte(markerTLS),
		},
		{
			name:             "status must be 101",
			response:         "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n",
			wantErrorContain: "status 200",
		},
		{
			name:             "connection header missing",
			response:         "HTTP/1.1 101 Switching Protocols\r\nUpgrade: raw\r\n\r\n",
			wantErrorContain: "Connection: Upgrade",
		},
		{
			name:             "connection token not substring",
			response:         "HTTP/1.1 101 Switching Protocols\r\nConnection: upgrader\r\nUpgrade: raw\r\n\r\n",
			wantErrorContain: "Connection: Upgrade",
		},
		{
			name:             "upgrade header must be raw",
			response:         "HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: websocket\r\n\r\n",
			wantErrorContain: "Upgrade: raw",
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var relay *protocolTestTLSServer
			relay = newProtocolTestTLSServer(t, []string{"localhost", "alice.localhost"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case pathDomain:
					protocolTestWriteOK(t, w, domainResponse{ProtocolVersion: ProtocolVersion})
				case pathConnect:
					if r.Method != http.MethodGet {
						t.Errorf("connect method = %s, want GET", r.Method)
					}
					if r.ProtoMajor != 1 || r.ProtoMinor != 1 {
						t.Errorf("connect protocol = %s, want HTTP/1.1", r.Proto)
					}
					if want := strings.TrimPrefix(relay.URL, "https://"); r.Host != want {
						t.Errorf("connect Host = %q, want %q", r.Host, want)
					}
					if !headerHasToken(r.Header, "Connection", "upgrade") || !strings.EqualFold(r.Header.Get("Upgrade"), "raw") {
						t.Errorf("connect upgrade headers = %v", r.Header)
					}
					if got := r.Header.Get(accessTokenHeader); got != "lease-token" {
						t.Errorf("connect access token = %q, want lease-token", got)
					}
					conn, readWriter, hijackErr := http.NewResponseController(w).Hijack()
					if hijackErr != nil {
						t.Errorf("hijack connect: %v", hijackErr)
						return
					}
					_, _ = readWriter.WriteString(test.response)
					if test.bufferedMarker != nil {
						_ = readWriter.WriteByte(*test.bufferedMarker)
					}
					if flushErr := readWriter.Flush(); flushErr != nil {
						t.Errorf("flush upgrade response: %v", flushErr)
						_ = conn.Close()
					}
				default:
					http.NotFound(w, r)
				}
			}))
			supervisor, err := newRelaySupervisor(relay.URL, identity, defaultRelayTimings())
			if err != nil {
				t.Fatalf("newRelaySupervisor: %v", err)
			}
			defer supervisor.resetControl()
			if err := supervisor.initializeControl(context.Background()); err != nil {
				t.Fatalf("initializeControl: %v", err)
			}
			supervisor.leaseMu.Lock()
			supervisor.lease.token = "lease-token"
			supervisor.leaseMu.Unlock()

			conn, err := supervisor.openReverseSession(context.Background())
			if test.wantErrorContain != "" {
				if err == nil || !strings.Contains(err.Error(), test.wantErrorContain) {
					if conn != nil {
						_ = conn.Close()
					}
					t.Fatalf("openReverseSession error = %v, want containing %q", err, test.wantErrorContain)
				}
				return
			}
			if err != nil {
				t.Fatalf("openReverseSession: %v", err)
			}
			defer conn.Close()
			var marker [1]byte
			if _, err := io.ReadFull(conn, marker[:]); err != nil {
				t.Fatalf("read response-buffered marker: %v", err)
			}
			if marker[0] != *test.bufferedMarker {
				t.Fatalf("buffered marker = 0x%02x, want 0x%02x", marker[0], *test.bufferedMarker)
			}
		})
	}
}

func TestReverseSessionMarkerBoundaries(t *testing.T) {
	tests := []struct {
		name             string
		markers          []byte
		wantErrorContain string
	}{
		{"raw unsupported", []byte{markerRaw}, "unsupported raw stream marker 0x01"},
		{"keepalive is skipped before raw", []byte{markerKeepalive, markerRaw}, "unsupported raw stream marker 0x01"},
		{"unknown rejected", []byte{0x7f}, "unknown stream marker 0x7f"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			client, relay := net.Pipe()
			defer client.Close()
			defer relay.Close()
			supervisor := &relaySupervisor{timings: relayTimings{idleTimeout: time.Second}}
			type result struct {
				transferred bool
				claimed     bool
				err         error
			}
			resultChannel := make(chan result, 1)
			go func() {
				transferred, claimed, err := supervisor.runReverseSession(context.Background(), client, func(context.Context, net.Conn) bool {
					t.Error("offer called for non-TLS marker")
					return false
				})
				resultChannel <- result{transferred: transferred, claimed: claimed, err: err}
			}()
			if _, err := relay.Write(test.markers); err != nil {
				t.Fatalf("write markers: %v", err)
			}
			outcome := <-resultChannel
			if outcome.transferred || outcome.claimed {
				t.Fatalf("runReverseSession returned transferred=%v claimed=%v", outcome.transferred, outcome.claimed)
			}
			if outcome.err == nil || !strings.Contains(outcome.err.Error(), test.wantErrorContain) {
				t.Fatalf("runReverseSession error = %v, want containing %q", outcome.err, test.wantErrorContain)
			}
			if !isTerminalRelayFailure(outcome.err) {
				t.Fatalf("marker error %v is not terminal", outcome.err)
			}
		})
	}
}

type protocolTestTLSServer struct {
	Server *httptest.Server
	URL    string
	Key    *ecdsa.PrivateKey
}

func newProtocolTestTLSServer(t testing.TB, dnsNames []string, handler http.Handler) *protocolTestTLSServer {
	t.Helper()
	certificate := protocolTestCertificate(t, dnsNames)
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
		Certificates: []tls.Certificate{certificate},
	}
	server.StartTLS()
	t.Cleanup(server.Close)
	_, port, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatalf("split fake relay address: %v", err)
	}
	key, ok := certificate.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("fake relay key type = %T", certificate.PrivateKey)
	}
	return &protocolTestTLSServer{Server: server, URL: "https://localhost:" + port, Key: key}
}

func protocolTestCertificate(t testing.TB, dnsNames []string) tls.Certificate {
	t.Helper()
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate fake relay key: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "portalite protocol test relay"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(time.Hour),
		DNSNames:              append([]string(nil), dnsNames...),
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		t.Fatalf("create fake relay certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse fake relay certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: privateKey, Leaf: leaf}
}

func protocolTestWriteOK(t testing.TB, w http.ResponseWriter, data any) {
	t.Helper()
	payload, err := json.Marshal(data)
	if err != nil {
		t.Fatalf("marshal fake relay data: %v", err)
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(apiEnvelope{OK: true, Data: payload}); err != nil {
		t.Errorf("write fake relay response: %v", err)
	}
}

func protocolTestByte(value byte) *byte {
	return &value
}

type protocolRoundTripFunc func(*http.Request) (*http.Response, error)

func (f protocolRoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

type protocolTimeoutReader struct {
	sentPartial bool
}

func (r *protocolTimeoutReader) Read(destination []byte) (int, error) {
	if !r.sentPartial {
		r.sentPartial = true
		return copy(destination, `{"ok":true`), nil
	}
	return 0, protocolTimeoutError{}
}

type protocolTimeoutError struct{}

func (protocolTimeoutError) Error() string   { return "relay body read timed out" }
func (protocolTimeoutError) Timeout() bool   { return true }
func (protocolTimeoutError) Temporary() bool { return true }
