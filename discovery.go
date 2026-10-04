package portalite

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
)

const (
	pathDiscovery = "/discovery"

	// discoveryProtocolVersion is the version of the /discovery document
	// itself. It is independent of ProtocolVersion, which versions the
	// tenant tunnel: a relay can speak a current tunnel while publishing a
	// different discovery revision.
	discoveryProtocolVersion = "9"

	discoveryPollInterval = 30 * time.Second

	// defaultMaxActiveRelays caps how many relays an exposure supervises at
	// once when ExposeConfig.MaxActiveRelays is unset.
	defaultMaxActiveRelays = 8

	maxDiscoveryResponseBytes int64 = 1 << 20
)

// relayDescriptor is one relay advertisement from a /discovery document.
type relayDescriptor struct {
	Address           string    `json:"address"`
	Version           string    `json:"version"`
	IssuedAt          time.Time `json:"issued_at"`
	ExpiresAt         time.Time `json:"expires_at"`
	APIHTTPSAddr      string    `json:"api_https_addr"`
	IVNPDestination   string    `json:"ivnp_destination,omitempty"`
	SupportsUDP       bool      `json:"supports_udp,omitempty"`
	SupportsTCP       bool      `json:"supports_tcp,omitempty"`
	ActiveConnections int64     `json:"active_connections,omitempty"`
	TCPBPS            float64   `json:"tcp_bps,omitempty"`
	Signature         string    `json:"signature,omitempty"`
}

type incompatibleRelayEntry struct {
	URL             string    `json:"url"`
	ProtocolVersion string    `json:"protocol_version"`
	LastSeenAt      time.Time `json:"last_seen_at"`
}

type discoveryResponse struct {
	ProtocolVersion    string                   `json:"protocol_version"`
	GeneratedAt        time.Time                `json:"generated_at"`
	Relays             []relayDescriptor        `json:"relays"`
	IncompatibleRelays []incompatibleRelayEntry `json:"incompatible_relays,omitempty"`
}

// canonicalDescriptorBytes reproduces the relay's signing payload byte for
// byte. Field order, JSON names, and nanosecond timestamps must match, or
// verification fails on descriptors that are actually valid.
func canonicalDescriptorBytes(descriptor relayDescriptor) ([]byte, error) {
	canonical := struct {
		Address           string  `json:"address"`
		Version           string  `json:"version"`
		IssuedAtUnixNano  int64   `json:"issued_at_unix_nano"`
		ExpiresAtUnixNano int64   `json:"expires_at_unix_nano"`
		APIHTTPSAddr      string  `json:"api_https_addr"`
		SupportsUDP       bool    `json:"supports_udp"`
		SupportsTCP       bool    `json:"supports_tcp"`
		ActiveConnections int64   `json:"active_connections"`
		TCPBPS            float64 `json:"tcp_bps"`
		IVNPDestination   string  `json:"ivnp_destination,omitempty"`
	}{
		Address:           strings.TrimSpace(descriptor.Address),
		Version:           strings.TrimSpace(descriptor.Version),
		IssuedAtUnixNano:  descriptor.IssuedAt.UTC().UnixNano(),
		ExpiresAtUnixNano: descriptor.ExpiresAt.UTC().UnixNano(),
		APIHTTPSAddr:      strings.TrimSpace(descriptor.APIHTTPSAddr),
		SupportsUDP:       descriptor.SupportsUDP,
		SupportsTCP:       descriptor.SupportsTCP,
		ActiveConnections: descriptor.ActiveConnections,
		TCPBPS:            descriptor.TCPBPS,
		IVNPDestination:   strings.TrimSpace(descriptor.IVNPDestination),
	}
	return json.Marshal(canonical)
}

// verifyRelayDescriptor proves that the descriptor was signed by the key that
// derives its Address. The signature is recoverable, so no public key is
// needed out of band.
//
// This proves self-consistency only: a verified relay vouches for itself, not
// for the relays it lists. Never treat a relay's mention of another relay as
// evidence about that other relay.
func verifyRelayDescriptor(descriptor relayDescriptor, now time.Time) error {
	rawSignature := strings.TrimSpace(descriptor.Signature)
	if rawSignature == "" {
		return errors.New("relay descriptor is not signed")
	}
	compact, err := base64.StdEncoding.DecodeString(rawSignature)
	if err != nil {
		return fmt.Errorf("relay descriptor signature is not valid base64: %w", err)
	}
	if len(compact) != 65 {
		return fmt.Errorf("relay descriptor signature is %d bytes, want 65", len(compact))
	}
	address := strings.TrimSpace(descriptor.Address)
	if address == "" {
		return errors.New("relay descriptor has no address")
	}

	descriptor.Signature = ""
	canonical, err := canonicalDescriptorBytes(descriptor)
	if err != nil {
		return fmt.Errorf("canonicalize relay descriptor: %w", err)
	}
	digest := sha256.Sum256(canonical)
	publicKey, _, err := ecdsa.RecoverCompact(compact, digest[:])
	if err != nil {
		return fmt.Errorf("recover relay descriptor signer: %w", err)
	}
	if publicKey == nil {
		return errors.New("relay descriptor signature is invalid")
	}
	if derived := ethereumAddress(publicKey); !strings.EqualFold(derived, address) {
		return errors.New("relay descriptor address does not match its signing key")
	}
	if descriptor.ExpiresAt.IsZero() || !descriptor.ExpiresAt.After(now) {
		return errors.New("relay descriptor is expired")
	}
	if !descriptor.IssuedAt.IsZero() && descriptor.IssuedAt.After(now.Add(5*time.Minute)) {
		return errors.New("relay descriptor is issued in the future")
	}
	return nil
}

// discoveryCandidates holds the verified relays learned from /discovery.
type discoveryCandidates struct {
	mu      sync.Mutex
	relays  map[string]time.Time // relay URL -> descriptor expiry
	udpOnly map[string]bool      // relay URL -> advertises a UDP backhaul
	seen    map[string]struct{}  // relay URLs ever accepted, so a failure is not retried blindly
}

func newDiscoveryCandidates() *discoveryCandidates {
	return &discoveryCandidates{
		relays:  make(map[string]time.Time),
		udpOnly: make(map[string]bool),
		seen:    make(map[string]struct{}),
	}
}

// merge records verified relays, dropping entries whose freshness has lapsed.
func (c *discoveryCandidates) merge(now time.Time, entries map[string]discoveryCandidate) {
	c.mu.Lock()
	defer c.mu.Unlock()
	for rawURL, entry := range entries {
		if !entry.expiresAt.After(now) {
			delete(c.relays, rawURL)
			delete(c.udpOnly, rawURL)
			continue
		}
		c.relays[rawURL] = entry.expiresAt
		c.udpOnly[rawURL] = entry.supportsUDP
		c.seen[rawURL] = struct{}{}
	}
	for rawURL, expiresAt := range c.relays {
		if !expiresAt.After(now) {
			delete(c.relays, rawURL)
			delete(c.udpOnly, rawURL)
		}
	}
}

// known reports whether the relay URL was ever advertised by a verified
// descriptor, regardless of whether it is currently fresh.
func (c *discoveryCandidates) known(rawURL string) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, ok := c.seen[rawURL]
	return ok
}

// selectRelays returns fresh candidate URLs not already active, sorted for
// deterministic behavior, filtered to relays advertising a UDP backhaul when
// the exposure requires one.
func (c *discoveryCandidates) selectRelays(now time.Time, active map[string]struct{}, requireUDP bool) []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	selected := make([]string, 0, len(c.relays))
	for rawURL, expiresAt := range c.relays {
		if !expiresAt.After(now) {
			continue
		}
		if _, isActive := active[rawURL]; isActive {
			continue
		}
		if requireUDP && !c.udpOnly[rawURL] {
			continue
		}
		selected = append(selected, rawURL)
	}
	sort.Strings(selected)
	return selected
}

type discoveryCandidate struct {
	expiresAt   time.Time
	supportsUDP bool
}

// discoveryClient fetches and verifies /discovery documents.
type discoveryClient struct {
	http *http.Client
}

func newDiscoveryClient(timeout time.Duration) *discoveryClient {
	transport := &http.Transport{
		Proxy:               http.ProxyFromEnvironment,
		ForceAttemptHTTP2:   false,
		TLSNextProto:        make(map[string]func(string, *tls.Conn) http.RoundTripper),
		TLSHandshakeTimeout: timeout,
	}
	return &discoveryClient{http: &http.Client{Transport: transport, Timeout: timeout}}
}

func (c *discoveryClient) close() {
	if c == nil || c.http == nil {
		return
	}
	if transport, ok := c.http.Transport.(*http.Transport); ok {
		transport.CloseIdleConnections()
	}
}

// fetch verifies one relay's discovery document and returns the relays it
// advertises. A relay that cannot be reached, answers with the wrong discovery
// revision, or serves unverifiable descriptors contributes nothing.
func (c *discoveryClient) fetch(ctx context.Context, relayURL string, now time.Time) (map[string]discoveryCandidate, error) {
	parsed, err := url.Parse(relayURL)
	if err != nil {
		return nil, fmt.Errorf("parse discovery relay URL: %w", err)
	}
	host := parsed.Hostname()
	if host == "" {
		return nil, errors.New("discovery relay URL has no hostname")
	}

	request, err := http.NewRequestWithContext(ctx, http.MethodGet, relayURL+pathDiscovery, nil)
	if err != nil {
		return nil, fmt.Errorf("build discovery request: %w", err)
	}
	request.Header.Set("Accept", "application/json")

	// A local development relay is trusted for discovery only when it is
	// loopback; every public relay is verified against system roots.
	client := c.http
	if isLocalRelayHostname(host) {
		local := *c.http
		local.Transport = &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			ForceAttemptHTTP2:   false,
			TLSNextProto:        make(map[string]func(string, *tls.Conn) http.RoundTripper),
			TLSHandshakeTimeout: c.http.Timeout,
			TLSClientConfig:     &tls.Config{MinVersion: tls.VersionTLS12, ServerName: host, InsecureSkipVerify: true}, //nolint:gosec
		}
		client = &local
		defer func() {
			if transport, ok := local.Transport.(*http.Transport); ok {
				transport.CloseIdleConnections()
			}
		}()
	}

	response, err := client.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch relay discovery: %w", err)
	}
	defer response.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(response.Body, maxDiscoveryResponseBytes+1))
	if err != nil {
		return nil, fmt.Errorf("read relay discovery: %w", err)
	}
	if int64(len(payload)) > maxDiscoveryResponseBytes {
		return nil, errors.New("relay discovery response exceeds limit")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		return nil, fmt.Errorf("relay discovery returned status %d", response.StatusCode)
	}

	var envelope struct {
		Data  json.RawMessage `json:"data,omitempty"`
		OK    bool            `json:"ok"`
		Error *apiErrorBody   `json:"error,omitempty"`
	}
	if err := json.Unmarshal(payload, &envelope); err != nil {
		return nil, fmt.Errorf("decode relay discovery envelope: %w", err)
	}
	if !envelope.OK || len(envelope.Data) == 0 {
		return nil, errors.New("relay discovery response is not a successful envelope")
	}
	var document discoveryResponse
	if err := json.Unmarshal(envelope.Data, &document); err != nil {
		return nil, fmt.Errorf("decode relay discovery document: %w", err)
	}
	if strings.TrimSpace(document.ProtocolVersion) != discoveryProtocolVersion {
		return nil, fmt.Errorf("relay discovery protocol %q is unsupported", document.ProtocolVersion)
	}

	candidates := make(map[string]discoveryCandidate, len(document.Relays))
	for _, descriptor := range document.Relays {
		if err := verifyRelayDescriptor(descriptor, now); err != nil {
			continue
		}
		candidateURL, err := normalizeRelay(descriptor.APIHTTPSAddr)
		if err != nil {
			continue
		}
		candidates[candidateURL] = discoveryCandidate{
			expiresAt:   descriptor.ExpiresAt,
			supportsUDP: descriptor.SupportsUDP,
		}
	}
	if len(candidates) == 0 {
		return nil, errors.New("relay discovery advertised no verifiable relays")
	}
	return candidates, nil
}

// discoverySeeds returns the relay URLs a discovery refresh should poll.
func discoverySeeds(active map[string]struct{}) []string {
	seeds := make([]string, 0, len(active))
	for rawURL := range active {
		seeds = append(seeds, rawURL)
	}
	sort.Strings(seeds)
	return seeds
}
