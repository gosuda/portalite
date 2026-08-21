package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"gosuda.org/portalite"
)

func TestRunHelpAndInvalidInvocation(t *testing.T) {
	t.Parallel()

	for _, args := range [][]string{{"--help"}, {"-h"}, {"expose", "--help"}, {"expose", "-h"}} {
		args := args
		t.Run(strings.Join(args, " "), func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if exit := run(context.Background(), args, &stdout, &stderr); exit != 0 {
				t.Fatalf("run(%q) exit = %d, want 0", args, exit)
			}
			if got := stdout.String(); got != usageLine {
				t.Fatalf("stdout = %q, want %q", got, usageLine)
			}
			if got := stderr.String(); got != "" {
				t.Fatalf("stderr = %q, want empty", got)
			}
		})
	}

	tests := []struct {
		name    string
		args    []string
		message string
	}{
		{name: "missing command", message: "missing command"},
		{name: "unknown command", args: []string{"serve"}, message: `unknown command "serve"`},
		{name: "missing target", args: []string{"expose"}, message: "missing TARGET"},
		{name: "extra target", args: []string{"expose", "8080", "9090"}, message: "expected exactly one TARGET"},
		{name: "invalid target", args: []string{"expose", "https://target.example"}, message: "target must be a TCP host and port, not a URL"},
		{name: "invalid relay", args: []string{"expose", "--relay", "http://relay.example", "8080"}, message: "relay 1: relay URL must use HTTPS"},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			var stdout, stderr bytes.Buffer
			if exit := run(context.Background(), test.args, &stdout, &stderr); exit != 2 {
				t.Fatalf("run(%q) exit = %d, want 2", test.args, exit)
			}
			if got := stdout.String(); got != "" {
				t.Fatalf("stdout = %q, want empty", got)
			}
			want := "portalite: " + test.message + "\n" + usageLine
			if got := stderr.String(); got != want {
				t.Fatalf("stderr = %q, want %q", got, want)
			}
		})
	}
}

func TestRunValidatesBeforeIdentityIO(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		args func(string) []string
	}{
		{
			name: "target",
			args: func(identity string) []string {
				return []string{"expose", "--identity", identity, "https://target.example"}
			},
		},
		{
			name: "relay",
			args: func(identity string) []string {
				return []string{"expose", "--identity", identity, "--relay", "http://relay.example", "8080"}
			},
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			parent := filepath.Join(t.TempDir(), "must-not-exist")
			identity := filepath.Join(parent, "identity.json")
			if exit := run(context.Background(), test.args(identity), io.Discard, io.Discard); exit != 2 {
				t.Fatalf("exit = %d, want 2", exit)
			}
			if _, err := os.Stat(parent); !os.IsNotExist(err) {
				t.Fatalf("identity parent was touched before validation: stat error = %v", err)
			}
		})
	}
}

func TestDefaultAndExplicitRelaySelection(t *testing.T) {
	t.Parallel()

	defaults, err := selectRelays(nil)
	if err != nil {
		t.Fatalf("select default relays: %v", err)
	}
	wantDefaults := []string{
		"https://rly.best",
		"https://portal.thumbgo.kr",
		"https://portal.rabbitson87.dev",
		"https://portal.dawnfullstack.com",
		"https://portal.damn.it.com",
		"https://s-h.day",
		"https://gosunuts.xyz",
	}
	if len(defaults) != len(wantDefaults) {
		t.Fatalf("default relay count = %d, want %d", len(defaults), len(wantDefaults))
	}
	for index := range wantDefaults {
		if defaults[index] != wantDefaults[index] {
			t.Fatalf("defaults[%d] = %q, want %q", index, defaults[index], wantDefaults[index])
		}
	}

	explicit, err := selectRelays([]string{
		"SECOND.EXAMPLE/relay",
		"https://first.example:443/",
		"https://second.example",
		"first.example",
	})
	if err != nil {
		t.Fatalf("select explicit relays: %v", err)
	}
	wantExplicit := []string{"https://second.example", "https://first.example"}
	if len(explicit) != len(wantExplicit) {
		t.Fatalf("explicit relay count = %d, want %d: %q", len(explicit), len(wantExplicit), explicit)
	}
	for index := range wantExplicit {
		if explicit[index] != wantExplicit[index] {
			t.Fatalf("explicit[%d] = %q, want %q", index, explicit[index], wantExplicit[index])
		}
	}
}

func TestRunIdentityCreationReuseAndNameConflict(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	identityDir := filepath.Join(root, "private", "nested")
	identityPath := filepath.Join(identityDir, "identity.json")
	args := []string{"expose", "--identity", identityPath, "--name", " Reused-Name ", "8080"}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	var stdout, stderr bytes.Buffer

	invalidIdentity := filepath.Join(root, "invalid", "identity.json")
	invalidArgs := []string{"expose", "--identity", invalidIdentity, "--name", "-invalid", "8080"}
	if exit := run(ctx, invalidArgs, &stdout, &stderr); exit != 2 {
		t.Fatalf("invalid name exit = %d, want 2", exit)
	}
	wantInvalid := "portalite: identity name must not begin or end with a hyphen\n" + usageLine
	if got := stderr.String(); got != wantInvalid {
		t.Fatalf("invalid name stderr = %q, want %q", got, wantInvalid)
	}
	if _, err := os.Stat(filepath.Dir(invalidIdentity)); !os.IsNotExist(err) {
		t.Fatalf("invalid name created identity directory: stat error = %v", err)
	}
	stdout.Reset()
	stderr.Reset()
	if exit := run(ctx, args, &stdout, &stderr); exit != 0 {
		t.Fatalf("create exit = %d, want 0; stderr = %q", exit, stderr.String())
	}
	if stdout.Len() != 0 || stderr.Len() != 0 {
		t.Fatalf("create output = stdout %q stderr %q, want empty", stdout.String(), stderr.String())
	}

	info, err := os.Stat(identityPath)
	if err != nil {
		t.Fatalf("stat identity: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("identity permissions = %#o, want 0600", got)
	}
	dirInfo, err := os.Stat(identityDir)
	if err != nil {
		t.Fatalf("stat identity directory: %v", err)
	}
	if got := dirInfo.Mode().Perm(); got != 0o700 {
		t.Fatalf("identity directory permissions = %#o, want 0700", got)
	}
	created, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatalf("read identity: %v", err)
	}
	identity, err := portalite.ParseIdentity(created)
	if err != nil {
		t.Fatalf("parse identity: %v", err)
	}
	if got := identity.Name(); got != "reused-name" {
		t.Fatalf("identity name = %q, want %q", got, "reused-name")
	}
	if len(created) == 0 || created[len(created)-1] != '\n' {
		t.Fatalf("persisted identity must end in one newline: %q", created)
	}

	stdout.Reset()
	stderr.Reset()
	if exit := run(ctx, args, &stdout, &stderr); exit != 0 {
		t.Fatalf("reuse exit = %d, want 0; stderr = %q", exit, stderr.String())
	}
	reused, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatalf("read reused identity: %v", err)
	}
	if !bytes.Equal(reused, created) {
		t.Fatal("reusing an identity changed its contents")
	}

	conflictArgs := []string{"expose", "--identity", identityPath, "--name", "other-name", "8080"}
	stdout.Reset()
	stderr.Reset()
	if exit := run(ctx, conflictArgs, &stdout, &stderr); exit != 2 {
		t.Fatalf("name conflict exit = %d, want 2", exit)
	}
	wantError := "portalite: identity name \"other-name\" does not match existing identity \"reused-name\"\n" + usageLine
	if got := stderr.String(); got != wantError {
		t.Fatalf("name conflict stderr = %q, want %q", got, wantError)
	}
	afterConflict, err := os.ReadFile(identityPath)
	if err != nil {
		t.Fatalf("read identity after conflict: %v", err)
	}
	if !bytes.Equal(afterConflict, created) {
		t.Fatal("name conflict changed the identity file")
	}
}

func TestRunIdentityGenerationFailureIsRuntimeError(t *testing.T) {
	t.Parallel()

	identityPath := filepath.Join(t.TempDir(), "missing", "identity.json")
	generationErr := errors.New("generate secp256k1 private key: random source failed")
	generatorCalled := false
	loadIdentity := func(path, requestedName string) (portalite.Identity, error) {
		return loadOrCreateIdentityWith(
			path,
			requestedName,
			func(name string) (portalite.Identity, error) {
				generatorCalled = true
				if name != "valid-name" {
					t.Fatalf("generator name = %q, want %q", name, "valid-name")
				}
				return portalite.Identity{}, generationErr
			},
			os.OpenFile,
		)
	}

	var stdout, stderr bytes.Buffer
	exit := runWithIdentityLoader(
		context.Background(),
		[]string{"expose", "--identity", identityPath, "--name", " Valid-Name ", "8080"},
		&stdout,
		&stderr,
		loadIdentity,
	)
	if exit != 1 {
		t.Fatalf("exit = %d, want 1", exit)
	}
	if !generatorCalled {
		t.Fatal("identity generator was not called")
	}
	if got := stdout.String(); got != "" {
		t.Fatalf("stdout = %q, want empty", got)
	}
	wantStderr := "portalite: " + generationErr.Error() + "\n"
	if got := stderr.String(); got != wantStderr {
		t.Fatalf("stderr = %q, want %q", got, wantStderr)
	}
	if strings.Contains(stderr.String(), usageLine) {
		t.Fatalf("runtime generation error included usage: %q", stderr.String())
	}
	if _, err := os.Stat(filepath.Dir(identityPath)); !os.IsNotExist(err) {
		t.Fatalf("generation failure touched identity directory: stat error = %v", err)
	}
}

func TestIdentityCreateRaceUsesWinner(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		requestedName string
		winnerName    string
		wantConflict  bool
	}{
		{
			name:          "compatible name",
			requestedName: " Race-Name ",
			winnerName:    "race-name",
		},
		{
			name:          "conflicting name",
			requestedName: "loser-name",
			winnerName:    "winner-name",
			wantConflict:  true,
		},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			identityPath := filepath.Join(t.TempDir(), "private", "identity.json")
			winner, err := portalite.IdentityFromPrivateKey(
				test.winnerName,
				"0000000000000000000000000000000000000000000000000000000000000002",
			)
			if err != nil {
				t.Fatalf("create winner identity: %v", err)
			}
			winnerData, err := winner.MarshalJSON()
			if err != nil {
				t.Fatalf("marshal winner identity: %v", err)
			}
			winnerData = append(winnerData, '\n')

			loserName, err := normalizeRequestedIdentityName(test.requestedName)
			if err != nil {
				t.Fatalf("normalize requested name: %v", err)
			}
			loser, err := portalite.IdentityFromPrivateKey(
				loserName,
				"0000000000000000000000000000000000000000000000000000000000000003",
			)
			if err != nil {
				t.Fatalf("create loser identity: %v", err)
			}

			openCalled := false
			openAsRaceLoser := func(name string, flag int, perm os.FileMode) (*os.File, error) {
				if openCalled {
					t.Fatal("identity opener called more than once")
				}
				openCalled = true
				file, openErr := os.OpenFile(name, flag, perm)
				if openErr != nil {
					return nil, openErr
				}
				if chmodErr := file.Chmod(0o600); chmodErr != nil {
					_ = file.Close()
					return nil, chmodErr
				}
				written, writeErr := file.Write(winnerData)
				if writeErr == nil && written != len(winnerData) {
					writeErr = io.ErrShortWrite
				}
				if closeErr := file.Close(); writeErr == nil {
					writeErr = closeErr
				}
				if writeErr != nil {
					return nil, writeErr
				}
				return nil, &os.PathError{Op: "open", Path: name, Err: os.ErrExist}
			}

			got, err := loadOrCreateIdentityWith(
				identityPath,
				test.requestedName,
				func(name string) (portalite.Identity, error) {
					if name != loserName {
						t.Fatalf("generated identity name = %q, want %q", name, loserName)
					}
					return loser, nil
				},
				openAsRaceLoser,
			)
			if !openCalled {
				t.Fatal("test did not exercise the O_EXCL EEXIST loser path")
			}
			if test.wantConflict {
				var usageErr *identityUsageError
				if !errors.As(err, &usageErr) {
					t.Fatalf("error = %v, want identity usage conflict", err)
				}
				want := `identity name "loser-name" does not match existing identity "winner-name"`
				if err.Error() != want {
					t.Fatalf("error = %q, want %q", err, want)
				}
			} else {
				if err != nil {
					t.Fatalf("loadOrCreateIdentityWith: %v", err)
				}
				if got.Address() != winner.Address() {
					t.Fatalf("returned address = %q, want winner %q", got.Address(), winner.Address())
				}
				if got.Address() == loser.Address() {
					t.Fatal("returned the losing generated identity")
				}
			}

			persisted, err := os.ReadFile(identityPath)
			if err != nil {
				t.Fatalf("read winner identity: %v", err)
			}
			if !bytes.Equal(persisted, winnerData) {
				t.Fatal("O_EXCL loser changed the winner identity file")
			}
			info, err := os.Stat(identityPath)
			if err != nil {
				t.Fatalf("stat winner identity: %v", err)
			}
			if got := info.Mode().Perm(); got != 0o600 {
				t.Fatalf("winner identity permissions = %#o, want 0600", got)
			}
		})
	}
}

func TestIdentityCreationPreservesPreexistingParentMode(t *testing.T) {
	t.Parallel()

	parent := filepath.Join(t.TempDir(), "preexisting")
	if err := os.Mkdir(parent, 0o750); err != nil {
		t.Fatalf("create identity parent: %v", err)
	}
	if err := os.Chmod(parent, 0o750); err != nil {
		t.Fatalf("set identity parent permissions: %v", err)
	}
	identityPath := filepath.Join(parent, "identity.json")
	if _, err := loadOrCreateIdentity(identityPath, "parent-mode"); err != nil {
		t.Fatalf("create identity: %v", err)
	}
	info, err := os.Stat(parent)
	if err != nil {
		t.Fatalf("stat identity parent: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o750 {
		t.Fatalf("pre-existing parent permissions = %#o, want unchanged 0750", got)
	}
}

func TestRunEndToEndTerminalRelayFailure(t *testing.T) {
	relay := newCLITestRelay(t)
	defer relay.Close()

	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/through-portalite" {
			http.Error(w, "wrong path", http.StatusNotFound)
			return
		}
		_, _ = io.WriteString(w, "local target reached")
	}))
	defer target.Close()
	targetAddress := strings.TrimPrefix(target.URL, "http://")

	identityPath := filepath.Join(t.TempDir(), "identity.json")
	args := []string{"expose", "--relay", relay.URL(), "--identity", identityPath, "--name", "runtime-test", targetAddress}
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run(context.Background(), args, &stdout, &stderr)
	}()

	body, err := relay.TenantRequest("runtime-test", "/through-portalite")
	if err != nil {
		t.Fatalf("tenant request: %v", err)
	}
	if body != "local target reached" {
		t.Fatalf("tenant response body = %q, want %q", body, "local target reached")
	}
	relay.ForceTerminalConnectFailure()

	if exit := waitRunExit(t, done); exit != 1 {
		t.Fatalf("run exit = %d, want 1", exit)
	}
	relay.AssertHealthy(t)
	if got := relay.UnregisterCount(); got != 1 {
		t.Fatalf("unregister count = %d, want 1", got)
	}
	wantStdout := "URL https://runtime-test.localhost:" + strconv.Itoa(relay.SNIPort()) + "\n"
	if got := stdout.String(); got != wantStdout {
		t.Fatalf("stdout = %q, want %q", got, wantStdout)
	}
	wantStderr := "portalite: relay " + relay.URL() + ": transport_mismatch: forced connect failure\n"
	if got := stderr.String(); got != wantStderr {
		t.Fatalf("stderr = %q, want %q", got, wantStderr)
	}
	if strings.Contains(stderr.String(), portalite.ErrNoRelays.Error()) {
		t.Fatalf("stderr repeats aggregate ErrNoRelays: %q", stderr.String())
	}
}

func TestRunCancelExitsZeroAndExplicitRelaysReplaceDefaults(t *testing.T) {
	relay := newCLITestRelay(t)
	defer relay.Close()
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "cancel target reached")
	}))
	defer target.Close()
	targetAddress := strings.TrimPrefix(target.URL, "http://")

	identityPath := filepath.Join(t.TempDir(), "identity.json")
	ctx, cancel := context.WithCancel(context.Background())
	args := []string{
		"expose",
		"--relay", relay.URL() + "/relay",
		"--relay", relay.URL() + "/",
		"--relay", relay.URL(),
		"--identity", identityPath,
		"--name", "cancel-test",
		targetAddress,
	}
	var stdout, stderr bytes.Buffer
	done := make(chan int, 1)
	go func() {
		done <- run(ctx, args, &stdout, &stderr)
	}()

	body, err := relay.TenantRequest("cancel-test", "/")
	if err != nil {
		t.Fatalf("tenant request before cancel: %v", err)
	}
	if body != "cancel target reached" {
		t.Fatalf("tenant response body = %q, want %q", body, "cancel target reached")
	}
	cancel()
	if exit := waitRunExit(t, done); exit != 0 {
		t.Fatalf("run exit = %d, want 0", exit)
	}
	relay.AssertHealthy(t)
	if got := relay.RegistrationCount(); got != 1 {
		t.Fatalf("registration count = %d, want 1; repeated explicit relays were not de-duplicated", got)
	}
	if got := relay.UnregisterCount(); got != 1 {
		t.Fatalf("unregister count = %d, want 1", got)
	}
	wantStdout := "URL https://cancel-test.localhost:" + strconv.Itoa(relay.SNIPort()) + "\n"
	if got := stdout.String(); got != wantStdout {
		t.Fatalf("stdout = %q, want %q", got, wantStdout)
	}
	if got := stderr.String(); got != "" {
		t.Fatalf("stderr = %q, want empty", got)
	}
}

func waitRunExit(t *testing.T, done <-chan int) int {
	t.Helper()
	select {
	case exit := <-done:
		return exit
	case <-time.After(15 * time.Second):
		t.Fatal("run did not exit")
		return -1
	}
}

type cliTestRelay struct {
	server  *httptest.Server
	url     string
	port    int
	key     *ecdsa.PrivateKey
	certPEM []byte

	mu              sync.Mutex
	identityName    string
	identityAddress string
	registrations   int
	unregisters     int
	failure         error
	failConnect     bool
	connections     map[net.Conn]struct{}
	connectReady    chan net.Conn
}

func newCLITestRelay(t *testing.T) *cliTestRelay {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate relay key: %v", err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	if err != nil {
		t.Fatalf("generate certificate serial: %v", err)
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "localhost"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              []string{"localhost", "*.localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create relay certificate: %v", err)
	}
	certificate := tls.Certificate{
		Certificate: [][]byte{der},
		PrivateKey:  key,
		Leaf:        template,
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	relay := &cliTestRelay{
		key:          key,
		certPEM:      certPEM,
		connections:  make(map[net.Conn]struct{}),
		connectReady: make(chan net.Conn, 32),
	}
	server := httptest.NewUnstartedServer(http.HandlerFunc(relay.handle))
	server.EnableHTTP2 = false
	server.TLS = &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"http/1.1"},
	}
	server.StartTLS()
	relay.server = server
	_, rawPort, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		server.Close()
		t.Fatalf("parse relay listener address: %v", err)
	}
	relay.port, err = strconv.Atoi(rawPort)
	if err != nil {
		server.Close()
		t.Fatalf("parse relay listener port: %v", err)
	}
	relay.url = "https://localhost:" + rawPort
	return relay
}

func (r *cliTestRelay) URL() string { return r.url }

func (r *cliTestRelay) SNIPort() int { return r.port }

func (r *cliTestRelay) Close() {
	r.mu.Lock()
	connections := make([]net.Conn, 0, len(r.connections))
	for connection := range r.connections {
		connections = append(connections, connection)
	}
	r.connections = make(map[net.Conn]struct{})
	r.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
	r.server.Close()
}

func (r *cliTestRelay) handle(w http.ResponseWriter, request *http.Request) {
	switch request.URL.Path {
	case "/sdk/domain":
		r.writeOK(w, map[string]any{"protocol_version": portalite.ProtocolVersion})
	case "/sdk/register/challenge":
		var input struct {
			Identity struct {
				Name    string `json:"name"`
				Address string `json:"address"`
			} `json:"identity"`
			TTL int `json:"ttl"`
		}
		if !r.decode(request, &input) {
			return
		}
		if input.Identity.Name == "" || input.Identity.Address == "" || input.TTL != 120 {
			r.recordFailure(fmt.Errorf("unexpected challenge request: %+v", input))
		}
		r.mu.Lock()
		r.identityName = input.Identity.Name
		r.identityAddress = input.Identity.Address
		r.mu.Unlock()
		r.writeOK(w, map[string]any{
			"challenge_id": "cli-test-challenge",
			"expires_at":   time.Now().Add(time.Minute),
			"siwe_message": "exact cli test SIWE message",
		})
	case "/sdk/register":
		var input struct {
			ChallengeID   string `json:"challenge_id"`
			SIWEMessage   string `json:"siwe_message"`
			SIWESignature string `json:"siwe_signature"`
		}
		if !r.decode(request, &input) {
			return
		}
		if input.ChallengeID != "cli-test-challenge" || input.SIWEMessage != "exact cli test SIWE message" || len(input.SIWESignature) != 132 || !strings.HasPrefix(input.SIWESignature, "0x") {
			r.recordFailure(fmt.Errorf("unexpected register request: %+v", input))
		}
		r.mu.Lock()
		r.registrations++
		name, address := r.identityName, r.identityAddress
		r.mu.Unlock()
		r.writeOK(w, map[string]any{
			"identity":     map[string]string{"name": name, "address": address},
			"expires_at":   time.Now().Add(5 * time.Minute),
			"access_token": "cli-test-token",
			"sni_port":     r.port,
		})
	case "/sdk/renew":
		var input struct {
			AccessToken string `json:"access_token"`
			TTL         int    `json:"ttl"`
		}
		if !r.decode(request, &input) {
			return
		}
		if input.AccessToken != "cli-test-token" || input.TTL != 120 {
			r.recordFailure(fmt.Errorf("unexpected renew request: %+v", input))
		}
		r.writeOK(w, map[string]any{"expires_at": time.Now().Add(5 * time.Minute), "access_token": "cli-test-token"})
	case "/sdk/unregister":
		var input struct {
			AccessToken string `json:"access_token"`
		}
		if !r.decode(request, &input) {
			return
		}
		if input.AccessToken != "cli-test-token" {
			r.recordFailure(fmt.Errorf("unexpected unregister token %q", input.AccessToken))
		}
		r.mu.Lock()
		r.unregisters++
		r.mu.Unlock()
		r.writeOK(w, struct{}{})
	case "/v1/sign":
		r.handleSign(w, request)
	case "/sdk/connect":
		r.handleConnect(w, request)
	default:
		r.recordFailure(fmt.Errorf("unexpected relay path %q", request.URL.Path))
		http.NotFound(w, request)
	}
}

func (r *cliTestRelay) decode(request *http.Request, output any) bool {
	defer request.Body.Close()
	if err := json.NewDecoder(request.Body).Decode(output); err != nil {
		r.recordFailure(fmt.Errorf("decode %s: %w", request.URL.Path, err))
		return false
	}
	return true
}

func (r *cliTestRelay) writeOK(w http.ResponseWriter, data any) {
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{"ok": true, "data": data}); err != nil {
		r.recordFailure(fmt.Errorf("write relay response: %w", err))
	}
}

func (r *cliTestRelay) handleSign(w http.ResponseWriter, request *http.Request) {
	if token := request.Header.Get("X-Portal-Access-Token"); token != "cli-test-token" {
		r.recordFailure(fmt.Errorf("sign token = %q", token))
	}
	var input struct {
		KeyID     string `json:"key_id"`
		Algorithm string `json:"algorithm"`
		Digest    []byte `json:"digest"`
	}
	if !r.decode(request, &input) {
		return
	}
	if input.KeyID != "relay-cert" || input.Algorithm != "ECDSA_SHA256" || len(input.Digest) != 32 {
		r.recordFailure(fmt.Errorf("unexpected sign request: key=%q algorithm=%q digest=%d bytes", input.KeyID, input.Algorithm, len(input.Digest)))
	}
	signature, err := ecdsa.SignASN1(rand.Reader, r.key, input.Digest)
	if err != nil {
		r.recordFailure(fmt.Errorf("sign digest: %w", err))
		http.Error(w, "signing failed", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := json.NewEncoder(w).Encode(map[string]any{
		"key_id":    input.KeyID,
		"algorithm": input.Algorithm,
		"signature": signature,
	}); err != nil {
		r.recordFailure(fmt.Errorf("write sign response: %w", err))
	}
}

func (r *cliTestRelay) handleConnect(w http.ResponseWriter, request *http.Request) {
	if token := request.Header.Get("X-Portal-Access-Token"); token != "cli-test-token" {
		r.recordFailure(fmt.Errorf("connect token = %q", token))
	}
	if !strings.EqualFold(request.Header.Get("Upgrade"), "raw") || !strings.Contains(strings.ToLower(request.Header.Get("Connection")), "upgrade") {
		r.recordFailure(fmt.Errorf("unexpected connect upgrade headers: %v", request.Header))
	}

	r.mu.Lock()
	fail := r.failConnect
	r.mu.Unlock()
	if fail {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusConflict)
		_ = json.NewEncoder(w).Encode(map[string]any{
			"ok": false,
			"error": map[string]string{
				"code":    "transport_mismatch",
				"message": "forced connect failure",
			},
		})
		return
	}

	hijacker, ok := w.(http.Hijacker)
	if !ok {
		r.recordFailure(fmt.Errorf("relay response writer does not support hijacking"))
		http.Error(w, "hijacking unsupported", http.StatusInternalServerError)
		return
	}
	connection, buffered, err := hijacker.Hijack()
	if err != nil {
		r.recordFailure(fmt.Errorf("hijack reverse connection: %w", err))
		return
	}
	if _, err := buffered.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: raw\r\n\r\n"); err != nil {
		r.recordFailure(fmt.Errorf("write reverse upgrade: %w", err))
		_ = connection.Close()
		return
	}
	if err := buffered.Flush(); err != nil {
		r.recordFailure(fmt.Errorf("flush reverse upgrade: %w", err))
		_ = connection.Close()
		return
	}

	r.mu.Lock()
	if r.failConnect {
		r.mu.Unlock()
		_ = connection.Close()
		return
	}
	r.connections[connection] = struct{}{}
	r.mu.Unlock()
	select {
	case r.connectReady <- connection:
	default:
		r.recordFailure(fmt.Errorf("reverse session notification buffer is full"))
		_ = connection.Close()
	}
}

func (r *cliTestRelay) WaitForReverseSession(t *testing.T) net.Conn {
	t.Helper()
	select {
	case connection := <-r.connectReady:
		return connection
	case <-time.After(10 * time.Second):
		t.Fatal("relay did not receive a reverse session")
		return nil
	}
}

func (r *cliTestRelay) TenantRequest(identityName, path string) (string, error) {
	connection := r.WaitForReverseSessionForRequest()
	if connection == nil {
		return "", fmt.Errorf("relay did not receive a reverse session")
	}
	r.mu.Lock()
	delete(r.connections, connection)
	r.mu.Unlock()

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(r.certPEM) {
		_ = connection.Close()
		return "", fmt.Errorf("append relay certificate")
	}
	if err := connection.SetDeadline(time.Now().Add(10 * time.Second)); err != nil {
		return "", fmt.Errorf("set tenant deadline: %w", err)
	}
	if _, err := connection.Write([]byte{0x02}); err != nil {
		return "", fmt.Errorf("write TLS marker: %w", err)
	}
	tenant := tls.Client(connection, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: identityName + ".localhost",
		RootCAs:    roots,
		NextProtos: []string{"http/1.1"},
	})
	defer tenant.Close()
	if err := tenant.Handshake(); err != nil {
		return "", fmt.Errorf("tenant TLS handshake: %w", err)
	}
	if _, err := fmt.Fprintf(tenant, "GET %s HTTP/1.1\r\nHost: local.test\r\nConnection: close\r\n\r\n", path); err != nil {
		return "", fmt.Errorf("write tenant request: %w", err)
	}
	response, err := http.ReadResponse(bufio.NewReader(tenant), nil)
	if err != nil {
		return "", fmt.Errorf("read tenant response: %w", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		return "", fmt.Errorf("read tenant body: %w", err)
	}
	if response.StatusCode != http.StatusOK {
		return "", fmt.Errorf("tenant response status %d: %s", response.StatusCode, body)
	}
	return string(body), nil
}

func (r *cliTestRelay) WaitForReverseSessionForRequest() net.Conn {
	select {
	case connection := <-r.connectReady:
		return connection
	case <-time.After(10 * time.Second):
		return nil
	}
}

func (r *cliTestRelay) ForceTerminalConnectFailure() {
	r.mu.Lock()
	r.failConnect = true
	connections := make([]net.Conn, 0, len(r.connections))
	for connection := range r.connections {
		connections = append(connections, connection)
	}
	r.connections = make(map[net.Conn]struct{})
	r.mu.Unlock()
	for _, connection := range connections {
		_ = connection.Close()
	}
}

func (r *cliTestRelay) RegistrationCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.registrations
}

func (r *cliTestRelay) UnregisterCount() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.unregisters
}

func (r *cliTestRelay) recordFailure(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failure == nil {
		r.failure = err
	}
}

func (r *cliTestRelay) AssertHealthy(t *testing.T) {
	t.Helper()
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.failure != nil {
		t.Fatalf("fake relay failure: %v", r.failure)
	}
}
