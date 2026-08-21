package portalite

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strconv"
	"strings"
	"testing"

	"github.com/decred/dcrd/dcrec/secp256k1/v4/ecdsa"
	"golang.org/x/crypto/sha3"
)

const scalarOnePrivateKey = "0000000000000000000000000000000000000000000000000000000000000001"

const scalarOnePublicKey = "0279be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"

const scalarOneAddress = "0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf"

const fixedSIWEMessage = "localhost wants you to sign in with your Ethereum account:\n0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf\n\nAuthorize Portalite protocol 8.\n\nURI: https://localhost/sdk/register\nVersion: 1\nChain ID: 1\nNonce: exact-nonce-1234\nIssued At: 2026-08-21T00:00:00Z"

func TestIdentityScalarOneVectors(t *testing.T) {
	identity, err := IdentityFromPrivateKey("  Alice-1  ", scalarOnePrivateKey)
	if err != nil {
		t.Fatalf("IdentityFromPrivateKey: %v", err)
	}
	if got, want := identity.Name(), "alice-1"; got != want {
		t.Fatalf("Name() = %q, want %q", got, want)
	}
	if got := identity.PublicKey(); got != scalarOnePublicKey {
		t.Fatalf("PublicKey() = %q, want %q", got, scalarOnePublicKey)
	}
	if got := identity.Address(); got != scalarOneAddress {
		t.Fatalf("Address() = %q, want %q", got, scalarOneAddress)
	}

	persisted, err := json.Marshal(identity)
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}
	want := `{"name":"alice-1","address":"` + scalarOneAddress + `","public_key":"` + scalarOnePublicKey + `","private_key":"` + scalarOnePrivateKey + `"}`
	if string(persisted) != want {
		t.Fatalf("persisted identity = %s, want %s", persisted, want)
	}
}

func TestNormalizeEthereumAddress(t *testing.T) {
	valid := []string{
		scalarOneAddress,
		strings.TrimPrefix(scalarOneAddress, "0x"),
		strings.ToLower(scalarOneAddress),
		"0X" + strings.ToUpper(strings.TrimPrefix(scalarOneAddress, "0x")),
	}
	for _, address := range valid {
		got, err := normalizeEthereumAddress(address)
		if err != nil {
			t.Errorf("normalizeEthereumAddress(%q): %v", address, err)
			continue
		}
		if got != scalarOneAddress {
			t.Errorf("normalizeEthereumAddress(%q) = %q, want %q", address, got, scalarOneAddress)
		}
	}

	invalid := []string{
		"",
		"0x" + strings.Repeat("0", 39),
		"0x" + strings.Repeat("0", 41),
		"0x" + strings.Repeat("g", 40),
		"0x7e5F4552091A69125d5DfCb7b8C2659029395Bdf",
	}
	for _, address := range invalid {
		if got, err := normalizeEthereumAddress(address); err == nil {
			t.Errorf("normalizeEthereumAddress(%q) = %q, want error", address, got)
		}
	}
}

func TestIdentityFixedSIWECompactRecovery(t *testing.T) {
	identity, err := IdentityFromPrivateKey("alice", scalarOnePrivateKey)
	if err != nil {
		t.Fatalf("IdentityFromPrivateKey: %v", err)
	}
	signature, err := identity.signEthereumPersonalMessage(fixedSIWEMessage)
	if err != nil {
		t.Fatalf("signEthereumPersonalMessage: %v", err)
	}
	assertPersonalSignatureRecovers(t, fixedSIWEMessage, signature, scalarOnePublicKey)
}

func TestParseIdentityRejectsTamperingAndPreservesReceiver(t *testing.T) {
	original, err := IdentityFromPrivateKey("preserved", scalarOnePrivateKey)
	if err != nil {
		t.Fatalf("IdentityFromPrivateKey: %v", err)
	}
	before, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal original identity: %v", err)
	}

	tests := []struct {
		name    string
		payload string
	}{
		{
			name: "address",
			payload: `{"name":"attacker","address":"0x0000000000000000000000000000000000000000",` +
				`"public_key":"` + scalarOnePublicKey + `","private_key":"` + scalarOnePrivateKey + `"}`,
		},
		{
			name: "public key",
			payload: `{"name":"attacker","address":"` + scalarOneAddress + `",` +
				`"public_key":"020000000000000000000000000000000000000000000000000000000000000000",` +
				`"private_key":"` + scalarOnePrivateKey + `"}`,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := ParseIdentity([]byte(test.payload)); err == nil {
				t.Fatal("ParseIdentity accepted tampered persisted identity")
			}

			receiver := original
			if err := json.Unmarshal([]byte(test.payload), &receiver); err == nil {
				t.Fatal("UnmarshalJSON accepted tampered persisted identity")
			}
			after, err := json.Marshal(receiver)
			if err != nil {
				t.Fatalf("marshal receiver after rejected update: %v", err)
			}
			if !bytes.Equal(after, before) {
				t.Fatalf("receiver changed after rejected update: got %s, want %s", after, before)
			}
		})
	}
}

func TestParseIdentityPersistedCompatibilityBoundaries(t *testing.T) {
	upperPublicKey := "0X" + strings.ToUpper(scalarOnePublicKey)
	upperAddress := "0X" + strings.ToUpper(strings.TrimPrefix(scalarOneAddress, "0x"))
	payload := `{"name":"  ALICE  ","address":"` + upperAddress + `","public_key":"` + upperPublicKey + `",` +
		`"private_key":"0X` + scalarOnePrivateKey + `","derivation_path":"ignored","token_secret":"ignored","future":true}`
	identity, err := ParseIdentity([]byte(payload))
	if err != nil {
		t.Fatalf("ParseIdentity compatible private-key document: %v", err)
	}
	if identity.Name() != "alice" || identity.Address() != scalarOneAddress || identity.PublicKey() != scalarOnePublicKey {
		t.Fatalf("parsed identity = (%q, %q, %q)", identity.Name(), identity.Address(), identity.PublicKey())
	}

	if _, err := ParseIdentity([]byte(`{"name":"alice","mnemonic":"words only"}`)); err == nil || !strings.Contains(err.Error(), "mnemonic") {
		t.Fatalf("mnemonic-only ParseIdentity error = %v, want explicit unsupported-format error", err)
	}
	if _, err := ParseIdentity([]byte(`{"name":"alice"}`)); err == nil || !strings.Contains(err.Error(), "private_key") {
		t.Fatalf("missing-key ParseIdentity error = %v, want private_key error", err)
	}
}

func TestIdentityNameBoundaries(t *testing.T) {
	valid := []struct {
		input string
		want  string
	}{
		{"a", "a"},
		{"  A-B9  ", "a-b9"},
		{strings.Repeat("z", 63), strings.Repeat("z", 63)},
	}
	for _, test := range valid {
		identity, err := IdentityFromPrivateKey(test.input, scalarOnePrivateKey)
		if err != nil {
			t.Errorf("IdentityFromPrivateKey(%q): %v", test.input, err)
			continue
		}
		if identity.Name() != test.want {
			t.Errorf("IdentityFromPrivateKey(%q).Name() = %q, want %q", test.input, identity.Name(), test.want)
		}
	}

	invalid := []string{
		"", "   ", strings.Repeat("a", 64), "-alice", "alice-", "alice.example",
		"alice_example", "álîce", "alice/example", "alice example",
	}
	for _, name := range invalid {
		t.Run(fmt.Sprintf("%q", name), func(t *testing.T) {
			if _, err := IdentityFromPrivateKey(name, scalarOnePrivateKey); err == nil {
				t.Fatalf("IdentityFromPrivateKey accepted invalid name %q", name)
			}
		})
	}
}

func TestIdentityPrivateKeyBoundaries(t *testing.T) {
	const orderMinusOne = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364140"
	valid := []string{
		scalarOnePrivateKey,
		"0x" + scalarOnePrivateKey,
		"0X" + strings.ToUpper(orderMinusOne),
	}
	for _, privateKey := range valid {
		if _, err := IdentityFromPrivateKey("alice", privateKey); err != nil {
			t.Errorf("IdentityFromPrivateKey rejected valid scalar %q: %v", privateKey, err)
		}
	}

	const order = "fffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"
	invalid := []string{
		"", "1", strings.Repeat("0", 60) + "01", strings.Repeat("0", 65),
		strings.Repeat("0", 64), order, strings.Repeat("g", 64), "0x" + strings.Repeat("1", 63),
	}
	for _, privateKey := range invalid {
		t.Run(privateKey, func(t *testing.T) {
			if _, err := IdentityFromPrivateKey("alice", privateKey); err == nil {
				t.Fatalf("IdentityFromPrivateKey accepted invalid scalar %q", privateKey)
			}
		})
	}
}

func TestNormalizeTargetBoundaries(t *testing.T) {
	valid := []struct {
		input string
		want  string
	}{
		{"1", "127.0.0.1:1"},
		{" :65535 ", "127.0.0.1:65535"},
		{"localhost:080", "localhost:80"},
		{"example.com:443", "example.com:443"},
		{"127.0.0.1:3000", "127.0.0.1:3000"},
		{"[::1]:443", "[::1]:443"},
		{"[2001:0db8::1]:00080", "[2001:db8::1]:80"},
	}
	for _, test := range valid {
		got, err := NormalizeTarget(test.input)
		if err != nil {
			t.Errorf("NormalizeTarget(%q): %v", test.input, err)
			continue
		}
		if got != test.want {
			t.Errorf("NormalizeTarget(%q) = %q, want %q", test.input, got, test.want)
		}
	}

	invalid := []string{
		"", "0", "65536", ":0", ":65536", "localhost", "https://localhost:443",
		"localhost:443/path", "localhost:", "[::1]", "::1:443", "[]:443", "user@host:443",
	}
	for _, target := range invalid {
		t.Run(target, func(t *testing.T) {
			if _, err := NormalizeTarget(target); err == nil {
				t.Fatalf("NormalizeTarget accepted invalid target %q", target)
			}
		})
	}
}

func TestNormalizeRelaysBoundariesAndDeduplication(t *testing.T) {
	inputs := []string{
		" EXAMPLE.COM. ",
		"https://example.com:443/",
		"https://Second.Example:8443/relay",
		"second.example:8443",
	}
	got, err := NormalizeRelays(inputs)
	if err != nil {
		t.Fatalf("NormalizeRelays: %v", err)
	}
	want := []string{
		"https://example.com",
		"https://second.example:8443",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("NormalizeRelays() = %#v, want %#v", got, want)
	}

	invalid := [][]string{
		nil,
		{},
		{""},
		{"http://relay.example"},
		{"https://user@relay.example"},
		{"https://relay.example?x=1"},
		{"https://relay.example#fragment"},
		{"https://relay.example/other"},
		{"https://relay.example/relay/"},
		{"https://relay.example:0"},
		{"https://relay.example:65536"},
		{"https://relay_example"},
		{"https://rélais.example"},
		{"https://relay.example:"},
		{"https://[::1]"},
		{"https://[::1]:8443/relay"},
		{"https://[2001:0db8::1]:443/relay"},
		{"https://[::ffff:127.0.0.1]"},
	}
	for index, relays := range invalid {
		t.Run(strconv.Itoa(index), func(t *testing.T) {
			if _, err := NormalizeRelays(relays); err == nil {
				t.Fatalf("NormalizeRelays accepted invalid inputs %#v", relays)
			}
		})
	}
}

func TestDefaultRelaysOrderAndDefensiveCopy(t *testing.T) {
	want := []string{
		"https://gosunuts.xyz",
		"https://portal.thumbgo.kr",
		"https://portal.rabbitson87.dev",
		"https://s-h.day",
		"https://portal.dawnfullstack.com",
		"https://kakashit.org",
		"https://portal.damn.it.com",
	}
	first := DefaultRelays()
	if fmt.Sprint(first) != fmt.Sprint(want) {
		t.Fatalf("DefaultRelays() = %#v, want %#v", first, want)
	}
	first[0] = "https://mutated.invalid"
	second := DefaultRelays()
	if fmt.Sprint(second) != fmt.Sprint(want) {
		t.Fatalf("mutating returned defaults changed registry: %#v", second)
	}
}

func assertPersonalSignatureRecovers(t testing.TB, message, signature, wantPublicKey string) {
	t.Helper()
	if len(signature) != 132 || !strings.HasPrefix(signature, "0x") {
		t.Fatalf("signature = %q, want 0x followed by 65 bytes", signature)
	}
	wire, err := hex.DecodeString(signature[2:])
	if err != nil {
		t.Fatalf("decode signature: %v", err)
	}
	compact := make([]byte, 65)
	compact[0] = wire[64]
	copy(compact[1:], wire[:64])

	hasher := sha3.NewLegacyKeccak256()
	_, _ = io.WriteString(hasher, "\x19Ethereum Signed Message:\n"+strconv.Itoa(len(message)))
	_, _ = io.WriteString(hasher, message)
	publicKey, compressed, err := ecdsa.RecoverCompact(compact, hasher.Sum(nil))
	if err != nil {
		t.Fatalf("RecoverCompact: %v", err)
	}
	if compressed {
		t.Fatal("recoverable signature unexpectedly requests compressed-key encoding")
	}
	if got := hex.EncodeToString(publicKey.SerializeCompressed()); got != wantPublicKey {
		t.Fatalf("recovered public key = %q, want %q", got, wantPublicKey)
	}
}
