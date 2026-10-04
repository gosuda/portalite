package portalite

import (
	"context"
	"encoding/base64"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/decred/dcrd/dcrec/secp256k1/v4"
)

// A descriptor is only usable when its signature recovers to its own address.
func TestVerifyRelayDescriptorRejectsTamperedAndStaleEntries(t *testing.T) {
	now := time.Now().UTC()
	key, err := secp256k1.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	valid := signDescriptorWithKey(t, key, "https://relay.example", now)
	if err := verifyRelayDescriptor(valid, now); err != nil {
		t.Fatalf("verify valid descriptor: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(relayDescriptor) relayDescriptor
	}{
		{
			name: "unsigned",
			mutate: func(d relayDescriptor) relayDescriptor {
				d.Signature = ""
				return d
			},
		},
		{
			name: "address swapped",
			mutate: func(d relayDescriptor) relayDescriptor {
				d.Address = "0x0000000000000000000000000000000000000001"
				return d
			},
		},
		{
			name: "api address swapped",
			mutate: func(d relayDescriptor) relayDescriptor {
				d.APIHTTPSAddr = "https://attacker.example"
				return d
			},
		},
		{
			name: "signature corrupted",
			mutate: func(d relayDescriptor) relayDescriptor {
				raw, decodeErr := base64.StdEncoding.DecodeString(d.Signature)
				if decodeErr != nil {
					t.Fatalf("decode signature: %v", decodeErr)
				}
				raw[len(raw)-1] ^= 0xff
				d.Signature = base64.StdEncoding.EncodeToString(raw)
				return d
			},
		},
		{
			name: "expired",
			mutate: func(d relayDescriptor) relayDescriptor {
				d.ExpiresAt = now.Add(-time.Minute)
				return d
			},
		},
		{
			name: "not base64",
			mutate: func(d relayDescriptor) relayDescriptor {
				d.Signature = "not base64 !!"
				return d
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if err := verifyRelayDescriptor(test.mutate(valid), now); err == nil {
				t.Fatal("verifyRelayDescriptor accepted an invalid descriptor")
			}
		})
	}
}

// Canonical bytes must reproduce the relay's signing payload exactly, or every
// genuine descriptor would fail verification.
func TestCanonicalDescriptorBytesMatchTheRelayPayload(t *testing.T) {
	now := time.Date(2026, 10, 4, 3, 0, 0, 123456789, time.UTC)
	descriptor := relayDescriptor{
		Address:           "0xabc",
		Version:           "9",
		IssuedAt:          now,
		ExpiresAt:         now.Add(time.Minute),
		APIHTTPSAddr:      "https://relay.example",
		SupportsUDP:       true,
		SupportsTCP:       false,
		ActiveConnections: 7,
		TCPBPS:            1.5,
	}
	payload, err := canonicalDescriptorBytes(descriptor)
	if err != nil {
		t.Fatalf("canonicalize: %v", err)
	}
	// Field order and the nanosecond timestamps are the wire contract.
	want := `{"address":"0xabc","version":"9",` +
		`"issued_at_unix_nano":` + strconv.FormatInt(now.UnixNano(), 10) + `,` +
		`"expires_at_unix_nano":` + strconv.FormatInt(now.Add(time.Minute).UnixNano(), 10) + `,` +
		`"api_https_addr":"https://relay.example",` +
		`"supports_udp":true,"supports_tcp":false,` +
		`"active_connections":7,"tcp_bps":1.5}`
	if string(payload) != want {
		t.Fatalf("canonical bytes =\n%s\nwant\n%s", payload, want)
	}
}

// A relay's discovery document expands membership with relays it lists, and
// the exposure supervises them.
func TestExposureAdoptsDiscoveredRelays(t *testing.T) {
	advertised := newFakeRelay(t, "advertised", fakeRelayOptions{})
	defer advertised.close()
	seed := newFakeRelay(t, "seed", fakeRelayOptions{advertiseRelays: []string{advertised.url}})
	defer seed.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exposure, err := exposeWithTimings(ctx, ExposeConfig{
		Relays:   []string{seed.url},
		Identity: newTestIdentity(t),
	}, testRelayTimings())
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}
	defer exposure.Close()

	// The advertised relay must become a member and reach ready on its own.
	ready := waitForReady(t, exposure, 2)
	if _, ok := ready[advertised.url]; !ok {
		t.Fatalf("ready relays = %v, want the discovered relay %s", ready, advertised.url)
	}
	if _, ok := ready[seed.url]; !ok {
		t.Fatalf("ready relays = %v, want the explicit seed %s", ready, seed.url)
	}
	seed.waitFor(t, "seed discovery request", func() bool { return seed.discoveryCount >= 1 })
	seed.assertNoErrors(t)
	advertised.assertNoErrors(t)
}

// Discovery must never adopt an unverifiable advertisement.
func TestExposureIgnoresUnsupportedDiscoveryRevision(t *testing.T) {
	relay := newFakeRelay(t, "bad-discovery", fakeRelayOptions{
		discoveryUnsupported: true,
		advertiseRelays:      []string{"https://attacker.example"},
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
	defer exposure.Close()

	_ = waitForReady(t, exposure, 1)
	relay.waitFor(t, "discovery request", func() bool { return relay.discoveryCount >= 1 })
	statuses := exposure.Relays()
	if len(statuses) != 1 || statuses[0].RelayURL != relay.url {
		t.Fatalf("relays = %+v, want only the explicit relay", statuses)
	}
}

// DisableDiscovery keeps the exposure on exactly the relays it was given.
func TestExposureDisableDiscoveryKeepsMembershipFixed(t *testing.T) {
	advertised := newFakeRelay(t, "advertised-fixed", fakeRelayOptions{})
	defer advertised.close()
	seed := newFakeRelay(t, "seed-fixed", fakeRelayOptions{advertiseRelays: []string{advertised.url}})
	defer seed.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exposure, err := exposeWithTimings(ctx, ExposeConfig{
		Relays:           []string{seed.url},
		Identity:         newTestIdentity(t),
		DisableDiscovery: true,
	}, testRelayTimings())
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}
	defer exposure.Close()

	_ = waitForReady(t, exposure, 1)
	// Give the loop time to run if it were enabled.
	time.Sleep(100 * time.Millisecond)
	if got := seed.discoveryCount; got != 0 {
		t.Fatalf("discovery requests = %d, want 0 when discovery is disabled", got)
	}
	statuses := exposure.Relays()
	if len(statuses) != 1 || statuses[0].RelayURL != seed.url {
		t.Fatalf("relays = %+v, want only the explicit relay", statuses)
	}
}

// MaxActiveRelays caps how many relays discovery may add; explicit relays are
// retained regardless of the cap.
func TestExposureMaxActiveRelaysCapsDiscoveredAdditions(t *testing.T) {
	first := newFakeRelay(t, "cap-a", fakeRelayOptions{})
	defer first.close()
	second := newFakeRelay(t, "cap-b", fakeRelayOptions{})
	defer second.close()
	seed := newFakeRelay(t, "cap-seed", fakeRelayOptions{
		advertiseRelays: []string{first.url, second.url},
	})
	defer seed.close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exposure, err := exposeWithTimings(ctx, ExposeConfig{
		Relays:          []string{seed.url},
		Identity:        newTestIdentity(t),
		MaxActiveRelays: 1,
	}, testRelayTimings())
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}
	defer exposure.Close()

	_ = waitForReady(t, exposure, 1)
	seed.waitFor(t, "a discovered relay to be adopted", func() bool {
		return len(exposure.Relays()) >= 2
	})
	// Settle: the cap must hold at one discovered addition.
	time.Sleep(150 * time.Millisecond)
	statuses := exposure.Relays()
	if len(statuses) != 2 {
		t.Fatalf("relays = %+v, want the seed plus exactly one discovered relay", statuses)
	}
	found := false
	for _, status := range statuses {
		if status.RelayURL == seed.url {
			found = true
		}
	}
	if !found {
		t.Fatalf("relays = %+v, want the explicit seed retained", statuses)
	}
}

// The cap bounds discovered additions, so an explicit set as large as the cap
// still grows. This is the default path: DefaultRelays already fills a naive
// total-membership cap, which would make discovery inert.
func TestExposureDiscoveryExpandsBeyondExplicitSetSize(t *testing.T) {
	var explicit []string
	var relays []*fakeRelay
	// Three explicit relays, matching the shape of the built-in list.
	for _, name := range []string{"explicit-a", "explicit-b", "explicit-c"} {
		relay := newFakeRelay(t, name, fakeRelayOptions{})
		relays = append(relays, relay)
		explicit = append(explicit, relay.url)
	}
	defer func() {
		for _, relay := range relays {
			relay.close()
		}
	}()

	advertised := newFakeRelay(t, "beyond-cap", fakeRelayOptions{})
	defer advertised.close()
	relays[0].options.advertiseRelays = []string{advertised.url}
	relays[0].discoveryRelays = append(relays[0].discoveryRelays,
		signDescriptorWithNewKey(t, advertised.url, time.Now().UTC()))

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	exposure, err := exposeWithTimings(ctx, ExposeConfig{
		Relays:          explicit,
		Identity:        newTestIdentity(t),
		MaxActiveRelays: 3, // equal to the explicit set size
	}, testRelayTimings())
	if err != nil {
		t.Fatalf("Expose: %v", err)
	}
	defer exposure.Close()

	relays[0].waitFor(t, "discovery to expand past the explicit set size", func() bool {
		return len(exposure.Relays()) >= len(explicit)+1
	})
	statuses := exposure.Relays()
	if len(statuses) != len(explicit)+1 {
		t.Fatalf("relays = %d, want %d: discovery must add relays beyond the explicit set",
			len(statuses), len(explicit)+1)
	}
}

// A relay that fails terminally is never re-adopted by discovery, so the
// exposure does not loop on a rejected relay.
func TestExposureDoesNotReAdoptRejectedRelay(t *testing.T) {
	relay := newFakeRelay(t, "rejected", fakeRelayOptions{})
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
	defer exposure.Close()

	_ = waitForReady(t, exposure, 1)
	// Force a terminal failure, then confirm discovery does not revive it.
	relay.closeOneIdleAndRejectReconnect(t)
	failed := waitForFailed(t, exposure, relay.url)
	if failed.Err == nil {
		t.Fatal("terminal failure reported no error")
	}
	if _, err := exposure.WaitReady(context.Background()); !errors.Is(err, ErrNoRelays) {
		t.Fatalf("WaitReady error = %v, want ErrNoRelays", err)
	}
	statuses := exposure.Relays()
	if len(statuses) != 1 || statuses[0].State != RelayFailed {
		t.Fatalf("relays = %+v, want the single failed relay", statuses)
	}
}
