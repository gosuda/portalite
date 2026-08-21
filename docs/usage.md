# Usage

## Requirements

- Go 1.25 or newer
- A local TCP service for CLI proxying, or a Go server that accepts a `net.Listener`
- Outbound HTTPS access to the selected relays

## Fault-tolerant virtual listener

`portalite.Expose` starts one independent supervisor per relay and returns immediately. The returned `*portalite.Exposure` implements `net.Listener`; pass it directly to `http.Server.Serve`, `grpc.Server.Serve`, or any server that accepts a listener.

```go
package main

import (
	"context"
	"errors"
	"log"
	"net"
	"net/http"
	"os/signal"
	"syscall"

	"gosuda.org/portalite"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	identity, err := portalite.GenerateIdentity("demo")
	if err != nil {
		log.Fatal(err)
	}

	listener, err := portalite.Expose(ctx, portalite.ExposeConfig{
		Identity: identity,
		Relays:   portalite.DefaultRelays(),
	})
	if err != nil {
		log.Fatal(err)
	}
	defer listener.Close()

	ready, err := listener.WaitReady(ctx)
	if err != nil {
		log.Fatal(err)
	}
	for _, relay := range ready {
		log.Printf("ready: %s via %s", relay.PublicURL, relay.RelayURL)
	}

	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("hello from portalite\n"))
	})}
	if err := server.Serve(listener); err != nil && !errors.Is(err, net.ErrClosed) && !errors.Is(err, http.ErrServerClosed) {
		log.Fatal(err)
	}
}
```

For a long-running server, start `Serve` immediately and observe `Updates` in another goroutine instead of blocking on `WaitReady`. `WaitReady` does not consume the update stream.

```go
go func() {
	for status := range listener.Updates() {
		log.Printf("relay=%s state=%s public=%s err=%v",
			status.RelayURL, status.State, status.PublicURL, status.Err)
	}
}()
```

Only one goroutine should consume `Updates`. Use `Relays` for sorted point-in-time snapshots.

### Relay state semantics

- `connecting`: registration, renewal, or reverse-session setup is still in progress.
- `ready`: the relay passed Protocol 8 and tenant-certificate checks, returned a valid `/v1/sign` signature for its certificate, and accepted at least one reverse HTTP/1.1 session.
- `failed`: that relay reached a terminal protocol, certificate, authentication, or transport error.

`ready` validates the SDK-to-relay control, signing, and reverse-session paths. It does not actively send a request through the relay's public ingress. An external routing or firewall fault can therefore still make an individual public URL unreachable.

Each relay owns its lease, token, signer, reverse sessions, retries, and shutdown. A terminal failure changes only that relay to `failed`; connections from other relays continue through the same listener. `Accept` returns `portalite.ErrNoRelays` only after every configured relay has failed. Calling `Close`, or canceling the parent context, returns `net.ErrClosed` to blocked accept calls and unregisters each live lease.

## Identity persistence

Generate an identity once and persist its JSON with mode `0600`:

```go
identity, err := portalite.GenerateIdentity("my-service")
data, err := identity.MarshalJSON()
```

Load it on the next run:

```go
identity, err := portalite.ParseIdentity(data)
```

Identity names are lowercase single DNS labels, 1–63 characters, using only ASCII letters, digits, and interior hyphens. The JSON contains the private key; do not publish or share it.

## CLI

Build the command:

```sh
go build -o portalite ./cmd/portalite
```

Expose a local HTTP service on port 3000 through all default relays:

```sh
./portalite expose 3000
```

Use explicit relays instead of the defaults:

```sh
./portalite expose \
  --relay https://relay-a.example \
  --relay https://relay-b.example \
  --identity ./identity.json \
  --name my-service \
  127.0.0.1:3000
```

Flags must appear before the target. Repeating `--relay` replaces the built-in relay set; canonical duplicates are removed while preserving input order. Without `--relay`, the CLI uses `portalite.DefaultRelays()`.

The command writes one line per ready relay to stdout:

```text
URL https://my-service.relay.example
```

Terminal relay failures are written to stderr. One failed relay does not terminate the command while another relay remains live or retrying. `SIGINT` and `SIGTERM` cancel sessions, unregister leases, and exit successfully after cleanup.

If the identity file does not exist, the CLI creates it with mode `0600` and creates missing parent directories with mode `0700`. An existing identity is never overwritten.

## Target formats

The CLI accepts:

- `3000`
- `:3000`
- `127.0.0.1:3000`
- `hostname:3000`
- `[::1]:3000`

A bare port binds the proxy target to `127.0.0.1`. URL schemes, paths, bare hosts, and ports outside 1–65535 are rejected.

## Default relays

`portalite.DefaultRelays()` returns a defensive copy of the built-in registry:

1. `https://rly.best`
2. `https://portal.thumbgo.kr`
3. `https://portal.rabbitson87.dev`
4. `https://portal.dawnfullstack.com`
5. `https://portal.damn.it.com`
6. `https://s-h.day`
7. `https://gosunuts.xyz`

Relay availability is operational state, not a static guarantee. Consume `Updates`, call `WaitReady`, or inspect `Relays` instead of assuming every configured relay is reachable.

## UDP support

The full Portal server and reference tunnel contain an optional UDP proxy: registration requests `udp_enabled`, the relay allocates a public UDP port, and framed datagrams travel over a QUIC backhaul to the client before being forwarded to a local UDP target. A relay can disable this feature through policy or lack of a configured port range/backhaul.

Portalite intentionally implements only the ordinary HTTPS stream transport. Its public SDK and CLI do not expose UDP, QUIC, raw TCP port allocation, multi-hop, or ECH controls. Receiving the raw stream marker is treated as a terminal protocol error for that relay.

## API summary

```go
func Expose(context.Context, ExposeConfig) (*Exposure, error)
func (e *Exposure) Accept() (net.Conn, error)
func (e *Exposure) WaitReady(context.Context) ([]RelayStatus, error)
func (e *Exposure) Updates() <-chan RelayStatus
func (e *Exposure) Relays() []RelayStatus
func (e *Exposure) Addr() net.Addr
func (e *Exposure) Close() error
func Proxy(context.Context, *Exposure, string) error
```

`Proxy` is the sole accept consumer when used. Do not call `Accept` or run another server on the same exposure concurrently with `Proxy`.
