package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"

	"gosuda.org/portalite"
)

const usageLine = "Usage: portalite-http-demo [--relay HTTPS_URL]... [--name LABEL]\n"

type relayFlags []string

func (r *relayFlags) String() string { return strings.Join(*r, ",") }
func (r *relayFlags) Set(value string) error {
	*r = append(*r, value)
	return nil
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("portalite-http-demo", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var relays relayFlags
	var name string
	fs.Var(&relays, "relay", "relay HTTPS URL")
	fs.StringVar(&name, "name", "", "ephemeral identity name")
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			_, _ = io.WriteString(stdout, usageLine)
			return 0
		}
		fmt.Fprintf(stderr, "portalite-http-demo: %v\n%s", err, usageLine)
		return 2
	}
	if fs.NArg() != 0 {
		fmt.Fprintf(stderr, "portalite-http-demo: unexpected argument %q\n%s", fs.Arg(0), usageLine)
		return 2
	}
	if len(relays) == 0 {
		relays = portalite.DefaultRelays()
	}
	normalizedRelays, err := portalite.NormalizeRelays(relays)
	if err != nil {
		fmt.Fprintf(stderr, "portalite-http-demo: %v\n", err)
		return 2
	}
	if name == "" {
		name, err = randomIdentityName()
		if err != nil {
			fmt.Fprintf(stderr, "portalite-http-demo: %v\n", err)
			return 1
		}
	}
	identity, err := portalite.GenerateIdentity(name)
	if err != nil {
		fmt.Fprintf(stderr, "portalite-http-demo: %v\n", err)
		return 2
	}

	listener, err := portalite.Expose(ctx, portalite.ExposeConfig{
		Relays:   normalizedRelays,
		Identity: identity,
	})
	if err != nil {
		fmt.Fprintf(stderr, "portalite-http-demo: %v\n", err)
		return 1
	}

	var updates sync.WaitGroup
	updates.Add(1)
	go func() {
		defer updates.Done()
		for status := range listener.Updates() {
			switch status.State {
			case portalite.RelayReady:
				fmt.Fprintf(stdout, "URL %s\n", status.PublicURL)
			case portalite.RelayFailed:
				fmt.Fprintf(stderr, "portalite-http-demo: relay %s: %v\n", status.RelayURL, status.Err)
			}
		}
	}()

	server := &http.Server{Handler: demoHandler(identity.Name())}
	serveErr := server.Serve(listener)
	closeErr := listener.Close()
	updates.Wait()
	if ctx.Err() != nil {
		return 0
	}
	if errors.Is(serveErr, portalite.ErrNoRelays) {
		return 1
	}
	if serveErr != nil && !errors.Is(serveErr, net.ErrClosed) && !errors.Is(serveErr, http.ErrServerClosed) {
		fmt.Fprintf(stderr, "portalite-http-demo: %v\n", serveErr)
		return 1
	}
	if closeErr != nil {
		fmt.Fprintf(stderr, "portalite-http-demo: %v\n", closeErr)
		return 1
	}
	return 0
}

func demoHandler(identityName string) http.Handler {
	return http.HandlerFunc(func(response http.ResponseWriter, request *http.Request) {
		response.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(response, "portalite virtual HTTP server\nidentity=%s\nmethod=%s\npath=%s\n", identityName, request.Method, request.URL.Path)
	})
}

func randomIdentityName() (string, error) {
	var suffix [6]byte
	if _, err := rand.Read(suffix[:]); err != nil {
		return "", fmt.Errorf("generate identity name: %w", err)
	}
	return "http-demo-" + hex.EncodeToString(suffix[:]), nil
}
