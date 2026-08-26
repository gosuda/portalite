package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"

	"gosuda.org/portalite"
)

const usageLine = "Usage: portalite expose [--relay HTTPS_URL]... [--identity FILE] [--name LABEL] [--udp-target TARGET] [TARGET]\n"

type relayFlags []string

func (r *relayFlags) String() string {
	return strings.Join(*r, ",")
}

func (r *relayFlags) Set(value string) error {
	*r = append(*r, value)
	return nil
}

type identityLoader func(path, requestedName string) (portalite.Identity, error)

type identityGenerator func(name string) (portalite.Identity, error)

type identityFileOpener func(name string, flag int, perm os.FileMode) (*os.File, error)

type identityUsageError struct {
	err error
}

func (e *identityUsageError) Error() string {
	return e.err.Error()
}

func (e *identityUsageError) Unwrap() error {
	return e.err
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	return runWithIdentityLoader(ctx, args, stdout, stderr, loadOrCreateIdentity)
}

func runWithIdentityLoader(
	ctx context.Context,
	args []string,
	stdout, stderr io.Writer,
	loadIdentity identityLoader,
) int {
	if len(args) == 1 && (args[0] == "--help" || args[0] == "-h") {
		writeUsage(stdout)
		return 0
	}
	if len(args) == 0 {
		return usageError(stderr, "missing command")
	}
	if args[0] != "expose" {
		return usageError(stderr, fmt.Sprintf("unknown command %q", args[0]))
	}

	fs := flag.NewFlagSet("portalite expose", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	var relayValues relayFlags
	var identityPath string
	var name string
	var udpTarget string
	fs.Var(&relayValues, "relay", "relay HTTPS URL")
	fs.StringVar(&identityPath, "identity", "identity.json", "identity file")
	fs.StringVar(&name, "name", "", "identity name for a new identity")
	fs.StringVar(&udpTarget, "udp-target", "", "local UDP target")
	if err := fs.Parse(args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			writeUsage(stdout)
			return 0
		}
		return usageError(stderr, err.Error())
	}
	if fs.NArg() > 1 {
		return usageError(stderr, "expected at most one TCP TARGET")
	}
	target := ""
	var err error
	if fs.NArg() == 1 {
		target, err = portalite.NormalizeTarget(fs.Arg(0))
		if err != nil {
			return usageError(stderr, err.Error())
		}
	}
	if udpTarget != "" {
		udpTarget, err = portalite.NormalizeTarget(udpTarget)
		if err != nil {
			return usageError(stderr, err.Error())
		}
	}
	if target == "" && udpTarget == "" {
		return usageError(stderr, "missing TCP TARGET or --udp-target")
	}
	relays, err := selectRelays(relayValues)
	if err != nil {
		return usageError(stderr, err.Error())
	}

	identity, err := loadIdentity(identityPath, name)
	if err != nil {
		var usageErr *identityUsageError
		if errors.As(err, &usageErr) {
			return usageError(stderr, err.Error())
		}
		fmt.Fprintf(stderr, "portalite: %v\n", err)
		return 1
	}

	if err := ctx.Err(); err != nil {
		return 0
	}
	exposure, err := portalite.Expose(ctx, portalite.ExposeConfig{
		Relays:     relays,
		Identity:   identity,
		UDPEnabled: udpTarget != "",
	})
	if err != nil {
		if ctx.Err() != nil {
			return 0
		}
		if errors.Is(err, portalite.ErrNoRelays) {
			return 1
		}
		fmt.Fprintf(stderr, "portalite: %v\n", err)
		return 1
	}

	var updates sync.WaitGroup
	updates.Add(1)
	go func() {
		defer updates.Done()
		for status := range exposure.Updates() {
			writeRelayStatus(stdout, stderr, status)
		}
	}()

	err = portalite.ProxyWithConfig(ctx, exposure, portalite.ProxyConfig{
		TCPTarget: target,
		UDPTarget: udpTarget,
	})
	updates.Wait()
	if ctx.Err() != nil {
		return 0
	}
	if errors.Is(err, portalite.ErrNoRelays) {
		return 1
	}
	if err != nil {
		fmt.Fprintf(stderr, "portalite: %v\n", err)
		return 1
	}
	return 0
}

func writeRelayStatus(stdout, stderr io.Writer, status portalite.RelayStatus) {
	switch status.State {
	case portalite.RelayReady:
		fmt.Fprintf(stdout, "URL %s\n", status.PublicURL)
	case portalite.RelayUDPReady:
		fmt.Fprintf(stdout, "UDP %s\n", status.UDPAddr)
	case portalite.RelayFailed:
		fmt.Fprintf(stderr, "portalite: relay %s: %v\n", status.RelayURL, status.Err)
	}
}

func writeUsage(w io.Writer) {
	_, _ = io.WriteString(w, usageLine)
}

func usageError(stderr io.Writer, message string) int {
	fmt.Fprintf(stderr, "portalite: %s\n", message)
	writeUsage(stderr)
	return 2
}

func selectRelays(explicit []string) ([]string, error) {
	inputs := explicit
	if len(inputs) == 0 {
		inputs = portalite.DefaultRelays()
	}
	return portalite.NormalizeRelays(inputs)
}

func loadOrCreateIdentity(path, requestedName string) (portalite.Identity, error) {
	return loadOrCreateIdentityWith(path, requestedName, portalite.GenerateIdentity, os.OpenFile)
}

func loadOrCreateIdentityWith(
	path, requestedName string,
	generate identityGenerator,
	openFile identityFileOpener,
) (portalite.Identity, error) {
	normalizedRequestedName, err := normalizeRequestedIdentityName(requestedName)
	if err != nil {
		return portalite.Identity{}, &identityUsageError{err: err}
	}

	data, err := os.ReadFile(path)
	if err == nil {
		identity, parseErr := portalite.ParseIdentity(data)
		if parseErr != nil {
			return portalite.Identity{}, fmt.Errorf("read identity %q: %w", path, parseErr)
		}
		if err := checkIdentityName(identity, normalizedRequestedName, path); err != nil {
			return portalite.Identity{}, &identityUsageError{err: err}
		}
		return identity, nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return portalite.Identity{}, fmt.Errorf("read identity %q: %w", path, err)
	}

	identityName := normalizedRequestedName
	if identityName == "" {
		var random [6]byte
		if _, err := rand.Read(random[:]); err != nil {
			return portalite.Identity{}, fmt.Errorf("generate identity name: %w", err)
		}
		identityName = "portalite-" + hex.EncodeToString(random[:])
	}
	identity, err := generate(identityName)
	if err != nil {
		return portalite.Identity{}, err
	}
	encoded, err := identity.MarshalJSON()
	if err != nil {
		return portalite.Identity{}, fmt.Errorf("encode identity: %w", err)
	}
	encoded = append(encoded, '\n')

	parent := filepath.Dir(path)
	if err := ensureIdentityDirectory(parent); err != nil {
		return portalite.Identity{}, fmt.Errorf("create identity directory %q: %w", parent, err)
	}
	var file *os.File
	for {
		file, err = openFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
		if err == nil {
			break
		}
		if !errors.Is(err, os.ErrExist) {
			return portalite.Identity{}, fmt.Errorf("create identity %q: %w", path, err)
		}

		winnerIdentity, retryCreate, raceErr := readIdentityAfterCreateRace(path, normalizedRequestedName)
		if raceErr != nil {
			return portalite.Identity{}, raceErr
		}
		if retryCreate {
			continue
		}
		return winnerIdentity, nil
	}

	keep := false
	defer func() {
		if !keep {
			_ = os.Remove(path)
		}
	}()
	if err := file.Chmod(0o600); err != nil {
		_ = file.Close()
		return portalite.Identity{}, fmt.Errorf("set identity permissions %q: %w", path, err)
	}
	written, writeErr := file.Write(encoded)
	if writeErr == nil && written != len(encoded) {
		writeErr = io.ErrShortWrite
	}
	if writeErr != nil {
		_ = file.Close()
		return portalite.Identity{}, fmt.Errorf("write identity %q: %w", path, writeErr)
	}
	if err := file.Close(); err != nil {
		return portalite.Identity{}, fmt.Errorf("close identity %q: %w", path, err)
	}
	keep = true
	return identity, nil
}

func ensureIdentityDirectory(path string) error {
	err := os.Mkdir(path, 0o700)
	if err == nil {
		return os.Chmod(path, 0o700)
	}
	if errors.Is(err, os.ErrExist) {
		info, statErr := os.Stat(path)
		if statErr != nil {
			return statErr
		}
		if !info.IsDir() {
			return fmt.Errorf("%s exists and is not a directory", path)
		}
		return nil
	}
	if !errors.Is(err, os.ErrNotExist) {
		return err
	}

	parent := filepath.Dir(path)
	if parent == path {
		return err
	}
	if err := ensureIdentityDirectory(parent); err != nil {
		return err
	}
	return ensureIdentityDirectory(path)
}

func readIdentityAfterCreateRace(path, requestedName string) (portalite.Identity, bool, error) {
	const (
		waitLimit = time.Second
		pollDelay = 10 * time.Millisecond
	)

	deadline := time.Now().Add(waitLimit)
	for {
		winner, readErr := os.ReadFile(path)
		if errors.Is(readErr, os.ErrNotExist) {
			return portalite.Identity{}, true, nil
		}
		if readErr != nil {
			return portalite.Identity{}, false, fmt.Errorf("read identity %q after create race: %w", path, readErr)
		}

		winnerIdentity, parseErr := portalite.ParseIdentity(winner)
		if parseErr == nil {
			if nameErr := checkIdentityName(winnerIdentity, requestedName, path); nameErr != nil {
				return portalite.Identity{}, false, &identityUsageError{err: nameErr}
			}
			return winnerIdentity, false, nil
		}

		remaining := time.Until(deadline)
		if remaining <= 0 {
			return portalite.Identity{}, false, fmt.Errorf("read identity %q after create race: %w", path, parseErr)
		}
		if remaining < pollDelay {
			time.Sleep(remaining)
		} else {
			time.Sleep(pollDelay)
		}
	}
}

const identityNameValidationPrivateKey = "0000000000000000000000000000000000000000000000000000000000000001"

func normalizeRequestedIdentityName(requestedName string) (string, error) {
	if requestedName == "" {
		return "", nil
	}
	identity, err := portalite.IdentityFromPrivateKey(requestedName, identityNameValidationPrivateKey)
	if err != nil {
		return "", err
	}
	return identity.Name(), nil
}

func checkIdentityName(identity portalite.Identity, requestedName, path string) error {
	if requestedName == "" {
		return nil
	}
	if requestedName != identity.Name() {
		return fmt.Errorf("identity name %q does not match existing identity %q in %q (delete the file or use --identity to specify a different path)", requestedName, identity.Name(), path)
	}
	return nil
}
