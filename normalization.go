package portalite

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// NormalizeTarget validates a local TCP target. A bare port or :PORT is
// expanded to the IPv4 loopback address; all other inputs must contain an
// explicit host and port.
func NormalizeTarget(raw string) (string, error) {
	target := strings.TrimSpace(raw)
	if target == "" {
		return "", errors.New("target is required")
	}

	if isASCIIDigits(target) {
		port, err := normalizePort(target, "target")
		if err != nil {
			return "", err
		}
		return net.JoinHostPort("127.0.0.1", port), nil
	}
	if strings.HasPrefix(target, ":") && isASCIIDigits(target[1:]) {
		port, err := normalizePort(target[1:], "target")
		if err != nil {
			return "", err
		}
		return net.JoinHostPort("127.0.0.1", port), nil
	}
	if strings.Contains(target, "://") {
		return "", errors.New("target must be a TCP host and port, not a URL")
	}

	host, rawPort, err := net.SplitHostPort(target)
	if err != nil {
		return "", fmt.Errorf("target must be PORT, :PORT, HOST:PORT, or [IPv6]:PORT: %w", err)
	}
	if host == "" {
		return "", errors.New("target host is required")
	}
	port, err := normalizePort(rawPort, "target")
	if err != nil {
		return "", err
	}

	if strings.HasPrefix(target, "[") || strings.Contains(host, ":") {
		address, err := netip.ParseAddr(host)
		if err != nil || !address.Is6() {
			return "", errors.New("bracketed target host must be a valid IPv6 address")
		}
		host = address.String()
	} else if address, err := netip.ParseAddr(host); err == nil {
		host = address.String()
	} else if !validTargetHost(host) {
		return "", errors.New("target host contains invalid URL or path characters")
	}

	return net.JoinHostPort(host, port), nil
}

// NormalizeRelays validates, canonicalizes, and de-duplicates relay HTTPS
// origins while preserving the first occurrence of each origin.
func NormalizeRelays(inputs []string) ([]string, error) {
	if len(inputs) == 0 {
		return nil, errors.New("at least one relay is required")
	}

	result := make([]string, 0, len(inputs))
	seen := make(map[string]struct{}, len(inputs))
	for index, input := range inputs {
		canonical, err := normalizeRelay(input)
		if err != nil {
			return nil, fmt.Errorf("relay %d: %w", index+1, err)
		}
		if _, exists := seen[canonical]; exists {
			continue
		}
		seen[canonical] = struct{}{}
		result = append(result, canonical)
	}
	if len(result) == 0 {
		return nil, errors.New("at least one relay is required")
	}
	return result, nil
}

func normalizeRelay(raw string) (string, error) {
	relay := strings.TrimSpace(raw)
	if relay == "" {
		return "", errors.New("relay URL is required")
	}
	if strings.ContainsAny(relay, "?#") {
		return "", errors.New("relay URL must not contain a query or fragment")
	}
	if !strings.Contains(relay, "://") {
		relay = "https://" + relay
	}

	parsed, err := url.Parse(relay)
	if err != nil {
		return "", fmt.Errorf("invalid relay URL: %w", err)
	}
	if !strings.EqualFold(parsed.Scheme, "https") {
		return "", errors.New("relay URL must use HTTPS")
	}
	if parsed.Opaque != "" || parsed.Host == "" {
		return "", errors.New("relay URL must contain an HTTPS hostname")
	}
	if parsed.User != nil {
		return "", errors.New("relay URL must not contain user information")
	}
	if parsed.ForceQuery || parsed.RawQuery != "" || parsed.Fragment != "" || parsed.RawFragment != "" {
		return "", errors.New("relay URL must not contain a query or fragment")
	}
	if parsed.RawPath != "" {
		return "", errors.New("relay URL path must be empty, /, or /relay")
	}
	if parsed.Path != "" && parsed.Path != "/" && parsed.Path != "/relay" {
		return "", errors.New("relay URL path must be empty, /, or /relay")
	}
	if strings.HasSuffix(parsed.Host, ":") {
		return "", errors.New("relay URL port is required after ':'")
	}

	host := parsed.Hostname()
	if strings.Contains(host, ":") && strings.Contains(host, "%") {
		return "", errors.New("relay URL must not contain an IPv6 zone identifier")
	}
	host = strings.ToLower(host)
	host = strings.TrimSuffix(host, ".")
	if host == "" {
		return "", errors.New("relay URL hostname is required")
	}
	for _, char := range host {
		if char >= 0x80 {
			return "", errors.New("relay URL hostname must contain only ASCII characters")
		}
	}

	if address, err := netip.ParseAddr(host); err == nil {
		if address.Is6() {
			return "", errors.New("relay URL must use a DNS hostname, not an IPv6 literal")
		}
		host = address.String()
	} else if strings.Contains(host, ":") {
		return "", errors.New("relay URL contains an invalid IPv6 address")
	} else if !validDNSHostname(host) {
		return "", errors.New("relay URL contains an invalid hostname")
	}

	port := parsed.Port()
	if port != "" {
		port, err = normalizePort(port, "relay URL")
		if err != nil {
			return "", err
		}
		if port == "443" {
			port = ""
		}
	}

	authority := host
	if strings.Contains(host, ":") {
		authority = "[" + host + "]"
	}
	if port != "" {
		authority = net.JoinHostPort(host, port)
	}
	return "https://" + authority, nil
}

func normalizePort(raw, subject string) (string, error) {
	if !isASCIIDigits(raw) {
		return "", fmt.Errorf("%s port must be a decimal number", subject)
	}
	port, err := strconv.ParseUint(raw, 10, 16)
	if err != nil || port == 0 {
		return "", fmt.Errorf("%s port must be between 1 and 65535", subject)
	}
	return strconv.FormatUint(port, 10), nil
}

func isASCIIDigits(value string) bool {
	if value == "" {
		return false
	}
	for index := range len(value) {
		if value[index] < '0' || value[index] > '9' {
			return false
		}
	}
	return true
}

func validTargetHost(host string) bool {
	for _, char := range host {
		if char <= ' ' || char == 0x7f || char == '/' || char == '\\' || char == '?' || char == '#' || char == '@' || char == '[' || char == ']' {
			return false
		}
	}
	return true
}

func validDNSHostname(host string) bool {
	if host == "" || len(host) > 253 {
		return false
	}
	for _, char := range host {
		if char >= 0x80 {
			return false
		}
	}
	labels := strings.Split(host, ".")
	for _, label := range labels {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := range len(label) {
			char := label[index]
			if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') || char == '-' {
				continue
			}
			return false
		}
	}
	return true
}
