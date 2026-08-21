package portalite

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// ProtocolVersion is the relay SDK protocol version implemented by Portalite.
const ProtocolVersion = "8"

const (
	pathDomain            = "/sdk/domain"
	pathRegisterChallenge = "/sdk/register/challenge"
	pathRegister          = "/sdk/register"
	pathRenew             = "/sdk/renew"
	pathUnregister        = "/sdk/unregister"
	pathConnect           = "/sdk/connect"

	accessTokenHeader = "X-Portal-Access-Token"

	markerKeepalive byte = 0x00
	markerRaw       byte = 0x01 // Recognized only so the unsupported raw transport can be rejected.
	markerTLS       byte = 0x02

	maxControlResponseBytes int64 = 1 << 20
)

// APIError is an error returned by a relay control-plane endpoint.
type APIError struct {
	StatusCode int
	Code       string
	Message    string
}

func (e *APIError) Error() string {
	if e == nil {
		return ""
	}

	code := strings.TrimSpace(e.Code)
	message := strings.TrimSpace(e.Message)
	if code != "" {
		return code + ": " + message
	}
	if message != "" {
		return message
	}
	if e.StatusCode > 0 {
		return fmt.Sprintf("api request failed with status %d", e.StatusCode)
	}
	return "api request failed"
}

type apiEnvelope struct {
	Data  json.RawMessage `json:"data,omitempty"`
	Error *apiErrorBody   `json:"error,omitempty"`
	OK    bool            `json:"ok"`
}

type apiErrorBody struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

type domainResponse struct {
	ProtocolVersion string `json:"protocol_version"`
}

type identityRef struct {
	Name    string `json:"name,omitempty"`
	Address string `json:"address,omitempty"`
}

type challengeRequest struct {
	Identity identityRef `json:"identity"`
	TTL      int         `json:"ttl,omitempty"`
}

type challengeResponse struct {
	ChallengeID string    `json:"challenge_id"`
	ExpiresAt   time.Time `json:"expires_at"`
	SIWEMessage string    `json:"siwe_message"`
}

type registerRequest struct {
	ChallengeID   string `json:"challenge_id"`
	SIWEMessage   string `json:"siwe_message"`
	SIWESignature string `json:"siwe_signature"`
}

type registerResponse struct {
	Identity    identityRef `json:"identity"`
	ExpiresAt   time.Time   `json:"expires_at"`
	AccessToken string      `json:"access_token"`
	SNIPort     int         `json:"sni_port,omitempty"`
}

type renewRequest struct {
	AccessToken string `json:"access_token"`
	TTL         int    `json:"ttl,omitempty"`
}

type renewResponse struct {
	ExpiresAt   time.Time `json:"expires_at"`
	AccessToken string    `json:"access_token"`
}

type unregisterRequest struct {
	AccessToken string `json:"access_token"`
}
