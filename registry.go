package portalite

// defaultRelays mirrors the canonical relay registry published by
// gosuda/portal-tunnel (registry.json) for the current protocol generation.
// Relay availability is operational state, not a static guarantee.
var defaultRelays = [...]string{
	"https://gosunuts.xyz",
	"https://portal.thumbgo.kr",
	"https://portal.rabbitson87.dev",
	"https://s-h.day",
	"https://portal.dawnfullstack.com",
	"https://kakashit.org",
	"https://portal.damn.it.com",
	"https://portal.dps0340.win",
}

// DefaultRelays returns the canonical built-in relay URLs in registry order.
// Each call returns an independent slice.
func DefaultRelays() []string {
	result := make([]string, len(defaultRelays))
	copy(result, defaultRelays[:])
	return result
}
