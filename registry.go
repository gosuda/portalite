package portalite

// defaultRelays is the built-in relay bootstrap set. It mirrors the union of
// relays currently published by the network's /discovery endpoint, validated
// against the tunnel protocol this SDK speaks. Relay availability is
// operational state, not a static guarantee.
var defaultRelays = [...]string{
	"https://gosunuts.xyz",
	"https://kakashit.org",
	"https://korokorok.com",
	"https://portal.damn.it.com",
	"https://portal.dawnfullstack.com",
	"https://portal.naratteu.dynv6.net",
	"https://portal.rabbitson87.dev",
	"https://portal.thumbgo.kr",
	"https://rly.best",
	"https://s-h.day",
}

// DefaultRelays returns the canonical built-in relay URLs in registry order.
// Each call returns an independent slice.
func DefaultRelays() []string {
	result := make([]string, len(defaultRelays))
	copy(result, defaultRelays[:])
	return result
}
