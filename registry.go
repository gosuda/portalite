package portalite

var defaultRelays = [...]string{
	"https://rly.best",
	"https://portal.thumbgo.kr",
	"https://portal.rabbitson87.dev",
	"https://portal.dawnfullstack.com",
	"https://portal.damn.it.com",
	"https://s-h.day",
	"https://gosunuts.xyz",
}

// DefaultRelays returns the canonical built-in relay URLs in registry order.
// Each call returns an independent slice.
func DefaultRelays() []string {
	result := make([]string, len(defaultRelays))
	copy(result, defaultRelays[:])
	return result
}
