package portalite

var defaultRelays = [...]string{
	"https://gosunuts.xyz",
	"https://portal.thumbgo.kr",
	"https://portal.rabbitson87.dev",
	"https://s-h.day",
	"https://portal.dawnfullstack.com",
	"https://kakashit.org",
	"https://portal.damn.it.com",
}

// DefaultRelays returns the canonical built-in relay URLs in registry order.
// Each call returns an independent slice.
func DefaultRelays() []string {
	result := make([]string, len(defaultRelays))
	copy(result, defaultRelays[:])
	return result
}
