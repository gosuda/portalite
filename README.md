# portalite

Portalite is a small Go SDK and CLI for exposing one service through multiple Protocol 8 relays. Its `Exposure` type implements `net.Listener` and isolates relay failures so healthy relays continue serving connections.

[Usage and API documentation](docs/usage.md)
