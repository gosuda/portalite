# portalite

Portalite is a small Go SDK and CLI for exposing one service through multiple Protocol 10 relays, discovered automatically from the network. Its `Exposure` type implements `net.Listener` and isolates relay failures so healthy relays continue serving connections.

[Usage and API documentation](docs/usage.md)
