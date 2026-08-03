# Use hashicorp/vault/api rather than vault-client-go

`hashicorp/vault-client-go` looks like the modern official client, but
it has been frozen at v0.4.3 since December 2023, still declares itself
BETA and unfit for production, and is generated from an OpenAPI
specification HashiCorp has never made official. We use
`hashicorp/vault/api` (v1.23.0) instead: it is what Vault's own CLI is
built on, so it tracks the server's real behaviour, and it is still
actively released.

## Consequences

`vault/api` is verbose and stringly-typed — a KV v2 read arrives as
`Secret.Data["data"].(map[string]any)`. Hiding that is this package's
reason to exist. It also pulls in roughly ten transitive
`hashicorp/go-*` dependencies, so `go.sum` is larger than the size of
this codebase would suggest.

An earlier internal Go client hand-rolled the same requests over
`net/http`. That avoids the dependencies but reimplements retry,
TLS configuration and error handling, none of which was covered by
tests.
