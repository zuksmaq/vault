# Vault — Context

A read-only client for reading secrets from a HashiCorp Vault KV v2
secrets engine. See `docs/adr/` for the individual decisions and their
rationale.

## Language

**Secret**:
The complete set of key/value pairs stored at one path in the KV v2
engine. A secret is a whole path's contents, not one value.
_Avoid_: credential, config, entry

**Secret value**:
One value inside a secret, addressed by its key.
_Avoid_: secret (when a single value is meant), field

**Mount point**:
The path the KV v2 secrets engine is mounted at, `secret` by default.
Distinct from a secret path, which is addressed within the mount.
_Avoid_: engine path, backend

**Secret path**:
The location of a secret within the mount point, as typed into the
Vault UI's search. Never includes the mount point or KV v2's `data`
segment.
_Avoid_: key, secret name

**AppRole**:
The role ID and secret ID pair issued when a vault is created, used by
programs to authenticate. The secret ID is itself a secret and expires.
_Avoid_: role, credentials

**Static token**:
A Vault token handed to the client directly rather than earned by
logging in. There is nothing to log in with when it expires, so it
fails permanently.
_Avoid_: root token, auth token

**Coercion**:
The rule that renders a JSON secret value as a string: strings pass
through, numbers keep their literal form, bools become `true` or
`false`, and objects and arrays become compact JSON.

**Lazy re-authentication**:
Recovering from an expired token by logging in again when a read is
refused, rather than renewing ahead of expiry.
_Avoid_: refresh, renewal

## Conventions

- Read-only. The client never writes, deletes or lists. Secrets are
  provisioned through the Vault UI.
- Latest version only. KV v2 keeps history, but reading a specific
  version is out of scope.
- Errors are sentinel values (`var ErrXxx = errors.New(...)`) wrapped
  with `%w` and checked via `errors.Is` — no exception-style type
  hierarchy.
- Construction is `New(cfg, opts...)`: a config struct with a
  `Validate()` method for mandatory fields, functional options for
  optional cross-cutting concerns. No builder pattern.
- TLS verification is on unless explicitly disabled, and disabling it
  is logged.
- Logging via `log/slog`, silent unless a logger is supplied. Secret
  values, key names and role IDs are never logged.
- Every method takes a `context.Context` as its first argument.
- No exported interface. Consumers declare the narrow interface they
  need at the point they consume it, and fake that in their tests.
