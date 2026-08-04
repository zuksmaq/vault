# vault

A small, read-only Go client that reads secrets from a HashiCorp Vault
KV v2 secrets engine.

A service supplies an address, a mount point and one credential — an
AppRole, or a static token for local work — and reads a secret either as
a map of strings or bound directly into its own configuration struct.
Token expiry is handled without the caller knowing. TLS is verified
unless verification is deliberately turned off. Failures arrive as
sentinel errors the caller can branch on.

The API reference lives in the package documentation; this file covers
getting started, what the environment controls, and what changes if you
are replacing something else with it.

## Install

```bash
go get github.com/zuksmaq/vault
```

## Quick start

An unattended service authenticates with an AppRole. Construction logs
in, so a rejected credential fails at startup rather than on the first
read:

```go
client, err := vault.New(vault.Config{
    Address: "https://vault.example.com",
    AppRole: vault.AppRole{RoleID: roleID, SecretID: secretID},
}, vault.WithLogger(logger))
if err != nil {
    return err
}

secrets, err := client.GetSecrets(ctx, "app/config")
```

For local work, a token copied from the Vault UI does instead. It cannot
be renewed, so it is not for anything unattended:

```go
client, err := vault.New(vault.Config{
    Address: "https://vault.example.com",
    Token:   token,
})
```

Exactly one credential is required. Neither is an error, and so is both
— you are never left guessing which one is in use.

## Reading secrets

Three methods read, each taking a `context.Context` first. A secret path
is given without the mount point and without KV v2's `data` segment; the
client assembles the full path.

1. **`GetSecrets(ctx, path)`** — every secret value at a path, as a
   `map[string]string`.

2. **`GetSecret(ctx, path, key)`** — one secret value, by its key. A key
   the secret does not hold is `ErrNotFound`, not an empty string, so a
   typo cannot pass for a value that is legitimately empty.

3. **`Unmarshal(ctx, path, &v)`** — the secret bound into your own
   struct.

The first two render every value as a string: strings pass through,
numbers keep their literal form (`8080`, never `8080.000000`), bools
become `true` or `false`, and objects and arrays become compact JSON.

## Binding into a struct

`Unmarshal` binds the raw secret through `encoding/json` tags — before
coercion rather than after — so ports arrive as integers and flags as
bools:

```go
var cfg struct {
    Username string         `json:"username"`
    Port     int            `json:"port"`
    TLS      bool           `json:"tls"`
    Timeout  vault.Duration `json:"timeout"`
    Database struct {
        Host string `json:"host"`
        Port int    `json:"port"`
    } `json:"database"`
}

err := client.Unmarshal(ctx, "app/config", &cfg)
```

Declare a duration as `vault.Duration`, not `time.Duration`, because
`encoding/json` reads the latter only as a count of nanoseconds.
`vault.Duration` accepts `"30s"` and `"1h30m"`, and converts back with
`time.Duration(d)`.

## Environment variables

The address, the CA and whether to verify certificates fall back to the
variables the Vault CLI already honours, so one build runs against
several environments:

| Variable | Supplies |
| --- | --- |
| `VAULT_ADDR` | The Vault address |
| `VAULT_CACERT` | Path to the CA certificate |
| `VAULT_SKIP_VERIFY` | Turns certificate verification off |
| `VAULT_AGENT_ADDR` | An agent address, read by `vault/api` itself |

Precedence runs explicit configuration, then the environment, then the
secure default. A service that states a setting cannot be overridden by
a deployment manifest.

That last point is why `Config.InsecureSkipVerify` is a `*bool`: `nil`
defers to `VAULT_SKIP_VERIFY`, while a value set either way beats it. A
plain `bool` cannot tell a service that requires verification apart from
one that said nothing, and the former would then be unpicked silently.

A config that names an address also clears `VAULT_AGENT_ADDR`, which
otherwise outranks the address inside `vault/api` — so an explicit
address really is the one dialled.

## Transport security

Certificates are verified when the config says nothing, so a service is
never insecure merely because a field was forgotten. Supply an internal
CA as a file path (`CACertPath`) or as raw PEM bytes (`CACertPEM`) — the
bytes form exists so a pod can pass the service CA already mounted into
it, with no file to manage.

Verification can be turned off with `Config.InsecureSkipVerify` or with
`VAULT_SKIP_VERIFY`. Either route warns at construction through the
logger you supply, and nothing in this package suppresses that warning —
so supply a logger if you want to hear about it.

## Errors

Failures wrap a sentinel, checked with `errors.Is` and never compared
with `==`:

- `ErrInvalidConfig` — the config cannot produce a usable client.
- `ErrAuthFailed` — Vault rejected the credential.
- `ErrPermissionDenied` — a read Vault refused with a credential it
  accepted. With an AppRole an expired token is recovered from before
  this surfaces, so it means the role's policy does not allow the read;
  with a static token it also means the token has expired, because there
  is nothing to log in with.
- `ErrNotFound` — no such secret path, or no such key within one. The
  message says which.
- `ErrUnexpectedResponse` — a response shape this client does not
  understand.
- `ErrUnavailable` — sealed, rate limiting, or a stale read on a
  replica.

A transport failure is not flattened into a sentinel but wrapped intact,
so a timeout still answers to `errors.As` as a timeout.

Retries for failures Vault owns come from `vault/api`, which retries
with backoff by default. `ErrUnavailable` therefore surfaces only after
those attempts — do not add a second retry layer on top.

## Faking it in your tests

This package exports no interface. Declare the narrow one you actually
use, where you use it, and fake that — so you never stub methods you do
not call:

```go
type secretReader interface {
    GetSecrets(ctx context.Context, path string) (map[string]string, error)
}

func loadConfig(ctx context.Context, r secretReader) (Settings, error) {
    // ...
}
```

`*vault.Client` satisfies such an interface without being told about it.
The package's example tests carry a runnable version of this pattern,
fake and all, along with compiled examples of each method above.

## The mount point default

`Config.MountPoint` defaults to `secret`, which is where a KV v2 engine
is mounted unless somebody chose otherwise. It is a default, not a
discovery: if your Vault mounts KV v2 elsewhere, set the field. The
symptom of leaving it unset is `ErrNotFound` for a secret that plainly
exists in the UI.

## Migrating from the Python package

Two things change, and the first will not compile.

1. **Secrets no longer arrive through the environment.** The Python
   package pushed secret values into environment variables and let code
   read them with `os.environ` afterwards. This client accepts a struct
   or a map and keeps secrets in process memory.

   Read them into your own configuration struct with `Unmarshal`, or as
   a `map[string]string` with `GetSecrets`, and pass that value where it
   is needed. Secrets stay out of the environment on purpose: child
   processes and crash reporters cannot reach process memory.

2. **A connection failure and an expired token are no longer the same
   error.** The Python package's catch-all connection error made an
   expired token look like a network problem. Branch on the sentinels
   above instead.

The TLS note in the next section applies to you too, and it is the one
that fails on the very first connection.

## Migrating from either predecessor

**TLS is verified by default, so your first connection may fail.** Both
predecessors skipped verification, so a service that relied on that will
fail its first connection until it supplies a CA through `CACertPath` or
`CACertPEM`, or opts out explicitly. Opting out with
`InsecureSkipVerify` or `VAULT_SKIP_VERIFY` still works, but it is
deliberate and it is logged.

## Migrating from the earlier Go client

1. **A token is no longer something you obtain by hand.** Supply an
   AppRole and the client logs in for you, and logs in again when the
   token expires — the earlier client could not log in at all, so a
   human had to fetch a token first.

2. **Every method takes a `context.Context`.** A slow Vault can no
   longer hang your startup indefinitely.

## Running the tests

The default suite fakes Vault with `httptest` and needs no Docker. The
tagged suite starts a real Vault in a container and needs a container
runtime:

```bash
go test -race ./...
go test -tags integration -race ./...
```

Neither runs against a real production, development or test Vault.

## Out of scope

Deliberate omissions rather than gaps:

- Writing, patching or deleting secrets. Secrets are provisioned
  through the Vault UI.
- Reading a specific version of a secret, or its metadata. KV v2 keeps
  history; this reads the latest.
- Listing the secret paths under a prefix. Callers know their paths.
- Caching. Every read reaches Vault.
- Secrets engines other than KV v2, and Vault Enterprise namespaces.
- Kubernetes auth. Deferred, but `WithAuthMethod` accepts any
  `api.AuthMethod`, so it can be wired in the meantime.
- Setting environment variables from a secret. Secrets stay in process
  memory, out of reach of child processes and crash reporters.
- OpenTelemetry metrics. A client that reads a few paths at startup does
  not warrant them.
- An exported interface, and a `Close` method. There is no background
  goroutine and nothing to release.

## Decisions

The reasoning behind the choices above, and their costs, is recorded in
[the architecture decision records](docs/adr/), and the vocabulary this
package uses is defined in [CONTEXT.md](CONTEXT.md).
