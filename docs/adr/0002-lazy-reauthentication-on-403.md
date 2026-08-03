# Recover from token expiry by re-authenticating lazily

An AppRole login returns a token with a TTL, commonly an hour. The
Python and Go clients that preceded this one logged in once and never
renewed, so a long-running service failed an hour in with an error that
read like a network fault. We re-authenticate lazily instead: a read
refused with 403 triggers one login and one retry, and a second refusal
surfaces as `ErrPermissionDenied`.

## Considered Options

`api.LifetimeWatcher` renews a token from a background goroutine and is
the textbook answer for long-lived services. We rejected it on three
counts. It needs a goroutine per client and therefore a `Close()`
contract to avoid leaking one. It cannot help the static-token mode at
all, leaving two different lifecycle behaviours to document. And a
client that reads a handful of paths at startup gains nothing from
avoiding an occasional extra round-trip.

## Consequences

Re-authentication is single-flighted: concurrent readers meeting an
expired token produce one login, not one login each. Without that, a
token lapse becomes a self-inflicted login storm.

A service that reads secrets rarely pays one refused request plus a
login every time its token lapses, so the Vault issues more tokens than
renewal would. If lease-count quotas are ever tightened, revisit this.

Because there is no goroutine and no lease to release, the client needs
no `Close()`. Adding background renewal later would therefore be a
breaking change.
