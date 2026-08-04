package vault

import "errors"

var (
	// ErrInvalidConfig reports a configuration that cannot produce a
	// usable client.
	ErrInvalidConfig = errors.New("invalid config")

	// ErrAuthFailed reports a credential Vault rejected, so no token was
	// issued and no read can be attempted.
	ErrAuthFailed = errors.New("authentication failed")

	// ErrNotFound reports that a secret path does not exist.
	ErrNotFound = errors.New("not found")

	// ErrUnexpectedResponse reports a response Vault returned in a shape
	// this client does not understand.
	ErrUnexpectedResponse = errors.New("unexpected response")

	// ErrUnavailable reports a failure Vault owns and may recover from —
	// sealed, rate limiting, or a stale read on a replica. vault/api has
	// already retried by the time this surfaces, so retrying again is a
	// judgement the caller makes.
	ErrUnavailable = errors.New("vault unavailable")
)
