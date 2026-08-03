package vault

import "errors"

var (
	// ErrInvalidConfig reports a configuration that cannot produce a
	// usable client.
	ErrInvalidConfig = errors.New("invalid config")

	// ErrNotFound reports that a secret path does not exist.
	ErrNotFound = errors.New("not found")

	// ErrUnexpectedResponse reports a response Vault returned in a shape
	// this client does not understand.
	ErrUnexpectedResponse = errors.New("unexpected response")
)
