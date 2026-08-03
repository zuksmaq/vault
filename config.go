package vault

import "fmt"

// defaultMountPoint is where the KV v2 secrets engine is mounted unless a
// config says otherwise.
const defaultMountPoint = "secret"

// Config describes the Vault instance to read from and the credential to
// read with.
type Config struct {
	// Address is the base URL of the Vault instance, for example
	// https://vault.example.com.
	Address string

	// MountPoint is the path the KV v2 secrets engine is mounted at. It
	// defaults to "secret" when empty.
	MountPoint string

	// Token is a Vault token handed to the client directly. It cannot be
	// renewed, so it is meant for local work.
	Token string
}

// Validate reports whether the config carries the mandatory fields.
func (c Config) Validate() error {
	if c.Address == "" {
		return fmt.Errorf("%w: address is required", ErrInvalidConfig)
	}
	if c.Token == "" {
		return fmt.Errorf("%w: a token is required", ErrInvalidConfig)
	}
	return nil
}

// mountPoint returns the configured mount point, or the default.
func (c Config) mountPoint() string {
	if c.MountPoint == "" {
		return defaultMountPoint
	}
	return c.MountPoint
}
