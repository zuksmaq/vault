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

	// AppRole is the credential an unattended service authenticates with.
	// It is mutually exclusive with Token.
	AppRole AppRole
}

// AppRole is the role ID and secret ID pair issued when a vault is
// created, which a program logs in with.
type AppRole struct {
	// RoleID names the role to log in as. It is not a secret, but it is
	// never logged either.
	RoleID string

	// SecretID is the role's credential. It is exchanged for a token at
	// construction.
	SecretID string
}

// supplied reports whether the config names an AppRole at all, as opposed
// to naming one incompletely.
func (r AppRole) supplied() bool {
	return r != AppRole{}
}

// Validate reports whether the config carries the mandatory fields and a
// coherent credential. It judges the config alone: a client built with
// WithAuthMethod carries its credential outside the config, so New is the
// authority on whether a credential was supplied at all.
func (c Config) Validate() error {
	if c.Address == "" {
		return fmt.Errorf("%w: address is required", ErrInvalidConfig)
	}
	if c.AppRole.supplied() && (c.AppRole.RoleID == "" || c.AppRole.SecretID == "") {
		return fmt.Errorf("%w: an approle needs both a role id and a secret id", ErrInvalidConfig)
	}
	// Which credential is in use must never be a guess.
	if c.Token != "" && c.AppRole.supplied() {
		return fmt.Errorf("%w: a static token and an approle were both supplied, want one", ErrInvalidConfig)
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
