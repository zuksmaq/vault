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

	// SecretID is the role's credential. It expires, so a client holding
	// one re-authenticates rather than failing permanently.
	SecretID string
}

// supplied reports whether the config names an AppRole at all, as opposed
// to naming one incompletely.
func (r AppRole) supplied() bool {
	return r != AppRole{}
}

// Validate reports whether the config carries the mandatory fields.
func (c Config) Validate() error {
	return c.validate(false)
}

// validate reports whether the config carries the mandatory fields, given
// whether an option supplied the credential instead. Only New knows that,
// because options are applied after the config is read.
func (c Config) validate(hasAuthMethod bool) error {
	if c.Address == "" {
		return fmt.Errorf("%w: address is required", ErrInvalidConfig)
	}
	if c.AppRole.supplied() && (c.AppRole.RoleID == "" || c.AppRole.SecretID == "") {
		return fmt.Errorf("%w: an approle needs both a role id and a secret id", ErrInvalidConfig)
	}

	credentials := 0
	if c.Token != "" {
		credentials++
	}
	if c.AppRole.supplied() {
		credentials++
	}
	if hasAuthMethod {
		credentials++
	}

	switch credentials {
	case 1:
		return nil
	case 0:
		return fmt.Errorf("%w: a static token or an approle is required", ErrInvalidConfig)
	default:
		// Which credential is in use must never be a guess.
		return fmt.Errorf("%w: %d credentials supplied, want exactly one", ErrInvalidConfig, credentials)
	}
}

// mountPoint returns the configured mount point, or the default.
func (c Config) mountPoint() string {
	if c.MountPoint == "" {
		return defaultMountPoint
	}
	return c.MountPoint
}
