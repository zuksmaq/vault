package vault

import "fmt"

// defaultMountPoint is where the KV v2 secrets engine is mounted unless a
// config says otherwise.
const defaultMountPoint = "secret"

// Config describes the Vault instance to read from and the credential to
// read with.
type Config struct {
	// Address is the base URL of the Vault instance, for example
	// https://vault.example.com. It falls back to VAULT_ADDR when empty,
	// which is how one build runs against several environments.
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

	// CACertPath is the path to a PEM file holding the CA that signed the
	// Vault's certificate. It takes precedence over CACertPEM, and both
	// take precedence over VAULT_CACERT.
	CACertPath string

	// CACertPEM is that same CA as raw PEM bytes, so a pod can pass the
	// service CA already mounted into it with no file to manage.
	CACertPEM []byte

	// InsecureSkipVerify stops the client verifying the Vault's
	// certificate, which leaves the connection open to interception. It is
	// named as crypto/tls names it so that it reads as alarming in review,
	// and supplying the CA above is the better answer. Turning it on logs a
	// warning through the supplied logger.
	//
	// It is a pointer so that all three answers can be told apart: nil
	// leaves the decision to VAULT_SKIP_VERIFY, and verifies when that is
	// unset too, while a value set either way beats that variable — a
	// service that has decided it needs verification keeps it whatever the
	// deployment manifests say.
	InsecureSkipVerify *bool
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
// WithAuthMethod carries its credential outside the config, and an address
// may arrive from VAULT_ADDR, so New — which fills both in first — is the
// authority on whether either was supplied at all.
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
