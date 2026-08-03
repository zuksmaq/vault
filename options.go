package vault

import (
	"log/slog"

	"github.com/hashicorp/vault/api"
)

// An Option configures optional client behaviour.
type Option func(*Client)

// WithLogger sends the client's diagnostics to logger. Without it the
// client writes nothing anywhere. Paths and outcomes are logged; secret
// values, secret keys and role IDs never are.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Client) {
		c.logger = logger
	}
}

// WithAuthMethod authenticates with auth instead of a credential this
// package models, for the cases it does not. It counts as the client's one
// credential, so the config must not supply another. This is the only part
// of the surface that exposes vault/api to a consumer.
func WithAuthMethod(auth api.AuthMethod) Option {
	return func(c *Client) {
		c.auth = auth
	}
}
