package vault

import "log/slog"

// An Option configures optional client behaviour.
type Option func(*Client)

// WithLogger sends the client's diagnostics to logger. Without it the
// client writes nothing anywhere. Paths and outcomes are logged; secret
// values, secret keys and role IDs never are.
func WithLogger(logger *slog.Logger) Option {
	return func(c *Client) {
		if logger != nil {
			c.logger = logger
		}
	}
}
