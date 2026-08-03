// Package vault reads secrets from a HashiCorp Vault KV v2 secrets
// engine. It is read-only and always reads the latest version of a secret.
package vault

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/hashicorp/vault/api"
	"github.com/hashicorp/vault/api/auth/approle"
)

// Client reads secrets from one Vault instance. It is safe for concurrent
// use, and holds no resources that need releasing.
type Client struct {
	api        *api.Client
	mountPoint string
	logger     *slog.Logger

	// auth is how the client earns a token, and is nil when a static token
	// was supplied — there is then nothing to log in with.
	auth api.AuthMethod
}

// New returns a client reading from the Vault the config describes. When
// the credential is an AppRole it logs in before returning, so rejected
// credentials surface here rather than on the first read.
func New(cfg Config, opts ...Option) (*Client, error) {
	client := &Client{
		mountPoint: cfg.mountPoint(),
		// A library writes nothing until its caller asks it to, and
		// never borrows the package-level default logger.
		logger: slog.New(slog.DiscardHandler),
	}
	// Options are applied before the config is validated, because an
	// option may itself be the credential the config is missing.
	for _, opt := range opts {
		opt(client)
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	// The config cannot see an auth method supplied by an option, so
	// whether exactly one credential was supplied is settled here.
	switch hasConfigCredential := cfg.Token != "" || cfg.AppRole.supplied(); {
	case hasConfigCredential && client.auth != nil:
		return nil, fmt.Errorf("%w: an auth method and a config credential were both supplied, want one", ErrInvalidConfig)
	case !hasConfigCredential && client.auth == nil:
		return nil, fmt.Errorf("%w: a static token or an approle is required", ErrInvalidConfig)
	}

	apiCfg := api.DefaultConfig()
	apiCfg.Address = cfg.Address

	apiClient, err := api.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("building vault client: %w", err)
	}
	client.api = apiClient

	if cfg.Token != "" {
		apiClient.SetToken(cfg.Token)
		return client, nil
	}

	if client.auth == nil {
		auth, err := approle.NewAppRoleAuth(cfg.AppRole.RoleID,
			&approle.SecretID{FromString: cfg.AppRole.SecretID})
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, err)
		}
		client.auth = auth
	}

	// New takes no context, so construction cannot be cancelled.
	if err := client.login(context.Background()); err != nil {
		return nil, err
	}
	return client, nil
}

// login exchanges the client's credential for a fresh token, which
// vault/api stores for subsequent requests.
func (c *Client) login(ctx context.Context) error {
	if _, err := c.api.Auth().Login(ctx, c.auth); err != nil {
		var respErr *api.ResponseError
		switch {
		case isUnavailable(err):
			// A sealed or overloaded Vault refuses a login too, which is
			// not the same as a credential it rejected.
			return fmt.Errorf("%w: logging in: %w", ErrUnavailable, err)
		case errors.As(err, &respErr):
			return fmt.Errorf("%w: logging in: %w", ErrAuthFailed, err)
		default:
			// Vault never answered, so it never rejected anything. The
			// failure is wrapped intact so a timeout still looks like one.
			return fmt.Errorf("logging in: %w", err)
		}
	}

	// The role ID identifies the credential, so the outcome is logged
	// without it.
	c.logger.DebugContext(ctx, "logged in")
	return nil
}

// GetSecrets returns every secret value at path, coerced to a string. The
// path is given without the mount point and without KV v2's data segment.
func (c *Client) GetSecrets(ctx context.Context, path string) (map[string]string, error) {
	data, err := c.read(ctx, path)
	if err != nil {
		return nil, err
	}

	secrets := make(map[string]string, len(data))
	for key, value := range data {
		secrets[key] = coerce(value)
	}

	// The count is safe to log; the keys it counts are not.
	c.logger.DebugContext(ctx, "read secret",
		"path", path, "mount", c.mountPoint, "values", len(secrets))
	return secrets, nil
}

// read returns the raw secret values stored at path. Failures are
// returned rather than logged, so that a caller reports them once.
func (c *Client) read(ctx context.Context, path string) (map[string]any, error) {
	secret, err := c.api.Logical().ReadWithContext(ctx, c.dataPath(path))
	if err != nil {
		// A failure Vault owns is worth retrying; a transport failure is
		// wrapped intact so a timeout still looks like a timeout.
		if isUnavailable(err) {
			return nil, fmt.Errorf("%w: reading %q: %w", ErrUnavailable, path, err)
		}
		return nil, fmt.Errorf("reading %q: %w", path, err)
	}
	if secret == nil {
		return nil, fmt.Errorf("%w: no secret at %q", ErrNotFound, path)
	}

	raw, ok := secret.Data["data"]
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a kv v2 secret", ErrUnexpectedResponse, path)
	}
	// A deleted secret keeps its metadata, so Vault answers with a null
	// body rather than nothing at all.
	if raw == nil {
		return nil, fmt.Errorf("%w: no secret at %q", ErrNotFound, path)
	}

	data, ok := raw.(map[string]any)
	if !ok {
		return nil, fmt.Errorf("%w: %q is not a kv v2 secret", ErrUnexpectedResponse, path)
	}
	return data, nil
}

// isUnavailable reports whether err is a failure Vault answered with and
// may recover from, as opposed to a transport failure or a refusal.
func isUnavailable(err error) bool {
	var respErr *api.ResponseError
	return errors.As(err, &respErr) && isVaultSideFailure(respErr.StatusCode)
}

// isVaultSideFailure reports whether status describes a failure Vault
// owns, which vault/api has already retried and which may therefore be
// worth retrying again. It deliberately mirrors what that library treats
// as transient: 501 means Vault will never serve the request, so it is
// not retried there and is not a temporary failure here.
func isVaultSideFailure(status int) bool {
	switch status {
	case http.StatusPreconditionFailed, http.StatusTooManyRequests:
		// A stale read on a performance replica, and rate limiting.
		return true
	case http.StatusNotImplemented:
		return false
	default:
		return status >= http.StatusInternalServerError
	}
}

// dataPath assembles the full read path for a secret path.
func (c *Client) dataPath(path string) string {
	return fmt.Sprintf("%s/data/%s", c.mountPoint, path)
}

// coerce renders a secret value as a string: strings pass through, and
// everything else keeps its JSON form.
func coerce(value any) string {
	if s, ok := value.(string); ok {
		return s
	}

	// The value was decoded from JSON, so it can always be encoded again.
	encoded, _ := json.Marshal(value)
	return string(encoded)
}
