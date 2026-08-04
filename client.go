// Package vault reads secrets from a HashiCorp Vault KV v2 secrets
// engine. It is read-only and always reads the latest version of a secret.
package vault

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"

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

	// tokenMu guards the token's lifecycle. Reads hold it for reading, so
	// they still run concurrently but no login can replace the token
	// mid-attempt; re-authentication holds it for writing. That is what
	// lets a refusal tell an expired token apart from one another reader
	// has already replaced, and so lets readers meeting one expired token
	// log in once between them rather than once each.
	tokenMu sync.RWMutex
}

// New returns a client reading from the Vault the config describes. When
// the credential is an AppRole it logs in before returning, so rejected
// credentials surface here rather than on the first read.
//
// The address, the CA and whether to verify certificates fall back to the
// environment variables the Vault CLI honours — VAULT_ADDR, VAULT_CACERT
// and VAULT_SKIP_VERIFY — when the config leaves them out. Anything the
// config states beats the environment.
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
	// The environment supplies what the config leaves out, so validation
	// judges the address the client will actually dial. vault/api reads the
	// same variable for itself; reading it here too is what lets a config
	// with no address at all be valid.
	addressFromConfig := cfg.Address != ""
	if !addressFromConfig {
		cfg.Address = os.Getenv(api.EnvVaultAddress)
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
	// DefaultConfig reads the environment, and a value it could not parse
	// is a misconfigured environment rather than a fault of Vault's.
	if apiCfg.Error != nil {
		return nil, fmt.Errorf("%w: %w", ErrInvalidConfig, apiCfg.Error)
	}
	apiCfg.Address = cfg.Address
	// VAULT_AGENT_ADDR outranks the address inside vault/api, so a config
	// that named an address has to clear it or the environment would win
	// after all.
	if addressFromConfig {
		apiCfg.AgentAddress = ""
	}

	// DefaultConfig has already read VAULT_CACERT and VAULT_SKIP_VERIFY from
	// the environment, which is the fallback layer. A CA supplied here
	// replaces the pool that read, so explicit configuration wins.
	if err := apiCfg.ConfigureTLS(&api.TLSConfig{
		CACert:      cfg.CACertPath,
		CACertBytes: cfg.CACertPEM,
	}); err != nil {
		return nil, fmt.Errorf("%w: configuring tls: %w", ErrInvalidConfig, err)
	}
	// Verification is the one setting the environment cannot be allowed to
	// have the last word on, and ConfigureTLS cannot express it: that only
	// ever switches verification off, never back on. So a config that has
	// decided either way is written straight onto the transport, over
	// whatever VAULT_SKIP_VERIFY put there.
	if cfg.InsecureSkipVerify != nil {
		// DefaultConfig always builds an *http.Transport today, so this
		// never fails. It is checked anyway because the alternative is a
		// panic, and because a future vault/api that wrapped its transport
		// would otherwise ignore a decision about verification silently.
		transport, ok := apiCfg.HttpClient.Transport.(*http.Transport)
		if !ok {
			return nil, fmt.Errorf("%w: cannot set certificate verification: vault/api supplied a %T", ErrInvalidConfig, apiCfg.HttpClient.Transport)
		}
		transport.TLSClientConfig.InsecureSkipVerify = *cfg.InsecureSkipVerify
	}
	// The warning follows the connection's actual state rather than this
	// config, so the environment's route out of verification is as loud as
	// the field's. Nothing suppresses it: the predecessor silenced the
	// equivalent warning, which is how services ended up unverified by
	// accident.
	if apiCfg.TLSConfig().InsecureSkipVerify {
		client.logger.WarnContext(context.Background(),
			"tls certificate verification disabled", "address", cfg.Address)
	}

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

// GetSecret returns the one secret value stored at path under key, coerced
// to a string. A key that the secret does not hold is ErrNotFound rather
// than an empty value.
func (c *Client) GetSecret(ctx context.Context, path, key string) (string, error) {
	data, err := c.read(ctx, path)
	if err != nil {
		return "", err
	}

	value, ok := data[key]
	if !ok {
		return "", fmt.Errorf("%w: no secret value at key %q in %q", ErrNotFound, key, path)
	}

	// A key name describes what the secret holds, so only the path is
	// logged.
	c.logger.DebugContext(ctx, "read secret value",
		"path", path, "mount", c.mountPoint)
	return coerce(value), nil
}

// read returns the raw secret values stored at path. Failures are
// returned rather than logged, so that a caller reports them once.
func (c *Client) read(ctx context.Context, path string) (map[string]any, error) {
	secret, usedToken, err := c.attempt(ctx, path)
	if isRefused(err) {
		// A static token cannot be renewed, so the refusal stands.
		if c.auth == nil {
			return nil, fmt.Errorf("%w: reading %q: %w", ErrPermissionDenied, path, err)
		}
		if loginErr := c.reauthenticate(ctx, usedToken); loginErr != nil {
			return nil, loginErr
		}

		secret, _, err = c.attempt(ctx, path)
		if isRefused(err) {
			// A fresh token was refused too, so the policy — not expiry —
			// is what denies this read. One retry, never a loop.
			return nil, fmt.Errorf("%w: reading %q: %w", ErrPermissionDenied, path, err)
		}
	}
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

// attempt reads path once, reporting the token the request carried. The
// token is held for reading across the whole request, so the token
// reported is provably the one Vault judged — without that, a login
// landing between capturing it and sending the request would make a
// refusal indistinguishable from one already recovered from.
func (c *Client) attempt(ctx context.Context, path string) (*api.Secret, string, error) {
	c.tokenMu.RLock()
	defer c.tokenMu.RUnlock()

	usedToken := c.api.Token()
	secret, err := c.api.Logical().ReadWithContext(ctx, c.dataPath(path))
	return secret, usedToken, err
}

// reauthenticate logs in again, unless another reader has already replaced
// the token usedToken identifies. Concurrent readers meeting one expired
// token therefore produce one login between them, not one each, per
// ADR-0002.
func (c *Client) reauthenticate(ctx context.Context, usedToken string) error {
	c.tokenMu.Lock()
	defer c.tokenMu.Unlock()

	if c.api.Token() != usedToken {
		return nil
	}
	return c.login(ctx)
}

// isRefused reports whether Vault refused the request. That is either an
// expired token or a policy that does not permit the read; which one it is
// only becomes clear after logging in again.
func isRefused(err error) bool {
	var respErr *api.ResponseError
	return errors.As(err, &respErr) && respErr.StatusCode == http.StatusForbidden
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
	// json.Marshal would escape <, > and & inside it, which mangles a URL
	// holding query parameters, so encoding is done with that off. An
	// encoder ends what it writes with a newline.
	var encoded bytes.Buffer
	enc := json.NewEncoder(&encoded)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(value)
	return strings.TrimSuffix(encoded.String(), "\n")
}
