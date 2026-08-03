// Package vault reads secrets from a HashiCorp Vault KV v2 secrets
// engine. It is read-only and always reads the latest version of a secret.
package vault

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/hashicorp/vault/api"
)

// Client reads secrets from one Vault instance. It is safe for concurrent
// use, and holds no resources that need releasing.
type Client struct {
	api        *api.Client
	mountPoint string
}

// New returns a client reading from the Vault the config describes.
func New(cfg Config) (*Client, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}

	apiCfg := api.DefaultConfig()
	apiCfg.Address = cfg.Address

	apiClient, err := api.NewClient(apiCfg)
	if err != nil {
		return nil, fmt.Errorf("building vault client: %w", err)
	}
	apiClient.SetToken(cfg.Token)

	return &Client{api: apiClient, mountPoint: cfg.mountPoint()}, nil
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
	return secrets, nil
}

// read returns the raw secret values stored at path.
func (c *Client) read(ctx context.Context, path string) (map[string]any, error) {
	secret, err := c.api.Logical().ReadWithContext(ctx, c.dataPath(path))
	if err != nil {
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
