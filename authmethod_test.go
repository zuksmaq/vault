package vault_test

import (
	"context"
	"errors"
	"net/http"
	"testing"

	"github.com/hashicorp/vault/api"
	"github.com/zuksmaq/vault"
)

// certAuth stands in for a credential this package does not model. It is
// the only test that imports hashicorp, because WithAuthMethod is the only
// part of the surface that exposes vault/api to a consumer.
type certAuth struct {
	token  string
	logins int
}

func (a *certAuth) Login(_ context.Context, client *api.Client) (*api.Secret, error) {
	a.logins++
	client.SetToken(a.token)
	return &api.Secret{Auth: &api.SecretAuth{ClientToken: a.token}}, nil
}

func TestWithAuthMethodSuppliesTheCredential(t *testing.T) {
	t.Parallel()

	var gotToken string
	address, _ := newVault(t,
		func(http.ResponseWriter, *http.Request) {
			t.Error("approle login served, want the supplied auth method to be used")
		},
		func(w http.ResponseWriter, r *http.Request) {
			gotToken = r.Header.Get("X-Vault-Token")
			writeSecret(t, w, `{"username":"app"}`)
		},
	)

	auth := &certAuth{token: "s.cert"}
	client, err := vault.New(vault.Config{Address: address}, vault.WithAuthMethod(auth))
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	if auth.logins != 1 {
		t.Errorf("logins = %d, want 1", auth.logins)
	}

	if _, err := client.GetSecrets(context.Background(), "app/config"); err != nil {
		t.Fatalf("GetSecrets() error = %v", err)
	}
	if gotToken != "s.cert" {
		t.Errorf("read token = %q, want the token the auth method issued", gotToken)
	}
}

func TestValidateAcceptsAConfigWhoseCredentialComesFromAnOption(t *testing.T) {
	t.Parallel()

	// A caller pre-flighting the config must not be told a setup New
	// accepts is invalid.
	cfg := vault.Config{Address: "https://vault.example.com"}
	if err := cfg.Validate(); err != nil {
		t.Errorf("Validate() error = %v, want nil", err)
	}
}

func TestWithAuthMethodIsAmbiguousAlongsideAConfigCredential(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  vault.Config
	}{
		{
			name: "alongside a static token",
			cfg:  vault.Config{Address: "https://vault.example.com", Token: "s.token"},
		},
		{
			name: "alongside an approle",
			cfg: vault.Config{
				Address: "https://vault.example.com",
				AppRole: vault.AppRole{RoleID: "role-id", SecretID: "secret-id"},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			_, err := vault.New(tt.cfg, vault.WithAuthMethod(&certAuth{token: "s.cert"}))
			if !errors.Is(err, vault.ErrInvalidConfig) {
				t.Fatalf("New() error = %v, want %v", err, vault.ErrInvalidConfig)
			}
		})
	}
}
