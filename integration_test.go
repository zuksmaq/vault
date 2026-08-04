//go:build integration

package vault_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hashicorp/vault/api"
	tcvault "github.com/testcontainers/testcontainers-go/modules/vault"
	"github.com/zuksmaq/vault"
)

// vaultImage is the Vault the suite starts. It is pinned so that a change
// in the wire format arrives when the image is bumped deliberately rather
// than on whichever day the tag moves.
const vaultImage = "hashicorp/vault:1.20.4"

// rootToken is the dev-mode root token the container is started with, used
// to provision the fixtures a read-only client cannot create for itself. It
// is not the credential under test: the AppRole this suite reads with is
// issued by the running Vault, over its API.
const rootToken = "integration-root"

// readerPolicy is the only policy the AppRole holds, so a read anywhere
// outside it is refused by the real server.
const readerPolicy = `path "secret/data/app/*" { capabilities = ["read"] }`

// TestIntegration exercises the package against a real Vault, checking what
// a hand-written fake cannot: the real KV v2 response envelope, the real
// AppRole login response, and the real body of a refusal. One container
// serves every subtest.
func TestIntegration(t *testing.T) {
	ctx := context.Background()
	address := startVault(ctx, t)
	root := rootClient(t, address)

	enableAppRole(ctx, t, root)
	putPolicy(ctx, t, root, "reader", readerPolicy)
	roleID, secretID := createAppRole(ctx, t, root, "reader")

	putSecret(ctx, t, root, "app/config", map[string]any{
		"username": "app",
		"port":     8080,
		"tls":      true,
		"timeout":  "30s",
		"database": map[string]any{"host": "db", "port": 5432},
	})
	// A secret the policy does not cover, so that a refusal is provably
	// about the policy rather than about the secret not being there.
	putSecret(ctx, t, root, "other/config", map[string]any{"username": "other"})

	// Constructing the client logs in, so a real AppRole login response is
	// exercised by every subtest below.
	client, err := vault.New(vault.Config{
		Address: address,
		AppRole: vault.AppRole{RoleID: roleID, SecretID: secretID},
	})
	if err != nil {
		t.Fatalf("building client: %v", err)
	}

	t.Run("GetSecrets returns the whole secret", func(t *testing.T) {
		t.Parallel()

		secrets, err := client.GetSecrets(ctx, "app/config")
		if err != nil {
			t.Fatalf("GetSecrets: %v", err)
		}

		want := map[string]string{
			"username": "app",
			// A real Vault answers with the number it was given, so a port
			// must survive the round trip without becoming 8080.000000.
			"port":     "8080",
			"tls":      "true",
			"timeout":  "30s",
			"database": `{"host":"db","port":5432}`,
		}
		if len(secrets) != len(want) {
			t.Fatalf("got %d secret values, want %d", len(secrets), len(want))
		}
		for key, value := range want {
			if secrets[key] != value {
				t.Errorf("%s = %q, want %q", key, secrets[key], value)
			}
		}
	})

	t.Run("GetSecret returns one value", func(t *testing.T) {
		t.Parallel()

		port, err := client.GetSecret(ctx, "app/config", "port")
		if err != nil {
			t.Fatalf("GetSecret: %v", err)
		}
		if port != "8080" {
			t.Errorf("port = %q, want %q", port, "8080")
		}
	})

	t.Run("Unmarshal binds typed fields", func(t *testing.T) {
		t.Parallel()

		var cfg struct {
			Username string         `json:"username"`
			Port     int            `json:"port"`
			TLS      bool           `json:"tls"`
			Timeout  vault.Duration `json:"timeout"`
			Database struct {
				Host string `json:"host"`
				Port int    `json:"port"`
			} `json:"database"`
		}
		if err := client.Unmarshal(ctx, "app/config", &cfg); err != nil {
			t.Fatalf("Unmarshal: %v", err)
		}

		if cfg.Username != "app" {
			t.Errorf("Username = %q, want %q", cfg.Username, "app")
		}
		if cfg.Port != 8080 {
			t.Errorf("Port = %d, want 8080", cfg.Port)
		}
		if !cfg.TLS {
			t.Error("TLS = false, want true")
		}
		if time.Duration(cfg.Timeout) != 30*time.Second {
			t.Errorf("Timeout = %v, want 30s", time.Duration(cfg.Timeout))
		}
		if cfg.Database.Host != "db" || cfg.Database.Port != 5432 {
			t.Errorf("Database = %+v, want {db 5432}", cfg.Database)
		}
	})

	// A path with no secret at it answers 404 with an empty body, which a
	// fake can only be assumed to imitate.
	t.Run("a missing secret path is not found", func(t *testing.T) {
		t.Parallel()

		_, err := client.GetSecrets(ctx, "app/absent")
		if !errors.Is(err, vault.ErrNotFound) {
			t.Errorf("got %v, want ErrNotFound", err)
		}
	})

	t.Run("a refused read is permission denied", func(t *testing.T) {
		t.Parallel()

		// The policy covers app/ only, so this secret exists but is not
		// readable. Logging in again gains nothing, so the second refusal
		// is what the caller sees.
		_, err := client.GetSecrets(ctx, "other/config")
		if !errors.Is(err, vault.ErrPermissionDenied) {
			t.Errorf("got %v, want ErrPermissionDenied", err)
		}
	})
}

// startVault runs a dev-mode Vault for the duration of the test and returns
// its address. Dev mode mounts a KV v2 engine at secret/, which is the mount
// point this package defaults to.
func startVault(ctx context.Context, t *testing.T) string {
	t.Helper()

	container, err := tcvault.Run(ctx, vaultImage, tcvault.WithToken(rootToken))
	if err != nil {
		t.Fatalf("starting vault container: %v", err)
	}
	t.Cleanup(func() {
		if err := container.Terminate(context.Background()); err != nil {
			t.Logf("terminating vault container: %v", err)
		}
	})

	address, err := container.HttpHostAddress(ctx)
	if err != nil {
		t.Fatalf("resolving vault address: %v", err)
	}
	return address
}

// rootClient returns a privileged client for provisioning the fixtures.
// This package is read-only by design, so the setup a test needs is done
// with vault/api directly rather than through the code under test.
func rootClient(t *testing.T, address string) *api.Client {
	t.Helper()

	cfg := api.DefaultConfig()
	cfg.Address = address

	client, err := api.NewClient(cfg)
	if err != nil {
		t.Fatalf("building root client: %v", err)
	}
	client.SetToken(rootToken)
	return client
}

// enableAppRole mounts the AppRole auth method, which dev mode does not
// enable on its own.
func enableAppRole(ctx context.Context, t *testing.T, root *api.Client) {
	t.Helper()

	err := root.Sys().EnableAuthWithOptionsWithContext(ctx, "approle",
		&api.EnableAuthOptions{Type: "approle"})
	if err != nil {
		t.Fatalf("enabling approle auth: %v", err)
	}
}

// putPolicy writes a policy for a role to hold.
func putPolicy(ctx context.Context, t *testing.T, root *api.Client, name, rules string) {
	t.Helper()

	if err := root.Sys().PutPolicyWithContext(ctx, name, rules); err != nil {
		t.Fatalf("writing policy %q: %v", name, err)
	}
}

// createAppRole creates a role holding the policy of the same name, then
// retrieves its role ID and issues a secret ID over the API — so no
// credential is hard-coded here.
func createAppRole(ctx context.Context, t *testing.T, root *api.Client, name string) (roleID, secretID string) {
	t.Helper()

	rolePath := "auth/approle/role/" + name
	_, err := root.Logical().WriteWithContext(ctx, rolePath, map[string]any{
		"token_policies": name,
		"token_ttl":      "1h",
	})
	if err != nil {
		t.Fatalf("creating role %q: %v", name, err)
	}

	role, err := root.Logical().ReadWithContext(ctx, rolePath+"/role-id")
	if err != nil {
		t.Fatalf("reading role id: %v", err)
	}
	secret, err := root.Logical().WriteWithContext(ctx, rolePath+"/secret-id", nil)
	if err != nil {
		t.Fatalf("issuing secret id: %v", err)
	}

	roleID, ok := role.Data["role_id"].(string)
	if !ok {
		t.Fatalf("role id is %T, want string", role.Data["role_id"])
	}
	secretID, ok = secret.Data["secret_id"].(string)
	if !ok {
		t.Fatalf("secret id is %T, want string", secret.Data["secret_id"])
	}
	return roleID, secretID
}

// putSecret writes a secret to the KV v2 engine dev mode mounts at secret/.
func putSecret(ctx context.Context, t *testing.T, root *api.Client, path string, values map[string]any) {
	t.Helper()

	_, err := root.Logical().WriteWithContext(ctx, "secret/data/"+path,
		map[string]any{"data": values})
	if err != nil {
		t.Fatalf("writing secret %q: %v", path, err)
	}
}
