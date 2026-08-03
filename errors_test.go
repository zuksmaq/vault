package vault_test

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zuksmaq/vault"
)

func TestGetSecretsServerFailureIsUnavailable(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		status int
	}{
		{name: "internal server error", status: http.StatusInternalServerError},
		{name: "bad gateway", status: http.StatusBadGateway},
		{name: "service unavailable", status: http.StatusServiceUnavailable},
		{name: "sealed", status: http.StatusServiceUnavailable},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := newClient(t, vault.Config{}, func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(t, w, tt.status, `{"errors":["vault is sealed"]}`)
			})

			_, err := client.GetSecrets(context.Background(), "app/config")
			if !errors.Is(err, vault.ErrUnavailable) {
				t.Fatalf("GetSecrets() error = %v, want %v", err, vault.ErrUnavailable)
			}
		})
	}
}

// TestGetSecretsTransportFailureKeepsUnderlyingError pins that a
// transport failure is wrapped rather than flattened into a sentinel, so
// a cancellation still looks like a cancellation to the caller. This is
// the deliberate departure from the Python package, whose catch-all
// connection error made every failure look like a network problem.
func TestGetSecretsTransportFailureKeepsUnderlyingError(t *testing.T) {
	t.Parallel()

	client := newClient(t, vault.Config{}, func(w http.ResponseWriter, _ *http.Request) {
		writeSecret(t, w, `{"username":"app"}`)
	})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := client.GetSecrets(ctx, "app/config")
	if err == nil {
		t.Fatal("GetSecrets() error = nil, want an error")
	}

	if !errors.Is(err, context.Canceled) {
		t.Errorf("errors.Is(err, context.Canceled) = false, want true; err = %v", err)
	}

	// A transport failure is not a Vault-side failure, so it must not
	// claim to be one.
	if errors.Is(err, vault.ErrUnavailable) {
		t.Error("a cancelled request reported itself as vault being unavailable")
	}
}

// TestGetSecretsUnreachableVaultKeepsNetworkError pins that failing to
// reach Vault at all stays inspectable as a network error rather than
// collapsing into a sentinel.
func TestGetSecretsUnreachableVaultKeepsNetworkError(t *testing.T) {
	t.Parallel()

	// A server that is closed before use gives an address nothing is
	// listening on.
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Close()

	client, err := vault.New(vault.Config{Address: srv.URL, Token: "s.token"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = client.GetSecrets(context.Background(), "app/config")
	if err == nil {
		t.Fatal("GetSecrets() error = nil, want an error")
	}

	var opErr *net.OpError
	if !errors.As(err, &opErr) {
		t.Errorf("errors.As(err, *net.OpError) = false, want true; err = %v", err)
	}

	if errors.Is(err, vault.ErrUnavailable) {
		t.Error("an unreachable vault reported itself as a vault-side failure")
	}
}

// TestSentinelsAreDistinct guards against a catch-all sentinel quietly
// swallowing unrelated failures.
func TestSentinelsAreDistinct(t *testing.T) {
	t.Parallel()

	sentinels := map[string]error{
		"ErrInvalidConfig":      vault.ErrInvalidConfig,
		"ErrNotFound":           vault.ErrNotFound,
		"ErrUnexpectedResponse": vault.ErrUnexpectedResponse,
		"ErrUnavailable":        vault.ErrUnavailable,
	}

	for name, err := range sentinels {
		for otherName, other := range sentinels {
			if name == otherName {
				continue
			}
			if errors.Is(err, other) {
				t.Errorf("errors.Is(%s, %s) = true, want false", name, otherName)
			}
		}
	}
}
