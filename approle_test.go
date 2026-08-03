package vault_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zuksmaq/vault"
)

// loginRequest is the body Vault expects at an AppRole login endpoint.
type loginRequest struct {
	RoleID   string `json:"role_id"`
	SecretID string `json:"secret_id"`
}

// newVault starts a Vault answering logins with login and reads with read,
// and returns it alongside a count of the logins it served.
func newVault(t *testing.T, login, read http.HandlerFunc) (address string, logins *int) {
	t.Helper()

	count := 0
	mux := http.NewServeMux()
	mux.HandleFunc("/v1/auth/approle/login", func(w http.ResponseWriter, r *http.Request) {
		count++
		login(w, r)
	})
	mux.HandleFunc("/v1/secret/data/", read)

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return srv.URL, &count
}

// writeToken answers a login with token as the issued token.
func writeToken(t *testing.T, w http.ResponseWriter, token string) {
	t.Helper()

	writeJSON(t, w, http.StatusOK,
		`{"auth":{"client_token":"`+token+`","lease_duration":3600,"renewable":true}}`)
}

func TestNewLogsInWithAppRole(t *testing.T) {
	t.Parallel()

	var got loginRequest
	var gotToken string
	address, logins := newVault(t,
		func(w http.ResponseWriter, r *http.Request) {
			if err := json.NewDecoder(r.Body).Decode(&got); err != nil {
				t.Errorf("decoding login request: %v", err)
			}
			writeToken(t, w, "s.issued")
		},
		func(w http.ResponseWriter, r *http.Request) {
			gotToken = r.Header.Get("X-Vault-Token")
			writeSecret(t, w, `{"username":"app"}`)
		},
	)

	client, err := vault.New(vault.Config{
		Address: address,
		AppRole: vault.AppRole{RoleID: "role-id", SecretID: "secret-id"},
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if *logins != 1 {
		t.Errorf("logins = %d, want 1", *logins)
	}
	want := loginRequest{RoleID: "role-id", SecretID: "secret-id"}
	if got != want {
		t.Errorf("login request = %+v, want %+v", got, want)
	}

	if _, err := client.GetSecrets(context.Background(), "app/config"); err != nil {
		t.Fatalf("GetSecrets() error = %v", err)
	}
	if gotToken != "s.issued" {
		t.Errorf("read token = %q, want the token the login issued", gotToken)
	}
}

func TestNewRejectsRefusedAppRole(t *testing.T) {
	t.Parallel()

	address, _ := newVault(t,
		func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusBadRequest, `{"errors":["invalid role or secret id"]}`)
		},
		func(w http.ResponseWriter, _ *http.Request) {
			t.Error("read served, want no read after a refused login")
			writeSecret(t, w, `{}`)
		},
	)

	_, err := vault.New(vault.Config{
		Address: address,
		AppRole: vault.AppRole{RoleID: "role-id", SecretID: "wrong"},
	})
	if !errors.Is(err, vault.ErrAuthFailed) {
		t.Fatalf("New() error = %v, want %v", err, vault.ErrAuthFailed)
	}
}

func TestNewReportsUnavailableVaultAtLogin(t *testing.T) {
	t.Parallel()

	address, _ := newVault(t,
		func(w http.ResponseWriter, _ *http.Request) {
			writeJSON(t, w, http.StatusServiceUnavailable, `{"errors":["vault is sealed"]}`)
		},
		func(http.ResponseWriter, *http.Request) {},
	)

	_, err := vault.New(vault.Config{
		Address: address,
		AppRole: vault.AppRole{RoleID: "role-id", SecretID: "secret-id"},
	})
	if !errors.Is(err, vault.ErrUnavailable) {
		t.Fatalf("New() error = %v, want %v", err, vault.ErrUnavailable)
	}
}
