package vault_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zuksmaq/vault"
)

// kvEnvelope writes the KV v2 read response envelope around the given
// secret body.
func kvEnvelope(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	if _, err := w.Write([]byte(`{"data":{"data":` + body + `,"metadata":{"version":1}}}`)); err != nil {
		t.Errorf("writing response: %v", err)
	}
}

func TestGetSecretsReadsValues(t *testing.T) {
	t.Parallel()

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		kvEnvelope(t, w, `{"username":"app","password":"hunter2"}`)
	}))
	defer srv.Close()

	client, err := vault.New(vault.Config{Address: srv.URL, Token: "s.token"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got, err := client.GetSecrets(context.Background(), "app/config")
	if err != nil {
		t.Fatalf("GetSecrets() error = %v", err)
	}

	if want := "/v1/secret/data/app/config"; gotPath != want {
		t.Errorf("request path = %q, want %q", gotPath, want)
	}

	want := map[string]string{"username": "app", "password": "hunter2"}
	if len(got) != len(want) {
		t.Fatalf("GetSecrets() = %v, want %v", got, want)
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("GetSecrets()[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func TestGetSecretsUsesConfiguredMountPoint(t *testing.T) {
	t.Parallel()

	var gotPath string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		kvEnvelope(t, w, `{"username":"app"}`)
	}))
	defer srv.Close()

	client, err := vault.New(vault.Config{
		Address:    srv.URL,
		MountPoint: "kv",
		Token:      "s.token",
	})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err := client.GetSecrets(context.Background(), "app/config"); err != nil {
		t.Fatalf("GetSecrets() error = %v", err)
	}

	if want := "/v1/kv/data/app/config"; gotPath != want {
		t.Errorf("request path = %q, want %q", gotPath, want)
	}
}

func TestGetSecretsCoercesNonStringValues(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		kvEnvelope(t, w, `{"port":8080,"debug":true,"limits":{"max":10},"hosts":["a","b"]}`)
	}))
	defer srv.Close()

	client, err := vault.New(vault.Config{Address: srv.URL, Token: "s.token"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got, err := client.GetSecrets(context.Background(), "app/config")
	if err != nil {
		t.Fatalf("GetSecrets() error = %v", err)
	}

	want := map[string]string{
		"port":   "8080",
		"debug":  "true",
		"limits": `{"max":10}`,
		"hosts":  `["a","b"]`,
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("GetSecrets()[%q] = %q, want %q", k, got[k], v)
		}
	}
}

func TestGetSecretsMissingSecretPath(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusNotFound)
		if _, err := w.Write([]byte(`{"errors":[]}`)); err != nil {
			t.Errorf("writing response: %v", err)
		}
	}))
	defer srv.Close()

	client, err := vault.New(vault.Config{Address: srv.URL, Token: "s.token"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	if _, err := client.GetSecrets(context.Background(), "app/missing"); !errors.Is(err, vault.ErrNotFound) {
		t.Fatalf("GetSecrets() error = %v, want %v", err, vault.ErrNotFound)
	}
}

func TestGetSecretsUnexpectedResponse(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{name: "not a kv v2 envelope", body: `{"data":{"username":"app"}}`},
		{name: "data is not an object", body: `{"data":{"data":"nonsense"}}`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				if _, err := w.Write([]byte(tt.body)); err != nil {
					t.Errorf("writing response: %v", err)
				}
			}))
			defer srv.Close()

			client, err := vault.New(vault.Config{Address: srv.URL, Token: "s.token"})
			if err != nil {
				t.Fatalf("New() error = %v", err)
			}

			_, err = client.GetSecrets(context.Background(), "app/config")
			if !errors.Is(err, vault.ErrUnexpectedResponse) {
				t.Fatalf("GetSecrets() error = %v, want %v", err, vault.ErrUnexpectedResponse)
			}
		})
	}
}
