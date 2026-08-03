package vault_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/zuksmaq/vault"
)

// newClient starts a Vault answering with handler and returns a client
// pointed at it.
func newClient(t *testing.T, cfg vault.Config, handler http.HandlerFunc) *vault.Client {
	t.Helper()

	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)

	cfg.Address = srv.URL
	cfg.Token = "s.token"

	client, err := vault.New(cfg)
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}
	return client
}

// writeJSON answers with body as a JSON response.
func writeJSON(t *testing.T, w http.ResponseWriter, status int, body string) {
	t.Helper()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if _, err := w.Write([]byte(body)); err != nil {
		t.Errorf("writing response: %v", err)
	}
}

// writeSecret answers with the KV v2 read envelope around body.
func writeSecret(t *testing.T, w http.ResponseWriter, body string) {
	t.Helper()

	writeJSON(t, w, http.StatusOK, `{"data":{"data":`+body+`,"metadata":{"version":1}}}`)
}

func TestGetSecretsReadsValues(t *testing.T) {
	t.Parallel()

	var gotPath string
	client := newClient(t, vault.Config{}, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		writeSecret(t, w, `{"username":"app","password":"hunter2"}`)
	})

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
	client := newClient(t, vault.Config{MountPoint: "kv"}, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		writeSecret(t, w, `{"username":"app"}`)
	})

	if _, err := client.GetSecrets(context.Background(), "app/config"); err != nil {
		t.Fatalf("GetSecrets() error = %v", err)
	}

	if want := "/v1/kv/data/app/config"; gotPath != want {
		t.Errorf("request path = %q, want %q", gotPath, want)
	}
}

func TestGetSecretsCoercesNonStringValues(t *testing.T) {
	t.Parallel()

	client := newClient(t, vault.Config{}, func(w http.ResponseWriter, _ *http.Request) {
		writeSecret(t, w, `{"port":8080,"debug":true,"limits":{"max":10},"hosts":["a","b"]}`)
	})

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

func TestGetSecretsNotFound(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		body string
	}{
		{
			name: "secret path does not exist",
			body: `{"errors":[]}`,
		},
		{
			name: "secret was deleted",
			body: `{"data":{"data":null,"metadata":{"deletion_time":"2026-01-01T00:00:00Z","version":1}}}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			client := newClient(t, vault.Config{}, func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(t, w, http.StatusNotFound, tt.body)
			})

			_, err := client.GetSecrets(context.Background(), "app/missing")
			if !errors.Is(err, vault.ErrNotFound) {
				t.Fatalf("GetSecrets() error = %v, want %v", err, vault.ErrNotFound)
			}
		})
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

			client := newClient(t, vault.Config{}, func(w http.ResponseWriter, _ *http.Request) {
				writeJSON(t, w, http.StatusOK, tt.body)
			})

			_, err := client.GetSecrets(context.Background(), "app/config")
			if !errors.Is(err, vault.ErrUnexpectedResponse) {
				t.Fatalf("GetSecrets() error = %v, want %v", err, vault.ErrUnexpectedResponse)
			}
		})
	}
}
