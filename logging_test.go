package vault_test

import (
	"bytes"
	"context"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/zuksmaq/vault"
)

// countingHandler records how many log records it is asked to handle.
type countingHandler struct {
	slog.Handler
	records int
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *countingHandler) Handle(_ context.Context, r slog.Record) error {
	h.records++
	return nil
}

// TestClientIsSilentWithoutLogger pins that a client given no logger
// writes nowhere at all — including the package-level default logger,
// which a library must never borrow.
func TestClientIsSilentWithoutLogger(t *testing.T) {
	counter := &countingHandler{Handler: slog.NewTextHandler(&bytes.Buffer{}, nil)}
	slog.SetDefault(slog.New(counter))

	client := newClient(t, vault.Config{}, func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "missing") {
			writeJSON(t, w, http.StatusNotFound, `{"errors":[]}`)
			return
		}
		writeSecret(t, w, `{"username":"app"}`)
	})

	if _, err := client.GetSecrets(context.Background(), "app/config"); err != nil {
		t.Fatalf("GetSecrets() error = %v", err)
	}
	if _, err := client.GetSecrets(context.Background(), "app/missing"); err == nil {
		t.Fatal("GetSecrets() error = nil, want an error")
	}

	if counter.records != 0 {
		t.Errorf("wrote %d log records without a logger, want 0", counter.records)
	}
}

// TestLoggerNeverRecordsSecrets pins that enabling debug logging does not
// leak the things Vault exists to protect.
func TestLoggerNeverRecordsSecrets(t *testing.T) {
	t.Parallel()

	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))

	client := newClient(t, vault.Config{}, func(w http.ResponseWriter, _ *http.Request) {
		writeSecret(t, w, `{"totallyDistinctKey":"totallyDistinctValue"}`)
	}, vault.WithLogger(logger))

	if _, err := client.GetSecrets(context.Background(), "app/config"); err != nil {
		t.Fatalf("GetSecrets() error = %v", err)
	}

	if logged.Len() == 0 {
		t.Fatal("logger recorded nothing, so this test would pass vacuously")
	}

	for _, secret := range []string{"totallyDistinctKey", "totallyDistinctValue"} {
		if strings.Contains(logged.String(), secret) {
			t.Errorf("log records contain %q:\n%s", secret, logged.String())
		}
	}
}

// TestLoggerRecordsThePath pins the other half: paths and outcomes are
// exactly what a caller enabling debug logging is entitled to see.
func TestLoggerRecordsThePath(t *testing.T) {
	t.Parallel()

	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))

	client := newClient(t, vault.Config{}, func(w http.ResponseWriter, _ *http.Request) {
		writeSecret(t, w, `{"username":"app"}`)
	}, vault.WithLogger(logger))

	if _, err := client.GetSecrets(context.Background(), "app/config"); err != nil {
		t.Fatalf("GetSecrets() error = %v", err)
	}

	if !strings.Contains(logged.String(), "app/config") {
		t.Errorf("log records do not mention the secret path:\n%s", logged.String())
	}
}
