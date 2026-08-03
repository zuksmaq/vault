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

// countingHandler records how many log records it is asked to handle. It
// implements slog.Handler outright rather than embedding one, so that
// records routed through With or WithGroup are still counted.
type countingHandler struct {
	records int
}

func (h *countingHandler) Enabled(context.Context, slog.Level) bool { return true }

func (h *countingHandler) Handle(context.Context, slog.Record) error {
	h.records++
	return nil
}

func (h *countingHandler) WithAttrs([]slog.Attr) slog.Handler { return h }

func (h *countingHandler) WithGroup(string) slog.Handler { return h }

// TestClientIsSilentWithoutLogger pins that a client given no logger
// writes nowhere at all — including the package-level default logger,
// which a library must never borrow.
func TestClientIsSilentWithoutLogger(t *testing.T) {
	counter := &countingHandler{}
	restore := slog.Default()
	slog.SetDefault(slog.New(counter))
	t.Cleanup(func() { slog.SetDefault(restore) })

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

// TestLoggerRecordsPathsButNeverSecrets pins both halves of the logging
// contract: a caller who opts in sees the path and the outcome, and
// enabling debug logging never leaks what Vault exists to protect.
func TestLoggerRecordsPathsButNeverSecrets(t *testing.T) {
	t.Parallel()

	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, &slog.HandlerOptions{Level: slog.LevelDebug}))

	client := newClient(t, vault.Config{}, func(w http.ResponseWriter, _ *http.Request) {
		writeSecret(t, w, `{"totallyDistinctKey":"totallyDistinctValue"}`)
	}, vault.WithLogger(logger))

	if _, err := client.GetSecrets(context.Background(), "app/config"); err != nil {
		t.Fatalf("GetSecrets() error = %v", err)
	}

	if !strings.Contains(logged.String(), "app/config") {
		t.Errorf("log records do not mention the secret path:\n%s", logged.String())
	}

	for _, secret := range []string{"totallyDistinctKey", "totallyDistinctValue"} {
		if strings.Contains(logged.String(), secret) {
			t.Errorf("log records contain %q:\n%s", secret, logged.String())
		}
	}
}
