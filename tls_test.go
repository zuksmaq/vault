package vault_test

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/zuksmaq/vault"
)

// tlsServer starts a Vault answering over TLS with one secret, and returns
// its address and its own certificate as PEM. The certificate is signed by
// nobody a system root store knows, which is what makes it a fair stand-in
// for an internal CA.
func tlsServer(t *testing.T) (address string, caPEM []byte) {
	t.Helper()

	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeSecret(t, w, `{"username":"app"}`)
	}))
	t.Cleanup(srv.Close)

	caPEM = pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: srv.Certificate().Raw,
	})
	if caPEM == nil {
		t.Fatal("encoding the test server certificate as PEM")
	}
	return srv.URL, caPEM
}

// readOverTLS builds a client from cfg and reads a secret through it.
func readOverTLS(t *testing.T, cfg vault.Config, opts ...vault.Option) error {
	t.Helper()

	cfg.Token = "s.token"
	client, err := vault.New(cfg, opts...)
	if err != nil {
		return err
	}
	_, err = client.GetSecrets(context.Background(), "app/config")
	return err
}

func TestTLSVerifiesWithSuppliedCA(t *testing.T) {
	t.Parallel()

	address, caPEM := tlsServer(t)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("writing the ca file: %v", err)
	}

	tests := []struct {
		name string
		cfg  vault.Config
	}{
		{
			name: "as raw pem bytes",
			cfg:  vault.Config{Address: address, CACertPEM: caPEM},
		},
		{
			name: "as a file path",
			cfg:  vault.Config{Address: address, CACertPath: caFile},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			if err := readOverTLS(t, tt.cfg); err != nil {
				t.Fatalf("GetSecrets() over verified TLS error = %v", err)
			}
		})
	}
}

// TestTLSVerifiesByDefault is the other half of the pair: the same
// connection that succeeds with a CA must fail without one, or the test
// above would pass on a client that verifies nothing.
func TestTLSVerifiesByDefault(t *testing.T) {
	t.Parallel()

	address, _ := tlsServer(t)

	err := readOverTLS(t, vault.Config{Address: address})
	if err == nil {
		t.Fatal("GetSecrets() error = nil, want the certificate to be rejected")
	}

	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Errorf("GetSecrets() error = %v, want an unknown certificate authority", err)
	}
}

func TestTLSInsecureSkipVerify(t *testing.T) {
	t.Parallel()

	address, _ := tlsServer(t)

	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, nil))

	cfg := vault.Config{Address: address, InsecureSkipVerify: true}
	if err := readOverTLS(t, cfg, vault.WithLogger(logger)); err != nil {
		t.Fatalf("GetSecrets() with verification disabled error = %v", err)
	}

	// The warning is the whole point of the escape hatch being loud.
	if !strings.Contains(logged.String(), "level=WARN") {
		t.Errorf("disabling verification logged no warning:\n%s", logged.String())
	}
	if !strings.Contains(logged.String(), "verification") {
		t.Errorf("the warning does not say what was disabled:\n%s", logged.String())
	}
}

// TestTLSWarnsWhenTheEnvironmentDisablesVerification covers the route a
// whole environment opts out by. vault/api reads VAULT_SKIP_VERIFY itself,
// so nothing in the config says verification is off — the warning has to
// follow the connection's state, or this path is silent. Deciding the
// precedence between this and an explicit field is ticket 09; being loud
// about it is this ticket.
func TestTLSWarnsWhenTheEnvironmentDisablesVerification(t *testing.T) {
	t.Setenv("VAULT_SKIP_VERIFY", "true")

	address, _ := tlsServer(t)

	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, nil))

	if err := readOverTLS(t, vault.Config{Address: address}, vault.WithLogger(logger)); err != nil {
		t.Fatalf("GetSecrets() with verification disabled by the environment error = %v", err)
	}

	if !strings.Contains(logged.String(), "level=WARN") {
		t.Errorf("the environment disabled verification without a warning:\n%s", logged.String())
	}
}

// TestTLSWarnsOnlyWhenVerificationIsDisabled pins that the warning is not
// noise a caller learns to ignore.
func TestTLSWarnsOnlyWhenVerificationIsDisabled(t *testing.T) {
	t.Parallel()

	address, caPEM := tlsServer(t)

	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, nil))

	cfg := vault.Config{Address: address, CACertPEM: caPEM}
	if err := readOverTLS(t, cfg, vault.WithLogger(logger)); err != nil {
		t.Fatalf("GetSecrets() over verified TLS error = %v", err)
	}

	if strings.Contains(logged.String(), "level=WARN") {
		t.Errorf("verified TLS logged a warning:\n%s", logged.String())
	}
}

func TestTLSRejectsUnusableCA(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		cfg  vault.Config
	}{
		{
			name: "ca file does not exist",
			cfg:  vault.Config{CACertPath: filepath.Join(t.TempDir(), "absent.pem")},
		},
		{
			name: "ca pem is not a certificate",
			cfg:  vault.Config{CACertPEM: []byte("-----BEGIN CERTIFICATE-----\nnonsense\n")},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			tt.cfg.Address = "https://vault.example.test"
			tt.cfg.Token = "s.token"

			_, err := vault.New(tt.cfg)
			if !errors.Is(err, vault.ErrInvalidConfig) {
				t.Fatalf("New() error = %v, want %v", err, vault.ErrInvalidConfig)
			}
		})
	}
}
