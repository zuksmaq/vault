package vault_test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/zuksmaq/vault"
)

// These tests set environment variables, so none of them call t.Parallel:
// the process environment is shared, and t.Setenv refuses a parallel test
// for exactly that reason.

// namedServer starts a Vault that answers every read with one secret
// naming the server, so a test can tell which of two addresses was used.
func namedServer(t *testing.T, name string) string {
	t.Helper()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		writeSecret(t, w, `{"server":"`+name+`"}`)
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

// readServerName reads the secret and reports which server answered.
func readServerName(t *testing.T, cfg vault.Config) (string, error) {
	t.Helper()

	cfg.Token = "s.token"
	client, err := vault.New(cfg)
	if err != nil {
		return "", err
	}
	secrets, err := client.GetSecrets(context.Background(), "app/config")
	if err != nil {
		return "", err
	}
	return secrets["server"], nil
}

func TestAddressFallsBackToTheEnvironment(t *testing.T) {
	pinVaultEnvironment(t)
	address := namedServer(t, "environment")
	t.Setenv("VAULT_ADDR", address)

	got, err := readServerName(t, vault.Config{})
	if err != nil {
		t.Fatalf("GetSecrets() error = %v", err)
	}
	if got != "environment" {
		t.Errorf("read from %q, want the server named by VAULT_ADDR", got)
	}
}

func TestConfiguredAddressBeatsTheEnvironment(t *testing.T) {
	pinVaultEnvironment(t)
	t.Setenv("VAULT_ADDR", namedServer(t, "environment"))

	got, err := readServerName(t, vault.Config{Address: namedServer(t, "config")})
	if err != nil {
		t.Fatalf("GetSecrets() error = %v", err)
	}
	if got != "config" {
		t.Errorf("read from %q, want the server named by the config", got)
	}
}

// TestConfiguredAddressBeatsTheAgentAddress covers the variable that
// outranks the address inside vault/api rather than alongside it, which is
// a second way the environment could have won.
func TestConfiguredAddressBeatsTheAgentAddress(t *testing.T) {
	pinVaultEnvironment(t)
	t.Setenv("VAULT_AGENT_ADDR", namedServer(t, "agent"))

	got, err := readServerName(t, vault.Config{Address: namedServer(t, "config")})
	if err != nil {
		t.Fatalf("GetSecrets() error = %v", err)
	}
	if got != "config" {
		t.Errorf("read from %q, want the server named by the config", got)
	}
}

func TestUnparseableEnvironmentValueIsInvalidConfig(t *testing.T) {
	pinVaultEnvironment(t)
	t.Setenv("VAULT_SKIP_VERIFY", "yeah-nah")

	cfg := vault.Config{Address: "https://vault.example.test", Token: "s.token"}
	if _, err := vault.New(cfg); !errors.Is(err, vault.ErrInvalidConfig) {
		t.Fatalf("New() error = %v, want %v", err, vault.ErrInvalidConfig)
	}
}

func TestAddressIsRequiredFromSomewhere(t *testing.T) {
	pinVaultEnvironment(t)

	_, err := vault.New(vault.Config{Token: "s.token"})
	if !errors.Is(err, vault.ErrInvalidConfig) {
		t.Fatalf("New() error = %v, want %v", err, vault.ErrInvalidConfig)
	}
}

func TestCAFallsBackToTheEnvironment(t *testing.T) {
	pinVaultEnvironment(t)
	address, caPEM := tlsServer(t)

	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, caPEM, 0o600); err != nil {
		t.Fatalf("writing the ca file: %v", err)
	}
	t.Setenv("VAULT_CACERT", caFile)

	if err := readOverTLS(t, vault.Config{Address: address}); err != nil {
		t.Fatalf("GetSecrets() verified against the environment's CA error = %v", err)
	}
}

// unrelatedCAPEM returns a self-signed CA that signed nothing on any test
// connection. httptest hands every TLS server it starts the same built-in
// certificate, so two test servers cannot stand in for two different CAs.
func unrelatedCAPEM(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating a key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "unrelated test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating a certificate: %v", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestConfiguredCABeatsTheEnvironment pins the precedence in both
// directions, because only the second half can tell "the config's CA was
// used" apart from "either CA would have done".
func TestConfiguredCABeatsTheEnvironment(t *testing.T) {
	pinVaultEnvironment(t)
	address, serverCAPEM := tlsServer(t)

	caFile := func(t *testing.T, name string, caPEM []byte) string {
		t.Helper()

		path := filepath.Join(t.TempDir(), name)
		if err := os.WriteFile(path, caPEM, 0o600); err != nil {
			t.Fatalf("writing the ca file: %v", err)
		}
		return path
	}

	t.Run("the config's CA verifies where the environment's would not", func(t *testing.T) {
		t.Setenv("VAULT_CACERT", caFile(t, "unrelated.pem", unrelatedCAPEM(t)))

		if err := readOverTLS(t, vault.Config{Address: address, CACertPEM: serverCAPEM}); err != nil {
			t.Fatalf("GetSecrets() verified against the config's CA error = %v", err)
		}
	})

	t.Run("the config's CA is used even when the environment's is the good one", func(t *testing.T) {
		t.Setenv("VAULT_CACERT", caFile(t, "server.pem", serverCAPEM))

		err := readOverTLS(t, vault.Config{Address: address, CACertPEM: unrelatedCAPEM(t)})
		if err == nil {
			t.Fatal("GetSecrets() error = nil, want the config's CA to have replaced the environment's")
		}

		var unknownAuthority x509.UnknownAuthorityError
		if !errors.As(err, &unknownAuthority) {
			t.Errorf("GetSecrets() error = %v, want an unknown certificate authority", err)
		}
	})
}

func TestEnvironmentDisablesVerification(t *testing.T) {
	pinVaultEnvironment(t)
	t.Setenv("VAULT_SKIP_VERIFY", "true")

	address, _ := tlsServer(t)

	// No CA anywhere, so this read can only succeed unverified.
	if err := readOverTLS(t, vault.Config{Address: address}); err != nil {
		t.Fatalf("GetSecrets() with verification disabled by the environment error = %v", err)
	}
}

// TestConfiguredVerificationBeatsTheEnvironment is the pair that matters
// most: a service that has decided it needs verification keeps it, whatever
// the deployment manifests say. vault/api cannot express this on its own —
// its ConfigureTLS only ever switches verification off.
func TestConfiguredVerificationBeatsTheEnvironment(t *testing.T) {
	pinVaultEnvironment(t)
	t.Setenv("VAULT_SKIP_VERIFY", "true")

	address, _ := tlsServer(t)

	var logged bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&logged, nil))

	verify := false
	cfg := vault.Config{Address: address, InsecureSkipVerify: &verify}
	err := readOverTLS(t, cfg, vault.WithLogger(logger))
	if err == nil {
		t.Fatal("GetSecrets() error = nil, want the certificate to be rejected")
	}

	var unknownAuthority x509.UnknownAuthorityError
	if !errors.As(err, &unknownAuthority) {
		t.Errorf("GetSecrets() error = %v, want an unknown certificate authority", err)
	}

	// The warning tracks the connection, so an override that restored
	// verification must not leave a warning claiming otherwise.
	if strings.Contains(logged.String(), "level=WARN") {
		t.Errorf("verification was restored but a warning was logged anyway:\n%s", logged.String())
	}
}

// The other direction of the pointer — an explicit skip with no variable
// set — is TestTLSInsecureSkipVerify in tls_test.go.
