package vault_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/zuksmaq/vault"
)

// appRole is the credential these tests log in with. Re-authentication is
// only possible with something to log in with.
var appRole = vault.AppRole{RoleID: "role-id", SecretID: "secret-id"}

// tokenIssuer answers each login with a fresh token, so a read carrying a
// re-authenticated token can be told apart from the one that provoked it.
// The first login issues "s.v1", the second "s.v2", and so on.
func tokenIssuer(t *testing.T) http.HandlerFunc {
	t.Helper()

	var issued atomic.Int64
	return func(w http.ResponseWriter, _ *http.Request) {
		writeToken(t, w, fmt.Sprintf("s.v%d", issued.Add(1)))
	}
}

// refuse answers as Vault does when a token is expired or a policy does
// not permit the read.
func refuse(t *testing.T, w http.ResponseWriter) {
	t.Helper()

	writeJSON(t, w, http.StatusForbidden, `{"errors":["permission denied"]}`)
}

func TestGetSecretsRetriesOnceAfterReauthenticating(t *testing.T) {
	t.Parallel()

	var reads atomic.Int64
	address, logins := newVault(t, tokenIssuer(t), func(w http.ResponseWriter, r *http.Request) {
		reads.Add(1)
		// The token construction logged in for has since expired.
		if r.Header.Get("X-Vault-Token") == "s.v1" {
			refuse(t, w)
			return
		}
		writeSecret(t, w, `{"username":"app"}`)
	})

	client, err := vault.New(vault.Config{Address: address, AppRole: appRole})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	got, err := client.GetSecrets(context.Background(), "app/config")
	if err != nil {
		t.Fatalf("GetSecrets() error = %v, want the read to survive an expired token", err)
	}
	if got["username"] != "app" {
		t.Errorf("GetSecrets()[username] = %q, want %q", got["username"], "app")
	}

	// One login at construction and one on the refusal.
	if want := int64(2); logins.Load() != want {
		t.Errorf("logins = %d, want %d", logins.Load(), want)
	}
	if want := int64(2); reads.Load() != want {
		t.Errorf("reads = %d, want %d — the refused read and one retry", reads.Load(), want)
	}
}

func TestGetSecretsPermissionDeniedAfterASecondRefusal(t *testing.T) {
	t.Parallel()

	var reads atomic.Int64
	address, logins := newVault(t, tokenIssuer(t), func(w http.ResponseWriter, _ *http.Request) {
		reads.Add(1)
		// A policy that does not allow the read refuses a fresh token too.
		refuse(t, w)
	})

	client, err := vault.New(vault.Config{Address: address, AppRole: appRole})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = client.GetSecrets(context.Background(), "app/config")
	if !errors.Is(err, vault.ErrPermissionDenied) {
		t.Fatalf("GetSecrets() error = %v, want %v", err, vault.ErrPermissionDenied)
	}

	if want := int64(2); logins.Load() != want {
		t.Errorf("logins = %d, want %d — an insufficient policy must not be retried forever", logins.Load(), want)
	}
	if want := int64(2); reads.Load() != want {
		t.Errorf("reads = %d, want %d", reads.Load(), want)
	}
}

func TestGetSecretsPermissionDeniedWithAStaticToken(t *testing.T) {
	t.Parallel()

	var reads atomic.Int64
	address, logins := newVault(t,
		func(http.ResponseWriter, *http.Request) {
			t.Error("login served, want none — a static token has nothing to log in with")
		},
		func(w http.ResponseWriter, _ *http.Request) {
			reads.Add(1)
			refuse(t, w)
		},
	)

	client, err := vault.New(vault.Config{Address: address, Token: "s.static"})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	_, err = client.GetSecrets(context.Background(), "app/config")
	if !errors.Is(err, vault.ErrPermissionDenied) {
		t.Fatalf("GetSecrets() error = %v, want %v", err, vault.ErrPermissionDenied)
	}

	if logins.Load() != 0 {
		t.Errorf("logins = %d, want 0", logins.Load())
	}
	if want := int64(1); reads.Load() != want {
		t.Errorf("reads = %d, want %d — there is nothing to log in with, so no retry", reads.Load(), want)
	}
}

func TestGetSecretsConcurrentReadersProduceOneLogin(t *testing.T) {
	t.Parallel()

	address, logins := newVault(t, tokenIssuer(t), func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") == "s.v1" {
			refuse(t, w)
			return
		}
		writeSecret(t, w, `{"username":"app"}`)
	})

	client, err := vault.New(vault.Config{Address: address, AppRole: appRole})
	if err != nil {
		t.Fatalf("New() error = %v", err)
	}

	// A start barrier so the readers meet the expired token together,
	// which is the case that would otherwise become a login storm.
	const readers = 20
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, readers)

	for i := range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			_, errs[i] = client.GetSecrets(context.Background(), "app/config")
		}()
	}
	close(start)
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("reader %d: GetSecrets() error = %v", i, err)
		}
	}

	// One login at construction, and one shared by every reader that met
	// the expired token — not one login each.
	if want := int64(2); logins.Load() != want {
		t.Errorf("logins = %d, want %d", logins.Load(), want)
	}
}
