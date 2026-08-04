package vault_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"time"

	"github.com/zuksmaq/vault"
)

// An unattended service authenticates with an AppRole, which this package
// logs in with at construction and logs in again when the token expires.
func ExampleNew() {
	client, err := vault.New(vault.Config{
		Address: "https://vault.example.com",
		AppRole: vault.AppRole{
			RoleID:   os.Getenv("APP_ROLE_ID"),
			SecretID: os.Getenv("APP_SECRET_ID"),
		},
	}, vault.WithLogger(slog.New(slog.NewTextHandler(os.Stderr, nil))))
	if err != nil {
		// A rejected credential or an unusable config fails here rather
		// than on the first read.
		fmt.Println(err)
		return
	}

	secrets, err := client.GetSecrets(context.Background(), "app/config")
	if err != nil {
		fmt.Println(err)
		return
	}
	fmt.Println(len(secrets))
}

// A static token suits local work with a token copied from the Vault UI.
// The address is left to VAULT_ADDR, the variable the Vault CLI honours.
func ExampleNew_staticToken() {
	client, err := vault.New(vault.Config{Token: os.Getenv("VAULT_TOKEN")})
	if err != nil {
		fmt.Println(err)
		return
	}
	_ = client
}

// A Vault that mounts its KV v2 engine somewhere other than "secret" needs
// the mount point named. Secret paths stay relative to it, and never
// include KV v2's data segment.
func ExampleNew_mountPoint() {
	client, err := vault.New(vault.Config{
		Address:    "https://vault.example.com",
		MountPoint: "platform",
		Token:      os.Getenv("VAULT_TOKEN"),
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	// Reads "platform/data/app/config".
	_, err = client.GetSecrets(context.Background(), "app/config")
	fmt.Println(err)
}

// An internal CA can be supplied as raw PEM bytes, so a pod passes the
// service CA already mounted into it with no file to manage.
func ExampleNew_internalCA() {
	ca, err := os.ReadFile("/var/run/secrets/kubernetes.io/serviceaccount/service-ca.crt")
	if err != nil {
		fmt.Println(err)
		return
	}

	client, err := vault.New(vault.Config{
		Address:   "https://vault.example.com",
		CACertPEM: ca,
		AppRole: vault.AppRole{
			RoleID:   os.Getenv("APP_ROLE_ID"),
			SecretID: os.Getenv("APP_SECRET_ID"),
		},
	})
	if err != nil {
		fmt.Println(err)
		return
	}
	_ = client
}

// Every secret value at a path arrives as a string, whatever its JSON
// type: a number keeps its literal form, and an object becomes compact
// JSON.
func ExampleClient_GetSecrets() {
	client, err := vault.New(vault.Config{
		Address: "https://vault.example.com",
		Token:   os.Getenv("VAULT_TOKEN"),
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	secrets, err := client.GetSecrets(context.Background(), "app/config")
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(secrets["username"], secrets["port"])
}

// One secret value is read by its key. A key the secret does not hold is
// ErrNotFound rather than an empty string, so a typo cannot pass for a
// value that is legitimately empty.
func ExampleClient_GetSecret() {
	client, err := vault.New(vault.Config{
		Address: "https://vault.example.com",
		Token:   os.Getenv("VAULT_TOKEN"),
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	port, err := client.GetSecret(context.Background(), "app/config", "port")
	switch {
	case errors.Is(err, vault.ErrNotFound):
		fmt.Println("no port configured")
	case err != nil:
		fmt.Println(err)
	default:
		fmt.Println(port)
	}
}

// Binding a secret into a struct is where type fidelity is recovered: the
// raw secret is bound through encoding/json tags, so a port arrives as an
// int and a nested value keeps its structure. A duration is declared as
// vault.Duration, which reads "30s" as well as a count of nanoseconds.
func ExampleClient_Unmarshal() {
	client, err := vault.New(vault.Config{
		Address: "https://vault.example.com",
		Token:   os.Getenv("VAULT_TOKEN"),
	})
	if err != nil {
		fmt.Println(err)
		return
	}

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

	if err := client.Unmarshal(context.Background(), "app/config", &cfg); err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(cfg.Port, time.Duration(cfg.Timeout), cfg.Database.Host)
}

// Failures wrap a sentinel, so a caller branches on what went wrong with
// errors.Is and logs something actionable. A transport failure is wrapped
// intact rather than flattened, so a timeout still answers to errors.As.
func Example_errors() {
	client, err := vault.New(vault.Config{
		Address: "https://vault.example.com",
		Token:   os.Getenv("VAULT_TOKEN"),
	})
	if err != nil {
		fmt.Println(err)
		return
	}

	secrets, err := client.GetSecrets(context.Background(), "app/config")
	switch {
	case errors.Is(err, vault.ErrNotFound):
		fmt.Println("no secret at that path, or the mount point is wrong")
	case errors.Is(err, vault.ErrPermissionDenied):
		fmt.Println("the role's policy does not allow this read")
	case errors.Is(err, vault.ErrAuthFailed):
		fmt.Println("vault rejected the credential")
	case errors.Is(err, vault.ErrUnavailable):
		// vault/api has already retried with backoff by the time this
		// arrives, so retrying again is a judgement, not a reflex.
		fmt.Println("vault is sealed, rate limiting, or serving a stale read")
	case err != nil:
		fmt.Println("vault could not be reached:", err)
	default:
		fmt.Println(len(secrets))
	}
}

// settingsLoader is the narrow interface a consumer of this package
// declares for itself, naming only the method it calls. This package
// exports no interface, so nobody stubs methods they never use — and
// *vault.Client satisfies this one without being told about it.
type settingsLoader interface {
	Unmarshal(ctx context.Context, path string, v any) error
}

// appSettings is what the consumer reads its own configuration into.
type appSettings struct {
	Port int `json:"port"`
}

// loadSettings is the code under test, which depends on the interface
// rather than on this package's concrete type.
func loadSettings(ctx context.Context, loader settingsLoader) (appSettings, error) {
	var settings appSettings
	if err := loader.Unmarshal(ctx, "app/config", &settings); err != nil {
		return appSettings{}, fmt.Errorf("loading settings: %w", err)
	}
	return settings, nil
}

// fakeLoader is the consumer's own fake, which needs one method because
// the interface names one.
type fakeLoader struct{ port int }

func (f fakeLoader) Unmarshal(_ context.Context, _ string, v any) error {
	settings, ok := v.(*appSettings)
	if !ok {
		return fmt.Errorf("unexpected target %T", v)
	}
	settings.Port = f.port
	return nil
}

// A consumer fakes the narrow interface it declared, with no help from
// this package and no container in sight.
func Example_consumerDefinedInterface() {
	settings, err := loadSettings(context.Background(), fakeLoader{port: 8080})
	if err != nil {
		fmt.Println(err)
		return
	}

	fmt.Println(settings.Port)
	// Output: 8080
}
