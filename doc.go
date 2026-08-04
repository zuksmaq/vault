// Package vault reads secrets from a HashiCorp Vault KV v2 secrets
// engine. It is read-only and always reads the latest version of a secret.
//
// A service supplies an address, a mount point and one credential, then
// reads a secret either as a map of strings or bound directly into its own
// configuration struct. Token expiry is handled without the caller
// knowing. TLS is verified unless verification is deliberately turned off.
// Failures arrive as sentinel errors the caller can branch on.
//
// # Construction
//
// New takes a [Config] and any number of [Option] values:
//
//	client, err := vault.New(vault.Config{
//		Address: "https://vault.example.com",
//		AppRole: vault.AppRole{RoleID: roleID, SecretID: secretID},
//	}, vault.WithLogger(logger))
//
// Construction fails when the config names neither credential or both, so
// a misconfiguration surfaces at startup rather than on the first read.
// With an AppRole, New logs in before returning, so a rejected credential
// surfaces there too.
//
// # Credentials
//
// A client authenticates one of two ways, and exactly one must be given.
//
// An [AppRole] is the role ID and secret ID pair an unattended service
// logs in with. Its token expires, and this package earns a new one when
// it does.
//
// A static token is a token handed over directly, as copied from the Vault
// UI for local work. Nothing can be done when it expires, so a refused
// read is reported rather than recovered from.
//
// [WithAuthMethod] is the escape hatch for a credential this package does
// not model, such as Kubernetes auth. It counts as the one credential, so
// the config must not supply another.
//
// # Reading secrets
//
// Three methods read, each taking a context as its first argument. A
// secret path is given without the mount point and without KV v2's data
// segment; the client assembles the full path.
//
//   - [Client.GetSecrets] returns every secret value at a path as a
//     map[string]string.
//   - [Client.GetSecret] returns one secret value by its key.
//   - [Client.Unmarshal] binds a secret into a caller-supplied struct.
//
// The mount point defaults to "secret", which is where a KV v2 engine is
// mounted unless somebody chose otherwise. A Vault that mounts it
// elsewhere needs Config.MountPoint set; the symptom of leaving it unset
// is [ErrNotFound] for a secret that plainly exists.
//
// # Coercion
//
// GetSecrets and GetSecret render each secret value as a string. Strings
// pass through unchanged. Numbers keep their literal form, so a port
// stored as 8080 arrives as "8080" and not as "8080.000000". Bools become
// "true" or "false". Objects and arrays become compact JSON.
//
// # Binding into a struct
//
// Unmarshal binds the raw secret through encoding/json tags, before
// coercion rather than after, so fields typed as int, bool, a nested
// struct or a slice receive typed values:
//
//	var cfg struct {
//		Username string         `json:"username"`
//		Port     int            `json:"port"`
//		Timeout  vault.Duration `json:"timeout"`
//	}
//	err := client.Unmarshal(ctx, "app/config", &cfg)
//
// Declare a duration as [Duration] rather than time.Duration, because
// encoding/json reads the latter only as a count of nanoseconds. Duration
// accepts "30s" and "1h30m", and converts back with time.Duration(d).
//
// # Environment variables
//
// The address, the CA and whether to verify certificates fall back to the
// variables the Vault CLI already honours, so the same build runs against
// several environments:
//
//   - VAULT_ADDR supplies the address.
//   - VAULT_CACERT supplies the path to the CA certificate.
//   - VAULT_SKIP_VERIFY turns certificate verification off.
//
// Precedence runs explicit configuration, then the environment, then the
// secure default. A service that states a setting cannot be overridden by
// a deployment manifest — including one that requires verification, which
// is why Config.InsecureSkipVerify is a *bool: nil defers to
// VAULT_SKIP_VERIFY, and a value set either way beats it.
//
// # Transport security
//
// Certificates are verified when the config says nothing, so a service is
// never insecure because a field was forgotten. An internal CA may be
// supplied as a file path or as raw PEM bytes, the latter so a pod can
// pass the service CA already mounted into it. Verification can be turned
// off with Config.InsecureSkipVerify or VAULT_SKIP_VERIFY; either route
// warns at construction through the logger [WithLogger] supplied, and
// nothing in this package suppresses that warning.
//
// # Errors
//
// Failures wrap a sentinel, so they are tested with errors.Is and never
// compared with ==: [ErrInvalidConfig], [ErrAuthFailed],
// [ErrPermissionDenied], [ErrNotFound], [ErrUnexpectedResponse] and
// [ErrUnavailable].
//
// One sentinel covers both a missing secret path and a missing key,
// because the caller's reaction is the same; the message says which it
// was. A transport failure is not flattened into a sentinel but wrapped
// intact, so a timeout still answers to errors.As as a timeout.
//
// Retries for failures Vault owns come from vault/api, which retries with
// backoff by default. ErrUnavailable therefore surfaces only after those
// attempts, and a second retry layer on top would multiply them.
//
// # Faking this client in tests
//
// This package exports no interface. A consumer declares the narrow
// interface it actually uses, at the point it uses it, and fakes that —
// so nobody stubs methods they never call:
//
//	type secretReader interface {
//		GetSecrets(ctx context.Context, path string) (map[string]string, error)
//	}
//
//	func loadConfig(ctx context.Context, r secretReader) (Settings, error) {
//		// ...
//	}
//
// *Client satisfies such an interface without being told about it.
//
// # Concurrency and lifetime
//
// A client is safe for concurrent use by many goroutines. It runs no
// background goroutine and holds nothing that needs releasing, so there is
// no Close: keep one for the lifetime of the process.
//
// # Out of scope
//
// These are deliberate omissions rather than gaps. Writing, patching and
// deleting: secrets are provisioned through the Vault UI. Reading a
// specific version or a secret's metadata: KV v2 keeps history, and this
// reads the latest. Listing the secret paths under a prefix: callers know
// their paths. Caching: every read reaches Vault. Secrets engines other
// than KV v2, and Vault Enterprise namespaces. Setting environment
// variables from a secret: secrets stay in process memory, where child
// processes and crash reporters cannot reach them. OpenTelemetry metrics:
// a client that reads a few paths at startup does not warrant them.
// Kubernetes auth, which [WithAuthMethod] can supply in the meantime.
package vault
