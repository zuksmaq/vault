# Bind secrets into a struct instead of setting environment variables

The Python package's `set_env_variables_from_vault` walked a secret and
set every key as an uppercased environment variable. We do not carry it
over. `Unmarshal(ctx, path, v)` decodes a secret into a caller-supplied
struct through `encoding/json` tags instead.

Three reasons. The Python version recurses into nested values but
discards the parent key, so two nested keys sharing a leaf name
overwrite each other and which one survives depends on map ordering.
Process environment is readable at `/proc/<pid>/environ`, inherited by
every child process, and routinely captured by crash reporters and APM
agents. And mutating global state at runtime in order to read it back
through `os.Getenv` is not how a Go service takes its configuration.

## Consequences

`Unmarshal` binds the raw JSON before string coercion, so nested
structures and genuine `int`, `bool` and `time.Duration` fields
survive. That recovers, exactly where it is useful, the type fidelity
that `GetSecrets` deliberately gives up. It needs no dependency beyond
`encoding/json`.

A service ported from the Python package cannot swap the library and
carry on reading `os.Environ`. It has to change code.
