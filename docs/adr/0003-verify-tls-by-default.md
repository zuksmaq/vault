# Verify TLS certificates by default

Both packages that preceded this one made unverified TLS the default:
the Python client defaulted `verify_ssl=False` and additionally
silenced urllib3's warnings, and the old Go client's `VerifySSL` field
enabled `InsecureSkipVerify` on its zero value. Internal guidance is
that verification is unnecessary on the on-premise network. We still
verify by default, because an insecure default makes future consumers
insecure by omission, on networks nobody has assessed, with nothing in
their code saying so.

## Consequences

Turning verification off stays easy: one field
(`InsecureSkipVerify`, named to match `crypto/tls` so it reads as
alarming in review) or one environment variable
(`VAULT_SKIP_VERIFY`). The environment variable is the intended route
for a whole environment to opt out once in its deployment manifests
without any code change. Either path logs a warning, which the Python
client's behaviour of silencing warnings prevented.

Supplying the internal CA is the preferred fix rather than skipping
verification. `CACertPEM` takes raw bytes specifically so an OpenShift
pod can pass the service CA already mounted into it, with no files to
manage or certificates to bake into images.

Precedence is explicit config, then environment variable, then the
secure default.

Services ported from either predecessor that quietly relied on the
insecure default will fail on their first connection until they supply
a CA or opt out deliberately.
