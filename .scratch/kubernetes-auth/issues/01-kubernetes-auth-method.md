# Support the Kubernetes auth method

Status: needs-info

Deferred during the design grilling. Recorded so the reasoning is not
lost, not because anything is blocked on it.

## Why it was deferred

AppRole means a pod must already hold a secret ID before it can fetch
any secrets, which is a secret delivered in order to fetch secrets.
Kubernetes auth removes that: the pod's projected ServiceAccount token
at `/var/run/secrets/kubernetes.io/serviceaccount/token` becomes the
credential, so there is nothing to provision or rotate.

It was cut because it is not how we work today. Vaults are created
through the UI, which issues a role ID and secret ID, and no consumer
has asked for anything else. Building it now would be speculative.

## What is needed before this can be picked up

Confirmation that the `kubernetes` auth method is enabled and
configured on the target Vault. All five of the following are
server-side and none can be fixed from client code:

1. The mount is enabled — `vault auth enable kubernetes`.
2. The mount is configured with the cluster API host and CA —
   `vault write auth/kubernetes/config kubernetes_host=...`.
3. A token-reviewer identity is bound to the `system:auth-delegator`
   ClusterRole, so Vault may call `TokenReview`.
4. Audience and issuer settings match, because OpenShift 4.11 and
   later issue short-lived, audience-bound ServiceAccount tokens.
5. A Vault role binds the ServiceAccount and namespace to a policy —
   `vault write auth/kubernetes/role/<name>
   bound_service_account_names=...
   bound_service_account_namespaces=... policies=...`.

Check with `vault auth list`, or ask whoever administers the Vault.

## Implementation notes

Small. `api/auth/approle` and `api/auth/kubernetes` both satisfy
`api.AuthMethod`, so no redesign is required — a `Kubernetes` field on
`Config` alongside `AppRole` and `Token`, and one more branch in
`Validate`. The `WithAuthMethod` option already allows a caller to wire
it themselves in the meantime.

Integration coverage can use a Vault dev container with the mount
enabled by the test itself, which proves the client code without
depending on the real cluster's configuration.
