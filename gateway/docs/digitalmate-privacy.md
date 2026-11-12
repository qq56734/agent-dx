# DigitalMate privacy configuration

This optional DigitalMateGateway service stores workspace credentials encrypted in
the accounts database. It is disabled when the `privacy` block is absent. It
does not add credentials to ADX initialization parameters or change Activator.

Add the following block to `ADX_JIUWEN_CONFIG` beside `tenant`, `jiuwen`, and the
configured `orbit` or `digitalmate` application. Paths and hostname are examples;
the server certificate must match the hostname used by the workspace.

```json
"privacy": {
  "listen": "0.0.0.0:18444",
  "tls_certificate": "/run/digitalmate-privacy/server.crt",
  "tls_private_key": "/run/digitalmate-privacy/server.key",
  "keyring_file": "/run/digitalmate-privacy/keyring.json",
  "legacy_keyring_file": "/run/digitalmate-privacy/legacy-keyring.json",
  "delivery": {
    "template": "orbit",
    "root": "/mnt/shared/credential-identities",
    "ca_file": "/run/digitalmate-privacy/ca.pem",
    "uid": 10001,
    "gid": 10001,
    "ttl_seconds": 3600,
    "renew_before_seconds": 1200
  }
}
```

Omit `legacy_keyring_file` for a new installation. Before starting the Gateway,
apply `gateway/src/ingress/accounts/schema.sql` using the schema-owner role;
the running Gateway only needs the corresponding database DML privileges. Back
up the database and check privileges before applying it to an existing service.

The privacy keyring is a private, regular file with permissions no broader than
`0600`, containing `{"active_key_id":"v1","keys":{"v1":"<base64 32-byte key>"}}`.
Generate it using a cryptographically secure random generator in a trusted
deployment process, protect and back it up separately, and never reuse the
Gateway's model-credential key. The legacy keyring is the original crypto
service keyring, not a newly generated replacement. Both keyrings and the TLS
private key belong only in the trusted Gateway process, never in a user volume,
template parameter, snapshot, log, or client. Preserve old keys while their
ciphertexts or rollback candidates still depend on them.

`gateway/examples/digitalmate-privacy-template.json` illustrates the required
template settings. For an existing installation retain its template name,
workspace path and `orbit-config` purpose. The identity volume's source must
resolve to `<delivery.root>/users/${privacy_identity}` on the same shared
storage; mount only that per-Binding directory read-only at `/run/orbit-crypto`.
Its short-lived bearer is not a root key. The Gateway prepares this directory
before activation, issues a token only for the matching active Binding and
generation, and renews it without a mobile session. It requires permission to
create files owned by the configured workload UID/GID. A deleted/recreated
Binding gets a fresh directory. Existing Bindings lacking `privacy_identity`
are rejected for a controlled migration, preserving their workspaces.

The example disables idle reclamation so background work can continue without a
connected phone. This consumes resources while the instance remains active;
apply it only to templates that require this behavior. Account disabling and
Binding deletion still prevent new access. A copied bearer can be replayed until
it expires or is revoked. A copied workload retaining access to the same
identity mount can obtain later rotations: this design does not add platform
workload attestation. Gateway and the authorized workspace can see plaintext in
memory; PostgreSQL stores authenticated ciphertext.

For a legacy workspace, keep the original keyring and ciphertext, set
`DIGITALMATE_PRIVACY_MIGRATE_LEGACY=1` on the new template, and activate the
new Binding using the same workspace. Import checks the original
tenant/workspace/`orbit-config` context, verifies readback, and preserves an
encrypted `.legacy-backup`. It refuses to overwrite a different or revoked
central value. Configuration changes are staged and reconciled against the
workspace receipt; a missing or uncertain receipt fails closed. Restoring a
process with an older in-memory configuration reloads the central value when
the persistent workspace revision has changed. The service does not currently
provide a separate user-facing secret-management API.

Each user/workspace is limited to 64 secret names and 4096 transaction records.
Pending updates are retained; finished transaction receipts are retained for 90
days and then removed on a later write. Recovery of an exceptionally old
finished update therefore requires operator reconciliation rather than guessing.

For rollback, first stop the workspace writer and keep it stopped through the
switch. With the current Gateway and legacy keyring available, run
`python -m server_engine.engine_cli privacy-rollback --workspace <workspace>`
in the trusted workspace context. It writes a new private
`.legacy-rollback.json` containing the **current** central secret in the old
envelope format, checks its revision, and leaves the active configuration
untouched. Back up the current configuration, install the verified candidate
atomically, switch back to the old service/template, and then restart. A stale
pre-migration backup can contain an invalidated OAuth refresh token and must not
be substituted for a current rollback candidate.
