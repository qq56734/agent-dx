# DigitalMate privacy configuration

This optional service runs inside DigitalMateGateway, stores authenticated
ciphertext in the accounts database, and is disabled without the `privacy` block.
It changes no Activator, Environment lifecycle, API Server or shared connection
pool behavior. Application admission uses the existing `AgentV2Access` flow.

Add this block to `ADX_JIUWEN_CONFIG` beside the existing application settings:

```json
{"privacy": {
  "listen": "0.0.0.0:18444",
  "template": "orbit",
  "tls_certificate": "/run/digitalmate-privacy/server.crt",
  "tls_private_key": "/run/digitalmate-privacy/server.key",
  "legacy_keyring_file": "/run/digitalmate-privacy/legacy-keyring.json"
}}
```

The template must match a configured Orbit/DigitalMate application. Hostname,
certificate and paths above are deployment examples. Omit `legacy_keyring_file`
for a fresh installation. The service uses the **existing Gateway credential
root** loaded from `ADX_CREDENTIAL_KEY_FILE`, with tenant/workspace/user/name AAD
for AES-256-GCM and a separately labelled HMAC key for business identities. No
additional encryption root is required. The Gateway process is trusted with
plaintext and the root; this is application encryption, not KMS isolation.
Protect and back up the existing root with the database. Root replacement is a
coordinated re-encryption/re-authorization operation, not a transparent file swap.

Before starting, apply `gateway/src/ingress/accounts/schema.sql` using the schema
owner; the runtime role needs only the corresponding DML privileges. This adds
secret records, transaction receipts and one business authorization table. It
creates no shared identity directories and requires no `chown` privileges.
The unpublished shared-directory prototype schema is not migrated automatically;
use the checked-in schema on a fresh/test database rather than silently reusing
its incompatible `privacy_grants` table.

## Identity and background operation

After standard service activation, the authenticated Gateway derives scope and
workspace from its own principal, strips client Authorization and identity
headers, and injects a sensitive `Authorization: Bearer dm-privacy-v1...` header
before forwarding the WebSocket handshake. It verifies the current active
Binding/workspace first. Tokens never appear in template parameters or files.
The trusted ingress-to-workload path must be encrypted or equivalently protected;
the generic connector supports configurations without TLS, so merely selecting
Gateway mode does not prove transport encryption. Verify the actual deployment.
Do not expose the trusted workload socket directly to untrusted callers.

DigitalMate starts its HTTP listener without reading private settings. It checks
the supplied header at the HTTPS privacy authority, loads private configuration,
and only then starts background producers and admits the socket. Other business
routes remain unavailable before admission. The capability stays in process
memory; editable settings, tools and inherited environment receive no copy.

Access lasts five minutes. The running DigitalMate process renews every minute
and also renews before using an almost-expired credential. Renewal checks the
current Binding generation/workspace and active account, without a mobile
session. A credential can recover after expiry for at most 30 days since its last
successful renewal; a longer outage requires a new authenticated handshake.
Reconnects to the same generation reuse their business authorization record.
Secret reads verify HMAC, authorization revocation/expiry and account status in
the business database, without an ADX RPC. Account disabling and business-grant
revocation deny subsequent checks. ADX-side deletion/replacement is detected at
renewal; an unrevoked access token can remain usable for at most five minutes.
Outages do not revoke a grant or silently extend access. Once a stale generation
has been detected and revoked, restoring it cannot revive that authorization.

The example keeps only the existing workspace volume; the public CA is installed
in the image at the illustrated path. Existing deployments retain their template
name, workspace path and `orbit-config` purpose. This service does not override
idle policies: a paused workload cannot execute background tasks. Configure that
policy separately where continuous background execution is required; do not
disable idle reclamation globally as a credential-delivery workaround.

## Snapshot and recovery boundary

A public/prewarmed snapshot must be captured **before user admission**. Its
listener can accept a fresh authenticated handshake after restore without a
user-specific identity mount. An expired identity restored in memory must renew
and revalidate its Binding before private storage access. Persistent workspace
revisions cause an older process configuration to reload the current secret.
Pending local/remote updates reconcile against the existing workspace receipt;
uncertain outcomes fail closed instead of guessing or reviving deleted secrets.

An authorized memory snapshot can contain both the bearer and already-loaded
third-party secrets. Do not publish it as a public image. This business service
provides no workload attestation: a clone that retains the same live Binding
identity/capability cannot be distinguished cryptographically from its source.
Generation change/revocation and short access expiry bound future service access;
they do not erase already-captured plaintext or revoke provider-issued tokens.
Local tests exercise startup, offline renewal and restored-state counterexamples;
they are not a real ADX runtime Snapshot/Restore or clone-isolation acceptance.

## Writes, migration and operations

Secret version checks and tombstones reject stale refreshes and resurrection.
The existing DigitalMate connection metadata is committed in a local database,
while the configuration center owns ciphertext: staged updates and existing
local receipts cover that concrete cross-store interruption. They do not make
an external OAuth provider's token exchange transactional. A response lost before
DigitalMate receives a rotated refresh token may still require reauthorization.

For a legacy workspace retain the original crypto keyring/ciphertext and opt in
with `DIGITALMATE_PRIVACY_MIGRATE_LEGACY=1`. Import checks the old tenant,
workspace and `orbit-config` context, verifies readback and preserves an encrypted
`.legacy-backup`; it refuses to overwrite a newer value or tombstone. No new
user-facing secret-management API is provided; existing DigitalMate settings
remain the management entry. Up to 64 keys and 4096 transaction records are
allowed per workspace; pending records are retained, completed receipts for 90
days. Authorization rows are capped at 64 per owner, reused on reconnect, and
expired/revoked rows are removed during the next authenticated admission.

For rollback stop the workspace writer and export the current value from an
already-authorized trusted `EngineConfiguration.prepare_legacy_rollback()` context.
It writes a private `.legacy-rollback.json` without replacing the live settings.
Install the verified current envelope atomically before returning to the old
service/template. A new CLI process cannot inherit the in-memory authorization;
no unattended rollback CLI is provided. A pre-migration backup may contain an
invalidated OAuth token and is not a safe substitute. Preserve old keys while
rollback or old ciphertext depends on them.

HTTPS requests have bounded body/connection/time limits and `no-store` responses.
The `digitalmate_privacy` structured event reports bounded operation, status and
handler duration, without tokens/user/workspace/value data. Aggregate it through
the existing log pipeline; no new metrics service or global scanner is added.
