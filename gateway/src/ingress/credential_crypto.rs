//! Workspace-authorized access to one operator-selected, ADX-managed crypto service.
use super::{
    agent_service::{AgentV2Access, ServiceSelector},
    server::{Ingress, IngressSecurity, ProxyBody},
};
use adx_agent_api::{managed::ManagedService, request::RequestContext};
use adx_agent_core::{
    service_grants::{credential_digest, ServiceAccess as Context, VerifyServiceGrant},
    Protocol, Scope,
};
use adx_credential_crypto::storage::{read_private, StorageError};
use bytes::Bytes;
use http::{header, HeaderValue, Method, Request, Response, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::Incoming;
use rustls::pki_types::ServerName;
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{convert::Infallible, path::PathBuf, sync::Arc, time::Duration};
use tokio::sync::Semaphore;
use tokio_rustls::TlsConnector;

const BODY_LIMIT: usize = 524_288;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CredentialCryptoConfig {
    /// Operator-selected service identity, independent of the caller's workspace grant.
    pub scope: Scope,
    pub port: u16,
    pub server_name: String,
    pub ca_file: PathBuf,
    /// Optional dedicated ingress host, separate from the backend TLS server name.
    #[serde(default)]
    pub frontend_host: Option<String>,
    #[serde(default = "default_timeout")]
    pub timeout_seconds: u64,
}
fn default_timeout() -> u64 {
    60
}

pub struct CredentialCryptoApi {
    config: CredentialCryptoConfig,
    access: AgentV2Access,
    managed: Arc<ManagedService>,
    tls: TlsConnector,
    server_name: ServerName<'static>,
    frontend_host: Option<String>,
    host: HeaderValue,
    slots: Semaphore,
}

struct ApiError(StatusCode, &'static str);
// Audit only pseudonymous routing metadata; never retain a bearer or request body.
struct CryptoAudit {
    operation: &'static str,
    context_hash: String,
    identity_hash: String,
    status: Option<u16>,
}
impl CryptoAudit {
    fn new(path: &str, context: &Context, credential: &str) -> Result<Self, ApiError> {
        let mut digest = Sha256::new();
        digest.update(b"adx-credential-audit-v1\0");
        digest.update(context.tenant.as_bytes());
        digest.update(b"\0");
        digest.update(context.workspace.as_bytes());
        let identity = credential_digest(credential)
            .map_err(|_| ApiError(StatusCode::UNAUTHORIZED, "UNAUTHORIZED"))?;
        Ok(Self {
            operation: if path == "/v1/seal" { "seal" } else { "open" },
            context_hash: hex::encode(digest.finalize()),
            identity_hash: identity[..16].to_owned(),
            status: None,
        })
    }
}
impl Drop for CryptoAudit {
    fn drop(&mut self) {
        if let Some(status) = self.status {
            tracing::info!(target: "adx_audit", event="credential_crypto_access",
                operation=self.operation, context_hash=%self.context_hash,
                identity_hash=%self.identity_hash, status, "credential crypto access");
        } else {
            tracing::warn!(target: "adx_audit", event="credential_crypto_access",
                operation=self.operation, context_hash=%self.context_hash,
                identity_hash=%self.identity_hash, outcome="interrupted", "credential crypto access");
        }
    }
}
impl ApiError {
    fn unavailable() -> Self {
        Self(StatusCode::SERVICE_UNAVAILABLE, "CRYPTO_UNAVAILABLE")
    }
    fn response(self) -> Response<ProxyBody> {
        response(
            self.0,
            Bytes::from(serde_json::json!({"code": self.1}).to_string()),
        )
    }
}
fn response(status: StatusCode, body: Bytes) -> Response<ProxyBody> {
    let mut response = Response::new(
        Full::new(body)
            .map_err(
                |never: Infallible| -> Box<dyn std::error::Error + Send + Sync> { match never {} },
            )
            .boxed_unsync(),
    );
    *response.status_mut() = status;
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static("application/json"),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response
}
impl CredentialCryptoApi {
    /// Rejects invalid scope, TLS trust or timeout configuration.
    pub fn new(
        config: CredentialCryptoConfig,
        managed: Arc<ManagedService>,
    ) -> Result<Self, StorageError> {
        config.scope.validate().map_err(|_| StorageError::Invalid)?;
        if config.port == 0 || !(1..=300).contains(&config.timeout_seconds) {
            return Err(StorageError::Invalid);
        }
        let server_name =
            ServerName::try_from(config.server_name.clone()).map_err(|_| StorageError::Invalid)?;
        let frontend_host = config
            .frontend_host
            .as_ref()
            .map(|host| {
                let authority = host
                    .parse::<http::uri::Authority>()
                    .map_err(|_| StorageError::Invalid)?;
                if authority.port().is_some() || host.contains('@') {
                    return Err(StorageError::Invalid);
                }
                Ok(authority.host().to_ascii_lowercase())
            })
            .transpose()?;
        let host_name = if config.server_name.contains(':') {
            format!("[{}]:{}", config.server_name, config.port)
        } else {
            format!("{}:{}", config.server_name, config.port)
        };
        let host = HeaderValue::from_str(&host_name).map_err(|_| StorageError::Invalid)?;
        let ca = read_private(&config.ca_file, 65_536)?;
        let certificates = rustls_pemfile::certs(&mut ca.as_slice())
            .collect::<Result<Vec<_>, _>>()
            .map_err(|_| StorageError::Invalid)?;
        if certificates.is_empty() {
            return Err(StorageError::Invalid);
        }
        let mut roots = rustls::RootCertStore::empty();
        for certificate in certificates {
            roots.add(certificate).map_err(|_| StorageError::Invalid)?;
        }
        adx_transport::install_crypto_provider();
        let mut tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        tls.alpn_protocols = vec![b"http/1.1".to_vec()];
        Ok(Self {
            config,
            access: AgentV2Access::new(managed.clone()),
            managed,
            tls: TlsConnector::from(Arc::new(tls)),
            server_name,
            frontend_host,
            host,
            slots: Semaphore::new(128),
        })
    }
    pub fn matches(path: &str) -> bool {
        matches!(path, "/v1/seal" | "/v1/open")
    }
    pub(super) fn matches_host<B>(&self, request: &Request<B>) -> bool {
        self.frontend_host.as_ref().is_none_or(|expected| {
            request
                .headers()
                .get(header::HOST)
                .and_then(|value| value.to_str().ok())
                .and_then(|value| value.parse::<http::uri::Authority>().ok())
                .map(|authority| authority.host().eq_ignore_ascii_case(expected))
                .or_else(|| {
                    request
                        .uri()
                        .host()
                        .map(|host| host.eq_ignore_ascii_case(expected))
                })
                .unwrap_or(false)
        })
    }
    pub(super) fn conflicts_proxy_routes(
        &self,
        routes: &[super::reverse_proxy::ProxyRoute],
    ) -> bool {
        routes.iter().any(|route| {
            let host_overlaps = self.frontend_host.as_ref().is_none_or(|host| {
                route
                    .host
                    .as_ref()
                    .is_none_or(|other| other.eq_ignore_ascii_case(host))
            });
            host_overlaps
                && ["/v1/seal", "/v1/open"].iter().any(|path| {
                    route.path_prefix == "/"
                        || path
                            .strip_prefix(&route.path_prefix)
                            .is_some_and(|suffix| suffix.is_empty() || suffix.starts_with('/'))
                })
        })
    }
    pub(super) fn conflicts_control_plane_routes(
        &self,
        routes: &[super::server::StaticRoute],
    ) -> bool {
        routes.iter().any(|route| {
            ["/v1/seal", "/v1/open"]
                .iter()
                .any(|path| route.matches(path))
        })
    }
    pub(super) async fn handle(
        &self,
        request: Request<Incoming>,
        ingress: Arc<Ingress>,
        security: IngressSecurity,
    ) -> Response<ProxyBody> {
        let context = Arc::new(RequestContext::new(Duration::from_secs(
            self.config.timeout_seconds,
        )));
        let mut audit = None;
        let response = match tokio::time::timeout_at(
            context.deadline(),
            self.forward(request, ingress, security, context.clone(), &mut audit),
        )
        .await
        {
            Ok(Ok(response)) => response,
            Ok(Err(error)) => error.response(),
            Err(_) => ApiError::unavailable().response(),
        };
        if let Some(audit) = &mut audit {
            audit.status = Some(response.status().as_u16());
        }
        response
    }
    async fn forward(
        &self,
        request: Request<Incoming>,
        ingress: Arc<Ingress>,
        security: IngressSecurity,
        context: Arc<RequestContext>,
        audit: &mut Option<CryptoAudit>,
    ) -> Result<Response<ProxyBody>, ApiError> {
        if security != IngressSecurity::Tls {
            return Err(ApiError(StatusCode::UPGRADE_REQUIRED, "TLS_REQUIRED"));
        }
        if request.method() != Method::POST {
            return Err(ApiError(
                StatusCode::METHOD_NOT_ALLOWED,
                "METHOD_NOT_ALLOWED",
            ));
        }
        if request.uri().query().is_some() || request.headers().contains_key(header::UPGRADE) {
            return Err(ApiError(StatusCode::BAD_REQUEST, "INVALID_REQUEST"));
        }
        let mut authorization = request.headers().get_all(header::AUTHORIZATION).iter();
        let bearer = authorization
            .next()
            .cloned()
            .filter(|_| authorization.next().is_none())
            .ok_or(ApiError(StatusCode::UNAUTHORIZED, "UNAUTHORIZED"))?;
        let credential = bearer
            .to_str()
            .ok()
            .and_then(|value| value.strip_prefix("Bearer "))
            .filter(|value| credential_digest(value).is_ok())
            .ok_or(ApiError(StatusCode::UNAUTHORIZED, "UNAUTHORIZED"))?;
        let _permit = self
            .slots
            .try_acquire()
            .map_err(|_| ApiError::unavailable())?;
        let path = request.uri().path().to_owned();
        let body = Limited::new(request.into_body(), BODY_LIMIT)
            .collect()
            .await
            .map_err(|_| ApiError(StatusCode::PAYLOAD_TOO_LARGE, "INVALID_REQUEST"))?
            .to_bytes();
        // Read only the context for admission. The crypto service validates the full request.
        #[derive(Deserialize)]
        struct Admission {
            context: Context,
        }
        let admission: Admission = serde_json::from_slice(&body)
            .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "INVALID_REQUEST"))?;
        admission
            .context
            .validate()
            .map_err(|_| ApiError(StatusCode::BAD_REQUEST, "INVALID_REQUEST"))?;
        *audit = Some(CryptoAudit::new(&path, &admission.context, credential)?);
        if !self
            .managed
            .verify_service_grant(
                &context,
                &VerifyServiceGrant {
                    credential: credential.into(),
                    expected: admission.context,
                },
            )
            .await
            .map_err(|_| ApiError(StatusCode::SERVICE_UNAVAILABLE, "AUTHORITY_UNAVAILABLE"))?
        {
            return Err(ApiError(StatusCode::FORBIDDEN, "FORBIDDEN"));
        }
        // Authority verification precedes any activation. Callers cannot select a service target.
        let selection = self
            .access
            .select(
                context,
                self.config.scope.clone(),
                ServiceSelector {
                    protocol: Protocol::Http,
                    port: Some(self.config.port),
                },
            )
            .await
            .map_err(|_| ApiError::unavailable())?;
        let stream = self
            .access
            .connect_service(&ingress, selection)
            .await
            .map_err(|_| ApiError::unavailable())?;
        let key = stream
            .http_pool_key()
            .map_err(|_| ApiError::unavailable())?;
        let cancelled = stream.cancellation();
        let exchange = async {
            let tls = self
                .tls
                .connect(self.server_name.clone(), stream)
                .await
                .map_err(|_| ApiError::unavailable())?;
            let mut upstream = Request::new(Full::new(body));
            *upstream.method_mut() = Method::POST;
            *upstream.uri_mut() = path.parse().map_err(|_| ApiError::unavailable())?;
            upstream
                .headers_mut()
                .insert(header::HOST, self.host.clone());
            upstream.headers_mut().insert(header::AUTHORIZATION, bearer);
            upstream.headers_mut().insert(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            );
            let (reply, _connection_permit) = ingress
                .http_pool
                .send_one_shot(key, upstream, tls)
                .await
                .map_err(|_| ApiError::unavailable())?;
            let status = reply.status();
            let body = Limited::new(reply.into_body(), BODY_LIMIT)
                .collect()
                .await
                .map_err(|_| ApiError::unavailable())?
                .to_bytes();
            Ok(response(status, body))
        };
        tokio::select! {
            _ = wait_for_invalidation(cancelled) => Err(ApiError::unavailable()),
            result = exchange => result,
        }
    }
}

// Crypto buffers the complete reply within its deadline. Normal transport EOF may
// drop the session owner before those bytes are consumed; only explicit route
// invalidation cancels this exchange. Other Gateway paths retain their contract.
async fn wait_for_invalidation(mut cancelled: tokio::sync::watch::Receiver<bool>) {
    loop {
        if *cancelled.borrow() {
            return;
        }
        if cancelled.changed().await.is_err() {
            std::future::pending::<()>().await;
            return;
        }
    }
}

#[cfg(test)]
mod cancellation_tests {
    use super::*;
    use tokio::sync::watch;

    #[tokio::test(start_paused = true)]
    async fn buffered_crypto_ignores_normal_eof_but_honors_explicit_invalidation() {
        let (sender, receiver) = watch::channel(false);
        drop(sender);
        assert!(
            tokio::time::timeout(Duration::from_millis(1), wait_for_invalidation(receiver),)
                .await
                .is_err()
        );
        for initially_cancelled in [false, true] {
            let (sender, receiver) = watch::channel(initially_cancelled);
            let waiting = tokio::spawn(wait_for_invalidation(receiver));
            if !initially_cancelled {
                sender.send(true).unwrap();
            }
            drop(sender);
            tokio::time::timeout(Duration::from_millis(1), waiting)
                .await
                .unwrap()
                .unwrap();
        }
    }
}
