//! Component evidence: real grant authority, Gateway, Relay, TLS and crypto router.
use super::*;
use crate::{
    common::protocol::GatewayPolicy,
    ingress::credential_crypto::{CredentialCryptoApi, CredentialCryptoConfig},
    node::Relay,
};
use adx_agent_api::{local::LocalControl, managed::ManagedService};
use adx_agent_core::{service_grants::*, Scope, TemplateDraft, TemplateRef};
use adx_credential_crypto::{
    access::{AccessClient, AccessConfig},
    service::{router, ServiceState},
    storage::write_private,
    Keyring,
};
use base64::{engine::general_purpose::STANDARD, Engine};
use serde_json::{json, Value};
use std::{collections::BTreeMap, time::Duration};
use tower::ServiceExt;

const ISSUER: &str = "private-crypto-test-issuer-at-least-32-bytes";
const VERIFIER: &str = "private-crypto-test-verifier-at-least-32-bytes";
const CERT: &[u8] = include_bytes!("../../tests/fixtures/ingress-cert.pem");
const KEY: &[u8] = include_bytes!("../../tests/fixtures/ingress-key.pem");

struct Fixture {
    gateway: Arc<Ingress>,
    backend: Arc<Backend>,
    activator: Arc<adx_activator::Activator>,
    grant: IssuedServiceGrant,
    headers: Arc<Mutex<Vec<http::HeaderMap>>>,
    stall: Arc<std::sync::atomic::AtomicBool>,
    authority_shutdown: Option<tokio::sync::oneshot::Sender<()>>,
    tasks: Vec<tokio::task::JoinHandle<()>>,
    _directory: tempfile::TempDir,
}
impl Fixture {
    async fn post(&self, path: &str, body: Value) -> (StatusCode, Value) {
        send(
            self,
            IngressSecurity::Tls,
            "POST",
            path,
            &self.grant.credential,
            body,
        )
        .await
    }
}
impl Drop for Fixture {
    fn drop(&mut self) {
        for task in &self.tasks {
            task.abort();
        }
    }
}
fn scope(template: &str, binding: &str) -> Scope {
    Scope {
        tenant: "tenant".into(),
        template: template.into(),
        template_ref: TemplateRef::Version("1".into()),
        binding_id: binding.into(),
    }
}
fn context() -> Value {
    json!({"tenant":"tenant", "workspace":"alice", "purpose":"orbit-config"})
}
fn seal() -> Value {
    json!({"context":context(), "plaintext":STANDARD.encode(b"provider-secret")})
}
async fn fixture_crypto(server_name: &str, timeout_seconds: u64) -> Fixture {
    fixture_crypto_with_host(server_name, timeout_seconds, None).await
}
async fn fixture_crypto_with_host(
    server_name: &str,
    timeout_seconds: u64,
    frontend_host: Option<&str>,
) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let token_file = directory.path().join("verification");
    let ca_file = directory.path().join("ca.pem");
    write_private(&token_file, VERIFIER.as_bytes(), false).unwrap();
    write_private(&ca_file, CERT, false).unwrap();
    let state = AgentState::new(Arc::new(MemoryRepository::default()));
    let backend = Arc::new(Backend::default());
    let activator = Arc::new(adx_activator::Activator::new(
        state.clone(),
        backend.clone(),
    ));
    let authority = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", authority.local_addr().unwrap());
    let app = adx_activator::server::router(activator.clone(), ISSUER, Duration::from_secs(3))
        .unwrap()
        .merge(
            adx_activator::service_grants::router(
                activator.clone(),
                ISSUER,
                VERIFIER,
                Duration::from_secs(3),
            )
            .unwrap(),
        );
    let (authority_shutdown, shutdown) = tokio::sync::oneshot::channel();
    let authority_task = tokio::spawn(async move {
        axum::serve(authority, app)
            .with_graceful_shutdown(async {
                let _ = shutdown.await;
            })
            .await
            .unwrap()
    });
    let access = || AccessConfig {
        url: url.clone(),
        token_file: token_file.clone(),
        ca_file: None,
        allow_loopback_http: true,
        timeout_seconds: 1,
    };
    let app = router(ServiceState {
        keys: Keyring::new("v1".into(), BTreeMap::from([("v1".into(), [7; 32])])).unwrap(),
        authorizer: AccessClient::new(&access()).unwrap(),
    });
    let private_key = directory.path().join("tls-key.pem");
    write_private(&private_key, KEY, false).unwrap();
    let acceptor = adx_transport::tls::http_server_acceptor(
        &ca_file,
        &private_key,
        None,
        vec![b"http/1.1".to_vec()],
    )
    .unwrap();
    let crypto = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = crypto.local_addr().unwrap().port();
    let headers = Arc::new(Mutex::new(Vec::new()));
    let observed = headers.clone();
    let stall = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let stalled = stall.clone();
    let crypto_task = tokio::spawn(async move {
        loop {
            let (stream, _) = crypto.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let app = app.clone();
            let observed = observed.clone();
            let stalled = stalled.clone();
            tokio::spawn(async move {
                let Ok(tls) = acceptor.accept(stream).await else {
                    return;
                };
                let _ = hyper::server::conn::http1::Builder::new()
                    .serve_connection(
                        TokioIo::new(tls),
                        service_fn(move |request: Request<Incoming>| {
                            observed.lock().unwrap().push(request.headers().clone());
                            let app = app.clone();
                            let stall = stalled.load(std::sync::atomic::Ordering::SeqCst);
                            async move {
                                if stall {
                                    tokio::time::sleep(Duration::from_secs(10)).await;
                                }
                                app.oneshot(request.map(axum::body::Body::new)).await
                            }
                        }),
                    )
                    .await;
            });
        }
    });
    let mut template: TemplateDraft = serde_json::from_str(include_str!(
        "../../../agent/activator/examples/credential-crypto-template.json"
    ))
    .unwrap();
    template.service[0].port = port;
    template
        .readiness_probe
        .as_mut()
        .unwrap()
        .tcp_socket
        .as_mut()
        .unwrap()
        .port = port;
    template.validate().unwrap();
    state.publish("tenant", &template).await.unwrap();
    let user_template: TemplateDraft = serde_json::from_value(json!({
        "name":"orbit", "image":"app:1", "isolation_runtime":"runsc",
        "resources":{"cpu_millis":1000,"memory_mib":512}
    }))
    .unwrap();
    state.publish("tenant", &user_template).await.unwrap();
    let user = state
        .create_binding_with_parameters(
            scope("orbit", "alice"),
            &BTreeMap::from([("workspace".into(), "alice".into())]),
        )
        .await
        .unwrap();
    let grant = activator
        .issue_service_grant(&IssueServiceGrant {
            scope: user.scope,
            expected_generation: user.generation,
            purpose: ORBIT_CONFIG_PURPOSE.into(),
            ttl_seconds: 60,
        })
        .await
        .unwrap();
    let binding = state
        .create_binding(scope("credential-crypto", "shared"))
        .await
        .unwrap();
    let relay = Arc::new(
        Relay::new(GatewayPolicy::for_local_mock(vec!["127.0.0.0/8"
            .parse()
            .unwrap()]))
        .with_route_enforcement(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let relay_server = relay.clone();
    let relay_task = tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let relay = relay_server.clone();
            tokio::spawn(async move {
                let _ = relay.serve_h2(stream).await;
            });
        }
    });
    let (gateway, _, routes) = fixture_with_routes().await;
    let route: crate::common::route::RouteInfo = serde_json::from_value(json!({
        "instanceID":binding.current.environment_id,"instanceStatus":{"code":3},
        "tenantID":"tenant", "environmentID":"crypto-runtime", "environmentIP":"127.0.0.1",
        "nodeProxyAddress":address.to_string()
    }))
    .unwrap();
    relay
        .activate_route(
            route.instance_id.clone(),
            route.environment_id.clone(),
            route.environment_ip.parse().unwrap(),
        )
        .await;
    routes.put(route);
    let managed = Arc::new(ManagedService::new(Arc::new(
        adx_agent_api::activator::ActivatorClient::new(
            vec![url.clone()],
            ISSUER.into(),
            Duration::from_secs(5),
            None,
            true,
        )
        .unwrap(),
    )));
    let api = CredentialCryptoApi::new(
        CredentialCryptoConfig {
            scope: binding.scope,
            port,
            server_name: server_name.into(),
            ca_file,
            frontend_host: frontend_host.map(str::to_owned),
            timeout_seconds,
        },
        managed,
    )
    .unwrap();
    let gateway = Arc::new(
        gateway
            .as_ref()
            .clone()
            .with_backend_http_pool_config(crate::ingress::http_pool::BackendHttpPoolConfig {
                max_connections_per_endpoint: 1,
                ..crate::ingress::http_pool::BackendHttpPoolConfig::default()
            })
            .with_credential_crypto_api(Arc::new(api)),
    );
    Fixture {
        gateway,
        backend,
        activator,
        grant,
        headers,
        stall,
        authority_shutdown: Some(authority_shutdown),
        tasks: vec![authority_task, crypto_task, relay_task],
        _directory: directory,
    }
}
async fn send(
    f: &Fixture,
    security: IngressSecurity,
    method: &str,
    path: &str,
    token: &str,
    body: Value,
) -> (StatusCode, Value) {
    let (mut sender, server, client) = connection(f.gateway.clone(), security).await;
    let mut request = request(method, path, token, "crypto-test", body);
    for name in ["x-adx-target-port", "x-adx-instance-id", "x-auth", "cookie"] {
        request
            .headers_mut()
            .insert(name, "attacker-controlled".parse().unwrap());
    }
    let response = sender.send_request(request).await.unwrap();
    let status = response.status();
    let body = response.collect().await.unwrap().to_bytes();
    let body = serde_json::from_slice(&body)
        .unwrap_or_else(|_| Value::String(String::from_utf8_lossy(&body).into()));
    server.abort();
    client.abort();
    (status, body)
}

#[tokio::test]
async fn managed_crypto_roundtrip_uses_fixed_binding_tls_and_only_workspace_identity() {
    let f = fixture_crypto("localhost", 5).await;
    assert!(f.backend.0.lock().unwrap().is_empty());
    let (status, sealed) = f.post("/v1/seal", seal()).await;
    assert_eq!(status, StatusCode::OK, "{sealed}");
    let (status, opened) = f
        .post(
            "/v1/open",
            json!({"context":context(), "envelope":sealed["envelope"]}),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{opened}");
    assert_eq!(opened["plaintext"], STANDARD.encode(b"provider-secret"));
    assert_eq!(
        f.gateway.backend_http_pool_metrics().opened_total,
        2,
        "crypto must use the shared backend HTTP transport"
    );
    assert_eq!(
        f.gateway.backend_http_pool_metrics().idle_connections,
        0,
        "crypto requests must not retain a connection across service identities"
    );
    assert_eq!(f.backend.0.lock().unwrap().len(), 1);
    let headers = f.headers.lock().unwrap();
    assert_eq!(headers.len(), 2);
    for headers in headers.iter() {
        assert_eq!(
            headers["authorization"],
            format!("Bearer {}", f.grant.credential)
        );
        assert_eq!(headers["content-type"], "application/json");
        for name in [
            "x-adx-target-port",
            "x-adx-instance-id",
            "x-auth",
            "cookie",
            "x-trace-id",
        ] {
            assert!(!headers.contains_key(name), "leaked {name}");
        }
    }
}

#[tokio::test]
async fn configured_listener_preserves_crypto_tls_and_route_boundaries() {
    use crate::ingress::{ListenerConfig, ListenerRoute};

    let f = fixture_crypto("localhost", 5).await;
    let gateway = Arc::new(
        f.gateway
            .as_ref()
            .clone()
            .with_client_acl(vec!["127.0.0.0/8".parse().unwrap()], false),
    );
    let client = reqwest::Client::builder()
        .no_proxy()
        .add_root_certificate(reqwest::Certificate::from_pem(CERT).unwrap())
        .pool_max_idle_per_host(0)
        .build()
        .unwrap();

    for tls in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let options = ListenerConfig {
            listen: address,
            tls,
            allow_http_credentials: !tls,
            allowed_routes: Some(vec![ListenerRoute {
                method: Some("POST".into()),
                path: "exact:/v1/seal".into(),
            }]),
        };
        let acceptor = tls.then(|| {
            adx_transport::tls::http_server_acceptor_pem(
                CERT,
                KEY,
                None,
                vec![b"http/1.1".to_vec()],
            )
            .unwrap()
        });
        let (stop, shutdown) = tokio::sync::watch::channel(false);
        let gateway = gateway.clone();
        let server = tokio::spawn(async move {
            gateway
                .serve_listener(listener, options, acceptor, shutdown)
                .await
        });
        let scheme = if tls { "https" } else { "http" };
        let base = format!("{scheme}://localhost:{}", address.port());
        let denied = client
            .post(format!("{base}/v1/open"))
            .bearer_auth(&f.grant.credential)
            .json(&seal())
            .send()
            .await
            .unwrap();
        assert_eq!(denied.status(), StatusCode::FORBIDDEN);
        assert!(f.backend.0.lock().unwrap().is_empty());

        if tls {
            let unauthorized = client
                .post(format!("{base}/v1/seal"))
                .bearer_auth("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")
                .json(&seal())
                .send()
                .await
                .unwrap();
            assert_eq!(unauthorized.status(), StatusCode::FORBIDDEN);
            assert!(f.backend.0.lock().unwrap().is_empty());
        }
        let response = client
            .post(format!("{base}/v1/seal"))
            .bearer_auth(&f.grant.credential)
            .json(&seal())
            .send()
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            if tls {
                StatusCode::OK
            } else {
                StatusCode::UPGRADE_REQUIRED
            }
        );
        if !tls {
            assert!(f.backend.0.lock().unwrap().is_empty());
        }
        stop.send(true).unwrap();
        server.await.unwrap().unwrap();
    }
}

#[tokio::test]
async fn existing_host_specific_application_route_precedes_crypto_on_the_same_path() {
    let mut f = fixture_crypto_with_host("localhost", 5, Some("crypto.example.test")).await;
    let app = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = app.local_addr().unwrap();
    let app_task = tokio::spawn(async move {
        axum::serve(
            app,
            axum::Router::new().fallback(|| async { "existing-app" }),
        )
        .await
        .unwrap();
    });
    f.tasks.push(app_task);
    f.gateway =
        Arc::new(
            f.gateway
                .as_ref()
                .clone()
                .with_proxy_routes(vec![crate::ingress::ProxyRoute {
                    name: "existing-app".into(),
                    path_prefix: "/v1/open".into(),
                    upstream: format!("http://{address}"),
                    strip_prefix: false,
                    host: Some("app.example.test".into()),
                }]),
        );
    let (mut sender, server, client) = connection(f.gateway.clone(), IngressSecurity::Tls).await;
    let mut app_request = request("POST", "/v1/open", "app-token", "app", json!({}));
    app_request
        .headers_mut()
        .insert(http::header::HOST, "app.example.test".parse().unwrap());
    let response = sender.send_request(app_request).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(response.collect().await.unwrap().to_bytes(), "existing-app");
    server.abort();
    client.abort();
    let (mut sender, server, client) = connection(f.gateway.clone(), IngressSecurity::Tls).await;
    let mut crypto = request("POST", "/v1/seal", &f.grant.credential, "crypto", seal());
    crypto
        .headers_mut()
        .insert(http::header::HOST, "crypto.example.test".parse().unwrap());
    let response = sender.send_request(crypto).await.unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    response.collect().await.unwrap();
    server.abort();
    client.abort();
}

#[derive(Clone)]
struct AuditWriter(Arc<Mutex<Vec<u8>>>);
impl std::io::Write for AuditWriter {
    fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(bytes);
        Ok(bytes.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn crypto_audit_records_results_without_credentials_or_plaintext() {
    // Like the existing ingress logging test, isolate tracing's process-wide
    // state from concurrently running tests while exercising the real request.
    const CHILD_ENV: &str = "ADX_TEST_CREDENTIAL_AUDIT_CHILD";
    if std::env::var_os(CHILD_ENV).is_none() {
        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "ingress::server::agent_api_tests::credential_crypto_tests::crypto_audit_records_results_without_credentials_or_plaintext",
                "--nocapture",
            ])
            .env(CHILD_ENV, "1")
            .output()
            .unwrap();
        let stdout = String::from_utf8_lossy(&output.stdout);
        assert!(
            output.status.success() && stdout.contains("1 passed; 0 failed"),
            "audit child failed or did not run: {stdout} {}",
            String::from_utf8_lossy(&output.stderr)
        );
        return;
    }
    let captured = AuditWriter(Arc::new(Mutex::new(Vec::new())));
    let writer = captured.clone();
    let subscriber = tracing_subscriber::fmt()
        .with_max_level(tracing::Level::INFO)
        .with_ansi(false)
        .without_time()
        .with_writer(move || writer.clone())
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    let f = fixture_crypto("localhost", 5).await;
    assert_eq!(f.post("/v1/seal", seal()).await.0, StatusCode::OK);
    let rejected = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx";
    assert_eq!(
        send(
            &f,
            IngressSecurity::Tls,
            "POST",
            "/v1/seal",
            rejected,
            seal()
        )
        .await
        .0,
        StatusCode::FORBIDDEN
    );
    let output = String::from_utf8(captured.0.lock().unwrap().clone()).unwrap();
    assert!(output.contains("credential_crypto_access"));
    assert!(output.contains("status=200"));
    assert!(output.contains("status=403"));
    assert!(!output.contains(&f.grant.credential));
    assert!(!output.contains(rejected));
    assert!(!output.contains("provider-secret"));
    assert!(!output.contains(&STANDARD.encode(b"provider-secret")));
}

#[tokio::test]
async fn denied_admission_never_activates_crypto() {
    let f = fixture_crypto("localhost", 5).await;
    for (security, method, path, token, expected) in [
        (
            IngressSecurity::Plaintext,
            "POST",
            "/v1/seal",
            f.grant.credential.as_str(),
            StatusCode::UPGRADE_REQUIRED,
        ),
        (
            IngressSecurity::Tls,
            "GET",
            "/v1/seal",
            f.grant.credential.as_str(),
            StatusCode::METHOD_NOT_ALLOWED,
        ),
        (
            IngressSecurity::Tls,
            "POST",
            "/v1/seal?target=other",
            f.grant.credential.as_str(),
            StatusCode::BAD_REQUEST,
        ),
        (
            IngressSecurity::Tls,
            "POST",
            "/v1/seal",
            "tenant",
            StatusCode::UNAUTHORIZED,
        ),
        (
            IngressSecurity::Tls,
            "POST",
            "/v1/seal",
            "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
            StatusCode::FORBIDDEN,
        ),
    ] {
        let (status, body) = send(&f, security, method, path, token, seal()).await;
        assert_eq!(status, expected, "{method} {path}: {body}");
    }
    for (field, value) in [
        ("workspace", "bob"),
        ("tenant", "other"),
        ("purpose", "digitalmate-config"),
    ] {
        let mut body = seal();
        body["context"][field] = json!(value);
        assert_eq!(
            f.post("/v1/seal", body).await.0,
            StatusCode::FORBIDDEN,
            "cross-{field}"
        );
    }
    assert!(f.backend.0.lock().unwrap().is_empty());
    assert!(f.headers.lock().unwrap().is_empty());
}

#[tokio::test]
async fn revoked_grant_or_authority_outage_denies_before_activation() {
    let mut f = fixture_crypto("localhost", 5).await;
    f.activator
        .revoke_service_grant(&RevokeServiceGrant {
            credential_digest: f.grant.credential_digest.clone(),
        })
        .await
        .unwrap();
    assert_eq!(f.post("/v1/seal", seal()).await.0, StatusCode::FORBIDDEN);
    f.authority_shutdown.take().unwrap().send(()).unwrap();
    tokio::time::timeout(Duration::from_secs(3), &mut f.tasks[0])
        .await
        .unwrap()
        .unwrap();
    let (_, body) = f.post("/v1/seal", seal()).await;
    assert_eq!(body["code"], "AUTHORITY_UNAVAILABLE");
    assert!(f.backend.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn managed_crypto_deadline_closes_stalled_exchange_without_replaying_request() {
    let f = fixture_crypto("localhost", 1).await;
    f.stall.store(true, std::sync::atomic::Ordering::SeqCst);
    let start = std::time::Instant::now();
    let (status, body) = f.post("/v1/seal", seal()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["code"], "CRYPTO_UNAVAILABLE");
    assert!(start.elapsed() < Duration::from_secs(3));
    assert_eq!(
        f.headers.lock().unwrap().len(),
        1,
        "unknown outcome must not replay"
    );
    tokio::time::timeout(Duration::from_millis(500), async {
        while f.gateway.active_sessions() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("deadline must release the shared Relay session");
    f.stall.store(false, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        f.post("/v1/seal", seal()).await.0,
        StatusCode::OK,
        "cancelled exchange must release the only endpoint permit"
    );
}

#[tokio::test]
async fn managed_crypto_rejects_untrusted_backend_tls_without_forwarding_plaintext() {
    let f = fixture_crypto("wrong-server.example", 5).await;
    let (status, body) = f.post("/v1/seal", seal()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["code"], "CRYPTO_UNAVAILABLE");
    assert!(f.headers.lock().unwrap().is_empty());
}

#[tokio::test]
async fn managed_crypto_bounds_bodies_and_rejects_upgrade_and_ambiguous_auth() {
    let f = fixture_crypto("localhost", 5).await;
    let body = json!({"context":context(),"plaintext":"A".repeat(524_288)});
    assert_eq!(
        f.post("/v1/seal", body).await.0,
        StatusCode::PAYLOAD_TOO_LARGE
    );
    for header in ["authorization", "upgrade"] {
        let (mut sender, server, client) =
            connection(f.gateway.clone(), IngressSecurity::Tls).await;
        let mut r = request("POST", "/v1/seal", &f.grant.credential, "crypto", seal());
        r.headers_mut().append(header, "untrusted".parse().unwrap());
        let response = sender.send_request(r).await.unwrap();
        assert!(response.status().is_client_error());
        response.collect().await.unwrap();
        server.abort();
        client.abort();
    }
    assert!(f.backend.0.lock().unwrap().is_empty());
}

#[tokio::test]
async fn managed_crypto_configuration_fails_closed_before_serving() {
    let f = fixture_crypto("localhost", 5).await;
    let managed = Arc::new(ManagedService::new(Arc::new(LocalControl::new(
        f.activator.clone(),
    ))));
    let value = json!({
        "scope":scope("credential-crypto", "shared"), "port":18443, "server_name":"localhost",
        "ca_file":f._directory.path().join("ca.pem"), "timeout_seconds":60
    });
    assert!(CredentialCryptoApi::new(
        serde_json::from_value(value.clone()).unwrap(),
        managed.clone()
    )
    .is_ok());
    for (field, invalid) in [
        ("port", json!(0)),
        ("timeout_seconds", json!(0)),
        ("timeout_seconds", json!(301)),
        ("server_name", json!("https://localhost/path")),
        ("frontend_host", json!("https://crypto.example/path")),
        ("frontend_host", json!("crypto.example:443")),
        (
            "scope",
            json!({"tenant":"", "template":"crypto", "template_ref":{"version":"1"},"binding_id":"shared"}),
        ),
        ("ca_file", json!(f._directory.path().join("verification"))),
    ] {
        let mut invalid_config = value.clone();
        invalid_config[field] = invalid;
        assert!(
            CredentialCryptoApi::new(
                serde_json::from_value(invalid_config).unwrap(),
                managed.clone()
            )
            .is_err(),
            "accepted invalid {field}"
        );
    }
}

#[tokio::test]
async fn crypto_host_and_application_routes_must_not_overlap() {
    let f = fixture_crypto("localhost", 5).await;
    let managed = Arc::new(ManagedService::new(Arc::new(LocalControl::new(
        f.activator.clone(),
    ))));
    let config = json!({
        "scope":scope("credential-crypto", "shared"), "port":18443, "server_name":"localhost",
        "ca_file":f._directory.path().join("ca.pem"), "timeout_seconds":60
    });
    let route = crate::ingress::ProxyRoute {
        name: "application".into(),
        path_prefix: "/v1/open".into(),
        upstream: "http://127.0.0.1:9000".into(),
        strip_prefix: false,
        host: Some("app.example.test".into()),
    };
    let legacy = CredentialCryptoApi::new(
        serde_json::from_value(config.clone()).unwrap(),
        managed.clone(),
    )
    .unwrap();
    assert!(legacy.conflicts_proxy_routes(std::slice::from_ref(&route)));
    assert!(legacy.conflicts_control_plane_routes(&[StaticRoute::Prefix("/v1".into())]));
    assert!(!legacy.conflicts_control_plane_routes(&[StaticRoute::Exact("/healthz".into())]));
    let mut host_config = config;
    host_config["frontend_host"] = json!("crypto.example.test");
    let separate =
        CredentialCryptoApi::new(serde_json::from_value(host_config).unwrap(), managed).unwrap();
    assert!(!separate.conflicts_proxy_routes(std::slice::from_ref(&route)));
    let request = Request::builder()
        .uri("/v1/open")
        .header("host", "CRYPTO.EXAMPLE.TEST:443")
        .body(())
        .unwrap();
    assert!(separate.matches_host(&request));
    let other = Request::builder()
        .uri("/v1/open")
        .header("host", "app.example.test")
        .body(())
        .unwrap();
    assert!(!separate.matches_host(&other));
    let mut catch_all = route;
    catch_all.host = None;
    catch_all.path_prefix = "/".into();
    assert!(separate.conflicts_proxy_routes(&[catch_all]));
}
