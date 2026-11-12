//! Optional privacy service lifecycle owned by DigitalMateGateway.

#[cfg(unix)]
mod implementation {
    use super::super::privacy_center::{BindingReader, PrivacyCenter};
    use super::super::privacy_cipher::PrivacyCipher;
    use super::super::privacy_delivery::{Delivery, DeliveryConfig};
    use super::super::privacy_http::PrivacyHttp;
    use crate::ingress::accounts::{AccountStore, Error};
    use serde::Deserialize;
    use std::{net::SocketAddr, path::PathBuf, sync::Arc, time::Duration};
    use tokio::{sync::watch, task::JoinHandle};

    #[derive(Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct PrivacyRuntimeConfig {
        pub listen: SocketAddr,
        pub tls_certificate: PathBuf,
        pub tls_private_key: PathBuf,
        pub keyring_file: PathBuf,
        #[serde(default)]
        pub legacy_keyring_file: Option<PathBuf>,
        pub delivery: DeliveryConfig,
    }

    pub(crate) struct PrivacyRuntime {
        pub delivery: Arc<Delivery>,
        shutdown: watch::Sender<bool>,
        listener: JoinHandle<()>,
        renewal: JoinHandle<()>,
    }

    impl PrivacyRuntime {
        pub fn start(
            config: PrivacyRuntimeConfig,
            store: AccountStore,
            bindings: Arc<dyn BindingReader>,
            model_key: &[u8; 32],
        ) -> Result<Self, Error> {
            tokio::runtime::Handle::try_current().map_err(|_| Error::Configuration)?;
            let cipher = PrivacyCipher::load(&config.keyring_file, model_key)
                .map_err(|_| Error::Configuration)?;
            let tls = adx_transport::tls::http_server_acceptor(
                &config.tls_certificate,
                &config.tls_private_key,
                None,
                vec![b"http/1.1".to_vec()],
            )
            .map_err(|_| Error::Configuration)?;
            let listener =
                std::net::TcpListener::bind(config.listen).map_err(|_| Error::Unavailable)?;
            listener
                .set_nonblocking(true)
                .map_err(|_| Error::Unavailable)?;
            let listener =
                tokio::net::TcpListener::from_std(listener).map_err(|_| Error::Unavailable)?;
            let delivery = Arc::new(Delivery::new(
                config.delivery,
                store.clone(),
                bindings.clone(),
            )?);
            let mut center = PrivacyCenter::new(store, cipher, bindings);
            if let Some(path) = &config.legacy_keyring_file {
                let legacy =
                    PrivacyCipher::load(path, model_key).map_err(|_| Error::Configuration)?;
                center = center.with_legacy(legacy);
            }
            let center = Arc::new(center);
            let http = Arc::new(PrivacyHttp::new(center));
            let (shutdown, receiver) = watch::channel(false);
            let listener_task = tokio::spawn(async move {
                if http.serve(listener, tls, receiver).await.is_err() {
                    tracing::error!("DigitalMate privacy HTTPS listener stopped");
                }
            });
            let refresh = delivery.clone();
            let mut receiver = shutdown.subscribe();
            let renewal_task = tokio::spawn(async move {
                let mut interval = tokio::time::interval(Duration::from_secs(2));
                loop {
                    tokio::select! {
                        changed = receiver.changed() => if changed.is_err() || *receiver.borrow() { break; },
                        _ = interval.tick() => { let _ = refresh.scan().await; }
                    }
                }
            });
            Ok(Self {
                delivery,
                shutdown,
                listener: listener_task,
                renewal: renewal_task,
            })
        }
    }

    impl Drop for PrivacyRuntime {
        fn drop(&mut self) {
            let _ = self.shutdown.send(true);
            self.listener.abort();
            self.renewal.abort();
        }
    }
}

#[cfg(unix)]
pub(crate) use implementation::{PrivacyRuntime, PrivacyRuntimeConfig};

#[cfg(all(test, unix))]
mod tests {
    use super::{PrivacyRuntime, PrivacyRuntimeConfig};
    use crate::ingress::accounts::{AccountStore, Error};
    use crate::ingress::digitalmategateway::privacy_center::BindingReader;
    use crate::ingress::digitalmategateway::privacy_delivery::DeliveryConfig;
    use adx_agent_core::{AgentBinding, BindingPhase, EnvironmentRef, Scope, TemplateRef};
    use async_trait::async_trait;
    use base64::{engine::general_purpose::STANDARD, Engine};
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, sync::Arc};
    use tokio::sync::Mutex;

    struct Bindings(Mutex<Option<AgentBinding>>);
    #[async_trait]
    impl BindingReader for Bindings {
        async fn binding(&self, _: &Scope) -> Result<AgentBinding, Error> {
            self.0.lock().await.clone().ok_or(Error::Unauthorized)
        }
    }

    #[tokio::test]
    #[ignore = "requires a dedicated disposable PostgreSQL database"]
    async fn runtime_delivers_identity_after_binding_without_phone_session() {
        let url = std::env::var("DIGITALMATE_PRIVACY_TEST_DATABASE_URL")
            .expect("disposable database required");
        let (client, connection) = tokio_postgres::connect(&url, tokio_postgres::NoTls)
            .await
            .unwrap();
        tokio::spawn(async move { connection.await.unwrap() });
        client
            .query_one("SELECT pg_advisory_lock(741650271132)", &[])
            .await
            .unwrap();
        client
            .batch_execute(include_str!("../accounts/schema.sql"))
            .await
            .unwrap();
        client
            .query_one("SELECT pg_advisory_unlock(741650271132)", &[])
            .await
            .unwrap();
        let user = format!("privacy-runtime-{}", uuid::Uuid::new_v4());
        client.execute("INSERT INTO adx_accounts.users(user_id,provider,developer_scope,client_id,union_id,agreement_version) VALUES($1,'test','privacy-test','test',$1,'1')", &[&user]).await.unwrap();
        let store = AccountStore::from_url(&url, true, None).await.unwrap();
        let bindings = Arc::new(Bindings(Mutex::new(None)));
        let temp = tempfile::tempdir().unwrap();
        let keys = temp.path().join("privacy.json");
        std::fs::write(
            &keys,
            serde_json::json!({"active_key_id":"v1","keys":{"v1":STANDARD.encode([7;32])}})
                .to_string(),
        )
        .unwrap();
        std::fs::set_permissions(&keys, std::fs::Permissions::from_mode(0o600)).unwrap();
        let fixtures = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        // SAFETY: geteuid takes no pointers and has no preconditions.
        let uid = unsafe { libc::geteuid() };
        // SAFETY: getegid takes no pointers and has no preconditions.
        let gid = unsafe { libc::getegid() };
        let config = PrivacyRuntimeConfig {
            listen: "127.0.0.1:0".parse().unwrap(),
            tls_certificate: fixtures.join("ingress-cert.pem"),
            tls_private_key: fixtures.join("ingress-key.pem"),
            keyring_file: keys,
            legacy_keyring_file: None,
            delivery: DeliveryConfig {
                template: "digitalmate".into(),
                root: temp.path().join("delivery"),
                ca_file: fixtures.join("ingress-cert.pem"),
                uid,
                gid,
                ttl_seconds: 3600,
                renew_before_seconds: 1200,
            },
        };
        let runtime =
            PrivacyRuntime::start(config, store.clone(), bindings.clone(), &[8; 32]).unwrap();
        let scope = Scope {
            tenant: "tenant-a".into(),
            template: "digitalmate".into(),
            template_ref: TemplateRef::Version("1".into()),
            binding_id: format!("binding-{}", uuid::Uuid::new_v4()),
        };
        let identity = runtime
            .delivery
            .prepare(&scope, "workspace-a", &user)
            .await
            .unwrap();
        *bindings.0.lock().await = Some(AgentBinding {
            scope,
            generation: "generation-a".into(),
            current: EnvironmentRef::new("1".into(), "instance-a".into()),
            secondary: None,
            phase: BindingPhase::Active,
            parameters: BTreeMap::from([
                ("workspace".into(), "workspace-a".into()),
                ("privacy_identity".into(), identity.clone()),
            ]),
            volumes: BTreeMap::new(),
            creation_attempts: BTreeMap::new(),
        });
        let token_path = runtime.delivery.token_path(&identity).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(8), async {
            while !token_path.exists() {
                tokio::time::sleep(std::time::Duration::from_millis(50)).await;
            }
        })
        .await
        .unwrap();
        assert!(!std::fs::read_to_string(token_path).unwrap().is_empty());
        drop(runtime);
        client.execute("DELETE FROM adx_accounts.privacy_grants g USING adx_accounts.privacy_identities i WHERE i.user_id=$1 AND g.tenant_id=i.tenant_id AND g.identity_id=i.identity_id", &[&user]).await.unwrap();
        client
            .execute(
                "DELETE FROM adx_accounts.privacy_identities WHERE user_id=$1",
                &[&user],
            )
            .await
            .unwrap();
        client
            .execute("DELETE FROM adx_accounts.users WHERE user_id=$1", &[&user])
            .await
            .unwrap();
    }
}
