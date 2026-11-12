//! Delivery of short-lived business identities over a read-only per-workspace mount.

#[cfg(unix)]
mod implementation {
    use super::super::privacy_center::BindingReader;
    use super::super::privacy_grants::{digest_token, generate_token};
    use crate::ingress::accounts::{AccountStore, Error, PrivacyOwner};
    use adx_agent_core::{BindingPhase, Scope};
    use serde::{Deserialize, Serialize};
    use std::{
        fs,
        io::Write,
        os::unix::fs::{MetadataExt, PermissionsExt},
        path::{Path, PathBuf},
        sync::Arc,
        time::{SystemTime, UNIX_EPOCH},
    };
    use zeroize::Zeroizing;

    #[derive(Clone, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct DeliveryConfig {
        pub template: String,
        pub root: PathBuf,
        pub ca_file: PathBuf,
        pub uid: u32,
        pub gid: u32,
        pub ttl_seconds: u64,
        pub renew_before_seconds: u64,
    }

    #[derive(Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct Delivered {
        scope: Scope,
        workspace: String,
        user: String,
        identity: String,
        generation: Option<String>,
        credential_digest: Option<String>,
        expires_at: i64,
        pending_revocations: Vec<String>,
    }

    pub(crate) struct Delivery {
        config: DeliveryConfig,
        store: AccountStore,
        bindings: Arc<dyn BindingReader>,
        renewal_permits: tokio::sync::Semaphore,
    }

    fn component(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 128
            && value
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-'))
    }

    fn directory(path: &Path, mode: u32) -> Result<(), Error> {
        let created = match fs::symlink_metadata(path) {
            Ok(meta) if !meta.is_dir() || meta.file_type().is_symlink() => {
                return Err(Error::Configuration)
            }
            Ok(meta) => {
                // SAFETY: geteuid takes no pointers and has no preconditions.
                let effective_uid = unsafe { libc::geteuid() };
                if meta.uid() != effective_uid
                    || meta.mode() & 0o022 != 0
                    || (mode == 0o700 && meta.mode() & 0o077 != 0)
                {
                    return Err(Error::Configuration);
                }
                false
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir_all(path).map_err(|_| Error::Unavailable)?;
                true
            }
            Err(_) => return Err(Error::Unavailable),
        };
        if created {
            fs::set_permissions(path, fs::Permissions::from_mode(mode))
                .map_err(|_| Error::Unavailable)?;
        }
        Ok(())
    }

    fn atomic(path: &Path, data: &[u8], mode: u32, owner: Option<(u32, u32)>) -> Result<(), Error> {
        let parent = path.parent().ok_or(Error::Configuration)?;
        let mut temp = tempfile::NamedTempFile::new_in(parent).map_err(|_| Error::Unavailable)?;
        temp.write_all(data).map_err(|_| Error::Unavailable)?;
        temp.as_file()
            .set_permissions(fs::Permissions::from_mode(mode))
            .map_err(|_| Error::Unavailable)?;
        if let Some((uid, gid)) = owner {
            std::os::unix::fs::chown(temp.path(), Some(uid), Some(gid))
                .map_err(|_| Error::Unavailable)?;
        }
        temp.as_file().sync_all().map_err(|_| Error::Unavailable)?;
        temp.persist(path).map_err(|_| Error::Unavailable)?;
        fs::File::open(parent)
            .and_then(|f| f.sync_all())
            .map_err(|_| Error::Unavailable)
    }

    fn now() -> Result<i64, Error> {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| Error::Unavailable)?
            .as_secs();
        i64::try_from(seconds).map_err(|_| Error::Unavailable)
    }

    impl Delivery {
        pub fn targets(&self, template: &str) -> bool {
            self.config.template == template
        }
        pub fn new(
            config: DeliveryConfig,
            store: AccountStore,
            bindings: Arc<dyn BindingReader>,
        ) -> Result<Self, Error> {
            if adx_agent_core::identifier(&config.template, "privacy delivery template").is_err()
                || !config.root.is_absolute()
                || !config.ca_file.is_absolute()
                || !(60..=86_400).contains(&config.ttl_seconds)
                || config.renew_before_seconds == 0
                || config.renew_before_seconds >= config.ttl_seconds
            {
                return Err(Error::Configuration);
            }
            directory(&config.root, 0o711)?;
            directory(&config.root.join("metadata"), 0o700)?;
            directory(&config.root.join("users"), 0o711)?;
            Ok(Self {
                config,
                store,
                bindings,
                renewal_permits: tokio::sync::Semaphore::new(4),
            })
        }

        fn reference(&self, identity: &str) -> Result<PathBuf, Error> {
            if !component(identity) {
                return Err(Error::Invalid);
            }
            Ok(self
                .config
                .root
                .join("metadata")
                .join(format!("{identity}.json")))
        }

        pub fn token_path(&self, identity: &str) -> Result<PathBuf, Error> {
            if !component(identity) {
                return Err(Error::Invalid);
            }
            Ok(self
                .config
                .root
                .join("users")
                .join(identity)
                .join("identity"))
        }

        fn load(&self, identity: &str) -> Result<Delivered, Error> {
            let path = self.reference(identity)?;
            let meta = fs::symlink_metadata(&path).map_err(|_| Error::Unavailable)?;
            if !meta.is_file() || meta.file_type().is_symlink() || meta.len() > 65_536 {
                return Err(Error::Unavailable);
            }
            let delivered: Delivered =
                serde_json::from_slice(&fs::read(path).map_err(|_| Error::Unavailable)?)
                    .map_err(|_| Error::Unavailable)?;
            if delivered.identity != identity
                || !component(&delivered.workspace)
                || delivered.scope.validate().is_err()
                || delivered.scope.template != self.config.template
                || delivered.pending_revocations.len() > 128
            {
                return Err(Error::Unavailable);
            }
            Ok(delivered)
        }

        fn save(&self, delivered: &Delivered) -> Result<(), Error> {
            atomic(
                &self.reference(&delivered.identity)?,
                &serde_json::to_vec(delivered).map_err(|_| Error::Unavailable)?,
                0o600,
                None,
            )
        }

        pub async fn prepare(
            &self,
            scope: &Scope,
            workspace: &str,
            user: &str,
        ) -> Result<String, Error> {
            if scope.validate().is_err()
                || scope.template != self.config.template
                || !component(workspace)
                || adx_agent_core::identifier(user, "privacy owner").is_err()
                || user.len() > 128
            {
                return Err(Error::Invalid);
            }
            let identity = format!("i-{}", uuid::Uuid::new_v4().simple());
            let user_dir = self.config.root.join("users").join(&identity);
            fs::create_dir(&user_dir).map_err(|_| Error::Unavailable)?;
            fs::set_permissions(&user_dir, fs::Permissions::from_mode(0o700))
                .map_err(|_| Error::Unavailable)?;
            std::os::unix::fs::chown(&user_dir, Some(self.config.uid), Some(self.config.gid))
                .map_err(|_| Error::Unavailable)?;
            let ca = fs::read(&self.config.ca_file).map_err(|_| Error::Unavailable)?;
            if ca.is_empty() || ca.len() > 65_536 {
                return Err(Error::Configuration);
            }
            atomic(
                &user_dir.join("ca.pem"),
                &ca,
                0o400,
                Some((self.config.uid, self.config.gid)),
            )?;
            self.save(&Delivered {
                scope: scope.clone(),
                workspace: workspace.into(),
                user: user.into(),
                identity: identity.clone(),
                generation: None,
                credential_digest: None,
                expires_at: 0,
                pending_revocations: Vec::new(),
            })?;
            Ok(identity)
        }

        pub async fn renew(&self, identity: &str) -> Result<(), Error> {
            let _permit = self
                .renewal_permits
                .try_acquire()
                .map_err(|_| Error::Unavailable)?;
            self.store
                .privacy_with_lock(identity, || self.renew_locked(identity))
                .await
        }

        /// Refresh only previously prepared identities; this never wakes an ADX instance.
        pub async fn scan(&self) -> Result<(), Error> {
            let entries =
                fs::read_dir(self.config.root.join("metadata")).map_err(|_| Error::Unavailable)?;
            let current = now()?;
            let mut unavailable = false;
            for entry in entries {
                let entry = entry.map_err(|_| Error::Unavailable)?;
                let path = entry.path();
                if path.extension().and_then(|value| value.to_str()) != Some("json") {
                    continue;
                }
                let Some(identity) = path.file_stem().and_then(|value| value.to_str()) else {
                    unavailable = true;
                    continue;
                };
                let saved = match self.load(identity) {
                    Ok(saved) => saved,
                    Err(_) => {
                        unavailable = true;
                        continue;
                    }
                };
                if saved.generation.is_some()
                    && saved.pending_revocations.is_empty()
                    && saved.expires_at
                        > current.saturating_add(self.config.renew_before_seconds as i64)
                {
                    let token = Zeroizing::new(
                        fs::read_to_string(self.token_path(identity)?).unwrap_or_default(),
                    );
                    if digest_token(token.trim()).as_ref() == saved.credential_digest.as_ref()
                        && saved.credential_digest.is_some()
                    {
                        continue;
                    }
                }
                match self.renew(identity).await {
                    Ok(()) | Err(Error::Conflict | Error::Unauthorized) => (),
                    Err(_) => unavailable = true,
                }
            }
            if unavailable {
                Err(Error::Unavailable)
            } else {
                Ok(())
            }
        }

        async fn renew_locked(&self, identity: &str) -> Result<(), Error> {
            let mut saved = self.load(identity)?;
            let binding = self.bindings.binding(&saved.scope).await?;
            if binding.phase != BindingPhase::Active
                || binding.scope != saved.scope
                || binding.parameters.get("workspace") != Some(&saved.workspace)
                || binding.parameters.get("privacy_identity") != Some(&saved.identity)
                || binding.generation.is_empty()
            {
                return Err(Error::Conflict);
            }
            match &saved.generation {
                Some(generation) if generation != &binding.generation => {
                    return Err(Error::Conflict)
                }
                Some(_) => (),
                None => {
                    saved.generation = Some(binding.generation.clone());
                    self.save(&saved)?;
                }
            }
            let current = now()?;
            if saved.expires_at > current.saturating_add(self.config.renew_before_seconds as i64) {
                if let Some(digest) = &saved.credential_digest {
                    let token = Zeroizing::new(
                        fs::read_to_string(self.token_path(identity)?).unwrap_or_default(),
                    );
                    let valid_file = digest_token(token.trim()).as_ref() == Some(digest);
                    let valid_grant =
                        self.store
                            .privacy_get_grant(digest)
                            .await?
                            .is_some_and(|grant| {
                                !grant.revoked
                                    && grant.generation == binding.generation
                                    && grant.identity == identity
                            });
                    if valid_file && valid_grant {
                        return self.finish_revocations(&mut saved).await;
                    }
                }
            }
            let (token, _) = self.issue_and_journal(&mut saved, current).await?;
            atomic(
                &self.token_path(identity)?,
                token.as_bytes(),
                0o400,
                Some((self.config.uid, self.config.gid)),
            )?;
            self.finish_revocations(&mut saved).await
        }

        async fn issue_and_journal(
            &self,
            saved: &mut Delivered,
            current: i64,
        ) -> Result<(Zeroizing<String>, String), Error> {
            let generation = saved.generation.as_deref().ok_or(Error::Conflict)?;
            let token = generate_token().map_err(|_| Error::Unavailable)?;
            let digest = digest_token(&token).ok_or(Error::Unavailable)?;
            let expires_at = current
                .checked_add(self.config.ttl_seconds as i64)
                .ok_or(Error::Unavailable)?;
            let owner = PrivacyOwner {
                tenant: &saved.scope.tenant,
                workspace: &saved.workspace,
                user: &saved.user,
            };
            self.store
                .privacy_issue_grant(
                    &digest,
                    &owner,
                    &saved.scope,
                    &saved.identity,
                    generation,
                    expires_at,
                )
                .await?;
            if let Some(old) = saved.credential_digest.replace(digest.clone()) {
                saved.pending_revocations.push(old);
            }
            saved.pending_revocations.sort_unstable();
            saved.pending_revocations.dedup();
            if saved.pending_revocations.len() > 128 {
                return Err(Error::Unavailable);
            }
            saved.expires_at = expires_at;
            self.save(saved)?;
            Ok((token, digest))
        }

        async fn finish_revocations(&self, saved: &mut Delivered) -> Result<(), Error> {
            if saved
                .credential_digest
                .as_ref()
                .is_some_and(|current| saved.pending_revocations.contains(current))
            {
                return Err(Error::Unavailable);
            }
            for digest in &saved.pending_revocations {
                self.store.privacy_revoke_grant(digest).await?;
            }
            if !saved.pending_revocations.is_empty() {
                saved.pending_revocations.clear();
                self.save(saved)?;
            }
            Ok(())
        }

        #[cfg(test)]
        pub async fn inject_unpublished_replacement_for_test(&self, identity: &str) {
            let mut saved = self.load(identity).unwrap();
            let _ = self
                .issue_and_journal(&mut saved, now().unwrap())
                .await
                .unwrap();
        }
    }
}

#[cfg(unix)]
pub(crate) use implementation::{Delivery, DeliveryConfig};

#[cfg(all(test, unix))]
mod tests {
    use super::{Delivery, DeliveryConfig};
    use crate::ingress::accounts::{AccountStore, Error};
    use crate::ingress::digitalmategateway::privacy_center::BindingReader;
    use crate::ingress::digitalmategateway::privacy_grants::digest_token;
    use adx_agent_core::{AgentBinding, BindingPhase, EnvironmentRef, Scope, TemplateRef};
    use async_trait::async_trait;
    use std::{collections::BTreeMap, os::unix::fs::PermissionsExt, sync::Arc};
    use tokio::sync::Mutex;

    struct Binding(Mutex<Option<AgentBinding>>);
    #[async_trait]
    impl BindingReader for Binding {
        async fn binding(&self, scope: &Scope) -> Result<AgentBinding, Error> {
            let value = self.0.lock().await.clone().ok_or(Error::Unauthorized)?;
            if value.scope != *scope {
                return Err(Error::Unauthorized);
            }
            Ok(value)
        }
    }

    #[tokio::test]
    #[ignore = "requires a dedicated disposable PostgreSQL database"]
    async fn identity_is_delivered_only_to_its_generation_and_recovers_rotation() {
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
        let user = format!("privacy-delivery-{}", uuid::Uuid::new_v4());
        client.execute("INSERT INTO adx_accounts.users(user_id,provider,developer_scope,client_id,union_id,agreement_version) VALUES($1,'test','privacy-test','test',$1,'1')", &[&user]).await.unwrap();
        let store = AccountStore::from_url(&url, true, None).await.unwrap();
        let bindings = Arc::new(Binding(Mutex::new(None)));
        let temp = tempfile::tempdir().unwrap();
        let ca = temp.path().join("ca.pem");
        std::fs::write(&ca, "synthetic-test-ca").unwrap();
        // SAFETY: these process identity calls take no pointers or preconditions.
        let uid = unsafe { libc::geteuid() };
        // SAFETY: getegid takes no pointers and has no preconditions.
        let gid = unsafe { libc::getegid() };
        let config = DeliveryConfig {
            template: "digitalmate".into(),
            root: temp.path().join("delivery"),
            ca_file: ca,
            uid,
            gid,
            ttl_seconds: 3600,
            renew_before_seconds: 1200,
        };
        let delivery = Delivery::new(config, store.clone(), bindings.clone()).unwrap();
        let scope = Scope {
            tenant: "tenant-a".into(),
            template: "digitalmate".into(),
            template_ref: TemplateRef::Version("1".into()),
            binding_id: format!("binding-{}", uuid::Uuid::new_v4()),
        };
        let identity = delivery
            .prepare(&scope, "workspace-a", &user)
            .await
            .unwrap();
        let token_path = delivery.token_path(&identity).unwrap();
        assert!(!token_path.exists());
        let binding = AgentBinding {
            scope: scope.clone(),
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
        };
        *bindings.0.lock().await = Some(binding);
        delivery.renew(&identity).await.unwrap();
        let first = std::fs::read_to_string(&token_path).unwrap();
        let first_digest = digest_token(&first).unwrap();
        assert_eq!(
            std::fs::metadata(&token_path).unwrap().permissions().mode() & 0o777,
            0o400
        );
        assert!(
            !store
                .privacy_get_grant(&first_digest)
                .await
                .unwrap()
                .unwrap()
                .revoked
        );
        delivery.renew(&identity).await.unwrap();
        assert_eq!(std::fs::read_to_string(&token_path).unwrap(), first);
        // A saved replacement whose file was never published is recovered, and every old digest is revoked.
        delivery
            .inject_unpublished_replacement_for_test(&identity)
            .await;
        delivery.renew(&identity).await.unwrap();
        let replaced = std::fs::read_to_string(&token_path).unwrap();
        assert_ne!(replaced, first);
        assert!(
            store
                .privacy_get_grant(&first_digest)
                .await
                .unwrap()
                .unwrap()
                .revoked
        );
        bindings.0.lock().await.as_mut().unwrap().generation = "generation-b".into();
        assert!(matches!(
            delivery.renew(&identity).await,
            Err(Error::Conflict)
        ));
        assert_eq!(std::fs::read_to_string(&token_path).unwrap(), replaced);
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
