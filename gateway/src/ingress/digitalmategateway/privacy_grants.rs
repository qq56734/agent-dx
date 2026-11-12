//! Workspace identity validation for the DigitalMate privacy service.

use adx_agent_core::{AgentBinding, BindingPhase, Scope};
use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine};
use ring::rand::{SecureRandom, SystemRandom};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

#[derive(Debug, thiserror::Error)]
pub(crate) enum GrantError {
    #[error("workspace identity generation unavailable")]
    Unavailable,
}

pub(crate) fn generate_token() -> Result<Zeroizing<String>, GrantError> {
    let mut bytes = Zeroizing::new([0u8; 32]);
    SystemRandom::new()
        .fill(bytes.as_mut())
        .map_err(|_| GrantError::Unavailable)?;
    Ok(Zeroizing::new(URL_SAFE_NO_PAD.encode(bytes.as_ref())))
}

pub(crate) fn digest_token(token: &str) -> Option<String> {
    if token.len() != 43 {
        return None;
    }
    let decoded = Zeroizing::new(URL_SAFE_NO_PAD.decode(token.as_bytes()).ok()?);
    if decoded.len() != 32 || URL_SAFE_NO_PAD.encode(decoded.as_slice()) != token {
        return None;
    }
    Some(hex::encode(Sha256::digest(token.as_bytes())))
}

pub(crate) struct Grant {
    pub scope: Scope,
    pub workspace: String,
    /// The private identity directory is unique to this Binding creation attempt.
    pub identity: String,
    pub generation: String,
    pub expires_at: i64,
    pub revoked: bool,
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum GrantDecision {
    Allow,
    Deny,
}

impl Grant {
    pub fn check(&self, binding: &AgentBinding, now: i64) -> GrantDecision {
        if self.revoked
            || self.expires_at <= now
            || !safe_component(&self.workspace)
            || !safe_component(&self.identity)
            || self.scope.validate().is_err()
            || binding.phase != BindingPhase::Active
            || binding.scope != self.scope
            || binding.parameters.get("workspace") != Some(&self.workspace)
            || binding.parameters.get("privacy_identity") != Some(&self.identity)
            || self.generation.is_empty()
            || self.generation != binding.generation
        {
            return GrantDecision::Deny;
        }
        GrantDecision::Allow
    }
}

fn safe_component(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::{digest_token, generate_token, Grant, GrantDecision};
    use adx_agent_core::{AgentBinding, BindingPhase, EnvironmentRef, Scope, TemplateRef};
    use std::collections::BTreeMap;

    fn binding() -> AgentBinding {
        AgentBinding {
            scope: Scope {
                tenant: "tenant".into(),
                template: "digitalmate".into(),
                template_ref: TemplateRef::Version("1".into()),
                binding_id: "binding-a".into(),
            },
            generation: "generation-a".into(),
            current: EnvironmentRef::new("1".into(), "instance-a".into()),
            secondary: None,
            phase: BindingPhase::Active,
            parameters: BTreeMap::from([
                ("workspace".into(), "workspace-a".into()),
                ("privacy_identity".into(), "identity-a".into()),
            ]),
            volumes: BTreeMap::new(),
            creation_attempts: BTreeMap::new(),
        }
    }

    fn grant() -> Grant {
        Grant {
            scope: binding().scope,
            workspace: "workspace-a".into(),
            identity: "identity-a".into(),
            generation: "generation-a".into(),
            expires_at: 200,
            revoked: false,
        }
    }

    #[test]
    fn grant_is_bound_to_the_active_workspace_identity_and_generation() {
        assert_eq!(grant().check(&binding(), 100), GrantDecision::Allow);
        let mut changed = binding();
        changed.generation = "generation-b".into();
        assert_eq!(grant().check(&changed, 100), GrantDecision::Deny);
        let mut changed = binding();
        changed
            .parameters
            .insert("workspace".into(), "workspace-b".into());
        assert_eq!(grant().check(&changed, 100), GrantDecision::Deny);
        let mut changed = binding();
        changed
            .parameters
            .insert("privacy_identity".into(), "identity-b".into());
        assert_eq!(grant().check(&changed, 100), GrantDecision::Deny);
        let mut changed = binding();
        changed.phase = BindingPhase::Deleting;
        assert_eq!(grant().check(&changed, 100), GrantDecision::Deny);
        let mut changed = binding();
        changed.scope.binding_id = "binding-b".into();
        assert_eq!(grant().check(&changed, 100), GrantDecision::Deny);
    }

    #[test]
    fn expired_and_revoked_grants_are_never_reused() {
        assert_eq!(grant().check(&binding(), 200), GrantDecision::Deny);
        let mut revoked = grant();
        revoked.revoked = true;
        assert_eq!(revoked.check(&binding(), 100), GrantDecision::Deny);
    }

    #[test]
    fn missing_generation_is_never_authorized() {
        let mut pending = grant();
        pending.generation.clear();
        assert_eq!(pending.check(&binding(), 100), GrantDecision::Deny);
        let mut changed = binding();
        changed
            .parameters
            .insert("privacy_identity".into(), "identity-b".into());
        assert_eq!(pending.check(&changed, 100), GrantDecision::Deny);
    }

    #[test]
    fn tokens_are_random_private_bearers_with_canonical_digests() {
        let first = generate_token().unwrap();
        let second = generate_token().unwrap();
        assert_ne!(*first, *second);
        assert_eq!(first.len(), 43);
        assert_ne!(digest_token(&first), digest_token(&second));
        assert_eq!(digest_token(&first).unwrap().len(), 64);
        assert!(digest_token("").is_none());
        assert!(digest_token(&format!("{}!", first.as_str())).is_none());
        assert!(digest_token(&"x".repeat(4096)).is_none());
    }
}
