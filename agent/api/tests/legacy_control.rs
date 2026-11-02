use adx_agent_api::{
    activator::Control, managed::ManagedService, request::RequestContext, Error, Result,
};
use adx_agent_core::{
    activator::*,
    service_grants::{ServiceAccess, VerifyServiceGrant},
    AgentBinding, Scope, TemplateDraft, TemplateVersion,
};
use async_trait::async_trait;
use std::{
    sync::{
        atomic::{AtomicUsize, Ordering},
        Arc,
    },
    time::Duration,
};

// An implementation written before service-grant verification existed.
struct LegacyControl(AtomicUsize);

#[async_trait]
impl Control for LegacyControl {
    async fn resolve(&self, _: &RequestContext, _: &ResolveRequest) -> Result<ResolvedTarget> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Error::Unsupported("unused".into()))
    }
    async fn binding_view(&self, _: &RequestContext, _: &Scope) -> Result<BindingView> {
        Err(Error::Unsupported("unused".into()))
    }
    async fn update_alias(&self, _: &RequestContext, _: &AliasUpdate) -> Result<AliasSnapshot> {
        Err(Error::Unsupported("unused".into()))
    }
    async fn publish(
        &self,
        _: &RequestContext,
        _: &str,
        _: &TemplateDraft,
    ) -> Result<TemplateVersion> {
        Err(Error::Unsupported("unused".into()))
    }
    async fn template(
        &self,
        _: &RequestContext,
        _: &str,
        _: &str,
        _: &str,
    ) -> Result<TemplateVersion> {
        Err(Error::Unsupported("unused".into()))
    }
    async fn binding(&self, _: &RequestContext, _: &Scope) -> Result<AgentBinding> {
        Err(Error::Unsupported("unused".into()))
    }
    async fn list_bindings(&self, _: &RequestContext, _: &BindingList) -> Result<BindingPage> {
        Err(Error::Unsupported("unused".into()))
    }
    async fn delete_binding(&self, _: &RequestContext, _: &Scope) -> Result<()> {
        Err(Error::Unsupported("unused".into()))
    }
    async fn activate(&self, _: &RequestContext, _: &Scope, _: Option<&str>) -> Result<Target> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Error::Unsupported("unused".into()))
    }
    async fn activate_with_cache(
        &self,
        _: &RequestContext,
        _: &Scope,
        _: Option<&str>,
        _: bool,
    ) -> Result<Target> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Err(Error::Unsupported("unused".into()))
    }
}

#[tokio::test]
async fn legacy_control_rejects_service_grants_by_default() {
    let control = Arc::new(LegacyControl(AtomicUsize::new(0)));
    let ctx = RequestContext::new(Duration::from_secs(1));
    let request = VerifyServiceGrant {
        credential: "fixture".into(),
        expected: ServiceAccess {
            tenant: "tenant".into(),
            workspace: "workspace".into(),
            purpose: "orbit-config".into(),
        },
    };
    assert!(matches!(
        control.verify_service_grant(&ctx, &request).await,
        Err(Error::Unsupported(_))
    ));
    let managed = ManagedService::new(control.clone());
    assert!(matches!(
        managed.verify_service_grant(&ctx, &request).await,
        Err(Error::Unsupported(_))
    ));
    assert_eq!(control.0.load(Ordering::SeqCst), 0);
}
