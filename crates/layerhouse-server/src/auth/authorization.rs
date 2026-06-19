use async_trait::async_trait;

use crate::error::LayerhouseError;
use crate::store::metadata::NamespaceStore;

use super::permissions::OciAction;
use super::principal::Actor;

#[derive(Debug, Clone)]
pub struct AuthzRequest {
    pub actor: Actor,
    pub repository: String,
    pub action: OciAction,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzDecision {
    Allow,
    Deny,
}

#[async_trait]
pub trait Authorizer {
    async fn authorize(
        &self,
        request: &AuthzRequest,
        namespaces: &dyn NamespaceStore,
    ) -> Result<AuthzDecision, LayerhouseError>;
}
