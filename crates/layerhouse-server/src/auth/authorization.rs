use async_trait::async_trait;

use crate::error::LayerhouseError;
use crate::store::metadata::NamespaceStore;
use crate::store::metadata::handle::handle_of;
use crate::store::metadata::{Namespace, NamespaceEpoch};

use super::permissions::OciAction;
use super::principal::Actor;

#[derive(Debug, Clone)]
pub struct AuthzRequest {
    pub actor: Actor,
    pub repository: String,
    pub resource: Option<RepositoryResource>,
    pub action: OciAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NamespaceResource {
    pub epoch: NamespaceEpoch,
}

impl NamespaceResource {
    pub fn from_namespace(namespace: &Namespace) -> Self {
        Self {
            epoch: NamespaceEpoch::from_namespace(namespace),
        }
    }

    pub fn entity_id(&self) -> String {
        self.epoch.entity_id()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RepositoryResource {
    pub namespace: NamespaceResource,
    pub relative_path: String,
}

impl RepositoryResource {
    pub fn from_repository(
        repository: &str,
        namespace: &Namespace,
    ) -> Result<Self, LayerhouseError> {
        let handle = handle_of(repository)?;
        if handle != namespace.handle {
            return Err(LayerhouseError::NameInvalid(format!(
                "repository {repository:?} is not under namespace {:?}",
                namespace.handle
            )));
        }
        let relative_path = repository
            .strip_prefix(&format!("{handle}/"))
            .ok_or_else(|| {
                LayerhouseError::NameInvalid(format!(
                    "repository {repository:?} is not under namespace {handle:?}"
                ))
            })?
            .to_string();
        Ok(Self {
            namespace: NamespaceResource::from_namespace(namespace),
            relative_path,
        })
    }

    pub fn entity_id(&self) -> String {
        format!("{}/{}", self.namespace.entity_id(), self.relative_path)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AuthorizedRepositoryAccess {
    pub repository: String,
    pub action: OciAction,
    pub expected_namespace: Option<NamespaceEpoch>,
}

impl AuthorizedRepositoryAccess {
    pub fn new(
        repository: impl Into<String>,
        action: OciAction,
        expected_namespace: Option<NamespaceEpoch>,
    ) -> Self {
        Self {
            repository: repository.into(),
            action,
            expected_namespace,
        }
    }

    pub fn record_expected_namespace(&self, epochs: &mut Vec<NamespaceEpoch>) {
        let Some(epoch) = self.expected_namespace.as_ref() else {
            return;
        };
        if !epochs.iter().any(|existing| existing == epoch) {
            epochs.push(epoch.clone());
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthzDecision {
    Allow,
    Deny,
}

#[async_trait]
#[allow(dead_code)]
pub trait Authorizer {
    async fn authorize(
        &self,
        request: &AuthzRequest,
        namespaces: &dyn NamespaceStore,
    ) -> Result<AuthzDecision, LayerhouseError>;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::Subject;
    use crate::store::metadata::Owner;

    fn namespace(handle: &str, generation: u64) -> Namespace {
        Namespace {
            handle: handle.to_string(),
            generation,
            owner: Owner::User(Subject::new("subject-alice")),
            owner_label: "alice".to_string(),
            created_at: 1,
        }
    }

    #[test]
    fn repository_resource_ids_include_namespace_generation() {
        let resource = RepositoryResource::from_repository("acme/api", &namespace("acme", 7))
            .expect("repository resource builds");

        assert_eq!(resource.namespace.entity_id(), "acme#7");
        assert_eq!(resource.relative_path, "api");
        assert_eq!(resource.entity_id(), "acme#7/api");
    }

    #[test]
    fn reclaimed_namespace_gets_distinct_repository_resource_id() {
        let old_resource = RepositoryResource::from_repository("acme/api", &namespace("acme", 1))
            .expect("old resource builds");
        let new_resource = RepositoryResource::from_repository("acme/api", &namespace("acme", 2))
            .expect("new resource builds");

        assert_ne!(old_resource.entity_id(), new_resource.entity_id());
        assert_eq!(old_resource.entity_id(), "acme#1/api");
        assert_eq!(new_resource.entity_id(), "acme#2/api");
    }
}
