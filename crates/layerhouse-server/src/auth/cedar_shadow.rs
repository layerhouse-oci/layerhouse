use cedar_policy::{Authorizer, Context, Decision, Entities, EntityUid, PolicySet, Request};
use serde_json::{Value, json};
use std::collections::BTreeSet;

use crate::store::metadata::NamespaceEpoch;

use super::principal::{PrincipalKind, ProviderQualifiedId, stable_group_ids};

const STABLE_GROUP_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const SHADOW_POLICY: CedarPolicySource<'static> = CedarPolicySource(
    r#"
permit(
    principal == User::"test:user:subject-owner",
    action == Action::"pull",
    resource in Namespace::"acme#1"
);
permit(
    principal == User::"test:user:subject-owner",
    action == Action::"create",
    resource in Namespace::"acme#1"
);
permit(
    principal == User::"test:user:subject-owner",
    action == Action::"update",
    resource in Namespace::"acme#1"
);
permit(
    principal == User::"test:user:subject-owner",
    action == Action::"delete",
    resource in Namespace::"acme#1"
);
permit(
    principal in Group::"test:group:550e8400-e29b-41d4-a716-446655440000",
    action == Action::"pull",
    resource in Namespace::"acme#1"
);
permit(
    principal in Group::"test:group:550e8400-e29b-41d4-a716-446655440000",
    action == Action::"create",
    resource in Namespace::"acme#1"
);
"#,
);

#[derive(Debug, Clone, Copy)]
struct CedarPolicySource<'a>(&'a str);

impl CedarPolicySource<'_> {
    fn parse(self) -> Result<PolicySet, String> {
        self.0
            .parse::<PolicySet>()
            .map_err(|err| format!("invalid Cedar shadow policy: {err}"))
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CedarEntityType {
    User,
    Group,
    Namespace,
    Repository,
    Action,
}

impl CedarEntityType {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Group => "Group",
            Self::Namespace => "Namespace",
            Self::Repository => "Repository",
            Self::Action => "Action",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CedarAction {
    Pull,
    Create,
    Update,
    Delete,
}

impl CedarAction {
    fn as_str(self) -> &'static str {
        match self {
            Self::Pull => "pull",
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
        }
    }

    fn entity_uid(self) -> Result<EntityUid, String> {
        CedarEntityId::new(CedarEntityType::Action, self.as_str()).entity_uid()
    }
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct CedarEntityId {
    entity_type: CedarEntityType,
    id: String,
}

impl CedarEntityId {
    fn new(entity_type: CedarEntityType, id: impl Into<String>) -> Self {
        Self {
            entity_type,
            id: id.into(),
        }
    }

    fn from_principal(id: &ProviderQualifiedId) -> Self {
        let entity_type = match id.kind() {
            PrincipalKind::User => CedarEntityType::User,
            PrincipalKind::Group => CedarEntityType::Group,
        };
        Self::new(entity_type, id.to_string())
    }

    fn entity_uid(&self) -> Result<EntityUid, String> {
        format!(r#"{}::"{}""#, self.entity_type.as_str(), self.id)
            .parse()
            .map_err(|err| format!("invalid Cedar entity uid: {err}"))
    }

    fn json_uid(&self) -> Value {
        json!({ "type": self.entity_type.as_str(), "id": self.id })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CedarPrincipal {
    entity: CedarEntityId,
}

impl CedarPrincipal {
    fn from_provider_id(id: &ProviderQualifiedId) -> Self {
        Self {
            entity: CedarEntityId::from_principal(id),
        }
    }

    fn user(provider: &str, id: &str) -> Result<Self, String> {
        ProviderQualifiedId::new(provider, PrincipalKind::User, id)
            .map(|id| Self::from_provider_id(&id))
            .map_err(|err| err.to_string())
    }

    fn entity_id(&self) -> &CedarEntityId {
        &self.entity
    }

    fn entity_uid(&self) -> Result<EntityUid, String> {
        self.entity.entity_uid()
    }

    fn json_uid(&self) -> Value {
        self.entity.json_uid()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CedarGroup {
    entity: CedarEntityId,
}

impl CedarGroup {
    fn new(provider: &str, id: &str) -> Result<Self, String> {
        ProviderQualifiedId::new(provider, PrincipalKind::Group, id)
            .map(|id| Self::from_provider_id(&id))
            .map_err(|err| err.to_string())
    }

    fn from_provider_id(id: &ProviderQualifiedId) -> Self {
        Self {
            entity: CedarEntityId::from_principal(id),
        }
    }

    fn json_uid(&self) -> Value {
        self.entity.json_uid()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CedarNamespace {
    entity: CedarEntityId,
}

impl CedarNamespace {
    fn new(epoch: &NamespaceEpoch) -> Self {
        Self {
            entity: CedarEntityId::new(CedarEntityType::Namespace, epoch.entity_id()),
        }
    }

    fn json_uid(&self) -> Value {
        self.entity.json_uid()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CedarRepository {
    entity: CedarEntityId,
    namespace: CedarNamespace,
}

impl CedarRepository {
    fn new(epoch: &NamespaceEpoch, relative_path: &str) -> Self {
        let namespace = CedarNamespace::new(epoch);
        Self {
            entity: CedarEntityId::new(
                CedarEntityType::Repository,
                format!("{}/{relative_path}", epoch.entity_id()),
            ),
            namespace,
        }
    }

    fn entity_uid(&self) -> Result<EntityUid, String> {
        self.entity.entity_uid()
    }

    fn json_uid(&self) -> Value {
        self.entity.json_uid()
    }

    fn namespace(&self) -> &CedarNamespace {
        &self.namespace
    }
}

#[derive(Debug, Clone)]
struct CedarEntitySet {
    principal: CedarPrincipal,
    group_parents: Vec<CedarGroup>,
    repositories: Vec<CedarRepository>,
}

impl CedarEntitySet {
    fn new(principal: CedarPrincipal) -> Self {
        Self {
            principal,
            group_parents: Vec::new(),
            repositories: Vec::new(),
        }
    }

    fn with_group_parent(mut self, group: CedarGroup) -> Self {
        self.group_parents.push(group);
        self
    }

    fn with_repository(mut self, repository: CedarRepository) -> Self {
        self.repositories.push(repository);
        self
    }

    fn build(&self) -> Result<Entities, String> {
        let mut entities = Vec::new();

        entities.push(json!({
            "uid": self.principal.json_uid(),
            "attrs": {},
            "parents": self
                .group_parents
                .iter()
                .map(CedarGroup::json_uid)
                .collect::<Vec<_>>(),
        }));

        for group in &self.group_parents {
            entities.push(json!({
                "uid": group.json_uid(),
                "attrs": {},
                "parents": [],
            }));
        }

        let mut namespaces = BTreeSet::new();
        for repository in &self.repositories {
            if namespaces.insert(repository.namespace().entity.clone()) {
                entities.push(json!({
                    "uid": repository.namespace().json_uid(),
                    "attrs": {},
                    "parents": [],
                }));
            }
            entities.push(json!({
                "uid": repository.json_uid(),
                "attrs": {},
                "parents": [repository.namespace().json_uid()],
            }));
        }

        Entities::from_json_value(Value::Array(entities), None)
            .map_err(|err| format!("invalid Cedar shadow entities: {err}"))
    }
}

fn shadow_decision(
    policy_src: CedarPolicySource<'_>,
    principal: &CedarPrincipal,
    action: CedarAction,
    resource: &CedarRepository,
    entities: &Entities,
) -> Decision {
    let Ok(policy_set) = policy_src.parse() else {
        return Decision::Deny;
    };
    let Ok(request) = Request::new(
        match principal.entity_uid() {
            Ok(uid) => uid,
            Err(_) => return Decision::Deny,
        },
        match action.entity_uid() {
            Ok(uid) => uid,
            Err(_) => return Decision::Deny,
        },
        match resource.entity_uid() {
            Ok(uid) => uid,
            Err(_) => return Decision::Deny,
        },
        Context::empty(),
        None,
    ) else {
        return Decision::Deny;
    };

    Authorizer::new()
        .is_authorized(&request, &policy_set, entities)
        .decision()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cedar_entity_ids_use_provider_qualified_principals() {
        let user = ProviderQualifiedId::new("kanidm", PrincipalKind::User, "user-1").unwrap();
        let group = ProviderQualifiedId::new(
            "kanidm",
            PrincipalKind::Group,
            "550e8400-e29b-41d4-a716-446655440000",
        )
        .unwrap();

        assert_eq!(
            CedarPrincipal::from_provider_id(&user).entity_id(),
            &CedarEntityId::new(CedarEntityType::User, "kanidm:user:user-1")
        );
        assert_eq!(
            CedarGroup::from_provider_id(&group).entity,
            CedarEntityId::new(
                CedarEntityType::Group,
                "kanidm:group:550e8400-e29b-41d4-a716-446655440000",
            )
        );
    }

    #[test]
    fn cedar_shadow_inputs_exclude_display_group_names() {
        let groups = vec![
            STABLE_GROUP_ID.to_string(),
            "registry_admins".to_string(),
            "registry_admins@example.test".to_string(),
        ];
        let ids = stable_group_ids("kanidm", &groups)
            .into_iter()
            .map(|id| CedarGroup::from_provider_id(&id))
            .collect::<Vec<_>>();

        assert_eq!(
            ids,
            vec![CedarGroup::new("kanidm", STABLE_GROUP_ID).unwrap()]
        );
    }

    #[test]
    fn cedar_shadow_authorizes_owner_and_stable_group_grants() {
        let epoch = NamespaceEpoch::new("acme", 1);
        let repository = CedarRepository::new(&epoch, "app");
        let owner = CedarPrincipal::user("test", "subject-owner").unwrap();
        let group = CedarGroup::new("test", STABLE_GROUP_ID).unwrap();
        let builder = CedarPrincipal::user("test", "subject-builder").unwrap();
        let owner_entities = CedarEntitySet::new(owner.clone())
            .with_repository(repository.clone())
            .build()
            .unwrap();
        let builder_entities = CedarEntitySet::new(builder.clone())
            .with_group_parent(group)
            .with_repository(repository.clone())
            .build()
            .unwrap();

        assert_eq!(
            shadow_decision(
                SHADOW_POLICY,
                &owner,
                CedarAction::Delete,
                &repository,
                &owner_entities
            ),
            Decision::Allow
        );
        assert_eq!(
            shadow_decision(
                SHADOW_POLICY,
                &builder,
                CedarAction::Pull,
                &repository,
                &builder_entities,
            ),
            Decision::Allow
        );
        assert_eq!(
            shadow_decision(
                SHADOW_POLICY,
                &builder,
                CedarAction::Create,
                &repository,
                &builder_entities,
            ),
            Decision::Allow
        );
        assert_eq!(
            shadow_decision(
                SHADOW_POLICY,
                &builder,
                CedarAction::Update,
                &repository,
                &builder_entities,
            ),
            Decision::Deny
        );
    }

    #[test]
    fn cedar_shadow_denies_display_group_name_without_stable_group_parent() {
        let epoch = NamespaceEpoch::new("acme", 1);
        let repository = CedarRepository::new(&epoch, "app");
        let actor = CedarPrincipal::user("test", "subject-display-only").unwrap();
        let entities = CedarEntitySet::new(actor.clone())
            .with_repository(repository.clone())
            .build()
            .unwrap();

        assert_eq!(
            shadow_decision(
                SHADOW_POLICY,
                &actor,
                CedarAction::Create,
                &repository,
                &entities,
            ),
            Decision::Deny
        );
    }

    #[test]
    fn cedar_shadow_repository_ids_are_namespace_generation_aware() {
        let old_epoch = NamespaceEpoch::new("acme", 1);
        let new_epoch = NamespaceEpoch::new("acme", 2);
        let old_repository = CedarRepository::new(&old_epoch, "app");
        let new_repository = CedarRepository::new(&new_epoch, "app");
        let owner = CedarPrincipal::user("test", "subject-owner").unwrap();
        let entities = CedarEntitySet::new(owner.clone())
            .with_repository(old_repository.clone())
            .with_repository(new_repository.clone())
            .build()
            .unwrap();

        assert_eq!(
            shadow_decision(
                SHADOW_POLICY,
                &owner,
                CedarAction::Create,
                &old_repository,
                &entities,
            ),
            Decision::Allow
        );
        assert_eq!(
            shadow_decision(
                SHADOW_POLICY,
                &owner,
                CedarAction::Create,
                &new_repository,
                &entities,
            ),
            Decision::Deny
        );
    }

    #[test]
    fn cedar_shadow_policy_compile_failure_fails_closed() {
        let epoch = NamespaceEpoch::new("acme", 1);
        let repository = CedarRepository::new(&epoch, "app");
        let owner = CedarPrincipal::user("test", "subject-owner").unwrap();
        let entities = CedarEntitySet::new(owner.clone())
            .with_repository(repository.clone())
            .build()
            .unwrap();

        assert_eq!(
            shadow_decision(
                CedarPolicySource("not cedar policy"),
                &owner,
                CedarAction::Create,
                &repository,
                &entities,
            ),
            Decision::Deny
        );
    }
}
