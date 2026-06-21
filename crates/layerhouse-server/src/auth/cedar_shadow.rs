use cedar_policy::{
    Authorizer as CedarAuthorizer, Context, Decision, Entities, EntityUid, PolicySet, Request,
    Schema, ValidationMode, Validator,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

use crate::auth::authorization::{AuthzRequest, RepositoryResource};
use crate::auth::permissions::{self, OciAction};
use crate::auth::token::TokenType;
use crate::store::metadata::handle::{handle_of, is_handle_reserved};
use crate::store::metadata::{
    NamespaceEpoch, NamespaceGrant, NamespaceGrantGrantee, NamespaceStore, Owner,
};

use super::AuthService;
use super::principal::{PrincipalKind, ProviderQualifiedId, stable_group_ids};

const STABLE_GROUP_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
const BUILDER_GROUP_ID: &str = "550e8400-e29b-41d4-a716-446655440001";
const CI_GROUP_ID: &str = "550e8400-e29b-41d4-a716-446655440002";

const SHADOW_SCHEMA: CedarSchemaSource<'static> = CedarSchemaSource(
    r#"
entity Group;
entity User in [Group];
entity Namespace;
entity Repository in [Namespace];

action "pull", "create", "update", "delete" appliesTo {
    principal: [User],
    resource: [Repository],
    context: {
        "repository": String,
        "resource_id": String,
        "namespace_id": String,
        "token_type": String,
        "username": String,
        "display_name": String,
        "email": String,
        "scope_count": Long,
        "namespace_epoch_count": Long
    }
};
"#,
);

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
struct CedarSchemaSource<'a>(&'a str);

impl CedarSchemaSource<'_> {
    fn parse(self) -> Result<Schema, String> {
        let (schema, warnings) = Schema::from_cedarschema_str(self.0)
            .map_err(|err| format!("invalid Cedar shadow schema: {err}"))?;
        let warnings = warnings.collect::<Vec<_>>();
        if warnings.is_empty() {
            Ok(schema)
        } else {
            Err(format!(
                "invalid Cedar shadow schema: {} warning(s)",
                warnings.len()
            ))
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CedarPolicySource<'a>(&'a str);

impl CedarPolicySource<'_> {
    fn parse(self, schema: &Schema) -> Result<PolicySet, String> {
        let policy_set = self
            .0
            .parse::<PolicySet>()
            .map_err(|err| format!("invalid Cedar shadow policy: {err}"))?;
        let validation =
            Validator::new(schema.clone()).validate(&policy_set, ValidationMode::Strict);
        if validation.validation_passed() {
            Ok(policy_set)
        } else {
            Err(format!("invalid Cedar shadow policy: {validation}"))
        }
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
    fn from_oci(action: OciAction) -> Self {
        match action {
            OciAction::Pull => Self::Pull,
            OciAction::Create => Self::Create,
            OciAction::Update => Self::Update,
            OciAction::Delete => Self::Delete,
        }
    }

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

    fn policy_ref(&self) -> Result<String, String> {
        Ok(format!(
            "{}::{}",
            self.entity_type.as_str(),
            cedar_string_literal(&self.id)?
        ))
    }

    fn entity_uid(&self) -> Result<EntityUid, String> {
        self.policy_ref()?
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

    fn policy_ref(&self) -> Result<String, String> {
        self.entity.policy_ref()
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

    fn from_resource(resource: &RepositoryResource) -> Self {
        Self::new(&resource.namespace.epoch, &resource.relative_path)
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

    fn from_request(request: &AuthzRequest, repository: CedarRepository) -> Self {
        let mut group_ids = BTreeSet::new();
        let mut entities = Self::new(CedarPrincipal::from_provider_id(&request.actor.principal))
            .with_repository(repository);
        for id in &request.actor.group_ids {
            if id.kind() == PrincipalKind::Group {
                let group = CedarGroup::from_provider_id(id);
                if group_ids.insert(group.entity.clone()) {
                    entities = entities.with_group_parent(group);
                }
            }
        }
        entities
    }

    fn with_group_parent(mut self, group: CedarGroup) -> Self {
        self.group_parents.push(group);
        self
    }

    fn with_repository(mut self, repository: CedarRepository) -> Self {
        self.repositories.push(repository);
        self
    }

    fn build(&self, schema: &Schema) -> Result<Entities, String> {
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

        Entities::from_json_value(Value::Array(entities), Some(schema))
            .map_err(|err| format!("invalid Cedar shadow entities: {err}"))
    }
}

fn shadow_decision(policy_src: CedarPolicySource<'_>, request: &AuthzRequest) -> Decision {
    shadow_decision_with_schema(SHADOW_SCHEMA, policy_src, request).unwrap_or(Decision::Deny)
}

fn shadow_decision_with_schema(
    schema_src: CedarSchemaSource<'_>,
    policy_src: CedarPolicySource<'_>,
    request: &AuthzRequest,
) -> Result<Decision, String> {
    let schema = schema_src.parse()?;
    let policy_set = policy_src.parse(&schema)?;

    if cross_user_personal_namespace(request) {
        return Ok(Decision::Deny);
    }
    if permissions::in_personal_namespace(request.actor.username.as_deref(), &request.repository) {
        return Ok(Decision::Allow);
    }
    if !explicit_scope_guard_allows(request) {
        return Ok(Decision::Deny);
    }

    let Some(resource) = request.resource.as_ref() else {
        return Ok(Decision::Deny);
    };
    let repository = CedarRepository::from_resource(resource);
    let entities = CedarEntitySet::from_request(request, repository.clone()).build(&schema)?;
    let principal_uid = CedarPrincipal::from_provider_id(&request.actor.principal).entity_uid()?;
    let action_uid = CedarAction::from_oci(request.action).entity_uid()?;
    let resource_uid = repository.entity_uid()?;
    let context = Context::from_json_value(context_json(request), Some((&schema, &action_uid)))
        .map_err(|err| format!("invalid Cedar shadow context: {err}"))?;
    let request = Request::new(
        principal_uid,
        action_uid,
        resource_uid,
        context,
        Some(&schema),
    )
    .map_err(|err| format!("invalid Cedar shadow request: {err}"))?;

    Ok(CedarAuthorizer::new()
        .is_authorized(&request, &policy_set, &entities)
        .decision())
}

async fn shadow_policy_for_request(
    auth: &AuthService,
    request: &AuthzRequest,
    namespaces: &dyn NamespaceStore,
) -> Result<String, String> {
    let mut policy = String::new();
    let Some(resource) = request.resource.as_ref() else {
        return Ok(policy);
    };
    let epoch = &resource.namespace.epoch;
    if let Some(namespace) = namespaces
        .get_namespace(&epoch.handle)
        .await
        .map_err(|err| err.to_string())?
        && NamespaceEpoch::from_namespace(&namespace) == *epoch
    {
        append_namespace_owner_policies(
            &mut policy,
            request.actor.principal.provider(),
            &namespace.owner,
            epoch,
        )?;
        for grant in namespaces
            .list_namespace_grants(&epoch.handle)
            .await
            .map_err(|err| err.to_string())?
        {
            append_namespace_grant_policies(&mut policy, &grant, epoch)?;
        }
    }
    append_config_permission_policies(&mut policy, auth, request, epoch)?;
    Ok(policy)
}

fn append_namespace_owner_policies(
    policy: &mut String,
    provider: &str,
    owner: &Owner,
    epoch: &NamespaceEpoch,
) -> Result<(), String> {
    let Owner::User(subject) = owner else {
        return Ok(());
    };
    let id = ProviderQualifiedId::new(provider, PrincipalKind::User, subject.as_str())
        .map_err(|err| err.to_string())?;
    let principal = format!(
        "principal == {}",
        CedarEntityId::from_principal(&id).policy_ref()?
    );
    append_permits_for_actions(policy, &principal, OciAction::Delete, epoch)
}

fn append_namespace_grant_policies(
    policy: &mut String,
    grant: &NamespaceGrant,
    epoch: &NamespaceEpoch,
) -> Result<(), String> {
    match &grant.grantee {
        NamespaceGrantGrantee::Group { id } => {
            let principal = format!(
                "principal in {}",
                CedarEntityId::from_principal(id).policy_ref()?
            );
            append_permits_for_actions(policy, &principal, grant.action, epoch)
        }
        NamespaceGrantGrantee::User { id } => {
            let principal = format!(
                "principal == {}",
                CedarEntityId::from_principal(id).policy_ref()?
            );
            append_permits_for_actions(policy, &principal, grant.action, epoch)
        }
        NamespaceGrantGrantee::Public => {
            if permissions::action_matches(grant.action, OciAction::Pull) {
                append_permit(policy, "principal", OciAction::Pull, epoch)?;
            }
            Ok(())
        }
    }
}

fn append_config_permission_policies(
    policy: &mut String,
    auth: &AuthService,
    request: &AuthzRequest,
    epoch: &NamespaceEpoch,
) -> Result<(), String> {
    for mapping in &auth.config.permissions {
        for group in &mapping.groups {
            let Ok(group_id) = ProviderQualifiedId::parse(group) else {
                continue;
            };
            if group_id.kind() != PrincipalKind::Group {
                continue;
            }
            let principal = format!(
                "principal in {}",
                CedarEntityId::from_principal(&group_id).policy_ref()?
            );
            for scope in &mapping.scopes {
                if let Some((_, allowed_action)) = permissions::matching_scope(
                    std::slice::from_ref(scope),
                    &request.repository,
                    OciAction::Pull,
                ) {
                    append_permits_for_actions(policy, &principal, allowed_action, epoch)?;
                }
            }
        }
    }
    Ok(())
}

fn append_permits_for_actions(
    policy: &mut String,
    principal: &str,
    allowed: OciAction,
    epoch: &NamespaceEpoch,
) -> Result<(), String> {
    for action in implied_actions(allowed) {
        append_permit(policy, principal, action, epoch)?;
    }
    Ok(())
}

fn append_permit(
    policy: &mut String,
    principal: &str,
    action: OciAction,
    epoch: &NamespaceEpoch,
) -> Result<(), String> {
    let action = cedar_string_literal(CedarAction::from_oci(action).as_str())?;
    let namespace = CedarNamespace::new(epoch).policy_ref()?;
    policy.push_str(&format!(
        "permit({principal}, action == Action::{action}, resource in {namespace});\n"
    ));
    Ok(())
}

fn implied_actions(allowed: OciAction) -> impl Iterator<Item = OciAction> {
    [
        OciAction::Pull,
        OciAction::Create,
        OciAction::Update,
        OciAction::Delete,
    ]
    .into_iter()
    .filter(move |requested| permissions::action_matches(allowed, *requested))
}

fn cedar_string_literal(value: &str) -> Result<String, String> {
    serde_json::to_string(value).map_err(|err| format!("invalid Cedar string literal: {err}"))
}

fn cross_user_personal_namespace(request: &AuthzRequest) -> bool {
    let Some(namespace_user) = permissions::in_personal_namespace_of(&request.repository) else {
        return false;
    };
    request
        .actor
        .username
        .as_deref()
        .is_none_or(|username| username != namespace_user)
}

fn explicit_scope_guard_allows(request: &AuthzRequest) -> bool {
    if !matches!(
        request.actor.token_type,
        TokenType::PersonalAccess | TokenType::OciBearer
    ) {
        return true;
    }

    let expected = request
        .resource
        .as_ref()
        .map(|resource| &resource.namespace.epoch);
    match permissions::matching_scope(&request.actor.scopes, &request.repository, request.action) {
        Some((repo_pattern, _)) => {
            scope_matches_namespace_epoch(&request.actor.namespace_epochs, &repo_pattern, expected)
        }
        None => false,
    }
}

fn scope_matches_namespace_epoch(
    actor_epochs: &[NamespaceEpoch],
    repo_pattern: &str,
    expected: Option<&NamespaceEpoch>,
) -> bool {
    let Some(expected) = expected else {
        return true;
    };
    let Ok(handle) = handle_of(repo_pattern) else {
        return repo_pattern == "*";
    };
    if is_handle_reserved(handle) || handle != expected.handle {
        return true;
    }
    actor_epochs.iter().any(|epoch| epoch == expected)
}

fn context_json(request: &AuthzRequest) -> Value {
    let resource_id = request
        .resource
        .as_ref()
        .map(RepositoryResource::entity_id)
        .unwrap_or_default();
    let namespace_id = request
        .resource
        .as_ref()
        .map(|resource| resource.namespace.entity_id())
        .unwrap_or_default();
    json!({
        "repository": request.repository.as_str(),
        "resource_id": resource_id,
        "namespace_id": namespace_id,
        "token_type": token_type_name(&request.actor.token_type),
        "username": request.actor.username.as_deref().unwrap_or_default(),
        "display_name": request.actor.display_name.as_deref().unwrap_or_default(),
        "email": request.actor.email.as_deref().unwrap_or_default(),
        "scope_count": len_as_i64(request.actor.scopes.len()),
        "namespace_epoch_count": len_as_i64(request.actor.namespace_epochs.len()),
    })
}

fn token_type_name(token_type: &TokenType) -> &'static str {
    match token_type {
        TokenType::OidcAccess => "oidc_access",
        TokenType::PersonalAccess => "personal_access",
        TokenType::OciBearer => "oci_bearer",
        TokenType::Session => "session",
    }
}

fn len_as_i64(len: usize) -> i64 {
    i64::try_from(len).unwrap_or(i64::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::authorization::{Authorizer, AuthzDecision};
    use crate::auth::identity::Subject;
    use crate::auth::token::AuthIdentity;
    use crate::config::PermissionMapping;
    use crate::store::metadata::{InMemoryMetadataStore, ReleaseReason, typed_id::OrgId};

    fn identity(
        subject: &str,
        token_type: TokenType,
        groups: &[&str],
        scopes: &[&str],
    ) -> AuthIdentity {
        AuthIdentity::for_test(subject, token_type, groups, scopes)
    }

    fn group_id(id: &str) -> ProviderQualifiedId {
        ProviderQualifiedId::new("test", PrincipalKind::Group, id).unwrap()
    }

    async fn claim(store: &InMemoryMetadataStore, handle: &str, owner: Owner) {
        store
            .claim_namespace(handle, owner, handle, Subject::new("claimer"), true, 100)
            .await
            .expect("claim should succeed");
    }

    async fn grant(
        store: &InMemoryMetadataStore,
        namespace: &str,
        id: &str,
        grantee: NamespaceGrantGrantee,
        action: OciAction,
    ) {
        store
            .put_namespace_grant(
                NamespaceGrant {
                    id: id.to_string(),
                    namespace: namespace.to_string(),
                    label: grantee.label(),
                    grantee,
                    action,
                    created_by: Subject::new("grant-owner"),
                    created_at: 200,
                    updated_by: Subject::new("grant-owner"),
                    updated_at: 200,
                },
                "grant-owner",
                "test",
            )
            .await
            .expect("grant should persist");
    }

    async fn parity_decision(
        auth: &AuthService,
        identity: &AuthIdentity,
        repository: &str,
        action: OciAction,
        store: &InMemoryMetadataStore,
    ) -> (AuthzDecision, Decision) {
        let authorization = auth
            .authorize_repository(identity, repository, action, store)
            .await
            .expect("compatibility authorization should evaluate");
        let request = AuthzRequest {
            actor: identity.actor(),
            repository: repository.to_string(),
            resource: authorization.resource,
            action,
        };
        let compat = auth
            .authorize(&request, store)
            .await
            .expect("compatibility authorizer should evaluate request");
        let policy = shadow_policy_for_request(auth, &request, store)
            .await
            .expect("shadow policy should build");
        let cedar = shadow_decision(CedarPolicySource(&policy), &request);
        (compat, cedar)
    }

    async fn assert_parity(
        auth: &AuthService,
        identity: &AuthIdentity,
        repository: &str,
        action: OciAction,
        store: &InMemoryMetadataStore,
        expected: AuthzDecision,
    ) {
        let (compat, cedar) = parity_decision(auth, identity, repository, action, store).await;
        assert_eq!(compat, expected);
        assert_eq!(cedar, cedar_decision(expected));
    }

    fn cedar_decision(decision: AuthzDecision) -> Decision {
        match decision {
            AuthzDecision::Allow => Decision::Allow,
            AuthzDecision::Deny => Decision::Deny,
        }
    }

    fn request_for_fixture(
        principal: CedarPrincipal,
        groups: Vec<CedarGroup>,
        repository: CedarRepository,
        action: OciAction,
    ) -> AuthzRequest {
        let group_ids = groups
            .iter()
            .map(|group| {
                ProviderQualifiedId::parse(&group.entity.id).expect("fixture group id should parse")
            })
            .collect();
        let epoch = repository.namespace.epoch();
        let relative_path = repository
            .entity
            .id
            .split_once('/')
            .map(|(_, path)| path)
            .expect("fixture repository entity id contains relative path");
        let repository_name = format!("{}/{relative_path}", epoch.handle);
        let namespace = crate::store::metadata::Namespace {
            handle: epoch.handle.clone(),
            generation: epoch.generation,
            owner: Owner::User(Subject::new("fixture-owner")),
            owner_label: "fixture-owner".to_string(),
            created_at: 1,
        };
        let resource = RepositoryResource::from_repository(&repository_name, &namespace)
            .expect("fixture repository resource should build");

        AuthzRequest {
            actor: crate::auth::principal::Actor {
                principal: ProviderQualifiedId::parse(&principal.entity.id)
                    .expect("fixture principal id should parse"),
                username: None,
                display_name: None,
                email: None,
                group_ids,
                display_groups: Vec::new(),
                scopes: Vec::new(),
                namespace_epochs: Vec::new(),
                token_type: TokenType::OidcAccess,
            },
            repository: repository_name,
            resource: Some(resource),
            action,
        }
    }

    trait CedarNamespaceExt {
        fn epoch(&self) -> NamespaceEpoch;
    }

    impl CedarNamespaceExt for CedarNamespace {
        fn epoch(&self) -> NamespaceEpoch {
            let (handle, generation) = self
                .entity
                .id
                .split_once('#')
                .expect("fixture namespace entity id contains generation");
            NamespaceEpoch::new(
                handle,
                generation
                    .parse::<u64>()
                    .expect("fixture generation should parse"),
            )
        }
    }

    #[test]
    fn cedar_schema_validates_shadow_policy() {
        let schema = SHADOW_SCHEMA.parse().expect("schema should parse");
        SHADOW_POLICY
            .parse(&schema)
            .expect("shadow policy should validate against schema");
    }

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

        let owner_request =
            request_for_fixture(owner, Vec::new(), repository.clone(), OciAction::Delete);
        assert_eq!(
            shadow_decision(SHADOW_POLICY, &owner_request),
            Decision::Allow
        );

        let builder_pull = request_for_fixture(
            builder.clone(),
            vec![group.clone()],
            repository.clone(),
            OciAction::Pull,
        );
        let builder_create = request_for_fixture(
            builder.clone(),
            vec![group.clone()],
            repository.clone(),
            OciAction::Create,
        );
        let builder_update =
            request_for_fixture(builder, vec![group], repository.clone(), OciAction::Update);
        assert_eq!(
            shadow_decision(SHADOW_POLICY, &builder_pull),
            Decision::Allow
        );
        assert_eq!(
            shadow_decision(SHADOW_POLICY, &builder_create),
            Decision::Allow
        );
        assert_eq!(
            shadow_decision(SHADOW_POLICY, &builder_update),
            Decision::Deny
        );
    }

    #[test]
    fn cedar_shadow_denies_display_group_name_without_stable_group_parent() {
        let epoch = NamespaceEpoch::new("acme", 1);
        let repository = CedarRepository::new(&epoch, "app");
        let actor = CedarPrincipal::user("test", "subject-display-only").unwrap();
        let request = request_for_fixture(actor, Vec::new(), repository, OciAction::Create);

        assert_eq!(shadow_decision(SHADOW_POLICY, &request), Decision::Deny);
    }

    #[test]
    fn cedar_shadow_repository_ids_are_namespace_generation_aware() {
        let old_epoch = NamespaceEpoch::new("acme", 1);
        let new_epoch = NamespaceEpoch::new("acme", 2);
        let old_repository = CedarRepository::new(&old_epoch, "app");
        let new_repository = CedarRepository::new(&new_epoch, "app");
        let owner = CedarPrincipal::user("test", "subject-owner").unwrap();
        let old_request =
            request_for_fixture(owner.clone(), Vec::new(), old_repository, OciAction::Create);
        let new_request = request_for_fixture(owner, Vec::new(), new_repository, OciAction::Create);

        assert_eq!(
            shadow_decision(SHADOW_POLICY, &old_request),
            Decision::Allow
        );
        assert_eq!(shadow_decision(SHADOW_POLICY, &new_request), Decision::Deny);
    }

    #[test]
    fn cedar_shadow_setup_failures_fail_closed() {
        let epoch = NamespaceEpoch::new("acme", 1);
        let repository = CedarRepository::new(&epoch, "app");
        let owner = CedarPrincipal::user("test", "subject-owner").unwrap();
        let request = request_for_fixture(owner, Vec::new(), repository, OciAction::Create);

        assert_eq!(
            shadow_decision(CedarPolicySource("not cedar policy"), &request),
            Decision::Deny
        );
        assert_eq!(
            shadow_decision_with_schema(
                CedarSchemaSource("not cedar schema"),
                SHADOW_POLICY,
                &request,
            )
            .unwrap_or(Decision::Deny),
            Decision::Deny
        );
    }

    #[tokio::test]
    async fn cedar_shadow_parity_owner_allows_and_non_owner_denies() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-alice"))).await;

        let alice = identity("subject-alice", TokenType::OidcAccess, &[], &[]);
        assert_parity(
            &auth,
            &alice,
            "acme/app",
            OciAction::Create,
            &store,
            AuthzDecision::Allow,
        )
        .await;

        let bob = identity("subject-bob", TokenType::OidcAccess, &[], &[]);
        assert_parity(
            &auth,
            &bob,
            "acme/app",
            OciAction::Create,
            &store,
            AuthzDecision::Deny,
        )
        .await;
    }

    #[tokio::test]
    async fn cedar_shadow_parity_namespace_group_grant_ladder() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-owner"))).await;
        grant(
            &store,
            "acme",
            "grant-1",
            NamespaceGrantGrantee::Group {
                id: group_id(BUILDER_GROUP_ID),
            },
            OciAction::Create,
        )
        .await;

        let builder = identity(
            "subject-builder",
            TokenType::OidcAccess,
            &[BUILDER_GROUP_ID],
            &[],
        );
        assert_parity(
            &auth,
            &builder,
            "acme/app",
            OciAction::Pull,
            &store,
            AuthzDecision::Allow,
        )
        .await;
        assert_parity(
            &auth,
            &builder,
            "acme/app",
            OciAction::Create,
            &store,
            AuthzDecision::Allow,
        )
        .await;
        assert_parity(
            &auth,
            &builder,
            "acme/app",
            OciAction::Update,
            &store,
            AuthzDecision::Deny,
        )
        .await;
    }

    #[tokio::test]
    async fn cedar_shadow_parity_display_group_labels_deny() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-owner"))).await;
        grant(
            &store,
            "acme",
            "grant-1",
            NamespaceGrantGrantee::Group {
                id: group_id(BUILDER_GROUP_ID),
            },
            OciAction::Create,
        )
        .await;

        let display_only = identity(
            "subject-builder",
            TokenType::OidcAccess,
            &["registry_builders"],
            &[],
        );
        assert_parity(
            &auth,
            &display_only,
            "acme/app",
            OciAction::Create,
            &store,
            AuthzDecision::Deny,
        )
        .await;
    }

    #[tokio::test]
    async fn cedar_shadow_parity_config_rbac_stable_group_allows() {
        let auth = AuthService::for_test(vec![PermissionMapping {
            name: "ci".to_string(),
            groups: vec![format!("test:group:{CI_GROUP_ID}")],
            scopes: vec!["repository:acme/*:create".to_string()],
        }]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-owner"))).await;

        let ci = identity("subject-ci", TokenType::OidcAccess, &[CI_GROUP_ID], &[]);
        assert_parity(
            &auth,
            &ci,
            "acme/app",
            OciAction::Create,
            &store,
            AuthzDecision::Allow,
        )
        .await;
    }

    #[tokio::test]
    async fn cedar_shadow_parity_config_rbac_display_mapping_denies() {
        let auth = AuthService::for_test(vec![PermissionMapping {
            name: "admins".to_string(),
            groups: vec!["registry_admins".to_string()],
            scopes: vec!["repository:acme/*:create".to_string()],
        }]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-owner"))).await;

        let admin = identity(
            "subject-admin",
            TokenType::OidcAccess,
            &["registry_admins"],
            &[],
        );
        assert_parity(
            &auth,
            &admin,
            "acme/app",
            OciAction::Create,
            &store,
            AuthzDecision::Deny,
        )
        .await;
    }

    #[tokio::test]
    async fn cedar_shadow_parity_scope_epoch_ceiling_denies_overbroad_policy() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-owner"))).await;

        let mut pat = identity(
            "subject-owner",
            TokenType::PersonalAccess,
            &[],
            &["repository:acme/app:pull"],
        );
        pat.namespace_epochs = vec![NamespaceEpoch::new("acme", 1)];
        assert_parity(
            &auth,
            &pat,
            "acme/app",
            OciAction::Create,
            &store,
            AuthzDecision::Deny,
        )
        .await;

        store
            .release_namespace(
                "acme",
                Subject::new("subject-owner"),
                ReleaseReason::OwnerDeleted,
                300,
            )
            .await
            .expect("owner can release empty namespace");
        claim(&store, "acme", Owner::User(Subject::new("subject-owner"))).await;
        let mut stale_bearer = identity(
            "subject-owner",
            TokenType::OciBearer,
            &[],
            &["repository:acme/app:create"],
        );
        stale_bearer.namespace_epochs = vec![NamespaceEpoch::new("acme", 1)];
        assert_parity(
            &auth,
            &stale_bearer,
            "acme/app",
            OciAction::Create,
            &store,
            AuthzDecision::Deny,
        )
        .await;
    }

    #[tokio::test]
    async fn cedar_shadow_parity_public_grant_is_pull_only() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-owner"))).await;
        grant(
            &store,
            "acme",
            "public",
            NamespaceGrantGrantee::Public,
            OciAction::Pull,
        )
        .await;

        let bob = identity("subject-bob", TokenType::OidcAccess, &[], &[]);
        assert_parity(
            &auth,
            &bob,
            "acme/app",
            OciAction::Pull,
            &store,
            AuthzDecision::Allow,
        )
        .await;
        assert_parity(
            &auth,
            &bob,
            "acme/app",
            OciAction::Create,
            &store,
            AuthzDecision::Deny,
        )
        .await;
    }

    #[tokio::test]
    async fn cedar_shadow_parity_unclaimed_namespace_write_denied_before_policy() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        let actor = identity("subject-owner", TokenType::OidcAccess, &[], &[]);
        auth.check_permission(&actor, "acme/app", OciAction::Create, &store)
            .await
            .expect_err("compatibility authorizer denies unclaimed writes");

        let request = AuthzRequest {
            actor: actor.actor(),
            repository: "acme/app".to_string(),
            resource: None,
            action: OciAction::Create,
        };
        assert_eq!(shadow_decision(SHADOW_POLICY, &request), Decision::Deny);
    }

    #[tokio::test]
    async fn cedar_shadow_parity_org_owner_does_not_implicitly_allow() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::Org(OrgId::generate())).await;

        let actor = identity("subject-owner", TokenType::OidcAccess, &[], &[]);
        assert_parity(
            &auth,
            &actor,
            "acme/app",
            OciAction::Create,
            &store,
            AuthzDecision::Deny,
        )
        .await;
    }
}
