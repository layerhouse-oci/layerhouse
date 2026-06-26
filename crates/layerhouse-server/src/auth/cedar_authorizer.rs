use cedar_policy::{
    Authorizer as CedarPolicyAuthorizer, Context, Decision, Entities, EntityUid,
    PolicySet as CedarPolicySet, Request, Schema, ValidationMode, Validator,
};
use serde_json::{Value, json};
use std::collections::BTreeSet;

use crate::auth::authorization::{AuthzDecision, AuthzRequest, RepositoryResource};
use crate::auth::permissions::{self, OciAction};
use crate::auth::token::TokenType;
use crate::store::metadata::handle::{handle_of, is_handle_reserved};
use crate::store::metadata::{
    AuthorizationStore, NamespaceEpoch, NamespaceGrant, NamespaceGrantGrantee, NamespaceStore,
    Owner, PolicySet as MetadataPolicySet,
};

use super::AuthService;
use super::principal::{PrincipalKind, ProviderQualifiedId};

const AUTHORIZATION_SCHEMA: CedarSchemaSource<'static> = CedarSchemaSource(
    r#"
entity Group;
entity User in [Group];
entity Anonymous;
entity Namespace;
entity Repository in [Namespace];
entity Registry;

action "pull", "create", "update", "delete" appliesTo {
    principal: [User, Anonymous],
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

action "admin" appliesTo {
    principal: [User],
    resource: [Registry],
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

#[derive(Debug, Clone, Copy)]
struct CedarSchemaSource<'a>(&'a str);

impl CedarSchemaSource<'_> {
    fn parse(self) -> Result<Schema, String> {
        let (schema, warnings) = Schema::from_cedarschema_str(self.0)
            .map_err(|err| format!("invalid Cedar authorization schema: {err}"))?;
        let warnings = warnings.collect::<Vec<_>>();
        if warnings.is_empty() {
            Ok(schema)
        } else {
            Err(format!(
                "invalid Cedar authorization schema: {} warning(s)",
                warnings.len()
            ))
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct CedarPolicySource<'a>(&'a str);

impl CedarPolicySource<'_> {
    fn parse(self, schema: &Schema) -> Result<CedarPolicySet, String> {
        let policy_set = self
            .0
            .parse::<CedarPolicySet>()
            .map_err(|err| format!("invalid Cedar authorization policy: {err}"))?;
        let validation =
            Validator::new(schema.clone()).validate(&policy_set, ValidationMode::Strict);
        if validation.validation_passed() {
            Ok(policy_set)
        } else {
            Err(format!("invalid Cedar authorization policy: {validation}"))
        }
    }
}

pub(crate) fn validate_policy_text(policy: &str) -> Result<(), String> {
    let schema = AUTHORIZATION_SCHEMA.parse()?;
    CedarPolicySource(policy).parse(&schema).map(|_| ())
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum CedarEntityType {
    User,
    Group,
    Namespace,
    Repository,
    Registry,
    Action,
}

impl CedarEntityType {
    fn as_str(self) -> &'static str {
        match self {
            Self::User => "User",
            Self::Group => "Group",
            Self::Namespace => "Namespace",
            Self::Repository => "Repository",
            Self::Registry => "Registry",
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
    Admin,
}

impl CedarAction {
    fn from_oci(action: OciAction) -> Self {
        match action {
            OciAction::Pull => Self::Pull,
            OciAction::Create => Self::Create,
            OciAction::Update => Self::Update,
            OciAction::Delete => Self::Delete,
            OciAction::Admin => Self::Admin,
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Self::Pull => "pull",
            Self::Create => "create",
            Self::Update => "update",
            Self::Delete => "delete",
            Self::Admin => "admin",
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

    #[cfg(test)]
    fn user(provider: &str, id: &str) -> Result<Self, String> {
        ProviderQualifiedId::new(provider, PrincipalKind::User, id)
            .map(|id| Self::from_provider_id(&id))
            .map_err(|err| err.to_string())
    }

    #[cfg(test)]
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
    #[cfg(test)]
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
    namespace: Option<CedarNamespace>,
}

impl CedarRepository {
    fn new(epoch: &NamespaceEpoch, relative_path: &str) -> Self {
        let namespace = CedarNamespace::new(epoch);
        Self {
            entity: CedarEntityId::new(
                CedarEntityType::Repository,
                format!("{}/{relative_path}", epoch.entity_id()),
            ),
            namespace: Some(namespace),
        }
    }

    fn from_resource(resource: &RepositoryResource) -> Self {
        Self::new(&resource.namespace.epoch, &resource.relative_path)
    }

    fn unresolved(repository: &str) -> Self {
        Self {
            entity: CedarEntityId::new(CedarEntityType::Repository, repository),
            namespace: None,
        }
    }

    fn entity_uid(&self) -> Result<EntityUid, String> {
        self.entity.entity_uid()
    }

    fn json_uid(&self) -> Value {
        self.entity.json_uid()
    }

    fn namespace(&self) -> Option<&CedarNamespace> {
        self.namespace.as_ref()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct CedarRegistry {
    entity: CedarEntityId,
}

impl CedarRegistry {
    fn root() -> Self {
        Self {
            entity: CedarEntityId::new(CedarEntityType::Registry, "root"),
        }
    }

    fn entity_uid(&self) -> Result<EntityUid, String> {
        self.entity.entity_uid()
    }

    fn policy_ref(&self) -> Result<String, String> {
        self.entity.policy_ref()
    }

    fn json_uid(&self) -> Value {
        self.entity.json_uid()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum CedarResource {
    Repository(CedarRepository),
    Registry(CedarRegistry),
}

impl CedarResource {
    fn from_request(request: &AuthzRequest) -> Self {
        if request.repository == "*" && request.resource.is_none() {
            return Self::Registry(CedarRegistry::root());
        }
        match request.resource.as_ref() {
            Some(resource) => Self::Repository(CedarRepository::from_resource(resource)),
            None => Self::Repository(CedarRepository::unresolved(&request.repository)),
        }
    }

    fn entity_uid(&self) -> Result<EntityUid, String> {
        match self {
            Self::Repository(repository) => repository.entity_uid(),
            Self::Registry(registry) => registry.entity_uid(),
        }
    }

    fn policy_ref(&self) -> Result<String, String> {
        match self {
            Self::Repository(repository) => repository.entity.policy_ref(),
            Self::Registry(registry) => registry.policy_ref(),
        }
    }

    fn exact_policy_expr(&self) -> Result<String, String> {
        Ok(format!("resource == {}", self.policy_ref()?))
    }
}

#[derive(Debug, Clone)]
struct CedarEntitySet {
    principal: CedarPrincipal,
    group_parents: Vec<CedarGroup>,
    resources: Vec<CedarResource>,
}

impl CedarEntitySet {
    fn new(principal: CedarPrincipal) -> Self {
        Self {
            principal,
            group_parents: Vec::new(),
            resources: Vec::new(),
        }
    }

    fn from_request(request: &AuthzRequest, resource: CedarResource) -> Self {
        let mut group_ids = BTreeSet::new();
        let mut entities = Self::new(CedarPrincipal::from_provider_id(&request.actor.principal))
            .with_resource(resource);
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

    fn with_resource(mut self, resource: CedarResource) -> Self {
        self.resources.push(resource);
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
        for resource in &self.resources {
            match resource {
                CedarResource::Repository(repository) => {
                    if let Some(namespace) = repository.namespace()
                        && namespaces.insert(namespace.entity.clone())
                    {
                        entities.push(json!({
                            "uid": namespace.json_uid(),
                            "attrs": {},
                            "parents": [],
                        }));
                    }
                    let parents = repository
                        .namespace()
                        .map(|namespace| vec![namespace.json_uid()])
                        .unwrap_or_default();
                    entities.push(json!({
                        "uid": repository.json_uid(),
                        "attrs": {},
                        "parents": parents,
                    }));
                }
                CedarResource::Registry(registry) => {
                    entities.push(json!({
                        "uid": registry.json_uid(),
                        "attrs": {},
                        "parents": [],
                    }));
                }
            }
        }

        Entities::from_json_value(Value::Array(entities), Some(schema))
            .map_err(|err| format!("invalid Cedar authorization entities: {err}"))
    }
}

pub(crate) struct CedarRepositoryAuthorizer;

impl CedarRepositoryAuthorizer {
    pub(crate) fn new() -> Self {
        Self
    }

    pub(crate) async fn authorize(
        &self,
        auth: &AuthService,
        request: &AuthzRequest,
        store: &dyn AuthorizationStore,
    ) -> Result<AuthzDecision, String> {
        let policy = policy_for_request(auth, request, store).await?;
        Ok(to_authz_decision(cedar_decision(
            CedarPolicySource(&policy),
            request,
        )))
    }

    pub(crate) async fn max_grantable_action(
        &self,
        auth: &AuthService,
        actor: &crate::auth::principal::Actor,
        repository: &str,
        store: &dyn AuthorizationStore,
    ) -> Result<Option<OciAction>, String> {
        let resource = repository_resource_for_authorization(repository, store).await?;
        let mut max = None;
        for action in [
            OciAction::Pull,
            OciAction::Create,
            OciAction::Update,
            OciAction::Delete,
        ] {
            let request = AuthzRequest {
                actor: actor.clone(),
                repository: repository.to_string(),
                resource: resource.clone(),
                action,
            };
            if self.authorize(auth, &request, store).await? == AuthzDecision::Allow {
                max = Some(action);
            }
        }
        Ok(max)
    }
}

async fn repository_resource_for_authorization(
    repository: &str,
    namespaces: &dyn NamespaceStore,
) -> Result<Option<RepositoryResource>, String> {
    let Ok(handle) = handle_of(repository) else {
        return Ok(None);
    };
    if is_handle_reserved(handle) {
        return Ok(None);
    }
    namespaces
        .get_namespace(handle)
        .await
        .map_err(|err| err.to_string())?
        .map(|namespace| RepositoryResource::from_repository(repository, &namespace))
        .transpose()
        .map_err(|err| err.to_string())
}

fn to_authz_decision(decision: Decision) -> AuthzDecision {
    match decision {
        Decision::Allow => AuthzDecision::Allow,
        Decision::Deny => AuthzDecision::Deny,
    }
}

fn cedar_decision(policy_src: CedarPolicySource<'_>, request: &AuthzRequest) -> Decision {
    cedar_decision_with_schema(AUTHORIZATION_SCHEMA, policy_src, request).unwrap_or(Decision::Deny)
}

fn cedar_decision_with_schema(
    schema_src: CedarSchemaSource<'_>,
    policy_src: CedarPolicySource<'_>,
    request: &AuthzRequest,
) -> Result<Decision, String> {
    let schema = schema_src.parse()?;
    let policy_set = policy_src.parse(&schema)?;

    if cross_user_personal_namespace(request) {
        return Ok(Decision::Deny);
    }
    if unclaimed_write(request) {
        return Ok(Decision::Deny);
    }
    if !explicit_scope_guard_allows(request) {
        return Ok(Decision::Deny);
    }
    if permissions::in_personal_namespace(request.actor.username.as_deref(), &request.repository) {
        return Ok(Decision::Allow);
    }

    let resource = CedarResource::from_request(request);
    let entities = CedarEntitySet::from_request(request, resource.clone()).build(&schema)?;
    let principal_uid = CedarPrincipal::from_provider_id(&request.actor.principal).entity_uid()?;
    let action_uid = CedarAction::from_oci(request.action).entity_uid()?;
    let resource_uid = resource.entity_uid()?;
    let context = Context::from_json_value(context_json(request), Some((&schema, &action_uid)))
        .map_err(|err| format!("invalid Cedar authorization context: {err}"))?;
    let request = Request::new(
        principal_uid,
        action_uid,
        resource_uid,
        context,
        Some(&schema),
    )
    .map_err(|err| format!("invalid Cedar authorization request: {err}"))?;

    Ok(CedarPolicyAuthorizer::new()
        .is_authorized(&request, &policy_set, &entities)
        .decision())
}

async fn policy_for_request(
    auth: &AuthService,
    request: &AuthzRequest,
    store: &dyn AuthorizationStore,
) -> Result<String, String> {
    let mut policy = String::new();
    let resource = CedarResource::from_request(request);
    if let Some(repository_resource) = request.resource.as_ref() {
        let epoch = &repository_resource.namespace.epoch;
        if let Some(namespace) = store
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
            for grant in store
                .list_namespace_grants(&epoch.handle)
                .await
                .map_err(|err| err.to_string())?
            {
                append_namespace_grant_policies(&mut policy, &grant, epoch)?;
            }
        }
    }
    append_enabled_config_policy_sets(&mut policy, &auth.config.policy_sets);
    append_explicit_scope_policies(&mut policy, request, &resource)?;
    append_enabled_metadata_policy_sets(
        &mut policy,
        &store
            .list_policy_sets()
            .await
            .map_err(|err| err.to_string())?,
    );
    Ok(policy)
}

fn append_enabled_policy_texts<'a>(
    policy: &mut String,
    policy_sets: impl IntoIterator<Item = &'a str>,
) {
    for cedar_text in policy_sets {
        if !policy.ends_with('\n') {
            policy.push('\n');
        }
        policy.push_str(cedar_text);
        if !policy.ends_with('\n') {
            policy.push('\n');
        }
    }
}

fn append_enabled_config_policy_sets(
    policy: &mut String,
    policy_sets: &[crate::config::ConfigPolicySet],
) {
    append_enabled_policy_texts(
        policy,
        policy_sets
            .iter()
            .filter(|policy_set| policy_set.enabled)
            .map(|policy_set| policy_set.cedar_text.as_str()),
    );
}

fn append_enabled_metadata_policy_sets(policy: &mut String, policy_sets: &[MetadataPolicySet]) {
    append_enabled_policy_texts(
        policy,
        policy_sets
            .iter()
            .filter(|policy_set| policy_set.enabled)
            .map(|policy_set| policy_set.cedar_text.as_str()),
    );
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
    let resource = namespace_policy_expr(epoch)?;
    append_permits_for_actions(policy, &principal, OciAction::Delete, &resource)
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
            let resource = namespace_policy_expr(epoch)?;
            append_permits_for_actions(policy, &principal, grant.action, &resource)
        }
        NamespaceGrantGrantee::User { id } => {
            let principal = format!(
                "principal == {}",
                CedarEntityId::from_principal(id).policy_ref()?
            );
            let resource = namespace_policy_expr(epoch)?;
            append_permits_for_actions(policy, &principal, grant.action, &resource)
        }
        NamespaceGrantGrantee::Public => Ok(()),
    }
}

fn append_explicit_scope_policies(
    policy: &mut String,
    request: &AuthzRequest,
    resource: &CedarResource,
) -> Result<(), String> {
    if !matches!(
        request.actor.token_type,
        TokenType::PersonalAccess | TokenType::OciBearer
    ) {
        return Ok(());
    }
    let Some((_, allowed_action)) =
        permissions::matching_scope(&request.actor.scopes, &request.repository, request.action)
    else {
        return Ok(());
    };
    let principal = format!(
        "principal == {}",
        CedarEntityId::from_principal(&request.actor.principal).policy_ref()?
    );
    let resource = resource.exact_policy_expr()?;
    append_permits_for_actions(policy, &principal, allowed_action, &resource)
}

fn append_permits_for_actions(
    policy: &mut String,
    principal: &str,
    allowed: OciAction,
    resource: &str,
) -> Result<(), String> {
    for action in implied_actions(allowed) {
        append_permit(policy, principal, action, resource)?;
    }
    Ok(())
}

fn append_permit(
    policy: &mut String,
    principal: &str,
    action: OciAction,
    resource: &str,
) -> Result<(), String> {
    let action = cedar_string_literal(CedarAction::from_oci(action).as_str())?;
    policy.push_str(&format!(
        "permit({principal}, action == Action::{action}, {resource});\n"
    ));
    Ok(())
}

fn namespace_policy_expr(epoch: &NamespaceEpoch) -> Result<String, String> {
    Ok(format!(
        "resource in {}",
        CedarNamespace::new(epoch).policy_ref()?
    ))
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

fn unclaimed_write(request: &AuthzRequest) -> bool {
    if request.action == OciAction::Pull || request.resource.is_some() || request.repository == "*"
    {
        return false;
    }
    handle_of(&request.repository)
        .map(|handle| !is_handle_reserved(handle))
        .unwrap_or(false)
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
    let resource = CedarResource::from_request(request);
    context_json_for_parts(
        &request.repository,
        resource_context_id(&resource),
        namespace_context_id(&resource),
        token_type_name(&request.actor.token_type),
        request.actor.username.as_deref().unwrap_or_default(),
        request.actor.display_name.as_deref().unwrap_or_default(),
        request.actor.email.as_deref().unwrap_or_default(),
        len_as_i64(request.actor.scopes.len()),
        len_as_i64(request.actor.namespace_epochs.len()),
    )
}

#[allow(clippy::too_many_arguments)]
fn context_json_for_parts(
    repository: &str,
    resource_id: String,
    namespace_id: String,
    token_type: &str,
    username: &str,
    display_name: &str,
    email: &str,
    scope_count: i64,
    namespace_epoch_count: i64,
) -> Value {
    json!({
        "repository": repository,
        "resource_id": resource_id,
        "namespace_id": namespace_id,
        "token_type": token_type,
        "username": username,
        "display_name": display_name,
        "email": email,
        "scope_count": scope_count,
        "namespace_epoch_count": namespace_epoch_count,
    })
}

fn resource_context_id(resource: &CedarResource) -> String {
    match resource {
        CedarResource::Repository(repository) => repository.entity.id.clone(),
        CedarResource::Registry(registry) => registry.entity.id.clone(),
    }
}

fn namespace_context_id(resource: &CedarResource) -> String {
    match resource {
        CedarResource::Repository(repository) => repository
            .namespace()
            .map(|namespace| namespace.entity.id.clone())
            .unwrap_or_default(),
        CedarResource::Registry(_) => String::new(),
    }
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
    use crate::auth::authorization::Authorizer;
    use crate::auth::identity::Subject;
    use crate::auth::principal::stable_group_ids;
    use crate::auth::token::AuthIdentity;
    use crate::config::ConfigPolicySet;
    use crate::store::metadata::{
        InMemoryMetadataStore, PolicySet as MetadataPolicySet, PolicySource, PolicyStore,
        ReleaseReason, Repository, RepositoryStore, Visibility, typed_id::OrgId,
    };

    const STABLE_GROUP_ID: &str = "550e8400-e29b-41d4-a716-446655440000";
    const BUILDER_GROUP_ID: &str = "550e8400-e29b-41d4-a716-446655440001";
    const CI_GROUP_ID: &str = "550e8400-e29b-41d4-a716-446655440002";

    const TEST_POLICY: CedarPolicySource<'static> = CedarPolicySource(
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

    fn config_policy_set(id: &str, cedar_text: impl Into<String>) -> ConfigPolicySet {
        ConfigPolicySet {
            id: id.to_string(),
            name: id.to_string(),
            enabled: true,
            cedar_text: cedar_text.into(),
        }
    }

    fn group_repository_policy(
        id: &str,
        group: &str,
        allowed: OciAction,
        resource_expr: &str,
    ) -> ConfigPolicySet {
        let mut cedar_text = String::new();
        for action in [
            OciAction::Pull,
            OciAction::Create,
            OciAction::Update,
            OciAction::Delete,
        ] {
            if permissions::action_matches(allowed, action) {
                cedar_text.push_str(&format!(
                    "permit(principal in Group::\"test:group:{group}\", action == Action::\"{}\", {resource_expr});\n",
                    action.scope_token()
                ));
            }
        }
        config_policy_set(id, cedar_text)
    }

    fn admin_policy(id: &str, group: &str) -> ConfigPolicySet {
        config_policy_set(
            id,
            format!(
                r#"permit(
    principal in Group::"test:group:{group}",
    action == Action::"admin",
    resource == Registry::"root"
);"#
            ),
        )
    }

    async fn claim(store: &InMemoryMetadataStore, handle: &str, owner: Owner) {
        store
            .claim_namespace(handle, owner, handle, Subject::new("claimer"), true, 100)
            .await
            .expect("claim should succeed");
    }

    async fn put_repo(store: &InMemoryMetadataStore, name: &str, visibility: Visibility) {
        store
            .put_repository(Repository {
                name: name.to_string(),
                description: String::new(),
                created_by: None,
                visibility,
                created_at: 100,
            })
            .await
            .expect("repository metadata should persist");
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

    async fn enforced_decision(
        auth: &AuthService,
        identity: &AuthIdentity,
        repository: &str,
        action: OciAction,
        store: &InMemoryMetadataStore,
    ) -> AuthzDecision {
        let (_, resource) = auth
            .repository_resource_context(repository, action, store)
            .await
            .expect("authorization context should evaluate");
        let request = AuthzRequest {
            actor: identity.actor(),
            repository: repository.to_string(),
            resource,
            action,
        };
        let service = auth
            .authorize(&request, store)
            .await
            .expect("AuthService should evaluate request");
        let cedar = CedarRepositoryAuthorizer::new()
            .authorize(auth, &request, store)
            .await
            .expect("Cedar authorizer should evaluate request");
        assert_eq!(service, cedar);
        service
    }

    async fn assert_enforced(
        auth: &AuthService,
        identity: &AuthIdentity,
        repository: &str,
        action: OciAction,
        store: &InMemoryMetadataStore,
        expected: AuthzDecision,
    ) {
        let actual = enforced_decision(auth, identity, repository, action, store).await;
        assert_eq!(actual, expected);
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
        let epoch = repository
            .namespace()
            .expect("fixture repository should have a namespace")
            .epoch();
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
    fn cedar_schema_validates_authorization_policy() {
        let schema = AUTHORIZATION_SCHEMA.parse().expect("schema should parse");
        TEST_POLICY
            .parse(&schema)
            .expect("policy should validate against schema");
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
    fn cedar_authorizer_inputs_exclude_display_group_names() {
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
    fn cedar_authorizer_authorizes_owner_and_stable_group_grants() {
        let epoch = NamespaceEpoch::new("acme", 1);
        let repository = CedarRepository::new(&epoch, "app");
        let owner = CedarPrincipal::user("test", "subject-owner").unwrap();
        let group = CedarGroup::new("test", STABLE_GROUP_ID).unwrap();
        let builder = CedarPrincipal::user("test", "subject-builder").unwrap();

        let owner_request =
            request_for_fixture(owner, Vec::new(), repository.clone(), OciAction::Delete);
        assert_eq!(cedar_decision(TEST_POLICY, &owner_request), Decision::Allow);

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
        assert_eq!(cedar_decision(TEST_POLICY, &builder_pull), Decision::Allow);
        assert_eq!(
            cedar_decision(TEST_POLICY, &builder_create),
            Decision::Allow
        );
        assert_eq!(cedar_decision(TEST_POLICY, &builder_update), Decision::Deny);
    }

    #[test]
    fn cedar_authorizer_denies_display_group_name_without_stable_group_parent() {
        let epoch = NamespaceEpoch::new("acme", 1);
        let repository = CedarRepository::new(&epoch, "app");
        let actor = CedarPrincipal::user("test", "subject-display-only").unwrap();
        let request = request_for_fixture(actor, Vec::new(), repository, OciAction::Create);

        assert_eq!(cedar_decision(TEST_POLICY, &request), Decision::Deny);
    }

    #[test]
    fn cedar_authorizer_repository_ids_are_namespace_generation_aware() {
        let old_epoch = NamespaceEpoch::new("acme", 1);
        let new_epoch = NamespaceEpoch::new("acme", 2);
        let old_repository = CedarRepository::new(&old_epoch, "app");
        let new_repository = CedarRepository::new(&new_epoch, "app");
        let owner = CedarPrincipal::user("test", "subject-owner").unwrap();
        let old_request =
            request_for_fixture(owner.clone(), Vec::new(), old_repository, OciAction::Create);
        let new_request = request_for_fixture(owner, Vec::new(), new_repository, OciAction::Create);

        assert_eq!(cedar_decision(TEST_POLICY, &old_request), Decision::Allow);
        assert_eq!(cedar_decision(TEST_POLICY, &new_request), Decision::Deny);
    }

    #[test]
    fn cedar_authorizer_setup_failures_fail_closed() {
        let epoch = NamespaceEpoch::new("acme", 1);
        let repository = CedarRepository::new(&epoch, "app");
        let owner = CedarPrincipal::user("test", "subject-owner").unwrap();
        let request = request_for_fixture(owner, Vec::new(), repository, OciAction::Create);

        assert_eq!(
            cedar_decision(CedarPolicySource("not cedar policy"), &request),
            Decision::Deny
        );
        assert_eq!(
            cedar_decision_with_schema(
                CedarSchemaSource("not cedar schema"),
                TEST_POLICY,
                &request,
            )
            .unwrap_or(Decision::Deny),
            Decision::Deny
        );
    }

    #[tokio::test]
    async fn cedar_enforcement_owner_allows_and_non_owner_denies() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-alice"))).await;

        let alice = identity("subject-alice", TokenType::OidcAccess, &[], &[]);
        assert_enforced(
            &auth,
            &alice,
            "acme/app",
            OciAction::Create,
            &store,
            AuthzDecision::Allow,
        )
        .await;

        let bob = identity("subject-bob", TokenType::OidcAccess, &[], &[]);
        assert_enforced(
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
    async fn cedar_enforcement_namespace_group_grant_ladder() {
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
        assert_enforced(
            &auth,
            &builder,
            "acme/app",
            OciAction::Pull,
            &store,
            AuthzDecision::Allow,
        )
        .await;
        assert_enforced(
            &auth,
            &builder,
            "acme/app",
            OciAction::Create,
            &store,
            AuthzDecision::Allow,
        )
        .await;
        assert_enforced(
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
    async fn cedar_enforcement_display_group_labels_deny() {
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
        assert_enforced(
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
    async fn cedar_enforcement_config_rbac_stable_group_allows() {
        let auth = AuthService::for_test(vec![group_repository_policy(
            "ci",
            CI_GROUP_ID,
            OciAction::Create,
            "resource in Namespace::\"acme#1\"",
        )]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-owner"))).await;

        let ci = identity("subject-ci", TokenType::OidcAccess, &[CI_GROUP_ID], &[]);
        assert_enforced(
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
    async fn cedar_enforcement_config_rbac_display_mapping_denies() {
        let auth = AuthService::for_test(vec![config_policy_set(
            "display-label",
            r#"permit(
    principal in Group::"registry_admins",
    action == Action::"create",
    resource in Namespace::"acme#1"
);"#,
        )]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-owner"))).await;

        let admin = identity(
            "subject-admin",
            TokenType::OidcAccess,
            &["registry_admins"],
            &[],
        );
        assert_enforced(
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
    async fn cedar_enforcement_raft_policy_sets_are_authoritative_when_enabled() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::Org(OrgId::generate())).await;
        let mut builder = identity(
            "subject-builder",
            TokenType::OidcAccess,
            &[BUILDER_GROUP_ID],
            &[],
        );
        builder.username = Some("builder".to_string());

        auth.check_permission(&builder, "acme/app", OciAction::Create, &store)
            .await
            .expect_err("no builtin grant exists yet");

        let policy = MetadataPolicySet {
            id: "acme-builders".to_string(),
            name: "acme builders".to_string(),
            source: PolicySource::Raft,
            cedar_text: format!(
                r#"permit(
    principal in Group::"test:group:{BUILDER_GROUP_ID}",
    action == Action::"create",
    resource in Namespace::"acme#1"
);"#
            ),
            enabled: true,
            created_by: Subject::new("subject-admin"),
            updated_by: Subject::new("subject-admin"),
            created_at: 1,
            updated_at: 1,
        };
        store.put_policy_set(policy.clone()).await.unwrap();

        auth.check_permission(&builder, "acme/app", OciAction::Create, &store)
            .await
            .expect("enabled Raft Cedar policy allows create");

        let mut disabled = policy;
        disabled.enabled = false;
        store.put_policy_set(disabled).await.unwrap();
        auth.check_permission(&builder, "acme/app", OciAction::Create, &store)
            .await
            .expect_err("disabled Raft Cedar policy is ignored");
    }

    #[tokio::test]
    async fn cedar_enforcement_admin_access_uses_registry_root_resource() {
        let auth = AuthService::for_test(vec![admin_policy("admin", CI_GROUP_ID)]);
        let store = InMemoryMetadataStore::default();
        let admin = identity("subject-admin", TokenType::OidcAccess, &[CI_GROUP_ID], &[]);

        auth.check_admin_access(&admin, &store)
            .await
            .expect("Cedar authorizer allows admin access");
        let request = AuthzRequest {
            actor: admin.actor(),
            repository: "*".to_string(),
            resource: None,
            action: OciAction::Admin,
        };
        let cedar = CedarRepositoryAuthorizer::new()
            .authorize(&auth, &request, &store)
            .await
            .expect("Cedar authorizer should evaluate admin request");
        assert_eq!(cedar, AuthzDecision::Allow);

        claim(&store, "acme", Owner::Org(OrgId::generate())).await;
        auth.check_permission(&admin, "acme/app", OciAction::Delete, &store)
            .await
            .expect_err("control-plane admin does not imply repository delete");
    }

    #[tokio::test]
    async fn cedar_enforcement_unclaimed_pull_allowed_but_write_guarded() {
        let auth = AuthService::for_test(vec![group_repository_policy(
            "ci",
            CI_GROUP_ID,
            OciAction::Create,
            "resource == Repository::\"acme/app\"",
        )]);
        let store = InMemoryMetadataStore::default();
        let ci = identity("subject-ci", TokenType::OidcAccess, &[CI_GROUP_ID], &[]);

        assert_enforced(
            &auth,
            &ci,
            "acme/app",
            OciAction::Pull,
            &store,
            AuthzDecision::Allow,
        )
        .await;

        auth.check_permission(&ci, "acme/app", OciAction::Create, &store)
            .await
            .expect_err("Cedar authorizer denies unclaimed writes before policy");
        let request = AuthzRequest {
            actor: ci.actor(),
            repository: "acme/app".to_string(),
            resource: None,
            action: OciAction::Create,
        };
        let cedar = CedarRepositoryAuthorizer::new()
            .authorize(&auth, &request, &store)
            .await
            .expect("Cedar authorizer should evaluate unclaimed write");
        assert_eq!(cedar, AuthzDecision::Deny);
    }

    #[tokio::test]
    async fn cedar_enforcement_scope_epoch_ceiling_denies_overbroad_policy() {
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
        assert_enforced(
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
        assert_enforced(
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
    async fn cedar_enforcement_scoped_tokens_do_not_escape_own_personal_namespace() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();

        let mut pat = identity(
            "subject-alice",
            TokenType::PersonalAccess,
            &[],
            &["repository:users/alice/app:pull"],
        );
        pat.username = Some("alice".to_string());
        assert_enforced(
            &auth,
            &pat,
            "users/alice/app",
            OciAction::Pull,
            &store,
            AuthzDecision::Allow,
        )
        .await;
        assert_enforced(
            &auth,
            &pat,
            "users/alice/app",
            OciAction::Create,
            &store,
            AuthzDecision::Deny,
        )
        .await;
        assert_enforced(
            &auth,
            &pat,
            "users/alice/other",
            OciAction::Pull,
            &store,
            AuthzDecision::Deny,
        )
        .await;

        let mut bearer = identity(
            "subject-alice",
            TokenType::OciBearer,
            &[],
            &["repository:users/alice/app:pull"],
        );
        bearer.username = Some("alice".to_string());
        assert_enforced(
            &auth,
            &bearer,
            "users/alice/app",
            OciAction::Create,
            &store,
            AuthzDecision::Deny,
        )
        .await;
    }

    #[tokio::test]
    async fn cedar_enforcement_public_namespace_grant_is_inert() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-owner"))).await;
        put_repo(&store, "acme/app", Visibility::Private).await;
        grant(
            &store,
            "acme",
            "public",
            NamespaceGrantGrantee::Public,
            OciAction::Pull,
        )
        .await;

        let bob = identity("subject-bob", TokenType::OidcAccess, &[], &[]);
        assert_enforced(
            &auth,
            &bob,
            "acme/app",
            OciAction::Pull,
            &store,
            AuthzDecision::Deny,
        )
        .await;
        assert_enforced(
            &auth,
            &bob,
            "acme/app",
            OciAction::Create,
            &store,
            AuthzDecision::Deny,
        )
        .await;

        auth.check_public_pull("acme/app", &store).await.expect_err(
            "repository visibility, not namespace public grant, controls anonymous pull",
        );
    }

    #[tokio::test]
    async fn cedar_enforcement_max_grantable_action_matches_direct_cedar() {
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
        let (service_action, _) = auth
            .max_grantable_action(&builder, "acme/app", &store)
            .await
            .expect("AuthService should derive max grantable action");
        let cedar = CedarRepositoryAuthorizer::new()
            .max_grantable_action(&auth, &builder.actor(), "acme/app", &store)
            .await
            .expect("Cedar authorizer should derive max grantable action");
        assert_eq!(service_action, OciAction::Create);
        assert_eq!(cedar, Some(service_action));
    }

    #[tokio::test]
    async fn cedar_enforcement_unclaimed_namespace_write_denied_before_policy() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        let actor = identity("subject-owner", TokenType::OidcAccess, &[], &[]);
        auth.check_permission(&actor, "acme/app", OciAction::Create, &store)
            .await
            .expect_err("Cedar authorizer denies unclaimed writes");

        let request = AuthzRequest {
            actor: actor.actor(),
            repository: "acme/app".to_string(),
            resource: None,
            action: OciAction::Create,
        };
        assert_eq!(cedar_decision(TEST_POLICY, &request), Decision::Deny);
    }

    #[tokio::test]
    async fn cedar_enforcement_org_owner_does_not_implicitly_allow() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::Org(OrgId::generate())).await;

        let actor = identity("subject-owner", TokenType::OidcAccess, &[], &[]);
        assert_enforced(
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
