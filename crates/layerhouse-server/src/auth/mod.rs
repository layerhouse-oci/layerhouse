pub mod authorization;
pub(crate) mod cedar_shadow;
pub mod discovery;
pub mod identity;
pub mod jwks;
pub mod middleware;
pub mod oauth2;
pub mod permissions;
pub mod principal;
pub mod session;
pub mod token;
pub mod token_endpoint;

use std::sync::Arc;
use tokio::sync::RwLock;

use async_trait::async_trait;
use axum::http::HeaderMap;

use crate::config::{AuthConfig, CookieSecureMode, S3Config};
use crate::error::LayerhouseError;
use crate::store::metadata::handle::{handle_of, is_handle_reserved};
use crate::store::metadata::{
    NamespaceEpoch, NamespaceGrant, NamespaceGrantGrantee, NamespaceStore, Owner, TokenStore,
};

use self::authorization::{
    AuthorizedRepositoryAccess, Authorizer, AuthzDecision, AuthzRequest, RepositoryResource,
};
use self::discovery::OidcDiscovery;
use self::identity::Subject;
use self::jwks::{CachedJwksDocument, JwksCache, JwksMetrics, JwksS3Cache};
use self::permissions::PermissionResolver;
use self::permissions::action_rank;
use self::principal::{PrincipalKind, ProviderQualifiedId, stable_group_ids};
use self::token::{AuthIdentity, TokenType};

/// Whether a namespace `owner` grants `identity` the full action ladder in the
/// claimed namespace. A `User` owner matches by typed subject. `Org` ownership
/// returns `false` for now: there is no actor->org membership map yet, so
/// org-owned namespaces rely on admin or an explicit RBAC grant until org
/// membership lands.
fn owner_grants(owner: &Owner, identity: &AuthIdentity) -> bool {
    match owner {
        Owner::User(subject) => *subject == identity.subject,
        Owner::Org(_) => false,
    }
}

fn namespace_grant_matches(
    grant: &NamespaceGrant,
    identity: &AuthIdentity,
    action: permissions::OciAction,
) -> bool {
    if !permissions::action_matches(grant.action, action) {
        return false;
    }
    match &grant.grantee {
        NamespaceGrantGrantee::Group { id } => identity.group_ids.iter().any(|group| group == id),
        NamespaceGrantGrantee::User { id } => *id == identity.principal,
        NamespaceGrantGrantee::Public => action == permissions::OciAction::Pull,
    }
}

fn max_namespace_grant_action(
    grants: &[NamespaceGrant],
    identity: &AuthIdentity,
) -> Option<permissions::OciAction> {
    grants
        .iter()
        .filter(|grant| namespace_grant_matches(grant, identity, permissions::OciAction::Pull))
        .map(|grant| grant.action)
        .max_by_key(|action| action_rank(*action))
}

fn authorization_group_keys(identity: &AuthIdentity) -> Vec<String> {
    identity.group_ids.iter().map(ToString::to_string).collect()
}

pub struct AuthService {
    pub config: AuthConfig,
    discovery: RwLock<OidcDiscovery>,
    jwks_cache: Arc<RwLock<JwksCache>>,
    jwks_s3_cache: Option<Arc<JwksS3Cache>>,
    permission_resolver: PermissionResolver,
    token_signing_key: jsonwebtoken::EncodingKey,
    token_verification_key: jsonwebtoken::DecodingKey,
    session_key: [u8; 32],
}

struct FreshAuthMaterial {
    issuer_internal_url: String,
    discovery_doc: serde_json::Value,
    discovery: OidcDiscovery,
    jwks_endpoint: String,
    jwks: serde_json::Value,
    fetched_at_unix: u64,
}

struct RepositoryAuthorization {
    decision: AuthzDecision,
    access: AuthorizedRepositoryAccess,
    resource: Option<RepositoryResource>,
}

fn repository_authorization(
    repository: &str,
    action: permissions::OciAction,
    decision: AuthzDecision,
    expected_namespace: Option<NamespaceEpoch>,
    resource: Option<RepositoryResource>,
) -> RepositoryAuthorization {
    RepositoryAuthorization {
        decision,
        access: AuthorizedRepositoryAccess::new(repository, action, expected_namespace),
        resource,
    }
}

fn scope_matches_namespace_epoch(
    identity: &AuthIdentity,
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
    identity
        .namespace_epochs
        .iter()
        .any(|epoch| epoch == expected)
}

fn max_scope_action_for_identity(
    identity: &AuthIdentity,
    repository: &str,
    expected: Option<&NamespaceEpoch>,
) -> Option<permissions::OciAction> {
    use permissions::OciAction::{Create, Delete, Pull, Update};

    [Delete, Update, Create, Pull].into_iter().find(|action| {
        permissions::matching_scope(&identity.scopes, repository, *action)
            .map(|(repo_pattern, _)| {
                scope_matches_namespace_epoch(identity, &repo_pattern, expected)
            })
            .unwrap_or(false)
    })
}

fn uses_explicit_scopes(identity: &AuthIdentity) -> bool {
    matches!(
        identity.token_type,
        TokenType::PersonalAccess | TokenType::OciBearer
    )
}

impl AuthService {
    pub(crate) fn provider_name(&self) -> &str {
        self.config.provider_name.trim()
    }

    pub(crate) fn user_principal(
        &self,
        subject: &str,
    ) -> Result<ProviderQualifiedId, LayerhouseError> {
        ProviderQualifiedId::new(self.provider_name(), PrincipalKind::User, subject)
    }

    pub async fn new(
        config: AuthConfig,
        s3_config: Option<&S3Config>,
    ) -> Result<Self, LayerhouseError> {
        // Decode signing keys (first key signs, all verify)
        let first_signing_key = config.token_signing_keys.first().ok_or_else(|| {
            LayerhouseError::Internal("at least one token signing key is required".to_string())
        })?;
        let signing_key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            first_signing_key,
        )
        .map_err(|e| LayerhouseError::Internal(format!("invalid token signing key: {}", e)))?;

        let signing_key = jsonwebtoken::EncodingKey::from_secret(&signing_key_bytes);
        let verification_key = jsonwebtoken::DecodingKey::from_secret(&signing_key_bytes);

        // Decode session encryption key
        let session_key_bytes = base64::Engine::decode(
            &base64::engine::general_purpose::STANDARD,
            &config.session_encryption_key,
        )
        .map_err(|e| LayerhouseError::Internal(format!("invalid session encryption key: {}", e)))?;

        let session_key: [u8; 32] = session_key_bytes.try_into().map_err(|_| {
            LayerhouseError::Internal("session encryption key must be 32 bytes".to_string())
        })?;

        let permission_resolver = PermissionResolver::new(&config.permissions);
        let jwks_cache = Arc::new(RwLock::new(JwksCache::empty()));
        let jwks_s3_cache = match s3_config {
            Some(s3_config) => Some(Arc::new(
                JwksS3Cache::new(s3_config, config.jwks_cache_s3_key.clone()).await,
            )),
            None => None,
        };

        let discovery = match Self::fetch_fresh_auth_material(&config).await {
            Ok(material) => {
                Self::install_fresh_material(
                    &jwks_cache,
                    jwks_s3_cache.as_deref(),
                    &config,
                    &material,
                )
                .await?;
                material.discovery
            }
            Err(fetch_err) => {
                Self::load_cached_material(
                    &jwks_cache,
                    jwks_s3_cache.as_deref(),
                    &config,
                    fetch_err,
                )
                .await?
            }
        };

        Ok(Self {
            config,
            discovery: RwLock::new(discovery),
            jwks_cache,
            jwks_s3_cache,
            permission_resolver,
            token_signing_key: signing_key,
            token_verification_key: verification_key,
            session_key,
        })
    }

    async fn fetch_fresh_auth_material(
        config: &AuthConfig,
    ) -> Result<FreshAuthMaterial, LayerhouseError> {
        let mut errors = Vec::new();
        for issuer_internal_url in config.issuer_internal_urls() {
            match Self::fetch_auth_material_from_issuer(config, issuer_internal_url).await {
                Ok(material) => return Ok(material),
                Err(err) => {
                    errors.push(format!("{issuer_internal_url}: {err}"));
                    tracing::warn!(
                        issuer_internal_url,
                        err = %err,
                        "OIDC discovery/JWKS endpoint failed"
                    );
                }
            }
        }

        Err(LayerhouseError::Internal(format!(
            "OIDC discovery/JWKS fetch failed for all configured endpoints: {}",
            errors.join("; ")
        )))
    }

    async fn fetch_auth_material_from_issuer(
        config: &AuthConfig,
        issuer_internal_url: &str,
    ) -> Result<FreshAuthMaterial, LayerhouseError> {
        let discovery_doc =
            OidcDiscovery::fetch_document(issuer_internal_url, config.tls_insecure_skip_verify)
                .await?;
        let discovery =
            OidcDiscovery::from_document(&discovery_doc, issuer_internal_url, &config.issuer_url)?;

        let configured_jwks_urls = config.jwks_urls();
        let jwks_candidates: Vec<String> = if configured_jwks_urls.is_empty() {
            vec![discovery.jwks_uri.clone()]
        } else {
            configured_jwks_urls
                .into_iter()
                .map(ToString::to_string)
                .collect()
        };

        let mut errors = Vec::new();
        for jwks_endpoint in jwks_candidates {
            match jwks::fetch_jwks(&jwks_endpoint, config.tls_insecure_skip_verify).await {
                Ok(jwks) => {
                    return Ok(FreshAuthMaterial {
                        issuer_internal_url: issuer_internal_url.to_string(),
                        discovery_doc,
                        discovery,
                        jwks_endpoint,
                        jwks,
                        fetched_at_unix: jwks::now_unix(),
                    });
                }
                Err(err) => {
                    errors.push(format!("{jwks_endpoint}: {err}"));
                    tracing::warn!(jwks_endpoint, err = %err, "JWKS endpoint failed");
                }
            }
        }

        Err(LayerhouseError::Internal(format!(
            "JWKS fetch failed for issuer {issuer_internal_url}: {}",
            errors.join("; ")
        )))
    }

    async fn install_fresh_material(
        jwks_cache: &Arc<RwLock<JwksCache>>,
        jwks_s3_cache: Option<&JwksS3Cache>,
        config: &AuthConfig,
        material: &FreshAuthMaterial,
    ) -> Result<(), LayerhouseError> {
        let key_count = {
            let mut cache = jwks_cache.write().await;
            cache.refresh_from_value(
                &material.jwks,
                material.fetched_at_unix,
                false,
                material.jwks_endpoint.clone(),
            )?
        };

        tracing::info!(
            key_count,
            endpoint = %material.jwks_endpoint,
            issuer_internal_url = %material.issuer_internal_url,
            "JWKS cache refreshed"
        );

        if let Some(jwks_s3_cache) = jwks_s3_cache {
            let document = CachedJwksDocument::new(
                config.issuer_url.clone(),
                material.issuer_internal_url.clone(),
                material.discovery_doc.clone(),
                material.jwks.clone(),
                material.fetched_at_unix,
            );
            if let Err(err) = jwks_s3_cache.store(&document).await {
                tracing::warn!(err = %err, "failed to persist last-good JWKS cache");
            }
        }

        Ok(())
    }

    async fn load_cached_material(
        jwks_cache: &Arc<RwLock<JwksCache>>,
        jwks_s3_cache: Option<&JwksS3Cache>,
        config: &AuthConfig,
        fetch_err: LayerhouseError,
    ) -> Result<OidcDiscovery, LayerhouseError> {
        {
            let mut cache = jwks_cache.write().await;
            cache.record_refresh_failure();
        }

        let Some(jwks_s3_cache) = jwks_s3_cache else {
            return Err(LayerhouseError::Internal(format!(
                "initial JWKS fetch failed and no S3 JWKS cache is configured: {fetch_err}"
            )));
        };
        let document = jwks_s3_cache.load().await?.ok_or_else(|| {
            LayerhouseError::Internal(format!(
                "initial JWKS fetch failed and S3 JWKS cache is empty: {fetch_err}"
            ))
        })?;

        Self::install_cached_document(jwks_cache, config, &document).await
    }

    async fn install_cached_document(
        jwks_cache: &Arc<RwLock<JwksCache>>,
        config: &AuthConfig,
        document: &CachedJwksDocument,
    ) -> Result<OidcDiscovery, LayerhouseError> {
        if document.issuer_url != config.issuer_url {
            return Err(LayerhouseError::Internal(format!(
                "cached JWKS issuer {} does not match configured issuer {}",
                document.issuer_url, config.issuer_url
            )));
        }
        if !document.within_stale_window(config.jwks_max_stale_seconds) {
            return Err(LayerhouseError::Internal(format!(
                "cached JWKS is {}s old, exceeding configured stale window of {}s",
                document.age_seconds(),
                config.jwks_max_stale_seconds
            )));
        }

        let discovery = OidcDiscovery::from_document(
            &document.discovery,
            &document.issuer_internal_url,
            &config.issuer_url,
        )?;
        let key_count = {
            let mut cache = jwks_cache.write().await;
            cache.refresh_from_value(
                &document.jwks,
                document.fetched_at_unix,
                true,
                format!("s3:{}", config.jwks_cache_s3_key),
            )?
        };
        tracing::warn!(
            key_count,
            age_seconds = document.age_seconds(),
            "using stale last-good JWKS cache because IdP endpoints are unreachable"
        );
        Ok(discovery)
    }

    pub fn session_key(&self) -> &[u8; 32] {
        &self.session_key
    }

    pub fn start_jwks_refresh(self: &Arc<Self>) {
        let svc = Arc::clone(self);
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(
                svc.config.jwks_refresh_seconds,
            ));
            loop {
                interval.tick().await;
                if let Err(e) = svc.refresh_jwks_once().await {
                    tracing::warn!(err = %e, "JWKS refresh failed");
                }
            }
        });
    }

    pub async fn refresh_jwks_once(&self) -> Result<(), LayerhouseError> {
        match Self::fetch_fresh_auth_material(&self.config).await {
            Ok(material) => {
                Self::install_fresh_material(
                    &self.jwks_cache,
                    self.jwks_s3_cache.as_deref(),
                    &self.config,
                    &material,
                )
                .await?;
                let mut discovery = self.discovery.write().await;
                *discovery = material.discovery;
                Ok(())
            }
            Err(err) => {
                let mut cache = self.jwks_cache.write().await;
                cache.record_refresh_failure();
                Err(err)
            }
        }
    }

    pub async fn validate_token<M: TokenStore>(
        &self,
        token: &str,
        metadata: &M,
    ) -> Result<AuthIdentity, LayerhouseError> {
        // 1. Try as layerhouse PAT (starts with "layerhouse-")
        if token.starts_with("layerhouse-") {
            return self.validate_pat(token, metadata).await;
        }

        // 2. Try as layerhouse OCI bearer token (signed by us)
        if let Ok(identity) = self.validate_oci_token(token) {
            return Ok(identity);
        }

        // 3. Try as OIDC access token (validate via JWKS)
        self.validate_oidc_token(token).await
    }

    async fn validate_pat<M: TokenStore>(
        &self,
        token: &str,
        metadata: &M,
    ) -> Result<AuthIdentity, LayerhouseError> {
        use sha2::Digest;
        let token_hash = hex::encode(sha2::Sha256::digest(token.as_bytes()));

        let pat = metadata
            .get_personal_access_token_by_hash(&token_hash)
            .await?
            .ok_or_else(|| LayerhouseError::Unauthorized {
                message: "invalid token".to_string(),
                realm: None,
                service: None,
                scope: None,
            })?;

        if let Some(exp) = pat.expires_at {
            let now = chrono::Utc::now().timestamp() as u64;
            if now > exp {
                return Err(LayerhouseError::Unauthorized {
                    message: "token expired".to_string(),
                    realm: None,
                    service: None,
                    scope: None,
                });
            }
        }

        let principal = self.user_principal(&pat.subject)?;
        Ok(AuthIdentity {
            subject: Subject::new(pat.subject),
            principal,
            username: pat.username,
            display_name: None,
            email: None,
            groups: vec![],
            group_ids: vec![],
            scopes: pat.scopes,
            namespace_epochs: pat.namespace_epochs,
            token_type: TokenType::PersonalAccess,
        })
    }

    fn validate_oci_token(&self, token: &str) -> Result<AuthIdentity, LayerhouseError> {
        let token_data = jsonwebtoken::decode::<token::TokenClaims>(
            token,
            &self.token_verification_key,
            &jsonwebtoken::Validation::default(),
        )
        .map_err(|_| LayerhouseError::Unauthorized {
            message: "invalid token".to_string(),
            realm: None,
            service: None,
            scope: None,
        })?;

        let claims = token_data.claims;
        let display_name = claims.display_name();
        let username = claims.username();
        let email = claims.email();
        let groups = claims.groups.unwrap_or_default();
        let principal = self.user_principal(&claims.subject)?;
        let group_ids = stable_group_ids(self.provider_name(), &groups);
        Ok(AuthIdentity {
            subject: Subject::new(claims.subject),
            principal,
            username,
            display_name,
            email,
            groups,
            group_ids,
            scopes: claims
                .scope
                .map(|s| s.split(' ').map(ToString::to_string).collect())
                .unwrap_or_default(),
            namespace_epochs: claims.namespace_epochs,
            token_type: TokenType::OciBearer,
        })
    }

    async fn verify_token_claims(
        &self,
        token: &str,
        audience: &str,
    ) -> Result<token::TokenClaims, LayerhouseError> {
        let header =
            jsonwebtoken::decode_header(token).map_err(|_| LayerhouseError::Unauthorized {
                message: "invalid token".to_string(),
                realm: None,
                service: None,
                scope: None,
            })?;

        let kid = header.kid.ok_or_else(|| LayerhouseError::Unauthorized {
            message: "token missing kid".to_string(),
            realm: None,
            service: None,
            scope: None,
        })?;

        let mut jwks = self.jwks_cache.read().await;
        let dec_key = if let Some(dec_key) = jwks.find_key(&kid) {
            dec_key
        } else {
            drop(jwks);
            if let Err(err) = self.refresh_jwks_once().await {
                tracing::warn!(kid, err = %err, "immediate JWKS refresh for unknown kid failed");
            }
            jwks = self.jwks_cache.read().await;
            jwks.find_key(&kid)
                .ok_or_else(|| LayerhouseError::Unauthorized {
                    message: "unknown signing key".to_string(),
                    realm: None,
                    service: None,
                    scope: None,
                })?
        };

        let mut validation = jsonwebtoken::Validation::new(header.alg);
        validation.set_audience(&[audience]);
        validation.set_issuer(&[&self.config.issuer_url]);

        let token_data = jsonwebtoken::decode::<token::TokenClaims>(token, dec_key, &validation)
            .map_err(|_| LayerhouseError::Unauthorized {
                message: "invalid token".to_string(),
                realm: None,
                service: None,
                scope: None,
            })?;

        Ok(token_data.claims)
    }

    /// Validates the OIDC ID token against JWKS and returns the verified claims.
    /// The caller is responsible for checking subject consistency with the access token.
    /// ID tokens always validate audience against client_id (OIDC spec requirement).
    pub(crate) async fn verify_id_token(
        &self,
        id_token: &str,
    ) -> Result<token::TokenClaims, LayerhouseError> {
        self.verify_token_claims(id_token, &self.config.client_id)
            .await
    }

    /// Validates the OIDC access token via JWKS and returns the user's groups,
    /// token subject, and expiration timestamp (Unix seconds).
    pub(crate) async fn verify_access_token(
        &self,
        access_token: &str,
    ) -> Result<(Vec<String>, String, usize), LayerhouseError> {
        let audience = self
            .config
            .effective_access_token_audience()
            .unwrap_or(&self.config.client_id);
        let claims = self.verify_token_claims(access_token, audience).await?;
        Ok((
            claims.extract_groups(&self.config.group_claim),
            claims.subject,
            claims.exp,
        ))
    }

    async fn validate_oidc_token(&self, token: &str) -> Result<AuthIdentity, LayerhouseError> {
        let audience = self
            .config
            .effective_access_token_audience()
            .unwrap_or(&self.config.client_id);
        let claims = self.verify_token_claims(token, audience).await?;

        let display_name = claims.display_name();
        let username = claims.username();
        let email = claims.email();
        let user_groups = claims.extract_groups(&self.config.group_claim);
        let principal = self.user_principal(&claims.subject)?;
        let group_ids = stable_group_ids(self.provider_name(), &user_groups);

        Ok(AuthIdentity {
            subject: Subject::new(claims.subject),
            principal,
            username,
            display_name,
            email,
            groups: user_groups,
            group_ids,
            namespace_epochs: Vec::new(),
            scopes: vec![],
            token_type: TokenType::OidcAccess,
        })
    }

    pub async fn check_permission(
        &self,
        identity: &AuthIdentity,
        repository: &str,
        action: permissions::OciAction,
        namespaces: &dyn NamespaceStore,
    ) -> Result<AuthorizedRepositoryAccess, LayerhouseError> {
        let authorization = self
            .authorize_repository(identity, repository, action, namespaces)
            .await?;
        let request = AuthzRequest {
            actor: identity.actor(),
            repository: repository.to_string(),
            resource: authorization.resource.clone(),
            action,
        };
        let resource_id = request.resource.as_ref().map(RepositoryResource::entity_id);
        tracing::trace!(
            repository = %request.repository,
            resource_id = resource_id.as_deref().unwrap_or("unresolved"),
            action = ?request.action,
            actor_subject = %request.actor.principal.local_id(),
            actor_principal = %request.actor.principal,
            actor_username = request.actor.username.as_deref().unwrap_or(""),
            actor_display_name = request.actor.display_name.as_deref().unwrap_or(""),
            actor_email = request.actor.email.as_deref().unwrap_or(""),
            actor_group_count = request.actor.group_ids.len(),
            actor_display_group_count = request.actor.display_groups.len(),
            actor_scope_count = request.actor.scopes.len(),
            actor_namespace_epoch_count = request.actor.namespace_epochs.len(),
            actor_token_type = ?request.actor.token_type,
            "compatibility authorizer evaluating request"
        );
        self.trace_cedar_shadow_decision(&request, namespaces, authorization.decision)
            .await;
        match authorization.decision {
            AuthzDecision::Allow => Ok(authorization.access),
            AuthzDecision::Deny => Err(LayerhouseError::Denied(format!(
                "access denied for repository {}",
                repository
            ))),
        }
    }

    async fn authorize_repository(
        &self,
        identity: &AuthIdentity,
        repository: &str,
        action: permissions::OciAction,
        namespaces: &dyn NamespaceStore,
    ) -> Result<RepositoryAuthorization, LayerhouseError> {
        // Personal-namespace auto-grant: any authenticated user has the full
        // action ladder under `users/<their-username>/`. Keyed on
        // `identity.username`, which is now populated for PATs as well as OIDC
        // sessions (see `validate_pat`).
        if permissions::in_personal_namespace(identity.username.as_deref(), repository) {
            return Ok(repository_authorization(
                repository,
                action,
                AuthzDecision::Allow,
                None,
                None,
            ));
        }

        // Personal-namespace boundary guard: repos under `users/<someone>/`
        // are private. Only the namespace owner (matched above) gets through;
        // any other access — cross-user PAT scope, delegated RBAC, OCI bearer
        // tokens — is denied. This closes the gap where a PAT scoped to
        // `users/bob/*` could bypass the namespace gate (the `users` handle is
        // reserved, so `is_handle_reserved` skips the claim check).
        if let Some(ns_user) = permissions::in_personal_namespace_of(repository)
            && identity.username.as_deref().is_none_or(|u| u != ns_user)
        {
            return Ok(repository_authorization(
                repository,
                action,
                AuthzDecision::Deny,
                None,
                None,
            ));
        }

        let mut expected_namespace = None;
        let mut resource = None;

        // Writes to `<handle>/...` are gated on a live namespace claim, mirroring
        // the Raft apply-time gate (`require_live_namespace`). Reads and targets
        // with no resolvable handle (the `"*"` admin wildcard, single-segment
        // repos) skip the gate and fall through to RBAC. `handle_of` erroring is
        // treated as "no handle to gate on", not a hard failure, so the admin
        // path and cross-namespace pulls keep working.
        if let Ok(handle) = handle_of(repository)
            && !is_handle_reserved(handle)
        {
            match namespaces.get_namespace(handle).await? {
                None if action != permissions::OciAction::Pull => {
                    return Err(LayerhouseError::Denied(format!(
                        "namespace {handle:?} is not claimed"
                    )));
                }
                None => {}
                Some(ns) => {
                    expected_namespace =
                        Some(crate::store::metadata::NamespaceEpoch::from_namespace(&ns));
                    resource = Some(RepositoryResource::from_repository(repository, &ns)?);
                    if owner_grants(&ns.owner, identity) && !uses_explicit_scopes(identity) {
                        return Ok(repository_authorization(
                            repository,
                            action,
                            AuthzDecision::Allow,
                            expected_namespace,
                            resource,
                        ));
                    }
                    let grants = namespaces.list_namespace_grants(handle).await?;
                    if grants
                        .iter()
                        .any(|grant| namespace_grant_matches(grant, identity, action))
                    {
                        return Ok(repository_authorization(
                            repository,
                            action,
                            AuthzDecision::Allow,
                            expected_namespace,
                            resource,
                        ));
                    }
                }
            }
        }

        // PATs and minted OCI bearer tokens carry explicit repository scopes.
        if uses_explicit_scopes(identity) {
            let decision = match permissions::matching_scope(&identity.scopes, repository, action) {
                Some((repo_pattern, _))
                    if scope_matches_namespace_epoch(
                        identity,
                        &repo_pattern,
                        expected_namespace.as_ref(),
                    ) =>
                {
                    AuthzDecision::Allow
                }
                Some(_) | None => AuthzDecision::Deny,
            };
            return Ok(repository_authorization(
                repository,
                action,
                decision,
                expected_namespace,
                resource,
            ));
        }

        // OIDC tokens: map groups to permissions via config
        let group_keys = authorization_group_keys(identity);
        let decision = match self
            .permission_resolver
            .check(&group_keys, repository, action)
        {
            Ok(()) => Ok(AuthzDecision::Allow),
            Err(LayerhouseError::Denied(_)) => Ok(AuthzDecision::Deny),
            Err(error) => Err(error),
        }?;
        Ok(repository_authorization(
            repository,
            action,
            decision,
            expected_namespace,
            resource,
        ))
    }

    pub async fn check_admin_access(
        &self,
        identity: &AuthIdentity,
        namespaces: &dyn NamespaceStore,
    ) -> Result<(), LayerhouseError> {
        self.check_permission(identity, "*", permissions::OciAction::Delete, namespaces)
            .await?;
        Ok(())
    }

    /// Compute the maximum action the actor can perform on `repository`,
    /// and where that access came from. Used by the dashboard to render
    /// the access ladder and authorization reason panel.
    pub async fn max_grantable_action(
        &self,
        identity: &AuthIdentity,
        repository: &str,
        namespaces: &dyn NamespaceStore,
    ) -> Result<(permissions::OciAction, permissions::GrantSource), LayerhouseError> {
        use permissions::OciAction::*;

        self.trace_cedar_shadow_max_grantable(identity, repository, namespaces)
            .await;

        // Personal namespace grants the full ladder.
        if permissions::in_personal_namespace(identity.username.as_deref(), repository) {
            return Ok((Delete, permissions::GrantSource::Personal));
        }

        let mut expected_namespace = None;

        // Namespace owner via claim — full ladder.
        if let Ok(handle) = handle_of(repository)
            && !is_handle_reserved(handle)
            && let Some(ns) = namespaces.get_namespace(handle).await?
        {
            expected_namespace = Some(NamespaceEpoch::from_namespace(&ns));
            if owner_grants(&ns.owner, identity) && !uses_explicit_scopes(identity) {
                return Ok((Delete, permissions::GrantSource::Personal));
            }
            let grants = namespaces.list_namespace_grants(handle).await?;
            if let Some(action) = max_namespace_grant_action(&grants, identity) {
                return Ok((action, permissions::GrantSource::GroupGrant));
            }
        }

        // Check scopes (PAT or OCI bearer).
        let scope_max =
            max_scope_action_for_identity(identity, repository, expected_namespace.as_ref());

        // Check OIDC group grants.
        let group_keys = authorization_group_keys(identity);
        let group_max = self
            .permission_resolver
            .max_action_from_groups(&group_keys, repository);

        let max = match (scope_max, group_max) {
            (Some(s), Some(g)) => Some(if action_rank(s) >= action_rank(g) {
                s
            } else {
                g
            }),
            (Some(s), None) => Some(s),
            (None, Some(g)) => Some(g),
            (None, None) => None,
        };

        match max {
            Some(action) => Ok((action, permissions::GrantSource::GroupGrant)),
            None => Err(LayerhouseError::Denied(format!(
                "access denied for repository {}",
                repository
            ))),
        }
    }

    pub async fn check_public_pull(
        &self,
        repository: &str,
        namespaces: &dyn NamespaceStore,
    ) -> Result<(), LayerhouseError> {
        let handle = handle_of(repository)?;
        if is_handle_reserved(handle) {
            self.trace_cedar_shadow_public_pull(repository, namespaces, AuthzDecision::Deny)
                .await;
            return Err(LayerhouseError::Denied(format!(
                "repository {repository:?} is not public"
            )));
        }
        let grants = namespaces.list_namespace_grants(handle).await?;
        let decision = if grants.iter().any(|grant| {
            matches!(grant.grantee, NamespaceGrantGrantee::Public)
                && permissions::action_matches(grant.action, permissions::OciAction::Pull)
        }) {
            AuthzDecision::Allow
        } else {
            AuthzDecision::Deny
        };
        self.trace_cedar_shadow_public_pull(repository, namespaces, decision)
            .await;
        match decision {
            AuthzDecision::Allow => Ok(()),
            AuthzDecision::Deny => Err(LayerhouseError::Denied(format!(
                "repository {repository:?} is not public"
            ))),
        }
    }

    async fn trace_cedar_shadow_decision(
        &self,
        request: &AuthzRequest,
        namespaces: &dyn NamespaceStore,
        compatibility: AuthzDecision,
    ) {
        match cedar_shadow::CedarShadowAuthorizer::new()
            .authorize(self, request, namespaces)
            .await
        {
            Ok(shadow) if shadow != compatibility => {
                tracing::warn!(
                    repository = %request.repository,
                    action = ?request.action,
                    compatibility = ?compatibility,
                    cedar_shadow = ?shadow,
                    "Cedar shadow authorization mismatch"
                );
            }
            Ok(shadow) => {
                tracing::trace!(
                    repository = %request.repository,
                    action = ?request.action,
                    cedar_shadow = ?shadow,
                    "Cedar shadow authorization matched compatibility decision"
                );
            }
            Err(err) => {
                tracing::warn!(
                    repository = %request.repository,
                    action = ?request.action,
                    err = %err,
                    "Cedar shadow authorization failed closed"
                );
            }
        }
    }

    async fn trace_cedar_shadow_public_pull(
        &self,
        repository: &str,
        namespaces: &dyn NamespaceStore,
        compatibility: AuthzDecision,
    ) {
        match cedar_shadow::CedarShadowAuthorizer::new()
            .authorize_public_pull(repository, namespaces)
            .await
        {
            Ok(shadow) if shadow != compatibility => {
                tracing::warn!(
                    repository,
                    compatibility = ?compatibility,
                    cedar_shadow = ?shadow,
                    "Cedar shadow public-pull mismatch"
                );
            }
            Ok(shadow) => {
                tracing::trace!(
                    repository,
                    cedar_shadow = ?shadow,
                    "Cedar shadow public-pull matched compatibility decision"
                );
            }
            Err(err) => {
                tracing::warn!(
                    repository,
                    err = %err,
                    "Cedar shadow public-pull failed closed"
                );
            }
        }
    }

    async fn trace_cedar_shadow_max_grantable(
        &self,
        identity: &AuthIdentity,
        repository: &str,
        namespaces: &dyn NamespaceStore,
    ) {
        match cedar_shadow::CedarShadowAuthorizer::new()
            .max_grantable_action(self, &identity.actor(), repository, namespaces)
            .await
        {
            Ok(action) => {
                tracing::trace!(
                    repository,
                    cedar_shadow_max_grantable = ?action,
                    "Cedar shadow grantability evaluated"
                );
            }
            Err(err) => {
                tracing::warn!(
                    repository,
                    err = %err,
                    "Cedar shadow grantability failed closed"
                );
            }
        }
    }

    /// Maximum action granted by group mappings for a repository.
    /// Delegates to the inner [`PermissionResolver`].
    pub fn max_action_from_groups(
        &self,
        user_groups: &[String],
        repository: &str,
    ) -> Option<permissions::OciAction> {
        self.permission_resolver
            .max_action_from_groups(user_groups, repository)
    }

    pub fn mint_oci_token(
        &self,
        identity: &AuthIdentity,
        _service: &str,
        scopes: &str,
        namespace_epochs: Vec<NamespaceEpoch>,
    ) -> Result<String, LayerhouseError> {
        let now = chrono::Utc::now();
        let exp = (now + chrono::Duration::hours(1)).timestamp() as usize;

        let claims = token::TokenClaims {
            subject: identity.subject.as_str().to_string(),
            exp,
            aud: None,
            groups: Some(identity.groups.clone()),
            name: identity.display_name.clone(),
            preferred_username: identity.username.clone(),
            email: identity.email.clone(),
            scope: Some(scopes.to_string()),
            namespace_epochs,
            token_type: Some("oci_bearer".to_string()),
            iat: Some(now.timestamp() as usize),
            iss: Some("layerhouse".to_string()),
            additional_claims: serde_json::Value::Null,
        };

        let header = jsonwebtoken::Header::default();
        jsonwebtoken::encode(&header, &claims, &self.token_signing_key)
            .map_err(|e| LayerhouseError::Internal(format!("failed to mint token: {}", e)))
    }

    pub fn token_endpoint_url(&self) -> &str {
        &self.config.token_endpoint_url
    }

    pub fn redirect_uri(&self) -> &str {
        &self.config.redirect_uri
    }

    pub async fn authorization_endpoint(&self) -> String {
        self.discovery.read().await.authorization_endpoint.clone()
    }

    pub async fn token_exchange_endpoint(&self) -> String {
        self.discovery.read().await.token_endpoint.clone()
    }

    pub async fn end_session_endpoint(&self) -> Option<String> {
        self.discovery.read().await.end_session_endpoint.clone()
    }

    pub async fn jwks_metrics(&self) -> JwksMetrics {
        self.jwks_cache.read().await.metrics()
    }

    /// Build an `AuthService` offline, with the given permission mappings and
    /// no live OIDC discovery/JWKS. For tests that need a real `AuthService`
    /// instance (e.g. route-level permission enforcement) without network/S3.
    #[cfg(test)]
    pub(crate) fn for_test(permissions: Vec<crate::config::PermissionMapping>) -> Self {
        use base64::Engine as _;
        let mut config = tests::auth_config();
        config.permissions = permissions;
        let signing_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&config.token_signing_keys[0])
            .expect("valid signing key");
        let session_key_bytes = base64::engine::general_purpose::STANDARD
            .decode(&config.session_encryption_key)
            .expect("valid session key");
        let session_key: [u8; 32] = session_key_bytes.try_into().expect("32-byte session key");
        let permission_resolver = PermissionResolver::new(&config.permissions);
        Self {
            discovery: RwLock::new(OidcDiscovery {
                authorization_endpoint: String::new(),
                token_endpoint: String::new(),
                jwks_uri: String::new(),
                end_session_endpoint: None,
            }),
            jwks_cache: Arc::new(RwLock::new(JwksCache::empty())),
            jwks_s3_cache: None,
            permission_resolver,
            token_signing_key: jsonwebtoken::EncodingKey::from_secret(&signing_key_bytes),
            token_verification_key: jsonwebtoken::DecodingKey::from_secret(&signing_key_bytes),
            session_key,
            config,
        }
    }
}

#[async_trait]
impl Authorizer for AuthService {
    async fn authorize(
        &self,
        request: &AuthzRequest,
        namespaces: &dyn NamespaceStore,
    ) -> Result<AuthzDecision, LayerhouseError> {
        let resource_id = request.resource.as_ref().map(RepositoryResource::entity_id);
        tracing::trace!(
            repository = %request.repository,
            resource_id = resource_id.as_deref().unwrap_or("unresolved"),
            action = ?request.action,
            "compatibility authorizer evaluating request"
        );
        let identity = AuthIdentity {
            subject: Subject::new(request.actor.principal.local_id()),
            principal: request.actor.principal.clone(),
            username: request.actor.username.clone(),
            display_name: request.actor.display_name.clone(),
            email: request.actor.email.clone(),
            groups: request.actor.display_groups.clone(),
            group_ids: request.actor.group_ids.clone(),
            scopes: request.actor.scopes.clone(),
            namespace_epochs: request.actor.namespace_epochs.clone(),
            token_type: request.actor.token_type.clone(),
        };
        Ok(self
            .authorize_repository(&identity, &request.repository, request.action, namespaces)
            .await?
            .decision)
    }
}

pub(crate) struct CookieFlags {
    pub secure: bool,
    pub same_site: &'static str,
}

impl CookieFlags {
    /// Returns the attribute portion of a Set-Cookie header:
    /// "HttpOnly; SameSite=Lax" or "HttpOnly; Secure; SameSite=Lax" etc.
    pub(crate) fn attributes(&self) -> String {
        let mut parts: Vec<&str> = vec!["HttpOnly"];
        if self.secure {
            parts.push("Secure");
        }
        parts.push(self.same_site);
        parts.join("; ")
    }
}

/// Returns cookie flags appropriate for the request's security context.
///
/// - `Disabled`: `SameSite=Lax` without `Secure` (for localhost HTTP dev)
/// - `Enabled`: `Secure; SameSite=Lax` (forced HTTPS).
/// - `Auto`: checks `X-Forwarded-Proto` header first, falls back to
///   `server_tls_enabled`. HTTPS → `Secure; SameSite=Lax`; HTTP → `SameSite=Lax`.
pub(crate) fn cookie_secure_flag(
    headers: &HeaderMap,
    cookie_secure_mode: &CookieSecureMode,
    server_tls_enabled: bool,
) -> CookieFlags {
    match cookie_secure_mode {
        CookieSecureMode::Disabled => {
            return CookieFlags {
                secure: false,
                same_site: "SameSite=Lax",
            };
        }
        CookieSecureMode::Enabled => {
            return CookieFlags {
                secure: true,
                same_site: "SameSite=Lax",
            };
        }
        CookieSecureMode::Auto => {}
    }
    let https = headers
        .get("X-Forwarded-Proto")
        .and_then(|v| v.to_str().ok())
        .map(|p| p.eq_ignore_ascii_case("https"))
        .unwrap_or(false)
        || server_tls_enabled;
    if https {
        CookieFlags {
            secure: true,
            same_site: "SameSite=Lax",
        }
    } else {
        CookieFlags {
            secure: false,
            same_site: "SameSite=Lax",
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use base64::Engine;
    use tokio::sync::RwLock;

    use super::{AuthService, CachedJwksDocument, JwksCache, jwks};
    use crate::auth::identity::Subject;
    use crate::auth::permissions::{self, OciAction};
    use crate::auth::principal::{PrincipalKind, ProviderQualifiedId};
    use crate::auth::token::{AuthIdentity, TokenType};
    use crate::config::{AuthConfig, PermissionMapping};
    use crate::store::metadata::typed_id::OrgId;
    use crate::store::metadata::{
        InMemoryMetadataStore, NamespaceEpoch, NamespaceGrant, NamespaceGrantGrantee,
        NamespaceStore, Owner, ReleaseReason,
    };

    pub(super) fn auth_config() -> AuthConfig {
        AuthConfig {
            provider_name: "test".to_string(),
            issuer_url: "https://idp.example.test/oauth2/openid/layerhouse".to_string(),
            issuer_internal_url: None,
            issuer_internal_urls: Vec::new(),
            jwks_urls: Vec::new(),
            client_id: "layerhouse".to_string(),
            client_secret: "secret".to_string(),
            token_endpoint_url: "https://registry.example.test/v2/token".to_string(),
            redirect_uri: "https://registry.example.test/oauth2/callback".to_string(),
            tls_insecure_skip_verify: false,
            jwks_refresh_seconds: 300,
            jwks_cache_s3_key: "auth/jwks/last-good.json".to_string(),
            jwks_max_stale_seconds: 24 * 60 * 60,
            token_signing_keys: vec![base64::engine::general_purpose::STANDARD.encode(b"signing")],
            session_encryption_key: base64::engine::general_purpose::STANDARD.encode([7u8; 32]),
            permissions: vec![PermissionMapping {
                name: "admin".to_string(),
                groups: vec!["test:group:550e8400-e29b-41d4-a716-446655440000".to_string()],
                scopes: vec!["repository:*:*".to_string()],
            }],
            cookie_secure_mode: super::CookieSecureMode::Auto,
            group_claim: "groups".to_string(),
            login_scopes: "openid profile email groups".to_string(),
            access_token_audience: None,
        }
    }

    fn discovery_doc() -> serde_json::Value {
        serde_json::json!({
            "authorization_endpoint": "https://idp.example.test/oauth2/authorize",
            "token_endpoint": "https://idp.example.test/oauth2/token",
            "jwks_uri": "https://idp.example.test/oauth2/openid/layerhouse/public_key.jwk",
            "end_session_endpoint": "https://idp.example.test/oauth2/logout"
        })
    }

    fn cached_doc(fetched_at_unix: u64) -> CachedJwksDocument {
        CachedJwksDocument::new(
            "https://idp.example.test/oauth2/openid/layerhouse".to_string(),
            "https://idp.internal:8443/oauth2/openid/layerhouse".to_string(),
            discovery_doc(),
            serde_json::json!({"keys":[]}),
            fetched_at_unix,
        )
    }

    #[tokio::test]
    async fn cached_jwks_startup_accepts_last_good_material_within_window() {
        let config = auth_config();
        let cache = Arc::new(RwLock::new(JwksCache::empty()));
        let document = cached_doc(jwks::now_unix().saturating_sub(60));

        let discovery = AuthService::install_cached_document(&cache, &config, &document)
            .await
            .expect("fresh cached material should be accepted");

        assert_eq!(
            discovery.jwks_uri,
            "https://idp.internal:8443/oauth2/openid/layerhouse/public_key.jwk"
        );
        let metrics = cache.read().await.metrics();
        assert!(metrics.stale_mode);
        assert_eq!(
            metrics.endpoint.as_deref(),
            Some("s3:auth/jwks/last-good.json")
        );
    }

    #[tokio::test]
    async fn cached_jwks_startup_rejects_expired_material() {
        let config = auth_config();
        let cache = Arc::new(RwLock::new(JwksCache::empty()));
        let document = cached_doc(jwks::now_unix().saturating_sub(25 * 60 * 60));

        let err = AuthService::install_cached_document(&cache, &config, &document)
            .await
            .expect_err("expired cached material should be rejected");
        assert!(
            err.to_string()
                .contains("exceeding configured stale window")
        );
    }

    #[tokio::test]
    async fn cached_jwks_startup_rejects_wrong_issuer() {
        let config = auth_config();
        let cache = Arc::new(RwLock::new(JwksCache::empty()));
        let mut document = cached_doc(jwks::now_unix());
        document.issuer_url = "https://other.example.test".to_string();

        let err = AuthService::install_cached_document(&cache, &config, &document)
            .await
            .expect_err("wrong issuer should be rejected");
        assert!(err.to_string().contains("does not match configured issuer"));
    }

    fn identity(
        subject: &str,
        token_type: TokenType,
        groups: &[&str],
        scopes: &[&str],
    ) -> AuthIdentity {
        AuthIdentity::for_test(subject, token_type, groups, scopes)
    }

    fn user_id(subject: &str) -> ProviderQualifiedId {
        ProviderQualifiedId::new("test", PrincipalKind::User, subject).unwrap()
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

    #[tokio::test]
    async fn write_owner_implicit_grant_and_non_owner_denied() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-alice"))).await;

        let alice = identity("subject-alice", TokenType::OidcAccess, &[], &[]);
        auth.check_permission(&alice, "acme/app", OciAction::Create, &store)
            .await
            .expect("owner gets implicit write grant");

        let bob = identity("subject-bob", TokenType::OidcAccess, &[], &[]);
        auth.check_permission(&bob, "acme/app", OciAction::Create, &store)
            .await
            .expect_err("non-owner without RBAC grant is denied");
    }

    #[tokio::test]
    async fn check_permission_returns_authorized_namespace_epoch() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-alice"))).await;

        let alice = identity("subject-alice", TokenType::OidcAccess, &[], &[]);
        let first_access = auth
            .check_permission(&alice, "acme/app", OciAction::Create, &store)
            .await
            .expect("owner gets first-generation access");
        assert_eq!(
            first_access.expected_namespace,
            Some(NamespaceEpoch::new("acme", 1))
        );

        store
            .release_namespace(
                "acme",
                Subject::new("subject-alice"),
                ReleaseReason::OwnerDeleted,
                101,
            )
            .await
            .expect("owner can release empty namespace");
        claim(&store, "acme", Owner::User(Subject::new("subject-bob"))).await;

        let bob = identity("subject-bob", TokenType::OidcAccess, &[], &[]);
        let second_access = auth
            .check_permission(&bob, "acme/app", OciAction::Create, &store)
            .await
            .expect("new owner gets second-generation access");
        assert_eq!(
            second_access.expected_namespace,
            Some(NamespaceEpoch::new("acme", 2))
        );
        assert_ne!(
            first_access.expected_namespace,
            second_access.expected_namespace
        );
    }

    #[tokio::test]
    async fn scoped_token_epoch_must_match_reclaimed_namespace() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-owner"))).await;

        let mut old_pat = identity(
            "subject-owner",
            TokenType::PersonalAccess,
            &[],
            &["repository:acme/app:*"],
        );
        old_pat.namespace_epochs = vec![NamespaceEpoch::new("acme", 1)];

        auth.check_permission(&old_pat, "acme/app", OciAction::Create, &store)
            .await
            .expect("epoch-bound PAT works before reclaim");

        store
            .release_namespace(
                "acme",
                Subject::new("subject-owner"),
                ReleaseReason::OwnerDeleted,
                101,
            )
            .await
            .expect("owner can release empty namespace");
        claim(&store, "acme", Owner::User(Subject::new("subject-owner"))).await;

        auth.check_permission(&old_pat, "acme/app", OciAction::Create, &store)
            .await
            .expect_err("stale PAT epoch cannot authorize reclaimed namespace");
        auth.max_grantable_action(&old_pat, "acme/app", &store)
            .await
            .expect_err("stale PAT epoch cannot appear grantable after reclaim");

        let mut new_pat = identity(
            "subject-owner",
            TokenType::PersonalAccess,
            &[],
            &["repository:acme/app:*"],
        );
        new_pat.namespace_epochs = vec![NamespaceEpoch::new("acme", 2)];
        auth.check_permission(&new_pat, "acme/app", OciAction::Create, &store)
            .await
            .expect("current PAT epoch can authorize reclaimed namespace");
    }

    #[tokio::test]
    async fn write_to_unclaimed_handle_denied_even_with_rbac_grant() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();

        // PAT carries a matching scope, but the handle is never claimed.
        let pat = identity(
            "subject-x",
            TokenType::PersonalAccess,
            &[],
            &["repository:acme/*:*"],
        );
        auth.check_permission(&pat, "acme/app", OciAction::Create, &store)
            .await
            .expect_err("writes to an unclaimed handle are denied up front");
    }

    #[tokio::test]
    async fn delegated_rbac_grant_authorizes_non_owner_write() {
        let auth = AuthService::for_test(vec![PermissionMapping {
            name: "ci".to_string(),
            groups: vec!["test:group:550e8400-e29b-41d4-a716-446655440002".to_string()],
            scopes: vec!["repository:acme/*:create".to_string()],
        }]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-owner"))).await;

        let ci = identity(
            "subject-ci",
            TokenType::OidcAccess,
            &["550e8400-e29b-41d4-a716-446655440002"],
            &[],
        );
        auth.check_permission(&ci, "acme/app", OciAction::Create, &store)
            .await
            .expect("delegated group grant authorizes the write");
    }

    #[tokio::test]
    async fn grantable_action_uses_stable_group_ids() {
        let auth = AuthService::for_test(vec![PermissionMapping {
            name: "ci".to_string(),
            groups: vec!["test:group:550e8400-e29b-41d4-a716-446655440002".to_string()],
            scopes: vec!["repository:acme/*:create".to_string()],
        }]);
        let store = InMemoryMetadataStore::default();
        let ci = identity(
            "subject-ci",
            TokenType::OidcAccess,
            &["550e8400-e29b-41d4-a716-446655440002"],
            &[],
        );

        let (action, source) = auth
            .max_grantable_action(&ci, "acme/app", &store)
            .await
            .expect("stable group ID grants are grantable");
        assert_eq!(action, OciAction::Create);
        assert_eq!(source, permissions::GrantSource::GroupGrant);
    }

    #[tokio::test]
    async fn grantable_action_ignores_display_group_mappings() {
        let auth = AuthService::for_test(vec![PermissionMapping {
            name: "admins".to_string(),
            groups: vec!["registry_admins".to_string()],
            scopes: vec!["repository:acme/*:create".to_string()],
        }]);
        let store = InMemoryMetadataStore::default();
        let admin = identity(
            "subject-admin",
            TokenType::OidcAccess,
            &["registry_admins"],
            &[],
        );

        auth.max_grantable_action(&admin, "acme/app", &store)
            .await
            .expect_err("display group labels must not authorize");
    }

    #[tokio::test]
    async fn namespace_group_grant_authorizes_ladder_up_to_action() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-owner"))).await;
        grant(
            &store,
            "acme",
            "grant-1",
            NamespaceGrantGrantee::Group {
                id: group_id("550e8400-e29b-41d4-a716-446655440001"),
            },
            OciAction::Create,
        )
        .await;

        let builder = identity(
            "subject-builder",
            TokenType::OidcAccess,
            &["550e8400-e29b-41d4-a716-446655440001"],
            &[],
        );
        auth.check_permission(&builder, "acme/app", OciAction::Pull, &store)
            .await
            .expect("create grant includes pull");
        auth.check_permission(&builder, "acme/app", OciAction::Create, &store)
            .await
            .expect("create grant includes create");
        auth.check_permission(&builder, "acme/app", OciAction::Update, &store)
            .await
            .expect_err("create grant does not include update");
    }

    #[tokio::test]
    async fn namespace_user_grant_survives_label_changes_by_subject() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-owner"))).await;
        grant(
            &store,
            "acme",
            "grant-1",
            NamespaceGrantGrantee::User {
                id: user_id("subject-alice"),
            },
            OciAction::Pull,
        )
        .await;

        let mut alice = identity("subject-alice", TokenType::OidcAccess, &[], &[]);
        alice.username = Some("renamed-alice".to_string());
        auth.check_permission(&alice, "acme/app", OciAction::Pull, &store)
            .await
            .expect("user grant keys on subject, not username");
        auth.check_permission(&alice, "acme/app", OciAction::Create, &store)
            .await
            .expect_err("pull-only user grant cannot create");
    }

    #[tokio::test]
    async fn namespace_public_grant_allows_pull_only() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-owner"))).await;
        grant(
            &store,
            "acme",
            "grant-public",
            NamespaceGrantGrantee::Public,
            OciAction::Pull,
        )
        .await;

        auth.check_public_pull("acme/app", &store)
            .await
            .expect("public grant allows anonymous pull");
        let bob = identity("subject-bob", TokenType::OidcAccess, &[], &[]);
        auth.check_permission(&bob, "acme/app", OciAction::Pull, &store)
            .await
            .expect("public grant also lets authenticated users pull");
        auth.check_permission(&bob, "acme/app", OciAction::Create, &store)
            .await
            .expect_err("public grant cannot write");
    }

    #[tokio::test]
    async fn reads_are_ungated_by_namespace_claim() {
        let auth = AuthService::for_test(vec![PermissionMapping {
            name: "readers".to_string(),
            groups: vec!["test:group:550e8400-e29b-41d4-a716-446655440003".to_string()],
            scopes: vec!["repository:acme/*:pull".to_string()],
        }]);
        let store = InMemoryMetadataStore::default();

        // No claim for "acme"; a Pull still resolves via RBAC.
        let reader = identity(
            "subject-r",
            TokenType::OidcAccess,
            &["550e8400-e29b-41d4-a716-446655440003"],
            &[],
        );
        auth.check_permission(&reader, "acme/app", OciAction::Pull, &store)
            .await
            .expect("pulls skip the namespace gate");
    }

    #[tokio::test]
    async fn admin_access_bypasses_namespace_gate() {
        let auth = AuthService::for_test(vec![PermissionMapping {
            name: "admin".to_string(),
            groups: vec!["test:group:550e8400-e29b-41d4-a716-446655440004".to_string()],
            scopes: vec!["repository:*:*".to_string()],
        }]);
        let store = InMemoryMetadataStore::default();

        let admin = identity(
            "subject-admin",
            TokenType::OidcAccess,
            &["550e8400-e29b-41d4-a716-446655440004"],
            &[],
        );
        auth.check_admin_access(&admin, &store)
            .await
            .expect("admin `*` grant authorizes regardless of claims");
    }

    #[tokio::test]
    async fn org_owned_handle_denies_actor_without_grant() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::Org(OrgId::generate())).await;

        // Org ownership grants nothing implicitly yet (no membership map), and
        // the actor has neither admin nor a delegated grant.
        let actor = identity("subject-y", TokenType::OidcAccess, &[], &[]);
        auth.check_permission(&actor, "acme/app", OciAction::Create, &store)
            .await
            .expect_err("org-owned handle denies a non-admin actor without a grant");
    }

    #[tokio::test]
    async fn released_handle_denies_writes_until_reclaim() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();
        claim(&store, "acme", Owner::User(Subject::new("subject-alice"))).await;
        store
            .release_namespace(
                "acme",
                Subject::new("subject-alice"),
                ReleaseReason::OwnerDeleted,
                200,
            )
            .await
            .expect("release should succeed");

        // The handle now has only a tombstone, no live claim. Even the prior
        // owner is gated until the handle is reclaimed.
        let alice = identity("subject-alice", TokenType::OidcAccess, &[], &[]);
        auth.check_permission(&alice, "acme/app", OciAction::Create, &store)
            .await
            .expect_err("a released handle denies writes until it is reclaimed");
    }

    // ── Personal-namespace boundary tests ─────────────────────────────

    #[tokio::test]
    async fn pat_cross_user_personal_namespace_denied() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();

        // Alice creates a PAT with a scope targeting Bob's personal namespace.
        let pat = identity(
            "subject-alice",
            TokenType::PersonalAccess,
            &[],
            &["repository:users/bob/app:*"],
        );
        let err = auth
            .check_permission(&pat, "users/bob/app", OciAction::Create, &store)
            .await
            .expect_err("cross-user personal namespace must be denied");
        assert!(err.to_string().contains("access denied"), "{err:?}");
    }

    #[tokio::test]
    async fn pat_own_personal_namespace_allowed() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();

        // Alice with her own personal namespace — auto-grant.
        let mut alice = identity("subject-alice", TokenType::PersonalAccess, &[], &[]);
        alice.username = Some("alice".to_string());
        auth.check_permission(&alice, "users/alice/app", OciAction::Create, &store)
            .await
            .expect("own personal namespace is allowed");
    }

    #[tokio::test]
    async fn oidc_cross_user_personal_namespace_denied_despite_rbac() {
        // Even with an RBAC grant matching `users/bob/*`, Alice cannot access
        // Bob's personal namespace via OIDC — personal namespaces are private.
        let auth = AuthService::for_test(vec![PermissionMapping {
            name: "cross-ns".to_string(),
            groups: vec!["ci".to_string()],
            scopes: vec!["repository:users/bob/*:create".to_string()],
        }]);
        let store = InMemoryMetadataStore::default();

        let alice = identity("subject-alice", TokenType::OidcAccess, &["ci"], &[]);
        let err = auth
            .check_permission(&alice, "users/bob/app", OciAction::Create, &store)
            .await
            .expect_err("cross-user personal namespace denied despite RBAC grant");
        assert!(err.to_string().contains("access denied"), "{err:?}");
    }

    #[tokio::test]
    async fn oci_bearer_cross_user_personal_namespace_denied() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();

        // OCI bearer token with scopes for another user's namespace.
        let bearer = identity(
            "subject-alice",
            TokenType::OciBearer,
            &[],
            &["repository:users/bob/app:*"],
        );
        let err = auth
            .check_permission(&bearer, "users/bob/app", OciAction::Create, &store)
            .await
            .expect_err("OCI bearer cross-user personal namespace must be denied");
        assert!(err.to_string().contains("access denied"), "{err:?}");
    }

    #[tokio::test]
    async fn cross_user_personal_namespace_pull_denied() {
        let auth = AuthService::for_test(vec![]);
        let store = InMemoryMetadataStore::default();

        // Pull to another user's namespace with a valid pull scope.
        // The cross-user guard applies to ALL actions (including Pull).
        let pat = identity(
            "subject-alice",
            TokenType::PersonalAccess,
            &[],
            &["repository:users/bob/app:pull"],
        );
        let err = auth
            .check_permission(&pat, "users/bob/app", OciAction::Pull, &store)
            .await
            .expect_err("pull to cross-user personal namespace is denied");
        assert!(err.to_string().contains("access denied"), "{err:?}");
    }
}
