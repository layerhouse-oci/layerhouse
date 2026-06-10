pub mod discovery;
pub mod jwks;
pub mod middleware;
pub mod oauth2;
pub mod permissions;
pub mod session;
pub mod token;
pub mod token_endpoint;

use std::sync::Arc;
use tokio::sync::RwLock;

use axum::http::HeaderMap;

use crate::config::{AuthConfig, CookieSecureMode, S3Config};
use crate::error::LayerhouseError;
use crate::store::metadata::TokenStore;

use self::discovery::OidcDiscovery;
use self::jwks::{CachedJwksDocument, JwksCache, JwksMetrics, JwksS3Cache};
use self::permissions::PermissionResolver;
use self::token::{AuthIdentity, TokenType};

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

impl AuthService {
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

        Ok(AuthIdentity {
            subject: pat.subject,
            username: pat.username,
            display_name: None,
            email: None,
            groups: vec![],
            scopes: pat.scopes,
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
        Ok(AuthIdentity {
            subject: claims.subject,
            username,
            display_name,
            email,
            groups: claims.groups.unwrap_or_default(),
            scopes: claims
                .scope
                .map(|s| s.split(' ').map(ToString::to_string).collect())
                .unwrap_or_default(),
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

        Ok(AuthIdentity {
            subject: claims.subject,
            username,
            display_name,
            email,
            groups: user_groups,
            scopes: vec![],
            token_type: TokenType::OidcAccess,
        })
    }

    pub fn check_permission(
        &self,
        identity: &AuthIdentity,
        repository: &str,
        action: permissions::OciAction,
    ) -> Result<(), LayerhouseError> {
        // Personal-namespace auto-grant: any authenticated user has the full
        // action ladder under `users/<their-username>/`. Keyed on
        // `identity.username`, which is now populated for PATs as well as OIDC
        // sessions (see `validate_pat`).
        if permissions::in_personal_namespace(identity.username.as_deref(), repository) {
            return Ok(());
        }

        // PATs and minted OCI bearer tokens carry explicit repository scopes.
        if matches!(
            identity.token_type,
            TokenType::PersonalAccess | TokenType::OciBearer
        ) {
            return self
                .permission_resolver
                .check_scopes(&identity.scopes, repository, action);
        }

        // OIDC tokens: map groups to permissions via config
        self.permission_resolver
            .check(&identity.groups, repository, action)
    }

    pub fn check_admin_access(&self, identity: &AuthIdentity) -> Result<(), LayerhouseError> {
        self.check_permission(identity, "*", permissions::OciAction::Delete)
    }

    pub fn mint_oci_token(
        &self,
        identity: &AuthIdentity,
        _service: &str,
        scopes: &str,
    ) -> Result<String, LayerhouseError> {
        let now = chrono::Utc::now();
        let exp = (now + chrono::Duration::hours(1)).timestamp() as usize;

        let claims = token::TokenClaims {
            subject: identity.subject.clone(),
            exp,
            aud: None,
            groups: Some(identity.groups.clone()),
            name: identity.display_name.clone(),
            preferred_username: identity.username.clone(),
            email: identity.email.clone(),
            scope: Some(scopes.to_string()),
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
    use crate::config::{AuthConfig, PermissionMapping};

    fn auth_config() -> AuthConfig {
        AuthConfig {
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
                groups: vec!["registry_admins".to_string()],
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
}
