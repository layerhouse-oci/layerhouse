use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use std::sync::Arc;

use crate::error::LayerhouseError;
use crate::routes::AppState;
use crate::store::blob::BlobStore;
use crate::store::metadata::{ManifestStore, MetadataStore, TokenStore};

use super::permissions::OciAction;
use super::session::DashboardSession;

fn clear_session_cookie_str(flags: &super::CookieFlags) -> String {
    format!(
        "layerhouse_session=; {}; Path=/; Max-Age=0",
        flags.attributes()
    )
}

pub async fn auth_middleware<M: MetadataStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();

    // Skip public paths
    if is_public_path(&path) {
        return next.run(req).await;
    }

    // Skip auth for OAuth2 error pages — the query param breaks the
    // redirect loop that would otherwise occur when state cookies are
    // missing or mismatched (e.g. Secure-cookie-on-HTTP scenarios).
    // Only dashboard paths (not /api/, /v2/, /raft/) are exempted —
    // OCI registry and admin routes still require auth.
    if has_oauth_error_query(&req) && is_dashboard_request_path(&path) {
        return next.run(req).await;
    }

    // After logout without OIDC end_session, the user has a logged-out
    // marker cookie so the middleware doesn't immediately re-auth them
    // via the still-active IdP SSO session.
    if has_logged_out_marker(&req) && is_dashboard_request_path(&path) {
        return next.run(req).await;
    }

    let Some(auth_service) = &state.auth else {
        return next.run(req).await;
    };

    let flags = super::cookie_secure_flag(
        req.headers(),
        &state.cookie_secure_mode,
        state.server_tls_enabled,
    );

    // Resolve the OCI action for /v2/ requests once, before authentication.
    // The action is identity-independent but a manifest PUT requires a
    // metadata lookup to tell Create (new tag) from Update (overwrite), so we
    // compute it here and reuse it for both the auth challenge and the
    // post-auth permission check — the challenge scope must name the exact
    // action the request needs.
    let oci_action = if path.starts_with("/v2/") {
        Some(resolve_oci_action(&state.core.metadata, &path, req.method()).await)
    } else {
        None
    };

    let credential = extract_credential(&req);
    let uses_session_cookie = matches!(credential, Some(RequestCredential::SessionCookies(_)));
    let identity = match authenticate_request(auth_service, &state.core.metadata, credential).await
    {
        Ok(Some(identity)) => identity,
        Ok(None) => return auth_required_response(auth_service, &req, oci_action),
        Err(e) if uses_session_cookie => {
            return session_cookie_auth_error_response(&req, e, &flags);
        }
        Err(e) => return e.into_response(),
    };

    if path.starts_with("/v2/") {
        let repository = extract_repository_from_path(&path);
        let action = oci_action.unwrap_or(OciAction::Pull);

        if let Err(e) = auth_service
            .check_permission(&identity, &repository, action, &state.core.metadata)
            .await
        {
            return e.into_response();
        }
    }

    if path.starts_with("/api/v1/admin/")
        && let Err(e) = auth_service
            .check_admin_access(&identity, &state.core.metadata)
            .await
    {
        return e.into_response();
    }

    // Attach identity to request extensions for downstream handlers
    let mut req = req;
    req.extensions_mut().insert(identity);
    next.run(req).await
}

fn is_public_path(path: &str) -> bool {
    path == "/healthz"
        || path == "/readyz"
        || path == "/metrics"
        || path == "/v2/"
        || path == "/v2/token"
        || path == "/favicon.svg"
        || path == "/api/v1/session/logout"
        || path.starts_with("/assets/")
        || path.starts_with("/brand/")
        || path.starts_with("/oauth2/")
}

fn extract_bearer_token(req: &Request<Body>) -> Option<&str> {
    req.headers()
        .get(header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
}

enum RequestCredential {
    Bearer(String),
    SessionCookies(Vec<String>),
}

fn extract_credential(req: &Request<Body>) -> Option<RequestCredential> {
    if let Some(token) = extract_bearer_token(req) {
        return Some(RequestCredential::Bearer(token.to_string()));
    }
    let session_cookies: Vec<String> = extract_cookies(req, "layerhouse_session")
        .into_iter()
        .map(ToString::to_string)
        .collect();
    (!session_cookies.is_empty()).then_some(RequestCredential::SessionCookies(session_cookies))
}

async fn authenticate_request<M: TokenStore>(
    auth: &super::AuthService,
    metadata: &M,
    credential: Option<RequestCredential>,
) -> Result<Option<super::token::AuthIdentity>, LayerhouseError> {
    let Some(credential) = credential else {
        return Ok(None);
    };

    match credential {
        RequestCredential::Bearer(token) => {
            auth.validate_token::<M>(&token, metadata).await.map(Some)
        }
        RequestCredential::SessionCookies(cookie_values) => {
            authenticate_session_cookies(&cookie_values, auth.session_key()).map(Some)
        }
    }
}

fn authenticate_session_cookies(
    cookie_values: &[String],
    key: &[u8; 32],
) -> Result<super::token::AuthIdentity, LayerhouseError> {
    let now = chrono::Utc::now().timestamp() as u64;
    let mut last_error_message = "invalid session";

    for cookie_value in cookie_values {
        let Ok(session) = DashboardSession::decrypt(cookie_value, key) else {
            last_error_message = "invalid session";
            continue;
        };

        if now >= session.expires_at {
            last_error_message = "session expired";
            continue;
        }

        // Build identity directly from the encrypted session — no per-request
        // JWKS validation. The tokens were verified once at login and the
        // encrypted cookie is trusted for the session lifetime (max 1 hour).
        return Ok(super::token::AuthIdentity {
            subject: super::identity::Subject::new(session.subject),
            username: session.username,
            display_name: session.display_name,
            email: session.email,
            groups: session.groups,
            scopes: vec![],
            token_type: super::token::TokenType::Session,
        });
    }

    Err(LayerhouseError::Unauthorized {
        message: last_error_message.to_string(),
        realm: None,
        service: None,
        scope: None,
    })
}

fn extract_cookies<'a>(req: &'a Request<Body>, name: &str) -> Vec<&'a str> {
    let mut values = Vec::new();
    for cookie in req
        .headers()
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok())
    {
        for part in cookie.split(';') {
            let Some((key, value)) = part.trim().split_once('=') else {
                continue;
            };
            if key == name {
                values.push(value);
            }
        }
    }
    values
}

fn auth_required_response(
    auth: &super::AuthService,
    req: &Request<Body>,
    oci_action: Option<OciAction>,
) -> Response {
    let path = req.uri().path();
    if is_dashboard_request_path(path) {
        let cookie_header_count = req.headers().get_all(header::COOKIE).iter().count();
        tracing::info!(
            path = %path,
            cookie_header_count,
            "dashboard request missing auth credential; redirecting to oauth2 start"
        );
        return Redirect::temporary("/oauth2/start").into_response();
    }

    // Only emit OCI WWW-Authenticate challenges with scope for /v2/ paths.
    // Non-/v2/ paths (API, dashboard) get a plain 401 without scope.
    if !path.starts_with("/v2/") {
        return LayerhouseError::Unauthorized {
            message: "authentication required".to_string(),
            realm: None,
            service: None,
            scope: None,
        }
        .into_response();
    }

    let repository = extract_repository_from_path(path);

    // Use the request Host header as the OCI service name, per the
    // Distribution spec. Deriving it from the first path segment (the
    // old behaviour) broke token validation for namespaced repos like
    // /v2/qa/auth-test/alpine/... where "qa" is not a service name.
    let service = req
        .headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("registry");

    // Derive scope from the resolved OCI action instead of hardcoding `*`.
    // Docker follows the challenge and requests a token with the challenged
    // scope, so the scope must name the exact action the request needs: a
    // brand-new tag is challenged `create` (a create-only PAT suffices), an
    // overwrite is challenged `update`.
    let scope_action = oci_action.unwrap_or(OciAction::Pull).scope_token();

    let scope = if repository.is_empty() {
        // e.g. /v2/_catalog — don't emit a broken scope
        None
    } else {
        Some(format!("repository:{}:{}", repository, scope_action))
    };

    LayerhouseError::Unauthorized {
        message: "authentication required".to_string(),
        realm: Some(auth.token_endpoint_url().to_string()),
        service: Some(service.to_string()),
        scope,
    }
    .into_response()
}

fn session_cookie_auth_error_response(
    req: &Request<Body>,
    error: LayerhouseError,
    flags: &super::CookieFlags,
) -> Response {
    let path = req.uri().path();
    let session_cookie_count = extract_cookies(req, "layerhouse_session").len();
    if is_dashboard_request_path(path) {
        tracing::warn!(
            path = %path,
            session_cookie_count,
            error = %error,
            "dashboard session cookie rejected; redirecting to oauth2 start"
        );
    } else {
        tracing::warn!(
            path = %path,
            session_cookie_count,
            error = %error,
            "session cookie rejected"
        );
    }

    let mut response = if is_dashboard_request_path(req.uri().path()) {
        Redirect::temporary("/oauth2/start").into_response()
    } else {
        error.into_response()
    };
    expire_session_cookie(&mut response, flags);
    response
}

fn has_oauth_error_query(req: &Request<Body>) -> bool {
    req.uri()
        .query()
        .map(|q| q.contains("oauth_error="))
        .unwrap_or(false)
}

fn has_logged_out_marker(req: &Request<Body>) -> bool {
    req.headers()
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .map(|c| c.contains("layerhouse_logged_out=1"))
        .unwrap_or(false)
}

fn is_dashboard_request_path(path: &str) -> bool {
    !path.starts_with("/api/") && !path.starts_with("/v2/") && !path.starts_with("/raft/")
}

fn expire_session_cookie(response: &mut Response, flags: &super::CookieFlags) {
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&clear_session_cookie_str(flags))
            .expect("valid clear-session header value"),
    );
}

fn extract_repository_from_path(path: &str) -> String {
    path.strip_prefix("/v2/")
        .and_then(|rest| {
            let parts: Vec<&str> = rest.split('/').collect();
            parts
                .iter()
                .position(|part| {
                    matches!(
                        *part,
                        "blobs" | "manifests" | "tags" | "referrers" | "uploads"
                    )
                })
                .filter(|index| *index > 0)
                .map(|index| parts[..index].join("/"))
        })
        .unwrap_or_default()
}

/// Resolve the OCI action a `/v2/` request needs, performing the manifest
/// existence lookup that distinguishes Create from Update.
///
/// The HTTP method alone yields the base action (`OciAction::from_method`):
/// reads → Pull, DELETE → Delete, writes → Create. The one case the method
/// cannot decide is a manifest PUT: pushing a brand-new tag is `Create`, while
/// overwriting an existing one is `Update`. We resolve that by looking the
/// manifest up in the Raft-local metadata store (in-memory, no S3) — present
/// means Update, absent means Create. Blob and upload PUTs stay `Create`.
async fn resolve_oci_action<M: ManifestStore>(
    metadata: &M,
    path: &str,
    method: &http::Method,
) -> OciAction {
    let base = OciAction::from_method(method);
    if base != OciAction::Create {
        return base;
    }
    let Some((name, reference)) = manifest_put_target(path) else {
        // Not a manifest PUT (blob/upload write) — stays Create.
        return OciAction::Create;
    };
    match metadata.get_manifest(&name, &reference).await {
        Ok(Some(_)) => OciAction::Update,
        Ok(None) => OciAction::Create,
        // Lookup error: fail closed to the higher tier. We cannot prove the tag
        // is absent, so challenge/charge Update rather than silently
        // downgrading to Create. The write-time re-check in `put_manifest`
        // enforces the same boundary against the committed state.
        Err(_) => OciAction::Update,
    }
}

/// Extract `(name, reference)` from a manifest PUT path
/// (`/v2/<name>/manifests/<reference>`), or `None` for any other path.
fn manifest_put_target(path: &str) -> Option<(String, String)> {
    let rest = path.strip_prefix("/v2/")?;
    let (name, reference) = rest.rsplit_once("/manifests/")?;
    if name.is_empty() || reference.is_empty() || reference.contains('/') {
        return None;
    }
    Some((name.to_string(), reference.to_string()))
}

#[cfg(test)]
mod tests {
    use super::{
        RequestCredential, authenticate_session_cookies, extract_cookies, extract_credential,
        extract_repository_from_path, is_public_path, manifest_put_target, resolve_oci_action,
        session_cookie_auth_error_response,
    };
    use crate::auth::CookieFlags;
    use crate::auth::permissions::OciAction;
    use crate::auth::session::DashboardSession;
    use crate::auth::token::TokenType;
    use crate::error::LayerhouseError;
    use crate::store::metadata::{InMemoryMetadataStore, ManifestEntry, ManifestStore};
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};

    fn invalid_session_error() -> LayerhouseError {
        LayerhouseError::Unauthorized {
            message: "invalid session".to_string(),
            realm: None,
            service: None,
            scope: None,
        }
    }

    fn encrypted_session(expires_at: u64) -> String {
        DashboardSession {
            subject: "user-1".to_string(),
            username: Some("user".to_string()),
            display_name: None,
            email: None,
            groups: vec!["layerhouse_admins@example.com".to_string()],
            expires_at,
        }
        .encrypt(&[42u8; 32])
        .expect("session encrypts")
    }

    #[test]
    fn extracts_duplicate_session_cookies_in_order() {
        let req = Request::builder()
            .uri("/")
            .header(
                header::COOKIE,
                "layerhouse_session=stale; other=1; layerhouse_session=fresh",
            )
            .body(Body::empty())
            .expect("request");

        assert_eq!(
            extract_cookies(&req, "layerhouse_session"),
            vec!["stale", "fresh"]
        );

        match extract_credential(&req) {
            Some(RequestCredential::SessionCookies(values)) => {
                assert_eq!(values, vec!["stale".to_string(), "fresh".to_string()]);
            }
            _ => panic!("expected session cookies credential"),
        }
    }

    #[test]
    fn authenticates_later_valid_session_cookie_when_stale_cookie_comes_first() {
        let valid = encrypted_session(chrono::Utc::now().timestamp() as u64 + 60);
        let identity = authenticate_session_cookies(&["stale".to_string(), valid], &[42u8; 32])
            .expect("later valid cookie should authenticate");

        assert_eq!(identity.subject, "user-1");
        assert_eq!(identity.token_type, TokenType::Session);
        assert_eq!(
            identity.groups,
            vec!["layerhouse_admins@example.com".to_string()]
        );
    }

    #[test]
    fn rejects_session_cookies_when_none_are_valid() {
        let expired = encrypted_session(1);
        let err = authenticate_session_cookies(&["stale".to_string(), expired], &[42u8; 32])
            .expect_err("all invalid or expired cookies should fail");

        assert!(matches!(
            err,
            LayerhouseError::Unauthorized { message, .. } if message == "session expired"
        ));
    }

    #[test]
    fn extracts_multi_segment_repository_names() {
        assert_eq!(
            extract_repository_from_path("/v2/qa/auth-test/alpine/blobs/uploads/"),
            "qa/auth-test/alpine"
        );
        assert_eq!(
            extract_repository_from_path("/v2/qa/auth-test/alpine/manifests/v1"),
            "qa/auth-test/alpine"
        );
        assert_eq!(
            extract_repository_from_path("/v2/qa/auth-test/alpine/tags/list"),
            "qa/auth-test/alpine"
        );
    }

    #[test]
    fn invalid_dashboard_session_redirects_and_clears_cookie() {
        let req = Request::builder()
            .uri("/")
            .body(Body::empty())
            .expect("request");

        let response = session_cookie_auth_error_response(
            &req,
            invalid_session_error(),
            &CookieFlags {
                secure: false,
                same_site: "SameSite=Lax",
            },
        );

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("/oauth2/start")
        );
        assert_eq!(
            response
                .headers()
                .get(header::SET_COOKIE)
                .and_then(|value| value.to_str().ok()),
            Some("layerhouse_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
        );
    }

    #[test]
    fn invalid_api_session_remains_unauthorized_and_clears_cookie() {
        let req = Request::builder()
            .uri("/api/v1/session")
            .body(Body::empty())
            .expect("request");

        let response = session_cookie_auth_error_response(
            &req,
            invalid_session_error(),
            &CookieFlags {
                secure: false,
                same_site: "SameSite=Lax",
            },
        );

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(header::SET_COOKIE)
                .and_then(|value| value.to_str().ok()),
            Some("layerhouse_session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0")
        );
    }

    #[test]
    fn dashboard_static_assets_are_public() {
        assert!(is_public_path("/assets/index-abc123.js"));
        assert!(is_public_path("/brand/layerhouse-mark-dark.svg"));
        assert!(is_public_path("/favicon.svg"));
        assert!(is_public_path("/api/v1/session/logout"));
        assert!(!is_public_path("/"));
        assert!(!is_public_path("/api/v1/session"));
    }

    #[test]
    fn from_method_pull_for_get() {
        assert_eq!(OciAction::from_method(&http::Method::GET), OciAction::Pull);
        assert_eq!(OciAction::from_method(&http::Method::HEAD), OciAction::Pull);
    }

    #[test]
    fn from_method_create_for_post_put_patch() {
        // Writes default to Create; a manifest PUT overwrite is upgraded to
        // Update by resolve_oci_action after a metadata lookup.
        assert_eq!(
            OciAction::from_method(&http::Method::POST),
            OciAction::Create
        );
        assert_eq!(
            OciAction::from_method(&http::Method::PUT),
            OciAction::Create
        );
        assert_eq!(
            OciAction::from_method(&http::Method::PATCH),
            OciAction::Create
        );
    }

    #[test]
    fn from_method_delete_for_delete() {
        assert_eq!(
            OciAction::from_method(&http::Method::DELETE),
            OciAction::Delete
        );
    }

    #[test]
    fn scope_tokens_match_action_ladder() {
        assert_eq!(OciAction::Pull.scope_token(), "pull");
        assert_eq!(OciAction::Create.scope_token(), "create");
        assert_eq!(OciAction::Update.scope_token(), "update");
        assert_eq!(OciAction::Delete.scope_token(), "delete");
    }

    #[test]
    fn manifest_put_target_matches_only_manifest_paths() {
        assert_eq!(
            manifest_put_target("/v2/qa/auth-test/alpine/manifests/v1"),
            Some(("qa/auth-test/alpine".to_string(), "v1".to_string()))
        );
        // Blob and upload writes are not manifest PUTs.
        assert_eq!(
            manifest_put_target("/v2/qa/auth-test/alpine/blobs/uploads/"),
            None
        );
        assert_eq!(manifest_put_target("/v2/foo/manifests/"), None);
        // A reference containing a slash is not a valid manifest reference.
        assert_eq!(manifest_put_target("/v2/foo/manifests/a/b"), None);
        assert_eq!(manifest_put_target("/healthz"), None);
    }

    fn manifest_entry() -> ManifestEntry {
        let body = b"{}".to_vec();
        ManifestEntry {
            digest: crate::oci::digest::Digest::sha256(&body),
            content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            body,
            referenced_blobs: Vec::new(),
            subject: None,
            artifact_type: None,
            annotations: None,
            stored_size_bytes: 0,
            manifest_size_bytes: 2,
            created_at: 1,
            last_modified: 1,
            config_summary: None,
        }
    }

    // T2: the Create/Update boundary, both directions. A manifest PUT to a
    // brand-new tag resolves to Create; the same PUT once the tag exists
    // resolves to Update.
    #[tokio::test]
    async fn resolve_action_manifest_put_create_then_update() {
        let store = InMemoryMetadataStore::default();
        let path = "/v2/team-a/app/manifests/v1";

        // Tag does not exist yet → Create.
        assert_eq!(
            resolve_oci_action(&store, path, &http::Method::PUT).await,
            OciAction::Create
        );

        // Push the tag, then the same PUT is an overwrite → Update.
        store
            .put_manifest("team-a/app", "v1", manifest_entry())
            .await
            .expect("put manifest");
        assert_eq!(
            resolve_oci_action(&store, path, &http::Method::PUT).await,
            OciAction::Update
        );
    }

    #[tokio::test]
    async fn resolve_action_blob_and_upload_writes_stay_create() {
        let store = InMemoryMetadataStore::default();
        // Blob upload writes are never manifest PUTs, so they stay Create even
        // when a manifest with a colliding-looking reference exists.
        assert_eq!(
            resolve_oci_action(&store, "/v2/team-a/app/blobs/uploads/", &http::Method::POST).await,
            OciAction::Create
        );
        assert_eq!(
            resolve_oci_action(
                &store,
                "/v2/team-a/app/blobs/uploads/abc",
                &http::Method::PUT
            )
            .await,
            OciAction::Create
        );
    }

    #[tokio::test]
    async fn resolve_action_reads_and_deletes_ignore_manifest_lookup() {
        let store = InMemoryMetadataStore::default();
        assert_eq!(
            resolve_oci_action(&store, "/v2/team-a/app/manifests/v1", &http::Method::GET).await,
            OciAction::Pull
        );
        assert_eq!(
            resolve_oci_action(&store, "/v2/team-a/app/manifests/v1", &http::Method::HEAD).await,
            OciAction::Pull
        );
        assert_eq!(
            resolve_oci_action(&store, "/v2/team-a/app/manifests/v1", &http::Method::DELETE).await,
            OciAction::Delete
        );
    }

    #[test]
    fn empty_repository_for_catalog_path() {
        // /v2/_catalog has no repository name
        assert_eq!(extract_repository_from_path("/v2/_catalog"), "");
    }

    #[test]
    fn empty_repository_for_v2_root() {
        assert_eq!(extract_repository_from_path("/v2/"), "");
    }
}
