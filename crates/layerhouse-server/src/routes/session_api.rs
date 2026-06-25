use axum::extract::{Extension, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Json, Router};
use serde::Serialize;
use std::sync::Arc;

use crate::auth::token::{AuthIdentity, TokenType};
use crate::error::LayerhouseError;
use crate::routes::AppState;
use crate::store::metadata::AuthorizationStore;

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub auth_enabled: bool,
    pub subject: Option<String>,
    pub principal: Option<String>,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub group_ids: Vec<String>,
    pub scopes: Vec<String>,
    pub token_type: Option<String>,
    pub is_admin: bool,
}

pub fn routes<M: AuthorizationStore, B: Send + Sync + 'static>() -> Router<Arc<AppState<M, B>>> {
    Router::new()
        .route("/api/v1/session", axum::routing::get(get_session::<M, B>))
        .route(
            "/api/v1/session/logout",
            axum::routing::get(logout_session::<M, B>).post(logout_session::<M, B>),
        )
}

async fn get_session<M: AuthorizationStore, B: Send + Sync + 'static>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<impl IntoResponse, LayerhouseError> {
    if state.auth.is_none() {
        return Ok(Json(SessionResponse {
            auth_enabled: false,
            subject: None,
            principal: None,
            username: None,
            display_name: None,
            email: None,
            groups: vec![],
            group_ids: vec![],
            scopes: vec![],
            token_type: None,
            is_admin: true,
        }));
    }

    // Session discovery: auth is enabled but the caller has no valid identity.
    // Return 200 with the logged-out state so the dashboard can render the
    // "Sign in with OIDC" affordance instead of treating this as a hard error.
    let Some(Extension(identity)) = identity else {
        return Ok(Json(SessionResponse {
            auth_enabled: true,
            subject: None,
            principal: None,
            username: None,
            display_name: None,
            email: None,
            groups: vec![],
            group_ids: vec![],
            scopes: vec![],
            token_type: None,
            is_admin: false,
        }));
    };

    let is_admin = if let Some(auth) = state.auth.as_ref() {
        auth.check_admin_access(&identity, &state.core.metadata)
            .await
            .is_ok()
    } else {
        false
    };

    Ok(Json(SessionResponse {
        auth_enabled: true,
        subject: Some(identity.subject.into_string()),
        principal: Some(identity.principal.to_string()),
        username: identity.username,
        display_name: identity.display_name,
        email: identity.email,
        groups: identity.groups,
        group_ids: identity.group_ids.iter().map(ToString::to_string).collect(),
        scopes: identity.scopes,
        token_type: Some(token_type_name(identity.token_type).to_string()),
        is_admin,
    }))
}

async fn logout_session<M: Send + Sync + 'static, B: Send + Sync + 'static>(
    State(state): State<Arc<AppState<M, B>>>,
    headers: HeaderMap,
) -> Response {
    // Read the logout hint cookie (path-scoped, only sent to this endpoint).
    let logout_hint = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|c| extract_cookie_value(c, "layerhouse_logout_hint"))
        .map(|s| s.to_string());

    let end_session_url = match (&state.auth, logout_hint) {
        (Some(auth), Some(id_token)) => auth.end_session_endpoint().await.map(|url| {
            format!(
                "{}?id_token_hint={}&post_logout_redirect_uri=/",
                url, id_token
            )
        }),
        _ => None,
    };
    let configured_logout_url = end_session_url
        .is_none()
        .then(|| {
            state
                .auth
                .as_ref()
                .and_then(|auth| auth.logout_url().map(str::to_owned))
        })
        .flatten();

    let flags = crate::auth::cookie_secure_flag(
        &headers,
        &state.cookie_secure_mode,
        state.server_tls_enabled,
    );
    let had_idp_logout = end_session_url.is_some() || configured_logout_url.is_some();
    let mut response = match end_session_url.or(configured_logout_url) {
        Some(url) => Redirect::temporary(&url).into_response(),
        // When there is no OIDC end_session endpoint (or no logout hint),
        // set a logged-out marker to break the auto-re-auth loop.
        None => Redirect::temporary("/").into_response(),
    };
    // Clear both session cookies
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "layerhouse_session=; {}; Path=/; Max-Age=0",
            flags.attributes()
        ))
        .expect("valid clear-session header value"),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "layerhouse_logout_hint=; {}; Path=/api/v1/session/logout; Max-Age=0",
            flags.attributes()
        ))
        .expect("valid clear-logout-hint header value"),
    );
    // Set a short-lived marker so the middleware knows not to auto-redirect
    // to /oauth2/start (which would immediately re-auth via IdP SSO).
    if !had_idp_logout {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&format!(
                "layerhouse_logged_out=1; {}; Path=/; Max-Age=300",
                flags.attributes()
            ))
            .expect("valid logged-out marker value"),
        );
    }
    response
}

fn extract_cookie_value<'a>(cookie: &'a str, name: &str) -> Option<&'a str> {
    cookie.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name).then_some(value)
    })
}

fn token_type_name(token_type: TokenType) -> &'static str {
    match token_type {
        TokenType::OidcAccess => "oidc_access",
        TokenType::PersonalAccess => "personal_access",
        TokenType::OciBearer => "oci_bearer",
        TokenType::Session => "session",
    }
}

#[cfg(test)]
mod tests {
    use super::{SessionResponse, logout_session};
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode, header};
    use std::sync::Arc;

    use crate::auth::AuthService;
    use crate::config::CookieSecureMode;
    use crate::routes::{AppState, RegistryCore};
    use crate::store::blob::InMemoryBlobStore;
    use crate::store::metadata::InMemoryMetadataStore;
    use crate::store::upload::UploadTracker;

    fn state_with_logout_url(
        logout_url: &str,
    ) -> Arc<AppState<InMemoryMetadataStore, InMemoryBlobStore>> {
        Arc::new(AppState {
            core: RegistryCore {
                metadata: InMemoryMetadataStore::default(),
                blobs: InMemoryBlobStore::default(),
                uploads: UploadTracker::default(),
                upload_semaphore: tokio::sync::Semaphore::new(8),
            },
            mirror: crate::mirror::MirrorManager::new(),
            gc_status: Arc::new(tokio::sync::RwLock::new(crate::gc::GcStatus::default())),
            raft: None,
            raft_tls: None,
            auth: Some(Arc::new(AuthService::for_test_logout_url(logout_url))),
            server_tls_enabled: false,
            cookie_secure_mode: CookieSecureMode::Disabled,
        })
    }

    #[test]
    fn session_response_uses_explicit_identity_fields() {
        let value = serde_json::to_value(SessionResponse {
            auth_enabled: true,
            subject: Some("subject-uuid".to_string()),
            principal: Some("test:user:subject-uuid".to_string()),
            username: Some("admin".to_string()),
            display_name: Some("Admin User".to_string()),
            email: Some("admin@layerhouse.local".to_string()),
            groups: vec!["registry_admins".to_string()],
            group_ids: vec!["test:group:550e8400-e29b-41d4-a716-446655440000".to_string()],
            scopes: vec![],
            token_type: Some("oidc_access".to_string()),
            is_admin: true,
        })
        .expect("serialize session");

        assert!(value.get("user_id").is_none());
        assert_eq!(value["subject"], "subject-uuid");
        assert_eq!(value["principal"], "test:user:subject-uuid");
        assert_eq!(value["username"], "admin");
        assert_eq!(value["display_name"], "Admin User");
        assert_eq!(value["email"], "admin@layerhouse.local");
        assert_eq!(
            value["group_ids"],
            serde_json::json!(["test:group:550e8400-e29b-41d4-a716-446655440000"])
        );
        assert_eq!(value["is_admin"], true);
    }

    #[test]
    fn auth_disabled_session_identity_fields_are_null() {
        let value = serde_json::to_value(SessionResponse {
            auth_enabled: false,
            subject: None,
            principal: None,
            username: None,
            display_name: None,
            email: None,
            groups: vec![],
            group_ids: vec![],
            scopes: vec![],
            token_type: None,
            is_admin: true,
        })
        .expect("serialize session");

        assert!(value.get("user_id").is_none());
        assert!(value["subject"].is_null());
        assert!(value["principal"].is_null());
        assert!(value["username"].is_null());
        assert!(value["display_name"].is_null());
        assert!(value["email"].is_null());
        assert_eq!(value["is_admin"], true);
    }

    #[test]
    fn logged_out_discovery_reports_auth_enabled_without_identity() {
        // The session endpoint doubles as a discovery probe: when auth is on
        // but the caller is unauthenticated, it must report auth_enabled with a
        // null subject so the dashboard can render the sign-in affordance.
        let value = serde_json::to_value(SessionResponse {
            auth_enabled: true,
            subject: None,
            principal: None,
            username: None,
            display_name: None,
            email: None,
            groups: vec![],
            group_ids: vec![],
            scopes: vec![],
            token_type: None,
            is_admin: false,
        })
        .expect("serialize session");

        assert_eq!(value["auth_enabled"], true);
        assert!(value["subject"].is_null());
        assert!(value["principal"].is_null());
        assert_eq!(value["is_admin"], false);
    }

    #[tokio::test]
    async fn logout_uses_configured_idp_logout_url_when_discovery_has_no_end_session() {
        let response = logout_session(
            State(state_with_logout_url("https://idp.example.test/ui/logout")),
            HeaderMap::new(),
        )
        .await;

        assert_eq!(response.status(), StatusCode::TEMPORARY_REDIRECT);
        assert_eq!(
            response
                .headers()
                .get(header::LOCATION)
                .and_then(|value| value.to_str().ok()),
            Some("https://idp.example.test/ui/logout")
        );

        let cookies = response
            .headers()
            .get_all(header::SET_COOKIE)
            .iter()
            .filter_map(|value| value.to_str().ok())
            .collect::<Vec<_>>();
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with("layerhouse_session=;"))
        );
        assert!(
            cookies
                .iter()
                .any(|cookie| cookie.starts_with("layerhouse_logout_hint=;"))
        );
        assert!(
            cookies
                .iter()
                .all(|cookie| !cookie.starts_with("layerhouse_logged_out=1"))
        );
    }
}
