use axum::extract::{Extension, State};
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Redirect, Response};
use axum::{Json, Router};
use serde::Serialize;
use std::sync::Arc;

use crate::auth::token::{AuthIdentity, TokenType};
use crate::error::OrbChrysaError;
use crate::routes::AppState;

#[derive(Debug, Serialize)]
pub struct SessionResponse {
    pub auth_enabled: bool,
    pub subject: Option<String>,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub groups: Vec<String>,
    pub scopes: Vec<String>,
    pub token_type: Option<String>,
}

pub fn routes<M: Send + Sync + 'static, B: Send + Sync + 'static>() -> Router<Arc<AppState<M, B>>> {
    Router::new()
        .route("/api/v1/session", axum::routing::get(get_session::<M, B>))
        .route(
            "/api/v1/session/logout",
            axum::routing::get(logout_session::<M, B>).post(logout_session::<M, B>),
        )
}

async fn get_session<M: Send + Sync + 'static, B: Send + Sync + 'static>(
    State(state): State<Arc<AppState<M, B>>>,
    identity: Option<Extension<AuthIdentity>>,
) -> Result<impl IntoResponse, OrbChrysaError> {
    if state.auth.is_none() {
        return Ok(Json(SessionResponse {
            auth_enabled: false,
            subject: None,
            username: None,
            display_name: None,
            email: None,
            groups: vec![],
            scopes: vec![],
            token_type: None,
        }));
    }

    let Some(Extension(identity)) = identity else {
        return Err(OrbChrysaError::Unauthorized {
            message: "authentication required".to_string(),
            realm: None,
            service: None,
            scope: None,
        });
    };

    Ok(Json(SessionResponse {
        auth_enabled: true,
        subject: Some(identity.subject),
        username: identity.username,
        display_name: identity.display_name,
        email: identity.email,
        groups: identity.groups,
        scopes: identity.scopes,
        token_type: Some(token_type_name(identity.token_type).to_string()),
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
        .and_then(|c| extract_cookie_value(c, "orb_chrysa_logout_hint"))
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

    let flags = crate::auth::cookie_secure_flag(
        &headers,
        &state.cookie_secure_mode,
        state.server_tls_enabled,
    );
    let had_end_session = end_session_url.is_some();
    let mut response = match end_session_url {
        Some(url) => Redirect::temporary(&url).into_response(),
        // When there is no OIDC end_session endpoint (or no logout hint),
        // set a logged-out marker to break the auto-re-auth loop.
        None => Redirect::temporary("/").into_response(),
    };
    // Clear both session cookies
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "orb_chrysa_session=; {}; Path=/; Max-Age=0",
            flags.attributes()
        ))
        .expect("valid clear-session header value"),
    );
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "orb_chrysa_logout_hint=; {}; Path=/api/v1/session/logout; Max-Age=0",
            flags.attributes()
        ))
        .expect("valid clear-logout-hint header value"),
    );
    // Set a short-lived marker so the middleware knows not to auto-redirect
    // to /oauth2/start (which would immediately re-auth via Kanidm SSO).
    if !had_end_session {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&format!(
                "orb_chrysa_logged_out=1; {}; Path=/; Max-Age=300",
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
        TokenType::KanidmAccess => "kanidm_access",
        TokenType::PersonalAccess => "personal_access",
        TokenType::OciBearer => "oci_bearer",
        TokenType::Session => "session",
    }
}

#[cfg(test)]
mod tests {
    use super::SessionResponse;

    #[test]
    fn session_response_uses_explicit_identity_fields() {
        let value = serde_json::to_value(SessionResponse {
            auth_enabled: true,
            subject: Some("subject-uuid".to_string()),
            username: Some("admin".to_string()),
            display_name: Some("Admin User".to_string()),
            email: Some("admin@orb-chrysa.local".to_string()),
            groups: vec!["registry_admins".to_string()],
            scopes: vec![],
            token_type: Some("kanidm_access".to_string()),
        })
        .expect("serialize session");

        assert!(value.get("user_id").is_none());
        assert_eq!(value["subject"], "subject-uuid");
        assert_eq!(value["username"], "admin");
        assert_eq!(value["display_name"], "Admin User");
        assert_eq!(value["email"], "admin@orb-chrysa.local");
    }

    #[test]
    fn auth_disabled_session_identity_fields_are_null() {
        let value = serde_json::to_value(SessionResponse {
            auth_enabled: false,
            subject: None,
            username: None,
            display_name: None,
            email: None,
            groups: vec![],
            scopes: vec![],
            token_type: None,
        })
        .expect("serialize session");

        assert!(value.get("user_id").is_none());
        assert!(value["subject"].is_null());
        assert!(value["username"].is_null());
        assert!(value["display_name"].is_null());
        assert!(value["email"].is_null());
    }
}
