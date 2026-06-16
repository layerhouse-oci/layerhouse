use axum::extract::Query;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine;
use rand::Rng;
use sha2::Digest;
use std::sync::Arc;

use crate::error::LayerhouseError;
use crate::routes::AppState;
use crate::store::metadata::{NamespaceStore, ObservedIdentity};

use super::identity::Subject;
use super::session::DashboardSession;

const OAUTH2_COOKIE: &str = "layerhouse_oauth2";
const OAUTH2_COOKIE_MAX_AGE_SECS: u64 = 600;
const OAUTH2_STATE_ERROR_LOCATION: &str = "/?oauth_error=state#/oauth2/error";
const OAUTH2_SESSION_ERROR_LOCATION: &str = "/?oauth_error=session#/oauth2/error";
const MAX_SET_COOKIE_HEADER_LEN: usize = 4096;

fn oauth2_cookie_clear_str(flags: &super::CookieFlags) -> String {
    format!(
        "layerhouse_oauth2=; {}; Path=/oauth2; Max-Age=0",
        flags.attributes()
    )
}

#[derive(serde::Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    #[serde(default, rename = "state")]
    pub _state: Option<String>,
}

pub async fn oauth2_start<M, B>(
    axum::extract::State(app_state): axum::extract::State<Arc<AppState<M, B>>>,
    headers: HeaderMap,
) -> Result<Response, LayerhouseError> {
    let auth = app_state
        .auth
        .as_ref()
        .ok_or_else(|| LayerhouseError::Internal("auth not configured".to_string()))?;

    let state = random_urlsafe(32);
    let code_verifier = random_urlsafe(32);
    let code_challenge = pkce_challenge(&code_verifier);

    let authorization_endpoint = auth.authorization_endpoint().await;
    // If the user explicitly logged out (layerhouse_logged_out marker),
    // request interactive re-authentication so the IdP doesn't silently
    // re-approve via the still-active SSO session.
    let require_login = headers
        .get(header::COOKIE)
        .and_then(|v| v.to_str().ok())
        .and_then(|c| extract_cookie(c, "layerhouse_logged_out"))
        .is_some();

    let mut params: Vec<String> = vec![
        format!("response_type=code"),
        format!("client_id={}", percent_encode(&auth.config.client_id)),
        format!("redirect_uri={}", percent_encode(auth.redirect_uri())),
        format!("scope={}", percent_encode(&auth.config.login_scopes)),
        format!("state={}", percent_encode(&state)),
        format!("code_challenge={}", percent_encode(&code_challenge)),
        "code_challenge_method=S256".to_string(),
    ];
    if require_login {
        params.push("prompt=login".to_string());
        params.push("max_age=0".to_string());
    }
    let auth_url = format!("{}?{}", authorization_endpoint, params.join("&"));

    let flags = super::cookie_secure_flag(
        &headers,
        &app_state.cookie_secure_mode,
        app_state.server_tls_enabled,
    );
    let mut response = Redirect::temporary(&auth_url).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{}={}.{}; {}; Path=/oauth2; Max-Age={}",
            OAUTH2_COOKIE,
            state,
            code_verifier,
            flags.attributes(),
            OAUTH2_COOKIE_MAX_AGE_SECS
        ))
        .map_err(|e| LayerhouseError::Internal(format!("oauth2 cookie failed: {}", e)))?,
    );
    // Clear the logged-out marker so subsequent logins use silent SSO again.
    if require_login {
        response.headers_mut().append(
            header::SET_COOKIE,
            HeaderValue::from_str(&format!(
                "layerhouse_logged_out=; {}; Path=/; Max-Age=0",
                flags.attributes()
            ))
            .expect("valid clear-logged-out marker value"),
        );
    }
    Ok(response)
}

pub async fn oauth2_callback<M, B>(
    axum::extract::State(state): axum::extract::State<Arc<AppState<M, B>>>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, LayerhouseError>
where
    M: NamespaceStore,
{
    let Some(code) = query.code.as_deref().filter(|code| !code.is_empty()) else {
        return Ok(Redirect::temporary("/oauth2/start").into_response());
    };

    let flags = super::cookie_secure_flag(
        &headers,
        &state.cookie_secure_mode,
        state.server_tls_enabled,
    );

    let code_verifier = match oauth2_code_verifier(&headers, query._state.as_deref()) {
        Ok(code_verifier) => code_verifier,
        Err(OAuth2StateError) => return Ok(oauth2_state_error_response(&flags)),
    };

    let auth = state
        .auth
        .as_ref()
        .ok_or_else(|| LayerhouseError::Internal("auth not configured".to_string()))?;

    // Exchange authorization code for tokens at the discovered token endpoint
    let token_url = auth.token_exchange_endpoint().await;

    let mut client_builder =
        aioduct::TokioClient::builder().timeout(std::time::Duration::from_secs(10));
    if auth.config.tls_insecure_skip_verify {
        client_builder = client_builder.danger_accept_invalid_certs();
    }
    let client = client_builder
        .build()
        .map_err(|e| LayerhouseError::Internal(format!("HTTP client build failed: {}", e)))?;

    let form_body = form_encode(&[
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", auth.redirect_uri()),
        ("client_id", &auth.config.client_id),
        ("client_secret", &auth.config.client_secret),
        ("code_verifier", &code_verifier),
    ]);

    let response = client
        .request(http::Method::POST, &token_url)
        .map_err(|e| LayerhouseError::Internal(format!("token request build failed: {}", e)))?
        .header_str("content-type", "application/x-www-form-urlencoded")
        .map_err(|e| LayerhouseError::Internal(format!("header failed: {}", e)))?
        .body(form_body)
        .send()
        .await
        .map_err(|e| LayerhouseError::Internal(format!("token exchange failed: {}", e)))?;

    let body = response
        .text()
        .await
        .map_err(|e| LayerhouseError::Internal(format!("token read failed: {}", e)))?;

    let token: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| LayerhouseError::Internal(format!("token parse failed: {}", e)))?;

    let access_token = token["access_token"]
        .as_str()
        .ok_or_else(|| LayerhouseError::Internal("missing access_token".to_string()))?
        .to_string();
    let id_token_str = token["id_token"]
        .as_str()
        .ok_or_else(|| LayerhouseError::Internal("missing id_token".to_string()))?
        .to_string();

    // Verify both tokens against JWKS (replaces the previous from_jwt_unverified path).
    let id_claims = auth.verify_id_token(&id_token_str).await?;
    let (access_groups, access_subject, access_exp) =
        auth.verify_access_token(&access_token).await?;

    // Merge groups from both tokens: some IdPs put groups in the ID token
    // rather than the access token.
    let id_groups = id_claims.extract_groups(&auth.config.group_claim);
    let mut all_groups = access_groups.clone();
    for g in &id_groups {
        if !all_groups.contains(g) {
            all_groups.push(g.clone());
        }
    }

    tracing::info!(
        "oauth2 callback: subject={} access_token_groups={:?} id_token_groups={:?} merged={:?}",
        access_subject,
        access_groups,
        id_groups,
        all_groups,
    );

    // Subject consistency: the subject in both tokens must match.
    if id_claims.subject != access_subject {
        return Err(LayerhouseError::Unauthorized {
            message: "token subject mismatch".to_string(),
            realm: None,
            service: None,
            scope: None,
        });
    }

    let now = chrono::Utc::now().timestamp() as u64;
    let expires_in = token["expires_in"].as_u64().unwrap_or(3600);
    // Cap session lifetime at the minimum of: token expires_in,
    // id_token exp, access_token exp, and the 1-hour hard cap.
    let token_expires_at = now + expires_in;
    let id_expires_at = id_claims.exp as u64;
    let access_expires_at = access_exp as u64;
    let session_max_age = token_expires_at
        .min(id_expires_at)
        .min(access_expires_at)
        .min(now + 3600)
        .saturating_sub(now);

    let id_token_ttl_secs = id_expires_at.saturating_sub(now);
    let access_token_ttl_secs = access_expires_at.saturating_sub(now);
    if session_max_age == 0 {
        tracing::warn!(
            expires_in,
            id_token_ttl_secs,
            access_token_ttl_secs,
            "oauth2 callback produced zero-length dashboard session"
        );
        return Ok(oauth2_session_error_response(&flags));
    }

    let id_username = id_claims.username();
    let id_display_name = id_claims.display_name();
    let id_email = id_claims.email();
    let id_subject = id_claims.subject;

    let session = DashboardSession {
        subject: id_subject,
        username: id_username,
        display_name: id_display_name,
        email: id_email,
        groups: all_groups,
        expires_at: now + session_max_age,
    };

    if let Err(error) = state
        .core
        .metadata
        .put_observed_identity(ObservedIdentity {
            subject: Subject::new(session.subject.clone()),
            username: session.username.clone(),
            display_name: session.display_name.clone(),
            email: session.email.clone(),
            groups: session.groups.clone(),
            last_seen_at: now,
        })
        .await
    {
        tracing::warn!(error = %error, "failed to record observed identity");
    }

    let cookie_value = session.encrypt(auth.session_key())?;
    let session_group_count = session.groups.len();
    let session_cookie = format!(
        "layerhouse_session={}; {}; Path=/; Max-Age={}",
        cookie_value,
        flags.attributes(),
        session_max_age
    );
    let logout_hint_cookie = format!(
        "layerhouse_logout_hint={}; {}; Path=/api/v1/session/logout; Max-Age={}",
        id_token_str,
        flags.attributes(),
        session_max_age
    );

    tracing::info!(
        session_max_age,
        expires_in,
        id_token_ttl_secs,
        access_token_ttl_secs,
        session_cookie_len = session_cookie.len(),
        logout_hint_cookie_len = logout_hint_cookie.len(),
        session_group_count,
        secure_cookie = flags.secure,
        "oauth2 callback session cookies prepared"
    );

    if session_cookie.len() > MAX_SET_COOKIE_HEADER_LEN {
        tracing::warn!(
            session_cookie_len = session_cookie.len(),
            max_cookie_len = MAX_SET_COOKIE_HEADER_LEN,
            "oauth2 dashboard session cookie exceeds browser cookie limit"
        );
        return Ok(oauth2_session_error_response(&flags));
    }

    let mut response = Redirect::temporary("/").into_response();
    response.headers_mut().append(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&session_cookie)
            .map_err(|e| LayerhouseError::Internal(format!("session cookie failed: {}", e)))?,
    );
    if logout_hint_cookie.len() <= MAX_SET_COOKIE_HEADER_LEN {
        // Store the raw id_token in a path-scoped cookie so it is only sent
        // to the logout endpoint.
        response.headers_mut().append(
            axum::http::header::SET_COOKIE,
            axum::http::HeaderValue::from_str(&logout_hint_cookie).map_err(|e| {
                LayerhouseError::Internal(format!("logout hint cookie failed: {}", e))
            })?,
        );
    } else {
        tracing::warn!(
            logout_hint_cookie_len = logout_hint_cookie.len(),
            max_cookie_len = MAX_SET_COOKIE_HEADER_LEN,
            "skipping oversized oauth2 logout hint cookie"
        );
    }
    append_clear_oauth2_cookie(&mut response, &flags);
    Ok(response)
}

#[derive(Debug)]
struct OAuth2StateError;

fn oauth2_code_verifier(
    headers: &HeaderMap,
    state: Option<&str>,
) -> Result<String, OAuth2StateError> {
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookie| extract_cookie(cookie, OAUTH2_COOKIE))
        .ok_or(OAuth2StateError)?;

    let (stored_state, code_verifier) = cookie.split_once('.').ok_or(OAuth2StateError)?;

    if Some(stored_state) != state {
        return Err(OAuth2StateError);
    }

    Ok(code_verifier.to_string())
}

fn oauth2_state_error_response(flags: &super::CookieFlags) -> Response {
    oauth2_error_response(OAUTH2_STATE_ERROR_LOCATION, flags)
}

fn oauth2_session_error_response(flags: &super::CookieFlags) -> Response {
    oauth2_error_response(OAUTH2_SESSION_ERROR_LOCATION, flags)
}

fn oauth2_error_response(location: &str, flags: &super::CookieFlags) -> Response {
    let mut response = Redirect::temporary(location).into_response();
    append_clear_oauth2_cookie(&mut response, flags);
    response
}

fn append_clear_oauth2_cookie(response: &mut Response, flags: &super::CookieFlags) {
    response.headers_mut().append(
        header::SET_COOKIE,
        HeaderValue::from_str(&oauth2_cookie_clear_str(flags))
            .expect("valid clear-cookie header value"),
    );
}

fn extract_cookie<'a>(cookie: &'a str, name: &str) -> Option<&'a str> {
    cookie.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name).then_some(value)
    })
}

fn random_urlsafe(len: usize) -> String {
    let mut bytes = vec![0u8; len];
    rand::rng().fill_bytes(&mut bytes);
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes)
}

fn pkce_challenge(code_verifier: &str) -> String {
    let digest = sha2::Sha256::digest(code_verifier.as_bytes());
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(digest)
}

fn form_encode(fields: &[(&str, &str)]) -> String {
    fields
        .iter()
        .map(|(key, value)| format!("{}={}", percent_encode(key), percent_encode(value)))
        .collect::<Vec<_>>()
        .join("&")
}

fn percent_encode(value: &str) -> String {
    value
        .bytes()
        .flat_map(|byte| match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                vec![byte as char]
            }
            _ => format!("%{byte:02X}").chars().collect(),
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use crate::config::default_login_scopes;

    use super::percent_encode;

    #[test]
    fn login_scope_default_includes_groups_for_dashboard_permissions() {
        let scopes = default_login_scopes();
        assert_eq!(scopes, "openid profile email groups");
        assert_eq!(percent_encode(&scopes), "openid%20profile%20email%20groups");
    }
}
