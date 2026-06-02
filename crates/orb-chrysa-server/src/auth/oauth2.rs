use axum::extract::Query;
use axum::http::{HeaderMap, HeaderValue, header};
use axum::response::{IntoResponse, Redirect, Response};
use base64::Engine;
use rand::Rng;
use sha2::Digest;
use std::sync::Arc;

use crate::error::OrbChrysaError;
use crate::routes::AppState;

use super::session::DashboardSession;
use super::token::TokenClaims;

const OAUTH2_COOKIE: &str = "orb_chrysa_oauth2";
const OAUTH2_COOKIE_MAX_AGE_SECS: u64 = 600;
const OAUTH2_LOGIN_SCOPE: &str = "openid profile email groups";

#[derive(serde::Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    #[serde(default, rename = "state")]
    pub _state: Option<String>,
}

pub async fn oauth2_start<M, B>(
    axum::extract::State(state): axum::extract::State<Arc<AppState<M, B>>>,
) -> Result<Response, OrbChrysaError> {
    let auth = state
        .auth
        .as_ref()
        .ok_or_else(|| OrbChrysaError::Internal("auth not configured".to_string()))?;

    let state = random_urlsafe(32);
    let code_verifier = random_urlsafe(32);
    let code_challenge = pkce_challenge(&code_verifier);

    let authorization_endpoint = auth.authorization_endpoint().await;
    let auth_url = format!(
        "{}?response_type=code&client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
        authorization_endpoint,
        percent_encode(&auth.config.client_id),
        percent_encode(auth.redirect_uri()),
        percent_encode(OAUTH2_LOGIN_SCOPE),
        percent_encode(&state),
        percent_encode(&code_challenge),
    );

    let mut response = Redirect::temporary(&auth_url).into_response();
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_str(&format!(
            "{}={}.{}; HttpOnly; Secure; SameSite=Lax; Path=/oauth2; Max-Age={}",
            OAUTH2_COOKIE, state, code_verifier, OAUTH2_COOKIE_MAX_AGE_SECS
        ))
        .map_err(|e| OrbChrysaError::Internal(format!("oauth2 cookie failed: {}", e)))?,
    );
    Ok(response)
}

pub async fn oauth2_callback<M, B>(
    axum::extract::State(state): axum::extract::State<Arc<AppState<M, B>>>,
    headers: HeaderMap,
    Query(query): Query<CallbackQuery>,
) -> Result<Response, OrbChrysaError> {
    let Some(code) = query.code.as_deref().filter(|code| !code.is_empty()) else {
        return Ok(Redirect::temporary("/oauth2/start").into_response());
    };

    let auth = state
        .auth
        .as_ref()
        .ok_or_else(|| OrbChrysaError::Internal("auth not configured".to_string()))?;

    let code_verifier = oauth2_code_verifier(&headers, query._state.as_deref())?;

    // Exchange authorization code for tokens at the discovered token endpoint
    let token_url = auth.token_exchange_endpoint().await;

    let mut client_builder =
        aioduct::TokioClient::builder().timeout(std::time::Duration::from_secs(10));
    if auth.config.tls_insecure_skip_verify {
        client_builder = client_builder.danger_accept_invalid_certs();
    }
    let client = client_builder
        .build()
        .map_err(|e| OrbChrysaError::Internal(format!("HTTP client build failed: {}", e)))?;

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
        .map_err(|e| OrbChrysaError::Internal(format!("token request build failed: {}", e)))?
        .header_str("content-type", "application/x-www-form-urlencoded")
        .map_err(|e| OrbChrysaError::Internal(format!("header failed: {}", e)))?
        .body(form_body)
        .send()
        .await
        .map_err(|e| OrbChrysaError::Internal(format!("token exchange failed: {}", e)))?;

    let body = response
        .text()
        .await
        .map_err(|e| OrbChrysaError::Internal(format!("token read failed: {}", e)))?;

    let token: serde_json::Value = serde_json::from_str(&body)
        .map_err(|e| OrbChrysaError::Internal(format!("token parse failed: {}", e)))?;

    let access_token = token["access_token"]
        .as_str()
        .ok_or_else(|| OrbChrysaError::Internal("missing access_token".to_string()))?
        .to_string();
    let id_token = token["id_token"]
        .as_str()
        .ok_or_else(|| OrbChrysaError::Internal("missing id_token".to_string()))?;
    let id_claims = TokenClaims::from_jwt_unverified(id_token)
        .ok_or_else(|| OrbChrysaError::Internal("invalid id_token".to_string()))?;
    let refresh_token = token["refresh_token"].as_str().unwrap_or("").to_string();
    let id_token = id_token.to_string();

    let now = chrono::Utc::now().timestamp() as u64;
    let expires_in = token["expires_in"].as_u64().unwrap_or(86400);
    let username = id_claims.username();
    let display_name = id_claims.display_name();
    let email = id_claims.email();

    let session = DashboardSession {
        subject: id_claims.subject,
        username,
        display_name,
        email,
        access_token,
        refresh_token,
        id_token,
        expires_at: now + expires_in,
    };

    let cookie_value = session.encrypt(auth.session_key())?;

    let mut response = Redirect::temporary("/").into_response();
    response.headers_mut().append(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_str(&format!(
            "orb_chrysa_session={}; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age={}",
            cookie_value, expires_in
        ))
        .expect("valid cookie header value"),
    );
    response.headers_mut().append(
        axum::http::header::SET_COOKIE,
        axum::http::HeaderValue::from_static(
            "orb_chrysa_oauth2=; HttpOnly; Secure; SameSite=Lax; Path=/oauth2; Max-Age=0",
        ),
    );
    Ok(response)
}

fn oauth2_code_verifier(
    headers: &HeaderMap,
    state: Option<&str>,
) -> Result<String, OrbChrysaError> {
    let cookie = headers
        .get(header::COOKIE)
        .and_then(|value| value.to_str().ok())
        .and_then(|cookie| extract_cookie(cookie, OAUTH2_COOKIE))
        .ok_or_else(|| OrbChrysaError::Unauthorized {
            message: "missing oauth2 state".to_string(),
            realm: None,
            service: None,
            scope: None,
        })?;

    let (stored_state, code_verifier) =
        cookie
            .split_once('.')
            .ok_or_else(|| OrbChrysaError::Unauthorized {
                message: "invalid oauth2 state".to_string(),
                realm: None,
                service: None,
                scope: None,
            })?;

    if Some(stored_state) != state {
        return Err(OrbChrysaError::Unauthorized {
            message: "oauth2 state mismatch".to_string(),
            realm: None,
            service: None,
            scope: None,
        });
    }

    Ok(code_verifier.to_string())
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
    use super::{OAUTH2_LOGIN_SCOPE, percent_encode};

    #[test]
    fn login_scope_requests_groups_for_dashboard_permissions() {
        assert_eq!(OAUTH2_LOGIN_SCOPE, "openid profile email groups");
        assert_eq!(
            percent_encode(OAUTH2_LOGIN_SCOPE),
            "openid%20profile%20email%20groups"
        );
    }
}
