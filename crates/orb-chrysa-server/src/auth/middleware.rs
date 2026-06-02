use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::{HeaderValue, header};
use axum::middleware::Next;
use axum::response::{IntoResponse, Redirect, Response};
use std::sync::Arc;

use crate::error::OrbChrysaError;
use crate::routes::AppState;
use crate::store::blob::BlobStore;
use crate::store::metadata::TokenStore;

use super::permissions::OciAction;
use super::session::DashboardSession;

const CLEAR_SESSION_COOKIE: &str =
    "orb_chrysa_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0";

pub async fn auth_middleware<M: TokenStore, B: BlobStore>(
    State(state): State<Arc<AppState<M, B>>>,
    req: Request<Body>,
    next: Next,
) -> Response {
    let path = req.uri().path().to_string();

    // Skip public paths
    if is_public_path(&path) {
        return next.run(req).await;
    }

    let Some(auth_service) = &state.auth else {
        return next.run(req).await;
    };

    let credential = extract_credential(&req);
    let uses_session_cookie = matches!(credential, Some(RequestCredential::SessionCookie(_)));
    let identity = match authenticate_request(auth_service, &state.core.metadata, credential).await
    {
        Ok(Some(identity)) => identity,
        Ok(None) => return auth_required_response(auth_service, &req),
        Err(e) if uses_session_cookie => return session_cookie_auth_error_response(&req, e),
        Err(e) => return e.into_response(),
    };

    if path.starts_with("/v2/") {
        let repository = extract_repository_from_path(&path);
        let action = OciAction::from_method(req.method());

        if let Err(e) = auth_service.check_permission(&identity, &repository, action) {
            return e.into_response();
        }
    }

    if path.starts_with("/api/v1/admin/")
        && let Err(e) = auth_service.check_admin_access(&identity)
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
    SessionCookie(String),
}

fn extract_credential(req: &Request<Body>) -> Option<RequestCredential> {
    if let Some(token) = extract_bearer_token(req) {
        return Some(RequestCredential::Bearer(token.to_string()));
    }
    extract_cookie(req, "orb_chrysa_session")
        .map(str::to_string)
        .map(RequestCredential::SessionCookie)
}

async fn authenticate_request<M: TokenStore>(
    auth: &super::AuthService,
    metadata: &M,
    credential: Option<RequestCredential>,
) -> Result<Option<super::token::AuthIdentity>, OrbChrysaError> {
    let Some(credential) = credential else {
        return Ok(None);
    };

    match credential {
        RequestCredential::Bearer(token) => {
            auth.validate_token::<M>(&token, metadata).await.map(Some)
        }
        RequestCredential::SessionCookie(cookie_value) => {
            let session =
                DashboardSession::decrypt(&cookie_value, auth.session_key()).map_err(|_| {
                    OrbChrysaError::Unauthorized {
                        message: "invalid session".to_string(),
                        realm: None,
                        service: None,
                        scope: None,
                    }
                })?;
            let now = chrono::Utc::now().timestamp() as u64;
            if now >= session.expires_at {
                return Err(OrbChrysaError::Unauthorized {
                    message: "session expired".to_string(),
                    realm: None,
                    service: None,
                    scope: None,
                });
            }

            let mut identity = auth
                .validate_token::<M>(&session.access_token, metadata)
                .await?;
            if identity.subject != session.subject {
                return Err(OrbChrysaError::Unauthorized {
                    message: "session subject mismatch".to_string(),
                    realm: None,
                    service: None,
                    scope: None,
                });
            }
            identity.username = session.username;
            identity.display_name = session.display_name;
            identity.email = session.email;
            Ok(Some(identity))
        }
    }
}

fn extract_cookie<'a>(req: &'a Request<Body>, name: &str) -> Option<&'a str> {
    let cookie = req.headers().get(header::COOKIE)?.to_str().ok()?;
    cookie.split(';').find_map(|part| {
        let (key, value) = part.trim().split_once('=')?;
        (key == name).then_some(value)
    })
}

fn auth_required_response(auth: &super::AuthService, req: &Request<Body>) -> Response {
    let path = req.uri().path();
    if is_dashboard_request_path(path) {
        return Redirect::temporary("/oauth2/start").into_response();
    }

    let repository = extract_repository_from_path(path);
    let service = path
        .strip_prefix("/v2/")
        .and_then(|rest| rest.split('/').next())
        .unwrap_or("registry");

    OrbChrysaError::Unauthorized {
        message: "authentication required".to_string(),
        realm: Some(auth.token_endpoint_url().to_string()),
        service: Some(service.to_string()),
        scope: Some(format!("repository:{}:*", repository)),
    }
    .into_response()
}

fn session_cookie_auth_error_response(req: &Request<Body>, error: OrbChrysaError) -> Response {
    let mut response = if is_dashboard_request_path(req.uri().path()) {
        Redirect::temporary("/oauth2/start").into_response()
    } else {
        error.into_response()
    };
    expire_session_cookie(&mut response);
    response
}

fn is_dashboard_request_path(path: &str) -> bool {
    !path.starts_with("/api/") && !path.starts_with("/v2/") && !path.starts_with("/raft/")
}

fn expire_session_cookie(response: &mut Response) {
    response.headers_mut().insert(
        header::SET_COOKIE,
        HeaderValue::from_static(CLEAR_SESSION_COOKIE),
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

#[cfg(test)]
mod tests {
    use super::{extract_repository_from_path, is_public_path, session_cookie_auth_error_response};
    use crate::error::OrbChrysaError;
    use axum::body::Body;
    use axum::http::{Request, StatusCode, header};

    fn invalid_session_error() -> OrbChrysaError {
        OrbChrysaError::Unauthorized {
            message: "invalid session".to_string(),
            realm: None,
            service: None,
            scope: None,
        }
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

        let response = session_cookie_auth_error_response(&req, invalid_session_error());

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
            Some("orb_chrysa_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")
        );
    }

    #[test]
    fn invalid_api_session_remains_unauthorized_and_clears_cookie() {
        let req = Request::builder()
            .uri("/api/v1/session")
            .body(Body::empty())
            .expect("request");

        let response = session_cookie_auth_error_response(&req, invalid_session_error());

        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
        assert_eq!(
            response
                .headers()
                .get(header::SET_COOKIE)
                .and_then(|value| value.to_str().ok()),
            Some("orb_chrysa_session=; HttpOnly; Secure; SameSite=Lax; Path=/; Max-Age=0")
        );
    }

    #[test]
    fn dashboard_static_assets_are_public() {
        assert!(is_public_path("/assets/index-abc123.js"));
        assert!(is_public_path("/brand/orb-chrysa-mark-dark.svg"));
        assert!(is_public_path("/favicon.svg"));
        assert!(!is_public_path("/"));
        assert!(!is_public_path("/api/v1/session"));
    }
}
