mod handlers;
mod types;

use std::sync::Arc;

use axum::Router;

use crate::routes::AppState;
use crate::store::blob::BlobStore;
use crate::store::metadata::NamespaceStore;

pub fn routes<M: NamespaceStore, B: BlobStore>() -> Router<Arc<AppState<M, B>>> {
    Router::new()
        .route(
            "/api/v1/account/namespaces",
            axum::routing::get(handlers::list_account_namespaces::<M, B>),
        )
        .route(
            "/api/v1/admin/namespaces",
            axum::routing::get(handlers::list_namespaces::<M, B>),
        )
        .route(
            "/api/v1/admin/namespaces/{handle}",
            axum::routing::get(handlers::get_namespace::<M, B>),
        )
        .route(
            "/api/v1/admin/namespaces/{handle}/claim",
            axum::routing::post(handlers::claim_namespace::<M, B>),
        )
        .route(
            "/api/v1/admin/namespaces/{handle}/release",
            axum::routing::post(handlers::release_namespace::<M, B>),
        )
        .route(
            "/api/v1/admin/namespaces/{handle}/revoke",
            axum::routing::post(handlers::revoke_namespace::<M, B>),
        )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::identity::Subject;
    use crate::auth::token::AuthIdentity;
    use crate::routes::test_state_with_auth;
    use crate::store::blob::InMemoryBlobStore;
    use crate::store::metadata::InMemoryMetadataStore;
    use axum::body::Body;
    use serde::Serialize;
    use tower::ServiceExt;

    fn user_identity() -> AuthIdentity {
        AuthIdentity {
            subject: Subject::new("user-1"),
            username: Some("alice".to_string()),
            display_name: None,
            email: None,
            groups: vec![],
            scopes: vec![],
            token_type: crate::auth::token::TokenType::PersonalAccess,
        }
    }

    fn admin_identity() -> AuthIdentity {
        AuthIdentity {
            subject: Subject::new("admin-1"),
            username: Some("admin".to_string()),
            display_name: None,
            email: None,
            groups: vec!["registry_admins".to_string()],
            scopes: vec!["repository:*:*".to_string()],
            token_type: crate::auth::token::TokenType::PersonalAccess,
        }
    }

    fn other_user_identity() -> AuthIdentity {
        AuthIdentity {
            subject: Subject::new("user-2"),
            username: Some("bob".to_string()),
            display_name: None,
            email: None,
            groups: vec![],
            scopes: vec![],
            token_type: crate::auth::token::TokenType::PersonalAccess,
        }
    }

    fn post_json(
        uri: &str,
        body: &impl Serialize,
        identity: &AuthIdentity,
    ) -> axum::http::Request<Body> {
        let mut req = axum::http::Request::builder()
            .method(axum::http::Method::POST)
            .uri(uri)
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(body).unwrap_or_default()))
            .unwrap();
        req.extensions_mut().insert(identity.clone());
        req
    }

    fn get(uri: &str, identity: &AuthIdentity) -> axum::http::Request<Body> {
        let mut req = axum::http::Request::builder()
            .method(axum::http::Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap();
        req.extensions_mut().insert(identity.clone());
        req
    }

    fn get_unauthenticated(uri: &str) -> axum::http::Request<Body> {
        axum::http::Request::builder()
            .method(axum::http::Method::GET)
            .uri(uri)
            .body(Body::empty())
            .unwrap()
    }

    #[tokio::test]
    async fn claim_and_get_namespace() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state.clone());

        let resp = app
            .oneshot(post_json(
                "/api/v1/admin/namespaces/acme/claim",
                &serde_json::json!({}),
                &user_identity(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::CREATED);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(data["handle"], "acme");
        assert_eq!(data["owner_kind"], "user");
    }

    #[tokio::test]
    async fn claim_reserved_handle_rejected() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state.clone());

        let resp = app
            .oneshot(post_json(
                "/api/v1/admin/namespaces/users/claim",
                &serde_json::json!({}),
                &user_identity(),
            ))
            .await
            .unwrap();
        assert!(!resp.status().is_success());
    }

    #[tokio::test]
    async fn list_namespaces_requires_admin() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state.clone());

        // Regular user cannot list
        let resp = app
            .clone()
            .oneshot(get("/api/v1/admin/namespaces", &user_identity()))
            .await
            .unwrap();
        assert!(!resp.status().is_success());

        // Admin can list
        let resp = app
            .clone()
            .oneshot(get("/api/v1/admin/namespaces", &admin_identity()))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
    }

    #[tokio::test]
    async fn account_namespaces_requires_auth() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state.clone());

        let resp = app
            .oneshot(get_unauthenticated("/api/v1/account/namespaces"))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn account_namespaces_returns_current_user_claims() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state.clone());

        let resp = app
            .clone()
            .oneshot(post_json(
                "/api/v1/admin/namespaces/acme/claim",
                &serde_json::json!({}),
                &user_identity(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::CREATED);

        let resp = app
            .clone()
            .oneshot(post_json(
                "/api/v1/admin/namespaces/other/claim",
                &serde_json::json!({}),
                &other_user_identity(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::CREATED);

        let resp = app
            .oneshot(get("/api/v1/account/namespaces", &user_identity()))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(data["namespaces"].as_array().unwrap().len(), 1);
        assert_eq!(data["namespaces"][0]["handle"], "acme");
        assert_eq!(data["namespaces"][0]["owner_kind"], "user");
    }

    #[tokio::test]
    async fn release_and_revoke_namespace() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state.clone());

        // Claim as user
        let resp = app
            .clone()
            .oneshot(post_json(
                "/api/v1/admin/namespaces/acme/claim",
                &serde_json::json!({}),
                &user_identity(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::CREATED);

        // Non-admin cannot revoke
        let resp = app
            .clone()
            .oneshot(post_json(
                "/api/v1/admin/namespaces/acme/revoke",
                &serde_json::json!({}),
                &user_identity(),
            ))
            .await
            .unwrap();
        assert!(!resp.status().is_success());

        // Admin can revoke
        let resp = app
            .clone()
            .oneshot(post_json(
                "/api/v1/admin/namespaces/acme/revoke",
                &serde_json::json!({}),
                &admin_identity(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn non_owner_cannot_release() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state.clone());

        // Alice claims the namespace
        let resp = app
            .clone()
            .oneshot(post_json(
                "/api/v1/admin/namespaces/acme/claim",
                &serde_json::json!({}),
                &user_identity(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::CREATED);

        // Bob cannot release Alice's namespace
        let bob = AuthIdentity {
            subject: Subject::new("user-2"),
            username: Some("bob".to_string()),
            display_name: None,
            email: None,
            groups: vec![],
            scopes: vec![],
            token_type: crate::auth::token::TokenType::PersonalAccess,
        };
        let resp = app
            .clone()
            .oneshot(post_json(
                "/api/v1/admin/namespaces/acme/release",
                &serde_json::json!({}),
                &bob,
            ))
            .await
            .unwrap();
        assert!(!resp.status().is_success());

        // Alice can still release her own namespace
        let resp = app
            .oneshot(post_json(
                "/api/v1/admin/namespaces/acme/release",
                &serde_json::json!({}),
                &user_identity(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::NO_CONTENT);
    }
}
