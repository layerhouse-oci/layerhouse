mod handlers;
mod types;

use std::sync::Arc;

use axum::Router;

use crate::routes::AppState;
use crate::store::blob::BlobStore;
use crate::store::metadata::AuthorizationStore;

pub fn routes<M: AuthorizationStore, B: BlobStore>() -> Router<Arc<AppState<M, B>>> {
    Router::new()
        .route(
            "/api/v1/account/namespaces",
            axum::routing::get(handlers::list_account_namespaces::<M, B>),
        )
        .route(
            "/api/v1/account/observed-users",
            axum::routing::get(handlers::search_observed_users::<M, B>),
        )
        .route(
            "/api/v1/account/namespaces/{handle}/grants",
            axum::routing::get(handlers::list_account_namespace_grants::<M, B>)
                .post(handlers::create_account_namespace_grant::<M, B>),
        )
        .route(
            "/api/v1/account/namespaces/{handle}/grants/{grant_id}",
            axum::routing::patch(handlers::update_account_namespace_grant::<M, B>)
                .delete(handlers::delete_account_namespace_grant::<M, B>),
        )
        .route(
            "/api/v1/admin/namespaces",
            axum::routing::get(handlers::list_namespaces::<M, B>),
        )
        .route(
            "/api/v1/admin/namespaces/{handle}/grants",
            axum::routing::get(handlers::list_admin_namespace_grants::<M, B>)
                .post(handlers::create_admin_namespace_grant::<M, B>),
        )
        .route(
            "/api/v1/admin/namespaces/{handle}/grants/{grant_id}",
            axum::routing::patch(handlers::update_admin_namespace_grant::<M, B>)
                .delete(handlers::delete_admin_namespace_grant::<M, B>),
        )
        .route(
            "/api/v1/admin/namespaces/{handle}/grant-audit",
            axum::routing::get(handlers::list_admin_namespace_grant_audit::<M, B>),
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
    use crate::auth::token::AuthIdentity;
    use crate::routes::test_state_with_auth;
    use crate::store::blob::InMemoryBlobStore;
    use crate::store::metadata::InMemoryMetadataStore;
    use axum::body::Body;
    use serde::Serialize;
    use tower::ServiceExt;

    fn user_identity() -> AuthIdentity {
        let mut identity = AuthIdentity::for_test(
            "user-1",
            crate::auth::token::TokenType::OidcAccess,
            &[],
            &[],
        );
        identity.username = Some("alice".to_string());
        identity
    }

    fn admin_identity() -> AuthIdentity {
        let mut identity = AuthIdentity::for_test(
            "admin-1",
            crate::auth::token::TokenType::PersonalAccess,
            &["registry_admins"],
            &["repository:*:*"],
        );
        identity.username = Some("admin".to_string());
        identity
    }

    fn other_user_identity() -> AuthIdentity {
        let mut identity = AuthIdentity::for_test(
            "user-2",
            crate::auth::token::TokenType::OidcAccess,
            &[],
            &[],
        );
        identity.username = Some("bob".to_string());
        identity
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

    fn patch_json(
        uri: &str,
        body: &impl Serialize,
        identity: &AuthIdentity,
    ) -> axum::http::Request<Body> {
        let mut req = axum::http::Request::builder()
            .method(axum::http::Method::PATCH)
            .uri(uri)
            .header("Content-Type", "application/json")
            .body(Body::from(serde_json::to_string(body).unwrap_or_default()))
            .unwrap();
        req.extensions_mut().insert(identity.clone());
        req
    }

    fn delete_json(
        uri: &str,
        body: &impl Serialize,
        identity: &AuthIdentity,
    ) -> axum::http::Request<Body> {
        let mut req = axum::http::Request::builder()
            .method(axum::http::Method::DELETE)
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
    async fn owner_can_manage_namespace_grants() {
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
                "/api/v1/account/namespaces/acme/grants",
                &serde_json::json!({
                    "grantee": {"kind": "group", "id": "test:group:550e8400-e29b-41d4-a716-446655440020"},
                    "action": "create"
                }),
                &user_identity(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        let grant_id = data["id"].as_str().unwrap().to_string();
        assert_eq!(data["action"], "create");

        let resp = app
            .clone()
            .oneshot(patch_json(
                &format!("/api/v1/account/namespaces/acme/grants/{grant_id}"),
                &serde_json::json!({"action": "update"}),
                &user_identity(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let resp = app
            .clone()
            .oneshot(get(
                "/api/v1/account/namespaces/acme/grants",
                &user_identity(),
            ))
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(data["grants"][0]["action"], "update");

        let resp = app
            .oneshot(delete_json(
                &format!("/api/v1/account/namespaces/acme/grants/{grant_id}"),
                &serde_json::json!({}),
                &user_identity(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::NO_CONTENT);
    }

    #[tokio::test]
    async fn non_owner_cannot_manage_account_namespace_grants() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state.clone());

        app.clone()
            .oneshot(post_json(
                "/api/v1/admin/namespaces/acme/claim",
                &serde_json::json!({}),
                &user_identity(),
            ))
            .await
            .unwrap();

        let resp = app
            .oneshot(post_json(
                "/api/v1/account/namespaces/acme/grants",
                &serde_json::json!({
                    "grantee": {"kind": "group", "id": "test:group:550e8400-e29b-41d4-a716-446655440020"},
                    "action": "pull"
                }),
                &other_user_identity(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::FORBIDDEN);
    }

    #[tokio::test]
    async fn admin_grant_mutations_require_reason_and_write_audit() {
        let state = test_state_with_auth(vec![]);
        let app = routes::<InMemoryMetadataStore, InMemoryBlobStore>().with_state(state.clone());

        app.clone()
            .oneshot(post_json(
                "/api/v1/admin/namespaces/acme/claim",
                &serde_json::json!({}),
                &user_identity(),
            ))
            .await
            .unwrap();

        let resp = app
            .clone()
            .oneshot(post_json(
                "/api/v1/admin/namespaces/acme/grants",
                &serde_json::json!({
                    "grantee": {"kind": "user", "id": "test:user:user-2"},
                    "action": "pull"
                }),
                &admin_identity(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::BAD_REQUEST);

        let resp = app
            .clone()
            .oneshot(post_json(
                "/api/v1/admin/namespaces/acme/grants",
                &serde_json::json!({
                    "grantee": {"kind": "user", "id": "test:user:user-2"},
                    "action": "pull",
                    "reason": "support request"
                }),
                &admin_identity(),
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), axum::http::StatusCode::OK);

        let resp = app
            .oneshot(get(
                "/api/v1/admin/namespaces/acme/grant-audit",
                &admin_identity(),
            ))
            .await
            .unwrap();
        let body = axum::body::to_bytes(resp.into_body(), 4096).await.unwrap();
        let data: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(data["audit"].as_array().unwrap().len(), 1);
        assert_eq!(data["audit"][0]["reason"], "support request");
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
        let bob = other_user_identity();
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
