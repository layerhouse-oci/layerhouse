pub(crate) mod bindings {
    wasmtime::component::bindgen!({
        world: "directory-connector",
        path: "../../wit",
        exports: { default: async },
    });
}

use std::future::Future;
use std::sync::Arc;
use std::time::Duration;

use tokio::sync::Semaphore;
use tokio::time::Instant;
use wasmtime::component::{Component, Linker, ResourceTable};
use wasmtime::{Config, Engine, Store, StoreLimits, StoreLimitsBuilder};
use wasmtime_wasi::{WasiCtx, WasiCtxBuilder, WasiCtxView, WasiView};
use wasmtime_wasi_http::WasiHttpCtx;
use wasmtime_wasi_http::p2::{WasiHttpCtxView, WasiHttpView};

use super::http_host::{DirectoryHttpHooks, DirectoryHttpPolicy};
use super::{ConnectorInfo, DirectoryConnector, DirectoryError, sanitize_connector_error_message};

#[derive(Clone, Debug)]
pub struct WasmDirectoryLimits {
    pub connector_info_timeout: Duration,
    pub memory_limit_bytes: usize,
    pub max_concurrent_calls: usize,
}

impl Default for WasmDirectoryLimits {
    fn default() -> Self {
        Self {
            connector_info_timeout: Duration::from_millis(2_000),
            memory_limit_bytes: 64 * 1024 * 1024,
            max_concurrent_calls: 8,
        }
    }
}

pub struct WasmDirectoryConnector {
    engine: Engine,
    component: Component,
    linker: Linker<ConnectorStore>,
    limits: WasmDirectoryLimits,
    http_policy: DirectoryHttpPolicy,
    semaphore: Arc<Semaphore>,
}

struct ConnectorStore {
    wasi: WasiCtx,
    http: WasiHttpCtx,
    http_hooks: DirectoryHttpHooks,
    table: ResourceTable,
    limits: StoreLimits,
}

impl ConnectorStore {
    fn new(
        memory_limit_bytes: usize,
        http_policy: DirectoryHttpPolicy,
        call_timeout: Duration,
    ) -> Self {
        let http_hooks = DirectoryHttpHooks::new(http_policy, call_timeout);
        let mut http = WasiHttpCtx::new();
        http.set_field_size_limit(http_hooks.header_limit_bytes());

        Self {
            wasi: WasiCtxBuilder::new().build(),
            http,
            http_hooks,
            table: ResourceTable::new(),
            limits: StoreLimitsBuilder::new()
                .memory_size(memory_limit_bytes)
                .build(),
        }
    }
}

impl WasiView for ConnectorStore {
    fn ctx(&mut self) -> WasiCtxView<'_> {
        WasiCtxView {
            ctx: &mut self.wasi,
            table: &mut self.table,
        }
    }
}

impl WasiHttpView for ConnectorStore {
    fn http(&mut self) -> WasiHttpCtxView<'_> {
        WasiHttpCtxView {
            ctx: &mut self.http,
            table: &mut self.table,
            hooks: &mut self.http_hooks,
        }
    }
}

impl WasmDirectoryConnector {
    pub(crate) fn from_binary_with_http_policy(
        bytes: &[u8],
        limits: WasmDirectoryLimits,
        http_policy: DirectoryHttpPolicy,
    ) -> Result<Self, DirectoryError> {
        if limits.memory_limit_bytes == 0 {
            return Err(DirectoryError::InvalidQuery(
                "memory_limit_bytes must be positive".to_string(),
            ));
        }
        if limits.max_concurrent_calls == 0 {
            return Err(DirectoryError::InvalidQuery(
                "max_concurrent_calls must be positive".to_string(),
            ));
        }

        let mut config = Config::new();
        config.wasm_component_model(true);

        let engine = Engine::new(&config).map_err(host_internal)?;
        let component = Component::from_binary(&engine, bytes).map_err(host_invalid_response)?;
        let mut linker = Linker::new(&engine);
        wasmtime_wasi::p2::add_to_linker_async(&mut linker).map_err(host_internal)?;
        wasmtime_wasi_http::p2::add_only_http_to_linker_async(&mut linker)
            .map_err(host_internal)?;

        Ok(Self {
            engine,
            component,
            linker,
            http_policy,
            semaphore: Arc::new(Semaphore::new(limits.max_concurrent_calls)),
            limits,
        })
    }

    async fn instantiate(
        &self,
        call_timeout: Duration,
    ) -> Result<(Store<ConnectorStore>, bindings::DirectoryConnector), DirectoryError> {
        let mut store = Store::new(
            &self.engine,
            ConnectorStore::new(
                self.limits.memory_limit_bytes,
                self.http_policy.clone(),
                call_timeout,
            ),
        );
        store.limiter(|state| &mut state.limits);

        let connector = bindings::DirectoryConnector::instantiate_async(
            &mut store,
            &self.component,
            &self.linker,
        )
        .await
        .map_err(host_invalid_response)?;

        Ok((store, connector))
    }

    async fn with_deadline<F, Fut, T>(
        &self,
        timeout: Duration,
        operation: F,
    ) -> Result<T, DirectoryError>
    where
        F: FnOnce(Duration) -> Fut,
        Fut: Future<Output = Result<T, DirectoryError>>,
    {
        let started = Instant::now();
        let permit = tokio::time::timeout(timeout, self.semaphore.acquire())
            .await
            .map_err(|_| DirectoryError::Timeout("connector concurrency slot timed out".into()))?
            .map_err(host_internal)?;

        let remaining = timeout
            .checked_sub(started.elapsed())
            .ok_or_else(|| DirectoryError::Timeout("connector call timed out".into()))?;

        let result = tokio::time::timeout(remaining, operation(remaining))
            .await
            .map_err(|_| DirectoryError::Timeout("connector call timed out".into()))?;
        drop(permit);
        result
    }

    async fn do_connector_info(
        &self,
        call_timeout: Duration,
    ) -> Result<ConnectorInfo, DirectoryError> {
        let (mut store, connector) = self.instantiate(call_timeout).await?;
        let info = connector
            .call_connector_info(&mut store)
            .await
            .map_err(host_internal)?;
        Ok(info.into())
    }
}

#[async_trait::async_trait]
impl DirectoryConnector for WasmDirectoryConnector {
    async fn connector_info(&self) -> Result<ConnectorInfo, DirectoryError> {
        self.with_deadline(self.limits.connector_info_timeout, |remaining| {
            self.do_connector_info(remaining)
        })
        .await
    }
}

fn host_internal(error: impl std::fmt::Display) -> DirectoryError {
    DirectoryError::Internal(sanitize_connector_error_message(&error.to_string()))
}

fn host_invalid_response(error: impl std::fmt::Display) -> DirectoryError {
    DirectoryError::InvalidResponse(sanitize_connector_error_message(&error.to_string()))
}

impl From<bindings::ConnectorInfo> for ConnectorInfo {
    fn from(value: bindings::ConnectorInfo) -> Self {
        Self {
            name: value.name,
            version: value.version,
            provider: value.provider,
            abi_version: value.abi_version,
        }
    }
}

impl From<bindings::DirectoryError> for DirectoryError {
    fn from(value: bindings::DirectoryError) -> Self {
        match value {
            bindings::DirectoryError::InvalidQuery(message) => {
                Self::InvalidQuery(sanitize_connector_error_message(&message))
            }
            bindings::DirectoryError::UnsupportedProvider(message) => {
                Self::UnsupportedProvider(sanitize_connector_error_message(&message))
            }
            bindings::DirectoryError::NotFound(message) => {
                Self::NotFound(sanitize_connector_error_message(&message))
            }
            bindings::DirectoryError::UpstreamUnavailable(message) => {
                Self::UpstreamUnavailable(sanitize_connector_error_message(&message))
            }
            bindings::DirectoryError::UpstreamUnauthorized(message) => {
                Self::UpstreamUnauthorized(sanitize_connector_error_message(&message))
            }
            bindings::DirectoryError::RateLimited(message) => {
                Self::RateLimited(sanitize_connector_error_message(&message))
            }
            bindings::DirectoryError::Timeout(message) => {
                Self::Timeout(sanitize_connector_error_message(&message))
            }
            bindings::DirectoryError::InvalidResponse(message) => {
                Self::InvalidResponse(sanitize_connector_error_message(&message))
            }
            bindings::DirectoryError::Internal(message) => {
                Self::Internal(sanitize_connector_error_message(&message))
            }
        }
    }
}

mod test_support {
    #![cfg(test)]

    use std::path::Path;
    use std::time::Duration;

    use crate::directory::http_host::DirectoryHttpPolicy;

    use super::super::test_api::{
        ConnectorContext, DirectoryConnectorTestExt, DirectoryPrincipal, HealthResponse,
        HealthState, PrincipalKind, PrincipalRef, PrincipalStatus, ResolveFailure, ResolveRequest,
        ResolveResponse, ResolveResult, SearchFilter, SearchRequest, SearchResponse, TlsMode,
    };
    use super::{
        WasmDirectoryConnector, WasmDirectoryLimits, bindings, host_internal, host_invalid_response,
    };
    use crate::directory::DirectoryError;

    impl WasmDirectoryConnector {
        pub fn from_file(
            path: impl AsRef<Path>,
            limits: WasmDirectoryLimits,
        ) -> Result<Self, DirectoryError> {
            let bytes = std::fs::read(path).map_err(host_invalid_response)?;
            Self::from_binary_with_http_policy(&bytes, limits, DirectoryHttpPolicy::deny_all())
        }

        async fn do_health(&self, ctx: ConnectorContext) -> Result<HealthResponse, DirectoryError> {
            let timeout = Duration::from_millis(ctx.timeout_ms);
            self.with_deadline(timeout, |remaining| async move {
                let (mut store, connector) = self.instantiate(remaining).await?;
                let response = connector
                    .call_health(&mut store, &ctx.into())
                    .await
                    .map_err(host_internal)?
                    .map_err(DirectoryError::from)?;
                Ok(response.into())
            })
            .await
        }

        async fn do_search_principals(
            &self,
            ctx: ConnectorContext,
            request: SearchRequest,
        ) -> Result<SearchResponse, DirectoryError> {
            let timeout = Duration::from_millis(ctx.timeout_ms);
            self.with_deadline(timeout, |remaining| async move {
                let (mut store, connector) = self.instantiate(remaining).await?;
                let response = connector
                    .call_search_principals(&mut store, &ctx.into(), &request.into())
                    .await
                    .map_err(host_internal)?
                    .map_err(DirectoryError::from)?;
                Ok(response.into())
            })
            .await
        }

        async fn do_resolve_principals(
            &self,
            ctx: ConnectorContext,
            request: ResolveRequest,
        ) -> Result<ResolveResponse, DirectoryError> {
            let timeout = Duration::from_millis(ctx.timeout_ms);
            self.with_deadline(timeout, |remaining| async move {
                let (mut store, connector) = self.instantiate(remaining).await?;
                let response = connector
                    .call_resolve_principals(&mut store, &ctx.into(), &request.into())
                    .await
                    .map_err(host_internal)?
                    .map_err(DirectoryError::from)?;
                Ok(response.into())
            })
            .await
        }
    }

    #[async_trait::async_trait]
    impl DirectoryConnectorTestExt for WasmDirectoryConnector {
        async fn health(&self, ctx: ConnectorContext) -> Result<HealthResponse, DirectoryError> {
            self.do_health(ctx).await
        }

        async fn search_principals(
            &self,
            ctx: ConnectorContext,
            request: SearchRequest,
        ) -> Result<SearchResponse, DirectoryError> {
            self.do_search_principals(ctx, request).await
        }

        async fn resolve_principals(
            &self,
            ctx: ConnectorContext,
            request: ResolveRequest,
        ) -> Result<ResolveResponse, DirectoryError> {
            self.do_resolve_principals(ctx, request).await
        }
    }

    impl From<ConnectorContext> for bindings::ConnectorContext {
        fn from(value: ConnectorContext) -> Self {
            Self {
                provider: value.provider,
                base_origin: value.base_origin,
                timeout_ms: value.timeout_ms,
                tls_mode: value.tls_mode.into(),
            }
        }
    }

    impl From<TlsMode> for bindings::TlsMode {
        fn from(value: TlsMode) -> Self {
            match value {
                TlsMode::PlainHttp => Self::PlainHttp,
                TlsMode::SystemRoots => Self::SystemRoots,
                TlsMode::CustomCa => Self::CustomCa,
                TlsMode::InsecureSkipVerify => Self::InsecureSkipVerify,
            }
        }
    }

    impl From<PrincipalKind> for bindings::PrincipalKind {
        fn from(value: PrincipalKind) -> Self {
            match value {
                PrincipalKind::User => Self::User,
                PrincipalKind::Group => Self::Group,
            }
        }
    }

    impl From<bindings::PrincipalKind> for PrincipalKind {
        fn from(value: bindings::PrincipalKind) -> Self {
            match value {
                bindings::PrincipalKind::User => Self::User,
                bindings::PrincipalKind::Group => Self::Group,
            }
        }
    }

    impl From<bindings::PrincipalStatus> for PrincipalStatus {
        fn from(value: bindings::PrincipalStatus) -> Self {
            match value {
                bindings::PrincipalStatus::Active => Self::Active,
                bindings::PrincipalStatus::Disabled => Self::Disabled,
                bindings::PrincipalStatus::Deleted => Self::Deleted,
                bindings::PrincipalStatus::Unknown => Self::Unknown,
            }
        }
    }

    impl From<bindings::HealthState> for HealthState {
        fn from(value: bindings::HealthState) -> Self {
            match value {
                bindings::HealthState::Healthy => Self::Healthy,
                bindings::HealthState::Degraded => Self::Degraded,
                bindings::HealthState::Unauthorized => Self::Unauthorized,
                bindings::HealthState::Unavailable => Self::Unavailable,
                bindings::HealthState::Misconfigured => Self::Misconfigured,
            }
        }
    }

    impl From<PrincipalRef> for bindings::PrincipalRef {
        fn from(value: PrincipalRef) -> Self {
            Self {
                kind: value.kind.into(),
                local_id: value.local_id,
            }
        }
    }

    impl From<bindings::PrincipalRef> for PrincipalRef {
        fn from(value: bindings::PrincipalRef) -> Self {
            Self {
                kind: value.kind.into(),
                local_id: value.local_id,
            }
        }
    }

    impl From<bindings::DirectoryPrincipal> for DirectoryPrincipal {
        fn from(value: bindings::DirectoryPrincipal) -> Self {
            Self {
                ref_: value.ref_.into(),
                display_name: value.display_name,
                display_hierarchy: value.display_hierarchy,
                login: value.login,
                email: value.email,
                description: value.description,
                status: value.status.into(),
                fetched_at_unix: value.fetched_at_unix,
            }
        }
    }

    impl From<SearchFilter> for bindings::SearchFilter {
        fn from(value: SearchFilter) -> Self {
            match value {
                SearchFilter::FreeText(value) => Self::FreeText(value),
                SearchFilter::ExactLocalId(value) => Self::ExactLocalId(value),
            }
        }
    }

    impl From<SearchRequest> for bindings::SearchRequest {
        fn from(value: SearchRequest) -> Self {
            Self {
                filter: value.filter.into(),
                kinds: value.kinds.into_iter().map(Into::into).collect(),
                limit: value.limit,
                cursor: value.cursor,
            }
        }
    }

    impl From<bindings::SearchResponse> for SearchResponse {
        fn from(value: bindings::SearchResponse) -> Self {
            Self {
                principals: value.principals.into_iter().map(Into::into).collect(),
                next_cursor: value.next_cursor,
                warnings: value
                    .warnings
                    .into_iter()
                    .map(DirectoryError::from)
                    .collect(),
            }
        }
    }

    impl From<ResolveRequest> for bindings::ResolveRequest {
        fn from(value: ResolveRequest) -> Self {
            Self {
                refs: value.refs.into_iter().map(Into::into).collect(),
            }
        }
    }

    impl From<bindings::ResolveFailure> for ResolveFailure {
        fn from(value: bindings::ResolveFailure) -> Self {
            Self {
                ref_: value.ref_.into(),
                error: DirectoryError::from(value.error),
            }
        }
    }

    impl From<bindings::ResolveResult> for ResolveResult {
        fn from(value: bindings::ResolveResult) -> Self {
            match value {
                bindings::ResolveResult::Found(value) => Self::Found(value.into()),
                bindings::ResolveResult::NotFound(value) => Self::NotFound(value.into()),
                bindings::ResolveResult::Failed(value) => Self::Failed(value.into()),
            }
        }
    }

    impl From<bindings::ResolveResponse> for ResolveResponse {
        fn from(value: bindings::ResolveResponse) -> Self {
            Self {
                results: value.results.into_iter().map(Into::into).collect(),
                warnings: value
                    .warnings
                    .into_iter()
                    .map(DirectoryError::from)
                    .collect(),
            }
        }
    }

    impl From<bindings::HealthResponse> for HealthResponse {
        fn from(value: bindings::HealthResponse) -> Self {
            Self {
                state: value.state.into(),
                message: value.message,
                checked_at_unix: value.checked_at_unix,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use super::super::test_api::{
        ConnectorContext, DirectoryConnectorTestExt, HealthState, PrincipalKind, PrincipalRef,
        ResolveRequest, ResolveResult, SearchFilter, SearchRequest, TlsMode,
    };
    use super::*;

    fn fake_component_path() -> Option<PathBuf> {
        match std::env::var_os("LAYERHOUSE_TEST_FAKE_DIRECTORY_COMPONENT") {
            Some(path) => Some(PathBuf::from(path)),
            None if explicitly_filtered_under_libtest()
                && !std::env::vars_os().any(|(key, _)| key == "NEXTEST")
                && std::env::var_os("CARGO_LLVM_COV").is_none() =>
            {
                panic!(
                    "missing LAYERHOUSE_TEST_FAKE_DIRECTORY_COMPONENT; run `just connector-check`"
                );
            }
            None => None,
        }
    }

    fn explicitly_filtered_under_libtest() -> bool {
        std::env::args().any(|arg| arg.contains("directory_wasm"))
    }

    fn fake_context() -> ConnectorContext {
        ConnectorContext {
            provider: "fake".to_string(),
            base_origin: "https://fake.example.test".to_string(),
            timeout_ms: 2_000,
            tls_mode: TlsMode::SystemRoots,
        }
    }

    #[tokio::test]
    async fn directory_wasm_fake_component_roundtrip() {
        let Some(path) = fake_component_path() else {
            eprintln!(
                "skipping directory_wasm_fake_component_roundtrip; run `just connector-check`"
            );
            return;
        };

        let connector = WasmDirectoryConnector::from_file(path, WasmDirectoryLimits::default())
            .expect("load fake component");

        let info = connector.connector_info().await.expect("connector info");
        assert_eq!(info.provider, "fake");
        assert_eq!(info.abi_version, "0.0.3");

        let health = connector.health(fake_context()).await.expect("health");
        assert_eq!(health.state, HealthState::Healthy);

        let search = connector
            .search_principals(
                fake_context(),
                SearchRequest {
                    filter: SearchFilter::FreeText("alice".to_string()),
                    kinds: vec![PrincipalKind::User],
                    limit: 20,
                    cursor: None,
                },
            )
            .await
            .expect("search");
        assert_eq!(search.principals.len(), 1);
        assert_eq!(search.principals[0].ref_.local_id, "alice");
        assert_eq!(search.next_cursor.as_deref(), Some("fake-page-2"));

        let resolve = connector
            .resolve_principals(
                fake_context(),
                ResolveRequest {
                    refs: vec![
                        PrincipalRef {
                            kind: PrincipalKind::User,
                            local_id: "alice".to_string(),
                        },
                        PrincipalRef {
                            kind: PrincipalKind::Group,
                            local_id: "missing".to_string(),
                        },
                        PrincipalRef {
                            kind: PrincipalKind::User,
                            local_id: "fail".to_string(),
                        },
                    ],
                },
            )
            .await
            .expect("resolve");
        assert!(matches!(resolve.results[0], ResolveResult::Found(_)));
        assert!(matches!(resolve.results[1], ResolveResult::NotFound(_)));
        assert!(matches!(resolve.results[2], ResolveResult::Failed(_)));
    }

    #[tokio::test]
    async fn directory_wasm_sanitizes_connector_errors() {
        let Some(path) = fake_component_path() else {
            eprintln!(
                "skipping directory_wasm_sanitizes_connector_errors; run `just connector-check`"
            );
            return;
        };

        let connector = WasmDirectoryConnector::from_file(path, WasmDirectoryLimits::default())
            .expect("load fake component");
        let error = connector
            .search_principals(
                fake_context(),
                SearchRequest {
                    filter: SearchFilter::FreeText("emit-long-error".to_string()),
                    kinds: vec![PrincipalKind::User],
                    limit: 20,
                    cursor: None,
                },
            )
            .await
            .expect_err("search error");

        match error {
            DirectoryError::InvalidQuery(message) => {
                assert!(message.len() <= super::super::ERROR_MESSAGE_LIMIT_BYTES);
                assert!(!message.contains("secret-token"));
                assert!(!message.contains("Authorization:"));
                assert_eq!(
                    message,
                    "connector error contained redacted sensitive context"
                );
            }
            other => panic!("unexpected error: {other:?}"),
        }
    }
}
