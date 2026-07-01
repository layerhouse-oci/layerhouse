#![cfg(test)]

use async_trait::async_trait;

use super::DirectoryError;

#[async_trait]
pub trait DirectoryConnectorTestExt: Send + Sync {
    async fn health(&self, ctx: ConnectorContext) -> Result<HealthResponse, DirectoryError>;
    async fn search_principals(
        &self,
        ctx: ConnectorContext,
        request: SearchRequest,
    ) -> Result<SearchResponse, DirectoryError>;
    async fn resolve_principals(
        &self,
        ctx: ConnectorContext,
        request: ResolveRequest,
    ) -> Result<ResolveResponse, DirectoryError>;
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ConnectorContext {
    pub provider: String,
    pub base_origin: String,
    pub timeout_ms: u64,
    pub tls_mode: TlsMode,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TlsMode {
    PlainHttp,
    SystemRoots,
    CustomCa,
    InsecureSkipVerify,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrincipalKind {
    User,
    Group,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PrincipalStatus {
    Active,
    Disabled,
    Deleted,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum HealthState {
    Healthy,
    Degraded,
    Unauthorized,
    Unavailable,
    Misconfigured,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrincipalRef {
    pub kind: PrincipalKind,
    pub local_id: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DirectoryPrincipal {
    pub ref_: PrincipalRef,
    pub display_name: String,
    pub display_hierarchy: Vec<String>,
    pub login: Option<String>,
    pub email: Option<String>,
    pub description: Option<String>,
    pub status: PrincipalStatus,
    pub fetched_at_unix: Option<u64>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SearchFilter {
    FreeText(String),
    ExactLocalId(String),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchRequest {
    pub filter: SearchFilter,
    pub kinds: Vec<PrincipalKind>,
    pub limit: u32,
    pub cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SearchResponse {
    pub principals: Vec<DirectoryPrincipal>,
    pub next_cursor: Option<String>,
    pub warnings: Vec<DirectoryError>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolveRequest {
    pub refs: Vec<PrincipalRef>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolveResponse {
    pub results: Vec<ResolveResult>,
    pub warnings: Vec<DirectoryError>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ResolveResult {
    Found(DirectoryPrincipal),
    NotFound(PrincipalRef),
    Failed(ResolveFailure),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolveFailure {
    pub ref_: PrincipalRef,
    pub error: DirectoryError,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HealthResponse {
    pub state: HealthState,
    pub message: String,
    pub checked_at_unix: u64,
}
