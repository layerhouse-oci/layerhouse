//! Metadata store traits and types.
//!
//! This module is split into several sub-modules for maintainability:
//! - `types`: domain types (ManifestEntry, MirrorRule, SyncJob, etc.)
//! - `traits`: trait definitions (ManifestStore, MirrorConfigStore, etc.)
//! - `typed_id`: prefixed Layerhouse-internal identifiers (`OrgId`, ...)
//! - `handle`: handle and repository-path grammar validators
//! - `in_memory`: test-only InMemoryMetadataStore implementation

pub mod handle;
pub mod traits;
pub mod typed_id;
pub mod types;

#[cfg(test)]
pub(crate) mod in_memory;

// Re-export everything so existing `use crate::store::metadata::*` imports
// continue to work without changes.
pub use traits::*;
pub use types::*;

#[cfg(test)]
pub use in_memory::InMemoryMetadataStore;
