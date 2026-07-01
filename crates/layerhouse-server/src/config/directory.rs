use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

use super::ConfigError;

mod validation;

#[cfg(test)]
mod tests;

pub(super) use validation::validate_directory_config;

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DirectoryConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub component_path: Option<String>,
    #[serde(default)]
    pub component_sha256: Option<String>,
    #[serde(default)]
    pub base_origin: Option<String>,
    #[serde(default)]
    pub api_token_file: Option<String>,
    #[serde(default)]
    pub tls_ca_file: Option<String>,
    #[serde(default)]
    pub tls_insecure_skip_verify: bool,
    #[serde(default)]
    pub timeout_ms: Option<u64>,
    #[serde(default)]
    pub max_concurrent_calls: Option<usize>,
    #[serde(default)]
    pub memory_limit_bytes: Option<usize>,
}

impl DirectoryConfig {
    pub fn timeout_ms(&self) -> u64 {
        self.timeout_ms.unwrap_or(default_directory_timeout_ms())
    }

    pub fn max_concurrent_calls(&self) -> usize {
        self.max_concurrent_calls
            .unwrap_or(default_directory_max_concurrent_calls())
    }

    pub fn memory_limit_bytes(&self) -> usize {
        self.memory_limit_bytes
            .unwrap_or(default_directory_memory_limit_bytes())
    }

    pub fn resolve_component_path(
        &self,
        config_dir: Option<&Path>,
    ) -> Result<Option<PathBuf>, ConfigError> {
        self.component_path
            .as_deref()
            .map(|path| {
                resolve_config_relative_path("auth.directory.component_path", path, config_dir)
            })
            .transpose()
    }

    pub fn resolve_api_token_file(
        &self,
        config_dir: Option<&Path>,
    ) -> Result<Option<PathBuf>, ConfigError> {
        self.api_token_file
            .as_deref()
            .map(|path| {
                resolve_config_relative_path("auth.directory.api_token_file", path, config_dir)
            })
            .transpose()
    }

    pub fn resolve_tls_ca_file(
        &self,
        config_dir: Option<&Path>,
    ) -> Result<Option<PathBuf>, ConfigError> {
        self.tls_ca_file
            .as_deref()
            .map(|path| {
                resolve_config_relative_path("auth.directory.tls_ca_file", path, config_dir)
            })
            .transpose()
    }
}

fn default_directory_timeout_ms() -> u64 {
    2_000
}

fn default_directory_max_concurrent_calls() -> usize {
    8
}

fn default_directory_memory_limit_bytes() -> usize {
    64 * 1024 * 1024
}

fn resolve_config_relative_path(
    field: &str,
    value: &str,
    config_dir: Option<&Path>,
) -> Result<PathBuf, ConfigError> {
    if value.trim().is_empty() {
        return Err(ConfigError::Invalid(format!("{field} must not be empty")));
    }

    let path = Path::new(value);
    if path.is_absolute() {
        return Ok(path.to_path_buf());
    }

    let config_dir = config_dir.ok_or_else(|| {
        ConfigError::Invalid(format!(
            "{field} is relative but the config source has no filesystem directory"
        ))
    })?;
    Ok(config_dir.join(path))
}
