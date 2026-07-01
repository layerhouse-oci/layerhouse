use std::io::BufReader;
use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::Digest;
use thiserror::Error;

use crate::auth::principal::ProviderId;
use crate::config::{AuthConfig, Config, ConfigError, DirectoryConfig};

use super::wasm::{WasmDirectoryConnector, WasmDirectoryLimits};
use super::{ConnectorInfo, DirectoryConnector};

const EXPECTED_ABI_VERSION: &str = env!("CARGO_PKG_VERSION");

#[derive(Debug, Error)]
pub enum DirectoryStartupError {
    #[error("{0}")]
    Config(#[from] ConfigError),
    #[error("directory connector startup failed: {0}")]
    Invalid(String),
}

pub(crate) async fn validate_directory_startup(
    config: &Config,
    config_dir: Option<&Path>,
) -> Result<(), DirectoryStartupError> {
    let Some(auth) = &config.auth else {
        return Ok(());
    };
    validate_auth_directory_startup(auth, config_dir).await
}

async fn validate_auth_directory_startup(
    auth: &AuthConfig,
    config_dir: Option<&Path>,
) -> Result<(), DirectoryStartupError> {
    let Some(directory) = &auth.directory else {
        return Ok(());
    };
    if !directory.enabled {
        return Ok(());
    }

    let resolved = ResolvedDirectoryStartupConfig::from_directory(directory, config_dir)?;
    validate_api_token_file(&resolved.api_token_file)?;
    if let Some(tls_ca_file) = &resolved.tls_ca_file {
        validate_tls_ca_file(tls_ca_file)?;
    }

    let component_bytes = read_file(
        "auth.directory.component_path",
        &resolved.component_path,
        "read configured WASM component",
    )?;
    validate_component_digest(&component_bytes, &resolved.component_sha256)?;

    let connector = WasmDirectoryConnector::from_binary(
        &component_bytes,
        WasmDirectoryLimits {
            connector_info_timeout: Duration::from_millis(directory.timeout_ms()),
            memory_limit_bytes: directory.memory_limit_bytes(),
            max_concurrent_calls: directory.max_concurrent_calls(),
        },
    )
    .map_err(|err| {
        DirectoryStartupError::Invalid(format!(
            "auth.directory.component_path did not load as a valid directory connector component: {err}"
        ))
    })?;

    let info = connector.connector_info().await.map_err(|err| {
        DirectoryStartupError::Invalid(format!(
            "auth.directory.component_path did not expose valid directory connector metadata: {err}"
        ))
    })?;
    validate_connector_info(&info)?;

    tracing::info!(
        connector_name = %info.name,
        connector_version = %info.version,
        provider = %info.provider,
        abi_version = %info.abi_version,
        "validated directory connector startup"
    );

    Ok(())
}

struct ResolvedDirectoryStartupConfig {
    component_path: PathBuf,
    component_sha256: String,
    api_token_file: PathBuf,
    tls_ca_file: Option<PathBuf>,
}

impl ResolvedDirectoryStartupConfig {
    fn from_directory(
        directory: &DirectoryConfig,
        config_dir: Option<&Path>,
    ) -> Result<Self, DirectoryStartupError> {
        let component_path = required_resolved_path(
            "auth.directory.component_path",
            directory.resolve_component_path(config_dir)?,
        )?;
        let api_token_file = required_resolved_path(
            "auth.directory.api_token_file",
            directory.resolve_api_token_file(config_dir)?,
        )?;
        let tls_ca_file = directory.resolve_tls_ca_file(config_dir)?;
        let component_sha256 = directory
            .component_sha256
            .clone()
            .ok_or_else(|| missing_field("auth.directory.component_sha256"))?;

        Ok(Self {
            component_path,
            component_sha256,
            api_token_file,
            tls_ca_file,
        })
    }
}

fn required_resolved_path(
    field: &'static str,
    path: Option<PathBuf>,
) -> Result<PathBuf, DirectoryStartupError> {
    path.ok_or_else(|| missing_field(field))
}

fn missing_field(field: &'static str) -> DirectoryStartupError {
    DirectoryStartupError::Invalid(format!(
        "{field} is required when auth.directory.enabled is true"
    ))
}

fn read_file(
    field: &'static str,
    path: &Path,
    action: &'static str,
) -> Result<Vec<u8>, DirectoryStartupError> {
    std::fs::read(path).map_err(|err| {
        DirectoryStartupError::Invalid(format!(
            "{field} could not {action} at {}: {err}",
            path.display()
        ))
    })
}

fn validate_component_digest(bytes: &[u8], expected: &str) -> Result<(), DirectoryStartupError> {
    let actual = sha256_digest(bytes);
    if actual != expected {
        return Err(DirectoryStartupError::Invalid(format!(
            "auth.directory.component_sha256 mismatch for auth.directory.component_path: expected {expected}, actual {actual}"
        )));
    }
    Ok(())
}

fn sha256_digest(bytes: &[u8]) -> String {
    let digest = sha2::Sha256::digest(bytes);
    format!("sha256:{}", hex::encode(digest))
}

fn validate_api_token_file(path: &Path) -> Result<(), DirectoryStartupError> {
    let content = std::fs::read_to_string(path).map_err(|err| {
        DirectoryStartupError::Invalid(format!(
            "auth.directory.api_token_file could not read token file at {}: {err}. Ensure the file contains the raw Kanidm bearer token only.",
            path.display()
        ))
    })?;
    let token = strip_one_final_line_ending(&content);
    if token.is_empty() {
        return Err(DirectoryStartupError::Invalid(
            "auth.directory.api_token_file must not be empty".to_string(),
        ));
    }

    let lower = token.to_ascii_lowercase();
    if lower.starts_with("bearer ") || lower.starts_with("authorization:") {
        return Err(DirectoryStartupError::Invalid(
            "auth.directory.api_token_file must contain the raw token value, not a Bearer prefix or Authorization header".to_string(),
        ));
    }
    if token.chars().any(char::is_whitespace) {
        return Err(DirectoryStartupError::Invalid(
            "auth.directory.api_token_file token value must not contain whitespace except one final LF or CRLF".to_string(),
        ));
    }

    Ok(())
}

fn strip_one_final_line_ending(value: &str) -> &str {
    value
        .strip_suffix("\r\n")
        .or_else(|| value.strip_suffix('\n'))
        .unwrap_or(value)
}

fn validate_tls_ca_file(path: &Path) -> Result<(), DirectoryStartupError> {
    let bytes = read_file(
        "auth.directory.tls_ca_file",
        path,
        "read configured PEM CA bundle",
    )?;
    if bytes.is_empty() {
        return Err(DirectoryStartupError::Invalid(
            "auth.directory.tls_ca_file must not be empty".to_string(),
        ));
    }

    let mut reader = BufReader::new(bytes.as_slice());
    let mut certificate_count = 0usize;
    loop {
        match rustls_pemfile::read_one(&mut reader).map_err(|err| {
            DirectoryStartupError::Invalid(format!(
                "auth.directory.tls_ca_file is not a valid PEM CA bundle: {err}"
            ))
        })? {
            Some(rustls_pemfile::Item::X509Certificate(_)) => certificate_count += 1,
            Some(
                rustls_pemfile::Item::Pkcs1Key(_)
                | rustls_pemfile::Item::Pkcs8Key(_)
                | rustls_pemfile::Item::Sec1Key(_),
            ) => {
                return Err(DirectoryStartupError::Invalid(
                    "auth.directory.tls_ca_file must not contain private keys".to_string(),
                ));
            }
            Some(_) => {
                return Err(DirectoryStartupError::Invalid(
                    "auth.directory.tls_ca_file must contain only CA certificates".to_string(),
                ));
            }
            None => break,
        }
    }

    if certificate_count == 0 {
        return Err(DirectoryStartupError::Invalid(
            "auth.directory.tls_ca_file must contain at least one CA certificate".to_string(),
        ));
    }
    Ok(())
}

fn validate_connector_info(info: &ConnectorInfo) -> Result<(), DirectoryStartupError> {
    if info.name.trim().is_empty() {
        return Err(DirectoryStartupError::Invalid(
            "directory connector metadata name must not be empty".to_string(),
        ));
    }
    if info.version.trim().is_empty() {
        return Err(DirectoryStartupError::Invalid(
            "directory connector metadata version must not be empty".to_string(),
        ));
    }
    if info.abi_version != EXPECTED_ABI_VERSION {
        return Err(DirectoryStartupError::Invalid(format!(
            "directory connector ABI version mismatch: expected {EXPECTED_ABI_VERSION}, connector reported {}",
            info.abi_version
        )));
    }

    let provider = ProviderId::new(&info.provider).map_err(|err| {
        DirectoryStartupError::Invalid(format!(
            "directory connector provider {:?} is not a valid Layerhouse principal provider: {err}",
            info.provider
        ))
    })?;
    if provider.as_str() != info.provider {
        return Err(DirectoryStartupError::Invalid(format!(
            "directory connector provider {:?} must be canonical with no surrounding whitespace",
            info.provider
        )));
    }

    Ok(())
}

#[cfg(test)]
mod tests;
