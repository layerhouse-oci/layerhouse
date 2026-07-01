use std::path::Path;

use super::DirectoryConfig;
use crate::config::ConfigError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DirectoryBaseOriginScheme {
    Http,
    Https,
}

pub(crate) fn validate_directory_config(
    directory: &DirectoryConfig,
    config_dir: Option<&Path>,
) -> Result<(), ConfigError> {
    if directory.timeout_ms() == 0 {
        return Err(ConfigError::Invalid(
            "auth.directory.timeout_ms must be greater than zero".to_string(),
        ));
    }
    if directory.max_concurrent_calls() == 0 {
        return Err(ConfigError::Invalid(
            "auth.directory.max_concurrent_calls must be greater than zero".to_string(),
        ));
    }
    if directory.memory_limit_bytes() == 0 {
        return Err(ConfigError::Invalid(
            "auth.directory.memory_limit_bytes must be greater than zero".to_string(),
        ));
    }

    if !directory.enabled {
        return Ok(());
    }

    require_directory_field(
        "auth.directory.component_path",
        directory.component_path.as_deref(),
    )?;
    require_directory_field(
        "auth.directory.component_sha256",
        directory.component_sha256.as_deref(),
    )?;
    require_directory_field(
        "auth.directory.base_origin",
        directory.base_origin.as_deref(),
    )?;
    require_directory_field(
        "auth.directory.api_token_file",
        directory.api_token_file.as_deref(),
    )?;

    directory.resolve_component_path(config_dir)?;
    directory.resolve_api_token_file(config_dir)?;
    directory.resolve_tls_ca_file(config_dir)?;

    validate_component_sha256(directory.component_sha256.as_deref().unwrap_or_default())?;
    let scheme = validate_base_origin(directory.base_origin.as_deref().unwrap_or_default())?;
    validate_directory_tls_config(directory, scheme)?;

    Ok(())
}

fn require_directory_field(field: &str, value: Option<&str>) -> Result<(), ConfigError> {
    match value {
        Some(value) if !value.trim().is_empty() => Ok(()),
        _ => Err(ConfigError::Invalid(format!(
            "{field} is required when auth.directory.enabled is true"
        ))),
    }
}

fn validate_component_sha256(value: &str) -> Result<(), ConfigError> {
    let digest = value.strip_prefix("sha256:").ok_or_else(|| {
        ConfigError::Invalid(
            "auth.directory.component_sha256 must be sha256:<64 lowercase hex>".to_string(),
        )
    })?;

    if digest.len() != 64
        || !digest
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(ConfigError::Invalid(
            "auth.directory.component_sha256 must be sha256:<64 lowercase hex>".to_string(),
        ));
    }

    Ok(())
}

fn validate_base_origin(value: &str) -> Result<DirectoryBaseOriginScheme, ConfigError> {
    if value != value.trim() || value.is_empty() {
        return Err(ConfigError::Invalid(
            "auth.directory.base_origin must be an http:// or https:// origin".to_string(),
        ));
    }
    if value.contains('#') {
        return Err(ConfigError::Invalid(
            "auth.directory.base_origin must not include a fragment".to_string(),
        ));
    }
    let Some((_, authority_text)) = value.split_once("://") else {
        return Err(ConfigError::Invalid(
            "auth.directory.base_origin must be an http:// or https:// origin".to_string(),
        ));
    };
    if authority_text.is_empty() || authority_text.contains('/') || authority_text.contains('?') {
        return Err(ConfigError::Invalid(
            "auth.directory.base_origin must not include a path or query".to_string(),
        ));
    }

    let uri = value.parse::<http::Uri>().map_err(|err| {
        ConfigError::Invalid(format!(
            "auth.directory.base_origin is not a valid URI: {err}"
        ))
    })?;
    let scheme = match uri.scheme_str() {
        Some("http") => DirectoryBaseOriginScheme::Http,
        Some("https") => DirectoryBaseOriginScheme::Https,
        _ => {
            return Err(ConfigError::Invalid(
                "auth.directory.base_origin must use http:// or https://".to_string(),
            ));
        }
    };
    let authority = uri.authority().ok_or_else(|| {
        ConfigError::Invalid("auth.directory.base_origin must include a host".to_string())
    })?;
    if authority.as_str().contains('@') {
        return Err(ConfigError::Invalid(
            "auth.directory.base_origin must not include userinfo".to_string(),
        ));
    }

    Ok(scheme)
}

fn validate_directory_tls_config(
    directory: &DirectoryConfig,
    scheme: DirectoryBaseOriginScheme,
) -> Result<(), ConfigError> {
    match scheme {
        DirectoryBaseOriginScheme::Http => {
            if directory.tls_insecure_skip_verify {
                return Err(ConfigError::Invalid(
                    "auth.directory.tls_insecure_skip_verify is only valid for https:// base_origin"
                        .to_string(),
                ));
            }
            if directory.tls_ca_file.is_some() {
                return Err(ConfigError::Invalid(
                    "auth.directory.tls_ca_file is only valid for https:// base_origin".to_string(),
                ));
            }
        }
        DirectoryBaseOriginScheme::Https => {
            if directory.tls_insecure_skip_verify && directory.tls_ca_file.is_some() {
                return Err(ConfigError::Invalid(
                    "auth.directory.tls_ca_file and auth.directory.tls_insecure_skip_verify are mutually exclusive"
                        .to_string(),
                ));
            }
        }
    }

    Ok(())
}
