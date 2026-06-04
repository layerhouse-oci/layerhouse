use crate::error::OrbChrysaError;

#[derive(Debug, Clone)]
pub struct OidcDiscovery {
    pub authorization_endpoint: String,
    pub token_endpoint: String,
    pub jwks_uri: String,
    pub end_session_endpoint: Option<String>,
}

impl OidcDiscovery {
    /// Fetch OIDC discovery document from `{issuer_url}/.well-known/openid-configuration`.
    ///
    /// `issuer_url` is the URL used to reach the IdP (may be an internal hostname).
    /// `public_base` is the public-facing base URL advertised to browsers — used to
    /// rewrite `token_endpoint` and `jwks_uri` back to the internal host so that
    /// server-to-server calls (token exchange, JWKS fetch) use the reachable address.
    pub(crate) async fn fetch_document(
        issuer_url: &str,
        tls_insecure: bool,
    ) -> Result<serde_json::Value, OrbChrysaError> {
        let discovery_url = format!(
            "{}/.well-known/openid-configuration",
            issuer_url.trim_end_matches('/')
        );

        let mut client_builder = aioduct::TokioClient::builder()
            .timeout(std::time::Duration::from_secs(10))
            .connect_timeout(std::time::Duration::from_secs(5));
        if tls_insecure {
            client_builder = client_builder.danger_accept_invalid_certs();
        }
        let client = client_builder
            .build()
            .map_err(|e| OrbChrysaError::Internal(format!("HTTP client build failed: {}", e)))?;

        let response = client
            .request(http::Method::GET, &discovery_url)
            .map_err(|e| {
                OrbChrysaError::Internal(format!("discovery request build failed: {}", e))
            })?
            .send()
            .await
            .map_err(|e| OrbChrysaError::Internal(format!("discovery fetch failed: {}", e)))?;

        let body = response
            .text()
            .await
            .map_err(|e| OrbChrysaError::Internal(format!("discovery read failed: {}", e)))?;

        serde_json::from_str(&body)
            .map_err(|e| OrbChrysaError::Internal(format!("discovery parse failed: {}", e)))
    }

    pub(crate) fn from_document(
        doc: &serde_json::Value,
        issuer_url: &str,
        public_base: &str,
    ) -> Result<Self, OrbChrysaError> {
        let authorization_endpoint = doc["authorization_endpoint"]
            .as_str()
            .ok_or_else(|| {
                OrbChrysaError::Internal("discovery missing authorization_endpoint".to_string())
            })?
            .to_string();

        // token_endpoint and jwks_uri are used server-to-server — rewrite their
        // host to the internal issuer host so they are reachable from the container.
        let token_endpoint = rewrite_base(
            doc["token_endpoint"].as_str().ok_or_else(|| {
                OrbChrysaError::Internal("discovery missing token_endpoint".to_string())
            })?,
            public_base,
            issuer_url,
        );

        let jwks_uri = rewrite_base(
            doc["jwks_uri"].as_str().ok_or_else(|| {
                OrbChrysaError::Internal("discovery missing jwks_uri".to_string())
            })?,
            public_base,
            issuer_url,
        );

        let end_session_endpoint = doc["end_session_endpoint"]
            .as_str()
            .map(ToString::to_string);

        tracing::info!(
            authorization_endpoint,
            token_endpoint,
            jwks_uri,
            end_session_endpoint = end_session_endpoint.as_deref().unwrap_or("none"),
            "OIDC discovery complete"
        );

        Ok(Self {
            authorization_endpoint,
            token_endpoint,
            jwks_uri,
            end_session_endpoint,
        })
    }
}

/// Replace the scheme+host+port prefix of `url` from `from_base` to `to_base`.
/// Extracts just the scheme+host+port from each base before comparing.
/// If `url` doesn't start with the extracted prefix, return it unchanged.
fn rewrite_base(url: &str, from_base: &str, to_base: &str) -> String {
    let from_origin = extract_origin(from_base);
    let to_origin = extract_origin(to_base);
    if let Some(rest) = url.strip_prefix(from_origin.as_str()) {
        format!("{}{}", to_origin, rest)
    } else {
        url.to_string()
    }
}

/// Extract scheme+host+port from a URL, e.g.
/// "https://localhost:8443/oauth2/openid/orb-chrysa" → "https://localhost:8443"
fn extract_origin(url: &str) -> String {
    // Find the end of scheme (after "://")
    let after_scheme = url.find("://").map(|i| i + 3).unwrap_or(0);
    // Find the next "/" after the host
    let path_start = url[after_scheme..]
        .find('/')
        .map(|i| i + after_scheme)
        .unwrap_or(url.len());
    url[..path_start].to_string()
}

#[cfg(test)]
mod tests {
    use super::{extract_origin, rewrite_base};

    #[test]
    fn extracts_origin_from_full_issuer_url() {
        assert_eq!(
            extract_origin("https://localhost:8443/oauth2/openid/orb-chrysa"),
            "https://localhost:8443"
        );
        assert_eq!(
            extract_origin("https://idp.internal:8443/oauth2/openid/orb-chrysa"),
            "https://idp.internal:8443"
        );
        assert_eq!(
            extract_origin("https://localhost:8443"),
            "https://localhost:8443"
        );
    }

    #[test]
    fn rewrites_public_origin_to_internal() {
        assert_eq!(
            rewrite_base(
                "https://localhost:8443/oauth2/token",
                "https://localhost:8443/oauth2/openid/orb-chrysa",
                "https://idp.internal:8443/oauth2/openid/orb-chrysa"
            ),
            "https://idp.internal:8443/oauth2/token"
        );
        assert_eq!(
            rewrite_base(
                "https://localhost:8443/oauth2/openid/orb-chrysa/public_key.jwk",
                "https://localhost:8443/oauth2/openid/orb-chrysa",
                "https://idp.internal:8443/oauth2/openid/orb-chrysa"
            ),
            "https://idp.internal:8443/oauth2/openid/orb-chrysa/public_key.jwk"
        );
    }

    #[test]
    fn leaves_unmatched_url_unchanged() {
        assert_eq!(
            rewrite_base(
                "https://other:8443/oauth2/token",
                "https://localhost:8443/oauth2/openid/orb-chrysa",
                "https://idp.internal:8443/oauth2/openid/orb-chrysa"
            ),
            "https://other:8443/oauth2/token"
        );
    }
}
