wit_bindgen::generate!({
    world: "directory-connector",
    path: "../../../wit",
});

struct Component;

impl Guest for Component {
    fn connector_info() -> ConnectorInfo {
        ConnectorInfo {
            name: "Fake Directory".to_string(),
            version: env!("CARGO_PKG_VERSION").to_string(),
            provider: "fake".to_string(),
            abi_version: "0.0.3".to_string(),
        }
    }

    fn search_principals(
        ctx: ConnectorContext,
        request: SearchRequest,
    ) -> Result<SearchResponse, DirectoryError> {
        ensure_fake_provider(&ctx)?;
        if request.limit == 0 {
            return Err(DirectoryError::InvalidQuery(
                "search limit must be positive".to_string(),
            ));
        }

        let query = match request.filter {
            SearchFilter::FreeText(query) => query,
            SearchFilter::ExactLocalId(local_id) => local_id,
        };

        if query == "emit-long-error" {
            return Err(DirectoryError::InvalidQuery(long_sensitive_error()));
        }

        let mut warnings = Vec::new();
        if query == "emit-warning" {
            warnings.push(DirectoryError::RateLimited(
                " retry later\r\nAuthorization: Bearer warning-token ".to_string(),
            ));
        }

        let principal = fake_user(&query);
        let next_cursor = request.cursor.is_none().then(|| "fake-page-2".to_string());

        Ok(SearchResponse {
            principals: vec![principal],
            next_cursor,
            warnings,
        })
    }

    fn resolve_principals(
        ctx: ConnectorContext,
        request: ResolveRequest,
    ) -> Result<ResolveResponse, DirectoryError> {
        ensure_fake_provider(&ctx)?;

        let results = request
            .refs
            .into_iter()
            .map(|r| match r.local_id.as_str() {
                "missing" => ResolveResult::NotFound(r),
                "fail" => ResolveResult::Failed(ResolveFailure {
                    ref_: r,
                    error: DirectoryError::UpstreamUnavailable(
                        " upstream failed\nAuthorization: Bearer resolve-token ".to_string(),
                    ),
                }),
                _ => ResolveResult::Found(fake_principal(r)),
            })
            .collect();

        Ok(ResolveResponse {
            results,
            warnings: Vec::new(),
        })
    }

    fn health(ctx: ConnectorContext) -> Result<HealthResponse, DirectoryError> {
        ensure_fake_provider(&ctx)?;
        Ok(HealthResponse {
            state: HealthState::Healthy,
            message: format!("fake connector healthy for {}", ctx.base_origin),
            checked_at_unix: 1_718_000_000,
        })
    }
}

fn ensure_fake_provider(ctx: &ConnectorContext) -> Result<(), DirectoryError> {
    if ctx.provider == "fake" {
        Ok(())
    } else {
        Err(DirectoryError::UnsupportedProvider(format!(
            "expected fake provider, got {}",
            ctx.provider
        )))
    }
}

fn fake_user(seed: &str) -> DirectoryPrincipal {
    fake_principal(PrincipalRef {
        kind: PrincipalKind::User,
        local_id: if seed.is_empty() {
            "alice".to_string()
        } else {
            seed.to_string()
        },
    })
}

fn fake_principal(ref_: PrincipalRef) -> DirectoryPrincipal {
    let display_name = match ref_.kind {
        PrincipalKind::User => format!("User {}", ref_.local_id),
        PrincipalKind::Group => format!("Group {}", ref_.local_id),
    };

    DirectoryPrincipal {
        ref_,
        display_name,
        display_hierarchy: vec!["Fake Directory".to_string()],
        login: Some("alice@example.test".to_string()),
        email: Some("alice@example.test".to_string()),
        description: Some("fixture principal".to_string()),
        status: PrincipalStatus::Active,
        fetched_at_unix: Some(1_718_000_000),
    }
}

fn long_sensitive_error() -> String {
    let repeated = "0123456789abcdef".repeat(80);
    format!(
        "  invalid query {repeated}\nAuthorization: Bearer secret-token\nhttps://kanidm.example.test/search?token=secret\nresponse body: {{\"secret\":\"value\"}}  "
    )
}

export!(Component);
