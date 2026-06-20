use crate::config::PermissionMapping;
use crate::error::LayerhouseError;

/// Where a permission grant came from. Used by the dashboard to explain
/// *why* a user can access (or grant access to) a repository.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantSource {
    /// Actor's own personal namespace — full access implicit.
    Personal,
    /// Available through OIDC group → RBAC mapping.
    GroupGrant,
    /// Anonymous pull; limited grant ceiling.
    Public,
}

/// Repository kind derived from manifest artifact types.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "snake_case")]
pub enum RepoKind {
    Image,
    Helm,
    Wasm,
    Artifact,
    Unknown,
}

/// Action ladder for repository access. Higher tiers imply all lower ones:
/// `Pull < Create < Update < Delete`. `Create` is "add a manifest/tag that
/// does not yet exist"; `Update` additionally allows overwriting an existing
/// tag. This is the single source of truth for the action model — verb
/// derivation, scope-string tokens, and the implication ladder all live here.
#[derive(
    Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, serde::Serialize, serde::Deserialize,
)]
#[serde(rename_all = "lowercase")]
pub enum OciAction {
    Pull,
    Create,
    Update,
    Delete,
}

impl OciAction {
    /// Base action implied by the HTTP method alone. Writes default to
    /// `Create`; the manifest-PUT overwrite case is upgraded to `Update` by
    /// the middleware after a manifest-existence lookup (it is not derivable
    /// from the method).
    pub fn from_method(method: &http::Method) -> Self {
        match *method {
            http::Method::GET | http::Method::HEAD => OciAction::Pull,
            http::Method::DELETE => OciAction::Delete,
            _ => OciAction::Create,
        }
    }

    /// Wire scope-string token for this action (`repository:<name>:<token>`).
    /// Used both to emit `WWW-Authenticate` challenge scopes and to label
    /// minted OCI bearer tokens. Spec-compliant clients echo the challenged
    /// scope back to `/v2/token`, so the token must name the exact action the
    /// request needs (e.g. a brand-new tag is challenged `create`, not
    /// `update`, so a create-only grant is sufficient).
    pub fn scope_token(self) -> &'static str {
        match self {
            OciAction::Pull => "pull",
            OciAction::Create => "create",
            OciAction::Update => "update",
            OciAction::Delete => "delete",
        }
    }
}

pub struct PermissionResolver {
    mappings: Vec<CompiledMapping>,
}

struct CompiledMapping {
    groups: Vec<String>,
    rules: Vec<(String, OciAction)>,
}

impl PermissionResolver {
    pub fn new(mappings: &[PermissionMapping]) -> Self {
        let compiled = mappings
            .iter()
            .map(|m| {
                let rules: Vec<(String, OciAction)> = m
                    .scopes
                    .iter()
                    .filter_map(|scope| parse_scope(scope))
                    .collect();
                CompiledMapping {
                    groups: m.groups.clone(),
                    rules,
                }
            })
            .collect();
        Self { mappings: compiled }
    }

    /// Check permissions using group membership (for OIDC tokens).
    pub fn check(
        &self,
        user_groups: &[String],
        repository: &str,
        action: OciAction,
    ) -> Result<(), LayerhouseError> {
        for mapping in &self.mappings {
            if mapping.groups.iter().any(|group| {
                user_groups
                    .iter()
                    .any(|user_group| group_matches(group, user_group))
            }) && mapping.rules.iter().any(|(repo_pattern, allowed_action)| {
                match_repository(repo_pattern, repository)
                    && action_matches(*allowed_action, action)
            }) {
                return Ok(());
            }
        }
        Err(LayerhouseError::Denied(format!(
            "access denied for repository {}",
            repository
        )))
    }

    /// Maximum action granted by group mappings for a repository.
    /// Returns `None` when no group grant covers the repository.
    pub fn max_action_from_groups(
        &self,
        user_groups: &[String],
        repository: &str,
    ) -> Option<OciAction> {
        let mut best: Option<OciAction> = None;
        for mapping in &self.mappings {
            if !mapping
                .groups
                .iter()
                .any(|group| user_groups.iter().any(|ug| group_matches(group, ug)))
            {
                continue;
            }
            for (repo_pattern, allowed_action) in &mapping.rules {
                if match_repository(repo_pattern, repository)
                    && action_matches(*allowed_action, OciAction::Pull)
                {
                    best = match best {
                        Some(current) if action_rank(*allowed_action) > action_rank(current) => {
                            Some(*allowed_action)
                        }
                        None => Some(*allowed_action),
                        _ => best,
                    };
                }
            }
        }
        best
    }
}

pub(crate) fn group_matches(configured: &str, user_group: &str) -> bool {
    configured == user_group
}

pub(crate) fn parse_scope(scope: &str) -> Option<(String, OciAction)> {
    let parts: Vec<&str> = scope.splitn(4, ':').collect();
    if parts.len() < 3 || parts[0] != "repository" {
        return None;
    }
    let repo = parts[1..parts.len() - 1].join(":");
    let action_str = parts.last()?;
    let action = action_str
        .split(',')
        .filter_map(parse_action_token)
        .max_by_key(|action| action_rank(*action))?;
    Some((repo, action))
}

pub(crate) fn matching_scope(
    scopes: &[String],
    repository: &str,
    action: OciAction,
) -> Option<(String, OciAction)> {
    scopes.iter().find_map(|scope| {
        let (repo_pattern, allowed_action) = parse_scope(scope)?;
        if match_repository(&repo_pattern, repository) && action_matches(allowed_action, action) {
            Some((repo_pattern, allowed_action))
        } else {
            None
        }
    })
}

/// Map a single scope-string token to its action. `*` is an alias for the
/// top of the ladder (`Delete`). Unknown tokens (including the legacy `push`,
/// which is intentionally not parsed) yield `None`.
fn parse_action_token(token: &str) -> Option<OciAction> {
    match token.trim() {
        "*" | "delete" => Some(OciAction::Delete),
        "update" => Some(OciAction::Update),
        "create" => Some(OciAction::Create),
        "pull" => Some(OciAction::Pull),
        _ => None,
    }
}

/// Ladder position: higher rank implies all lower actions.
pub fn action_rank(action: OciAction) -> u8 {
    match action {
        OciAction::Pull => 0,
        OciAction::Create => 1,
        OciAction::Update => 2,
        OciAction::Delete => 3,
    }
}

fn match_repository(pattern: &str, repo: &str) -> bool {
    if pattern == "*" {
        return true;
    }
    if let Some(prefix) = pattern.strip_suffix("/*") {
        return repo == prefix || repo.starts_with(&format!("{}/", prefix));
    }
    pattern == repo
}

/// A grant for `allowed` covers a request for `requested` when it sits at or
/// above the requested tier: `Delete ⊇ Update ⊇ Create ⊇ Pull`.
pub fn action_matches(allowed: OciAction, requested: OciAction) -> bool {
    action_rank(allowed) >= action_rank(requested)
}

/// Personal-namespace auto-grant: every authenticated user has full access
/// (any action) to repositories under `users/<their-username>/`. Returns true
/// when `username` is present and `repository` falls in that namespace. The
/// action is irrelevant — the personal namespace grants the whole ladder.
pub fn in_personal_namespace(username: Option<&str>, repository: &str) -> bool {
    let Some(username) = username.filter(|u| !u.is_empty()) else {
        return false;
    };
    let prefix = format!("users/{}/", username);
    repository.starts_with(&prefix)
}

/// If `repository` lives under the `users/` prefix, return the target username
/// (the segment immediately after `users/`). Returns `None` for paths outside
/// the personal-namespace tree.
pub fn in_personal_namespace_of(repository: &str) -> Option<&str> {
    let rest = repository.strip_prefix("users/")?;
    let username = rest.split('/').next()?;
    if username.is_empty() {
        None
    } else {
        Some(username)
    }
}

/// Validate that a PAT scope string doesn't target another user's personal
/// namespace. Scopes matching the identity's own `users/` namespace are
/// allowed; everything else is syntactically fine (the auth layer validates
/// actual permission at request time).
pub fn pat_scope_allowed_for_identity(
    scope: &str,
    username: Option<&str>,
) -> Result<(), LayerhouseError> {
    let Some((repo_pattern, _action)) = parse_scope(scope) else {
        // Unparseable scopes are caught later by the auth layer.
        return Ok(());
    };
    // Strip trailing `/*` so `in_personal_namespace_of("users/bob/*")` extracts
    // `"bob"` rather than `"bob*"`.
    let repo_pattern = repo_pattern.strip_suffix("/*").unwrap_or(&repo_pattern);
    let Some(target_user) = in_personal_namespace_of(repo_pattern) else {
        return Ok(());
    };
    let Some(my_username) = username.filter(|u| !u.is_empty()) else {
        return Err(LayerhouseError::Denied(format!(
            "scope {scope:?} targets a personal namespace but your session has no username"
        )));
    };
    if target_user != my_username {
        return Err(LayerhouseError::Denied(format!(
            "scope {scope:?} targets another user's personal namespace"
        )));
    }
    Ok(())
}

/// Maximum action an actor can perform on `repository` based solely on their
/// explicit scopes (PAT or OCI bearer). Returns `None` when no scope matches.
/// The caller is responsible for also checking personal-namespace and
/// namespace-claim owner grants.
pub fn max_action_from_scopes(scopes: &[String], repository: &str) -> Option<OciAction> {
    scopes
        .iter()
        .filter_map(|scope| parse_scope(scope))
        .filter(|(pattern, _)| match_repository(pattern, repository))
        .map(|(_, action)| action)
        .max_by_key(|a| action_rank(*a))
}

/// Check whether `identity` holds a grant pattern that would cover a
/// namespace-pattern scope like `repository:<prefix>/*`. Returns the
/// maximum grantable action for that pattern, if any.
pub fn max_action_for_namespace_pattern(scopes: &[String], prefix: &str) -> Option<OciAction> {
    let pattern_repo = format!("{prefix}/*");
    max_action_from_scopes(scopes, &pattern_repo)
}

/// Derive candidate namespace patterns from an identity's scopes for a given
/// search prefix. Returns patterns the actor can grant (e.g., `team-a/*` from
/// an RBAC mapping or PAT scope).
pub fn derive_namespace_patterns(
    scopes: &[String],
    search_prefix: &str,
) -> Vec<(String, OciAction)> {
    let mut patterns: Vec<(String, OciAction)> = Vec::new();
    for scope in scopes {
        if let Some((repo_pattern, action)) = parse_scope(scope)
            && let Some(prefix) = repo_pattern.strip_suffix("/*")
            && !prefix.is_empty()
            && prefix != "*"
            && (search_prefix.is_empty() || prefix.starts_with(search_prefix))
        {
            patterns.push((format!("repository:{prefix}/*"), action));
        }
    }
    patterns.sort();
    patterns.dedup();
    patterns
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_scope_pull() {
        assert_eq!(
            parse_scope("repository:foo:pull"),
            Some(("foo".to_string(), OciAction::Pull))
        );
    }

    #[test]
    fn parse_scope_create() {
        assert_eq!(
            parse_scope("repository:foo:pull,create"),
            Some(("foo".to_string(), OciAction::Create))
        );
    }

    #[test]
    fn parse_scope_keeps_highest_action() {
        // Comma-separated tokens resolve to the highest tier present.
        assert_eq!(
            parse_scope("repository:foo:pull,create,update"),
            Some(("foo".to_string(), OciAction::Update))
        );
    }

    #[test]
    fn parse_scope_wildcard() {
        assert_eq!(
            parse_scope("repository:foo:*"),
            Some(("foo".to_string(), OciAction::Delete))
        );
    }

    #[test]
    fn parse_scope_rejects_legacy_push() {
        // `push` is no longer a recognized token; a lone `push` yields nothing.
        assert_eq!(parse_scope("repository:foo:push"), None);
        // Mixed with a known token, only the known token survives.
        assert_eq!(
            parse_scope("repository:foo:pull,push"),
            Some(("foo".to_string(), OciAction::Pull))
        );
    }

    #[test]
    fn action_ladder_implications() {
        use OciAction::*;
        // Delete covers everything.
        for requested in [Pull, Create, Update, Delete] {
            assert!(action_matches(Delete, requested));
        }
        // Update covers all but Delete.
        assert!(action_matches(Update, Pull));
        assert!(action_matches(Update, Create));
        assert!(action_matches(Update, Update));
        assert!(!action_matches(Update, Delete));
        // Create covers Pull and Create only.
        assert!(action_matches(Create, Pull));
        assert!(action_matches(Create, Create));
        assert!(!action_matches(Create, Update));
        assert!(!action_matches(Create, Delete));
        // Pull covers only Pull.
        assert!(action_matches(Pull, Pull));
        assert!(!action_matches(Pull, Create));
        assert!(!action_matches(Pull, Update));
        assert!(!action_matches(Pull, Delete));
    }

    #[test]
    fn scope_token_round_trips_through_parser() {
        use OciAction::*;
        for action in [Pull, Create, Update, Delete] {
            let scope = format!("repository:foo:{}", action.scope_token());
            assert_eq!(parse_scope(&scope), Some(("foo".to_string(), action)));
        }
    }

    #[test]
    fn match_wildcard_repo() {
        assert!(match_repository("*", "anything"));
    }

    #[test]
    fn match_prefix_pattern() {
        assert!(match_repository("platform/*", "platform"));
        assert!(match_repository("platform/*", "platform/backend"));
        assert!(!match_repository("platform/*", "other"));
    }

    #[test]
    fn group_matching_is_exact_only() {
        let resolver = PermissionResolver::new(&[PermissionMapping {
            name: "admins".to_string(),
            groups: vec!["test:group:550e8400-e29b-41d4-a716-446655440010".to_string()],
            scopes: vec!["repository:*:*".to_string()],
        }]);

        assert!(
            resolver
                .check(
                    &["test:group:550e8400-e29b-41d4-a716-446655440010".to_string()],
                    "qa/test",
                    OciAction::Create
                )
                .is_ok()
        );
        assert!(
            resolver
                .check(
                    &["registry_admins@localhost".to_string()],
                    "qa/test",
                    OciAction::Create
                )
                .is_err()
        );
    }

    #[test]
    fn exact_group_spn_does_not_match_other_domains() {
        assert!(group_matches(
            "registry_admins@prod.example",
            "registry_admins@prod.example"
        ));
        assert!(!group_matches(
            "registry_admins@prod.example",
            "registry_admins@localhost"
        ));
    }

    #[test]
    fn personal_namespace_grants_own_prefix() {
        assert!(in_personal_namespace(Some("alice"), "users/alice/app"));
        assert!(in_personal_namespace(
            Some("alice"),
            "users/alice/nested/repo"
        ));
    }

    #[test]
    fn personal_namespace_rejects_other_users_and_missing_username() {
        // Another user's namespace is off-limits.
        assert!(!in_personal_namespace(Some("alice"), "users/bob/app"));
        // The bare `users/<name>` (no trailing slash) is not inside the
        // namespace — only `users/<name>/...` is.
        assert!(!in_personal_namespace(Some("alice"), "users/alice"));
        // A prefix collision (`alicia` vs `alice`) must not match.
        assert!(!in_personal_namespace(Some("alice"), "users/alicia/app"));
        // No username (anonymous / unpopulated) never grants.
        assert!(!in_personal_namespace(None, "users/alice/app"));
        assert!(!in_personal_namespace(Some(""), "users/alice/app"));
        // A repo outside the personal namespace is never auto-granted.
        assert!(!in_personal_namespace(Some("alice"), "team-a/app"));
    }

    #[test]
    fn in_personal_namespace_of_extracts_username() {
        assert_eq!(in_personal_namespace_of("users/alice/app"), Some("alice"));
        assert_eq!(
            in_personal_namespace_of("users/alice/nested/repo"),
            Some("alice")
        );
        assert_eq!(in_personal_namespace_of("users/alice"), Some("alice"));
        assert_eq!(in_personal_namespace_of("team-a/app"), None);
        assert_eq!(in_personal_namespace_of("users"), None);
        assert_eq!(in_personal_namespace_of("users/"), None);
        assert_eq!(in_personal_namespace_of(""), None);
    }

    #[test]
    fn pat_scope_allowed_rejects_cross_user_target() {
        let err = pat_scope_allowed_for_identity("repository:users/bob/app:*", Some("alice"))
            .expect_err("cross-user scope must be rejected");
        assert!(err.to_string().contains("personal namespace"), "{err:?}");

        // Own namespace is fine.
        pat_scope_allowed_for_identity("repository:users/alice/app:*", Some("alice"))
            .expect("own personal namespace scope is allowed");

        // Non-users scope is fine.
        pat_scope_allowed_for_identity("repository:team-a/*:*", Some("alice"))
            .expect("non-users scope is allowed");

        // Unparseable scope is fine (caught later).
        pat_scope_allowed_for_identity("bad-scope", Some("alice"))
            .expect("unparseable scope passes syntax check");

        // Missing username with a users/ scope.
        let err = pat_scope_allowed_for_identity("repository:users/bob/app:*", None)
            .expect_err("users/ scope without username must be rejected");
        assert!(err.to_string().contains("no username"), "{err:?}");
    }

    #[test]
    fn pat_scope_wildcard_own_namespace_allowed() {
        // A wildcard scope targeting `users/bob/*` is allowed when the
        // identity is `bob` — the `/*` suffix is stripped before username
        // extraction so we compare `"bob"` vs `"bob"`, not `"bob*"`.
        pat_scope_allowed_for_identity("repository:users/bob/*:*", Some("bob"))
            .expect("wildcard scope for own namespace is allowed");
    }

    #[test]
    fn pat_scope_prefix_collision_rejected() {
        // `alicia` is a prefix of `alice` but is a different user — the
        // scope must be rejected even though the strings share a prefix.
        let err = pat_scope_allowed_for_identity("repository:users/alicia/app:pull", Some("alice"))
            .expect_err("prefix-collision scope must be rejected");
        assert!(err.to_string().contains("personal namespace"), "{err:?}");
    }
}
