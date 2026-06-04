use crate::config::PermissionMapping;
use crate::error::OrbChrysaError;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OciAction {
    Pull,
    Push,
    Delete,
}

impl OciAction {
    pub fn from_method(method: &http::Method) -> Self {
        match *method {
            http::Method::GET | http::Method::HEAD => OciAction::Pull,
            http::Method::DELETE => OciAction::Delete,
            _ => OciAction::Push,
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
    ) -> Result<(), OrbChrysaError> {
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
        Err(OrbChrysaError::Denied(format!(
            "access denied for repository {}",
            repository
        )))
    }

    /// Check permissions using explicit scopes (for PAT tokens).
    pub fn check_scopes(
        &self,
        scopes: &[String],
        repository: &str,
        action: OciAction,
    ) -> Result<(), OrbChrysaError> {
        for scope in scopes {
            if let Some((repo_pattern, allowed_action)) = parse_scope(scope)
                && match_repository(&repo_pattern, repository)
                && action_matches(allowed_action, action)
            {
                return Ok(());
            }
        }
        Err(OrbChrysaError::Denied(format!(
            "access denied for repository {}",
            repository
        )))
    }
}

fn group_matches(configured: &str, user_group: &str) -> bool {
    if configured == user_group {
        return true;
    }
    !configured.contains('@')
        && user_group
            .split_once('@')
            .is_some_and(|(local_name, _domain)| local_name == configured)
}

pub(crate) fn parse_scope(scope: &str) -> Option<(String, OciAction)> {
    let parts: Vec<&str> = scope.splitn(4, ':').collect();
    if parts.len() < 3 || parts[0] != "repository" {
        return None;
    }
    let repo = parts[1..parts.len() - 1].join(":");
    let action_str = parts.last()?;
    let actions: Vec<&str> = action_str.split(',').collect();
    let action = if actions
        .iter()
        .any(|action| *action == "*" || *action == "delete")
    {
        OciAction::Delete
    } else if actions.contains(&"push") {
        OciAction::Push
    } else if actions.contains(&"pull") {
        OciAction::Pull
    } else {
        return None;
    };
    Some((repo, action))
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

fn action_matches(allowed: OciAction, requested: OciAction) -> bool {
    match (allowed, requested) {
        (OciAction::Delete, _) => true, // * or delete covers everything
        (OciAction::Push, OciAction::Push) => true,
        (OciAction::Push, OciAction::Pull) => true, // push implies pull
        (OciAction::Pull, OciAction::Pull) => true,
        _ => false,
    }
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
    fn parse_scope_push_pull() {
        assert_eq!(
            parse_scope("repository:foo:pull,push"),
            Some(("foo".to_string(), OciAction::Push))
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
    fn matches_group_spn_by_local_name() {
        let resolver = PermissionResolver::new(&[PermissionMapping {
            name: "admins".to_string(),
            groups: vec!["registry_admins".to_string()],
            scopes: vec!["repository:*:*".to_string()],
        }]);

        assert!(
            resolver
                .check(
                    &["registry_admins@localhost".to_string()],
                    "qa/test",
                    OciAction::Push
                )
                .is_ok()
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
}
