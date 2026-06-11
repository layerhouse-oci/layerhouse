//! Handle and repository-path grammar validators.
//!
//! Layerhouse repository paths are always at least two segments:
//! `<handle>/<name>[/<sub>...]`. The leading segment ("handle") names a
//! namespace owner and follows GitHub-style grammar:
//!   - 3..=39 chars
//!   - lowercase ASCII alnum and single dashes
//!   - regex equivalent: `[a-z0-9](?:-[a-z0-9])*`
//!
//! Reserved-handle gating lives elsewhere — this module only enforces grammar
//! so it can be reused by both the route layer and the apply layer.

#![allow(dead_code)]

use crate::error::LayerhouseError;

const HANDLE_MIN_LEN: usize = 3;
const HANDLE_MAX_LEN: usize = 39;

/// Validate that `s` is a syntactically well-formed handle.
///
/// Grammar: `[a-z0-9](?:-[a-z0-9])*`, 3..=39 chars total. No consecutive
/// dashes, no leading/trailing dash.
pub fn validate_handle(s: &str) -> Result<(), LayerhouseError> {
    if s.len() < HANDLE_MIN_LEN || s.len() > HANDLE_MAX_LEN {
        return Err(LayerhouseError::Internal(format!(
            "handle {s:?} has invalid length: must be {HANDLE_MIN_LEN}..={HANDLE_MAX_LEN} chars"
        )));
    }
    let bytes = s.as_bytes();
    let mut prev_dash = false;
    for (idx, &b) in bytes.iter().enumerate() {
        let is_alnum = b.is_ascii_lowercase() || b.is_ascii_digit();
        let is_dash = b == b'-';
        if !is_alnum && !is_dash {
            return Err(LayerhouseError::Internal(format!(
                "handle {s:?} contains illegal character {:?}",
                b as char
            )));
        }
        if idx == 0 && is_dash {
            return Err(LayerhouseError::Internal(format!(
                "handle {s:?} cannot start with a dash"
            )));
        }
        if idx == bytes.len() - 1 && is_dash {
            return Err(LayerhouseError::Internal(format!(
                "handle {s:?} cannot end with a dash"
            )));
        }
        if is_dash && prev_dash {
            return Err(LayerhouseError::Internal(format!(
                "handle {s:?} cannot contain consecutive dashes"
            )));
        }
        prev_dash = is_dash;
    }
    Ok(())
}

/// Validate that `s` is a well-formed repository path: two-or-more
/// `<segment>` parts joined by `/`. Each segment is non-empty and matches the
/// OCI subset Layerhouse accepts: lowercase alnum plus `-`, `_`, `.`. The
/// leading segment additionally satisfies [`validate_handle`].
pub fn validate_repository_path(s: &str) -> Result<(), LayerhouseError> {
    if s.is_empty() {
        return Err(LayerhouseError::Internal(
            "repository path is empty".to_string(),
        ));
    }
    if s.starts_with('/') || s.ends_with('/') {
        return Err(LayerhouseError::Internal(format!(
            "repository path {s:?} cannot start or end with '/'"
        )));
    }
    if s.contains("//") {
        return Err(LayerhouseError::Internal(format!(
            "repository path {s:?} contains an empty segment"
        )));
    }
    let mut segments = s.split('/');
    let first = segments.next().expect("split on non-empty input");
    validate_handle(first)?;
    let mut had_more = false;
    for seg in segments {
        had_more = true;
        validate_path_segment(seg)?;
    }
    if !had_more {
        return Err(LayerhouseError::Internal(format!(
            "repository path {s:?} requires at least two segments (<handle>/<name>)"
        )));
    }
    Ok(())
}

fn validate_path_segment(seg: &str) -> Result<(), LayerhouseError> {
    if seg.is_empty() {
        return Err(LayerhouseError::Internal(
            "repository path contains an empty segment".to_string(),
        ));
    }
    for &b in seg.as_bytes() {
        let ok =
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'_' || b == b'.';
        if !ok {
            return Err(LayerhouseError::Internal(format!(
                "repository path segment {seg:?} contains illegal character {:?}",
                b as char
            )));
        }
    }
    Ok(())
}

/// Extract the leading handle from a validated repository path. Errors when
/// `repository` is a bare one-segment string (no `/`).
pub fn handle_of(repository: &str) -> Result<&str, LayerhouseError> {
    let (head, rest) = repository.split_once('/').ok_or_else(|| {
        LayerhouseError::Internal(format!(
            "repository {repository:?} is missing a namespace handle prefix"
        ))
    })?;
    if rest.is_empty() {
        return Err(LayerhouseError::Internal(format!(
            "repository {repository:?} is missing the name segment after the handle"
        )));
    }
    Ok(head)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn handle_accepts_valid_examples() {
        for s in ["alice", "alice-1", "apache-airflow", "a-b-c", "abc", "x9z"] {
            validate_handle(s).unwrap_or_else(|_| panic!("expected {s:?} to be valid"));
        }
    }

    #[test]
    fn handle_rejects_invalid_examples() {
        let bad = [
            ("Alice", "uppercase"),
            ("1", "too short"),
            ("ab", "too short"),
            ("--", "leading dash + consecutive"),
            ("a--b", "consecutive dashes"),
            ("-alice", "leading dash"),
            ("alice-", "trailing dash"),
            ("alice_1", "underscore"),
            ("alice.1", "dot"),
            ("alice 1", "space"),
            (&"a".repeat(40), "too long"),
        ];
        for (s, reason) in bad {
            assert!(
                validate_handle(s).is_err(),
                "expected {s:?} to be rejected ({reason})"
            );
        }
    }

    #[test]
    fn repository_path_accepts_valid_examples() {
        for s in [
            "alice/app",
            "alice/app/sub/leaf",
            "team-1/svc.api",
            "alice/sub_dir/v1",
        ] {
            validate_repository_path(s).unwrap_or_else(|_| panic!("expected {s:?} to be valid"));
        }
    }

    #[test]
    fn repository_path_rejects_invalid_examples() {
        let bad = [
            "alice",
            "alice/",
            "/alice/app",
            "alice//app",
            "Alice/app",
            "",
            "alice/APP",
            "alice/app!",
        ];
        for s in bad {
            assert!(
                validate_repository_path(s).is_err(),
                "expected {s:?} to be rejected"
            );
        }
    }

    #[test]
    fn handle_of_extracts_first_segment() {
        assert_eq!(handle_of("alice/app").unwrap(), "alice");
        assert_eq!(handle_of("alice/app/sub").unwrap(), "alice");
        assert_eq!(handle_of("team-1/svc/api/v2").unwrap(), "team-1");
    }

    #[test]
    fn handle_of_rejects_bare_handle_or_missing_name() {
        assert!(handle_of("alice").is_err());
        assert!(handle_of("alice/").is_err());
    }
}
