use super::principal::{PrincipalKind, ProviderQualifiedId, stable_group_ids};

#[derive(Debug, Clone, PartialEq, Eq)]
struct CedarEntityId {
    type_name: &'static str,
    id: String,
}

impl CedarEntityId {
    fn from_principal(id: &ProviderQualifiedId) -> Self {
        let type_name = match id.kind() {
            PrincipalKind::User => "User",
            PrincipalKind::Group => "Group",
        };
        Self {
            type_name,
            id: id.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cedar_entity_ids_use_provider_qualified_principals() {
        let user = ProviderQualifiedId::new("kanidm", PrincipalKind::User, "user-1").unwrap();
        let group = ProviderQualifiedId::new(
            "kanidm",
            PrincipalKind::Group,
            "550e8400-e29b-41d4-a716-446655440000",
        )
        .unwrap();

        assert_eq!(
            CedarEntityId::from_principal(&user),
            CedarEntityId {
                type_name: "User",
                id: "kanidm:user:user-1".to_string(),
            }
        );
        assert_eq!(
            CedarEntityId::from_principal(&group),
            CedarEntityId {
                type_name: "Group",
                id: "kanidm:group:550e8400-e29b-41d4-a716-446655440000".to_string(),
            }
        );
    }

    #[test]
    fn cedar_shadow_inputs_exclude_display_group_names() {
        let groups = vec![
            "550e8400-e29b-41d4-a716-446655440000".to_string(),
            "registry_admins".to_string(),
            "registry_admins@example.test".to_string(),
        ];
        let ids = stable_group_ids("kanidm", &groups)
            .into_iter()
            .map(|id| CedarEntityId::from_principal(&id))
            .collect::<Vec<_>>();

        assert_eq!(
            ids,
            vec![CedarEntityId {
                type_name: "Group",
                id: "kanidm:group:550e8400-e29b-41d4-a716-446655440000".to_string(),
            }]
        );
    }
}
