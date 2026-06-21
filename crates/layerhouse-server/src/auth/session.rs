use aes_gcm::aead::rand_core::RngCore;
use aes_gcm::aead::{Aead, OsRng};
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use serde::{Deserialize, Serialize};

use crate::error::LayerhouseError;

#[derive(Debug, Serialize, Deserialize)]
pub struct DashboardSession {
    pub subject: String,
    pub principal: String,
    pub username: Option<String>,
    pub display_name: Option<String>,
    pub email: Option<String>,
    pub groups: Vec<String>,
    #[serde(default)]
    pub group_ids: Vec<String>,
    pub expires_at: u64,
}

impl DashboardSession {
    pub fn encrypt(&self, key: &[u8; 32]) -> Result<String, LayerhouseError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
        let mut nonce_bytes = [0u8; 12];
        OsRng.fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let plaintext =
            serde_json::to_vec(self).map_err(|e| LayerhouseError::Serialization(e.to_string()))?;

        let ciphertext = cipher
            .encrypt(nonce, plaintext.as_ref())
            .map_err(|e| LayerhouseError::Internal(format!("encryption failed: {}", e)))?;

        let mut result = nonce_bytes.to_vec();
        result.extend_from_slice(&ciphertext);
        Ok(base64::Engine::encode(
            &base64::engine::general_purpose::STANDARD,
            &result,
        ))
    }

    pub fn decrypt(encrypted: &str, key: &[u8; 32]) -> Result<Self, LayerhouseError> {
        let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));

        let data = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, encrypted)
            .map_err(|e| LayerhouseError::Internal(format!("base64 decode failed: {}", e)))?;

        if data.len() < 12 {
            return Err(LayerhouseError::Internal(
                "invalid session data".to_string(),
            ));
        }

        let (nonce_bytes, ciphertext) = data.split_at(12);
        let nonce = Nonce::from_slice(nonce_bytes);

        let plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|_| LayerhouseError::Internal("session decryption failed".to_string()))?;

        serde_json::from_slice(&plaintext)
            .map_err(|e| LayerhouseError::Serialization(e.to_string()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::auth::principal::{PrincipalKind, ProviderQualifiedId};

    #[test]
    fn encrypt_decrypt_round_trip() {
        let key = [42u8; 32];
        let principal = ProviderQualifiedId::new("kanidm", PrincipalKind::User, "user:1")
            .unwrap()
            .to_string();
        let group = ProviderQualifiedId::new(
            "kanidm",
            PrincipalKind::Group,
            "550e8400-e29b-41d4-a716-446655440000",
        )
        .unwrap()
        .to_string();
        let session = DashboardSession {
            subject: "user-1".into(),
            principal,
            username: Some("admin".into()),
            display_name: Some("Admin".into()),
            email: Some("admin@test.local".into()),
            groups: vec!["registry_admins".into()],
            group_ids: vec![group],
            expires_at: 1717200000,
        };

        let encrypted = session.encrypt(&key).unwrap();
        let decrypted = DashboardSession::decrypt(&encrypted, &key).unwrap();

        assert_eq!(decrypted.subject, session.subject);
        assert_eq!(decrypted.principal, session.principal);
        assert_eq!(decrypted.username, session.username);
        assert_eq!(decrypted.email, session.email);
        assert_eq!(decrypted.groups, session.groups);
        assert_eq!(decrypted.group_ids, session.group_ids);
        assert_eq!(decrypted.expires_at, session.expires_at);
    }

    #[test]
    fn decrypt_wrong_key_fails() {
        let session = DashboardSession {
            subject: "user-1".into(),
            principal: "kanidm:user:user-1".into(),
            username: None,
            display_name: None,
            email: None,
            groups: vec![],
            group_ids: vec![],
            expires_at: 1,
        };

        let encrypted = session.encrypt(&[1u8; 32]).unwrap();
        let result = DashboardSession::decrypt(&encrypted, &[2u8; 32]);
        assert!(result.is_err());
    }

    #[test]
    fn cookie_size_under_4096_bytes() {
        let key = [42u8; 32];
        // Representative claims: long-ish subject/email, multiple groups.
        let session = DashboardSession {
            subject: "a1b2c3d4-e5f6-7890-abcd-ef1234567890".into(),
            principal: "kanidm:user:a1b2c3d4-e5f6-7890-abcd-ef1234567890".into(),
            username: Some("adamcavendish".into()),
            display_name: Some("Adam Cavendish".into()),
            email: Some("adam.cavendish@modest-destiny.com".into()),
            groups: vec![
                "layerhouse_admins".into(),
                "layerhouse_developers".into(),
                "qa/auth-test/developers".into(),
            ],
            group_ids: vec![],
            expires_at: 1717200000,
        };

        let encrypted = session.encrypt(&key).unwrap();
        // "layerhouse_session=" + encrypted_value
        let cookie_value = format!("layerhouse_session={}", encrypted);
        assert!(
            cookie_value.len() < 4096,
            "session cookie must be under 4096 bytes, got {}",
            cookie_value.len()
        );
    }
}
