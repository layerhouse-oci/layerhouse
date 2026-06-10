use crate::oci::digest::Digest;
use std::collections::BTreeMap;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SizedDescriptor {
    pub digest: Digest,
    pub size: u64,
}

pub fn is_manifest_media_type(media_type: &str) -> bool {
    matches!(
        media_type,
        "application/vnd.oci.image.manifest.v1+json"
            | "application/vnd.oci.image.index.v1+json"
            | "application/vnd.oci.artifact.manifest.v1+json"
            | "application/vnd.docker.distribution.manifest.v2+json"
            | "application/vnd.docker.distribution.manifest.list.v2+json"
    )
}

pub fn extract_referenced_digests(value: &serde_json::Value) -> Vec<Digest> {
    let mut digests = Vec::new();

    if let Some(config) = value.get("config")
        && let Some(d) = descriptor_digest(config)
    {
        digests.push(d);
    }

    if let Some(layers) = value.get("layers").and_then(|l| l.as_array()) {
        for layer in layers {
            if let Some(d) = descriptor_digest(layer) {
                digests.push(d);
            }
        }
    }

    if let Some(blobs) = value.get("blobs").and_then(|b| b.as_array()) {
        for blob in blobs {
            if let Some(d) = descriptor_digest(blob) {
                digests.push(d);
            }
        }
    }

    digests
}

pub fn extract_sized_referenced_descriptors(value: &serde_json::Value) -> Vec<SizedDescriptor> {
    let mut descriptors = Vec::new();

    if let Some(config) = value.get("config")
        && let Some(descriptor) = sized_descriptor(config)
    {
        descriptors.push(descriptor);
    }

    if let Some(layers) = value.get("layers").and_then(|l| l.as_array()) {
        for layer in layers {
            if let Some(descriptor) = sized_descriptor(layer) {
                descriptors.push(descriptor);
            }
        }
    }

    if let Some(blobs) = value.get("blobs").and_then(|b| b.as_array()) {
        for blob in blobs {
            if let Some(descriptor) = sized_descriptor(blob) {
                descriptors.push(descriptor);
            }
        }
    }

    descriptors
}

pub fn stored_size_bytes(value: &serde_json::Value) -> u64 {
    stored_size_from_descriptors(extract_sized_referenced_descriptors(value))
}

pub fn stored_size_from_descriptors<I>(descriptors: I) -> u64
where
    I: IntoIterator<Item = SizedDescriptor>,
{
    let mut by_digest: BTreeMap<String, u64> = BTreeMap::new();
    for descriptor in descriptors {
        by_digest
            .entry(descriptor.digest.to_string())
            .and_modify(|size| *size = (*size).max(descriptor.size))
            .or_insert(descriptor.size);
    }
    by_digest.values().sum()
}

fn descriptor_digest(value: &serde_json::Value) -> Option<Digest> {
    let digest = value.get("digest")?.as_str()?;
    Digest::from_str_checked(digest)
}

fn sized_descriptor(value: &serde_json::Value) -> Option<SizedDescriptor> {
    Some(SizedDescriptor {
        digest: descriptor_digest(value)?,
        size: value.get("size")?.as_u64()?,
    })
}

pub fn extract_subject_digest(value: &serde_json::Value) -> Option<Digest> {
    let digest_str = value.get("subject")?.get("digest")?.as_str()?;
    Digest::from_str_checked(digest_str)
}

pub fn extract_artifact_type(value: &serde_json::Value) -> Option<String> {
    if let Some(at) = value.get("artifactType").and_then(|v| v.as_str()) {
        return Some(at.to_string());
    }
    let config_mt = value.get("config")?.get("mediaType")?.as_str()?;
    if config_mt != "application/vnd.oci.empty.v1+json" {
        return Some(config_mt.to_string());
    }
    None
}

pub fn extract_annotations(value: &serde_json::Value) -> Option<serde_json::Value> {
    value.get("annotations").cloned()
}

pub fn extract_config_summary(manifest: &serde_json::Value) -> Option<serde_json::Value> {
    let mut summary = serde_json::Map::new();

    if let Some(config) = manifest.get("config").and_then(|v| v.as_object()) {
        if let Some(media_type) = config.get("mediaType").and_then(|v| v.as_str()) {
            summary.insert("mediaType".to_string(), media_type.into());
        }
        if let Some(digest) = config.get("digest").and_then(|v| v.as_str()) {
            summary.insert("config_digest".to_string(), digest.into());
        }
        if let Some(size) = config.get("size").and_then(|v| v.as_u64()) {
            summary.insert("config_size".to_string(), size.into());
        }
    }

    if let Some(layers) = manifest.get("layers").and_then(|v| v.as_array()) {
        summary.insert("layer_count".to_string(), layers.len().into());
        let total: u64 = layers
            .iter()
            .filter_map(|layer| layer.get("size").and_then(|v| v.as_u64()))
            .sum();
        summary.insert("layer_size_bytes".to_string(), total.into());
    }

    if let Some(blobs) = manifest.get("blobs").and_then(|v| v.as_array()) {
        summary.insert("blob_count".to_string(), blobs.len().into());
        let total: u64 = blobs
            .iter()
            .filter_map(|blob| blob.get("size").and_then(|v| v.as_u64()))
            .sum();
        summary.insert("blob_size_bytes".to_string(), total.into());
    }

    if let Some(manifests) = manifest.get("manifests").and_then(|v| v.as_array()) {
        summary.insert("manifest_count".to_string(), manifests.len().into());
        let platforms: Vec<serde_json::Value> = manifests
            .iter()
            .filter_map(|m| m.get("platform"))
            .cloned()
            .collect();
        if !platforms.is_empty() {
            summary.insert("platforms".to_string(), platforms.into());
        }
    }

    if let Some(artifact_type) = manifest.get("artifactType").and_then(|v| v.as_str()) {
        summary.insert("artifactType".to_string(), artifact_type.into());
    }

    if summary.is_empty() {
        None
    } else {
        Some(serde_json::Value::Object(summary))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn digest(id: u64) -> String {
        format!("sha256:{id:064x}")
    }

    #[test]
    fn stored_size_dedupes_config_and_layers_by_digest() {
        let shared = digest(1);
        let unique = digest(2);
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "config": {
                "mediaType": "application/vnd.oci.image.config.v1+json",
                "digest": shared,
                "size": 2
            },
            "layers": [
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": unique.clone(),
                    "size": 4
                },
                {
                    "mediaType": "application/vnd.oci.image.layer.v1.tar",
                    "digest": unique,
                    "size": 4
                }
            ]
        });

        assert_eq!(extract_sized_referenced_descriptors(&manifest).len(), 3);
        assert_eq!(stored_size_bytes(&manifest), 6);
    }

    #[test]
    fn stored_size_counts_oci_artifact_blobs() {
        let manifest = serde_json::json!({
            "mediaType": "application/vnd.oci.artifact.manifest.v1+json",
            "artifactType": "application/vnd.example.sbom",
            "blobs": [
                {
                    "mediaType": "application/vnd.example.sbom.layer",
                    "digest": digest(3),
                    "size": 10
                },
                {
                    "mediaType": "application/vnd.example.signature",
                    "digest": digest(4),
                    "size": 12
                }
            ]
        });

        assert_eq!(stored_size_bytes(&manifest), 22);
        assert_eq!(extract_referenced_digests(&manifest).len(), 2);
    }

    #[test]
    fn descriptorless_manifest_has_no_stored_payload_size() {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "annotations": {
                "example": "metadata-only"
            }
        });

        assert!(extract_sized_referenced_descriptors(&manifest).is_empty());
        assert_eq!(stored_size_bytes(&manifest), 0);
    }

    #[test]
    fn index_child_manifests_are_not_counted_as_stored_blobs() {
        let manifest = serde_json::json!({
            "schemaVersion": 2,
            "mediaType": "application/vnd.oci.image.index.v1+json",
            "manifests": [
                {
                    "mediaType": "application/vnd.oci.image.manifest.v1+json",
                    "digest": digest(5),
                    "size": 200
                }
            ]
        });

        assert_eq!(stored_size_bytes(&manifest), 0);
        assert!(extract_referenced_digests(&manifest).is_empty());
    }
}
