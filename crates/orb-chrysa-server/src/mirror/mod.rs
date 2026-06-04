pub mod client;
pub mod scheduler;

use std::collections::HashMap;
use std::sync::Arc;

use futures::StreamExt;
use tokio::sync::Mutex;
use tokio::sync::RwLock;
use tokio_util::io::ReaderStream;

use crate::error::OrbChrysaError;
use crate::oci::digest::Digest;
use crate::oci::manifest;
use crate::store::blob::BlobStore;
#[allow(unused_imports)]
use crate::store::metadata::{
    ManifestEntry, ManifestStore, MirrorConfigStore, MirrorDirection, MirrorRule, MirrorStrategy,
    ProxyCache, RegistryStore, WarmFilter, now_epoch,
};

use client::{
    UpstreamClient, UpstreamRef, extract_blob_descriptors, extract_child_manifests,
    is_index_manifest,
};

const RULES_CACHE_TTL_SECS: u64 = 30;

pub struct ResolvedMirrorJob {
    pub direction: MirrorDirection,
    pub local_repo: String,
    pub tags: Vec<String>,
}

pub struct MirrorManager {
    client: UpstreamClient,
    inflight: Mutex<HashMap<String, Arc<tokio::sync::Notify>>>,
    rules_cache: RwLock<(Vec<MirrorRule>, tokio::time::Instant)>,
    proxy_cache: RwLock<(Vec<ProxyCache>, tokio::time::Instant)>,
}

impl MirrorManager {
    pub fn new() -> Self {
        Self {
            client: UpstreamClient::new(),
            inflight: Mutex::new(HashMap::new()),
            rules_cache: RwLock::new((Vec::new(), tokio::time::Instant::now())),
            proxy_cache: RwLock::new((Vec::new(), tokio::time::Instant::now())),
        }
    }

    /// Clear the proxy cache so the next pull-through sees the latest config.
    /// Call after put/delete on proxy caches.
    pub async fn invalidate_proxy_cache(&self) {
        self.proxy_cache.write().await.0.clear();
    }

    /// Clear the rules cache so the next pull-through sees the latest config.
    /// Call after put/delete on mirror rules.
    pub async fn invalidate_rules_cache(&self) {
        self.rules_cache.write().await.0.clear();
    }

    fn make_upstream_ref(rule: &MirrorRule, upstream_repo: &str) -> UpstreamRef {
        UpstreamRef::new(
            &rule.upstream_registry,
            upstream_repo,
            rule.plain_http,
            rule.insecure_tls,
            rule.outbound_proxy.clone(),
            rule.username.clone(),
            rule.password.clone(),
        )
    }

    fn make_proxy_upstream_ref(cache: &ProxyCache, upstream_repo: &str) -> UpstreamRef {
        UpstreamRef::new(
            &cache.upstream_registry,
            upstream_repo,
            cache.plain_http,
            cache.insecure_tls,
            cache.outbound_proxy.clone(),
            cache.username.clone(),
            cache.password.clone(),
        )
    }

    fn default_mirror_upstream_repo(rule: &MirrorRule) -> String {
        rule.upstream_prefix
            .clone()
            .unwrap_or_else(|| rule.local_prefix.clone())
    }

    fn default_proxy_upstream_repo(cache: &ProxyCache) -> String {
        cache
            .upstream_prefix
            .clone()
            .unwrap_or_else(|| cache.local_prefix.clone())
    }

    fn match_rule<'a>(
        rules: &'a [MirrorRule],
        repo_name: &str,
    ) -> Option<(&'a MirrorRule, String)> {
        let mut best: Option<(&MirrorRule, String)> = None;
        for rule in rules {
            if rule.direction != MirrorDirection::Pull {
                continue;
            }
            if let Some(suffix) = Self::prefix_suffix(repo_name, &rule.local_prefix) {
                let upstream_repo = if let Some(ref prefix) = rule.upstream_prefix {
                    if suffix.is_empty() {
                        prefix.clone()
                    } else {
                        format!("{}/{}", prefix, suffix)
                    }
                } else if suffix.is_empty() {
                    continue;
                } else {
                    suffix.to_string()
                };
                if best
                    .as_ref()
                    .map(|(existing, _)| rule.local_prefix.len() > existing.local_prefix.len())
                    .unwrap_or(true)
                {
                    best = Some((rule, upstream_repo));
                }
            }
        }
        best
    }

    fn match_proxy_cache<'a>(
        caches: &'a [ProxyCache],
        repo_name: &str,
    ) -> Option<(&'a ProxyCache, String)> {
        let mut best: Option<(&ProxyCache, String)> = None;
        for cache in caches {
            if let Some(suffix) = Self::prefix_suffix(repo_name, &cache.local_prefix) {
                let upstream_repo = if let Some(ref prefix) = cache.upstream_prefix {
                    if suffix.is_empty() {
                        prefix.clone()
                    } else {
                        format!("{}/{}", prefix, suffix)
                    }
                } else if suffix.is_empty() {
                    continue;
                } else {
                    suffix.to_string()
                };
                if best
                    .as_ref()
                    .map(|(existing, _)| cache.local_prefix.len() > existing.local_prefix.len())
                    .unwrap_or(true)
                {
                    best = Some((cache, upstream_repo));
                }
            }
        }
        best
    }

    fn prefix_suffix<'a>(repo_name: &'a str, prefix: &str) -> Option<&'a str> {
        if repo_name == prefix {
            return Some("");
        }
        repo_name
            .strip_prefix(prefix)
            .and_then(|suffix| suffix.strip_prefix('/'))
    }
    #[allow(dead_code)]
    async fn dedup_acquire(&self, key: &str) -> bool {
        let mut inflight = self.inflight.lock().await;
        if inflight.contains_key(key) {
            let notify = inflight.get(key).unwrap().clone();
            drop(inflight);
            notify.notified().await;
            return true;
        }
        inflight.insert(key.to_string(), Arc::new(tokio::sync::Notify::new()));
        false
    }

    #[allow(dead_code)]
    async fn dedup_finish(&self, key: &str) {
        if let Some(notify) = self.inflight.lock().await.remove(key) {
            notify.notify_waiters();
        }
    }

    fn glob_matches(pattern: &str, value: &str) -> bool {
        if pattern == "*" {
            return true;
        }
        if !pattern.contains('*') {
            return pattern == value;
        }
        let parts: Vec<&str> = pattern.split('*').filter(|p| !p.is_empty()).collect();
        if parts.is_empty() {
            return true;
        }
        if !pattern.starts_with('*') && !value.starts_with(parts[0]) {
            return false;
        }

        let mut rest = value;
        for part in &parts {
            let Some(idx) = rest.find(part) else {
                return false;
            };
            rest = &rest[idx + part.len()..];
        }

        if !pattern.ends_with('*')
            && let Some(last) = parts.last()
        {
            return value.ends_with(last);
        }
        true
    }

    async fn latest_tags(
        &self,
        upstream: &UpstreamRef,
        count: u32,
    ) -> Result<Vec<String>, OrbChrysaError> {
        let mut tags = self.client.list_tags(upstream).await?;
        tags.sort();
        tags.reverse();
        tags.truncate(count as usize);
        Ok(tags)
    }

    async fn resolve_mirror_strategy_tags(
        &self,
        strategy: &MirrorStrategy,
        upstream: &UpstreamRef,
    ) -> Result<Vec<String>, OrbChrysaError> {
        match strategy {
            MirrorStrategy::All => self.client.list_tags(upstream).await,
            MirrorStrategy::Latest { count } => self.latest_tags(upstream, *count).await,
            MirrorStrategy::Pattern { pattern } => {
                let tags = self.client.list_tags(upstream).await?;
                Ok(tags
                    .into_iter()
                    .filter(|tag| Self::glob_matches(pattern, tag))
                    .collect())
            }
        }
    }

    async fn resolve_local_strategy_tags<M: ManifestStore + MirrorConfigStore>(
        strategy: &MirrorStrategy,
        local_repo: &str,
        metadata: &M,
    ) -> Result<Vec<String>, OrbChrysaError> {
        match strategy {
            MirrorStrategy::All => metadata.list_tags(local_repo, None, None).await,
            MirrorStrategy::Latest { count } => {
                let summaries = metadata.list_manifest_summaries(local_repo).await?;
                let mut tagged = Vec::new();
                for summary in summaries {
                    for tag in summary.tags {
                        tagged.push((tag, summary.last_modified));
                    }
                }
                tagged.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
                tagged.truncate(*count as usize);
                Ok(tagged.into_iter().map(|(tag, _)| tag).collect())
            }
            MirrorStrategy::Pattern { pattern } => {
                let tags = metadata.list_tags(local_repo, None, None).await?;
                Ok(tags
                    .into_iter()
                    .filter(|tag| Self::glob_matches(pattern, tag))
                    .collect())
            }
        }
    }

    async fn resolve_warm_filter_tags(
        &self,
        filters: &[WarmFilter],
        upstream: &UpstreamRef,
    ) -> Result<Vec<String>, OrbChrysaError> {
        let mut selected = std::collections::BTreeSet::new();
        let mut all_tags: Option<Vec<String>> = None;

        for filter in filters {
            match filter {
                WarmFilter::None => {}
                WarmFilter::All => {
                    let tags = match &all_tags {
                        Some(tags) => tags.clone(),
                        None => {
                            let tags = self.client.list_tags(upstream).await?;
                            all_tags = Some(tags.clone());
                            tags
                        }
                    };
                    selected.extend(tags);
                }
                WarmFilter::Latest { count, .. } => {
                    selected.extend(self.latest_tags(upstream, *count).await?);
                }
                WarmFilter::Pattern { pattern } => {
                    let tags = match &all_tags {
                        Some(tags) => tags.clone(),
                        None => {
                            let tags = self.client.list_tags(upstream).await?;
                            all_tags = Some(tags.clone());
                            tags
                        }
                    };
                    selected.extend(
                        tags.into_iter()
                            .filter(|tag| Self::glob_matches(pattern, tag)),
                    );
                }
            }
        }

        Ok(selected.into_iter().collect())
    }

    pub async fn resolve_mirror_job<M: ManifestStore + MirrorConfigStore>(
        &self,
        rule_id: &str,
        metadata: &M,
    ) -> Result<ResolvedMirrorJob, OrbChrysaError> {
        let Some(rule) = metadata.get_mirror_rule(rule_id).await? else {
            return Err(OrbChrysaError::NameUnknown(rule_id.to_string()));
        };

        if rule.direction == MirrorDirection::Push {
            let tags =
                Self::resolve_local_strategy_tags(&rule.strategy, &rule.local_prefix, metadata)
                    .await?;
            return Ok(ResolvedMirrorJob {
                direction: MirrorDirection::Push,
                local_repo: rule.local_prefix,
                tags,
            });
        }

        let upstream_repo = Self::default_mirror_upstream_repo(&rule);
        let upstream = Self::make_upstream_ref(&rule, &upstream_repo);
        let tags = self
            .resolve_mirror_strategy_tags(&rule.strategy, &upstream)
            .await?;
        // Force-refresh so subsequent per-tag manifest pulls see this rule.
        self.invalidate_rules_cache().await;
        Ok(ResolvedMirrorJob {
            direction: MirrorDirection::Pull,
            local_repo: rule.local_prefix,
            tags,
        })
    }

    pub async fn resolve_proxy_cache_job<M: ManifestStore + MirrorConfigStore>(
        &self,
        cache_id: &str,
        metadata: &M,
    ) -> Result<(String, Vec<String>), OrbChrysaError> {
        let Some(cache) = metadata.get_proxy_cache(cache_id).await? else {
            return Err(OrbChrysaError::NameUnknown(cache_id.to_string()));
        };
        let upstream_repo = Self::default_proxy_upstream_repo(&cache);
        let upstream = Self::make_proxy_upstream_ref(&cache, &upstream_repo);
        tracing::info!(
            "warm: listing tags for {}://{}/v2/{}/tags/list (local prefix: {})",
            upstream.scheme,
            upstream.registry,
            upstream.repository,
            cache.local_prefix,
        );
        let tags = self
            .resolve_warm_filter_tags(&cache.warm_filters, &upstream)
            .await?;
        tracing::info!(
            "warm: resolved {} tags for cache {} (will pull as local repo {})",
            tags.len(),
            cache_id,
            cache.local_prefix,
        );
        // Force-refresh so subsequent per-tag manifest pulls see this cache.
        self.invalidate_proxy_cache().await;
        Ok((cache.local_prefix, tags))
    }

    async fn get_rules<M: ManifestStore + MirrorConfigStore>(
        &self,
        metadata: &M,
    ) -> Result<Vec<MirrorRule>, OrbChrysaError> {
        {
            let cache = self.rules_cache.read().await;
            if !cache.0.is_empty() && cache.1.elapsed().as_secs() < RULES_CACHE_TTL_SECS {
                return Ok(cache.0.clone());
            }
        }

        let rules = metadata.list_mirror_rules().await?;
        let mut cache = self.rules_cache.write().await;
        *cache = (rules.clone(), tokio::time::Instant::now());
        Ok(rules)
    }

    async fn get_proxy_caches<M: ManifestStore + MirrorConfigStore>(
        &self,
        metadata: &M,
    ) -> Result<Vec<ProxyCache>, OrbChrysaError> {
        {
            let cache = self.proxy_cache.read().await;
            if !cache.0.is_empty() && cache.1.elapsed().as_secs() < RULES_CACHE_TTL_SECS {
                return Ok(cache.0.clone());
            }
        }

        let caches = metadata.list_proxy_caches().await?;
        let mut cache = self.proxy_cache.write().await;
        *cache = (caches.clone(), tokio::time::Instant::now());
        Ok(caches)
    }

    pub async fn pull_manifest<M: RegistryStore, B: BlobStore>(
        &self,
        repo_name: &str,
        reference: &str,
        metadata: &M,
        blobs: &B,
    ) -> Result<Option<ManifestEntry>, OrbChrysaError> {
        if let Some(result) = self
            .pull_manifest_from_proxy_cache(repo_name, reference, metadata, blobs)
            .await?
        {
            return Ok(Some(result));
        }

        let result = self
            .pull_manifest_from_mirror_rule(repo_name, reference, metadata, blobs)
            .await?;
        if result.is_none() {
            tracing::warn!(
                "pull_manifest: no match for {}:{} (not in proxy cache or mirror rules)",
                repo_name,
                reference,
            );
        }
        Ok(result)
    }

    async fn pull_manifest_from_proxy_cache<M: RegistryStore, B: BlobStore>(
        &self,
        repo_name: &str,
        reference: &str,
        metadata: &M,
        blobs: &B,
    ) -> Result<Option<ManifestEntry>, OrbChrysaError> {
        let caches = self.get_proxy_caches(metadata).await?;
        let Some((cache, upstream_repo)) = Self::match_proxy_cache(&caches, repo_name) else {
            return Ok(None);
        };

        let dedup_key = format!("proxy-cache:{}:{}", repo_name, reference);

        {
            let mut inflight = self.inflight.lock().await;
            if let Some(notify) = inflight.get(&dedup_key) {
                let notify = notify.clone();
                drop(inflight);
                notify.notified().await;
                return metadata.get_manifest(repo_name, reference).await;
            }
            let notify = Arc::new(tokio::sync::Notify::new());
            inflight.insert(dedup_key.clone(), notify);
        }

        let upstream = Self::make_proxy_upstream_ref(cache, &upstream_repo);
        let result = self
            .do_pull(repo_name, reference, &upstream, metadata, blobs)
            .await;

        let notify = self.inflight.lock().await.remove(&dedup_key);
        if let Some(notify) = notify {
            notify.notify_waiters();
        }

        result
    }

    async fn pull_manifest_from_mirror_rule<M: RegistryStore, B: BlobStore>(
        &self,
        repo_name: &str,
        reference: &str,
        metadata: &M,
        blobs: &B,
    ) -> Result<Option<ManifestEntry>, OrbChrysaError> {
        let rules = self.get_rules(metadata).await?;

        if rules.is_empty() {
            return Ok(None);
        }

        let Some((rule, upstream_repo)) = Self::match_rule(&rules, repo_name) else {
            return Ok(None);
        };

        let dedup_key = format!("{}:{}", repo_name, reference);

        {
            let mut inflight = self.inflight.lock().await;
            if let Some(notify) = inflight.get(&dedup_key) {
                let notify = notify.clone();
                drop(inflight);
                notify.notified().await;
                return metadata.get_manifest(repo_name, reference).await;
            }
            let notify = Arc::new(tokio::sync::Notify::new());
            inflight.insert(dedup_key.clone(), notify.clone());
        }

        let upstream = Self::make_upstream_ref(rule, &upstream_repo);
        let result = self
            .do_pull(repo_name, reference, &upstream, metadata, blobs)
            .await;

        let notify = self.inflight.lock().await.remove(&dedup_key);
        if let Some(notify) = notify {
            notify.notify_waiters();
        }

        result
    }

    pub async fn pull_blob<M: RegistryStore, B: BlobStore>(
        &self,
        repo_name: &str,
        digest: &Digest,
        metadata: &M,
        blobs: &B,
    ) -> Result<bool, OrbChrysaError> {
        if self
            .pull_blob_from_proxy_cache(repo_name, digest, metadata, blobs)
            .await?
        {
            return Ok(true);
        }

        self.pull_blob_from_mirror_rule(repo_name, digest, metadata, blobs)
            .await
    }

    async fn pull_blob_from_proxy_cache<M: RegistryStore, B: BlobStore>(
        &self,
        repo_name: &str,
        digest: &Digest,
        metadata: &M,
        blobs: &B,
    ) -> Result<bool, OrbChrysaError> {
        let caches = self.get_proxy_caches(metadata).await?;
        let Some((cache, upstream_repo)) = Self::match_proxy_cache(&caches, repo_name) else {
            return Ok(false);
        };

        let dedup_key = format!("proxy-cache:blob:{}:{}", repo_name, digest);

        {
            let mut inflight = self.inflight.lock().await;
            if let Some(notify) = inflight.get(&dedup_key) {
                let notify = notify.clone();
                drop(inflight);
                notify.notified().await;
                return Ok(blobs.stat(digest).await.is_ok());
            }
            let notify = Arc::new(tokio::sync::Notify::new());
            inflight.insert(dedup_key.clone(), notify);
        }

        let upstream = Self::make_proxy_upstream_ref(cache, &upstream_repo);
        let result = self.do_pull_blob(digest, &upstream, blobs).await;

        let notify = self.inflight.lock().await.remove(&dedup_key);
        if let Some(notify) = notify {
            notify.notify_waiters();
        }

        result.map(|()| true)
    }

    async fn pull_blob_from_mirror_rule<M: RegistryStore, B: BlobStore>(
        &self,
        repo_name: &str,
        digest: &Digest,
        metadata: &M,
        blobs: &B,
    ) -> Result<bool, OrbChrysaError> {
        let rules = self.get_rules(metadata).await?;
        if rules.is_empty() {
            return Ok(false);
        }

        let Some((rule, upstream_repo)) = Self::match_rule(&rules, repo_name) else {
            return Ok(false);
        };

        let dedup_key = format!("blob:{}", digest);

        {
            let mut inflight = self.inflight.lock().await;
            if let Some(notify) = inflight.get(&dedup_key) {
                let notify = notify.clone();
                drop(inflight);
                notify.notified().await;
                return Ok(blobs.stat(digest).await.is_ok());
            }
            let notify = Arc::new(tokio::sync::Notify::new());
            inflight.insert(dedup_key.clone(), notify);
        }

        let upstream = Self::make_upstream_ref(rule, &upstream_repo);
        let result = self.do_pull_blob(digest, &upstream, blobs).await;

        let notify = self.inflight.lock().await.remove(&dedup_key);
        if let Some(notify) = notify {
            notify.notify_waiters();
        }

        result.map(|()| true)
    }

    async fn do_pull_blob<B: BlobStore>(
        &self,
        digest: &Digest,
        upstream: &UpstreamRef,
        blobs: &B,
    ) -> Result<(), OrbChrysaError> {
        self.client.ensure_auth(upstream).await?;
        let digest_str = digest.to_string();
        let resp = self.client.get_blob(upstream, &digest_str).await?;
        let body_stream = resp.into_bytes_stream();
        let stream: crate::store::blob::ByteStream =
            Box::pin(futures::stream::unfold(body_stream, |mut s| async move {
                let chunk = s.next().await?;
                Some((
                    chunk.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
                    s,
                ))
            }));
        blobs.put_streaming(digest, stream).await?;
        tracing::info!(
            "mirror: pulled blob {}",
            &digest_str[..19.min(digest_str.len())]
        );
        Ok(())
    }

    async fn do_pull<M: RegistryStore, B: BlobStore>(
        &self,
        repo_name: &str,
        reference: &str,
        upstream: &UpstreamRef,
        metadata: &M,
        blobs: &B,
    ) -> Result<Option<ManifestEntry>, OrbChrysaError> {
        self.client.ensure_auth(upstream).await?;

        let upstream_head = self.client.head_manifest(upstream, reference).await?;
        let Some((upstream_digest, _)) = upstream_head else {
            tracing::warn!(
                "upstream manifest not found: {}/{}:{} ({}://{}/v2/{}/manifests/{})",
                upstream.registry,
                upstream.repository,
                reference,
                upstream.scheme,
                upstream.registry,
                upstream.repository,
                reference,
            );
            return Ok(None);
        };

        if let Ok(Some(local)) = metadata.get_manifest(repo_name, reference).await
            && local.digest.to_string() == upstream_digest
        {
            return Ok(Some(local));
        }

        let manifest_data = self.client.get_manifest(upstream, reference).await?;
        self.store_manifest_recursive(
            repo_name,
            reference,
            &manifest_data,
            upstream,
            metadata,
            blobs,
        )
        .await?;

        metadata.get_manifest(repo_name, reference).await
    }

    async fn store_manifest_recursive<M: RegistryStore, B: BlobStore>(
        &self,
        repo_name: &str,
        reference: &str,
        manifest_data: &client::ManifestData,
        upstream: &UpstreamRef,
        metadata: &M,
        blobs: &B,
    ) -> Result<(), OrbChrysaError> {
        let parsed: serde_json::Value = serde_json::from_slice(&manifest_data.body)
            .map_err(|e| OrbChrysaError::Upstream(format!("invalid manifest JSON: {}", e)))?;

        if is_index_manifest(&manifest_data.content_type) {
            let children = extract_child_manifests(&parsed);
            for child in &children {
                if metadata
                    .get_manifest(repo_name, &child.digest)
                    .await
                    .ok()
                    .flatten()
                    .is_some()
                {
                    continue;
                }

                let child_manifest = self.client.get_manifest(upstream, &child.digest).await?;
                Box::pin(self.store_manifest_recursive(
                    repo_name,
                    &child.digest,
                    &child_manifest,
                    upstream,
                    metadata,
                    blobs,
                ))
                .await?;
            }
        } else {
            let blob_descs = extract_blob_descriptors(&parsed);
            self.pull_blobs(&blob_descs, upstream, blobs).await?;
        }

        let digest = Digest::sha256(&manifest_data.body);
        let referenced_blobs = manifest::extract_referenced_digests(&parsed);

        let entry = ManifestEntry::from_parsed_json(
            &parsed,
            manifest_data.content_type.clone(),
            manifest_data.body.clone(),
            referenced_blobs,
        );

        metadata
            .put_manifest(repo_name, reference, entry.clone())
            .await?;

        let digest_ref = digest.to_string();
        if reference != digest_ref {
            metadata.put_manifest(repo_name, &digest_ref, entry).await?;
        }

        tracing::info!(
            "mirror: stored manifest {} for {}/{}",
            &digest.to_string()[..19.min(digest.to_string().len())],
            repo_name,
            reference
        );

        Ok(())
    }

    async fn pull_blobs<B: BlobStore>(
        &self,
        blob_descs: &[client::BlobDescriptor],
        upstream: &UpstreamRef,
        blob_store: &B,
    ) -> Result<(), OrbChrysaError> {
        for blob in blob_descs {
            let digest_str = blob.digest.clone();
            let Some(digest) = Digest::from_str_checked(&digest_str) else {
                tracing::warn!("mirror: skipping invalid digest: {}", digest_str);
                continue;
            };

            if blob_store.stat(&digest).await.is_ok() {
                continue;
            }

            let resp = self.client.get_blob(upstream, &digest_str).await?;
            let body_stream = resp.into_bytes_stream();
            let stream: crate::store::blob::ByteStream =
                Box::pin(futures::stream::unfold(body_stream, |mut s| async move {
                    let chunk = s.next().await?;
                    Some((
                        chunk.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>),
                        s,
                    ))
                }));
            blob_store.put_streaming(&digest, stream).await?;
            tracing::info!(
                "mirror: stored blob {}",
                &digest_str[..19.min(digest_str.len())]
            );
        }

        Ok(())
    }

    pub async fn push_manifest_for_rule<M: RegistryStore, B: BlobStore>(
        &self,
        rule_id: &str,
        reference: &str,
        metadata: &M,
        blobs: &B,
    ) -> Result<bool, OrbChrysaError> {
        let Some(rule) = metadata.get_mirror_rule(rule_id).await? else {
            return Err(OrbChrysaError::NameUnknown(rule_id.to_string()));
        };
        if rule.direction != MirrorDirection::Push {
            return Err(OrbChrysaError::NameInvalid(format!(
                "mirror rule {} is not a push rule",
                rule_id
            )));
        }

        let Some(entry) = metadata.get_manifest(&rule.local_prefix, reference).await? else {
            return Ok(false);
        };

        let upstream_repo = Self::default_mirror_upstream_repo(&rule);
        let upstream = Self::make_upstream_ref(&rule, &upstream_repo);
        self.client.ensure_push_auth(&upstream).await?;
        self.push_manifest_recursive(
            &rule.local_prefix,
            reference,
            &entry,
            &upstream,
            metadata,
            blobs,
        )
        .await?;
        Ok(true)
    }

    async fn push_manifest_recursive<M: RegistryStore, B: BlobStore>(
        &self,
        repo_name: &str,
        reference: &str,
        entry: &ManifestEntry,
        upstream: &UpstreamRef,
        metadata: &M,
        blobs: &B,
    ) -> Result<(), OrbChrysaError> {
        let parsed: serde_json::Value = serde_json::from_slice(&entry.body).map_err(|e| {
            OrbChrysaError::ManifestInvalid(format!("invalid manifest JSON: {}", e))
        })?;

        if is_index_manifest(&entry.content_type) {
            for child in extract_child_manifests(&parsed) {
                let child_entry = metadata
                    .get_manifest(repo_name, &child.digest)
                    .await?
                    .ok_or_else(|| OrbChrysaError::ManifestUnknown(child.digest.clone()))?;
                Box::pin(self.push_manifest_recursive(
                    repo_name,
                    &child.digest,
                    &child_entry,
                    upstream,
                    metadata,
                    blobs,
                ))
                .await?;
            }
        } else {
            let blob_descs = extract_blob_descriptors(&parsed);
            self.push_blobs(&blob_descs, upstream, blobs).await?;
        }

        self.client
            .put_manifest(upstream, reference, &entry.body, &entry.content_type)
            .await?;
        tracing::info!(
            "mirror: pushed manifest {} for {}:{}",
            &entry.digest.to_string()[..19.min(entry.digest.to_string().len())],
            repo_name,
            reference
        );
        Ok(())
    }

    async fn push_blobs<B: BlobStore>(
        &self,
        blob_descs: &[client::BlobDescriptor],
        upstream: &UpstreamRef,
        blobs: &B,
    ) -> Result<(), OrbChrysaError> {
        for blob in blob_descs {
            let Some(digest) = Digest::from_str_checked(&blob.digest) else {
                tracing::warn!("mirror: skipping invalid digest: {}", blob.digest);
                continue;
            };

            if self.client.head_blob(upstream, &blob.digest).await? {
                continue;
            }

            let info = blobs.stat(&digest).await?;
            let local = blobs.get(&digest).await?;
            let stream: crate::store::blob::ByteStream = match local {
                crate::store::blob::BlobStream::S3(output) => Box::pin(
                    ReaderStream::new(output.body.into_async_read()).map(|chunk| {
                        chunk.map_err(|e| Box::new(e) as Box<dyn std::error::Error + Send + Sync>)
                    }),
                ),
                #[cfg(test)]
                crate::store::blob::BlobStream::Memory(stream) => stream,
            };

            self.client
                .push_blob_stream(upstream, &blob.digest, info.size, stream)
                .await?;
            tracing::info!(
                "mirror: pushed blob {}",
                &blob.digest[..19.min(blob.digest.len())]
            );
        }

        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::store::blob::BlobStore;
    use crate::store::metadata::{
        InMemoryMetadataStore, ManifestStore, MirrorConfigStore, OutboundProxy, SyncJobKind,
        SyncJobStatus, mirror_rule_job,
    };
    use axum::body::Body;
    use axum::extract::State;
    use axum::http::{HeaderMap, StatusCode};
    use axum::response::IntoResponse;
    use axum::routing::{head, post, put};
    use bytes::Bytes;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use tokio::sync::Mutex as TokioMutex;

    fn manifest_entry(body: &[u8], last_modified: u64) -> ManifestEntry {
        ManifestEntry {
            digest: Digest::sha256(body),
            content_type: "application/vnd.oci.image.manifest.v1+json".to_string(),
            body: body.to_vec(),
            referenced_blobs: serde_json::from_slice::<serde_json::Value>(body)
                .map(|value| manifest::extract_referenced_digests(&value))
                .unwrap_or_default(),
            subject: None,
            artifact_type: None,
            annotations: None,
            size_bytes: body.len() as u64,
            created_at: last_modified,
            last_modified,
            config_summary: None,
        }
    }

    #[tokio::test]
    async fn resolves_push_mirror_latest_from_local_tags() {
        let manager = MirrorManager::new();
        let metadata = InMemoryMetadataStore::default();

        metadata
            .put_mirror_rule(MirrorRule {
                id: "push-api".to_string(),
                direction: MirrorDirection::Push,
                local_prefix: "platform/api".to_string(),
                upstream_registry: "upstream.local".to_string(),
                upstream_prefix: Some("prod/api".to_string()),
                schedule: None,
                strategy: MirrorStrategy::Latest { count: 1 },
                plain_http: true,
                insecure_tls: false,
                outbound_proxy: OutboundProxy::default(),
                username: None,
                password: None,
                created_at: 1,
            })
            .await
            .expect("put rule");
        metadata
            .put_manifest(
                "platform/api",
                "old",
                manifest_entry(br#"{"schemaVersion":2,"name":"old"}"#, 10),
            )
            .await
            .expect("put old manifest");
        metadata
            .put_manifest(
                "platform/api",
                "new",
                manifest_entry(br#"{"schemaVersion":2,"name":"new"}"#, 20),
            )
            .await
            .expect("put new manifest");

        let resolved = manager
            .resolve_mirror_job("push-api", &metadata)
            .await
            .expect("resolve push mirror");

        assert_eq!(resolved.direction, MirrorDirection::Push);
        assert_eq!(resolved.local_repo, "platform/api");
        assert_eq!(resolved.tags, vec!["new"]);
    }

    #[test]
    fn push_direction_is_part_of_scheduled_mirror_job_metadata() {
        let job = mirror_rule_job(
            &MirrorRule {
                id: "push-api".to_string(),
                direction: MirrorDirection::Push,
                local_prefix: "platform/api".to_string(),
                upstream_registry: "upstream.local".to_string(),
                upstream_prefix: Some("prod/api".to_string()),
                schedule: Some("*/30 * * * *".to_string()),
                strategy: MirrorStrategy::All,
                plain_http: true,
                insecure_tls: false,
                outbound_proxy: OutboundProxy::default(),
                username: None,
                password: None,
                created_at: 1,
            },
            "mirror-rule-push-api".to_string(),
            10,
            1_800,
        );

        assert_eq!(job.kind, SyncJobKind::Mirror);
        assert_eq!(job.status, SyncJobStatus::Idle);
        assert_eq!(job.rule_id.as_deref(), Some("push-api"));
        assert_eq!(job.tags, vec!["all"]);
    }

    #[derive(Clone, Default)]
    struct PushCapture {
        manifest_seen: Arc<AtomicBool>,
        upload_started: Arc<AtomicUsize>,
        blob_bodies: Arc<TokioMutex<Vec<Bytes>>>,
        manifest_bodies: Arc<TokioMutex<Vec<Bytes>>>,
    }

    async fn start_push_registry() -> (String, PushCapture) {
        let capture = PushCapture::default();
        let app = axum::Router::new()
            .route("/v2/", axum::routing::get(|| async { StatusCode::OK }))
            .route(
                "/v2/prod/api/blobs/sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                head(|| async { StatusCode::NOT_FOUND }),
            )
            .route(
                "/v2/prod/api/blobs/uploads/",
                post(|State(capture): State<PushCapture>| async move {
                    let id = capture.upload_started.fetch_add(1, Ordering::SeqCst) + 1;
                    (
                        StatusCode::ACCEPTED,
                        [("Location", format!("/v2/prod/api/blobs/uploads/{id}"))],
                    )
                        .into_response()
                }),
            )
            .route(
                "/v2/prod/api/blobs/uploads/{id}",
                put(
                    |State(capture): State<PushCapture>, _headers: HeaderMap, body: Body| async move {
                        let bytes = axum::body::to_bytes(body, 1024 * 1024)
                            .await
                            .expect("blob body");
                        capture.blob_bodies.lock().await.push(bytes);
                        StatusCode::CREATED
                    },
                ),
            )
            .route(
                "/v2/prod/api/manifests/latest",
                put(|State(capture): State<PushCapture>, body: Body| async move {
                    let bytes = axum::body::to_bytes(body, 1024 * 1024)
                        .await
                        .expect("manifest body");
                    capture.manifest_seen.store(true, Ordering::SeqCst);
                    capture.manifest_bodies.lock().await.push(bytes);
                    StatusCode::CREATED
                }),
            )
            .with_state(capture.clone());

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind test registry");
        let addr = listener.local_addr().expect("registry addr");
        tokio::spawn(async move {
            axum::serve(listener, app)
                .await
                .expect("serve test registry");
        });

        (addr.to_string(), capture)
    }

    #[tokio::test]
    async fn push_manifest_for_rule_uploads_blob_and_manifest() {
        let (registry, capture) = start_push_registry().await;
        let manager = MirrorManager::new();
        let metadata = InMemoryMetadataStore::default();
        let blob_digest = "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let manifest = format!(
            r#"{{
                "schemaVersion": 2,
                "config": {{
                    "mediaType": "application/vnd.oci.image.config.v1+json",
                    "digest": "{blob_digest}",
                    "size": 0
                }},
                "layers": []
            }}"#
        );

        metadata
            .put_mirror_rule(MirrorRule {
                id: "push-api".to_string(),
                direction: MirrorDirection::Push,
                local_prefix: "platform/api".to_string(),
                upstream_registry: registry,
                upstream_prefix: Some("prod/api".to_string()),
                schedule: None,
                strategy: MirrorStrategy::All,
                plain_http: true,
                insecure_tls: false,
                outbound_proxy: OutboundProxy::default(),
                username: None,
                password: None,
                created_at: 1,
            })
            .await
            .expect("put rule");
        metadata
            .put_manifest(
                "platform/api",
                "latest",
                manifest_entry(manifest.as_bytes(), 20),
            )
            .await
            .expect("put manifest");
        let blob_store = crate::store::blob::InMemoryBlobStore::default();
        blob_store
            .put_streaming(
                &Digest::from_str_checked(blob_digest).expect("valid digest"),
                Box::pin(futures::stream::iter(vec![Ok::<
                    _,
                    Box<dyn std::error::Error + Send + Sync>,
                >(Bytes::new())])),
            )
            .await
            .expect("put empty config blob");

        let pushed = manager
            .push_manifest_for_rule("push-api", "latest", &metadata, &blob_store)
            .await
            .expect("push manifest");

        assert!(pushed);
        assert_eq!(capture.upload_started.load(Ordering::SeqCst), 1);
        assert!(capture.manifest_seen.load(Ordering::SeqCst));
        assert_eq!(capture.blob_bodies.lock().await.len(), 1);
        assert_eq!(capture.blob_bodies.lock().await[0], Bytes::new());
        assert_eq!(capture.manifest_bodies.lock().await.len(), 1);
    }
}
