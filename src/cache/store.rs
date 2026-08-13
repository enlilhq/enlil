use bytes::Bytes;
use moka::future::Cache;
use std::time::Duration;

#[derive(Clone)]
pub struct CachedResponse {
    pub body: Bytes,
    pub content_type: String,
    /// blake3 hash of body for integrity validation (cache poisoning prevention)
    pub integrity_hash: String,
    /// What the upstream call that produced this body actually cost, in microdollars.
    ///
    /// Stored so a cache hit can report the real saving. The hit path used to add a flat
    /// `4000` microdollars — $0.004 — per hit and present the running total as a dollar figure
    /// on the dashboard. That number was invented: it had no relationship to the model, the
    /// token count, or the provider's pricing.
    pub cost_micro: u64,
    /// Tokens the original call consumed, for the same reason.
    pub total_tokens: u32,
}

impl CachedResponse {
    /// A cache entry with no recorded cost. Used where the cost is genuinely unknown — for
    /// example overwriting a corrupted entry — so a hit on it reports a saving of zero rather
    /// than a guess.
    pub fn new(body: Bytes, content_type: String) -> Self {
        Self::with_cost(body, content_type, 0, 0)
    }

    /// A cache entry that remembers what producing it cost.
    pub fn with_cost(
        body: Bytes,
        content_type: String,
        cost_micro: u64,
        total_tokens: u32,
    ) -> Self {
        let integrity_hash = blake3::hash(&body).to_hex().to_string();
        Self {
            body,
            content_type,
            integrity_hash,
            cost_micro,
            total_tokens,
        }
    }

    /// Validates the cached body hasn't been tampered with
    pub fn is_valid(&self) -> bool {
        blake3::hash(&self.body).to_hex().to_string() == self.integrity_hash
    }
}

#[derive(Clone)]
pub struct CacheManager {
    /// Maps a semantic hash string to the cached HTTP response
    store: Cache<String, CachedResponse>,
}

impl Default for CacheManager {
    fn default() -> Self {
        Self::new()
    }
}

impl CacheManager {
    pub fn new() -> Self {
        Self::new_with_config(900, 10_000)
    }

    pub fn new_with_config(ttl_secs: u64, max_capacity: u64) -> Self {
        let store = Cache::builder()
            .time_to_live(Duration::from_secs(ttl_secs))
            .max_capacity(max_capacity)
            .build();

        Self { store }
    }

    pub async fn get(&self, hash: &str) -> Option<CachedResponse> {
        self.store.get(hash).await
    }

    pub async fn insert(&self, hash: &str, response: CachedResponse) {
        self.store.insert(hash.to_string(), response).await;
    }
}
