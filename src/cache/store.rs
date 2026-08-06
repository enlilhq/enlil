use moka::future::Cache;
use std::time::Duration;
use bytes::Bytes;

#[derive(Clone)]
pub struct CachedResponse {
    pub body: Bytes,
    pub content_type: String,
    /// blake3 hash of body for integrity validation (cache poisoning prevention)
    pub integrity_hash: String,
}

impl CachedResponse {
    pub fn new(body: Bytes, content_type: String) -> Self {
        let integrity_hash = blake3::hash(&body).to_hex().to_string();
        Self { body, content_type, integrity_hash }
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
