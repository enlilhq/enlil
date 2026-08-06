//! Deterministic replay / time-travel tracing.
//!
//! Every proxied request is assigned a `trace_id` (returned as the `x-trace-id`
//! response header) and recorded as a [`Trace`]: the governance decisions the proxy
//! made (protocol, loop-break, PII redaction, policy/injection verdicts, cache
//! disposition, failover), the final status/latency, and the token/cost outcome.
//!
//! The (post-redaction) request body is retained so an operator can **replay** the
//! exact request against the upstream and diff the fresh response against the original
//! — the foundation for time-travel debugging of an agent's decision path.
//!
//! Traces are held in a bounded in-memory store and are access-controlled + tenant-scoped
//! at the HTTP layer (see `routing::trace`). Authorization headers are deliberately NOT
//! persisted; a replay caller supplies their own upstream credentials.

use dashmap::DashMap;
use rusqlite::{params, Connection};
use serde::Serialize;
use std::collections::VecDeque;
use std::sync::Mutex;

#[cfg(feature = "lambda")]
pub mod dynamo;

/// Maximum number of traces retained in memory.
const TRACE_CAPACITY: usize = 500;
/// Cap on the retained request body (bytes) to bound memory.
const MAX_STORED_BODY: usize = 64 * 1024;
/// Cap on rows retained in the persistent store.
const TRACE_DB_CAPACITY: usize = 2000;

pub fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs()
}

/// A recorded request trace.
#[derive(Debug, Clone, Serialize)]
pub struct Trace {
    pub trace_id: String,
    pub timestamp: u64,
    pub tenant_id: String,
    pub session_id: String,
    pub agent_id: String,
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub upstream: String,
    /// Ordered log of governance decisions taken on the request path.
    pub steps: Vec<String>,
    pub cache: String,
    pub status: u16,
    pub blocked: bool,
    pub block_reason: Option<String>,
    pub latency_us: u64,
    pub total_tokens: u32,
    pub cost_microdollars: u64,
    /// blake3 of the original upstream response body (for replay diffing), if captured.
    pub response_hash: Option<String>,
    /// Effective upstream URI the request was (or would be) sent to. Used for replay.
    pub replay_uri: String,
    /// Post-redaction request body retained for replay. Never serialized in API responses.
    #[serde(skip)]
    pub replay_body: Vec<u8>,
    #[serde(skip)]
    pub replay_method: String,
}

impl Trace {
    /// Build a trace at request start; enriched as the request flows.
    #[allow(clippy::too_many_arguments)]
    pub fn start(
        trace_id: String,
        tenant_id: String,
        session_id: String,
        agent_id: String,
        method: String,
        path: String,
        protocol: String,
        upstream: String,
    ) -> Self {
        Trace {
            trace_id,
            timestamp: now_secs(),
            tenant_id,
            session_id,
            agent_id,
            method,
            path,
            protocol,
            upstream,
            steps: Vec::new(),
            cache: "n/a".to_string(),
            status: 0,
            blocked: false,
            block_reason: None,
            latency_us: 0,
            total_tokens: 0,
            cost_microdollars: 0,
            response_hash: None,
            replay_uri: String::new(),
            replay_body: Vec::new(),
            replay_method: "POST".to_string(),
        }
    }

    pub fn step(&mut self, msg: impl Into<String>) {
        self.steps.push(msg.into());
    }

    pub fn set_replay(&mut self, method: &str, uri: &str, body: &[u8]) {
        self.replay_method = method.to_string();
        self.replay_uri = uri.to_string();
        let n = body.len().min(MAX_STORED_BODY);
        self.replay_body = body[..n].to_vec();
    }
}

/// Non-body metadata for trace listings.
#[derive(Debug, Clone, Serialize)]
pub struct TraceSummary {
    pub trace_id: String,
    pub timestamp: u64,
    pub tenant_id: String,
    pub method: String,
    pub path: String,
    pub protocol: String,
    pub status: u16,
    pub blocked: bool,
    pub cache: String,
    pub latency_us: u64,
    pub total_tokens: u32,
    pub cost_microdollars: u64,
}

impl From<&Trace> for TraceSummary {
    fn from(t: &Trace) -> Self {
        TraceSummary {
            trace_id: t.trace_id.clone(),
            timestamp: t.timestamp,
            tenant_id: t.tenant_id.clone(),
            method: t.method.clone(),
            path: t.path.clone(),
            protocol: t.protocol.clone(),
            status: t.status,
            blocked: t.blocked,
            cache: t.cache.clone(),
            latency_us: t.latency_us,
            total_tokens: t.total_tokens,
            cost_microdollars: t.cost_microdollars,
        }
    }
}

/// Bounded, id-keyed store of recent traces.
pub struct TraceStore {
    traces: DashMap<String, Trace>,
    order: Mutex<VecDeque<String>>,
    /// Optional SQLite backing. Writes happen off the hot path via [`TraceStore::persist_snapshot`].
    db: Option<Mutex<Connection>>,
}

const TRACE_TABLE: &str = "CREATE TABLE IF NOT EXISTS traces (
    trace_id TEXT PRIMARY KEY,
    timestamp INTEGER NOT NULL,
    tenant_id TEXT,
    session_id TEXT,
    agent_id TEXT,
    method TEXT,
    path TEXT,
    protocol TEXT,
    upstream TEXT,
    steps TEXT,
    cache TEXT,
    status INTEGER,
    blocked INTEGER,
    block_reason TEXT,
    latency_us INTEGER,
    total_tokens INTEGER,
    cost_microdollars INTEGER,
    response_hash TEXT,
    replay_uri TEXT,
    replay_body BLOB,
    replay_method TEXT
);";

impl Default for TraceStore {
    fn default() -> Self {
        Self::new()
    }
}

impl TraceStore {
    /// In-memory only (used in tests and when no persistence path is configured).
    pub fn new() -> Self {
        Self {
            traces: DashMap::new(),
            order: Mutex::new(VecDeque::new()),
            db: None,
        }
    }

    /// Persistent store: opens/creates the SQLite table and hydrates recent traces into
    /// memory so `/api/traces` (and replay) work immediately after a restart. Falls back
    /// to in-memory if the DB can't be opened.
    pub fn new_persistent(path: &str) -> Self {
        if let Some(parent) = std::path::Path::new(path).parent() {
            if !parent.as_os_str().is_empty() {
                let _ = std::fs::create_dir_all(parent);
            }
        }
        let conn = match Connection::open(path) {
            Ok(c) => c,
            Err(e) => {
                tracing::error!("Failed to open trace DB at '{}': {} — traces will be in-memory only", path, e);
                return Self::new();
            }
        };
        if let Err(e) = conn.execute_batch(TRACE_TABLE) {
            tracing::error!("Failed to create traces table: {} — traces will be in-memory only", e);
            return Self::new();
        }
        let store = Self {
            traces: DashMap::new(),
            order: Mutex::new(VecDeque::new()),
            db: Some(Mutex::new(conn)),
        };
        store.hydrate();
        store
    }

    /// Load the most recent traces from SQLite into memory (called once at startup).
    fn hydrate(&self) {
        let Some(db) = &self.db else { return };
        let conn = db.lock().unwrap();
        let mut stmt = match conn.prepare(
            "SELECT trace_id, timestamp, tenant_id, session_id, agent_id, method, path, protocol, \
             upstream, steps, cache, status, blocked, block_reason, latency_us, total_tokens, \
             cost_microdollars, response_hash, replay_uri, replay_body, replay_method \
             FROM traces ORDER BY timestamp DESC LIMIT ?1",
        ) {
            Ok(s) => s,
            Err(e) => { tracing::error!("trace hydrate prepare failed: {}", e); return; }
        };
        let rows = stmt.query_map(params![TRACE_CAPACITY as i64], |row| {
            let steps_json: String = row.get(9).unwrap_or_default();
            let steps: Vec<String> = serde_json::from_str(&steps_json).unwrap_or_default();
            Ok(Trace {
                trace_id: row.get(0)?,
                timestamp: row.get::<_, i64>(1)? as u64,
                tenant_id: row.get(2)?,
                session_id: row.get(3)?,
                agent_id: row.get(4)?,
                method: row.get(5)?,
                path: row.get(6)?,
                protocol: row.get(7)?,
                upstream: row.get(8)?,
                steps,
                cache: row.get(10)?,
                status: row.get::<_, i64>(11)? as u16,
                blocked: row.get::<_, i64>(12)? != 0,
                block_reason: row.get(13)?,
                latency_us: row.get::<_, i64>(14)? as u64,
                total_tokens: row.get::<_, i64>(15)? as u32,
                cost_microdollars: row.get::<_, i64>(16)? as u64,
                response_hash: row.get(17)?,
                replay_uri: row.get(18)?,
                replay_body: row.get::<_, Vec<u8>>(19).unwrap_or_default(),
                replay_method: row.get(20)?,
            })
        });
        let rows = match rows { Ok(r) => r, Err(e) => { tracing::error!("trace hydrate query failed: {}", e); return; } };
        // Rows come newest-first; reverse so insertion order matches record() (newest last).
        let mut loaded: Vec<Trace> = rows.filter_map(|r| r.ok()).collect();
        loaded.reverse();
        let mut order = self.order.lock().unwrap();
        for t in loaded {
            let id = t.trace_id.clone();
            self.traces.insert(id.clone(), t);
            order.push_back(id);
        }
        if !order.is_empty() {
            tracing::info!("Hydrated {} traces from persistent store", order.len());
        }
    }

    /// Snapshot all in-memory traces to SQLite (called periodically, off the request path).
    pub fn persist_snapshot(&self) {
        let Some(db) = &self.db else { return };
        let snapshot: Vec<Trace> = self.traces.iter().map(|e| e.value().clone()).collect();
        if snapshot.is_empty() {
            return;
        }
        let conn = db.lock().unwrap();
        for t in &snapshot {
            let steps_json = serde_json::to_string(&t.steps).unwrap_or_else(|_| "[]".to_string());
            let _ = conn.execute(
                "INSERT OR REPLACE INTO traces (trace_id, timestamp, tenant_id, session_id, agent_id, \
                 method, path, protocol, upstream, steps, cache, status, blocked, block_reason, \
                 latency_us, total_tokens, cost_microdollars, response_hash, replay_uri, replay_body, replay_method) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13,?14,?15,?16,?17,?18,?19,?20,?21)",
                params![
                    t.trace_id, t.timestamp as i64, t.tenant_id, t.session_id, t.agent_id,
                    t.method, t.path, t.protocol, t.upstream, steps_json, t.cache,
                    t.status as i64, t.blocked as i64, t.block_reason, t.latency_us as i64,
                    t.total_tokens as i64, t.cost_microdollars as i64, t.response_hash,
                    t.replay_uri, t.replay_body, t.replay_method,
                ],
            );
        }
        // Bound the persistent store.
        let _ = conn.execute(
            "DELETE FROM traces WHERE trace_id NOT IN (SELECT trace_id FROM traces ORDER BY timestamp DESC LIMIT ?1)",
            params![TRACE_DB_CAPACITY as i64],
        );
    }

    /// Insert a completed trace, evicting the oldest if over capacity.
    pub fn record(&self, trace: Trace) {
        let id = trace.trace_id.clone();
        self.traces.insert(id.clone(), trace);
        let mut order = self.order.lock().unwrap();
        order.push_back(id);
        while order.len() > TRACE_CAPACITY {
            if let Some(old) = order.pop_front() {
                self.traces.remove(&old);
            }
        }
    }

    /// Enrich a recorded trace with token/cost/response-hash once the body is processed.
    pub fn enrich_usage(&self, trace_id: &str, total_tokens: u32, cost_microdollars: u64, response_hash: Option<String>) {
        if let Some(mut t) = self.traces.get_mut(trace_id) {
            t.total_tokens = total_tokens;
            t.cost_microdollars = cost_microdollars;
            if response_hash.is_some() {
                t.response_hash = response_hash;
            }
        }
    }

    /// Fetch a full trace, enforcing tenant scope unless super-admin.
    pub fn get_scoped(&self, trace_id: &str, caller_tenant: &str, super_admin: bool) -> Option<Trace> {
        let t = self.traces.get(trace_id)?;
        if super_admin || t.tenant_id == caller_tenant {
            Some(t.clone())
        } else {
            None
        }
    }

    /// List recent trace summaries (newest first), tenant-scoped unless super-admin.
    pub fn list(&self, caller_tenant: &str, super_admin: bool, limit: usize) -> Vec<TraceSummary> {
        let order = self.order.lock().unwrap();
        order
            .iter()
            .rev()
            .filter_map(|id| self.traces.get(id))
            .filter(|t| super_admin || t.tenant_id == caller_tenant)
            .take(limit)
            .map(|t| TraceSummary::from(&*t))
            .collect()
    }

    pub fn len(&self) -> usize {
        self.traces.len()
    }

    pub fn is_empty(&self) -> bool {
        self.traces.is_empty()
    }
}

/// Backend-selecting wrapper: SQLite locally/on-Fargate, DynamoDB on Lambda.
///
/// Every method is `async fn` for a uniform call-site regardless of backend — the
/// SQLite arm does its (synchronous, in-process) work directly; only the DynamoDB
/// arm awaits real network I/O. `persist_snapshot` is a SQLite-only concept (the
/// DynamoDB arm writes each trace immediately in `record`/`enrich_usage`, so there
/// is nothing to batch-flush) — it's a no-op on that backend rather than an error.
pub enum TraceBackend {
    Sqlite(TraceStore),
    #[cfg(feature = "lambda")]
    Dynamo(dynamo::DynamoTraceStore),
}

impl TraceBackend {
    /// Selects the backend from the environment:
    /// - `TRACE_BACKEND=dynamodb` (requires `--features lambda`) uses DynamoDB,
    ///   with the table name from `TRACE_TABLE` (default `plumb_traces`).
    /// - Anything else (including unset) falls back to the existing SQLite path.
    pub async fn from_env() -> Self {
        #[cfg(feature = "lambda")]
        {
            if std::env::var("TRACE_BACKEND").map(|v| v.eq_ignore_ascii_case("dynamodb")).unwrap_or(false) {
                let table = std::env::var("TRACE_TABLE").unwrap_or_else(|_| "plumb_traces".to_string());
                tracing::info!("TraceStore backend: DynamoDB (table={})", table);
                return TraceBackend::Dynamo(dynamo::DynamoTraceStore::new(table).await);
            }
        }
        let path = crate::config::data_path("traces.db");
        tracing::info!("TraceStore backend: SQLite ({})", path);
        TraceBackend::Sqlite(TraceStore::new_persistent(&path))
    }

    pub async fn record(&self, trace: Trace) {
        match self {
            TraceBackend::Sqlite(s) => s.record(trace),
            #[cfg(feature = "lambda")]
            TraceBackend::Dynamo(d) => d.record(&trace).await,
        }
    }

    pub async fn enrich_usage(&self, trace_id: &str, total_tokens: u32, cost_microdollars: u64, response_hash: Option<String>) {
        match self {
            TraceBackend::Sqlite(s) => s.enrich_usage(trace_id, total_tokens, cost_microdollars, response_hash),
            #[cfg(feature = "lambda")]
            TraceBackend::Dynamo(d) => d.enrich_usage(trace_id, total_tokens, cost_microdollars, response_hash).await,
        }
    }

    pub async fn get_scoped(&self, trace_id: &str, caller_tenant: &str, super_admin: bool) -> Option<Trace> {
        match self {
            TraceBackend::Sqlite(s) => s.get_scoped(trace_id, caller_tenant, super_admin),
            #[cfg(feature = "lambda")]
            TraceBackend::Dynamo(d) => d.get_scoped(trace_id, caller_tenant, super_admin).await,
        }
    }

    pub async fn list(&self, caller_tenant: &str, super_admin: bool, limit: usize) -> Vec<TraceSummary> {
        match self {
            TraceBackend::Sqlite(s) => s.list(caller_tenant, super_admin, limit),
            #[cfg(feature = "lambda")]
            TraceBackend::Dynamo(d) => d.list(caller_tenant, super_admin, limit).await,
        }
    }

    /// SQLite-only: periodic flush of the in-memory trace map to disk. No-op on
    /// DynamoDB, which writes each trace immediately (see module docs above).
    pub fn persist_snapshot(&self) {
        match self {
            TraceBackend::Sqlite(s) => s.persist_snapshot(),
            #[cfg(feature = "lambda")]
            TraceBackend::Dynamo(_) => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn mk(id: &str, tenant: &str) -> Trace {
        Trace::start(
            id.into(), tenant.into(), "s".into(), "a".into(),
            "POST".into(), "/v1/x".into(), "OpenAI".into(), "http://up".into(),
        )
    }

    #[test]
    fn test_record_and_scope() {
        let store = TraceStore::new();
        store.record(mk("t1", "acme"));
        store.record(mk("t2", "other"));

        assert!(store.get_scoped("t1", "acme", false).is_some());
        assert!(store.get_scoped("t1", "other", false).is_none(), "cross-tenant must be denied");
        assert!(store.get_scoped("t1", "other", true).is_some(), "super-admin sees all");

        let acme = store.list("acme", false, 100);
        assert_eq!(acme.len(), 1);
        assert_eq!(store.list("*", true, 100).len(), 2);
    }

    #[test]
    fn test_enrich_usage() {
        let store = TraceStore::new();
        store.record(mk("t1", "acme"));
        store.enrich_usage("t1", 1234, 5678, Some("hash".into()));
        let t = store.get_scoped("t1", "acme", false).unwrap();
        assert_eq!(t.total_tokens, 1234);
        assert_eq!(t.cost_microdollars, 5678);
        assert_eq!(t.response_hash.as_deref(), Some("hash"));
    }

    #[test]
    fn test_capacity_eviction() {
        let store = TraceStore::new();
        for i in 0..(TRACE_CAPACITY + 10) {
            store.record(mk(&format!("t{}", i), "acme"));
        }
        assert_eq!(store.len(), TRACE_CAPACITY);
        // Oldest evicted.
        assert!(store.get_scoped("t0", "acme", true).is_none());
    }

    #[test]
    fn test_persistence_hydrates_on_reopen() {
        let path = std::env::temp_dir().join(format!("traces-test-{}.db", uuid::Uuid::new_v4().simple()));
        let path_str = path.to_str().unwrap();

        {
            let store = TraceStore::new_persistent(path_str);
            let mut t = mk("persisted-1", "acme");
            t.status = 200;
            t.step("protocol_detected=OpenAI");
            t.set_replay("POST", "http://up/v1/x", b"{\"model\":\"gpt-4o\"}");
            store.record(t);
            store.enrich_usage("persisted-1", 42, 100, Some("abc123".into()));
            store.persist_snapshot();
        }

        // Reopen from the same path — the trace should be hydrated into memory.
        let reopened = TraceStore::new_persistent(path_str);
        let t = reopened.get_scoped("persisted-1", "acme", true).expect("trace should survive restart");
        assert_eq!(t.status, 200);
        assert_eq!(t.total_tokens, 42);
        assert_eq!(t.cost_microdollars, 100);
        assert_eq!(t.response_hash.as_deref(), Some("abc123"));
        assert!(t.steps.iter().any(|s| s.contains("protocol_detected")));
        // Replay body (a #[serde(skip)] field) must be preserved for replay.
        assert_eq!(t.replay_body, b"{\"model\":\"gpt-4o\"}");
        assert_eq!(t.replay_uri, "http://up/v1/x");

        let _ = std::fs::remove_file(&path);
    }
}
