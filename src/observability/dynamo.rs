//! DynamoDB-backed trace store — the Lambda-compatible alternative to
//! [`super::TraceStore`] (SQLite + in-memory DashMap). Only compiled with
//! `--features lambda`.
//!
//! Table shape (see `infra/dynamodb.md`):
//!   trace_id (String)  — partition key (primary lookup: `get_scoped`)
//!   timestamp (Number) — sort key on the table itself (not used for the base
//!                        table's primary lookup, but required by the GSI below)
//!   tenant_id, session_id, agent_id, method, path, protocol, upstream,
//!   steps (String, JSON-encoded Vec<String>), cache, status, blocked,
//!   block_reason, latency_us, total_tokens, cost_microdollars, response_hash,
//!   replay_uri, replay_body (Binary), replay_method — all mirror `Trace` 1:1.
//!
//! GSI `tenant-timestamp-index`: partition key `tenant_id`, sort key `timestamp`.
//! Used by `list(tenant, limit)` (tenant-scoped, newest-first) exactly like the
//! SQLite path's `ORDER BY timestamp DESC`. Super-admin "list all tenants" has no
//! single-partition equivalent on DynamoDB; at near-zero trace volume this falls
//! back to a bounded `Scan`, which is the one place this store's Big-O differs
//! from the SQLite version — flagged rather than silently degraded. Revisit if
//! trace volume grows enough that a full-table scan becomes expensive.

use aws_sdk_dynamodb::types::AttributeValue;
use aws_sdk_dynamodb::Client;
use std::collections::HashMap;

use super::{Trace, TraceSummary};

const GSI_NAME: &str = "tenant-timestamp-index";

pub struct DynamoTraceStore {
    client: Client,
    table: String,
}

impl DynamoTraceStore {
    pub async fn new(table: impl Into<String>) -> Self {
        let config = aws_config::load_defaults(aws_config::BehaviorVersion::latest()).await;
        Self {
            client: Client::new(&config),
            table: table.into(),
        }
    }

    #[cfg(test)]
    pub fn with_client(client: Client, table: impl Into<String>) -> Self {
        Self {
            client,
            table: table.into(),
        }
    }

    pub async fn record(&self, trace: &Trace) {
        let item = trace_to_item(trace);
        if let Err(e) = self
            .client
            .put_item()
            .table_name(&self.table)
            .set_item(Some(item))
            .send()
            .await
        {
            tracing::error!("DynamoDB trace record failed: {}", e);
        }
    }

    /// Enrich a recorded trace with token/cost/response-hash. DynamoDB has no
    /// in-place partial update analog as cheap as the DashMap version, so this
    /// does a targeted `UpdateItem` rather than read-modify-write.
    pub async fn enrich_usage(
        &self,
        trace_id: &str,
        total_tokens: u32,
        cost_microdollars: u64,
        response_hash: Option<String>,
    ) {
        let mut update_expr = "SET total_tokens = :tt, cost_microdollars = :cm".to_string();
        let mut values: HashMap<String, AttributeValue> = HashMap::new();
        values.insert(
            ":tt".to_string(),
            AttributeValue::N(total_tokens.to_string()),
        );
        values.insert(
            ":cm".to_string(),
            AttributeValue::N(cost_microdollars.to_string()),
        );
        if let Some(hash) = response_hash {
            update_expr.push_str(", response_hash = :rh");
            values.insert(":rh".to_string(), AttributeValue::S(hash));
        }

        let mut key = HashMap::new();
        key.insert(
            "trace_id".to_string(),
            AttributeValue::S(trace_id.to_string()),
        );

        if let Err(e) = self
            .client
            .update_item()
            .table_name(&self.table)
            .set_key(Some(key))
            .update_expression(update_expr)
            .set_expression_attribute_values(Some(values))
            .send()
            .await
        {
            tracing::error!("DynamoDB trace enrich_usage failed: {}", e);
        }
    }

    /// Fetch a full trace by id, enforcing tenant scope unless super-admin.
    pub async fn get_scoped(
        &self,
        trace_id: &str,
        caller_tenant: &str,
        super_admin: bool,
    ) -> Option<Trace> {
        let mut key = HashMap::new();
        key.insert(
            "trace_id".to_string(),
            AttributeValue::S(trace_id.to_string()),
        );

        let result = self
            .client
            .get_item()
            .table_name(&self.table)
            .set_key(Some(key))
            .send()
            .await;
        let item = match result {
            Ok(out) => out.item?,
            Err(e) => {
                tracing::error!("DynamoDB trace get_scoped failed: {}", e);
                return None;
            }
        };
        let trace = item_to_trace(&item)?;
        if super_admin || trace.tenant_id == caller_tenant {
            Some(trace)
        } else {
            None
        }
    }

    /// List recent trace summaries (newest first), tenant-scoped via the GSI.
    /// Super-admin (no scoping) falls back to a bounded Scan — see module docs.
    pub async fn list(
        &self,
        caller_tenant: &str,
        super_admin: bool,
        limit: usize,
    ) -> Vec<TraceSummary> {
        if super_admin {
            let result = self
                .client
                .scan()
                .table_name(&self.table)
                .limit(limit as i32)
                .send()
                .await;
            let mut items: Vec<TraceSummary> = match result {
                Ok(out) => out
                    .items
                    .unwrap_or_default()
                    .iter()
                    .filter_map(item_to_trace)
                    .map(|t| TraceSummary::from(&t))
                    .collect(),
                Err(e) => {
                    tracing::error!("DynamoDB trace list (scan) failed: {}", e);
                    return Vec::new();
                }
            };
            items.sort_by_key(|t| std::cmp::Reverse(t.timestamp));
            items.truncate(limit);
            return items;
        }

        let result = self
            .client
            .query()
            .table_name(&self.table)
            .index_name(GSI_NAME)
            .key_condition_expression("tenant_id = :t")
            .expression_attribute_values(":t", AttributeValue::S(caller_tenant.to_string()))
            .scan_index_forward(false)
            .limit(limit as i32)
            .send()
            .await;

        match result {
            Ok(out) => out
                .items
                .unwrap_or_default()
                .iter()
                .filter_map(item_to_trace)
                .map(|t| TraceSummary::from(&t))
                .collect(),
            Err(e) => {
                tracing::error!("DynamoDB trace list failed: {}", e);
                Vec::new()
            }
        }
    }
}

fn trace_to_item(t: &Trace) -> HashMap<String, AttributeValue> {
    let mut item = HashMap::new();
    item.insert(
        "trace_id".to_string(),
        AttributeValue::S(t.trace_id.clone()),
    );
    item.insert(
        "timestamp".to_string(),
        AttributeValue::N(t.timestamp.to_string()),
    );
    item.insert(
        "tenant_id".to_string(),
        AttributeValue::S(t.tenant_id.clone()),
    );
    item.insert(
        "session_id".to_string(),
        AttributeValue::S(t.session_id.clone()),
    );
    item.insert(
        "agent_id".to_string(),
        AttributeValue::S(t.agent_id.clone()),
    );
    item.insert("method".to_string(), AttributeValue::S(t.method.clone()));
    item.insert("path".to_string(), AttributeValue::S(t.path.clone()));
    item.insert(
        "protocol".to_string(),
        AttributeValue::S(t.protocol.clone()),
    );
    item.insert(
        "upstream".to_string(),
        AttributeValue::S(t.upstream.clone()),
    );
    item.insert(
        "steps".to_string(),
        AttributeValue::S(serde_json::to_string(&t.steps).unwrap_or_else(|_| "[]".to_string())),
    );
    item.insert("cache".to_string(), AttributeValue::S(t.cache.clone()));
    item.insert(
        "status".to_string(),
        AttributeValue::N(t.status.to_string()),
    );
    item.insert("blocked".to_string(), AttributeValue::Bool(t.blocked));
    if let Some(reason) = &t.block_reason {
        item.insert(
            "block_reason".to_string(),
            AttributeValue::S(reason.clone()),
        );
    }
    item.insert(
        "latency_us".to_string(),
        AttributeValue::N(t.latency_us.to_string()),
    );
    item.insert(
        "total_tokens".to_string(),
        AttributeValue::N(t.total_tokens.to_string()),
    );
    item.insert(
        "cost_microdollars".to_string(),
        AttributeValue::N(t.cost_microdollars.to_string()),
    );
    if let Some(hash) = &t.response_hash {
        item.insert("response_hash".to_string(), AttributeValue::S(hash.clone()));
    }
    item.insert(
        "replay_uri".to_string(),
        AttributeValue::S(t.replay_uri.clone()),
    );
    item.insert(
        "replay_body".to_string(),
        AttributeValue::B(t.replay_body.clone().into()),
    );
    item.insert(
        "replay_method".to_string(),
        AttributeValue::S(t.replay_method.clone()),
    );
    item
}

fn item_to_trace(item: &HashMap<String, AttributeValue>) -> Option<Trace> {
    let steps: Vec<String> = item
        .get("steps")
        .and_then(|v| v.as_s().ok())
        .and_then(|s| serde_json::from_str(s).ok())
        .unwrap_or_default();

    Some(Trace {
        trace_id: item.get("trace_id")?.as_s().ok()?.clone(),
        timestamp: item.get("timestamp")?.as_n().ok()?.parse().ok()?,
        tenant_id: item.get("tenant_id")?.as_s().ok()?.clone(),
        session_id: item
            .get("session_id")
            .and_then(|v| v.as_s().ok())
            .cloned()
            .unwrap_or_default(),
        agent_id: item
            .get("agent_id")
            .and_then(|v| v.as_s().ok())
            .cloned()
            .unwrap_or_default(),
        method: item
            .get("method")
            .and_then(|v| v.as_s().ok())
            .cloned()
            .unwrap_or_default(),
        path: item
            .get("path")
            .and_then(|v| v.as_s().ok())
            .cloned()
            .unwrap_or_default(),
        protocol: item
            .get("protocol")
            .and_then(|v| v.as_s().ok())
            .cloned()
            .unwrap_or_default(),
        upstream: item
            .get("upstream")
            .and_then(|v| v.as_s().ok())
            .cloned()
            .unwrap_or_default(),
        steps,
        cache: item
            .get("cache")
            .and_then(|v| v.as_s().ok())
            .cloned()
            .unwrap_or_default(),
        status: item
            .get("status")
            .and_then(|v| v.as_n().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        blocked: item
            .get("blocked")
            .and_then(|v| v.as_bool().ok())
            .copied()
            .unwrap_or(false),
        block_reason: item
            .get("block_reason")
            .and_then(|v| v.as_s().ok())
            .cloned(),
        latency_us: item
            .get("latency_us")
            .and_then(|v| v.as_n().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        total_tokens: item
            .get("total_tokens")
            .and_then(|v| v.as_n().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        cost_microdollars: item
            .get("cost_microdollars")
            .and_then(|v| v.as_n().ok())
            .and_then(|s| s.parse().ok())
            .unwrap_or(0),
        response_hash: item
            .get("response_hash")
            .and_then(|v| v.as_s().ok())
            .cloned(),
        replay_uri: item
            .get("replay_uri")
            .and_then(|v| v.as_s().ok())
            .cloned()
            .unwrap_or_default(),
        replay_body: item
            .get("replay_body")
            .and_then(|v| v.as_b().ok())
            .map(|b| b.clone().into_inner())
            .unwrap_or_default(),
        replay_method: item
            .get("replay_method")
            .and_then(|v| v.as_s().ok())
            .cloned()
            .unwrap_or_else(|| "POST".to_string()),
    })
}
