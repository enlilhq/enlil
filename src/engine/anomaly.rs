use dashmap::DashMap;
use std::time::Instant;

/// Simple statistical anomaly detector using z-score on request patterns
pub struct AnomalyDetector {
    tenant_patterns: DashMap<String, TenantPattern>,
}

struct TenantPattern {
    request_intervals: Vec<f64>, // seconds between requests
    payload_sizes: Vec<usize>,
    last_request: Instant,
}

impl Default for AnomalyDetector {
    fn default() -> Self {
        Self::new()
    }
}

impl AnomalyDetector {
    pub fn new() -> Self {
        Self {
            tenant_patterns: DashMap::new(),
        }
    }

    /// Record a request and return anomaly score (0.0 = normal, >2.0 = suspicious, >3.0 = anomalous)
    pub fn record(&self, tenant_id: &str, payload_size: usize) -> f64 {
        let now = Instant::now();
        let mut entry = self
            .tenant_patterns
            .entry(tenant_id.to_string())
            .or_insert_with(|| TenantPattern {
                request_intervals: Vec::new(),
                payload_sizes: Vec::new(),
                last_request: now,
            });

        let interval = now.duration_since(entry.last_request).as_secs_f64();
        entry.last_request = now;

        if !entry.request_intervals.is_empty() {
            entry.request_intervals.push(interval);
        } else {
            entry.request_intervals.push(interval);
            entry.payload_sizes.push(payload_size);
            return 0.0; // Not enough data
        }
        entry.payload_sizes.push(payload_size);

        // Keep last 100 samples
        if entry.request_intervals.len() > 100 {
            let drain_to = entry.request_intervals.len() - 100;
            entry.request_intervals.drain(0..drain_to);
            let drain_to2 = entry.payload_sizes.len() - 100;
            entry.payload_sizes.drain(0..drain_to2);
        }

        if entry.request_intervals.len() < 5 {
            return 0.0;
        } // Need minimum samples

        // Z-score on request interval (detect bursts)
        let interval_score = z_score(&entry.request_intervals, interval);

        // Z-score on payload size (detect unusual payloads)
        let size_score = z_score_usize(&entry.payload_sizes, payload_size);

        // Combined anomaly score (negative z-score on interval = faster than normal = suspicious)
        let burst_score = if interval_score < 0.0 {
            -interval_score
        } else {
            0.0
        };
        (burst_score + size_score.abs()) / 2.0
    }
}

fn z_score(data: &[f64], value: f64) -> f64 {
    let n = data.len() as f64;
    let mean = data.iter().sum::<f64>() / n;
    let variance = data.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / n;
    let std_dev = variance.sqrt();
    if std_dev < 0.001 {
        return 0.0;
    }
    (value - mean) / std_dev
}

fn z_score_usize(data: &[usize], value: usize) -> f64 {
    let floats: Vec<f64> = data.iter().map(|&x| x as f64).collect();
    z_score(&floats, value as f64)
}
