//! Lightweight metrics: counters + latency samples with p50/p95/p99.
//! Phase 5 observability, dependency-free.

use std::collections::BTreeMap;
use std::sync::Mutex;

#[derive(Default)]
pub struct Metrics {
    counters: Mutex<BTreeMap<String, u64>>,
    samples: Mutex<BTreeMap<String, Vec<u64>>>,
}

/// Summary of one latency series (microseconds).
#[derive(Debug, Clone, serde::Serialize)]
pub struct Summary {
    pub n: u64,
    pub p50_us: u64,
    pub p95_us: u64,
    pub p99_us: u64,
    pub max_us: u64,
    pub mean_us: u64,
}

impl Metrics {
    pub fn new() -> Self {
        Self::default()
    }

    /// Record one latency sample in microseconds.
    pub fn record_us(&self, series: &str, us: u64) {
        self.samples
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(series.to_string())
            .or_default()
            .push(us);
        // Cap memory: keep the most recent 20k samples per series.
        let mut s = self.samples.lock().unwrap_or_else(|p| p.into_inner());
        if let Some(v) = s.get_mut(series) {
            if v.len() > 20_000 {
                let cut = v.len() - 20_000;
                v.drain(0..cut);
            }
        }
    }

    /// Increment a counter by one.
    pub fn count(&self, name: &str) {
        self.bump(name, 1);
    }

    /// Increment a counter by `by`.
    pub fn bump(&self, name: &str, by: u64) {
        *self
            .counters
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .entry(name.to_string())
            .or_insert(0) += by;
    }

    /// Current value of a counter.
    pub fn counter(&self, name: &str) -> u64 {
        self.counters
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(name)
            .copied()
            .unwrap_or(0)
    }

    /// Summarize a latency series.
    pub fn summarize(&self, series: &str) -> Option<Summary> {
        let mut v = self
            .samples
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(series)
            .cloned()?;
        if v.is_empty() {
            return None;
        }
        v.sort_unstable();
        let n = v.len() as u64;
        let pick = |p: f64| -> u64 {
            let idx = (((n as f64) * p).ceil() as usize)
                .saturating_sub(1)
                .min(v.len() - 1);
            v[idx]
        };
        let mean = v.iter().sum::<u64>() / n.max(1);
        Some(Summary {
            n,
            p50_us: pick(0.50),
            p95_us: pick(0.95),
            p99_us: pick(0.99),
            max_us: v[v.len() - 1],
            mean_us: mean,
        })
    }

    /// Full snapshot (counters + all summaries) as JSON.
    pub fn snapshot_json(&self) -> serde_json::Value {
        let counters = self
            .counters
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .clone();
        // Copy the series names out first — `summarize` re-locks `samples`
        // and std Mutex is not reentrant (holding the guard across the loop
        // would deadlock).
        let names: Vec<String> = self
            .samples
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .keys()
            .cloned()
            .collect();
        let mut series = serde_json::Map::new();
        for name in names {
            if let Some(s) = self.summarize(&name) {
                series.insert(name, serde_json::to_value(s).unwrap());
            }
        }
        serde_json::json!({ "counters": counters, "series": series })
    }
}
