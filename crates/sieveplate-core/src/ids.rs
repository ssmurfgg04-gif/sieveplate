//! Global id minting (envelope ids and promise ids share one space so a
//! `__reply` envelope's `id` can double as the promise it resolves).

use std::sync::atomic::{AtomicU64, Ordering};

static COUNTER: AtomicU64 = AtomicU64::new(1);

/// Next unique id.
pub fn next_id() -> u64 {
    COUNTER.fetch_add(1, Ordering::Relaxed)
}
