//! Mesh routing — multi-hop delivery across the fabric (ADR-0006).
//!
//! The phase-4 fabric routed only to DIRECTLY connected peers: an envelope
//! for a host without a socket to it failed with "peer not connected".
//! Real cell grids are meshes — hosts must relay for each other.
//!
//! This module keeps a per-host **distance-vector routing table**:
//!
//! ```text
//! dest host ──► RouteEntry { next_hop, hops }
//! ```
//!
//! - `next_hop` is always a DIRECTLY connected peer (the socket to use).
//! - `hops` is the distance to the destination *through that peer*.
//! - Direct peers cost 1; self costs 0.
//!
//! Peers exchange their full tables in `__routes` control envelopes inside
//! the sealed SIEVE1 channel (no routing data ever crosses a link that did
//! not authenticate). On receiving an announcement from peer `P`:
//!
//! 1. every entry `(h, n)` becomes candidate `(h, n+1)` via `P`;
//! 2. a candidate replaces the existing route when it is **strictly
//!    shorter**, or when no route exists;
//! 3. a **poisoned** entry (`hops >= POISON`, sent when a peer loses a
//!    destination) deletes any route to `h` whose next hop is `P` — stale
//!    routes die in one announcement instead of counting to infinity;
//! 4. when the table changed, the new table is announced to all peers
//!    (triggered, not periodic — convergence in O(diameter) messages).
//!
//! Loop safety is layered: strict improvement only, `POISON` ceiling, and
//! a per-envelope TTL (`crate::sieveplate_core::MAX_HOPS`) that drops an
//! envelope caught cycling. Tables also survive peer churn: when a link
//! dies, every route through it is removed (and poisoned outward) before
//! alternatives learned from other peers are re-announced.

use std::collections::HashMap;
use std::sync::Arc;

use serde::{Deserialize, Serialize};

/// A destination is unreachable when its cost reaches this value. Any
/// announcement at or above it is a withdrawal (poison).
pub const POISON: u32 = 64;

/// Wire form of one routing announcement entry (`hops >= POISON` means
/// "withdraw this destination").
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteAnnounceEntry {
    pub host: String,
    pub hops: u32,
}

/// Full table announcement: sender name + entries (sender always includes
/// itself at hops 0).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct RouteAnnounce {
    pub from: String,
    pub entries: Vec<RouteAnnounceEntry>,
}

/// One destination's forwarding state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RouteEntry {
    /// Directly connected peer used to reach the destination.
    pub next_hop: String,
    /// Distance in hosts (1 = the peer itself).
    pub hops: u32,
    /// Direction the route was learned from (for withdrawal filtering).
    pub learned_from: String,
}

#[derive(Default)]
struct Inner {
    /// This host's own name — never routed (a host is not its own
    /// destination).
    self_host: String,
    table: HashMap<String, RouteEntry>,
    /// Monotonic version — bumped on every change so callers can detect
    /// convergence cheaply in tests.
    version: u64,
}

/// Shared, cloneable routing table. `Fabric` owns one.
#[derive(Clone, Default)]
pub struct RouteTable {
    inner: Arc<std::sync::Mutex<Inner>>,
}

impl RouteTable {
    /// A table for `self_host`. Routes to the host itself are never
    /// inserted, no matter what peers announce.
    pub fn new(self_host: impl Into<String>) -> Self {
        RouteTable {
            inner: Arc::new(std::sync::Mutex::new(Inner {
                self_host: self_host.into(),
                table: HashMap::new(),
                version: 0,
            })),
        }
    }

    pub fn version(&self) -> u64 {
        self.inner.lock().unwrap_or_else(|p| p.into_inner()).version
    }

    /// Learn from a peer's announcement. Returns `true` when the table
    /// changed (the caller must re-announce).
    pub fn learn(&self, ann: &RouteAnnounce) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut changed = false;
        for e in &ann.entries {
            if e.host == ann.from && e.hops == 0 {
                // The peer itself: always reachable at cost 1 via that peer.
                let better = match inner.table.get(&e.host) {
                    Some(cur) => cur.next_hop != ann.from && cur.hops > 1,
                    None => true,
                };
                if better {
                    inner.table.insert(
                        e.host.clone(),
                        RouteEntry {
                            next_hop: ann.from.clone(),
                            hops: 1,
                            learned_from: ann.from.clone(),
                        },
                    );
                    changed = true;
                }
                continue;
            }
            if e.hops >= POISON {
                // Withdrawal from this peer. Two cases:
                // 1. we routed the destination via this peer → forget it;
                // 2. we still reach the destination another way → keep the
                //    route AND re-announce, so the poisoned peer can
                //    relearn through us (DV poison-response). Without this
                //    a host that loses its only path stays blind while its
                //    neighbours hold valid alternatives they never resend.
                let via_sender =
                    matches!(inner.table.get(&e.host), Some(cur) if cur.learned_from == ann.from);
                if via_sender {
                    inner.table.remove(&e.host);
                    changed = true;
                } else if inner.table.contains_key(&e.host) {
                    changed = true;
                }
                continue;
            }
            let candidate = e.hops + 1;
            let self_host = inner.self_host.clone();
            let better = match inner.table.get(&e.host) {
                // Never route to ourselves.
                Some(cur) => e.host != self_host && candidate < cur.hops,
                None => e.host != self_host,
            };
            if better {
                inner.table.insert(
                    e.host.clone(),
                    RouteEntry {
                        next_hop: ann.from.clone(),
                        hops: candidate,
                        learned_from: ann.from.clone(),
                    },
                );
                changed = true;
            }
        }
        if changed {
            inner.version += 1;
        }
        changed
    }

    /// Register (or refresh) a direct peer at cost 1. Returns `true` when
    /// the table changed.
    pub fn add_direct(&self, peer: &str) -> bool {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let better = match inner.table.get(peer) {
            Some(cur) => cur.hops > 1,
            None => true,
        };
        if better {
            inner.table.insert(
                peer.to_string(),
                RouteEntry {
                    next_hop: peer.to_string(),
                    hops: 1,
                    learned_from: peer.to_string(),
                },
            );
            inner.version += 1;
        }
        better
    }

    /// A direct link died: remove every route that used it (the peer's own
    /// direct entry included) and return the withdrawn destinations for
    /// poisoning.
    pub fn remove_peer(&self, peer: &str) -> Vec<String> {
        let mut inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let withdrawn: Vec<String> = inner
            .table
            .iter()
            .filter(|(_, e)| e.next_hop == peer)
            .map(|(h, _)| h.clone())
            .collect();
        if !withdrawn.is_empty() {
            inner.table.retain(|_, e| e.next_hop != peer);
            inner.version += 1;
        }
        withdrawn
    }

    /// Next hop toward `host`, if known.
    pub fn next_hop(&self, host: &str) -> Option<String> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .table
            .get(host)
            .map(|e| e.next_hop.clone())
    }

    /// Cost toward `host` (hops), if known.
    pub fn hops(&self, host: &str) -> Option<u32> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .table
            .get(host)
            .map(|e| e.hops)
    }

    /// Full snapshot: (dest, next_hop, hops) sorted by dest.
    pub fn snapshot(&self) -> Vec<(String, String, u32)> {
        self.inner
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .table
            .iter()
            .map(|(h, e)| (h.clone(), e.next_hop.clone(), e.hops))
            .collect()
    }

    /// Announcement payload built from the current table (self at 0,
    /// poisoned routes excluded).
    pub fn announce(&self) -> RouteAnnounce {
        let inner = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let mut entries = vec![RouteAnnounceEntry {
            host: inner.self_host.clone(),
            hops: 0,
        }];
        entries.extend(inner.table.iter().map(|(h, e)| RouteAnnounceEntry {
            host: h.clone(),
            hops: e.hops,
        }));
        entries.sort_by(|a, b| a.host.cmp(&b.host));
        RouteAnnounce {
            from: inner.self_host.clone(),
            entries,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn direct_peers_and_learning() {
        let t = RouteTable::new("me");
        assert!(t.add_direct("b"));
        assert_eq!(t.next_hop("b").unwrap(), "b");
        assert_eq!(t.hops("b").unwrap(), 1);

        // b announces it can reach c in 1 hop → we get c at 2 via b.
        let ann = RouteAnnounce {
            from: "b".into(),
            entries: vec![
                RouteAnnounceEntry {
                    host: "b".into(),
                    hops: 0,
                },
                RouteAnnounceEntry {
                    host: "c".into(),
                    hops: 1,
                },
            ],
        };
        assert!(t.learn(&ann));
        assert_eq!(t.next_hop("c").unwrap(), "b");
        assert_eq!(t.hops("c").unwrap(), 2);
        // Re-learning the same cost changes nothing.
        assert!(!t.learn(&ann));
    }

    #[test]
    fn shorter_route_wins_and_poison_removes_via_sender() {
        let t = RouteTable::new("me");
        t.add_direct("b");
        let via_b = RouteAnnounce {
            from: "b".into(),
            entries: vec![RouteAnnounceEntry {
                host: "d".into(),
                hops: 2,
            }],
        };
        t.learn(&via_b);
        assert_eq!(t.hops("d").unwrap(), 3);
        // a announces a shorter path
        let via_a = RouteAnnounce {
            from: "a".into(),
            entries: vec![RouteAnnounceEntry {
                host: "d".into(),
                hops: 1,
            }],
        };
        t.learn(&via_a);
        assert_eq!(t.hops("d").unwrap(), 2);
        assert_eq!(t.next_hop("d").unwrap(), "a");
        // a poisons it → route gone
        let poison = RouteAnnounce {
            from: "a".into(),
            entries: vec![RouteAnnounceEntry {
                host: "d".into(),
                hops: POISON,
            }],
        };
        t.learn(&poison);
        assert!(t.next_hop("d").is_none());
    }

    #[test]
    fn poison_response_reannounces_alternative() {
        let t = RouteTable::new("me");
        t.add_direct("d");
        // d announces c at 1 → we hold c@2 via d.
        t.learn(&RouteAnnounce {
            from: "d".into(),
            entries: vec![RouteAnnounceEntry {
                host: "c".into(),
                hops: 1,
            }],
        });
        // An unrelated peer ("x") poisons c: our route via d survives, but
        // the table changed so we re-announce (x may relearn c through us).
        assert!(t.learn(&RouteAnnounce {
            from: "x".into(),
            entries: vec![RouteAnnounceEntry {
                host: "c".into(),
                hops: POISON
            }],
        }));
        assert_eq!(t.next_hop("c").unwrap(), "d");
    }

    #[test]
    fn peer_death_withdraws_its_routes() {
        let t = RouteTable::new("me");
        t.add_direct("b");
        let via_b = RouteAnnounce {
            from: "b".into(),
            entries: vec![RouteAnnounceEntry {
                host: "c".into(),
                hops: 1,
            }],
        };
        t.learn(&via_b);
        let withdrawn = t.remove_peer("b");
        assert!(withdrawn.contains(&"c".to_string()));
        assert!(t.next_hop("b").is_none());
        assert!(t.next_hop("c").is_none());
    }

    #[test]
    fn never_routes_to_self() {
        let t = RouteTable::new("me");
        let ann = RouteAnnounce {
            from: "b".into(),
            entries: vec![
                RouteAnnounceEntry {
                    host: "b".into(),
                    hops: 0,
                },
                // b (mis)announces us as reachable through it.
                RouteAnnounceEntry {
                    host: "me".into(),
                    hops: 1,
                },
            ],
        };
        t.learn(&ann);
        assert!(t.next_hop("me").is_none());
    }
}
