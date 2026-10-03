//! Hash-chained, append-only event log.
//!
//! The organic data topology requirement: "searching for a file" becomes a
//! temporal query over the event log. Every meaningful system event (cell
//! created, actor woke, turn committed, sense fired) is appended here.
//!
//! Tamper evidence: each record commits to the hash of the previous record
//! (a blockchain-style chain, content-addressed via the CAS hash function).
//! `verify()` walks the chain and proves it intact.

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::cas::content_hash;
use crate::datalog::{Fact, Term};
use crate::error::StoreError;

const GENESIS: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// One event in the system history.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EventRecord {
    pub seq: u64,
    pub ts_ms: u128,
    pub kind: String,
    /// Ordered key/value attributes (kept ordered for deterministic hashing).
    pub attrs: Vec<(String, String)>,
    /// Hash of the previous record (chain).
    pub prev: String,
    /// Hash of this record: sha256(canonical_json(self minus hash)).
    pub hash: String,
}

impl EventRecord {
    fn compute_hash(&self) -> String {
        let mut probe = self.clone();
        probe.hash = String::new();
        content_hash(serde_json::to_string(&probe).unwrap_or_default().as_bytes())
    }

    fn canonical_line(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }
}

/// Append-only, hash-chained event log stored as JSON lines.
pub struct EventLog {
    path: PathBuf,
    inner: Mutex<LogState>,
}

struct LogState {
    file: fs::File,
    seq: u64,
    head: String,
}

impl EventLog {
    /// Open (or create) the log at `path`. An existing log is verified.
    pub fn open(path: impl Into<PathBuf>) -> Result<Self, StoreError> {
        let path = path.into();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let (seq, head) = if path.exists() {
            let mut seq = 0u64;
            let mut head = GENESIS.to_string();
            for rec in read_records(&path)? {
                let expected = rec.compute_hash();
                if expected != rec.hash {
                    return Err(StoreError::Corrupt {
                        seq: rec.seq,
                        why: "record hash mismatch".into(),
                    });
                }
                if rec.prev != head {
                    return Err(StoreError::Corrupt {
                        seq: rec.seq,
                        why: "chain broken".into(),
                    });
                }
                head = rec.hash.clone();
                seq = rec.seq;
            }
            (seq, head)
        } else {
            (0, GENESIS.to_string())
        };
        let file = OpenOptions::new().create(true).append(true).open(&path)?;
        Ok(Self {
            path,
            inner: Mutex::new(LogState { file, seq, head }),
        })
    }

    /// Append an event and return the record (including its chain hash).
    pub fn append(
        &self,
        kind: &str,
        attrs: Vec<(String, String)>,
    ) -> Result<EventRecord, StoreError> {
        let mut st = self.inner.lock().unwrap_or_else(|p| p.into_inner());
        let rec = EventRecord {
            seq: st.seq + 1,
            ts_ms: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.as_millis())
                .unwrap_or(0),
            kind: kind.to_string(),
            attrs,
            prev: st.head.clone(),
            hash: String::new(),
        };
        let hash = rec.compute_hash();
        let mut rec = rec;
        rec.hash = hash;
        writeln!(st.file, "{}", rec.canonical_line())?;
        st.seq = rec.seq;
        st.head = rec.hash.clone();
        Ok(rec)
    }

    /// Read every record in order.
    pub fn records(&self) -> Result<Vec<EventRecord>, StoreError> {
        read_records(&self.path)
    }

    /// Verify the full chain. Ok(()) = intact.
    pub fn verify(&self) -> Result<(), StoreError> {
        let mut head = GENESIS.to_string();
        for rec in read_records(&self.path)? {
            if rec.compute_hash() != rec.hash {
                return Err(StoreError::Corrupt {
                    seq: rec.seq,
                    why: "record hash mismatch".into(),
                });
            }
            if rec.prev != head {
                return Err(StoreError::Corrupt {
                    seq: rec.seq,
                    why: "chain broken".into(),
                });
            }
            head = rec.hash;
        }
        Ok(())
    }

    /// Number of records.
    pub fn len(&self) -> Result<u64, StoreError> {
        Ok(self.inner.lock().unwrap_or_else(|p| p.into_inner()).seq)
    }

    /// True when the log has no records.
    pub fn is_empty(&self) -> Result<bool, StoreError> {
        Ok(self.len()? == 0)
    }

    /// Project the log into Datalog facts for semantic queries.
    ///
    /// Fact shapes:
    /// - `create(seq, cell, template)`
    /// - `turn_ok(seq, cell, msg, us)`
    /// - `turn_fail(seq, cell, msg, reason)`
    /// - `wake(seq, cell, us)`
    /// - `evict(seq, cell)`
    /// - `snapshot(seq, cell, hash)`
    /// - `restore(seq, cell, hash)`
    /// - `sense(seq, source, name)`
    pub fn facts(&self) -> Result<Vec<Fact>, StoreError> {
        let mut facts = Vec::new();
        for rec in self.records()? {
            let get = |k: &str| -> String {
                rec.attrs
                    .iter()
                    .find(|(a, _)| a == k)
                    .map(|(_, v)| v.clone())
                    .unwrap_or_default()
            };
            let seq = Term::Int(rec.seq as i64);
            match rec.kind.as_str() {
                "cell.create" => facts.push(Fact {
                    pred: "create".into(),
                    terms: vec![seq, Term::Sym(get("cell")), Term::Sym(get("template"))],
                }),
                "turn.ok" => facts.push(Fact {
                    pred: "turn_ok".into(),
                    terms: vec![
                        seq,
                        Term::Sym(get("cell")),
                        Term::Sym(get("msg")),
                        Term::Int(get("us").parse::<i64>().unwrap_or(0)),
                    ],
                }),
                "turn.fail" => facts.push(Fact {
                    pred: "turn_fail".into(),
                    terms: vec![
                        seq,
                        Term::Sym(get("cell")),
                        Term::Sym(get("msg")),
                        Term::Sym(get("reason")),
                    ],
                }),
                "cell.wake" => facts.push(Fact {
                    pred: "wake".into(),
                    terms: vec![
                        seq,
                        Term::Sym(get("cell")),
                        Term::Int(get("us").parse::<i64>().unwrap_or(0)),
                    ],
                }),
                "cell.evict" => facts.push(Fact {
                    pred: "evict".into(),
                    terms: vec![seq, Term::Sym(get("cell"))],
                }),
                "cell.snapshot" => facts.push(Fact {
                    pred: "snapshot".into(),
                    terms: vec![seq, Term::Sym(get("cell")), Term::Sym(get("hash"))],
                }),
                "cell.restore" => facts.push(Fact {
                    pred: "restore".into(),
                    terms: vec![seq, Term::Sym(get("cell")), Term::Sym(get("hash"))],
                }),
                "sense.fire" => facts.push(Fact {
                    pred: "sense".into(),
                    terms: vec![seq, Term::Sym(get("source")), Term::Sym(get("name"))],
                }),
                _ => {}
            }
        }
        Ok(facts)
    }
}

fn read_records(path: &Path) -> Result<Vec<EventRecord>, StoreError> {
    if !path.exists() {
        return Ok(Vec::new());
    }
    let f = fs::File::open(path)?;
    let mut out = Vec::new();
    for line in BufReader::new(f).lines() {
        let line = line?;
        if line.trim().is_empty() {
            continue;
        }
        out.push(serde_json::from_str(&line)?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chain_append_verify_and_tamper_detection() {
        let dir = std::env::temp_dir().join(format!("sp-log-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let path = dir.join("events.jsonl");
        {
            let log = EventLog::open(&path).unwrap();
            log.append("cell.create", vec![("cell".into(), "counter".into())])
                .unwrap();
            log.append(
                "turn.ok",
                vec![
                    ("cell".into(), "counter".into()),
                    ("us".into(), "42".into()),
                ],
            )
            .unwrap();
            assert!(log.verify().is_ok());
        }
        // tamper: rewrite a line
        let data = fs::read_to_string(&path)
            .unwrap()
            .replace("counter", "hacked");
        fs::write(&path, data).unwrap();
        let log = EventLog::open(&path);
        assert!(log.is_err() || log.unwrap().verify().is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn facts_projection() {
        let dir = std::env::temp_dir().join(format!("sp-facts-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let log = EventLog::open(dir.join("e.jsonl")).unwrap();
        log.append(
            "cell.wake",
            vec![("cell".into(), "c1".into()), ("us".into(), "900".into())],
        )
        .unwrap();
        let facts = log.facts().unwrap();
        assert_eq!(facts.len(), 1);
        assert_eq!(facts[0].pred, "wake");
        let _ = fs::remove_dir_all(&dir);
    }
}
