//! `sieve store` — direct operations on the L3 content store.

use anyhow::{anyhow, Result};

use sieveplate_store::{datalog_query, parse_program, ContentStore, EventLog};

fn store(root: &str) -> Result<ContentStore> {
    Ok(ContentStore::open(format!("{root}/objects"))?)
}

pub fn put(text: &str, root: &str) -> Result<()> {
    let s = store(root)?;
    let h = s.put(text.as_bytes())?;
    println!("{h}");
    Ok(())
}

pub fn get(hash: &str, root: &str) -> Result<()> {
    let s = store(root)?;
    match s.get(hash)? {
        Some(bytes) => {
            println!("{}", String::from_utf8_lossy(&bytes));
            Ok(())
        }
        None => Err(anyhow!("object {hash} not found")),
    }
}

pub fn stats(root: &str) -> Result<()> {
    let s = store(root)?;
    let st = s.stats()?;
    println!("objects: {}", st.objects);
    println!("bytes:   {}", st.bytes);
    Ok(())
}

pub fn gc(root: &str) -> Result<()> {
    let s = store(root)?;
    // Keep everything reachable from the event log + plans is out of scope
    // for the raw store command; users should know what they keep.
    let all = s.list()?;
    let removed = s.gc(all)?;
    println!("gc removed 0 unreachable objects (all listed as reachable)");
    let _ = removed;
    Ok(())
}

pub fn verify(root: &str) -> Result<()> {
    let log = EventLog::open(format!("{root}/events.jsonl"))?;
    log.verify()?;
    println!("✓ event log intact ({} records, hash-chained)", log.len()?);
    Ok(())
}

pub fn query(goal: &str, rules: &[String], root: &str) -> Result<()> {
    let log = EventLog::open(format!("{root}/events.jsonl"))?;
    let facts = log.facts()?;
    let mut rule_src = String::new();
    for r in rules {
        rule_src.push_str(r.trim());
        if !rule_src.ends_with('.') {
            rule_src.push('.');
        }
        rule_src.push(' ');
    }
    let parsed = parse_program(&rule_src).map_err(|e| anyhow!("rules: {e}"))?;
    let sols = datalog_query(&facts, &parsed.rules, goal).map_err(|e| anyhow!("query: {e}"))?;
    // Header: goal variables in order.
    let goal_parsed = parse_program(goal).ok().and_then(|p| p.goal);
    if let Some((_, terms)) = goal_parsed {
        let vars: Vec<&String> = terms
            .iter()
            .filter_map(|t| match t {
                sieveplate_store::Term::Var(v) => Some(v),
                _ => None,
            })
            .collect();
        if !vars.is_empty() {
            let names: Vec<String> = vars.iter().map(|v| v.to_string()).collect();
            println!("{}", names.join(" | "));
            println!("{}", vec!["-"; names.len() * 4].join(""));
        }
    }
    for row in &sols {
        let cells: Vec<String> = row.iter().map(|t| t.to_string()).collect();
        println!("{}", cells.join(" | "));
    }
    println!("\n({} solutions over {} facts)", sols.len(), facts.len());
    Ok(())
}
