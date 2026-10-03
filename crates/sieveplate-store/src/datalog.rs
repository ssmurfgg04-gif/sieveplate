//! Embedded Datalog engine — the semantic query layer of the L3 store.
//!
//! Why Datalog: "searching for a file" in Sieveplate is a *temporal query
//! over the event log*, not a path lookup. Facts about what happened
//! (turns, wakes, evictions) are projected from the hash-chained event log;
//! rules define semantic relations over those facts.
//!
//! Implementation: a compact, dependency-free Datalog with
//! - facts:  `edge(a, b).`
//! - rules:  `path(X, Y) :- edge(X, Z), path(Z, Y).`
//! - goals:  `path(a, X)?`
//!
//! Terms are symbols, integers, or variables. Evaluation is naive fixpoint
//! (with an iteration cap) — entirely adequate for system-log scale.

use std::collections::BTreeMap;
use std::fmt;

use crate::error::StoreError;

/// A Datalog term: symbol, integer, or variable.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Term {
    Sym(String),
    Int(i64),
    Var(String),
}

impl fmt::Display for Term {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Term::Sym(s) => write!(f, "{s}"),
            Term::Int(i) => write!(f, "{i}"),
            Term::Var(v) => write!(f, "{v}"),
        }
    }
}

/// A ground fact: `pred(t1, ..., tn).`
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Fact {
    pub pred: String,
    pub terms: Vec<Term>,
}

/// A rule: `head :- body1, body2, ...`
#[derive(Debug, Clone)]
pub struct Rule {
    pub head: (String, Vec<Term>),
    pub body: Vec<(String, Vec<Term>)>,
}

/// A parsed program: facts + rules + an optional goal.
#[derive(Debug, Default)]
pub struct Program {
    pub facts: Vec<Fact>,
    pub rules: Vec<Rule>,
    pub goal: Option<(String, Vec<Term>)>,
}

// ---------------------------------------------------------------------------
// Parser
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq)]
enum Tok {
    Ident(String),
    Int(i64),
    LParen,
    RParen,
    Comma,
    Dot,
    ColonDash,
    Question,
}

fn tokenize(src: &str) -> Result<Vec<Tok>, StoreError> {
    let mut toks = Vec::new();
    let mut chars = src.chars().peekable();
    while let Some(&c) = chars.peek() {
        match c {
            ' ' | '\t' | '\n' | '\r' => {
                chars.next();
            }
            '(' => {
                toks.push(Tok::LParen);
                chars.next();
            }
            ')' => {
                toks.push(Tok::RParen);
                chars.next();
            }
            ',' => {
                toks.push(Tok::Comma);
                chars.next();
            }
            '.' => {
                toks.push(Tok::Dot);
                chars.next();
            }
            '?' => {
                toks.push(Tok::Question);
                chars.next();
            }
            ':' => {
                chars.next();
                if chars.peek() == Some(&'-') {
                    chars.next();
                    toks.push(Tok::ColonDash);
                } else {
                    return Err(StoreError::Datalog("expected ':-' after ':'".into()));
                }
            }
            '"' => {
                chars.next();
                let mut s = String::new();
                while let Some(&c2) = chars.peek() {
                    if c2 == '"' {
                        break;
                    }
                    s.push(c2);
                    chars.next();
                }
                if chars.next() != Some('"') {
                    return Err(StoreError::Datalog("unterminated quoted symbol".into()));
                }
                toks.push(Tok::Ident(s));
            }
            c if c.is_ascii_digit() => {
                let mut s = String::new();
                while let Some(&c2) = chars.peek() {
                    if !c2.is_ascii_digit() {
                        break;
                    }
                    s.push(c2);
                    chars.next();
                }
                toks.push(Tok::Int(
                    s.parse()
                        .map_err(|_| StoreError::Datalog(format!("bad integer: {s}")))?,
                ));
            }
            c if c.is_alphabetic() || c == '_' => {
                let mut s = String::new();
                while let Some(&c2) = chars.peek() {
                    if !(c2.is_alphanumeric() || c2 == '_' || c2 == '-' || c2 == '/') {
                        break;
                    }
                    s.push(c2);
                    chars.next();
                }
                toks.push(Tok::Ident(s));
            }
            other => {
                return Err(StoreError::Datalog(format!(
                    "unexpected character '{other}'"
                )))
            }
        }
    }
    Ok(toks)
}

fn term_of_ident(name: &str) -> Term {
    // Uppercase or leading underscore => variable.
    if name.starts_with('_')
        || name
            .chars()
            .next()
            .map(|c| c.is_uppercase())
            .unwrap_or(false)
    {
        Term::Var(name.to_string())
    } else {
        Term::Sym(name.to_string())
    }
}

fn parse_atom(toks: &[Tok], pos: &mut usize) -> Result<(String, Vec<Term>), StoreError> {
    let pred = match toks.get(*pos) {
        Some(Tok::Ident(s)) => s.clone(),
        _ => return Err(StoreError::Datalog("expected predicate name".into())),
    };
    *pos += 1;
    let mut terms = Vec::new();
    if matches!(toks.get(*pos), Some(Tok::LParen)) {
        *pos += 1;
        loop {
            match toks.get(*pos) {
                Some(Tok::Ident(s)) => {
                    terms.push(term_of_ident(s));
                    *pos += 1;
                }
                Some(Tok::Int(i)) => {
                    terms.push(Term::Int(*i));
                    *pos += 1;
                }
                _ => return Err(StoreError::Datalog("expected term".into())),
            }
            match toks.get(*pos) {
                Some(Tok::Comma) => *pos += 1,
                Some(Tok::RParen) => {
                    *pos += 1;
                    break;
                }
                _ => return Err(StoreError::Datalog("expected ',' or ')'".into())),
            }
        }
    }
    Ok((pred, terms))
}

/// Parse a program: any number of facts and rules, optionally ending with a
/// goal terminated by `?`.
pub fn parse_program(src: &str) -> Result<Program, StoreError> {
    let toks = tokenize(src)?;
    let mut prog = Program::default();
    let mut pos = 0usize;
    while pos < toks.len() {
        let atom = parse_atom(&toks, &mut pos)?;
        match toks.get(pos) {
            Some(Tok::Dot) => {
                pos += 1;
                prog.facts.push(Fact {
                    pred: atom.0,
                    terms: atom.1,
                });
            }
            Some(Tok::Question) => {
                pos += 1;
                prog.goal = Some(atom);
            }
            Some(Tok::ColonDash) => {
                pos += 1;
                let mut body = Vec::new();
                loop {
                    let b = parse_atom(&toks, &mut pos)?;
                    body.push(b);
                    match toks.get(pos) {
                        Some(Tok::Comma) => pos += 1,
                        Some(Tok::Dot) => {
                            pos += 1;
                            break;
                        }
                        _ => {
                            return Err(StoreError::Datalog(
                                "expected ',' or '.' in rule body".into(),
                            ))
                        }
                    }
                }
                prog.rules.push(Rule { head: atom, body });
            }
            _ => return Err(StoreError::Datalog("expected '.', '?' or ':-'".into())),
        }
    }
    Ok(prog)
}

// ---------------------------------------------------------------------------
// Evaluation
// ---------------------------------------------------------------------------

type Subst = BTreeMap<String, Term>;

fn walk(t: &Term, s: &Subst) -> Term {
    match t {
        Term::Var(v) => match s.get(v) {
            Some(t2) => walk(t2, s),
            None => t.clone(),
        },
        other => other.clone(),
    }
}

fn unify(a: &[Term], b: &[Term], s: &Subst) -> Option<Subst> {
    if a.len() != b.len() {
        return None;
    }
    let mut s = s.clone();
    for (x, y) in a.iter().zip(b.iter()) {
        let x = walk(x, &s);
        let y = walk(y, &s);
        match (&x, &y) {
            (Term::Var(v), _) => {
                s.insert(v.clone(), y);
            }
            (_, Term::Var(v)) => {
                s.insert(v.clone(), x);
            }
            _ if x == y => {}
            _ => return None,
        }
    }
    Some(s)
}

/// Naive-fixpoint evaluation. `max_iters` guards runaway programs.
fn fixpoint(prog: &Program, max_iters: usize) -> BTreeMap<(String, usize), Vec<Vec<Term>>> {
    // facts indexed by (pred, arity)
    let mut db: BTreeMap<(String, usize), Vec<Vec<Term>>> = BTreeMap::new();
    let mut index_of: BTreeMap<Vec<Term>, ()> = BTreeMap::new();

    let insert = |db: &mut BTreeMap<(String, usize), Vec<Vec<Term>>>,
                  pred: &str,
                  terms: Vec<Term>,
                  seen: &mut BTreeMap<Vec<Term>, ()>| {
        let key = (pred.to_string(), terms.len());
        let entry = db.entry(key).or_default();
        let fingerprint = vec![Term::Sym(pred.to_string())]
            .into_iter()
            .chain(terms.iter().cloned())
            .collect::<Vec<_>>();
        if seen.insert(fingerprint, ()).is_none() {
            entry.push(terms);
        }
    };

    for f in &prog.facts {
        insert(&mut db, &f.pred, f.terms.clone(), &mut index_of);
    }

    for _ in 0..max_iters {
        let mut changed = false;
        for rule in &prog.rules {
            // Collect all matches for the first body atom, then join.
            let results = eval_rule(rule, &db);
            for terms in results {
                let before = db
                    .get(&(rule.head.0.clone(), rule.head.1.len()))
                    .map(|v| v.len())
                    .unwrap_or(0);
                insert(&mut db, &rule.head.0, terms, &mut index_of);
                let after = db
                    .get(&(rule.head.0.clone(), rule.head.1.len()))
                    .map(|v| v.len())
                    .unwrap_or(0);
                if after > before {
                    changed = true;
                }
            }
        }
        if !changed {
            break;
        }
    }
    db
}

fn eval_rule(rule: &Rule, db: &BTreeMap<(String, usize), Vec<Vec<Term>>>) -> Vec<Vec<Term>> {
    let mut subs: Vec<Subst> = vec![BTreeMap::new()];
    for (pred, terms) in &rule.body {
        let candidates = db
            .get(&(pred.clone(), terms.len()))
            .cloned()
            .unwrap_or_default();
        let mut next = Vec::new();
        for s in &subs {
            let wanted: Vec<Term> = terms.iter().map(|t| walk(t, s)).collect();
            for c in &candidates {
                if let Some(s2) = unify(&wanted, c, s) {
                    next.push(s2);
                }
            }
        }
        subs = next;
        if subs.is_empty() {
            break;
        }
    }
    // Project onto head terms.
    let mut out = Vec::new();
    for s in subs {
        out.push(rule.head.1.iter().map(|t| walk(t, &s)).collect());
    }
    out
}

/// Evaluate a program and return goal bindings (one Vec per solution,
/// containing values for the goal's variables in order of appearance).
pub fn query(facts: &[Fact], rules: &[Rule], goal: &str) -> Result<Vec<Vec<Term>>, StoreError> {
    let mut prog = Program {
        facts: facts.to_vec(),
        rules: rules.to_vec(),
        goal: None,
    };
    let parsed = parse_program(goal)?;
    // Anything parsed as facts here is treated as extra rules/facts context.
    prog.facts.extend(parsed.facts);
    prog.rules.extend(parsed.rules);
    let goal = parsed
        .goal
        .ok_or_else(|| StoreError::Datalog("goal must end with '?' e.g. 'path(a, X)?'".into()))?;

    let db = fixpoint(&prog, 10_000);
    let candidates = db
        .get(&(goal.0.clone(), goal.1.len()))
        .cloned()
        .unwrap_or_default();

    let mut order: Vec<String> = Vec::new();
    for t in &goal.1 {
        if let Term::Var(v) = t {
            if !order.contains(v) {
                order.push(v.clone());
            }
        }
    }

    let mut out = Vec::new();
    let mut seen: BTreeMap<Vec<Term>, ()> = BTreeMap::new();
    for c in &candidates {
        if let Some(s) = unify(&goal.1, c, &BTreeMap::new()) {
            let row: Vec<Term> = order
                .iter()
                .map(|v| walk(&Term::Var(v.clone()), &s))
                .collect();
            if seen.insert(row.clone(), ()).is_none() {
                out.push(row);
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fact(pred: &str, terms: &[Term]) -> Fact {
        Fact {
            pred: pred.into(),
            terms: terms.to_vec(),
        }
    }

    #[test]
    fn parses_and_queries_simple_goal() {
        let prog = parse_program("edge(a, b). edge(b, c). edge(a, X)?").unwrap();
        assert_eq!(prog.facts.len(), 2); // the goal atom is the query, not a fact
        assert_eq!(prog.goal.as_ref().unwrap().0, "edge");
    }

    #[test]
    fn recursive_transitive_closure() {
        let facts = vec![
            fact("edge", &[Term::Sym("a".into()), Term::Sym("b".into())]),
            fact("edge", &[Term::Sym("b".into()), Term::Sym("c".into())]),
            fact("edge", &[Term::Sym("c".into()), Term::Sym("d".into())]),
        ];
        let rules =
            parse_program("path(X, Y) :- edge(X, Y). path(X, Y) :- edge(X, Z), path(Z, Y).")
                .unwrap()
                .rules;
        let mut sols = query(&facts, &rules, "path(a, X)?").unwrap();
        sols.sort();
        let syms: Vec<String> = sols
            .into_iter()
            .map(|row| match &row[0] {
                Term::Sym(s) => s.clone(),
                other => format!("{other}"),
            })
            .collect();
        assert_eq!(syms, vec!["b", "c", "d"]);
    }

    #[test]
    fn joins_and_ints() {
        let facts = vec![
            fact(
                "wake",
                &[Term::Int(1), Term::Sym("c1".into()), Term::Int(900)],
            ),
            fact(
                "wake",
                &[Term::Int(2), Term::Sym("c2".into()), Term::Int(1200)],
            ),
        ];
        // Slow wakes: wake(SEQ, C, US), US > 1000 — express as rule matching const.
        let rules = parse_program("slow(C) :- wake(_, C, 1200).").unwrap().rules;
        let sols = query(&facts, &rules, "slow(C)?").unwrap();
        assert_eq!(sols.len(), 1);
        assert_eq!(sols[0][0], Term::Sym("c2".into()));
    }
}
