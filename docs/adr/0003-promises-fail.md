# ADR-0003: Promises fail — no silent timeouts

Status: accepted · Date: 2026-10-03

## Context

Actor systems classically handle failed calls with timeouts. In a system
where turns roll back atomically, a timeout is a lie: the runtime *knows*
the call failed and *why* — it just failed to say so. During the Phase-1
build we found (and fixed) a fault-cascade bug where failure envelopes
aimed at nonexistent cells generated further failures forever.

## Decision

1. **Promises have an error outcome.** `Promises::resolve_fail(pid,
   reason)`; waiters receive `Err(reason)`. A rolled-back turn, an unknown
   target, or a failed wake resolves the caller's promise instead of
   dropping the reply.
2. **Faults never cascade.** The vat consumes fabric-level envelopes
   (`__reply`, `__fault`) at its boundary and never delivers them to cells.
   `__fault` envelopes flow only to *real* originating cells; external
   callers get promise failures.
3. **Foreign promises are ignored.** A reply hopping through a host whose
   registry did not mint the promise is routed onward, not recorded —
   resolve on unknown ids is a no-op (no unbounded growth).
4. **Timeouts remain** only as a last-resort liveness net at call sites;
   they are not the error-handling mechanism.

## Consequences

- Callers get precise error reasons; retries become policy, not guessing.
- The failure of one cell can never loop another into permanent work.
- `mint()` creates the promise slot eagerly, closing the resolve-before-
  waiter race.
