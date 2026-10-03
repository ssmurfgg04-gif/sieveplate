# Security Policy

## The security model in one page

Sieveplate's security posture is **object-capability discipline**:

1. **No ambient authority.** A cell can only act on targets named by
   capabilities in its own table. `ctx.send` / `ctx.call` fail with
   `NoCap` otherwise. There is no global namespace a cell can address.
2. **Authorities are explicit and attenuable.** `CapTable::attenuate`
   enforces subset-of-parent; `revoke` is immediate.
3. **Cells are failure-contained.** A handler error or panic rolls back
   only that cell's state; the vat and other cells continue. The supervisor
   bounds crash loops (one-for-one, max_restarts, respawn from template).
4. **History is tamper-evident.** The event log is a SHA-256 hash chain,
   verified on open. The CAS verifies every object on read. Silent
   corruption is a design-level non-goal: it is *detected*.
5. **Promises never hang.** A rolled-back turn resolves the caller's
   promise with an error — failures are data, not timeouts.

## Known boundaries (read before deploying)

- **In-process vats are NOT memory isolation.** Cells are isolated by
  discipline (single-threaded, message passing, capability addressing),
  not by the MMU. For mutually distrusting code, use the seL4 port target
  (`platforms/sel4/`) or OS-level process isolation around separate hosts.
- **The TCP fabric is unencrypted and unauthenticated.** It is a transport
  with a name handshake, not a security boundary. Put inter-host traffic
  inside a tunnel (WireGuard/mTLS) for anything untrusted.
- **Datalog is a query engine, not a sandbox.** Rules run against the
  fact set only; there is no I/O. Termination is bounded by an iteration
  cap.
- **Deliberate test verbs.** The bundled `counter` cell accepts `poison`
  and `panic` verbs for rollback testing. Do not register test templates in
  production registries.

## Reporting a vulnerability

Open a GitHub security advisory (Security → Report a vulnerability) rather
than a public issue. Include the crate, the turn/vat path involved, and a
minimal reproduction. We aim to acknowledge within 7 days.

## Supported versions

| version | support |
|---|---|
| 0.1.x | active development |
