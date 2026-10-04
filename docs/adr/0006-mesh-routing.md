# ADR-0006: Mesh routing (multi-hop envelope delivery)

Status: implemented
Date: 2026-10

## Context

The phase-4 fabric routed only to **directly** connected peers: an
envelope for a host without a socket to it failed with
`peer not connected`. Real cell grids are meshes — hosts must relay for
each other, survive relay death, and reroute around failures.

## Decision

A per-host **distance-vector routing table** (`sieveplate-fabric::mesh`):
`dest host → { next_hop (a direct peer), hops, learned_from }`.

- Peers exchange their FULL tables in `__routes` control envelopes,
  carried **inside the sealed SIEVE1 channel** — no routing data ever
  crosses a link that did not authenticate.
- Learning: a candidate replaces the existing route only when it is
  **strictly shorter** (ties keep the first route); `POISON` (≥ 64 hops)
  means withdrawal.
- **Poison-response**: a peer receiving a withdrawal for a destination it
  can still reach keeps its route AND re-announces, so the blinded host
  relearns through it. Without this, a host that loses its only path
  stays blind while neighbours hold valid alternatives they never resend.
- **Peer death**: every route whose next hop was the dead link is
  withdrawn and poisoned outward; in-flight calls are handled by crash
  detection (below).
- **Loop safety**: strict-improvement only + POISON ceiling + a
  per-envelope TTL (`MAX_HOPS = 16`) decremented at every forwarder.
- Peer keys: peers are attached under their **fabric host name**
  (announced in `__hello`), not the handshake identity name — routing
  works regardless of what the link's certificate calls the host.

## Failure semantics (multi-hop crash detection)

In-flight calls are tracked against the **link they actually use** (the
next hop), not the final destination. When a link dies:

- calls originated on this host resolve as failures immediately;
- calls this host merely FORWARDED get a `__fault` envelope routed back
  to the original caller, which resolves as a failure there too.

A caller always gets an ANSWER or a FAILURE — never a timeout that hides
the difference, at any mesh depth.

## Alternatives rejected

- **Link-state (OSPF-style)**: full topology knowledge is overkill for
  grids of pinned, long-lived peers; DV converges in O(diameter)
  announcements and is ~300 lines to audit.
- **Source routing** (encode the path in each envelope): brittle under
  churn and leaks the topology into every message.

## Consequences

- Three-host line and four-host ring tests (kill relay mid-run,
  reroute, recover on relink) live in `crates/sieveplate-ctl/tests/mesh.rs`.
- Transient loops in general graphs are possible while tables converge;
  they are bounded by TTL and self-heal via strict-improvement learning.
  Periodic table refresh is deliberately NOT implemented — updates are
  fully event-driven (link up/down).
