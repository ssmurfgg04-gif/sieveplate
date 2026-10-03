# ADR-0001: Name — `sieveplate`

Status: accepted · Date: 2026-10-03

## Context

The guiding specification's working title was "AURA-OS". Two problems:
(1) it reads as a backronym with cosmic aesthetics — the tacky register the
team explicitly wanted to avoid; (2) the name is in use.

## Candidates evaluated (GitHub availability checked 2026-10-03,
repo + user/org search)

| candidate | verdict |
|---|---|
| aura / aura-os | taken; tacky (rejected up front) |
| symplast | existing repos + squatted user |
| phloem | `Phloem-AI`, `autumnai/phloem` |
| cambium | ★499 LLM-governance project + Cambium Networks shadow |
| parenchyma | ★76 HPC framework |
| cellwright / protoplast / meristem / tonoplast | collisions at various sizes |
| **sieveplate** | **0 repos, 0 orgs** |
| metaphloem | 0 collisions (runner-up, kept as fallback) |

## Decision

**sieveplate.** In plant anatomy, the sieve plate is the perforated
end-wall shared by two living sieve-tube cells: signals and nutrients pass
through the perforations, and the cells can seal the openings on demand.
That is the architecture in one word — living cells, gated channels,
flowing signals, sealable boundaries. The binary is `sieve`.

## Consequences

- Zero GitHub name collision at adoption time (verified).
- The botanical metaphor gives us honest vocabulary: cells, vats, senses,
  fabric, membranes. Resist metaphor creep beyond real mechanisms.
- `metaphloem` remains available as a rename candidate if a serious
  trademark conflict ever surfaces.
