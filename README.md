# LISPMIND

LISPMIND is a research platform for autonomous, self-healing multi-agent systems implemented in ANSI Common Lisp (SBCL). It combines genetic programming for strategy optimization, CLOS Metaobject Protocol hooks for runtime code evolution, multi-tier fault tolerance spanning userland through firmware, and hardware-bound encrypted credential vaults — all inside a single long-running Lisp image that recovers without process restarts. MIT licensed; the changelog's latest entry is v2.5.1 (the `.asd` still carries 2.5.0).

## Features

- **Agent orchestration** — CLOS-based agent classes (`agent-class.lisp`, `orchestrator.lisp`) with a macros DSL, checkpoints, and image-level persistence (`checkpoint.lisp`, `image-persist.lisp`) for resurrection without restarts.
- **Genetic strategy evolution** — tree-based genetic programming (`evolution.lisp`, `evolution-v2.4.lisp`) optimizes agent fitness functions at runtime; hotpatching (`hotpatch.lisp`) applies changes live.
- **Encrypted resource vault** — AES-256-GCM encrypted storage (vendored Ironclad) with TPM-bound keys, ChaCha8 obfuscation, and emergency break-glass protocols (`resource-registry.lisp`, `break-glass.lisp`: shred-all-assets, radio-silence, diagnostics).
- **Distributed coordination** — gossip mesh v2.4 with 64-byte heartbeats, 256-byte commands, jittered intervals, and TLS camouflage (`gossip.lisp`, `gossip-v2.4.lisp`).
- **Kernel/hardware integration (v2.5)** — eBPF/LKM/UEFI interfaces, kernel orchestrator, and persistence hierarchy spanning userland → kernel → firmware (`kernel-orchestrator.lisp`, `persistence-hierarchy.lisp`, `rust-ffi-bridge.lisp`).
- **Operational tooling** — dashboard (`dashboard.lisp`), telemetry, websocket interface, MCP bridge, OSINT engine, policy gatekeeper, operational validator, and an integration checklist / stress-test suite (`demo.lisp`, `operational-validator.lisp`).

## Tech stack

ANSI Common Lisp (SBCL 2.3+), ASDF (`lispmind.asd`, serial build of 34 modules), Quicklisp (bordeaux-threads, closer-mop, alexandria, cl-ppcre, local-time, cl-store, lparallel, ironclad, cl-base64), vendored Ironclad, optional libzmq (gossip mesh).

## Getting started

From `docs/GETTING_STARTED.md`:

- Install SBCL 2.3+ and Quicklisp
- Quickload the dependencies listed above (bordeaux-threads, closer-mop, alexandria, cl-ppcre, local-time, cl-store, lparallel, ironclad, cl-base64; optional `cl-zeromq` with libzmq3-dev)
- Load the system: `(ql:quickload :lispmind)` — or `(asdf:load-system :lispmind)`
- Run the demo: `(lispmind:run-demo)`; run the integration checklist: `(lispmind:run-integration-checklist)`

## Project structure

```
.
├── lispmind.asd           # ASDF system definition (34 serial modules)
├── *.lisp                 # agent-class, orchestrator, evolution, gossip, checkpoint,
│                          #   image-persist, telemetry, dashboard, demo, inference,
│                          #   resource-registry (vault), break-glass, mcp-bridge,
│                          #   osint-engine, kernel-orchestrator, persistence-hierarchy,
│                          #   rust-ffi-bridge, policy-gatekeeper, ...
├── docs/                  # ARCHITECTURE.md, GETTING_STARTED.md
├── CHANGELOG.md           # version history (2.5.1)
└── CITATION.cff, LICENSE
```

## Status

**Real project, large.** ~80k lines of Common Lisp with full docs and a changelog. The repo ships a long-form research-style README (motivation, architecture diagram, design principles); this is a condensed version grounded in `lispmind.asd`, `docs/GETTING_STARTED.md`, and the module list.
