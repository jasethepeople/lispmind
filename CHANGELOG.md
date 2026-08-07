# Changelog

All notable changes to LISPMIND are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.5.1] -- 2025-07-04 -- Operational Research

### Added
- **TTR (Time-to-Recover) Measurement** -- Automatic timing of every persistence recovery event with SLA compliance checking (<= 300 seconds)
- **Alert Storm Suppression** -- Sliding-window rate limiter prevents telemetry flooding during recovery cascades (max 3 alerts/60s per event type)
- **Stress Testing** -- `(stress-test-recovery N)` runs N simulated recovery cycles and reports statistical summary
- **TLS Camouflage** -- JA3-compatible TLS fingerprints for gossip mesh traffic, matching Chrome, Firefox, Safari, or Edge profiles
- **TLS Fingerprint Rotation** -- Automatic rotation of TLS profile every hour to avoid static fingerprint cataloging
- **Host Browser Detection** -- Auto-detect the host's real browser and match its fingerprint
- **Break-Glass Emergency Protocols**:
  - `(shred-all-assets)` -- 4-phase emergency destruction: zero-fill keys, poison heap memory, unload all kernel implants, delete logs, exit process
  - `(radio-silence-trigger)` -- Enter dormant mode: halt all network activity, suspend persistence manager, monitor for wake-up file signal
  - `(break-glass-diagnostics)` -- 13-point emergency readiness verification
- **Operational Validation Suite** -- 7 automated checks: VM baseline, telemetry jitter (50-70s), TPM availability, gossip mesh topology, persistence health, vault initialization, FFI status
- **Forward Declarations** -- `forward-declarations.lisp` with DEFVAR stubs for 50+ special variables to prevent ASDF serial compilation failures
- **Integration Checklist** -- `(run-integration-checklist)` comprehensive validation with pass/fail reporting

### Security
- Jittered 50-70s heartbeat interval to prevent behavioral pattern detection
- Randomized 120-300s watchdog interval with no predictable persistence checks
- TPM-derived HMAC key derivation (key never stored in userland memory)
- PBKDF2 200,000 iterations with multi-artifact hardware binding
- ChaCha8 stream cipher replaces trivial XOR obfuscation for load-time protection
- AES-256-GCM with strict authentication tag verification on every decrypt
- Load-aware healing: pauses when security tools or users are active
- Low-key asset detection: uses LSPs, port scanning, and process lists instead of WMI/registry queries
- `with-kernel-persistence-cleanup` macro: removes all artifacts on failed deployment
- 4-phase emergency shred: multi-pass overwrite, random renames, filesystem sync
- Per-step init watchdog timers with graceful degradation on timeout
- Release build flag: removes ASCII banner and debug output in production
- Integrity scan detection: pauses persistence during sfc, chkdsk, AV scans
- Generic error codes in production mode to prevent sensitive state leakage
- Gossip alert on FFI stub fallback with operator confirmation required
- GC-safe pinned objects (`sb-sys:with-pinned-objects`) for all FFI string/vector passing
- Buffer size validation before every C call (max 16MB, max string 4096)

### Fixed
- **8 Forward Reference Violations** -- Reordered ASDF components so infrastructure compiles before consumers; added `forward-declarations.lisp`
- **Runtime Crash** -- `handle-condition` in `agent-class.lisp` now defends against `UNBOUND-SLOT`, `NIL`, and non-function restart policies, returning `:RETRY` instead of crashing
- **2 API Inconsistencies** -- Renamed shadowed functions in `system-init-v2.5.lisp`:
  - `handle-kernel-load-request` -> `handle-gossip-kernel-load-request`
  - `handle-kernel-load-response` -> `handle-gossip-kernel-load-response`

---

## [2.5.0] -- 2025-07-04 -- ABSOLUTE

### Added
- **Kernel Orchestrator** -- Kernel-level agent management with 16 tools: 5 eBPF, 4 LKM, 4 drivers, 3 UEFI implants
- **OS Fingerprinting** -- TTL analysis, port scanning, banner extraction for automatic implant selection
- **Stealth Hook Registry** -- Tracks all kernel hooks with memory offsets and original bytes for restoration
- **Kernel-Denied Back-Off** -- Automatic fallback to userland when kernel access is blocked
- **HMAC Authentication** -- Signed gossip messages for kernel load requests
- **3-Tier Escalating Persistence**:
  - Tier 1 (Userland): 17 methods -- registry, WMI, schtasks, services, startup, winlogon, IFEO, COM, DLL hijack, systemd, cron, bashrc, LD_PRELOAD, MOTD, rc.local
  - Tier 2 (Kernel): 8 methods -- eBPF, LKM, SSDT hook, IRP hook, minifilter, kernel callback, kprobe, ftrace
  - Tier 3 (Firmware): 5 methods -- UEFI bootkit, SMM implant, ACPI rootkit, BIOS Option ROM, MBR bootkit
- **Strategic Asset Detection** -- 10 indicators: DC, cloud mgmt, DB server, cred vault, Exchange, VPN, jump host, network centrality, backup, file server
- **Self-Healing Watchdog** -- 30-second interval monitoring with automatic recovery and circuit breaker (5 failures = operator alert)
- **Rust FFI Bridge** -- SBCL `sb-alien` bindings to `liblispmind_core.so` with 7 C functions: deploy_implant, check_health, unload_implant, shared_memory_read, shared_memory_write, get_implant_info, rotate_transport
- **Encrypted Resource Vault** -- AES-256-GCM encrypted vault for binary blobs with hardware-bound key derivation, XOR load-time obfuscation, Base64 transport encoding
- **Master Init v2.5** -- 9-step ordered initialization wiring all modules, persistence state manager, health monitor

### Security
- Fail-closed 6-layer policy gatekeeper with 8 profiles
- Categorical ARM/DISARM safety framework
- Max concurrent execution limits
- Target whitelist enforcement
- Root-required flag for sensitive operations

---

## [2.4.0] -- 2025-07-04 -- Tactical Swarm

### Added
- **145 Offensive Tools** -- Full Kali Linux integration via `kali-interface.lisp`
- **Zero-Delay Execution Pipeline** -- No simulation, direct tool invocation
- **TTS (Time-to-Shell) Fitness Function** -- Genetic evolution optimized for real-world shell acquisition speed
- **LOLBin-Aware Mutation** -- Avoids living-off-the-land binaries to evade behavioral detection
- **Pivot Chains** -- Recursive tunneling via Chisel and Ligolo-ng
- **In-Memory Reflective Loading** -- No disk touch for sensitive operations
- **Low-Bandwidth Gossip Mesh** -- 64B heartbeat, 256B commands, 10KB/s ceiling
- **Tactical Checkpoint** -- Resume-from-death: serialize network map + pivot chains + sessions every 30 seconds
- **Fail-Fast Rotation** -- Rapid agent replacement on tool failure
- **Persistence-First Design** -- Every foothold immediately establishes userland persistence

---

## [2.3.2] -- 2025-07-04 -- Engineering & Scientific Module

### Added
- **153 Scientific Tools** -- Math, physics, CAD, electronics, AI/ML integration
- **OpenFOAM Interface** -- CFD simulation orchestration
- **FreeCAD/KiCad Integration** -- Parametric modeling and PCB design
- **TensorFlow/PyTorch/Julia Bridges** -- Neural network and scientific computing
- **Physical Safety Profile** -- Thermal monitoring, hardware bounds checking
- **`define-agent-tool` Macro** -- Code generation for scientific tool wrappers

---

## [2.3.1] -- 2025-07-04 -- Offensive Suite

### Added
- **Policy Gatekeeper** -- 6-layer safety: category armed, override, forbidden patterns, target whitelist, max concurrent, root required
- **8 Safety Profiles** -- `:default`, `:recon`, `:offensive`, `:defensive`, `:maintenance`, `:physical`, `:research`, `:break-glass`
- **MCP Bridge Server** -- Model Context Protocol with 35 tools and 25 resources
- **LOLBin Registry** -- Living-off-the-land binary catalog for evasion

---

## [2.3.0] -- 2025-07-04 -- Intelligence Layer

### Added
- **OSINT Engine** -- 8 collectors: DNS, WHOIS, Shodan, certificate transparency, geolocation, breach databases, social media, dark web
- **Knowledge Graph** -- Relationship mapping between discovered entities
- **Model Router** -- Automatic LLM selection (Llama, Hermes, CodeLlama) based on task type

---

## [2.0.0] -- 2025-07-04 -- The Immortal Swarm

### Added
- **Genetic Programming Evolution** -- Tree-based agent strategy evolution with tournament selection
- **ZeroMQ Gossip Mesh** -- Distributed PUB/SUB agent communication
- **Golden Image Persistence** -- cl-store serialization for image-level resurrection
- **Real-Time FlameGraphs** -- sb-sprof profiling with automatic bottleneck detection
- **Auto-Tuning** -- Self-adjusting agent parameters based on performance metrics
- **WebSocket Telemetry** -- Real-time metrics streaming to external dashboards

---

## [1.0.0] -- 2025-07-04 -- The Foundation

### Added
- **Self-Healing Orchestrator** -- Monitor loop with 7 automatic restart strategies
- **CLOS MOP Hooks** -- `:around` methods for transparent agent interception
- **Hot-Patching** -- Zero-downtime strategy replacement via `update-agent-strategy`
- **Condition/Restart Protocol** -- Lisp-native error recovery with `define-condition` and `find-restart`
- **Agent Factory** -- `define-agent-type` macro for rapid agent generation
- **ASCII Dashboard** -- Real-time REPL visualization of swarm state

---

## Version Summary

| Version | Codename | Theme | Lines |
|---------|----------|-------|-------|
| 1.0.0 | Foundation | Self-healing, MOP, hot-patching | ~15,000 |
| 2.0.0 | Immortal Swarm | Evolution, gossip, golden images | +20,000 |
| 2.3.0 | Intelligence | OSINT, LLM routing, knowledge graph | +5,000 |
| 2.3.1 | Offensive Suite | 145 tools, gatekeeper, MCP bridge | +8,000 |
| 2.3.2 | Engineering | 153 scientific tools, physical safety | +4,000 |
| 2.4.0 | Tactical Swarm | Zero-delay, TTS fitness, pivot chains | +10,000 |
| 2.5.0 | ABSOLUTE | Kernel implants, 3-tier persistence, FFI | +14,000 |
| 2.5.1 | Operational Research | TTR, TLS camo, break-glass, validation | +4,000 |
| **Total** | | | **~80,398** |
