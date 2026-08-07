# LISPMIND Architecture Documentation

## Table of Contents

1. [System Overview](#system-overview)
2. [Agent Lifecycle](#agent-lifecycle)
3. [Resilience Model](#resilience-model)
4. [Kernel Integration](#kernel-integration)
5. [Gossip Mesh Protocol](#gossip-mesh-protocol)
6. [Evolutionary Engine](#evolutionary-engine)
7. [Security Architecture](#security-architecture)
8. [Emergency Protocols](#emergency-protocols)
9. [Operational Validation](#operational-validation)

---

## System Overview

LISPMIND operates as a single, long-running SBCL image. All components share the same address space, enabling zero-copy communication between agents, the orchestrator, and the kernel bridge. The system is organized into layers:

### Layer 0: Foundation
- **Package System** (`packages.lisp`): 263+ exported symbols
- **Condition System** (`conditions.lisp`): Hierarchical conditions with 6 restart strategies
- **MOP Hooks** (`agent-class.lisp`): `:around` methods on `agent` class for transparent interception
- **Macro Factory** (`macros.lisp`): `define-agent-type` generates complete agent classes

### Layer 1: Core Runtime
- **Orchestrator** (`orchestrator.lisp`): Agent registry, 2-second monitor loop, healing engine
- **Hotpatch** (`hotpatch.lisp`): Runtime strategy replacement without restart
- **Checkpoint** (`checkpoint.lisp`): cl-store serialization for state preservation
- **Profiler** (`profiler.lisp`): sb-sprof flamegraphs with auto-tuning

### Layer 2: Distributed Mesh
- **Gossip** (`gossip.lisp`, `gossip-v2.4.lisp`): ZeroMQ PUB/SUB with tactical low-bandwidth mode
- **Telemetry** (`telemetry.lisp`): Metrics pipeline with 50-70s jitter
- **WebSocket** (`websocket.lisp`): Real-time dashboard streaming

### Layer 3: Intelligence
- **Evolution** (`evolution.lisp`, `evolution-v2.4.lisp`): Tree-based genetic programming
- **Inference** (`inference.lisp`): LLM model router
- **OSINT** (`osint-engine.lisp`): 8 collectors with knowledge graph

### Layer 4: Tool Integration
- **Security Assessment** (`kali-interface.lisp`): 145 security tool wrappers
- **Engineering** (`engineering-interface.lisp`): 153 scientific tool wrappers
- **MCP Bridge** (`mcp-bridge.lisp`): Model Context Protocol server

### Layer 5: Kernel/Hardware
- **Kernel Orchestrator** (`kernel-orchestrator.lisp`): eBPF/LKM/Driver/UEFI management
- **Resilience Hierarchy** (`persistence-hierarchy.lisp`): 3-tier escalating resilience
- **Rust FFI** (`rust-ffi-bridge.lisp`): C-ABI bridge to liblispmind_core.so
- **Resource Vault** (`resource-registry.lisp`): AES-256-GCM encrypted blob storage

### Layer 6: Operational
- **Emergency Shutdown** (`break-glass.lisp`): Sanitization protocols
- **Validator** (`operational-validator.lisp`): Integration test suite

---

## Agent Lifecycle

```
CREATE -> MONITOR -> (HEAL|EVOLVE|REPLACE) -> CHECKPOINT -> PERSIST
  ^                                                           |
  |___________________________________________________________|
```

1. **CREATE**: `make-agent` or `define-agent-type` macro
2. **MONITOR**: Orchestrator's 2-second loop checks health, restarts, errors
3. **HEAL**: Condition/restart protocol attempts 7 strategies:
   - `:retry` -- immediate retry
   - `:reconnect` -- network reconnect
   - `:reload` -- reload configuration
   - `:hotpatch` -- live strategy replacement
   - `:restart` -- process restart (preserves state)
   - `:evolve` -- genetic mutation
   - `:rebirth` -- full agent replacement
4. **EVOLVE**: Genetic programming optimizes strategy tree
5. **REPLACE**: Agent replaced with evolved clone, state transferred
6. **CHECKPOINT**: State serialized to disk via cl-store
7. **PERSIST**: Userland/kernel/firmware hooks ensure survival across reboots

---

## Resilience Model

The 3-tier model implements a **value-based escalation strategy**:

```
Target Value Assessment
         |
    +----+----+
    |         |
  < 50      >= 50
    |         |
 Tier 1    Tier 2
(Userland) (Kernel)
    |         |
    +----+----+
         |
    Strategic Asset?
         |
    +----+----+
    |         |
   No       Yes
    |         |
  Stop    Tier 3
         (Firmware)
```

### Tier 1: Userland (17 methods)
- Windows: Registry Run keys, WMI event subscriptions, scheduled tasks, services, winlogon shell, IFEO, COM hijacking, DLL search order hijacking
- Linux: systemd services, cron jobs, bashrc/rc modifications, LD_PRELOAD, MOTD, rc.local

### Tier 2: Kernel (8 methods)
- eBPF programs (network, tracepoint, kprobe)
- Loadable Kernel Modules (LKM)
- SSDT (System Service Descriptor Table) hooks
- IRP (I/O Request Packet) hooks
- Minifilter drivers
- Kernel callbacks (process, thread, image load)
- Kprobes and ftrace

### Tier 3: Firmware (5 methods)
- UEFI bootkit (DXE driver injection)
- SMM (System Management Mode) implant
- ACPI rootkit (DSDT/SSDT table modification)
- BIOS Option ROM
- MBR bootkit

---

## Kernel Integration

### OS Fingerprinting
Before deploying any kernel probe, LISPMIND fingerprints the target:

1. **TTL Analysis**: OS-specific default TTL values (Linux=64, Windows=128, BSD=255)
2. **Port Scanning**: Service banner extraction for version identification
3. **Protocol Analysis**: TCP window size, options, and behavior patterns

### Probe Selection Matrix

| Target OS | Protection Level | Recommended Probe | Stealth Rating |
|-----------|-----------------|-------------------|----------------|
| Linux | None | eBPF | 9/10 |
| Linux | Moderate | LKM | 7/10 |
| Linux | High | Custom Driver | 6/10 |
| Windows | None | Driver | 8/10 |
| Windows | Moderate | UEFI Bootkit | 9/10 |
| Windows | High | SMM Implant | 10/10 |

### Integrity Probe Registry
All kernel modifications are tracked in `*kernel-stealth-registry*`:
- Original bytes before modification
- Memory offset and length
- Probe type and target function
- Restoration capability for clean removal

---

## Gossip Mesh Protocol

### Packet Format (Tactical Mode)

```
HEARTBEAT (64 bytes max):
  [agent-id: 8 bytes][status: 1 byte][pivot-depth: 1 byte]
  [uptime: 4 bytes][hmac: 16 bytes][padding: 34 bytes]

COMMAND (256 bytes max):
  [target-agent: 8 bytes][command-type: 1 byte][priority: 1 byte]
  [params-length: 2 bytes][params: 244 bytes]

KERNEL LOAD REQUEST:
  [request-type: 1 byte][binary-blob-id: 32 bytes]
  [target-host: 32 bytes][auth-token: 16 bytes]
```

### TLS Camouflage
Gossip mesh TLS handshakes are configured to match common browser fingerprints:

| Browser | JA3 Hash | Cipher Suites | Extensions |
|---------|----------|---------------|------------|
| Chrome 120 | `cd08e3...` | AES-128-GCM, AES-256-GCM, ChaCha20 | ALPN, SNI, key_share, supported_versions |
| Firefox 121 | `7c02db...` | AES-128-GCM, AES-256-GCM, ChaCha20 | ALPN, SNI, key_share, psk_key_exchange_modes |
| Safari 17 | `b3b0a4...` | AES-128-GCM, AES-256-GCM | ALPN, SNI, key_share, encrypt_then_mac |

### Bandwidth Constraints
- Heartbeat: 64 bytes every 50-70 seconds (jittered)
- Commands: 256 bytes max, batched when possible
- Telemetry: 10KB/s ceiling, compressed
- Total mesh overhead: < 1KB/s per node

---

## Evolutionary Engine

### Fitness Function (TTR)
Time-to-Recover (TTR) measures the elapsed time from system degradation detection to stable recovery. Lower is better.

```
fitness(agent) = 1 / (1 + TTR_seconds)
```

### Pattern-Aware Mutation
Mutation operators avoid generating strategies that rely on heavily monitored binaries:
- `powershell.exe` (heavily monitored)
- `certutil.exe` (known abuse)
- `mshta.exe` (behavioral detection)
- `regsvr32.exe` (signatured)

Instead, mutations prefer:
- Direct socket connections
- In-memory reflective loading
- System binaries not on behavioral deny-lists

### Tournament Selection
Each generation:
1. Sample 7 agents randomly
2. Select the fittest
3. Mutate with 15% probability per node
4. Crossover with 25% probability
5. Replace least fit agent with offspring

---

## Security Architecture

### 6-Layer Gatekeeper

```
Layer 1: Category Armed      -- Is the tool category enabled?
Layer 2: Override Check       -- Is an override in effect?
Layer 3: Forbidden Patterns   -- Does the target match forbidden patterns?
Layer 4: Target Whitelist     -- Is the target on the whitelist?
Layer 5: Max Concurrent       -- Are we below the concurrent limit?
Layer 6: Root Required        -- Does this tool need root and do we have it?
```

### Safety Profiles
- `:default` -- Standard protections
- `:recon` -- Passive only, no modifications
- `:offensive` -- Full tool access with logging
- `:defensive` -- Monitor-only, no probes
- `:maintenance` -- Healing and recovery only
- `:physical` -- Engineering tools, thermal limits
- `:research` -- Experimental features allowed
- `:break-glass` -- All protections disabled (requires explicit confirmation)

---

## Emergency Protocols

### Emergency Sanitization (`shred-all-assets`)

**Phase 1: Key Destruction (0-2s)**
- Zero-fill `*resource-vault-key*` (3 passes: 0x00, 0xFF, random)
- Clear all derived keys from memory
- Force full GC to reclaim key material

**Phase 2: Heap Poisoning (2-5s)**
- Iterate `*resource-vault*` hash table
- Overwrite each entry's `encrypted-data` with random bytes
- Overwrite each entry's `auth-tag` and `nonce`
- Destroy hash table structure

**Phase 3: Kernel Cleanup (5-8s)**
- Iterate `*kernel-implants*`
- Call `remove-kernel-implant` for each (restores original bytes)
- Stop kernel health monitor
- Unload Rust FFI library

**Phase 4: Cover Tracks (8-10s)**
- Flush telemetry buffer
- Stop gossip mesh
- Delete local log files (3-pass overwrite + random rename)
- Exit process with code 0 (clean exit)

### Radio Silence (`radio-silence-trigger`)

**Entry:**
1. Set `*radio-silence-mode-p* = T`
2. Stop gossip mesh (close all sockets)
3. Suspend persistence state manager
4. Suspend persistence watchdog
5. Enter dormant monitoring loop

**Dormant Loop:**
- Sleep 8-12 seconds (jittered)
- Check for wake-up signal:
  - File exists at `*wake-up-file-path*`?
  - File contains magic bytes `0x4C495350` ("LISP")?
  - Timeout reached (if `:duration` specified)?
- On wake-up: exit dormant mode, resume all services

**Exit:**
1. Clear `*radio-silence-mode-p*`
2. Restart gossip mesh
3. Restart persistence state manager
4. Restart persistence watchdog
5. Publish "resumed" telemetry event

---

## Operational Validation

### 7-Check Integration Checklist

| Check | Command | Pass Criteria |
|-------|---------|---------------|
| 1. VM Baseline | `take-system-baseline` | Baseline captured and comparable |
| 2. Telemetry Jitter | `validate-telemetry-jitter` | Mean interval 50-70s, stdev < 10s |
| 3. TPM Availability | `validate-tpm-availability` | `/dev/tpmrm0` accessible or Windows TPM present |
| 4. Gossip Mesh | `validate-gossip-mesh-topology` | >= 2 peers, primary + secondary relay |
| 5. Resilience Health | `persistence-feedback-loop-status` | All agents healthy, last TTR < 300s |
| 6. Vault Initialized | `vault-status` | Vault exists, key set, >= 0 entries |
| 7. FFI Loaded | `rust-ffi-status` | Library loaded OR stub mode confirmed |

### TTR SLA
- **Target:** <= 300 seconds from degradation detection to stable recovery
- **Measurement:** Automatic via `record-recovery-start` / `record-recovery-end`
- **Reporting:** `(ttr-within-sla-p 300)` returns T if compliant

---

*For implementation details, see the source code and inline documentation.*
