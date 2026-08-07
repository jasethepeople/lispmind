;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;;
;;;; LISPMIND.ASD -- ASDF System Definition
;;;;
;;;; This file defines the LISPMIND system for ASDF (Another System Definition
;;;; Facility). LISPMIND is a self-healing agentic AI orchestrator built on
;;;; CLOS MOP, the condition/restart system, and advanced concurrency primitives.
;;;;
;;;; Load with: (ql:quickload :lispmind)

(defsystem :lispmind
  :description "LISPMIND -- Self-Healing Agentic AI Orchestrator"
  :author "Lisp Machine Wizard"
  :license "MIT"
  :version "2.5.0"

  ;; -------------------------------------------------------------------------
  ;; Serial compilation ensures files are compiled in declaration order.
  ;; Each file builds on symbols defined in the previous ones.
  ;; -------------------------------------------------------------------------
  :serial t

  ;; -------------------------------------------------------------------------
  ;; Component Graph -- each arrow is a compile-time dependency
  ;;
  ;;   packages --> conditions --> agent-class --> macros --> orchestrator
  ;;        |                                                    |
  ;;        |   hotpatch <-- checkpoint <-- gossip <-- evolution  |
  ;;        |                       |              |              |
  ;;        |                       v              v              v
  ;;        |               image-persist    profiler       dashboard --> demo
  ;;        |                                                     ^
  ;;        |   telemetry --> websocket --> kali-interface          |
  ;;        |                                    |                  |
  ;;        |                       policy-gatekeeper               |
  ;;        |                                    |                  |
  ;;        |                               mcp-bridge              |
  ;;        |                                    |                  |
  ;;        |          inference --> osint-engine                   |
  ;;        |                                                     |
  ;;        |   engineering-interface --> system-init               |
  ;;        |                                                     |
  ;;        |   [v2.4 TACTICAL SWARM]                             |
  ;;        |   offensive-engine --> evolution-v2.4               |
  ;;        |   gossip-v2.4 --> tactical-checkpoint               |
  ;;        |   system-init-v2.4                                  |
  ;;        |                                                     |
  ;;        |   [v2.5 ABSOLUTE — Kernel/Hardware Integration]     |
  ;;        |   rust-ffi-bridge --> resource-registry             |
  ;;        |   kernel-orchestrator --> persistence-hierarchy     |
  ;;        |   system-init-v2.5 --> break-glass                  |
  ;;        |   break-glass --> operational-validator             |
  ;;        |                                                     |
  ;;        |   forward-declarations -- Prevents forward refs     |
  ;;
  ;; packages              -- Central package definition.
  ;; conditions            -- Custom condition hierarchy + restart API.
  ;; agent-class           -- CLOS agent class with MOP hooks.
  ;; macros                -- DSL macro (define-agent-type).
  ;; orchestrator          -- Registry, monitor loop, healing.
  ;; hotpatch              -- Safe function replacement.
  ;; checkpoint            -- State serialization via cl-store.
  ;; gossip                -- ZeroMQ mesh (stub mode fallback).
  ;; evolution             -- Genetic programming.
  ;; image-persist         -- Golden image resurrection.
  ;; profiler              -- FlameGraphs + auto-tuning.
  ;; telemetry             -- Metrics pipeline.
  ;; websocket             -- WebSocket/TCP server.
  ;; kali-interface        -- 145 offensive tool wrappers + LOLBins.
  ;; policy-gatekeeper     -- 8 profiles + 6-layer gatekeeper.
  ;; mcp-bridge            -- MCP server (35+ tools, 25+ resources).
  ;; inference             -- Model Router (Llama, Hermes, CodeLlama).
  ;; osint-engine          -- 8 OSINT tools + Collector Mesh.
  ;; engineering-interface -- 153 scientific tools (math/physics/CAD/EDA/AI).
  ;; system-init           -- Master init: memory mgmt + verification.
  ;; dashboard             -- ASCII REPL dashboard.
  ;; demo                  -- 7-act demonstration.
  ;;
  ;; [v2.4 TACTICAL SWARM — Pure Offensive Operations]
  ;; offensive-engine      -- Tactical pipeline: zero-delay + pivot chains +
  ;;                          persistence-first + fail-fast + in-memory.
  ;; evolution-v2.4        -- TTS-optimized fitness + LOLBin-aware mutation +
  ;;                          framework avoidance.
  ;; gossip-v2.4           -- Low-bandwidth tactical mesh: 64B heartbeat +
  ;;                          256B commands, 10KB/sec ceiling.
  ;; tactical-checkpoint   -- Resume-from-death: serialize network map +
  ;;                          pivot chains + sessions every 30s.
  ;; system-init-v2.4      -- Stripped tactical init: speed + evasion only,
  ;;                          all simulation/defensive logic removed.
  ;;
  ;; [v2.5 INFRASTRUCTURE — Lowest-level v2.5 components first]
  ;; rust-ffi-bridge       -- SBCL sb-alien FFI to Rust core library
  ;;                          (liblispmind_core.so). 7 bound functions.
  ;; resource-registry     -- AES-256-GCM encrypted vault for binary blobs.
  ;;                          Load-time obfuscation + hardware-bound keys.
  ;;
  ;; [v2.5 CONSUMERS — Depend on infrastructure above]
  ;; kernel-orchestrator   -- Kernel-level agent management: eBPF/LKM/driver
  ;;                          implants, OS fingerprinting, stealth hook registry.
  ;; persistence-hierarchy -- 3-tier escalating persistence: userland → kernel
  ;;                          → firmware. Self-healing watchdog + recovery.
  ;;
  ;; [v2.5 MASTER INIT — Depends on all above]
  ;; system-init-v2.5      -- Master v2.5 init: wires kernel, FFI, vault,
  ;;                          persistence watchdog, gossip, health monitor.
  ;;
  ;; [v2.5.1 OPERATIONAL — Depends on all above]
  ;; break-glass           -- Emergency protocols: 4-phase asset shred,
  ;;                          radio silence / dormant mode, kill switches.
  ;; operational-validator -- Integration validation: TTR measurement,
  ;;                          alert storm suppression, TLS camouflage audit,
  ;;                          gossip mesh topology, TPM integrity checks.
  ;;
  ;; forward-declarations  -- DEFVAR stubs for all v2.5+ special variables.
  ;;                          Prevents forward-reference violations with :serial t.
  ;; -------------------------------------------------------------------------
  :components ((:file "packages")
               (:file "conditions")
               (:file "agent-class")
               (:file "macros")
               (:file "orchestrator")
               (:file "hotpatch")
               (:file "checkpoint")
               (:file "tactical-checkpoint")
               (:file "gossip")
               (:file "gossip-v2.4")
               (:file "evolution")
               (:file "evolution-v2.4")
               (:file "image-persist")
               (:file "profiler")
               (:file "telemetry")
               (:file "websocket")
               (:file "kali-interface")
               (:file "offensive-engine")
               (:file "policy-gatekeeper")
               (:file "mcp-bridge")
               (:file "inference")
               (:file "osint-engine")
               (:file "engineering-interface")
               (:file "system-init")
               (:file "system-init-v2.4")
               ;; -- Forward declarations for v2.5+ (prevents forward-ref errors) --
               (:file "forward-declarations")
               ;; -- v2.5 INFRASTRUCTURE (lowest-level first) --
               (:file "rust-ffi-bridge")      ; FFI bindings — no v2.5 deps
               (:file "resource-registry")    ; Encrypted vault — no v2.5 deps
               ;; -- v2.5 CONSUMERS (depend on infrastructure above) --
               (:file "kernel-orchestrator")  ; Uses FFI + vault
               (:file "persistence-hierarchy") ; Uses vault
               ;; -- v2.5 MASTER INIT (depends on all above) --
               (:file "system-init-v2.5")     ; Wires everything
               ;; -- v2.5.1 OPERATIONAL (depends on all above) --
               (:file "break-glass")          ; Emergency protocols
               (:file "operational-validator") ; Validation suite
               (:file "dashboard")
               (:file "demo"))

  ;; -------------------------------------------------------------------------
  ;; Dependency Justification
  ;; -------------------------------------------------------------------------
  ;; Each dependency was chosen deliberately to solve a specific engineering
  ;; problem.  No bloat -- every library earns its place.
  ;;
  ;; :bordeaux-threads  -- Portable threading API across Lisp implementations.
  ;;                       We use it for agent monitor threads, heartbeat
  ;;                       timers, and lock-protected slot access.  Essential
  ;;                       for any concurrent orchestrator.
  ;;
  ;; :closer-mop        -- CLOS Meta-Object Protocol portability layer.
  ;;                       Enables :around methods on slot accessors for
  ;;                       health/status change notifications, class
  ;;                       introspection, and metaclass manipulation.
  ;;
  ;; :alexandria        -- The de-facto standard utility library.  Provides
  ;;                       `once-only', `with-gensyms', `define-constant',
  ;;                       and other macros that keep our code clean and
  ;;                       battle-tested.
  ;;
  ;; :cl-ppcre          -- Perl-compatible regular expressions.  Used in
  ;;                       agent log parsing, strategy validation, and
  ;;                       dashboard filtering.
  ;;
  ;; :local-time        -- High-precision timestamp handling.  Powers agent
  ;;                       heartbeats, checkpoint timestamps, and elapsed-time
  ;;                       calculations for strategy-stall detection.
  ;;
  ;; :cl-store          -- Fast binary serialization of Lisp objects.  The
  ;;                       backbone of the checkpoint/restore system that
  ;;                       enables zero-downtime agent persistence.
  ;;
  ;; :lparallel         -- Parallel programming toolkit (thread pools,
  ;;                       channels, promises).  Used to parallelize
  ;;                       multi-agent strategy execution and checkpoint
  ;;                       I/O operations.
  ;;
  ;; :cl-zeromq         -- [OPTIONAL] ZeroMQ bindings for distributed gossip.
  ;;                       Install libzmq3-dev + (ql:quickload :cl-zeromq).
  ;;                       If absent, gossip runs in stub mode with warnings.
  ;;                       Commented out by default for air-gapped installs.
  ;;
  ;; :ironclad           -- Cryptographic toolkit. AES-256-GCM encryption,
  ;;                       PBKDF2 key derivation, SHA-256 hashing, HMAC for
  ;;                       the resource vault and gossip authentication.
  ;;                       Install: (ql:quickload :ironclad)
  ;;
  ;; :cl-base64          -- Base64 encoding/decoding for transport of
  ;;                       encrypted vault entries over gossip mesh.
  ;;                       Install: (ql:quickload :cl-base64)
  ;; -------------------------------------------------------------------------
  :depends-on (:bordeaux-threads
               :closer-mop
               :alexandria
               :cl-ppcre
               :local-time
               :cl-store
               :lparallel
               :ironclad
               :cl-base64
               ;; :cl-zeromq   ; uncomment after `apt install libzmq3-dev'
               ))
