;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;; ============================================================================
;;;; FORWARD-DECLARATIONS.LISP -- Compile-time forward declarations for v2.5+
;;;; ============================================================================
;;;;
;;;; This file exists to prevent forward-reference violations when compiling
;;;; LISPMIND with :serial t.  It provides DEFVAR stubs for all special
;;;; variables defined across the v2.5+ kernel/hardware and operational
;;;; research modules.
;;;;
;;;; The component order in lispmind.asd is:
;;;;   forward-declarations -> rust-ffi-bridge -> resource-registry
;;;;   -> kernel-orchestrator -> persistence-hierarchy
;;;;   -> system-init-v2.5 -> break-glass -> operational-validator
;;;;
;;;; By placing this file first, all subsequent files can reference these
;;;; variables at compile time without triggering "undefined variable" warnings
;;;; or load-order failures.
;;;;
;;;; DO NOT add initialization logic here -- these are pure declarations.
;;;; Each defining file provides the real docstring and init-form.
;;;; ============================================================================

(in-package :lispmind)

;;;; ---------------------------------------------------------------------------
;;;; rust-ffi-bridge.lisp  —  FFI binding state
;;;; ---------------------------------------------------------------------------

(defvar *rust-ffi-version* nil)
(defvar *kernel-rust-ffi-available-p* nil)
(defvar *rust-library-path* nil)
(defvar *rust-library-handle* nil)
(defvar *ffi-last-error* nil)
(defvar *ffi-call-timeout* nil)
(defvar *ffi-verbose* nil)
(defvar *ffi-log-calls* nil)
(defvar *ffi-production-mode-p* nil)
(defvar *ffi-stub-active-without-consent-p* nil)
(defvar *ffi-stub-confirmed-p* nil)
(defvar *ffi-max-buffer-size* nil)
(defvar *ffi-max-string-length* nil)
(defvar *ffi-default-buffer-size* nil)
(defvar *ffi-implant-registry* nil)
(defvar *ffi-registry-lock* nil)
(defvar *ffi-performance-log* nil)
(defvar *ffi-performance-lock* nil)
(defvar *ffi-config-file* nil)

;;;; ---------------------------------------------------------------------------
;;;; resource-registry.lisp  —  Encrypted vault state
;;;; ---------------------------------------------------------------------------

(defvar *resource-vault* nil)
(defvar *resource-vault-key* nil)
(defvar *resource-vault-path* nil)
(defvar *resource-vault-version* nil)
(defvar *resource-vault-initialized-p* nil)
(defvar *resource-vault-encrypted-p* nil)
(defvar *resource-vault-lock* nil)
(defvar *resource-obfuscation-key* nil)
(defvar *resource-max-blob-size* nil)
(defvar *vault-key-derivation-tier* nil)
(defvar *vault-strict-verification-p* nil)
(defvar *resource-vault-diagnostics-log* nil)
(defvar *code-signing-required-p* nil)

;;;; ---------------------------------------------------------------------------
;;;; kernel-orchestrator.lisp  —  Kernel implant state
;;;; ---------------------------------------------------------------------------

(defvar *kernel-orchestrator-version* nil)
(defvar *kernel-implant-registry* nil)
(defvar *kernel-registry-lock* nil)
(defvar *kernel-hardened-hosts* nil)
(defvar *kernel-hardened-lock* nil)
(defvar *kernel-toolchain-registry* nil)
(defvar *kernel-toolchain-lock* nil)
(defvar *kernel-stealth-registry* nil)
(defvar *kernel-stealth-lock* nil)
(defvar *kernel-telemetry-topic* nil)
(defvar *kernel-health-monitor-interval* nil)
(defvar *kernel-max-retry-delay* nil)
(defvar *kernel-request-counter* nil)
(defvar *kernel-request-lock* nil)
(defvar *kernel-health-monitor-thread* nil)
(defvar *kernel-health-monitor-running-p* nil)
(defvar *kernel-fallback-methods* nil)
(defvar *code-signing-cert-path* nil)
(defvar *kernel-quiet-windows* nil)
(defvar *kernel-implant-queue* nil)
(defvar *kernel-implant-queue-lock* nil)
(defvar *kernel-auth-tpm-handle* nil)
(defvar *kernel-auth-secret-derived* nil)
(defvar *kernel-auth-derivation-lock* nil)
(defvar *kernel-tpm-device* nil)
(defvar *kernel-auth-secret* nil)
(defvar *kernel-heartbeat-device* nil)
(defvar *kernel-heartbeat-use-ioctl-p* nil)

;;;; ---------------------------------------------------------------------------
;;;; persistence-hierarchy.lisp  —  Persistence state
;;;; ---------------------------------------------------------------------------

(defvar *persistence-watchdog-interval* nil)
(defvar *persistence-watchdog-agents* nil)
(defvar *persistence-watchdog-thread* nil)
(defvar *persistence-watchdog-running-p* nil)
(defvar *persistence-recovery-log* nil)
(defvar *persistence-recovery-attempts* nil)
(defvar *persistence-max-recovery-attempts* nil)
(defvar *persistence-tiers* nil)
(defvar *persistence-tier-by-level* nil)
(defvar *persistence-escalation-log* nil)
(defvar *strategic-asset-indicators* nil)
(defvar *strategic-asset-port-signatures* nil)
(defvar *tactical-telemetry-topic* nil)

;;;; ---------------------------------------------------------------------------
;;;; system-init-v2.5.lisp  —  Master init state
;;;; ---------------------------------------------------------------------------

(defvar *lispmind-version* nil)
(defvar *lispmind-version-name* nil)
(defvar *lispmind-init-complete-p* nil)
(defvar *lispmind-init-sequence* nil)
(defvar *lispmind-shutdown-sequence* nil)
(defvar *v25-init-log* nil)
(defvar *kernel-hardware-integration-enabled-p* nil)
(defvar *radio-silence-mode-p* nil)
(defvar *radio-silence-triggers* nil)
(defvar *radio-silence-last-trigger* nil)
(defvar *radio-silence-engaged-at* nil)
(defvar *persistence-postponed-due-to-scan-p* nil)
(defvar *persistence-state-manager-running-p* nil)
(defvar *persistence-state-manager-thread* nil)
(defvar *persistence-state-manager-interval* nil)
(defvar *tls-camouflage-enabled-p* nil)
(defvar *tls-camouflage-browser* nil)
(defvar *tls-camouflage-os* nil)
(defvar *gossip-camouflage-enabled-p* nil)
(defvar *lispmind-release-build-p* nil)

;;;; ---------------------------------------------------------------------------
;;;; break-glass.lisp  —  Emergency protocol state
;;;; ---------------------------------------------------------------------------

(defvar *break-glass-active-p* nil)
(defvar *break-glass-log* nil)
(defvar *shred-all-assets-executed-p* nil)
(defvar *radio-silence-executed-p* nil)
(defvar *dormant-mode-active-p* nil)
(defvar *wake-up-file-path* nil)
(defvar *break-glass-emergency-contact* nil)
(defvar *break-glass-version* nil)

;;;; ---------------------------------------------------------------------------
;;;; operational-validator.lisp  —  Validation state
;;;; ---------------------------------------------------------------------------

(defvar *system-baseline* nil)
(defvar *telemetry-jitter-log* nil)
(defvar *integration-checklist-results* nil)

;;;; ============================================================================
;;;; End of forward declarations
;;;; ============================================================================
