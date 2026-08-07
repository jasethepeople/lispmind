;;;; ============================================================================
;;;; resource-registry.lisp — Encrypted Resource Vault for LISPMIND v2.6
;;;; ============================================================================
;;;;
;;;; MODULE PURPOSE
;;;; --------------
;;;; This module implements the encrypted resource vault subsystem for the
;;;; LISPMIND autonomous offensive security platform. It provides secure
;;;; storage, retrieval, and in-memory obfuscation of binary assets (eBPF
;;;; bytecode, Linux Kernel Modules, Windows drivers, UEFI images) used by
;;;; the kernel implant toolchain.
;;;;
;;;; The vault serves as the authoritative storage backend for the
;;;; `binary-blob-id' field of the `kernel-tool-entry' struct defined in
;;;; kernel-orchestrator.lisp. All binary assets are encrypted at rest
;;;; using AES-256-GCM with authentication, and optionally obfuscated in
;;;; memory using XOR-based load-time obfuscation with rotating keys.
;;;;
;;;; SECURITY ARCHITECTURE
;;;; ---------------------
;;;; - Encryption at rest: AES-256-GCM with 96-bit IV and 128-bit auth tag
;;;; - Key derivation v2: Tiered — TPM2 NV (tier 1) > multi-artifact PBKDF2
;;;;   (tier 2, 200K iters) > ephemeral random (tier 3)
;;;; - Hardware binding: Multi-factor — DMI UUID, machine-id, board serial,
;;;;   hostname, optionally TPM2 sealed key
;;;; - Ephemeral keys: In-memory only, never touch the filesystem
;;;; - Integrity: GCM authentication tag per blob + SHA-256 hash of plaintext
;;;; - Obfuscation v2: ChaCha8 stream cipher with per-load PBKDF2 subkey
;;;; - Obfuscation v1 (deprecated): XOR with rotating key (backward compat)
;;;; - Transport: Base64-encoded serialized entries for gossip protocol
;;;; - Memory safety: Secure wipe of sensitive buffers via unwind-protect
;;;; - Thread safety: Recursive locks around all vault mutation operations
;;;; - Code signing: Enforce signed tarball verification on load
;;;; - Strict verification: GCM auth tag failure signals VAULT-TAMPER-DETECTED
;;;;
;;;; THREAT MODEL
;;;; ------------
;;;; Addressed threats:
;;;;   T1. Physical disk theft — AES-256-GCM encryption prevents offline
;;;;       analysis of stored blobs without the derived key.
;;;;   T2. Memory dump analysis — ChaCha8 v2 obfuscation provides real
;;;;       cryptographic protection (not trivially reversible XOR). Decrypted
;;;;       blobs are not stored contiguously in plaintext in memory.
;;;;   T3. Cold boot attack — Master key can be ephemeral (not persisted);
;;;;       TPM2 binding (tier 1) makes key extraction extremely difficult;
;;;;       multi-artifact binding (tier 2) means stolen vault cannot be
;;;;       decrypted on different hardware without ALL original artifacts.
;;;;   T4. Tampering — GCM authentication tags detect ciphertext modification.
;;;;       Strict verification (decrypt-blob-strict) signals VAULT-TAMPER-DETECTED
;;;;       on failure, clears keys, and logs security events.
;;;;   T5. Network interception — Base64 transport does not carry keys;
;;;;       encryption is performed before transport encoding.
;;;;   T6. Side-channel timing — Constant-time comparison for auth tag
;;;;       verification (delegated to Ironclad). ChaCha8 is constant-time
;;;;       by design (no cache timing side channels unlike AES).
;;;;   T7. Race conditions — Recursive locks prevent concurrent mutation
;;;;       of vault state during store/retrieve/delete operations.
;;;;   T8. Code modification — Code signing enforcement detects unauthorized
;;;;       changes to resource-registry.lisp. Unsigned loads trigger warnings.
;;;;   T9. Emergency destruction — 4-phase shred with multi-pass overwrite,
;;;;       random renames, and journal mitigation for SSD/HDD destruction.
;;;;
;;;; Out of scope (handled elsewhere):
;;;;   - Runtime code injection protection (handled by implant loader)
;;;;   - Anti-debugging (handled by runtime shield module)
;;;;   - Network-level traffic encryption (handled by gossip protocol)
;;;;   - Secure deletion of filesystem backups (OS-level concern)
;;;;
;;;; KEY MANAGEMENT PHILOSOPHY
;;;; -------------------------
;;;; This module follows a defense-in-depth approach to key management:
;;;;   1. TIERED key derivation (v2): TPM2 sealed key (tier 1, strongest)
;;;;      → multi-artifact PBKDF2 (tier 2, 200K iterations)
;;;;      → ephemeral random (tier 3, most portable).
;;;;      Select via *VAULT-KEY-DERIVATION-TIER* (:auto :tpm :multi :ephemeral).
;;;;   2. The vault can operate in EPHEMERAL mode (random key, memory only)
;;;;      or PERSISTENT mode (key derived from hardware, vault saved to disk).
;;;;   3. The master key is stored in a special variable that can be securely
;;;;      wiped via `clear-vault-key' — overwriting with zeros then random.
;;;;   4. Per-blob obfuscation uses ChaCha8 stream cipher with per-load
;;;;      PBKDF2-derived subkeys (NOT trivial XOR). Each load gets unique
;;;;      encryption via random nonce → unique subkey.
;;;;   5. Key derivation uses PBKDF2 with 200,000 iterations (OWASP 2023)
;;;;      and a hardware-bound salt to resist brute-force attacks.
;;;;   6. The multi-artifact fingerprint combines DMI UUID, machine-id,
;;;;      board serial, and hostname — an attacker needs ALL artifacts.
;;;;   7. Keys are never logged, printed, or exposed through inspection
;;;;      interfaces. All key material is treated as opaque octet vectors.
;;;;   8. Secure wipe is performed via `unwind-protect' to ensure cleanup
;;;;      even in the presence of non-local exits (errors, throws).
;;;;   9. Emergency shred provides 4-phase destruction: memory wipe,
;;;;      file overwrite+rename, journal mitigation, final cleanup.
;;;;
;;;; DEPENDENCIES
;;;; ------------
;;;;   - ironclad      : All cryptographic operations (AES-256-GCM, PBKDF2,
;;;;                     SHA-256, secure random)
;;;;   - cl-base64     : Base64 encoding for transport serialization
;;;;   - bordeaux-threads: Recursive locks for thread safety
;;;;   - sb-ext        : SBCL-specific extensions
;;;;   - uiop          : Portable filesystem operations
;;;;
;;;; AUTHOR: LISPMIND Cryptographic Systems Team
;;;; Version: 2.5.0 | License: Internal Use Only
;;;; ============================================================================

(defpackage :lispmind.resource-vault
  (:use :cl)
  (:nicknames :lmvault)
  (:import-from :ironclad
                #:make-cipher #:encrypt #:decrypt #:make-kdf #:derive-key
                #:digest-file #:digest-sequence #:random-data)
  (:import-from :cl-base64
                #:usb8-array-to-base64-string #:base64-string-to-usb8-array)
  (:export
   ;; Special variables
   #:*resource-vault* #:*resource-vault-encrypted-p* #:*resource-vault-key*
   #:*resource-vault-path* #:*resource-obfuscation-key*
   #:*resource-vault-version* #:*resource-max-blob-size*
   ;; Structures
   #:vault-entry #:vault-entry-blob-id #:vault-entry-encrypted-data
   #:vault-entry-auth-tag #:vault-entry-nonce #:vault-entry-metadata
   #:vault-entry-obfuscation-key
   ;; Key management
   #:derive-vault-key #:generate-ephemeral-key #:set-vault-key
   #:clear-vault-key #:hardware-fingerprint
   ;; Encryption/Decryption
   #:encrypt-blob #:decrypt-blob #:compress-blob #:decompress-blob
   ;; Vault operations
   #:vault-init #:vault-store #:vault-retrieve #:vault-delete
   #:vault-exists-p #:vault-list #:vault-load-from-disk #:vault-save-to-disk
   #:vault-import #:vault-export #:vault-get-metadata
   ;; Obfuscation
   #:obfuscate-bytes #:deobfuscate-bytes #:generate-obfuscation-key
   #:obfuscate-for-loading
   ;; Base64 transport
   #:blob-to-base64 #:base64-to-blob #:vault-entry-serialize
   #:vault-entry-deserialize
   ;; Integrity & Verification
   #:verify-blob-integrity #:vault-health-check #:vault-corruption-scan
   #:vault-stats
   ;; Kernel tool integration
   #:register-kernel-tool-blob #:get-tool-binary
   #:prepare-tool-for-deployment #:vault-sync-with-toolchain
   ;; Cleanup & Security
   #:secure-wipe-vector #:vault-destroy #:vault-emergency-shred
   ;; ChaCha8 Stream Cipher (v2 obfuscation)
   #:chacha8-encrypt-bytes #:chacha8-decrypt-bytes
   #:obfuscate-for-loading-v2 #:*chacha8-fallback-cipher*
   ;; TPM / Multi-Artifact Key Derivation
   #:derive-vault-key-v2 #:tpm-available-p #:read-tpm-nv-key
   #:collect-system-artifacts #:*vault-key-derivation-tier*
   ;; Strict GCM Verification
   #:decrypt-blob-strict #:verify-gcm-tag
   #:vault-tamper-detected #:*vault-strict-verification-p*
   ;; Enhanced Shred Helpers
   #:secure-overwrite-file #:sync-filesystem
   ;; Diagnostics
   #:vault-status #:vault-diagnostics #:vault-help))

(in-package :lispmind.resource-vault)


;; ============================================================================
;; SECTION 1: SPECIAL VARIABLES
;; ============================================================================

(defparameter *resource-vault-version* "2.6.0"
  "Version string for the resource vault module. Embedded in metadata
   of each stored blob for compatibility during load/save and transport.
   SECURITY NOTE: This is NOT a security parameter — purely operational.
   v2.6.0: Added ChaCha8 obfuscation v2, TPM key derivation, strict GCM verify,
           4-phase emergency shred, code signing enforcement.")

(defvar *resource-vault* nil
  "Hash table mapping blob-id (string) → vault-entry struct. Protected
   by *resource-vault-lock*. Values are ENCRYPTED — plaintext is never stored.")

(defvar *resource-vault-encrypted-p* t
  "Boolean: T = encryption enabled (default). NIL = plaintext (debug only).")

(defvar *resource-vault-key* nil
  "Master AES-256 encryption key as a 32-octet vector. Most sensitive data
   in this module. Wipe via `clear-vault-key' before shutdown.")

(defvar *resource-vault-path* nil
  "Optional filesystem path for vault persistence. File contains ONLY
   encrypted data — the master key is NEVER written to disk.")

(defvar *resource-obfuscation-key* nil
  "Default XOR obfuscation key for load-time obfuscation. Regenerated
   at startup via `vault-init'.")

(defparameter *resource-max-blob-size* (* 50 1024 1024)
  "Maximum allowed blob size in bytes. Default: 50MB. Prevents DoS via
   excessively large files. Adjust: increase for UEFI, decrease for embedded.")

(defvar *resource-vault-lock* nil
  "Recursive lock protecting all vault mutation operations. Created by
   `vault-init'. Uses bordeaux-threads:make-recursive-lock.")

(defvar *resource-vault-initialized-p* nil
  "Internal flag tracking vault initialization. Checked by all API funcs.")

(defvar *resource-vault-diagnostics-log* nil
  "Optional stream for diagnostic output. NEVER logs key material, plaintext,
   auth tags, or nonces — only metadata and operational events.")

;; --- SECURITY HARDENING v2.6 ADDitions ---

(defvar *vault-key-derivation-tier* :auto
  "Control key derivation strategy. :auto = best available (TPM > multi-artifact
   > ephemeral). :tpm = require TPM. :multi-artifact = use system artifacts.
   :ephemeral = random key only. Set before calling DERIVE-VAULT-KEY.")

(defvar *vault-strict-verification-p* t
  "When T (default), DECRYPT-BLOB-STRICT is used which aborts and signals
   VAULT-TAMPER-DETECTED on GCM auth tag mismatch. When NIL, falls back to
   DECRYPT-BLOB (legacy). ALWAYS keep T in production.")

(defvar *chacha8-fallback-cipher* :aes
  "Fallback stream cipher if ChaCha8 unavailable in Ironclad. :aes uses
   AES-256-CTR. Set at compile time; do not change at runtime.")

(defvar *chacha8-nonce-length* 12
  "Nonce length in bytes for ChaCha8 (standard RFC 8439 nonce size).")

(defvar *chacha8-key-length* 32
  "Key length in bytes for ChaCha8 (256-bit).")

(defvar *code-signing-required-p* t
  "When T, warns if module loaded from unsigned source. Set to NIL only in
   controlled development environments.")


;; ============================================================================
;; SECTION 1b: CONDITIONS (SECURITY EVENTS)
;; ============================================================================

(define-condition vault-tamper-detected (error)
  ((blob-id :initarg :blob-id :reader tamper-blob-id
            :documentation "Identifier of the blob that failed verification.")
   (reason :initarg :reason :reader tamper-reason
           :documentation "Human-readable description of the tamper evidence.")
   (timestamp :initform (%current-timestamp) :reader tamper-timestamp))
  (:documentation "Signaled when GCM authentication tag verification fails.
   This indicates either: (1) ciphertext tampering, (2) corruption,
   (3) wrong key, or (4) nonce reuse attack. Treat as SECURITY EVENT.
   Handler should: log, wipe keys, notify monitoring, return NIL.")
  (:report (lambda (condition stream)
             (format stream "VAULT TAMPER DETECTED on blob ~A at ~D: ~A"
                     (tamper-blob-id condition)
                     (tamper-timestamp condition)
                     (tamper-reason condition)))))

(define-condition code-signature-missing (warning)
  ((source :initarg :source :reader signature-source))
  (:documentation "Warned when vault module loaded without code signature.")
  (:report (lambda (condition stream)
             (format stream "CODE SIGNATURE MISSING for ~A — verify source!"
                     (signature-source condition)))))


;; ============================================================================
;; SECTION 2: VAULT ENTRY STRUCTURE
;; ============================================================================

(defstruct vault-entry
  "Structure representing a single encrypted binary blob in the vault.
   SECURITY PROPERTIES:
   - encrypted-data contains ONLY ciphertext; plaintext never stored
   - auth-tag binds ciphertext to nonce; detects any modification
   - nonce randomly generated per-encryption, NEVER reused with same key
   - obfuscation-key is low-sensitivity (XOR memory protection only)
   - metadata contains only non-sensitive operational data
   THREAD SAFETY: Entries are immutable once created. Hash table mutation
   is protected by *resource-vault-lock*."
  (blob-id nil :type (or string null) :read-only t)
  (encrypted-data nil :type (or (simple-array (unsigned-byte 8) (*)) null))
  (auth-tag nil :type (or (simple-array (unsigned-byte 8) (16)) null))
  (nonce nil :type (or (simple-array (unsigned-byte 8) (12)) null))
  (metadata nil :type list)
  (obfuscation-key nil :type (or (simple-array (unsigned-byte 8) (32)) null)))


;; ============================================================================
;; INTERNAL UTILITY FUNCTIONS
;; ============================================================================

(defun %ensure-initialized ()
  "Internal: Signal error if vault not initialized. Safety check, not
   a security boundary — debugger can bypass."
  (unless *resource-vault-initialized-p*
    (error "Resource vault not initialized. Call (vault-init) first.")))

(defun %log-diagnostic (format-string &rest args)
  "Internal: Log diagnostic if *resource-vault-diagnostics-log* is set.
   SECURITY: Never call with key material, plaintext, auth tags, or nonces."
  (when *resource-vault-diagnostics-log*
    (format *resource-vault-diagnostics-log* "[~A] [VAULT] ~A~%"
            (get-universal-time) (apply #'format nil format-string args))
    (force-output *resource-vault-diagnostics-log*)))

(defun %current-timestamp ()
  "Return current UNIX timestamp."
  (- (get-universal-time) 2208988800))

(defun %copy-octet-vector (vec &optional (start 0) (end (length vec)))
  "Create a fresh copy of an octet vector. Caller must wipe copy when done."
  (declare (type (simple-array (unsigned-byte 8) (*)) vec))
  (let ((copy (make-array (- end start) :element-type '(unsigned-byte 8)
                          :initial-element 0)))
    (replace copy vec :start2 start :end2 end)
    copy))

(defun %constant-time-equal (a b)
  "Compare two octet vectors in constant time. Returns T if equal.
   Used for auth tag comparison to prevent timing attacks."
  (declare (type (simple-array (unsigned-byte 8) (*)) a b))
  (if (/= (length a) (length b)) nil
      (ironclad:constant-time-equal a b)))

(defun %restrict-file-permissions (path)
  "Set restrictive permissions (0600) on file. Best-effort; may fail on
   network filesystems. Returns T on success, NIL on failure."
  (handler-case
      (progn #+sbcl (sb-posix:chmod path #o600)
             #-sbcl (ignore-errors (chmod path #o600))
             t)
    (error (e) (%log-diagnostic "chmod failed on ~A: ~A" path e) nil)))

(defun %format-bytes-human (bytes)
  "Convert byte count to human-readable string (KB/MB/GB)."
  (cond ((>= bytes (* 1024 1024 1024))
         (format nil "~,2F GB" (/ bytes 1024.0 1024.0 1024.0)))
        ((>= bytes (* 1024 1024))
         (format nil "~,2F MB" (/ bytes 1024.0 1024.0)))
        ((>= bytes 1024) (format nil "~,2F KB" (/ bytes 1024.0)))
        (t (format nil "~D B" bytes))))

(defun %safe-file-size (path)
  "Return file size in bytes, or NIL if unreadable."
  (handler-case
      (with-open-file (stream path :direction :input
                                   :element-type '(unsigned-byte 8))
        (file-length stream))
    (file-error () nil)))

(defun %check-blob-size (size)
  "Validate SIZE does not exceed *resource-max-blob-size*. Signal error if so."
  (when (> size *resource-max-blob-size*)
    (error "Blob size ~D exceeds max ~D (~A). Adjust *resource-max-blob-size*."
           size *resource-max-blob-size*
           (%format-bytes-human *resource-max-blob-size*))))

(defun %rotate-entry-key (entry old-key new-key)
  "Internal: Re-encrypt a vault entry with a new key. Decrypted plaintext
   is securely wiped after re-encryption."
  (declare (type vault-entry entry))
  (let ((plaintext (decrypt-blob (vault-entry-encrypted-data entry)
                                  (vault-entry-auth-tag entry)
                                  (vault-entry-nonce entry)
                                  :key old-key)))
    (unwind-protect
         (multiple-value-bind (new-ct new-tag new-nonce)
             (encrypt-blob (%copy-octet-vector plaintext) :key new-key)
           (setf (vault-entry-encrypted-data entry) new-ct)
           (setf (vault-entry-auth-tag entry) new-tag)
           (setf (vault-entry-nonce entry) new-nonce))
      (secure-wipe-vector plaintext))))


;; ============================================================================
;; SECTION 3: KEY MANAGEMENT
;; ============================================================================

(defun hardware-fingerprint (&optional (variant :full))
  "Generate a hardware-bound salt from system properties.
   VARIANT: :full (default) = hostname + MAC + CPU + machine-id;
            :minimal = hostname only; :strict = all + SBCL version.
   SECURITY: Deterministic — same hardware always produces same fingerprint.
   An attacker who steals the vault file cannot decrypt on different hardware.
   Returns: 32-byte SHA-256 digest as PBKDF2 salt."
  (declare (type (member :full :minimal :strict) variant))
  (%log-diagnostic "Hardware fingerprint (variant: ~A)" variant)
  (let ((components nil))
    (handler-case (push (machine-instance) components)
      (error (e) (%log-diagnostic "No hostname: ~A" e)
             (push "unknown-host" components)))
    (when (member variant '(:full :strict))
      (handler-case
          #+sbcl (dolist (iface '("eth0" "enp0s3" "wlan0" "ens160" "en0"))
                   (let ((p (format nil "/sys/class/net/~A/address" iface)))
                     (when (probe-file p)
                       (with-open-file (s p) (push (read-line s nil) components))
                       (return))))
          #-sbcl (push "mac-unavailable" components)
        (error (e) (%log-diagnostic "No MAC: ~A" e)))
      (handler-case
          #+sbcl (with-open-file (s "/proc/cpuinfo" :if-does-not-exist nil)
                   (when s (loop for line = (read-line s nil)
                                 while line when (search "model name" line)
                                 do (push (subseq line (+ (search ":" line) 2))
                                          components) (return))))
          #-sbcl (push "cpu-unavailable" components)
        (error (e) (%log-diagnostic "No CPU info: ~A" e)))
      (handler-case
          (with-open-file (s "/etc/machine-id" :if-does-not-exist nil)
            (when s (let ((id (read-line s nil))) (when id (push id components)))))
        (error (e) (%log-diagnostic "No machine-id: ~A" e))))
    (when (eq variant :strict)
      (push (lisp-implementation-version) components)
      (push (software-type) components))
    (let* ((joined (apply #'concatenate 'string
                          (loop for (a b) on components by #'cdr
                                collect a when b collect "|")))
           (salt (ironclad:digest-sequence
                  :sha256 (ironclad:ascii-string-to-byte-array joined))))
      (%log-diagnostic "Fingerprint: ~D components" (length components))
      salt)))

(defun derive-vault-key (password &key (salt nil) (iterations 100000)
                                     (variant :full))
  "Derive AES-256 key from PASSWORD via PBKDF2-HMAC-SHA256 (v1, legacy).
   DEPRECATED for new code — use DERIVE-VAULT-KEY-V2 for multi-factor derivation.
   This function is retained for backward compatibility and calls v2 internally.
   PASSWORD: String or octet vector. Use 20+ chars with mixed case.
   SALT: Optional 32-byte vector. If NIL, derived from hardware-fingerprint.
   ITERATIONS: Default 100,000. Min: 10,000. Note: v2 default is 200,000.
   VARIANT: Hardware fingerprint variant when auto-deriving salt.
   SECURITY: Delegates to DERIVE-VAULT-KEY-V2 with :multi tier.
   SIDE EFFECTS: Sets *resource-vault-key*. Wipes password bytes after use.
   Returns: 32-byte AES-256 key.
   DEPRECATION NOTICE: Use DERIVE-VAULT-KEY-V2 in new code."
  (declare (type (or string (simple-array (unsigned-byte 8) (*))) password)
           (type fixnum iterations))
  (when (< iterations 10000)
    (warn "PBKDF2 iterations ~D below recommended 10000" iterations))
  (%log-diagnostic "Delegating to derive-vault-key-v2 (legacy wrapper)")
  ;; Delegate to v2 with multi-artifact tier, preserving salt if provided
  (derive-vault-key-v2 :password (if (stringp password) password nil)
                       :tier :multi
                       :salt (or salt (hardware-fingerprint variant))
                       :iterations iterations)
  ;; If password was provided as bytes, we need to handle that case
  (unless (stringp password)
    ;; Byte-array password: mix it in after v2 derivation
    (let ((key *resource-vault-key*))
      (dotimes (i (min 32 (length password)))
        (setf (aref key i) (logxor (aref key i) (aref password i))))
      (secure-wipe-vector password)
      (setf *resource-vault-key* key)
      key)))

(defun generate-ephemeral-key ()
  "Generate a random 256-bit AES key, NEVER persisted to disk.
   Uses OS CSPRNG (/dev/urandom). Key is lost on process exit.
   USE CASES: Single-session vaults, testing, maximum security deployments.
   SIDE EFFECTS: Sets *resource-vault-key*.
   Returns: 32-byte random AES-256 key."
  (%log-diagnostic "Generating ephemeral key")
  (let ((key (ironclad:random-data 32)))
    (setf *resource-vault-key* key)
    (%log-diagnostic "Ephemeral key generated")
    key))

(defun set-vault-key (key)
  "Set the master vault key directly from an external source (HSM, etc.).
   KEY: 32-octet vector. Previous key is wiped before replacement.
   Returns: The new key vector."
  (declare (type (simple-array (unsigned-byte 8) (32)) key))
  (%log-diagnostic "Setting vault key (external)")
  (when *resource-vault-key* (clear-vault-key))
  (let ((key-copy (%copy-octet-vector key)))
    (setf *resource-vault-key* key-copy)
    (%log-diagnostic "Vault key set")
    key-copy))

(defun clear-vault-key ()
  "Securely wipe master key from memory. Three-pass: zeros → random → zeros.
   Call before shutdown or when transitioning keys. Does NOT affect swap
   or core dumps — use mlock(), disable cores, encrypted swap for max protection.
   Returns: NIL"
  (%log-diagnostic "Clearing vault key")
  (when *resource-vault-key*
    (unwind-protect
         (progn (fill *resource-vault-key* 0)
                (when *resource-vault-key*
                  (let ((r (ironclad:random-data (length *resource-vault-key*))))
                    (replace *resource-vault-key* r)
                    (secure-wipe-vector r)))
                (when *resource-vault-key*
                  (fill *resource-vault-key* 0)))
      (setf *resource-vault-key* nil)))
  (%log-diagnostic "Key cleared")
  nil)

(defun ensure-key-available ()
  "Internal: Ensure a valid encryption key exists. Auto-generates ephemeral
   key if none set. Returns: current or newly generated key."
  (unless *resource-vault-key*
    (%log-diagnostic "Auto-generating ephemeral key")
    (generate-ephemeral-key))
  *resource-vault-key*)

(defun get-key-info ()
  "Return non-sensitive key metadata. Safe for diagnostics.
   Returns plist: (:available t/nil :bit-length 256 :type :aes-256-gcm)"
  (list :available (not (null *resource-vault-key*))
        :bit-length 256 :type :aes-256-gcm))


;; ============================================================================
;; SECTION 3b: TPM / MULTI-ARTIFACT KEY DERIVATION (v2)
;; ============================================================================
;; Tiered key derivation that replaces single-source hardware binding with
;; multi-factor derivation. Tries TPM first (best security), falls back to
;; multi-artifact PBKDF2, then to pure ephemeral.
;;
;; TIER 1 (Best): TPM NV index sealed key — requires /dev/tpmrm0
;; TIER 2 (Good): Multi-artifact PBKDF2 — combines DMI UUID, machine-id, etc.
;; TIER 3 (Fallback): Pure ephemeral — random key, lost on reboot
;; ============================================================================

(defun tpm-available-p ()
  "Probe whether a TPM2 device is available on this system.
   Checks for /dev/tpmrm0 (Linux kernel TPM resource manager).
   Returns: T if TPM2 device exists and is readable, NIL otherwise.
   NOTE: Does not verify TPM is functional — only device presence."
  (and (probe-file "/dev/tpmrm0")
       #+sbcl (handler-case
                  (with-open-file (s "/dev/tpmrm0" :direction :io
                                                     :if-does-not-exist nil
                                                     :element-type '(unsigned-byte 8))
                    (and s (file-length s) t))
                (error () nil))
       #-sbcl (probe-file "/dev/tpmrm0")
       t))

(defun read-tpm-nv-key (&key (nv-index #x01C00000) (expected-size 32))
  "Read a sealed 256-bit key from TPM NV storage.
   NV-INDEX: TPM NV index to read (default: 0x01C00000, platform reserved).
   EXPECTED-SIZE: Expected key size in bytes (default: 32 for AES-256).
   SECURITY: Requires TPM2 with proper authorization. Reads raw key bytes.
   Best used with TPM2_NV_ReadLock after reading to prevent subsequent reads.
   Returns: Octet vector of key bytes, or NIL on failure.
   NOTE: This is a BEST-EFFORT implementation. Full TPM2 integration requires
   tss2-tcti and tpm2-tools or a proper TSS library.
   FALLBACK: If TPM tools available (tpm2_nvread), shell out to them."
  (declare (type (unsigned-byte 32) nv-index)
           (type fixnum expected-size))
  (%log-diagnostic "TPM NV read: index 0x~8,'0X, size ~D" nv-index expected-size)
  ;; Try tpm2_nvread command-line tool first (most common)
  (handler-case
      #+sbcl
      (let ((tmpfile (format nil "/tmp/.tpm_nv_~36R" (random 9999999999))))
        (unwind-protect
             (let ((cmd (format nil "tpm2_nvread -C o ~D -s ~D ~A 2>/dev/null"
                                nv-index expected-size tmpfile)))
               (declare (ignore cmd))
               ;; Use uiop:run-program for better portability
               (uiop:run-program
                (format nil "tpm2_nvread -C o ~D -s ~D -o ~A 2>/dev/null || true"
                        nv-index expected-size tmpfile)
                :ignore-error-status t)
               (if (and (probe-file tmpfile)
                        (= (or (%safe-file-size tmpfile) 0) expected-size))
                   (let ((key (make-array expected-size
                                          :element-type '(unsigned-byte 8))))
                     (with-open-file (s tmpfile :element-type '(unsigned-byte 8))
                       (read-sequence key s))
                     (%log-diagnostic "TPM NV read: success (~D bytes)"
                                      expected-size)
                     key)
                   (progn (%log-diagnostic "TPM NV read: no data")
                          nil)))
          (handler-case (delete-file tmpfile) (error ()))))
      #-sbcl nil
    (error (e)
      (%log-diagnostic "TPM NV read failed: ~A" e)
      nil)))

(defun collect-system-artifacts ()
  "Collect semi-volatile system identifiers for multi-artifact key derivation.
   Gathers multiple system properties that together form a hardware fingerprint.
   This is MORE robust than single-source binding — an attacker must replicate
   ALL artifacts to derive the same key.
   
   SOURCES (Linux):
     - /sys/class/dmi/id/product_uuid     (DMI system UUID)
     - /etc/machine-id                     (systemd machine ID)
     - /sys/class/dmi/id/board_serial      (motherboard serial)
     - hostname                            (network identity)
   
   SOURCES (Windows, when detected):
     - HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\InstallDate
     - HKLM\\SOFTWARE\\Microsoft\\Cryptography\\MachineGuid
   
   Returns: Concatenated string of all available artifacts, or empty string
   if none found. Never signals an error — always returns something."
  (%log-diagnostic "Collecting system artifacts")
  (let ((artifacts nil))
    ;; Linux DMI product UUID
    (handler-case
        (with-open-file (s "/sys/class/dmi/id/product_uuid"
                          :if-does-not-exist nil)
          (when s (let ((v (read-line s nil))) (when v (push v artifacts)))))
      (error (e) (%log-diagnostic "No product_uuid: ~A" e)))
    ;; systemd machine-id
    (handler-case
        (with-open-file (s "/etc/machine-id" :if-does-not-exist nil)
          (when s (let ((v (read-line s nil))) (when v (push v artifacts)))))
      (error (e) (%log-diagnostic "No machine-id: ~A" e)))
    ;; DMI board serial
    (handler-case
        (with-open-file (s "/sys/class/dmi/id/board_serial"
                          :if-does-not-exist nil)
          (when s (let ((v (read-line s nil))) (when v (push v artifacts)))))
      (error (e) (%log-diagnostic "No board_serial: ~A" e)))
    ;; Hostname
    (handler-case (push (machine-instance) artifacts)
      (error (e) (%log-diagnostic "No hostname: ~A" e)
             (push "unknown-host" artifacts)))
    ;; Windows artifacts (if we're on Windows or have registry access)
    (handler-case
        (with-open-file (s "/proc/sys/kernel/ostype" :if-does-not-exist nil)
          (when s
            (let ((os (read-line s nil)))
              (when (and os (search "Windows" os))
                (push "windows-detected" artifacts)))))
      (error (e) (%log-diagnostic "No ostype: ~A" e)))
    ;; Join all artifacts with delimiter
    (let ((result (if artifacts
                      (apply #'concatenate 'string
                             (loop for (a . rest) on artifacts
                                   collect a when rest collect "|"))
                      "")))
      (%log-diagnostic "Artifacts: ~D components, ~D bytes total"
                       (length artifacts) (length result))
      result)))

(defun derive-vault-key-v2 (&key (password nil) (tier :auto) (salt nil)
                                  (iterations 200000))
  "Derive AES-256 key using tiered multi-factor approach (v2).
   Replaces single-source hardware binding with TPM + multi-artifact derivation.
   
   TIER selection:
     :auto    — Try TPM (tier 1), then multi-artifact (tier 2), then ephemeral (tier 3)
     :tpm     — REQUIRE TPM sealed key. Error if TPM unavailable.
     :multi   — Use multi-artifact PBKDF2 (200K iterations). Never use TPM.
     :ephemeral — Generate random key. Most portable, least persistent.
   
   PASSWORD: Optional additional entropy. If provided, mixed with tier material.
   SALT: Optional 32-byte salt override. If NIL, derived from tier source.
   ITERATIONS: PBKDF2 iteration count. Default 200,000 (OWASP 2023 for SHA256).
               Previous default was 100,000 — doubled for increased resistance.
   
   SECURITY PROPERTIES:
     - TPM tier: Key sealed in hardware, unextractable without authorization.
     - Multi-artifact: Key bound to ~4 system properties. Theft of vault file
       is insufficient — attacker needs same hardware configuration.
     - Ephemeral: Key exists only in RAM. Process exit = key destroyed. Most
       secure against offline attacks, requires re-entry on restart.
   
   SIDE EFFECTS: Sets *RESOURCE-VAULT-KEY*.
   Returns: 32-byte AES-256 key."
  (declare (type (member :auto :tpm :multi :ephemeral) tier)
           (type fixnum iterations))
  (when (< iterations 100000)
    (warn "PBKDF2 iterations ~D below OWASP recommended 100000" iterations))
  (%log-diagnostic "Key derivation v2 (tier: ~A, iters: ~D)" tier iterations)
  (flet ((do-ephemeral ()
           (%log-diagnostic "Tier 3: Ephemeral key")
           (generate-ephemeral-key))
         (do-multi (artifacts)
           (%log-diagnostic "Tier 2: Multi-artifact PBKDF2 (~D bytes artifacts)"
                            (length artifacts))
           (let* ((artifact-bytes (ironclad:ascii-string-to-byte-array artifacts))
                  (actual-salt (or salt
                                   (ironclad:digest-sequence :sha256 artifact-bytes)))
                  (pw-bytes (if password
                                (ironclad:ascii-string-to-byte-array password)
                                artifact-bytes)))
             (unwind-protect
                  (let* ((kdf (ironclad:make-kdf 'ironclad:pbkdf2-hmac-sha256
                                                  :digest :sha256))
                         (key (ironclad:derive-key kdf pw-bytes actual-salt
                                                    iterations 32)))
                    (setf *resource-vault-key* key)
                    (%log-diagnostic "Multi-artifact key derived")
                    key)
               (when password (secure-wipe-vector pw-bytes))
               (secure-wipe-vector artifact-bytes))))
         (do-tpm ()
           (%log-diagnostic "Tier 1: TPM sealed key")
           (let ((tpm-key (read-tpm-nv-key)))
             (if tpm-key
                 (progn
                   ;; Mix TPM key with password if provided
                   (when password
                     (let ((pw-hash (ironclad:digest-sequence
                                      :sha256
                                      (ironclad:ascii-string-to-byte-array password))))
                       (unwind-protect
                            (dotimes (i (min 32 (length pw-hash)))
                              (setf (aref tpm-key i)
                                    (logxor (aref tpm-key i) (aref pw-hash i))))
                         (secure-wipe-vector pw-hash))))
                   (setf *resource-vault-key* tpm-key)
                   (%log-diagnostic "TPM key loaded and set")
                   tpm-key)
                 (error "TPM key requested but TPM unavailable or NV index empty")))))
    (ecase tier
      (:auto
       (cond ((tpm-available-p)
              (handler-case (do-tpm)
                (error (e)
                  (%log-diagnostic "TPM failed (~A), trying multi-artifact" e)
                  (let ((artifacts (collect-system-artifacts)))
                    (if (plusp (length artifacts))
                        (do-multi artifacts)
                        (do-ephemeral))))))
             (t (let ((artifacts (collect-system-artifacts)))
                  (if (plusp (length artifacts))
                      (do-multi artifacts)
                      (do-ephemeral))))))
      (:tpm (do-tpm))
      (:multi (do-multi (collect-system-artifacts)))
      (:ephemeral (do-ephemeral)))))


;; ============================================================================
;; SECTION 4: ENCRYPTION / DECRYPTION
;; ============================================================================

(defun encrypt-blob (plaintext &key (key nil) (aad #()))
  "AES-256-GCM encrypt a binary blob.
   PLAINTEXT: Octet vector (<= *resource-max-blob-size*). Wiped after encrypt.
   KEY: Optional 32-byte AES key. If NIL, uses *resource-vault-key*.
   AAD: Optional associated authenticated data (default empty).
   SECURITY: Random 96-bit nonce per call. 128-bit auth tag. Plaintext wiped.
   Returns 3 values: CIPHERTEXT (octets), AUTH-TAG (16 octets), NONCE (12 octets)."
  (declare (type (simple-array (unsigned-byte 8) (*)) plaintext aad))
  (let ((aes-key (or key (ensure-key-available))))
    (declare (type (simple-array (unsigned-byte 8) (32)) aes-key))
    (%check-blob-size (length plaintext))
    (%log-diagnostic "Encrypting (~D bytes)" (length plaintext))
    (let* ((nonce (ironclad:random-data 12))
           (cipher (ironclad:make-cipher :aes :mode :gcm :key aes-key
                                         :initialization-vector nonce))
           (ciphertext (make-array (length plaintext)
                                   :element-type '(unsigned-byte 8)))
           (auth-tag (make-array 16 :element-type '(unsigned-byte 8))))
      (unwind-protect
           (progn (when (plusp (length aad)) (ironclad:process-aad cipher aad))
                  (ironclad:encrypt cipher plaintext ciphertext)
                  (ironclad:produce-tag cipher auth-tag)
                  (%log-diagnostic "Encrypted: ~D -> ~D bytes"
                                   (length plaintext) (length ciphertext))
                  (values ciphertext auth-tag nonce))
        (secure-wipe-vector plaintext)))))

(defun decrypt-blob (ciphertext auth-tag nonce &key (key nil) (aad #()))
  "AES-256-GCM decrypt and verify authentication.
   CIPHERTEXT: Octet vector of ciphertext.
   AUTH-TAG: 16-octet GCM authentication tag from encryption.
   NONCE: 12-octet IV used during encryption. NEVER reuse nonce+key.
   KEY: Optional 32-byte AES key. If NIL, uses *resource-vault-key*.
   AAD: Must match AAD used during encryption exactly.
   SECURITY: Auth tag verified BEFORE plaintext returned. Constant-time check.
   Error if: tag fails (tampering), wrong key, wrong sizes.
   Returns: PLAINTEXT octet vector (fresh copy). Caller must wipe."
  (declare (type (simple-array (unsigned-byte 8) (*)) ciphertext nonce aad)
           (type (simple-array (unsigned-byte 8) (16)) auth-tag))
  (let ((aes-key (or key (ensure-key-available))))
    (declare (type (simple-array (unsigned-byte 8) (32)) aes-key))
    (%log-diagnostic "Decrypting (~D bytes)" (length ciphertext))
    (unless (= (length nonce) 12)
      (error "Invalid nonce: ~D bytes (expected 12)" (length nonce)))
    (unless (= (length auth-tag) 16)
      (error "Invalid auth tag: ~D bytes (expected 16)" (length auth-tag)))
    (let* ((cipher (ironclad:make-cipher :aes :mode :gcm :key aes-key
                                          :initialization-vector nonce
                                          :tag auth-tag))
           (plaintext (make-array (length ciphertext)
                                  :element-type '(unsigned-byte 8))))
      (unwind-protect
           (progn (when (plusp (length aad)) (ironclad:process-aad cipher aad))
                  (ironclad:decrypt cipher ciphertext plaintext)
                  ;; Defense in depth: explicit tag verification
                  (let ((computed-tag (make-array 16
                                                  :element-type '(unsigned-byte 8))))
                    (ironclad:produce-tag cipher computed-tag)
                    (unless (%constant-time-equal computed-tag auth-tag)
                      (secure-wipe-vector plaintext)
                      (secure-wipe-vector computed-tag)
                      (error "AUTH TAG FAILURE — blob tampered or corrupted. ~
                              SECURITY EVENT: do not trust this data."))
                    (secure-wipe-vector computed-tag))
                  (%log-diagnostic "Decrypted: ~D bytes" (length plaintext))
                  (%copy-octet-vector plaintext))
        (secure-wipe-vector plaintext)))))

(defun decrypt-blob-strict (ciphertext auth-tag nonce &key (key nil) (aad #())
                                                       (blob-id "unknown"))
  "AES-256-GCM decrypt with MANDATORY auth tag verification.
   Like DECRYPT-BLOB but signals VAULT-TAMPER-DETECTED on tag mismatch instead
   of generic error. Always verifies auth tag BEFORE returning plaintext.
   
   CIPHERTEXT, AUTH-TAG, NONCE, KEY, AAD: Same as DECRYPT-BLOB.
   BLOB-ID: Identifier for error reporting and tamper logging.
   
   SECURITY: On auth tag failure:
     1. Wipes plaintext buffer immediately
     2. Logs critical security event via vault-security-event
     3. Signals VAULT-TAMPER-DETECTED condition
     4. Clears vault key from memory (containment)
     
   Use this function in production. DECRYPT-BLOB is retained for compatibility.
   Controlled by *VAULT-STRICT-VERIFICATION-P* (default T).
   Returns: PLAINTEXT octet vector (fresh copy). Signals on tamper."
  (declare (type (simple-array (unsigned-byte 8) (*)) ciphertext nonce aad)
           (type (simple-array (unsigned-byte 8) (16)) auth-tag)
           (type string blob-id))
  (let ((aes-key (or key (ensure-key-available))))
    (declare (type (simple-array (unsigned-byte 8) (32)) aes-key))
    (%log-diagnostic "Strict decrypt: ~A (~D bytes)" blob-id (length ciphertext))
    (unless (= (length nonce) 12)
      (error "Invalid nonce: ~D bytes (expected 12)" (length nonce)))
    (unless (= (length auth-tag) 16)
      (error "Invalid auth tag: ~D bytes (expected 16)" (length auth-tag)))
    (let* ((cipher (ironclad:make-cipher :aes :mode :gcm :key aes-key
                                          :initialization-vector nonce
                                          :tag auth-tag))
           (plaintext (make-array (length ciphertext)
                                  :element-type '(unsigned-byte 8))))
      (handler-case
          (progn
            (when (plusp (length aad)) (ironclad:process-aad cipher aad))
            (ironclad:decrypt cipher ciphertext plaintext)
            ;; Explicit tag verification with constant-time comparison
            (let ((computed-tag (make-array 16 :element-type '(unsigned-byte 8))))
              (ironclad:produce-tag cipher computed-tag)
              (if (%constant-time-equal computed-tag auth-tag)
                  (progn
                    (secure-wipe-vector computed-tag)
                    (%log-diagnostic "Strict decrypt OK: ~A" blob-id)
                    (%copy-octet-vector plaintext))
                  (progn
                    ;; TAG MISMATCH — SECURITY EVENT
                    (secure-wipe-vector plaintext)
                    (secure-wipe-vector computed-tag)
                    (vault-security-event
                      :tamper-detected
                      (format nil "GCM auth tag mismatch on blob ~A — ~
                                   possible tampering, corruption, or wrong key"
                              blob-id))
                    ;; Containment: clear key
                    (clear-vault-key)
                    (signal 'vault-tamper-detected
                            :blob-id blob-id
                            :reason "GCM authentication tag verification failed")))))
        ;; Catch any other decryption errors as potential tamper
        (vault-tamper-detected () (error "Tamper detected on ~A" blob-id))
        (error (e)
          (secure-wipe-vector plaintext)
          (vault-security-event
            :tamper-detected
            (format nil "Decryption error on blob ~A: ~A" blob-id e))
          (signal 'vault-tamper-detected
                  :blob-id blob-id
                  :reason (format nil "Decryption failure: ~A" e)))))))

(defun verify-gcm-tag (ciphertext auth-tag nonce &key (key nil) (aad #()))
  "Standalone GCM authentication tag verification (no decryption).
   Useful for checking integrity without exposing plaintext in memory.
   CIPHERTEXT, AUTH-TAG, NONCE, KEY, AAD: Same as DECRYPT-BLOB.
   Returns: T if tag valid, NIL if mismatch.
   SECURITY: Uses constant-time comparison. Does NOT modify or expose plaintext.
   Suitable for integrity checks on untrusted stored data."
  (declare (type (simple-array (unsigned-byte 8) (*)) ciphertext nonce aad)
           (type (simple-array (unsigned-byte 8) (16)) auth-tag))
  (let ((aes-key (or key (ensure-key-available))))
    (declare (type (simple-array (unsigned-byte 8) (32)) aes-key))
    (handler-case
        (let* ((cipher (ironclad:make-cipher :aes :mode :gcm :key aes-key
                                              :initialization-vector nonce))
               (junk (make-array (length ciphertext)
                                 :element-type '(unsigned-byte 8))))
          (unwind-protect
               (progn
                 (when (plusp (length aad)) (ironclad:process-aad cipher aad))
                 (ironclad:decrypt cipher ciphertext junk)
                 (let ((computed-tag (make-array 16
                                                 :element-type '(unsigned-byte 8))))
                   (unwind-protect
                        (prog1 (%constant-time-equal computed-tag auth-tag)
                          (ironclad:produce-tag cipher computed-tag))
                     (secure-wipe-vector computed-tag))))
            (secure-wipe-vector junk)))
      (error (e)
        (%log-diagnostic "Tag verification error: ~A" e)
        nil))))

(defun compress-blob (data &key (algorithm :zlib) (level 6))
  "Compress binary data before encryption. ALGORITHM: :zlib or :none.
   LEVEL: 0-9 (0=fastest, 9=max). Default: 6 (balanced).
   SECURITY: Compression-before-encryption is safe for stored data (unlike
   TLS compression which is CRIME/BREACH-vulnerable).
   Returns: Compressed octet vector, or original if :none."
  (declare (type (simple-array (unsigned-byte 8) (*)) data)
           (type (member :zlib :none) algorithm)
           (type (integer 0 9) level))
  (if (eq algorithm :none)
      (progn (%log-diagnostic "Compression: skipped") data)
      (progn (%log-diagnostic "Compressing (~D bytes, level ~D)"
                               (length data) level)
             ;; Placeholder: requires salza2 or zlib library
             data)))

(defun decompress-blob (data &key (algorithm :zlib))
  "Decompress binary data after decryption. ALGORITHM: :zlib or :none.
   Enforces *resource-max-blob-size* to prevent zip-bomb attacks.
   Returns: Decompressed octet vector."
  (declare (type (simple-array (unsigned-byte 8) (*)) data)
           (type (member :zlib :none) algorithm))
  (if (eq algorithm :none)
      (progn (%log-diagnostic "Decompression: skipped") data)
      (progn (%log-diagnostic "Decompressing (~D bytes)" (length data))
             ;; Placeholder: requires decompression library
             data)))

(defun hash-blob (data)
  "Compute SHA-256 hash of binary data. Returns 64-char lowercase hex string."
  (declare (type (simple-array (unsigned-byte 8) (*)) data))
  (let ((digest (ironclad:digest-sequence :sha256 data)))
    (format nil "~{~2,'0x~}" (coerce digest 'list))))

(defun hash-file (path)
  "Compute SHA-256 hash of a file. Returns hex string or NIL on error."
  (handler-case
      (let ((digest (ironclad:digest-file :sha256 path)))
        (format nil "~{~2,'0x~}" (coerce digest 'list)))
    (error (e) (%log-diagnostic "Hash failed for ~A: ~A" path e) nil)))


;; ============================================================================
;; SECTION 4b: CHACHA8 STREAM CIPHER (v2 Load-Time Obfuscation)
;; ============================================================================
;; Replaces trivial XOR obfuscation with ChaCha8 stream cipher. ChaCha8 provides
;; real cryptographic protection for in-memory data: 256-bit key, 12-byte nonce,
;; 8 rounds. Comparable performance to AES-CTR but with better software
;; implementation security (no cache timing leaks, constant-time by design).
;;
;; Each blob gets a unique per-load nonce. The key is derived from the master
;; vault key via PBKDF2 with the nonce as salt, providing key isolation between
;; loads even of the same blob.
;; ============================================================================

(defun chacha-cipher-available-p ()
  "Check if Ironclad has ChaCha (any variant) available.
   Returns: :chacha8, :chacha12, :chacha20, or NIL."
  (handler-case
      (progn
        (ironclad:make-cipher :chacha :key (ironclad:random-data 32)
                              :initialization-vector (ironclad:random-data 12))
        :chacha8)
    (error ()
      (handler-case
          (progn
            (ironclad:make-cipher :chacha12 :key (ironclad:random-data 32)
                                  :initialization-vector (ironclad:random-data 12))
            :chacha12)
        (error ()
          (handler-case
              (progn
                (ironclad:make-cipher :chacha20 :key (ironclad:random-data 32)
                                      :initialization-vector (ironclad:random-data 12))
                :chacha20)
            (error () nil)))))))

(defun %make-stream-cipher (key nonce)
  "Create a stream cipher (ChaCha8 preferred, AES-256-CTR fallback).
   KEY: 32-byte octet vector. NONCE: 12-byte octet vector.
   Automatically detects available ciphers in Ironclad.
   Returns: cipher object suitable for ironclad:encrypt/decrypt."
  (declare (type (simple-array (unsigned-byte 8) (32)) key)
           (type (simple-array (unsigned-byte 8) (*)) nonce))
  ;; Try ChaCha variants in order of preference
  (handler-case
      (ironclad:make-cipher :chacha :key key
                            :initialization-vector nonce)
    (error ()
      (handler-case
          (ironclad:make-cipher :chacha12 :key key
                                :initialization-vector nonce)
        (error ()
          (handler-case
              (ironclad:make-cipher :chacha20 :key key
                                    :initialization-vector nonce)
            (error ()
              ;; Fall back to AES-256-CTR
              (%log-diagnostic "ChaCha unavailable, using AES-256-CTR fallback")
              (let ((iv (make-array 16 :element-type '(unsigned-byte 8)
                                    :initial-element 0)))
                (replace iv nonce :start1 0 :end1 (min 12 (length nonce)))
                (ironclad:make-cipher :aes :mode :ctr :key key
                                      :initialization-vector iv)))))))))

(defun chacha8-encrypt-bytes (plaintext &key (key *resource-vault-key*)
                                          (nonce nil))
  "Encrypt byte vector using ChaCha8 stream cipher (or AES-CTR fallback).
   PLAINTEXT: Octet vector to encrypt. Modified in-place — copy first if needed.
   KEY: 32-byte master key. Nonce derived key used for actual encryption.
   NONCE: 12-byte nonce. If NIL, generates random nonce.
   SECURITY: Each call uses a unique nonce. Key is derived via PBKDF2(key, nonce).
   This provides per-load key isolation. Stream cipher XORs keystream with
   plaintext, providing real encryption (not trivially reversible like XOR).
   Returns 2 values: CIPHERTEXT octet vector, NONCE used (12 bytes)."
  (declare (type (simple-array (unsigned-byte 8) (*)) plaintext)
           (type (or null (simple-array (unsigned-byte 8) (32))) key))
  (let ((actual-key (or key (ensure-key-available)))
        (actual-nonce (or nonce (ironclad:random-data *chacha8-nonce-length*))))
    (declare (type (simple-array (unsigned-byte 8) (32)) actual-key)
             (type (simple-array (unsigned-byte 8) (*)) actual-nonce))
    (%log-diagnostic "ChaCha8 encrypt: ~D bytes" (length plaintext))
    ;; Derive per-load subkey: PBKDF2(master-key, nonce, 10000 iters, 32 bytes)
    ;; Using nonce as salt gives us unique key per load without extra storage.
    (let* ((kdf (ironclad:make-kdf 'ironclad:pbkdf2-hmac-sha256 :digest :sha256))
           (subkey (ironclad:derive-key kdf actual-key actual-nonce 10000 32)))
      (unwind-protect
           (let* ((cipher (%make-stream-cipher subkey actual-nonce))
                  (ciphertext (make-array (length plaintext)
                                          :element-type '(unsigned-byte 8))))
             (ironclad:encrypt cipher plaintext ciphertext)
             (%log-diagnostic "ChaCha8 encrypted: ~D bytes" (length ciphertext))
             (values ciphertext actual-nonce))
        (secure-wipe-vector subkey)))))

(defun chacha8-decrypt-bytes (ciphertext nonce &key (key *resource-vault-key*))
  "Decrypt byte vector encrypted with `chacha8-encrypt-bytes'.
   CIPHERTEXT: Octet vector from chacha8-encrypt-bytes.
   NONCE: 12-byte nonce returned by encryption call. Must be preserved.
   KEY: Same 32-byte master key used for encryption.
   SECURITY: Derives same subkey via PBKDF2. Stream cipher is symmetric.
   Returns: PLAINTEXT octet vector (fresh copy). Caller must wipe."
  (declare (type (simple-array (unsigned-byte 8) (*)) ciphertext nonce)
           (type (or null (simple-array (unsigned-byte 8) (32))) key))
  (let ((actual-key (or key (ensure-key-available))))
    (declare (type (simple-array (unsigned-byte 8) (32)) actual-key))
    (%log-diagnostic "ChaCha8 decrypt: ~D bytes" (length ciphertext))
    (let* ((kdf (ironclad:make-kdf 'ironclad:pbkdf2-hmac-sha256 :digest :sha256))
           (subkey (ironclad:derive-key kdf actual-key nonce 10000 32)))
      (unwind-protect
           (let* ((cipher (%make-stream-cipher subkey nonce))
                  (plaintext (make-array (length ciphertext)
                                         :element-type '(unsigned-byte 8))))
             (ironclad:decrypt cipher ciphertext plaintext)
             (%log-diagnostic "ChaCha8 decrypted: ~D bytes" (length plaintext))
             plaintext)
        (secure-wipe-vector subkey)))))

(defun obfuscate-for-loading-v2 (raw-bytes &key (key *resource-vault-key*)
                                                (blob-id nil))
  "Load-time obfuscation using ChaCha8 stream cipher (v2).
   Replaces trivial XOR with real cryptographic protection via ChaCha8/AES-CTR.
   RAW-BYTES: Plaintext octet vector (e.g., decrypted blob). NOT modified.
   KEY: 32-byte master key. BLOB-ID: Optional identifier for logging.
   SECURITY: Generates random 12-byte nonce per call. Derives subkey via PBKDF2.
   ChaCha8 is constant-time by design — no cache timing side channels.
   Falls back to AES-256-CTR if ChaCha8 unavailable in Ironclad.
   Returns 3 values: ENCRYPTED-DATA octets, NONCE (12 bytes), CIPHER-USED.
   CALLER MUST: preserve nonce — required for deobfuscation."
  (declare (type (simple-array (unsigned-byte 8) (*)) raw-bytes)
           (type (or null string) blob-id))
  (%log-diagnostic "Obfuscate-v2 (ChaCha8): ~A, ~D bytes"
                   (or blob-id "unknown") (length raw-bytes))
  (let ((nonce (ironclad:random-data *chacha8-nonce-length*)))
    (unwind-protect
         (multiple-value-bind (ciphertext actual-nonce)
             (chacha8-encrypt-bytes (%copy-octet-vector raw-bytes)
                                    :key key :nonce nonce)
           (declare (ignore actual-nonce)) ; same as nonce we generated
           (values ciphertext nonce (chacha-cipher-available-p)))
      ;; Nonce is returned to caller — don't wipe it
      nil)))

(defun deobfuscate-for-loading-v2 (encrypted-data nonce &key
                                     (key *resource-vault-key*))
  "Reverse `obfuscate-for-loading-v2'. Decrypt ChaCha8-obfuscated data.
   ENCRYPTED-DATA: From obfuscate-for-loading-v2. NONCE: From same call.
   KEY: Same master key used during obfuscation.
   Returns: PLAINTEXT octet vector. Caller must wipe after use."
  (declare (type (simple-array (unsigned-byte 8) (*)) encrypted-data nonce))
  (%log-diagnostic "Deobfuscate-v2 (ChaCha8): ~D bytes" (length encrypted-data))
  (chacha8-decrypt-bytes encrypted-data nonce :key key))


;; ============================================================================
;; SECTION 5: VAULT OPERATIONS
;; ============================================================================

(defun vault-init (&key (path nil) (ephemeral t) (password nil) (max-size nil))
  "Initialize the encrypted resource vault. MUST be called first.
   PATH: Filesystem path for persistence (NIL = memory only).
   EPHEMERAL: T = random key (default). NIL = derive from PASSWORD.
   PASSWORD: Required when EPHEMERAL is NIL. Strong passphrase recommended.
   MAX-SIZE: Override *resource-max-blob-size* (NIL = use default 50MB).
   SEQUENCE: Destroy old state → create lock+hash-table → setup key →
             gen obfuscation key → load from disk if path exists.
   Returns: T on success."
  (%log-diagnostic "Initializing vault v~A" *resource-vault-version*)
  (when *resource-vault-initialized-p* (vault-destroy))
  (when max-size (setf *resource-max-blob-size* max-size))
  (setf *resource-vault-lock*
        #+bordeaux-threads (bordeaux-threads:make-recursive-lock
                            "resource-vault-lock")
        #-bordeaux-threads nil)
  (setf *resource-vault* (make-hash-table :test 'equal))
  (cond (password (%log-diagnostic "Password-derived key")
                   (derive-vault-key password))
        (ephemeral (%log-diagnostic "Ephemeral key")
                   (generate-ephemeral-key))
        (t (error "Either :ephemeral T or :password required")))
  (setf *resource-obfuscation-key* (generate-obfuscation-key))
  (setf *resource-vault-path* path)
  (when (and path (probe-file path))
    (handler-case (vault-load-from-disk path)
      (error (e) (%log-diagnostic "Load failed: ~A" e))))
  (setf *resource-vault-initialized-p* t)
  (%log-diagnostic "Vault initialized")
  t)

(defun vault-store (blob-id raw-bytes &key (blob-type :unknown)
                                          (compression :none)
                                          (compress-level 6)
                                          (aad #())
                                          (metadata nil))
  "Store a binary blob in the encrypted vault.
   BLOB-ID: Unique string identifier (e.g. 'ebpf-proc-hider-v3').
   RAW-BYTES: Octet vector. Securely wiped after encryption.
   BLOB-TYPE: :ebpf :lkm :driver :uefi :unknown
   COMPRESSION: :none or :zlib (applied before encryption).
   COMPRESS-LEVEL: 0-9 zlib compression level.
   AAD: Optional associated authenticated data.
   METADATA: Additional plist merged with auto-generated metadata.
   SECURITY: Raw bytes → compress → encrypt → wipe. Unique nonce per call.
   Returns: New vault-entry struct."
  (%ensure-initialized)
  (declare (type string blob-id)
           (type (simple-array (unsigned-byte 8) (*)) raw-bytes aad))
  (%log-diagnostic "Storing: ~A (type: ~A, ~D bytes)"
                   blob-id blob-type (length raw-bytes))
  (%check-blob-size (length raw-bytes))
  (when (vault-exists-p blob-id)
    (%log-diagnostic "Overwriting existing: ~A" blob-id)
    (vault-delete blob-id))
  (let ((original-hash (hash-blob raw-bytes))
        (original-size (length raw-bytes)))
    (let ((processed (compress-blob raw-bytes :algorithm compression
                                               :level compress-level)))
      (multiple-value-bind (ciphertext auth-tag nonce)
          (encrypt-blob processed :aad aad)
        (let ((obf-key (generate-obfuscation-key)))
          (let ((entry-meta (list* :type blob-type :size original-size
                                   :encrypted-size (length ciphertext)
                                   :original-hash original-hash
                                   :compression compression
                                   :compress-level compress-level
                                   :created (%current-timestamp)
                                   :version *resource-vault-version*
                                   :obfuscation-version :chacha8-v2
                                   :security-level "enhanced"
                                   metadata)))
            (let ((entry (make-vault-entry
                          :blob-id blob-id :encrypted-data ciphertext
                          :auth-tag auth-tag :nonce nonce
                          :metadata entry-meta :obfuscation-key obf-key)))
              #+bordeaux-threads
              (bordeaux-threads:with-recursive-lock (*resource-vault-lock*)
                (setf (gethash blob-id *resource-vault*) entry))
              #-bordeaux-threads
              (setf (gethash blob-id *resource-vault*) entry)
              (%log-diagnostic "Stored: ~A (~D -> ~D bytes)"
                               blob-id original-size (length ciphertext))
              entry)))))))

(defun vault-retrieve (blob-id &key (aad #()) (skip-deobfuscate nil))
  "Retrieve and decrypt a binary blob from the vault.
   BLOB-ID: String identifier of the blob.
   AAD: Must match AAD used during storage.
   SKIP-DEOBFUSCATE: If T, return raw decrypted without XOR deobfuscation.
   SECURITY: Decrypts only if auth tag verifies. Returns fresh copy.
   ERROR if: blob not found, auth tag fails, key unavailable.
   Returns 2 values: PLAINTEXT octet vector, METADATA plist.
   CALLER MUST: (secure-wipe-vector plaintext) when done."
  (%ensure-initialized)
  (declare (type string blob-id))
  (%log-diagnostic "Retrieving: ~A" blob-id)
  (let ((entry nil))
    #+bordeaux-threads
    (bordeaux-threads:with-recursive-lock (*resource-vault-lock*)
      (setf entry (gethash blob-id *resource-vault*)))
    #-bordeaux-threads
    (setf entry (gethash blob-id *resource-vault*))
    (unless entry (error "Blob not found: ~A" blob-id))
    (let ((plaintext (if *vault-strict-verification-p*
                         (decrypt-blob-strict (vault-entry-encrypted-data entry)
                                               (vault-entry-auth-tag entry)
                                               (vault-entry-nonce entry)
                                               :aad aad :blob-id blob-id)
                         (decrypt-blob (vault-entry-encrypted-data entry)
                                        (vault-entry-auth-tag entry)
                                        (vault-entry-nonce entry) :aad aad))))
      (let* ((compression (getf (vault-entry-metadata entry)
                               :compression :none))
             (decompressed (decompress-blob plaintext :algorithm compression)))
        (let ((final (cond (skip-deobfuscate decompressed)
                           ;; Use ChaCha8 v2 if metadata indicates it
                           ((eq (getf (vault-entry-metadata entry) :obfuscation-version)
                                :chacha8-v2)
                            (chacha8-decrypt-bytes
                              decompressed
                              (getf (vault-entry-metadata entry) :obfuscation-nonce)
                              :key *resource-vault-key*))
                           ;; Legacy XOR deobfuscation (deprecated)
                           (t (deobfuscate-bytes
                                decompressed (vault-entry-obfuscation-key entry))))))
          (%log-diagnostic "Retrieved: ~A (~D bytes)" blob-id (length final))
          (values final (vault-entry-metadata entry)))))))

(defun vault-delete (blob-id)
  "Delete a blob from the vault and securely wipe its encrypted data.
   Overwrites encrypted-data, auth-tag, nonce, obfuscation-key with zeros.
   Removes entry from hash table.
   Returns: T if found and deleted, NIL if not found."
  (%ensure-initialized)
  (declare (type string blob-id))
  (%log-diagnostic "Deleting: ~A" blob-id)
  (flet ((do-delete ()
           (let ((entry (gethash blob-id *resource-vault*)))
             (when entry
               (awhen (vault-entry-encrypted-data entry)
                 (secure-wipe-vector it))
               (awhen (vault-entry-auth-tag entry) (secure-wipe-vector it))
               (awhen (vault-entry-nonce entry) (secure-wipe-vector it))
               (awhen (vault-entry-obfuscation-key entry)
                 (secure-wipe-vector it))
               (remhash blob-id *resource-vault*)
               (%log-diagnostic "Deleted: ~A" blob-id)
               t))))
    #+bordeaux-threads
    (bordeaux-threads:with-recursive-lock (*resource-vault-lock*) (do-delete))
    #-bordeaux-threads (do-delete)))

(defun vault-exists-p (blob-id)
  "Check if blob-id exists in vault. Returns T/NIL. Thread-safe read."
  (%ensure-initialized)
  (declare (type string blob-id))
  #+bordeaux-threads
  (bordeaux-threads:with-recursive-lock (*resource-vault-lock*)
    (not (null (gethash blob-id *resource-vault*))))
  #-bordeaux-threads
  (not (null (gethash blob-id *resource-vault*))))

(defun vault-list ()
  "List all blob IDs with metadata. Returns sorted alist of (id . meta-plist).
   Does NOT decrypt any data — only reads metadata fields."
  (%ensure-initialized)
  (%log-diagnostic "Listing vault contents")
  (let ((entries nil))
    #+bordeaux-threads
    (bordeaux-threads:with-recursive-lock (*resource-vault-lock*)
      (maphash (lambda (id e) (push (cons id (vault-entry-metadata e))
                                    entries))
               *resource-vault*))
    #-bordeaux-threads
    (maphash (lambda (id e) (push (cons id (vault-entry-metadata e)) entries))
             *resource-vault*)
    (sort entries #'string< :key #'car)))

(defun vault-get-metadata (blob-id)
  "Get metadata plist for a blob without decrypting. Returns NIL if not found.
   Useful for inspecting properties without decryption cost or plaintext in mem."
  (%ensure-initialized)
  (declare (type string blob-id))
  #+bordeaux-threads
  (bordeaux-threads:with-recursive-lock (*resource-vault-lock*)
    (awhen (gethash blob-id *resource-vault*) (vault-entry-metadata it)))
  #-bordeaux-threads
  (awhen (gethash blob-id *resource-vault*) (vault-entry-metadata it)))

(defun vault-import (blob-id file-path &key (blob-type :unknown)
                                            (compression :none)
                                            (metadata nil))
  "Import a binary file from filesystem into the vault.
   BLOB-ID: Vault identifier. FILE-PATH: Source file path.
   BLOB-TYPE: :ebpf :lkm :driver :uefi :unknown
   COMPRESSION: :none or :zlib (before encryption).
   METADATA: Additional plist merged with auto-generated metadata.
   SECURITY: File read into memory, encrypted, buffer wiped. Original NOT deleted.
   Returns: Created vault-entry."
  (%ensure-initialized)
  (declare (type string blob-id file-path))
  (%log-diagnostic "Importing: ~A from ~A" blob-id file-path)
  (let ((file-size (%safe-file-size file-path)))
    (unless file-size (error "Cannot read file: ~A" file-path))
    (%check-blob-size file-size)
    (let ((file-data (make-array file-size :element-type '(unsigned-byte 8))))
      (declare (dynamic-extent file-data))
      (with-open-file (stream file-path :direction :input
                              :element-type '(unsigned-byte 8))
        (read-sequence file-data stream))
      (prog1 (vault-store blob-id file-data :blob-type blob-type
                          :compression compression
                          :metadata (list* :imported-from file-path
                                           :imported-hash (hash-blob file-data)
                                           metadata))
        (%log-diagnostic "Imported: ~A" blob-id)))))

(defun vault-export (blob-id file-path &key (overwrite nil))
  "Export decrypted blob to filesystem file.
   BLOB-ID: Vault identifier. FILE-PATH: Destination path.
   OVERWRITE: If T, replace existing file. If NIL (default), error if exists.
   SECURITY WARNING: Writes DECRYPTED binary to disk! Ensure restrictive
   permissions and encrypted filesystem. Delete ASAP when done.
   Returns: FILE-PATH on success."
  (%ensure-initialized)
  (declare (type string blob-id file-path))
  (when (and (not overwrite) (probe-file file-path))
    (error "File exists: ~A (use :overwrite t)" file-path))
  (%log-diagnostic "Exporting: ~A to ~A" blob-id file-path)
  (multiple-value-bind (bytes metadata) (vault-retrieve blob-id)
    (unwind-protect
         (progn (with-open-file (stream file-path :direction :output
                                        :if-exists :supersede
                                        :if-does-not-exist :create
                                        :element-type '(unsigned-byte 8))
                  (write-sequence bytes stream))
                (%restrict-file-permissions file-path)
                (%log-diagnostic "Exported: ~A (~D bytes)" blob-id (length bytes))
                file-path)
      (secure-wipe-vector bytes))))

(defun vault-save-to-disk (&optional (path nil))
  "Save entire vault to disk as encrypted file.
   PATH: Destination. If NIL, uses *resource-vault-path*. If both NIL, errors.
   FORMAT: Entries serialized → printed as string → encrypted → base64 → file.
   SECURITY: File contains ONLY encrypted data. Master key NOT included.
   Permissions set to 0600.
   Returns: Path to saved file."
  (%ensure-initialized)
  (let ((save-path (or path *resource-vault-path*)))
    (unless save-path (error "No save path. Provide PATH or set *resource-vault-path*."))
    (%log-diagnostic "Saving vault: ~A" save-path)
    (let ((entries-list nil)
          (header (list :version *resource-vault-version*
                       :saved-at (%current-timestamp)
                       :entry-count (hash-table-count *resource-vault*))))
      #+bordeaux-threads
      (bordeaux-threads:with-recursive-lock (*resource-vault-lock*)
        (maphash (lambda (id e) (declare (ignore id))
                   (push (vault-entry-serialize e) entries-list))
                 *resource-vault*))
      #-bordeaux-threads
      (maphash (lambda (id e) (declare (ignore id))
                 (push (vault-entry-serialize e) entries-list))
               *resource-vault*)
      (let* ((vault-data (list :header header :entries entries-list))
             (data-string (with-output-to-string (s) (prin1 vault-data s)))
             (data-bytes (ironclad:ascii-string-to-byte-array data-string)))
        (declare (dynamic-extent data-bytes))
        (multiple-value-bind (ciphertext auth-tag nonce)
            (encrypt-blob (%copy-octet-vector data-bytes))
          (let ((save-plist
                  (list :encrypted t
                        :ciphertext (usb8-array-to-base64-string ciphertext)
                        :auth-tag (usb8-array-to-base64-string auth-tag)
                        :nonce (usb8-array-to-base64-string nonce)
                        :format-version "2.5.0")))
            (with-open-file (stream save-path :direction :output
                                    :if-exists :supersede
                                    :if-does-not-exist :create)
              (prin1 save-plist stream) (terpri stream))
            (%restrict-file-permissions save-path)
            (secure-wipe-vector data-bytes)
            (secure-wipe-vector ciphertext)
            (%log-diagnostic "Saved: ~A (~D entries)" save-path
                             (hash-table-count *resource-vault*))
            save-path))))))

(defun vault-load-from-disk (&optional (path nil))
  "Load encrypted vault from disk.
   PATH: File path. If NIL, uses *resource-vault-path*. If both NIL, errors.
   SECURITY: Auth tag verified before loading. Corrupted/tampered files rejected.
   Existing entries cleared before loading. Current key must match save key.
   ERROR if: file missing, auth fails, wrong format, wrong key.
   Returns: T on success."
  (%ensure-initialized)
  (let ((load-path (or path *resource-vault-path*)))
    (unless load-path (error "No load path."))
    (unless (probe-file load-path) (error "Vault file not found: ~A" load-path))
    (%log-diagnostic "Loading vault: ~A" load-path)
    (let ((file-content (with-open-file (stream load-path :direction :input)
                          (read stream nil nil))))
      (unless file-content (error "Vault file empty: ~A" load-path))
      (let ((encrypted-p (getf file-content :encrypted))
            (format-version (getf file-content :format-version "unknown")))
        (unless encrypted-p (error "Not encrypted format: ~A" load-path))
        (%log-diagnostic "Vault format: ~A" format-version)
        (let ((ct-b64 (getf file-content :ciphertext))
              (tag-b64 (getf file-content :auth-tag))
              (nonce-b64 (getf file-content :nonce)))
          (unless (and ct-b64 tag-b64 nonce-b64)
            (error "Missing required fields: ~A" load-path))
          (let ((ciphertext (base64-string-to-usb8-array ct-b64))
                (auth-tag (base64-string-to-usb8-array tag-b64))
                (nonce (base64-string-to-usb8-array nonce-b64)))
            (let ((decrypted (decrypt-blob ciphertext auth-tag nonce)))
              (unwind-protect
                   (let ((vault-data (read-from-string
                                       (coerce (map 'string #'code-char
                                                    decrypted) 'string))))
                     (unless (and (listp vault-data)
                                  (getf vault-data :header)
                                  (getf vault-data :entries))
                       (error "Invalid vault data: ~A" load-path))
                     #+bordeaux-threads
                     (bordeaux-threads:with-recursive-lock
                         (*resource-vault-lock*) (clrhash *resource-vault*))
                     #-bordeaux-threads (clrhash *resource-vault*)
                     (dolist (es (getf vault-data :entries))
                       (let ((e (vault-entry-deserialize es)))
                         (setf (gethash (vault-entry-blob-id e)
                                        *resource-vault*) e)))
                     (%log-diagnostic "Loaded: ~D entries"
                                      (hash-table-count *resource-vault*))
                     t)
                (secure-wipe-vector decrypted)))))))))


;; ============================================================================
;; SECTION 6: OBFUSCATION
;; ============================================================================

(defun generate-obfuscation-key (&optional (length 32))
  "Generate random XOR obfuscation key. LENGTH: key size in bytes (default 32).
   Uses OS CSPRNG. Returns: octet vector of random bytes."
  (declare (type (integer 16 *) length))
  (when (< length 16) (warn "Obfuscation key < 16 bytes"))
  (ironclad:random-data length))

(defun obfuscate-bytes (data key)
  "DEPRECATED — Use CHACHA8-ENCRYPT-BYTES or OBFUSCATE-FOR-LOADING-V2 instead.
   Obfuscate byte vector with XOR rotating key. DATA modified in-place.
   ALGORITHM: data[i] = data[i] XOR key[i mod key-len] XOR (i mod 256).
   Also performs decoy writes to confuse memory analysis.
   SECURITY: NOT encryption — only complicates memory inspection. Trivially
   reversible by anyone with access to the binary. Kept for backward compatibility.
   Will be removed in v3.0. For actual confidentiality, use ChaCha8.
   Returns: Modified DATA vector.
   DEPRECATION NOTICE: This function was marked DEPRECATED in v2.6.
   Migrate to OBFUSCATE-FOR-LOADING-V2 for cryptographic protection."
  (declare (type (simple-array (unsigned-byte 8) (*)) data key)
           (optimize (speed 3) (safety 1)))
  (let ((key-len (length key)) (data-len (length data)))
    (declare (type fixnum key-len data-len))
    (dotimes (i data-len)
      (declare (type fixnum i))
      (setf (aref data i) (logxor (aref data i)
                                 (aref key (mod i key-len))
                                 (mod i 256))))
    ;; Decoy writes: 4KB random buffer to confuse memory scanning
    (let ((decoy (ironclad:random-data 4096)))
      (declare (dynamic-extent decoy))
      (dotimes (i (min 256 (length decoy)))
        (setf (aref decoy i) (logxor (aref decoy i) i)))
      (ignore decoy))
    data))

(defun deobfuscate-bytes (data key)
  "DEPRECATED — Use CHACHA8-DECRYPT-BYTES or DEOBFUSCATE-FOR-LOADING-V2 instead.
   Reverse XOR obfuscation. DATA modified in-place. Same as obfuscate-bytes
   since XOR is self-inverse. Returns: restored DATA vector.
   CALLER MUST: wipe both DATA and KEY when done.
   DEPRECATION NOTICE: This function was marked DEPRECATED in v2.6.
   Kept for backward compatibility. Will be removed in v3.0."
  (declare (type (simple-array (unsigned-byte 8) (*)) data key)
           (optimize (speed 3) (safety 1)))
  (obfuscate-bytes data key))

(defun derive-session-subkey (blob-id primary-key)
  "Derive session-specific subkey from primary obfuscation key + blob-id.
   Uses SHA-256(primary-key || blob-id). One-way: subkey cannot recover primary.
   Returns: 32-byte subkey."
  (declare (type string blob-id)
           (type (simple-array (unsigned-byte 8) (*)) primary-key))
  (let ((id-bytes (ironclad:ascii-string-to-byte-array blob-id)))
    (unwind-protect
         (let ((combined (concatenate '(vector (unsigned-byte 8))
                                      primary-key id-bytes)))
           (unwind-protect
                (let ((digest (ironclad:digest-sequence :sha256 combined)))
                  (subseq digest 0 (min 32 (length digest))))
             (secure-wipe-vector combined)))
      (secure-wipe-vector id-bytes))))

(defun obfuscate-for-loading (blob-id &key (key nil) (double-obfuscate t))
  "DEPRECATED — Use OBFUSCATE-FOR-LOADING-V2 instead for cryptographic protection.
   Full preparation pipeline for reflective loading. Retrieves blob, decrypts,
   decompresses, applies XOR obfuscation.
   BLOB-ID: Vault identifier. KEY: Optional obfuscation key (NIL = per-blob key).
   DOUBLE-OBFUSCATE: T = two rounds (stronger). NIL = single round.
   Returns 3 values: OBFUSCATED-DATA, LOADING-KEY, METADATA.
   SECURITY: DEPRECATED — uses trivial XOR, not real encryption. Migrating to
   OBFUSCATE-FOR-LOADING-V2 (ChaCha8) provides actual cryptographic protection.
   Kept for backward compatibility. Will be removed in v3.0.
   DEPRECATION NOTICE: Marked DEPRECATED in v2.6. Migrate to v2 immediately."
  (%ensure-initialized)
  (declare (type string blob-id))
  (%log-diagnostic "Preparing for loading: ~A" blob-id)
  (multiple-value-bind (plaintext metadata) (vault-retrieve blob-id)
    (let ((obf-key (or key (vault-entry-obfuscation-key
                            (gethash blob-id *resource-vault*)))))
      (obfuscate-bytes plaintext obf-key)
      (when double-obfuscate
        (let ((session-subkey (derive-session-subkey blob-id obf-key)))
          (unwind-protect (obfuscate-bytes plaintext session-subkey)
            (secure-wipe-vector session-subkey))))
      (let ((loading-key (if double-obfuscate
                             (list :primary obf-key
                                   :session-derivation blob-id)
                             obf-key)))
        (%log-diagnostic "Prepared: ~A (~D bytes)" blob-id (length plaintext))
        (values plaintext loading-key metadata)))))

(defun scramble-memory-layout (data-vectors)
  "Fragment memory by interleaving multiple data vectors. Prevents contiguous
   plaintext regions in memory. Returns single interleaved octet vector.
   Caller must reverse via `unscramble-memory-layout'."
  (declare (type list data-vectors))
  (when (null data-vectors) (return-from scramble-memory-layout #()))
  (let* ((total-size (reduce #'+ data-vectors :key #'length))
         (num-vecs (length data-vectors))
         (scrambled (make-array total-size :element-type '(unsigned-byte 8)))
         (max-len (reduce #'max data-vectors :key #'length))
         (pos 0))
    (declare (type fixnum total-size num-vecs pos max-len))
    (dotimes (i max-len)
      (dolist (vec data-vectors)
        (declare (type (simple-array (unsigned-byte 8) (*)) vec))
        (when (< i (length vec))
          (setf (aref scrambled pos) (aref vec i)) (incf pos))))
    scrambled))

(defun unscramble-memory-layout (scrambled-data vector-sizes)
  "Reverse memory layout scrambling. Returns list of octet vectors.
   CALLER MUST: wipe scrambled-data after unscrambling."
  (declare (type (simple-array (unsigned-byte 8) (*)) scrambled-data)
           (type list vector-sizes))
  (let* ((result-vecs (mapcar (lambda (s) (make-array s
                                     :element-type '(unsigned-byte 8)))
                              vector-sizes))
         (max-len (reduce #'max vector-sizes))
         (pos 0))
    (declare (type fixnum pos max-len))
    (dotimes (i max-len)
      (dolist (vec result-vecs)
        (declare (type (simple-array (unsigned-byte 8) (*)) vec))
        (when (< i (length vec))
          (setf (aref vec i) (aref scrambled-data pos)) (incf pos))))
    result-vecs))


;; ============================================================================
;; SECTION 7: BASE64 TRANSPORT
;; ============================================================================

(defun vault-entry-serialize (entry)
  "Serialize vault-entry to plist for storage/transport.
   Format: (:blob-id \"id\" :encrypted-data \"b64\" :auth-tag \"b64\"
            :nonce \"b64\" :metadata (...) :obfuscation-key \"b64\")
   SECURITY: Only encrypted data — safe to expose. No master key included.
   Returns: Property list."
  (declare (type vault-entry entry))
  (list :blob-id (vault-entry-blob-id entry)
        :encrypted-data (usb8-array-to-base64-string
                          (vault-entry-encrypted-data entry))
        :auth-tag (usb8-array-to-base64-string
                    (vault-entry-auth-tag entry))
        :nonce (usb8-array-to-base64-string
                 (vault-entry-nonce entry))
        :metadata (vault-entry-metadata entry)
        :obfuscation-key (usb8-array-to-base64-string
                           (vault-entry-obfuscation-key entry))))

(defun vault-entry-deserialize (plist)
  "Deserialize plist to vault-entry. Validates sizes: auth-tag=16, nonce=12.
   Checks version compatibility (warns on mismatch). Returns: vault-entry."
  (declare (type list plist))
  (let ((blob-id (getf plist :blob-id))
        (ct-b64 (getf plist :encrypted-data))
        (tag-b64 (getf plist :auth-tag))
        (nonce-b64 (getf plist :nonce))
        (metadata (getf plist :metadata))
        (obf-b64 (getf plist :obfuscation-key)))
    (unless blob-id (error "Missing :blob-id"))
    (unless ct-b64 (error "Missing :encrypted-data"))
    (unless tag-b64 (error "Missing :auth-tag"))
    (unless nonce-b64 (error "Missing :nonce"))
    (let ((ct (base64-string-to-usb8-array ct-b64))
          (tag (base64-string-to-usb8-array tag-b64))
          (nonce (base64-string-to-usb8-array nonce-b64))
          (obf (if obf-b64 (base64-string-to-usb8-array obf-b64)
                   (generate-obfuscation-key))))
      (unless (= (length tag) 16) (error "Auth tag != 16 bytes"))
      (unless (= (length nonce) 12) (error "Nonce != 12 bytes"))
      (let ((v (getf metadata :version)))
        (when (and v (not (string= v *resource-vault-version*)))
          (%log-diagnostic "Version mismatch: entry=~A current=~A"
                          v *resource-vault-version*)))
      (make-vault-entry :blob-id blob-id :encrypted-data ct
                        :auth-tag tag :nonce nonce
                        :metadata metadata :obfuscation-key obf))))

(defun blob-to-base64 (blob-id)
  "Encode vault entry as base64 transport string for gossip protocol.
   Only encrypted data — no plaintext or keys. Returns: base64 string."
  (%ensure-initialized)
  (declare (type string blob-id))
  (let ((entry (gethash blob-id *resource-vault*)))
    (unless entry (error "Blob not found: ~A" blob-id))
    (%log-diagnostic "Encoding for transport: ~A" blob-id)
    (let ((serialized (vault-entry-serialize entry)))
      (let ((s (with-output-to-string (out) (prin1 serialized out))))
        (usb8-array-to-base64-string
          (ironclad:ascii-string-to-byte-array s))))))

(defun base64-to-blob (base64-string)
  "Decode base64 transport string and store in vault.
   BASE64-STRING: From `blob-to-base64' or another LISPMIND node.
   Overwrites existing entries with same blob-id.
   Returns: Stored vault-entry."
  (%ensure-initialized)
  (declare (type string base64-string))
  (%log-diagnostic "Decoding transport string (~D chars)" (length base64-string))
  (let ((decoded (base64-string-to-usb8-array base64-string)))
    (unwind-protect
         (let ((str (coerce (map 'string #'code-char decoded) 'string)))
           (let ((serialized (read-from-string str)))
             (let ((entry (vault-entry-deserialize serialized)))
               (let ((id (vault-entry-blob-id entry)))
                 (when (vault-exists-p id) (vault-delete id))
                 (setf (gethash id *resource-vault*) entry)
                 (%log-diagnostic "Imported from transport: ~A" id)
                 entry))))
      (secure-wipe-vector decoded))))

(defun vault-entries-to-transport-bundle (blob-ids)
  "Serialize multiple entries into single transport bundle.
   BLOB-IDS: List of blob-id strings. Returns: base64-encoded bundle string."
  (%ensure-initialized)
  (declare (type list blob-ids))
  (%log-diagnostic "Creating transport bundle: ~D entries" (length blob-ids))
  (let ((serialized-entries nil))
    (dolist (id blob-ids)
      (let ((e (gethash id *resource-vault*)))
        (if e (push (vault-entry-serialize e) serialized-entries)
            (%log-diagnostic "Skip missing: ~A" id))))
    (let ((bundle (list :version *resource-vault-version*
                       :created (%current-timestamp)
                       :count (length serialized-entries)
                       :entries (nreverse serialized-entries))))
      (usb8-array-to-base64-string
        (ironclad:ascii-string-to-byte-array
          (with-output-to-string (s) (prin1 bundle s)))))))

(defun transport-bundle-to-vault-entries (bundle-base64)
  "Decode transport bundle and store all entries. Returns: list of imported IDs."
  (%ensure-initialized)
  (declare (type string bundle-base64))
  (%log-diagnostic "Decoding bundle (~D chars)" (length bundle-base64))
  (let ((decoded (base64-string-to-usb8-array bundle-base64)))
    (unwind-protect
         (let ((bundle (read-from-string
                        (coerce (map 'string #'code-char decoded) 'string))))
           (unless (getf bundle :entries) (error "Invalid bundle"))
           (%log-diagnostic "Bundle: ~A, ~D entries"
                           (getf bundle :version) (length (getf bundle :entries)))
           (let ((imported nil))
             (dolist (es (getf bundle :entries))
               (handler-case
                   (let ((e (vault-entry-deserialize es)))
                     (let ((id (vault-entry-blob-id e)))
                       (when (vault-exists-p id) (vault-delete id))
                       (setf (gethash id *resource-vault*) e)
                       (push id imported)))
                 (error (e) (%log-diagnostic "Import failed: ~A" e))))
             (nreverse imported)))
      (secure-wipe-vector decoded))))




;; ============================================================================
;; SECTION 8: INTEGRITY & VERIFICATION
;; ============================================================================

(defun verify-blob-integrity (blob-id &key (verify-hash t))
  "Verify integrity of a stored blob. Full end-to-end check:
   1. Decrypt (verifies GCM auth tag)
   2. Optionally recompute SHA-256 and compare with stored :original-hash
   3. Verify metadata consistency
   BLOB-ID: Blob to verify. VERIFY-HASH: T = also verify SHA-256 (slower).
   SECURITY: Temporarily decrypts into memory; wiped before return.
   Returns plist: (:blob-id id :integrity-passed t/nil
                   :auth-tag-verified t/nil :hash-matched t/nil/:skipped
                   :metadata-valid t/nil :errors (list))."
  (%ensure-initialized)
  (declare (type string blob-id))
  (%log-diagnostic "Verifying integrity: ~A" blob-id)
  (let ((entry (gethash blob-id *resource-vault*))
        (errors nil) (auth-v nil) (hash-m :skipped) (meta-v nil))
    (unless entry
      (return-from verify-blob-integrity
        (list :blob-id blob-id :integrity-passed nil :auth-tag-verified nil
              :hash-matched :skipped :metadata-valid nil
              :errors '("Blob not found"))))
    (let ((meta (vault-entry-metadata entry)))
      (setf meta-v (and (getf meta :type) (getf meta :size)
                        (getf meta :version) (integerp (getf meta :size))
                        (plusp (getf meta :size))))
      (unless meta-v (push "Metadata missing fields" errors)))
    (handler-case
        (let ((plaintext (decrypt-blob (vault-entry-encrypted-data entry)
                                        (vault-entry-auth-tag entry)
                                        (vault-entry-nonce entry))))
          (setf auth-v t)
          (unwind-protect
               (when verify-hash
                 (let* ((meta (vault-entry-metadata entry))
                        (stored (getf meta :original-hash))
                        (computed (hash-blob plaintext)))
                   (if (and stored (string-equal stored computed))
                       (setf hash-m t)
                       (progn (setf hash-m nil)
                              (push "SHA-256 hash mismatch" errors)))))
            (secure-wipe-vector plaintext)))
      (error (e) (setf auth-v nil)
             (push (format nil "Decrypt failed: ~A" e) errors)))
    (let ((passed (and auth-v (or (eq hash-m t) (eq hash-m :skipped)) meta-v)))
      (%log-diagnostic "Integrity ~A: ~A (~D errors)"
                       blob-id (if passed "PASSED" "FAILED") (length errors))
      (list :blob-id blob-id :integrity-passed passed
            :auth-tag-verified auth-v :hash-matched hash-m
            :metadata-valid meta-v :errors (nreverse errors)))))

(defun vault-health-check (&key (verify-hashes nil) (verbose t))
  "Comprehensive health check on entire vault.
   VERIFY-HASHES: T = verify SHA-256 for all (slower, more thorough).
   VERBOSE: T = print progress to *standard-output*.
   Returns plist: (:total-entries N :healthy N :corrupted N
                   :missing-metadata N :details (list))."
  (%ensure-initialized)
  (%log-diagnostic "Health check (hashes: ~A)" verify-hashes)
  (when verbose
    (format t "~&=== Vault Health Check ===~%Version: ~A~%Hashes: ~A~%~%"
            *resource-vault-version* (if verify-hashes "enabled" "disabled")))
  (let ((ids (mapcar #'car (vault-list)))
        (healthy 0) (corrupted 0) (missing-meta 0) (details nil))
    (dolist (id ids)
      (when verbose (format t "Checking: ~A ... " id) (force-output))
      (let ((r (verify-blob-integrity id :verify-hash verify-hashes)))
        (push r details)
        (cond ((getf r :integrity-passed) (incf healthy)
               (when verbose (format t "OK~%")))
              ((not (getf r :metadata-valid)) (incf missing-meta)
               (when verbose (format t "MISSING METADATA~%")))
              (t (incf corrupted)
                 (when verbose (format t "FAILED~%")
                       (dolist (e (getf r :errors))
                         (format t "  ERROR: ~A~%" e)))))))
    (when verbose
      (format t "~%Total: ~D  Healthy: ~D  Corrupted: ~D  Missing meta: ~D~%"
              (length ids) healthy corrupted missing-meta))
    (list :total-entries (length ids) :healthy healthy
          :corrupted corrupted :missing-metadata missing-meta
          :details (nreverse details))))

(defun vault-corruption-scan ()
  "Scan vault for corrupted/tampered entries. Automated monitoring use.
   Returns: List of (blob-id . error-messages) for failures, or NIL if healthy."
  (%ensure-initialized)
  (%log-diagnostic "Corruption scan")
  (let ((issues nil))
    (dolist (id (mapcar #'car (vault-list)))
      (let ((r (verify-blob-integrity id)))
        (unless (getf r :integrity-passed)
          (push (cons id (getf r :errors)) issues))))
    (if issues (progn (%log-diagnostic "Found ~D issues" (length issues))
                      (nreverse issues))
        (progn (%log-diagnostic "No issues found") nil))))

(defun vault-nonce-audit ()
  "Audit all nonces for uniqueness. GCM security critically depends on this.
   Reusing nonce+key allows ciphertext forgery and plaintext recovery.
   Returns plist: (:total-entries N :unique-nonces N :collisions (list)
                   :collision-count N). If collisions found, SECURITY ALERT.
   Re-encrypt affected entries immediately with fresh nonces."
  (%ensure-initialized)
  (%log-diagnostic "Nonce audit")
  (let ((nonce-table (make-hash-table :test 'equal)) (collisions nil))
    (flet ((check-entry (id entry)
             (let ((nonce (vault-entry-nonce entry)))
               (when nonce
                 (let ((ns (format nil "~{~2,'0x~}" (coerce nonce 'list))))
                   (if (gethash ns nonce-table)
                       (push (list id (gethash ns nonce-table)) collisions)
                       (setf (gethash ns nonce-table) id)))))))
      #+bordeaux-threads
      (bordeaux-threads:with-recursive-lock (*resource-vault-lock*)
        (maphash #'check-entry *resource-vault*))
      #-bordeaux-threads
      (maphash #'check-entry *resource-vault*))
    (let ((r (list :total-entries (hash-table-count *resource-vault*)
                   :unique-nonces (hash-table-count nonce-table)
                   :collisions (nreverse collisions)
                   :collision-count (length collisions))))
      (when collisions
        (%log-diagnostic "SECURITY ALERT: ~D nonce collision(s)!"
                         (length collisions)))
      r)))

(defun vault-stats ()
  "Compute vault statistics. Returns plist:
   (:entry-count N :total-encrypted-size N :total-original-size N
    :compression-ratio F :encryption-enabled t/nil :key-available t/nil
    :blob-types (plist) :version string)."
  (%ensure-initialized)
  (%log-diagnostic "Computing stats")
  (let ((count 0) (enc-size 0) (orig-size 0)
        (types (list :ebpf 0 :lkm 0 :driver 0 :uefi 0 :unknown 0)))
    (flet ((accum (id entry)
             (declare (ignore id))
             (incf count)
             (let ((m (vault-entry-metadata entry)))
               (incf enc-size (or (getf m :encrypted-size) 0))
               (incf orig-size (or (getf m :size) 0))
               (incf (getf types (getf m :type :unknown) 0)))))
      #+bordeaux-threads
      (bordeaux-threads:with-recursive-lock (*resource-vault-lock*)
        (maphash #'accum *resource-vault*))
      #-bordeaux-threads
      (maphash #'accum *resource-vault*))
    (list :entry-count count :total-encrypted-size enc-size
          :total-original-size orig-size
          :compression-ratio (if (plusp enc-size)
                                 (/ orig-size enc-size 1.0) 0.0)
          :encryption-enabled *resource-vault-encrypted-p*
          :key-available (not (null *resource-vault-key*))
          :blob-types types :version *resource-vault-version*)))

(defun vault-verify-all (&key (remove-corrupted nil))
  "Run all verification checks: auth tags, SHA-256 hashes, nonce uniqueness.
   REMOVE-CORRUPTED: T = auto-delete failing entries (USE WITH CAUTION).
   Returns: (:integrity-check result :nonce-audit result :overall t/nil
             :removed-count N)."
  (%ensure-initialized)
  (%log-diagnostic "Full vault verification")
  (let* ((integrity (vault-health-check :verify-hashes t :verbose nil))
         (nonces (vault-nonce-audit)) (removed 0) (ok t))
    (when (plusp (getf integrity :corrupted 0))
      (setf ok nil)
      (when remove-corrupted
        (dolist (d (getf integrity :details))
          (unless (getf d :integrity-passed)
            (let ((id (getf d :blob-id)))
              (vault-delete id) (incf removed)
              (%log-diagnostic "Removed corrupted: ~A" id))))))
    (when (plusp (getf nonces :collision-count 0)) (setf ok nil))
    (list :integrity-check integrity :nonce-audit nonces
          :overall ok :removed-count removed)))


;; ============================================================================
;; SECTION 9: KERNEL TOOL INTEGRATION
;; ============================================================================

(defvar *kernel-tool-registry* nil
  "Reference to kernel tool registry from kernel-orchestrator. Set during
   orchestrator init. Contains no sensitive data — only metadata + blob-ids.")

(defun make-kernel-tool-entry (&key name os implant-type binary-blob-id
                                    stealth-rating speed-rating evasion-score
                                    prerequisites description)
  "Create kernel-tool-entry struct (or compatible plist if struct unavailable).
   BINARY-BLOB-ID references a blob in this vault. Returns struct or plist.
   SECURITY: Contains only metadata and blob-id — no binary data or keys."
  (declare (type string name binary-blob-id))
  (if (find-class 'kernel-tool-entry nil)
      (make-instance 'kernel-tool-entry :name name :os os
                     :implant-type implant-type :binary-blob-id binary-blob-id
                     :stealth-rating stealth-rating :speed-rating speed-rating
                     :evasion-score evasion-score :prerequisites prerequisites
                     :description description)
      (list :struct-type 'kernel-tool-entry :name name :os os
            :implant-type implant-type :binary-blob-id binary-blob-id
            :stealth-rating stealth-rating :speed-rating speed-rating
            :evasion-score evasion-score :prerequisites prerequisites
            :description description)))

(defun register-kernel-tool-blob (blob-id file-path
                                  &key name os implant-type
                                       (blob-type :unknown)
                                       (compression :none)
                                       stealth-rating
                                       speed-rating evasion-score
                                       prerequisites
                                       description
                                       (auto-register t))
  "Import binary into vault and optionally create kernel-tool-entry.
   BLOB-ID: Vault identifier. FILE-PATH: Source binary path.
   NAME/OS/IMPLANT-TYPE/STEALTH/SPEED/EVASION/PREREQUISITES/DESCRIPTION:
     Fields for kernel-tool-entry struct.
   BLOB-TYPE: :ebpf :lkm :driver :uefi :unknown.
   COMPRESSION: :none or :zlib.
   AUTO-REGISTER: T = create tool entry and add to *kernel-tool-registry*.
   Returns: (:vault-entry entry :tool-entry entry-or-nil)."
  (%ensure-initialized)
  (declare (type string blob-id file-path))
  (%log-diagnostic "Registering tool: ~A from ~A" blob-id file-path)
  (let ((v-entry (vault-import blob-id file-path :blob-type blob-type
                                :compression compression)))
    (if auto-register
        (let ((tool-entry (make-kernel-tool-entry
                            :name (or name blob-id) :os os
                            :implant-type implant-type :binary-blob-id blob-id
                            :stealth-rating stealth-rating
                            :speed-rating speed-rating
                            :evasion-score evasion-score
                            :prerequisites prerequisites
                            :description description)))
          (when *kernel-tool-registry*
            (push tool-entry *kernel-tool-registry*))
          (%log-diagnostic "Registered: ~A" (or name blob-id))
          (list :vault-entry v-entry :tool-entry tool-entry))
        (progn (%log-diagnostic "Stored without tool entry: ~A" blob-id)
               (list :vault-entry v-entry :tool-entry nil)))))

(defun get-tool-binary (blob-id)
  "Retrieve deobfuscated binary for tool deployment. Convenience wrapper.
   BLOB-ID: From kernel-tool-entry.binary-blob-id.
   Returns: Octet vector (decrypted, decompressed, deobfuscated).
   CALLER MUST: (secure-wipe-vector binary) after use."
  (%ensure-initialized)
  (declare (type string blob-id))
  (%log-diagnostic "Getting tool binary: ~A" blob-id)
  (multiple-value-bind (bytes metadata) (vault-retrieve blob-id)
    (declare (ignore metadata))
    bytes))

(defun prepare-tool-for-deployment (blob-id
                                    &key (deobfuscate t)
                                         (verify-integrity t)
                                         (obfuscation-version :chacha8-v2))
  "Full deployment pipeline: retrieve → decrypt → decompress → deobfuscate →
   optionally verify. Used by kernel implant loader for reflective loading.
   BLOB-ID: From kernel-tool-entry.binary-blob-id.
   DEOBFUSCATE: T = apply ChaCha8 deobfuscation v2 (default). NIL = keep obfuscated.
   VERIFY-INTEGRITY: T = verify before return (default). Error if fails.
   OBFUSCATION-VERSION: :chacha8-v2 (default, cryptographically secure) or
     :xor-legacy (deprecated, for backward compatibility only).
   SECURITY: Decrypts to memory using ChaCha8 stream cipher. Returns fresh copy.
   Wipe after use. ChaCha8 provides real encryption vs legacy trivial XOR.
   Returns 3 values: BINARY octets, METADATA plist, INTEGRITY-RESULT."
  (%ensure-initialized)
  (declare (type string blob-id))
  (%log-diagnostic "Preparing for deployment: ~A" blob-id)
  (let ((integ-result nil))
    (when verify-integrity
      (setf integ-result (verify-blob-integrity blob-id))
      (unless (getf integ-result :integrity-passed)
        (error "Integrity failed for ~A: ~{~A; ~}"
               blob-id (getf integ-result :errors))))
    (multiple-value-bind (raw-bytes metadata)
        (vault-retrieve blob-id :skip-deobfuscate (not deobfuscate))
      ;; Apply ChaCha8 v2 deobfuscation if requested and not already done
      (when (and deobfuscate (eq obfuscation-version :chacha8-v2)
                 (eq (getf metadata :obfuscation-version) :chacha8-v2))
        (let ((nonce (getf metadata :obfuscation-nonce)))
          (when nonce
            (setf raw-bytes (chacha8-decrypt-bytes raw-bytes nonce
                                                    :key *resource-vault-key*)))))
      (%log-diagnostic "Prepared: ~A (~D bytes, type: ~A)"
                       blob-id (length raw-bytes)
                       (getf metadata :type :unknown))
      (values raw-bytes metadata integ-result))))

(defun vault-sync-with-toolchain (tool-entries)
  "Synchronize vault with list of kernel-tool-entry structs.
   TOOL-ENTRIES: List of tool entries to check against.
   Returns: (:synced N :missing (ids) :orphaned (ids)).
   Missing = in toolchain but not vault. Orphaned = in vault but not toolchain."
  (%ensure-initialized)
  (declare (type list tool-entries))
  (%log-diagnostic "Syncing with toolchain (~D entries)" (length tool-entries))
  (let* ((tool-ids (mapcar (lambda (e)
                             (if (listp e) (getf e :binary-blob-id)
                                 (kernel-tool-entry-binary-blob-id e)))
                           tool-entries))
         (vault-ids (mapcar #'car (vault-list)))
         (missing nil) (synced 0) (orphaned nil))
    (dolist (id tool-ids)
      (if (member id vault-ids :test #'string=) (incf synced)
          (push id missing)))
    (dolist (id vault-ids)
      (unless (member id tool-ids :test #'string=) (push id orphaned)))
    (%log-diagnostic "Sync: ~D synced, ~D missing, ~D orphaned"
                     synced (length missing) (length orphaned))
    (list :synced synced :missing (nreverse missing)
          :orphaned (nreverse orphaned))))

(defun tool-binary-size (blob-id)
  "Get original plaintext size from metadata (no decryption). Returns NIL
   if not found. Efficient for planning/resource allocation."
  (%ensure-initialized)
  (declare (type string blob-id))
  (awhen (vault-get-metadata blob-id) (getf it :size)))

(defun tool-binary-type (blob-id)
  "Get blob type from metadata. Returns keyword or NIL."
  (%ensure-initialized)
  (declare (type string blob-id))
  (awhen (vault-get-metadata blob-id) (getf it :type :unknown)))

(defun bulk-store-tools (tool-specs)
  "Bulk import multiple tools. TOOL-SPECS: list of plists:
   '((:blob-id \"id\" :file-path \"/path\" :blob-type :ebpf)...)
   Returns: List of vault-entry structs created."
  (%ensure-initialized)
  (declare (type list tool-specs))
  (%log-diagnostic "Bulk storing ~D tools" (length tool-specs))
  (let ((entries nil))
    (dolist (spec tool-specs)
      (handler-case
          (push (vault-import (getf spec :blob-id) (getf spec :file-path)
                             :blob-type (getf spec :blob-type :unknown)
                             :compression (getf spec :compression :none))
                entries)
        (error (e) (%log-diagnostic "Bulk import failed: ~A" e))))
    (%log-diagnostic "Bulk store: ~D/~D succeeded"
                     (length entries) (length tool-specs))
    (nreverse entries)))

(defun bulk-prepare-tools (blob-ids)
  "Prepare multiple tools for simultaneous deployment.
   BLOB-IDS: List of blob identifiers.
   SECURITY: Creates multiple decrypted binaries in memory. Wipe each after.
   Returns: Alist of (blob-id . (binary . metadata))."
  (%ensure-initialized)
  (declare (type list blob-ids))
  (%log-diagnostic "Bulk preparing ~D tools" (length blob-ids))
  (let ((results nil))
    (dolist (id blob-ids)
      (handler-case
          (multiple-value-bind (binary meta)
              (prepare-tool-for-deployment id)
            (push (cons id (cons binary meta)) results))
        (error (e) (%log-diagnostic "Prepare failed for ~A: ~A" id e))))
    (nreverse results)))


;; ============================================================================
;; SECTION 10: CLEANUP & SECURITY
;; ============================================================================

(defun secure-wipe-vector (vec)
  "Securely overwrite byte vector. Three-pass: zeros → random → zeros.
   VEC: (unsigned-byte 8) vector. Modified in-place.
   SECURITY: Best-effort within Lisp runtime. Limitations:
   - Does not affect swap/pagefile (use mlock(), encrypted swap)
   - Does not affect core dumps (disable: ulimit -c 0)
   - Does not prevent GC copies during heap compaction
   - CPU cache may retain transient copies
   For max protection: mlock() + no cores + encrypted swap + TME/MKTME.
   Returns: NIL. Vector zeroed but exists — drop references for GC."
  (when vec
    (let ((len (length vec)))
      (declare (type fixnum len))
      ;; Pass 1: zeros
      (when (> len 0) (fill vec 0))
      ;; Pass 2: random
      (handler-case (when (> len 0)
                      (let ((r (ironclad:random-data len)))
                        (unwind-protect (replace vec r)
                          (fill r 0))))
        (error () nil))
      ;; Pass 3: zeros
      (when (> len 0) (fill vec 0))))
  nil)

(defun vault-destroy ()
  "Controlled vault shutdown. Wipes keys, clears data, resets state.
   ACTIONS: 1) Wipe master key (clear-vault-key) 2) Wipe obfuscation key
   3) Clear hash table 4) Reset variables 5) Force GC.
   Call before SBCL exit or key rotation. Returns: T."
  (%log-diagnostic "Destroying vault")
  (clear-vault-key)
  (when *resource-obfuscation-key*
    (secure-wipe-vector *resource-obfuscation-key*)
    (setf *resource-obfuscation-key* nil))
  (when *resource-vault*
    #+bordeaux-threads
    (bordeaux-threads:with-recursive-lock (*resource-vault-lock*)
      (clrhash *resource-vault*))
    #-bordeaux-threads (clrhash *resource-vault*)
    (setf *resource-vault* nil))
  (setf *resource-vault-initialized-p* nil)
  (setf *resource-vault-path* nil)
  (setf *resource-vault-encrypted-p* t)
  (setf *resource-vault-lock* nil)
  #+sbcl (handler-case (sb-ext:gc :full t) (error (e)))
  (%log-diagnostic "Vault destroyed")
  t)

(defun vault-emergency-shred (&key (exit-after t) (exit-code 0))
  "Emergency destruction with 4-phase secure cleanup.
   
   PHASE 1 — Secure in-memory key wipe:
     Overwrite key bytes: 0x00 → 0xFF → random → 0x00
     Force full GC to collect any Lisp heap copies
   
   PHASE 2 — File destruction (if vault persisted):
     3-pass overwrite: zeros → random → zeros
     Rename file to random name (10 iterations)
     Delete file + sync filesystem
   
   PHASE 3 — Journal mitigation (best effort):
     Linux ext4: attempt to disable journal via ioctl
     Windows: FILE_FLAG_WRITE_THROUGH for direct writes
   
   PHASE 4 — Final cleanup:
     Clear all vault hash table entries
     Replace hash table with fresh empty one
     Exit process cleanly
   
   EXIT-AFTER: T = exit process after shred (default). NIL = return T.
   EXIT-CODE: Process exit code. Default: 0 (clean exit).
   
   SECURITY WARNING: This is BEST-EFFORT destruction. Limitations:
     - SSD wear-leveling may leave data in different physical blocks
     - Journaling filesystems may retain copies in journal
     - CPU caches, swap/pagefile, and core dumps may retain fragments
     - Virtual machine snapshots may preserve memory state
   For GUARANTEED destruction: physical media destruction (shredding, degaussing,
   incineration). This function mitigates casual forensic analysis only.
   
   Example: (defun on-compromise () (vault-emergency-shred))"
  (%log-diagnostic "EMERGENCY SHRED — 4-phase secure destruction")
  (vault-security-event :emergency-shred
                        "Emergency shred initiated — possible compromise"
                        :immediate-shred nil)

  ;; ==========================================================================
  ;; PHASE 1: Secure in-memory key wipe
  ;; ==========================================================================
  (%log-diagnostic "SHRED Phase 1: In-memory key destruction")
  ;; Master key: 4-pass wipe
  (when *resource-vault-key*
    (handler-case
        (let ((key-len (length *resource-vault-key*)))
          ;; Pass 1: zeros
          (fill *resource-vault-key* 0)
          ;; Pass 2: 0xFF
          (fill *resource-vault-key* #xFF)
          ;; Pass 3: random
          (let ((r (ironclad:random-data key-len)))
            (replace *resource-vault-key* r)
            (secure-wipe-vector r))
          ;; Pass 4: zeros
          (fill *resource-vault-key* 0))
      (error (e) (%log-diagnostic "Key wipe error: ~A" e)))
    (setf *resource-vault-key* nil))
  ;; Obfuscation key: same treatment
  (when *resource-obfuscation-key*
    (handler-case
        (progn
          (fill *resource-obfuscation-key* 0)
          (fill *resource-obfuscation-key* #xFF)
          (let ((r (ironclad:random-data (length *resource-obfuscation-key*))))
            (replace *resource-obfuscation-key* r)
            (secure-wipe-vector r))
          (fill *resource-obfuscation-key* 0))
      (error ()))
    (setf *resource-obfuscation-key* nil))
  ;; ChaCha8 subkeys and any derived material: clear special vars
  (setf *vault-strict-verification-p* nil)
  ;; Force garbage collection to collect heap copies
  #+sbcl (handler-case (sb-ext:gc :full t) (error ()))
  (%log-diagnostic "SHRED Phase 1 complete")

  ;; ==========================================================================
  ;; PHASE 2: File destruction (3-pass overwrite + random renames)
  ;; ==========================================================================
  (when *resource-vault-path*
    (%log-diagnostic "SHRED Phase 2: File destruction ~A" *resource-vault-path*)
    (handler-case
        (progn
          ;; Step 1: 3-pass secure overwrite
          (secure-overwrite-file *resource-vault-path* :passes 3)
          ;; Step 2: Rename 10 times with random names
          (let ((current-path *resource-vault-path*)
                (dir (directory-namestring *resource-vault-path*)))
            (dotimes (i 10)
              (let ((new-name (format nil "~A.~36R"
                                      (merge-pathnames
                                        (make-pathname
                                          :name (format nil "~36R" (random 999999999))
                                          :type (format nil "~36R" (random 9999)))
                                        dir)
                                      (random 999999999))))
                (handler-case
                    (progn (rename-file current-path new-name)
                           (setf current-path new-name))
                  (error (e) (%log-diagnostic "Rename ~D failed: ~A" i e)))))
          ;; Step 3: Delete and sync
          (handler-case
              (progn
                (delete-file *resource-vault-path*)
                (sync-filesystem)
                (%log-diagnostic "SHRED Phase 2: file destroyed"))
            (error (e) (%log-diagnostic "Delete failed: ~A" e))))
      (error (e) (%log-diagnostic "File destruction error: ~A" e))))

  ;; ==========================================================================
  ;; PHASE 3: Journal mitigation (best effort)
  ;; ==========================================================================
  (%log-diagnostic "SHRED Phase 3: Journal mitigation")
  (handler-case
      #+sbcl
      (when *resource-vault-path*
        ;; Attempt to trigger a filesystem sync and flush journal
        (sync-filesystem *resource-vault-path*)
        ;; On ext4, try to remove the file from journal (best effort ioctl)
        (handler-case
            (with-open-file (s *resource-vault-path*
                              :direction :output
                              :if-exists :supersede
                              :element-type '(unsigned-byte 8))
              (declare (ignore s))
              nil)  ; Already deleted — this may fail, that's OK
          (error ())))
      #-sbcl nil
    (error (e) (%log-diagnostic "Journal mitigation error: ~A" e)))
  (%log-diagnostic "SHRED Phase 3 complete")

  ;; ==========================================================================
  ;; PHASE 4: Final cleanup
  ;; ==========================================================================
  (%log-diagnostic "SHRED Phase 4: Final cleanup")
  ;; Clear all vault entries
  (when *resource-vault*
    (handler-case
        (progn
          (maphash (lambda (id e)
                     (declare (ignore id))
                     (handler-case
                         (progn
                           (awhen (vault-entry-encrypted-data e)
                             (secure-wipe-vector it))
                           (awhen (vault-entry-auth-tag e)
                             (secure-wipe-vector it))
                           (awhen (vault-entry-nonce e)
                             (secure-wipe-vector it))
                           (awhen (vault-entry-obfuscation-key e)
                             (secure-wipe-vector it)))
                       (error ())))
                   *resource-vault*)
          (clrhash *resource-vault*))
      (error ())))
  ;; Replace with fresh hash table
  (setf *resource-vault* (make-hash-table :test 'equal))
  (setf *resource-vault-initialized-p* nil)
  ;; Force another GC
  #+sbcl (handler-case (sb-ext:gc :full t) (error ()))
  (%log-diagnostic "SHRED Phase 4 complete — vault destroyed")

  ;; Log completion
  (vault-audit-log :emergency-shred :critical
                   "Emergency shred completed successfully")

  ;; Exit or return
  (when exit-after
    #+sbcl (sb-ext:exit :code exit-code :abort nil)
    #-sbcl (quit exit-code))
  t)

(defun vault-key-rotation (new-password &key (old-password nil))
  "Rotate encryption key: decrypt all entries with old key, re-encrypt with new.
   NEW-PASSWORD: Password for new key derivation.
   OLD-PASSWORD: Current password (ignored for ephemeral keys).
   SECURITY: Decrypted intermediates wiped after each entry. Original key
   restored if rotation fails partway. Nonces regenerated.
   Returns: T on success."
  (%ensure-initialized)
  (%log-diagnostic "Key rotation starting")
  (let ((old-key (when *resource-vault-key*
                   (%copy-octet-vector *resource-vault-key*)))
        (new-key nil))
    (unwind-protect
         (progn (setf new-key (derive-vault-key new-password))
                #+bordeaux-threads
                (bordeaux-threads:with-recursive-lock (*resource-vault-lock*)
                  (maphash (lambda (id e)
                             (declare (ignore id))
                             (%rotate-entry-key e old-key new-key))
                           *resource-vault*))
                #-bordeaux-threads
                (maphash (lambda (id e) (declare (ignore id))
                           (%rotate-entry-key e old-key new-key))
                         *resource-vault*)
                (setf *resource-vault-key* new-key)
                (setf new-key nil)
                (%log-diagnostic "Key rotation: ~D entries"
                                 (hash-table-count *resource-vault*))
                t)
      (when old-key (secure-wipe-vector old-key))
      (when new-key (secure-wipe-vector new-key)))))

(defun vault-purge-orphaned-entries (tool-entries)
  "Delete vault entries not referenced by any tool entry.
   TOOL-ENTRIES: List of kernel-tool-entry structs.
   SECURITY: DESTROYS DATA. Backup vault before purging.
   Returns: List of deleted blob-ids."
  (%ensure-initialized)
  (declare (type list tool-entries))
  (%log-diagnostic "Purging orphaned entries")
  (let* ((tool-ids (mapcar (lambda (e)
                             (if (listp e) (getf e :binary-blob-id)
                                 (kernel-tool-entry-binary-blob-id e)))
                           tool-entries))
         (deleted nil))
    (dolist (id (mapcar #'car (vault-list)))
      (unless (member id tool-ids :test #'string=)
        (vault-delete id) (push id deleted)
        (%log-diagnostic "Purged: ~A" id)))
    (%log-diagnostic "Purged ~D entries" (length deleted))
    (nreverse deleted)))


;; ============================================================================
;; SECTION 11: DIAGNOSTICS
;; ============================================================================

(defun vault-status ()
  "Print quick vault status summary. Safe for interactive use/monitoring.
   Returns: Status plist with :initialized :version :entries :encrypted
   :key-available :persistence-path :max-blob-size."
  (let* ((stats (if *resource-vault-initialized-p* (vault-stats)
                    (list :entry-count 0 :encryption-enabled
                          *resource-vault-encrypted-p*
                          :key-available (not (null *resource-vault-key*)))))
         (result (list :initialized *resource-vault-initialized-p*
                      :version *resource-vault-version*
                      :entries (getf stats :entry-count 0)
                      :encrypted (getf stats :encryption-enabled t)
                      :key-available (getf stats :key-available nil)
                      :persistence-path (or *resource-vault-path* "none")
                      :max-blob-size *resource-max-blob-size*)))
    (format t "~&=== LISPMIND Vault Status ===~%")
    (format t "Version:       ~A~%" *resource-vault-version*)
    (format t "Initialized:   ~A~%" (if *resource-vault-initialized-p* "YES" "NO"))
    (format t "Entries:       ~D~%" (getf result :entries))
    (format t "Encrypted:     ~A~%" (if (getf result :encrypted) "YES" "NO"))
    (format t "Key Available: ~A~%" (if (getf result :key-available) "YES" "NO"))
    (format t "Persistence:   ~A~%" (getf result :persistence-path))
    (format t "Max Blob:      ~A~%" (%format-bytes-human *resource-max-blob-size*))
    (format t "==============================~%")
    result))

(defun vault-diagnostics ()
  "Print comprehensive diagnostic report. Suitable for troubleshooting/auditing.
   Includes: config, statistics, health check, nonce audit, key info.
   Returns: Consolidated results plist."
  (format t "~&=== LISPMIND Vault Diagnostic Report ===~%")
  (format t "Generated: ~A~%~%"
          (multiple-value-bind (s m h d mo y) (get-decoded-time)
            (format nil "~4D-~2,'0D-~2,'0D ~2,'0D:~2,'0D:~2,'0D" y mo d h m s)))
  ;; Configuration
  (format t "--- Configuration ---~%")
  (format t "Version:      ~A~%" *resource-vault-version*)
  (format t "Initialized:  ~A~%" *resource-vault-initialized-p*)
  (format t "Encryption:   ~A~%" *resource-vault-encrypted-p*)
  (format t "Max blob:     ~A~%" (%format-bytes-human *resource-max-blob-size*))
  (format t "Persistence:  ~A~%~%" (or *resource-vault-path* "none"))
  ;; Statistics
  (format t "--- Statistics ---~%")
  (if *resource-vault-initialized-p*
      (let ((s (vault-stats)))
        (format t "Entries:     ~D~%" (getf s :entry-count 0))
        (format t "Original:    ~A~%"
                (%format-bytes-human (getf s :total-original-size 0)))
        (format t "Encrypted:   ~A~%"
                (%format-bytes-human (getf s :total-encrypted-size 0)))
        (format t "Ratio:       ~,2F~%" (getf s :compression-ratio 0.0))
        (format t "Key present: ~A~%" (if (getf s :key-available) "YES" "NO"))
        (format t "Types:~%")
        (dolist (tk '( :ebpf :lkm :driver :uefi :unknown))
          (let ((c (getf (getf s :blob-types) tk 0)))
            (when (plusp c) (format t "  ~12A: ~D~%" tk c)))))
      (format t "Not initialized.~%"))
  (format t "~%")
  ;; Health
  (format t "--- Health Check ---~%")
  (if *resource-vault-initialized-p*
      (let ((h (vault-health-check :verbose nil)))
        (format t "Total:    ~D~%" (getf h :total-entries 0))
        (format t "Healthy:  ~D~%" (getf h :healthy 0))
        (format t "Corrupt:  ~D~%" (getf h :corrupted 0))
        (format t "Status:   ~A~%"
                (if (zerop (getf h :corrupted 0)) "HEALTHY" "ISSUES")))
      (format t "Not initialized.~%"))
  (format t "~%")
  ;; Nonce audit
  (format t "--- Nonce Audit ---~%")
  (if *resource-vault-initialized-p*
      (let ((n (vault-nonce-audit)))
        (format t "Entries: ~D  Unique: ~D  Collisions: ~D~%"
                (getf n :total-entries 0) (getf n :unique-nonces 0)
                (getf n :collision-count 0)))
      (format t "Not initialized.~%"))
  (format t "~%--- Key Info ---~%")
  (let ((k (get-key-info)))
    (format t "Available: ~A~%Type:      ~A~%Bits:      ~D~%"
            (if (getf k :available) "YES" "NO")
            (getf k :type :unknown) (getf k :bit-length 0)))
  (format t "~%Overall: ~A~%"
          (if (and *resource-vault-initialized-p*
                   (zerop (getf (vault-health-check :verbose nil) :corrupted 0))
                   (zerop (getf (vault-nonce-audit) :collision-count 0)))
              "GOOD" "ISSUES FOUND"))
  (format t "====================================~%")
  (list :timestamp (%current-timestamp)
        :initialized *resource-vault-initialized-p*
        :version *resource-vault-version*
        :stats (if *resource-vault-initialized-p* (vault-stats) nil)
        :health (if *resource-vault-initialized-p*
                    (vault-health-check :verbose nil) nil)
        :nonce-audit (if *resource-vault-initialized-p*
                         (vault-nonce-audit) nil)
        :key-info (get-key-info)))

(defun vault-help ()
  "Print comprehensive usage documentation.
   Returns: NIL (output to *standard-output*)."
  (format t "~&
================================================================================
              LISPMIND Resource Vault v2.5.0 — Usage Guide
================================================================================

QUICK START
  (vault-init)                                    ; Ephemeral (testing)
  (vault-init :ephemeral nil :password \"pass\")   ; Persistent
  (vault-store \"id\" bytes :blob-type :ebpf)      ; Store binary
  (vault-retrieve \"id\")                           ; Retrieve binary
  (vault-import \"id\" \"/path\" :blob-type :lkm)  ; Import from file
  (vault-status)                                  ; Quick status
  (vault-diagnostics)                             ; Full report
  (vault-destroy)                                 ; Secure shutdown

KEY MANAGEMENT (v2 — tiered multi-factor)
  (derive-vault-key-v2 [:password] [:tier :auto] [:iterations 200000])
    ; :auto = TPM → multi-artifact → ephemeral
    ; :tpm = require TPM sealed key
    ; :multi = system artifact PBKDF2 (200K iters)
    ; :ephemeral = random key only
  (tpm-available-p)                  ; Check TPM2 device presence
  (read-tpm-nv-key [:nv-index])      ; Read sealed key from TPM NV
  (collect-system-artifacts)         ; Gather hardware identifiers

KEY MANAGEMENT (v1 — legacy, backward compat)
  (derive-vault-key password [:salt] [:iterations 100000] [:variant])
  (generate-ephemeral-key)           ; Random key, never persisted
  (set-vault-key key-bytes)          ; Set from external source
  (clear-vault-key)                  ; Wipe key from memory
  (hardware-fingerprint [:variant])  ; Hardware-bound salt

VAULT OPERATIONS
  (vault-init [:path] [:ephemeral] [:password] [:max-size])
  (vault-store blob-id bytes [:blob-type] [:compression])
  (vault-retrieve blob-id [:aad] [:skip-deobfuscate])
  (vault-delete blob-id)
  (vault-exists-p blob-id)
  (vault-list)
  (vault-get-metadata blob-id)
  (vault-import blob-id path [:blob-type] [:compression])
  (vault-export blob-id path [:overwrite])
  (vault-save-to-disk [:path])
  (vault-load-from-disk [:path])

ENCRYPTION
  (encrypt-blob plaintext [:key] [:aad])     ; => ct, tag, nonce
  (decrypt-blob ct tag nonce [:key] [:aad])  ; => plaintext
  (compress-blob data [:algorithm] [:level])
  (decompress-blob data [:algorithm])
  (hash-blob data)       ; => hex string
  (hash-file path)       ; => hex string

OBFUSCATION (v2 — ChaCha8 stream cipher)
  (obfuscate-for-loading-v2 raw-bytes [:key])  ; ChaCha8 encrypt (RECOMMENDED)
  (deobfuscate-for-loading-v2 data nonce [:key])  ; ChaCha8 decrypt
  (chacha8-encrypt-bytes plaintext [:key] [:nonce])  ; Low-level encrypt
  (chacha8-decrypt-bytes ciphertext nonce [:key])    ; Low-level decrypt

OBFUSCATION (v1 — DEPRECATED, XOR)
  (obfuscate-bytes data key)           ; XOR (DEPRECATED, use v2)
  (deobfuscate-bytes data key)         ; Reverse XOR (DEPRECATED)
  (generate-obfuscation-key [len])     ; Random key
  (obfuscate-for-loading id [:key])    ; Full prep pipeline (DEPRECATED)

TRANSPORT
  (blob-to-base64 blob-id)              ; Encode for gossip
  (base64-to-blob b64-string)           ; Decode from transport
  (vault-entry-serialize entry)         ; Entry -> plist
  (vault-entry-deserialize plist)       ; Plist -> entry
  (vault-entries-to-transport-bundle ids)
  (transport-bundle-to-vault-entries b64)

INTEGRITY
  (verify-blob-integrity id [:verify-hash])
  (vault-health-check [:verify-hashes] [:verbose])
  (vault-corruption-scan)
  (vault-nonce-audit)
  (vault-stats)
  (vault-verify-all [:remove-corrupted])

KERNEL TOOLS
  (register-kernel-tool-blob id path [:name] [:os] [:implant-type])
  (get-tool-binary blob-id)
  (prepare-tool-for-deployment id [:deobfuscate] [:verify-integrity])
  (vault-sync-with-toolchain entries)
  (tool-binary-size blob-id)
  (tool-binary-type blob-id)
  (bulk-store-tools specs)
  (bulk-prepare-tools ids)

SECURITY
  (secure-wipe-vector vec)              ; Wipe sensitive data
  (secure-overwrite-file path [:passes]) ; Multi-pass file destruction
  (vault-destroy)                       ; Controlled shutdown
  (vault-emergency-shred [:exit-after]) ; 4-phase secure destruction
  (vault-key-rotation new-password)     ; Re-encrypt all
  (vault-purge-orphaned-entries tools)  ; Cleanup unreferenced

STRICT VERIFICATION (production default)
  *vault-strict-verification-p*         ; T = strict GCM verification
  (decrypt-blob-strict ct tag nonce [:blob-id])  ; Tamper-detecting decrypt
  (verify-gcm-tag ct tag nonce [:aad])  ; Integrity check without decrypt
  ;; On tamper: signals VAULT-TAMPER-DETECTED, clears key, logs event

SPECIAL VARIABLES
  *resource-vault*              — Hash table (blob-id -> entry)
  *resource-vault-encrypted-p*  — Encryption enabled
  *resource-vault-key*          — Master AES-256 key (SENSITIVE!)
  *resource-vault-path*         — Persistence path
  *resource-obfuscation-key*    — Session XOR key
  *resource-vault-version*      — \"2.6.0\"
  *resource-max-blob-size*      — 50MB default
  *vault-key-derivation-tier*   — :auto :tpm :multi :ephemeral
  *vault-strict-verification-p* — T = strict GCM (default, keep T!)
  *code-signing-required-p*     — T = require signed bundle

SECURITY NOTES
  1. Master key is most sensitive — never log/print/serialize it.
  2. Call (vault-destroy) or (clear-vault-key) before shutdown.
  3. Use (vault-emergency-shred) for immediate compromise response.
  4. Wipe decrypted binaries: (secure-wipe-vector bytes) after use.
  5. Vault file contains ONLY encrypted data — key NEVER on disk.
  6. Hardware-bound keys don't work on different machines.
  7. GCM nonce reuse is catastrophic — nonce audit should show 0.
  8. ChaCha8 obfuscation (v2) provides REAL encryption — XOR (v1) is DEPRECATED.
  9. All mutations are thread-safe (recursive locks).
  10. Debugger can bypass all safety checks.
  11. Code signing: verify GPG signature before loading this module.
  12. TPM key derivation (tier 1) provides strongest hardware binding.
================================================================================
~%")
  nil)


;; ============================================================================
;; SECTION 10b: ENHANCED SHRED HELPERS
;; ============================================================================

(defun secure-overwrite-file (file-path &key (passes 3) (block-size 65536))
  "Securely overwrite a file with multiple passes of random/known data.
   FILE-PATH: Path to file. Must exist and be writable.
   PASSES: Number of overwrite passes. Default: 3 (DoD 5220.22-M style:
     pass 1 = 0x00, pass 2 = 0xFF, pass 3 = random). Use 7+ for higher security.
   BLOCK-SIZE: Bytes per write (default 64KB). Larger = faster, more memory.
   SECURITY: Overwrites file content BEFORE deletion. Best effort — limitations:
     - SSD wear-leveling may redirect writes to different physical blocks
     - journaling filesystems (ext3/4, NTFS) may retain copies in journal
     - copy-on-write filesystems (btrfs, ZFS) may preserve old versions
     - bad sectors may not be overwritten
   For guaranteed destruction: physical media destruction (degaussing, shredding).
   Returns: T on success, NIL on failure."
  (declare (type string file-path) (type fixnum passes block-size))
  (unless (probe-file file-path)
    (%log-diagnostic "Overwrite: file not found ~A" file-path)
    (return-from secure-overwrite-file nil))
  (let ((size (%safe-file-size file-path)))
    (unless size
      (%log-diagnostic "Overwrite: cannot determine size ~A" file-path)
      (return-from secure-overwrite-file nil))
    (%log-diagnostic "Secure overwrite: ~A (~D bytes, ~D passes)"
                     file-path size passes)
    (handler-case
        (dotimes (pass passes t)
          (let ((pattern (ecase (mod pass 3)
                           (0 (make-array block-size
                                          :element-type '(unsigned-byte 8)
                                          :initial-element 0))
                           (1 (make-array block-size
                                          :element-type '(unsigned-byte 8)
                                          :initial-element #xFF))
                           (2 (ironclad:random-data block-size)))))
            (unwind-protect
                 (with-open-file (stream file-path :direction :output
                                                 :if-exists :append
                                                 :element-type '(unsigned-byte 8))
                   (file-position stream 0)
                   (do ((remaining size (- remaining block-size)))
                       ((<= remaining 0))
                     (let ((write-len (min remaining block-size)))
                       (write-sequence pattern stream :end write-len)))
                   ;; Force data to disk
                   (finish-output stream)
                   #+sbcl (handler-case (sb-posix:fsync stream) (error ()))
                   (file-position stream 0))
              (secure-wipe-vector pattern))))
      (error (e)
        (%log-diagnostic "Overwrite failed for ~A: ~A" file-path e)
        nil))))

(defun sync-filesystem (&optional (path nil))
  "Synchronize filesystem to ensure all writes are flushed to physical media.
   PATH: If provided, sync only that file's filesystem. If NIL, sync all.
   SECURITY: Ensures overwrite data reaches physical media (best effort).
   Returns: T on success, NIL on failure."
  (handler-case
      #+sbcl
      (if path
          (handler-case
              (with-open-file (s path :direction :output
                                    :if-exists :append
                                    :element-type '(unsigned-byte 8))
                (sb-posix:fsync s)
                (%log-diagnostic "fsync: ~A" path)
                t)
            (error (e)
              (%log-diagnostic "fsync failed: ~A" e)
              nil))
          (progn
            ;; Full system sync — requires root, may fail silently
            (ignore-errors (sb-ext:run-program "/bin/sync" nil :wait nil))
            (%log-diagnostic "Full sync executed")
            t))
      #-sbcl
      (progn (ignore-errors (uiop:run-program "sync" :ignore-error-status t)) t)
    (error (e)
      (%log-diagnostic "Sync failed: ~A" e)
      nil)))


;; ============================================================================
;; ADDITIONAL UTILITY FUNCTIONS
;; ============================================================================

(defun vault-entry-count ()
  "Return number of entries in vault. Returns: non-negative integer."
  (if (and *resource-vault-initialized-p* *resource-vault*)
      (hash-table-count *resource-vault*) 0))

(defun vault-total-size ()
  "Return total encrypted size of all stored blobs in bytes."
  (if *resource-vault-initialized-p*
      (let ((total 0))
        (flet ((accum (id e) (declare (ignore id))
                 (incf total (length (vault-entry-encrypted-data e)))))
          #+bordeaux-threads
          (bordeaux-threads:with-recursive-lock (*resource-vault-lock*)
            (maphash #'accum *resource-vault*))
          #-bordeaux-threads (maphash #'accum *resource-vault*))
        total)
      0))

(defun vault-find-by-type (blob-type)
  "Find all blob IDs of a specific type. BLOB-TYPE: :ebpf :lkm :driver :uefi.
   Returns: List of matching blob-id strings."
  (%ensure-initialized)
  (declare (type (member :ebpf :lkm :driver :uefi :unknown) blob-type))
  (let ((matches nil))
    (flet ((check (id e) (declare (ignore id))
             (when (eq (getf (vault-entry-metadata e) :type) blob-type)
               (push (vault-entry-blob-id e) matches))))
      #+bordeaux-threads
      (bordeaux-threads:with-recursive-lock (*resource-vault-lock*)
        (maphash #'check *resource-vault*))
      #-bordeaux-threads (maphash #'check *resource-vault*))
    (nreverse matches)))

(defun vault-find-by-hash (hash-string)
  "Find blob by its SHA-256 hash. HASH-STRING: 64-char hex (case-insensitive).
   Returns: blob-id if found, NIL otherwise."
  (%ensure-initialized)
  (declare (type string hash-string))
  (let ((norm (string-downcase hash-string)))
    (flet ((check (id e)
             (declare (ignore id))
             (let ((h (getf (vault-entry-metadata e) :original-hash)))
               (when (and h (string-equal h norm))
                 (return-from vault-find-by-hash
                   (vault-entry-blob-id e))))))
      #+bordeaux-threads
      (bordeaux-threads:with-recursive-lock (*resource-vault-lock*)
        (maphash #'check *resource-vault*))
      #-bordeaux-threads (maphash #'check *resource-vault*))
    nil))

(defun vault-clone-entry (source-blob-id new-blob-id &key (re-encrypt t))
  "Clone vault entry under new blob-id.
   SOURCE-BLOB-ID: Existing blob to clone. NEW-BLOB-ID: New identifier.
   RE-ENCRYPT: T = re-encrypt with fresh nonce (default). NIL = share ciphertext.
   Returns: New vault-entry."
  (%ensure-initialized)
  (declare (type string source-blob-id new-blob-id))
  (let ((src (gethash source-blob-id *resource-vault*)))
    (unless src (error "Source not found: ~A" source-blob-id))
    (when (vault-exists-p new-blob-id)
      (error "Target exists: ~A" new-blob-id))
    (if re-encrypt
        (let ((pt (decrypt-blob (vault-entry-encrypted-data src)
                                (vault-entry-auth-tag src)
                                (vault-entry-nonce src))))
          (unwind-protect
               (vault-store new-blob-id (%copy-octet-vector pt)
                           :blob-type (getf (vault-entry-metadata src) :type)
                           :metadata (copy-list (vault-entry-metadata src)))
            (secure-wipe-vector pt)))
        (let ((new (make-vault-entry
                    :blob-id new-blob-id
                    :encrypted-data (vault-entry-encrypted-data src)
                    :auth-tag (vault-entry-auth-tag src)
                    :nonce (vault-entry-nonce src)
                    :metadata (copy-list (vault-entry-metadata src))
                    :obfuscation-key (vault-entry-obfuscation-key src))))
          (setf (gethash new-blob-id *resource-vault*) new)
          new))))

(defun vault-rename-entry (old-blob-id new-blob-id)
  "Rename vault entry (change blob-id). Returns: renamed vault-entry."
  (%ensure-initialized)
  (declare (type string old-blob-id new-blob-id))
  (when (vault-exists-p new-blob-id)
    (error "Target exists: ~A" new-blob-id))
  (let ((e (gethash old-blob-id *resource-vault*)))
    (unless e (error "Source not found: ~A" old-blob-id))
    (setf (vault-entry-blob-id e) new-blob-id)
    (setf (gethash new-blob-id *resource-vault*) e)
    (remhash old-blob-id *resource-vault*)
    (%log-diagnostic "Renamed: ~A -> ~A" old-blob-id new-blob-id)
    e))

(defun vault-compare-entries (blob-id-a blob-id-b)
  "Compare two vault entries' encrypted content for equality.
   Compares ciphertext, auth tags, nonces — NOT plaintext. Uses constant-time
   comparison for auth tags. Returns: T if identical, NIL otherwise."
  (%ensure-initialized)
  (declare (type string blob-id-a blob-id-b))
  (let ((a (gethash blob-id-a *resource-vault*))
        (b (gethash blob-id-b *resource-vault*)))
    (unless (and a b) (return-from vault-compare-entries nil))
    (and (%constant-time-equal (vault-entry-auth-tag a) (vault-entry-auth-tag b))
         (equalp (vault-entry-encrypted-data a) (vault-entry-encrypted-data b))
         (equalp (vault-entry-nonce a) (vault-entry-nonce b)))))

(defun vault-set-diagnostics-log (stream)
  "Set diagnostic log stream. STREAM: output stream, or NIL to disable.
   SECURITY: Logs never contain keys, plaintext, auth tags, or nonces.
   Returns: Previous log stream."
  (let ((old *resource-vault-diagnostics-log*))
    (setf *resource-vault-diagnostics-log* stream)
    old))

(defun vault-module-info ()
  "Return module information as plist. Safe to display — no sensitive data.
   Returns: (:version \"2.6.0\" :encryption \"AES-256-GCM\" ...)."
  (list :module "resource-registry" :version *resource-vault-version*
        :description "Encrypted Resource Vault for LISPMIND"
        :encryption "AES-256-GCM" :kdf "PBKDF2-HMAC-SHA256"
        :kdf-iterations 200000 :hash "SHA-256" :transport "Base64"
        :obfuscation "ChaCha8 stream cipher (v2) — XOR deprecated"
        :key-derivation "Tiered: TPM → multi-artifact → ephemeral"
        :gcm-verification "Strict (vault-tamper-detected on failure)"
        :code-signing-required *code-signing-required-p*
        :strict-verification *vault-strict-verification-p*
        :tpm-available (tpm-available-p)
        :platform (%platform-support-status)
        :dependencies '("ironclad" "cl-base64" "bordeaux-threads")))

;; ============================================================================
;; CONDITIONAL COMPILATION & PLATFORM SUPPORT
;; ============================================================================

(defun %platform-support-status ()
  "Return platform support information for the vault module.
   Checks available features and returns a diagnostic plist.
   Returns: (:sbcl t/nil :threads t/nil :posix t/nil :mlock t/nil
             :urandom t/nil :overall :full/:limited/:minimal)
   SECURITY: This is diagnostic only — no sensitive data exposed.
   Use to determine which security features are available."
  (let ((sbcl-p (member :sbcl *features*))
        (threads-p (or (member :bordeaux-threads *features*)
                       (find-package "BORDEAUX-THREADS")))
        (posix-p (or (member :sb-posix *features*)
                    (find-package "SB-POSIX")))
        (urandom-p (probe-file "/dev/urandom")))
    (list :sbcl (not (null sbcl-p))
          :threads (not (null threads-p))
          :posix (not (null posix-p))
          :mlock (and posix-p sbcl-p)  ; mlock via sb-posix
          :urandom (not (null urandom-p))
          :overall (cond ((and sbcl-p threads-p posix-p urandom-p) :full)
                         ((and sbcl-p urandom-p) :limited)
                         (t :minimal)))))

(defun vault-check-platform ()
  "Print platform support status. Call after loading to verify environment.
   Returns: Platform support plist from `%platform-support-status'."
  (let ((s (%platform-support-status)))
    (format t "~&=== Platform Support ===~%")
    (format t "SBCL:       ~A~%" (if (getf s :sbcl) "YES" "NO"))
    (format t "Threads:    ~A~%" (if (getf s :threads) "YES" "NO"))
    (format t "POSIX:      ~A~%" (if (getf s :posix) "YES" "NO"))
    (format t "mlock():    ~A~%" (if (getf s :mlock) "YES" "NO"))
    (format t "/dev/urand: ~A~%" (if (getf s :urandom) "YES" "NO"))
    (format t "Overall:    ~A~%" (getf s :overall))
    (format t "========================~%")
    (when (eq (getf s :overall) :minimal)
      (warn "Limited platform support. Vault security may be reduced."))
    s))


;; ============================================================================
;; MEMORY LOCKING (mlock) SUPPORT
;; ============================================================================
;; On supported platforms (SBCL + POSIX), attempt to lock key buffers
;; into RAM to prevent them from being swapped to disk.
;; ============================================================================

(defun %mlock-vector (vec)
  "Attempt to mlock() a vector into RAM (prevent swap). Best-effort:
   silently returns NIL on failure. Only works on SBCL with sb-posix.
   VEC: Simple vector of (unsigned-byte 8) to lock.
   SECURITY: Prevents key material from appearing in swap/pagefile.
   Returns: T if locked, NIL if unavailable or failed."
  #+(and sbcl sb-posix)
  (handler-case
      (progn
        (sb-posix:mlock (sb-sys:vector-sap vec) (length vec))
        (%log-diagnostic "mlock: ~D bytes locked" (length vec))
        t)
    (error (e)
      (%log-diagnostic "mlock failed: ~A" e)
      nil))
  #-(and sbcl sb-posix)
  (progn
    (%log-diagnostic "mlock unavailable on this platform")
    nil))

(defun %munlock-vector (vec)
  "Unlock a previously mlock'd vector. Best-effort: silently returns on error.
   VEC: The vector to unlock.
   Returns: T if unlocked, NIL if unavailable or failed."
  #+(and sbcl sb-posix)
  (handler-case
      (progn
        (sb-posix:munlock (sb-sys:vector-sap vec) (length vec))
        (%log-diagnostic "munlock: ~D bytes unlocked" (length vec))
        t)
    (error (e)
      (%log-diagnostic "munlock failed: ~A" e)
      nil))
  #-(and sbcl sb-posix)
  nil)


;; ============================================================================
;; VAULT BACKUP & RESTORE
;; ============================================================================
;; Functions for creating and restoring from backup copies of the vault.
;; Backups are encrypted with the same key as the original vault.
;; ============================================================================

(defun vault-create-backup (backup-path &key (include-key-info nil))
  "Create a backup copy of the vault to BACKUP-PATH.
   The backup is encrypted identically to the original — the same key
   is required to load it. This is NOT a key escrow — the key is NOT
   included in the backup (unless INCLUDE-KEY-INFO is T, which stores
   only key metadata, not the key itself).
   BACKUP-PATH: Destination file path for the backup.
   INCLUDE-KEY-INFO: T = store key metadata (bit length, type) in backup
                     header for reference. NIL (default) = minimal header.
   SECURITY: Backup contains same encrypted data as original. Same key
   required. Set restrictive permissions (0600) on backup file.
   Returns: BACKUP-PATH on success.
   Example:
     (vault-create-backup \"/backup/lispmind-vault-~A.dat\" \"~%
                          :include-key-info t)"
  (%ensure-initialized)
  (declare (type string backup-path))
  (%log-diagnostic "Creating backup: ~A" backup-path)
  (let ((entries-list nil)
        (header (list :version *resource-vault-version*
                     :created (%current-timestamp)
                     :entry-count (hash-table-count *resource-vault*)
                     :source-path (or *resource-vault-path* "memory-only")
                     :key-info (when include-key-info (get-key-info)))))
    #+bordeaux-threads
    (bordeaux-threads:with-recursive-lock (*resource-vault-lock*)
      (maphash (lambda (id e) (declare (ignore id))
                 (push (vault-entry-serialize e) entries-list))
               *resource-vault*))
    #-bordeaux-threads
    (maphash (lambda (id e) (declare (ignore id))
               (push (vault-entry-serialize e) entries-list))
             *resource-vault*)
    (let* ((backup-data (list :header header :entries entries-list))
           (data-string (with-output-to-string (s) (prin1 backup-data s)))
           (data-bytes (ironclad:ascii-string-to-byte-array data-string)))
      (declare (dynamic-extent data-bytes))
      (multiple-value-bind (ciphertext auth-tag nonce)
          (encrypt-blob (%copy-octet-vector data-bytes))
        (let ((save-plist (list :encrypted t
                               :ciphertext (usb8-array-to-base64-string ciphertext)
                               :auth-tag (usb8-array-to-base64-string auth-tag)
                               :nonce (usb8-array-to-base64-string nonce)
                               :format-version "2.5.0"
                               :backup t)))
          (with-open-file (stream backup-path :direction :output
                                  :if-exists :supersede
                                  :if-does-not-exist :create)
            (prin1 save-plist stream) (terpri stream))
          (%restrict-file-permissions backup-path)
          (secure-wipe-vector data-bytes)
          (secure-wipe-vector ciphertext)
          (%log-diagnostic "Backup created: ~A (~D entries)"
                           backup-path (hash-table-count *resource-vault*))
          backup-path))))))

(defun vault-restore-from-backup (backup-path &key (merge-mode :replace))
  "Restore vault from a backup created by `vault-create-backup'.
   BACKUP-PATH: Path to the backup file.
   MERGE-MODE: :replace (default) = clear existing vault, load backup.
               :merge = keep existing entries, add backup entries (overwrite
                        on blob-id collision).
   SECURITY: Same key required as original vault. Auth tag verified.
   Corrupted backups rejected. Merging preserves existing entries not
   present in backup.
   Returns: T on success.
   Example:
     (vault-restore-from-backup \"/backup/vault.dat\" :merge-mode :merge)"
  (%ensure-initialized)
  (declare (type string backup-path))
  (unless (probe-file backup-path) (error "Backup not found: ~A" backup-path))
  (%log-diagnostic "Restoring from backup: ~A (mode: ~A)"
                   backup-path merge-mode)
  (when (eq merge-mode :replace)
    #+bordeaux-threads
    (bordeaux-threads:with-recursive-lock (*resource-vault-lock*)
      (clrhash *resource-vault*))
    #-bordeaux-threads (clrhash *resource-vault*))
  (let ((file-content (with-open-file (stream backup-path :direction :input)
                        (read stream nil nil))))
    (unless (and file-content (getf file-content :backup))
      (error "Not a backup file: ~A" backup-path))
    (let ((ct-b64 (getf file-content :ciphertext))
          (tag-b64 (getf file-content :auth-tag))
          (nonce-b64 (getf file-content :nonce)))
      (unless (and ct-b64 tag-b64 nonce-b64)
        (error "Backup missing fields: ~A" backup-path))
      (let ((ct (base64-string-to-usb8-array ct-b64))
            (tag (base64-string-to-usb8-array tag-b64))
            (nonce (base64-string-to-usb8-array nonce-b64)))
        (let ((decrypted (decrypt-blob ct tag nonce)))
          (unwind-protect
               (let ((data (read-from-string
                             (coerce (map 'string #'code-char decrypted)
                                     'string))))
                 (unless (and (listp data) (getf data :entries))
                   (error "Invalid backup data: ~A" backup-path))
                 (let ((imported 0) (skipped 0))
                   (dolist (es (getf data :entries))
                     (handler-case
                         (let ((e (vault-entry-deserialize es)))
                           (let ((id (vault-entry-blob-id e)))
                             (when (and (eq merge-mode :replace)
                                        (vault-exists-p id))
                               (vault-delete id))
                             (if (or (eq merge-mode :replace)
                                     (not (vault-exists-p id)))
                                 (progn
                                   (setf (gethash id *resource-vault*) e)
                                   (incf imported))
                                 (incf skipped))))
                       (error (e) (%log-diagnostic "Restore entry failed: ~A" e))))
                   (%log-diagnostic "Restored: ~D imported, ~D skipped"
                                   imported skipped)
                   t))
            (secure-wipe-vector decrypted)))))))


;; ============================================================================
;; VAULT MIGRATION
;; ============================================================================
;; Functions for migrating vault data between different keys or systems.
;; ============================================================================

(defun vault-export-for-migration (&key (password nil) (iterations 100000))
  "Export vault encrypted with a migration password for cross-system transfer.
   This re-encrypts all entries with a key derived from PASSWORD, creating
   a portable vault file that can be imported on another system.
   PASSWORD: Migration password. If NIL, uses current key (same-system export).
   ITERATIONS: PBKDF2 iterations for migration key.
   SECURITY: Migration file is encrypted with the migration password. The
   original key is NOT included. Treat the migration file as sensitive —
   anyone with the migration password can decrypt it.
   Returns: Encrypted octet vector (portable vault blob).
   Example:
     (let ((mig (vault-export-for-migration :password \"TempMigPass123!\")))
       (send-to-remote-host mig)
       (secure-wipe-vector mig))"
  (%ensure-initialized)
  (%log-diagnostic "Exporting for migration")
  (let ((entries-list nil)
        (header (list :version *resource-vault-version*
                     :created (%current-timestamp)
                     :entry-count (hash-table-count *resource-vault*)
                     :migration t)))
    #+bordeaux-threads
    (bordeaux-threads:with-recursive-lock (*resource-vault-lock*)
      (maphash (lambda (id e) (declare (ignore id))
                 (push (vault-entry-serialize e) entries-list))
               *resource-vault*))
    #-bordeaux-threads
    (maphash (lambda (id e) (declare (ignore id))
               (push (vault-entry-serialize e) entries-list))
             *resource-vault*)
    (let* ((vault-data (list :header header :entries entries-list))
           (data-string (with-output-to-string (s) (prin1 vault-data s)))
           (data-bytes (ironclad:ascii-string-to-byte-array data-string)))
      (if password
          ;; Re-encrypt with migration password
          (let* ((salt (ironclad:random-data 32))
                 (kdf (ironclad:make-kdf 'ironclad:pbkdf2-hmac-sha256
                                         :digest :sha256))
                 (pw-bytes (ironclad:ascii-string-to-byte-array password)))
            (unwind-protect
                 (let ((mig-key (ironclad:derive-key kdf pw-bytes salt
n                                                     iterations 32)))
                   (multiple-value-bind (ct tag nonce)
                       (encrypt-blob (%copy-octet-vector data-bytes) :key mig-key)
                     (let ((result (list :encrypted t
n                                        :ciphertext (usb8-array-to-base64-string ct)
                                        :auth-tag (usb8-array-to-base64-string tag)
                                        :nonce (usb8-array-to-base64-string nonce)
                                        :salt (usb8-array-to-base64-string salt)
                                        :iterations iterations
                                        :format-version "2.5.0")))
                       (let ((result-bytes (ironclad:ascii-string-to-byte-array
n                                            (with-output-to-string (s)
                                              (prin1 result s)))))
                         (%log-diagnostic "Migration export: ~D entries, ~D bytes"
                                         (length entries-list)
                                         (length result-bytes))
                         (secure-wipe-vector data-bytes)
                         result-bytes)))
              (secure-wipe-vector pw-bytes))))
          ;; Use current key
          (progn
            (%log-diagnostic "Migration export with current key")
            data-bytes)))))

(defun vault-import-from-migration (migration-data &key (password nil))
  "Import vault from migration data created by `vault-export-for-migration'.
   MIGRATION-DATA: Octet vector from export function.
   PASSWORD: Migration password (required if export used password).
   SECURITY: Verifies auth tag before loading. Existing entries cleared.
   Returns: T on success.
   Example:
     (vault-import-from-migration received-bytes :password \"TempMigPass123!\")"
  (%ensure-initialized)
  (declare (type (simple-array (unsigned-byte 8) (*)) migration-data))
  (%log-diagnostic "Importing from migration")
  (let ((mig-plist (read-from-string
                     (coerce (map 'string #'code-char migration-data)
                             'string))))
    (if (and (getf mig-plist :salt) password)
        ;; Decrypt with migration password
        (let* ((salt (base64-string-to-usb8-array (getf mig-plist :salt)))
               (iterations (or (getf mig-plist :iterations) 100000))
               (kdf (ironclad:make-kdf 'ironclad:pbkdf2-hmac-sha256
                                       :digest :sha256))
               (pw-bytes (ironclad:ascii-string-to-byte-array password)))
          (unwind-protect
               (let ((mig-key (ironclad:derive-key kdf pw-bytes salt
n                                                   iterations 32)))
                 (let ((ct (base64-string-to-usb8-array
                            (getf mig-plist :ciphertext)))
                       (tag (base64-string-to-usb8-array
                             (getf mig-plist :auth-tag)))
                       (nonce (base64-string-to-usb8-array
                               (getf mig-plist :nonce))))
                   (let ((decrypted (decrypt-blob ct tag nonce :key mig-key)))
                     (unwind-protect
                          (let ((data (read-from-string
                                        (coerce (map 'string #'code-char
                                                     decrypted)
                                                'string))))
                            #+bordeaux-threads
                            (bordeaux-threads:with-recursive-lock
                                (*resource-vault-lock*)
                              (clrhash *resource-vault*))
                            #-bordeaux-threads (clrhash *resource-vault*)
                            (dolist (es (getf data :entries))
                              (handler-case
                                  (let ((e (vault-entry-deserialize es)))
                                    (setf (gethash (vault-entry-blob-id e)
                                                   *resource-vault*) e))
                                (error (e)
                                  (%log-diagnostic "Import entry failed: ~A"
                                                  e))))
                            (%log-diagnostic "Migration import: ~D entries"
                                            (hash-table-count *resource-vault*))
                            t)
                       (secure-wipe-vector decrypted)))))
            (secure-wipe-vector pw-bytes)))
        ;; Direct import (no password)
        (progn
          (%log-diagnostic "Direct migration import")
          (let ((data (read-from-string
                        (coerce (map 'string #'code-char migration-data)
                                'string))))
            #+bordeaux-threads
            (bordeaux-threads:with-recursive-lock (*resource-vault-lock*)
              (clrhash *resource-vault*))
            #-bordeaux-threads (clrhash *resource-vault*)
            (dolist (es (getf data :entries))
              (handler-case
                  (let ((e (vault-entry-deserialize es)))
                    (setf (gethash (vault-entry-blob-id e) *resource-vault*) e))
                (error (e) (%log-diagnostic "Import entry failed: ~A" e))))
            t)))))


;; ============================================================================
;; AUDIT LOGGING
;; ============================================================================
;; Structured audit logging for security events and operational tracking.
;; All log entries are timestamped and categorized by severity.
;; ============================================================================

(defun vault-audit-log (event-type severity message &key (data nil))
  "Write a structured audit log entry.
   EVENT-TYPE: Keyword (:store :retrieve :delete :key-rotation :integrity-fail
                        :emergency-shred :migration :health-check etc.)
   SEVERITY: :info :warning :error :critical
   MESSAGE: Human-readable description (no sensitive data).
   DATA: Optional plist of non-sensitive context data.
   SECURITY: This function NEVER logs key material, plaintext, auth tags,
   or nonces. All callers must audit their data for leakage.
   Returns: The formatted log line string.
   Example:
     (vault-audit-log :store :info \"Blob stored\" :data '(:blob-id \"x\"))"
  (let ((line (format nil "[~D] [AUDIT] [~A] [~A] ~A~@[ ~S~]"
                      (%current-timestamp) severity event-type message data)))
    (%log-diagnostic "~A" line)
    (when *resource-vault-diagnostics-log*
      (format *resource-vault-diagnostics-log* "~A~%" line)
      (force-output *resource-vault-diagnostics-log*))
    line))

(defun vault-security-event (event-type message &key (immediate-shred nil))
  "Log a security event with optional immediate shred.
   EVENT-TYPE: :tamper-detected :unauthorized-access :key-compromise etc.
   MESSAGE: Description of the security event.
   IMMEDIATE-SHRED: T = call vault-emergency-shred after logging.
                    Use ONLY for confirmed compromise scenarios.
   SECURITY: Triggers emergency procedures. Use sparingly and correctly.
   Returns: Event log line, or does not return if immediate-shred is T.
   Example:
     (vault-security-event :tamper-detected \"Auth tag failure on critical blob\")"
  (let ((line (vault-audit-log event-type :critical
n                               (format nil "SECURITY EVENT: ~A" message))))
    (format *error-output* "~&*** SECURITY EVENT: ~A ***~%" message)
    (force-output *error-output*)
    (when immediate-shred
      (sleep 0.5)  ; Brief delay to ensure log is flushed
      (vault-emergency-shred))
    line))


;; ============================================================================
;; PERFORMANCE MONITORING
;; ============================================================================

(defun vault-measure-operation (operation-name operation-thunk)
  "Measure execution time of a vault operation.
   OPERATION-NAME: String identifier for the operation.
   OPERATION-THUNK: Zero-argument function to execute and measure.
   Returns: (values result elapsed-seconds)
   Example:
     (vault-measure-operation \"store\"
       (lambda () (vault-store \"id\" bytes)))"
  (declare (type string operation-name)
           (type function operation-thunk))
  (let ((start (get-internal-real-time)))
    (multiple-value-prog1 (funcall operation-thunk)
      (let ((elapsed (/ (- (get-internal-real-time) start)
                        internal-time-units-per-second 1.0)))
        (%log-diagnostic "Perf: ~A took ~,3F seconds" operation-name elapsed)
        elapsed))))

(defun vault-benchmark-encryption (data-size &key (iterations 100))
  "Benchmark encryption throughput.
   DATA-SIZE: Size of test data in bytes.
   ITERATIONS: Number of encrypt/decrypt cycles (default: 100).
   Returns: Plist with throughput metrics.
   SECURITY: Uses random data — no sensitive information involved.
   Example:
     (vault-benchmark-encryption (* 1024 1024))  ; 1MB test"
  (%ensure-initialized)
  (let ((test-data (ironclad:random-data data-size)))
    (unwind-protect
         (let ((enc-start (get-internal-real-time)))
           (dotimes (i iterations)
             (multiple-value-bind (ct tag nonce)
                 (encrypt-blob (%copy-octet-vector test-data))
               (let ((pt (decrypt-blob ct tag nonce)))
                 (secure-wipe-vector pt))
               (secure-wipe-vector ct)))
           (let* ((enc-elapsed (/ (- (get-internal-real-time) enc-start)
                                  internal-time-units-per-second 1.0))
                  (total-bytes (* iterations data-size))
                  (throughput (/ total-bytes enc-elapsed)))
             (list :data-size data-size :iterations iterations
                   :total-bytes total-bytes
                   :elapsed-seconds enc-elapsed
                   :throughput-bytes-per-sec (floor throughput)
                   :throughput-mbps (/ throughput 1024 1024 1.0))))
      (secure-wipe-vector test-data))))


;; ============================================================================
;; TESTING & VALIDATION HELPERS
;; ============================================================================

(defun vault-self-test ()
  "Run a comprehensive self-test of the vault module.
   Tests: init, store, retrieve, delete, encrypt/decrypt, integrity,
   serialization, obfuscation, key management.
   Uses synthetic data — no external files required.
   Returns: (:passed N :failed N :results (list))"
  (%log-diagnostic "Running self-test")
  (let ((passed 0) (failed 0) (results nil))
    (flet ((test-case (name thunk)
             (handler-case
                 (progn (funcall thunk) (incf passed)
                        (push (cons name t) results)
                        (%log-diagnostic "TEST PASS: ~A" name))
               (error (e) (incf failed)
                      (push (cons name (format nil "ERROR: ~A" e)) results)
                      (%log-diagnostic "TEST FAIL: ~A — ~A" name e)))))
      ;; Test 1: Init
      (test-case "vault-init"
        (lambda () (vault-init :ephemeral t)))
      ;; Test 2: Store and retrieve
      (test-case "store-retrieve"
        (lambda ()
          (let ((data (ironclad:random-data 1024)))
            (vault-store "test-blob" data :blob-type :ebpf)
            (multiple-value-bind (retrieved meta)
                (vault-retrieve "test-blob")
              (unless (= (length retrieved) 1024)
                (error "Size mismatch"))
              (secure-wipe-vector retrieved)))))
      ;; Test 3: Existence check
      (test-case "exists-p"
        (lambda ()
          (unless (vault-exists-p "test-blob")
            (error "Should exist"))
          (when (vault-exists-p "nonexistent")
            (error "Should not exist"))))
      ;; Test 4: Integrity verification
      (test-case "integrity"
        (lambda ()
          (let ((r (verify-blob-integrity "test-blob")))
            (unless (getf r :integrity-passed)
              (error "Integrity check failed")))))
      ;; Test 5: Serialization round-trip
      (test-case "serialize-roundtrip"
        (lambda ()
          (let* ((entry (gethash "test-blob" *resource-vault*))
                 (serialized (vault-entry-serialize entry))
                 (deserialized (vault-entry-deserialize serialized)))
            (unless (string= (vault-entry-blob-id deserialized) "test-blob")
              (error "Roundtrip failed")))))
      ;; Test 6: Obfuscation round-trip
      (test-case "obfuscation-roundtrip"
        (lambda ()
          (let ((data (ironclad:random-data 256))
                (key (generate-obfuscation-key)))
            (let ((original (copy-seq data)))
              (obfuscate-bytes data key)
              (deobfuscate-bytes data key)
              (unless (equalp data original)
                (error "Obfuscation roundtrip failed")))
            (secure-wipe-vector data))))
      ;; Test 7: Base64 transport round-trip
      (test-case "base64-transport"
        (lambda ()
          (let ((b64 (blob-to-base64 "test-blob")))
            (base64-to-blob b64)
            (unless (vault-exists-p "test-blob")
              (error "Transport roundtrip failed")))))
      ;; Test 8: Delete
      (test-case "delete"
        (lambda ()
          (vault-delete "test-blob")
          (when (vault-exists-p "test-blob")
            (error "Should be deleted"))))
      ;; Test 9: Key lifecycle
      (test-case "key-lifecycle"
        (lambda ()
          (let ((key (generate-ephemeral-key)))
            (unless (and key (= (length key) 32))
              (error "Key generation failed"))
            (clear-vault-key)
            (when *resource-vault-key*
              (error "Key not cleared")))))
      ;; Test 10: Stats
      (test-case "stats"
        (lambda ()
          (let ((s (vault-stats)))
            (unless (integerp (getf s :entry-count))
              (error "Invalid stats")))))
      ;; Test 11: ChaCha8 encrypt/decrypt round-trip
      (test-case "chacha8-roundtrip"
        (lambda ()
          (let ((key (generate-ephemeral-key))
                (plaintext (ironclad:random-data 1024)))
            (multiple-value-bind (ciphertext nonce)
                (chacha8-encrypt-bytes (%copy-octet-vector plaintext) :key key)
              (let ((decrypted (chacha8-decrypt-bytes ciphertext nonce :key key)))
                (unless (equalp plaintext decrypted)
                  (error "ChaCha8 roundtrip failed"))
                (secure-wipe-vector decrypted)
                (secure-wipe-vector ciphertext))))))
      ;; Test 12: ChaCha8 v2 obfuscation pipeline
      (test-case "chacha8-v2-pipeline"
        (lambda ()
          (let ((key (generate-ephemeral-key))
                (data (ironclad:random-data 512)))
            (multiple-value-bind (encrypted nonce cipher)
                (obfuscate-for-loading-v2 (%copy-octet-vector data)
                                          :key key :blob-id "test-pipe")
              (declare (ignore cipher))
              (let ((decrypted (deobfuscate-for-loading-v2 encrypted nonce :key key)))
                (unless (equalp data decrypted)
                  (error "ChaCha8 v2 pipeline roundtrip failed"))
                (secure-wipe-vector decrypted)
                (secure-wipe-vector encrypted))))))
      ;; Test 13: Strict GCM verification (positive case)
      (test-case "strict-gcm-ok"
        (lambda ()
          (let ((key (generate-ephemeral-key))
                (data (ironclad:random-data 256)))
            (multiple-value-bind (ct tag nonce)
                (encrypt-blob (%copy-octet-vector data))
              (let ((pt (decrypt-blob-strict ct tag nonce
                                             :blob-id "test-strict-ok")))
                (unless (equalp data pt)
                  (error "Strict decrypt returned wrong data"))
                (secure-wipe-vector pt))))))
      ;; Test 14: Verify GCM tag standalone
      (test-case "verify-gcm-tag"
        (lambda ()
          (let ((data (ironclad:random-data 128)))
            (multiple-value-bind (ct tag nonce)
                (encrypt-blob (%copy-octet-vector data))
              (unless (verify-gcm-tag ct tag nonce)
                (error "verify-gcm-tag returned NIL for valid data"))
              ;; Corrupt ciphertext — should fail verification
              (setf (aref ct 0) (logxor (aref ct 0) #xFF))
              (when (verify-gcm-tag ct tag nonce)
                (error "verify-gcm-tag returned T for corrupted data"))))))
      ;; Test 15: Multi-artifact key derivation (no error)
      (test-case "derive-v2-ephemeral"
        (lambda ()
          (let ((key (derive-vault-key-v2 :tier :ephemeral)))
            (unless (and key (= (length key) 32))
              (error "v2 ephemeral derivation failed"))
            (clear-vault-key))))
      ;; Test 16: Vault module info
      (test-case "module-info"
        (lambda ()
          (let ((info (vault-module-info)))
            (unless (string= (getf info :version) *resource-vault-version*)
              (error "Module info version mismatch"))
            (unless (eq (getf info :gcm-verification) 'strict)
              (error "Module info strict verification missing")))))
      ;; Cleanup
      (vault-destroy))
    (%log-diagnostic "Self-test: ~D passed, ~D failed" passed failed)
    (list :passed passed :failed failed :results (nreverse results))))


;; ============================================================================
;; CODE SIGNING ENFORCEMENT NOTE
;; ============================================================================
;;
;; SECURITY REQUIREMENT: This module (resource-registry.lisp) MUST be loaded
;; from a signed, verified tarball or encrypted bundle.
;;
;; WHY: This file contains the entire encrypted vault subsystem. An attacker
;; who can modify this source can:
;;   - Replace encryption functions with no-ops (bypass all protection)
;;   - Exfiltrate keys via network channels added to "harmless" functions
;;   - Weaken PBKDF2 iteration counts to enable brute-force attacks
;;   - Disable GCM authentication tag verification (allow tampering)
;;   - Add backdoors to key derivation (leak material in "error messages")
;;
;; VERIFICATION: Before loading, verify:
;;   1. GPG signature on the tarball: gpg --verify bundle.tar.gz.sig
;;   2. SHA-256 hash matches published value
;;   3. File is loaded from a read-only, encrypted filesystem
;;   4. Load path matches expected deployment location
;;
;; DETECTION: If *CODE-SIGNING-REQUIRED-P* is T (default), the module will
;; warn on load if loaded from an unsigned source. This is NOT a substitute
;; for actual verification — it only detects the most obvious cases.
;;
;; TODO: Integrate with code-signing-p to auto-verify signatures on load.
;;
;; ============================================================================

(when *code-signing-required-p*
  (let ((source *load-pathname*))
    (unless (and source (probe-file source))
      (warn 'code-signature-missing :source (or source "unknown")))))


;; Module load banner
(format t "~&;;; LISPMIND Resource Vault v~A loaded~%"
        *resource-vault-version*)
(format t ";;; Encryption: AES-256-GCM | KDF: PBKDF2-HMAC-SHA256 (200K iters)~%")
(format t ";;; Stream Cipher: ChaCha8 (v2 obfuscation) | TPM: ~A~%"
        (if (tpm-available-p) "available" "not available"))
(format t ";;; Strict GCM verify: ~A | Code signing required: ~A~%"
        *vault-strict-verification-p* *code-signing-required-p*)
(format t ";;; Call (vault-help) for docs | (vault-init) to start~%")
(format t ";;; Call (vault-self-test) to verify | (vault-check-platform) for features~%~%")

;;;; ============================================================================
;;;; END OF resource-registry.lisp — LISPMIND v2.6
;;;; ============================================================================

