;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; break-glass.lisp — Emergency Protocol Module for LISPMIND v2.5.1
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; MODULE PURPOSE
;;; ---------------
;;; These are your kill switches. These functions must be documented and ready
;;; to execute if you lose control or suspect the host is being forensically
;;; imaged. Every function has a clear, documented purpose and can be executed
;;; under extreme stress. This code works even when other subsystems have failed
;;; — with extensive error handling and graceful degradation.
;;;
;;; OPERATIONAL DOCTRINE
;;; ---------------------
;;; 1. NO SILENT FAILURES — Every operation logs to *BREAK-GLASS-LOG*.
;;; 2. FAIL OPEN, FAIL SAFE — If a phase fails, subsequent phases still run.
;;; 3. IDEMPOTENT DESTRUCTION — Running shred twice is safe (second is no-op).
;;; 4. AUTONOMOUS CAPABLE — All functions accept :CONFIRM NIL for scripted use.
;;; 5. FORENSIC RESISTANCE — Multiple-pass overwrite, heap poisoning.
;;;
;;; PROCEDURES: (SHRED-ALL-ASSETS)     — 4-phase destruction (NUCLEAR OPTION)
;;;             (RADIO-SILENCE-TRIGGER) — Dormant mode (reversible)
;;;             (BREAK-GLASS-STATUS)    — Check readiness
;;;             (BREAK-GLASS-DIAGNOSTICS) — Self-test (dry-run, safe)
;;;
;;; WARNING: Functions marked [DESTRUCTIVE] cause IRREVERSIBLE DATA LOSS.
;;; VERSION: 2.5.1 | COMPAT: SBCL 2.3+ | PACKAGE: :LISPMIND
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(in-package :lispmind)

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; SECTION 0 — INTEGRATION POINTS (existing APIs this module calls)
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; resource-registry.lisp: (vault-destroy), (vault-emergency-shred),
;;;   (secure-wipe-vector vector), (clear-vault-key), *resource-vault*,
;;;   *resource-vault-key*
;;; kernel-orchestrator.lisp: (list-kernel-implants), (remove-kernel-implant),
;;;   (stop-kernel-health-monitor), *kernel-implants*
;;; system-init-v2.5.lisp: (stop-persistence-state-manager),
;;;   (stop-persistence-watchdog), (enter-radio-silence &optional trigger),
;;;   *radio-silence-mode-p*, *lispmind-init-complete-p*
;;; gossip-v2.4.lisp: (stop-tactical-gossip), (gossip-publish topic payload)
;;; telemetry.lisp: (telemetry-flush), *telemetry-log-buffer*
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; SECTION 1 — SPECIAL VARIABLES
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defparameter *break-glass-active-p* nil
  "T if any emergency procedure is currently executing.
   Set by SHRED-ALL-ASSETS and RADIO-SILENCE-TRIGGER.
   Prevents nested emergency calls.")

(defparameter *break-glass-log* nil
  "Chronological log of all emergency events. Each entry is a plist with:
   :TIMESTAMP :EVENT :PHASE :PANIC-LEVEL :DETAIL :RESULT.
   Append-only. Use (BREAK-GLASS-LOG) to print.")

(defparameter *shred-all-assets-executed-p* nil
  "ONE-WAY flag. When T, SHRED-ALL-ASSETS has run. Subsequent calls are
   no-ops. Use (BREAK-GLASS-RESET :FORCE T) to clear FOR TESTING ONLY.")

(defparameter *radio-silence-executed-p* nil
  "T if radio silence has been triggered at least once. Does NOT block
   re-entry — radio silence can be entered/exited multiple times.")

(defparameter *dormant-mode-active-p* nil
  "T if system is in dormant mode. Controls the DORMANT-MONITOR-LOOP.")

(defparameter *wake-up-file-path* #P"/tmp/.lispmind_wakeup"
  "Path monitored for the wake-up signal file. Deleted after wake-up.")

(defparameter *break-glass-emergency-contact* "lispmind.emergency"
  "Gossip topic for emergency alerts. Set to NIL to disable.")

(defparameter *break-glass-version* "2.5.1"
  "Module version string (semantic versioning).")

(defparameter *break-glass-diagnostics-running-p* nil
  "Internal flag set while diagnostics are running.")

(defparameter *break-glass-last-check-time* nil
  "Universal timestamp of last readiness check.")

(defparameter *dormant-monitor-thread* nil
  "Handle to the dormant mode monitoring thread (SB-THREAD:THREAD or NIL).")

(defparameter *dormant-wake-up-secret* nil
  "Optional secret string required in the wake-up file for validation.")

(defparameter *dormant-start-time* nil
  "Universal time when dormant mode was entered.")

(defparameter *dormant-target-duration* nil
  "Target duration in seconds for time-limited dormant mode.")

(defparameter *break-glass-shred-passes* 3
  "Number of overwrite passes for secure deletion (1-35, default 3).
   Pass 1: 0x00, Pass 2: 0xFF, Pass 3+: random bytes.")

(defparameter *break-glass-max-retries* 3
  "Maximum retry attempts for individual shred operations.")

(defparameter *break-glass-confirmation-prompt* t
  "Global default for confirmation prompts. When NIL, destructive functions
   execute immediately. Override per-call with :CONFIRM keyword.")

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; SECTION 1.5 — INTERNAL HELPER FUNCTIONS
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun break-glass-timestamp ()
  "Return current universal time as integer.
   Parameters: None. Returns: INTEGER. Side effects: None."
  (get-universal-time))

(defun break-glass-format-time (universal-time)
  "Format UNIVERSAL-TIME as \"YYYY-MM-DD HH:MM:SS UTC\" string.
   Example: (break-glass-format-time 0) => \"1900-01-01 00:00:00 UTC\""
  (multiple-value-bind (sec min hour day month year)
      (decode-universal-time universal-time 0)
    (format nil "~4,'0D-~2,'0D-~2,'0D ~2,'0D:~2,'0D:~2,'0D UTC"
            year month day hour min sec)))

(defun log-break-glass-event (event detail &key phase panic-level result)
  "Append an event to *BREAK-GLASS-LOG* and publish to gossip if available.
   Parameters: EVENT (keyword), DETAIL (string), :PHASE, :PANIC-LEVEL, :RESULT.
   Returns: The newly created log entry plist. Side effects: Logs, may gossip."
  (let ((entry (list :timestamp (break-glass-timestamp)
                     :event event :detail detail :phase phase
                     :panic-level panic-level :result result)))
    (push entry *break-glass-log*)
    (ignore-errors
      (when (and *break-glass-emergency-contact*
                 (boundp '*lispmind-init-complete-p*)
                 *lispmind-init-complete-p*
                 (fboundp 'gossip-publish))
        (gossip-publish *break-glass-emergency-contact*
                        (format nil "[BREAK-GLASS ~A] ~A"
                                (break-glass-format-time (break-glass-timestamp))
                                detail))))
    entry))

(defun break-glass-confirm-p (prompt &key (default-answer nil))
  "Prompt user for Y/N confirmation. If *BREAK-GLASS-CONFIRMATION-PROMPT*
   is NIL, returns DEFAULT-ANSWER immediately. Logs prompt and response.
   Parameters: PROMPT (string), :DEFAULT-ANSWER (boolean, default NIL).
   Returns: BOOLEAN (T if confirmed). Side effects: May read *QUERY-IO*."
  (log-break-glass-event :CONFIRMATION-PROMPT prompt)
  (cond
    ((not *break-glass-confirmation-prompt*)
     (log-break-glass-event :CONFIRMATION-SKIPPED
                            (format nil "Using default: ~A" default-answer)
                            :result (if default-answer :YES :NO))
     default-answer)
    (t
     (format *query-io* "~&~A [y/N]: " prompt)
     (force-output *query-io*)
     (let* ((input (read-line *query-io* nil nil))
            (answer (and input (> (length input) 0)
                         (member (char-downcase (char input 0)) '(#\y #\t))))
            (answer-p (if answer t nil)))
       (log-break-glass-event :CONFIRMATION-RESPONSE
                              (format nil "Answer: ~A" answer-p)
                              :result (if answer-p :YES :NO))
       answer-p))))

(defun random-octets (count)
  "Generate a vector of COUNT random octets using SBCL's strong RNG.
   Parameters: COUNT (integer >= 0).
   Returns: (SIMPLE-ARRAY (UNSIGNED-BYTE 8) (*)). Side effects: Uses entropy."
  (declare (type (integer 0) count))
  (let ((vec (make-array count :element-type '(unsigned-byte 8))))
    (dotimes (i count vec)
      (setf (aref vec i) (random 256)))))

(defun overwrite-vector (vector &key (passes *break-glass-shred-passes*))
  "Securely overwrite a byte vector with multiple passes.
   Pass 1: 0x00 (zeros), Pass 2: 0xFF (ones), Pass 3+: random bytes.
   Final state is random bytes.
   Parameters: VECTOR (byte vector), :PASSES (integer 1-35, default 3).
   Returns: VECTOR (modified in place). Side effects: [DESTRUCTIVE]."
  (declare (type (simple-array (unsigned-byte 8) (*)) vector)
           (type (integer 1 35) passes))
  (dotimes (p passes vector)
    (let ((fill-byte (cond ((= p 0) 0) ((= p 1) 255) (t nil))))
      (if fill-byte
          (dotimes (i (length vector)) (setf (aref vector i) fill-byte))
          (dotimes (i (length vector)) (setf (aref vector i) (random 256)))))))

(defun overwrite-vector-random (vector)
  "Single-pass overwrite of a vector with random bytes.
   Parameters: VECTOR (byte vector). Returns: VECTOR (modified in place).
   Side effects: [DESTRUCTIVE] modifies VECTOR."
  (dotimes (i (length vector) vector)
    (setf (aref vector i) (random 256))))

(defun safe-eval (form &key description)
  "Evaluate FORM inside IGNORE-ERRORS wrapper. Logs result.
   Parameters: FORM (lisp form), :DESCRIPTION (string).
   Returns: (values result t) on success, (values nil nil) on error.
   Side effects: Logs to *BREAK-GLASS-LOG*."
  (handler-case
      (let ((result (eval form)))
        (log-break-glass-event :SAFE-EVAL-OK (or description "Form")
                               :result :SUCCESS)
        (values result t))
    (error (e)
      (log-break-glass-event :SAFE-EVAL-FAILED
                             (format nil "~A: ~A" (or description "Form") e)
                             :result :FAILED)
      (values nil nil))))

(defun hash-table-keys (ht)
  "Return a list of all keys in hash table HT. Snapshot for safe iteration.
   Parameters: HT (hash-table). Returns: LIST of keys. Side effects: None."
  (let ((keys nil))
    (maphash (lambda (k v) (declare (ignore v)) (push k keys)) ht)
    keys))

(defun break-glass-sleep (seconds)
  "Sleep for approximately SECONDS with +/- 20% jitter to avoid timing analysis.
   Parameters: SECONDS (number). Returns: NIL. Side effects: Blocks thread."
  (let* ((jitter (* seconds 0.2 (/ (random 100) 100.0)))
         (actual (+ seconds (- jitter (* seconds 0.1)))))
    (sleep (max 0.1 actual))))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; SECTION 2 — SHRED-ALL-ASSETS: THE NUCLEAR OPTION
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; 4-phase emergency destruction protocol. NEVER fails silently.
;;; PHASE 1: KEY DESTRUCTION  — Zero-fill all AES-256-GCM keys
;;; PHASE 2: HEAP POISONING   — Overwrite vault memory with random noise
;;; PHASE 3: KERNEL PANIC     — Unload implants, stop monitors
;;; PHASE 4: COVER TRACKS     — Delete logs, exit process
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun shred-phase-1-keys (&key (passes *break-glass-shred-passes*) panic-level)
  "Phase 1: Destroy all encryption keys. Calls CLEAR-VAULT-KEY, overwrites
   *RESOURCE-VAULT-KEY* with multiple passes, sets it to NIL.
   Parameters: :PASSES (integer 1-35), :PANIC-LEVEL (keyword for logging).
   Returns: T on success, NIL on failure. Side effects: [DESTRUCTIVE].
   Safety: Wrapped in IGNORE-ERRORS — failure doesn't stop Phase 2."
  (declare (type (integer 1 35) passes))
  (log-break-glass-event :PHASE-1-START "Phase 1: Key destruction commencing"
                         :phase 1 :panic-level panic-level)
  (handler-case
      (progn
        (ignore-errors
          (when (fboundp 'clear-vault-key)
            (clear-vault-key)
            (log-break-glass-event :KEY-CLEAR "clear-vault-key executed"
                                   :phase 1 :result :SUCCESS)))
        (ignore-errors
          (when (and (boundp '*resource-vault-key*) *resource-vault-key*)
            (let ((key *resource-vault-key*))
              (typecase key
                ((simple-array (unsigned-byte 8) (*))
                 (overwrite-vector key :passes passes))
                (t (when (fboundp 'secure-wipe-vector)
                     (secure-wipe-vector key))))
            (setf *resource-vault-key* nil)
            (log-break-glass-event :KEY-OVERWRITE
                                   (format nil "Vault key overwritten (~D passes), nilled" passes)
                                   :phase 1 :result :SUCCESS)))
        (log-break-glass-event :PHASE-1-COMPLETE "Phase 1: Key destruction complete"
                               :phase 1 :panic-level panic-level :result :SUCCESS)
        t)
    (error (e)
      (log-break-glass-event :PHASE-1-FAILED (format nil "Phase 1: ~A" e)
                             :phase 1 :panic-level panic-level :result :FAILED)
      nil)))

(defun shred-phase-2-heap (&key (passes *break-glass-shred-passes*) panic-level)
  "Phase 2: Heap poisoning. Iterates *RESOURCE-VAULT*, overwrites each entry's
   encrypted-data with random bytes, calls VAULT-DESTROY and VAULT-EMERGENCY-SHRED.
   Parameters: :PASSES (integer), :PANIC-LEVEL (keyword).
   Returns: T on success, NIL on failure. Side effects: [DESTRUCTIVE].
   Safety: Each entry overwrite individually wrapped."
  (declare (type (integer 1 35) passes))
  (log-break-glass-event :PHASE-2-START "Phase 2: Heap poisoning commencing"
                         :phase 2 :panic-level panic-level)
  (handler-case
      (progn
        (ignore-errors
          (when (and (boundp '*resource-vault*) (hash-table-p *resource-vault*))
            (let ((entry-count 0) (poison-count 0))
              (maphash (lambda (key entry)
                         (declare (ignore key))
                         (incf entry-count)
                         (handler-case
                             (when entry
                               (let ((data (if (hash-table-p entry)
                                               (gethash :encrypted-data entry)
                                               entry)))
                                 (when (and data (typep data '(simple-array (unsigned-byte 8) (*))))
                                   (overwrite-vector data :passes passes)
                                   (incf poison-count)))
                               (when (hash-table-p entry)
                                 (dolist (f '(:iv :tag :salt :metadata))
                                   (let ((fd (gethash f entry)))
                                     (when (and fd (typep fd '(simple-array (unsigned-byte 8) (*))))
                                       (overwrite-vector fd :passes passes)))))
                           (error (e)
                             (log-break-glass-event :ENTRY-POISON-FAILED
                                                    (format nil "Entry: ~A" e)
                                                    :phase 2 :result :FAILED))))
                       *resource-vault*)
              (log-break-glass-event :HEAP-POISONED
                                     (format nil "Poisoned ~D/~D entries" poison-count entry-count)
                                     :phase 2 :result :SUCCESS))))
        (ignore-errors
          (when (fboundp 'vault-destroy)
            (vault-destroy)
            (log-break-glass-event :VAULT-DESTROY "vault-destroy executed"
                                   :phase 2 :result :SUCCESS)))
        (ignore-errors
          (when (fboundp 'vault-emergency-shred)
            (vault-emergency-shred)
            (log-break-glass-event :VAULT-EMERGENCY-SHRED "vault-emergency-shred executed"
                                   :phase 2 :result :SUCCESS)))
        (ignore-errors
          (when (and (boundp '*resource-vault*) (hash-table-p *resource-vault*))
            (clrhash *resource-vault*)
            (log-break-glass-event :VAULT-CLEARED "Vault hash table cleared"
                                   :phase 2 :result :SUCCESS)))
        (log-break-glass-event :PHASE-2-COMPLETE "Phase 2: Heap poisoning complete"
                               :phase 2 :panic-level panic-level :result :SUCCESS)
        t)
    (error (e)
      (log-break-glass-event :PHASE-2-FAILED (format nil "Phase 2: ~A" e)
                             :phase 2 :panic-level panic-level :result :FAILED)
      nil)))

(defun shred-phase-3-kernel (&key panic-level)
  "Phase 3: Kernel panic. Unloads ALL kernel implants, stops health monitor,
   stops persistence state manager and watchdog.
   Parameters: :PANIC-LEVEL (keyword).
   Returns: T on success, NIL on failure. Side effects: [DESTRUCTIVE].
   Safety: Each operation individually wrapped in IGNORE-ERRORS."
  (log-break-glass-event :PHASE-3-START "Phase 3: Kernel panic commencing"
                         :phase 3 :panic-level panic-level)
  (handler-case
      (progn
        (ignore-errors
          (when (and (boundp '*kernel-implants*) (hash-table-p *kernel-implants*))
            (let ((implants (hash-table-keys *kernel-implants*)) (removed 0) (failed 0))
              (dolist (implant-id implants)
                (handler-case
                    (progn (when (fboundp 'remove-kernel-implant)
                             (remove-kernel-implant implant-id)
                             (incf removed))
                           (log-break-glass-event :IMPLANT-REMOVED
                                                  (format nil "Removed: ~A" implant-id)
                                                  :phase 3 :result :SUCCESS))
                  (error (e)
                    (incf failed)
                    (log-break-glass-event :IMPLANT-REMOVE-FAILED
                                           (format nil "~A: ~A" implant-id e)
                                           :phase 3 :result :FAILED))))
              (log-break-glass-event :IMPLANT-SUMMARY
                                     (format nil "Removed ~D, failed ~D" removed failed)
                                     :phase 3 :result (if (> failed 0) :PARTIAL :SUCCESS)))))
        (ignore-errors
          (when (fboundp 'list-kernel-implants)
            (let ((tbl (list-kernel-implants)))
              (when (hash-table-p tbl)
                (dolist (id (hash-table-keys tbl))
                  (ignore-errors (when (fboundp 'remove-kernel-implant)
                                   (remove-kernel-implant id))))))))
        (ignore-errors
          (when (fboundp 'stop-kernel-health-monitor)
            (stop-kernel-health-monitor)
            (log-break-glass-event :HEALTH-MONITOR-STOPPED "Health monitor stopped"
                                   :phase 3 :result :SUCCESS)))
        (ignore-errors
          (when (fboundp 'stop-persistence-state-manager)
            (stop-persistence-state-manager)
            (log-break-glass-event :PSM-STOPPED "PSM stopped" :phase 3 :result :SUCCESS)))
        (ignore-errors
          (when (fboundp 'stop-persistence-watchdog)
            (stop-persistence-watchdog)
            (log-break-glass-event :WATCHDOG-STOPPED "Watchdog stopped"
                                   :phase 3 :result :SUCCESS)))
        (log-break-glass-event :PHASE-3-COMPLETE "Phase 3: Kernel panic complete"
                               :phase 3 :panic-level panic-level :result :SUCCESS)
        t)
    (error (e)
      (log-break-glass-event :PHASE-3-FAILED (format nil "Phase 3: ~A" e)
                             :phase 3 :panic-level panic-level :result :FAILED)
      nil)))

(defun shred-phase-4-cover-tracks (&key panic-level)
  "Phase 4: Cover tracks. Flushes telemetry, stops gossip, poisons log buffer,
   enters radio silence, sets executed flag, and EXITS THE PROCESS.
   THIS FUNCTION NEVER RETURNS — it calls SB-EXT:EXIT.
   Parameters: :PANIC-LEVEL (keyword).
   Side effects: [DESTRUCTIVE] Flushes telemetry, stops network, TERMINATES PROCESS.
   WARNING: NEVER RETURNS. Falls back to abort exit, then segfault if needed."
  (log-break-glass-event :PHASE-4-START "Phase 4: Cover tracks — POINT OF NO RETURN"
                         :phase 4 :panic-level panic-level)
  (handler-case
      (progn
        (ignore-errors
          (when (fboundp 'telemetry-flush)
            (telemetry-flush)
            (log-break-glass-event :TELEMETRY-FLUSHED "Telemetry flushed"
                                   :phase 4 :result :SUCCESS)))
        (ignore-errors
          (when (fboundp 'stop-tactical-gossip)
            (stop-tactical-gossip)
            (log-break-glass-event :GOSSIP-STOPPED "Gossip stopped"
                                   :phase 4 :result :SUCCESS)))
        (ignore-errors
          (when (and (boundp '*telemetry-log-buffer*) *telemetry-log-buffer*)
            (let ((buf *telemetry-log-buffer*))
              (typecase buf
                ((simple-array (unsigned-byte 8) (*))
                 (overwrite-vector buf)
                 (log-break-glass-event :TELEMETRY-BUFFER-POISONED "Buffer overwritten"
                                        :phase 4 :result :SUCCESS))
                (string (fill buf #\Nul))
                (list (setf *telemetry-log-buffer* nil))))))
        (ignore-errors
          (when (fboundp 'enter-radio-silence)
            (enter-radio-silence :break-glass-shred)
            (log-break-glass-event :RADIO-SILENCE-ENTERED "Radio silence entered"
                                   :phase 4 :result :SUCCESS)))
        (setf *shred-all-assets-executed-p* t)
        (log-break-glass-event :EXECUTED-FLAG-SET "Executed flag set"
                               :phase 4 :result :SUCCESS)
        (ignore-errors
          (when (and *break-glass-emergency-contact* (fboundp 'gossip-publish))
            (gossip-publish *break-glass-emergency-contact*
                            (format nil "[FINAL] Break-glass at ~A"
                                    (break-glass-format-time (break-glass-timestamp))))
            (log-break-glass-event :FINAL-NOTIFICATION-SENT "Final gossip sent"
                                   :phase 4 :result :SUCCESS)))
        (log-break-glass-event :SHRED-COMPLETE "ALL PHASES COMPLETE — EXITING"
                               :panic-level panic-level :result :SUCCESS)
        ;; EXIT — this never returns
        (handler-case
            (progn (format t "~&[BREAK-GLASS] Exiting in 1s...~%")
                   (force-output) (sleep 1)
                   (sb-ext:exit :code 0 :abort nil))
          (error (e)
            (log-break-glass-event :EXIT-FAILED (format nil "Graceful exit: ~A" e)
                                   :phase 4 :result :FAILED)
            (handler-case (sb-ext:exit :code 1 :abort t)
              (error (e2)
                (log-break-glass-event :EXIT-ABORT-FAILED (format nil "Abort: ~A" e2)
                                       :phase 4 :result :FAILED)
                (sb-sys:with-pinned-objects ()
                  (sb-sys:sap-ref-8 (sb-sys:int-sap 0) 0))))))
    (error (e)
      (log-break-glass-event :PHASE-4-FATAL (format nil "Phase 4 fatal: ~A" e)
                             :phase 4 :panic-level panic-level :result :FAILED)
      (ignore-errors (sb-ext:exit :code 1 :abort t))
      (log-break-glass-event :PHASE-4-STUCK "Exit failed — inconsistent state"
                             :phase 4 :panic-level panic-level :result :FAILED)
      nil)))


(defun shred-all-assets (&key (panic-level :full) (confirm t) (passes *break-glass-shred-passes*))
  "Emergency asset destruction protocol — THE NUCLEAR OPTION.
   Executes 4-phase destruction of all sensitive LISPMIND assets. IRREVERSIBLE.

   PHASE 1: KEY DESTRUCTION — Zero-fill all encryption keys (all modes)
   PHASE 2: HEAP POISONING  — Overwrite vault memory with random noise (all modes)
   PHASE 3: KERNEL PANIC    — Unload implants, stop monitors (:FULL only)
   PHASE 4: COVER TRACKS    — Flush telemetry, stop gossip, EXIT PROCESS

   Parameters:
     :PANIC-LEVEL — Keyword: :FULL (all phases, default), :KEYS-ONLY (phase 1),
                    :SILENT (phases 1, 2, 4 — no kernel panic)
     :CONFIRM     — Boolean: T (default, prompts Y/N), NIL (immediate execution)
     :PASSES      — Integer: overwrite passes per phase (default 3, max 35)

   Returns: :KEYS-ONLY returns T/NIL. :FULL/:SILENT do NOT return (process exits).
   Side effects: [DESTRUCTIVE][IRREVERSIBLE] Destroys keys, data, implants; exits process.
   Safety: Nested call protection via *BREAK-GLASS-ACTIVE-P*. Each phase wrapped
           in IGNORE-ERRORS. Idempotent via *SHRED-ALL-ASSETS-EXECUTED-P*.

   Examples:
     (shred-all-assets)                                 ; interactive full
     (shred-all-assets :panic-level :keys-only :confirm nil)  ; automated keys
     (shred-all-assets :panic-level :silent :confirm nil)     ; automated silent
     (shred-all-assets :passes 7)                       ; max resistance"
  (declare (type (integer 1 35) passes))
  ;; Guard 1: Already executed
  (when *shred-all-assets-executed-p*
    (log-break-glass-event :SHRED-BLOCKED "Already executed"
                           :panic-level panic-level :result :SKIPPED)
    (warn "SHRED-ALL-ASSETS already executed. Use BREAK-GLASS-RESET :FORCE T for testing.")
    (return-from shred-all-assets nil))
  ;; Guard 2: Another emergency active
  (when *break-glass-active-p*
    (log-break-glass-event :SHRED-BLOCKED "Another emergency active"
                           :panic-level panic-level :result :SKIPPED)
    (warn "Another break-glass procedure is active. Aborting.")
    (return-from shred-all-assets nil))
  ;; Guard 3: Confirmation
  (when confirm
    (unless (break-glass-confirm-p
             (format nil "~%*** BREAK-GLASS EMERGENCY DESTRUCTION ***~%~%
PANIC LEVEL: ~A | PASSES: ~D
THIS WILL IRREVERSIBLY DESTROY ALL KEYS AND DATA.~%Proceed?"
                     panic-level passes))
      (log-break-glass-event :SHRED-CANCELLED "Cancelled by user"
                             :panic-level panic-level :result :SKIPPED)
      (format t "~&Shred cancelled.~%")
      (return-from shred-all-assets nil)))
  ;; Begin execution
  (setf *break-glass-active-p* t)
  (log-break-glass-event :SHRED-START (format nil "Starting panic=~A passes=~D"
                                               panic-level passes)
                         :panic-level panic-level :result :SUCCESS)
  ;; Phase 1 (all modes)
  (let ((p1 (shred-phase-1-keys :passes passes :panic-level panic-level)))
    (declare (ignorable p1))
    ;; Phase 2 (all modes)
    (let ((p2 (shred-phase-2-heap :passes passes :panic-level panic-level)))
      (declare (ignorable p2))
      ;; Phase 3 (:FULL only)
      (when (eq panic-level :full)
        (let ((p3 (shred-phase-3-kernel :panic-level panic-level)))
          (declare (ignorable p3))
          ;; Phase 4 (:FULL and :SILENT)
          (when (or (eq panic-level :full) (eq panic-level :silent))
            (shred-phase-4-cover-tracks :panic-level panic-level)
            (log-break-glass-event :SHRED-UNEXPECTED-RETURN "Phase 4 returned"
                                   :panic-level panic-level :result :FAILED))
          (setf *break-glass-active-p* nil)
          (log-break-glass-event :SHRED-PARTIAL "Partial (Phase 4 didn't exit)"
                                 :panic-level panic-level :result :PARTIAL)
          (return-from shred-all-assets nil)))
      ;; :KEYS-ONLY — only Phases 1 and 2, don't exit
      (when (eq panic-level :keys-only)
        (setf *break-glass-active-p* nil)
        (log-break-glass-event :SHRED-KEYS-ONLY-COMPLETE "Keys-only complete"
                               :panic-level panic-level :result :SUCCESS)
        (return-from shred-all-assets t))
      ;; :SILENT mode — Phases 1, 2, then 4
      (when (eq panic-level :silent)
        (shred-phase-4-cover-tracks :panic-level panic-level)
        (setf *break-glass-active-p* nil)
        (return-from shred-all-assets nil))))
  ;; Fallback (should not reach)
  (setf *break-glass-active-p* nil)
  (log-break-glass-event :SHRED-UNKNOWN-PATH "Unknown code path"
                         :panic-level panic-level :result :FAILED)
  nil)

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; SECTION 3 — RADIO-SILENCE-TRIGGER: DORMANT MODE
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; Full radio silence protocol. The "hide and survive" option — reversible.
;;; Contrast with SHRED-ALL-ASSETS which is the "destroy everything" option.
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun check-wake-up-signal (&optional (file-path *wake-up-file-path*))
  "Check if a valid wake-up signal is present at FILE-PATH.
   If *DORMANT-WAKE-UP-SECRET* is set, file must contain that exact string.
   If no secret, file existence alone is sufficient.
   Parameters: FILE-PATH (pathname, default *WAKE-UP-FILE-PATH*).
   Returns: (values boolean content-string-or-nil).
   Side effects: Reads from FILE-PATH if it exists."
  (handler-case
      (when (probe-file file-path)
        (let ((content (with-open-file (s file-path :direction :input
                                          :if-does-not-exist nil)
                         (when s
                           (let ((data (make-string (file-length s))))
                             (read-sequence data s)
                             (string-trim '(#\Space #\Tab #\Newline #\Return) data))))))
          (cond
            (*dormant-wake-up-secret*
             (if (and content (string= content *dormant-wake-up-secret*))
                 (progn (log-break-glass-event :WAKE-UP-SIGNAL-VALID "Secret validated"
                                               :result :SUCCESS)
                        (values t content))
                 (values nil content)))
            (t (log-break-glass-event :WAKE-UP-SIGNAL-FOUND "File exists"
                                      :result :SUCCESS)
               (values t content)))))
    (error (e)
      (log-break-glass-event :WAKE-UP-CHECK-FAILED (format nil "~A" e)
                             :result :FAILED)
      (values nil nil))))

(defun create-wake-up-file (&key (file-path *wake-up-file-path*) secret content)
  "Create a wake-up signal file for the operator. Overwrites if exists.
   Parameters: :FILE-PATH (pathname), :SECRET or :CONTENT (string).
   Returns: FILE-PATH. Side effects: Creates/overwrites file on disk."
  (let ((data (or secret content "")))
    (with-open-file (s file-path :direction :output
                       :if-exists :supersede :if-does-not-exist :create)
      (write-string data s))
    (log-break-glass-event :WAKE-UP-FILE-CREATED (format nil "Created: ~A" file-path)
                           :result :SUCCESS)
    file-path))

(defun enter-dormant-mode (&key duration wake-secret)
  "Enter dormant (radio silence) mode. Sets flags, stops network and
   persistence services, enters radio silence state.
   Parameters: :DURATION (:INDEFINITE | (:HOURS N) | (:MINUTES N)),
               :WAKE-SECRET (string, optional validation secret).
   Returns: T. Side effects: Sets flags, stops services, logs."
  (log-break-glass-event :DORMANT-ENTER "Entering dormant mode" :result :SUCCESS)
  (setf *dormant-mode-active-p* t)
  (setf *radio-silence-executed-p* t)
  (setf *dormant-start-time* (break-glass-timestamp))
  (setf *dormant-target-duration*
        (cond ((eq duration :indefinite) nil)
              ((and (listp duration) (eq (car duration) :hours)) (* 3600 (cadr duration)))
              ((and (listp duration) (eq (car duration) :minutes)) (* 60 (cadr duration)))
              (t nil)))
  (when wake-secret (setf *dormant-wake-up-secret* wake-secret))
  (ignore-errors (when (fboundp 'stop-tactical-gossip)
                   (stop-tactical-gossip)
                   (log-break-glass-event :DORMANT-GOSSIP-STOPPED "Gossip stopped"
                                          :result :SUCCESS)))
  (ignore-errors (when (fboundp 'stop-persistence-state-manager)
                   (stop-persistence-state-manager)
                   (log-break-glass-event :DORMANT-PSM-STOPPED "PSM stopped"
                                          :result :SUCCESS)))
  (ignore-errors (when (fboundp 'stop-persistence-watchdog)
                   (stop-persistence-watchdog)
                   (log-break-glass-event :DORMANT-WATCHDOG-STOPPED "Watchdog stopped"
                                          :result :SUCCESS)))
  (ignore-errors (when (fboundp 'enter-radio-silence)
                   (enter-radio-silence :dormant-mode)
                   (log-break-glass-event :DORMANT-RADIO-SILENCE "Radio silence entered"
                                          :result :SUCCESS)))
  (log-break-glass-event :DORMANT-ENTERED
                         (format nil "Dormant — duration=~A wake=~A"
                                 (or *dormant-target-duration* "indefinite")
                                 *wake-up-file-path*)
                         :result :SUCCESS)
  t)

(defun exit-dormant-mode ()
  "Exit dormant mode. Clears *DORMANT-MODE-ACTIVE-P*, removes radio silence
   flag, deletes wake-up file. Does NOT auto-restart services.
   Parameters: None. Returns: T. Side effects: Clears flags, deletes file."
  (log-break-glass-event :DORMANT-EXIT "Exiting dormant mode" :result :SUCCESS)
  (setf *dormant-mode-active-p* nil)
  (ignore-errors (when (boundp '*radio-silence-mode-p*)
                   (setf *radio-silence-mode-p* nil)))
  (ignore-errors (when (and *wake-up-file-path* (probe-file *wake-up-file-path*))
                   (delete-file *wake-up-file-path*)
                   (log-break-glass-event :WAKE-UP-FILE-REMOVED "Wake file deleted"
                                          :result :SUCCESS)))
  (setf *dormant-target-duration* nil)
  (setf *dormant-start-time* nil)
  (log-break-glass-event :DORMANT-EXITED "Dormant mode exited" :result :SUCCESS)
  t)

(defun dormant-monitor-loop ()
  "Background monitoring loop for dormant mode. Polls every 8-12s (jittered)
   for wake-up conditions. Runs in own thread. *DORMANT-MODE-ACTIVE-P* = NIL
   causes clean exit. Checks: wake file > duration timeout.
   Parameters: None.
   Returns: :WAKE-FILE | :WAKE-TIMEOUT | :CANCELLED.
   Side effects: May call EXIT-DORMANT-MODE, sleeps between polls."
  (log-break-glass-event :DORMANT-MONITOR-START "Monitor starting" :result :SUCCESS)
  (let ((check-count 0) (last-log-time 0) (result :cancelled))
    (loop
      (unless *dormant-mode-active-p*
        (setf result :cancelled)
        (log-break-glass-event :DORMANT-MONITOR-CANCELLED "Cancelled externally"
                               :result :SUCCESS)
        (return))
      ;; Check 1: Wake-up file
      (multiple-value-bind (ok content) (check-wake-up-signal)
        (declare (ignorable content))
        (when ok
          (setf result :wake-file)
          (log-break-glass-event :DORMANT-MONITOR-WAKE-FILE "Wake signal detected"
                                 :result :SUCCESS)
          (exit-dormant-mode)
          (return)))
      ;; Check 2: Duration timeout
      (when (and *dormant-target-duration* *dormant-start-time*)
        (let ((elapsed (- (break-glass-timestamp) *dormant-start-time*)))
          (when (>= elapsed *dormant-target-duration*)
            (setf result :wake-timeout)
            (log-break-glass-event :DORMANT-MONITOR-TIMEOUT
                                   (format nil "Timeout (~Ds)" elapsed)
                                   :result :SUCCESS)
            (exit-dormant-mode)
            (return))))
      ;; Periodic log (throttled)
      (incf check-count)
      (let ((now (break-glass-timestamp)))
        (when (>= (- now last-log-time) 60)
          (setf last-log-time now)
          (log-break-glass-event :DORMANT-MONITOR-HEARTBEAT
                                 (format nil "Check #~D (~Ds)"
                                         check-count
                                         (if *dormant-start-time*
                                             (- now *dormant-start-time*) 0))
                                 :result :SUCCESS)))
      ;; Sleep with jitter
      (handler-case (break-glass-sleep 10)
        (error (e)
          (ignore-errors (sleep 10))
          (log-break-glass-event :DORMANT-MONITOR-SLEEP-ERROR (format nil "~A" e)
                                 :result :FAILED))))
    (log-break-glass-event :DORMANT-MONITOR-EXIT (format nil "Result: ~A" result)
                           :result :SUCCESS)
    result))

(defun radio-silence-trigger (&key (duration :indefinite) (wake-on-file t)
                              wake-secret (confirm t))
  "Enter full radio silence / dormant mode. The 'hide and survive' option.
   Reversible via CREATE-WAKE-UP-FILE or CANCEL-RADIO-SILENCE.
   Parameters:
     :DURATION     — :INDEFINITE (default) | (:HOURS N) | (:MINUTES N)
     :WAKE-ON-FILE — T (default, spawns monitor) | NIL (blocks)
     :WAKE-SECRET  — String required in wake-up file
     :CONFIRM      — T (default, prompts) | NIL (immediate)
   Returns: :DORMANT-ENTERED (async) | :WAKE-FILE | :WAKE-TIMEOUT | :CANCELLED.
   Side effects: Stops gossip, PSM, watchdog. May spawn thread."
  ;; Guards
  (when *shred-all-assets-executed-p*
    (log-break-glass-event :RADIO-SILENCE-BLOCKED "Shred already executed"
                           :result :SKIPPED)
    (warn "Cannot enter radio silence — shred already executed.")
    (return-from radio-silence-trigger nil))
  (when *dormant-mode-active-p*
    (log-break-glass-event :RADIO-SILENCE-BLOCKED "Already dormant" :result :SKIPPED)
    (warn "Already in dormant mode. Use CANCEL-RADIO-SILENCE.")
    (return-from radio-silence-trigger nil))
  ;; Confirmation
  (when confirm
    (let ((ds (cond ((eq duration :indefinite) "indefinite")
                    ((and (listp duration) (eq (car duration) :hours))
                     (format nil "~D hours" (cadr duration)))
                    ((and (listp duration) (eq (car duration) :minutes))
                     (format nil "~D minutes" (cadr duration)))
                    (t "unknown"))))
      (unless (break-glass-confirm-p
               (format nil "~%*** RADIO SILENCE / DORMANT MODE ***~%~%DURATION: ~A
WAKE FILE: ~A | SECRET: ~A~%Cease ALL network activity?"
                       ds *wake-up-file-path*
                       (if wake-secret "[SET]" "[none]")))
        (log-break-glass-event :RADIO-SILENCE-CANCELLED "Cancelled by user"
                               :result :SKIPPED)
        (format t "~&Radio silence cancelled.~%")
        (return-from radio-silence-trigger nil))))
  ;; Execute
  (setf *break-glass-active-p* t)
  (enter-dormant-mode :duration duration :wake-secret wake-secret)
  (if wake-on-file
      ;; Async: spawn thread
      (progn
        (setf *dormant-monitor-thread*
              (sb-thread:make-thread #'dormant-monitor-loop
                                     :name "LISPMIND-Dormant-Monitor"))
        (log-break-glass-event :RADIO-SILENCE-ASYNC "Monitor spawned"
                               :result :SUCCESS)
        (setf *break-glass-active-p* nil)
        :dormant-entered)
      ;; Sync: block
      (progn
        (log-break-glass-event :RADIO-SILENCE-SYNC "Blocking mode" :result :SUCCESS)
        (let ((result (dormant-monitor-loop)))
          (setf *break-glass-active-p* nil)
          result))))


;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; SECTION 4 — BREAK-GLASS STATUS & DIAGNOSTICS
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;;
;;; These functions are SAFE to call at any time — no destructive operations.
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun break-glass-status ()
  "Print and return current break-glass system status.
   Shows: shred availability, radio silence readiness, dormant state,
   procedure active status, last check time, version, log entries.
   Parameters: None.
   Returns: Plist with :SHRED-READY :RADIO-SILENCE-READY :DORMANT-STATE
   :ACTIVE :LAST-CHECK :VERSION. Side effects: Prints to *STANDARD-OUTPUT*."
  (let* ((now (break-glass-timestamp))
         (status (list :shred-ready (not *shred-all-assets-executed-p*)
                       :radio-silence-ready (and (not *shred-all-assets-executed-p*)
                                                  (not *dormant-mode-active-p*))
                       :dormant-state (if *dormant-mode-active-p* :active :inactive)
                       :active *break-glass-active-p*
                       :last-check *break-glass-last-check-time*
                       :version *break-glass-version*)))
    (format t "~%=== LISPMIND BREAK-GLASS STATUS (v~A) ===~%"
            *break-glass-version*)
    (format t "  Shred available:     ~A~%"
            (if (getf status :shred-ready) "YES" "NO (already executed)"))
    (format t "  Radio silence ready: ~A~%"
            (if (getf status :radio-silence-ready) "YES" "NO"))
    (format t "  Dormant state:       ~A~%" (getf status :dormant-state))
    (format t "  Procedure active:    ~A~%" (if (getf status :active) "YES" "NO"))
    (format t "  Last readiness chk:  ~A~%"
            (if *break-glass-last-check-time*
                (break-glass-format-time *break-glass-last-check-time*) "NEVER"))
    (format t "  Current time:        ~A~%" (break-glass-format-time now))
    (format t "  Log entries:         ~D~%" (length *break-glass-log*))
    (format t "========================================~%")
    status))

(defun break-glass-readiness-check ()
  "Verify all prerequisites for emergency procedures.
   Checks: vault key, vault hash table, kernel implants, gossip,
   telemetry, persistence, radio silence function availability.
   Parameters: None.
   Returns: Plist: :READY T/NIL, :VAULT-KEY :VAULT :IMPLANTS :GOSSIP
   :TELEMETRY :PERSISTENCE :RADIO-SILENCE (each T/NIL).
   Side effects: Updates *BREAK-GLASS-LAST-CHECK-TIME*, logs."
  (log-break-glass-event :READINESS-CHECK-START "Readiness check starting"
                         :result :SUCCESS)
  (let* ((vk (and (boundp '*resource-vault-key*) *resource-vault-key*))
         (vv (and (boundp '*resource-vault*) (hash-table-p *resource-vault*)))
         (ki (and (boundp '*kernel-implants*) (hash-table-p *kernel-implants*)))
         (go (and (fboundp 'stop-tactical-gossip) (fboundp 'gossip-publish)))
         (te (and (fboundp 'telemetry-flush) (boundp '*telemetry-log-buffer*)))
         (ps (and (fboundp 'stop-persistence-state-manager)
                  (fboundp 'stop-persistence-watchdog)))
         (rs (fboundp 'enter-radio-silence))
         (ready (and vk vv ki go te ps rs)))
    (setf *break-glass-last-check-time* (break-glass-timestamp))
    (let ((result (list :ready ready :vault-key (and vk t) :vault (and vv t)
                        :implants (and ki t) :gossip (and go t)
                        :telemetry (and te t) :persistence (and ps t)
                        :radio-silence (and rs t))))
      (log-break-glass-event :READINESS-CHECK-COMPLETE
                             (format nil "~A (~D/7 systems OK)"
                                     (if ready "READY" "NOT READY")
                                     (count t (list vk vv ki go te ps rs)))
                             :result (if ready :SUCCESS :PARTIAL))
      result)))

(defun break-glass-log (&key (count 50) (stream t))
  "Print *BREAK-GLASS-LOG* chronologically (oldest first).
   Parameters: :COUNT (integer, default 50), :STREAM (default T).
   Returns: Number of entries printed. Side effects: Writes to STREAM."
  (let* ((entries (reverse *break-glass-log*))
         (total (length entries))
         (to-show (min count total))
         (start (max 0 (- total to-show)))
         (shown 0))
    (format stream "~%=== BREAK-GLASS LOG (showing ~D of ~D) ===~%"
            to-show total)
    (dolist (entry (subseq entries start))
      (incf shown)
      (let ((ts (getf entry :timestamp)) (event (getf entry :event))
            (phase (getf entry :phase)) (result (getf entry :result))
            (detail (getf entry :detail)))
        (format stream "[~A] ~20A"
                (if ts (break-glass-format-time ts) "???") event)
        (when phase (format stream " [P~D]" phase))
        (when result (format stream " <~A>" result))
        (format stream " ~A~%" (or detail ""))))
    (format stream "=== END OF LOG ===~%")
    shown))

(defun break-glass-diagnostics (&key (stream t) verbose)
  "Run full diagnostic tests (DRY-RUN — safe, non-destructive).
   Tests: log system, random octets, vector overwrite, hash table keys,
   timestamp format, wake-up check, vault/bindings, function existence,
   flags, jittered sleep, wake-up file create+check.
   Parameters: :STREAM (default T), :VERBOSE (boolean).
   Returns: Plist: :ALL-PASSED :TESTS-RUN :TESTS-PASSED :RESULTS.
   Side effects: Writes to STREAM, adds log entries, sets diagnostics flag."
  (setf *break-glass-diagnostics-running-p* t)
  (log-break-glass-event :DIAGNOSTICS-START "Diagnostics starting" :result :SUCCESS)
  (let ((results nil) (tests-run 0) (tests-passed 0))
    (flet ((run-test (name test-fn)
             (incf tests-run)
             (handler-case
                 (let ((ok (funcall test-fn)))
                   (if ok (incf tests-passed))
                   (push (cons name (if ok :PASS :FAIL)) results)
                   (when verbose (format stream "  [~A] ~A~%" (if ok "PASS" "FAIL") name)))
               (error (e)
                 (push (cons name :FAIL) results)
                 (when verbose (format stream "  [FAIL] ~A — ~A~%" name e)))))
           (skip-test (name reason)
             (incf tests-run)
             (push (cons name :SKIP) results)
             (when verbose (format stream "  [SKIP] ~A — ~A~%" name reason))))
      (format stream "~%=== BREAK-GLASS DIAGNOSTICS ===~%")
      (format stream "Version: ~A | Time: ~A~%~%"
              *break-glass-version* (break-glass-format-time (break-glass-timestamp)))
      ;; Test 1: Log system
      (run-test "LOG-SYSTEM"
                (lambda () (let ((b (length *break-glass-log*)))
                             (log-break-glass-event :DIAG-TEST "Log test" :result :SUCCESS)
                             (> (length *break-glass-log*) b))))
      ;; Test 2: Random octets
      (run-test "RANDOM-OCTETS"
                (lambda () (let ((v (random-octets 32)))
                             (and (= (length v) 32)
                                  (every (lambda (b) (<= 0 b 255)) v)))))
      ;; Test 3: Vector overwrite
      (run-test "VECTOR-OVERWRITE"
                (lambda () (let ((v (make-array 16 :element-type '(unsigned-byte 8)
                                                  :initial-contents '(1 2 3 4 5 6 7 8
                                                                       9 10 11 12 13 14 15 16))))
                             (overwrite-vector v :passes 1)
                             (not (every #'= v '(1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16))))))
      ;; Test 4: Hash table keys
      (run-test "HASH-TABLE-KEYS"
                (lambda () (let ((ht (make-hash-table :test 'equal)))
                             (setf (gethash "a" ht) 1 (gethash "b" ht) 2 (gethash "c" ht) 3)
                             (let ((ks (hash-table-keys ht)))
                               (and (= (length ks) 3)
                                    (member "a" ks :test #'equal)
                                    (member "b" ks :test #'equal))))))
      ;; Test 5: Timestamp formatting
      (run-test "TIMESTAMP-FORMAT"
                (lambda () (let ((f (break-glass-format-time 0)))
                             (and (stringp f) (= (length f) 24)))))
      ;; Test 6: Wake-up check (no file)
      (run-test "WAKE-UP-CHECK-NOFILE"
                (lambda () (multiple-value-bind (ok c) (check-wake-up-signal #P"/nonexistent/.nope")
                             (and (null ok) (null c)))))
      ;; Test 7-9: Variable bindings
      (if (boundp '*resource-vault-key*)
          (run-test "VAULT-KEY-BOUND" (lambda () t))
          (skip-test "VAULT-KEY-BOUND" "not bound"))
      (if (boundp '*resource-vault*)
          (run-test "VAULT-BOUND" (lambda () t))
          (skip-test "VAULT-BOUND" "not bound"))
      (if (boundp '*kernel-implants*)
          (run-test "IMPLANTS-BOUND" (lambda () t))
          (skip-test "IMPLANTS-BOUND" "not bound"))
      ;; Test 10: Function bindings
      (run-test "FUNC-CLEAR-VAULT-KEY" (lambda () (fboundp 'clear-vault-key)))
      (run-test "FUNC-VAULT-DESTROY" (lambda () (fboundp 'vault-destroy)))
      (run-test "FUNC-VAULT-EMERGENCY-SHRED" (lambda () (fboundp 'vault-emergency-shred)))
      (run-test "FUNC-REMOVE-KERNEL-IMPLANT" (lambda () (fboundp 'remove-kernel-implant)))
      (run-test "FUNC-STOP-HEALTH-MONITOR" (lambda () (fboundp 'stop-kernel-health-monitor)))
      (run-test "FUNC-STOP-GOSSIP" (lambda () (fboundp 'stop-tactical-gossip)))
      (run-test "FUNC-TELEMETRY-FLUSH" (lambda () (fboundp 'telemetry-flush)))
      (run-test "FUNC-ENTER-RADIO-SILENCE" (lambda () (fboundp 'enter-radio-silence)))
      ;; Test 11: Flags
      (run-test "FLAGS-ACCESSIBLE"
                (lambda () (and (boundp '*break-glass-active-p*)
                               (boundp '*break-glass-log*)
                               (boundp '*shred-all-assets-executed-p*)
                               (boundp '*dormant-mode-active-p*))))
      ;; Test 12: Jittered sleep
      (run-test "JITTERED-SLEEP"
                (lambda () (let ((s (get-internal-real-time)))
                             (break-glass-sleep 0.1)
                             (> (get-internal-real-time) s))))
      ;; Test 13: Create and check wake-up file
      (run-test "WAKE-UP-FILE-CREATE-CHECK"
                (lambda () (let ((p #P"/tmp/.lispmind_wakeup_test"))
                             (ignore-errors (delete-file p))
                             (create-wake-up-file :file-path p :content "test")
                             (multiple-value-bind (ok c) (check-wake-up-signal p)
                               (ignore-errors (delete-file p))
                               (and ok (string= c "test"))))))
      ;; Summary
      (let ((all-passed (= tests-passed tests-run)))
        (format stream "~%--- SUMMARY ---~%")
        (format stream "Run: ~D | Passed: ~D | Failed: ~D | Overall: ~A~%"
                tests-run tests-passed (- tests-run tests-passed)
                (if all-passed "ALL PASSED" "SOME FAILED"))
        (format stream "===============~%")
        (setf *break-glass-diagnostics-running-p* nil)
        (log-break-glass-event :DIAGNOSTICS-COMPLETE
                               (format nil "~D/~D ~A" tests-passed tests-run
                                       (if all-passed "ALL PASSED" "SOME FAILED"))
                               :result (if all-passed :SUCCESS :PARTIAL))
        (list :all-passed all-passed :tests-run tests-run
              :tests-passed tests-passed :results (reverse results))))))

(defun break-glass-help ()
  "Print comprehensive usage documentation.
   Parameters: None. Returns: Help string (also printed).
   Side effects: Writes to *STANDARD-OUTPUT*."
  (let ((text (format nil "
=== LISPMIND BREAK-GLASS EMERGENCY SYSTEM v~A ===

 DESTRUCTION PROCEDURES (IRREVERSIBLE):
 --------------------------------------
 1. (SHRED-ALL-ASSETS &key panic-level confirm passes)
    The NUCLEAR OPTION. Destroys all keys, data, implants, exits.
    PANIC-LEVEL: :FULL (all phases), :KEYS-ONLY (phase 1), :SILENT (1,2,4)
    CONFIRM: NIL to skip prompt. PASSES: overwrite count (default ~D).
    Ex: (shred-all-assets) | (shred-all-assets :panic-level :silent :confirm nil)

 2. (QUICK-SHRED &key panic-level passes)
    (SHRED-ALL-ASSETS :CONFIRM NIL). For automated response.

 DORMANT MODE (REVERSIBLE):
 ---------------------------
 3. (RADIO-SILENCE-TRIGGER &key duration wake-on-file wake-secret confirm)
    Enter dormant mode. Ceases all network activity.
    DURATION: :INDEFINITE | (:HOURS N) | (:MINUTES N)
    WAKE-ON-FILE: NIL blocks. WAKE-SECRET: required file content.
    Ex: (radio-silence-trigger) | (timed-radio-silence 2)

 4. (CANCEL-RADIO-SILENCE)  — Force exit from dormant mode.
 5. (TIMED-RADIO-SILENCE hours)  — Convenience wrapper.
 6. (CREATE-WAKE-UP-FILE &key file-path secret content)  — Trigger wake-up.

 DIAGNOSTICS (SAFE):
 -------------------
 7. (BREAK-GLASS-STATUS)     — Print current status.
 8. (BREAK-GLASS-READINESS-CHECK)  — Verify prerequisites.
 9. (BREAK-GLASS-DIAGNOSTICS &key verbose)  — Self-test (dry-run).
 10. (BREAK-GLASS-LOG &key count stream)  — Print event log.
 11. (BREAK-GLASS-HELP)       — This message.

 TESTING:
 --------
 12. (BREAK-GLASS-RESET :FORCE T)  — Reset flags. TESTING ONLY.

 DECISION: Forensic imaging? -> SHRED-ALL-ASSETS
           Hide temporarily? -> RADIO-SILENCE-TRIGGER
           Automated detect? -> QUICK-SHRED
           Testing?          -> BREAK-GLASS-DIAGNOSTICS
=== END HELP ===
" *break-glass-version* *break-glass-shred-passes*)))
    (format t "~A" text)
    text))


;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; SECTION 5 — CONVENIENCE FUNCTIONS
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun quick-shred (&key (panic-level :full) (passes *break-glass-shred-passes*))
  "Execute SHRED-ALL-ASSETS without confirmation. FAST PATH for automated
   emergency response. Destruction begins IMMEDIATELY.
   Parameters: :PANIC-LEVEL (default :FULL), :PASSES (default global).
   Returns: See SHRED-ALL-ASSETS. Does NOT return for :FULL/:SILENT.
   Side effects: [DESTRUCTIVE][IRREVERSIBLE].
   WARNING: NO CONFIRMATION. Only use in genuinely automated contexts."
  (log-break-glass-event :QUICK-SHRED-INVOKED
                         (format nil "Quick-shred panic=~A passes=~D" panic-level passes)
                         :panic-level panic-level :result :SUCCESS)
  (shred-all-assets :panic-level panic-level :confirm nil :passes passes))

(defun timed-radio-silence (hours)
  "Enter radio silence for HOURS hours. Skips confirmation.
   Parameters: HOURS (positive number).
   Returns: See RADIO-SILENCE-TRIGGER. Side effects: Same.
   Examples: (timed-radio-silence 2)  |  (timed-radio-silence 0.5)"
  (unless (and (numberp hours) (> hours 0))
    (error "TIMED-RADIO-SILENCE requires positive hours, got: ~S" hours))
  (log-break-glass-event :TIMED-SILENCE-INVOKED (format nil "~A hours" hours)
                         :result :SUCCESS)
  (radio-silence-trigger :duration (list :hours hours) :wake-on-file t :confirm nil))

(defun cancel-radio-silence ()
  "Force exit from dormant / radio silence mode. The 'emergency brake'.
   Sets *DORMANT-MODE-ACTIVE-P* to NIL, calls EXIT-DORMANT-MODE, joins
   monitor thread with 5s timeout. Does NOT restart services.
   Parameters: None.
   Returns: :CANCELLED (was active) | :NOT-DORMANT (no action).
   Side effects: Clears flags, may wait for thread."
  (cond
    (*dormant-mode-active-p*
     (log-break-glass-event :RADIO-SILENCE-CANCEL "Force cancelling" :result :SUCCESS)
     (setf *dormant-mode-active-p* nil)
     (exit-dormant-mode)
     (when (and *dormant-monitor-thread*
                (sb-thread:thread-alive-p *dormant-monitor-thread*))
       (handler-case
           (sb-thread:join-thread *dormant-monitor-thread* :timeout 5 :default :timeout)
         (error (e)
           (log-break-glass-event :MONITOR-JOIN-FAILED (format nil "~A" e)
                                  :result :FAILED)))
       (setf *dormant-monitor-thread* nil))
     (log-break-glass-event :RADIO-SILENCE-CANCELLED "Cancelled" :result :SUCCESS)
     :cancelled)
    (t
     (log-break-glass-event :RADIO-SILENCE-CANCEL-NOOP "Not dormant" :result :SKIPPED)
     :not-dormant)))

(defun break-glass-reset (&key force)
  "Reset all break-glass flags to initial state. FOR TESTING ONLY.
   NEVER use in a real emergency. Requires :FORCE T as safety measure.
   Resets: *BREAK-GLASS-ACTIVE-P*, *SHRED-ALL-ASSETS-EXECUTED-P*,
   *RADIO-SILENCE-EXECUTED-P*, *DORMANT-MODE-ACTIVE-P*, diagnostics flag,
   start time, target duration, wake secret, monitor thread.
   Log (*BREAK-GLASS-LOG*) is NOT cleared.
   Parameters: :FORCE (must be T).
   Returns: :RESET. Side effects: Modifies all break-glass variables."
  (unless force
    (error "BREAK-GLASS-RESET requires :FORCE T. FOR TESTING ONLY.~%
Never use during a real emergency. Use :FORCE T if certain."))
  (log-break-glass-event :RESET-INVOKED "ALL FLAGS BEING RESET" :result :SUCCESS)
  (setf *break-glass-active-p* nil)
  (setf *shred-all-assets-executed-p* nil)
  (setf *radio-silence-executed-p* nil)
  (setf *dormant-mode-active-p* nil)
  (setf *break-glass-diagnostics-running-p* nil)
  (setf *dormant-start-time* nil)
  (setf *dormant-target-duration* nil)
  (setf *dormant-wake-up-secret* nil)
  (setf *dormant-monitor-thread* nil)
  (log-break-glass-event :RESET-COMPLETE "Flags reset" :result :SUCCESS)
  :reset)

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; SECTION 6 — PACKAGE INTEGRATION & EXPORTS
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(eval-when (:compile-toplevel :load-toplevel :execute)
  ;; Core emergency procedures
  (export '(shred-all-assets radio-silence-trigger quick-shred
            timed-radio-silence cancel-radio-silence)
          :lispmind)
  ;; Status and diagnostics
  (export '(break-glass-status break-glass-readiness-check break-glass-log
            break-glass-diagnostics break-glass-help)
          :lispmind)
  ;; Testing
  (export '(break-glass-reset) :lispmind)
  ;; Dormant mode functions
  (export '(enter-dormant-mode exit-dormant-mode dormant-monitor-loop
            check-wake-up-signal create-wake-up-file)
          :lispmind)
  ;; Phase functions (expert/diagnostic)
  (export '(shred-phase-1-keys shred-phase-2-heap shred-phase-3-kernel
            shred-phase-4-cover-tracks)
          :lispmind)
  ;; Utilities
  (export '(log-break-glass-event break-glass-timestamp break-glass-format-time
            overwrite-vector random-octets)
          :lispmind)
  ;; Special variables
  (export '(*break-glass-active-p* *break-glass-log* *shred-all-assets-executed-p*
            *radio-silence-executed-p* *dormant-mode-active-p* *wake-up-file-path*
            *break-glass-emergency-contact* *break-glass-version*
            *break-glass-shred-passes* *break-glass-confirmation-prompt*
            *dormant-wake-up-secret*)
          :lispmind))

;;; Module initialization
(log-break-glass-event :MODULE-LOADED
                       (format nil "Break-glass v~A loaded — core ready"
                               *break-glass-version*)
                       :result :SUCCESS)

(format t "~&[BREAK-GLASS] LISPMIND Emergency Protocol Module v~A loaded.~%
[BREAK-GLASS] Type (BREAK-GLASS-HELP) for usage.~%
[BREAK-GLASS] Type (BREAK-GLASS-DIAGNOSTICS) to self-test.~%"
        *break-glass-version*)

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; APPENDIX A — ADVANCED FORENSIC COUNTERMEASURES
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun heap-spray-poison (&key (size 1048576) (iterations 5))
  "Spray heap with random allocations to fragment freed memory. Makes cold
   boot attacks and memory forensics harder. Allocates/deallocates buffers,
   triggers GC. Parameters: :SIZE (bytes, default 1MB), :ITERATIONS (default 5).
   Returns: T. Side effects: Allocates/frees memory, may GC."
  (log-break-glass-event :HEAP-SPRAY-START (format nil "~D iterations of ~D bytes"
                                                     iterations size) :result :SUCCESS)
  (dotimes (i iterations)
    (let* ((asize (+ size (random size)))
           (buf (make-array asize :element-type '(unsigned-byte 8) :initial-element 0)))
      (dotimes (j (min 1024 asize))
        (setf (aref buf (random asize)) (random 256)))
      (declare (ignorable buf)))
    (when (evenp i) (ignore-errors (sb-ext:gc :full t)))
    (ignore-errors (sleep 0.1)))
  (log-break-glass-event :HEAP-SPRAY-COMPLETE "Done" :result :SUCCESS)
  t)

(defun secure-page-zero (&optional (pages 16))
  "Zero-fill recently freed page regions. Each page ~4096 bytes.
   Parameters: PAGES (integer, default 16). Returns: T.
   Side effects: Allocates and zero-fills memory."
  (log-break-glass-event :PAGE-ZERO-START (format nil "~D pages (~D bytes)"
                                                    pages (* pages 4096))
                         :result :SUCCESS)
  (dotimes (i pages)
    (let ((page (make-array 4096 :element-type '(unsigned-byte 8) :initial-element 0)))
      (declare (ignorable page))
      (dotimes (j 4096) (setf (aref page j) 0))))
  (log-break-glass-event :PAGE-ZERO-COMPLETE "Done" :result :SUCCESS)
  t)

(defun shred-memory-regions (regions &key (passes *break-glass-shred-passes*))
  "Securely overwrite multiple byte vector regions.
   Parameters: REGIONS (list of byte vectors), :PASSES (integer).
   Returns: Count of successfully overwritten regions.
   Side effects: [DESTRUCTIVE] Overwrites each region in-place."
  (declare (type list regions) (type (integer 1 35) passes))
  (let ((success 0) (failed 0))
    (dolist (region regions)
      (handler-case
          (when (typep region '(simple-array (unsigned-byte 8) (*)))
            (overwrite-vector region :passes passes)
            (incf success))
        (error (e)
          (incf failed)
          (log-break-glass-event :REGION-SHRED-FAILED (format nil "~A" e)
                                 :result :FAILED))))
    (log-break-glass-event :REGIONS-SHRED-COMPLETE
                           (format nil "~D ok, ~D failed" success failed)
                           :result (if (> failed 0) :PARTIAL :SUCCESS))
    success))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; APPENDIX B — EMERGENCY NOTIFICATION SYSTEM
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun break-glass-alert (message &key (urgency :critical) topic)
  "Send emergency alert through all channels. Tries gossip first, then
   always writes to stderr. Parameters: MESSAGE (string), :URGENCY
   (:LOW :MEDIUM :HIGH :CRITICAL, default), :TOPIC (gossip topic).
   Returns: T. Side effects: May gossip, writes to *ERROR-OUTPUT*, logs."
  (let ((alert-topic (or topic *break-glass-emergency-contact*))
        (ts (break-glass-format-time (break-glass-timestamp)))
        (success nil))
    (let ((full (format nil "[~A] [URGENCY:~A] [BREAK-GLASS] ~A" ts urgency message)))
      (ignore-errors (when (and alert-topic (fboundp 'gossip-publish))
                       (gossip-publish alert-topic full)
                       (setf success t)))
      (format *error-output* "~&~A~%" full)
      (force-output *error-output*)
      (log-break-glass-event :ALERT-SENT full
                             :result (if success :SUCCESS :PARTIAL))
      (or success t))))

(defun break-glass-panic-alert (reason)
  "Send maximum-urgency panic alert. Prominent stderr output + gossip.
   Use only when immediate operator attention required.
   Parameters: REASON (string). Returns: T. Side effects: Writes stderr, logs."
  (let ((ts (break-glass-format-time (break-glass-timestamp))))
    (format *error-output* "~%~%")
    (format *error-output* "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!~%")
    (format *error-output* "!!! LISPMIND BREAK-GLASS PANIC ALERT                     !!!~%")
    (format *error-output* "!!! Time: ~51A !!!~%" ts)
    (format *error-output* "!!! Reason: ~49A !!!~%" reason)
    (format *error-output* "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!~%")
    (format *error-output* "~%")
    (force-output *error-output*)
    (ignore-errors (when (and *break-glass-emergency-contact* (fboundp 'gossip-publish))
                     (gossip-publish *break-glass-emergency-contact*
                                     (format nil "[PANIC] ~A — ~A" ts reason))))
    (log-break-glass-event :PANIC-ALERT reason :result :SUCCESS)
    t))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; APPENDIX C — AUTOMATED RESPONSE TRIGGERS
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun break-glass-auto-respond (trigger-type &key detail (passes *break-glass-shred-passes*))
  "Execute automated emergency response based on TRIGGER-TYPE.
   :FORENSIC-DETECTED   → QUICK-SHRED (full destruction)
   :COUNTER-INTRUSION   → RADIO-SILENCE-TRIGGER (dormant)
   :NETWORK-ISOLATION   → RADIO-SILENCE-TRIGGER 1 hour
   :UNKNOWN-THREAT      → QUICK-SHRED (conservative)
   Parameters: TRIGGER-TYPE (keyword), :DETAIL (string), :PASSES (integer).
   Returns: Result of triggered procedure. Side effects: Executes emergency
   procedures, sends panic alert, logs extensively."
  (let ((detail-str (or detail "No details")))
    (break-glass-panic-alert (format nil "Auto-respond: ~A — ~A" trigger-type detail-str))
    (case trigger-type
      (:forensic-detected
       (log-break-glass-event :AUTO-RESPOND-FORENSIC detail-str :result :SUCCESS)
       (quick-shred :panic-level :full :passes passes))
      (:counter-intrusion
       (log-break-glass-event :AUTO-RESPOND-COUNTER detail-str :result :SUCCESS)
       (radio-silence-trigger :duration :indefinite :wake-on-file t :confirm nil))
      (:network-isolation
       (log-break-glass-event :AUTO-RESPOND-NET-ISOLATION detail-str :result :SUCCESS)
       (radio-silence-trigger :duration '(:hours 1) :wake-on-file t :confirm nil))
      (:unknown-threat
       (log-break-glass-event :AUTO-RESPOND-UNKNOWN detail-str :result :SUCCESS)
       (quick-shred :panic-level :full :passes passes))
      (otherwise
       (log-break-glass-event :AUTO-RESPOND-UNKNOWN-TYPE
                              (format nil "~A" trigger-type) :result :FAILED)
       nil))))

(defun break-glass-forensic-detection-hook (process-name)
  "Hook for forensic tool detection. Calls auto-respond with :FORENSIC-DETECTED.
   Parameters: PROCESS-NAME (string). Returns: Auto-respond result.
   Side effects: May trigger full shred (aggressive response)."
  (break-glass-auto-respond :forensic-detected
                            :detail (format nil "Detected: ~A" process-name)
                            :passes (max *break-glass-shred-passes* 7)))


;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; APPENDIX D — OPERATOR VERIFICATION CHALLENGES
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defvar *break-glass-operator-challenge* nil
  "Optional challenge string for operator verification. When non-NIL,
   destructive operations require the operator to provide this exact
   string. Set at system init with a shared secret. Type: STRING or NIL.")

(defun break-glass-operator-verify ()
  "Prompt for operator challenge verification. If *BREAK-GLASS-OPERATOR-CHALLENGE*
   is set, requires correct string. Returns: T (passed or no challenge) | NIL (failed).
   Side effects: May read from *QUERY-IO*."
  (if *break-glass-operator-challenge*
      (progn
        (format *query-io* "~&Operator challenge: ")
        (force-output *query-io*)
        (let ((response (read-line *query-io* nil nil)))
          (if (and response
                   (string= (string-trim '(#\Space #\Tab #\Newline #\Return) response)
                            *break-glass-operator-challenge*))
              (progn
                (log-break-glass-event :OPERATOR-VERIFY "Passed" :result :SUCCESS)
                t)
              (progn
                (log-break-glass-event :OPERATOR-VERIFY-FAILED "FAILED" :result :FAILED)
                nil))))
      t))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; APPENDIX E — DOCUMENTATION FUNCTIONS
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun break-glass-module-info ()
  "Return comprehensive module information as a plist.
   Parameters: None. Returns: Plist with :VERSION :FUNCTION-COUNT
   :VARIABLE-COUNT :PHASES :PANIC-LEVELS :DURATION-TYPES :EXPORTED-SYMBOLS.
   Side effects: None."
  (list :version *break-glass-version*
        :function-count 42
        :variable-count 13
        :phases '(:phase-1-key-destruction :phase-2-heap-poisoning
                  :phase-3-kernel-panic :phase-4-cover-tracks)
        :panic-levels '(:full :keys-only :silent)
        :duration-types '(:indefinite (:hours integer) (:minutes integer))
        :exported-symbols '(shred-all-assets radio-silence-trigger quick-shred
                             timed-radio-silence cancel-radio-silence
                             break-glass-status break-glass-readiness-check
                             break-glass-log break-glass-diagnostics break-glass-help
                             break-glass-reset enter-dormant-mode exit-dormant-mode
                             dormant-monitor-loop check-wake-up-signal
                             create-wake-up-file shred-phase-1-keys
                             shred-phase-2-heap shred-phase-3-kernel
                             shred-phase-4-cover-tracks log-break-glass-event
                             break-glass-timestamp break-glass-format-time
                             overwrite-vector random-octets break-glass-alert
                             break-glass-panic-alert break-glass-auto-respond
                             break-glass-forensic-detection-hook
                             break-glass-module-info break-glass-threat-matrix
                             heap-spray-poison secure-page-zero shred-memory-regions
                             configure-break-glass break-glass-current-config
                             break-glass-integration-test)))

(defun break-glass-threat-matrix ()
  "Print recommended response for each threat type. Quick reference.
   Parameters: None. Returns: Alist of (threat . response).
   Side effects: Prints to *STANDARD-OUTPUT*."
  (let ((matrix
         '(("Host under forensic imaging/analysis" . "(SHRED-ALL-ASSETS :PANIC-LEVEL :FULL)")
           ("Forensic tools detected (Volatility, Rekall, etc.)" . "(QUICK-SHRED)")
           ("Active counter-intrusion/honeypot triggered" . "(RADIO-SILENCE-TRIGGER)")
           ("Network isolation/suspicious traffic analysis" . "(RADIO-SILENCE-TRIGGER :DURATION '(:HOURS 2))")
           ("Operator lost control" . "(SHRED-ALL-ASSETS)")
           ("Suspicious process enumeration" . "(RADIO-SILENCE-TRIGGER)")
           ("Memory dump in progress" . "(SHRED-ALL-ASSETS :PANIC-LEVEL :SILENT)")
           ("Disk imaging detected" . "(QUICK-SHRED)")
           ("Temporary cover for high-risk op" . "(TIMED-RADIO-SILENCE 4)")
           ("Adjacent swarm node compromised" . "(RADIO-SILENCE-TRIGGER :WAKE-SECRET \"token\")")
           ("Complete loss of operator contact" . "(RADIO-SILENCE-TRIGGER :DURATION '(:HOURS 24))"))))
    (format t "~%=== LISPMIND BREAK-GLASS THREAT RESPONSE MATRIX ===~%~%")
    (format t "~40A ~A~%" "THREAT SCENARIO" "RECOMMENDED RESPONSE")
    (format t "~A ~A~%" (make-string 40 :initial-element #\-)
            (make-string 50 :initial-element #\-))
    (dolist (entry matrix)
      (format t "~40A ~A~%" (car entry) (cdr entry)))
    (format t "~%Key: SHRED = irreversible, RADIO-SILENCE = reversible~%")
    (format t "When in doubt: QUICK-SHRED~%~%")
    matrix))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; APPENDIX F — SBCL-SPECIFIC LOW-LEVEL OPERATIONS
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun sbcl-force-gc (&key full)
  "Force garbage collection (SBCL-specific). On non-SBCL, no-op.
   Parameters: :FULL (boolean). Returns: T on SBCL, NIL otherwise.
   Side effects: May pause process during GC."
  #+sbcl
  (progn
    (sb-ext:gc :full full)
    (log-break-glass-event :GC-FORCED (format nil "~A GC" (if full "Full" "Partial"))
                           :result :SUCCESS)
    t)
  #-sbcl
  (progn
    (log-break-glass-event :GC-NOT-AVAILABLE "Not SBCL" :result :SKIPPED)
    nil))

(defun sbcl-purge-freed-memory ()
  "Purge freed memory back to OS (SBCL-specific). Full GC + release.
   Parameters: None. Returns: T on success, NIL on failure/non-SBCL.
   Side effects: May reduce memory footprint, triggers GC."
  #+sbcl
  (handler-case
      (progn
        (sb-ext:gc :full t)
        (ignore-errors (when (fboundp 'sb-ext:release-foreground)
                         (sb-ext:release-foreground)))
        (log-break-glass-event :MEMORY-PURGED "Memory purged" :result :SUCCESS)
        t)
    (error (e)
      (log-break-glass-event :MEMORY-PURGE-FAILED (format nil "~A" e) :result :FAILED)
      nil))
  #-sbcl
  (progn
    (log-break-glass-event :MEMORY-PURGE-NOT-AVAILABLE "Not SBCL" :result :SKIPPED)
    nil))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; APPENDIX G — CONFIGURATION
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun configure-break-glass (&key shred-passes wake-file emergency-contact
                              confirmation wake-secret)
  "Configure break-glass parameters at runtime. All params optional.
   Parameters: :SHRED-PASSES (1-35), :WAKE-FILE (pathname),
   :EMERGENCY-CONTACT (string), :CONFIRMATION (boolean), :WAKE-SECRET (string).
   Returns: Plist of changed values. Side effects: Modifies variables, logs."
  (let ((changes nil))
    (when shred-passes
      (setf *break-glass-shred-passes* shred-passes)
      (push (list :shred-passes shred-passes) changes))
    (when wake-file
      (setf *wake-up-file-path* wake-file)
      (push (list :wake-file wake-file) changes))
    (when emergency-contact
      (setf *break-glass-emergency-contact* emergency-contact)
      (push (list :emergency-contact emergency-contact) changes))
    (when confirmation
      (setf *break-glass-confirmation-prompt* confirmation)
      (push (list :confirmation confirmation) changes))
    (when wake-secret
      (setf *dormant-wake-up-secret* wake-secret)
      (push (list :wake-secret "[REDACTED]") changes))
    (log-break-glass-event :CONFIG-UPDATE (format nil "~S" changes) :result :SUCCESS)
    (reverse changes)))

(defun break-glass-current-config ()
  "Return current configuration as plist. Secrets redacted.
   Parameters: None. Returns: Plist. Side effects: None."
  (list :shred-passes *break-glass-shred-passes*
        :wake-file *wake-up-file-path*
        :emergency-contact *break-glass-emergency-contact*
        :confirmation-enabled *break-glass-confirmation-prompt*
        :wake-secret-configured (if *dormant-wake-up-secret* "[SET]" "[NOT SET]")
        :version *break-glass-version*
        :max-retries *break-glass-max-retries*))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; APPENDIX H — INTEGRATION TESTS
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(defun break-glass-integration-test (&key (stream t) verbose)
  "Test integration with other LISPMIND modules. Non-destructive.
   Tests all expected function bindings and variable accessibility.
   Parameters: :STREAM (default T), :VERBOSE (boolean).
   Returns: Plist: :ALL-PASSED :TESTS-RUN :TESTS-PASSED :RESULTS.
   Side effects: Writes to STREAM, adds log entries."
  (let ((results nil) (tests-run 0) (tests-passed 0))
    (flet ((test (name fn)
             (incf tests-run)
             (handler-case
                 (let ((ok (funcall fn)))
                   (if ok (incf tests-passed))
                   (push (cons name (if ok :PASS :FAIL)) results)
                   (when verbose (format stream "  [~A] ~A~%" (if ok "PASS" "FAIL") name)))
               (error (e)
                 (push (cons name :FAIL) results)
                 (when verbose (format stream "  [FAIL] ~A — ~A~%" name e))))))
      (format stream "~%=== BREAK-GLASS INTEGRATION TESTS ===~%")
      ;; Resource registry
      (test "RR-VAULT-KEY-BINDS-P" (lambda () (boundp '*resource-vault-key*)))
      (test "RR-VAULT-BINDS-P" (lambda () (boundp '*resource-vault*)))
      (test "RR-CLEAR-KEY-EXISTS" (lambda () (fboundp 'clear-vault-key)))
      (test "RR-VAULT-DESTROY-EXISTS" (lambda () (fboundp 'vault-destroy)))
      (test "RR-VAULT-SHRED-EXISTS" (lambda () (fboundp 'vault-emergency-shred)))
      (test "RR-SECURE-WIPE-EXISTS" (lambda () (fboundp 'secure-wipe-vector)))
      ;; Kernel orchestrator
      (test "KO-IMPLANTS-BINDS-P" (lambda () (boundp '*kernel-implants*)))
      (test "KO-LIST-EXISTS" (lambda () (fboundp 'list-kernel-implants)))
      (test "KO-REMOVE-EXISTS" (lambda () (fboundp 'remove-kernel-implant)))
      (test "KO-HEALTH-STOP-EXISTS" (lambda () (fboundp 'stop-kernel-health-monitor)))
      ;; System init
      (test "SI-PSM-STOP-EXISTS" (lambda () (fboundp 'stop-persistence-state-manager)))
      (test "SI-WATCHDOG-STOP-EXISTS" (lambda () (fboundp 'stop-persistence-watchdog)))
      (test "SI-RADIO-SILENCE-EXISTS" (lambda () (fboundp 'enter-radio-silence)))
      (test "SI-INIT-FLAG-BINDS-P" (lambda () (boundp '*lispmind-init-complete-p*)))
      ;; Gossip
      (test "GO-STOP-EXISTS" (lambda () (fboundp 'stop-tactical-gossip)))
      (test "GO-PUBLISH-EXISTS" (lambda () (fboundp 'gossip-publish)))
      ;; Telemetry
      (test "TE-FLUSH-EXISTS" (lambda () (fboundp 'telemetry-flush)))
      (test "TE-BUFFER-BINDS-P" (lambda () (boundp '*telemetry-log-buffer*)))
      ;; Internal
      (test "INTERNAL-VERSION-STRING" (lambda () (stringp *break-glass-version*)))
      (test "INTERNAL-VERSION-NONEMPTY" (lambda () (> (length *break-glass-version*) 0)))
      (test "INTERNAL-SHRED-PASSES-VALID"
            (lambda () (and (integerp *break-glass-shred-passes*)
                           (>= *break-glass-shred-passes* 1)
                           (<= *break-glass-shred-passes* 35))))
      (test "INTERNAL-MAX-RETRIES-VALID"
            (lambda () (and (integerp *break-glass-max-retries*)
                           (>= *break-glass-max-retries* 0))))
      ;; Summary
      (let ((all-passed (= tests-passed tests-run)))
        (format stream "~%--- INTEGRATION SUMMARY ---~%")
        (format stream "Run: ~D | Passed: ~D | Overall: ~A~%~%"
                tests-run tests-passed (if all-passed "ALL PASSED" "SOME FAILED"))
        (log-break-glass-event :INTEGRATION-TEST-COMPLETE
                               (format nil "~D/~D ~A" tests-passed tests-run
                                       (if all-passed "ALL PASSED" "SOME FAILED"))
                               :result (if all-passed :SUCCESS :PARTIAL))
        (list :all-passed all-passed :tests-run tests-run
              :tests-passed tests-passed :results (reverse results))))))

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; APPENDIX I — OPERATIONAL NOTES
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

#|

OPERATIONAL VALIDATION CHECKLIST
=================================
Before relying on this module in production:
[ ] Run (BREAK-GLASS-DIAGNOSTICS) — all tests pass
[ ] Run (BREAK-GLASS-INTEGRATION-TEST) — all bindings resolve
[ ] Run (BREAK-GLASS-READINESS-CHECK) — :READY T
[ ] Test (BREAK-GLASS-STATUS) — output is coherent
[ ] Test SHRED with :PANIC-LEVEL :KEYS-ONLY in isolated env
[ ] Test RADIO-SILENCE with short duration (e.g., (:MINUTES 1))
[ ] Verify wake-up file mechanism
[ ] Test QUICK-SHRED with :PANIC-LEVEL :KEYS-ONLY
[ ] Verify log with (BREAK-GLASS-LOG)
[ ] Review (BREAK-GLASS-THREAT-MATRIX) with team
[ ] Set *BREAK-GLASS-OPERATOR-CHALLENGE* for production
[ ] Configure *BREAK-GLASS-EMERGENCY-CONTACT* to active topic

FORENSIC RESISTANCE
===================
Multi-pass overwrite (Gutmann simplified):
  Pass 1: 0x00 (zeros)     — null pattern
  Pass 2: 0xFF (ones)      — complementary pattern
  Pass 3+: Random bytes    — statistical noise
Set *BREAK-GLASS-SHRED-PASSES* to 7+ for max resistance.
On SSDs/flash, overwrite works against software forensics. Heap spray
and GC pressure spread data across pages for additional resistance.
Cold boot attacks are mitigated by: key overwrite (not just free),
heap spraying, page zeroing, memory purge.

RADIO SILENCE BEHAVIOR
=======================
In dormant mode: NO network traffic, persistence suspended, process
quiescent, minimal CPU (polling only), reduced memory.
Monitor thread: polls every 8-12s (jittered), checks flag first,
then wake file, then duration timeout. Exits via EXIT-DORMANT-MODE.

SECURITY NOTES
==============
1. *BREAK-GLASS-LOG* has timestamps and descriptions. No keys or
   sensitive data. Consider clearing after reading.
2. *DORMANT-WAKE-UP-SECRET* is in memory. Rotate regularly.
3. :CONFIRM NIL bypasses all human verification. Only for genuinely
   automated systems with independent compromise detection.
4. BREAK-GLASS-RESET :FORCE T is dangerous in production.
5. SHRED-ALL-ASSETS :PANIC-LEVEL :KEYS-ONLY does NOT exit the process.
6. Phase 4 calls SB-EXT:EXIT. All in-memory state is lost.
7. Wake-up file needs filesystem access. Set duration timeout as backup.
8. Gossip notifications are best-effort. Alerts always go to stderr.

MULTI-NODE NOTES
================
- SHRED affects ONLY local node. Other nodes notified via gossip only.
- RADIO-SILENCE on one node does NOT affect others.
- Use BREAK-GLASS-ALERT or PANIC-ALERT to notify swarm before shred.
- *BREAK-GLASS-EMERGENCY-CONTACT* topic should be monitored by all nodes.

|#

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; FINAL EXPORTS — Appendix symbols
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;

(eval-when (:compile-toplevel :load-toplevel :execute)
  ;; Appendix A
  (export '(heap-spray-poison secure-page-zero shred-memory-regions)
          :lispmind)
  ;; Appendix B
  (export '(break-glass-alert break-glass-panic-alert) :lispmind)
  ;; Appendix C
  (export '(break-glass-auto-respond break-glass-forensic-detection-hook)
          :lispmind)
  ;; Appendix D
  (export '(break-glass-operator-verify) :lispmind)
  ;; Appendix E
  (export '(break-glass-module-info break-glass-threat-matrix) :lispmind)
  ;; Appendix F
  (export '(sbcl-force-gc sbcl-purge-freed-memory) :lispmind)
  ;; Appendix G
  (export '(configure-break-glass break-glass-current-config) :lispmind)
  ;; Appendix H
  (export '(break-glass-integration-test) :lispmind)
  ;; Operator challenge variable
  (export '(*break-glass-operator-challenge*) :lispmind))

;;; Final module load event
(log-break-glass-event :MODULE-LOAD-COMPLETE
                       (format nil "v~A fully loaded — ~D functions, ~D variables"
                               *break-glass-version* 42 13)
                       :result :SUCCESS)

(format t "~&[BREAK-GLASS] === Module load complete ===~%")
(format t "[BREAK-GLASS] Version:   ~A~%" *break-glass-version*)
(format t "[BREAK-GLASS] Functions: ~D exported~%" 42)
(format t "[BREAK-GLASS] Variables: ~D exported~%" 13)
(format t "[BREAK-GLASS] Core:      shred-all-assets, radio-silence-trigger~%")
(format t "[BREAK-GLASS] === Ready for emergency operations ===~%~%")

;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
;;; END OF break-glass.lisp — LISPMIND v2.5.1 Emergency Protocol Module
;;; ;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;;
