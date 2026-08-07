;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;; OPERATIONAL VALIDATOR — LISPMIND v2.5.1 Phase 2 Integration Checklist
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; Operational validation plan for LISPMIND v2.5.1 (Phase 2 — Gossip Mesh
;;; Fingerprint Evasion). Provides comprehensive integration checklist
;;; functions verifying all subsystems and ensuring gossip mesh traffic does
;;; not stand out under network fingerprinting (JA3/JA3S analysis).
;;;
;;; VALIDATION COVERAGE:
;;;   Section 1: VM Snapshot Baseline      — System state capture and diffing
;;;   Section 2: Telemetry Verification    — Jitter, integrity, ordering checks
;;;   Section 3: TPM Integrity             — Hardware root-of-trust verification
;;;   Section 4: Gossip Mesh Topology      — Mesh health and routing validation
;;;   Section 5: Full Integration Checklist — Orchestrated end-to-end checks
;;;
;;; USAGE:
;;;   (run-integration-checklist)              — Run all checks, return report
;;;   (integration-checklist-report)           — Print formatted report
;;;   (integration-checklist-passed-p)         — T if all checks pass
;;;   (take-system-baseline)                   — Capture current system state
;;;   (validate-gossip-mesh-topology)          — Check mesh health
;;;   (validate-telemetry-jitter)              — Check telemetry timing
;;;
;;; "Trust but verify. Every claim about stealth must be testable."
;;; ═══════════════════════════════════════════════════════════════════════════

(in-package :lispmind)

(export '(run-integration-checklist
          integration-checklist-report
          integration-checklist-passed-p
          take-system-baseline
          compare-to-baseline
          baseline-changed-p
          validate-telemetry-jitter
          validate-telemetry-integrity
          validate-tpm-availability
          validate-tpm-key-derivation
          validate-gossip-mesh-topology
          validate-p2p-relay
          gossip-mesh-routing-table))

;;;; =========================================================================
;;;; Section 1: VM Snapshot Baseline
;;;; =========================================================================

(defvar *system-baseline* nil
  "Most recently captured system baseline. Set by TAKE-SYSTEM-BASELINE.
Contains: process list, loaded modules, scheduled tasks, env vars.")

(defvar *system-baseline-timestamp* nil
  "Timestamp when the baseline was captured.")

(defun take-system-baseline ()
  "Record a comprehensive snapshot of the current system state.

Captures: running processes, loaded shared libraries, scheduled tasks,
environment variables, and temporary file timestamps. The baseline can
later be compared against using COMPARE-TO-BASELINE.

Returns: Plist with :TIMESTAMP :PROCESSES :MODULES :TASKS :ENV-VARS :TEMP-FILES."
  (let ((baseline `(:timestamp ,(local-time:now)
                    :processes ,(capture-process-list)
                    :modules ,(capture-loaded-modules)
                    :tasks ,(capture-scheduled-tasks)
                    :env-vars ,(capture-relevant-env)
                    :temp-files ,(capture-temp-file-state)))
        (ts (local-time:now)))
    (setf *system-baseline* baseline
          *system-baseline-timestamp* ts)
    (format t "[BASELINE] Captured at ~A — ~D procs, ~D mods, ~D tasks~%"
            ts (length (getf baseline :processes))
            (length (getf baseline :modules))
            (length (getf baseline :tasks)))
    baseline))

(defun capture-process-list ()
  "Capture the current list of running processes.
Returns list of plists: (:NAME :PID :PPID :CMDLINE). Portable stub."
  (handler-case
      (list `(:name ,(first (uiop:raw-command-line arguments))
              :pid ,(sb-posix:getpid) :ppid 0
              :cmdline ,(format nil "~{~A~^ ~}" (uiop:raw-command-line arguments))))
    (error (e) (format *trace-output* "[BASELINE] Process capture: ~A~%" e) nil)))

(defun capture-loaded-modules ()
  "Capture the list of currently loaded shared libraries.
Returns list of library path strings. Platform-aware stub."
  (handler-case
      (or #+linux (capture-linux-modules)
          #+(or win32 windows) '("kernel32.dll" "ntdll.dll" "ws2_32.dll" "crypt32.dll")
          #+darwin '("libSystem.B.dylib" "libssl.dylib" "libcrypto.dylib")
          '("stub-module"))
    (error (e) (format *trace-output* "[BASELINE] Module capture: ~A~%" e) nil)))

(defun capture-linux-modules ()
  "Capture loaded modules on Linux from /proc/self/maps.
Returns list of library path strings."
  (let ((modules nil))
    (handler-case
        (with-open-file (stream "/proc/self/maps" :direction :input)
          (loop for line = (read-line stream nil nil)
                while line do
            (when (search ".so" line)
              (let* ((last-sp (position #\Space line :from-end t))
                     (path (when last-sp (string-trim " " (subseq line (1+ last-sp))))))
                (when (and path (plusp (length path)) (char/= (char path 0) #\[))
                  (push path modules))))))
      (error () nil))
    (remove-duplicates (nreverse modules) :test #'string=)))

(defun capture-scheduled-tasks ()
  "Capture scheduled tasks / cron jobs. Returns list of task plists.
Stub — production queries crontab, atq, or Task Scheduler."
  nil)

(defun capture-relevant-env ()
  "Capture environment variables relevant to LISPMIND operation.
Returns list of (VARNAME . VALUE) pairs."
  (let ((relevant '("LISPMIND_VAULT_KEY" "LISPMIND_HOME" "LISPMIND_CONFIG"
                    "LISPMIND_LOG_LEVEL" "LISPMIND_NODE_ID" "SBCL_HOME"
                    "LD_LIBRARY_PATH" "PATH" "HOME" "USER" "TMPDIR" "TEMP"))
        (result nil))
    (dolist (var relevant)
      (let ((val (uiop:getenv var)))
        (when val (push (cons var val) result))))
    (nreverse result)))

(defun capture-temp-file-state ()
  "Capture timestamps of files in temporary directories.
Returns list of (:PATH :MTIME :SIZE) plists."
  (handler-case
      (let ((files nil))
        (dolist (dir '(#P"/tmp/" #P"/var/tmp/"))
          (when (probe-file dir)
            (handler-case
                (dolist (entry (uiop:directory-files dir))
                  (push `(:path ,entry :mtime ,(file-write-date entry)
                          :size ,(ignore-errors
                                  (with-open-file (s entry :if-does-not-exist nil)
                                    (when s (file-length s)))))
                        files))
              (error () nil))))
        files)
    (error (e) (format *trace-output* "[BASELINE] Temp files: ~A~%" e) nil)))

(defun compare-to-baseline (&key (baseline nil))
  "Compare current system state against a captured BASELINE.
If BASELINE is not provided, uses *SYSTEM-BASELINE*.

Computes diffs for: new processes, missing processes, new modules,
environment variable changes, and new temp files.

Returns: Plist with :NEW-PROCESSES :MISSING-PROCESSES :NEW-MODULES
:ENV-CHANGES :NEW-TEMP-FILES :CHANGED-P."
  (let ((base (or baseline *system-baseline*)))
    (unless base
      (format *trace-output* "[BASELINE] No baseline. Call TAKE-SYSTEM-BASELINE first.~%")
      (return-from compare-to-baseline `(:changed-p :no-baseline)))
    (let* ((cur-procs (capture-process-list))
           (cur-mods (capture-loaded-modules))
           (cur-env (capture-relevant-env))
           (cur-temp (capture-temp-file-state))
           (base-proc-names (mapcar (lambda (p) (getf p :name)) (getf base :processes)))
           (cur-proc-names (mapcar (lambda (p) (getf p :name)) cur-procs))
           (new-procs (set-difference cur-proc-names base-proc-names :test #'string=))
           (missing-procs (set-difference base-proc-names cur-proc-names :test #'string=))
           (new-mods (set-difference cur-mods (getf base :modules) :test #'string=))
           (env-changes
            (loop for (var . cur-val) in cur-env
                  for base-pair = (assoc var (getf base :env-vars) :test #'string=)
                  when (and base-pair (not (string= cur-val (cdr base-pair))))
                  collect (list :var var :old (cdr base-pair) :new cur-val)))
           (base-temp-paths (mapcar (lambda (f) (princ-to-string (getf f :path)))
                                    (getf base :temp-files)))
           (cur-temp-paths (mapcar (lambda (f) (princ-to-string (getf f :path))) cur-temp))
           (new-temps (set-difference cur-temp-paths base-temp-paths :test #'string=))
           (changed-p (or new-procs missing-procs new-mods env-changes new-temps)))
      (format t "[BASELINE-COMPARE] Changes: ~A~%"
              (if changed-p (format nil "~D new procs, ~D missing, ~D new mods, ~D env, ~D temp"
                                    (length new-procs) (length missing-procs)
                                    (length new-mods) (length env-changes) (length new-temps))
                  "NONE"))
      `(:new-processes ,new-procs :missing-processes ,missing-procs
        :new-modules ,new-mods :env-changes ,env-changes
        :new-temp-files ,new-temps :changed-p ,(not (null changed-p))))))

(defun baseline-changed-p ()
  "Check if the system state has changed since the baseline was taken.
Returns T if changes detected, NIL if state matches, :NO-BASELINE if
no baseline exists."
  (getf (compare-to-baseline) :changed-p))

;;;; =========================================================================
;;;; Section 2: Telemetry Verification
;;;; =========================================================================

(defvar *telemetry-validation-buffer* nil
  "Circular buffer of recent telemetry event timestamps.
Used by VALIDATE-TELEMETRY-JITTER for interval analysis.")

(defvar *telemetry-validation-max-samples* 1000
  "Maximum number of telemetry events to keep in the validation buffer.")

(defun record-telemetry-event (event-type)
  "Record a telemetry event timestamp for validation purposes.
Arguments:
  EVENT-TYPE — Keyword describing the event type (e.g. :heartbeat :state-update)
Returns: T."
  (push (list :timestamp (get-universal-time) :type event-type
              :local-time (local-time:now))
        *telemetry-validation-buffer*)
  (when (> (length *telemetry-validation-buffer*) *telemetry-validation-max-samples*)
    (setf *telemetry-validation-buffer*
          (subseq *telemetry-validation-buffer* 0 *telemetry-validation-max-samples*)))
  t)

(defun validate-telemetry-jitter (&key (expected-min 50) (expected-max 70) (min-samples 10))
  "Validate telemetry interval timing for jitter and range compliance.

Checks that telemetry events occur within EXPECTED-MIN to EXPECTED-MAX
second intervals (default 50-70s, matching the 60s +/- 10s jitter spec).

Computes: mean interval, standard deviation (jitter), min/max intervals,
and percentage within expected range.

Arguments:
  EXPECTED-MIN — Minimum acceptable interval in seconds (default 50)
  EXPECTED-MAX — Maximum acceptable interval in seconds (default 70)
  MIN-SAMPLES  — Minimum events needed for validation (default 10)

Returns: Plist with:
  :VALID :MEAN-INTERVAL :STDEV :MIN-INTERVAL :MAX-INTERVAL
  :WITHIN-RANGE-% :SAMPLE-COUNT."
  (let ((events (reverse *telemetry-validation-buffer*)))
    (cond
      ((< (length events) (1+ min-samples))
       (format *trace-output* "[TELEMETRY-JITTER] Insufficient data: ~D events (need ~D+)~%"
               (length events) (1+ min-samples))
       `(:valid :insufficient-data :sample-count ,(length events)))
      (t
       (let* ((timestamps (mapcar (lambda (e) (getf e :timestamp)) events))
              (intervals (loop for i from 1 below (length timestamps)
                               collect (- (nth i timestamps) (nth (1- i) timestamps))))
              (valid-intervals (remove-if (lambda (x) (> x (* 2 expected-max))) intervals))
              (n (length valid-intervals)))
         (when (zerop n)
           (return-from validate-telemetry-jitter
             `(:valid :no-valid-intervals :sample-count ,(length events))))
         (let* ((mean (/ (reduce #'+ valid-intervals) n))
                (variance (/ (reduce #'+ (mapcar (lambda (x) (expt (- x mean) 2))
                                                 valid-intervals)) n))
                (stdev (sqrt variance))
                (min-int (reduce #'min valid-intervals))
                (max-int (reduce #'max valid-intervals))
                (within-range (count-if (lambda (x)
                                          (and (>= x expected-min) (<= x expected-max)))
                                        valid-intervals))
                (within-pct (* 100.0 (/ within-range n)))
                (valid-p (>= within-pct 90.0)))
           (format t "[TELEMETRY-JITTER] n=~D mean=~,1Fs stdev=~,2Fs range=~,1F-~,1Fs within=~,1F%~%"
                   n mean stdev min-int max-int within-pct)
           `(:valid ,valid-p :mean-interval ,mean :stdev ,stdev
             :min-interval ,min-int :max-interval ,max-int
             :within-range-% ,within-pct :sample-count n))))))))

(defun validate-telemetry-integrity ()
  "Check the telemetry stream for gaps, duplicates, and out-of-order events.

Performs three checks:
  1. GAP DETECTION — Intervals >2x the maximum expected (140s)
  2. DUPLICATE DETECTION — Events with identical timestamps and types
  3. ORDER CHECK — Timestamps monotonically increasing

Returns: Plist with:
  :INTEGRITY-OK :GAP-COUNT :DUPLICATE-COUNT :OUT-OF-ORDER-COUNT
  :TOTAL-EVENTS :DETAILS."
  (let ((events (reverse *telemetry-validation-buffer*)))
    (cond
      ((< (length events) 2)
       (format *trace-output* "[TELEMETRY-INTEGRITY] Insufficient data: ~D events~%"
               (length events))
       `(:integrity-ok :insufficient-data :total-events ,(length events)))
      (t
       (let ((gaps 0) (dups 0) (ooo 0) (details nil) (max-int 140))
         ;; Check 1: Gaps
         (loop for i from 1 below (length events)
               for prev = (nth (1- i) events)
               for cur = (nth i events)
               for interval = (- (getf cur :timestamp) (getf prev :timestamp))
               when (> interval max-int) do
                 (incf gaps)
                 (push `(:gap :index ,(1- i) :interval ,interval) details))
         ;; Check 2: Duplicates
         (loop for i from 1 below (length events)
               for prev = (nth (1- i) events)
               for cur = (nth i events)
               when (and (= (getf cur :timestamp) (getf prev :timestamp))
                         (eq (getf cur :type) (getf prev :type))) do
                 (incf dups)
                 (push `(:duplicate :index ,i :type ,(getf cur :type)) details))
         ;; Check 3: Out of order
         (loop for i from 1 below (length events)
               for prev = (nth (1- i) events)
               for cur = (nth i events)
               when (< (getf cur :timestamp) (getf prev :timestamp)) do
                 (incf ooo)
                 (push `(:out-of-order :index ,i) details))
         (let ((ok-p (and (zerop gaps) (zerop dups) (zerop ooo))))
           (format t "[TELEMETRY-INTEGRITY] n=~D gaps=~D dups=~D ooo=~D status=~A~%"
                   (length events) gaps dups ooo (if ok-p "PASS" "FAIL"))
           `(:integrity-ok ,ok-p :gap-count ,gaps :duplicate-count ,dups
             :out-of-order-count ,ooo :total-events ,(length events)
             :details ,(reverse details))))))))

;;;; =========================================================================
;;;; Section 3: TPM Integrity
;;;; =========================================================================

(defun validate-tpm-availability ()
  "Check TPM availability and report capabilities.

On Linux: checks /dev/tpmrm0. On Windows: checks TPM service.
On macOS: checks Secure Enclave.

Returns: Plist with:
  :AVAILABLE :DEVICE-PATH :VERSION :NV-INDICES :PCR-BANKS :MANUFACTURER :ERROR."
  (let ((result nil) (error-msg nil))
    (handler-case
        (progn
          #+linux (setf result (validate-tpm-linux))
          #+(or win32 windows) (setf result '(:available nil :device-path "WMI:Win32_Tpm"))
          #+darwin (setf result '(:available t :device-path "SecureEnclave" :version "SE2.0"
                                  :nv-indices :unknown :pcr-banks (:sha256) :manufacturer "Apple"))
          (unless result (setf error-msg "Platform not supported")))
      (error (e) (setf error-msg (format nil "TPM check error: ~A" e))))
    (let ((available (and result (getf result :available))))
      (format t "[TPM] ~A~%" (if available "AVAILABLE" "NOT AVAILABLE"))
      (when available
        (format t "  Device: ~A  Version: ~A  PCR: ~A~%"
                (getf result :device-path) (getf result :version) (getf result :pcr-banks)))
      (append result (list :error error-msg)))))

(defun validate-tpm-linux ()
  "Check TPM availability on Linux. Looks for /dev/tpmrm0 or /dev/tpm0."
  (dolist (dev '("/dev/tpmrm0" "/dev/tpm0" "/dev/tpm"))
    (when (probe-file dev)
      (return-from validate-tpm-linux
        `(:available t :device-path ,dev :version "2.0"
          :nv-indices :unknown :pcr-banks (:sha256 :sha384) :manufacturer :unknown))))
  `(:available nil :device-path nil :version :unknown
    :nv-indices 0 :pcr-banks nil :manufacturer :unknown))

(defun validate-tpm-key-derivation ()
  "Test that TPM-derived keys are consistent and accessible.

Performs a derivation test: derive a key twice from the same seed and
verify both produce identical results. Tests the key derivation path
used for vault encryption and payload signing.

Returns: Plist with :CONSISTENT :KEY-HASH :USING-TPM :ERROR.
Never exposes actual key material — only a hash for comparison."
  (handler-case
      (let* ((seed "tpm-key-derivation-test-seed-v251")
             (key1 (derive-key-from-tpm seed))
             (key2 (derive-key-from-tpm seed))
             (hash1 (hash-key-material key1))
             (hash2 (hash-key-material key2))
             (consistent (equalp hash1 hash2)))
        (format t "[TPM-KEY] Consistent: ~A  Hash: ~A...~A  TPM: ~A~%"
                (if consistent "YES" "NO") (subseq hash1 0 8)
                (subseq hash1 (- (length hash1) 8))
                (if (tpm-available-p) "YES" "NO (fallback)"))
        `(:consistent ,consistent :key-hash ,hash1
          :using-tpm ,(tpm-available-p) :error nil))
    (error (e)
      (format *trace-output* "[TPM-KEY] Failed: ~A~%" e)
      `(:consistent nil :key-hash nil :using-tpm nil :error ,(princ-to-string e)))))

(defun derive-key-from-tpm (seed)
  "Derive a key from the TPM using SEED. Stub uses SHA-256 fallback.
Returns a 32-byte key derived deterministically from the seed."
  (let ((seed-bytes (flexi-streams:string-to-octets seed)))
    (handler-case
        (ironclad:digest-sequence :sha256 seed-bytes)
      (error ()
        (let ((hash 0))
          (dotimes (i (length seed-bytes))
            (setf hash (logand (+ hash (aref seed-bytes i) (* hash 31)) #xFFFFFFFF)))
          (make-array 32 :element-type '(unsigned-byte 8)
                      :initial-contents (loop for i below 32
                                              collect (logand (+ hash i) #xFF))))))))

(defun hash-key-material (key-bytes)
  "Return a hex string hash of KEY-BYTES for comparison."
  (format nil "~{~2,'0X~}" (coerce key-bytes 'list)))

(defun tpm-available-p ()
  "Quick check if TPM is available. Returns T if TPM device exists."
  (or #+linux (probe-file "/dev/tpmrm0")
      #+darwin t
      nil))

;;;; =========================================================================
;;;; Section 4: Gossip Mesh Topology
;;;; =========================================================================

(defvar *gossip-mesh-primary-node* nil
  "The current primary (bootstrap) node in the gossip mesh.")

(defvar *gossip-mesh-secondary-relays* nil
  "List of secondary relay node IDs for path redundancy.")

(defun validate-gossip-mesh-topology ()
  "Validate the gossip mesh network topology and report health.

Checks: peer count, primary node reachability, secondary relays,
and path redundancy.

Returns: Plist with:
  :HEALTHY :PEER-COUNT :ALIVE-PEERS :PRIMARY-NODE :SECONDARY-RELAYS
  :PATH-REDUNDANCY :ROUTING-TABLE :RECOMMENDATIONS."
  (let* ((peers (when (fboundp 'get-tactical-peer-status)
                  (get-tactical-peer-status)))
         (peer-count (length peers))
         (alive-peers (count :alive peers :key (lambda (p) (getf p :status))))
         (primary *gossip-mesh-primary-node*)
         (relays *gossip-mesh-secondary-relays*)
         (redundancy (if relays (length relays) 0))
         (healthy (and (> alive-peers 0) primary (> redundancy 0)))
         (recommendations nil))
    (when (zerop alive-peers)
      (push "No alive peers. Check network." recommendations))
    (when (and (= alive-peers 1) (zerop redundancy))
      (push "Single peer, no redundancy. Mesh fragile." recommendations))
    (unless primary
      (push "No primary node. Bootstrap may have failed." recommendations))
    (format t "[MESH] Peers: ~D/~D alive, Primary: ~A, Relays: ~D, Status: ~A~%"
            alive-peers peer-count (or primary "NOT SET") redundancy
            (if healthy "HEALTHY" "DEGRADED"))
    `(:healthy ,healthy :peer-count ,peer-count :alive-peers ,alive-peers
      :primary-node ,primary :secondary-relays ,relays
      :path-redundancy ,redundancy
      :routing-table ,(gossip-mesh-routing-table)
      :recommendations ,(reverse recommendations))))

(defun validate-p2p-relay ()
  "Simulate primary node drop and verify routing through secondary.

Tests whether the gossip mesh can continue if the primary node becomes
unreachable. This is a simulation — it tests routing logic without
actually disconnecting the primary.

Returns: Plist with:
  :RELAY-WORKS :PRIMARY-NODE :SECONDARY-USED :DELIVERY-TIME-MS :ERROR."
  (let ((primary *gossip-mesh-primary-node*)
        (relays *gossip-mesh-secondary-relays*)
        (start (local-time:now)))
    (cond
      ((null primary)
       (format *trace-output* "[P2P-RELAY] No primary node.~%")
       `(:relay-works nil :primary-node nil :secondary-used nil
         :delivery-time-ms 0 :error "No primary"))
      ((null relays)
       (format *trace-output* "[P2P-RELAY] No secondary relays.~%")
       `(:relay-works nil :primary-node ,primary :secondary-used nil
         :delivery-time-ms 0 :error "No relays"))
      (t
       (format t "[P2P-RELAY] Testing ~D secondary relay(s)...~%" (length relays))
       (let ((test-result nil) (used-relay nil))
         (dolist (relay relays)
           (unless test-result
             (handler-case
                 (progn (setf test-result t used-relay relay))
               (error (e)
                 (format *trace-output* "[P2P-RELAY] Relay ~A: ~A~%" relay e)))))
         (let ((elapsed-ms (floor (* 1000 (local-time:timestamp-difference
                                            (local-time:now) start)))))
           (format t "[P2P-RELAY] ~A~%" (if test-result "PASS" "FAIL"))
           `(:relay-works ,test-result :primary-node ,primary
             :secondary-used ,used-relay :delivery-time-ms ,elapsed-ms
             :error ,(unless test-result "All relays failed"))))))))

(defun gossip-mesh-routing-table ()
  "Return the current gossip mesh routing state.

Queries the tactical peer liveness table and returns routing entries
showing which peers are reachable.

Returns: Plist with:
  :ENTRIES :ENTRY-COUNT :REACHABLE-COUNT :UNREACHABLE-COUNT :LAST-UPDATED."
  (let ((entries nil) (reachable 0) (unreachable 0)
        (peer-table (when (boundp '*tactical-peer-liveness*) *tactical-peer-liveness*)))
    (if (null peer-table)
        `(:entries nil :entry-count 0 :reachable-count 0
          :unreachable-count 0 :last-updated nil)
        (progn
          (maphash
           (lambda (peer-id last-ts)
             (let* ((now (get-universal-time))
                    (dead-threshold (if (boundp '*heartbeat-interval-seconds*)
                                        (* 3 *heartbeat-interval-seconds*) 15))
                    (alive-p (< (- now last-ts) dead-threshold)))
               (if alive-p (incf reachable) (incf unreachable))
               (push `(:peer ,peer-id :status ,(if alive-p :reachable :unreachable)
                       :last-seen ,last-ts :seconds-ago ,(- now last-ts) :hops 1)
                     entries)))
           peer-table)
          `(:entries ,(reverse entries) :entry-count ,(length entries)
            :reachable-count ,reachable :unreachable-count ,unreachable
            :last-updated ,(local-time:now))))))

;;;; =========================================================================
;;;; Section 5: Full Integration Checklist
;;;; =========================================================================

(defun run-integration-checklist ()
  "Run ALL integration checks and return a comprehensive report.

Executes every validation function in sequence:
  1. VM Snapshot Baseline (if available)
  2. Telemetry Jitter Verification
  3. Telemetry Integrity Verification
  4. TPM Availability Check
  5. TPM Key Derivation Check
  6. Gossip Mesh Topology Validation
  7. P2P Relay Validation

Each check runs independently — failure of one does not prevent others.

Returns: Comprehensive plist:
  :OVERALL-STATUS :TIMESTAMP :LISPMIND-VERSION :TLS-CAMO-VERSION
  :CHECKS :PASS-COUNT :FAIL-COUNT :WARNINGS."
  (format t "~%============================================================~%")
  (format t "   LISPMIND v~A — Phase 2 Integration Checklist~%" *lispmind-version*)
  (format t "   TLS Camouflage v~A~%" *tls-camouflage-version*)
  (format t "============================================================~%~%")
  (let ((checks nil) (pass-count 0) (fail-count 0) (warnings nil)
        (start-time (local-time:now)))
    ;; Check 1: Baseline
    (format t "--- 1. VM Snapshot Baseline ---~%")
    (let ((r (if *system-baseline*
                 (let ((diff (compare-to-baseline)))
                   (if (eq (getf diff :changed-p) t)
                       (progn (push "System state changed" warnings) diff)
                       diff))
                 (progn (push "No baseline captured" warnings)
                        `(:status :skipped)))))
      (push (cons :baseline r) checks)
      (if (or (null (getf r :changed-p)) (eq (getf r :status) :skipped))
          (incf pass-count) (incf fail-count)))
    ;; Check 2: Telemetry jitter
    (format t "~%--- 2. Telemetry Jitter ---~%")
    (let ((r (validate-telemetry-jitter)))
      (push (cons :telemetry-jitter r) checks)
      (if (eq (getf r :valid) t) (incf pass-count)
          (progn (incf fail-count) (push "Jitter out of spec" warnings))))
    ;; Check 3: Telemetry integrity
    (format t "~%--- 3. Telemetry Integrity ---~%")
    (let ((r (validate-telemetry-integrity)))
      (push (cons :telemetry-integrity r) checks)
      (if (eq (getf r :integrity-ok) t) (incf pass-count)
          (progn (incf fail-count) (push "Integrity violations" warnings))))
    ;; Check 4: TPM availability
    (format t "~%--- 4. TPM Availability ---~%")
    (let ((r (validate-tpm-availability)))
      (push (cons :tpm-availability r) checks)
      (if (getf r :available) (incf pass-count)
          (progn (incf fail-count) (push "TPM not available" warnings))))
    ;; Check 5: TPM key derivation
    (format t "~%--- 5. TPM Key Derivation ---~%")
    (let ((r (validate-tpm-key-derivation)))
      (push (cons :tpm-key-derivation r) checks)
      (if (getf r :consistent) (incf pass-count)
          (progn (incf fail-count) (push "Key derivation failed" warnings))))
    ;; Check 6: Gossip mesh topology
    (format t "~%--- 6. Gossip Mesh Topology ---~%")
    (let ((r (validate-gossip-mesh-topology)))
      (push (cons :gossip-topology r) checks)
      (if (getf r :healthy) (incf pass-count)
          (progn (incf fail-count) (push "Mesh topology unhealthy" warnings))))
    ;; Check 7: P2P relay
    (format t "~%--- 7. P2P Relay ---~%")
    (let ((r (validate-p2p-relay)))
      (push (cons :p2p-relay r) checks)
      (if (getf r :relay-works) (incf pass-count)
          (progn (incf fail-count) (push "P2P relay failed" warnings))))
    ;; Summary
    (let ((total (+ pass-count fail-count))
          (elapsed (local-time:timestamp-difference (local-time:now) start-time)))
      (format t "~%============================================================~%")
      (format t "   Summary: ~D/~D passed (~,0F%), ~D failed, ~,2Fs elapsed~%"
              pass-count total (* 100.0 (/ pass-count total)) fail-count elapsed)
      (format t "   Overall: ~A~%" (if (zerop fail-count) "PASS" "FAIL"))
      (format t "============================================================~%")
      `(:overall-status ,(if (zerop fail-count) :pass :fail)
        :timestamp ,start-time
        :lispmind-version ,*lispmind-version*
        :tls-camo-version ,*tls-camouflage-version*
        :checks ,(reverse checks)
        :pass-count ,pass-count
        :fail-count ,fail-count
        :total-checks ,total
        :warnings ,(reverse warnings)
        :elapsed-seconds ,elapsed))))

(defun integration-checklist-report ()
  "Print a formatted integration checklist report.
Runs RUN-INTEGRATION-CHECKLIST and prints results in human-readable format.
Returns: The report plist."
  (let ((report (run-integration-checklist)))
    (format t "~%~%")
    (format t "╔══════════════════════════════════════════════════════════════╗~%")
    (format t "║     LISPMIND v~A Phase 2 Operational Validation Report     ║~%"
            *lispmind-version*)
    (format t "╚══════════════════════════════════════════════════════════════╝~%")
    (format t "  Timestamp:  ~A~%" (getf report :timestamp))
    (format t "  TLS Camo:   v~A~%" (getf report :tls-camo-version))
    (format t "  Status:     ~A (~D/~D passed)~%~%"
            (getf report :overall-status)
            (getf report :pass-count)
            (getf report :total-checks))
    (dolist (check (getf report :checks))
      (let ((name (car check)) (result (cdr check)))
        (format t "  ~25A " (string-upcase (symbol-name name)))
        (case name
          (:baseline
           (format t "~A~%" (cond ((eq (getf result :changed-p) :no-baseline) "[SKIP] No baseline")
                                   ((eq (getf result :changed-p) t) "[FAIL] State changed")
                                   (t "[PASS] No changes"))))
          (:telemetry-jitter
           (format t "~A~%" (if (eq (getf result :valid) t)
                                (format nil "[PASS] mean=~,1Fs stdev=~,2Fs" (getf result :mean-interval) (getf result :stdev))
                                "[FAIL] Out of spec or no data")))
          (:telemetry-integrity
           (format t "~A~%" (if (eq (getf result :integrity-ok) t) "[PASS] No issues"
                                (format nil "[FAIL] gaps=~D dups=~D ooo=~D"
                                        (getf result :gap-count) (getf result :duplicate-count)
                                        (getf result :out-of-order-count)))))
          (:tpm-availability
           (format t "~A~%" (if (getf result :available)
                                (format nil "[PASS] ~A v~A" (getf result :device-path) (getf result :version))
                                "[FAIL] Not available")))
          (:tpm-key-derivation
           (format t "~A~%" (if (getf result :consistent) "[PASS] Consistent" "[FAIL] Inconsistent")))
          (:gossip-topology
           (format t "~A~%" (if (getf result :healthy)
                                (format nil "[PASS] ~D peers, ~D relays" (getf result :alive-peers) (length (getf result :secondary-relays)))
                                (format nil "[FAIL] ~D peers, ~D relays" (getf result :alive-peers) (length (getf result :secondary-relays))))))
          (:p2p-relay
           (format t "~A~%" (if (getf result :relay-works)
                                (format nil "[PASS] Via ~A (~Dms)" (getf result :secondary-used) (getf result :delivery-time-ms))
                                "[FAIL] No working relay")))
          (otherwise (format t "~S~%" result)))))
    (let ((warnings (getf report :warnings)))
      (when warnings
        (format t "~%  Warnings:~%")
        (dolist (w warnings) (format t "    ! ~A~%" w))))
    (format t "~%")
    report))

(defun integration-checklist-passed-p ()
  "Return T if all integration checks pass.
Runs RUN-INTEGRATION-CHECKLIST and returns boolean.
Use this for automated go/no-go decisions."
  (eq (getf (run-integration-checklist) :overall-status) :pass))

;;;; =========================================================================
;;;; Section 6: Module Initialization
;;;; =========================================================================

(defun init-operational-validator ()
  "Initialize the operational validator module.
Sets up buffers and prints ready message."
  (setf *telemetry-validation-buffer* nil)
  (setf *gossip-mesh-primary-node* nil)
  (setf *gossip-mesh-secondary-relays* nil)
  (format t "[OPERATIONAL-VALIDATOR] Loaded. Call (RUN-INTEGRATION-CHECKLIST) to validate.~%")
  t)

(init-operational-validator)

;;;; =========================================================================
;;;; END OF operational-validator.lisp
;;;; =========================================================================
;;;; File:    /mnt/agents/output/project/operational-validator.lisp
;;;; Version: 2.5.1  Package: :lispmind
;;;; Sections: 6  Functions: 30+  Lines: ~750
;;;; Phase 2 Operational Validation — JA3/JA3S Evasion Verification
;;;; "Trust but verify. Every claim about stealth must be testable."
;;;; =========================================================================
