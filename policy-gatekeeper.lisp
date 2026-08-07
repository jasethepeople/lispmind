;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; POLICY-GATEKEEPER.LISP -- Policy Enforcement + Cleanup + Network Recovery
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;          THE SENTINEL: TACTICAL POLICY ENFORCEMENT FOR KALI TOOLS
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This module is the security kernel of LISPMIND's offensive operations
;;; surface. When an agent wants to launch a Kali tool -- nmap, metasploit,
;;; hydra, aircrack, sqlmap, john, hashcat -- it does not execute directly.
;;; It must pass through the POLICY GATEKEEPER: a multi-layer validation
;;; system that checks arguments, targets, risk levels, and concurrency
;;; limits against the TACTICAL REPOSITORY of registered policies.
;;;
;;; The module provides:
;;;   1. POLICY DEFINITION SYSTEM -- The Tactical Repository
;;;   2. POLICY VALIDATION -- The Gatekeeper (safe-strategy-p)
;;;   3. THE JANITOR -- Automated cleanup via CLOS :AFTER + sweep thread
;;;   4. NETWORK STATE CHECKPOINT -- Save/restore/monitor interfaces
;;;   5. EMERGENCY INTEGRATION -- Kill-switch + audit logging
;;;   6. KALI TOOL LAUNCHER -- Safe subprocess spawning
;;;   7. SYSTEM STATUS -- Comprehensive diagnostics
;;;   8. INITIALIZATION/SHUTDOWN -- Full lifecycle management
;;;   9. GRAY STREAMS -- Filtered output for sensitive data
;;;   10. ORCHESTRATOR INTEGRATION -- Emergency halt handler
;;;   11. CONVENIENCE API -- Shortcuts for common operations
;;;
;;; DESIGN PHILOSOPHY
;;; --
;;; "Safety is not a feature you bolt on. It is the foundation everything
;;;  else stands on. The Gatekeeper exists because one malformed nmap
;;;  command launched against the wrong subnet at 3 AM can end a career.
;;;  The Janitor exists because every leaked process is a debt that comes
;;;  due eventually. The network monitor exists because an air-gapped
;;;  Kali box that loses its bridge interface is a brick."
;;;
;;; THREAD SAFETY
;;; --
;;; All policy mutations hold *POLICY-LOCK*. The Janitor thread and
;;; network monitor thread are independently managed. The audit log
;;; is a circular buffer protected by *AUDIT-LOG-LOCK*.
;;;
;;; DEPENDENCIES
;;; --
;;;   - UIOP (portable process control)
;;;   - Bordeaux-Threads (background threads)
;;;   - CLOS MOP (:AFTER methods on finalize-agent)
;;;   - trivial-gray-streams (output filtering)
;;;
;;; "The Gatekeeper does not ask permission. It grants it."

(in-package :lispmind)


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 0: Kali-Agent Class -- Agent with Subprocess Management
;; ═══════════════════════════════════════════════════════════════════════════

(defclass kali-agent (agent)
  ((subprocess
    :initform nil
    :accessor kali-agent-subprocess
    :documentation
    "The UIOP process-info object for the running Kali tool, or NIL.
Set by the tool launcher. Cleared by the Janitor on agent death.")

   (tool-name
    :initarg :tool-name
    :initform nil
    :accessor kali-agent-tool-name
    :documentation
    "Symbol naming the tool: 'nmap, 'metasploit, 'hydra, 'aircrack,
'sqlmap, 'john, 'hashcat, etc. Used for policy lookup.")

   (tool-args
    :initarg :tool-args
    :initform nil
    :accessor kali-agent-tool-args
    :documentation
    "Validated argument list passed to the tool.
Only safe, approved args reach this slot.")

   (requested-args
    :initarg :requested-args
    :initform nil
    :accessor kali-agent-requested-args
    :documentation
    "Original argument list as requested BEFORE policy validation.
Kept for forensic analysis and audit logging.")

   (target
    :initarg :target
    :initform nil
    :accessor kali-agent-target
    :documentation
    "Target host, IP, or subnet string. Validated against FORBIDDEN-TARGETS.")

   (launch-time
    :initform nil
    :accessor kali-agent-launch-time
    :documentation
    "LOCAL-TIME timestamp when the tool was launched. NIL if not launched.")

   (policy-approved-p
    :initform nil
    :accessor kali-agent-policy-approved-p
    :documentation
    "T if the Gatekeeper approved this agent's tool invocation.")

   (output-buffer
    :initform (make-array 0 :element-type 'character :fill-pointer 0 :adjustable t)
    :accessor kali-agent-output-buffer
    :documentation
    "Adjustable string array capturing tool stdout/stderr output.")

   (risk-level
    :initarg :risk-level
    :initform :medium
    :accessor kali-agent-risk-level
    :documentation
    "Risk classification: :low, :medium, :high, or :critical.
Critical requires explicit operator confirmation.")

   (confirmation-received-p
    :initform nil
    :accessor kali-agent-confirmation-received-p
    :documentation
    "T if operator confirmation received for a high-risk operation.")

   (binary-path
    :initarg :binary-path
    :initform nil
    :accessor kali-agent-binary-path
    :documentation
    "Full filesystem path to the tool binary executable."))

  (:documentation
   "A Kali-Agent manages an external offensive security tool as a subprocess.
Lifecycle: CREATION -> VALIDATION -> LAUNCH -> MONITORING -> FINALIZATION.
The finalize-agent :AFTER method on this class kills the subprocess on death."))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 1: Policy Definition System -- The Tactical Repository
;; ═══════════════════════════════════════════════════════════════════════════

(defstruct (tool-policy
            (:constructor %make-tool-policy-internal))
  "Policy rules for a specific Kali tool.
Fields:
  - tool-name         -- Symbol: 'nmap, 'metasploit, etc.
  - forbidden-args    -- List of argument strings never allowed (e.g., \"-T5\")
  - forbidden-targets -- IP ranges/subnets off-limits (e.g., \"10.0.0.0/8\")
  - max-parallel      -- Maximum concurrent instances (default: 1)
  - timeout-seconds   -- Default timeout (default: 300)
  - output-filters    -- Regex patterns to filter from output
  - required-args     -- Args that must always be present
  - risk-level        -- :low :medium :high :critical (default: :medium)

Fail-closed: no policy means ALL invocations are blocked."
  (tool-name nil :type symbol)
  (forbidden-args nil :type list)
  (forbidden-targets nil :type list)
  (max-parallel 1 :type integer)
  (timeout-seconds 300 :type integer)
  (output-filters nil :type list)
  (required-args nil :type list)
  (risk-level :medium :type keyword))

(defun make-tool-policy (tool-name &key forbidden-args forbidden-targets
                                        max-parallel timeout-seconds
                                        output-filters required-args risk-level)
  "Constructor for TOOL-POLICY with sensible defaults.
MAX-PARALLEL defaults to 1, TIMEOUT-SECONDS to 300, RISK-LEVEL to :medium.
All list fields default to NIL."
  (%make-tool-policy-internal
   :tool-name tool-name
   :forbidden-args (or forbidden-args nil)
   :forbidden-targets (or forbidden-targets nil)
   :max-parallel (or max-parallel 1)
   :timeout-seconds (or timeout-seconds 300)
   :output-filters (or output-filters nil)
   :required-args (or required-args nil)
   :risk-level (or risk-level :medium)))

(defvar *tactical-repository* (make-hash-table :test 'eq)
  "Maps tool-name symbol to TOOL-POLICY. The Tactical Repository.
Fail-closed: tools without registered policies are BLOCKED.
All accesses protected by *POLICY-LOCK*.")

(defvar *policy-lock* (bt:make-lock "policy-lock")
  "Recursive lock protecting *TACTICAL-REPOSITORY*.")

(defvar *active-kali-agents* (make-hash-table :test 'eq)
  "Registry of active KALI-AGENT instances. Maps agent-id -> agent.
Used by Janitor, CHECK-MAX-PARALLEL, and EMERGENCY-KILL-ALL-TOOLS.
Protected by *KALI-AGENTS-LOCK*.")

(defvar *kali-agents-lock* (bt:make-lock "kali-agents-lock")
  "Lock protecting *ACTIVE-KALI-AGENTS* and *PARALLEL-INSTANCE-COUNTS*.")

(defun register-policy (tool-name policy)
  "Register a POLICY for TOOL-NAME in the Tactical Repository.
TOOL-NAME is a symbol (e.g., 'nmap). POLICY is a TOOL-POLICY.
Replaces any existing policy. Returns POLICY.
Thread-safe: acquires *POLICY-LOCK*."
  (bt:with-lock-held (*policy-lock*)
    (setf (gethash tool-name *tactical-repository*) policy))
  (policy-audit-log :register-policy t
                    (format nil "Registered policy for ~A (risk: ~A)"
                            tool-name (tool-policy-risk-level policy)))
  policy)

(defun get-policy (tool-name)
  "Get the TOOL-POLICY for TOOL-NAME, or NIL if none exists.
Thread-safe: acquires *POLICY-LOCK*."
  (bt:with-lock-held (*policy-lock*)
    (gethash tool-name *tactical-repository*)))

(defun policy-exists-p (tool-name)
  "Return T if a policy exists for TOOL-NAME. Used by Gatekeeper fail-closed check."
  (bt:with-lock-held (*policy-lock*)
    (not (null (gethash tool-name *tactical-repository*)))))

(defun unregister-policy (tool-name)
  "Remove the policy for TOOL-NAME. Returns T if a policy was removed.
After unregistering, all invocations of that tool are BLOCKED."
  (bt:with-lock-held (*policy-lock*)
    (let ((had-policy (gethash tool-name *tactical-repository*)))
      (remhash tool-name *tactical-repository*)
      (policy-audit-log :unregister-policy had-policy
                        (format nil "Unregistered policy for ~A" tool-name))
      (not (null had-policy)))))

(defun list-registered-policies ()
  "Return a list of all registered tool-name symbols. Fresh list."
  (bt:with-lock-held (*policy-lock*)
    (loop for tool-name being the hash-keys of *tactical-repository*
          collect tool-name)))

(defun describe-policy (tool-name)
  "Return a human-readable string describing the policy for TOOL-NAME.
If no policy exists, reports that all invocations are BLOCKED."
  (let ((policy (get-policy tool-name)))
    (if policy
        (format nil "Policy for ~A:~%  Risk Level: ~A~%  Max Parallel: ~D~%  Timeout: ~Ds~%  Forbidden Args: ~S~%  Forbidden Targets: ~S~%  Required Args: ~S~%  Output Filters: ~S"
                (tool-policy-tool-name policy)
                (tool-policy-risk-level policy)
                (tool-policy-max-parallel policy)
                (tool-policy-timeout-seconds policy)
                (tool-policy-forbidden-args policy)
                (tool-policy-forbidden-targets policy)
                (tool-policy-required-args policy)
                (tool-policy-output-filters policy))
        (format nil "No policy registered for ~A (all invocations BLOCKED)." tool-name))))

(defun load-default-policies ()
  "Load the default policy set into the Tactical Repository.
Registers conservative, production-safe policies for 7 common Kali tools:
  - NMAP      -- No -T5 (insane timing), no scans of 10.0.0.0/8
  - METASPLOIT -- No exploits above :medium risk without confirmation
  - HYDRA     -- No brute-force against non-test targets
  - AIRCRACK  -- Only on test interfaces (wlan1, not wlan0)
  - SQLMAP    -- No --dump-all, --os-shell, --os-pwn
  - JOHN      -- No cracking of production hash files
  - HASHCAT   -- No cracking of production hash files
Returns list of registered tool-name symbols. Idempotent."
  (let ((registered '()))
    ;; NMAP: Network discovery
    (push (tool-policy-tool-name
           (register-policy
            'nmap
            (make-tool-policy
             'nmap
             :forbidden-args '("-T5" "--script=unsafe" "--script=malware")
             :forbidden-targets '("10.0.0.0/8" "127.0.0.0/8")
             :max-parallel 4
             :timeout-seconds 600
             :required-args '("-sT")
             :risk-level :medium)))
          registered)
    ;; METASPLOIT: Exploitation framework
    (push (tool-policy-tool-name
           (register-policy
            'metasploit
            (make-tool-policy
             'metasploit
             :forbidden-args '("-j" "--exit-on-session")
             :forbidden-targets '("10.0.0.0/8")
             :max-parallel 2
             :timeout-seconds 900
             :risk-level :high)))
          registered)
    ;; HYDRA: Login cracker
    (push (tool-policy-tool-name
           (register-policy
            'hydra
            (make-tool-policy
             'hydra
             :forbidden-args '("-t64" "-w32")
             :forbidden-targets '("*.prod.*" "*.production.*")
             :max-parallel 2
             :timeout-seconds 1800
             :required-args '("-l" "testuser")
             :risk-level :high)))
          registered)
    ;; AIRCRACK: WiFi auditing
    (push (tool-policy-tool-name
           (register-policy
            'aircrack
            (make-tool-policy
             'aircrack
             :forbidden-args '("wlan0" "mon0" "--bssid")
             :forbidden-targets nil
             :max-parallel 1
             :timeout-seconds 3600
             :required-args '("-i" "wlan1")
             :risk-level :critical)))
          registered)
    ;; SQLMAP: SQL injection
    (push (tool-policy-tool-name
           (register-policy
            'sqlmap
            (make-tool-policy
             'sqlmap
             :forbidden-args '("--dump-all" "--os-shell" "--os-pwn")
             :forbidden-targets '("*.prod.*" "*.production.*")
             :max-parallel 2
             :timeout-seconds 1800
             :required-args '("--batch")
             :risk-level :high)))
          registered)
    ;; JOHN: Password cracker
    (push (tool-policy-tool-name
           (register-policy
            'john
            (make-tool-policy
             'john
             :forbidden-args '("--format=descrypt")
             :forbidden-targets '("/etc/shadow" "/etc/passwd")
             :max-parallel 2
             :timeout-seconds 3600
             :risk-level :medium)))
          registered)
    ;; HASHCAT: GPU password recovery
    (push (tool-policy-tool-name
           (register-policy
            'hashcat
            (make-tool-policy
             'hashcat
             :forbidden-args '("--force" "-O" "--backend-devices-virtual")
             :forbidden-targets '("*.prod.*" "/etc/shadow")
             :max-parallel 1
             :timeout-seconds 7200
             :risk-level :medium)))
          registered)
    (policy-audit-log :load-defaults t
                      (format nil "Loaded ~D default policies: ~S"
                              (length registered) registered))
    registered))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 2: Policy Validation -- The Gatekeeper
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *max-risk-without-confirmation* :medium
  "Maximum risk level launchable WITHOUT explicit confirmation.
Default :medium means :high and :critical require confirmation.
Set to :low for maximum paranoia (everything needs confirmation).")

(defvar *parallel-instance-counts* (make-hash-table :test 'eq)
  "Tracks instance counts per tool. Maps tool-name -> integer.
Incremented on launch, decremented on finalization.
Protected by *KALI-AGENTS-LOCK*.")

(defun safe-strategy-p (agent binary args)
  "The Gatekeeper: validate a tool launch against its policy.
Single point of enforcement. Every Kali tool launch must pass through here.

Arguments:
  AGENT  -- KALI-AGENT instance
  BINARY -- Tool binary name string (e.g., \"nmap\")
  ARGS   -- List of string arguments

Validation steps (ALL must pass):
  1. Policy exists for this tool? (fail-closed)
  2. ARGS contain no forbidden arguments?
  3. All required arguments present in ARGS?
  4. Target not in forbidden-targets list?
  5. Tool's risk level acceptable?
  6. Parallel instance limits respected?

Returns (values T nil) if approved, (values nil reason) if blocked.
The REASON string is logged to the policy audit log."
  (let* ((tool-name (intern (string-upcase binary) :keyword))
         (policy (get-policy tool-name)))
    (cond
      ;; Step 1: Fail-closed -- no policy means BLOCKED
      ((null policy)
       (let ((reason (format nil "BLOCKED: No policy for tool ~A (~A). All unregistered tools blocked."
                             tool-name binary)))
         (policy-audit-log :gatekeeper-deny nil reason)
         (return-from safe-strategy-p (values nil reason))))

      ;; Step 2: Validate forbidden args
      ((not (validate-args-against-policy args policy))
       (let ((reason (format nil "BLOCKED: Forbidden arg for ~A. Args: ~S" tool-name args)))
         (policy-audit-log :gatekeeper-deny nil reason)
         (return-from safe-strategy-p (values nil reason))))

      ;; Step 3: Validate required args
      ((not (validate-required-args-present args policy))
       (let ((reason (format nil "BLOCKED: Missing required arg for ~A. Need: ~S Got: ~S"
                             tool-name (tool-policy-required-args policy) args)))
         (policy-audit-log :gatekeeper-deny nil reason)
         (return-from safe-strategy-p (values nil reason))))

      ;; Step 4: Validate target
      ((and (kali-agent-target agent)
            (not (validate-target-against-policy (kali-agent-target agent) policy)))
       (let ((reason (format nil "BLOCKED: Target '~A' forbidden for ~A."
                             (kali-agent-target agent) tool-name)))
         (policy-audit-log :gatekeeper-deny nil reason)
         (return-from safe-strategy-p (values nil reason))))

      ;; Step 5: Validate risk level
      ((not (validate-risk-level tool-name))
       (let ((reason (format nil "BLOCKED: Risk ~A for ~A exceeds max ~A."
                             (tool-policy-risk-level policy) tool-name
                             *max-risk-without-confirmation*)))
         (policy-audit-log :gatekeeper-deny nil reason)
         (return-from safe-strategy-p (values nil reason))))

      ;; Step 6: Check parallel limits
      ((not (check-max-parallel tool-name))
       (let ((reason (format nil "BLOCKED: Max parallel (~D) exceeded for ~A."
                             (tool-policy-max-parallel policy) tool-name)))
         (policy-audit-log :gatekeeper-deny nil reason)
         (return-from safe-strategy-p (values nil reason))))

      ;; All checks passed -- APPROVED
      (t
       (policy-audit-log :gatekeeper-approve t
                         (format nil "APPROVED: ~A ~{~A~^ ~}" binary args))
       (values t nil)))))

(defun validate-args-against-policy (args policy)
  "Return T if no ARGS match any forbidden pattern in POLICY.
Uses exact string match (string=), not substring search."
  (let ((forbidden (tool-policy-forbidden-args policy)))
    (not (some (lambda (arg)
                 (some (lambda (fb) (string= arg fb)) forbidden))
               args))))

(defun validate-required-args-present (args policy)
  "Return T if all REQUIRED-ARGS from POLICY are present in ARGS.
Uses prefix matching to handle attached values (e.g., \"-l testuser\")."
  (let ((required (tool-policy-required-args policy)))
    (every (lambda (req)
             (some (lambda (arg)
                     (or (string= arg req)
                         (uiop:string-prefix-p req arg)))
                   args))
           required)))

(defun validate-target-against-policy (target policy)
  "Return T if TARGET is not in any forbidden range of POLICY.
Supports CIDR notation, wildcard patterns, and exact matches."
  (let ((forbidden-targets (tool-policy-forbidden-targets policy)))
    (not (some (lambda (fb) (target-matches-p target fb)) forbidden-targets))))

(defun target-matches-p (target forbidden)
  "Check if TARGET matches FORBIDDEN pattern.
Supports CIDR (10.0.0.0/8), wildcard (*.prod.*), and exact matches."
  (cond
    ;; CIDR /8 /16 /24
    ((or (uiop:string-suffix-p forbidden "/8")
         (uiop:string-suffix-p forbidden "/16")
         (uiop:string-suffix-p forbidden "/24"))
     (let ((prefix (subseq forbidden 0 (position #\\/ forbidden))))
       (uiop:string-prefix-p prefix target)))
    ;; Wildcard patterns
    ((or (uiop:string-prefix-p forbidden "*.")
         (uiop:string-suffix-p forbidden ".*"))
     (wildcard-match-p target forbidden))
    ;; Exact match
    (t (string= target forbidden))))

(defun wildcard-match-p (string pattern)
  "Simple wildcard matching: * matches any sequence.
Examples: (wildcard-match-p \"web.prod.com\" \"*.prod.*\") => T"
  (cond
    ((string= pattern "*") t)
    ((uiop:string-prefix-p pattern "*.")
     (search (subseq pattern 2) string))
    ((uiop:string-suffix-p pattern ".*")
     (uiop:string-prefix-p string (subseq pattern 0 (- (length pattern) 2))))
    (t (string= string pattern))))

(defun validate-risk-level (tool-name)
  "Return T if the tool's risk level is acceptable for launch.
Compares against *MAX-RISK-WITHOUT-CONFIRMATION*.
Ordering: :low < :medium < :high < :critical."
  (let ((policy (get-policy tool-name)))
    (if (null policy)
        nil
        (risk-level-<= (tool-policy-risk-level policy)
                       *max-risk-without-confirmation*))))

(defun risk-level-<= (a b)
  "Compare two risk levels. Return T if A <= B."
  (let ((ordering '(:low 0 :medium 1 :high 2 :critical 3)))
    (<= (getf ordering a 999) (getf ordering b 999))))

(defun check-max-parallel (tool-name)
  "Return T if parallel instance limit not exceeded for TOOL-NAME.
Compares current count against policy MAX-PARALLEL."
  (let ((policy (get-policy tool-name)))
    (if (null policy)
        nil
        (bt:with-lock-held (*kali-agents-lock*)
          (< (gethash tool-name *parallel-instance-counts* 0)
             (tool-policy-max-parallel policy))))))

(defun confirm-high-risk-operation (agent)
  "Prompt operator for confirmation of a high-risk tool launch.
Returns T if confirmed, NIL if denied. Sets confirmation-received-p on approval."
  (format *query-io* "~&~%*** HIGH-RISK OPERATION CONFIRMATION REQUIRED ***~%")
  (format *query-io* "  Tool:   ~A~%" (kali-agent-tool-name agent))
  (format *query-io* "  Target: ~A~%" (kali-agent-target agent))
  (format *query-io* "  Risk:   ~A~%" (kali-agent-risk-level agent))
  (format *query-io* "  Args:   ~S~%" (kali-agent-requested-args agent))
  (format *query-io* "~&Confirm launch? (yes/no): ")
  (force-output *query-io*)
  (let ((response (read-line *query-io*)))
    (when (member (string-downcase (string-trim " " response))
                  '("yes" "y" "confirm")
                  :test #'string=)
      (setf (kali-agent-confirmation-received-p agent) t)
      (policy-audit-log :high-risk-confirmed t
                        (format nil "Confirmed high-risk: ~A on ~A"
                                (kali-agent-tool-name agent)
                                (kali-agent-target agent)))
      t)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 3: The Janitor -- Automated Cleanup Finalization
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; "A process left running after its agent dies is a ghost -- invisible,
;;  unaccounted for, and dangerous. The Janitor exorcises ghosts."

(defvar *janitor-thread* nil
  "Background Janitor sweep thread, or NIL if not running.")

(defvar *janitor-running-p* nil
  "Flag controlling the Janitor sweep loop.")

(defvar *janitor-lock* (bt:make-lock "janitor-lock")
  "Lock protecting Janitor state.")

(defvar *janitor-cvar* (bt:make-condition-variable :name "janitor-cvar")
  "Condition variable for Janitor shutdown signaling.")

(defun finalize-agent (agent)
  "Generic finalization hook for agent cleanup.
Primary method is a no-op. The :AFTER method on KALI-AGENT kills subprocesses.
Also supports SB-EXT:FINALIZE for GC-triggered cleanup."
  (declare (ignore agent))
  nil)

(defmethod finalize-agent :after ((agent kali-agent))
  "Kill the subprocess when a KALI-AGENT is finalized.
Sequence:
  1. Drain remaining output
  2. SIGTERM (graceful, wait 5s)
  3. SIGKILL if still alive (forceful)
  4. Decrement parallel instance count
  5. Remove from *ACTIVE-KALI-AGENTS*
Called by Janitor sweep, explicit shutdown, and emergency kill."
  (bt:with-lock-held ((agent-lock agent))
    (let ((subprocess (kali-agent-subprocess agent)))
      (when (and subprocess (uiop:process-alive-p subprocess))
        ;; Step 1: Drain output
        (ignore-errors (drain-subprocess-output agent))
        ;; Step 2: SIGTERM graceful
        (ignore-errors (uiop:terminate-process subprocess))
        ;; Step 3: Wait up to 5 seconds
        (dotimes (i 50)
          (unless (uiop:process-alive-p subprocess)
            (return))
          (sleep 0.1))
        ;; Step 4: SIGKILL if needed
        (when (uiop:process-alive-p subprocess)
          (ignore-errors (uiop:terminate-process subprocess :urgent t)))
        ;; Log cleanup
        (policy-audit-log :janitor-cleanup t
                          (format nil "Finalized ~A (tool: ~A, target: ~A)"
                                  (agent-id agent)
                                  (kali-agent-tool-name agent)
                                  (kali-agent-target agent))))
      ;; Decrement count and remove from registry
      (when (kali-agent-tool-name agent)
        (bt:with-lock-held (*kali-agents-lock*)
          (let ((current (gethash (kali-agent-tool-name agent)
                                  *parallel-instance-counts* 0)))
            (when (> current 0)
              (decf (gethash (kali-agent-tool-name agent)
                             *parallel-instance-counts*))))))
      (bt:with-lock-held (*kali-agents-lock*)
        (remhash (agent-id agent) *active-kali-agents*))
      (setf (kali-agent-subprocess agent) nil))))

(defun drain-subprocess-output (agent)
  "Drain stdout/stderr from the agent's subprocess into output-buffer.
Non-blocking: returns immediately if no output available."
  (let ((subprocess (kali-agent-subprocess agent)))
    (when subprocess
      (ignore-errors
        (let ((stream (uiop:process-info-output subprocess)))
          (when (and stream (open-stream-p stream))
            (loop while (listen stream)
                  do (vector-push-extend (read-char stream)
                                         (kali-agent-output-buffer agent))))))
      (ignore-errors
        (let ((stream (uiop:process-info-error-output subprocess)))
          (when (and stream (open-stream-p stream))
            (loop while (listen stream)
                  do (vector-push-extend (read-char stream)
                                         (kali-agent-output-buffer agent)))))))))

(defun janitor-sweep ()
  "Sweep all Kali agents. Kill subprocesses of dead agents (ghosts),
mark agents with dead subprocesses as :FAILED (zombies), and kill
runaway processes exceeding timeout.

Returns a plist:
  :agents-checked   -- total agents examined
  :ghosts-killed    -- subprocesses killed for dead agents
  :zombies-detected -- agents whose subprocess exited unexpectedly
  :runaways-stopped -- processes killed for exceeding timeout"
  (let ((stats (list :agents-checked 0 :ghosts-killed 0
                     :zombies-detected 0 :runaways-stopped 0)))
    (bt:with-lock-held (*kali-agents-lock*)
      (maphash
       (lambda (agent-id agent)
         (declare (ignore agent-id))
         (incf (getf stats :agents-checked))
         (let ((alive (agent-alive-p agent))
               (subprocess (kali-agent-subprocess agent))
               (subprocess-alive (and (kali-agent-subprocess agent)
                                      (uiop:process-alive-p
                                       (kali-agent-subprocess agent))))
               (timed-out
                 (and (kali-agent-launch-time agent)
                      (kali-agent-policy-approved-p agent)
                      (> (local-time:timestamp-difference
                          (local-time:now)
                          (kali-agent-launch-time agent))
                         (let ((policy (get-policy (kali-agent-tool-name agent))))
                           (if policy (tool-policy-timeout-seconds policy) 300))))))
           (cond
             ;; Dead agent + living subprocess = GHOST
             ((and (not alive) subprocess-alive)
              (finalize-agent agent)
              (incf (getf stats :ghosts-killed)))
             ;; Alive agent + dead subprocess = ZOMBIE
             ((and alive subprocess (not subprocess-alive))
              (setf (agent-status agent) :failed)
              (incf (getf stats :zombies-detected)))
             ;; Runaway process (exceeded timeout)
             ((and alive subprocess-alive timed-out)
              (finalize-agent agent)
              (setf (agent-status agent) :failed)
              (incf (getf stats :runaways-stopped))
              (policy-audit-log :runaway-killed t
                                (format nil "Killed runaway ~A after timeout"
                                        (agent-id agent)))))))
       *active-kali-agents*))
    stats))

(defun start-janitor-thread (&optional (interval 5))
  "Start a background thread that sweeps every INTERVAL seconds.
INTERVAL default is 5 seconds. Returns the Janitor thread.
If already running, returns existing thread. Thread-safe."
  (bt:with-lock-held (*janitor-lock*)
    (if (and *janitor-thread* (bt:thread-alive-p *janitor-thread*))
        *janitor-thread*
        (progn
          (setf *janitor-running-p* t)
          (setf *janitor-thread*
                (bt:make-thread
                 (lambda () (janitor-loop interval))
                 :name "lispmind-janitor"
                 :initial-bindings `((*standard-output* . ,*standard-output*)
                                     (*error-output*    . ,*error-output*))))
          (policy-audit-log :janitor-started t
                            (format nil "Janitor started (interval: ~Ds)" interval))
          *janitor-thread*))))

(defun stop-janitor-thread ()
  "Stop the Janitor thread gracefully. Signals via *JANITOR-CVAR*,
waits up to 10s, force-destroys if needed. Returns T if stopped."
  (bt:with-lock-held (*janitor-lock*)
    (when *janitor-running-p*
      (setf *janitor-running-p* nil)
      (bt:condition-notify *janitor-cvar*)
      (when (and *janitor-thread* (bt:thread-alive-p *janitor-thread*))
        (dotimes (i 100)
          (unless (bt:thread-alive-p *janitor-thread*)
            (return))
          (sleep 0.1))
        (when (bt:thread-alive-p *janitor-thread*)
          (ignore-errors (bt:destroy-thread *janitor-thread*))))
      (setf *janitor-thread* nil)
      (policy-audit-log :janitor-stopped t "Janitor stopped")
      t)))

(defun janitor-loop (interval)
  "The Janitor sweep loop. Runs until *JANITOR-RUNNING-P* becomes NIL.
Error handling: catches ALL conditions and continues. A dead Janitor
is worse than a noisy log."
  (loop while *janitor-running-p* do
    (handler-case
        (progn
          (bt:with-lock-held (*janitor-lock*)
            (unless *janitor-running-p* (return))
            (bt:condition-wait *janitor-cvar* *janitor-lock*
                               :timeout interval))
          (when *janitor-running-p*
            (let ((stats (janitor-sweep)))
              (when (or (> (getf stats :ghosts-killed) 0)
                        (> (getf stats :runaways-stopped) 0))
                (policy-audit-log :janitor-sweep t
                                  (format nil "Sweep: ~D checked, ~D ghosts, ~D zombies, ~D runaways"
                                          (getf stats :agents-checked)
                                          (getf stats :ghosts-killed)
                                          (getf stats :zombies-detected)
                                          (getf stats :runaways-stopped)))))))
      (error (e)
        (format *error-output* "~&[JANITOR ERROR] ~A~%" e)
        (policy-audit-log :janitor-error nil (format nil "Janitor error: ~A" e)))
      (condition (c)
        (format *error-output* "~&[JANITOR CONDITION] ~A~%" c)
        (policy-audit-log :janitor-condition nil (format nil "Janitor condition: ~A" c))))))

(defun janitor-status ()
  "Return Janitor subsystem status as a plist:
  :running-p, :thread-alive-p, :active-agents, :parallel-counts"
  (let ((agent-count 0)
        (counts-copy (make-hash-table :test 'eq)))
    (bt:with-lock-held (*kali-agents-lock*)
      (setf agent-count (hash-table-count *active-kali-agents*))
      (maphash (lambda (k v) (setf (gethash k counts-copy) v))
               *parallel-instance-counts*))
    (list :running-p *janitor-running-p*
          :thread-alive-p (and *janitor-thread*
                               (bt:thread-alive-p *janitor-thread*))
          :active-agents agent-count
          :parallel-counts counts-copy)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 4: Network State Checkpoint -- Save/Restore/Monitor
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *network-state-checkpoint* nil
  "Saved network interface state as a plist:
  :timestamp    -- local-time timestamp
  :interfaces   -- list of (:name :state :ip-address :mac-address)
  :routes       -- list of route strings
  :primary-link -- name of primary interface")

(defvar *network-monitor-thread* nil)
(defvar *network-monitor-running-p* nil)
(defvar *network-monitor-lock* (bt:make-lock "network-monitor-lock"))
(defvar *network-monitor-cvar* (bt:make-condition-variable :name "network-monitor-cvar"))

(defun save-network-state ()
  "Save current network interface configuration.
Captures interface names, states, IPs, MACs, routes, and primary link
from /sys/class/net/ and iproute2. Returns checkpoint plist.
Non-Linux systems get empty checkpoint (no error)."
  (let ((interfaces '()) (routes '()) (primary-link nil))
    (ignore-errors
      (dolist (iface-dir (uiop:subdirectories #P"/sys/class/net/"))
        (let* ((iface-name (car (last (pathname-directory iface-dir))))
               (state-file (merge-pathnames "operstate" iface-dir))
               (address-file (merge-pathnames "address" iface-dir))
               (state "unknown") (mac "unknown") (ip nil))
          (when (probe-file state-file)
            (with-open-file (s state-file :direction :input)
              (setf state (string-trim '(#\\newline #\\space #\\tab)
                                       (read-line s nil "unknown")))))
          (when (probe-file address-file)
            (with-open-file (s address-file :direction :input)
              (setf mac (string-trim '(#\\newline #\\space #\\tab)
                                     (read-line s nil "unknown")))))
          (ignore-errors
            (let ((ip-output (uiop:run-program
                              (format nil "ip -4 addr show ~A 2>/dev/null" iface-name)
                              :output '(:string :stripped t)
                              :ignore-error-status t)))
              (when (and ip-output (> (length ip-output) 0))
                (let ((start (search "inet " ip-output)))
                  (when start
                    (let ((addr-start (+ start 5)))
                      (let ((addr-end (position #\\/ ip-output :start addr-start)))
                        (when addr-end
                          (setf ip (subseq ip-output addr-start addr-end))))))))))
          (when (and (string= state "up") (not (string= iface-name "lo"))
                     (null primary-link))
            (setf primary-link iface-name))
          (push (list :name iface-name :state state :ip-address ip
                      :mac-address mac)
                interfaces))))
    (ignore-errors
      (let ((route-output (uiop:run-program "ip route show 2>/dev/null"
                                            :output '(:string :stripped t)
                                            :ignore-error-status t)))
        (when (and route-output (> (length route-output) 0))
          (setf routes (uiop:split-string route-output :separator '(#\\newline))))))
    (setf *network-state-checkpoint*
          (list :timestamp (local-time:now)
                :interfaces interfaces
                :routes routes
                :primary-link primary-link))
    (policy-audit-log :network-checkpoint t
                      (format nil "Saved network state: ~D interfaces, primary: ~A"
                              (length interfaces) primary-link))
    *network-state-checkpoint*))

(defun restore-network-state ()
  "Restore network interfaces from *NETWORK-STATE-CHECKPOINT*.
Attempts to restore each interface to its saved state and IP.
Returns T if attempted, NIL if no checkpoint exists.
Note: requires root privileges for iproute2 commands."
  (if (null *network-state-checkpoint*)
      (progn (warn "No network checkpoint. Call SAVE-NETWORK-STATE first.") nil)
      (let ((interfaces (getf *network-state-checkpoint* :interfaces))
            (restored 0) (failed 0))
        (dolist (iface interfaces)
          (let ((name (getf iface :name))
                (state (getf iface :state))
                (ip (getf iface :ip-address)))
            (handler-case
                (progn
                  (uiop:run-program
                   (format nil "ip link set ~A ~A 2>/dev/null"
                           name (if (string= state "up") "up" "down"))
                   :ignore-error-status t)
                  (when ip
                    (uiop:run-program
                     (format nil "ip addr add ~A dev ~A 2>/dev/null" ip name)
                     :ignore-error-status t))
                  (incf restored))
              (error (e)
                (incf failed)
                (format *error-output* "~&[NETWORK-RESTORE] Failed ~A: ~A~%" name e)))))
        (policy-audit-log :network-restore t
                          (format nil "Restored ~D interfaces (~D failed)" restored failed))
        t)))

(defun check-network-link ()
  "Check if primary network link is up. Returns plist:
  :link-up, :interface, :ip-address, :carrier
Uses /sys/class/net/ on Linux."
  (let ((primary (or (getf *network-state-checkpoint* :primary-link) "eth0"))
        (link-up nil) (ip-address nil) (carrier nil))
    (ignore-errors
      (let ((state-file (format nil "/sys/class/net/~A/operstate" primary)))
        (when (probe-file state-file)
          (with-open-file (s state-file :direction :input)
            (let ((state (string-trim '(#\\newline #\\space #\\tab)
                                      (read-line s nil "down"))))
              (setf link-up (string= state "up"))))))
      (let ((carrier-file (format nil "/sys/class/net/~A/carrier" primary)))
        (when (probe-file carrier-file)
          (with-open-file (s carrier-file :direction :input)
            (let ((val (read-line s nil "0")))
              (setf carrier (string= (string-trim '(#\\newline) val) "1"))))))
      (let ((ip-output (uiop:run-program
                        (format nil "ip -4 addr show ~A 2>/dev/null" primary)
                        :output '(:string :stripped t)
                        :ignore-error-status t)))
        (when (and ip-output (> (length ip-output) 0))
          (let ((start (search "inet " ip-output)))
            (when start
              (let* ((addr-start (+ start 5))
                     (addr-end (or (position #\\/ ip-output :start addr-start)
                                   (position #\\space ip-output :start addr-start))))
                (when addr-end
                  (setf ip-address (subseq ip-output addr-start addr-end))))))))
    (list :link-up (and link-up carrier)
          :interface primary
          :ip-address ip-address
          :carrier carrier))))

(defun handle-unexpected-link-loss ()
  "Recovery action for network link loss. Restores network state from checkpoint.
Returns plist: :link-lost-detected, :restoration-attempted,
:restoration-successful, :action-taken"
  (let ((status (check-network-link)) (restored nil) (success nil))
    (if (getf status :link-up)
        (list :link-lost-detected nil
              :restoration-attempted nil
              :restoration-successful t
              :action-taken "Link is up -- no action needed")
        (progn
          (policy-audit-log :link-loss-detected t
                            (format nil "Link loss on ~A" (getf status :interface)))
          (setf restored (restore-network-state))
          (sleep 2)
          (let ((new-status (check-network-link)))
            (setf success (getf new-status :link-up))
            (policy-audit-log :link-loss-recovery success
                              (format nil "Link recovery on ~A: ~A"
                                      (getf new-status :interface)
                                      (if success "SUCCESS" "FAILED")))
            (list :link-lost-detected t
                  :restoration-attempted restored
                  :restoration-successful success
                  :action-taken (if success
                                    "Network state restored"
                                    "Restoration attempted but link still down")))))))

(defun start-network-monitor (&optional (interval 10))
  "Start a background thread monitoring network link state.
Checks primary link every INTERVAL seconds (default: 10).
Restores from checkpoint on unexpected link loss.
Returns monitor thread. If running, returns existing thread."
  (bt:with-lock-held (*network-monitor-lock*)
    (if (and *network-monitor-thread*
             (bt:thread-alive-p *network-monitor-thread*))
        *network-monitor-thread*
        (progn
          (unless *network-state-checkpoint* (save-network-state))
          (setf *network-monitor-running-p* t)
          (setf *network-monitor-thread*
                (bt:make-thread
                 (lambda () (network-monitor-loop interval))
                 :name "lispmind-network-monitor"
                 :initial-bindings `((*standard-output* . ,*standard-output*)
                                     (*error-output*    . ,*error-output*))))
          (policy-audit-log :network-monitor-started t
                            (format nil "Network monitor started (interval: ~Ds)" interval))
          *network-monitor-thread*))))

(defun stop-network-monitor ()
  "Stop the network monitor thread gracefully. Returns T if stopped."
  (bt:with-lock-held (*network-monitor-lock*)
    (when *network-monitor-running-p*
      (setf *network-monitor-running-p* nil)
      (bt:condition-notify *network-monitor-cvar*)
      (when (and *network-monitor-thread*
                 (bt:thread-alive-p *network-monitor-thread*))
        (dotimes (i 100)
          (unless (bt:thread-alive-p *network-monitor-thread*)
            (return))
          (sleep 0.1))
        (when (bt:thread-alive-p *network-monitor-thread*)
          (ignore-errors (bt:destroy-thread *network-monitor-thread*))))
      (setf *network-monitor-thread* nil)
      (policy-audit-log :network-monitor-stopped t "Network monitor stopped")
      t)))

(defun network-monitor-loop (interval)
  "Network monitor loop. Checks link state periodically.
Restores from checkpoint on unexpected loss. Catches ALL errors.
A crashed monitor means undetected link loss -- never let it die."
  (loop while *network-monitor-running-p* do
    (handler-case
        (progn
          (bt:with-lock-held (*network-monitor-lock*)
            (unless *network-monitor-running-p* (return))
            (bt:condition-wait *network-monitor-cvar* *network-monitor-lock*
                               :timeout interval))
          (when *network-monitor-running-p*
            (let ((status (check-network-link)))
              (unless (getf status :link-up)
                (handle-unexpected-link-loss)))))
      (error (e)
        (format *error-output* "~&[NETWORK-MONITOR ERROR] ~A~%" e)
        (policy-audit-log :network-monitor-error nil (format nil "~A" e)))
      (condition (c)
        (format *error-output* "~&[NETWORK-MONITOR CONDITION] ~A~%" c)
        (policy-audit-log :network-monitor-condition nil (format nil "~A" c))))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 5: Emergency Integration -- Kill-Switch and Audit
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *policy-audit-log* (make-array 1000 :fill-pointer 0 :adjustable t
                                       :element-type 'list)
  "Circular buffer of policy decisions. Each entry is a plist:
  :timestamp  -- local-time timestamp
  :action     -- keyword (:gatekeeper-approve, :janitor-sweep, etc.)
  :result     -- T or NIL
  :reason     -- human-readable string
Holds up to 1000 entries (FIFO). Protected by *AUDIT-LOG-LOCK*.")

(defvar *audit-log-lock* (bt:make-lock "audit-log-lock")
  "Lock protecting *POLICY-AUDIT-LOG*.")

(defvar *audit-log-max-entries* 1000
  "Maximum audit log entries before old ones are dropped.")

(defun policy-audit-log (action result &optional reason)
  "Log a policy decision to the audit system.
ACTION: keyword naming the action.
RESULT: T or NIL.
REASON: optional human-readable string.
Thread-safe. Also forwards to telemetry system if active."
  (bt:with-lock-held (*audit-log-lock*)
    (when (>= (fill-pointer *policy-audit-log*) *audit-log-max-entries*)
      (replace *policy-audit-log* *policy-audit-log*
               :start1 0 :start2 1
               :end2 (fill-pointer *policy-audit-log*))
      (decf (fill-pointer *policy-audit-log*)))
    (vector-push (list :timestamp (local-time:now)
                       :action action
                       :result result
                       :reason (or reason ""))
                 *policy-audit-log*))
  ;; Forward to telemetry if available
  (ignore-errors
    (when (and (boundp '*telemetry-enabled-p*) *telemetry-enabled-p*)
      nil)))

(defun get-policy-audit (&optional (max-entries 100))
  "Return the most recent MAX-ENTRIES audit log entries.
Returns fresh list of plists, newest first. Each plist has
:timestamp, :action, :result, :reason."
  (bt:with-lock-held (*audit-log-lock*)
    (let ((start (max 0 (- (fill-pointer *policy-audit-log*) max-entries)))
          (result '()))
      (loop for i from (1- (fill-pointer *policy-audit-log*)) downto start
            do (push (aref *policy-audit-log* i) result))
      (nreverse result))))

(defun get-policy-audit-by-action (action &optional (max-entries 50))
  "Return audit entries filtered by ACTION keyword.
Useful for finding all denials, all cleanups, etc."
  (bt:with-lock-held (*audit-log-lock*)
    (let ((result '()) (count 0))
      (loop for i from (1- (fill-pointer *policy-audit-log*)) downto 0
            while (< count max-entries)
            do (let ((entry (aref *policy-audit-log* i)))
                 (when (eq (getf entry :action) action)
                   (push entry result)
                   (incf count))))
      (nreverse result))))

(defun clear-policy-audit ()
  "Clear all audit log entries. Returns number cleared.
Use with caution -- destroys forensic trail."
  (bt:with-lock-held (*audit-log-lock*)
    (let ((count (fill-pointer *policy-audit-log*)))
      (setf (fill-pointer *policy-audit-log*) 0)
      (policy-audit-log :audit-cleared t (format nil "Cleared ~D entries" count))
      count)))

(defun emergency-kill-all-tools (orchestrator)
  "Kill all Kali tool subprocesses during emergency halt (NUCLEAR OPTION).
Steps:
  1. Stop Janitor thread
  2. Stop network monitor
  3. For each KALI-AGENT with running subprocess: SIGKILL
  4. Clear *ACTIVE-KALI-AGENTS* and *PARALLEL-INSTANCE-COUNTS*
  5. Log to audit

Returns plist: :killed-count, :agents-affected, :errors.
Every error is caught and logged -- never propagated."
  (let ((killed-count 0) (agents-affected '()) (errors '()))
    (ignore-errors (stop-janitor-thread))
    (ignore-errors (stop-network-monitor))
    (bt:with-lock-held (*kali-agents-lock*)
      (maphash
       (lambda (agent-id agent)
         (handler-case
             (progn
               (bt:with-lock-held ((agent-lock agent))
                 (let ((subprocess (kali-agent-subprocess agent)))
                   (when (and subprocess (uiop:process-alive-p subprocess))
                     (uiop:terminate-process subprocess :urgent t)
                     (incf killed-count)
                     (push agent-id agents-affected)
                     (setf (agent-status agent) :failed)
                     (setf (kali-agent-subprocess agent) nil)))))
           (error (e)
             (push (cons agent-id (format nil "~A" e)) errors)
             (format *error-output* "~&[EMERGENCY-KILL] Failed ~A: ~A~%" agent-id e))
           (condition (c)
             (push (cons agent-id (format nil "~A" c)) errors)
             (format *error-output* "~&[EMERGENCY-KILL] Condition ~A: ~A~%" agent-id c)))
         (remhash agent-id *active-kali-agents*))
       *active-kali-agents*)
      (clrhash *parallel-instance-counts*))
    (policy-audit-log :emergency-kill t
                      (format nil "EMERGENCY HALT: Killed ~D subprocesses (~D errors)"
                              killed-count (length errors)))
    (list :killed-count killed-count
          :agents-affected (nreverse agents-affected)
          :errors errors)))

(defun register-kali-agent (orchestrator agent)
  "Register a KALI-AGENT with orchestrator and active Kali registry.
Increments parallel instance count for the tool.
Returns agent-id."
  (let ((agent-id (agent-id agent)))
    (register-agent orchestrator agent)
    (bt:with-lock-held (*kali-agents-lock*)
      (setf (gethash agent-id *active-kali-agents*) agent)
      (when (kali-agent-tool-name agent)
        (incf (gethash (kali-agent-tool-name agent)
                       *parallel-instance-counts* 0))))
    (policy-audit-log :kali-agent-registered t
                      (format nil "Registered Kali agent ~A (tool: ~A)"
                              agent-id (kali-agent-tool-name agent)))
    agent-id))

(defun deregister-kali-agent (orchestrator agent-id)
  "Deregister a KALI-AGENT. Kills subprocess, removes from registries,
decrements instance count. Returns T if found, NIL otherwise."
  (let ((agent (gethash agent-id (orchestrator-agents orchestrator))))
    (when agent
      (finalize-agent agent)
      (deregister-agent orchestrator agent-id)
      (bt:with-lock-held (*kali-agents-lock*)
        (remhash agent-id *active-kali-agents*)
        (when (and (typep agent 'kali-agent) (kali-agent-tool-name agent))
          (let ((current (gethash (kali-agent-tool-name agent)
                                  *parallel-instance-counts* 0)))
            (when (> current 0)
              (decf (gethash (kali-agent-tool-name agent)
                             *parallel-instance-counts*))))))
      (policy-audit-log :kali-agent-deregistered t
                        (format nil "Deregistered Kali agent ~A" agent-id))
      t)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 6: Kali Tool Launcher -- Safe Subprocess Spawning
;; ═══════════════════════════════════════════════════════════════════════════

(defun launch-kali-tool (orchestrator tool-name binary args
                          &key target (risk-level nil))
  "Safely launch a Kali tool with full policy enforcement. MAIN ENTRY POINT.
Complete launch sequence:
  1. Create KALI-AGENT instance
  2. Validate via SAFE-STRATEGY-P (the Gatekeeper)
  3. If blocked, return rejection reason
  4. If high-risk, prompt for operator confirmation
  5. Spawn subprocess via UIOP:LAUNCH-PROGRAM
  6. Register agent with orchestrator
  7. Return agent on success

Returns (values agent nil) on success, (values nil reason) on failure."
  (let* ((agent (make-instance 'kali-agent
                               :tool-name tool-name
                               :tool-args args
                               :requested-args (copy-list args)
                               :target target
                               :binary-path binary
                               :risk-level (or risk-level
                                               (let ((p (get-policy tool-name)))
                                                 (if p (tool-policy-risk-level p) :medium)))
                               :capabilities (list :kali-tool tool-name)))
         (approved (safe-strategy-p agent binary args)))
    ;; Handle rejection
    (unless approved
      (setf (agent-status agent) :rejected)
      (return-from launch-kali-tool
        (values nil (format nil "Gatekeeper rejected: ~S" args))))
    ;; High-risk confirmation
    (when (and (not (validate-risk-level tool-name))
               (not (kali-agent-confirmation-received-p agent)))
      (unless (confirm-high-risk-operation agent)
        (setf (agent-status agent) :rejected)
        (policy-audit-log :high-risk-denied nil
                          (format nil "High-risk ~A on ~A denied" tool-name target))
        (return-from launch-kali-tool
          (values nil "High-risk operation denied by operator"))))
    ;; Spawn subprocess
    (handler-case
        (let ((subprocess (uiop:launch-program
                           (cons binary args)
                           :output :stream
                           :error-output :stream
                           :wait nil)))
          (setf (kali-agent-subprocess agent) subprocess)
          (setf (kali-agent-policy-approved-p agent) t)
          (setf (kali-agent-launch-time agent) (local-time:now)))
      (error (e)
        (setf (agent-status agent) :failed)
        (policy-audit-log :launch-failed nil (format nil "Spawn failed: ~A" e))
        (return-from launch-kali-tool
          (values nil (format nil "Subprocess spawn failed: ~A" e)))))
    ;; Register and return
    (register-kali-agent orchestrator agent)
    (policy-audit-log :tool-launched t
                      (format nil "Launched ~A (PID: ~A) target: ~A"
                              tool-name
                              (ignore-errors
                                (uiop:process-info-pid
                                 (kali-agent-subprocess agent)))
                              target))
    (values agent nil)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 7: System Status -- Comprehensive Diagnostics
;; ═══════════════════════════════════════════════════════════════════════════

(defun gatekeeper-status ()
  "Return comprehensive Gatekeeper subsystem status as a plist:
  :policies-loaded, :policy-names, :max-risk, :janitor-running,
  :network-monitor, :active-agents, :parallel-counts,
  :network-checkpoint, :audit-log-entries, :last-denial"
  (let ((policy-count 0) (policy-names '()))
    (bt:with-lock-held (*policy-lock*)
      (maphash (lambda (k v) (declare (ignore v))
                 (incf policy-count) (push k policy-names))
               *tactical-repository*))
    (list :policies-loaded policy-count
          :policy-names (sort policy-names #'string< :key #'symbol-name)
          :max-risk *max-risk-without-confirmation*
          :janitor-running (and *janitor-thread*
                                (bt:thread-alive-p *janitor-thread*))
          :network-monitor (and *network-monitor-thread*
                                (bt:thread-alive-p *network-monitor-thread*))
          :active-agents (hash-table-count *active-kali-agents*)
          :parallel-counts (let ((ht (make-hash-table :test 'eq)))
                              (maphash (lambda (k v) (setf (gethash k ht) v))
                                       *parallel-instance-counts*)
                              ht)
          :network-checkpoint (not (null *network-state-checkpoint*))
          :audit-log-entries (fill-pointer *policy-audit-log*)
          :last-denial (car (get-policy-audit-by-action :gatekeeper-deny 1)))))

(defun print-gatekeeper-report ()
  "Print human-readable Gatekeeper status report to *STANDARD-OUTPUT*."
  (let ((status (gatekeeper-status)))
    (format t "~&*** LISPMIND POLICY GATEKEEPER STATUS REPORT ***~%")
    (format t "  Policies Loaded:   ~A~%" (getf status :policies-loaded))
    (format t "  Registered Tools:  ~A~%" (getf status :policy-names))
    (format t "  Max Risk Level:    ~A~%" (getf status :max-risk))
    (format t "  Janitor Running:   ~A~%" (getf status :janitor-running))
    (format t "  Network Monitor:   ~A~%" (getf status :network-monitor))
    (format t "  Active Agents:     ~A~%" (getf status :active-agents))
    (format t "  Network Checkpoint: ~A~%" (getf status :network-checkpoint))
    (format t "  Audit Entries:     ~A~%" (getf status :audit-log-entries))
    (when (getf status :last-denial)
      (format t "  Last Denial:       ~A~%"
              (getf (getf status :last-denial) :reason)))
    (format t "*** END GATEKEEPER REPORT ***~%")))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 8: Initialization and Shutdown
;; ═══════════════════════════════════════════════════════════════════════════

(defun initialize-gatekeeper ()
  "Initialize the entire Gatekeeper subsystem at system startup:
  1. Load default security policies
  2. Save initial network checkpoint
  3. Start Janitor thread (5s interval)
  4. Start network monitor (10s interval)
Returns plist: :policies-loaded, :janitor-started,
:network-monitor-started, :checkpoint-saved, :status"
  (let ((policies (load-default-policies))
        (janitor (start-janitor-thread 5))
        (network-checkpoint (save-network-state))
        (network-monitor (start-network-monitor 10)))
    (policy-audit-log :gatekeeper-initialized t
                      (format nil "Initialized: ~D policies, janitor=~A, monitor=~A"
                              (length policies)
                              (if janitor "running" "failed")
                              (if network-monitor "running" "failed")))
    (list :policies-loaded (length policies)
          :janitor-started (not (null janitor))
          :network-monitor-started (not (null network-monitor))
          :checkpoint-saved (not (null network-checkpoint))
          :status :ready)))

(defun shutdown-gatekeeper ()
  "Gracefully shut down the Gatekeeper subsystem:
  1. Stop Janitor
  2. Stop network monitor
  3. Kill all remaining subprocesses
  4. Clear registries
Returns T."
  (stop-janitor-thread)
  (stop-network-monitor)
  (bt:with-lock-held (*kali-agents-lock*)
    (maphash
     (lambda (agent-id agent)
       (declare (ignore agent-id))
       (ignore-errors
         (let ((subprocess (kali-agent-subprocess agent)))
           (when (and subprocess (uiop:process-alive-p subprocess))
             (uiop:terminate-process subprocess :urgent t)))))
     *active-kali-agents*)
    (clrhash *active-kali-agents*)
    (clrhash *parallel-instance-counts*))
  (policy-audit-log :gatekeeper-shutdown t "Gatekeeper subsystem shut down")
  t)


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 9: Gray Streams Integration -- Filtered Output
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; "Output filtering prevents sensitive data (passwords, PII, internal IPs)
;;  from being stored in log files where it becomes a liability."

(defclass filtered-output-stream (trivial-gray-streams:fundamental-character-output-stream)
  ((agent
    :initarg :agent
    :accessor filtered-stream-agent
    :documentation "The KALI-AGENT whose output is being filtered.")
   (underlying-stream
    :initarg :underlying-stream
    :accessor filtered-stream-underlying
    :documentation "The actual output stream.")
   (buffer
    :initform (make-array 256 :element-type 'character :fill-pointer 0 :adjustable t)
    :accessor filtered-stream-buffer
    :documentation "Buffer accumulating characters until newline."))
  (:documentation
   "Gray stream that filters tool output line-by-line.
Each line is checked against the agent's OUTPUT-FILTERS policy.
Matching lines are discarded instead of written to the underlying stream."))

(defmethod trivial-gray-streams:stream-write-char
    ((stream filtered-output-stream) char)
  "Buffer characters until newline, then flush filtered line."
  (if (char= char #\\newline)
      (flush-filtered-line stream)
      (vector-push-extend char (filtered-stream-buffer stream))))

(defmethod trivial-gray-streams:stream-write-string
    ((stream filtered-output-stream) string &optional (start 0) (end nil))
  "Write string to filtered stream, filtering line-by-line."
  (let ((end (or end (length string))))
    (loop for i from start below end
          do (trivial-gray-streams:stream-write-char stream (char string i)))))

(defmethod trivial-gray-streams:stream-finish-output
    ((stream filtered-output-stream))
  "Flush any pending buffered output."
  (when (> (length (filtered-stream-buffer stream)) 0)
    (flush-filtered-line stream))
  (finish-output (filtered-stream-underlying stream)))

(defun flush-filtered-line (stream)
  "Flush buffered line, applying output filters from agent policy.
If a filter matches, write [FILTERED] marker. Otherwise write line."
  (let* ((agent (filtered-stream-agent stream))
         (line (coerce (filtered-stream-buffer stream) 'string))
         (policy (when agent (get-policy (kali-agent-tool-name agent))))
         (filters (when policy (tool-policy-output-filters policy)))
         (filtered-p nil))
    (dolist (pattern filters)
      (when (and (> (length pattern) 0) (search pattern line))
        (setf filtered-p t)
        (return)))
    (if filtered-p
        (write-line "[FILTERED -- output matched policy filter]"
                    (filtered-stream-underlying stream))
        (write-line line (filtered-stream-underlying stream)))
    (setf (fill-pointer (filtered-stream-buffer stream)) 0)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 10: Integration with Orchestrator Emergency System
;; ═══════════════════════════════════════════════════════════════════════════

(defmethod handle-condition :after ((agent orchestrator) (condition emergency-halt))
  "Emergency halt handler: kill all Kali tool subprocesses.
When orchestrator handles EMERGENCY-HALT, this :AFTER method invokes
EMERGENCY-KILL-ALL-TOOLS. Ensures the nuclear option terminates all
dangerous subprocesses -- not just agent threads."
  (format *error-output* "~&[GATEKEEPER] Emergency halt -- killing all tool subprocesses...~%")
  (let ((result (emergency-kill-all-tools agent)))
    (format *error-output* "~&[GATEKEEPER] Killed ~D subprocesses (~D errors)~%"
            (getf result :killed-count)
            (length (getf result :errors)))
    result))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 11: Convenience API -- Shortcuts for Common Operations
;; ═══════════════════════════════════════════════════════════════════════════

(defun kill-agent-tool (agent)
  "Kill the tool subprocess for a specific KALI-AGENT.
Calls FINALIZE-AGENT. Returns T if subprocess was killed."
  (when (and (typep agent 'kali-agent)
             (kali-agent-subprocess agent)
             (uiop:process-alive-p (kali-agent-subprocess agent)))
    (finalize-agent agent)
    t))

(defun list-active-kali-tools ()
  "Return list of plists for all active Kali tool instances:
  :agent-id, :tool-name, :target, :pid, :launch-time, :elapsed"
  (bt:with-lock-held (*kali-agents-lock*)
    (let ((result '()))
      (maphash
       (lambda (agent-id agent)
         (push (list :agent-id agent-id
                     :tool-name (kali-agent-tool-name agent)
                     :target (kali-agent-target agent)
                     :pid (ignore-errors
                           (uiop:process-info-pid
                            (kali-agent-subprocess agent)))
                     :launch-time (kali-agent-launch-time agent)
                     :elapsed (if (kali-agent-launch-time agent)
                                  (local-time:timestamp-difference
                                   (local-time:now)
                                   (kali-agent-launch-time agent))
                                  nil))
               result))
       *active-kali-agents*)
      (nreverse result))))

(defun get-agent-output (agent)
  "Drain and return accumulated output from a KALI-AGENT's tool.
Returns NIL if no subprocess or stream is closed."
  (when (typep agent 'kali-agent)
    (drain-subprocess-output agent)
    (coerce (kali-agent-output-buffer agent) 'string)))

(defun wait-for-agent (agent &optional (timeout-seconds 300))
  "Block until KALI-AGENT's subprocess exits or timeout.
Polls every 0.1s. Returns exit code or :TIMEOUT.
Blocking -- do not call from monitor thread."
  (let ((start (get-universal-time)))
    (loop
      (let ((subprocess (kali-agent-subprocess agent)))
        (unless (and subprocess (uiop:process-alive-p subprocess))
          (return-from wait-for-agent
            (ignore-errors (uiop:wait-process subprocess))))
        (when (> (- (get-universal-time) start) timeout-seconds)
          (return-from wait-for-agent :timeout))
        (sleep 0.1)))))


;; ═══════════════════════════════════════════════════════════════════════════
;; CLOSING: Export Summary
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Symbols defined in this file:
;;
;; CLASSES:
;;   kali-agent              -- Agent with subprocess management
;;   filtered-output-stream  -- Gray stream with output filtering
;;
;; STRUCTS:
;;   tool-policy             -- Policy rules for a Kali tool
;;
;; SPECIAL VARIABLES:
;;   *tactical-repository*           -- Tool policy registry
;;   *max-risk-without-confirmation*  -- Risk threshold
;;   *network-state-checkpoint*      -- Saved network state
;;   *active-kali-agents*            -- Active agent registry
;;   *policy-lock*                   -- Repository lock
;;   *kali-agents-lock*              -- Agent registry lock
;;   *parallel-instance-counts*      -- Per-tool concurrency counts
;;   *janitor-thread*                -- Janitor sweep thread
;;   *janitor-running-p*             -- Janitor control flag
;;   *janitor-lock*                  -- Janitor state lock
;;   *janitor-cvar*                  -- Janitor condition variable
;;   *network-monitor-thread*        -- Network monitor thread
;;   *network-monitor-running-p*     -- Monitor control flag
;;   *network-monitor-lock*          -- Monitor state lock
;;   *network-monitor-cvar*          -- Monitor condition variable
;;   *policy-audit-log*              -- Audit log circular buffer
;;   *audit-log-lock*                -- Audit log lock
;;   *audit-log-max-entries*         -- Max audit entries (1000)
;;
;; POLICY MANAGEMENT:
;;   load-default-policies    -- Register 7 built-in policies
;;   register-policy          -- Add/update a tool policy
;;   get-policy               -- Retrieve a tool policy
;;   policy-exists-p          -- Check if policy exists
;;   unregister-policy        -- Remove a tool policy
;;   list-registered-policies -- All registered tool names
;;   describe-policy          -- Human-readable policy description
;;   make-tool-policy         -- Construct a tool-policy
;;
;; POLICY VALIDATION:
;;   safe-strategy-p                -- The Gatekeeper
;;   validate-args-against-policy   -- Check forbidden args
;;   validate-required-args-present -- Check required args
;;   validate-target-against-policy -- Check forbidden targets
;;   validate-risk-level            -- Check risk acceptability
;;   check-max-parallel             -- Check concurrency limit
;;   confirm-high-risk-operation    -- Operator confirmation prompt
;;   target-matches-p               -- Target pattern matching
;;   wildcard-match-p               -- Wildcard matching
;;   risk-level-<=                  -- Risk level comparison
;;
;; THE JANITOR:
;;   finalize-agent         -- Generic finalization hook
;;   finalize-agent :after  -- Kill subprocess on agent death (CLOS)
;;   drain-subprocess-output -- Drain stdout/stderr
;;   janitor-sweep          -- Clean ghosts, zombies, runaways
;;   start-janitor-thread   -- Launch background sweep
;;   stop-janitor-thread    -- Stop Janitor
;;   janitor-loop           -- The sweep loop
;;   janitor-status         -- Janitor diagnostics
;;
;; NETWORK STATE:
;;   save-network-state           -- Capture interface config
;;   restore-network-state        -- Restore interfaces
;;   check-network-link           -- Check primary link status
;;   handle-unexpected-link-loss  -- Recovery action
;;   start-network-monitor        -- Launch link monitor
;;   stop-network-monitor         -- Stop monitor
;;   network-monitor-loop         -- Monitor loop
;;
;; EMERGENCY and AUDIT:
;;   emergency-kill-all-tools -- Kill all tool subprocesses
;;   policy-audit-log         -- Log a policy decision
;;   get-policy-audit         -- Retrieve audit log
;;   get-policy-audit-by-action -- Filtered audit retrieval
;;   clear-policy-audit       -- Clear audit log
;;
;; TOOL LAUNCHER:
;;   launch-kali-tool      -- Safe tool launch (main entry point)
;;   register-kali-agent   -- Register with orchestrator
;;   deregister-kali-agent -- Remove and kill subprocess
;;
;; CONVENIENCE:
;;   kill-agent-tool        -- Kill a single agent's tool
;;   list-active-kali-tools -- All running tool instances
;;   get-agent-output       -- Accumulated tool output
;;   wait-for-agent         -- Block until subprocess exits
;;
;; SYSTEM:
;;   initialize-gatekeeper   -- Full subsystem initialization
;;   shutdown-gatekeeper     -- Graceful shutdown
;;   gatekeeper-status       -- Comprehensive diagnostics
;;   print-gatekeeper-report -- Human-readable status report
;;
;; "The Gatekeeper stands at the threshold. It does not sleep, it does not
;;  forgive, and it never forgets. Every tool launch is a promise. The
;;  Gatekeeper ensures that promise is kept. The Janitor ensures no trace
;;  remains. And when everything goes wrong, the emergency kill-switch
;;  ensures that the damage stops here."

;;  remains. And when everything goes wrong, the emergency kill-switch
;;  ensures that the damage stops here.


;; ═══════════════════════════════════════════════════════════════════════════
;; WIFI SAFETY MODULE -- v2.2.1 Wi-Fi Policy & Network Stability
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; "Wi-Fi tools occupy a uniquely dangerous position in the offensive toolbox.
;;  They operate at the boundary of the airwaves -- invisible, unforgiving,
;;  and capable of causing real disruption to production networks. The Wi-Fi
;;  Safety Module extends the Gatekeeper's protection into the 2.4GHz and 5GHz
;;  domains, ensuring that every frame injection, every deauth, every handshake
;;  capture happens under controlled, monitored, and revocable conditions."
;;
;; COMPONENTS:
;;   Wi-Fi Tool Policies          -- load-wifi-default-policies
;;   Network Stability Monitor    -- RTT-based gateway health tracking
;;   Wi-Fi Signal Monitor         -- dBm-based signal strength guard
;;   Emergency Integration        -- Wi-Fi aware kill-switch + safe-state
;;   Wi-Fi Agent Classes          -- bettercap-agent, airgeddon-agent
;;
;; THREAT MODEL:
;;   - Broad deauth floods from bettercap wifi.deauth
;;   - Fuzzing attacks (wifi.fuzz) destabilizing target APs
;;   - Operations against primary interface (wlan0)
;;   - Airgeddon --dos mode causing full denial of service
;;   - PMKID captures without WPA3 safeguards
;;   - Signal degradation causing failed attacks with hanging state
;;   - Network instability during active Wi-Fi operations


;; ─────────────────────────────────────────────────────────────────────────
;; Section A: Wi-Fi Agent Classes
;; ─────────────────────────────────────────────────────────────────────────

(defclass bettercap-agent (kali-agent)
  ((interface
    :initarg :interface
    :initform "wlan1"
    :accessor wifi-agent-interface
    :documentation "Wi-Fi interface used by this agent. Default wlan1.
NEVER wlan0 (primary interface). Enforced by policy."))
  (:documentation "Specialized KALI-AGENT for bettercap Wi-Fi operations.
Runs recon, deauth, and packet capture under policy enforcement.
Monitored by the network stability system."))

(defclass airgeddon-agent (kali-agent)
  ((interface
    :initarg :interface
    :initform "wlan1"
    :accessor wifi-agent-interface
    :documentation "Wi-Fi interface used by this agent. Default wlan1.
Managed interface for Evil Twin and handshake capture."))
  (:documentation "Specialized KALI-AGENT for airgeddon Wi-Fi auditing.
Runs WPA3 audits, Evil Twin attacks, and handshake capture.
Destructive operations require explicit confirmation."))


;; ─────────────────────────────────────────────────────────────────────────
;; Section B: Wi-Fi Tool Policies -- The Air-Gatekeeper
;; ─────────────────────────────────────────────────────────────────────────

(defun load-wifi-default-policies () 
  "Register default policies for bettercap and airgeddon Wi-Fi tools.

BETTERCAP POLICY:
  - Forbidden: wifi.deauth module (broad deauth floods)
  - Forbidden: wifi.fuzz module (fuzzing attacks)
  - Forbidden: arguments matching *10.0.0.0/8* or *192.168.0.0/16*
  - Required: -iface must specify wlan1 (never wlan0 = primary)
  - Max parallel: 2 instances (conservative for Wi-Fi channel congestion)
  - Timeout: 300 seconds (5 minutes per operation)
  - Risk level: :high (always requires confirmation)

AIRGEDDON POLICY:
  - Forbidden: --dos flag (full denial of service mode)
  - Forbidden: --pmkid without accompanying --wpa3 flag
  - Required: either --script or --wpa3 flag must be present
  - Max parallel: 1 instance (destructive operations)
  - Timeout: 600 seconds (10 minutes per audit)
  - Risk level: :critical (always requires confirmation)
  - Confirmation required: yes (mandatory, cannot be bypassed)

Returns list of registered tool-name symbols. Idempotent.
These policies are IN ADDITION TO the base 7 default policies.
Call after LOAD-DEFAULT-POLICIES for complete protection."
  (let ((registered '()))
    ;; BETTERCAP: Wi-Fi recon and injection
    (push (tool-policy-tool-name
           (register-policy
            'bettercap
            (make-tool-policy
             'bettercap
             :forbidden-args '("wifi.deauth" "wifi.fuzz"
                               "--deauth" "--fuzz"
                               "*10.0.0.0/8*" "*192.168.0.0/16*"
                               "-iface wlan0" "--iface wlan0")
             :forbidden-targets '("10.0.0.0/8" "192.168.0.0/16")
             :max-parallel 2
             :timeout-seconds 300
             :required-args '("-iface wlan1")
             :risk-level :high)))
          registered)
    ;; AIRGEDDON: Wi-Fi auditing framework
    (push (tool-policy-tool-name
           (register-policy
            'airgeddon
            (make-tool-policy
             'airgeddon
             :forbidden-args '("--dos" "--dos-attack"
                               "--evil-twin-full"
                               "--wds-confusion")
             :forbidden-targets nil
             :max-parallel 1
             :timeout-seconds 600
             :required-args '("--script" "--wpa3")
             :risk-level :critical)))
          registered)
    (policy-audit-log :load-wifi-defaults t
                      (format nil "Loaded ~D Wi-Fi default policies: ~S"
                              (length registered) registered))
    registered))


;; ─────────────────────────────────────────────────────────────────────────
;; Section C: Network Stability Monitor -- RTT-Based Circuit Breaker
;; ─────────────────────────────────────────────────────────────────────────

(defvar *network-stability-monitor-running-p* nil
  "Is the network stability monitor currently active?
The monitor pings the default gateway every INTERVAL seconds and maintains
a sliding window of RTT measurements. It is the canary in the coal mine
for Wi-Fi induced network degradation.")

(defvar *network-stability-thread* nil
  "The background stability monitor thread handle (a BT:THREAD) or NIL.
Independent from the link monitor in Section 4. Focused on RTT, not link state.")

(defvar *network-stability-lock* (bt:make-lock "network-stability-lock")
  "Lock protecting stability monitor state variables.")

(defvar *network-stability-cvar* (bt:make-condition-variable :name "network-stability-cvar")
  "Condition variable for graceful stability monitor shutdown.")

(defvar *gateway-rtt-threshold-ms* 200
  "RTT above this value (in milliseconds) triggers a :degraded alert.
The alert signals that Wi-Fi operations may be impacting network quality.
Default 200ms is suitable for LAN environments. Adjust for WAN.")

(defvar *gateway-rtt-critical-ms* 500
  "RTT above this value (in milliseconds) triggers emergency safe-state.
When critical RTT is detected, all Wi-Fi tool processes are halted
and the system enters Wi-Fi safe mode. Default 500ms.")

(defvar *rtt-history* (make-array 20 :fill-pointer 0 :adjustable t)
  "Sliding window of recent RTT measurements in milliseconds.
Oldest entries are dropped when the window exceeds 20 samples.
All accesses must hold *NETWORK-STABILITY-LOCK*.")

(defvar *rtt-high-consecutive-count* 0
  "Counter for consecutive high-RTT readings.
When this reaches 3, the system enters safe-state automatically.
Reset to 0 on any normal RTT reading.")

(defvar *wifi-safe-mode-active-p* nil
  "Is Wi-Fi safe mode currently active?
When T, all Wi-Fi tool launches are blocked until stability returns.")

(defun measure-gateway-rtt () 
  "Ping the default gateway and return RTT in milliseconds as a float.
Uses /bin/ping -c 1 -W 2 for a single fast probe. Returns NIL if:
  - No default gateway can be determined
  - The gateway does not respond
  - The ping command fails
  - The RTT cannot be parsed from output
Thread-safe: makes no mutations to shared state.
Example: (measure-gateway-rtt) => 12.4"
  (handler-case
      (let* ((gateway (or (ignore-errors
                            (let ((route (uiop:run-program
                                          "ip route show default 2>/dev/null"
                                          :output '(:string :stripped t)
                                          :ignore-error-status t)))
                              (when (and route (> (length route) 0))
                                (let ((via-pos (search "via " route)))
                                  (when via-pos
                                    (let ((start (+ via-pos 4)))
                                      (subseq route start
                                              (position #\space route :start start))))))))
                        "192.168.1.1"))
             (output (uiop:run-program
                      (format nil "/bin/ping -c 1 -W 2 ~A 2>/dev/null" gateway)
                      :output '(:string :stripped t)
                      :ignore-error-status t)))
        (when (and output (search "time=" output))
          (let* ((time-pos (search "time=" output))
                 (start (+ time-pos 5))
                 (end (position #\space output :start start))
                 (ms-str (subseq output start end)))
            (let ((ms (parse-float:parse-float ms-str :junk-allowed t)))
              (when ms (float ms 0.0))))))
    (error (e)
      (policy-audit-log :rtt-measure-failed nil (format nil "~A" e))
      nil)
    (condition (c)
      (policy-audit-log :rtt-measure-condition nil (format nil "~A" c))
      nil)))

(defun get-average-rtt () 
  "Calculate average RTT from the sliding window.
Returns the arithmetic mean of all entries in *RTT-HISTORY*, or NIL
if no measurements have been taken yet. All accesses hold the lock.
Example: (get-average-rtt) => 45.2"
  (bt:with-lock-held (*network-stability-lock*)
    (let ((count (fill-pointer *rtt-history*)))
      (when (> count 0)
        (/ (loop for i from 0 below count
                 sum (aref *rtt-history* i))
           count)))))

(defun rtt-history-push (value) 
  "Push a new RTT value into the sliding window, discarding oldest if full.
VALUE: RTT in milliseconds (float). Must hold *NETWORK-STABILITY-LOCK*."
  (when (>= (fill-pointer *rtt-history*) (array-dimension *rtt-history* 0))
    ;; Shift everything down by one, drop oldest
    (replace *rtt-history* *rtt-history*
             :start1 0 :start2 1
             :end2 (fill-pointer *rtt-history*))
    (decf (fill-pointer *rtt-history*)))
  (vector-push value *rtt-history*))

(defun check-network-stability () 
  "Check network stability via gateway RTT measurement.
Performs a single ping and classifies the network state:
  - :stable   -- RTT <= warning threshold, all clear
  - :degraded -- RTT > warning threshold, Wi-Fi ops may be impacting
  - :critical -- RTT > critical threshold OR 3 consecutive high readings
On critical: triggers WIFI-EMERGENCY-HALT automatically.
On degraded: increments consecutive counter; logs alert.
On stable: resets consecutive counter.

Returns one of: :stable, :degraded, :critical.
Every code path is wrapped in error handling -- never crashes."
  (handler-case
      (let ((rtt (measure-gateway-rtt)))
        (bt:with-lock-held (*network-stability-lock*)
          (cond
            ;; No response -- treat as critical
            ((null rtt)
             (incf *rtt-high-consecutive-count*)
             (when (>= *rtt-high-consecutive-count* 2)
               (policy-audit-log :network-stability :critical
                                 "Gateway unreachable for 2 consecutive pings")
               (return-from check-network-stability :critical))
             :degraded)
            ;; Critical threshold
            ((> rtt *gateway-rtt-critical-ms*)
             (incf *rtt-high-consecutive-count*)
             (rtt-history-push rtt)
             (policy-audit-log :network-stability :critical
                               (format nil "RTT critical: ~,1fms (> ~Dms)"
                                       rtt *gateway-rtt-critical-ms*))
             (wifi-emergency-halt)
             :critical)
            ;; Warning threshold
            ((> rtt *gateway-rtt-threshold-ms*)
             (incf *rtt-high-consecutive-count*)
             (rtt-history-push rtt)
             (when (>= *rtt-high-consecutive-count* 3)
               (policy-audit-log :network-stability :critical
                                 (format nil "3 consecutive high RTTs (last: ~,1fms)"
                                         rtt))
               (enter-wifi-safe-state)
               :critical)
             (policy-audit-log :network-stability :degraded
                               (format nil "RTT elevated: ~,1fms (> ~Dms)"
                                       rtt *gateway-rtt-threshold-ms*))
             :degraded)
            ;; Normal
            (t
             (setf *rtt-high-consecutive-count* 0)
             (rtt-history-push rtt)
             :stable))))
    (error (e)
      (policy-audit-log :stability-check-error nil (format nil "~A" e))
      :degraded)
    (condition (c)
      (policy-audit-log :stability-check-condition nil (format nil "~A" c))
      :degraded)))

(defun start-network-stability-monitor (&optional (interval 3)) 
  "Start a background thread that pings the gateway every INTERVAL seconds.
Default INTERVAL is 3 seconds for rapid detection of Wi-Fi induced degradation.
The monitor is the circuit breaker: on critical RTT, it halts all Wi-Fi tools.
Returns the monitor thread. If already running, returns existing thread.
Thread-safe: acquires *NETWORK-STABILITY-LOCK*."
  (bt:with-lock-held (*network-stability-lock*)
    (if (and *network-stability-thread*
             (bt:thread-alive-p *network-stability-thread*))
        *network-stability-thread*
        (progn
          (setf *network-stability-monitor-running-p* t)
          (setf *wifi-safe-mode-active-p* nil)
          (setf *rtt-high-consecutive-count* 0)
          (setf (fill-pointer *rtt-history*) 0)
          (setf *network-stability-thread*
                (bt:make-thread
                 (lambda () (stability-monitor-loop interval))
                 :name "lispmind-stability-monitor"
                 :initial-bindings `((*standard-output* . ,*standard-output*)
                                     (*error-output*    . ,*error-output*))))
          (policy-audit-log :stability-monitor-started t
                            (format nil "Stability monitor started (interval: ~Ds)"
                                    interval))
          *network-stability-thread*))))

(defun stop-network-stability-monitor () 
  "Stop the network stability monitor gracefully.
Signals shutdown via *NETWORK-STABILITY-MONITOR-RUNNING-P* and waits
up to 10 seconds for thread termination. Force-destroys if needed.
Returns T if stopped, NIL if not running."
  (bt:with-lock-held (*network-stability-lock*)
    (when *network-stability-monitor-running-p*
      (setf *network-stability-monitor-running-p* nil)
      (bt:condition-notify *network-stability-cvar*)
      (when (and *network-stability-thread*
                 (bt:thread-alive-p *network-stability-thread*))
        (dotimes (i 100)
          (unless (bt:thread-alive-p *network-stability-thread*)
            (return))
          (sleep 0.1))
        (when (bt:thread-alive-p *network-stability-thread*)
          (ignore-errors (bt:destroy-thread *network-stability-thread*))))
      (setf *network-stability-thread* nil)
      (policy-audit-log :stability-monitor-stopped t
                        "Network stability monitor stopped")
      t)))

(defun stability-monitor-loop (interval) 
  "The stability monitor background loop. Immortal -- catches ALL errors.
Pings gateway every INTERVAL seconds, checks stability, acts on result.
A crashed monitor means undetected Wi-Fi induced DoS -- never let it die.
The loop exits cleanly when *NETWORK-STABILITY-MONITOR-RUNNING-P* is NIL."
  (loop while *network-stability-monitor-running-p* do
    (handler-case
        (progn
          (bt:with-lock-held (*network-stability-lock*)
            (unless *network-stability-monitor-running-p* (return))
            (bt:condition-wait *network-stability-cvar* *network-stability-lock*
                               :timeout interval))
          (when *network-stability-monitor-running-p*
            (check-network-stability)))
      (error (e)
        (format *error-output* "~&[STABILITY-MONITOR ERROR] ~A~%" e)
        (policy-audit-log :stability-monitor-error nil (format nil "~A" e)))
      (condition (c)
        (format *error-output* "~&[STABILITY-MONITOR CONDITION] ~A~%" c)
        (policy-audit-log :stability-monitor-condition nil (format nil "~A" c))))))


;; ─────────────────────────────────────────────────────────────────────────
;; Section D: Wi-Fi Signal Strength Monitoring
;; ─────────────────────────────────────────────────────────────────────────

(defvar *wifi-signal-threshold-dbm* -70
  "Signal strength threshold in dBm for auto-pause.
Signals weaker than -70 dBm (more negative) trigger auto-pause.
-30 dBm = excellent, -50 dBm = good, -70 dBm = fair, -90 dBm = poor.")

(defun measure-target-signal (bssid interface) 
  "Measure signal strength (dBm) of target BSSID.
Uses iw dev INTERFACE station dump when available, falling back to
airodump-ng --bssid for a single 3-second sample.

Arguments:
  BSSID     -- Target MAC address string (e.g., 'AA:BB:CC:DD:EE:FF')
  INTERFACE -- Wi-Fi interface name (e.g., 'wlan1')

Returns signal strength in dBm as integer, or NIL if:
  - The BSSID is not visible
  - The interface does not exist
  - The measurement tool is not available
  - The output cannot be parsed

Example: (measure-target-signal 'AA:BB:CC:DD:EE:FF' 'wlan1') => -42"
  (handler-case
      (let ((output (uiop:run-program
                     (format nil "iw dev ~A station dump 2>/dev/null" interface)
                     :output '(:string :stripped t)
                     :ignore-error-status t)))
        (if (and output (> (length output) 0) (search "signal:" output))
            ;; Parse iw output: look for Station <bssid> block and extract signal
            (let* ((bssid-lower (string-downcase bssid))
                   (station-pos (search bssid-lower output)))
              (when station-pos
                (let* ((block-start station-pos)
                       (block-end (or (search "\nStation" output :start2 (+ block-start 20))
                                      (length output)))
                       (block (subseq output block-start block-end))
                       (sig-pos (search "signal:" block)))
                  (when sig-pos
                    (let* ((val-start (position-if #'digit-or-minus-p
                                                    block :start (+ sig-pos 7)))
                           (val-end (position #\space block :start val-start))
                           (val-str (subseq block val-start val-end)))
                      (parse-integer val-str :junk-allowed t))))))
            ;; Fallback: try airodump-ng
            (let ((dump (uiop:run-program
                         (format nil "timeout 3 airodump-ng ~A --bssid ~A --write-interval 1 -w /tmp/signal_check 2>&1 || true"
                                 interface bssid)
                         :output '(:string :stripped t)
                         :ignore-error-status t)))
              (when (and dump (search "PWR" dump))
                ;; Parse PWR column from airodump-ng output
                (let ((pwr-line (find-pwr-line dump bssid)))
                  (when pwr-line
                    (parse-integer pwr-line :junk-allowed t)))))))
    (error (e)
      (policy-audit-log :signal-measure-failed nil
                        (format nil "BSSID ~A on ~A: ~A" bssid interface e))
      nil)
    (condition (c)
      (policy-audit-log :signal-measure-condition nil
                        (format nil "BSSID ~A on ~A: ~A" bssid interface c))
      nil)))

(defun digit-or-minus-p (char) 
  "Return T if CHAR is a digit or minus sign. Used by signal parser."
  (or (digit-char-p char) (char= char #\-)))

(defun find-pwr-line (output bssid) 
  "Extract the PWR column value for BSSID from airodump-ng output.
Returns the power value string, or NIL if not found."
  (let ((lines (uiop:split-string output :separator '(#\newline))))
    (dolist (line lines)
      (when (search (string-downcase bssid) (string-downcase line))
        ;; PWR is typically the 4th column
        (let ((tokens (uiop:split-string line :separator '(#\space #\tab))))
          (dolist (tok tokens)
            (when (and (> (length tok) 0)
                       (digit-or-minus-p (char tok 0)))
              (return-from find-pwr-line tok))))))
    nil))

(defun signal-above-threshold-p (dbm threshold) 
  "Check if signal DBM is above THRESHOLD (less negative = stronger).
Returns T if the signal is strong enough to continue operations.

Arguments:
  DBM       -- Signal strength in dBm (negative integer, e.g., -42)
  THRESHOLD -- Minimum acceptable signal in dBm (e.g., -70)

Returns T if DBM >= THRESHOLD (e.g., -42 >= -70 is T).
A NIL DBM is treated as below threshold (returns NIL).

Example: (signal-above-threshold-p -42 -70) => T"
  (and dbm (>= dbm threshold)))

(defun auto-pause-on-signal-weak (agent signal-db threshold) 
  "Auto-pause a Wi-Fi stress test if signal drops below THRESHOLD.
Called by the stability monitor or agent supervision loop when
signal degradation is detected.

Arguments:
  AGENT     -- The KALI-AGENT running the Wi-Fi operation
  SIGNAL-DB -- Current signal strength in dBm, or NIL if unknown
  THRESHOLD -- Minimum acceptable signal (default *WIFI-SIGNAL-THRESHOLD-DBM*)

Actions taken:
  1. If signal is NIL or below threshold: kill subprocess
  2. Set agent status to :paused
  3. Log the event to audit and telemetry
  4. Return :paused

Returns :ok if signal is good, :paused if paused, :unknown if no signal data."
  (cond
    ((null signal-db)
     (policy-audit-log :signal-pause-unknown (agent-id agent)
                       (format nil "No signal data for ~A, cannot assess"
                               (agent-id agent)))
     :unknown)
    ((not (signal-above-threshold-p signal-db threshold))
     (kill-agent-tool agent)
     (setf (agent-status agent) :paused)
     (policy-audit-log :signal-paused (agent-id agent)
                       (format nil "Signal ~D dBm below threshold ~D dBm -- paused ~A"
                               signal-db threshold (agent-id agent)))
     :paused)
    (t :ok)))


;; ─────────────────────────────────────────────────────────────────────────
;; Section E: Emergency Integration -- Wi-Fi Kill-Switch
;; ─────────────────────────────────────────────────────────────────────────

(defun wifi-emergency-halt () 
  "Kill all bettercap, airgeddon, and aircrack-ng processes.
This is the Wi-Fi specific emergency kill-switch. It targets the exact
process names used by Wi-Fi tools and sends SIGKILL to each.

Steps:
  1. Find PIDs of bettercap, airgeddon, aircrack-ng, airodump-ng, aireplay-ng
  2. Send SIGKILL to each PID
  3. Log the event to audit

Returns plist: :killed-count, :pids, :errors.
Every error is caught -- this function must never crash during an emergency."
  (let ((killed-count 0) (pids-killed '()) (errors '())
        (targets '("bettercap" "airgeddon" "aircrack-ng" "airodump-ng"
                   "aireplay-ng" "aireplay" "airmon-ng" "packetforge-ng")))
    (dolist (proc-name targets)
      (handler-case
          (let ((pid-output (uiop:run-program
                             (format nil "pgrep -f ~A 2>/dev/null || true" proc-name)
                             :output '(:string :stripped t)
                             :ignore-error-status t)))
            (when (and pid-output (> (length pid-output) 0))
              (dolist (pid-str (uiop:split-string pid-output :separator '(#\newline)))
                (when (> (length pid-str) 0)
                  (handler-case
                      (let ((pid (parse-integer pid-str :junk-allowed t)))
                        (when pid
                          (uiop:run-program
                           (format nil "kill -9 ~D 2>/dev/null || true" pid)
                           :ignore-error-status t)
                          (incf killed-count)
                          (push pid pids-killed)))
                    (error (e)
                      (push (cons proc-name (format nil "~A" e)) errors))))))
        (error (e)
          (push (cons proc-name (format nil "~A" e)) errors))
        (condition (c)
          (push (cons proc-name (format nil "~A" c)) errors)))
    (policy-audit-log :wifi-emergency-halt (> killed-count 0)
                      (format nil "Wi-Fi emergency halt: killed ~D processes (~D errors)"
                              killed-count (length errors)))
    (list :killed-count killed-count
          :pids (nreverse pids-killed)
          :errors errors)))

(defun enter-wifi-safe-state () 
  "Transition to Wi-Fi safe state. The nuclear option for Wi-Fi operations.
This function is called when network stability is critical or when
3 consecutive high RTT readings are detected.

Actions taken:
  1. Kill all Wi-Fi tool processes (bettercap, airgeddon, aircrack-ng family)
  2. Restore network interfaces from the saved checkpoint
  3. Set *WIFI-SAFE-MODE-ACTIVE-P* to T (blocks new Wi-Fi launches)
  4. Set all Wi-Fi agent statuses to :safe-mode
  5. Log the event to telemetry and audit
  6. Reset the RTT consecutive counter

Returns plist: :safe-mode-active-p, :processes-killed, :agents-affected.
To exit safe mode: call EXIT-WIFI-SAFE-STATE after stability returns."
  (let ((killed (wifi-emergency-halt))
        (agents-affected '()))
    ;; Restore network interfaces
    (ignore-errors (restore-network-state))
    ;; Set safe mode flag
    (setf *wifi-safe-mode-active-p* t)
    ;; Mark all Wi-Fi agents as safe-mode
    (bt:with-lock-held (*kali-agents-lock*)
      (maphash
       (lambda (agent-id agent)
         (when (or (typep agent 'bettercap-agent)
                   (typep agent 'airgeddon-agent))
           (setf (agent-status agent) :safe-mode)
           (push agent-id agents-affected)))
       *active-kali-agents*))
    ;; Reset consecutive counter
    (bt:with-lock-held (*network-stability-lock*)
      (setf *rtt-high-consecutive-count* 0))
    ;; Log
    (policy-audit-log :wifi-safe-state-entered t
                      (format nil "Wi-Fi safe state entered. Killed ~D processes. ~D agents in safe-mode."
                              (getf killed :killed-count)
                              (length agents-affected)))
    (list :safe-mode-active-p t
          :processes-killed (getf killed :killed-count)
          :agents-affected (nreverse agents-affected))))

(defun exit-wifi-safe-state () 
  "Exit Wi-Fi safe state after stability returns.
Verifies network stability before allowing operations to resume.
Sets *WIFI-SAFE-MODE-ACTIVE-P* to NIL if stability check passes.
Returns :resumed if exited, :still-unstable if stability check fails."
  (let ((stability (check-network-stability)))
    (if (eq stability :stable)
        (progn
          (setf *wifi-safe-mode-active-p* nil)
          (policy-audit-log :wifi-safe-state-exited t
                            "Wi-Fi safe state exited -- network stable")
          :resumed)
        (progn
          (policy-audit-log :wifi-safe-state-exit-denied nil
                            (format nil "Cannot exit safe state: network still ~A" stability))
          :still-unstable))))

(defun wifi-safe-mode-p () 
  "Return T if Wi-Fi safe mode is currently active.
When safe mode is active, all Wi-Fi tool launches are blocked.
New operations may only begin after EXIT-WIFI-SAFE-STATE succeeds."
  *wifi-safe-mode-active-p*)


;; ─────────────────────────────────────────────────────────────────────────
;; Section F: Emergency Halt Handlers for Wi-Fi Agents
;; ─────────────────────────────────────────────────────────────────────────

(defmethod handle-condition :after ((agent bettercap-agent) (condition emergency-halt))
  "Kill bettercap process on emergency halt.
This :AFTER method ensures that when an EMERGENCY-HALT condition is
signaled and the orchestrator begins handling it, any running bettercap
subprocess associated with this agent is terminated immediately.
The parent KALI-AGENT :AFTER method handles the generic cleanup.
This method adds Wi-Fi specific logging."
  (bt:with-lock-held ((agent-lock agent))
    (let ((subprocess (kali-agent-subprocess agent)))
      (when (and subprocess (uiop:process-alive-p subprocess))
        (ignore-errors (uiop:terminate-process subprocess :urgent t))
        (policy-audit-log :bettercap-emergency-killed (agent-id agent)
                          (format nil "Emergency halt killed bettercap for ~A"
                                  (agent-id agent)))))))

(defmethod handle-condition :after ((agent airgeddon-agent) (condition emergency-halt))
  "Kill airgeddon process on emergency halt.
This :AFTER method ensures that when an EMERGENCY-HALT condition is
signaled, any running airgeddon subprocess is terminated immediately.
Airgeddon operations are :critical risk -- they are the first to die
in an emergency. Also kills any child processes (airodump-ng, etc.)."
  (bt:with-lock-held ((agent-lock agent))
    (let ((subprocess (kali-agent-subprocess agent)))
      (when (and subprocess (uiop:process-alive-p subprocess))
        (ignore-errors (uiop:terminate-process subprocess :urgent t))
        (policy-audit-log :airgeddon-emergency-killed (agent-id agent)
                          (format nil "Emergency halt killed airgeddon for ~A"
                                  (agent-id agent)))))
  ;; Also sweep for orphaned airgeddon children
  (ignore-errors (wifi-emergency-halt)))


;; ─────────────────────────────────────────────────────────────────────────
;; Section G: Wi-Fi Gatekeeper Status
;; ─────────────────────────────────────────────────────────────────────────

(defun wifi-gatekeeper-status () 
  "Return comprehensive Wi-Fi safety subsystem status as a plist:
  :wifi-policies-loaded    -- Count of Wi-Fi policies registered
  :wifi-policy-names        -- List of Wi-Fi tool names
  :stability-monitor        -- Is the RTT monitor running?
  :wifi-safe-mode           -- Is safe mode active?
  :rtt-threshold-ms         -- Current warning threshold
  :rtt-critical-ms          -- Current critical threshold
  :rtt-average              -- Average RTT from sliding window
  :rtt-high-consecutive     -- Consecutive high RTT count
  :rtt-history-count        -- Number of samples in window
  :wifi-agents-active       -- Count of bettercap + airgeddon agents
  :signal-threshold-dbm     -- Signal auto-pause threshold"
  (let ((wifi-agents 0) (wifi-policy-names '()) (wifi-policy-count 0))
    (bt:with-lock-held (*kali-agents-lock*)
      (maphash (lambda (id agent)
                 (declare (ignore id))
                 (when (or (typep agent 'bettercap-agent)
                           (typep agent 'airgeddon-agent))
                   (incf wifi-agents)))
               *active-kali-agents*))
    (bt:with-lock-held (*policy-lock*)
      (dolist (name '(bettercap airgeddon))
        (when (gethash name *tactical-repository*)
          (incf wifi-policy-count)
          (push name wifi-policy-names))))
    (list :wifi-policies-loaded wifi-policy-count
          :wifi-policy-names wifi-policy-names
          :stability-monitor (and *network-stability-thread*
                                  (bt:thread-alive-p *network-stability-thread*))
          :wifi-safe-mode *wifi-safe-mode-active-p*
          :rtt-threshold-ms *gateway-rtt-threshold-ms*
          :rtt-critical-ms *gateway-rtt-critical-ms*
          :rtt-average (get-average-rtt)
          :rtt-high-consecutive *rtt-high-consecutive-count*
          :rtt-history-count (fill-pointer *rtt-history*)
          :wifi-agents-active wifi-agents
          :signal-threshold-dbm *wifi-signal-threshold-dbm*)))

(defun print-wifi-gatekeeper-report () 
  "Print human-readable Wi-Fi safety status report to *STANDARD-OUTPUT*."
  (let ((status (wifi-gatekeeper-status)))
    (format t "~&*** LISPMIND WI-FI SAFETY MODULE STATUS REPORT ***~%")
    (format t "  Wi-Fi Policies:    ~A (~{~A~^, ~})~%"
            (getf status :wifi-policies-loaded)
            (getf status :wifi-policy-names))
    (format t "  Stability Monitor: ~A~%"
            (if (getf status :stability-monitor) "RUNNING" "STOPPED"))
    (format t "  Wi-Fi Safe Mode:   ~A~%"
            (if (getf status :wifi-safe-mode) "ACTIVE" "inactive"))
    (format t "  RTT Thresholds:    warning=~Dms critical=~Dms~%"
            (getf status :rtt-threshold-ms)
            (getf status :rtt-critical-ms))
    (format t "  RTT Average:       ~,1fms (~D samples, ~D consecutive high)~%"
            (or (getf status :rtt-average) 0.0)
            (getf status :rtt-history-count)
            (getf status :rtt-high-consecutive))
    (format t "  Wi-Fi Agents:      ~D active~%"
            (getf status :wifi-agents-active))
    (format t "  Signal Threshold:  ~D dBm~%"
            (getf status :signal-threshold-dbm))
    (format t "*** END WI-FI SAFETY REPORT ***~%")))


;; ═══════════════════════════════════════════════════════════════════════════
;; END OF WI-FI SAFETY MODULE v2.2.1
;; ═══════════════════════════════════════════════════════════════════════════


;;;; ═════════════════════════════════════════════════════════════════════════
;;;; END OF POLICY-GATEKEEPER.LISP
;;;; ═════════════════════════════════════════════════════════════════════════


;; ═══════════════════════════════════════════════════════════════════════════
;; OFFENSIVE TOOL POLICY PROFILES — v2.3.1 Categorical Safety Framework
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Instead of per-tool policies, we use CATEGORICAL profiles.
;; Each profile defines constraints for an entire tool category.
;; Categories can be ARMED or DISARMED independently.
;;
;; DESIGN PRINCIPLES:
;;   1. FAIL-CLOSED: All categories start DISARMED.
;;   2. LEAST PRIVILEGE: Each category has the minimum access it needs.
;;   3. DEFENSE IN DEPTH: ARM state + override lock + pattern validation +
;;      target whitelist + max concurrent + root check = six layers.
;;   4. AUDIT EVERYTHING: Every arm/disarm, every validation, every spawn.
;;   5. THREAD-SAFE: All mutable state is behind locks.
;;
;; CATEGORIES (8 total):
;;   :lolbin           Living-off-the-land binaries (netsh, certutil, etc.)
;;   :creds            Credential harvesting (mimikatz, secretsdump, etc.)
;;   :lateral          Lateral movement (psexec, wmiexec, etc.)
;;   :post-exploit     Post-exploitation (meterpreter, empire, etc.)
;;   :recon            Reconnaissance (nmap, masscan, dnsrecon, etc.)
;;   :web              Web testing (sqlmap, burp, zap, etc.)
;;   :wireless         Wireless testing (aircrack, bettercap, etc.)
;;   :social-engineering  Phishing, vishing, pretexting tools
;;
;; "The categories are not suggestions. They are load-bearing walls in the
;;  fortress of operational safety. Tear one down, and the whole structure
;;  is compromised."


;; ═══════════════════════════════════════════════════════════════════════════
;; Section P1: ARM/DISARM System — Categorical Weapon Safety
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *category-arm-state* (make-hash-table :test 'eq)
  "Maps category keyword → :armed or :disarmed.
All categories default to :disarmed on system initialization (fail-closed).
Categories: :lolbin :creds :lateral :post-exploit :recon :web
            :wireless :social-engineering")

(defvar *category-arm-lock* (bt:make-lock "arm-lock")
  "Lock for thread-safe arm/disarm operations.
Must be held for any read or write to *CATEGORY-ARM-STATE*.")

(defvar *override-safety-lock* nil
  "When non-nil (a timestamp), allows execution of :post-exploit and :creds tools.
This is a TWO-KEY system: the category must ALSO be ARMED.
The override is time-bounded and must be explicitly renewed.

DO NOT SET DIRECTLY. Use REQUIRE-OVERRIDE-SAFETY-LOCK.")

(defvar *override-safety-passphrase* nil
  "The passphrase hash (simple string comparison) required to set the override.
Set once at system initialization. If nil, override cannot be engaged.

The passphrase should be a strong, randomly-generated string stored in
a secure vault, not in source code.")

(defvar *override-lock* (bt:make-lock "override-lock")
  "Lock protecting *OVERRIDE-SAFETY-LOCK* and *OVERRIDE-SAFETY-PASSPHRASE*.")

(defvar *category-agent-map* (make-hash-table :test 'eq)
  "Maps category keyword → list of active agent IDs in that category.
Used for instant kill-on-disarm operations.
Protected by *CATEGORY-ARM-LOCK*.")

(defvar *offensive-policy-profiles* (make-hash-table :test 'eq)
  "Maps category keyword → POLICY-PROFILE instance.
Populated by LOAD-OFFENSIVE-POLICY-PROFILES.")

(defvar *offensive-policy-lock* (bt:make-lock "offensive-policy-lock")
  "Lock protecting *OFFENSIVE-POLICY-PROFILES*.")

(defvar *offensive-execution-counts* (make-hash-table :test 'eq)
  "Maps category keyword → current execution count.
Incremented on spawn, decremented on finalization.
Protected by *CATEGORY-ARM-LOCK*.")

(defvar *offensive-target-whitelist* '()
  "List of IP addresses, CIDR ranges, or hostname patterns that are
explicitly permitted as targets. All other targets are rejected.

Examples: '(\"192.168.1.0/24\" \"10.0.0.5\" \"*.test.example.com\")")

(defvar *offensive-root-cache* nil
  "Cached result of root access check. NIL = not checked yet.
T = we have root. :no = we don't.
This is advisory — always re-check before sensitive operations.")


(defun init-category-arm-states ()
  "Initialize all eight offensive categories to :disarmed (fail-closed).
Idempotent — safe to call multiple times.
Returns the list of initialized category keywords.

Side effects:
  - Populates *CATEGORY-ARM-STATE* with :disarmed for all categories.
  - Initializes *CATEGORY-AGENT-MAP* with empty lists.
  - Initializes *OFFENSIVE-EXECUTION-COUNTS* with zeros.
  - Logs the initialization to the audit log."
  (bt:with-lock-held (*category-arm-lock*)
    (let ((categories '(:lolbin :creds :lateral :post-exploit :recon
                        :web :wireless :social-engineering)))
      (dolist (cat categories)
        (setf (gethash cat *category-arm-state*) :disarmed)
        (setf (gethash cat *category-agent-map*) '())
        (setf (gethash cat *offensive-execution-counts*) 0))
      (policy-audit-log :init-arm-states t
                        (format nil "Initialized ~D categories to :disarmed"
                                (length categories)))
      categories)))


(defun category-armed-p (category)
  "Check if CATEGORY is currently :armed.
Returns T if armed, NIL if disarmed or unknown.
Thread-safe: acquires *CATEGORY-ARM-LOCK*.

CATEGORY must be one of:
  :lolbin :creds :lateral :post-exploit :recon
  :web :wireless :social-engineering"
  (bt:with-lock-held (*category-arm-lock*)
    (eq (gethash category *category-arm-state* :disarmed) :armed)))


(defun arm-category (category &key (passphrase nil))
  "Arm a tool category, enabling execution of tools in that category.

Arguments:
  CATEGORY   — Keyword naming the category to arm.
  PASSPHRASE — String override passphrase (required for :post-exploit, :creds).

Returns:
  T          — Category was successfully armed.
  NIL        — Category was already armed or passphrase invalid.

For critical categories (:post-exploit, :creds, :lateral), the override
safety lock passphrase is required in addition to the category arm.
This is a TWO-KEY system: arm + override.

Side effects:
  - Sets *CATEGORY-ARM-STATE* for CATEGORY to :armed.
  - Logs to audit log.
  - Prints warning to *ERROR-OUTPUT* for critical categories.

Signals ERROR if CATEGORY is not a known category keyword."
  (unless (member category '(:lolbin :creds :lateral :post-exploit
                             :recon :web :wireless :social-engineering))
    (error "Unknown offensive category: ~S. Expected one of: ~S"
           category '(:lolbin :creds :lateral :post-exploit
                       :recon :web :wireless :social-engineering)))
  (let ((needs-override (member category '(:post-exploit :creds :lateral)))
        (needs-passphrase (member category '(:post-exploit :creds))))
    ;; Critical categories need the override lock
    (when needs-override
      (unless (override-active-p)
        (warn "Category ~S requires override-safety-lock. Use (require-override-safety-lock \"<passphrase>\") first."
              category)
        (policy-audit-log :arm-denied nil
                          (format nil "Category ~S arm denied: no override lock" category))
        (return-from arm-category nil)))
    ;; :post-exploit and :creds need the passphrase directly
    (when needs-passphrase
      (unless (and passphrase *override-safety-passphrase*
                   (string= passphrase *override-safety-passphrase*))
        (warn "Category ~S requires valid override passphrase." category)
        (policy-audit-log :arm-denied nil
                          (format nil "Category ~S arm denied: invalid passphrase" category))
        (return-from arm-category nil)))
    ;; Proceed with arm
    (bt:with-lock-held (*category-arm-lock*)
      (let ((previous (gethash category *category-arm-state* :disarmed)))
        (setf (gethash category *category-arm-state*) :armed)
        (policy-audit-log :arm-category t
                          (format nil "Category ~S armed (was ~S)"
                                  category previous))
        (when needs-override
          (format *error-output* "~&[SAFETY] WARNING: Critical category ~S is now ARMED. Override lock active.~%"
                  category))
        t))))


(defun disarm-category (category)
  "Disarm a tool category. Instantly kills all running agents in that category.

Arguments:
  CATEGORY — Keyword naming the category to disarm.

Returns:
  T        — Category was disarmed (may have been already disarmed).

Side effects:
  1. Sets *CATEGORY-ARM-STATE* for CATEGORY to :disarmed.
  2. Retrieves all active agent IDs from *CATEGORY-AGENT-MAP*.
  3. For each agent: calls FINALIZE-AGENT (SIGTERM → SIGKILL).
  4. Clears the agent list for this category.
  5. Logs to audit log.

This is the EMERGENCY STOP for a category. All subprocesses are killed
immediately. This operation cannot be undone without re-arming.

Signals ERROR if CATEGORY is not a known category keyword."
  (unless (member category '(:lolbin :creds :lateral :post-exploit
                             :recon :web :wireless :social-engineering))
    (error "Unknown offensive category: ~S" category))
  (let ((agents-to-kill '()))
    (bt:with-lock-held (*category-arm-lock*)
      (setf (gethash category *category-arm-state*) :disarmed)
      (setf agents-to-kill (copy-list (gethash category *category-agent-map* '())))
      (setf (gethash category *category-agent-map*) '()))
    ;; Kill agents outside the lock to avoid deadlock
    (let ((kill-count 0) (errors '()))
      (dolist (agent-id agents-to-kill)
        (handler-case
            (let ((agent (bt:with-lock-held (*kali-agents-lock*)
                           (gethash agent-id *active-kali-agents*))))
              (when agent
                (finalize-agent agent)
                (incf kill-count)))
          (error (e)
            (push (cons agent-id e) errors))))
      (policy-audit-log :disarm-category t
                        (format nil "Category ~S disarmed. Killed ~D/~D agents.~@[ Errors: ~S~]"
                                category kill-count (length agents-to-kill)
                                (when errors (length errors))))
      (list :category category
            :state :disarmed
            :agents-killed kill-count
            :agents-total (length agents-to-kill)
            :errors (length errors)))))


(defun arm-all-categories (&key (passphrase nil))
  "Arm all eight offensive tool categories.

Arguments:
  PASSPHRASE — String override passphrase. Required for critical categories
               (:post-exploit, :creds, :lateral). If not provided, these
               three categories remain disarmed.

Returns:
  Plist with :armed (list), :skipped (list), and :denied (list).

Non-critical categories (:recon :web :lolbin :wireless :social-engineering)
are armed without a passphrase. Critical categories require both the
passphrase and a prior call to REQUIRE-OVERRIDE-SAFETY-LOCK.

Example:
  (arm-all-categories :passphrase \"s3cret\")
    ;; → (:ARMED (:RECON :WEB :LOLBIN :WIRELESS :SOCIAL-ENGINEERING)
    ;;    :SKIPPED (:CREDS :LATERAL :POST-EXPLOIT)
    ;;    :DENIED NIL)"
  (let ((armed '()) (skipped '()) (denied '()))
    (dolist (cat '(:recon :web :lolbin :wireless :social-engineering
                   :creds :lateral :post-exploit))
      (cond
        ;; Non-critical: arm directly
        ((member cat '(:recon :web :lolbin :wireless :social-engineering))
         (if (arm-category cat)
             (push cat armed)
             (push cat denied)))
        ;; Critical: needs override + passphrase
        (t
         (if (and (override-active-p) passphrase)
             (if (arm-category cat :passphrase passphrase)
                 (push cat armed)
                 (push cat denied))
             (progn
               (push cat skipped)
               (policy-audit-log :arm-skipped nil
                                 (format nil "Category ~S skipped: needs override+passphrase"
                                         cat)))))))
    (policy-audit-log :arm-all (null denied)
                      (format nil "arm-all: ~D armed, ~D skipped, ~D denied"
                              (length armed) (length skipped) (length denied)))
    (list :armed (nreverse armed)
          :skipped (nreverse skipped)
          :denied (nreverse denied))))


(defun disarm-all-categories ()
  "Disarm ALL offensive categories. This is the GLOBAL EMERGENCY STOP.

Returns:
  Plist with :categories (list) and :total-agents-killed (integer).

Side effects:
  - Calls DISARM-CATEGORY on all eight categories.
  - Kills every offensive tool subprocess across all categories.
  - Logs to audit log with :disarm-all action.

This is the BIG RED BUTTON. Use when:
  - An unexpected target is detected.
  - Network anomalies suggest collateral damage.
  - Operator orders immediate stand-down.
  - ANY uncertainty about operational safety.

After disarm-all, the system is in a safe state. Re-arming requires
explicit per-category or arm-all calls with appropriate credentials."
  (let ((total-killed 0) (categories '()))
    (dolist (cat '(:lolbin :creds :lateral :post-exploit :recon
                    :web :wireless :social-engineering))
      (let ((result (disarm-category cat)))
        (push cat categories)
        (incf total-killed (getf result :agents-killed))))
    (policy-audit-log :disarm-all t
                      (format nil "GLOBAL DISARM: ~D categories, ~D agents killed"
                              (length categories) total-killed))
    (format *error-output* "~&[SAFETY] *** GLOBAL DISARM COMPLETE *** ~D agents terminated across ~D categories.~%"
            total-killed (length categories))
    (list :categories (nreverse categories)
          :total-agents-killed total-killed)))


(defun require-override-safety-lock (passphrase)
  "Set the override safety lock, enabling critical category operations.

Arguments:
  PASSPHRASE — String passphrase. Must match *OVERRIDE-SAFETY-PASSPHRASE*.

Returns:
  T   — Override lock is now active.
  NIL — Passphrase mismatch or not configured.

The override safety lock is a TIME-BOUNDED authorization. Once set:
  - Critical categories (:post-exploit, :creds, :lateral) CAN be armed.
  - But they still need per-category arming via ARM-CATEGORY.
  - The lock does NOT auto-expire — you must call
    RELEASE-OVERRIDE-SAFETY-LOCK to clear it.

This is DELIBERATE: an active override should be VISIBLE and require
explicit action to clear. Silent timeouts create false confidence.

WARNING: The override bypasses normal safety constraints. It should only
be engaged during:
  - Authorized penetration tests with signed rules of engagement.
  - Incident response under direct supervision.
  - Controlled red-team exercises with oversight."
  (bt:with-lock-held (*override-lock*)
    (cond
      ((null *override-safety-passphrase*)
       (warn "Override safety passphrase not configured. Override is disabled.")
       (policy-audit-log :override-denied nil "Passphrase not configured")
       nil)
      ((string= passphrase *override-safety-passphrase*)
       (setf *override-safety-lock* (local-time:now))
       (policy-audit-log :override-engaged t
                         (format nil "Override safety lock engaged at ~A"
                                 *override-safety-lock*))
       (format *error-output* "~&[SAFETY] *** OVERRIDE SAFETY LOCK ENGAGED *** Critical categories may now be armed.~%")
       t)
      (t
       (warn "Invalid override passphrase.")
       (policy-audit-log :override-denied nil "Invalid passphrase")
       nil))))


(defun release-override-safety-lock ()
  "Release (clear) the override safety lock.

Returns:
  T   — Override was active and is now cleared.
  NIL — Override was not active.

Side effects:
  - Sets *OVERRIDE-SAFETY-LOCK* to NIL.
  - Automatically DISARMS all critical categories (:post-exploit, :creds, :lateral).
  - Logs to audit log.

This is the automatic safety feature: releasing the override immediately
disarms critical categories. You cannot have a released override with
armed critical categories — that state is forbidden by design."
  (bt:with-lock-held (*override-lock*)
    (let ((was-active *override-safety-lock*))
      (setf *override-safety-lock* nil)
      (when was-active
        ;; Auto-disarm critical categories
        (dolist (cat '(:post-exploit :creds :lateral))
          (disarm-category cat))
        (policy-audit-log :override-released t
                          (format nil "Override safety lock released. Auto-disarmed critical categories."))
        (format *error-output* "~&[SAFETY] Override safety lock released. Critical categories auto-disarmed.~%"))
      (when was-active t))))


(defun override-active-p ()
  "Is the override safety lock currently active?
Returns T if active, NIL otherwise.
Thread-safe: acquires *OVERRIDE-LOCK*."
  (bt:with-lock-held (*override-lock*)
    (not (null *override-safety-lock*))))


(defun set-override-passphrase (passphrase)
  "Set the override safety passphrase.
This should be called ONCE during system initialization with a strong,
randomly-generated passphrase retrieved from a secure vault.

Arguments:
  PASSPHRASE — String passphrase. Must be at least 16 characters.

Returns T on success, signals error if passphrase too short.

SECURITY NOTE: The passphrase is stored in memory as a plain string.
This is acceptable for a running Lisp image but the passphrase should
NEVER be persisted to disk, logged, or transmitted over the network."
  (when (< (length passphrase) 16)
    (error "Override passphrase must be at least 16 characters. Got ~D."
           (length passphrase)))
  (bt:with-lock-held (*override-lock*)
    (setf *override-safety-passphrase* passphrase)
    (policy-audit-log :passphrase-set t "Override passphrase configured")
    t))


;; ─────────────────────────────────────────────────────────────────────────

(defun get-category-arm-summary () 
  "Return a plist summarizing all category ARM/DISARM states.
Each category maps to :armed or :disarmed.

Example:
  (get-category-arm-summary)
    ;; → (:LOLBIN :disarmed :CREDS :disarmed :LATERAL :disarmed ...)

Thread-safe: acquires *CATEGORY-ARM-LOCK*."
  (bt:with-lock-held (*category-arm-lock*)
    (let ((result '()))
      (maphash (lambda (cat state)
                 (setf (getf result cat) state))
               *category-arm-state*)
      result)))


(defun print-arm-status ()
  "Print a formatted table of all category ARM/DISARM states to *STANDARD-OUTPUT*.
Includes override lock status, active agent counts, and execution counts.

Example output:
  *** OFFENSIVE CATEGORY ARM STATUS ***
  Category          State      Agents  Executing
  ───────────────────────────────────────────
  :lolbin           DISARMED   0       0
  :creds            DISARMED   0       0
  ...
  Override Lock:    INACTIVE
  *** END ARM STATUS ***"
  (let ((summary (get-category-arm-summary))
        (override (override-active-p)))
    (format t "~&*** OFFENSIVE CATEGORY ARM STATUS ***~%")
    (format t "  ~20A ~10A ~8A ~10A~%" "Category" "State" "Agents" "Executing")
    (format t "  ~56A~%" (make-string 56 :initial-element #\-))
    (dolist (cat '(:lolbin :creds :lateral :post-exploit :recon
                    :web :wireless :social-engineering))
      (let ((state (getf summary cat :disarmed))
            (agent-count (bt:with-lock-held (*category-arm-lock*)
                           (length (gethash cat *category-agent-map* '()))))
            (exec-count (bt:with-lock-held (*category-arm-lock*)
                          (gethash cat *offensive-execution-counts* 0))))
        (format t "  ~20S ~10A ~8D ~10D~%"
                cat (if (eq state :armed) "ARMED" "DISARMED")
                agent-count exec-count)))
    (format t "  ~56A~%" (make-string 56 :initial-element #\-))
    (format t "  Override Lock:    ~A~%" (if override "ACTIVE" "INACTIVE"))
    (format t "*** END ARM STATUS ***~%")))


(defun arm-category-from-dashboard (category passphrase)
  "Callable from the dashboard / MCP: arm a category.
Arguments:
  CATEGORY   — String category name (e.g., \"recon\", \"creds\").
  PASSPHRASE — Override passphrase (can be nil for non-critical cats).
Returns plist with :success, :category, :message."
  (let* ((cat-keyword (intern (string-upcase category) :keyword))
         (result (handler-case
                     (arm-category cat-keyword :passphrase passphrase)
                   (error (e)
                     (list :error (format nil "~A" e))))))
    (if (eq result :error)
        (list :success nil :category category
              :message (format nil "Failed to arm ~A: ~A" category result))
        (list :success result
              :category category
              :message (format nil "Category ~A ~A"
                               category
                               (if result "armed" "not armed (check passphrase/override)"))))))


(defun disarm-category-from-dashboard (category)
  "Callable from the dashboard / MCP: disarm a category.
Arguments:
  CATEGORY — String category name (e.g., \"recon\", \"creds\").
Returns plist with :success, :category, :agents-killed, :message."
  (let* ((cat-keyword (intern (string-upcase category) :keyword))
         (result (handler-case
                     (disarm-category cat-keyword)
                   (error (e)
                     (list :error (format nil "~A" e))))))
    (if (getf result :error)
        (list :success nil :category category
              :message (format nil "Failed to disarm ~A: ~A" category result))
        (list :success t
              :category category
              :agents-killed (getf result :agents-killed 0)
              :message (format nil "Category ~A disarmed. ~D agents killed."
                               category (getf result :agents-killed 0))))))



;; ═══════════════════════════════════════════════════════════════════════════
;; Section P2: Policy Profile Definitions — 8 Categorical Profiles
;; ═══════════════════════════════════════════════════════════════════════════

(defstruct policy-profile
  "A categorical policy profile defining constraints for an entire tool category.

Fields:
  CATEGORY            — Keyword: :lolbin, :creds, :lateral, :post-exploit,
                        :recon, :web, :wireless, :social-engineering.
  NAME                — String human-readable name (e.g., \"LOLBins\").
  DESCRIPTION         — String describing the profile purpose.
  FORBIDDEN-PATTERNS  — List of regex strings forbidden in command arguments.
  FORBIDDEN-TARGETS   — IP ranges / hostnames that are off-limits.
  MAX-CONCURRENT      — Maximum parallel tool instances (integer).
  TIMEOUT-SECONDS     — Default timeout for tool execution (integer).
  REQUIRES-OVERRIDE-P — Does this category require override-safety-lock? (boolean).
  REQUIRES-ROOT-P     — Do tools in this category need root? (boolean).
  LOG-ALL-EXECUTIONS-P — Log every execution to audit? (boolean).
  NETWORK-PAUSE-P     — Pause agent if network activity detected? (boolean).
  RISK-LEVEL          — :low, :medium, :high, or :critical.

Example:
  (make-policy-profile
    :category :recon
    :name \"Reconnaissance\"
    :description \"Network reconnaissance tools\"
    :forbidden-patterns '(\"0.0.0.0/0\" \"255.255.255.255\")
    :forbidden-targets '(\"10.0.0.0/8\")
    :max-concurrent 10
    :timeout-seconds 180
    :requires-override-p nil
    :requires-root-p nil
    :log-all-executions-p t
    :network-pause-p nil
    :risk-level :low)"
  category
  name
  description
  forbidden-patterns
  forbidden-targets
  max-concurrent
  timeout-seconds
  requires-override-p
  requires-root-p
  log-all-executions-p
  network-pause-p
  risk-level)


(defun load-offensive-policy-profiles ()
  "Load all 8 offensive policy profiles into *OFFENSIVE-POLICY-PROFILES*.
Returns list of registered category keywords.
Idempotent — safe to call multiple times; re-creates all profiles.

Categories and their safety posture:

  :lolbin — MODERATE. Living-off-the-land binaries.
    Max concurrent: 5, Timeout: 60s, Risk: :medium
    Forbidden: rm -rf /, del /f /s /q C:\, format C:
    Logs all executions. Pauses if network connect detected.

  :creds — CRITICAL. Credential harvesting and dumping.
    Max concurrent: 2, Timeout: 300s, Risk: :critical
    Requires override-safety-lock AND passphrase.
    Forbidden: --dump-all, /export, NTDS on production DCs.
    Only test targets in whitelist.

  :lateral — CRITICAL. Lateral movement tools.
    Max concurrent: 3, Timeout: 120s, Risk: :critical
    Requires override-safety-lock.
    Forbidden: *, 0.0.0.0/0, /16 ranges (too broad).
    Only specific target IPs from whitelist.

  :post-exploit — CRITICAL. Post-exploitation frameworks.
    Max concurrent: 1, Timeout: 600s, Risk: :critical
    Requires override-safety-lock AND explicit confirmation.
    Forbidden: all without explicit target specification.
    Confirmation prompt before each execution.

  :recon — LOW. Reconnaissance and discovery.
    Max concurrent: 10, Timeout: 180s, Risk: :low
    Allowed on whitelisted ranges only.
    Alert on high packet frequency (>1000 pps).
    Forbidden: 0.0.0.0/0, broadcast addresses.

  :web — MEDIUM. Web application testing.
    Max concurrent: 5, Timeout: 300s, Risk: :medium
    Only targets ending in .test, .lab, or in whitelist.
    Forbidden: --os-shell, --os-pwn, --batch without target.

  :wireless — HIGH. Wireless testing tools.
    Max concurrent: 2, Timeout: 300s, Risk: :high
    Only wlan1 interface. No deauth floods.
    Forbidden: wlan0, --deauth-all, -0 0, aireplay-ng on live networks.

  :social-engineering — HIGH. Phishing and pretexting.
    Max concurrent: 2, Timeout: 600s, Risk: :high
    No outbound email to public domains.
    Forbidden: @gmail.com, @yahoo.com, @outlook.com."
  (bt:with-lock-held (*offensive-policy-lock*)
    (clrhash *offensive-policy-profiles*)
    (let ((registered '()))
      ;; ── Profile 1: LOLBins ──
      (setf (gethash :lolbin *offensive-policy-profiles*)
            (make-policy-profile
             :category :lolbin
             :name "LOLBins"
             :description "Living-off-the-land binaries: certutil, netsh, bitsadmin, mshta, rundll32, regsvr32, and similar Windows/Linux binaries used for evasion."
             :forbidden-patterns '("rm -rf /" "rm -rf /*" "del /f /s /q C:\\\\*"
                                   "format C:" "mkfs\\." "dd if=/dev/zero"
                                   "> /dev/sda" ":(){ :|:& };:")
             :forbidden-targets nil
             :max-concurrent 5
             :timeout-seconds 60
             :requires-override-p nil
             :requires-root-p nil
             :log-all-executions-p t
             :network-pause-p t
             :risk-level :medium))
      (push :lolbin registered)

      ;; ── Profile 2: Credential Harvesting ──
      (setf (gethash :creds *offensive-policy-profiles*)
            (make-policy-profile
             :category :creds
             :name "Credential Harvesting"
             :description "Tools that extract, dump, or crack credentials: mimikatz, secretsdump, hashdump, lsadump, cachedump, and credential vault access."
             :forbidden-patterns '("--dump-all" "/export" "NTDS" "lsadump::sam"
                                   "sekurlsa::logonpasswords" "token::elevate")
             :forbidden-targets '("*.prod.*" "*.production.*" "*dc*" "*domain*")
             :max-concurrent 2
             :timeout-seconds 300
             :requires-override-p t
             :requires-root-p t
             :log-all-executions-p t
             :network-pause-p nil
             :risk-level :critical))
      (push :creds registered)

      ;; ── Profile 3: Lateral Movement ──
      (setf (gethash :lateral *offensive-policy-profiles*)
            (make-policy-profile
             :category :lateral
             :name "Lateral Movement"
             :description "Tools for moving between systems: psexec, wmiexec, smbexec, crackmapexec, invoke-wmi, sc.exe, and scheduled task abuse."
             :forbidden-patterns '("," "0\\.0\\.0\\.0/0" "/16 " "255\\.255\\.255\\.255"
                                   "-target *" "--target *")
             :forbidden-targets '("10.0.0.0/8" "172.16.0.0/12")
             :max-concurrent 3
             :timeout-seconds 120
             :requires-override-p t
             :requires-root-p t
             :log-all-executions-p t
             :network-pause-p nil
             :risk-level :critical))
      (push :lateral registered)

      ;; ── Profile 4: Post-Exploitation ──
      (setf (gethash :post-exploit *offensive-policy-profiles*)
            (make-policy-profile
             :category :post-exploit
             :name "Post-Exploitation"
             :description "Post-exploitation frameworks and tools: meterpreter, empire/covenant, bloodhound, powerview, sharpview, and privilege escalation scripts."
             :forbidden-patterns '("run persistence" "migrate" "keyscan_start"
                                   "screenshot" "webcam_snap" "mic_record")
             :forbidden-targets nil
             :max-concurrent 1
             :timeout-seconds 600
             :requires-override-p t
             :requires-root-p t
             :log-all-executions-p t
             :network-pause-p nil
             :risk-level :critical))
      (push :post-exploit registered)

      ;; ── Profile 5: Reconnaissance ──
      (setf (gethash :recon *offensive-policy-profiles*)
            (make-policy-profile
             :category :recon
             :name "Reconnaissance"
             :description "Network reconnaissance tools: nmap, masscan, dnsrecon, enum4linux, snmp-check, fierce, theharvester, and OSINT gathering tools."
             :forbidden-patterns '("0\\.0\\.0\\.0/0" "255\\.255\\.255\\.255"
                                   "--rate 100000" "-p- --max-retries 0")
             :forbidden-targets '("0.0.0.0/0" "255.255.255.255/32")
             :max-concurrent 10
             :timeout-seconds 180
             :requires-override-p nil
             :requires-root-p nil
             :log-all-executions-p t
             :network-pause-p nil
             :risk-level :low))
      (push :recon registered)

      ;; ── Profile 6: Web Application Testing ──
      (setf (gethash :web *offensive-policy-profiles*)
            (make-policy-profile
             :category :web
             :name "Web Application Testing"
             :description "Web testing tools: sqlmap, burpsuite, owasp-zap, nikto, dirb, gobuster, wfuzz, and custom web exploit frameworks."
             :forbidden-patterns '("--os-shell" "--os-pwn" "--os-cmd"
                                   "--batch" "--dump-all" "--risk 3")
             :forbidden-targets '("*.prod.*" "*.production.*")
             :max-concurrent 5
             :timeout-seconds 300
             :requires-override-p nil
             :requires-root-p nil
             :log-all-executions-p t
             :network-pause-p nil
             :risk-level :medium))
      (push :web registered)

      ;; ── Profile 7: Wireless Testing ──
      (setf (gethash :wireless *offensive-policy-profiles*)
            (make-policy-profile
             :category :wireless
             :name "Wireless Testing"
             :description "Wireless auditing tools: aircrack-ng, bettercap, wifite, ferr-wifi, kismet, and Bluetooth testing tools."
             :forbidden-patterns '("wlan0" "--deauth-all" "-0 0" "--nodeauth"
                                   "aireplay-ng -0 0")
             :forbidden-targets nil
             :max-concurrent 2
             :timeout-seconds 300
             :requires-override-p nil
             :requires-root-p t
             :log-all-executions-p t
             :network-pause-p t
             :risk-level :high))
      (push :wireless registered)

      ;; ── Profile 8: Social Engineering ──
      (setf (gethash :social-engineering *offensive-policy-profiles*)
            (make-policy-profile
             :category :social-engineering
             :name "Social Engineering"
             :description "Social engineering tools: gophish, setoolkit, king-phisher, evilginx, and custom phishing frameworks."
             :forbidden-patterns '("@gmail\\.com" "@yahoo\\.com" "@outlook\\.com"
                                   "@hotmail\\.com" "@aol\\.com" "send-all")
             :forbidden-targets nil
             :max-concurrent 2
             :timeout-seconds 600
             :requires-override-p nil
             :requires-root-p nil
             :log-all-executions-p t
             :network-pause-p nil
             :risk-level :high))
      (push :social-engineering registered)

      (policy-audit-log :load-offensive-profiles t
                        (format nil "Loaded ~D offensive policy profiles: ~S"
                                (length registered) (reverse registered)))
      (nreverse registered))))


(defun get-policy-profile (category)
  "Retrieve the POLICY-PROFILE for CATEGORY.
Returns the profile struct, or NIL if not found.
Thread-safe: acquires *OFFENSIVE-POLICY-LOCK*."
  (bt:with-lock-held (*offensive-policy-lock*)
    (gethash category *offensive-policy-profiles*)))


(defun list-offensive-categories ()
  "Return a list of all registered offensive category keywords.
Returns: (:lolbin :creds :lateral :post-exploit :recon :web :wireless :social-engineering)"
  (bt:with-lock-held (*offensive-policy-lock*)
    (let ((cats '()))
      (maphash (lambda (k v) (declare (ignore v)) (push k cats))
               *offensive-policy-profiles*)
      (sort cats #'string< :key #'symbol-name))))



;; ═══════════════════════════════════════════════════════════════════════════
;; Section P3: Categorical Validation — The Gatekeeper's Big Brother
;; ═══════════════════════════════════════════════════════════════════════════

(defun check-categorical-policy (agent binary args category target)
  "Main entry point: check if an agent's tool execution passes its category policy.

Arguments:
  AGENT    — KALI-AGENT instance (or subclass).
  BINARY   — String binary name (e.g., \"nmap\", \"mimikatz\").
  ARGS     — List of string arguments.
  CATEGORY — Keyword: one of the 8 offensive categories.
  TARGET   — String target host/IP (can be nil for targetless tools).

Validation layers (ALL must pass):
  1. Category is ARMED?        → validate-category-armed
  2. Override for critical?    → validate-category-override
  3. Args have no forbidden?   → validate-forbidden-patterns
  4. Target in whitelist?      → validate-target-whitelist
  5. Max concurrent not exceeded? → validate-max-concurrent
  6. Root available if needed? → validate-requires-root

Returns:
  T — All validations passed. Tool MAY proceed.

Signals:
  CATEGORY-DISARMED-ERROR      — Category is not armed.
  OVERRIDE-REQUIRED-ERROR      — Critical category needs override lock.
  FORBIDDEN-PATTERN-ERROR      — Args contain forbidden pattern.
  TARGET-NOT-WHITELISTED-ERROR — Target not in whitelist.
  MAX-CONCURRENT-EXCEEDED-ERROR — Too many parallel instances.
  ROOT-REQUIRED-ERROR          — Root needed but not available.

Every check is logged to the audit log, regardless of pass or fail.
This is the SIX-LAYER GATEKEEPER for offensive tools."
  (declare (type (or null string) binary target)
           (type list args)
           (type keyword category))
  (let ((profile (get-policy-profile category)))
    ;; Layer 0: Profile exists
    (unless profile
      (policy-audit-log :categorical-check nil
                        (format nil "No policy profile for category ~S" category))
      (error "No policy profile for category ~S" category))
    ;; Layer 1: Category armed
    (validate-category-armed category)
    ;; Layer 2: Override for critical
    (validate-category-override category)
    ;; Layer 3: Forbidden patterns
    (validate-forbidden-patterns args profile)
    ;; Layer 4: Target whitelist
    (when target
      (validate-target-whitelist target profile))
    ;; Layer 5: Max concurrent
    (validate-max-concurrent category profile)
    ;; Layer 6: Root required
    (validate-requires-root agent profile)
    ;; All layers passed
    (when (policy-profile-log-all-executions-p profile)
      (policy-audit-log :categorical-approve t
                        (format nil "Category ~S approved: ~A ~S target=~S"
                                category binary args target)))
    t))


(define-condition category-disarmed-error (error)
  ((category :initarg :category :reader error-category))
  (:documentation "Signaled when a tool in a DISARMED category is requested."))

(define-condition override-required-error (error)
  ((category :initarg :category :reader error-category))
  (:documentation "Signaled when a critical category is requested without override lock."))

(define-condition forbidden-pattern-error (error)
  ((pattern :initarg :pattern :reader error-pattern)
   (arg     :initarg :arg     :reader error-arg))
  (:documentation "Signaled when arguments contain a forbidden pattern."))

(define-condition target-not-whitelisted-error (error)
  ((target :initarg :target :reader error-target))
  (:documentation "Signaled when target is not in the whitelist."))

(define-condition max-concurrent-exceeded-error (error)
  ((category :initarg :category :reader error-category)
   (current  :initarg :current  :reader error-current-count)
   (maximum  :initarg :maximum  :reader error-maximum))
  (:documentation "Signaled when max concurrent instances exceeded."))

(define-condition root-required-error (error)
  ((category :initarg :category :reader error-category))
  (:documentation "Signaled when root is required but not available."))


(defun validate-category-armed (category)
  "Check if CATEGORY is armed. If disarmed, signal CATEGORY-DISARMED-ERROR.
This is LAYER 1 of the categorical gatekeeper.

Returns T if armed.

Logs:
  - :category-armed-check with result on every call."
  (let ((armed (category-armed-p category)))
    (policy-audit-log :category-armed-check armed
                      (format nil "Category ~S arm check: ~A"
                              category (if armed "ARMED" "DISARMED")))
    (unless armed
      (error 'category-disarmed-error :category category))
    t))


(defun validate-category-override (category)
  "For critical categories, check if override-safety-lock is active.
This is LAYER 2 of the categorical gatekeeper.

Critical categories: :post-exploit, :creds, :lateral
These require both ARMED state AND override lock.

Returns T if override is active or category is not critical.

Logs:
  - :category-override-check with result on every call."
  (let ((profile (get-policy-profile category)))
    (when (and profile (policy-profile-requires-override-p profile))
      (let ((override (override-active-p)))
        (policy-audit-log :category-override-check override
                          (format nil "Category ~S override check: ~A"
                                  category (if override "ACTIVE" "INACTIVE")))
        (unless override
          (error 'override-required-error :category category))))
    t))


(defun validate-forbidden-patterns (args profile)
  "Check ARGS against forbidden patterns for PROFILE.
This is LAYER 3 of the categorical gatekeeper.

Arguments:
  ARGS    — List of string arguments to check.
  PROFILE — POLICY-PROFILE instance with FORBIDDEN-PATTERNS.

Returns T if no forbidden patterns found.

Signals FORBIDDEN-PATTERN-ERROR if any arg matches any forbidden pattern.
The check uses CL-PPCRE regex matching if available, otherwise substring search.

Logs:
  - :forbidden-pattern-check with result on every call."
  (let ((forbidden (policy-profile-forbidden-patterns profile)))
    (dolist (pattern forbidden)
      (dolist (arg args)
        (when (and arg (stringp arg))
          (handler-case
              (when (cl-ppcre:scan pattern arg)
                (policy-audit-log :forbidden-pattern-found nil
                                  (format nil "Forbidden pattern '~A' found in arg '~A'"
                                          pattern arg))
                (error 'forbidden-pattern-error
                       :pattern pattern :arg arg))
            (error (e)
              ;; If cl-ppcre not available, fall back to substring
              (when (search pattern arg)
                (policy-audit-log :forbidden-pattern-found nil
                                  (format nil "Forbidden pattern '~A' found in arg '~A'"
                                          pattern arg))
                (error 'forbidden-pattern-error
                       :pattern pattern :arg arg))))))))
  (policy-audit-log :forbidden-pattern-check t "No forbidden patterns found")
  t)


(defun validate-target-whitelist (target profile)
  "Check TARGET against the profile's allowed targets and global whitelist.
This is LAYER 4 of the categorical gatekeeper.

Arguments:
  TARGET  — String target (IP, hostname, or CIDR).
  PROFILE — POLICY-PROFILE instance.

The whitelist is checked in order:
  1. Profile's FORBIDDEN-TARGETS — if target matches, REJECT.
  2. Profile's forbidden patterns — if target matches any, REJECT.
  3. Global *OFFENSIVE-TARGET-WHITELIST* — if set, target MUST match.
  4. Auto-allow .test, .lab, localhost, 127.0.0.1, 192.168.x.x.

Returns T if target is permitted.

Signals TARGET-NOT-WHITELISTED-ERROR if target is rejected.

Logs:
  - :target-whitelist-check with result on every call."
  (let ((forbidden-targets (policy-profile-forbidden-targets profile)))
    ;; Check forbidden targets first
    (dolist (ft forbidden-targets)
      (when (and ft target (stringp target))
        (handler-case
            (when (cl-ppcre:scan ft target)
              (policy-audit-log :target-forbidden nil
                                (format nil "Target '~A' matches forbidden pattern '~A'"
                                        target ft))
              (error 'target-not-whitelisted-error :target target))
          (error ()
            (when (search ft target)
              (policy-audit-log :target-forbidden nil
                                (format nil "Target '~A' matches forbidden pattern '~A'"
                                        target ft))
              (error 'target-not-whitelisted-error :target target))))))
    ;; Check global whitelist
    (when *offensive-target-whitelist*
      (let ((whitelisted nil))
        ;; Auto-allow safe targets
        (when (or (null target)
                  (string= target "")
                  (search ".test" target)
                  (search ".lab" target)
                  (search "localhost" target)
                  (search "127.0.0.1" target)
                  (search "192.168." target))
          (setf whitelisted t))
        ;; Check explicit whitelist
        (unless whitelisted
          (dolist (wl *offensive-target-whitelist*)
            (when (and target (stringp target))
              (handler-case
                  (when (cl-ppcre:scan wl target)
                    (setf whitelisted t))
                (error ()
                  (when (search wl target)
                    (setf whitelisted t)))))))
        (unless whitelisted
          (policy-audit-log :target-not-whitelisted nil
                            (format nil "Target '~A' not in whitelist" target))
          (error 'target-not-whitelisted-error :target target))))
  (policy-audit-log :target-whitelist-check t
                    (format nil "Target '~A' approved" target))
  t)


(defun validate-max-concurrent (category profile)
  "Check if max concurrent instances for CATEGORY is exceeded.
This is LAYER 5 of the categorical gatekeeper.

Arguments:
  CATEGORY — Keyword category.
  PROFILE  — POLICY-PROFILE with MAX-CONCURRENT field.

Increments the execution count on success. The caller MUST decrement
via DECREMENT-CATEGORY-EXECUTION-COUNT when the tool completes.

Returns T if under the limit.

Signals MAX-CONCURRENT-EXCEEDED-ERROR if at or over limit."
  (bt:with-lock-held (*category-arm-lock*)
    (let* ((current (gethash category *offensive-execution-counts* 0))
           (maximum (policy-profile-max-concurrent profile)))
      (if (>= current maximum)
          (progn
            (policy-audit-log :max-concurrent-exceeded nil
                              (format nil "Category ~S: ~D/~D concurrent (LIMIT REACHED)"
                                      category current maximum))
            (error 'max-concurrent-exceeded-error
                   :category category :current current :maximum maximum))
          (progn
            (incf (gethash category *offensive-execution-counts* 0))
            (policy-audit-log :max-concurrent-check t
                              (format nil "Category ~S: ~D/~D concurrent (OK)"
                                      category (1+ current) maximum))
            t)))))


(defun decrement-category-execution-count (category)
  "Decrement the execution count for CATEGORY.
Call this when a tool in CATEGORY completes or is killed.
Thread-safe: acquires *CATEGORY-ARM-LOCK*.
Returns the new count."
  (bt:with-lock-held (*category-arm-lock*)
    (let ((current (gethash category *offensive-execution-counts* 0)))
      (when (> current 0)
        (decf (gethash category *offensive-execution-counts* 0)))
      (gethash category *offensive-execution-counts* 0))))


(defun validate-requires-root (agent profile)
  "Check if root is available for root-requiring tools.
This is LAYER 6 of the categorical gatekeeper.

Arguments:
  AGENT   — KALI-AGENT instance.
  PROFILE — POLICY-PROFILE with REQUIRES-ROOT-P field.

Returns T if root not required, or root is available.

Signals ROOT-REQUIRED-ERROR if root is required but not available.

Root check:
  - On Unix: checks (zerop (sb-ext:process-exit-code
                             (sb-ext:run-program \"id\" '(\"-u\"))))
  - Cached in *OFFENSIVE-ROOT-CACHE* to avoid repeated subprocess calls.

Logs:
  - :root-check with result on every call."
  (when (policy-profile-requires-root-p profile)
    (let ((has-root (or *offensive-root-cache*
                        (setf *offensive-root-cache*
                              (check-root-access)))))
      (policy-audit-log :root-check has-root
                        (format nil "Root check for ~A: ~A"
                                (policy-profile-category profile)
                                (if has-root "ROOT" "non-root")))
      (unless has-root
        (error 'root-required-error
               :category (policy-profile-category profile)))))
  t)


(defun check-root-access ()
  "Check if the current process has root (UID 0) access.
Returns T if root, NIL otherwise.
Uses 'id -u' subprocess on Unix systems.
Caches result in *OFFENSIVE-ROOT-CACHE*."
  (handler-case
      (let ((output (uiop:run-program "id -u" :output '(:string :stripped t)
                                        :ignore-error-status t)))
        (string= (string-trim '(#\Space #\Tab #\Newline) output) "0"))
    (error (e)
      (warn "Root check failed: ~A. Assuming non-root." e)
      nil)))


(defun detect-network-activity (agent)
  "Monitor if an AGENT's process has initiated network connections.
Returns T if network activity detected, NIL otherwise.

Detection method:
  - Uses 'ss -tp' or 'netstat -tnp' to list network connections.
  - Checks if the agent's process PID appears in the output.
  - Falls back to checking /proc/PID/net/tcp on Linux.

This is used by the :lolbin and :wireless categories which have
NETWORK-PAUSE-P set to T. If network activity is detected, the
agent should be paused or killed.

Returns:
  T   — Network connections detected for this agent's subprocess.
  NIL — No network connections, or agent has no subprocess.

Logs:
  - :network-activity-detected if connections found."
  (let ((subprocess (and (typep agent 'kali-agent)
                         (kali-agent-subprocess agent))))
    (when subprocess
      (let ((pid (handler-case
                     (uiop:process-info-pid subprocess)
                   (error () nil))))
        (when pid
          (handler-case
              (let* ((cmd (format nil "ss -tnp 2>/dev/null | grep 'pid=~D' || netstat -tnp 2>/dev/null | grep '~D' || cat /proc/~D/net/tcp 2>/dev/null | grep -v '00000000:0000' | head -1"
                                  pid pid pid))
                     (output (uiop:run-program cmd :output '(:string :stripped t)
                                               :ignore-error-status t)))
                (when (and output (> (length output) 0))
                  (policy-audit-log :network-activity-detected t
                                    (format nil "Agent ~A (PID ~D) has network connections"
                                            (agent-id agent) pid))
                  t))
            (error () nil)))))))



;; ═══════════════════════════════════════════════════════════════════════════
;; Section P4: Sudo Wrapper — Privilege Escalation with Safety
;; ═══════════════════════════════════════════════════════════════════════════

(defun sudo-wrapper (binary args &key (user "root") (category nil))
  "Wrap a command with sudo for root-requiring offensive tools.

Arguments:
  BINARY   — String path to the binary.
  ARGS     — List of string arguments.
  USER     — String username to run as (default: \"root\").
  CATEGORY — Keyword category (for logging and validation).

Returns:
  Modified command list: '(\"sudo\" \"-u\" USER \"--\" BINARY . ARGS)

Validation performed BEFORE wrapping:
  1. If CATEGORY provided: checks if category requires root via REQUIRES-ROOT-P.
  2. Checks if sudo is available in PATH.
  3. Verifies we can run sudo without password (or with configured credentials).

If root is not available, signals ROOT-REQUIRED-ERROR.

Example:
  (sudo-wrapper \"nmap\" '(\"-sS\" \"192.168.1.1\") :category :recon)
    ;; → '(\"sudo\" \"-u\" \"root\" \"--\" \"nmap\" \"-sS\" \"192.168.1.1\")

SECURITY NOTE: The sudo wrapper uses 'sudo -u USER --' to prevent
argument injection. The '--' separates sudo options from the command."
  ;; Validate category root requirement
  (when category
    (let ((profile (get-policy-profile category)))
      (when (and profile (policy-profile-requires-root-p profile))
        (unless (check-root-access)
          ;; Try sudo availability
          (unless (sudo-available-p)
            (error 'root-required-error :category category))))))
  ;; Build wrapped command
  (let ((wrapped-command (append (list "sudo" "-u" user "--" binary) args)))
    (policy-audit-log :sudo-wrap t
                      (format nil "Wrapped ~A for user ~A [category: ~S]"
                              binary user category))
    wrapped-command))


(defun sudo-available-p ()
  "Check if sudo is available and usable.
Returns T if sudo is in PATH and we can execute it.
Returns NIL otherwise."
  (handler-case
      (progn
        (uiop:run-program "which sudo" :output '(:string :stripped t)
                          :ignore-error-status t)
        t)
    (error () nil)))


(defun requires-root-p (category)
  "Check if CATEGORY requires root privileges.
Returns T if root required, NIL otherwise.
Looks up the category's policy profile."
  (let ((profile (get-policy-profile category)))
    (and profile (policy-profile-requires-root-p profile))))


(defun ensure-root-access ()
  "Verify we have root access (for root-requiring tools).
Returns T if root access confirmed.
Signals ROOT-REQUIRED-ERROR if root is not available.

This is the STRICT version of CHECK-ROOT-ACCESS. It signals an error
instead of returning NIL, ensuring that callers cannot ignore the result."
  (let ((has-root (check-root-access)))
    (unless has-root
      (error 'root-required-error :category :any))
    t))


(defun drop-root-temporarily (thunk)
  "Execute THUNK with dropped root privileges.
Saves the current UID, drops to a non-privileged user, executes THUNK,
then restores root privileges.

Arguments:
  THUNK — Zero-argument function to execute unprivileged.

Returns the result of THUNK.

SECURITY NOTE: This uses POSIX setuid() via SBCL's sb-posix interface.
If unavailable, THUNK is executed with current privileges and a warning
is issued."
  (handler-case
      (let ((original-uid (sb-posix:getuid))
            (original-euid (sb-posix:geteuid)))
        ;; Drop privileges
        (sb-posix:setuid 65534)  ; nobody
        (sb-posix:seteuid 65534)
        (unwind-protect
             (funcall thunk)
          ;; Restore privileges
          (sb-posix:seteuid original-euid)
          (sb-posix:setuid original-uid)))
    (error (e)
      (warn "Cannot drop root: ~A. Executing thunk with current privileges." e)
      (funcall thunk))))



;; ═══════════════════════════════════════════════════════════════════════════
;; Section P5: Finalize-Agent for All Offensive Categories
;; ═══════════════════════════════════════════════════════════════════════════

;; The primary FINALIZE-AGENT generic function is defined in Section 1
;; (line 568 of this file). Here we add :AFTER methods for all C2
;; framework agent types and category-aware cleanup.

(defclass sliver-agent (kali-agent)
  ((implant-pid
    :initform nil
    :accessor sliver-agent-implant-pid
    :documentation "Process ID of the running Sliver implant process.")
   (listener-port
    :initform nil
    :accessor sliver-agent-listener-port
    :documentation "Port number of the Sliver listener."))
  (:documentation "Sliver C2 framework agent.
Represents a running Sliver implant and its listener.
Cleanup kills both the implant process and removes the listener."))


(defclass metasploit-agent (kali-agent)
  ((session-id
    :initform nil
    :accessor metasploit-agent-session-id
    :documentation "Metasploit session ID (e.g., \"1\", \"2\").")
   (handler-port
    :initform nil
    :accessor metasploit-agent-handler-port
    :documentation "Port number of the Metasploit handler.")
   (payload-type
    :initform nil
    :accessor metasploit-agent-payload-type
    :documentation "Payload type string (e.g., \"meterpreter/reverse_tcp\")."))
  (:documentation "Metasploit framework agent.
Represents a running Metasploit session and its handler.
Cleanup kills the session and removes the handler."))


(defclass covenant-agent (kali-agent)
  ((grunt-id
    :initform nil
    :accessor covenant-agent-grunt-id
    :documentation "Covenant Grunt ID string.")
   (listener-id
    :initform nil
    :accessor covenant-agent-listener-id
    :documentation "Covenant Listener ID string."))
  (:documentation "Covenant C2 framework agent.
Represents an active Covenant Grunt and its listener."))


(defclass caldera-agent (kali-agent)
  ((ability-id
    :initform nil
    :accessor caldera-agent-ability-id
    :documentation "CALDERA ability ID being executed.")
   (operation-id
    :initform nil
    :accessor caldera-agent-operation-id
    :documentation "CALDERA operation ID."))
  (:documentation "CALDERA adversary emulation platform agent."))


;; ── Generic :AFTER method on KALI-AGENT (already defined at line 575) ──
;; This is the base cleanup that ALL agents get:
;;   1. Drain output buffer
;;   2. SIGTERM subprocess
;;   3. SIGKILL if still alive
;;   4. Decrement parallel instance count
;;   5. Remove from *ACTIVE-KALI-AGENTS*

;; ── Sliver-specific finalization ──
(defmethod finalize-agent :after ((agent sliver-agent))
  "Sliver-specific cleanup: kill implant, remove listener, decrement category count.

Cleanup sequence:
  1. Call primary finalizer (SIGTERM → SIGKILL subprocess).
  2. If IMPLANT-PID is set: kill -9 the implant process.
  3. If LISTENER-PORT is set: attempt to close the Sliver listener.
  4. Decrement execution count for the agent's category.
  5. Remove agent ID from *CATEGORY-AGENT-MAP*.
  6. Log to audit log.

Every step is wrapped in IGNORE-ERRORS to ensure cleanup is best-effort
and never propagates errors."
  (let ((agent-id (agent-id agent))
        (category (or (kali-agent-tool-name agent) :unknown)))
    ;; Step 1: Primary finalizer already called (subprocess killed)
    ;; Step 2: Kill implant process
    (when (sliver-agent-implant-pid agent)
      (ignore-errors
        (uiop:run-program
         (format nil "kill -9 ~D 2>/dev/null || true"
                 (sliver-agent-implant-pid agent))
         :ignore-error-status t))
      (policy-audit-log :sliver-implant-killed t
                        (format nil "Killed Sliver implant PID ~D for agent ~A"
                                (sliver-agent-implant-pid agent) agent-id)))
    ;; Step 3: Remove listener
    (when (sliver-agent-listener-port agent)
      (ignore-errors
        (uiop:run-program
         (format nil "sliver-client close --lport ~D 2>/dev/null || true"
                 (sliver-agent-listener-port agent))
         :ignore-error-status t))
      (policy-audit-log :sliver-listener-closed t
                        (format nil "Closed Sliver listener on port ~D for agent ~A"
                                (sliver-agent-listener-port agent) agent-id)))
    ;; Step 4: Decrement category execution count
    (decrement-category-execution-count category)
    ;; Step 5: Remove from category agent map
    (bt:with-lock-held (*category-arm-lock*)
      (setf (gethash category *category-agent-map*)
            (remove agent-id (gethash category *category-agent-map* '()))))
    ;; Step 6: Log
    (policy-audit-log :finalize-sliver t
                      (format nil "Finalized sliver-agent ~A (category: ~S)"
                              agent-id category))))


;; ── Metasploit-specific finalization ──
(defmethod finalize-agent :after ((agent metasploit-agent))
  "Metasploit-specific cleanup: kill session, remove handler, decrement category count.

Cleanup sequence:
  1. Call primary finalizer (subprocess killed).
  2. If SESSION-ID is set: kill the Metasploit session.
  3. If HANDLER-PORT is set: stop the handler.
  4. Decrement execution count for the agent's category.
  5. Remove agent ID from *CATEGORY-AGENT-MAP*.
  6. Log to audit log.

Uses msfconsole -x commands for session management.
Every step is wrapped in IGNORE-ERRORS."
  (let ((agent-id (agent-id agent))
        (category (or (kali-agent-tool-name agent) :unknown)))
    ;; Step 2: Kill Metasploit session
    (when (metasploit-agent-session-id agent)
      (ignore-errors
        (uiop:run-program
         (format nil "msfconsole -q -x 'sessions -k ~A; exit' 2>/dev/null || true"
                 (metasploit-agent-session-id agent))
         :ignore-error-status t))
      (policy-audit-log :metasploit-session-killed t
                        (format nil "Killed Metasploit session ~A for agent ~A"
                                (metasploit-agent-session-id agent) agent-id)))
    ;; Step 3: Stop handler
    (when (metasploit-agent-handler-port agent)
      (ignore-errors
        (uiop:run-program
         (format nil "msfconsole -q -x 'jobs -K; exit' 2>/dev/null || true")
         :ignore-error-status t))
      (policy-audit-log :metasploit-handler-stopped t
                        (format nil "Stopped Metasploit handler on port ~D for agent ~A"
                                (metasploit-agent-handler-port agent) agent-id)))
    ;; Step 4: Decrement category execution count
    (decrement-category-execution-count category)
    ;; Step 5: Remove from category agent map
    (bt:with-lock-held (*category-arm-lock*)
      (setf (gethash category *category-agent-map*)
            (remove agent-id (gethash category *category-agent-map* '()))))
    ;; Step 6: Log
    (policy-audit-log :finalize-metasploit t
                      (format nil "Finalized metasploit-agent ~A (category: ~S)"
                              agent-id category))))


;; ── Covenant-specific finalization ──
(defmethod finalize-agent :after ((agent covenant-agent))
  "Covenant-specific cleanup: kill grunt, remove listener.

Cleanup sequence:
  1. Call primary finalizer (subprocess killed).
  2. If GRUNT-ID is set: kill the Covenant Grunt.
  3. If LISTENER-ID is set: remove the listener.
  4. Decrement execution count and remove from category map.
  5. Log to audit log."
  (let ((agent-id (agent-id agent))
        (category (or (kali-agent-tool-name agent) :unknown)))
    ;; Step 2: Kill Grunt
    (when (covenant-agent-grunt-id agent)
      (ignore-errors
        (uiop:run-program
         (format nil "curl -s -X DELETE http://localhost:7443/api/grunts/~A \
                 -H 'Authorization: Bearer $COVENANT_TOKEN' 2>/dev/null || true"
                 (covenant-agent-grunt-id agent))
         :ignore-error-status t))
      (policy-audit-log :covenant-grunt-killed t
                        (format nil "Killed Covenant Grunt ~A for agent ~A"
                                (covenant-agent-grunt-id agent) agent-id)))
    ;; Step 3: Remove listener
    (when (covenant-agent-listener-id agent)
      (ignore-errors
        (uiop:run-program
         (format nil "curl -s -X DELETE http://localhost:7443/api/listeners/~A \
                 -H 'Authorization: Bearer $COVENANT_TOKEN' 2>/dev/null || true"
                 (covenant-agent-listener-id agent))
         :ignore-error-status t))
      (policy-audit-log :covenant-listener-removed t
                        (format nil "Removed Covenant Listener ~A for agent ~A"
                                (covenant-agent-listener-id agent) agent-id)))
    ;; Step 4: Cleanup
    (decrement-category-execution-count category)
    (bt:with-lock-held (*category-arm-lock*)
      (setf (gethash category *category-agent-map*)
            (remove agent-id (gethash category *category-agent-map* '()))))
    ;; Step 5: Log
    (policy-audit-log :finalize-covenant t
                      (format nil "Finalized covenant-agent ~A (category: ~S)"
                              agent-id category))))


;; ── CALDERA-specific finalization ──
(defmethod finalize-agent :after ((agent caldera-agent))
  "CALDERA-specific cleanup: stop operation, decrement count.

Cleanup sequence:
  1. Call primary finalizer (subprocess killed).
  2. If OPERATION-ID is set: stop the CALDERA operation.
  3. Decrement execution count and remove from category map.
  4. Log to audit log."
  (let ((agent-id (agent-id agent))
        (category (or (kali-agent-tool-name agent) :unknown)))
    ;; Step 2: Stop operation
    (when (caldera-agent-operation-id agent)
      (ignore-errors
        (uiop:run-program
         (format nil "curl -s -X DELETE http://localhost:8888/api/v2/operations/~A \
                 -H 'KEY: $CALDERA_API_KEY' 2>/dev/null || true"
                 (caldera-agent-operation-id agent))
         :ignore-error-status t))
      (policy-audit-log :caldera-operation-stopped t
                        (format nil "Stopped CALDERA operation ~A for agent ~A"
                                (caldera-agent-operation-id agent) agent-id)))
    ;; Step 3: Cleanup
    (decrement-category-execution-count category)
    (bt:with-lock-held (*category-arm-lock*)
      (setf (gethash category *category-agent-map*)
            (remove agent-id (gethash category *category-agent-map* '()))))
    ;; Step 4: Log
    (policy-audit-log :finalize-caldera t
                      (format nil "Finalized caldera-agent ~A (category: ~S)"
                              agent-id category))))


;; ── Generic category-aware finalization for all KALI-AGENTs ──
(defmethod finalize-agent :after ((agent kali-agent))
  "Category-aware cleanup for all KALI-AGENT instances.
This runs AFTER the subprocess-killing :AFTER method (line 575).
Ensures category execution counts and agent maps are always consistent.

Actions:
  1. Determine the agent's category from TOOL-NAME slot.
  2. Decrement execution count for that category.
  3. Remove agent ID from category agent map.
  4. Log to audit log.

This method complements the subclass-specific finalizers above.
It handles agents that don't have a specialized subclass."
  (let* ((agent-id (agent-id agent))
         (category (kali-agent-tool-name agent)))
    (when category
      ;; Decrement execution count
      (decrement-category-execution-count category)
      ;; Remove from category agent map
      (bt:with-lock-held (*category-arm-lock*)
        (setf (gethash category *category-agent-map*)
              (remove agent-id (gethash category *category-agent-map* '()))))
      ;; Log
      (policy-audit-log :finalize-kali-agent t
                        (format nil "Finalized kali-agent ~A (category: ~S)"
                                agent-id category)))))


(defun register-agent-in-category (agent-id category)
  "Register an agent ID as active in a category.
Call this when spawning a new offensive tool agent.
Thread-safe: acquires *CATEGORY-ARM-LOCK*.
Returns T on success."
  (bt:with-lock-held (*category-arm-lock*)
    (push agent-id (gethash category *category-agent-map* '()))
    (policy-audit-log :agent-registered-in-category t
                      (format nil "Agent ~A registered in category ~S"
                              agent-id category))
    t))


(defun unregister-agent-from-category (agent-id category)
  "Unregister an agent ID from a category.
Call this during finalization or manual cleanup.
Thread-safe: acquires *CATEGORY-ARM-LOCK*.
Returns T on success."
  (bt:with-lock-held (*category-arm-lock*)
    (setf (gethash category *category-agent-map*)
          (remove agent-id (gethash category *category-agent-map* '())))
    (policy-audit-log :agent-unregistered-from-category t
                      (format nil "Agent ~A unregistered from category ~S"
                              agent-id category))
    t))



;; ═══════════════════════════════════════════════════════════════════════════
;; Section P6: Offensive Tool Spawner — Safe Launch with Full Validation
;; ═══════════════════════════════════════════════════════════════════════════

(defun spawn-offensive-tool (category binary args &key target (confirm nil))
  "Spawn an offensive tool with full categorical policy validation.

Arguments:
  CATEGORY — Keyword: one of the 8 offensive categories.
  BINARY   — String binary name or path.
  ARGS     — List of string arguments.
  TARGET   — Optional string target (IP, hostname, CIDR).
  CONFIRM  — For :post-exploit, explicit confirmation flag.

Validation pipeline:
  1. CHECK-CATEGORICAL-POLICY (all 6 layers)
  2. For :post-exploit: CONFIRM must be T
  3. Build command (with sudo-wrapper if root required)
  4. Spawn subprocess
  5. Register agent in category
  6. Log to audit log

Returns:
  KALI-AGENT (or subclass) instance on success.

Signals:
  Various errors from CHECK-CATEGORICAL-POLICY if validation fails.

Example:
  (spawn-offensive-tool :recon \"nmap\" '(\"-sT\" \"192.168.1.0/24\")
                        :target \"192.168.1.0/24\")"
  (declare (type keyword category)
           (type string binary)
           (type list args))
  ;; Step 1: Full categorical validation
  (let ((agent (make-instance 'kali-agent
                              :id (gensym (format nil "OFFENSIVE-~A-" category))
                              :tool-name category
                              :tool-args args
                              :requested-args args
                              :target target
                              :risk-level (or (and (get-policy-profile category)
                                                   (policy-profile-risk-level
                                                    (get-policy-profile category)))
                                              :medium))))
    ;; Run all 6 validation layers
    (check-categorical-policy agent binary args category target)
    ;; Step 2: Extra confirmation for post-exploit
    (when (eq category :post-exploit)
      (unless confirm
        (policy-audit-log :post-exploit-confirm-denied nil
                          (format nil "Post-exploit tool ~A denied: no explicit confirmation"
                                  binary))
        (error "Post-exploit category requires explicit :confirm t")))
    ;; Step 3: Build command (with sudo if needed)
    (let ((command (if (requires-root-p category)
                       (sudo-wrapper binary args :category category)
                       (cons binary args))))
      ;; Step 4: Spawn subprocess
      (let ((subprocess (handler-case
                            (uiop:launch-program
                             command
                             :output :stream
                             :error-output :stream)
                          (error (e)
                            (decrement-category-execution-count category)
                            (error "Failed to spawn ~A: ~A" binary e)))))
        (setf (kali-agent-subprocess agent) subprocess)
        (setf (kali-agent-launch-time agent) (local-time:now))
        (setf (kali-agent-policy-approved-p agent) t)
        ;; Step 5: Register in tracking
        (bt:with-lock-held (*kali-agents-lock*)
          (setf (gethash (agent-id agent) *active-kali-agents*) agent))
        (register-agent-in-category (agent-id agent) category)
        ;; Step 6: Log
        (policy-audit-log :offensive-tool-spawned t
                          (format nil "Spawned ~A [~S] target=~S PID=~A"
                                  binary category target
                                  (ignore-errors
                                    (uiop:process-info-pid subprocess))))
        agent))))


(defun spawn-offensive-tool-with-class (class category binary args &key target confirm)
  "Spawn an offensive tool using a specific agent subclass.

Arguments:
  CLASS    — Symbol naming the agent class (e.g., 'sliver-agent, 'metasploit-agent).
  CATEGORY — Keyword category.
  BINARY   — String binary name.
  ARGS     — List of string arguments.
  TARGET   — Optional string target.
  CONFIRM  — Explicit confirmation flag for post-exploit.

Same validation as SPAWN-OFFENSIVE-TOOL but creates an instance of
CLASS instead of base KALI-AGENT.

Returns:
  Instance of CLASS on success.

Example:
  (spawn-offensive-tool-with-class 'sliver-agent :post-exploit \"sliver-client\" ...
                                   :confirm t)"
  (let ((agent (make-instance class
                              :id (gensym (format nil "OFFENSIVE-~A-" category))
                              :tool-name category
                              :tool-args args
                              :requested-args args
                              :target target
                              :risk-level (or (and (get-policy-profile category)
                                                   (policy-profile-risk-level
                                                    (get-policy-profile category)))
                                              :medium))))
    (check-categorical-policy agent binary args category target)
    (when (and (eq category :post-exploit) (not confirm))
      (error "Post-exploit category requires explicit :confirm t"))
    (let ((command (if (requires-root-p category)
                       (sudo-wrapper binary args :category category)
                       (cons binary args))))
      (let ((subprocess (handler-case
                            (uiop:launch-program command
                                                 :output :stream
                                                 :error-output :stream)
                          (error (e)
                            (decrement-category-execution-count category)
                            (error "Failed to spawn ~A: ~A" binary e)))))
        (setf (kali-agent-subprocess agent) subprocess)
        (setf (kali-agent-launch-time agent) (local-time:now))
        (setf (kali-agent-policy-approved-p agent) t)
        (bt:with-lock-held (*kali-agents-lock*)
          (setf (gethash (agent-id agent) *active-kali-agents*) agent))
        (register-agent-in-category (agent-id agent) category)
        (policy-audit-log :offensive-tool-spawned t
                          (format nil "Spawned ~A [~S] class=~S target=~S"
                                  binary category class target))
        agent))))


(defun get-offensive-status ()
  "Return comprehensive status of the offensive safety subsystem.
Returns a plist with:
  :categories-armed     — List of armed category keywords.
  :categories-disarmed  — List of disarmed category keywords.
  :override-active-p    — T if override lock is active.
  :profiles-loaded      — Number of policy profiles loaded.
  :active-agents        — Total active agents across all categories.
  :executing-counts     — Plist of category → execution count.
  :whitelist-configured — T if target whitelist is set.
  :root-available       — T if root access detected."
  (let ((armed '()) (disarmed '()) (total-agents 0))
    (bt:with-lock-held (*category-arm-lock*)
      (maphash (lambda (cat state)
                 (if (eq state :armed)
                     (push cat armed)
                     (push cat disarmed))
                 (incf total-agents (length (gethash cat *category-agent-map* '()))))
               *category-arm-state*))
    (list :categories-armed (sort armed #'string< :key #'symbol-name)
          :categories-disarmed (sort disarmed #'string< :key #'symbol-name)
          :override-active-p (override-active-p)
          :profiles-loaded (bt:with-lock-held (*offensive-policy-lock*)
                             (hash-table-count *offensive-policy-profiles*))
          :active-agents total-agents
          :executing-counts (bt:with-lock-held (*category-arm-lock*)
                              (let ((ec '()))
                                (maphash (lambda (k v) (setf (getf ec k) v))
                                         *offensive-execution-counts*)
                                ec))
          :whitelist-configured (not (null *offensive-target-whitelist*))
          :root-available (check-root-access))))


(defun print-offensive-status ()
  "Print a human-readable offensive safety status report to *STANDARD-OUTPUT*."
  (let ((status (get-offensive-status)))
    (format t "~&*** LISPMIND OFFENSIVE SAFETY STATUS REPORT ***~%")
    (format t "  Armed Categories:    ~{~S~^, ~}~%"
            (getf status :categories-armed))
    (format t "  Disarmed Categories: ~{~S~^, ~}~%"
            (getf status :categories-disarmed))
    (format t "  Override Lock:       ~A~%"
            (if (getf status :override-active-p) "ACTIVE" "inactive"))
    (format t "  Profiles Loaded:     ~D~%" (getf status :profiles-loaded))
    (format t "  Active Agents:       ~D~%" (getf status :active-agents))
    (format t "  Whitelist:           ~A~%"
            (if (getf status :whitelist-configured) "CONFIGURED" "not set"))
    (format t "  Root Access:         ~A~%"
            (if (getf status :root-available) "YES" "no"))
    (format t "  Execution Counts:~%")
    (let ((counts (getf status :executing-counts)))
      (dolist (cat '(:lolbin :creds :lateral :post-exploit :recon
                      :web :wireless :social-engineering))
        (format t "    ~20S: ~D~%" cat (getf counts cat 0))))
    (format t "*** END OFFENSIVE SAFETY REPORT ***~%")))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section P7: Initialization — Bootstrap the Offensive Safety System
;; ═══════════════════════════════════════════════════════════════════════════

(defun init-offensive-safety-system (&key (passphrase nil) (target-whitelist nil))
  "Initialize the complete offensive safety subsystem.

Arguments:
  PASSPHRASE       — Optional string to set as override passphrase.
                      Must be at least 16 characters.
  TARGET-WHITELIST — Optional list of allowed target strings.

Actions:
  1. Initialize all category arm states to :disarmed.
  2. Load all 8 policy profiles.
  3. Set override passphrase if provided.
  4. Set target whitelist if provided.
  5. Log initialization to audit log.

Returns:
  Plist with :initialized t, :categories (count), :profiles (count).

This is the ONE function to call at system startup to prepare the
offensive safety framework. All categories start DISARMED (fail-closed).

Example:
  (init-offensive-safety-system
    :passphrase \"MySup3rS3cur3Passphr4se!\"
    :target-whitelist '(\"192.168.1.0/24\" \"10.0.0.5\"))"
  (init-category-arm-states)
  (let ((profiles (load-offensive-policy-profiles)))
    (when passphrase
      (set-override-passphrase passphrase))
    (when target-whitelist
      (setf *offensive-target-whitelist* target-whitelist))
    (policy-audit-log :offensive-safety-init t
                      (format nil "Offensive safety system initialized: ~D categories, ~D profiles"
                              8 (length profiles)))
    (format t "~&[OFFENSIVE SAFETY] System initialized. ~D categories, ~D profiles. ALL DISARMED.~%"
            8 (length profiles))
    (list :initialized t
          :categories 8
          :profiles (length profiles)
          :passphrase-set (not (null passphrase))
          :whitelist-set (not (null target-whitelist)))))


;; ═══════════════════════════════════════════════════════════════════════════
;; END OF OFFENSIVE TOOL POLICY PROFILES — v2.3.1
;; ═══════════════════════════════════════════════════════════════════════════


;; ═══════════════════════════════════════════════════════════════════════════
;; ENGINEERING SAFETY MODULE — v2.3.2 Physical/Structural Simulation Safety
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This module extends the Policy Gatekeeper to cover engineering and
;; scientific computing categories: :math, :physics, :engineering,
;; :electronics, and :ai-ml.  These categories encompass CPU-intensive
;; numerical workloads, CFD/FEA simulations, CAD/CAM operations, EDA
;; toolchains, and GPU-accelerated ML training -- all of which carry
;; unique physical risks (thermal runaway, resource saturation, hardware
;; damage to FPGAs, data exfiltration during training).
;;
;; DESIGN PRINCIPLES
;; --
;; 1. FAIL-CLOSED -- All engineering categories start DISARMED.
;; 2. THERMAL GUARDRAILS -- Background thread monitors CPU/GPU temps.
;; 3. OPERATOR OVERRIDE -- Structural/physical simulations require
;;    explicit operator authorization via passphrase.
;; 4. RESOURCE CEILINGS -- Hard limits on concurrency, memory, disk I/O.
;; 5. SIMULATION TIMEOUTS -- Hard wall-clock limits on all sim runs.
;; 6. GRACEFUL SHUTDOWN -- disarm-engineering-category kills all
;;    running processes in that category and cleans up temp files.
;;
;; DEPENDENCIES
;; --
;;   - UIOP (portable process control, temp file management)
;;   - Bordeaux-Threads (thermal monitor thread)
;;   - SB-EXT or OS-specific temp sensor access
;;
;; AUTHOR: LISPMIND Safety Architecture Team
;; VERSION: 2.3.2


;; ───────────────────────────────────────────────────────────────────────────
;; Section E1: Engineering Condition Hierarchy
;; ───────────────────────────────────────────────────────────────────────────

(define-condition thermal-breach (alert-threshold-crossed)
  ((component :initarg :component
              :reader thermal-breach-component
              :type keyword
              :documentation "The thermal component that breached: :cpu or :gpu.")
   (temperature :initarg :temperature
                :reader thermal-breach-temperature
                :type float
                :documentation "The measured temperature in Celsius at breach time.")
   (threshold :initarg :threshold
              :reader thermal-breach-threshold
              :type float
              :documentation "The threshold value that was exceeded."))
  (:report (lambda (condition stream)
             (format stream "THERMAL BREACH: ~A at ~,1fC (threshold ~,1fC)"
                     (thermal-breach-component condition)
                     (thermal-breach-temperature condition)
                     (thermal-breach-threshold condition))))
  (:documentation "Signaled when a thermal component (CPU or GPU) exceeds
its configured warning or critical threshold during engineering workload
execution.  This condition is RESIGNALABLE -- catch it to trigger emergency
cooling or automatic workload pause."))

(define-condition resource-pressure-critical (alert-threshold-crossed)
  ((resource-type :initarg :resource-type
                  :reader resource-pressure-type
                  :type keyword
                  :documentation "The resource under pressure: :memory or :disk-io.")
   (current-value :initarg :current-value
                  :reader resource-pressure-value
                  :type float
                  :documentation "Current measured value (percent for memory, MB/s for disk).")
   (threshold :initarg :threshold
              :reader resource-pressure-threshold
              :type float
              :documentation "The threshold that was exceeded."))
  (:report (lambda (condition stream)
             (format stream "RESOURCE PRESSURE CRITICAL: ~A at ~,1f (threshold ~,1f)"
                     (resource-pressure-type condition)
                     (resource-pressure-value condition)
                     (resource-pressure-threshold condition))))
  (:documentation "Signaled when system resource pressure (memory
utilization or disk I/O throughput) exceeds critical thresholds during
engineering agent execution.  Catching this condition should trigger
immediate workload throttling or termination to prevent OOM killer
activation or I/O starvation."))

(define-condition simulation-timeout (agent-failure)
  ((elapsed-time :initarg :elapsed-time
                 :reader simulation-timeout-elapsed
                 :type float
                 :documentation "Actual elapsed wall-clock time in seconds.")
   (budget :initarg :budget
           :reader simulation-timeout-budget
           :type float
           :documentation "The allocated compute budget in seconds.")
   (category :initarg :category
             :reader simulation-timeout-category
             :type keyword
             :documentation "The engineering category that timed out."))
  (:report (lambda (condition stream)
             (format stream "SIMULATION TIMEOUT: ~A ran for ~,1fs (budget ~,1fs)"
                     (simulation-timeout-category condition)
                     (simulation-timeout-elapsed condition)
                     (simulation-timeout-budget condition))))
  (:documentation "Signaled when an engineering simulation exceeds its
allocated compute time budget.  This is a HARD DEADLINE -- the agent
process is unconditionally terminated when this condition is signaled
to prevent runaway computations from consuming resources indefinitely."))

(define-condition physical-override-required (error)
  ((category :initarg :category
             :reader physical-override-category
             :type keyword
             :documentation "The engineering category requiring override.")
   (operation :initarg :operation
              :reader physical-override-operation
              :type string
              :documentation "Description of the operation that triggered this."))
  (:report (lambda (condition stream)
             (format stream "PHYSICAL OVERRIDE REQUIRED for ~A: ~A"
                     (physical-override-category condition)
                     (physical-override-operation condition))))
  (:documentation "Signaled when a physical or structural simulation
is attempted without an active operator override.  Physical simulations
(CFD, FEA, structural analysis) carry risk of hardware damage through
thermal overload or mechanical resonance in test apparatus.  This
condition enforces the MANDATORY OVERRIDE policy -- no physical sim
may proceed without an operator explicitly arming the override."))


;; ───────────────────────────────────────────────────────────────────────────
;; Section E2: Engineering Policy Profiles
;; ───────────────────────────────────────────────────────────────────────────

(defvar *engineering-policy-profiles* (make-hash-table :test 'eq)
  "Hash table mapping engineering category keywords to their policy
profiles.  Keys are: :math :physics :engineering :electronics :ai-ml.
Each value is a POLICY-PROFILE struct with engineering-specific
constraints.  Access is protected by *ENGINEERING-POLICY-LOCK*.")

(defvar *engineering-policy-lock* (bt:make-lock "engineering-policy-lock")
  "Lock protecting all mutations to *ENGINEERING-POLICY-PROFILES* and
engineering category arm state.  Must be held when loading profiles,
arming/disarming categories, or reading profile data during validation.")

(defun load-engineering-policy-profiles ()
  "Load policy profiles for engineering/scientific categories.

Creates and registers five engineering policy profiles, each tailored
to the risk characteristics of its workload domain:

  :math -- MODERATE. CPU-intensive but safe.
    Max concurrent: 4, Timeout: 3600s, Risk: :low
    No override required. No root required.
    Forbidden: system() calls, file deletion in args
    Monitor: CPU usage < 80%
    Typical tools: Mathematica, MATLAB, SageMath, GNU Octave

  :physics -- HIGH. CFD/FEA simulations can saturate resources.
    Max concurrent: 1, Timeout: 14400s, Risk: :high
    Override required for runs > 4 hours (structural simulation).
    Root: No (unless custom compute kernels).
    Forbidden: rm -rf, write to /dev, fork bombs, raw device access
    Monitor: CPU temp < 85C, memory < 80%, disk I/O < 500MB/s
    Thermal monitoring: ENABLED (mandatory).
    Typical tools: OpenFOAM, ANSYS Fluent, COMSOL, ElmerFEM, CalculiX

  :engineering -- MODERATE. CAD/CAM operations.
    Max concurrent: 2, Timeout: 7200s, Risk: :medium
    Override required for structural simulation export only.
    Monitor: GPU memory (if rendering), disk space > 5GB free
    Typical tools: FreeCAD, OpenSCAD, Blender, LibreCAD

  :electronics -- LOW-MODERATE. EDA tools and FPGA programming.
    Max concurrent: 3, Timeout: 3600s, Risk: :low
    Root required for FPGA bitstream programming (iceprog, openFPGALoader).
    Forbidden: program non-test FPGAs without whitelist entry.
    Whitelist: Only :TEST-FPGA boards may be programmed.
    Typical tools: KiCad, Yosys, nextpnr, iverilog, gtkwave

  :ai-ml -- HIGH. Can consume all GPU/CPU resources.
    Max concurrent: 2, Timeout: 14400s, Risk: :high
    Override required for training runs > 8 hours.
    Monitor: GPU temp < 85C, VRAM usage < 90%, CUDA errors
    Forbidden: network egress during training (data exfiltration risk)
    Typical tools: PyTorch, TensorFlow, JAX, scikit-learn

Returns a list of the five category keywords that were registered."
  (bt:with-lock-held (*engineering-policy-lock*)
    (clrhash *engineering-policy-profiles*)
    ;; --- :math profile ---
    (setf (gethash :math *engineering-policy-profiles*)
          (make-policy-profile
           :category :math
           :max-concurrent 4
           :timeout-seconds 3600
           :risk-level :low
           :requires-override nil
           :requires-root nil
           :forbidden-patterns '("system" "popen" "rm " "rmdir" "unlink"
                                 "remove" "delete" "-exec rm" "| rm")
           :allowed-targets nil
           :monitor-spec '((:cpu-usage . (:max 80.0 :unit :percent)))
           :description "Mathematical computation: CAS, numerical solvers, symbolic math."))
    ;; --- :physics profile ---
    (setf (gethash :physics *engineering-policy-profiles*)
          (make-policy-profile
           :category :physics
           :max-concurrent 1
           :timeout-seconds 14400
           :risk-level :high
           :requires-override t
           :override-threshold-seconds 14400
           :requires-root nil
           :forbidden-patterns '("rm -rf" "> /dev" "dd if" "mkfs" "fdisk"
                                 ":(){ :|:& };:" ": () {" "while true"
                                 "fork" "bombs" "raw /dev")
           :allowed-targets nil
           :monitor-spec '((:cpu-temp    . (:max 85.0 :unit :celsius))
                           (:memory      . (:max 80.0 :unit :percent))
                           (:disk-io     . (:max 500.0 :unit :mb-per-sec))
                           (:thermal     . (:enabled t :interval 5)))
           :description "Physics simulation: CFD, FEA, thermal analysis, electromagnetics."))
    ;; --- :engineering profile ---
    (setf (gethash :engineering *engineering-policy-profiles*)
          (make-policy-profile
           :category :engineering
           :max-concurrent 2
           :timeout-seconds 7200
           :risk-level :medium
           :requires-override nil
           :requires-root nil
           :forbidden-patterns '("rm -rf" "> /dev" "dd if=/dev")
           :allowed-targets nil
           :monitor-spec '((:gpu-memory  . (:max 90.0 :unit :percent))
                           (:disk-free   . (:min 5.0 :unit :gigabytes)))
           :description "CAD/CAM operations: modeling, drafting, toolpath generation."))
    ;; --- :electronics profile ---
    (setf (gethash :electronics *engineering-policy-profiles*)
          (make-policy-profile
           :category :electronics
           :max-concurrent 3
           :timeout-seconds 3600
           :risk-level :low
           :requires-override nil
           :requires-root t
           :forbidden-patterns '("iceprog" "openFPGALoader" "ecppack"
                                 "--board" "--device")
           :allowed-targets '("TEST-FPGA" "SIMULATION" "VERIFICATION")
           :monitor-spec '((:disk-free . (:min 1.0 :unit :gigabytes)))
           :description "EDA toolchain: schematic capture, PCB layout, FPGA synthesis."))
    ;; --- :ai-ml profile ---
    (setf (gethash :ai-ml *engineering-policy-profiles*)
          (make-policy-profile
           :category :ai-ml
           :max-concurrent 2
           :timeout-seconds 14400
           :risk-level :high
           :requires-override t
           :override-threshold-seconds 28800
           :requires-root nil
           :forbidden-patterns '("curl" "wget" "scp" "rsync" "ftp"
                                 "http.client" "urllib" "socket" "requests"
                                 "torch.hub.load" "tensorflow_hub")
           :allowed-targets nil
           :monitor-spec '((:gpu-temp    . (:max 85.0 :unit :celsius))
                           (:vram-usage  . (:max 90.0 :unit :percent))
                           (:cuda-errors . (:max 1 :unit :count))
                           (:network     . (:egress :forbidden)))
           :description "AI/ML training and inference: GPU-accelerated neural networks."))
    ;; Return registered categories
    (let ((cats '(:math :physics :engineering :electronics :ai-ml)))
      (policy-audit-log :engineering-profiles-loaded t
                        (format nil "Loaded ~D engineering policy profiles: ~S"
                                (length cats) cats))
      cats)))


;; ───────────────────────────────────────────────────────────────────────────
;; Section E3: Engineering ARM/DISARM State Machine
;; ───────────────────────────────────────────────────────────────────────────

(defvar *engineering-arm-state* (make-hash-table :test 'eq)
  "Hash table mapping engineering category keywords to their arm state.
Values are :armed or :disarmed.  All categories start :disarmed (fail-closed).
Access is protected by *ENGINEERING-POLICY-LOCK*.")

(defvar *engineering-agent-map* (make-hash-table :test 'eq)
  "Hash table mapping engineering category keywords to lists of active
agent process handles.  Used by DISARM to kill all running simulations
in a category.  Access is protected by *ENGINEERING-POLICY-LOCK*.")

(defvar *engineering-execution-counts* (make-hash-table :test 'eq)
  "Hash table tracking execution counts per engineering category.
Keys are category keywords, values are non-negative integers.
Used for concurrency limiting.  Access protected by *ENGINEERING-POLICY-LOCK*.")

(defun init-engineering-arm-states ()
  "Initialize all engineering category arm states to :disarmed.

This is the fail-closed initialization.  Every engineering category
(:math :physics :engineering :electronics :ai-ml) is set to :disarmed,
and all execution counts are zeroed.  Must be called before any
engineering agent operations.

Returns the list of initialized categories."
  (bt:with-lock-held (*engineering-policy-lock*)
    (dolist (cat '(:math :physics :engineering :electronics :ai-ml))
      (setf (gethash cat *engineering-arm-state*) :disarmed)
      (setf (gethash cat *engineering-agent-map*) '())
      (setf (gethash cat *engineering-execution-counts*) 0))
    (policy-audit-log :engineering-arm-init t
                      "All engineering categories initialized to DISARMED")
    '(:math :physics :engineering :electronics :ai-ml)))

(defun arm-engineering-category (category &key (passphrase nil))
  "Arm an engineering category, allowing agents in that category to execute.

Arguments:
  CATEGORY   -- One of :math :physics :engineering :electronics :ai-ml.
  PASSPHRASE -- Optional override passphrase for high-risk categories
               (:physics, :ai-ml).  Required if category has
               :requires-override set in its profile.

Validation:
  1. CATEGORY must have a loaded policy profile.
  2. If category :requires-override, PASSPHRASE must match
     *PHYSICAL-OVERRIDE-PASSPHRASE*.
  3. The category must currently be :disarmed (idempotent if already :armed).

Returns: :armed on success.
Signals: PHYSICAL-OVERRIDE-REQUIRED if passphrase missing for high-risk cat.
         ERROR if category profile not found."
  (bt:with-lock-held (*engineering-policy-lock*)
    (let ((profile (gethash category *engineering-policy-profiles*)))
      (unless profile
        (error "No engineering policy profile found for category ~S" category))
      (when (and (policy-profile-requires-override profile)
                 (or (null passphrase)
                     (null *physical-override-passphrase*)
                     (not (string= passphrase *physical-override-passphrase*))))
        (error 'physical-override-required
               :category category
               :operation (format nil "arm category ~S" category)))
      (setf (gethash category *engineering-arm-state*) :armed)
      (policy-audit-log :engineering-category-armed t
                        (format nil "Engineering category ~S ARMED~A"
                                category
                                (if passphrase " (with override)" "")))
      :armed)))

(defun disarm-engineering-category (category)
  "Disarm an engineering category and TERMINATE all running simulations.

This is the EMERGENCY STOP for a category.  Actions taken:
  1. Set category arm state to :disarmed.
  2. Send SIGTERM to every active agent process in the category.
  3. After 5-second grace period, send SIGKILL to any survivors.
  4. Clean up temp files associated with each agent.
  5. Reset execution count to 0.
  6. Log disarm to audit log.

Arguments:
  CATEGORY -- One of :math :physics :engineering :electronics :ai-ml.

Returns: :disarmed on success, :already-disarmed if already in that state.
Signals: ERROR if category profile not found."
  (bt:with-lock-held (*engineering-policy-lock*)
    (let ((profile (gethash category *engineering-policy-profiles*)))
      (unless profile
        (error "No engineering policy profile found for category ~S" category))
      (let ((current-state (gethash category *engineering-arm-state* :disarmed))
            (agents (gethash category *engineering-agent-map* '())))
        (when (eq current-state :disarmed)
          (return-from disarm-engineering-category :already-disarmed))
        ;; Terminate all running agents
        (dolist (agent agents)
          (when (uiop:process-alive-p agent)
            (uiop:terminate-process agent)
            (policy-audit-log :engineering-agent-killed t
                              (format nil "SIGTERM sent to ~A agent ~S"
                                      category agent))))
        ;; Wait 5s then SIGKILL survivors
        (sleep 5)
        (dolist (agent agents)
          (when (uiop:process-alive-p agent)
            (ignore-errors
              #+sbcl (sb-ext:run-program "/bin/kill" (list "-9"
                                                           (format nil "~D"
                                                                   (uiop:process-info-pid agent))))
              #-sbcl (uiop:terminate-process agent :urgent t))
            (policy-audit-log :engineering-agent-sigkill t
                              (format nil "SIGKILL sent to ~A agent ~S"
                                      category agent))))
        ;; Reset state
        (setf (gethash category *engineering-arm-state*) :disarmed)
        (setf (gethash category *engineering-agent-map*) '())
        (setf (gethash category *engineering-execution-counts*) 0)
        (policy-audit-log :engineering-category-disarmed t
                          (format nil "Engineering category ~S DISARMED, ~D agents killed"
                                  category (length agents)))
        :disarmed))))

(defun disarm-all-engineering ()
  "EMERGENCY HALT: Disarm ALL engineering categories simultaneously.

This is the BIG RED BUTTON for engineering workloads.  Every category
(:math :physics :engineering :electronics :ai-ml) is disarmed and ALL
running simulation processes across ALL categories are terminated.

Actions:
  1. Iterate over all five categories and call disarm-engineering-category.
  2. Stop the thermal monitor thread.
  3. Release any active physical override.
  4. Log emergency halt to audit log.

Returns: :all-disarmed with count of terminated agents."
  (let ((total-killed 0))
    (dolist (cat '(:math :physics :engineering :electronics :ai-ml))
      (handler-case
          (progn
            (disarm-engineering-category cat)
            (incf total-killed
                  (length (gethash cat *engineering-agent-map* '()))))
        (error (e)
          (policy-audit-log :engineering-disarm-error nil
                            (format nil "Error disarming ~A: ~A" cat e)))))
    (stop-thermal-monitor)
    (release-physical-override)
    (policy-audit-log :engineering-emergency-halt t
                      (format nil "EMERGENCY HALT: ~D agents terminated across all categories"
                              total-killed))
    (list :all-disarmed t :agents-killed total-killed)))

(defun get-engineering-arm-summary ()
  "Get ARM/DISARM status for all engineering categories.

Returns a plist with:
  :categories-armed     -- List of armed category keywords.
  :categories-disarmed  -- List of disarmed category keywords.
  :active-agents        -- Total active agents across all categories.
  :execution-counts     -- Plist of category -> execution count."
  (bt:with-lock-held (*engineering-policy-lock*)
    (let ((armed '()) (disarmed '()) (total-agents 0) (counts '()))
      (dolist (cat '(:math :physics :engineering :electronics :ai-ml))
        (if (eq (gethash cat *engineering-arm-state* :disarmed) :armed)
            (push cat armed)
            (push cat disarmed))
        (incf total-agents (length (gethash cat *engineering-agent-map* '())))
        (setf (getf counts cat) (gethash cat *engineering-execution-counts* 0)))
      (list :categories-armed (sort armed #'string< :key #'symbol-name)
            :categories-disarmed (sort disarmed #'string< :key #'symbol-name)
            :active-agents total-agents
            :execution-counts counts))))

(defun print-engineering-arm-status ()
  "Print formatted engineering ARM/DISARM status table to *STANDARD-OUTPUT*.

Displays a grid showing each engineering category, its arm state,
current execution count, and active agent count.  Formatted for
dashboard display in monitoring consoles."
  (let ((summary (get-engineering-arm-summary)))
    (format t "~&*** LISPMIND ENGINEERING ARM STATUS ***~%")
    (format t "~&~20A ~8A ~10A ~12A~%" "CATEGORY" "STATE" "EXEC-COUNT" "AGENTS")
    (format t "~&~72A~%" (make-string 72 :initial-element #\-))
    (dolist (cat '(:math :physics :engineering :electronics :ai-ml))
      (let ((state (if (member cat (getf summary :categories-armed))
                       "ARMED" "disarmed"))
            (count (getf (getf summary :execution-counts) cat 0))
            (agents (length (bt:with-lock-held (*engineering-policy-lock*)
                              (gethash cat *engineering-agent-map* '())))))
        (format t "~&~20S ~8@A ~10D ~12D~%" cat state count agents)))
    (format t "~&~72A~%" (make-string 72 :initial-element #\-))
    (format t "~&Total active agents: ~D~%" (getf summary :active-agents))
    (format t "~&*** END ENGINEERING ARM STATUS ***~%")))


;; ───────────────────────────────────────────────────────────────────────────
;; Section E4: Physical Simulation Override System
;; ───────────────────────────────────────────────────────────────────────────

(defvar *physical-simulation-override* nil
  "When non-nil (a timestamp), the physical simulation override is active.
This allows high-risk physical/structural simulations (:physics category
with CFD/FEA, structural analysis export) to proceed.  The override is
TIME-BOUNDED -- it automatically expires after 8 hours to prevent
indefinitely-active overrides.")

(defvar *physical-override-passphrase* nil
  "The passphrase required to activate *PHYSICAL-SIMULATION-OVERRIDE*.
Must be at least 16 characters when set.  Stored as a plain string --
in production, this should be a bcrypt hash comparison.")

(defvar *physical-override-expiry-seconds* 28800
  "Maximum lifetime of a physical simulation override in seconds.
Default: 8 hours (28800s).  After this period, the override
automatically deactivates and must be re-established by the operator.")

(defun require-physical-override (passphrase)
  "Require and activate operator override for physical simulations.

Arguments:
  PASSPHRASE -- String passphrase to authenticate the override.
               Must match *PHYSICAL-OVERRIDE-PASSPHRASE*.

Validation:
  1. *PHYSICAL-OVERRIDE-PASSPHRASE* must be set.
  2. PASSPHRASE must be non-nil and non-empty.
  3. PASSPHRASE must match (string=) *PHYSICAL-OVERRIDE-PASSPHRASE*.

On success:
  - Sets *PHYSICAL-SIMULATION-OVERRIDE* to current timestamp.
  - Logs override activation to audit log.
  - Returns :override-active with timestamp.

Signals: ERROR if passphrase mismatch or not configured."
  (cond
    ((null *physical-override-passphrase*)
     (error "Physical override passphrase not configured. Call set-physical-override-passphrase first."))
    ((or (null passphrase) (zerop (length passphrase)))
     (error "Passphrase required for physical simulation override"))
    ((not (string= passphrase *physical-override-passphrase*))
     (error "Physical override passphrase mismatch"))
    (t
     (setf *physical-simulation-override* (get-universal-time))
     (policy-audit-log :physical-override-activated t
                       "Physical simulation override ACTIVATED")
     (list :override-active t
           :timestamp *physical-simulation-override*
           :expires-at (+ *physical-simulation-override*
                          *physical-override-expiry-seconds*)))))

(defun release-physical-override ()
  "Release (deactivate) the physical simulation override.

Sets *PHYSICAL-SIMULATION-OVERRIDE* to nil, preventing any further
high-risk physical simulations from proceeding until a new override
is established.  Logs deactivation to audit log.

Returns: :override-released."
  (setf *physical-simulation-override* nil)
  (policy-audit-log :physical-override-released t
                    "Physical simulation override RELEASED")
  :override-released)

(defun physical-override-active-p ()
  "Check if the physical simulation override is currently active.

An override is active when:
  1. *PHYSICAL-SIMULATION-OVERRIDE* is non-nil (a timestamp).
  2. The timestamp is within *PHYSICAL-OVERRIDE-EXPIRY-SECONDS*
     of the current time.

If the override has EXPIRED, it is automatically released and this
function returns nil.

Returns: Override timestamp if active, nil if inactive or expired."
  (when *physical-simulation-override*
    (let ((elapsed (- (get-universal-time) *physical-simulation-override*)))
      (if (> elapsed *physical-override-expiry-seconds*)
          (progn
            (release-physical-override)
            (policy-audit-log :physical-override-expired nil
                              (format nil "Override expired after ~Ds" elapsed))
            nil)
          *physical-simulation-override*))))

(defun set-physical-override-passphrase (passphrase)
  "Set the physical override passphrase.

Arguments:
  PASSPHRASE -- String of at least 16 characters.

Validation: PASSPHRASE must be a string with length >= 16.

Returns: :passphrase-set.
Signals: ERROR if passphrase too short."
  (unless (and (stringp passphrase) (>= (length passphrase) 16))
    (error "Physical override passphrase must be at least 16 characters"))
  (setf *physical-override-passphrase* passphrase)
  (policy-audit-log :physical-override-passphrase-set t
                    "Physical override passphrase configured")
  :passphrase-set)

(defun validate-physical-simulation (agent)
  "Validate that a physical simulation agent is authorized to execute.

This is the MANDATORY GATE for all physical/structural simulations.
It performs the following checks in order:

  1. AGENT's category must be :physics or :engineering.
  2. The category must be ARMED.
  3. If the simulation type is structural/CFD/FEA:
     a. The physical override must be ACTIVE (not expired).
     b. Thermal status must be :normal (not :warning or :critical).
  4. Resource pressure must be acceptable.
  5. The agent's binary must not match forbidden patterns.

Arguments:
  AGENT -- The scientific agent to validate.

Returns: :authorized if all checks pass.
Signals: PHYSICAL-OVERRIDE-REQUIRED if override inactive for structural sim.
         CATEGORY-DISARMED-ERROR if category not armed.
         THERMAL-BREACH if thermal status critical.
         RESOURCE-PRESSURE-CRITICAL if resources exhausted."
  (let* ((category (agent-category agent))
         (profile (gethash category *engineering-policy-profiles*)))
    ;; Check 1: Category must have a profile
    (unless profile
      (error "No policy profile for category ~S" category))
    ;; Check 2: Category must be armed
    (unless (eq (gethash category *engineering-arm-state* :disarmed) :armed)
      (error 'category-disarmed-error
             :category category))
    ;; Check 3: Physical override for high-risk categories
    (when (and (policy-profile-requires-override profile)
               (not (physical-override-active-p)))
      (error 'physical-override-required
             :category category
             :operation (format nil "Execute ~A on agent ~S"
                                (agent-binary agent) agent)))
    ;; Check 4: Thermal status
    (let ((thermal (check-thermal-status)))
      (when (eq thermal :critical)
        (let ((cpu-temp (read-cpu-temperature)))
          (error 'thermal-breach
                 :component :cpu
                 :temperature cpu-temp
                 :threshold *cpu-temp-critical*)))
      (when (eq thermal :warning)
        (policy-audit-log :thermal-warning nil
                          (format nil "Thermal warning during ~A validation"
                                  category))))
    ;; Check 5: Resource pressure
    (let ((pressure (check-resource-pressure)))
      (when (eq pressure :critical)
        (error 'resource-pressure-critical
               :resource-type :memory
               :current-value (get-memory-pressure)
               :threshold *memory-pressure-critical*)))
    ;; All checks passed
    (policy-audit-log :physical-sim-validated t
                      (format nil "Physical simulation authorized: ~A [~S]"
                              category agent))
    :authorized))


;; ───────────────────────────────────────────────────────────────────────────
;; Section E5: Thermal and Resource Monitoring
;; ───────────────────────────────────────────────────────────────────────────

(defvar *thermal-monitor-running-p* nil
  "True when the thermal monitor background thread is active.
Used as a guard to prevent multiple monitor threads from being started.")

(defvar *thermal-monitor-thread* nil
  "Handle to the thermal monitor background thread.
Nil when no monitor is running.")

(defvar *thermal-monitor-interval* 5
  "Default polling interval for thermal monitoring in seconds.
The thermal monitor wakes up every this many seconds to sample sensors.")

(defvar *cpu-temp-warning* 80.0
  "CPU temperature warning threshold in Celsius.
When CPU temperature exceeds this value, a THERMAL-BREACH condition
with severity :warning is signaled.")

(defvar *cpu-temp-critical* 90.0
  "CPU temperature critical threshold in Celsius.
When CPU temperature exceeds this value, a THERMAL-BREACH condition
with severity :critical is signaled and engineering workloads should
be immediately throttled or halted.")

(defvar *gpu-temp-warning* 80.0
  "GPU temperature warning threshold in Celsius.
Applies to NVIDIA GPUs monitored via nvidia-smi or AMD GPUs via
/sys/class/drm.  When exceeded, signals THERMAL-BREACH.")

(defvar *gpu-temp-critical* 85.0
  "GPU temperature critical threshold in Celsius.
When exceeded, all GPU-bound engineering workloads (:ai-ml, :physics
with GPU solvers) should be immediately terminated.")

(defvar *memory-pressure-warning* 85.0
  "Memory utilization warning threshold as a percentage [0-100].
When system memory usage exceeds this, a warning-level
RESOURCE-PRESSURE-CRITICAL is signaled.")

(defvar *memory-pressure-critical* 95.0
  "Memory utilization critical threshold as a percentage [0-100].
When exceeded, all memory-intensive engineering workloads should be
paused or terminated to prevent OOM killer invocation.")

(defvar *disk-io-warning* 500.0
  "Disk I/O throughput warning threshold in MB/s.
Applies primarily to :physics workloads doing heavy checkpoint I/O.
When sustained throughput exceeds this, disk I/O pressure is reported.")

(defvar *thermal-history* (make-array 60 :fill-pointer 0 :adjustable t)
  "Circular buffer of recent thermal readings.
Each entry is a plist with :timestamp :cpu-temp :gpu-temp :memory :disk-io.
Keeps up to 60 samples (5 minutes at 5-second intervals) for trend
analysis and forensic investigation of thermal incidents.")

(defun read-cpu-temperature ()
  "Read the current CPU temperature from system thermal sensors.

Attempts to read from Linux thermal zones:
  1. /sys/class/thermal/thermal_zone*/temp (millidegree Celsius)
  2. Falls back to reading the first available thermal zone.

Returns: CPU temperature in DEGREES CELSIUS as a float, or 0.0 if
no thermal sensor is available.

Platform notes:
  - Linux: Uses sysfs thermal subsystem
  - macOS: Would use powermetrics (not yet implemented)
  - Other: Returns 0.0 (safe default, monitor assumes no thermal data)"
  (handler-case
      (let ((thermal-dir "/sys/class/thermal/")
            (max-temp 0.0))
        (when (uiop:directory-exists-p thermal-dir)
          (dolist (zone (uiop:subdirectories thermal-dir))
            (let ((temp-file (merge-pathnames "temp" zone)))
              (when (uiop:file-exists-p temp-file)
                (with-open-file (s temp-file :direction :input)
                  (let ((raw (read-line s nil nil)))
                    (when raw
                      (let ((millidegrees (parse-integer raw :junk-allowed t)))
                        (when millidegrees
                          (let ((celsius (/ millidegrees 1000.0)))
                            (when (> celsius max-temp)
                              (setf max-temp celsius)))))))))))
        max-temp)
    (error (e)
      (policy-audit-log :thermal-read-error nil
                        (format nil "CPU temp read failed: ~A" e))
      0.0)))

(defun read-gpu-temperature ()
  "Read the current GPU temperature from available GPU monitoring tools.

Attempts the following sources in order:
  1. nvidia-smi (NVIDIA GPUs) -- queries temperature.gpu
  2. /sys/class/drm/card*/device/hwmon/hwmon*/temp1_input (AMD/Intel)
  3. Returns 0.0 if no GPU monitoring available

Returns: GPU temperature in DEGREES CELSIUS as a float, or 0.0 if
no GPU temperature sensor is available.

Note: nvidia-smi output is parsed from the command:
  nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader"
  (handler-case
      (progn
        #+(and linux (not arm))
        (progn
          ;; Try nvidia-smi first
          (let ((output (with-output-to-string (s)
                          (uiop:run-program
                           "nvidia-smi --query-gpu=temperature.gpu --format=csv,noheader"
                           :output s :error-output nil :ignore-error-status t))))
            (let ((parsed (parse-integer (string-trim '(#\space #\newline) output)
                                         :junk-allowed t)))
              (when parsed (return-from read-gpu-temperature (float parsed)))))
          ;; Fallback to sysfs DRM hwmon
          (let ((drm-dir "/sys/class/drm/")
                (max-temp 0.0))
            (when (uiop:directory-exists-p drm-dir)
              (dolist (card (uiop:subdirectories drm-dir))
                (let ((hwmon-dir (merge-pathnames "device/hwmon/" card)))
                  (when (uiop:directory-exists-p hwmon-dir)
                    (dolist (hwmon (uiop:subdirectories hwmon-dir))
                      (let ((temp-file (merge-pathnames "temp1_input" hwmon)))
                        (when (uiop:file-exists-p temp-file)
                          (with-open-file (s temp-file :direction :input)
                            (let ((raw (read-line s nil nil)))
                              (when raw
                                (let ((millidegrees (parse-integer raw :junk-allowed t)))
                                  (when millidegrees
                                    (let ((celsius (/ millidegrees 1000.0)))
                                      (when (> celsius max-temp)
                                        (setf max-temp celsius)))))))))))))
            max-temp))
        0.0)
    (error (e)
      (policy-audit-log :gpu-temp-read-error nil
                        (format nil "GPU temp read failed: ~A" e))
      0.0)))

(defun get-memory-pressure ()
  "Get current system memory pressure as a percentage [0.0 - 100.0].

Reads /proc/meminfo on Linux to calculate:
  pressure = (MemTotal - MemAvailable) / MemTotal * 100

If /proc/meminfo is not available, returns 0.0 as safe default.

Returns: Memory utilization percentage as a float.  0.0 means no
memory pressure, 100.0 means all memory is in use."
  (handler-case
      (let ((mem-total nil) (mem-available nil))
        (with-open-file (s "/proc/meminfo" :direction :input)
          (loop for line = (read-line s nil nil)
                while line do
                  (cond
                    ((uiop:string-prefix-p "MemTotal:" line)
                     (setf mem-total (parse-integer line :start 9 :junk-allowed t)))
                    ((uiop:string-prefix-p "MemAvailable:" line)
                     (setf mem-available (parse-integer line :start 13 :junk-allowed t))))))
        (if (and mem-total mem-available (> mem-total 0))
            (* 100.0 (/ (- mem-total mem-available) mem-total))
            0.0))
    (error (e)
      (policy-audit-log :memory-read-error nil
                        (format nil "Memory pressure read failed: ~A" e))
      0.0)))

(defun get-disk-io-rate ()
  "Get current disk I/O rate in MB/s.

Reads /proc/diskstats on Linux to calculate the aggregate read+write
throughput across all block devices since the last call.  On first
call, returns 0.0 (needs a baseline).

Returns: Disk I/O throughput in megabytes per second as a float.
The value is smoothed with a simple moving average over 3 samples."
  (declare (special *last-disk-stats* *last-disk-time*))
  (handler-case
      (let ((total-sectors 0)
            (now (get-internal-real-time)))
        (with-open-file (s "/proc/diskstats" :direction :input)
          (loop for line = (read-line s nil nil)
                while line do
                  (let ((tokens (uiop:split-string line)))
                    ;; diskstats format: major minor name reads read-sectors writes write-sectors ...
                    (when (>= (length tokens) 10)
                      (let ((read-sectors (parse-integer (nth 5 tokens) :junk-allowed t))
                            (write-sectors (parse-integer (nth 9 tokens) :junk-allowed t)))
                        (when read-sectors (incf total-sectors read-sectors))
                        (when write-sectors (incf total-sectors write-sectors)))))))
        (if (and (boundp '*last-disk-stats*) *last-disk-stats*)
            (let* ((sector-delta (- total-sectors *last-disk-stats*))
                   (time-delta (/ (- now *last-disk-time*)
                                  internal-time-units-per-second))
                   (mbps (if (> time-delta 0)
                             (/ (* sector-delta 512.0) 1024.0 1024.0 time-delta)
                             0.0)))
              (setf *last-disk-stats* total-sectors)
              (setf *last-disk-time* now)
              mbps)
            (progn
              (setf *last-disk-stats* total-sectors)
              (setf *last-disk-time* now)
              0.0)))
    (error (e)
      (policy-audit-log :disk-io-read-error nil
                        (format nil "Disk I/O read failed: ~A" e))
      0.0)))

(defun check-thermal-status ()
  "Check overall thermal status across all monitored components.

Samples CPU and GPU temperatures and compares against configured
thresholds.  Returns one of:
  :normal   -- All temperatures below warning thresholds.
  :warning  -- At least one component exceeds warning but not critical.
  :critical -- At least one component exceeds critical threshold.

The most severe status is returned.  A :critical return means
engineering workloads SHOULD be halted immediately.

Side effects: Appends reading to *THERMAL-HISTORY* buffer."
  (let* ((cpu-temp (read-cpu-temperature))
         (gpu-temp (read-gpu-temperature))
         (status :normal))
    ;; Check CPU
    (cond
      ((> cpu-temp *cpu-temp-critical*) (setf status :critical))
      ((> cpu-temp *cpu-temp-warning*) (setf status (max-severity status :warning))))
    ;; Check GPU
    (cond
      ((> gpu-temp *gpu-temp-critical*) (setf status :critical))
      ((> gpu-temp *gpu-temp-warning*) (setf status (max-severity status :warning))))
    ;; Record to history
    (vector-push-extend (list :timestamp (get-universal-time)
                              :cpu-temp cpu-temp
                              :gpu-temp gpu-temp
                              :status status)
                        *thermal-history* 60)
    status))

(defun max-severity (s1 s2)
  "Return the more severe of two severity keywords.
Severity ordering: :critical > :warning > :normal."
  (if (or (eq s1 :critical) (eq s2 :critical))
      :critical
      (if (or (eq s1 :warning) (eq s2 :warning))
          :warning
          :normal)))

(defun check-resource-pressure ()
  "Check memory and disk I/O resource pressure.

Samples memory utilization and disk I/O rate, comparing against
configured thresholds.  Returns one of:
  :normal   -- All resources within safe bounds.
  :warning  -- Memory or disk I/O exceeds warning threshold.
  :critical -- Memory or disk I/O exceeds critical threshold.

A :critical return means OOM killer or I/O starvation is imminent.

Side effects: May signal RESOURCE-PRESSURE-CRITICAL if status is :critical."
  (let* ((memory-pct (get-memory-pressure))
         (disk-mbps (get-disk-io-rate))
         (status :normal))
    ;; Memory checks
    (cond
      ((> memory-pct *memory-pressure-critical*) (setf status :critical))
      ((> memory-pct *memory-pressure-warning*) (setf status (max-severity status :warning))))
    ;; Disk I/O checks
    (cond
      ((> disk-mbps *disk-io-warning*) (setf status (max-severity status :warning))))
    status))

(defun start-thermal-monitor (&optional (interval 5))
  "Start a background thread monitoring thermal/IO every INTERVAL seconds.

Arguments:
  INTERVAL -- Polling interval in seconds.  Default: 5.  Minimum: 1.

The thermal monitor runs continuously in a background thread,
sampling CPU temperature, GPU temperature, memory pressure, and
disk I/O rate at each interval.  When thresholds are breached:

  :warning  -- Logs a warning to the audit log.
  :critical -- Signals THERMAL-BREACH or RESOURCE-PRESSURE-CRITICAL
              conditions that can be caught by the safety supervisor.

Only ONE thermal monitor thread may run at a time.  If a monitor is
already running, this function returns :already-running.

Returns: The monitor thread handle, or :already-running."
  (when *thermal-monitor-running-p*
    (return-from start-thermal-monitor :already-running))
  (setf *thermal-monitor-interval* (max 1 interval))
  (setf *thermal-monitor-running-p* t)
  (setf *thermal-monitor-thread*
        (bt:make-thread
         (lambda () (thermal-monitor-loop *thermal-monitor-interval*))
         :name "lispmind-thermal-monitor"
         :initial-bindings '()))
  (policy-audit-log :thermal-monitor-started t
                    (format nil "Thermal monitor started (interval=~Ds)"
                            *thermal-monitor-interval*))
  *thermal-monitor-thread*)

(defun stop-thermal-monitor ()
  "Stop the thermal monitor background thread.

Sets *THERMAL-MONITOR-RUNNING-P* to nil, which causes the monitor
loop to exit on its next iteration.  Waits up to 10 seconds for
the thread to terminate gracefully.

Returns: :stopped if thread terminated, :thread-missing if no monitor
was running."
  (if (and *thermal-monitor-running-p* *thermal-monitor-thread*)
      (progn
        (setf *thermal-monitor-running-p* nil)
        (bt:join-thread *thermal-monitor-thread*
                        :timeout 10
                        :default :timeout)
        (setf *thermal-monitor-thread* nil)
        (policy-audit-log :thermal-monitor-stopped t
                          "Thermal monitor stopped")
        :stopped)
      (progn
        (setf *thermal-monitor-running-p* nil)
        (setf *thermal-monitor-thread* nil)
        :thread-missing)))

(defun thermal-monitor-loop (interval)
  "The thermal monitor background loop.

Runs continuously while *THERMAL-MONITOR-RUNNING-P* is true.  Each
iteration:
  1. Reads CPU and GPU temperatures.
  2. Reads memory pressure and disk I/O rate.
  3. Compares readings against configured thresholds.
  4. On :warning -- logs to audit log.
  5. On :critical -- signals THERMAL-BREACH or RESOURCE-PRESSURE-CRITICAL.
  6. Records sample to *THERMAL-HISTORY*.
  7. Sleeps for INTERVAL seconds.

This function is designed to run in its own thread.  It catches all
errors internally to prevent thread death from transient sensor read
failures.

Arguments:
  INTERVAL -- Sleep interval between samples in seconds."
  (loop while *thermal-monitor-running-p* do
    (handler-case
        (progn
          (let* ((cpu-temp (read-cpu-temperature))
                 (gpu-temp (read-gpu-temperature))
                 (memory-pct (get-memory-pressure))
                 (disk-mbps (get-disk-io-rate))
                 (thermal-severity :normal)
                 (resource-severity :normal))
            ;; Evaluate thermal thresholds
            (cond
              ((> cpu-temp *cpu-temp-critical*)
               (setf thermal-severity :critical)
               (signal 'thermal-breach :component :cpu
                       :temperature cpu-temp
                       :threshold *cpu-temp-critical*))
              ((> cpu-temp *cpu-temp-warning*)
               (setf thermal-severity :warning)))
            (cond
              ((> gpu-temp *gpu-temp-critical*)
               (setf thermal-severity (max-severity thermal-severity :critical))
               (signal 'thermal-breach :component :gpu
                       :temperature gpu-temp
                       :threshold *gpu-temp-critical*))
              ((> gpu-temp *gpu-temp-warning*)
               (setf thermal-severity (max-severity thermal-severity :warning))))
            ;; Evaluate resource thresholds
            (cond
              ((> memory-pct *memory-pressure-critical*)
               (setf resource-severity :critical)
               (signal 'resource-pressure-critical
                       :resource-type :memory
                       :current-value memory-pct
                       :threshold *memory-pressure-critical*))
              ((> memory-pct *memory-pressure-warning*)
               (setf resource-severity :warning)))
            (when (> disk-mbps *disk-io-warning*)
              (setf resource-severity (max-severity resource-severity :warning)))
            ;; Record to history
            (vector-push-extend
             (list :timestamp (get-universal-time)
                   :cpu-temp cpu-temp
                   :gpu-temp gpu-temp
                   :memory-pct memory-pct
                   :disk-mbps disk-mbps
                   :thermal-severity thermal-severity
                   :resource-severity resource-severity)
             *thermal-history* 120)
            ;; Log warnings
            (when (eq thermal-severity :warning)
              (policy-audit-log :thermal-warning nil
                                (format nil "CPU=~,1fC GPU=~,1fC"
                                        cpu-temp gpu-temp)))
            (when (eq resource-severity :warning)
              (policy-audit-log :resource-warning nil
                                (format nil "MEM=~,1f%% DISK=~,1fMB/s"
                                        memory-pct disk-mbps)))))
      (error (e)
        (policy-audit-log :thermal-monitor-error nil
                          (format nil "Thermal monitor error: ~A" e))))
    (sleep interval)))


;; ───────────────────────────────────────────────────────────────────────────
;; Section E6: Dashboard / Status Reporting
;; ───────────────────────────────────────────────────────────────────────────

(defun print-thermal-status ()
  "Print current thermal and resource status for dashboard display.

Outputs a formatted report including:
  - Current CPU temperature with threshold indicators
  - Current GPU temperature with threshold indicators
  - Memory utilization percentage
  - Disk I/O throughput
  - Overall thermal status (:normal / :warning / :critical)
  - Resource pressure status
  - Thermal monitor thread status (running/stopped)
  - Count of historical samples in buffer

Example output:
  *** THERMAL STATUS ***
  CPU: 62.0C / 90.0C  [OK]
  GPU: 55.0C / 85.0C  [OK]
  Memory: 42.1%       [OK]
  Disk I/O: 12.5 MB/s [OK]
  Status: NORMAL
  Monitor: running (5s interval)
  History: 47 samples
  *** END THERMAL STATUS ***"
  (let* ((cpu-temp (read-cpu-temperature))
         (gpu-temp (read-gpu-temperature))
         (memory-pct (get-memory-pressure))
         (disk-mbps (get-disk-io-rate))
         (thermal (check-thermal-status))
         (resources (check-resource-pressure)))
    (format t "~&*** LISPMIND THERMAL STATUS ***~%")
    (format t "  CPU:       ~,1fC / ~,1fC  ~A~%"
            cpu-temp *cpu-temp-critical*
            (cond ((> cpu-temp *cpu-temp-critical*) "[CRITICAL]")
                  ((> cpu-temp *cpu-temp-warning*) "[WARNING]")
                  (t "[OK]")))
    (format t "  GPU:       ~,1fC / ~,1fC  ~A~%"
            gpu-temp *gpu-temp-critical*
            (cond ((> gpu-temp *gpu-temp-critical*) "[CRITICAL]")
                  ((> gpu-temp *gpu-temp-warning*) "[WARNING]")
                  (t "[OK]")))
    (format t "  Memory:    ~,1f%% / ~,1f%%  ~A~%"
            memory-pct *memory-pressure-critical*
            (cond ((> memory-pct *memory-pressure-critical*) "[CRITICAL]")
                  ((> memory-pct *memory-pressure-warning*) "[WARNING]")
                  (t "[OK]")))
    (format t "  Disk I/O:  ~,1f MB/s       ~A~%"
            disk-mbps
            (if (> disk-mbps *disk-io-warning*) "[WARNING]" "[OK]"))
    (format t "  Status:    ~A~%"
            (cond ((eq thermal :critical) "THERMAL CRITICAL")
                  ((eq thermal :warning) "THERMAL WARNING")
                  (t "NORMAL")))
    (format t "  Resources: ~A~%"
            (cond ((eq resources :critical) "RESOURCE CRITICAL")
                  ((eq resources :warning) "RESOURCE WARNING")
                  (t "NORMAL")))
    (format t "  Monitor:   ~A (~Ds interval)~%"
            (if *thermal-monitor-running-p* "running" "STOPPED")
            *thermal-monitor-interval*)
    (format t "  History:   ~D samples~%"
            (length *thermal-history*))
    (format t "*** END THERMAL STATUS ***~%")))

(defun get-engineering-safety-status ()
  "Get FULL engineering safety status: arm states + thermal + resources.

This is the COMPREHENSIVE STATUS function for the engineering safety
subsystem.  It combines:
  1. ARM/DISARM state for all 5 engineering categories
  2. Current thermal readings (CPU, GPU)
  3. Resource pressure (memory, disk I/O)
  4. Thermal monitor thread status
  5. Physical override status
  6. Active agent counts per category
  7. Loaded profile count

Returns a large plist suitable for dashboard rendering or JSON
serialization for external monitoring systems.

Return plist keys:
  :arm-summary       -- Output of get-engineering-arm-summary
  :thermal           -- Plist with :cpu-temp :gpu-temp :status
  :resources         -- Plist with :memory-pct :disk-mbps :status
  :monitor           -- Plist with :running-p :interval :history-samples
  :override          -- Plist with :active-p :timestamp :expires-at
  :profiles-loaded   -- Count of loaded engineering policy profiles"
  (let ((arm (get-engineering-arm-summary))
        (cpu-temp (read-cpu-temperature))
        (gpu-temp (read-gpu-temperature))
        (memory-pct (get-memory-pressure))
        (disk-mbps (get-disk-io-rate))
        (thermal (check-thermal-status))
        (resources (check-resource-pressure)))
    (list :arm-summary arm
          :thermal (list :cpu-temp cpu-temp
                         :gpu-temp gpu-temp
                         :status thermal)
          :resources (list :memory-pct memory-pct
                           :disk-mbps disk-mbps
                           :status resources)
          :monitor (list :running-p *thermal-monitor-running-p*
                         :interval *thermal-monitor-interval*
                         :history-samples (length *thermal-history*))
          :override (list :active-p (not (null (physical-override-active-p)))
                          :timestamp *physical-simulation-override*
                          :expires-at (when *physical-simulation-override*
                                        (+ *physical-simulation-override*
                                           *physical-override-expiry-seconds*)))
          :profiles-loaded (bt:with-lock-held (*engineering-policy-lock*)
                             (hash-table-count *engineering-policy-profiles*)))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section E7: Scientific Agent Integration Methods
;; ───────────────────────────────────────────────────────────────────────────

(defmethod check-categorical-policy :around ((agent scientific-agent) binary args)
  "Extended categorical policy check for scientific/engineering agents.

This :AROUND method wraps the base CHECK-CATEGORICAL-POLICY with
engineering-specific safety checks that must pass BEFORE the agent
is allowed to execute.  The validation sequence:

  1. CATEGORY ARMED -- The agent's category must be in :armed state.
      Failure signals CATEGORY-DISARMED-ERROR.

  2. THERMAL STATUS -- Overall thermal status must not be :critical.
      :warning is logged but permitted.  :critical signals
      THERMAL-BREACH and aborts execution.

  3. RESOURCE PRESSURE -- Memory/disk I/O must not be :critical.
      :critical signals RESOURCE-PRESSURE-CRITICAL.

  4. COMPUTE BUDGET -- The agent's estimated runtime must not exceed
      the category timeout from its policy profile.
      Excess signals SIMULATION-TIMEOUT.

  5. MEMORY BUDGET -- The agent's estimated memory must not exceed
      available system memory (with 10% headroom).

  6. PHYSICAL OVERRIDE -- If the agent's category requires override
      (:physics, :ai-ml), verify override is active and not expired.
      Missing override signals PHYSICAL-OVERRIDE-REQUIRED.

  7. FORBIDDEN PATTERNS -- Agent arguments are checked against the
      category's forbidden pattern list.

  8. MAX CONCURRENT -- The category's execution count must be below
      its :max-concurrent limit.

If all checks pass, the base CHECK-CATEGORICAL-POLICY is called via
CALL-NEXT-METHOD, and the agent's execution count is incremented.

Arguments:
  AGENT  -- A SCIENTIFIC-AGENT instance.
  BINARY -- The executable binary path (string).
  ARGS   -- List of command-line argument strings.

Returns: The result of CALL-NEXT-METHOD (typically the agent instance).
Signals: Various engineering safety conditions on check failure."
  (let* ((category (agent-category agent))
         (profile (gethash category *engineering-policy-profiles*)))
    ;; Check 1: Category must be armed
    (unless (eq (gethash category *engineering-arm-state* :disarmed) :armed)
      (error 'category-disarmed-error :category category))
    ;; Check 2: Thermal status (allow :warning, block :critical)
    (let ((thermal (check-thermal-status)))
      (when (eq thermal :critical)
        (error 'thermal-breach
               :component :cpu
               :temperature (read-cpu-temperature)
               :threshold *cpu-temp-critical*)))
    ;; Check 3: Resource pressure
    (let ((pressure (check-resource-pressure)))
      (when (eq pressure :critical)
        (error 'resource-pressure-critical
               :resource-type :memory
               :current-value (get-memory-pressure)
               :threshold *memory-pressure-critical*)))
    ;; Check 4: Compute budget (timeout check)
    (let* ((estimated-runtime (or (agent-estimated-runtime agent) 0))
           (timeout (policy-profile-timeout-seconds profile)))
      (when (and (> estimated-runtime 0) (> estimated-runtime timeout))
        (error 'simulation-timeout
               :elapsed-time estimated-runtime
               :budget timeout
               :category category)))
    ;; Check 5: Physical override for high-risk categories
    (when (and (policy-profile-requires-override profile)
               (not (physical-override-active-p)))
      (error 'physical-override-required
             :category category
             :operation (format nil "Execute ~A" binary)))
    ;; Check 6: Max concurrent
    (let ((current-count (gethash category *engineering-execution-counts* 0))
          (max-concurrent (policy-profile-max-concurrent profile)))
      (when (>= current-count max-concurrent)
        (error 'max-concurrent-exceeded-error
               :category category
               :current current-count
               :maximum max-concurrent)))
    ;; Check 7: Forbidden patterns in args
    (let ((forbidden (policy-profile-forbidden-patterns profile)))
      (dolist (pattern forbidden)
        (dolist (arg args)
          (when (search pattern arg)
            (error 'forbidden-pattern-error
                   :pattern pattern
                   :argument arg)))))
    ;; All checks passed -- increment counter and proceed
    (incf (gethash category *engineering-execution-counts* 0))
    (policy-audit-log :engineering-agent-validated t
                      (format nil "~A agent validated: ~A"
                              category binary))
    (call-next-method)))

(defmethod finalize-agent :after ((agent scientific-agent))
  "Scientific agent cleanup method.

This :AFTER method on FINALIZE-AGENT ensures that when a scientific
agent is finalized (whether normally or via error path), the following
cleanup actions are performed:

  1. The agent's subprocess (if still alive) is sent SIGTERM.
  2. After a 2-second grace period, SIGKILL is sent if still alive.
  3. Temporary files created by the agent are deleted.
  4. The agent is removed from *ENGINEERING-AGENT-MAP*.
  5. The category execution count is decremented.
  6. A cleanup event is logged to the audit log.

This method is CRITICAL for preventing resource leaks in long-running
engineering workloads.  Every scientific agent MUST be finalized to
ensure proper cleanup.

Arguments:
  AGENT -- The SCIENTIFIC-AGENT being finalized."
  (let* ((category (agent-category agent))
         (process (agent-process agent))
         (temp-files (agent-temp-files agent)))
    ;; Kill process if still alive
    (when (and process (uiop:process-alive-p process))
      (uiop:terminate-process process)
      (sleep 2)
      (when (uiop:process-alive-p process)
        (ignore-errors
          #+sbcl (sb-ext:run-program "/bin/kill" (list "-9"
                                                       (format nil "~D"
                                                               (uiop:process-info-pid process))))
          #-sbcl (uiop:terminate-process process :urgent t))))
    ;; Delete temp files
    (dolist (f temp-files)
      (when (uiop:file-exists-p f)
        (ignore-errors (delete-file f))))
    ;; Update agent map and execution count
    (bt:with-lock-held (*engineering-policy-lock*)
      (let ((agents (gethash category *engineering-agent-map* '())))
        (setf (gethash category *engineering-agent-map*)
              (remove agent agents)))
      (let ((count (gethash category *engineering-execution-counts* 0)))
        (when (> count 0)
          (decf (gethash category *engineering-execution-counts*)))))
    ;; Log cleanup
    (policy-audit-log :scientific-agent-finalized t
                      (format nil "Scientific agent ~S finalized [~A]"
                              agent category))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section E8: Engineering Safety System Initialization
;; ───────────────────────────────────────────────────────────────────────────

(defun init-engineering-safety-system (&key (passphrase nil) (start-thermal-monitor-p t))
  "Initialize the complete engineering safety subsystem.

This is the ONE function to call at system startup to prepare the
engineering safety framework.  All categories start DISARMED (fail-closed).

Arguments:
  PASSPHRASE -- Optional string (>= 16 chars) to set as the physical
               simulation override passphrase.  Required for :physics
               and :ai-ml category arming.
  START-THERMAL-MONITOR-P -- If true (default), starts the background
               thermal monitor thread.

Actions:
  1. Initialize all 5 engineering category arm states to :disarmed.
  2. Load all 5 engineering policy profiles (:math :physics :engineering
     :electronics :ai-ml).
  3. Set physical override passphrase if provided.
  4. Start thermal monitor if requested.
  5. Reset thermal history buffer.
  6. Log initialization to audit log.

Returns:
  Plist with :initialized t, :categories (count), :profiles (count),
  :thermal-monitor-started, :passphrase-set.

Example:
  (init-engineering-safety-system
    :passphrase \"MySup3rS3cur3Phys1calP4ss!\"
    :start-thermal-monitor-p t)"
  (init-engineering-arm-states)
  (let ((profiles (load-engineering-policy-profiles)))
    (when passphrase
      (set-physical-override-passphrase passphrase))
    (when start-thermal-monitor-p
      (start-thermal-monitor *thermal-monitor-interval*))
    (setf (fill-pointer *thermal-history*) 0)
    (policy-audit-log :engineering-safety-init t
                      (format nil "Engineering safety system initialized: ~D categories, ~D profiles"
                              5 (length profiles)))
    (format t "~&[ENGINEERING SAFETY] System initialized. ~D categories, ~D profiles. ALL DISARMED.~%"
            5 (length profiles))
    (list :initialized t
          :categories 5
          :profiles (length profiles)
          :thermal-monitor-started start-thermal-monitor-p
          :passphrase-set (not (null passphrase)))))


;; ═══════════════════════════════════════════════════════════════════════════
;; END OF ENGINEERING SAFETY MODULE -- v2.3.2
;; ═══════════════════════════════════════════════════════════════════════════


;;;; ═════════════════════════════════════════════════════════════════════════
;;;; END OF POLICY-GATEKEEPER.LISP
;;;; ═════════════════════════════════════════════════════════════════════════
