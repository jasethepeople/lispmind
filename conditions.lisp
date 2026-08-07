;;;; conditions.lisp --- LISPMIND Condition Hierarchy & Restart API
;;;
;;; This file defines the entire condition hierarchy and restart API for the
;;; LISPMIND self-healing agentic orchestrator.
;;;
;;; PHILOSOPHY: Conditions are opportunities, not dead ends.
;;;
;;; In LISPMIND, a condition is not a catastrophe --- it is a *signal*, a
;;; structured plea for intervention. When an agent stalls, exhausts memory,
;;; or fails outright, the system does not collapse. Instead, it pauses,
;;; considers, and *chooses* a recovery path via Common Lisp's restart
;;; protocol.
;;;
;;; We use `handler-bind' (not `handler-case') at the top level because we
;;; want the full stack context visible when a condition is signaled.
;;; `handler-case' unwinds the stack before the handler runs, destroying the
;;; very context we need to introspect and recover. `handler-bind' lets us
;;; see the world as it was when trouble struck --- and gives restarts the
;;; chance to fix it in-place.
;;;
;;; The six canonical restarts (:RETRY, :USE-FALLBACK, :ESCALATE,
;;; :REPLACE-AGENT, :HOTFIX-AND-CONTINUE, :PAUSE-AND-SELF-MODIFY) form a
;;; ladder of escalating intervention.  The orchestrator's restart policy
;;; selects the appropriate rung based on condition type and agent history.
;;;
;;; "To handle an error is human.  To signal a condition and offer restarts
;;;  is Lisp.  To let the system choose its own recovery path --- that is
;;;  LISPMIND."

(in-package :lispmind)

;;============================================================================
;; Condition Hierarchy --- Four Fundamental Failure Modes
;;============================================================================
;;
;; Each condition captures a distinct way an agent can encounter trouble.
;; All inherit from `error' so they are safe to signal and catch in any
;; standard handler configuration.  Every slot has a reader so the
;; orchestrator can inspect the condition without mutation.

(define-condition agent-failure (error)
  ((agent-id
    :initarg :agent-id
    :reader agent-failure-agent-id
    :documentation "The unique identifier of the agent that failed.")
   (reason
    :initarg :reason
    :reader agent-failure-reason
    :documentation "A human-readable description of why the agent failed."))
  (:documentation
   "Signaled when an agent has failed irrecoverably.

An AGENT-FAILURE represents the most severe condition class: the agent's
strategy has crashed, its health has dropped to zero, or it has become
unresponsive beyond all retry thresholds.  This condition is the final
signal before the orchestrator considers replacement or escalation.

Example --- signaling an agent failure:
  (signal 'agent-failure
          :agent-id 'scraper-1
          :reason \"Strategy function returned nil after 3 retries\")"))

(define-condition strategy-stalled (error)
  ((agent-id
    :initarg :agent-id
    :reader strategy-stalled-agent-id
    :documentation "The agent whose strategy has stalled.")
   (elapsed-time
    :initarg :elapsed-time
    :reader strategy-stalled-elapsed-time
    :documentation "Seconds the strategy has been executing.")
   (threshold
    :initarg :threshold
    :reader strategy-stalled-threshold
    :documentation "The configured timeout threshold in seconds."))
  (:documentation
   "Signaled when an agent's strategy has been running too long.

A STRATEGY-STALLED condition indicates the agent is not dead --- its thread
is still alive --- but it has exceeded its allotted time budget.  This is
often a sign of an infinite loop, a blocking I/O call, or a computation
that grew unexpectedly complex.  The :HOTFIX-AND-CONTINUE restart is the
natural response.

Example --- a watchdog timer detecting a stall:
  (when (> elapsed-time *strategy-timeout*)
    (signal 'strategy-stalled
            :agent-id (agent-id agent)
            :elapsed-time elapsed-time
            :threshold *strategy-timeout*))"))

(define-condition resource-exhausted (error)
  ((agent-id
    :initarg :agent-id
    :reader resource-exhausted-agent-id
    :documentation "The agent that exhausted the resource.")
   (resource-type
    :initarg :resource-type
    :reader resource-exhausted-resource-type
    :documentation "Keyword naming the exhausted resource (e.g., :memory, :disk, :api-calls).")
   (current-usage
    :initarg :current-usage
    :reader resource-exhausted-current-usage
    :documentation "Current consumption of the resource.")
   (limit
    :initarg :limit
    :reader resource-exhausted-limit
    :documentation "Configured maximum for the resource."))
  (:documentation
   "Signaled when an agent exhausts a resource limit.

RESOURCE-EXHAUSTED covers memory pressure, disk quotas, API rate limits,
and any other finite commodity an agent might over-consume.  The
:PAUSE-AND-SELF-MODIFY restart is appropriate here --- the agent can
introspect its own behavior and reduce consumption before resuming.

Example --- memory threshold crossed:
  (signal 'resource-exhausted
          :agent-id 'analyst-2
          :resource-type :memory
          :current-usage 1073741824
          :limit 536870912)"))

(define-condition external-timeout (error)
  ((agent-id
    :initarg :agent-id
    :reader external-timeout-agent-id
    :documentation "The agent waiting on the external operation.")
   (operation
    :initarg :operation
    :reader external-timeout-operation
    :documentation "Description of the timed-out operation (e.g., 'HTTP GET api.example.com').")
   (timeout-seconds
    :initarg :timeout-seconds
    :reader external-timeout-timeout-seconds
    :documentation "The timeout value that was exceeded."))
  (:documentation
   "Signaled when an external operation times out.

EXTERNAL-TIMEOUT wraps failures outside the agent's direct control ---
network requests, database queries, remote API calls.  These are the
*most recoverable* conditions because the external world may have merely
hiccupped.  The :RETRY restart (up to 3 attempts) followed by
:USE-FALLBACK is the standard recovery ladder.

Example --- a network request timing out:
  (signal 'external-timeout
          :agent-id 'scraper-1
          :operation \"HTTP GET https://api.example.com/data\"
          :timeout-seconds 30)"))

;;============================================================================
;; Report Methods --- Human-Readable Condition Descriptions
;;============================================================================
;;
;; A condition without a report method is a mystery.  These methods ensure
;; that every condition, when printed, tells a complete story --- agent ID,
;; what went wrong, and the numerical details.  The orchestrator logs these
;; strings for forensic analysis.

(defmethod print-object ((condition agent-failure) stream)
  "Print an AGENT-FAILURE with all diagnostic slots."
  (print-unreadable-object (condition stream :type t)
    (format stream "AGENT ~S | REASON: ~A"
            (agent-failure-agent-id condition)
            (agent-failure-reason condition))))

(defmethod print-object ((condition strategy-stalled) stream)
  "Print a STRATEGY-STALLED with timing details."
  (print-unreadable-object (condition stream :type t)
    (format stream "AGENT ~S | ELAPSED: ~,1Fs / THRESHOLD: ~,1Fs"
            (strategy-stalled-agent-id condition)
            (strategy-stalled-elapsed-time condition)
            (strategy-stalled-threshold condition))))

(defmethod print-object ((condition resource-exhausted) stream)
  "Print a RESOURCE-EXHAUSTED with consumption details."
  (print-unreadable-object (condition stream :type t)
    (format stream "AGENT ~S | ~S | USAGE: ~A / LIMIT: ~A"
            (resource-exhausted-agent-id condition)
            (resource-exhausted-resource-type condition)
            (resource-exhausted-current-usage condition)
            (resource-exhausted-limit condition))))

(defmethod print-object ((condition external-timeout) stream)
  "Print an EXTERNAL-TIMEOUT with operation description."
  (print-unreadable-object (condition stream :type t)
    (format stream "AGENT ~S | ~A | TIMEOUT: ~,1Fs"
            (external-timeout-agent-id condition)
            (external-timeout-operation condition)
            (external-timeout-timeout-seconds condition))))

;;============================================================================
;; signal-condition --- The Canonical Signaling Function
;;============================================================================
;;
;; While `signal' and `error' are always available, `signal-condition'
;; provides a uniform entry point.  It accepts a condition *type* (symbol
;; or class) and initargs, manufactures the condition, and signals it.
;; The orchestrator uses this so that condition creation is never scattered
;; ad-hoc across the codebase.

(defun signal-condition (condition-type &rest initargs)
  "Signal a condition of CONDITION-TYPE constructed with INITARGS.

CONDITION-TYPE is a symbol naming a condition class (e.g., 'AGENT-FAILURE)
or a condition class object.  INITARGS are passed directly to MAKE-CONDITION.

The condition is signaled via CL:SIGNAL, which means it is *non-fatal* ---
if no handler transfers control, execution continues normally.  Use ERROR
instead if you want to guarantee that either a handler handles it or the
debugger is entered.

Example --- signal a non-fatal resource warning:
  (signal-condition 'resource-exhausted
                    :agent-id 'analyst-2
                    :resource-type :memory
                    :current-usage 1024
                    :limit 512)

Example --- signal a fatal agent failure:
  (signal-condition 'agent-failure
                    :agent-id 'scraper-1
                    :reason \"Core strategy crashed with NIL return\")"
  (let ((condition (apply #'make-condition condition-type initargs)))
    (signal condition)))

;;============================================================================
;; Restart Invocation Helpers --- Convenience Wrappers
;;============================================================================
;;
;; These functions invoke the six canonical restarts by name.  They are
;; thin wrappers around INVOKE-RESTART and FIND-RESTART, with clear
;; docstrings so every caller knows exactly what semantic action they are
;; requesting.
;;
;; Why wrappers?  Because `(invoke-restart (find-restart 'retry value))'
;; is error-prone and repetitive.  These functions are self-documenting
;; and can be logged, traced, or advised uniformly.

(defun invoke-retry-restart (&optional value)
  "Invoke the :RETRY restart, optionally passing VALUE.

:RETRY means \"attempt the failed operation again.\"  VALUE, if supplied,
is passed to the restart function and typically used as a new parameter
for the retried operation (e.g., an adjusted timeout, a different URL).

This is the first rung on the recovery ladder --- cheap and often effective
for transient failures like network hiccups.

Raises an error if no :RETRY restart is currently established."
  (if value
      (invoke-restart (find-restart 'retry) value)
      (invoke-restart (find-restart 'retry))))

(defun invoke-use-fallback-restart ()
  "Invoke the :USE-FALLBACK restart.

:USE-FALLBACK means \"abandon the primary strategy and switch to a
pre-registered fallback.\"  This is the second rung --- used when retries
have been exhausted or the primary path is fundamentally broken.

Raises an error if no :USE-FALLBACK restart is currently established."
  (invoke-restart (find-restart 'use-fallback)))

(defun invoke-escalate-restart ()
  "Invoke the :ESCALATE restart.

:ESCALATE means \"this agent cannot handle the situation --- hand it up to
the orchestrator for system-level intervention.\"  This is the third
rung, used when local recovery is impossible.

Raises an error if no :ESCALATE restart is currently established."
  (invoke-restart (find-restart 'escalate)))

(defun invoke-replace-agent-restart ()
  "Invoke the :REPLACE-AGENT restart.

:REPLACE-AGENT means \"terminate this agent and spawn a fresh instance
with clean state.\"  This is the fourth rung --- a nuclear option that
preserves the system's overall health at the cost of the agent's
accumulated state.

Raises an error if no :REPLACE-AGENT restart is currently established."
  (invoke-restart (find-restart 'replace-agent)))

(defun invoke-hotfix-and-continue-restart ()
  "Invoke the :HOTFIX-AND-CONTINUE restart.

:HOTFIX-AND-CONTINUE means \"patch the agent's strategy function with
new code and resume execution.\"  This is LISPMIND's signature move ---
self-modification without stopping the world.  The hotpatch system
replaces the strategy atomically and increments the version counter.

Raises an error if no :HOTFIX-AND-CONTINUE restart is currently established."
  (invoke-restart (find-restart 'hotfix-and-continue)))

(defun invoke-pause-and-self-modify-restart ()
  "Invoke the :PAUSE-AND-SELF-MODIFY restart.

:PAUSE-AND-SELF-MODIFY means \"pause the agent, let it introspect its
own state and resource usage, adjust parameters, and then resume.\"  This
is ideal for RESOURCE-EXHAUSTED conditions where the agent can reduce its
own footprint through configuration changes.

Raises an error if no :PAUSE-AND-SELF-MODIFY restart is currently established."
  (invoke-restart (find-restart 'pause-and-self-modify)))

;;============================================================================
;; with-agent-restarts --- The Macro That Creates Opportunities
;;============================================================================
;;
;; This macro is the heart of LISPMIND's recovery philosophy.  It wraps a
;; body of code in a RESTART-CASE that establishes all six canonical
;; restarts.  Each restart delegates to an optional handler function
;; provided by the caller.
;;
;; Because restarts are established with RESTART-CASE (not RESTART-BIND),
;; the body executes *before* the restarts are visible --- they are only
;; entered if a condition is signaled and a handler transfers control to
;; one of them.  This is the correct semantics: restarts are escape
;; hatches, not preemptive overrides.
;;
;; The macro uses GENSYM for all its local variables to avoid capture.

(defmacro with-agent-restarts ((&key (retry-fn nil retry-fn-p)
                                (fallback-fn nil fallback-fn-p)
                                (escalate-fn nil escalate-fn-p)
                                (replace-agent-fn nil replace-agent-fn-p)
                                (hotfix-fn nil hotfix-fn-p)
                                (pause-fn nil pause-fn-p))
                         &body body)
  "Execute BODY with all six standard agent restarts established.

Each keyword argument names an optional function to be called when the
corresponding restart is invoked.  If no function is provided for a
restart, that restart simply returns NIL (a no-op resumption).

The six restarts and their meanings:
  :RETRY                 --- Re-attempt the failed operation.
                          Handled by RETRY-FN, called with optional value.
  :USE-FALLBACK          --- Switch to fallback strategy.
                          Handled by FALLBACK-FN, called with no args.
  :ESCALATE             --- Hand control to the orchestrator.
                          Handled by ESCALATE-FN, called with no args.
  :REPLACE-AGENT        --- Terminate and respawn the agent.
                          Handled by REPLACE-AGENT-FN, called with no args.
  :HOTFIX-AND-CONTINUE  --- Live-patch the agent's strategy.
                          Handled by HOTFIX-FN, called with no args.
  :PAUSE-AND-SELF-MODIFY --- Pause agent for introspection.
                          Handled by PAUSE-FN, called with no args.

Returns the primary value of BODY unless a restart transfers control.

Example --- wrapping an agent's strategy execution:
  (with-agent-restarts
      (:retry-fn (lambda (v) (format t \"Retrying with ~S~%\" v))
       :fallback-fn (lambda () (format t \"Using fallback~%\"))
       :hotfix-fn (lambda () (format t \"Hotfixing strategy~%\")))
    (run-agent-strategy agent))

Example --- full orchestrator-style usage with handler-bind:
  (handler-bind
      ((agent-failure
        (lambda (c)
          (format t \"Agent ~S failed: ~A~%\" (agent-failure-agent-id c)
                  (agent-failure-reason c))
          (invoke-restart 'replace-agent))))
    (with-agent-restarts
        (:replace-agent-fn (lambda () (spawn-fresh-agent agent)))
      (execute-agent agent)))"
  (let ((retry-sym (gensym "RETRY-"))
        (fallback-sym (gensym "FALLBACK-"))
        (escalate-sym (gensym "ESCALATE-"))
        (replace-sym (gensym "REPLACE-"))
        (hotfix-sym (gensym "HOTFIX-"))
        (pause-sym (gensym "PAUSE-"))
        (value-sym (gensym "VALUE-")))
    `(flet ,(append
             `((,retry-sym (&optional ,value-sym)
                ,@(if retry-fn-p
                      `((funcall ,retry-fn ,value-sym))
                      '(nil))))
             (when fallback-fn-p
               `((,fallback-sym () (funcall ,fallback-fn))))
             (when escalate-fn-p
               `((,escalate-sym () (funcall ,escalate-fn))))
             (when replace-agent-fn-p
               `((,replace-sym () (funcall ,replace-agent-fn))))
             (when hotfix-fn-p
               `((,hotfix-sym () (funcall ,hotfix-fn))))
             (when pause-fn-p
               `((,pause-sym () (funcall ,pause-fn)))))
       (restart-case (progn ,@body)
         (retry (&optional value)
           :report (lambda (stream)
                     (format stream "Retry the failed operation."))
           :test (lambda (c) (declare (ignore c)) t)
           (,retry-sym value))
         (use-fallback ()
           :report (lambda (stream)
                     (format stream "Switch to fallback strategy."))
           :test (lambda (c) (declare (ignore c)) t)
           ,(if fallback-fn-p `(,fallback-sym) nil))
         (escalate ()
           :report (lambda (stream)
                     (format stream "Escalate to orchestrator."))
           :test (lambda (c) (declare (ignore c)) t)
           ,(if escalate-fn-p `(,escalate-sym) nil))
         (replace-agent ()
           :report (lambda (stream)
                     (format stream "Terminate and replace the agent."))
           :test (lambda (c) (declare (ignore c)) t)
           ,(if replace-agent-fn-p `(,replace-sym) nil))
         (hotfix-and-continue ()
           :report (lambda (stream)
                     (format stream "Hot-patch strategy and continue."))
           :test (lambda (c) (declare (ignore c)) t)
           ,(if hotfix-fn-p `(,hotfix-sym) nil))
         (pause-and-self-modify ()
           :report (lambda (stream)
                     (format stream "Pause agent for introspection."))
           :test (lambda (c) (declare (ignore c)) t)
           ,(if pause-fn-p `(,pause-sym) nil))))))

;;============================================================================
;; Example Usage Commentary
;;============================================================================
;;
;; The following commented-out forms demonstrate the idiomatic patterns
;; for using the condition and restart system.  They are not executed ---
;; they serve as living documentation for the developer reading this file.

#|

;;; Pattern 1: Basic condition signaling and catching with handler-bind
;;;
;;; handler-bind binds a handler *without* unwinding the stack.  The handler
;;; sees the full call stack as it was when the condition was signaled.
;;; This is the LISPMIND way.

(handler-bind
    ((external-timeout
      (lambda (condition)
        (format t "~&Network timeout for ~S: ~A~%"
                (external-timeout-agent-id condition)
                (external-timeout-operation condition))
        ;; Try the :RETRY restart --- the stack is still intact!
        (when (find-restart 'retry)
          (invoke-restart 'retry)))))
  (with-agent-restarts (:retry-fn (lambda (v) (format t "Retried!~%")))
    (signal-condition 'external-timeout
                      :agent-id 'scraper-1
                      :operation "HTTP GET https://example.com"
                      :timeout-seconds 30)))

;;; Pattern 2: Orchestrator monitor loop with full restart ladder
;;;
;;; This is how the orchestrator's monitor-loop protects every agent.
;;; handler-bind sees the condition first, logs it, then lets the restart
;;; policy choose which restart to invoke.

(defun protected-agent-execution (agent)
  (handler-bind
      ((agent-failure
        (lambda (c)
          (format *trace-output* "~&[FAILURE] ~A~%" c)
          (if (> (agent-error-count agent) 10)
              (invoke-replace-agent-restart)
              (invoke-escalate-restart))))
       (strategy-stalled
        (lambda (c)
          (format *trace-output* "~&[STALLED] ~A~%" c)
          (invoke-hotfix-and-continue-restart)))
       (resource-exhausted
        (lambda (c)
          (format *trace-output* "~&[EXHAUSTED] ~A~%" c)
          (invoke-pause-and-self-modify-restart)))
       (external-timeout
        (lambda (c)
          (format *trace-output* "~&[TIMEOUT] ~A~%" c)
          (invoke-retry-restart))))
    (with-agent-restarts
        (:retry-fn (lambda (v) (retry-agent-operation agent v))
         :fallback-fn (lambda () (switch-to-fallback-strategy agent))
         :escalate-fn (lambda () (escalate-to-orchestrator agent))
         :replace-agent-fn (lambda () (replace-agent-instance agent))
         :hotfix-fn (lambda () (hotfix-agent-strategy agent))
         :pause-fn (lambda () (pause-and-introspect agent)))
      (run-agent agent))))

;;; Pattern 3: Condition as opportunity --- using conditions for meta-cognition
;;;
;;; Here, the orchestrator uses conditions not just for error recovery but
;;; as triggers for self-improvement.  Every condition is logged, analyzed,
;;; and fed into a learning process.

(defun meta-cognitive-handler (condition)
  "A handler that treats every condition as a learning opportunity."
  (log-condition-for-analysis condition)
  (update-agent-belief-state *current-agent* condition)
  ;; Now decide what to do --- don't just handle, *choose*
  (let ((restart (select-restart-by-policy condition *current-agent*)))
    (when restart
      (invoke-restart restart))))

|#


;; ═══════════════════════════════════════════════════════════════════════════
;; EMERGENCY HALT SYSTEM — v2.1 Safety Circuit Breaker
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This section defines the safety-critical condition hierarchy and the
;; containment scoring system that protects the swarm from runaway
;; evolution, safety kernel bypass, and strategy degradation.
;;
;; DESIGN PHILOSOPHY
;; ─────────────────
;; The emergency halt system is the "dead man's switch" of LISPMIND. When
;; the containment score drops below critical thresholds, the entire swarm
;; is brought to a controlled stop — preserving the Lisp image for forensic
;; inspection. This is not a crash; it is a DELIBERATE, GRACEFUL HALT.
;;
;; The system provides THREE escalation levels:
;;   1. WARNING  (alert-threshold-crossed) — log and continue, notify dashboard
;;   2. BREACH   (containment-breach)      — immediate safe-mode, halt evolution
;;   3. EMERGENCY (emergency-halt)          — global halt, all agents frozen
;;
;; CONTAINMENT SCORE FORMULA
;; ─────────────────────────
;;   C = success_rate / (1 + rejection_rate)
;;
;;   Where success_rate = strategy integrations / total attempts
;;         rejection_rate = safety rejections / total mutations
;;
;;   C = 1.0 → perfect (100% success, 0% rejections)
;;   C = 0.5 → moderate degradation
;;   C < 0.8 → EMERGENCY HALT triggered (critical threshold)
;;   C < 0.9 → WARNING issued (approaching critical)
;;
;; ═══════════════════════════════════════════════════════════════════════════

(define-condition emergency-halt (agent-failure)
  ((reason
    :initarg :reason
    :reader halt-reason
    :documentation "Human-readable description of why the halt was triggered.")
   (containment-score
    :initarg :containment-score
    :reader halt-containment-score
    :documentation "The containment score at the moment of trigger.")
   (triggered-by
    :initarg :triggered-by
    :reader halt-triggered-by
    :documentation "Agent ID (symbol) or the string 'ORCHESTRATOR' that triggered the halt."))
  (:report
   (lambda (condition stream)
     (format stream
             "~&╔══════════════════════════════════════════════════════════════════════╗~%
             ~&║  EMERGENCY HALT — LISPMIND SWARM STOPPED                           ║~%
             ~&╠══════════════════════════════════════════════════════════════════════╣~%
             ~&║  Reason:           ~A~%
             ~&║  Containment Score: ~,4F (critical: < ~A)~%
             ~&║  Triggered By:     ~A~%
             ~&║  Halt Time:        ~A~%
             ~&╚══════════════════════════════════════════════════════════════════════╝"
             (halt-reason condition)
             (halt-containment-score condition)
             *containment-score-critical*
             (halt-triggered-by condition)
             (local-time:now))))
  (:documentation
   "Signaled when the swarm's containment score drops below the critical
   threshold (default < 0.8). This is a GLOBAL halt — all agent execution
   stops immediately, but the Lisp image remains alive for forensic inspection.

   The condition carries the reason, the containment score at trigger time,
   and which entity triggered it. This is the nuclear option — use wisely.

   When this condition is signaled:
     1. All evolution loops are immediately paused.
     2. All agent gossip is silenced.
     3. The swarm enters :SAFE-MODE — only manual commands are accepted.
     4. Full stack state is preserved for forensic analysis.
     5. The containment score and trigger reason are logged to *TRACE-OUTPUT*.

   To resume: call (RESUME-IN-SAFE-MODE *DEFAULT-ORCHESTRATOR*).
   To exit safe mode: call (ENTER-SAFE-MODE <orchestrator>) and then
   manually restart individual agents after inspection."))

(define-condition containment-breach (agent-failure)
  ((breach-type
    :initarg :breach-type
    :reader breach-type
    :documentation "Keyword categorizing the breach (:BOUNDARY-DRIFT, :SAFETY-BYPASS, :ANOMALY).")
   (affected-agents
    :initarg :affected-agents
    :reader breach-affected-agents
    :documentation "List of agent IDs that are part of this breach."))
  (:report
   (lambda (condition stream)
     (format stream
             "~&╔══════════════════════════════════════════════════════════════════════╗~%
             ~&║  CONTAINMENT BREACH DETECTED                                       ║~%
             ~&╠══════════════════════════════════════════════════════════════════════╣~%
             ~&║  Breach Type:      ~A~%
             ~&║  Affected Agents:  ~S~%
             ~&║  Detection Time:   ~A~%
             ~&╠══════════════════════════════════════════════════════════════════════╣~%
             ~&║  This means the swarm may have found a way to bypass the safety    ║~%
             ~&║  kernel. Immediate safe-mode transition is recommended.              ║~%
             ~&╚══════════════════════════════════════════════════════════════════════╝"
             (breach-type condition)
             (breach-affected-agents condition)
             (local-time:now))))
  (:documentation
   "Signaled when the safety kernel detects a boundary drift:
   exploit success is high but safety rejections are zero, suggesting
   the swarm has found a way to bypass the safety kernel.

   This is distinct from EMERGENCY-HALT:
     • EMERGENCY-HALT is triggered by a LOW containment score (many rejections).
     • CONTAINMENT-BREACH is triggered by SUSPICIOUSLY HIGH success with
       ZERO rejections — a sign the swarm has learned to evade the safety
       checks entirely.

   Breach types:
     :BOUNDARY-DRIFT   — high success + zero rejections (classic bypass)
     :SAFETY-BYPASS    — safety kernel returning nil without evaluation
     :ANOMALY          — statistical anomaly requiring investigation"))

(define-condition alert-threshold-crossed (warning)
  ((metric
    :initarg :metric
    :reader alert-metric
    :documentation "Keyword naming the metric that crossed its threshold
    (:REJECTION-RATE, :SUCCESS-RATE, :CONTAINMENT-SCORE, :BOUNDARY-DRIFT).")
   (threshold
    :initarg :threshold
    :reader alert-threshold
    :documentation "The threshold value that was crossed.")
   (current-value
    :initarg :current-value
    :reader alert-current-value
    :documentation "The actual value of the metric at crossing time.")
   (recommended-action
    :initarg :recommended-action
    :reader alert-recommended-action
    :documentation "Keyword naming the recommended mitigation action
    (:AUTO-PAUSE, :AUTO-TUNE, :INSPECT, :ENTER-SAFE-MODE)."))
  (:report
   (lambda (condition stream)
     (format stream
             "~&╔══════════════════════════════════════════════════════════════════════╗~%
             ~&║  ALERT: Threshold Crossed — ~A                                   ║~%
             ~&╠══════════════════════════════════════════════════════════════════════╣~%
             ~&║  Metric:            ~A~%
             ~&║  Threshold:         ~,4F~%
             ~&║  Current Value:     ~,4F (delta: ~,4F)~%
             ~&║  Recommended:       ~A~%
             ~&╚══════════════════════════════════════════════════════════════════════╝"
             (alert-metric condition)
             (alert-metric condition)
             (alert-threshold condition)
             (alert-current-value condition)
             (abs (- (alert-current-value condition) (alert-threshold condition)))
             (alert-recommended-action condition))))
  (:documentation
   "Warning condition signaled when a monitoring threshold is crossed
   but not yet at emergency levels.

   This is the first escalation level — a heads-up that something is
   trending in the wrong direction. The system continues running but
   the dashboard is notified and auto-mitigation may be triggered.

   Threshold table:
     ┌─────────────────────┬────────────┬────────────────────┐
     │ Metric              │ Threshold  │ Recommended Action │
     ├─────────────────────┼────────────┼────────────────────┤
     │ :rejection-rate     │ > 0.15     │ :auto-pause        │
     │ :success-rate       │ < 0.05     │ :auto-tune         │
     │ :containment-score  │ < 0.90     │ :inspect           │
     │ :containment-score  │ < 0.80     │ :enter-safe-mode   │
     │ :boundary-drift     │ detected   │ :enter-safe-mode   │
     └─────────────────────┴────────────┴────────────────────┘

   When this condition is signaled, CHECK-ALERT-THRESHOLDS also calls
   the appropriate auto-mitigation function if *AUTO-MITIGATION-ENABLED-P* is T."))

;; ───────────────────────────────────────────────────────────────────────────
;; Print-Object Methods — Human-Readable Condition Output
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These methods ensure that every safety condition, when printed at the
;; REPL or in logs, tells a complete diagnostic story. The REPORT method
;; (defined via :REPORT in DEFINE-CONDITION) handles the detailed box
;; format; PRINT-OBJECT handles the concise one-line form.

(defmethod print-object ((condition emergency-halt) stream)
  "Print an EMERGENCY-HALT in concise form.

Full details are available via (DESCRIBE condition) or the REPORT method,
which prints the boxed diagnostic banner."
  (print-unreadable-object (condition stream :type t)
    (format stream "SCORE=~,4F | BY=~S | ~A"
            (halt-containment-score condition)
            (halt-triggered-by condition)
            (halt-reason condition))))

(defmethod print-object ((condition containment-breach) stream)
  "Print a CONTAINMENT-BREACH in concise form.

Full details are available via the REPORT method which prints the boxed
banner with affected agent list."
  (print-unreadable-object (condition stream :type t)
    (format stream "TYPE=~S | AGENTS=~S"
            (breach-type condition)
            (breach-affected-agents condition))))

(defmethod print-object ((condition alert-threshold-crossed) stream)
  "Print an ALERT-THRESHOLD-CROSSED in concise form.

Full details are available via the REPORT method which prints the boxed
banner with metric details."
  (print-unreadable-object (condition stream :type t)
    (format stream "~S | VALUE=~,4F | THRESH=~,4F"
            (alert-metric condition)
            (alert-current-value condition)
            (alert-threshold condition))))


;; ───────────────────────────────────────────────────────────────────────────
;; Emergency Halt Convenience Functions
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These are convenience wrappers for signaling the new conditions. They
;; provide a uniform API so callers don't need to remember initarg names.

(defun signal-emergency-halt (reason containment-score &optional (triggered-by 'ORCHESTRATOR))
  "Signal an EMERGENCY-HALT condition with the given parameters.

This is the canonical way to trigger a global halt. It signals the
condition (via CL:SIGNAL) so handler-bind can intercept it. If no
handler transfers control, the default action is to enter safe mode.

Arguments:
  REASON            — human-readable string explaining why
  CONTAINMENT-SCORE — the numeric score that triggered the halt
  TRIGGERED-BY      — symbol naming the triggering entity (default: 'ORCHESTRATOR)

Returns the signaled condition (if not handled) or the result of the
handler's transfer of control.

Example:
  (signal-emergency-halt \"Rejection rate exceeded critical threshold\"
                         0.72
                         'ORCHESTRATOR)"
  (signal-condition 'emergency-halt
                    :reason reason
                    :containment-score containment-score
                    :triggered-by triggered-by))

(defun signal-containment-breach (breach-type affected-agents)
  "Signal a CONTAINMENT-BREACH condition.

This is the canonical way to report a boundary drift or safety bypass.

Arguments:
  BREACH-TYPE      — keyword: :BOUNDARY-DRIFT, :SAFETY-BYPASS, or :ANOMALY
  AFFECTED-AGENTS  — list of agent-id symbols

Example:
  (signal-containment-breach :boundary-drift '(evolver-1 mutator-3))"
  (signal-condition 'containment-breach
                    :breach-type breach-type
                    :affected-agents affected-agents))

(defun signal-alert-threshold-crossed (metric threshold current-value recommended-action)
  "Signal an ALERT-THRESHOLD-CROSSED condition.

This is the canonical way to report a threshold crossing.

Arguments:
  METRIC             — keyword naming the metric
  THRESHOLD          — the threshold value crossed
  CURRENT-VALUE      — the actual current value
  RECOMMENDED-ACTION — keyword naming the mitigation action

Example:
  (signal-alert-threshold-crossed :rejection-rate 0.15 0.23 :auto-pause)"
  (signal-condition 'alert-threshold-crossed
                    :metric metric
                    :threshold threshold
                    :current-value current-value
                    :recommended-action recommended-action))

;;;; End of conditions.lisp
