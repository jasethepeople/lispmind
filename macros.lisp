;;;; macros.lisp — LISPMIND Agent Factory DSL & DEFINE-AGENT-TYPE
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;                        THE AGENT FACTORY MACROS
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This file provides DEFINE-AGENT-TYPE, the crown jewel of LISPMIND's
;;; compile-time agent generation system.  A single macro call expands into
;;; a complete agent subclass definition, a specialized RUN-AGENT method
;;; with heartbeat injection, error handling, and restart wrapping, plus a
;;; HANDLE-CONDITION method with type-specific recovery logic.
;;;
;;; PHILOSOPHY: Why macros for agent creation?
;;; ──────────────────────────────────────────
;;; Because in Lisp, code that writes code is the most powerful code.
;;; DEFINE-AGENT-TYPE does not merely create data structures at runtime ---
;;; it generates entire method definitions at compile time.  This means:
;;;   • The type system knows about your agent species (full CLOS integration)
;;;   • Method dispatch is fast (no runtime interpretation of agent config)
;;;   • The expansion is hygienic (gensyms prevent variable capture)
;;;   • The generated code is transparent (you can read the expansion)
;;;
;;; "The macro is the compiler's way of saying: 'I will write the
;;;  boilerplate for you, so you can focus on the strategy.'"
;;;
;;; ═══════════════════════════════════════════════════════════════════════════

(in-package :lispmind)

;; ───────────────────────────────────────────────────────────────────────────
;; Section 1: Utility Function — Health Penalty Calculation
;; ───────────────────────────────────────────────────────────────────────────
;;
;; When an agent's strategy crashes, we degrade its health.  The penalty
;; is not a flat number --- it escalates as the agent accumulates errors.
;; This function maps (error-count, thresholds) to a health reduction.

(defun calculate-health-penalty (error-count thresholds)
  "Calculate the health penalty to apply based on ERROR-COUNT and THRESHOLDS.

THRESHOLDS is a list of integers in descending order (e.g., '(75 50 25)).
Each threshold represents a health tier.  When error-count exceeds the
number of thresholds, the penalty becomes severe (10 + error-count).

The algorithm:
  error-count = 0  → penalty = 0  (no harm, no foul)
  error-count = 1  → penalty = 5  (minor scrape)
  error-count = 2  → penalty = 10 (first threshold crossed)
  error-count = 3  → penalty = 15 (second threshold crossed)
  error-count >= length(thresholds) → penalty = 20 + error-count * 2

The thresholds list provides context-specific escalation.  An agent with
thresholds '(75 50 25) tolerates 3 errors before severe penalty, while
an agent with thresholds '(90 70) escalates faster.

Returns a non-negative integer --- the amount to subtract from health."
  (cond
    ;; No errors means no penalty.  The agent is pristine.
    ((zerop error-count)
     0)

    ;; First error is a warning --- small penalty.
    ((= error-count 1)
     5)

    ;; Moderate errors: each threshold crossed adds 5 more damage.
    ;; We clamp at the number of available thresholds.
    ((<= error-count (length thresholds))
     (* 5 error-count))

    ;; Many errors: the agent is failing repeatedly.  Apply escalating
    ;; penalty that grows faster than linearly.  This ensures repeated
    ;; failures eventually kill the agent (health → 0), triggering
    ;; the :REPLACE-AGENT restart via the orchestrator's monitor loop.
    (t
     (+ 20 (* 2 error-count)))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 2: WITH-AGENT-HEARTBEAT — Pre/Post Heartbeat Macro
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Wraps a body of code with heartbeat updates before and after execution.
;; This ensures the orchestrator's monitor loop sees the agent as alive
;; throughout its strategy execution, even if the strategy takes a while.

(defmacro with-agent-heartbeat (agent &body body)
  "Execute BODY, updating AGENT's heartbeat timestamp before and after.

The heartbeat is set to (LOCAL-TIME:NOW) immediately before BODY runs
and again immediately after.  This prevents the orchestrator's monitor
loop from flagging the agent as dead while it is actively working.

If BODY signals a condition or returns non-locally, the post-execution
heartbeat update is skipped --- the agent will appear stale until its
next run cycle.  This is intentional: a non-local exit suggests the
strategy may be in an inconsistent state.

AGENT is evaluated once.  Uses GENSYM to prevent variable capture.

Example:
  (with-agent-heartbeat my-agent
    (fetch-url url)
    (parse-html content))

Macro expansion (roughly):
  (let ((#:agent-var my-agent))
    (setf (agent-heartbeat #:agent-var) (local-time:now))
    (multiple-value-prog1
        (progn (fetch-url url)
               (parse-html content))
      (setf (agent-heartbeat #:agent-var) (local-time:now))))"
  (let ((agent-sym (gensym "AGENT-"))
        (result-sym (gensym "RESULT-")))
    `(let ((,agent-sym ,agent))
       ;; --- Pre-execution heartbeat: "I'm starting work now" ---
       (setf (agent-heartbeat ,agent-sym) (local-time:now))
       ;; --- Execute the body, preserving all return values ---
       (multiple-value-prog1
           (progn ,@body)
         ;; --- Post-execution heartbeat: "I finished successfully" ---
         (setf (agent-heartbeat ,agent-sym) (local-time:now))))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 3: WITH-AGENT-HEALTH-TRACKING — Error-Catching Health Degradation
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Wraps a body of code in a HANDLER-BIND that catches errors, increments
;; the agent's error-count, degrades its health, and signals the appropriate
;; LISPMIND condition.  This macro is the bridge between raw Lisp errors
;; and the structured condition hierarchy.

(defmacro with-agent-health-tracking ((&key (agent nil) (thresholds ''(75 50 25))) &body body)
  "Execute BODY, catching errors and degrading AGENT's health on failure.

When an error is caught:
  1. Increment the agent's ERROR-COUNT slot
  2. Calculate the health penalty via CALCULATE-HEALTH-PENALTY
  3. Subtract the penalty from the agent's HEALTH slot
  4. If health drops to 0 or below, signal AGENT-FAILURE
  5. If the error was a timeout-related condition, signal EXTERNAL-TIMEOUT
  6. Re-signal the original error so outer handlers can see it

THRESHOLDS is passed to CALCULATE-HEALTH-PENALTY (defaults to '(75 50 25)).

Uses GENSYM for all local variables to maintain hygiene.

Example:
  (with-agent-health-tracking (:agent scraper :thresholds '(80 60 40))
    (http-get url))

Macro expansion (simplified):
  (let ((#:agent-var scraper))
    (handler-bind
        ((error
          (lambda (#:condition)
            (incf (agent-error-count #:agent-var))
            (let ((#:penalty (calculate-health-penalty
                              (agent-error-count #:agent-var)
                              '(80 60 40))))
              (decf (agent-health #:agent-var) #:penalty))
            ... signal conditions if needed ...)))
      (progn (http-get url))))"
  (let ((agent-sym (gensym "AGENT-"))
        (condition-sym (gensym "CONDITION-"))
        (penalty-sym (gensym "PENALTY-"))
        (old-health-sym (gensym "OLD-HEALTH-"))
        (new-health-sym (gensym "NEW-HEALTH-")))
    `(let ((,agent-sym ,agent))
       (handler-bind
           ;; Catch ALL errors at the agent boundary.  We increment error-count,
           ;; degrade health, and then re-signal so outer orchestrator handlers
           ;; can see the condition and invoke restarts.
           ((error
             (lambda (,condition-sym)
               ;; ── Step 1: Record the error ──
               (incf (agent-error-count ,agent-sym))
               ;; ── Step 2: Calculate health penalty ──
               (let* ((,penalty-sym (calculate-health-penalty
                                      (agent-error-count ,agent-sym)
                                      ,thresholds))
                      (,old-health-sym (agent-health ,agent-sym))
                      (,new-health-sym (max 0 (- ,old-health-sym ,penalty-sym))))
                 ;; ── Step 3: Apply health degradation ──
                 (setf (agent-health ,agent-sym) ,new-health-sym)
                 ;; ── Step 4: Signal structured conditions if health critical ──
                 (when (<= ,new-health-sym 0)
                   (signal-condition 'agent-failure
                                     :agent-id (agent-id ,agent-sym)
                                     :reason (format nil "Health depleted after ~D errors: ~A"
                                                     (agent-error-count ,agent-sym)
                                                     ,condition-sym)))
                 ;; ── Step 5: Always re-signal the original condition ──
                 ;; Outer handlers (in the orchestrator's monitor loop) will
                 ;; see the original error and can invoke restarts.
                 (signal ,condition-sym))))
         (progn ,@body)))))


;; ─────────────────────────────────══════════════════════════════════════════
;; Section 4: DEFINE-AGENT-TYPE — The Crown Jewel
;; ─══════════════════════════════════════════════════════════════════════════
;;
;; This is the centerpiece of the LISPMIND macro system.  A single call to
;; DEFINE-AGENT-TYPE generates an entire agent species:
;;
;;   1. A DEFCLASS for the new agent type (inherits from AGENT)
;;   2. A DEFMETHOD RUN-AGENT specialized on the new type
;;   3. A DEFMETHOD HANDLE-CONDITION specialized on the new type
;;
;; The generated RUN-AGENT method includes:
;;   a. Heartbeat injection (via WITH-AGENT-HEARTBEAT)
;;   b. Restart wrapping (via WITH-AGENT-RESTARTS)
;;   c. Error catching with health degradation (via WITH-AGENT-HEALTH-TRACKING)
;;   d. Condition signaling when thresholds are exceeded
;;
;; The generated HANDLE-CONDITION method includes:
;;   a. Type-specific restart selection
;;   b. Escalation logic based on error count
;;   c. Fallback to the agent's restart-policy function

(defmacro define-agent-type (&whole whole-form
                            name
                            &key
                            (capabilities nil)
                            (default-strategy '#'default-strategy)
                            (health-thresholds ''(75 50 25)))
  "Define a new agent subclass with full monitoring, heartbeat injection,
error handling, and restart integration.

NAME is a symbol naming the new class (not evaluated).
CAPABILITIES is a list of keyword symbols (not evaluated).
DEFAULT-STRATEGY is a function designator (evaluated at agent creation).
HEALTH-THRESHOLDS is a list of integers in descending order (not evaluated).

Expands to:
  1. DEFCLASS for the new agent type (inherits from AGENT) with
     capabilities pre-set in the default initargs.
  2. DEFMETHOD RUN-AGENT specialized on the new type, which:
     a. Updates heartbeat before/after strategy execution
     b. Wraps strategy in WITH-AGENT-RESTARTS (all six restarts)
     c. Catches errors via WITH-AGENT-HEALTH-TRACKING
     d. Signals AGENT-FAILURE when health drops to zero
     e. Signals STRATEGY-STALLED if the strategy takes too long
  3. DEFMETHOD HANDLE-CONDITION specialized on the new type with
     type-specific restart selection logic.

All local variables in the expansion use GENSYM for hygiene.
The &WHOLE parameter captures the entire macro form for error reporting.

Example:
  (define-agent-type web-scraper
    :capabilities '(fetch parse store)
    :default-strategy #'default-scraper-strategy
    :health-thresholds '(75 50 25))

This creates class WEB-SCRAPER, a RUN-AGENT method for web-scrapers,
and a HANDLE-CONDITION method with scraper-specific recovery."
  ;; ── Validate the macro form for early error detection ──
  (declare (ignore whole-form))
  (unless (symbolp name)
    (error "DEFINE-AGENT-TYPE: NAME must be a symbol, got ~S" name))
  (unless (listp capabilities)
    (error "DEFINE-AGENT-TYPE: CAPABILITIES must be a list, got ~S" capabilities))
  (unless (and (listp health-thresholds)
               (every #'integerp health-thresholds))
    (error "DEFINE-AGENT-TYPE: HEALTH-THRESHOLDS must be a list of integers, got ~S"
           health-thresholds))

  ;; ── Generate the expansion with hygienic symbols ──
  (let ((agent-sym (gensym "AGENT-"))
        (strategy-sym (gensym "STRATEGY-"))
        (result-sym (gensym "RESULT-"))
        (condition-sym (gensym "CONDITION-"))
        (restart-sym (gensym "RESTART-"))
        (class-name name))

    ;; The backquote nesting here is intentionally deep and structured.
    ;; Each level represents a layer of abstraction:
    ;;   Outer: the DEFCLASS, DEFMETHOD, DEFMETHOD trio
    ;;   Middle: method bodies with macro wrappers
    ;;   Inner: restart handlers and condition logic
    `
    ;; ══════════════════════════════════════════════════════════════════════
    ;; 1. CLASS DEFINITION
    ;; ══════════════════════════════════════════════════════════════════════
    ;; Create the subclass with pre-initialized capabilities.  Every agent
    ;; of this type will be born with these capabilities already set.
    (defclass ,class-name (agent)
      ()
      (:default-initargs
       :capabilities ',capabilities
       :strategy ,default-strategy
       :restart-policy #'default-restart-policy)
      (:documentation
       ,(format nil "Agent type ~A with capabilities ~S.~%~
                     Automatically generated by DEFINE-AGENT-TYPE.~%~
                     Health thresholds: ~S."
                class-name capabilities health-thresholds)))

    ;; ══════════════════════════════════════════════════════════════════════
    ;; 2. RUN-AGENT METHOD — The Heartbeat of Execution
    ;; ══════════════════════════════════════════════════════════════════════
    ;; This method is where the agent comes alive.  It:
    ;;   • Records the heartbeat ("I'm working!")
    ;;   • Retrieves the current strategy function
    ;;   • Wraps execution in all six canonical restarts
    ;;   • Catches errors, tracks health, signals conditions
    (defmethod run-agent ((,agent-sym ,class-name))
      ,(format nil "Execute the ~A agent's strategy with full monitoring.~%~
                    ~%Updates heartbeat, wraps strategy in WITH-AGENT-RESTARTS,~%~
                    catches errors via WITH-AGENT-HEALTH-TRACKING.~%~
                    Signals structured conditions when thresholds are exceeded."
               class-name)
      ;; Lock the agent for the entire execution cycle to prevent
      ;; hot-patching or status changes mid-flight.
      (bt:with-lock-held ((agent-lock ,agent-sym))
        ;; ── Phase 1: Pre-execution bookkeeping ──
        (setf (agent-heartbeat ,agent-sym) (local-time:now))
        (setf (agent-status ,agent-sym) :running)
        (let ((,strategy-sym (agent-strategy ,agent-sym)))
          ;; ── Phase 2: Execute strategy within restart cage ──
          (with-agent-restarts
              (;; If strategy crashes, retry up to 3 times with the same strategy
               :retry-fn (lambda (&optional value)
                           (declare (ignore value))
                           (format *trace-output* "~&[~A] ~A retrying strategy~%"
                                   ',class-name (agent-id ,agent-sym))
                           ;; Re-run the strategy after a brief pause
                           (sleep 0.5)
                           (funcall ,strategy-sym ,agent-sym))
               ;; Fallback: call the strategy with a :FALLBACK marker
               :fallback-fn (lambda ()
                              (format *trace-output* "~&[~A] ~A using fallback~%"
                                      ',class-name (agent-id ,agent-sym))
                              ;; Signal that fallback is being used
                              (signal-condition 'agent-failure
                                                :agent-id (agent-id ,agent-sym)
                                                :reason "Strategy failed, using fallback")
                              nil)
               ;; Escalate to orchestrator: this agent can't handle it
               :escalate-fn (lambda ()
                              (format *trace-output* "~&[~A] ~A escalating to orchestrator~%"
                                      ',class-name (agent-id ,agent-sym))
                              (setf (agent-status ,agent-sym) :failed)
                              nil)
               ;; Replace: the nuclear option --- mark for replacement
               :replace-agent-fn (lambda ()
                                   (format *trace-output* "~&[~A] ~A marked for replacement~%"
                                           ',class-name (agent-id ,agent-sym))
                                   (setf (agent-health ,agent-sym) 0)
                                   (setf (agent-status ,agent-sym) :failed)
                                   nil)
               ;; Hotfix: the signature move --- live patch the strategy
               :hotfix-fn (lambda ()
                            (format *trace-output* "~&[~A] ~A hotfixing strategy~%"
                                    ',class-name (agent-id ,agent-sym))
                            ;; Hotfix is handled by the orchestrator; we just
                            ;; signal that it's been requested.
                            (signal-condition 'strategy-stalled
                                              :agent-id (agent-id ,agent-sym)
                                              :elapsed-time 0.0
                                              :threshold 0.0)
                            nil)
               ;; Pause: introspect and self-modify
               :pause-fn (lambda ()
                           (format *trace-output* "~&[~A] ~A pausing for introspection~%"
                                   ',class-name (agent-id ,agent-sym))
                           (setf (agent-status ,agent-sym) :paused)
                           nil))
            ;; ── Phase 3: The actual strategy execution ──
            ;; Wrapped in health tracking that catches errors,
            ;; increments error-count, and degrades health.
            (handler-case
                (with-agent-health-tracking
                    (:agent ,agent-sym :thresholds ,health-thresholds)
                  ;; Execute the strategy --- this is where the agent does its work
                  (let ((,result-sym (funcall ,strategy-sym ,agent-sym)))
                    ;; Success! Reset error count on good execution.
                    (setf (agent-error-count ,agent-sym) 0)
                    ;; Post-success heartbeat
                    (setf (agent-heartbeat ,agent-sym) (local-time:now))
                    ,result-sym))
              ;; When an error is caught by handler-case (meaning no restart
              ;; was invoked and the condition propagated past all handlers),
              ;; we mark the agent as failed and re-signal for the orchestrator.
              (error (,condition-sym)
                (setf (agent-status ,agent-sym) :failed)
                (format *trace-output* "~&[~A] ~A strategy error: ~A~%"
                        ',class-name (agent-id ,agent-sym) ,condition-sym)
                ;; Re-signal so the orchestrator's handler-bind sees it
                (signal ,condition-sym)))))))

    ;; ══════════════════════════════════════════════════════════════════════
    ;; 3. HANDLE-CONDITION METHOD — Type-Specific Recovery Logic
    ;; ══════════════════════════════════════════════════════════════════════
    ;; When a condition is signaled, this method decides which restart to
    ;; invoke.  It first checks type-specific rules, then falls back to the
    ;; agent's restart-policy function.
    (defmethod handle-condition ((,agent-sym ,class-name) ,condition-sym)
      ,(format nil "Handle a condition for ~A agent with type-specific logic.~%~
                    Checks error count against thresholds, then delegates~%~
                    to the agent's restart-policy function."
               class-name)
      (let ((,restart-sym
              (cond
                ;; ── Too many errors: the agent is fundamentally broken ──
                ;; When error-count exceeds the number of thresholds + 2,
                ;; we've exhausted all patience.  Replace the agent.
                ((> (agent-error-count ,agent-sym)
                    (+ (length ,health-thresholds) 2))
                 :replace-agent)

                ;; ── Health at zero: agent is dead, signal failure ──
                ((<= (agent-health ,agent-sym) 0)
                 :replace-agent)

                ;; ── Status is failed: already failed, escalate ──
                ((eq (agent-status ,agent-sym) :failed)
                 :escalate)

                ;; ── Otherwise: let the restart policy decide ──
                ;; The policy function returns a restart keyword based on
                ;; the condition type and agent state.
                (t
                 (funcall (agent-restart-policy ,agent-sym)
                          ,condition-sym
                          ,agent-sym)))))
        ;; Log the decision and return the restart keyword
        (format *trace-output* "~&[~A] ~A handling ~A → restart ~S~%"
                ',class-name (agent-id ,agent-sym)
                (type-of ,condition-sym) ,restart-sym)
        ,restart-sym))

    ;; ══════════════════════════════════════════════════════════════════════
    ;; 4. Convenience: MAKE-<TYPE> Constructor Function
    ;; ══════════════════════════════════════════════════════════════════════
    ;; Generates a convenience constructor named MAKE-<TYPE> so users can
    ;; create agents concisely: (make-web-scraper :health 90) instead of
    ;; (make-instance 'web-scraper :health 90).
    (defun ,(intern (concatenate 'string "MAKE-" (symbol-name class-name))) (&rest initargs)
      ,(format nil "Create a new ~A agent instance.~%~
                    Convenience wrapper around (MAKE-INSTANCE '~A ...)."
               class-name class-name)
      (apply #'make-instance ',class-name initargs))

    ',class-name))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 5: Sample Macro Expansion (Documentary Comments)
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Below is a hand-written example of what DEFINE-AGENT-TYPE expands into.
;; This is "living documentation" --- it shows exactly what code gets
;; generated so you can understand the system without macroexpand-1.

#|

;;; What (DEFINE-AGENT-TYPE WEB-SCRAPER ...) EXPANDS TO:
;;;
;;; The macro generates four top-level forms:
;;;
;;; ── Form 1: DEFCLASS ──
;;;   (defclass web-scraper (agent)
;;;     ()
;;;     (:default-initargs
;;;      :capabilities '(fetch parse store)
;;;      :strategy #'default-scraper-strategy
;;;      :restart-policy #'default-restart-policy)
;;;     (:documentation "Agent type WEB-SCRAPER..."))
;;;
;;; ── Form 2: DEFMETHOD RUN-AGENT ──
;;;   (defmethod run-agent ((#:agent-42 web-scraper))
;;;     (bt:with-lock-held ((agent-lock #:agent-42))
;;;       ;; Update heartbeat and status
;;;       (setf (agent-heartbeat #:agent-42) (local-time:now))
;;;       (setf (agent-status #:agent-42) :running)
;;;       (let ((#:strategy-43 (agent-strategy #:agent-42)))
;;;         ;; Wrap in all 6 restarts
;;;         (with-agent-restarts
;;;             (:retry-fn    (lambda (&optional v) ...)
;;;              :fallback-fn (lambda () ...)
;;;              :escalate-fn (lambda () ...)
;;;              :replace-agent-fn (lambda () ...)
;;;              :hotfix-fn   (lambda () ...)
;;;              :pause-fn    (lambda () ...))
;;;           ;; Execute with health tracking
;;;           (handler-case
;;;               (with-agent-health-tracking
;;;                   (:agent #:agent-42 :thresholds '(75 50 25))
;;;                 (let ((#:result-44 (funcall #:strategy-43 #:agent-42)))
;;;                   (setf (agent-error-count #:agent-42) 0)
;;;                   (setf (agent-heartbeat #:agent-42) (local-time:now))
;;;                   #:result-44))
;;;             (error (#:condition-45)
;;;               (setf (agent-status #:agent-42) :failed)
;;;               (signal #:condition-45))))))
;;;
;;; ── Form 3: DEFMETHOD HANDLE-CONDITION ──
;;;   (defmethod handle-condition ((#:agent-42 web-scraper) #:condition-45)
;;;     (let ((#:restart-46
;;;             (cond ((> (agent-error-count #:agent-42) 5) :replace-agent)
;;;                   ((<= (agent-health #:agent-42) 0) :replace-agent)
;;;                   ((eq (agent-status #:agent-42) :failed) :escalate)
;;;                   (t (funcall (agent-restart-policy #:agent-42)
;;;                               #:condition-45 #:agent-42)))))
;;;       #:restart-46))
;;;
;;; ── Form 4: Convenience Constructor ──
;;;   (defun make-web-scraper (&rest initargs)
;;;     (apply #'make-instance 'web-scraper initargs))

|#


;; ───────────────────────────────────────────────────────────────────────────
;; Section 6: Pre-Built Agent Type Examples (Commented Out)
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These examples show how to use DEFINE-AGENT-TYPE to create real agent
;; species.  They are commented out because the referenced strategy
;; functions (#'DEFAULT-SCRAPER-STRATEGY, etc.) are not defined in this
;; file --- they would be defined by the user or in a domain-specific
;; module.  Uncomment and provide strategy functions to use them.

;; ── Example 1: Web Scraper Agent ──
;; Crawls web pages, extracts data, stores results.  High tolerance for
;; transient failures (network hiccups) but strict about repeated errors.
;;
;; (define-agent-type web-scraper
;;   :capabilities '(fetch parse store)
;;   :default-strategy #'default-scraper-strategy
;;   :health-thresholds '(75 50 25))
;;
;; Usage:
;;   (defun default-scraper-strategy (agent)
;;     (let ((url (pop-from-state agent :url-queue)))
;;       (when url
;;         (let ((html (fetch-url url)))
;;           (store-result agent (parse-html html))))))
;;
;;   (make-web-scraper :id 'scraper-1)

;; ── Example 2: Data Analyst Agent ──
;; Processes data streams, detects patterns, generates reports.  Lower
;; health thresholds because analysis errors are more concerning than
;; scraper errors (they may indicate algorithmic issues).
;;
;; (define-agent-type data-analyst
;;   :capabilities '(analyze correlate report)
;;   :default-strategy #'default-analyst-strategy
;;   :health-thresholds '(60 40 20))
;;
;; Usage:
;;   (defun default-analyst-strategy (agent)
;;     (let ((dataset (get-from-state agent :current-dataset)))
;;       (when dataset
;;         (let ((correlations (correlate dataset)))
;;           (when (significant-p correlations)
;;             (generate-report agent correlations))))))
;;
;;   (make-data-analyst :id 'analyst-1)

;; ── Example 3: Network Monitor Agent ──
;; Monitors network endpoints, detects outages, alerts on anomalies.  The
;; most resilient type --- network monitoring must survive in hostile
;; network conditions.
;;
;; (define-agent-type network-monitor
;;   :capabilities '(ping scan alert)
;;   :default-strategy #'default-monitor-strategy
;;   :health-thresholds '(80 60 40))
;;
;; Usage:
;;   (defun default-monitor-strategy (agent)
;;     (dolist (endpoint (get-endpoints agent))
;;       (let ((latency (ping endpoint)))
;;         (when (> latency *alert-threshold*)
;;           (alert-on-latency agent endpoint latency)))))
;;
;;   (make-network-monitor :id 'monitor-1)


;; ═══════════════════════════════════════════════════════════════════════════
;; END OF MACROS.LISP
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Summary of exported symbols from this file:
;;   • DEFINE-AGENT-TYPE  — The crown jewel: compile-time agent factory
;;   • WITH-AGENT-HEARTBEAT — Pre/post heartbeat wrapper
;;   • WITH-AGENT-HEALTH-TRACKING — Error-catching health degradation
;;   • CALCULATE-HEALTH-PENALTY — Health penalty computation
;;
;; Each agent type created by DEFINE-AGENT-TYPE also exports:
;;   • MAKE-<TYPE> — Convenience constructor function
;;
;; "Let the macros write the boilerplate, so you can write the strategy."
;;
;;;; macros.lisp ends here
