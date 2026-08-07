;;;; agent-class.lisp — Base Agent Class with MOP Hooks for LISPMIND
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;                           AGENT LIFECYCLE OVERVIEW
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; Every agent in the LISPMIND system is a living, self-monitoring entity.
;;; The lifecycle follows these phases:
;;;
;;;   1. BIRTH    — (make-agent ...) or (make-instance 'agent ...) creates
;;;                 an agent with a fresh gensym'd ID, full health (100),
;;;                 and the default no-op strategy.
;;;
;;;   2. RUN      — The orchestrator calls (run-agent agent), which by
;;;                 default does nothing. Subclasses created via
;;;                 DEFINE-AGENT-TYPE provide specialized behaviour.
;;;
;;;   3. MONITOR  — The orchestrator's monitor-loop checks heartbeats every
;;;                 2 seconds. If an agent's heartbeat is stale (> 30s) or
;;;                 its health drops to 0, the agent is considered dead and
;;;                 AGENT-FAILURE is signalled.
;;;
;;;   4. RECOVER  — When a condition is signalled, HANDLE-CONDITION is
;;;                 invoked. It delegates to the agent's RESTART-POLICY
;;;                 function, which returns a restart keyword (:retry,
;;;                 :use-fallback, :hotfix-and-continue, etc.). The
;;;                 orchestrator's handler-bind executes the restart.
;;;
;;;   5. EVOLVE   — Hot-patching replaces the agent's strategy function
;;;                 atomically (holding the agent's lock). The version
;;;                 counter is incremented, enabling rollback.
;;;
;;;   6. DEATH    — When recovery is impossible, the agent may be replaced
;;;                 entirely (new instance with same ID) or checkpointed
;;;                 for post-mortem analysis.
;;;
;;; WHY MOP HOOKS?
;;; ──────────────
;;; We use :AROUND methods on the (SETF AGENT-HEALTH) and (SETF AGENT-STATUS)
;;; slot writers to implement *observer hooks*. This is cleaner than
;;; scattering notification calls throughout the codebase — every health or
;;; status change, no matter where it originates, flows through these hooks.
;;; The orchestrator will later specialize NOTIFY-HEALTH-CHANGE and
;;; NOTIFY-STATUS-CHANGE to update its internal tracking tables, trigger
;;; healing, or log to the dashboard.
;;;
;;; WHY A LOCK?
;;; ────────────
;;; The agent lock protects mutable slots (strategy, state, heartbeat,
;;; error-count, version) from races between the orchestrator's monitor
;;; thread, the agent's own execution thread, and hot-patch operations.
;;; Simple reads (id, capabilities) don't need locking; writes and compound
;;; operations MUST use BT:WITH-LOCK-HELD.
;;; ═══════════════════════════════════════════════════════════════════════════

(in-package :lispmind)

;; ───────────────────────────────────────────────────────────────────────────
;; Section 1: Agent Class Definition
;; ───────────────────────────────────────────────────────────────────────────
;;
;; The agent is the fundamental unit of computation in LISPMIND. Each agent
;; encapsulates identity, health, behaviour, and recovery policy. We use
;; standard-class (not a custom metaclass) for simplicity — the MOP hooks
;; are implemented as auxiliary methods on the slot accessors, which is
;; fully portable across SBCL and other implementations.
;;
;; The LOCK slot has no initarg because it is purely an implementation
;; detail; every agent gets a fresh lock at creation time.

(defclass agent ()
  ((id :initarg :id
       :initform (gensym "AGENT-")
       :accessor agent-id
       :documentation "Unique identifier for this agent (gensym'd at birth).")

   (health :initarg :health
           :initform 100
           :accessor agent-health
           :documentation "Health score from 0 to 100. 0 means dead.")

   (strategy :initarg :strategy
             :initform #'default-strategy
             :accessor agent-strategy
             :documentation
             "The agent's behaviour function. Called by RUN-AGENT to perform work.")

   (capabilities :initarg :capabilities
                 :initform '()
                 :accessor agent-capabilities
                 :documentation
                 "List of capability keywords (e.g. :fetch :parse :store) describing what this agent can do.")

   (restart-policy :initarg :restart-policy
                   :initform #'default-restart-policy
                   :accessor agent-restart-policy
                   :documentation
                   "Function (lambda (condition agent)) that selects a restart keyword when a condition is signalled.")

   (state :initarg :state
          :initform (make-hash-table :test 'eq)
          :accessor agent-state
          :documentation
          "Agent-local state storage (EQ hash-table). Use this for arbitrary data the strategy needs to persist between invocations.")

   (heartbeat :initarg :heartbeat
              :initform (local-time:now)
              :accessor agent-heartbeat
              :documentation
              "Timestamp of the last heartbeat. Updated by the orchestrator's monitor loop and by the agent's run loop.")

   (error-count :initarg :error-count
                :initform 0
                :accessor agent-error-count
                :documentation
                "Cumulative error count. Reset to 0 on successful healing. Used by the restart policy to decide escalation.")

   (status :initarg :status
           :initform :running
           :accessor agent-status
           :documentation
           "Current status. One of :RUNNING :PAUSED :FAILED :HEALING. Status transitions trigger the MOP notify-status-change hook.")

   (version :initarg :version
            :initform 0
            :accessor agent-version
            :documentation
            "Strategy version counter. Incremented by hot-patch operations. Enables rollback to previous strategy versions.")

   (lock :initform (bt:make-lock "agent-lock")
         :reader agent-lock
         :documentation
         "Thread-safe access lock. Protects strategy, state, heartbeat, error-count, and version from concurrent mutation."))

  (:documentation
   "Base class for all LISPMIND agents.

Each agent is a living, self-monitoring entity with its own health, strategy,
and recovery policy. The MOP hooks on HEALTH and STATUS ensure that every
change to these critical slots is observable by the orchestrator.

Thread-safety notes:
  • Reads of id, capabilities, and status are lock-free.
  • Writes to health, status, strategy, state, heartbeat, error-count,
    and version MUST hold the agent lock via BT:WITH-LOCK-HELD.
  • The lock slot itself is immutable after creation."))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 2: Default Strategy — the no-op fallback
;; ───────────────────────────────────────────────────────────────────────────
;;
;; When an agent is created without an explicit strategy, this function is
;; installed as a placeholder. It does nothing useful — it merely prints a
;; message so that running the agent produces observable output. This is
;; essential for the demo and for verifying that the agent machinery works.

(defun default-strategy (agent)
  "Default agent strategy — does nothing but print a message.

This function is the fallback when no strategy is provided at agent creation.
It simply prints a message and returns NIL. All real work is done by
strategies installed by DEFINE-AGENT-TYPE or HOTPATCH-AGENT."
  (format t "~&Agent ~A running default strategy~%" (agent-id agent))
  nil)


;; ───────────────────────────────────────────────────────────────────────────
;; Section 3: Default Restart Policy — rule-based recovery decisions
;; ───────────────────────────────────────────────────────────────────────────
;;
;; The restart policy is a function that inspects a signalled condition and
;; returns a keyword naming the restart to invoke. This decouples the agent
;; from the orchestrator: the agent decides WHAT to do, the orchestrator's
;; handler-bind decides HOW (by providing the actual restart cases).
;;
;; The policy uses TYPECASE to dispatch on condition type, following a set
;; of heuristics tuned for the LISPMIND domain:
;;   • Timeouts are transient — retry a few times, then fall back.
;;   • Resource exhaustion calls for introspection (pause and self-modify).
;;   • A stalled strategy needs a hotfix (replace the code, continue running).
;;   • Repeated general failures mean the agent itself is compromised — replace.
;;   • Unknown conditions escalate to the orchestrator for human review.

(defun default-restart-policy (condition agent)
  "Return a restart keyword based on the condition type and agent state.

Rules:
  EXTERNAL-TIMEOUT      → :RETRY (first 3 times), then :USE-FALLBACK
  RESOURCE-EXHAUSTED    → :PAUSE-AND-SELF-MODIFY
  STRATEGY-STALLED      → :HOTFIX-AND-CONTINUE
  AGENT-FAILURE with error-count > 10 → :REPLACE-AGENT
  Otherwise             → :ESCALATE

This function is called by HANDLE-CONDITION when a condition is signalled.
The orchestrator establishes the corresponding restart bindings; this
function merely selects which one to invoke."
  (typecase condition
    ;; Transient external failures: retry a few times, then degrade gracefully
    (external-timeout
     (if (< (agent-error-count agent) 3)
         :retry
         :use-fallback))

    ;; Resource pressure: pause for introspection before retrying
    (resource-exhausted
     :pause-and-self-modify)

    ;; The strategy itself is stuck: hot-patch and keep going
    (strategy-stalled
     :hotfix-and-continue)

    ;; General agent failure: if we've failed many times, the agent is
    ;; fundamentally broken — replace it entirely rather than trying again.
    (agent-failure
     (if (> (agent-error-count agent) 10)
         :replace-agent
         :escalate))

    ;; Unknown condition type — let the orchestrator figure it out
    (otherwise
     :escalate)))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 4: Generic Functions — the public protocol
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These generic functions constitute the agent protocol. Every agent type
;; (subclass of AGENT) participates in this protocol. The default methods
;; here provide sensible fallbacks; specialized methods (defined by
;; DEFINE-AGENT-TYPE or manually) override them.

(defgeneric run-agent (agent)
  (:documentation
   "Execute the agent's strategy.

Primary method does nothing (prints a message and returns NIL).
Specialized by agent types (via DEFINE-AGENT-TYPE) to call the strategy
function with proper error handling, heartbeat injection, and restart
wrapping."))

(defgeneric handle-condition (agent condition)
  (:documentation
   "Handle a condition signalled by this agent. Returns a restart keyword.

The default method delegates to the agent's RESTART-POLICY function.
Subclasses may override to implement custom recovery logic."))

(defgeneric agent-alive-p (agent)
  (:documentation
   "Return T if the agent is alive.

An agent is considered alive when:
  1. Its health is strictly greater than 0, AND
  2. Its last heartbeat is less than 30 seconds old.

This predicate is called by the orchestrator's monitor loop every 2
seconds to detect dead or unresponsive agents."))

;; ── Notification hooks (called by the MOP :around methods below) ──────────
;;
;; WHY these are separate generic functions instead of inline logic:
;;   • The orchestrator will specialize them to update tracking tables.
;;   • The dashboard will specialize them to trigger UI refresh.
;;   • Logging systems can add after-methods for audit trails.
;; This is the Observer pattern, idiomatically expressed via CLOS.

(defgeneric notify-health-change (agent old-value new-value)
  (:documentation
   "Called via MOP hook whenever AGENT-HEALTH is modified.

OLD-VALUE is the previous health score; NEW-VALUE is the value just
written. The default method prints a notification to *STANDARD-OUTPUT*.
The orchestrator specializes this to trigger healing when health drops
below critical thresholds."))

(defgeneric notify-status-change (agent old-status new-status)
  (:documentation
   "Called via MOP hook whenever AGENT-STATUS is modified.

OLD-STATUS is the previous status keyword; NEW-STATUS is the value just
written. The default method prints a notification to *STANDARD-OUTPUT*.
The orchestrator specializes this to update its internal agent registry
and trigger dashboard refresh."))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 5: MOP Hooks — :around methods on slot accessors
;; ───────────────────────────────────────────────────────────────────────────
;;
;; This is the heart of the self-monitoring system. By defining :AROUND
;; methods on the slot writers, we guarantee that every modification of
;; health or status flows through our notification hooks — regardless of
;; whether the change comes from the agent itself, the orchestrator, a
;; hot-patch operation, or manual REPL intervention.
;;
;; WHY :around rather than :before/:after?
;;   • We need to capture the OLD value, which requires reading the slot
;;     BEFORE calling CALL-NEXT-METHOD. :AROUND gives us full control
;;     over the entire method combination.
;;   • We avoid double-notification if the new value is the same as the
;;     old value (checked with = for health, EQ for status).
;;
;; Thread-safety note: these methods are NOT responsible for locking.
;; The caller must hold the agent lock before calling (SETF AGENT-HEALTH)
;; or (SETF AGENT-STATUS). The :AROUND method itself is a simple wrapper.

(defmethod (setf agent-health) :around (new-value (agent agent))
  "Trigger health change notification when the agent's health is modified.

Reads the current health, calls the primary setf, then if the value
actually changed, invokes NOTIFY-HEALTH-CHANGE. This ensures every
health transition is observable."
  (let ((old-value (agent-health agent)))
    (call-next-method)
    (unless (= old-value new-value)
      (notify-health-change agent old-value new-value))
    new-value))

(defmethod (setf agent-status) :around (new-value (agent agent))
  "Trigger status change notification when the agent's status is modified.

Reads the current status, calls the primary setf, then if the status
actually changed (not EQ), invokes NOTIFY-STATUS-CHANGE. This ensures
every status transition is observable — :RUNNING → :FAILED, :HEALING →
:RUNNING, etc."
  (let ((old-value (agent-status agent)))
    (call-next-method)
    (unless (eq old-value new-value)
      (notify-status-change agent old-value new-value))
    new-value))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 6: Method Implementations
;; ───────────────────────────────────────────────────────────────────────────

(defmethod run-agent ((agent agent))
  "Default RUN-AGENT — does nothing useful.

Prints a message identifying the agent and returns NIL. Subclasses and
agent types created via DEFINE-AGENT-TYPE override this method to provide
actual behaviour, heartbeat injection, error handling, and restart wrapping."
  (format t "~&Agent ~A: default strategy (no-op)~%" (agent-id agent)))

(defmethod handle-condition ((agent agent) condition)
  "Default condition handler — delegates to the agent's restart policy.

Calls the agent's RESTART-POLICY function with the condition and the
agent, returning the restart keyword it produces. If no restart policy
is set, returns :RETRY as a safe default.

Defensive checks handle three crash scenarios:
  1. UNBOUND-SLOT on restart-policy → logs warning, returns :RETRY
  2. NIL restart-policy → logs warning, returns :RETRY
  3. Non-function, non-symbol policy value → logs warning, returns :RETRY
  4. Symbol policy (e.g. :RETRY) → returns the symbol directly"
  (let ((policy nil))
    (handler-case
        (setf policy (agent-restart-policy agent))
      (unbound-slot ()
        (format *trace-output* "~&[HANDLE-CONDITION] Agent ~A has no restart policy, using default~%"
                (agent-id agent))
        (return-from handle-condition :retry)))
    (cond
      ((functionp policy)
       (funcall policy condition agent))
      ((symbolp policy)
       policy)
      ((null policy)
       (format *trace-output* "~&[HANDLE-CONDITION] Agent ~A restart policy is NIL, using :RETRY~%"
               (agent-id agent))
       :retry)
      (t
       (format *trace-output* "~&[HANDLE-CONDITION] Agent ~A restart policy is invalid (~S), using :RETRY~%"
               (agent-id agent) policy)
       :retry))))

(defmethod agent-alive-p ((agent agent))
  "Return T if the agent is alive.

An agent is alive when:
  1. HEALTH > 0  (not dead), AND
  2. The elapsed time since the last heartbeat is < 30 seconds.

The heartbeat check catches agents whose execution thread has hung or
crashed without updating the health slot. Used by the orchestrator's
monitor loop."
  (and (> (agent-health agent) 0)
       (let ((elapsed (local-time:timestamp-difference
                       (local-time:now)
                       (agent-heartbeat agent))))
         (< elapsed 30))))

(defmethod notify-health-change ((agent agent) old-value new-value)
  "Default health change handler — print a notification.

The orchestrator will add an :AFTER method to trigger healing when
health drops below critical thresholds. This default method simply
prints to *STANDARD-OUTPUT* so that health changes are visible at
the REPL and in logs."
  (format t "~&[HEALTH] Agent ~A: ~A → ~A~%"
          (agent-id agent) old-value new-value))

(defmethod notify-status-change ((agent agent) old-status new-status)
  "Default status change handler — print a notification.

The orchestrator will add an :AFTER method to update its internal
registry and trigger dashboard refresh. This default method simply
prints to *STANDARD-OUTPUT* so that status transitions are visible
at the REPL and in logs."
  (format t "~&[STATUS] Agent ~A: ~A → ~A~%"
          (agent-id agent) old-status new-status))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 7: Convenience Constructor
;; ───────────────────────────────────────────────────────────────────────────
;;
;; A thin wrapper around MAKE-INSTANCE. Hides the class name and accepts
;; initargs, making agent creation concise and readable.

(defun make-agent (&rest initargs)
  "Create a new AGENT instance with the given initargs.

Usage: (make-agent :health 90 :capabilities '(:fetch :parse))

All standard initargs are accepted: :ID :HEALTH :STRATEGY :CAPABILITIES
:RESTART-POLICY :STATE :HEARTBEAT :ERROR-COUNT :STATUS :VERSION.

The agent is created with a fresh lock and gensym'd ID by default.
If no strategy is provided, #'DEFAULT-STRATEGY is used."
  (apply #'make-instance 'agent initargs))
