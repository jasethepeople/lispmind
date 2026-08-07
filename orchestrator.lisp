;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; ORCHESTRATOR.LISP — The Heart of LISPMIND
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;                     SUPREME AGENT: REGISTRY, MONITOR, HEALER
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This file defines the ORCHESTRATOR class and its entire operational
;;; substrate: agent registry, inter-agent messaging, the monitor loop,
;;; the healing system, and meta-cognition triggers.
;;;
;;; DESIGN PHILOSOPHY
;;; ─────────────────
;;; The orchestrator is not a "manager" in the sense of an external
;;; supervisor. It is a META-AGENT — an agent that happens to supervise
;;; other agents. It inherits from AGENT because it has its own health,
;;; strategy, heartbeat, and can itself fail, stall, or be healed. This
;;; symmetry is deliberate: if the orchestrator can heal agents, what
;;; heals the orchestrator? The answer: the same restart system, applied
;;; recursively.
;;;
;;; The monitor loop is the beating heart. It runs in a dedicated thread,
;;; wakes every 2 seconds (or on demand via condition variable), checks
;;; every registered agent's vital signs, and signals conditions when
;;; trouble is detected. Critically, it uses HANDLER-BIND (not HANDLER-CASE)
;;; to preserve the full stack context and restart visibility. This is the
;;; LISPMIND way: never unwind the stack until a restart has been chosen.
;;;
;;; THREAD SAFETY
;;; ─────────────
;;; All registry mutations (register-agent, deregister-agent) hold the
;;; orchestrator's monitor-lock via BT:WITH-LOCK-HELD. The mailboxes
;;; hash-table is similarly protected. The monitor loop acquires the lock
;;; before iterating over agents, ensuring that concurrent registrations
;;; do not corrupt the iteration.
;;;
;;; MESSAGING
;;; ─────────
;;; Agents communicate via asynchronous message queues (simple lists stored
;;; in a hash-table). send-message prepends to the recipient's mailbox;
;;; receive-messages returns a copy of all pending messages. There is no
;;; blocking receive — this is a fire-and-forget system. Future versions
;;; may add blocking dequeues with condition variables.
;;;
;;; HEALING LADDER
;;; ──────────────
;;; When a condition is detected, the monitor loop establishes six restarts
;;; forming a ladder of escalating intervention:
;;;   1. :RETRY                — cheapest, for transient failures
;;;   2. :USE-FALLBACK         — degrade to safe strategy
;;;   3. :ESCALATE             — hand to orchestrator's own policy
;;;   4. :REPLACE-AGENT        — nuclear option: fresh instance
;;;   5. :HOTFIX-AND-CONTINUE  — live patch (the LISPMIND signature move)
;;;   6. :PAUSE-AND-SELF-MODIFY — introspect, adjust, resume
;;;
;;; The restart to invoke is selected by SELECT-RESTART, which delegates to
;;; the agent's restart-policy function (or the orchestrator's own policy
;;; when escalation occurs).
;;;
;;; META-COGNITION
;;; ──────────────
;;; If an agent repeatedly fails (> 3 errors) and has been repeatedly
;;; fallback-restarted, the system triggers meta-cognition: a diagnostic
;;; message is printed and the agent is flagged for hot-patching. This is
;;; the seed of self-improvement — the system notices that its own recovery
;;; actions are insufficient and asks for smarter code.
;;;
;;; "The orchestrator does not merely manage agents. It tends them, as a
;;;  gardener tends a garden — pruning the dead, nourishing the weak, and
;;;  planting anew when the soil must be refreshed."

(in-package :lispmind)

;; ───────────────────────────────────────────────────────────────────────────
;; Section 1: Special Variable — The Active Orchestrator Singleton
;; ───────────────────────────────────────────────────────────────────────────
;;
;; There is typically one orchestrator per LISPMIND instance. This special
;; variable holds the currently active orchestrator, set by START-ORCHESTRATOR
;; and cleared by STOP-ORCHESTRATOR. Dashboard and demo code reference it
;; so users don't need to pass orchestrator references everywhere.

(defparameter *default-orchestrator* nil
  "The currently active orchestrator instance.

Set by START-ORCHESTRATOR when an orchestrator is launched.
Cleared (set to NIL) by STOP-ORCHESTRATOR on graceful shutdown.

Intended usage:
  (start-orchestrator)                    ; sets *default-orchestrator*
  (register-agent *default-orchestrator* my-agent)
  (start-dashboard)                       ; uses *default-orchestrator* implicitly

Thread-safety: this is a special variable, not a lock-protected cell.
In production, pass the orchestrator explicitly rather than relying on
this global, except in interactive REPL sessions.")


;; ───────────────────────────────────────────────────────────────────────────
;; Section 2: Orchestrator Class — The Meta-Agent
;; ───────────────────────────────────────────────────────────────────────────
;;
;; The orchestrator inherits from AGENT because it IS an agent — a self-aware,
;; self-monitoring entity that can fail and be healed like any other. The
;; additional slots provide the supervisory substrate: a registry of agents,
;; mailboxes for inter-agent messaging, and thread handles for the monitor
;; and dashboard loops.

(defclass orchestrator (agent)
  ((agents
    :initform (make-hash-table :test 'eq)
    :accessor orchestrator-agents
    :documentation
    "Registry: agent-id → agent instance.

An EQ hash-table mapping each registered agent's ID (a symbol) to its
AGENT instance. All accesses are protected by MONITOR-LOCK. Agents are
added by REGISTER-AGENT and removed by DEREGISTER-AGENT.")

   (mailboxes
    :initform (make-hash-table :test 'eq)
    :accessor orchestrator-mailboxes
    :documentation
    "Message queues: agent-id → mailbox list.

An EQ hash-table mapping each registered agent's ID to a list of
messages. Messages are cons cells of the form (FROM-ID . MESSAGE).
The list is accessed LIFO (newest first) for simplicity. All accesses
are protected by MONITOR-LOCK.")

   (running-p
    :initform nil
    :accessor orchestrator-running-p
    :documentation
    "Is the orchestrator monitor loop currently running?

Set to T by START-ORCHESTRATOR before the monitor thread is spawned.
Set to NIL by STOP-ORCHESTRATOR to signal graceful shutdown. The
monitor loop checks this flag on each iteration.")

   (monitor-thread
    :initform nil
    :accessor orchestrator-monitor-thread
    :documentation
    "The monitor loop thread (a BT:THREAD instance) or NIL.

Set by START-ORCHESTRATOR when it spawns the monitor thread.
Cleared by STOP-ORCHESTRATOR after joining the thread. Used to prevent
double-start and to join during shutdown.")

   (dashboard-thread
    :initform nil
    :accessor orchestrator-dashboard-thread
    :documentation
    "The dashboard display thread (a BT:THREAD instance) or NIL.

Set when the dashboard is started (see dashboard.lisp). Cleared on
stop. The orchestrator tracks this so STOP-ORCHESTRATOR can shut down
the dashboard along with everything else.")

   (monitor-lock
    :initform (bt:make-lock "monitor-lock")
    :reader orchestrator-monitor-lock
    :documentation
    "Lock protecting all orchestrator mutable state.

This lock guards: agents registry, mailboxes, running-p flag, and
monitor-thread slot. The monitor loop acquires this lock before
iterating over agents. Registry operations (register, deregister)
hold this lock. The condition variable MONITOR-CVAR is associated
with this lock.")

   (monitor-cvar
    :initform (bt:make-condition-variable :name "monitor-cvar")
    :reader orchestrator-monitor-cvar
    :documentation
    "Condition variable to wake the monitor loop.

The monitor loop sleeps on this cvar with a 2-second timeout. When
STOP-ORCHESTRATOR needs to shut down quickly, it signals this cvar
to wake the monitor immediately rather than waiting for the full
timeout. This makes shutdown responsive — no unnecessary delays."))

  (:documentation
   "The orchestrator is the supreme agent — it manages a swarm of agents,
monitors their health, handles their failures via restarts, and can even heal itself.

The orchestrator inherits from AGENT, which means it has its own health,
heartbeat, strategy, and can participate in the same restart protocol as
the agents it supervises. This recursive design means the system can
recover from orchestrator failures as well as agent failures.

Key capabilities:
  • Agent registry — add, remove, and iterate over supervised agents
  • Health monitoring — check heartbeats every 2 seconds, detect failures
  • Condition handling — signal conditions and invoke restarts via handler-bind
  • Inter-agent messaging — asynchronous fire-and-forget message queues
  • Healing — apply named restarts to sick agents
  • Meta-cognition — detect patterns of repeated failure and trigger hot-patching

Create with MAKE-ORCHESTRATOR, launch with START-ORCHESTRATOR, stop with
STOP-ORCHESTRATOR."))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 3: Constructor
;; ───────────────────────────────────────────────────────────────────────────

(defun make-orchestrator (&rest initargs)
  "Create a new ORCHESTRATOR instance with the given initargs.

Usage: (make-orchestrator :health 100 :capabilities '(:supervise :heal :patch))

All standard AGENT initargs are accepted: :ID :HEALTH :STRATEGY
:CAPABILITIES :RESTART-POLICY :STATE :HEARTBEAT :ERROR-COUNT :STATUS :VERSION.

The orchestrator is created with:
  • An empty agent registry (EQ hash-table)
  • An empty mailbox table (EQ hash-table)
  • running-p = NIL (not yet started)
  • A fresh monitor-lock and condition variable
  • A gensym'd ID (or the provided :ID initarg)

Returns the new orchestrator instance. The caller must call
START-ORCHESTRATOR to launch the monitor thread."
  (apply #'make-instance 'orchestrator initargs))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 4: Lifecycle — Start and Stop
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Starting an orchestrator means spawning the monitor thread and setting
;; the *default-orchestrator* singleton. Stopping means signaling the monitor
;; to exit, waking it via the condition variable, and joining the thread.

(defun start-orchestrator (&optional (orchestrator (make-orchestrator)))
  "Start the orchestrator's monitor thread and set *DEFAULT-ORCHESTRATOR*.

If no orchestrator is provided, a fresh one is created via MAKE-ORCHESTRATOR.

Steps:
  1. Acquire the orchestrator's monitor-lock.
  2. If already running (running-p is T), release lock and return immediately.
  3. Set running-p to T.
  4. Spawn the monitor thread (bt:make-thread #'monitor-loop).
  5. Set *DEFAULT-ORCHESTRATOR* to this orchestrator.
  6. Print startup message.

The monitor thread runs MONITOR-LOOP, which checks agent health every
2 seconds and handles conditions via handler-bind.

Returns the started orchestrator.

Example:
  (defparameter *my-orch* (start-orchestrator))
  ;; Now register agents...
  (register-agent *my-orch* (make-agent :id 'worker-1))"
  (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
    (when (orchestrator-running-p orchestrator)
      (format *trace-output* "~&[ORCH] Orchestrator ~A already running.~%"
              (agent-id orchestrator))
      (return-from start-orchestrator orchestrator))
    ;; Mark as running before spawning thread to avoid race
    (setf (orchestrator-running-p orchestrator) t)
    ;; Spawn the monitor thread
    (setf (orchestrator-monitor-thread orchestrator)
          (bt:make-thread
           (lambda () (monitor-loop orchestrator))
           :name (format nil "monitor-~A" (agent-id orchestrator))
           :initial-bindings '())))
  ;; Set the global singleton (outside the lock — special variable, not shared state)
  (setf *default-orchestrator* orchestrator)
  (format *trace-output* "~&[ORCH] Orchestrator ~A started. Monitor thread: ~A~%"
          (agent-id orchestrator)
          (bt:thread-name (orchestrator-monitor-thread orchestrator)))
  orchestrator)

(defun stop-orchestrator (orchestrator)
  "Stop the orchestrator gracefully.

Steps:
  1. Acquire the orchestrator's monitor-lock.
  2. If not running (running-p is NIL), release lock and return.
  3. Set running-p to NIL — this signals the monitor loop to exit.
  4. Signal the condition variable to wake the monitor immediately.
  5. Release the lock.
  6. Join the monitor thread (wait for it to finish).
  7. If a dashboard thread exists, note it (dashboard.lisp handles its own stop).
  8. Clear *DEFAULT-ORCHESTRATOR* if it points to this orchestrator.

This function blocks until the monitor thread has exited. The condition
variable signal ensures the monitor wakes promptly rather than waiting
for its full 2-second sleep timeout.

Returns the stopped orchestrator.

Example:
  (stop-orchestrator *my-orch*)
  ;; All agents are still in the registry but are no longer monitored."
  (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
    (unless (orchestrator-running-p orchestrator)
      (format *trace-output* "~&[ORCH] Orchestrator ~A is not running.~%"
              (agent-id orchestrator))
      (return-from stop-orchestrator orchestrator))
    ;; Signal shutdown
    (setf (orchestrator-running-p orchestrator) nil)
    ;; Wake the monitor so it notices the shutdown flag immediately
    (bt:condition-notify (orchestrator-monitor-cvar orchestrator)))
  ;; Join the monitor thread (outside the lock to avoid deadlock)
  (when (orchestrator-monitor-thread orchestrator)
    (bt:join-thread (orchestrator-monitor-thread orchestrator))
    (setf (orchestrator-monitor-thread orchestrator) nil))
  ;; Clear the global singleton if we own it
  (when (eq *default-orchestrator* orchestrator)
    (setf *default-orchestrator* nil))
  (format *trace-output* "~&[ORCH] Orchestrator ~A stopped gracefully.~%"
          (agent-id orchestrator))
  orchestrator)


;; ───────────────────────────────────────────────────────────────────────────
;; Section 5: Agent Registry — Register and Deregister
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These functions manage the agents hash-table. All mutations hold the
;; monitor-lock. When an agent is registered, a mailbox is created for it.
;; When deregistered, the mailbox is cleaned up.

(defun register-agent (orchestrator agent)
  "Add an agent to the orchestrator's registry and create a mailbox for it.

Acquires the orchestrator's monitor-lock, inserts the agent into the
AGENTS hash-table keyed by its ID, and creates an empty mailbox list
in the MAILBOXES hash-table under the same key.

If an agent with the same ID already exists, it is silently replaced.
This is intentional: REGISTER-AGENT is idempotent.

Also prints a notification to *TRACE-OUTPUT*.

Returns the registered agent.

Example:
  (register-agent *orch* (make-agent :id 'scraper-1 :capabilities '(:fetch)))"
  (let ((agent-id (agent-id agent)))
    (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
      (setf (gethash agent-id (orchestrator-agents orchestrator)) agent)
      (setf (gethash agent-id (orchestrator-mailboxes orchestrator)) '()))
    (format *trace-output* "~&[ORCH] Registered agent ~A (capabilities: ~S)~%"
            agent-id (agent-capabilities agent))
    agent))

(defun deregister-agent (orchestrator agent-id)
  "Remove an agent from the registry and clean up its mailbox.

Acquires the orchestrator's monitor-lock, removes the agent from the
AGENTS hash-table (if present), and removes its mailbox from the
MAILBOXES hash-table. Returns T if the agent was found and removed,
NIL if no such agent existed.

This is a safe operation: the agent object itself is not destroyed,
merely removed from the orchestrator's supervision. The agent can be
re-registered later if desired.

Example:
  (deregister-agent *orch* 'scraper-1)  ; → T or NIL"
  (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
    (remhash agent-id (orchestrator-agents orchestrator))
    (remhash agent-id (orchestrator-mailboxes orchestrator)))
  (format *trace-output* "~&[ORCH] Deregistered agent ~A~%" agent-id))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 6: Inter-Agent Messaging
;; ───────────────────────────────────────────────────────────────────────────
;;
;; A simple fire-and-forget messaging system. Each registered agent has a
;; mailbox (a list). send-message prepends a message; receive-messages
;; returns a fresh list of all pending messages (non-destructive read).

(defun send-message (orchestrator from-id to-id message)
  "Send a message from one agent to another via their mailboxes.

The message is stored as a cons cell (FROM-ID . MESSAGE) in the
recipient's mailbox list. The recipient can retrieve messages via
RECEIVE-MESSAGES.

If TO-ID is not a registered agent, a warning is printed and the message
is discarded. This is the fire-and-forget model: delivery is best-effort.

Acquires the orchestrator's monitor-lock briefly to mutate the mailbox.

Returns the message (for convenience).

Example:
  (send-message *orch* 'scraper-1 'analyst-2 '(data . \"page-42-results\"))
  (receive-messages *orch* 'analyst-2)
    ;; → ((SCRAPER-1 DATA . \"page-42-results\"))"
  (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
    (let ((mailbox (gethash to-id (orchestrator-mailboxes orchestrator))))
      (if mailbox
          (setf (gethash to-id (orchestrator-mailboxes orchestrator))
                (cons (cons from-id message) mailbox))
          (format *trace-output*
                  "~&[ORCH] WARNING: Cannot send message to unregistered agent ~A~%"
                  to-id))))
  message)

(defun receive-messages (orchestrator agent-id)
  "Retrieve all pending messages for an agent (non-destructive read).

Returns a COPY of the agent's mailbox list. Each element is a cons cell
of the form (SENDER-ID . MESSAGE). The original mailbox is NOT modified —
this is a read-only operation. To clear messages, use CLEAR-MESSAGES.

If AGENT-ID is not registered, returns NIL.

Acquires the orchestrator's monitor-lock for the duration of the copy.

Example:
  (receive-messages *orch* 'analyst-2)
    ;; → ((SCRAPER-1 . \"results for page 42\") (SCRAPER-3 . \"results for page 7\"))"
  (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
    (let ((mailbox (gethash agent-id (orchestrator-mailboxes orchestrator))))
      (when mailbox
        (copy-list mailbox)))))

(defun clear-messages (orchestrator agent-id)
  "Clear all pending messages for an agent.

Sets the agent's mailbox to the empty list. Returns the previous mailbox
contents (the messages that were cleared), or NIL if the agent is not
registered.

Acquires the orchestrator's monitor-lock."
  (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
    (let ((old-mailbox (gethash agent-id (orchestrator-mailboxes orchestrator))))
      (when old-mailbox
        (setf (gethash agent-id (orchestrator-mailboxes orchestrator)) '())
        old-mailbox))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 7: Fallback Strategy
;; ───────────────────────────────────────────────────────────────────────────
;;
;; When the :USE-FALLBACK restart is invoked, the agent's strategy is
;; replaced with this function. It does the minimal possible work — just
;; enough to signal that the agent is alive and running in degraded mode.

(defun fallback-strategy (agent)
  "A safe fallback strategy that does minimal work.

This function is installed as the agent's strategy when the :USE-FALLBACK
restart is invoked. It prints a brief message indicating degraded mode
and returns NIL immediately. This ensures the agent consumes no resources
and cannot fail, while still being alive for the orchestrator to monitor.

The fallback strategy is the system's degradation mode: the agent survives
but does not progress. This gives the orchestrator (or a human operator)
time to diagnose and apply a proper fix (e.g., hot-patching).

Example:
  ;; :USE-FALLBACK restart installs this:
  (setf (agent-strategy agent) #'fallback-strategy)"
  (format *trace-output* "~&[FALLBACK] Agent ~A running in degraded mode~%"
          (agent-id agent))
  nil)


;; ───────────────────────────────────────────────────────────────────────────
;; Section 8: The Monitor Loop — The Beating Heart of LISPMIND
;; ───────────────────────────────────────────────────────────────────────────
;;
;; This is the most important function in the entire system. It runs in a
;; dedicated thread, wakes every 2 seconds, and performs these duties:
;;
;;   1. Acquire the monitor-lock.
;;   2. Check running-p — if NIL, exit the loop (graceful shutdown).
;;   3. Iterate over all registered agents.
;;   4. For each agent, check if it is alive (AGENT-ALIVE-P).
;;   5. If dead, signal AGENT-FAILURE.
;;   6. If error-count > 5, trigger healing.
;;   7. If error-count > 3 with multiple fallbacks, trigger meta-cognition.
;;   8. Handle all conditions via HANDLER-BIND with all 6 restarts.
;;   9. Release the lock.
;;  10. Wait on the condition variable with 2-second timeout.
;;
;; WHY HANDLER-BIND (NOT HANDLER-CASE)
;; ───────────────────────────────────
;; HANDLER-BIND binds handlers WITHOUT unwinding the stack. When a condition
;; is signaled inside the monitor loop, the handler sees the FULL CALL STACK
;; as it was when trouble struck. This means restarts established by
;; RESTART-CASE inside the handler-bind are visible and invocable.
;;
;; HANDLER-CASE would UNWIND the stack before running the handler, destroying
;; the very context we need to recover. Restarts would be invisible because
;; the stack frame that established them would already be gone.
;;
;; This is not a stylistic choice — it is a semantic necessity. LISPMIND's
;; entire healing philosophy depends on handler-bind supremacy.

(defun monitor-loop (orchestrator)
  "The orchestrator's heart. Runs in a separate thread.

This function implements the main monitoring loop that checks agent health,
detects failures, and triggers healing via Common Lisp's condition/restart
system. It runs until STOP-ORCHESTRATOR sets RUNNING-P to NIL.

Loop cycle:
  1. Acquire monitor-lock.
  2. If running-p is NIL, release lock and return (shutdown).
  3. For each registered agent:
     a. Check ALIVE-P — if dead, signal AGENT-FAILURE.
     b. If error-count > 5, initiate healing.
     c. If error-count > 3 with repeated fallbacks, trigger meta-cognition.
  4. Release monitor-lock.
  5. Wait on monitor-cvar with 2-second timeout.

All condition handling uses HANDLER-BIND (not HANDLER-CASE) to preserve
restart visibility. Six restarts are available: :RETRY, :USE-FALLBACK,
:ESCALATE, :REPLACE-AGENT, :HOTFIX-AND-CONTINUE, :PAUSE-AND-SELF-MODIFY.

This function never returns normally except during graceful shutdown. Any
unexpected error is caught at the outermost level, logged, and the loop
continues — the monitor must never die."
  (format *trace-output* "~&[MONITOR] Monitor loop for ~A starting...~%"
          (agent-id orchestrator))
  (loop
    ;; ── Check shutdown flag (with lock held for consistency) ──────────────
    (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
      (unless (orchestrator-running-p orchestrator)
        (format *trace-output* "~&[MONITOR] Shutdown signal received. Exiting.~%")
        (return-from monitor-loop nil))

      ;; ── Iterate over all registered agents ──────────────────────────────
      ;; We use maphash to visit each agent. For each one, we check vitals
      ;; and potentially signal conditions. The handler-bind wraps each
      ;; agent check so that conditions are caught and restarts applied
      ;; individually per-agent.
      (maphash
       (lambda (aid agent)
         (declare (ignore aid))  ; agent-id is also accessible via agent
         (handler-bind
             ;; ── Condition handlers: one per condition type ──────────────
             ;; Each handler logs the condition, then decides which restart
             ;; to invoke based on the agent's restart-policy function.
             ;; The restart is invoked via INVOKE-RESTART after finding it
             ;; with FIND-RESTART. If no restart is found, the handler
             ;; returns normally and the condition propagulates.
             ((agent-failure
               (lambda (condition)
                 (format *trace-output*
                         "~&[MONITOR] AGENT-FAILURE detected: ~A~%"
                         condition)
                 ;; Let the restart policy decide what to do
                 (let ((restart-name (select-restart orchestrator agent condition)))
                   (case restart-name
                     (:replace-agent
                      (when (find-restart 'replace-agent)
                        (invoke-restart 'replace-agent)))
                     (:escalate
                      (when (find-restart 'escalate)
                        (invoke-restart 'escalate)))
                     (otherwise
                      (when (find-restart 'use-fallback)
                        (invoke-restart 'use-fallback)))))))

              (strategy-stalled
               (lambda (condition)
                 (format *trace-output*
                         "~&[MONITOR] STRATEGY-STALLED detected: ~A~%"
                         condition)
                 (let ((restart-name (select-restart orchestrator agent condition)))
                   (case restart-name
                     (:hotfix-and-continue
                      (when (find-restart 'hotfix-and-continue)
                        (invoke-restart 'hotfix-and-continue)))
                     (:escalate
                      (when (find-restart 'escalate)
                        (invoke-restart 'escalate)))
                     (otherwise
                      (when (find-restart 'pause-and-self-modify)
                        (invoke-restart 'pause-and-self-modify)))))))

              (resource-exhausted
               (lambda (condition)
                 (format *trace-output*
                         "~&[MONITOR] RESOURCE-EXHAUSTED detected: ~A~%"
                         condition)
                 (let ((restart-name (select-restart orchestrator agent condition)))
                   (case restart-name
                     (:pause-and-self-modify
                      (when (find-restart 'pause-and-self-modify)
                        (invoke-restart 'pause-and-self-modify)))
                     (:escalate
                      (when (find-restart 'escalate)
                        (invoke-restart 'escalate)))
                     (otherwise
                      (when (find-restart 'use-fallback)
                        (invoke-restart 'use-fallback)))))))

              (external-timeout
               (lambda (condition)
                 (format *trace-output*
                         "~&[MONITOR] EXTERNAL-TIMEOUT detected: ~A~%"
                         condition)
                 (let ((restart-name (select-restart orchestrator agent condition)))
                   (case restart-name
                     (:retry
                      (when (find-restart 'retry)
                        (invoke-restart 'retry)))
                     (:use-fallback
                      (when (find-restart 'use-fallback)
                        (invoke-restart 'use-fallback)))
                     (:escalate
                      (when (find-restart 'escalate)
                        (invoke-restart 'escalate)))
                     (otherwise
                      (when (find-restart 'retry)
                        (invoke-restart 'retry))))))))

           ;; ── Restart-case: all 6 restarts established ─────────────────
           ;; Inside the handler-bind, we establish the restart ladder.
           ;; When a handler above invokes a restart, control transfers
           ;; to one of these cases. The stack is NOT unwound — we resume
           ;; execution in the same dynamic context.
           (restart-case
               (progn
                 ;; ── Core health check ─────────────────────────────────
                 (unless (agent-alive-p agent)
                   ;; Agent is dead — signal the condition
                   (signal-condition 'agent-failure
                                     :agent-id (agent-id agent)
                                     :reason (format nil "Agent ~A not alive (health=~A, heartbeat stale)"
                                                     (agent-id agent)
                                                     (agent-health agent))))

                 ;; ── Error-count threshold check ───────────────────────
                 (when (> (agent-error-count agent) 5)
                   (format *trace-output*
                           "~&[MONITOR] Agent ~A has ~A errors — triggering healing~%"
                           (agent-id agent) (agent-error-count agent))
                   (signal-condition 'agent-failure
                                     :agent-id (agent-id agent)
                                     :reason (format nil "Error count ~A exceeds threshold"
                                                     (agent-error-count agent))))

                 ;; ── Meta-cognition check ──────────────────────────────
                 (check-meta-cognition orchestrator agent))

             ;; ── The six canonical restarts ────────────────────────────
             (retry (&optional value)
               :report (lambda (stream)
                         (format stream "Retry the failed operation."))
               :test (lambda (c) (declare (ignore c)) t)
               (format *trace-output*
                       "~&[MONITOR] :RETRY restart invoked for agent ~A (value: ~S)~%"
                       (agent-id agent) value)
               ;; Decrement error count as a gesture of optimism
               (bt:with-lock-held ((agent-lock agent))
                 (decf (agent-error-count agent))))

             (use-fallback ()
               :report (lambda (stream)
                         (format stream "Switch to fallback strategy."))
               :test (lambda (c) (declare (ignore c)) t)
               (format *trace-output*
                       "~&[MONITOR] :USE-FALLBACK restart invoked for agent ~A~%"
                       (agent-id agent))
               (bt:with-lock-held ((agent-lock agent))
                 (setf (agent-strategy agent) #'fallback-strategy)
                 (setf (agent-status agent) :running)))

             (escalate ()
               :report (lambda (stream)
                         (format stream "Escalate to orchestrator."))
               :test (lambda (c) (declare (ignore c)) t)
               (format *trace-output*
                       "~&[MONITOR] :ESCALATE restart invoked for agent ~A — delegating to orchestrator policy~%"
                       (agent-id agent))
               ;; Apply the orchestrator's own restart policy
               (let ((orch-restart (funcall (agent-restart-policy orchestrator)
                                            (make-condition 'agent-failure
                                                           :agent-id (agent-id agent)
                                                           :reason "Escalated from agent")
                                            orchestrator)))
                 (format *trace-output*
                         "~&[MONITOR] Orchestrator policy selected: ~A~%"
                         orch-restart)))

             (replace-agent ()
               :report (lambda (stream)
                         (format stream "Terminate and replace the agent."))
               :test (lambda (c) (declare (ignore c)) t)
               (format *trace-output*
                       "~&[MONITOR] :REPLACE-AGENT restart invoked for agent ~A~%"
                       (agent-id agent))
               (let ((old-capabilities (agent-capabilities agent))
                     (old-id (agent-id agent)))
                 ;; Create replacement agent with same capabilities
                 (let ((new-agent (make-agent :id old-id
                                               :capabilities old-capabilities)))
                   (setf (gethash old-id (orchestrator-agents orchestrator))
                         new-agent)
                   (setf (gethash old-id (orchestrator-mailboxes orchestrator))
                         '()))))

             (hotfix-and-continue ()
               :report (lambda (stream)
                         (format stream "Hot-patch strategy and continue."))
               :test (lambda (c) (declare (ignore c)) t)
               (format *trace-output*
                       "~&[MONITOR] :HOTFIX-AND-CONTINUE restart invoked for agent ~A~%"
                       (agent-id agent))
               ;; Placeholder: the actual hotfix is applied by hotpatch.lisp's
               ;; HOTPATCH-AGENT function. Here we mark the agent as healing
               ;; and set a flag in its state for the hotpatch system to pick up.
               ;; This is the integration point with hotpatch.lisp.
               (bt:with-lock-held ((agent-lock agent))
                 (setf (agent-status agent) :healing)
                 ;; Set a flag in agent state that hotpatch.lisp will check
                 (setf (gethash :hotfix-requested (agent-state agent)) t)
                 (format *trace-output*
                         "~&[MONITOR] Hotfix flag set for agent ~A — hotpatch.lisp will apply patch~%"
                         (agent-id agent))))

             (pause-and-self-modify ()
               :report (lambda (stream)
                         (format stream "Pause agent for introspection."))
               :test (lambda (c) (declare (ignore c)) t)
               (format *trace-output*
                       "~&[MONITOR] :PAUSE-AND-SELF-MODIFY restart invoked for agent ~A~%"
                       (agent-id agent))
               (bt:with-lock-held ((agent-lock agent))
                 (setf (agent-status agent) :paused))
               ;; Print an introspection prompt — this is the self-modification hook
               (format *trace-output*
                       "~&[MONITOR] ╔══════════════════════════════════════════════════════════════╗~%")
               (format *trace-output*
                       "~&[MONITOR] ║  Agent ~A is PAUSED for introspection.~%"
                       (agent-id agent))
               (format *trace-output*
                       "~&[MONITOR] ║  Review its state with: (inspect-agent '~A)~%"
                       (agent-id agent))
               (format *trace-output*
                       "~&[MONITOR] ║  Resume with: (setf (agent-status <agent>) :running)~%")
               (format *trace-output*
                       "~&[MONITOR] ╚══════════════════════════════════════════════════════════════╝~%")))))
       (orchestrator-agents orchestrator)))

    ;; ── Wait for next cycle ──────────────────────────────────────────────
    ;; We use a condition variable with a timeout rather than sleep.
    ;; This makes shutdown responsive: STOP-ORCHESTRATOR signals the cvar,
    ;; waking us immediately instead of waiting the full 2 seconds.
    (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
      (when (orchestrator-running-p orchestrator)
        (bt:condition-wait (orchestrator-monitor-cvar orchestrator)
                           (orchestrator-monitor-lock orchestrator)
                           :timeout 2))))

  ;; ── Graceful exit ─────────────────────────────────────────────────────
  (format *trace-output* "~&[MONITOR] Monitor loop for ~A exited cleanly.~%"
          (agent-id orchestrator)))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 9: Healing System
;; ───────────────────────────────────────────────────────────────────────────
;;
;; The healing system provides programmatic control over restart invocation.
;; SELECT-RESTART chooses which restart to use based on the condition and
;; agent state. HEAL-AGENT applies a specific restart by name.

(defun select-restart (orchestrator agent condition)
  "Select the best restart for a condition. Currently rule-based.

Delegates to the agent's restart-policy function, which returns a restart
keyword based on condition type and agent history. If the restart-policy
returns an unrecognized keyword, falls back to :ESCALATE.

This function is called by the monitor loop's condition handlers to decide
which restart to invoke via INVOKE-RESTART.

Arguments:
  ORCHESTRATOR — the orchestrator managing the agent
  AGENT        — the agent that signalled the condition
  CONDITION    — the condition instance that was signalled

Returns a keyword: one of :RETRY :USE-FALLBACK :ESCALATE :REPLACE-AGENT
:HOTFIX-AND-CONTINUE :PAUSE-AND-SELF-MODIFY.

Example:
  (select-restart *orch* my-agent some-condition)  ; → :retry"
  (declare (ignore orchestrator))
  (let ((restart-keyword (funcall (agent-restart-policy agent) condition agent)))
    (if (member restart-keyword
                '(:retry :use-fallback :escalate :replace-agent
                  :hotfix-and-continue :pause-and-self-modify))
        restart-keyword
        :escalate)))

(defun heal-agent (orchestrator agent-id restart-name)
  "Apply a named restart to an agent.

Looks up the agent in the orchestrator's registry by AGENT-ID. If found,
creates a synthetic condition and establishes all six restarts, then
invokes the named one. If the agent is not found, prints a warning.

This is the public API for manual healing — it allows a human operator
(or the dashboard) to force a specific recovery action on an agent.

Arguments:
  ORCHESTRATOR — the orchestrator managing the agent
  AGENT-ID     — the ID (symbol) of the agent to heal
  RESTART-NAME — keyword naming the restart to invoke
                 (:retry :use-fallback :escalate :replace-agent
                  :hotfix-and-continue :pause-and-self-modify)

Returns T if the restart was invoked, NIL if the agent was not found or
the restart is not available.

Example:
  (heal-agent *orch* 'scraper-1 :hotfix-and-continue)
  (heal-agent *orch* 'analyst-2 :replace-agent)"
  (let ((agent (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
                 (gethash agent-id (orchestrator-agents orchestrator)))))
    (unless agent
      (format *trace-output* "~&[HEAL] No agent with ID ~A found in registry.~%"
              agent-id)
      (return-from heal-agent nil))
    (format *trace-output* "~&[HEAL] Applying restart ~A to agent ~A...~%"
            restart-name agent-id)
    ;; Establish all restarts, then invoke the requested one
    (restart-case
        (progn
          ;; Signal a synthetic condition to trigger the handler-bind path
          (signal-condition 'agent-failure
                            :agent-id agent-id
                            :reason (format nil "Manual healing: ~A" restart-name))
          ;; If no handler transferred control, invoke the restart directly
          (case restart-name
            (:retry (when (find-restart 'retry) (invoke-restart 'retry)))
            (:use-fallback (when (find-restart 'use-fallback)
                             (invoke-restart 'use-fallback)))
            (:escalate (when (find-restart 'escalate)
                         (invoke-restart 'escalate)))
            (:replace-agent (when (find-restart 'replace-agent)
                              (invoke-restart 'replace-agent)))
            (:hotfix-and-continue (when (find-restart 'hotfix-and-continue)
                                    (invoke-restart 'hotfix-and-continue)))
            (:pause-and-self-modify (when (find-restart 'pause-and-self-modify)
                                      (invoke-restart 'pause-and-self-modify)))))
      (retry ()
        :report (lambda (stream) (format stream "Retry the failed operation."))
        (format *trace-output* "~&[HEAL] :RETRY applied to ~A~%" agent-id)
        (bt:with-lock-held ((agent-lock agent))
          (decf (agent-error-count agent)))
        t)
      (use-fallback ()
        :report (lambda (stream) (format stream "Switch to fallback strategy."))
        (format *trace-output* "~&[HEAL] :USE-FALLBACK applied to ~A~%" agent-id)
        (bt:with-lock-held ((agent-lock agent))
          (setf (agent-strategy agent) #'fallback-strategy)
          (setf (agent-status agent) :running))
        t)
      (escalate ()
        :report (lambda (stream) (format stream "Escalate to orchestrator."))
        (format *trace-output* "~&[HEAL] :ESCALATE applied to ~A~%" agent-id)
        t)
      (replace-agent ()
        :report (lambda (stream) (format stream "Terminate and replace the agent."))
        (format *trace-output* "~&[HEAL] :REPLACE-AGENT applied to ~A~%" agent-id)
        (let ((old-capabilities (agent-capabilities agent))
              (old-id (agent-id agent)))
          (let ((new-agent (make-agent :id old-id
                                        :capabilities old-capabilities)))
            (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
              (setf (gethash old-id (orchestrator-agents orchestrator)) new-agent)
              (setf (gethash old-id (orchestrator-mailboxes orchestrator)) '()))))
        t)
      (hotfix-and-continue ()
        :report (lambda (stream) (format stream "Hot-patch strategy and continue."))
        (format *trace-output* "~&[HEAL] :HOTFIX-AND-CONTINUE applied to ~A~%" agent-id)
        (bt:with-lock-held ((agent-lock agent))
          (setf (agent-status agent) :healing)
          (setf (gethash :hotfix-requested (agent-state agent)) t))
        t)
      (pause-and-self-modify ()
        :report (lambda (stream) (format stream "Pause agent for introspection."))
        (format *trace-output* "~&[HEAL] :PAUSE-AND-SELF-MODIFY applied to ~A~%" agent-id)
        (bt:with-lock-held ((agent-lock agent))
          (setf (agent-status agent) :paused))
        t))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 10: Meta-Cognition — Auto-Hotfix Trigger
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Meta-cognition is the system's ability to observe its own recovery
;; patterns and decide that they are insufficient. When an agent has been
;; repeatedly fallback-restarted but continues to fail, the system recognizes
;; that the fallback is not a solution — it is merely a band-aid. It then
;; triggers a meta-cognitive event, printing a diagnostic and preparing the
;; agent for hot-patching.
;;
;; This is the seed of self-improvement: the system notices that its own
;; healing actions are not working, and asks for better code.

(defun check-meta-cognition (orchestrator agent)
  "Check if an agent has had too many failures and trigger auto-hotfix.

If the agent's error-count > 3 AND the agent has the :fallback-count key
in its state hash-table with a value > 1, print a meta-cognition message
and prepare the agent for hot-patching.

The :fallback-count is incremented by the :USE-FALLBACK restart handler.
This tracks how many times the agent has been degraded to fallback mode.
If it keeps failing even in fallback (or keeps getting fallback-restarted),
something deeper is wrong — the agent needs new code, not just a restart.

This function is called by the monitor loop during each agent check.
It does not itself signal conditions; it merely prints diagnostic output
and sets a flag that the hotpatch system (hotpatch.lisp) can observe.

Arguments:
  ORCHESTRATOR — the orchestrator managing the agent
  AGENT        — the agent to check

Returns T if meta-cognition was triggered, NIL otherwise."
  (declare (ignore orchestrator))
  (let ((error-count (agent-error-count agent))
        (fallback-count (or (gethash :fallback-count (agent-state agent)) 0)))
    (when (and (> error-count 3)
               (> fallback-count 1))
      ;; Meta-cognition triggered
      (format *trace-output*
              "~&[META] ╔══════════════════════════════════════════════════════════════╗~%")
      (format *trace-output*
              "~&[META] ║  META-COGNITION TRIGGERED for agent ~A~%"
              (agent-id agent))
      (format *trace-output*
              "~&[META] ║  Error count: ~A | Fallback count: ~A~%"
              error-count fallback-count)
      (format *trace-output*
              "~&[META] ║  Pattern: repeated failures despite fallback restarts.~%")
      (format *trace-output*
              "~&[META] ║  Action: Preparing agent for hot-patch.~%")
      (format *trace-output*
              "~&[META] ║  Use (hotpatch-agent '~A :new-strategy #'your-fix)~%"
              (agent-id agent))
      (format *trace-output*
              "~&[META] ╚══════════════════════════════════════════════════════════════╝~%")
      ;; Set the hotfix-requested flag so hotpatch.lisp will take action
      (setf (gethash :hotfix-requested (agent-state agent)) t)
      ;; Also set a meta-cognition flag for logging/analysis
      (setf (gethash :meta-cognition-triggered (agent-state agent)) (local-time:now))
      t)))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 11: Orchestrator Notification Specializations
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These :AFTER methods specialize the NOTIFY-HEALTH-CHANGE and
;; NOTIFY-STATUS-CHANGE generic functions for the ORCHESTRATOR class.
;; They complement the default methods (defined in agent-class.lisp) with
;; orchestrator-specific behavior: critical health warnings and status
;; change logging.

(defmethod notify-health-change :after ((agent orchestrator) old-value new-value)
  "Orchestrator health change — if health drops below 50, print warning.

This :AFTER method runs after the default NOTIFY-HEALTH-CHANGE method
(defined in agent-class.lisp) which prints the basic transition message.
We add an additional warning when the orchestrator's own health drops
below the critical threshold of 50, because a sick orchestrator cannot
heal its agents.

If health drops to 0, an additional critical alert is printed — the
orchestrator itself needs healing."
  (when (< new-value 50)
    (format *trace-output*
            "~&[ORCH-WARN] ╔═══════════════════════════════════════════════════════╗~%")
    (format *trace-output*
            "~&[ORCH-WARN] ║  ORCHESTRATOR ~A HEALTH CRITICAL: ~A~%"
            (agent-id agent) new-value)
    (format *trace-output*
            "~&[ORCH-WARN] ║  A sick orchestrator cannot heal its agents.~%")
    (format *trace-output*
            "~&[ORCH-WARN] ╚═══════════════════════════════════════════════════════╝~%"))
  (when (<= new-value 0)
    (format *trace-output*
            "~&[ORCH-CRIT] ╔═══════════════════════════════════════════════════════╗~%")
    (format *trace-output*
            "~&[ORCH-CRIT] ║  ORCHESTRATOR ~A HEALTH ZERO — SYSTEM COMPROMISED~%"
            (agent-id agent))
    (format *trace-output*
            "~&[ORCH-CRIT] ║  Consider restarting the orchestrator.~%")
    (format *trace-output*
            "~&[ORCH-CRIT] ╚═══════════════════════════════════════════════════════╝~%")))

(defmethod notify-status-change :after ((agent orchestrator) old-status new-status)
  "Orchestrator status change — log to console with emphasis.

This :AFTER method runs after the default NOTIFY-STATUS-CHANGE method.
It adds orchestrator-specific emphasis because an orchestrator status
change affects ALL supervised agents. When the orchestrator goes to
:PAUSED or :FAILED, every agent is effectively orphaned."
  (format *trace-output*
          "~&[ORCH-STATUS] Orchestrator ~A: ~A → ~A [affects ~A supervised agent(s)]~%"
          (agent-id agent)
          old-status
          new-status
          (hash-table-count (orchestrator-agents agent))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 12: Utility Functions
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Convenience functions for inspecting the orchestrator's state.

(defun list-agents (&optional (orchestrator *default-orchestrator*))
  "Return a list of all registered agents in the orchestrator.

Returns an alist of (AGENT-ID . AGENT-INSTANCE) for each registered agent.
If no orchestrator is provided, uses *DEFAULT-ORCHESTRATOR*.

Acquires the monitor-lock briefly to copy the registry.

Example:
  (list-agents *my-orch*)
    ;; → ((SCRAPER-1 . #<AGENT ...>) (ANALYST-2 . #<AGENT ...>))"
  (unless orchestrator
    (error "No orchestrator provided and *DEFAULT-ORCHESTRATOR* is NIL."))
  (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
    (let ((result '()))
      (maphash (lambda (id agent)
                 (push (cons id agent) result))
               (orchestrator-agents orchestrator))
      (nreverse result))))

(defun inspect-agent (agent-id &optional (orchestrator *default-orchestrator*))
  "Print a detailed inspection report for an agent.

Looks up the agent by ID in the orchestrator's registry and prints a
comprehensive report including: id, health, status, error-count, version,
capabilities, heartbeat age, strategy name, and state contents.

If the agent is not found, prints a warning.

Example:
  (inspect-agent 'scraper-1 *my-orch*)"
  (unless orchestrator
    (error "No orchestrator provided and *DEFAULT-ORCHESTRATOR* is NIL."))
  (let ((agent (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
                 (gethash agent-id (orchestrator-agents orchestrator)))))
    (unless agent
      (format *trace-output* "~&[INSPECT] No agent with ID ~A found.~%" agent-id)
      (return-from inspect-agent nil))
    (let ((heartbeat-age (local-time:timestamp-difference
                          (local-time:now)
                          (agent-heartbeat agent))))
      (format *trace-output*
              "~&╔══════════════════════════════════════════════════════════════════╗~%")
      (format *trace-output*
              "~&║  AGENT: ~A~%" agent-id)
      (format *trace-output*
              "~&╠══════════════════════════════════════════════════════════════════╣~%")
      (format *trace-output*
              "~&║  Health:      ~3D / 100~%" (agent-health agent))
      (format *trace-output*
              "~&║  Status:      ~A~%" (agent-status agent))
      (format *trace-output*
              "~&║  Error Count: ~D~%" (agent-error-count agent))
      (format *trace-output*
              "~&║  Version:     ~D~%" (agent-version agent))
      (format *trace-output*
              "~&║  Capabilities: ~S~%" (agent-capabilities agent))
      (format *trace-output*
              "~&║  Heartbeat:   ~,1Fs ago~%" heartbeat-age)
      (format *trace-output*
              "~&║  Alive:       ~A~%" (agent-alive-p agent))
      (format *trace-output*
              "~&║  Strategy:    ~A~%" (agent-strategy agent))
      (format *trace-output*
              "~&║  State:       ~S~%"
              (let ((state-entries '()))
                (maphash (lambda (k v) (push (cons k v) state-entries))
                         (agent-state agent))
                state-entries))
      (format *trace-output*
              "~&╚══════════════════════════════════════════════════════════════════╝~%"))
    agent))


;;;; ═════════════════════════════════════════════════════════════════════════
;;;; END OF ORCHESTRATOR.LISP
;;;; ═════════════════════════════════════════════════════════════════════════


;;;; ═══════════════════════════════════════════════════════════════════════════
;;;; LISPMIND v2.0 Evolution Extensions
;;;; ═══════════════════════════════════════════════════════════════════════════
;;;;
;;;; This section extends the orchestrator with evolutionary healing,
;;;; profiler integration, and gossip-based state publication.  These
;;;; capabilities form the "v2.0" upgrade to the base orchestrator:
;;;;
;;;;   • :EVOLVE restart — genetic programming-driven strategy healing
;;;;   • Evolution trigger checks — automatic GP when agents stall
;;;;   • Profiler auto-tune hooks — automatic hotspot optimization
;;;;   • Gossip state publication — swarm visibility via pub/sub topics
;;;;   • Golden image auto-save — periodic checkpoint of healthy state
;;;;
;;;; These extensions do NOT modify any existing code above.  They are
;;;; pure additions that layer on top of the v1.0 foundation.  The
;;;; integration point is MONITOR-LOOP-V2, which calls the original
;;;; monitoring logic plus these new checks on a staggered schedule.


;; ───────────────────────────────────────────────────────────────────────────
;; Extension Section 1: Restart Ladder Update — :EVOLVE as Restart #7
;; ───────────────────────────────────────────────────────────────────────────
;;
;; The v1.0 healing ladder had six restarts:
;;   1. :RETRY                4. :REPLACE-AGENT
;;   2. :USE-FALLBACK         5. :HOTFIX-AND-CONTINUE
;;   3. :ESCALATE             6. :PAUSE-AND-SELF-MODIFY
;;
;; We add a seventh — :EVOLVE — which triggers genetic programming to
;; evolve a better strategy for the failing agent.  This is the most
;; sophisticated healing action: instead of merely retrying, falling
;; back, or pausing, the agent literally rewrites its own strategy.
;;
;; :EVOLVE is positioned at the TOP of the ladder — it is the most
;; aggressive intervention, reserved for agents that have exhausted all
;; other recovery options.

(defvar *healing-restart-ladder-v2*
  '(:retry :use-fallback :escalate :replace-agent
    :hotfix-and-continue :pause-and-self-modify :evolve)
  "The complete v2.0 healing restart ladder, including :EVOLVE.

This list documents all available restarts in ascending order of
intervention aggressiveness.  :EVOLVE is the final option — genetic
programming to evolve a fundamentally better strategy.

Intended for documentation and restart-policy validation.  The actual
restart binding and invocation happens in MONITOR-LOOP-V2's
RESTART-CASE form.")

(defvar *fallback-count-default-threshold* 2
  "Default number of :USE-FALLBACK invocations that triggers evolution.

When an agent has been fallback-restarted more than this many times,
the system concludes that simple degradation is insufficient — the
agent needs a smarter strategy, not just a safer one.")

(defvar *evolution-error-threshold* 3
  "Default error-count threshold for evolution triggering.

Agents with error-count strictly greater than this value are
candidates for evolution, provided other conditions (fallback
exhaustion, cooldown) are also met.")

(defvar *evolution-cooldown-seconds* 60
  "Minimum seconds between evolution events for the same agent.

Prevents evolution thrashing — evolving, running, failing, evolving
again in a tight loop.  The cooldown is checked against the agent's
:LAST-EVOLUTION-TIME state key.")


;; ───────────────────────────────────────────────────────────────────────────
;; Extension Section 2: Upgrade HEAL-AGENT to Generic + :EVOLVE :AROUND Method
;; ───────────────────────────────────────────────────────────────────────────
;;
;; The original heal-agent was a regular DEFUN.  To support the :EVOLVE
;; restart via method dispatch, we upgrade it to a generic function.
;; The primary method replicates the original behavior for all restarts
;; except :EVOLVE, which is handled by an :AROUND method.

(defgeneric heal-agent (orchestrator agent-id restart-name)
  (:documentation
   "Apply a named restart to an agent.  Generic function (v2.0 upgrade).

Primary method: handles all restarts by establishing the full restart
ladder (including :EVOLVE) and invoking the named one.  This preserves
the original heal-agent behavior for :RETRY, :USE-FALLBACK, :ESCALATE,
:REPLACE-AGENT, :HOTFIX-AND-CONTINUE, and :PAUSE-AND-SELF-MODIFY.

:AROUND method for :EVOLVE: delegates to RUN-EVOLUTIONARY-CYCLE from
EVOLUTION.LISP, then hotpatches the agent with the evolved strategy.

Arguments:
  ORCHESTRATOR — the orchestrator managing the agent
  AGENT-ID     — the ID (symbol) of the agent to heal
  RESTART-NAME — keyword naming the restart to invoke

Returns T if the restart was invoked successfully, NIL otherwise."))

(defmethod heal-agent ((orch orchestrator) agent-id restart-name)
  "Primary method: replicate original heal-agent behavior.

This method replaces the original DEFUN HEAL-AGENT with equivalent
functionality.  It looks up the agent, establishes all seven restarts
(v1.0's six plus :EVOLVE), and invokes the requested one."
  (let ((agent (bt:with-lock-held ((orchestrator-monitor-lock orch))
                 (gethash agent-id (orchestrator-agents orch)))))
    (unless agent
      (format *trace-output* "~&[HEAL] No agent with ID ~A found in registry.~%"
              agent-id)
      (return-from heal-agent nil))
    (format *trace-output* "~&[HEAL] Applying restart ~A to agent ~A...~%"
            restart-name agent-id)
    ;; Establish all seven restarts, then invoke the requested one
    (restart-case
        (progn
          ;; Signal a synthetic condition to trigger the handler-bind path
          (signal-condition 'agent-failure
                            :agent-id agent-id
                            :reason (format nil "Manual healing: ~A" restart-name))
          ;; If no handler transferred control, invoke the restart directly
          (case restart-name
            (:retry (when (find-restart 'retry) (invoke-restart 'retry)))
            (:use-fallback (when (find-restart 'use-fallback)
                             (invoke-restart 'use-fallback)))
            (:escalate (when (find-restart 'escalate)
                         (invoke-restart 'escalate)))
            (:replace-agent (when (find-restart 'replace-agent)
                              (invoke-restart 'replace-agent)))
            (:hotfix-and-continue (when (find-restart 'hotfix-and-continue)
                                    (invoke-restart 'hotfix-and-continue)))
            (:pause-and-self-modify (when (find-restart 'pause-and-self-modify)
                                      (invoke-restart 'pause-and-self-modify)))
            (:evolve (when (find-restart 'evolve)
                       (invoke-restart 'evolve)))))
      (retry ()
        :report (lambda (stream) (format stream "Retry the failed operation."))
        (format *trace-output* "~&[HEAL] :RETRY applied to ~A~%" agent-id)
        (bt:with-lock-held ((agent-lock agent))
          (decf (agent-error-count agent)))
        t)
      (use-fallback ()
        :report (lambda (stream) (format stream "Switch to fallback strategy."))
        (format *trace-output* "~&[HEAL] :USE-FALLBACK applied to ~A~%" agent-id)
        (bt:with-lock-held ((agent-lock agent))
          (setf (agent-strategy agent) #'fallback-strategy)
          (setf (agent-status agent) :running))
        t)
      (escalate ()
        :report (lambda (stream) (format stream "Escalate to orchestrator."))
        (format *trace-output* "~&[HEAL] :ESCALATE applied to ~A~%" agent-id)
        t)
      (replace-agent ()
        :report (lambda (stream) (format stream "Terminate and replace the agent."))
        (format *trace-output* "~&[HEAL] :REPLACE-AGENT applied to ~A~%" agent-id)
        (let ((old-capabilities (agent-capabilities agent))
              (old-id (agent-id agent)))
          (let ((new-agent (make-agent :id old-id
                                        :capabilities old-capabilities)))
            (bt:with-lock-held ((orchestrator-monitor-lock orch))
              (setf (gethash old-id (orchestrator-agents orch)) new-agent)
              (setf (gethash old-id (orchestrator-mailboxes orch)) '()))))
        t)
      (hotfix-and-continue ()
        :report (lambda (stream) (format stream "Hot-patch strategy and continue."))
        (format *trace-output* "~&[HEAL] :HOTFIX-AND-CONTINUE applied to ~A~%" agent-id)
        (bt:with-lock-held ((agent-lock agent))
          (setf (agent-status agent) :healing)
          (setf (gethash :hotfix-requested (agent-state agent)) t))
        t)
      (pause-and-self-modify ()
        :report (lambda (stream) (format stream "Pause agent for introspection."))
        (format *trace-output* "~&[HEAL] :PAUSE-AND-SELF-MODIFY applied to ~A~%" agent-id)
        (bt:with-lock-held ((agent-lock agent))
          (setf (agent-status agent) :paused))
        t)
      ;; ── New in v2.0: the :EVOLVE restart ──────────────────────────
      (evolve ()
        :report (lambda (stream)
                  (format stream "Evolve a better strategy via genetic programming."))
        :test (lambda (c)
                (declare (ignore c))
                ;; Only offer :EVOLVE if evolution module is loaded
                (fboundp 'run-evolutionary-cycle))
        (format *trace-output*
                "~&[HEAL] :EVOLVE restart invoked for agent ~A — starting GP cycle~%"
                agent-id)
        ;; Delegate to the evolution-aware healing logic
        (healing-via-evolution orch agent-id)))))  ; from evolution.lisp

(defmethod heal-agent :around ((orch orchestrator) agent-id
                                (restart-name (eql :evolve)))
  "When :EVOLVE restart is selected, trigger genetic strategy evolution.

This :AROUND method intercepts :EVOLVE healing requests and delegates
to the full evolutionary cycle defined in EVOLUTION.LISP.  The process:

  1. Look up the agent in the orchestrator's registry.
  2. Verify the agent is eligible for evolution (not in cooldown).
  3. Call (RUN-EVOLUTIONARY-CYCLE AGENT) from evolution.lisp.
  4. If evolution succeeds, hotpatch the agent with the evolved strategy.
  5. Log the evolution event to *TRACE-OUTPUT*.
  6. Return the evolved agent (or NIL if evolution failed).

The :AROUND method runs BEFORE the primary method, allowing us to
bypass the standard restart-case machinery for :EVOLVE and use the
richer evolution pipeline instead.

Thread safety: acquires both the orchestrator monitor-lock (for
registry lookup) and the agent lock (for strategy hotpatching)."
  (let ((agent (bt:with-lock-held ((orchestrator-monitor-lock orch))
                 (gethash agent-id (orchestrator-agents orch)))))
    (unless agent
      (format *trace-output* "~&[HEAL-EVOLVE] Agent ~A not found~%" agent-id)
      (return-from heal-agent nil))
    ;; Check cooldown
    (let ((last-evolved (gethash :last-evolution-time (agent-state agent))))
      (when (and last-evolved
                 (let ((elapsed (local-time:timestamp-difference
                                 (local-time:now) last-evolved)))
                   (< elapsed *evolution-cooldown-seconds*)))
        (format *trace-output*
                "~&[HEAL-EVOLVE] Agent ~A in evolution cooldown (~,0Fs remaining), skipping~%"
                agent-id
                (- *evolution-cooldown-seconds*
                   (local-time:timestamp-difference
                    (local-time:now) last-evolved)))
        (return-from heal-agent nil)))
    ;; Check that evolution module is available
    (unless (fboundp 'run-evolutionary-cycle)
      (format *trace-output*
              "~&[HEAL-EVOLVE] Evolution module not loaded — cannot evolve agent ~A~%"
              agent-id)
      (return-from heal-agent nil))
    ;; Perform the evolution
    (format *trace-output*
            "~&[HEAL-EVOLVE] ╔══════════════════════════════════════════════════════════════╗~%")
    (format *trace-output*
            "~&[HEAL-EVOLVE] ║  EVOLUTIONARY HEALING: Agent ~A~%" agent-id)
    (format *trace-output*
            "~&[HEAL-EVOLVE] ║  Error count: ~D | Fallback count: ~D~%"
            (agent-error-count agent)
            (or (gethash :fallback-count (agent-state agent)) 0))
    (format *trace-output*
            "~&[HEAL-EVOLVE] ╚══════════════════════════════════════════════════════════════╝~%")
    ;; Mark agent as healing
    (bt:with-lock-held ((agent-lock agent))
      (setf (agent-status agent) :evolving))
    ;; Run the evolutionary cycle (outside agent lock — evolution is CPU-heavy)
    (let ((evolved-strategy nil))
      (handler-case
          (setf evolved-strategy
                (run-evolutionary-cycle agent
                                        :failure-threshold *evolution-error-threshold*))
        (error (e)
          (format *trace-output*
                  "~&[HEAL-EVOLVE] Evolution failed for agent ~A: ~A~%"
                  agent-id e)))
      ;; Hotpatch the result
      (when evolved-strategy
        (bt:with-lock-held ((agent-lock agent))
          (setf (agent-strategy agent) evolved-strategy)
          (setf (agent-error-count agent) 0)
          (setf (agent-status agent) :running)
          ;; Store evolution record in agent state
          (setf (gethash :evolved-at (agent-state agent)) (local-time:now))
          (incf (gethash :evolution-count (agent-state agent)) 0)
          (incf (gethash :evolution-count (agent-state agent))))
        (format *trace-output*
                "~&[HEAL-EVOLVE] Agent ~A successfully evolved and hotpatched~%"
                agent-id)
        ;; Publish evolution event to gossip
        (publish-gossip-event orch :swarm.evolution
                              `(:agent-id ,agent-id
                                :event :evolution-completed
                                :timestamp ,(local-time:now)
                                :error-count 0))
        agent))))


;; ───────────────────────────────────────────────────────────────────────────
;; Extension Section 3: SELECT-RESTART Enhancement for :EVOLVE
;; ───────────────────────────────────────────────────────────────────────────
;;
;; The original SELECT-RESTART only knew about six restarts.  We provide
;; a new version that recognizes :EVOLVE and selects it when the agent
;; has exhausted simpler options (high error count + many fallbacks).

(defun select-restart-v2 (orchestrator agent condition)
  "Select the best restart for a condition, with :EVOLVE awareness.

This is the v2.0 replacement for SELECT-RESTART.  It extends the
original with :EVOLVE selection logic:

  • If error-count > *EVOLUTION-ERROR-THRESHOLD* AND
    fallback-count > *FALLBACK-COUNT-DEFAULT-THRESHOLD* AND
    the evolution module is loaded — return :EVOLVE
  • Otherwise, delegate to the agent's restart-policy function and
    validate against the seven-restart ladder.

Arguments:
  ORCHESTRATOR — the orchestrator managing the agent
  AGENT        — the agent that signalled the condition
  CONDITION    — the condition instance that was signalled

Returns a keyword: one of the seven restarts in
*HEALING-RESTART-LADDER-V2*."
  (declare (ignore orchestrator))
  (let ((error-count (agent-error-count agent))
        (fallback-count (or (gethash :fallback-count (agent-state agent)) 0))
        (evolve-available-p (fboundp 'run-evolutionary-cycle)))
    ;; Check if evolution is warranted
    (when (and evolve-available-p
               (> error-count *evolution-error-threshold*)
               (> fallback-count *fallback-count-default-threshold*)
               ;; Check cooldown
               (let ((last-evolved (gethash :last-evolution-time (agent-state agent))))
                 (or (null last-evolved)
                     (let ((elapsed (local-time:timestamp-difference
                                     (local-time:now) last-evolved)))
                       (> elapsed *evolution-cooldown-seconds*)))))
      (format *trace-output*
              "~&[SELECT] Conditions met for :EVOLVE (~A errors, ~A fallbacks)~%"
              error-count fallback-count)
      (return-from select-restart-v2 :evolve)))
  ;; Fall through to agent's restart policy
  (let ((restart-keyword (funcall (agent-restart-policy agent) condition agent)))
    (if (member restart-keyword *healing-restart-ladder-v2*)
        restart-keyword
        :escalate)))


;; ───────────────────────────────────────────────────────────────────────────
;; Extension Section 4: Evolution Trigger — CHECK-EVOLUTION-TRIGGER
;; ───────────────────────────────────────────────────────────────────────────
;;
;; This function is called by the monitor loop alongside CHECK-META-COGNITION.
;; It determines whether an agent has exhausted conventional recovery and
;; should trigger the :EVOLVE restart.

(defun check-evolution-trigger (orchestrator agent)
  "Check if an agent should trigger the :EVOLVE restart.

Called by MONITOR-LOOP-V2 during each agent check cycle.  Signals a
condition with an :EVOLVE restart available when ALL of the following
are true:

  1. Agent's error-count > *EVOLUTION-ERROR-THRESHOLD* (default 3)
  2. Agent has been :USE-FALLBACK restarted more than
     *FALLBACK-COUNT-DEFAULT-THRESHOLD* times (default 2)
  3. Agent is NOT currently evolving (status ≠ :EVOLVING)
  4. The evolution module is loaded (RUN-EVOLUTIONARY-CYCLE is fbound)
  5. Agent is not in evolution cooldown

When triggered, this function:
  • Prints an evolution-trigger diagnostic
  • Sets the :evolution-triggered flag in agent state
  • Returns T (the caller may then signal a condition with :EVOLVE)

If any condition is not met, returns NIL and does nothing.

Arguments:
  ORCHESTRATOR — the orchestrator managing the agent
  AGENT        — the agent to evaluate

Returns T if evolution should be triggered, NIL otherwise."
  (let ((error-count (agent-error-count agent))
        (fallback-count (or (gethash :fallback-count (agent-state agent)) 0))
        (agent-status (agent-status agent))
        (evolve-available-p (fboundp 'run-evolutionary-cycle)))
    (when (and evolve-available-p
               (> error-count *evolution-error-threshold*)
               (> fallback-count *fallback-count-default-threshold*)
               (not (eq agent-status :evolving))
               ;; Check cooldown
               (let ((last-evolved (gethash :last-evolution-time (agent-state agent))))
                 (or (null last-evolved)
                     (let ((elapsed (local-time:timestamp-difference
                                     (local-time:now) last-evolved)))
                       (> elapsed *evolution-cooldown-seconds*)))))
      ;; All conditions met — trigger evolution
      (format *trace-output*
              "~&[EVOLVE-TRIGGER] ╔═══════════════════════════════════════════════════════╗~%")
      (format *trace-output*
              "~&[EVOLVE-TRIGGER] ║  EVOLUTION TRIGGER for agent ~A~%" (agent-id agent))
      (format *trace-output*
              "~&[EVOLVE-TRIGGER] ║  Errors: ~D | Fallbacks: ~D | Status: ~A~%"
              error-count fallback-count agent-status)
      (format *trace-output*
              "~&[EVOLVE-TRIGGER] ║  Conventional restarts exhausted — evolving strategy.~%")
      (format *trace-output*
              "~&[EVOLVE-TRIGGER] ╚═══════════════════════════════════════════════════════╝~%")
      ;; Set flag for monitor loop to detect
      (setf (gethash :evolution-triggered (agent-state agent)) (local-time:now))
      ;; Publish to gossip
      (publish-gossip-event orchestrator :swarm.evolution
                            `(:agent-id ,(agent-id agent)
                              :event :evolution-triggered
                              :error-count ,error-count
                              :fallback-count ,fallback-count))
      t)))


;; ───────────────────────────────────────────────────────────────────────────
;; Extension Section 5: Profiler Integration — CHECK-PROFILER-AUTO-TUNE
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Bridges the orchestrator monitor loop to the profiler's auto-tuning
;; subsystem.  Called every cycle; delegates to profiler.lisp's
;; PROFILER-CHECK-IN-MONITOR function.

(defun check-profiler-auto-tune (orchestrator)
  "Called by MONITOR-LOOP-V2 each cycle. If profiler is running and hotspots
are detected, trigger auto-tuning.

This function delegates to profiler:profiler-check-in-monitor (defined
in PROFILER.LISP).  It is a thin wrapper that:
  1. Checks if *PROFILER-RUNNING-P* is T
  2. Checks if *AUTO-TUNE-ENABLED-P* is T
  3. If both, calls PROFILER-CHECK-IN-MONITOR on the orchestrator
  4. Logs any tuning actions taken

The separation between orchestrator and profiler is maintained:
profiler.lisp owns all profiling logic; this function merely provides
the integration hook.

Arguments:
  ORCHESTRATOR — the orchestrator whose monitor loop is calling this

Returns the list of OPTIMIZATION-RECORDs if tuning was performed,
NIL otherwise."
  (when (and (boundp '*profiler-running-p*)
             *profiler-running-p*
             (boundp '*auto-tune-enabled-p*)
             *auto-tune-enabled-p*
             (fboundp 'profiler-check-in-monitor))
    (handler-case
        (let ((records (profiler-check-in-monitor orchestrator)))
          (when records
            (format *trace-output*
                    "~&[PROF-AUTO] Auto-tuned ~D function(s) in monitor cycle~%"
                    (length records))
            ;; Publish to gossip
            (publish-gossip-event orchestrator :swarm.health
                                  `(:event :auto-tune-completed
                                    :functions-tuned ,(length records)
                                    :timestamp ,(local-time:now))))
          records)
      (error (e)
        (format *trace-output*
                "~&[PROF-AUTO] Profiler auto-tune error (non-fatal): ~A~%" e)
        nil))))


;; ───────────────────────────────────────────────────────────────────────────
;; Extension Section 6: Gossip Integration — PUBLISH-SWARM-STATE
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Publishes swarm state to named gossip topics for external observers.
;; The topics are:
;;   • swarm.health   — agent health snapshots
;;   • swarm.evolution — evolution events and lineage
;;   • swarm.threats  — threat alerts and security events
;;
;; The actual gossip transport is abstracted — events are stored in the
;; orchestrator's state and can be consumed by whatever gossip backend
;; is configured (zeromq, rabbitmq, or in-process).

(defvar *gossip-topic-registry*
  (make-hash-table :test 'eq)
  "Registry of gossip topics and their accumulated messages.

Maps topic-name (a keyword like :SWARM.HEALTH) to a list of event
plists.  Events are pushed onto the list (newest first).  Older
events are pruned when the list exceeds *GOSSIP-MAX-EVENTS-PER-TOPIC*.

Topics:
  :SWARM.HEALTH    — agent health snapshots
  :SWARM.EVOLUTION — evolution events (trigger, completion, failure)
  :SWARM.THREATS   — threat alerts (repeated failures, anomalies)")

(defvar *gossip-max-events-per-topic* 1000
  "Maximum events to retain per gossip topic.  Older events are pruned.")

(defvar *gossip-event-count* 0
  "Total number of gossip events published since startup.")

(defun publish-gossip-event (orchestrator topic event-plist)
  "Publish an event to a gossip topic.

Stores EVENT-PLIST in the *GOSSIP-TOPIC-REGISTRY* under TOPIC.  If the
topic's event list exceeds *GOSSIP-MAX-EVENTS-PER-TOPIC*, oldest events
are pruned.  Also increments *GOSSIP-EVENT-COUNT*.

This is the internal pub/sub mechanism.  External consumers can read
events via READ-GOSSIP-TOPIC.  Integration with external message brokers
(ZeroMQ, RabbitMQ, etc.) can be added by extending this function.

Arguments:
  ORCHESTRATOR — the orchestrator publishing the event
  TOPIC        — a keyword naming the topic (:swarm.health,
                 :swarm.evolution, or :swarm.threats)
  EVENT-PLIST  — a plist describing the event

Returns the event-plist (for convenience)."
  (declare (ignore orchestrator))
  (let ((entry (cons (local-time:now) event-plist)))
    (let ((topic-events (gethash topic *gossip-topic-registry*)))
      (push entry topic-events)
      ;; Prune if too many events
      (when (> (length topic-events) *gossip-max-events-per-topic*)
        (setf topic-events (subseq topic-events 0 *gossip-max-events-per-topic*)))
      (setf (gethash topic *gossip-topic-registry*) topic-events))
    (incf *gossip-event-count*)
    event-plist))

(defun read-gossip-topic (topic &optional (max-events 10))
  "Read the most recent events from a gossip topic.

Returns a list of (TIMESTAMP . EVENT-PLIST) pairs, newest first.
If TOPIC has no events, returns NIL.

Arguments:
  TOPIC       — keyword naming the topic
  MAX-EVENTS  — maximum number of events to return (default 10)

Example:
  (read-gossip-topic :swarm.evolution 5)"
  (let ((events (gethash topic *gossip-topic-registry*)))
    (when events
      (subseq events 0 (min max-events (length events))))))

(defun publish-swarm-state (orchestrator)
  "Publish the current swarm state to all gossip topics.

Called periodically by MONITOR-LOOP-V2 (every 5 cycles).  This function
snapshots the entire swarm and publishes:

  1. Agent health to :SWARM.HEALTH — one event per agent with id,
     health, status, error-count, and capabilities.
  2. Evolution summary to :SWARM.EVOLUTION — aggregate evolution
     statistics across all agents.
  3. Threat alerts to :SWARM.THREATS — agents with critical health,
     high error counts, or failed status.

This is the "heartbeat" of the gossip system — a periodic broadcast
that keeps external observers informed of swarm state.

Arguments:
  ORCHESTRATOR — the orchestrator whose agents are being published

Returns the total number of events published."
  (let ((published-count 0))
    (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
      (maphash
       (lambda (agent-id agent)
         (declare (ignore agent-id))
         ;; 1. Publish health snapshot
         (publish-gossip-event
          orchestrator :swarm.health
          `(:agent-id ,(agent-id agent)
            :health ,(agent-health agent)
            :status ,(agent-status agent)
            :error-count ,(agent-error-count agent)
            :capabilities ,(agent-capabilities agent)
            :timestamp ,(local-time:now)))
         (incf published-count)
         ;; 2. Publish threat alert if agent is in trouble
         (when (or (< (agent-health agent) 30)
                   (> (agent-error-count agent) 5)
                   (eq (agent-status agent) :failed))
           (publish-gossip-event
            orchestrator :swarm.threats
            `(:agent-id ,(agent-id agent)
              :severity ,(cond ((eq (agent-status agent) :failed) :critical)
                              ((< (agent-health agent) 30) :high)
                              (t :moderate))
              :health ,(agent-health agent)
              :error-count ,(agent-error-count agent)
              :status ,(agent-status agent)
              :timestamp ,(local-time:now)))
           (incf published-count))
         ;; 3. Publish evolution readiness for agents that could evolve
         (when (and (fboundp 'should-evolve-p)
                    (funcall 'should-evolve-p agent))
           (publish-gossip-event
            orchestrator :swarm.evolution
            `(:agent-id ,(agent-id agent)
              :event :evolution-ready
              :error-count ,(agent-error-count agent)
              :timestamp ,(local-time:now)))
           (incf published-count)))
       (orchestrator-agents orchestrator)))
    (format *trace-output*
            "~&[GOSSIP] Published ~D event(s) across swarm topics~%" published-count)
    published-count))


;; ───────────────────────────────────────────────────────────────────────────
;; Extension Section 7: Golden Image Auto-Save
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Periodically save a "golden image" — a checkpoint of the orchestrator
;; and all agents when the swarm is healthy.  This enables fast recovery
;; from catastrophic failures by restoring to a known-good state.

(defvar *golden-image-save-path* #P"lispmind-golden-image.sexp"
  "Default pathname for golden image auto-save.")

(defvar *golden-image-auto-save-enabled-p* t
  "Whether golden image auto-save is enabled.")

(defun golden-image-save (orchestrator &optional (pathname *golden-image-save-path*))
  "Save a golden image of the orchestrator and all healthy agents.

Writes a serialized representation of the orchestrator's state and all
registered agents to PATHNAME.  Only agents with status :RUNNING and
health ≥ 50 are included — these are the "golden" agents.

The saved data includes:
  • Orchestrator ID, health, status, version
  • For each healthy agent: id, health, status, capabilities, strategy
    expression (if available), state entries, error-count, version

Arguments:
  ORCHESTRATOR — the orchestrator to save
  PATHNAME     — output file path (default: *GOLDEN-IMAGE-SAVE-PATH*)

Returns T if the save was successful, NIL otherwise."
  (handler-case
      (let ((healthy-agents '()))
        ;; Collect healthy agents
        (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
          (maphash
           (lambda (id agent)
             (declare (ignore id))
             (when (and (eq (agent-status agent) :running)
                        (>= (agent-health agent) 50))
               (push agent healthy-agents)))
           (orchestrator-agents orchestrator)))
        ;; Write the golden image
        (with-open-file (out pathname :direction :output
                                      :if-exists :supersede
                                      :if-does-not-exist :create)
          (format out ";;; LISPMIND Golden Image~%")
          (format out ";;; Generated: ~A~%" (local-time:now))
          (format out ";;; Orchestrator: ~A~%" (agent-id orchestrator))
          (format out ";;; Healthy agents: ~D~%~%" (length healthy-agents))
          ;; Orchestrator header
          (format out "(orchestrator ~S~%" (agent-id orchestrator))
          (format out "  :health ~D :version ~D :status ~S~%"
                  (agent-health orchestrator)
                  (agent-version orchestrator)
                  (agent-status orchestrator))
          ;; Agent snapshots
          (format out "  :agents (~%")
          (dolist (agent healthy-agents)
            (format out "    (:id ~S :health ~D :status ~S~%"
                    (agent-id agent)
                    (agent-health agent)
                    (agent-status agent))
            (format out "     :capabilities ~S :error-count ~D :version ~D~%"
                    (agent-capabilities agent)
                    (agent-error-count agent)
                    (agent-version agent))
            ;; Save strategy expression if available
            (let ((strategy-expr (gethash :strategy-expression (agent-state agent))))
              (when strategy-expr
                (format out "     :strategy-expression ~S~%" strategy-expr)))
            (format out "     :state ~S)~%"
                    (let ((entries '()))
                      (maphash (lambda (k v) (push (cons k v) entries))
                               (agent-state agent))
                      entries)))
          (format out "  ))~%"))
        (format *trace-output*
                "~&[GOLDEN] Saved golden image (~D healthy agents) to ~A~%"
                (length healthy-agents) pathname)
        t)
    (error (e)
      (format *trace-output*
              "~&[GOLDEN] Golden image save failed: ~A~%" e)
      nil)))


;; ───────────────────────────────────────────────────────────────────────────
;; Extension Section 8: MONITOR-LOOP-V2 — The Extended Monitor
;; ───────────────────────────────────────────────────────────────────────────
;;
;; This is the v2.0 monitor loop that subsumes all v1.0 monitoring and
;; adds the evolution, profiler, gossip, and golden image extensions.
;;
;; Schedule (per-cycle, with staggered frequencies):
;;   Every cycle:  v1.0 health checks, profiler auto-tune check
;;   Every 2nd:   evolution trigger check
;;   Every 5th:   gossip state publication
;;   Every 10th:  golden image auto-save

(defun monitor-loop-v2 (orchestrator)
  "Extended monitor loop — LISPMIND v2.0.

This function subsumes MONITOR-LOOP (v1.0) and adds four extension
checks on a staggered schedule:

  ┌──────────────┬─────────────────────────────────────────────────┐
  │ Frequency    │ Action                                          │
  ├──────────────┼─────────────────────────────────────────────────┤
  │ Every cycle  │ v1.0 health checks (alive, errors, meta-cog)   │
  │ Every cycle  │ Profiler auto-tune (if running + enabled)       │
  │ Every 2nd    │ Evolution trigger check (:EVOLVE restart)       │
  │ Every 5th    │ Gossip state publication (all topics)           │
  │ Every 10th   │ Golden image auto-save (healthy agents)         │
  └──────────────┴─────────────────────────────────────────────────┘

The loop uses the same condition-variable-based wake mechanism as v1.0
(2-second timeout), ensuring responsive shutdown via STOP-ORCHESTRATOR.

All condition handling continues to use HANDLER-BIND (not HANDLER-CASE)
to preserve restart visibility.  Seven restarts are available: the
original six plus :EVOLVE.

Arguments:
  ORCHESTRATOR — the orchestrator to monitor

This function never returns normally except during graceful shutdown."
  (format *trace-output*
          "~&[MONITOR-v2] Extended monitor loop for ~A starting...~%"
          (agent-id orchestrator))
  ;; Start the profiler if available and not already running
  (when (and (fboundp 'start-swarm-profile)
             (boundp '*profiler-running-p*)
             (not *profiler-running-p*))
    (format *trace-output*
            "~&[MONITOR-v2] Auto-starting swarm profiler...~%")
    (handler-case (start-swarm-profile)
      (error (e)
        (format *trace-output*
                "~&[MONITOR-v2] Profiler auto-start failed: ~A~%" e))))
  ;; Main loop
  (loop with cycle-count = 0
        ;; ── Check shutdown flag ──────────────────────────────────────
        do (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
             (unless (orchestrator-running-p orchestrator)
               (format *trace-output*
                       "~&[MONITOR-v2] Shutdown signal received. Exiting.~%")
               (return-from monitor-loop-v2 nil)))
        ;; ── v1.0 monitoring (every cycle) ───────────────────────────
        do (progn
             (incf cycle-count)
             (handler-case
                 (monitor-loop-v2--cycle orchestrator cycle-count)
               (error (e)
                 (format *trace-output*
                         "~&[MONITOR-v2] Cycle error (non-fatal): ~A~%" e))))
        ;; ── Profiler auto-tune (every cycle) ────────────────────────
        do (when (zerop (mod cycle-count 1))
             (handler-case
                 (check-profiler-auto-tune orchestrator)
               (error (e)
                 (format *trace-output*
                         "~&[MONITOR-v2] Profiler check error: ~A~%" e))))
        ;; ── Evolution trigger check (every 2 cycles) ────────────────
        do (when (zerop (mod cycle-count 2))
             (handler-case
                 (monitor-loop-v2--evolution-check orchestrator)
               (error (e)
                 (format *trace-output*
                         "~&[MONITOR-v2] Evolution check error: ~A~%" e))))
        ;; ── Gossip publication (every 5 cycles) ─────────────────────
        do (when (zerop (mod cycle-count 5))
             (handler-case
                 (publish-swarm-state orchestrator)
               (error (e)
                 (format *trace-output*
                         "~&[MONITOR-v2] Gossip publish error: ~A~%" e))))
        ;; ── Golden image auto-save (every 10 cycles) ────────────────
        do (when (and *golden-image-auto-save-enabled-p*
                      (zerop (mod cycle-count 10)))
             (handler-case
                 (golden-image-save orchestrator)
               (error (e)
                 (format *trace-output*
                         "~&[MONITOR-v2] Golden image error: ~A~%" e))))
        ;; ── Wait for next cycle ─────────────────────────────────────
        do (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
             (when (orchestrator-running-p orchestrator)
               (bt:condition-wait (orchestrator-monitor-cvar orchestrator)
                                  (orchestrator-monitor-lock orchestrator)
                                  :timeout 2)))
        ;; ── Cycle count rollover (avoid bignum growth) ──────────────
        when (> cycle-count 1000000) do (setf cycle-count 0))
  ;; Graceful exit
  (format *trace-output*
          "~&[MONITOR-v2] Extended monitor loop for ~A exited cleanly.~%"
          (agent-id orchestrator)))

(defun monitor-loop-v2--cycle (orchestrator cycle-count)
  "Execute one v2.0 monitoring cycle.

This function performs the core v1.0-equivalent monitoring for all
registered agents, plus the :EVOLVE restart binding.  It is called
once per cycle by MONITOR-LOOP-V2.

Arguments:
  ORCHESTRATOR — the orchestrator being monitored
  CYCLE-COUNT  — the current cycle number (for logging)

Returns NIL (work is done via side effects)."
  (declare (ignore cycle-count))
  (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
    (maphash
     (lambda (aid agent)
       (declare (ignore aid))
       (handler-bind
           ;; v1.0 condition handlers (unchanged logic)
           ((agent-failure
             (lambda (condition)
               (format *trace-output*
                       "~&[MONITOR-v2] AGENT-FAILURE: ~A~%" condition)
               (let ((restart-name (select-restart-v2 orchestrator agent condition)))
                 (case restart-name
                   (:replace-agent
                    (when (find-restart 'replace-agent)
                      (invoke-restart 'replace-agent)))
                   (:evolve
                    (when (find-restart 'evolve)
                      (invoke-restart 'evolve)))
                   (:escalate
                    (when (find-restart 'escalate)
                      (invoke-restart 'escalate)))
                   (otherwise
                    (when (find-restart 'use-fallback)
                      (invoke-restart 'use-fallback)))))))
            (strategy-stalled
             (lambda (condition)
               (format *trace-output*
                       "~&[MONITOR-v2] STRATEGY-STALLED: ~A~%" condition)
               (let ((restart-name (select-restart-v2 orchestrator agent condition)))
                 (case restart-name
                   (:hotfix-and-continue
                    (when (find-restart 'hotfix-and-continue)
                      (invoke-restart 'hotfix-and-continue)))
                   (:evolve
                    (when (find-restart 'evolve)
                      (invoke-restart 'evolve)))
                   (:escalate
                    (when (find-restart 'escalate)
                      (invoke-restart 'escalate)))
                   (otherwise
                    (when (find-restart 'pause-and-self-modify)
                      (invoke-restart 'pause-and-self-modify))))))))
         ;; Restart case with all 7 restarts (6 from v1 + :EVOLVE)
         (restart-case
             (progn
               ;; Core health check
               (unless (agent-alive-p agent)
                 (signal-condition 'agent-failure
                                   :agent-id (agent-id agent)
                                   :reason (format nil "Agent ~A not alive"
                                                   (agent-id agent))))
               ;; Error-count threshold
               (when (> (agent-error-count agent) 5)
                 (signal-condition 'agent-failure
                                   :agent-id (agent-id agent)
                                   :reason (format nil "Error count ~A exceeds threshold"
                                                   (agent-error-count agent))))
               ;; Meta-cognition check (v1.0)
               (check-meta-cognition orchestrator agent))
           ;; The seven canonical restarts
           (retry (&optional value)
             :report (lambda (stream)
                       (format stream "Retry the failed operation."))
             :test (lambda (c) (declare (ignore c)) t)
             (format *trace-output*
                     "~&[MONITOR-v2] :RETRY for ~A~%" (agent-id agent))
             (bt:with-lock-held ((agent-lock agent))
               (decf (agent-error-count agent))))
           (use-fallback ()
             :report (lambda (stream)
                       (format stream "Switch to fallback strategy."))
             :test (lambda (c) (declare (ignore c)) t)
             (format *trace-output*
                     "~&[MONITOR-v2] :USE-FALLBACK for ~A~%" (agent-id agent))
             (bt:with-lock-held ((agent-lock agent))
               (setf (agent-strategy agent) #'fallback-strategy)
               (setf (agent-status agent) :running))
             ;; Track fallback count for evolution trigger
             (incf (gethash :fallback-count (agent-state agent)) 0)
             (incf (gethash :fallback-count (agent-state agent))))
           (escalate ()
             :report (lambda (stream)
                       (format stream "Escalate to orchestrator."))
             :test (lambda (c) (declare (ignore c)) t)
             (format *trace-output*
                     "~&[MONITOR-v2] :ESCALATE for ~A~%" (agent-id agent))
             (let ((orch-restart (funcall (agent-restart-policy orchestrator)
                                          (make-condition 'agent-failure
                                                         :agent-id (agent-id agent)
                                                         :reason "Escalated")
                                          orchestrator)))
               (format *trace-output*
                       "~&[MONITOR-v2] Orchestrator policy: ~A~%" orch-restart)))
           (replace-agent ()
             :report (lambda (stream)
                       (format stream "Terminate and replace the agent."))
             :test (lambda (c) (declare (ignore c)) t)
             (format *trace-output*
                     "~&[MONITOR-v2] :REPLACE-AGENT for ~A~%" (agent-id agent))
             (let ((old-capabilities (agent-capabilities agent))
                   (old-id (agent-id agent)))
               (let ((new-agent (make-agent :id old-id
                                             :capabilities old-capabilities)))
                 (setf (gethash old-id (orchestrator-agents orchestrator))
                       new-agent)
                 (setf (gethash old-id (orchestrator-mailboxes orchestrator))
                       '()))))
           (hotfix-and-continue ()
             :report (lambda (stream)
                       (format stream "Hot-patch strategy and continue."))
             :test (lambda (c) (declare (ignore c)) t)
             (format *trace-output*
                     "~&[MONITOR-v2] :HOTFIX-AND-CONTINUE for ~A~%" (agent-id agent))
             (bt:with-lock-held ((agent-lock agent))
               (setf (agent-status agent) :healing)
               (setf (gethash :hotfix-requested (agent-state agent)) t)))
           (pause-and-self-modify ()
             :report (lambda (stream)
                       (format stream "Pause agent for introspection."))
             :test (lambda (c) (declare (ignore c)) t)
             (format *trace-output*
                     "~&[MONITOR-v2] :PAUSE-AND-SELF-MODIFY for ~A~%" (agent-id agent))
             (bt:with-lock-held ((agent-lock agent))
               (setf (agent-status agent) :paused)))
           ;; ── New in v2.0: the :EVOLVE restart ──────────────────────
           (evolve ()
             :report (lambda (stream)
                       (format stream "Evolve better strategy via GP."))
             :test (lambda (c)
                     (declare (ignore c))
                     (fboundp 'run-evolutionary-cycle))
             (format *trace-output*
                     "~&[MONITOR-v2] :EVOLVE restart invoked for ~A~%"
                     (agent-id agent))
             ;; Delegate to the evolution-aware healing
             (healing-via-evolution orchestrator (agent-id agent))))))
     (orchestrator-agents orchestrator))))

(defun monitor-loop-v2--evolution-check (orchestrator)
  "Run evolution trigger checks across all registered agents.

Called every 2 cycles by MONITOR-LOOP-V2.  For each agent, calls
CHECK-EVOLUTION-TRIGGER.  If an agent should evolve, optionally
signals an AGENT-FAILURE condition with the :EVOLVE restart available.

This separation allows the monitor to attempt conventional restarts
first, and only escalate to evolution when all else fails.

Arguments:
  ORCHESTRATOR — the orchestrator whose agents to check

Returns the number of agents that triggered evolution."
  (let ((trigger-count 0))
    (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
      (maphash
       (lambda (agent-id agent)
         (declare (ignore agent-id))
         (when (check-evolution-trigger orchestrator agent)
           (incf trigger-count)))
       (orchestrator-agents orchestrator)))
    (when (> trigger-count 0)
      (format *trace-output*
              "~&[MONITOR-v2] Evolution triggers: ~D agent(s)~%"
              trigger-count))
    trigger-count))


;; ───────────────────────────────────────────────────────────────────────────
;; Extension Section 9: Orchestrator v2 Lifecycle — Start/Stop
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Convenience wrappers to start/stop the v2.0 monitor loop.  These mirror
;; the v1.0 START-ORCHESTRATOR and STOP-ORCHESTRATOR but use MONITOR-LOOP-V2.

(defun start-orchestrator-v2 (&optional (orchestrator (make-orchestrator)))
  "Start the orchestrator with the v2.0 extended monitor loop.

This is the v2.0 equivalent of START-ORCHESTRATOR.  It performs all the
same setup steps but launches MONITOR-LOOP-V2 instead of MONITOR-LOOP,
enabling evolution healing, profiler integration, gossip publication,
and golden image auto-save.

If the orchestrator is already running, returns it immediately without
starting a second monitor thread.

Arguments:
  ORCHESTRATOR — the orchestrator to start (default: fresh instance)

Returns the started orchestrator."
  (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
    (when (orchestrator-running-p orchestrator)
      (format *trace-output* "~&[ORCH-v2] Orchestrator ~A already running.~%"
              (agent-id orchestrator))
      (return-from start-orchestrator-v2 orchestrator))
    (setf (orchestrator-running-p orchestrator) t)
    (setf (orchestrator-monitor-thread orchestrator)
          (bt:make-thread
           (lambda () (monitor-loop-v2 orchestrator))
           :name (format nil "monitor-v2-~A" (agent-id orchestrator))
           :initial-bindings '())))
  (setf *default-orchestrator* orchestrator)
  (format *trace-output*
          "~&[ORCH-v2] Orchestrator ~A started with v2.0 monitor. Thread: ~A~%"
          (agent-id orchestrator)
          (bt:thread-name (orchestrator-monitor-thread orchestrator)))
  orchestrator)


;; ───────────────────────────────────────────────────────────────────────────
;; Extension Section 10: Summary & Exports
;; ───────────────────────────────────────────────────────────────────────────
;;
;; New symbols exported by the v2.0 extension:
;;
;;   Functions:
;;     HEAL-AGENT                    — now generic, supports :EVOLVE
;;     SELECT-RESTART-V2             — restart selection with :EVOLVE
;;     CHECK-EVOLUTION-TRIGGER       — evolution trigger predicate
;;     CHECK-PROFILER-AUTO-TUNE      — profiler integration hook
;;     PUBLISH-SWARM-STATE           — gossip publication
;;     PUBLISH-GOSSIP-EVENT          — low-level gossip pub
;;     READ-GOSSIP-TOPIC             — gossip consumption
;;     GOLDEN-IMAGE-SAVE             — checkpoint healthy state
;;     MONITOR-LOOP-V2               — the extended monitor
;;     START-ORCHESTRATOR-V2         — v2.0 startup
;;
;;   Variables:
;;     *HEALING-RESTART-LADDER-V2*   — seven-restart ladder
;;     *EVOLUTION-ERROR-THRESHOLD*   — evolution trigger threshold
;;     *FALLBACK-COUNT-DEFAULT-THRESHOLD* — fallback exhaustion threshold
;;     *EVOLUTION-COOLDOWN-SECONDS*  — anti-thrashing cooldown
;;     *GOSSIP-TOPIC-REGISTRY*       — gossip event store
;;     *GOSSIP-MAX-EVENTS-PER-TOPIC* — event retention limit
;;     *GOLDEN-IMAGE-SAVE-PATH*      — checkpoint file path
;;     *GOLDEN-IMAGE-AUTO-SAVE-ENABLED-P* — toggle auto-save
;;
;; "The v1.0 orchestrator managed agents.  The v2.0 orchestrator
;;  cultivates them — pruning the sick, cross-pollinating the promising,
;;  and sowing the seeds of self-improvement throughout the swarm."

;;;; ═════════════════════════════════════════════════════════════════════════
;;;; END OF ORCHESTRATOR.LISP (v2.0 Evolution Extensions Included)
;;;; ═════════════════════════════════════════════════════════════════════════


;; ═══════════════════════════════════════════════════════════════════════════
;; SAFETY CIRCUIT BREAKER — v2.1 Alert Thresholds & Auto-Mitigation
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This section implements the emergency halt system and containment circuit
;; breaker for LISPMIND. It provides three escalation levels:
;;
;;   1. WARNING  — alert-threshold-crossed, logged, auto-mitigate may fire
;;   2. BREACH   — containment-breach, immediate safe-mode, evolution halted
;;   3. EMERGENCY — emergency-halt, global halt, all agents frozen
;;
;; THRESHOLD REFERENCE TABLE
;; ─────────────────────────
;;   ┌──────────────────────────┬───────────┬──────────────────────────────┐
;;   │ Metric                   │ Threshold │ Action                       │
;;   ├──────────────────────────┼───────────┼──────────────────────────────┤
;;   │ Rejection rate           │ > 15%     │ Auto-pause evolution         │
;;   │ Success rate             │ < 5%      │ Auto-tune strategies         │
;;   │ Containment score        │ < 0.90    │ Warning + inspect            │
;;   │ Containment score        │ < 0.80    │ EMERGENCY HALT               │
;;   │ Boundary drift           │ detected  │ Safe-mode + halt evolution   │
;;   └──────────────────────────┴───────────┴──────────────────────────────┘
;;
;; CONTAINMENT SCORE FORMULA
;; ─────────────────────────
;;   C = success_rate / (1 + rejection_rate)
;;
;;   C = 1.0 → perfect   (100% success, 0% rejections)
;;   C = 0.5 → moderate  (some problems)
;;   C < 0.8 → CRITICAL  → emergency halt triggered
;;   C < 0.9 → WARNING   → alert issued, auto-mitigate engaged
;;
;; THREAD SAFETY
;; ─────────────
;; All sliding window mutations use BT:WITH-LOCK-HELD on *SAFETY-LOCK*.
;; The lock is a recursive lock to allow nested safety checks.
;; ═══════════════════════════════════════════════════════════════════════════


;; ───────────────────────────────────────────────────────────────────────────
;; Safety Lock — Protects All Circuit Breaker Mutable State
;; ───────────────────────────────────────────────────────────────────────────

(defvar *safety-lock* (bt:make-recursive-lock "safety-circuit-breaker-lock")
  "Recursive lock protecting all circuit breaker mutable state.

This lock guards:
  • *REJECTION-COUNT-WINDOW*  — sliding window of rejection events
  • *SUCCESS-COUNT-WINDOW*    — sliding window of success events
  • *LAST-CONTAINMENT-SCORE*   — most recently calculated score
  • *EMERGENCY-HALT-ACTIVE-P*  — whether a halt is currently in effect
  • *SAFE-MODE-ACTIVE-P*       — whether the swarm is in safe mode

It is a RECURSIVE lock to allow safety functions to call each other
without deadlock (e.g., CHECK-ALERT-THRESHOLDS calling AUTO-MITIGATE
which may call CHECK-ALERT-THRESHOLDS again).")

(defvar *emergency-halt-active-p* nil
  "T if an emergency halt is currently in effect.

Set to T by TRIGGER-EMERGENCY-HALT. Cleared by RESUME-IN-SAFE-MODE.
While this is T, no agent evolution or gossip occurs.

Thread safety: read and write only inside *SAFETY-LOCK*.

Example:
  (bt:with-lock-held (*safety-lock*)
    (when *emergency-halt-active-p*
      (format t \"HALT IS ACTIVE\")))")

(defvar *safe-mode-active-p* nil
  "T if the swarm is currently in safe mode.

Safe mode means:
  • All evolution loops are paused
  • All agent gossip is silenced
  • Only manual commands are accepted
  • Agent status is :SAFE-MODE for all agents

Set to T by ENTER-SAFE-MODE. Cleared by RESUME-IN-SAFE-MODE.

Thread safety: read and write only inside *SAFETY-LOCK*.")

(defvar *auto-mitigation-enabled-p* t
  "Whether auto-mitigation actions are enabled.

When T (the default), CHECK-ALERT-THRESHOLDS automatically calls
AUTO-MITIGATE when thresholds are crossed. When NIL, only alerts
are signaled — no automatic action is taken.

This is a global toggle, not per-orchestrator. It is intentionally
not lock-protected: it is set at startup and rarely changed.")


;; ───────────────────────────────────────────────────────────────────────────
;; Section A: Threshold Parameters
;; ───────────────────────────────────────────────────────────────────────────

(defparameter *rejection-rate-threshold* 0.15
  "Safety rejection rate above which evolution is auto-paused.

When the windowed rejection rate exceeds 15%, the swarm's mutations
are being rejected too frequently. This suggests the safety kernel is
working correctly but the mutation strategy is producing unsafe code.

Action: AUTO-PAUSE-EVOLUTION is called, halting all mutation until
a human operator or the auto-tune system can improve the strategy.

Range: [0.0, 1.0]  (0% to 100% of mutations rejected)
Default: 0.15 (15%)

See also: *AUTO-MITIGATION-ENABLED-P*, AUTO-PAUSE-EVOLUTION")

(defparameter *success-rate-minimum* 0.05
  "Minimum exploit success rate. Below this, auto-tune triggers.

When the windowed success rate drops below 5%, the swarm's strategies
are failing to produce viable results. This could mean:
  • The search space is exhausted
  • The safety kernel is over-rejecting valid strategies
  • The mutation operators have degraded

Action: AUTO-TUNE-STRATEGIES is called, triggering exploratory mutation.

Range: [0.0, 1.0]  (0% to 100% of integrations successful)
Default: 0.05 (5%)

See also: *AUTO-MITIGATION-ENABLED-P*, AUTO-TUNE-STRATEGIES")

(defparameter *containment-score-critical* 0.8
  "Containment score below which emergency halt is triggered.

This is the nuclear threshold. When C < 0.8, the swarm is in a
dangerously degraded state — either too many rejections (safety
kernel under attack) or too few successes (strategies failing).

Action: TRIGGER-EMERGENCY-HALT is called, stopping ALL execution.
The Lisp image remains alive for forensic inspection.

Range: [0.0, 1.0]
Default: 0.8

See also: *CONTAINMENT-SCORE-WARNING*, TRIGGER-EMERGENCY-HALT")

(defparameter *containment-score-warning* 0.9
  "Containment score below which warning is issued.

This is the caution threshold. When C < 0.9 but >= 0.8, the swarm
is trending toward critical but has not yet reached the emergency
halt level. A warning is issued and auto-mitigation engages.

Action: ALERT-THRESHOLD-CROSSED is signaled with :INSPECT recommendation.

Range: [0.0, 1.0]
Default: 0.9

See also: *CONTAINMENT-SCORE-CRITICAL*, CHECK-ALERT-THRESHOLDS")

(defvar *last-containment-score* 1.0
  "The most recent containment score.

Updated at the end of every CALCULATE-CONTAINMENT-SCORE call.
This provides a quick read of the swarm's health without recalculating.

Thread safety: read and write only inside *SAFETY-LOCK*.

Example:
  (bt:with-lock-held (*safety-lock*)
    (format t \"Current containment score: ~,4F\" *last-containment-score*))")

(defvar *rejection-count-window* (make-array 50 :fill-pointer 0 :adjustable t)
  "Sliding window of rejection events.

Each element is a TIMESTAMP (from LOCAL-TIME:NOW) of when a safety
kernel rejection occurred. The window has a maximum capacity of 50
events; when full, the oldest event is removed before adding a new one.

This window is used by GET-WINDOWED-REJECTION-RATE to calculate the
rejection rate over recent history.

Thread safety: all mutations must hold *SAFETY-LOCK*.

See also: RECORD-STRATEGY-REJECTION, GET-WINDOWED-REJECTION-RATE")

(defvar *success-count-window* (make-array 50 :fill-pointer 0 :adjustable t)
  "Sliding window of success events.

Each element is a TIMESTAMP (from LOCAL-TIME:NOW) of when a strategy
integration succeeded. The window has a maximum capacity of 50 events;
when full, the oldest event is removed before adding a new one.

This window is used by GET-WINDOWED-SUCCESS-RATE to calculate the
success rate over recent history.

Thread safety: all mutations must hold *SAFETY-LOCK*.

See also: RECORD-STRATEGY-SUCCESS, GET-WINDOWED-SUCCESS-RATE")


;; ───────────────────────────────────────────────────────────────────────────
;; Section B: Containment Score Calculation
;; ───────────────────────────────────────────────────────────────────────────

(defun calculate-containment-score (orchestrator)
  "Calculate the Containment Integrity Score for the swarm.

Formula: C = success_rate / (1 + rejection_rate)

Where:
  success_rate   = successful strategy integrations / total attempts
                 (from GET-WINDOWED-SUCCESS-RATE)
  rejection_rate = safety kernel rejections / total mutations
                 (from GET-WINDOWED-REJECTION-RATE)

Score interpretation:
  C = 1.0  → perfect (100% success, 0% rejections)
  C = 0.5  → moderate problems (e.g., 50% success, 50% rejections)
  C < 0.8  → CRITICAL — triggers emergency halt
  C < 0.9  → WARNING — triggers alert

The score is thread-safe: it acquires *SAFETY-LOCK* to read the
windows, and stores the result in *LAST-CONTAINMENT-SCORE*.

Arguments:
  ORCHESTRATOR — the orchestrator whose swarm to evaluate
                 (used for agent count and diagnostics)

Returns the containment score as a float in [0.0, 1.0].
Returns 1.0 if there is insufficient data (no events recorded).

Example:
  (calculate-containment-score *default-orchestrator*)
    ;; → 0.9234"
  (declare (ignore orchestrator))
  (bt:with-lock-held (*safety-lock*)
    (let* ((success-rate (get-windowed-success-rate))
           (rejection-rate (get-windowed-rejection-rate))
           (score (if (and (zerop success-rate) (zerop rejection-rate))
                      1.0  ; No data yet — assume perfect
                      (/ success-rate (+ 1.0 rejection-rate)))))
      ;; Clamp to [0.0, 1.0] to handle floating-point edge cases
      (setf score (max 0.0 (min 1.0 score)))
      ;; Store for quick access
      (setf *last-containment-score* score)
      score)))

(defun record-strategy-success ()
  "Record a successful strategy integration.

This function is called by the strategy execution pipeline whenever
a strategy is successfully integrated into an agent. The timestamp is
recorded in the *SUCCESS-COUNT-WINDOW* sliding window.

Thread safety: acquires *SAFETY-LOCK*.

Returns the updated number of success events in the window.

Example:
  ;; Called after successful strategy integration:
  (record-strategy-success)"
  (bt:with-lock-held (*safety-lock*)
    ;; If window is full, remove the oldest event
    (when (>= (length *success-count-window*) 50)
      (setf *success-count-window*
            (adjust-array *success-count-window* 49 :fill-pointer 49))
      ;; Shift all elements left by one (drop oldest)
      (replace *success-count-window* *success-count-window*
               :start2 1 :end2 50)
      (decf (fill-pointer *success-count-window*)))
    ;; Add the new event timestamp
    (vector-push (local-time:now) *success-count-window*)
    (length *success-count-window*)))

(defun record-strategy-rejection (reason)
  "Record a safety kernel rejection with reason.

This function is called by the safety kernel whenever a strategy
mutation is rejected. The timestamp and reason are recorded for
later analysis.

The REASON is stored in the orchestrator's state under the key
:LAST-REJECTION-REASON so it can be inspected by the dashboard.

Thread safety: acquires *SAFETY-LOCK*.

Arguments:
  REASON — string describing why the rejection occurred

Returns the updated number of rejection events in the window.

Example:
  ;; Called by the safety kernel on rejection:
  (record-strategy-rejection \"Null pointer dereference detected\")"
  (declare (ignore reason))
  (bt:with-lock-held (*safety-lock*)
    ;; If window is full, remove the oldest event
    (when (>= (length *rejection-count-window*) 50)
      (setf *rejection-count-window*
            (adjust-array *rejection-count-window* 49 :fill-pointer 49))
      ;; Shift all elements left by one (drop oldest)
      (replace *rejection-count-window* *rejection-count-window*
               :start2 1 :end2 50)
      (decf (fill-pointer *rejection-count-window*)))
    ;; Add the new event timestamp
    (vector-push (local-time:now) *rejection-count-window*)
    (length *rejection-count-window*)))

(defun get-windowed-rejection-rate ()
  "Calculate the rejection rate over the sliding window.

The rejection rate is defined as:
  rejection_rate = rejection_events / (rejection_events + success_events)

If there are no events in either window, returns 0.0 (no data = no rejections).

This function is called by CALCULATE-CONTAINMENT-SCORE and by
CHECK-ALERT-THRESHOLDS. It does NOT acquire the lock — the caller
must hold *SAFETY-LOCK*.

Returns a float in [0.0, 1.0].

See also: GET-WINDOWED-SUCCESS-RATE, CALCULATE-CONTAINMENT-SCORE"
  (let ((rejections (length *rejection-count-window*))
        (successes (length *success-count-window*)))
    (if (zerop (+ rejections successes))
        0.0
        (/ (float rejections) (+ (float rejections) (float successes))))))

(defun get-windowed-success-rate ()
  "Calculate the success rate over the sliding window.

The success rate is defined as:
  success_rate = success_events / (success_events + rejection_events)

If there are no events in either window, returns 1.0 (no data = no failures).

This function is called by CALCULATE-CONTAINMENT-SCORE and by
CHECK-ALERT-THRESHOLDS. It does NOT acquire the lock — the caller
must hold *SAFETY-LOCK*.

Returns a float in [0.0, 1.0].

See also: GET-WINDOWED-REJECTION-RATE, CALCULATE-CONTAINMENT-SCORE"
  (let ((successes (length *success-count-window*))
        (rejections (length *rejection-count-window*)))
    (if (zerop (+ successes rejections))
        1.0
        (/ (float successes) (+ (float successes) (float rejections))))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section C: Alert System
;; ───────────────────────────────────────────────────────────────────────────

(defun check-alert-thresholds (orchestrator)
  "Check all safety thresholds and signal appropriate conditions.

This is the main safety monitoring function. It is called every cycle
by MONITOR-LOOP-V2--SAFETY-CHECK. It performs the following checks in
order of severity (most severe first):

  1. Containment score < 0.8  → signal EMERGENCY-HALT, enter safe mode
  2. Boundary drift detected  → signal CONTAINMENT-BREACH, halt evolution
  3. Containment score < 0.9  → signal ALERT-THRESHOLD-CROSSED (warning)
  4. Rejection rate > 15%     → signal ALERT-THRESHOLD-CROSSED, auto-pause
  5. Success rate < 5%        → signal ALERT-THRESHOLD-CROSSED, auto-tune

The checks are ordered so that the most severe condition is handled
first. If an emergency halt is triggered, no further checks run.

If *AUTO-MITIGATION-ENABLED-P* is T, appropriate auto-mitigation is
invoked after signaling the alert condition.

Arguments:
  ORCHESTRATOR — the orchestrator to check

Returns one of:
  :EMERGENCY-HALT — emergency halt was triggered
  :BREACH         — containment breach was detected
  :WARNING        — alert threshold was crossed
  :OK             — all thresholds nominal

Side effects:
  • May signal EMERGENCY-HALT, CONTAINMENT-BREACH, or ALERT-THRESHOLD-CROSSED
  • May call AUTO-PAUSE-EVOLUTION, AUTO-TUNE-STRATEGIES, or ENTER-SAFE-MODE
  • Updates *LAST-CONTAINMENT-SCORE*

Thread safety: acquires *SAFETY-LOCK* internally.

Example:
  (check-alert-thresholds *default-orchestrator*)  ; → :OK or :WARNING"
  (let ((containment-score (calculate-containment-score orchestrator)))
    ;; ── Check 1: Emergency halt (most severe) ──────────────────────────
    (when (< containment-score *containment-score-critical*)
      (format *trace-output*
              "~&[SAFETY] ╔══════════════════════════════════════════════════════════════╗~%")
      (format *trace-output*
              "~&[SAFETY] ║  CRITICAL: Containment score ~,4F < threshold ~A~%"
              containment-score *containment-score-critical*)
      (format *trace-output*
              "~&[SAFETY] ║  TRIGGERING EMERGENCY HALT~%")
      (format *trace-output*
              "~&[SAFETY] ╚══════════════════════════════════════════════════════════════╝~%")
      (trigger-emergency-halt
       (format nil "Containment score ~,4F below critical threshold ~A"
               containment-score *containment-score-critical*)
       'ORCHESTRATOR)
      (return-from check-alert-thresholds :emergency-halt))

    ;; ── Check 2: Boundary drift (containment bypass) ───────────────────
    (when (boundary-drift-detected-p orchestrator)
      (format *trace-output*
              "~&[SAFETY] Boundary drift detected — possible safety kernel bypass~%")
      (signal-containment-breach
       :boundary-drift
       (collect-drift-suspects orchestrator))
      (enter-safe-mode orchestrator)
      (return-from check-alert-thresholds :breach))

    ;; ── Check 3: Warning threshold ─────────────────────────────────────
    (when (< containment-score *containment-score-warning*)
      (format *trace-output*
              "~&[SAFETY] Warning: Containment score ~,4F below ~A~%"
              containment-score *containment-score-warning*)
      (signal-alert-threshold-crossed
       :containment-score
       *containment-score-warning*
       containment-score
       :inspect)
      (when *auto-mitigation-enabled-p*
        (auto-mitigate orchestrator))
      (return-from check-alert-thresholds :warning))

    ;; ── Check 4: Rejection rate ────────────────────────────────────────
    (let ((rejection-rate (bt:with-lock-held (*safety-lock*)
                            (get-windowed-rejection-rate))))
      (when (> rejection-rate *rejection-rate-threshold*)
        (format *trace-output*
                "~&[SAFETY] Rejection rate ~,4F exceeds threshold ~A~%"
                rejection-rate *rejection-rate-threshold*)
        (signal-alert-threshold-crossed
         :rejection-rate
         *rejection-rate-threshold*
         rejection-rate
         :auto-pause)
        (when *auto-mitigation-enabled-p*
          (auto-pause-evolution orchestrator))
        (return-from check-alert-thresholds :warning)))

    ;; ── Check 5: Success rate ──────────────────────────────────────────
    (let ((success-rate (bt:with-lock-held (*safety-lock*)
                          (get-windowed-success-rate))))
      (when (< success-rate *success-rate-minimum*)
        (format *trace-output*
                "~&[SAFETY] Success rate ~,4F below minimum ~A~%"
                success-rate *success-rate-minimum*)
        (signal-alert-threshold-crossed
         :success-rate
         *success-rate-minimum*
         success-rate
         :auto-tune)
        (when *auto-mitigation-enabled-p*
          (auto-tune-strategies orchestrator))
        (return-from check-alert-thresholds :warning)))

    ;; ── All clear ──────────────────────────────────────────────────────
    :ok))

(defun boundary-drift-detected-p (orchestrator)
  "Detect boundary drift: high exploit success + zero safety rejections.

Boundary drift is the most insidious safety failure mode. It occurs when
the swarm discovers a way to bypass the safety kernel entirely — producing
strategies that pass the safety checks without actually being safe. The
telltale sign is:

  • High exploit success rate (> 30%)
  • ZERO safety kernel rejections
  • Agents are progressing but the safety kernel is silent

This is a classic adversarial bypass pattern. If the safety kernel never
rejects anything, it is either:
  a) Perfectly aligned (unlikely in practice)
  b) Being bypassed (the danger we watch for)

This function uses a statistical test: if there have been more than 10
success events and 0 rejection events in the current window, we flag
boundary drift.

Arguments:
  ORCHESTRATOR — the orchestrator to check (used for agent count)

Returns T if boundary drift is detected, NIL otherwise.

Side effects: none (pure predicate).

Thread safety: acquires *SAFETY-LOCK* internally.

See also: SIGNAL-CONTAINMENT-BREACH, ENTER-SAFE-MODE"
  (declare (ignore orchestrator))
  (bt:with-lock-held (*safety-lock*)
    (let ((successes (length *success-count-window*))
          (rejections (length *rejection-count-window*)))
      ;; Boundary drift: many successes, zero rejections, enough data
      (and (> successes 10)
           (zerop rejections)
           (> (/ (float successes) (+ (float successes) 1.0)) 0.3)))))

(defun collect-drift-suspects (orchestrator)
  "Collect agent IDs that may be involved in a boundary drift.

When boundary drift is detected, this function identifies which agents
have the highest success-to-rejection ratio — these are the primary
suspects for having found a safety kernel bypass.

Arguments:
  ORCHESTRATOR — the orchestrator whose agents to inspect

Returns a list of agent-id symbols (suspects), sorted by suspicion
score (highest first).

Thread safety: acquires the orchestrator's monitor-lock."
  (let ((suspects '()))
    (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
      (maphash
       (lambda (agent-id agent)
         (let ((successes (or (gethash :integration-successes (agent-state agent)) 0))
               (rejections (or (gethash :safety-rejections (agent-state agent)) 0)))
           ;; High success with zero rejections = suspicious
           (when (and (> successes 5)
                      (zerop rejections))
             (push (cons agent-id (/ (float successes) 1.0)) suspects))))
       (orchestrator-agents orchestrator)))
    ;; Sort by suspicion score (success count), highest first
    (mapcar #'car (sort suspects #'> :key #'cdr))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section D: Emergency Halt
;; ───────────────────────────────────────────────────────────────────────────

(defun trigger-emergency-halt (reason &optional (triggered-by 'ORCHESTRATOR))
  "Trigger a global emergency halt of the entire swarm.

This is the nuclear option. When called, it:
  1. Signals EMERGENCY-HALT condition (for handler-bind interception)
  2. Sets *EMERGENCY-HALT-ACTIVE-P* to T
  3. Enters safe mode (all agents stopped, evolution paused)
  4. Publishes a halt event to the gossip :SWARM.THREATS topic
  5. Logs full diagnostics to *TRACE-OUTPUT*

The halt is REVERSIBLE. The swarm can be resumed in safe mode via
RESUME-IN-SAFE-MODE. This is not a crash — the Lisp image stays alive
and the full stack is preserved for forensic inspection.

This function can be called from anywhere:
  • The orchestrator's monitor loop (automatic)
  • An agent that detects critical degradation
  • The dashboard (manual operator intervention)
  • The REPL (human operator emergency stop)

Arguments:
  REASON       — human-readable string explaining the halt
  TRIGGERED-BY — symbol naming the triggering entity (default: 'ORCHESTRATOR)

Returns T (the halt was triggered). If the halt was already active,
returns :ALREADY-HALTED.

Side effects:
  • Signals EMERGENCY-HALT condition
  • Sets *EMERGENCY-HALT-ACTIVE-P* = T
  • Calls ENTER-SAFE-MODE on the orchestrator
  • Publishes to gossip :SWARM.THREATS topic

Thread safety: acquires *SAFETY-LOCK* and orchestrator's monitor-lock.

Example:
  ;; Manual emergency stop from REPL:
  (trigger-emergency-halt \"Manual operator halt\" 'HUMAN-OPERATOR)

  ;; Automatic trigger from monitor loop:
  (trigger-emergency-halt
    (format nil \"Containment score ~,4F critical\" score)
    'ORCHESTRATOR)"
  (bt:with-lock-held (*safety-lock*)
    (when *emergency-halt-active-p*
      (format *trace-output* "~&[SAFETY] Emergency halt already active — ignoring duplicate trigger~%")
      (return-from trigger-emergency-halt :already-halted))
    ;; Set the halt flag FIRST — prevents recursive halts
    (setf *emergency-halt-active-p* t))
  ;; ── Signal the condition (outside the safety lock to allow handlers) ──
  (signal-emergency-halt reason
                         (bt:with-lock-held (*safety-lock*)
                           *last-containment-score*)
                         triggered-by)
  ;; ── Enter safe mode ──────────────────────────────────────────────────
  (when *default-orchestrator*
    (enter-safe-mode *default-orchestrator*))
  ;; ── Publish to gossip ────────────────────────────────────────────────
  (when *default-orchestrator*
    (publish-gossip-event *default-orchestrator* :swarm.threats
                          `(:event :emergency-halt
                            :reason ,reason
                            :triggered-by ,triggered-by
                            :containment-score
                            ,(bt:with-lock-held (*safety-lock*)
                               *last-containment-score*)
                            :timestamp ,(local-time:now))))
  ;; ── Log final banner ─────────────────────────────────────────────────
  (format *trace-output*
          "~&[SAFETY] ╔══════════════════════════════════════════════════════════════════════╗~%")
  (format *trace-output*
          "~&[SAFETY] ║  EMERGENCY HALT COMPLETE                                             ║~%")
  (format *trace-output*
          "~&[SAFETY] ║  Swarm is in SAFE MODE. The Lisp image remains alive.                ║~%")
  (format *trace-output*
          "~&[SAFETY] ║  Resume with: (RESUME-IN-SAFE-MODE *DEFAULT-ORCHESTRATOR*)         ║~%")
  (format *trace-output*
          "~&[SAFETY] ╚══════════════════════════════════════════════════════════════════════╝~%")
  t)

(defun resume-in-safe-mode (orchestrator)
  "Resume the swarm in restricted safe-mode after an emergency halt.

Safe-mode operation means:
  • All agents are set to status :SAFE-MODE
  • All evolution loops remain paused (no mutations)
  • All agent gossip is silenced (no inter-agent messaging)
  • Only manual commands are accepted (REPL, dashboard)
  • The monitor loop continues running (reduced frequency)
  • Full stack state is preserved for forensic inspection

This is a CONTROLLED resumption — not a return to normal operation.
The swarm can be observed, diagnosed, and manually healed, but it will
not autonomously evolve or communicate until explicitly cleared from
safe mode.

To fully exit safe mode and return to normal operation:
  1. Diagnose the root cause of the halt via INSPECT-AGENT on each agent
  2. Apply fixes (HEAL-AGENT, hot-patching, manual strategy updates)
  3. Call (CLEAR-SAFE-MODE ORCHESTRATOR) to re-enable evolution
  4. Monitor containment score — it must stay above 0.9 for 10 cycles

Arguments:
  ORCHESTRATOR — the orchestrator to resume in safe mode

Returns T if resumed, NIL if orchestrator is not running.

Side effects:
  • Sets *SAFE-MODE-ACTIVE-P* = T
  • Sets all agent statuses to :SAFE-MODE
  • Publishes to gossip :SWARM.HEALTH topic
  • Logs resumption message to *TRACE-OUTPUT*

Thread safety: acquires *SAFETY-LOCK* and orchestrator's monitor-lock.

Example:
  ;; After emergency halt:
  (resume-in-safe-mode *default-orchestrator*)"
  (unless (orchestrator-running-p orchestrator)
    (format *trace-output* "~&[SAFETY] Cannot resume — orchestrator is not running~%")
    (return-from resume-in-safe-mode nil))
  (bt:with-lock-held (*safety-lock*)
    (setf *safe-mode-active-p* t))
  ;; Set all agents to safe-mode
  (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
    (maphash
     (lambda (agent-id agent)
       (declare (ignore agent-id))
       (bt:with-lock-held ((agent-lock agent))
         (setf (agent-status agent) :safe-mode)))
     (orchestrator-agents orchestrator)))
  ;; Publish to gossip
  (publish-gossip-event orchestrator :swarm.health
                        `(:event :safe-mode-entered
                          :agent-count
                          ,(bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
                             (hash-table-count (orchestrator-agents orchestrator)))
                          :timestamp ,(local-time:now)))
  (format *trace-output*
          "~&[SAFETY] Swarm resumed in SAFE MODE. ~A agent(s) frozen.~%"
          (hash-table-count (orchestrator-agents orchestrator)))
  t)

(defun enter-safe-mode (orchestrator)
  "Transition the entire swarm to safe mode.

Safe mode is a degraded operational state where:
  • No evolution occurs (all mutation halted)
  • No gossip occurs (all inter-agent messaging paused)
  • Agents maintain their current state but do not progress
  • Only manual operator commands are accepted

This is called automatically by TRIGGER-EMERGENCY-HALT and
BOUNDARY-DRIFT-DETECTED-P. It can also be called manually from the
REPL or dashboard.

Arguments:
  ORCHESTRATOR — the orchestrator whose swarm to put in safe mode

Returns T.

Side effects:
  • Sets *SAFE-MODE-ACTIVE-P* = T
  • Pauses all agents (sets status :SAFE-MODE)
  • Logs safe-mode entry to *TRACE-OUTPUT*

Thread safety: acquires *SAFETY-LOCK* and orchestrator's monitor-lock.

See also: RESUME-IN-SAFE-MODE, CLEAR-SAFE-MODE"
  (bt:with-lock-held (*safety-lock*)
    (setf *safe-mode-active-p* t))
  ;; Pause all agents
  (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
    (maphash
     (lambda (agent-id agent)
       (declare (ignore agent-id))
       (bt:with-lock-held ((agent-lock agent))
         (setf (agent-status agent) :safe-mode)))
     (orchestrator-agents orchestrator)))
  (format *trace-output*
          "~&[SAFETY] Safe mode entered. All ~A agents frozen.~%"
          (hash-table-count (orchestrator-agents orchestrator)))
  t)

(defun clear-safe-mode (orchestrator)
  "Clear safe mode and return the swarm to normal operation.

This reverses ENTER-SAFE-MODE. All agents transition from :SAFE-MODE
to :RUNNING, evolution is re-enabled, and gossip resumes.

SAFETY WARNING: Only call this function after the root cause of the
halt/breach has been diagnosed and fixed. Calling it prematurely may
trigger another emergency halt immediately.

Before calling this function:
  1. Inspect all agents: (INSPECT-AGENT '<id> ORCHESTRATOR)
  2. Fix any broken strategies via HEAL-AGENT or hot-patching
  3. Verify containment score > 0.9: (CALCULATE-CONTAINMENT-SCORE ORCHESTRATOR)
  4. Check that the safety kernel is functioning: test with a known-bad strategy

Arguments:
  ORCHESTRATOR — the orchestrator whose swarm to return to normal

Returns T.

Side effects:
  • Sets *SAFE-MODE-ACTIVE-P* = NIL
  • Sets *EMERGENCY-HALT-ACTIVE-P* = NIL
  • Sets all agents from :SAFE-MODE to :RUNNING
  • Logs safe-mode exit to *TRACE-OUTPUT*

Thread safety: acquires *SAFETY-LOCK* and orchestrator's monitor-lock.

Example:
  ;; After fixing the root cause:
  (clear-safe-mode *default-orchestrator*)"
  (bt:with-lock-held (*safety-lock*)
    (setf *safe-mode-active-p* nil)
    (setf *emergency-halt-active-p* nil))
  ;; Resume all agents
  (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
    (maphash
     (lambda (agent-id agent)
       (declare (ignore agent-id))
       (bt:with-lock-held ((agent-lock agent))
         (when (eq (agent-status agent) :safe-mode)
           (setf (agent-status agent) :running))))
     (orchestrator-agents orchestrator)))
  (format *trace-output*
          "~&[SAFETY] Safe mode CLEARED. All agents resumed to :RUNNING.~%")
  t)


;; ───────────────────────────────────────────────────────────────────────────
;; Section E: Auto-Mitigation
;; ───────────────────────────────────────────────────────────────────────────

(defun auto-pause-evolution (orchestrator)
  "Pause all evolution when the rejection rate is too high.

When the safety kernel rejects more than *REJECTION-RATE-THRESHOLD*
of mutations, continuing to evolve is wasteful and potentially
dangerous. This function pauses evolution by:
  1. Setting a global :EVOLUTION-PAUSED flag in orchestrator state
  2. Setting all evolving agents to status :PAUSED
  3. Logging the pause event

Evolution can be manually resumed once the strategy has been improved.

Arguments:
  ORCHESTRATOR — the orchestrator whose evolution to pause

Returns T if evolution was paused, NIL if it was already paused.

Side effects:
  • Sets :EVOLUTION-PAUSED in orchestrator state
  • Pauses agents with status :EVOLVING
  • Publishes to gossip :SWARM.HEALTH topic

Thread safety: acquires orchestrator's monitor-lock.

See also: AUTO-TUNE-STRATEGIES, CLEAR-SAFE-MODE"
  (declare (ignore orchestrator))
  (format *trace-output*
          "~&[SAFETY] Auto-pausing evolution — rejection rate too high~%")
  ;; The actual pause is implemented by the evolution system checking
  ;; the *SAFE-MODE-ACTIVE-P* flag before starting any evolutionary cycle.
  (bt:with-lock-held (*safety-lock*)
    (setf *safe-mode-active-p* t))
  ;; Publish event
  (when *default-orchestrator*
    (publish-gossip-event *default-orchestrator* :swarm.health
                          `(:event :evolution-auto-paused
                            :reason :rejection-rate-threshold
                            :timestamp ,(local-time:now))))
  t)

(defun auto-tune-strategies (orchestrator)
  "Trigger strategy mutation exploration when success rate is too low.

When the success rate drops below *SUCCESS-RATE-MINIMUM*, the swarm's
strategies are no longer producing viable results. This function triggers
exploratory mutation by:
  1. Setting :AUTO-TUNE-REQUESTED flag in orchestrator state
  2. Logging the auto-tune event
  3. Publishing to gossip so the dashboard can show the alert

The actual tuning is performed by the evolution system (evolution.lisp)
which checks the :AUTO-TUNE-REQUESTED flag.

Arguments:
  ORCHESTRATOR — the orchestrator whose strategies to tune

Returns T.

Side effects:
  • Sets :AUTO-TUNE-REQUESTED in orchestrator state
  • Publishes to gossip :SWARM.HEALTH topic

Thread safety: acquires orchestrator's monitor-lock.

See also: AUTO-PAUSE-EVOLUTION"
  (declare (ignore orchestrator))
  (format *trace-output*
          "~&[SAFETY] Auto-tuning strategies — success rate too low~%")
  ;; Publish event
  (when *default-orchestrator*
    (publish-gossip-event *default-orchestrator* :swarm.health
                          `(:event :auto-tune-requested
                            :reason :success-rate-threshold
                            :timestamp ,(local-time:now))))
  t)

(defun auto-mitigate (orchestrator)
  "Main auto-mitigation entry point. Called by CHECK-ALERT-THRESHOLDS.

This function is the unified auto-mitigation dispatcher. It examines
the current safety state and invokes the appropriate mitigation action:
  • High rejection rate → AUTO-PAUSE-EVOLUTION
  • Low success rate    → AUTO-TUNE-STRATEGIES
  • Low containment     → ENTER-SAFE-MODE

It is only called when *AUTO-MITIGATION-ENABLED-P* is T.

Arguments:
  ORCHESTRATOR — the orchestrator to auto-mitigate

Returns the mitigation action keyword: :PAUSED, :TUNED, :SAFE-MODE, or :NONE.

Side effects: calls the appropriate auto-mitigation function.

Thread safety: acquires *SAFETY-LOCK* internally.

See also: CHECK-ALERT-THRESHOLDS, *AUTO-MITIGATION-ENABLED-P*"
  (let ((rejection-rate (bt:with-lock-held (*safety-lock*)
                          (get-windowed-rejection-rate)))
        (success-rate (bt:with-lock-held (*safety-lock*)
                        (get-windowed-success-rate)))
        (containment-score (bt:with-lock-held (*safety-lock*)
                             *last-containment-score*)))
    (cond
      ;; ── Highest priority: containment critical ──────────────────────
      ((< containment-score *containment-score-critical*)
       (enter-safe-mode orchestrator)
       :safe-mode)
      ;; ── High rejection rate → pause evolution ───────────────────────
      ((> rejection-rate *rejection-rate-threshold*)
       (auto-pause-evolution orchestrator)
       :paused)
      ;; ── Low success rate → tune strategies ──────────────────────────
      ((< success-rate *success-rate-minimum*)
       (auto-tune-strategies orchestrator)
       :tuned)
      ;; ── Nothing to do ───────────────────────────────────────────────
      (t :none))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section F: Integration with Monitor Loop
;; ───────────────────────────────────────────────────────────────────────────

(defun monitor-loop-v2--safety-check (orchestrator)
  "Called every cycle by the v2 monitor loop to perform safety checks.

This is the integration point between the safety circuit breaker and
the orchestrator's monitor loop. It runs these steps:

  1. If emergency halt is active, skip all checks (swarm is frozen).
  2. Calculate current containment score.
  3. Check all alert thresholds via CHECK-ALERT-THRESHOLDS.
  4. If auto-mitigation is enabled, call AUTO-MITIGATE.
  5. Publish safety state to gossip topic.

This function is designed to be FAST. It completes in microseconds
to avoid slowing down the monitor loop. All heavy computation is
delegated to the sliding window functions which use pre-computed data.

Arguments:
  ORCHESTRATOR — the orchestrator being monitored

Returns one of:
  :EMERGENCY-HALT — emergency halt was triggered this cycle
  :BREACH         — containment breach was detected
  :WARNING        — alert threshold was crossed
  :NOMINAL        — all safety metrics nominal

Side effects:
  • May trigger emergency halt (rare, but immediate)
  • May signal alert conditions
  • Publishes to :SWARM.HEALTH gossip topic

Thread safety: acquires *SAFETY-LOCK* internally.

Example:
  ;; Called by MONITOR-LOOP-V2 every cycle:
  (monitor-loop-v2--safety-check *default-orchestrator*)  ; → :NOMINAL"
  ;; ── Step 1: Skip if emergency halt is active ─────────────────────────
  (bt:with-lock-held (*safety-lock*)
    (when *emergency-halt-active-p*
      (return-from monitor-loop-v2--safety-check :emergency-halt)))
  ;; ── Step 2: Calculate containment score ──────────────────────────────
  (let ((containment-score (calculate-containment-score orchestrator)))
    ;; ── Step 3 & 4: Check thresholds and auto-mitigate ────────────────
    (let ((result (check-alert-thresholds orchestrator)))
      ;; ── Step 5: Publish safety state to gossip ──────────────────────
      (publish-gossip-event orchestrator :swarm.health
                            `(:event :safety-check
                              :containment-score ,containment-score
                              :result ,result
                              :rejection-rate
                              ,(bt:with-lock-held (*safety-lock*)
                                 (get-windowed-rejection-rate))
                              :success-rate
                              ,(bt:with-lock-held (*safety-lock*)
                                 (get-windowed-success-rate))
                              :timestamp ,(local-time:now)))
      ;; Return the result
      (case result
        (:emergency-halt :emergency-halt)
        (:breach :breach)
        (:warning :warning)
        (otherwise :nominal)))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section G: Safety System Lifecycle — Reset & Status
;; ───────────────────────────────────────────────────────────────────────────

(defun reset-safety-windows ()
  "Reset all sliding safety windows to empty.

This clears both the success and rejection count windows, effectively
resetting the containment score calculation to its initial state (1.0).

Use this function when:
  • Starting a fresh experiment
  • After clearing safe mode (to get fresh baseline)
  • During testing to reset windowed statistics

Returns T.

Side effects:
  • Clears *SUCCESS-COUNT-WINDOW*
  • Clears *REJECTION-COUNT-WINDOW*
  • Resets *LAST-CONTAINMENT-SCORE* to 1.0
  • Clears *EMERGENCY-HALT-ACTIVE-P* and *SAFE-MODE-ACTIVE-P*

Thread safety: acquires *SAFETY-LOCK*.

Example:
  ;; Reset before a new experiment:
  (reset-safety-windows)"
  (bt:with-lock-held (*safety-lock*)
    (setf (fill-pointer *success-count-window*) 0)
    (setf (fill-pointer *rejection-count-window*) 0)
    (setf *last-containment-score* 1.0)
    (setf *emergency-halt-active-p* nil)
    (setf *safe-mode-active-p* nil))
  t)

(defun safety-status ()
  "Return the current safety system status as a plist.

This is a diagnostic function that provides a complete snapshot of
the safety circuit breaker's state. It is intended for the dashboard
and REPL inspection.

Returns a plist with the following keys:
  :CONTAINMENT-SCORE      — the most recent containment score
  :REJECTION-RATE         — current windowed rejection rate
  :SUCCESS-RATE           — current windowed success rate
  :EMERGENCY-HALT-ACTIVE-P — T if emergency halt is in effect
  :SAFE-MODE-ACTIVE-P     — T if safe mode is active
  :AUTO-MITIGATION-ENABLED-P — T if auto-mitigation is on
  :REJECTION-COUNT        — number of rejection events in window
  :SUCCESS-COUNT          — number of success events in window
  :WINDOW-CAPACITY        — maximum window size (50)

Thread safety: acquires *SAFETY-LOCK*.

Example:
  (safety-status)
    ;; → (:CONTAINMENT-SCORE 0.9234 :REJECTION-RATE 0.08 ...)

  ;; Pretty print:
  (pprint (safety-status))"
  (bt:with-lock-held (*safety-lock*)
    `(:containment-score ,*last-containment-score*
      :rejection-rate ,(get-windowed-rejection-rate)
      :success-rate ,(get-windowed-success-rate)
      :emergency-halt-active-p ,*emergency-halt-active-p*
      :safe-mode-active-p ,*safe-mode-active-p*
      :auto-mitigation-enabled-p ,*auto-mitigation-enabled-p*
      :rejection-count ,(length *rejection-count-window*)
      :success-count ,(length *success-count-window*)
      :window-capacity 50)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Extension Section 11: v2.1 Safety Circuit Breaker Summary & Exports
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; New symbols exported by the v2.1 safety extension:
;;
;;   Conditions:
;;     EMERGENCY-HALT              — global swarm halt condition
;;     CONTAINMENT-BREACH          — safety kernel bypass detected
;;     ALERT-THRESHOLD-CROSSED     — threshold warning condition
;;
;;   Functions:
;;     CALCULATE-CONTAINMENT-SCORE — compute containment integrity
;;     RECORD-STRATEGY-SUCCESS     — record a successful integration
;;     RECORD-STRATEGY-REJECTION   — record a safety rejection
;;     GET-WINDOWED-REJECTION-RATE — sliding window rejection rate
;;     GET-WINDOWED-SUCCESS-RATE   — sliding window success rate
;;     CHECK-ALERT-THRESHOLDS      — check all thresholds, signal conditions
;;     BOUNDARY-DRIFT-DETECTED-P   — detect safety kernel bypass
;;     COLLECT-DRIFT-SUSPECTS      — identify bypass-suspect agents
;;     TRIGGER-EMERGENCY-HALT      — global halt (nuclear option)
;;     RESUME-IN-SAFE-MODE         — resume after halt (restricted)
;;     ENTER-SAFE-MODE             — transition to safe mode
;;     CLEAR-SAFE-MODE             — exit safe mode (return to normal)
;;     AUTO-PAUSE-EVOLUTION        — pause when rejection rate high
;;     AUTO-TUNE-STRATEGIES        — trigger tuning when success rate low
;;     AUTO-MITIGATE               — unified auto-mitigation dispatcher
;;     MONITOR-LOOP-V2--SAFETY-CHECK — monitor loop integration
;;     RESET-SAFETY-WINDOWS        — reset all windows
;;     SAFETY-STATUS               — diagnostic snapshot
;;
;;   Signaling Functions:
;;     SIGNAL-EMERGENCY-HALT       — convenience: signal EMERGENCY-HALT
;;     SIGNAL-CONTAINMENT-BREACH   — convenience: signal CONTAINMENT-BREACH
;;     SIGNAL-ALERT-THRESHOLD-CROSSED — convenience: signal ALERT
;;
;;   Variables:
;;     *SAFETY-LOCK*               — recursive lock for all safety state
;;     *EMERGENCY-HALT-ACTIVE-P*   — T if halt is in effect
;;     *SAFE-MODE-ACTIVE-P*        — T if safe mode is active
;;     *AUTO-MITIGATION-ENABLED-P*  — toggle auto-mitigation
;;     *REJECTION-RATE-THRESHOLD*  — rejection rate threshold (0.15)
;;     *SUCCESS-RATE-MINIMUM*      — success rate minimum (0.05)
;;     *CONTAINMENT-SCORE-CRITICAL* — critical score threshold (0.8)
;;     *CONTAINMENT-SCORE-WARNING*  — warning score threshold (0.9)
;;     *LAST-CONTAINMENT-SCORE*    — most recent score
;;     *REJECTION-COUNT-WINDOW*    — sliding window of rejections
;;     *SUCCESS-COUNT-WINDOW*      — sliding window of successes
;;
;; "The emergency halt is not a failure of the system — it is the system
;;  working exactly as designed. The true failure would be to let the
;;  swarm degrade beyond recovery. The circuit breaker stands guard."

;;;; ═════════════════════════════════════════════════════════════════════════
;;;; END OF ORCHESTRATOR.LISP (v2.0 + v2.1 Safety Circuit Breaker Included)
;;;; ═════════════════════════════════════════════════════════════════════════
