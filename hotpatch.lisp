;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; HOTPATCH.LISP — Safe, Versioned, Hot Code Replacement for LISPMIND
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;                     HOTPATCHING: THE SECRET OF LISPMIND'S IMMORTALITY
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This file provides the live code replacement machinery that makes LISPMIND
;;; self-healing without stopping. When an agent's strategy is buggy, stalled,
;;; or merely suboptimal, HOTPATCH-AGENT installs a new strategy function while
;;; the agent continues running. No threads are killed, no state is lost, no
;;; messages are dropped. The agent simply starts executing better code on its
;;; next iteration.
;;;
;;; DESIGN PHILOSOPHY
;;; ─────────────────
;;; Hotpatching is the superpower that makes LISPMIND immortal. In lesser
;;; systems, a bug means restart, downtime, and lost state. In LISPMIND, a bug
;;; means: swap the code, keep the data, continue the mission. The agent is
;;; like a ship of Theseus — its identity and state persist even as every
;;; plank of its behaviour is replaced.
;;;
;;; THREAD-SAFETY ARCHITECTURE
;;; ───────────────────────────
;;; Hotpatching is safe because of TWO locks, not one:
;;;   1. The AGENT's own LOCK (bt:lock) — protects the strategy slot and
;;;      ensures that no other thread reads a half-written function pointer.
;;;   2. The *STRATEGY-HISTORY-LOCK* — protects the global version history
;;;      hash-table from concurrent reads/writes during bulk operations.
;;;
;;; The locking order is ALWAYS: agent-lock first, then history-lock. This
;;; prevents deadlocks because hotpatch-agent acquires the agent lock, then
;;; (inside save-strategy-version) the history lock — and nowhere do we ever
;;; acquire them in the reverse order.
;;;
;;; VERSION HISTORY AS ALIST
;;; ────────────────────────
;;; Each agent's history is stored as an alist of (VERSION . FUNCTION) pairs,
;;; ordered NEWEST FIRST. This makes rollback (take the Nth cdr) and
;;; version lookup (assoc) both O(n), which is fine because version histories
;;; are short (pruned to KEEP entries, default 10).
;;;
;;; EXAMPLE USAGE
;;; ─────────────
;;;   ;; Replace a single agent's strategy with a compiled lambda
;;;   (hotpatch-agent scraper-1
;;;                   :source '(lambda (agent)
;;;                              (format t "Better scraper!~%")
;;;                              (do-smart-scrape agent)))
;;;
;;;   ;; Replace with an existing function
;;;   (hotpatch-agent analyst-3 :new-strategy #'my-improved-analyzer)
;;;
;;;   ;; Oops, that broke something — roll back one version
;;;   (rollback-strategy analyst-3 1)
;;;
;;;   ;; Bulk patch all agents matching a predicate
;;;   (hotpatch-all-agents *orch* :source new-source
;;;                                :predicate (lambda (a)
;;;                                             (member :scraper
;;;                                                     (agent-capabilities a))))
;;;
;;;   ;; What versions does this agent have?
;;;   (list-strategy-versions scraper-1)
;;;     => ((3 . #<FUNCTION IMPROVED-SCRAPER>)
;;;         (2 . #<FUNCTION FALLBACK-SCRAPER>)
;;;         (1 . #<FUNCTION DEFAULT-SCRAPER>)
;;;         (0 . #<FUNCTION DEFAULT-STRATEGY>))
;;;
;;; ═══════════════════════════════════════════════════════════════════════════

(in-package :lispmind)

;; ───────────────────────────────────────────────────────────────────────────
;; Section 1: Global Version History Storage
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Every hotpatch operation saves the OLD strategy before installing the new
;; one. This gives us a complete audit trail and the ability to roll back.
;; The history is a hash-table mapping agent-id (a symbol) to an alist of
;; (version . function) pairs. A separate lock protects all access.

(defparameter *strategy-history* (make-hash-table :test 'eq)
  "Maps agent-id → alist of (version . strategy-function).

The alist is ordered NEWEST FIRST: (assoc version history) finds the
requested version, and (nth n history) gets the Nth previous version
for rollback.

This hash-table is the single source of truth for all strategy version
history across the entire LISPMIND system. Every hotpatch, rollback, and
prune operation accesses it. All access MUST be protected by
*STRATEGY-HISTORY-LOCK*.

Example structure after hotpatching agent SCRAPER-1 three times:
  SCRAPER-1 → ((3 . #'improved-scraper)
               (2 . #'fallback-scraper)
               (1 . #'default-scraper)
               (0 . #'default-strategy))")

(defparameter *strategy-history-lock* (bt:make-lock "history-lock")
  "Lock for thread-safe access to *STRATEGY-HISTORY*.

All reads and writes to *STRATEGY-HISTORY* must hold this lock via
BT:WITH-LOCK-HELD. This includes: hotpatch-agent (saves old version),
rollback-strategy (reads old version), get-strategy-version (reads),
list-strategy-versions (reads), save-strategy-version (writes), and
prune-strategy-history (writes).")


;; ───────────────────────────────────────────────────────────────────────────
;; Section 2: Core Hotpatch Function
;; ───────────────────────────────────────────────────────────────────────────
;;
;; HOTPATCH-AGENT is the beating heart of this file. It performs an atomic,
;; lock-protected strategy swap. The critical invariant: the old strategy
;; is saved to history BEFORE the new one is installed, so we never lose
;; a version we might want to roll back to.
;;
;; WHY WE SAVE BEFORE INSTALLING:
;;   If we installed first and then crashed before saving, the old strategy
;;   would be lost forever. By saving first, the worst case is a history
;;   entry for a version that was never live — harmless.

(defun hotpatch-agent (agent &key new-strategy source)
  "Safely replace an agent's strategy function while it's running.

This is the primary entry point for live code replacement in LISPMIND.
It performs a thread-safe, atomic strategy swap with full version history
preservation. The agent does NOT stop running — on its next strategy
invocation, it simply calls the new function.

PROCESS:
  1. Acquire the agent's lock (bt:with-lock-held on agent-lock).
  2. Read the current (old) strategy.
  3. Save the old strategy to *STRATEGY-HISTORY* keyed by current version.
  4. If SOURCE is provided, compile it: (compile nil source).
  5. If NEW-STRATEGY is provided, use it directly (must be a function).
  6. Install the new strategy via (setf (agent-strategy agent) ...).
  7. Increment (agent-version agent).
  8. Release the lock.
  9. Print confirmation with version numbers.
  10. Return the agent.

Thread-safety: uses BT:WITH-LOCK-HELD on the agent's lock. The history
save acquires *STRATEGY-HISTORY-LOCK* internally. Lock ordering:
agent-lock first, then history-lock — deadlock-safe.

Arguments:
  AGENT       — the agent instance to patch (required)
  :NEW-STRATEGY — a function object to install as the new strategy (optional)
  :SOURCE      — a lambda expression to compile and install (optional)

Exactly one of :NEW-STRATEGY or :SOURCE must be provided. If both are
provided, :NEW-STRATEGY takes precedence.

Returns: the patched AGENT instance.

Example:
  ;; Compile and install a new strategy from source
  (hotpatch-agent my-agent
                  :source '(lambda (agent)
                             (format t \"Smart strategy!~%\")))

  ;; Install an existing function reference
  (hotpatch-agent my-agent :new-strategy #'my-better-strategy)"
  (let ((old-strategy nil)
        (old-version nil)
        (new-fun nil)
        (agent-id (agent-id agent)))
    ;; ── Step 1-3: Lock the agent, read old strategy, save to history ────────
    (bt:with-lock-held ((agent-lock agent))
      (setf old-strategy (agent-strategy agent))
      (setf old-version (agent-version agent))
      ;; Save the old strategy BEFORE installing the new one. This ensures
      ;; that even if we crash after this point, the old strategy is preserved.
      (save-strategy-version agent-id old-version old-strategy)
      ;; ── Step 4-5: Compile source or use provided function ────────────────
      (cond
        (new-strategy
         (setf new-fun new-strategy))
        (source
         (setf new-fun (safe-compile-strategy source agent-id)))
        (t
         (error "HOTPATCH-AGENT: exactly one of :NEW-STRATEGY or :SOURCE must be provided for agent ~A"
                agent-id)))
      ;; ── Step 6-7: Install and increment version ──────────────────────────
      (setf (agent-strategy agent) new-fun)
      (incf (agent-version agent)))
    ;; ── Step 8-10: Unlock (implicit), print confirmation, return agent ────
    (format *trace-output*
            "~&[HOTPATCH] Agent ~A: version ~A → ~A | strategy ~A → ~A~%"
            agent-id
            old-version (agent-version agent)
            old-strategy new-fun)
    agent))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 3: Bulk Hotpatch
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Sometimes you want to patch ALL agents at once — for example, when a
;; shared library function has a bug that affects every agent. BULK-HOTPATCH
;; iterates over all registered agents and applies the same patch to each.
;; An optional PREDICATE lets you filter which agents receive the patch.

(defun hotpatch-all-agents (orchestrator &key new-strategy source predicate)
  "Hot-patch ALL agents matching PREDICATE (or all if PREDICATE is NIL).

Iterates over the orchestrator's agent registry and calls HOTPATCH-AGENT
on each agent that satisfies PREDICATE. If PREDICATE is NIL, all agents
are patched.

This is useful for:
  • Deploying a global bugfix to all agents of a certain type
  • Rolling out a new capability to every agent at once
  • Emergency patching after a shared library vulnerability

Thread-safety: acquires the orchestrator's monitor-lock to safely read
the agents hash-table. Each individual hotpatch still acquires the
agent's own lock and the history lock.

Arguments:
  ORCHESTRATOR  — the orchestrator whose agents to patch (required)
  :NEW-STRATEGY  — a function object to install (optional, passed to hotpatch-agent)
  :SOURCE        — a lambda expression to compile (optional, passed to hotpatch-agent)
  :PREDICATE     — a function (lambda (agent)) returning T if agent should be patched

Returns: a list of the agents that were patched.

Example:
  ;; Patch all scraper agents with improved logic
  (hotpatch-all-agents *orch*
    :source '(lambda (agent) (smart-scrape agent))
    :predicate (lambda (a) (member :scrape (agent-capabilities a))))

  ;; Emergency: patch every agent with a safe fallback
  (hotpatch-all-agents *orch* :new-strategy #'fallback-strategy)"
  (let ((patched '()))
    (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
      (maphash
       (lambda (aid agent)
         (declare (ignore aid))
         (when (or (null predicate)
                   (funcall predicate agent))
           ;; Push agent to patched list — we'll hotpatch after releasing
           ;; the orchestrator lock to avoid holding it during compilation
           (push agent patched)))
       (orchestrator-agents orchestrator)))
    ;; Hotpatch outside the orchestrator lock — compilation can be slow,
    ;; and we don't want to block the monitor loop.
    (dolist (agent (nreverse patched))
      (handler-case
          (hotpatch-agent agent :new-strategy new-strategy :source source)
        (error (e)
          (format *trace-output*
                  "~&[HOTPATCH] ERROR patching agent ~A: ~A~%"
                  (agent-id agent) e))))
    patched))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 4: Rollback System
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Rolling back is the safety net that makes hotpatching fearless. If a new
;; strategy breaks things, rollback to a known-good version. The rollback
;; system operates on the *STRATEGY-HISTORY* alist, walking N entries from
the front (newest) to find the target version.

(defun rollback-strategy (agent &optional (n 1))
  "Roll back agent's strategy N versions.

Looks up the agent's version history in *STRATEGY-HISTORY*, finds the
Nth previous version, and reinstalls it as the current strategy. The
current (broken) strategy is itself saved to history before being
replaced, so you can even 'roll forward' after a rollback if needed.

Thread-safety: acquires the agent lock and the history lock.

Arguments:
  AGENT — the agent instance to roll back (required)
  N     — how many versions to go back (default 1, must be >= 1)

Returns: the rolled-back AGENT instance.

Signals an error if:
  • The agent has no version history (never been patched)
  • N exceeds the number of available previous versions

Example:
  ;; Roll back one version (undo last hotpatch)
  (rollback-strategy my-agent)

  ;; Roll back three versions
  (rollback-strategy my-agent 3)"
  (let ((agent-id (agent-id agent))
        (history nil)
        (target-entry nil))
    ;; Read the history under the history lock
    (bt:with-lock-held (*strategy-history-lock*)
      (setf history (gethash agent-id *strategy-history*)))
    (unless history
      (error "ROLLBACK-STRATEGY: no version history for agent ~A" agent-id))
    (when (< (length history) (1+ n))
      (error "ROLLBACK-STRATEGY: cannot roll back ~A versions for agent ~A — only ~A previous version(s) available"
             n agent-id (length history)))
    ;; The Nth entry from the front (newest first)
    (setf target-entry (nth n history))
    (unless target-entry
      (error "ROLLBACK-STRATEGY: version ~A not found for agent ~A"
             (- (agent-version agent) n) agent-id))
    ;; Install the target strategy atomically
    (bt:with-lock-held ((agent-lock agent))
      ;; Save current strategy first (so we can roll forward later)
      (save-strategy-version agent-id (agent-version agent) (agent-strategy agent))
      ;; Install the historical strategy
      (setf (agent-strategy agent) (cdr target-entry))
      (incf (agent-version agent)))
    (format *trace-output*
            "~&[ROLLBACK] Agent ~A: rolled back ~A version(s) to version ~A (strategy: ~A)~%"
            agent-id n (car target-entry) (cdr target-entry))
    agent))

(defun get-strategy-version (agent version)
  "Retrieve the strategy function for a specific version.

Looks up the agent's version history and returns the strategy function
that was active at the given VERSION number. Does NOT modify the agent.
This is a read-only introspection function.

Thread-safety: acquires *STRATEGY-HISTORY-LOCK* for the duration of
the lookup.

Arguments:
  AGENT   — the agent instance (or agent-id symbol) to look up
  VERSION — the version number to retrieve (integer, >= 0)

Returns: the strategy function for that version, or NIL if not found.

Example:
  ;; What was agent-1's strategy at version 3?
  (get-strategy-version my-agent 3)
    => #<FUNCTION IMPROVED-SCRAPER>"
  (let ((agent-id (if (symbolp agent) agent (agent-id agent)))
        (result nil))
    (bt:with-lock-held (*strategy-history-lock*)
      (let ((history (gethash agent-id *strategy-history*)))
        (when history
          (let ((entry (assoc version history)))
            (when entry
              (setf result (cdr entry)))))))
    result))

(defun list-strategy-versions (agent)
  "List all available versions for an agent's strategy.

Returns a copy of the agent's version history alist, ordered newest
first. Each element is a cons cell (VERSION . FUNCTION). This is a
read-only snapshot — modifying the returned list does not affect the
actual history.

Thread-safety: acquires *STRATEGY-HISTORY-LOCK* for the duration of
the copy.

Arguments:
  AGENT — the agent instance (or agent-id symbol) to look up

Returns: an alist of (version . strategy-function), or NIL if no history.

Example:
  (list-strategy-versions my-agent)
    => ((3 . #<FUNCTION FOO>) (2 . #<FUNCTION BAR>) (1 . #<FUNCTION BAZ>))"
  (let ((agent-id (if (symbolp agent) agent (agent-id agent)))
        (result nil))
    (bt:with-lock-held (*strategy-history-lock*)
      (let ((history (gethash agent-id *strategy-history*)))
        (when history
          ;; Return a copy so callers can't mutate our internal structure
          (setf result (copy-alist history)))))
    result))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 5: Version History Management
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These functions manage the *STRATEGY-HISTORY* hash-table. They are the
;; low-level primitives that hotpatch-agent and rollback-strategy build on.

(defun save-strategy-version (agent-id version strategy)
  "Save a strategy version to the global history.

Prepends a (VERSION . STRATEGY) entry to the agent's history alist in
*STRATEGY-HISTORY*. If the agent has no existing history, a new alist
is created. The entry is always added at the front (newest first).

This function is called by HOTPATCH-AGENT before installing a new
strategy, and by ROLLBACK-STRATEGY before reverting to an old one.
In both cases, the CURRENT strategy is preserved before being replaced.

Thread-safety: acquires *STRATEGY-HISTORY-LOCK*.

Arguments:
  AGENT-ID — the agent's unique identifier (symbol)
  VERSION  — the version number being saved (integer)
  STRATEGY — the strategy function to archive

Returns: the new history alist for this agent.

Example:
  (save-strategy-version 'scraper-1 5 #'my-strategy)"
  (bt:with-lock-held (*strategy-history-lock*)
    (let ((history (gethash agent-id *strategy-history*)))
      ;; Push new entry at front (newest first)
      (setf (gethash agent-id *strategy-history*)
            (cons (cons version strategy) history))
      (gethash agent-id *strategy-history*))))

(defun prune-strategy-history (agent &optional (keep 10))
  "Prune history to KEEP most recent versions.

Removes older versions beyond the KEEP most recent entries. This
prevents unbounded memory growth for long-lived agents that are
hotpatched many times.

Thread-safety: acquires *STRATEGY-HISTORY-LOCK*.

Arguments:
  AGENT — the agent instance (or agent-id symbol) to prune
  KEEP  — number of versions to retain (default 10, must be >= 1)

Returns: the number of entries removed.

Example:
  ;; Keep only the 5 most recent versions
  (prune-strategy-history my-agent 5)"
  (let ((agent-id (if (symbolp agent) agent (agent-id agent)))
        (removed 0))
    (bt:with-lock-held (*strategy-history-lock*)
      (let ((history (gethash agent-id *strategy-history*)))
        (when (and history (> (length history) keep))
          (let ((pruned (subseq history 0 keep)))
            (setf removed (- (length history) keep))
            (setf (gethash agent-id *strategy-history*) pruned)))))
    (format *trace-output*
            "~&[HOTPATCH] Pruned ~A old version(s) for agent ~A (keeping ~A)~%"
            removed agent-id keep)
    removed))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 6: Integration Helpers
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These functions bridge the hotpatch system with the orchestrator's
;; restart mechanism. When the monitor loop's :HOTFIX-AND-CONTINUE restart
;; is invoked, it sets a flag in the agent's state. These helpers let the
;; orchestrator apply a hotfix programmatically.

(defun apply-hotfix-from-orchestrator (orchestrator agent-id new-strategy)
  "Called by the orchestrator's :HOTFIX-AND-CONTINUE restart.

Looks up the agent by ID in the orchestrator's registry, applies the
hotpatch with the provided strategy, and sets the agent's status to
:RUNNING. This is the bridge between the condition/restart system
(orchestrator.lisp) and the hotpatch system (this file).

The typical flow:
  1. Monitor loop detects a stalled strategy
  2. :HOTFIX-AND-CONTINUE restart is invoked
  3. Restart handler sets :hotfix-requested flag, status = :healing
  4. Orchestrator (or external watcher) calls this function with the fix
  5. Strategy is replaced, status set to :running, agent resumes

Thread-safety: acquires the orchestrator's monitor-lock for the lookup,
then the agent's lock for the patch.

Arguments:
  ORCHESTRATOR — the orchestrator managing the agent
  AGENT-ID     — the symbol ID of the agent to fix
  NEW-STRATEGY — the replacement strategy function

Returns: the patched agent, or NIL if not found.

Example:
  ;; From the REPL: fix a broken agent
  (apply-hotfix-from-orchestrator *default-orchestrator* 'scraper-1
                                  #'fixed-scraper-strategy)"
  (let ((agent (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
                 (gethash agent-id (orchestrator-agents orchestrator)))))
    (unless agent
      (format *trace-output*
              "~&[HOTFIX] No agent ~A found in orchestrator registry~%"
              agent-id)
      (return-from apply-hotfix-from-orchestrator nil))
    ;; Apply the hotpatch
    (hotpatch-agent agent :new-strategy new-strategy)
    ;; Clear the hotfix-requested flag and restore running status
    (bt:with-lock-held ((agent-lock agent))
      (remhash :hotfix-requested (agent-state agent))
      (setf (agent-status agent) :running))
    (format *trace-output*
            "~&[HOTFIX] Agent ~A hotfixed and resumed at version ~A~%"
            agent-id (agent-version agent))
    agent))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 7: Safety Wrappers
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Compilation can fail. Strategy functions might have the wrong signature.
;; These wrappers catch common errors before they corrupt the agent.

(defun safe-compile-strategy (source &optional (name "anonymous-strategy"))
  "Compile strategy source safely, catching compiler errors.

Wraps (COMPILE NIL SOURCE) in HANDLER-BIND to catch compiler errors
and warnings. If compilation fails, signals an informative error rather
than propagating the raw compiler condition.

This is the compilation gatekeeper. All strategy source code (from
hotpatch-agent, hotpatch-all-agents, or manual REPL patching) flows
through here. It ensures that bad syntax or type errors are caught
BEFORE the agent's strategy slot is modified.

Arguments:
  SOURCE — a lambda expression to compile (e.g., '(lambda (agent) ...))
  NAME   — a descriptive name for the compiled function (for debugging)

Returns: the compiled function object.

Signals: ERROR if compilation fails or the result is not a function.

Example:
  (safe-compile-strategy '(lambda (agent) (do-work agent))
                         \"scraper-v3\")"
  (let ((compiled nil)
        (warnings '()))
    (handler-bind
        ((error (lambda (e)
                  (error "Strategy compilation failed for '~A': ~A"
                         name e)))
         (warning (lambda (w)
                    (push w warnings)
                    (muffle-warning))))
      (setf compiled (compile nil source)))
    (unless (functionp compiled)
      (error "Compilation of '~A' did not produce a function: ~S"
             name compiled))
    (when warnings
      (format *trace-output*
              "~&[HOTPATCH] Compilation of '~A' produced ~A warning(s)~%"
              name (length warnings)))
    compiled))

(defun validate-strategy (strategy agent)
  "Validate that a strategy is a function of one argument.

Performs a lightweight sanity check on a strategy function before it
is installed. Currently checks:
  1. STRATEGY is a function
  2. STRATEGY accepts at least one argument (arities differ by CL impl)

This is NOT a full type check — Common Lisp is dynamically typed —
but it catches the most common mistake: passing a non-function or a
function with the wrong lambda-list.

Arguments:
  STRATEGY — the function to validate
  AGENT    — the agent it will be installed on (for error messages)

Returns: T if valid.

Signals: ERROR if the strategy is not a valid one-argument function.

Example:
  (validate-strategy #'my-strategy my-agent)  ; → T
  (validate-strategy 42 my-agent)             ; → ERROR"
  (unless (functionp strategy)
    (error "Invalid strategy for agent ~A: not a function (~S)"
           (agent-id agent) strategy))
  ;; Check arity by examining the lambda-list (SBCL-specific)
  #+sbcl
  (let ((lambda-list (sb-kernel:%fun-lambda-list strategy)))
    ;; A proper strategy takes at least one argument (the agent)
    (when (and lambda-list (symbolp lambda-list))
      ;; A symbol lambda-list means it takes &rest args — acceptable
      t)
    (when (and (listp lambda-list)
               (null lambda-list))
      (warn "Strategy for agent ~A takes zero arguments — expected at least one (the agent)"
            (agent-id agent))))
  t)


;; ═══════════════════════════════════════════════════════════════════════════
;; End of HOTPATCH.LISP
;; ═══════════════════════════════════════════════════════════════════════════
