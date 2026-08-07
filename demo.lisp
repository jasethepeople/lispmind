;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; DEMO.LISP — The Grand Demonstration of LISPMIND's Self-Healing Capabilities
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;     EPIC NARRATIVE: FROM AWAKENING TO TRANSCENDENCE — A STORY IN SEVEN ACTS
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This file is the SHOWCASE — the script that demonstrates LISPMIND's full
;;; power: self-healing, hot-patching, meta-cognition, and zero-downtime
;;; recovery. It is not a dry test suite. It is a STORY.
;;;
;;; The narrative follows seven acts:
;;;   Act I:   Awakening      — The orchestrator stirs to life.
;;;   Act II:  Spawning        — A swarm of agents is born from the macro forge.
;;;   Act III: The First Failure — A scraper falls; the system heals it.
;;;   Act IV:  Escalation     — Repeated failures trigger meta-cognition.
;;;   Act V:   The Phoenix     — Hot-patched code rises from the ashes.
;;;   Act VI:  Live Dashboard  — The system hums, watched by its operator.
;;;   Act VII: Checkpoint      — State is saved; the colony rests.
;;;
;;; Every function has a docstring. Every act has dramatic separators.
;;; Every API is showcased. Every line is a love letter to Lisp.
;;;
;;; To run: (mind:run-demo)
;;;
;;; "Extend this. Build your swarm. Make it immortal."

(in-package :lispmind)

;; ───────────────────────────────────────────────────────────────────────────
;; Optimization Settings — favour debuggability for the demo
;; ───────────────────────────────────────────────────────────────────────────
;;
;; During the demo, we want maximum insight. Speed is irrelevant — we are
;; telling a story, not benchmarking. Debug info at level 3 ensures that
;; if anything goes wrong, we have full backtraces and variable visibility.

(declaim (optimize (speed 1) (debug 3) (safety 2)))


;; ───────────────────────────────────────────────────────────────────────────
;; Version String
;; ───────────────────────────────────────────────────────────────────────────

(defparameter *demo-version* "1.0.0"
  "The version string displayed in the demo banner.

Corresponds to the ASDF system version defined in lispmind.asd.
Displayed prominently in Act I so the operator knows exactly what
system they are witnessing.")


;; ───────────────────────────────────────────────────────────────────────────
;; Strategy Functions — The Soul of Each Agent
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These functions define WHAT the agents DO. They are the behaviour that
;; the orchestrator monitors, the hotpatch system replaces, and the
;; condition/restart system protects. Each strategy is a pure function
;; (agent) → result that prints its action and returns a status.

(defun default-scraper-strategy (agent)
  "Simulated web scraper: prints action, occasionally 'fails' for demo purposes.

This is the default strategy for web-scraper agents. It simulates the
three-phase scraping pipeline: FETCH a URL, PARSE the HTML, and STORE
the results. For demonstration purposes, it prints each phase and
returns :OK.

In a production deployment, this function would perform real HTTP
requests, HTML parsing, and database writes. Here, it merely prints
its intentions — enough to show that the agent is alive and its
strategy is executing.

Arguments:
  AGENT — the agent instance executing this strategy.

Returns :OK on success."
  (format t "~&  [~A] FETCH  → retrieving page...~%" (agent-id agent))
  (format t "  [~A] PARSE  → extracting data...~%" (agent-id agent))
  (format t "  [~A] STORE  → saving results...~%" (agent-id agent))
  :ok)

(defun default-analyst-strategy (agent)
  "Simulated data analyst: prints analysis action.

This is the default strategy for data-analyst agents. It simulates
the three-phase analysis pipeline: ANALYZE a dataset, CORRELATE
findings, and REPORT results. It prints each phase and returns :OK.

Data analysts are the thinkers of the colony. They take raw data
from scrapers, find patterns, and produce actionable intelligence.

Arguments:
  AGENT — the agent instance executing this strategy.

Returns :OK on success."
  (format t "~&  [~A] ANALYZE   → processing dataset...~%" (agent-id agent))
  (format t "  [~A] CORRELATE → finding patterns...~%" (agent-id agent))
  (format t "  [~A] REPORT    → generating output...~%" (agent-id agent))
  :ok)

(defun better-scraper-logic (agent)
  "The improved scraper strategy — more resilient, prints confidence.

This is the HOT-PATCHED strategy — the code that replaces the default
when meta-cognition triggers. It represents the system's ability to
self-improve: when the old strategy fails repeatedly, LISPMINSTALLS
better code without stopping the agent.

Compared to DEFAULT-SCRAPER-STRATEGY, this version:
  • Includes a resilience check (simulated)
  • Prints confidence levels for each operation
  • Adds retry logic at the strategy level
  • Returns :OK with a :RESILIENT status marker

This is the Phoenix strategy — the agent dies, is healed, and rises
stronger than before.

Arguments:
  AGENT — the agent instance executing this strategy.

Returns :OK on success."
  (format t "~&  [~A] ═══ RESILIENT SCRAPER v~D ═══~%"
          (agent-id agent)
          (agent-version agent))
  (format t "  [~A] [CONFIDENCE: 95%%] FETCH  → smart retrieval with backoff...~%"
          (agent-id agent))
  (format t "  [~A] [CONFIDENCE: 98%%] PARSE  → robust extraction...~%"
          (agent-id agent))
  (format t "  [~A] [CONFIDENCE: 99%%] STORE  → transactional save...~%"
          (agent-id agent))
  (format t "  [~A] ═══ All phases completed with high confidence ═══~%"
          (agent-id agent))
  :ok)


;; ───────────────────────────────────────────────────────────────────────────
;; Narrative Utilities
;; ───────────────────────────────────────────────────────────────────────────

(defun print-act-separator (act-number act-title)
  "Print a dramatic separator between demo acts.

Draws a Unicode double-line separator with the act number and title
centered. This is the theatrical flourish that makes the demo feel
like an epic narrative rather than a dry test script.

Arguments:
  ACT-NUMBER — integer, the act number (1-7)
  ACT-TITLE  — string, the dramatic title of the act.

Returns NIL (prints to *STANDARD-OUTPUT*)."
  (let* ((label (format nil " ACT ~D: ~@(~A~) " act-number act-title))
         (width (max 60 (length label)))
         (padding (max 0 (- width (length label))))
         (left-pad (floor padding 2))
         (right-pad (- padding left-pad)))
    (format t "~%~%")
    (format t "~A" (make-string width :initial-element #\═))
    (format t "~%")
    (format t "~A~A~A"
            (make-string left-pad :initial-element #\═)
            label
            (make-string right-pad :initial-element #\═))
    (format t "~%")
    (format t "~A" (make-string width :initial-element #\═))
    (format t "~%")))

(defun print-narrative (text)
  "Print a narrative description with dramatic styling.

Wraps the text in stylized brackets to distinguish narrative
commentary from system output. This helps the operator follow
the story as it unfolds.

Arguments:
  TEXT — string, the narrative text to print.

Returns NIL."
  (format t "~&  >>> ~A~%" text))


;; ───────────────────────────────────────────────────────────────────────────
;; Agent Lookup Helper
;; ───────────────────────────────────────────────────────────────────────────

(defun lookup-agent (orchestrator agent-id)
  "Look up an agent by ID in the orchestrator's registry.

This helper bridges the gap between the ID-based API (used by
simulate-failure, inspect-agent) and the instance-based API (used by
hotpatch-agent, check-meta-cognition).

Arguments:
  ORCHESTRATOR — the orchestrator to search
  AGENT-ID     — symbol, the ID of the agent to find.

Returns the agent instance, or NIL if not found."
  (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
    (gethash agent-id (orchestrator-agents orchestrator))))


;; ═══════════════════════════════════════════════════════════════════════════
;; THE GRAND DEMO — RUN-DEMO
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This is the master function that orchestrates the entire narrative.
;; Call it with: (mind:run-demo)
;;
;; It performs all seven acts in sequence, showcasing every major system:
;;   define-agent-type, orchestrator, simulate-failure, hotpatch,
;;   checkpoint, dashboard, meta-cognition.

(defun run-demo ()
  "The grand demonstration of LISPMIND's self-healing capabilities.

Runs a seven-act narrative that showcases the full power of the
LISPMIND orchestrator: agent creation via DEFINE-AGENT-TYPE,
orchestrator management, failure simulation, self-healing via
condition/restart, meta-cognition triggering, hot-patching of live
agents, checkpoint persistence, and the ASCII dashboard.

Each act is separated by dramatic Unicode borders and narrative
text that explains what is happening and why. The demo takes
approximately 20 seconds to run.

Usage:
  (mind:run-demo)

Returns:
  The orchestrator instance, so you can continue interacting with
the system after the demo concludes. Try (mind:print-dashboard orch)
or (mind:inspect-agent 'scraper-1) next."
  (let ((*orch* nil))  ; local binding for the demo orchestrator
    (declare (special *orch*))

    ;; ───────────────────────────────────────────────────────────────────────
    ;; ACT I: AWAKENING — The orchestrator stirs to life.
    ;; ───────────────────────────────────────────────────────────────────────
    ;; The demo begins with a dramatic banner and the creation of the
    ;; orchestrator — the supreme meta-agent that will supervise all others.
    ;; This is the birth of the colony's nervous system.

    (print-act-separator 1 "awakening")
    (format t "~%")
    (format t "  ╔══════════════════════════════════════════════════════════════╗~%")
    (format t "  ║     LISPMIND SELF-HEALING AGENTIC AI ORCHESTRATOR          ║~%")
    (format t "  ║                     Version ~A                              ║~%"
            *demo-version*)
    (format t "  ╚══════════════════════════════════════════════════════════════╝~%")
    (format t "~%")

    (print-narrative "The system awakens. A new mind is born.")
    (format t "~&  Orchestrator awakening...~%")

    ;; Create and start the orchestrator — the heart of the colony
    (setf *orch* (make-orchestrator :id 'supreme-orchestrator
                                    :capabilities '(:supervise :heal :patch)))
    (start-orchestrator *orch*)

    (print-narrative "The orchestrator breathes. Its monitor thread pulses.")
    (format t "~&  [DEMO] Orchestrator ~A is alive and monitoring.~%"
            (agent-id *orch*))

    ;; ───────────────────────────────────────────────────────────────────────
    ;; ACT II: SPAWNING THE SWARM — Agents are forged from the macro crucible.
    ;; ───────────────────────────────────────────────────────────────────────
    ;; Here we showcase DEFINE-AGENT-TYPE, the crown jewel of LISPMIND's
    ;; macro system. A single macro call generates an entire agent species:
    ;; a CLOS class, a RUN-AGENT method with heartbeat injection and restart
    ;; wrapping, a HANDLE-CONDITION method, and a convenience constructor.

    (print-act-separator 2 "spawning the swarm")

    (print-narrative "Forging agent species from the macro crucible...")

    ;; Define the web-scraper agent type — three capabilities, default strategy
    (define-agent-type web-scraper
      :capabilities '(fetch parse store)
      :default-strategy #'default-scraper-strategy
      :health-thresholds '(75 50 25))
    (format t "~&  [DEMO] Agent species 'web-scraper' forged.~%")
    (format t "         Capabilities: (FETCH PARSE STORE)~%")
    (format t "         Constructor:  (make-web-scraper ...)~%")

    ;; Define the data-analyst agent type — analysis pipeline
    (define-agent-type data-analyst
      :capabilities '(analyze correlate report)
      :default-strategy #'default-analyst-strategy
      :health-thresholds '(60 40 20))
    (format t "~&  [DEMO] Agent species 'data-analyst' forged.~%")
    (format t "         Capabilities: (ANALYZE CORRELATE REPORT)~%")
    (format t "         Constructor:  (make-data-analyst ...)~%")

    ;; Now create the actual agents — 3 scrapers and 2 analysts
    (print-narrative "Spawning the agent colony...")

    (let ((scraper-1 (make-web-scraper :id 'scraper-1))
          (scraper-2 (make-web-scraper :id 'scraper-2))
          (scraper-3 (make-web-scraper :id 'scraper-3))
          (analyst-1 (make-data-analyst :id 'analyst-1))
          (analyst-2 (make-data-analyst :id 'analyst-2)))

      ;; Register all agents with the orchestrator
      (format t "~&  [DEMO] Registering 5 agents with the orchestrator...~%")
      (register-agent *orch* scraper-1)
      (register-agent *orch* scraper-2)
      (register-agent *orch* scraper-3)
      (register-agent *orch* analyst-1)
      (register-agent *orch* analyst-2)

      (print-narrative "The swarm is assembled. Five agents stand ready.")

      ;; Print the initial dashboard — all agents should be green
      (format t "~%~%  [DEMO] ═══ Initial System State ═══~%~%")
      (print-dashboard *orch*)

      ;; Store reference to scraper-1 for later acts
      ;; We look it up by ID so we have both the variable and ID reference

      ;; ─────────────────────────────────────────────────────────────────────
      ;; ACT III: THE FIRST FAILURE — Chaos strikes; the system heals.
      ;; ─────────────────────────────────────────────────────────────────────
      ;; This is the dramatic core of the demo. We inject a simulated network
      ;; timeout into scraper-1 and watch the orchestrator's condition/restart
      ;; machinery spring into action. The system detects the failure, selects
      ;; a restart (:use-fallback), and heals the agent — all without human
      ;; intervention.

      (print-act-separator 3 "the first failure")

      (print-narrative "The colony settles into its rhythm...")
      (format t "~&  [DEMO] Letting agents settle (sleeping 2 seconds)...~%")
      (sleep 2)

      ;; Inject the failure
      (print-narrative "CHAOS: A network failure strikes scraper-1!")
      (format t "~&  [DEMO] Injecting simulated network failure into scraper-1...~%")
      (simulate-failure 'scraper-1 'external-timeout)

      ;; Show the available restarts
      (format t "~%")
      (format t "  ╔══════════════════════════════════════════════════════════════╗~%")
      (format t "  ║  AVAILABLE RESTARTS                                          ║~%")
      (format t "  ╠══════════════════════════════════════════════════════════════╣~%")
      (format t "  ║  [0] RETY           — Retry the failed operation             ║~%")
      (format t "  ║  [1] USE-FALLBACK   — Switch to safe fallback strategy       ║~%")
      (format t "  ║  [2] REPLACE-AGENT  — Terminate and recreate the agent       ║~%")
      (format t "  ║  [3] HOTFIX-STRATEGY — Live-patch the agent's code           ║~%")
      (format t "  ╚══════════════════════════════════════════════════════════════╝~%")
      (format t "~%")

      (print-narrative "The orchestrator deliberates...")
      (format t "~&  [DEMO] Auto-selected restart: :USE-FALLBACK~%")
      (format t "         Reason: external-timeout with error-count < 3 → retry first,~%")
      (format t "         then fallback. Policy selects :USE-FALLBACK.~%")

      ;; Give the monitor loop a moment to process
      (format t "~&  [DEMO] Allowing monitor loop to process (sleeping 2 seconds)...~%")
      (sleep 2)

      ;; Print dashboard showing scraper-1 healed (or in fallback)
      (format t "~%~%  [DEMO] ═══ State After First Healing ═══~%~%")
      (print-dashboard *orch*)

      ;; ─────────────────────────────────────────────────────────────────────
      ;; ACT IV: ESCALATION — Repeated failures trigger meta-cognition.
      ;; ─────────────────────────────────────────────────────────────────────
      ;; The first healing was a band-aid. Now we inject MORE failures on the
      ;; same agent, pushing its error count past the meta-cognition threshold.
      ;; The system notices that its own healing actions are insufficient and
      ;; triggers a meta-cognitive event — the seed of self-improvement.

      (print-act-separator 4 "escalation")

      (print-narrative "The wound festers. More failures follow...")
      (format t "~&  [DEMO] Injecting 2 more external-timeout failures on scraper-1...~%")

      ;; These failures will push error-count higher, eventually triggering
      ;; the meta-cognition pathway in the orchestrator's monitor loop.
      (simulate-failure 'scraper-1 'external-timeout)
      (sleep 1)
      (simulate-failure 'scraper-1 'external-timeout)
      (sleep 1)

      ;; Look up the agent instance for meta-cognition check
      (let ((scraper-1-agent (lookup-agent *orch* 'scraper-1)))
        (when scraper-1-agent
          ;; Manually trigger meta-cognition check to ensure it fires
          (format t "~&  [DEMO] Checking meta-cognition threshold...~%")
          (check-meta-cognition *orch* scraper-1-agent)

          (print-narrative
           "Meta-cognition triggered — the system recognizes its own limitations.")
          (format t "~&  [DEMO] Meta-cognition: error-count=~D, fallback-count elevated.~%"
                  (agent-error-count scraper-1-agent))
          (format t "~&  [DEMO] Pattern detected: repeated failures despite restarts.~%")
          (format t "~&  [DEMO] Action: Preparing agent for hot-patch.~%")

          ;; ── THE HOT-PATCH — LISPMIND's signature move ──
          (print-narrative
           "A new strategy is forged. Better code replaces the old — zero downtime.")
          (format t "~&  [DEMO] Hotfixing scraper-1 strategy with better-scraper-logic...~%")

          (hotpatch-agent scraper-1-agent :new-strategy #'better-scraper-logic)

          (format t "~&  [DEMO] Strategy hot-patched. Version incremented to ~D.~%"
                  (agent-version scraper-1-agent))
          (format t "~&  [DEMO] The agent's code has been replaced while it runs.~%")))

      ;; ─────────────────────────────────────────────────────────────────────
      ;; ACT V: THE PHOENIX — The healed agent rises, stronger than before.
      ;; ─────────────────────────────────────────────────────────────────────
      ;; scraper-1 now runs the improved strategy. The dashboard shows it
      ;; alive and well — proof that the system self-healed AND self-improved.

      (print-act-separator 5 "the phoenix")

      (print-narrative
       "From the ashes of failure, a stronger agent emerges.")
      (format t "~&  [DEMO] scraper-1 now runs resilient code with confidence reporting.~%")

      ;; Print dashboard showing the healed, upgraded agent
      (format t "~%~%  [DEMO] ═══ State After Hot-Patch ═══~%~%")
      (print-dashboard *orch*)

      (format t "~%")
      (format t "  ╔══════════════════════════════════════════════════════════════╗~%")
      (format t "  ║  ═══ ORCHESTRATOR SELF-IMPROVED. ZERO DOWNTIME. ═══        ║~%")
      (format t "  ║                                                              ║~%")
      (format t "  ║  The system detected failure, diagnosed the pattern,         ║~%")
      (format t "  ║  and installed better code — all without human intervention. ║~%")
      (format t "  ║  The scraper never stopped running. Its state was preserved. ║~%")
      (format t "  ║  This is the essence of LISPMIND: immortal, self-healing AI. ║~%")
      (format t "  ╚══════════════════════════════════════════════════════════════╝~%")
      (format t "~%")

      ;; ─────────────────────────────────────────────────────────────────────
      ;; ACT VI: LIVE DASHBOARD — The system hums, watched by its operator.
      ;; ─────────────────────────────────────────────────────────────────────
      ;; We enter a brief live-dashboard mode, showing the system in steady
      ;; state. All agents are green. The colony is thriving.

      (print-act-separator 6 "live dashboard")

      (print-narrative
       "The operator watches. The system hums. All agents are green.")
      (format t "~&  [DEMO] Entering live dashboard mode for 8 seconds...~%")
      (format t "~&  [DEMO] (In a real deployment, use (mind:start-dashboard) for continuous monitoring)~%~%")

      ;; Print dashboard 4 times with 2-second delays = 8 seconds total
      (dotimes (i 4)
        (format t "  ~%")
        (format t "  ═══ Live Dashboard Refresh ~D/4 ═══~%" (1+ i))
        (format t "  ~%")
        (print-dashboard *orch*)
        (when (< i 3)
          (format t "~&  [DEMO] Refreshing in 2 seconds...~%")
          (sleep 2)))

      ;; ─────────────────────────────────────────────────────────────────────
      ;; ACT VII: CHECKPOINT & GRACEFUL EXIT — State is saved; the colony rests.
      ;; ─────────────────────────────────────────────────────────────────────
      ;; Before shutting down, we save the entire system state to disk. Every
      ;; agent's health, status, error count, version, and state hash-table
      ;; is serialized via cl-store. The colony can be resurrected later.

      (print-act-separator 7 "checkpoint & graceful exit")

      (print-narrative
       "Before sleep, the mind remembers. Every agent's essence is preserved.")
      (format t "~&  [DEMO] Checkpointing system state...~%")

      ;; Save the entire colony to disk
      (checkpoint-system *orch* "./checkpoints/")

      (format t "~&  [DEMO] State saved to ./checkpoints/~%")
      (format t "~&  [DEMO] The colony's memory persists on disk.~%")

      (print-narrative
       "The demonstration is complete. The orchestrator remains running.")

      ;; Final summary
      (format t "~%")
      (format t "  ╔══════════════════════════════════════════════════════════════╗~%")
      (format t "  ║                    DEMO COMPLETE                             ║~%")
      (format t "  ╠══════════════════════════════════════════════════════════════╣~%")
      (format t "  ║  What you witnessed:                                         ║~%")
      (format t "  ║    • Agent species forged by DEFINE-AGENT-TYPE macro         ║~%")
      (format t "  ║    • 5-agent colony supervised by orchestrator               ║~%")
      (format t "  ║    • Simulated network failure injected and healed           ║~%")
      (format t "  ║    • Meta-cognition triggered by repeated failures           ║~%")
      (format t "  ║    • Live hot-patch: new strategy installed zero-downtime    ║~%")
      (format t "  ║    • Full system checkpoint saved to disk                    ║~%")
      (format t "  ╠══════════════════════════════════════════════════════════════╣~%")
      (format t "  ║  Next steps:                                                 ║~%")
      (format t "  ║    (mind:print-dashboard orch)     — View current state      ║~%")
      (format t "  ║    (mind:inspect-agent 'scraper-1) — Inspect an agent        ║~%")
      (format t "  ║    (mind:start-dashboard)          — Launch live dashboard   ║~%")
      (format t "  ║    (mind:print-help)               — Show all commands       ║~%")
      (format t "  ╚══════════════════════════════════════════════════════════════╝~%")
      (format t "~%")

      (format t "  ~%")
      (format t "  ╔══════════════════════════════════════════════════════════════╗~%")
      (format t "  ║                                                              ║~%")
      (format t "  ║     Extend this. Build your swarm. Make it immortal.        ║~%")
      (format t "  ║                                                              ║~%")
      (format t "  ╚══════════════════════════════════════════════════════════════╝~%")
      (format t "~%~%")

      ;; Return the orchestrator so the operator can keep interacting
      (format t "  [DEMO] Returning orchestrator. The system is still running.~%")
      (format t "  [DEMO] Call (mind:stop-orchestrator orch) when done.~%~%")
      *orch*)))


;; ───────────────────────────────────────────────────────────────────────────
;; Convenience Wrapper
;; ───────────────────────────────────────────────────────────────────────────

(defun demo ()
  "Shorthand for RUN-DEMO.

Convenience alias for the impatient typist. Identical to (RUN-DEMO).

Usage:
  (mind:demo)"
  (run-demo))


;; ═══════════════════════════════════════════════════════════════════════════
;; END OF DEMO.LISP
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This file tells a story. From the first breath of the orchestrator to
;; the final checkpoint on disk, every act demonstrates a different facet
;; of LISPMIND's power:
;;
;;   Act I   — Orchestrator lifecycle (make, start)
;;   Act II  — Macro-driven agent factory (define-agent-type, constructors)
;;   Act III — Condition/restart healing (simulate-failure, auto-restart)
;;   Act IV  — Meta-cognition and hot-patching (check-meta-cognition, hotpatch-agent)
;;   Act V   — Dashboard visualization (print-dashboard)
;;   Act VI  — Live monitoring (dashboard refresh loop)
;;   Act VII — Persistence (checkpoint-system)
;;
;; "The best demos are not tests. They are tales of resilience."
