;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; DASHBOARD.LISP — REPL Dashboard & Interactive Commands for LISPMIND
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;                    THE GOD-MODE INTERFACE
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This file provides the entire REPL-based dashboard experience — the
;;; "God Mode" interface for controlling and observing the LISPMIND
;;; orchestrator. Every function is designed for the human operator sitting
;;; at the SBCL REPL, watching their agent colony live, breathe, and heal.
;;;
;;; DESIGN PHILOSOPHY
;;; ─────────────────
;;; The dashboard is not a separate GUI or web app. It is pure Common Lisp
;;; at the REPL — because on an air-gapped Kali system, the REPL *is* the
;;; interface. We use Unicode box-drawing characters for visual structure,
;;; ANSI color codes for health status, and real-time thread-based updates
;;; to create a living display that feels like a cockpit.
;;;
;;; The dashboard has two modes:
;;;   1. STATIC  — Call (mind:print-dashboard) for a one-shot snapshot.
;;;   2. LIVE    — Call (mind:start-dashboard) for a 2-second refresh loop.
;;;
;;; All dashboard operations are thread-safe. The dashboard thread only
;;; reads agent state (never writes), and it acquires no locks — reads of
;;; the slots it accesses (id, health, status, error-count, heartbeat) are
;;; atomic on SBCL for standard objects.
;;;
;;; UNICODE BOX-DRAWING LEGEND
;;; ───────────────────────────
;;;   ╔ ═ ╗  ╠ ═ ╣  ╠ ╬ ╣  ╚ ╩ ╝  ║
;;;   TL──TR  L══R   L═╬R  BL──BR  V
;;;   (top    (left   (cross  (bottom (vertical)
;;;    line    T       cross)  line)
;;;    with
;;;    corners)
;;;
;;; ANSI COLOR CODES (degrade gracefully on non-ANSI terminals)
;;; ────────────────────────────────────────────────────────────
;;;   ESC[32m  Green   — health 100 (perfect)
;;;   ESC[33m  Yellow  — health 75-99 (caution)
;;;   ESC[38;5;208m Orange — health 50-74 (warning)
;;;   ESC[31m  Red     — health < 50 (critical)
;;;   ESC[0m   Reset   — normal text
;;;
;;; "The REPL is not a debugger. It is the control panel of a living system."

(in-package :lispmind)

;; ───────────────────────────────────────────────────────────────────────────
;; Section 1: Dashboard Control Flags
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These special variables control the dashboard thread lifecycle and
;; display options. They are dynamically bound where appropriate and
;; are thread-safe for the single-dashboard-thread design.

(defparameter *dashboard-running-p* nil
  "Thread-local flag controlling the dashboard refresh loop.

When START-DASHBOARD sets this to T, the DASHBOARD-LOOP runs. When
STOP-DASHBOARD sets it to NIL, the loop exits gracefully after the
current sleep cycle completes.

This is a simple flag rather than a condition variable because the
dashboard thread sleeps on a fixed 2-second interval. The stop
latency is at most 2 seconds, which is acceptable for a display.")

(defparameter *dashboard-use-unicode-p* t
  "When T, use Unicode box-drawing characters for the dashboard.
When NIL, fall back to plain ASCII (+, -, |) for maximum terminal
compatibility. Set to NIL if your terminal cannot display Unicode.")

(defparameter *dashboard-use-color-p* t
  "When T, use ANSI color codes for health status highlighting.
When NIL, display health as plain numbers. Automatically disabled
if *STANDARD-OUTPUT* is not a terminal with color support.")


;; ───────────────────────────────────────────────────────────────────────────
;; Section 2: Unicode/ASCII Character Set
;; ───────────────────────────────────────────────────────────────────────────
;;
;; A dispatch table that selects the right characters based on the
;; Unicode preference flag. This keeps the rendering code clean —
;; it just calls these accessors and gets the right glyphs.

(defun dash-char ()
  "Return the horizontal line character (═ or =)."
  (if *dashboard-use-unicode-p* "═" "="))

(defun vert-char ()
  "Return the vertical line character (║ or |)."
  (if *dashboard-use-unicode-p* "║" "|"))

(defun tl-corner ()
  "Return the top-left corner character."
  (if *dashboard-use-unicode-p* "╔" "+"))

(defun tr-corner ()
  "Return the top-right corner character."
  (if *dashboard-use-unicode-p* "╗" "+"))

(defun bl-corner ()
  "Return the bottom-left corner character."
  (if *dashboard-use-unicode-p* "╚" "+"))

(defun br-corner ()
  "Return the bottom-right corner character."
  (if *dashboard-use-unicode-p* "╝" "+"))

(defun t-junction ()
  "Return a T-junction connecting from below (╦ or +)."
  (if *dashboard-use-unicode-p* "╦" "+"))

(defun b-junction ()
  "Return an inverted T-junction (╩ or +)."
  (if *dashboard-use-unicode-p* "╩" "+"))

(defun l-junction ()
  "Return a left T-junction (╠ or +)."
  (if *dashboard-use-unicode-p* "╠" "+"))

(defun r-junction ()
  "Return a right T-junction (╣ or +)."
  (if *dashboard-use-unicode-p* "╣" "+"))

(defun cross-junction ()
  "Return a cross junction (╬ or +)."
  (if *dashboard-use-unicode-p* "╬" "+"))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 3: ANSI Color Utilities
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Lightweight color formatting that degrades gracefully on terminals
;; without color support. The ESC character prefix follows the ANSI
;; escape sequence standard (ISO/IEC 6429).

(defun ansi-color (code)
  "Return an ANSI escape sequence string for the given color CODE.

CODE is an integer or a cons of (attribute ; color-code) for 256-color
mode. Returns the empty string if *DASHBOARD-USE-COLOR-P* is NIL.

Examples:
  (ansi-color 32)           → \"\e[32m\"   (green)
  (ansi-color '(38 5 208))  → \"\e[38;5;208m\" (orange)"
  (if *dashboard-use-color-p*
      (if (consp code)
          (format nil "~C[~{~A~^;~}m" #\Escape code)
          (format nil "~C[~Am" #\Escape code))
      ""))

(defun ansi-reset ()
  "Return the ANSI reset escape sequence, or empty string if color disabled."
  (if *dashboard-use-color-p*
      (format nil "~C[0m" #\Escape)
      ""))

(defun health-color (health)
  "Return an ANSI color escape string appropriate for a HEALTH value.

Color mapping:
  HEALTH = 100        → green  (ESC[32m)
  75 <= HEALTH < 100  → yellow (ESC[33m)
  50 <= HEALTH < 75   → orange (ESC[38;5;208m)
  HEALTH < 50         → red    (ESC[31m)

Returns the empty string if *DASHBOARD-USE-COLOR-P* is NIL."
  (cond ((= health 100) (ansi-color 32))     ; green: perfect
        ((>= health 75) (ansi-color 33))     ; yellow: caution
        ((>= health 50) (ansi-color '(38 5 208)))  ; orange: warning
        (t (ansi-color 31))))                ; red: critical


;; ───────────────────────────────────────────────────────────────────────────
;; Section 4: Terminal Control
;; ───────────────────────────────────────────────────────────────────────────

(defun clear-screen ()
  "Clear the terminal screen using ANSI escape codes.

Sends the \"clear screen and move cursor to home position\" sequence
(ESC[2J ESC[H). This is faster and more reliable than spawning an
external 'clear' process. Has no effect if *STANDARD-OUTPUT* is not
a terminal."
  (format t "~C[2J~C[H" #\Escape #\Escape)
  (force-output))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 5: Time Formatting Utilities
;; ───────────────────────────────────────────────────────────────────────────

(defun format-time-ago (timestamp)
  "Format a LOCAL-TIME:TIMESTAMP as a human-readable relative time string.

Calculates the difference between now and TIMESTAMP, returning strings
like 'just now', '2s ago', '1m ago', '5m ago', '1h ago', etc.

Arguments:
  TIMESTAMP — a LOCAL-TIME:TIMESTAMP instance (e.g., from AGENT-HEARTBEAT).

Returns a string suitable for display in the dashboard heartbeat column.

Examples:
  (format-time-ago (local-time:now))                    → \"just now\"
  (format-time-ago (local-time:timestamp- (now) 5 :sec)) → \"5s ago\""
  (let* ((now (local-time:now))
         (diff-sec (max 0 (floor (local-time:timestamp-difference now timestamp)))))
    (cond ((< diff-sec 2)   "just now")
          ((< diff-sec 60)  (format nil "~As ago" diff-sec))
          ((< diff-sec 120) "1m ago")
          ((< diff-sec 3600)
           (format nil "~Am ago" (floor diff-sec 60)))
          ((< diff-sec 7200) "1h ago")
          (t (format nil "~Ah ago" (floor diff-sec 3600))))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 6: Visual Health Bar
;; ───────────────────────────────────────────────────────────────────────────

(defun health-bar (health &optional (width 20))
  "Create a visual health bar string showing proportional fill.

Returns a string like '[████████░░░░░░░░░░░░] 100%' where the number
of filled blocks represents the health percentage. Uses Unicode full
block (█) and light shade (░) characters for visual clarity.

Arguments:
  HEALTH — integer from 0 to 100 representing health percentage.
  WIDTH  — number of bar segments (default 20). Each segment is ~5%.

Returns a string of the form '[<filled><empty>] <percent>%'.

Example:
  (health-bar 100)   → \"[████████████████████] 100%\"
  (health-bar 50)    → \"[██████████░░░░░░░░░░]  50%\"
  (health-bar 0)     → \"[░░░░░░░░░░░░░░░░░░░░]   0%\""
  (let ((filled (floor (* health width) 100))
        (empty (- width (floor (* health width) 100))))
    (format nil "[~A~A] ~3D%"
            (make-string filled :initial-element #\Full_Block)
            (make-string empty  :initial-element #\Light_Shade)
            health)))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 7: Dashboard Header & Footer
;; ───────────────────────────────────────────────────────────────────────────

(defun print-dashboard-header ()
  "Print the dashboard title banner with version information.

Displays a centered title in a Unicode box:
  ╔══════════════════════════════════════════════════════════════════════╗
  ║                 LISPMIND — AGENT ORCHESTRATOR v1.0.0               ║
  ╚══════════════════════════════════════════════════════════════════════╝

The title width is 70 characters. Color is applied to the version
number in green when color is enabled."
  (let* ((title "LISPMIND — AGENT ORCHESTRATOR v1.0.0")
         (inner-width 70)
         (padding (max 0 (floor (- inner-width (length title)) 2)))
         (left-pad (make-string padding :initial-element #\Space))
         (right-pad (make-string (max 0 (- inner-width (length title) padding))
                                 :initial-element #\Space)))
    (format t "~&~A~A~A~A~A~%"
            (tl-corner) (make-string inner-width :initial-element (aref (dash-char) 0))
            (tr-corner))
    (format t "~A~A~A~A~A~A~A~%"
            (vert-char) left-pad
            (ansi-color 36) title (ansi-reset)
            right-pad (vert-char))
    (format t "~A~A~A~A~A~%"
            (l-junction) (make-string inner-width :initial-element (aref (dash-char) 0))
            (r-junction))))

(defun print-dashboard-footer ()
  "Print help text showing available REPL commands at the bottom of the dashboard.

Displays a compact command reference so the operator never needs to
remember the full API. The footer is separated from the agent table
by a horizontal rule.

Example output:
  ╔══════════════════════════════════════════════════════════════════════╗
  ║  Commands: (mind:list-agents)  (mind:inspect-agent 'id)            ║
  ║  (mind:start-dashboard)  (mind:stop-dashboard)  (mind:run-demo)    ║
  ╚══════════════════════════════════════════════════════════════════════╝"
  (let* ((inner-width 70)
         (commands "Commands: (list-agents) (inspect-agent 'id) (start-dashboard) (run-demo)"))
    (format t "~&~A~A~A~%"
            (l-junction) (make-string inner-width :initial-element (aref (dash-char) 0))
            (r-junction))
    (format t "~A ~A~A~A ~A~%"
            (vert-char)
            (ansi-color 36) commands (ansi-reset)
            (make-string (max 0 (- inner-width (length commands) 1))
                         :initial-element #\Space)
            (vert-char))
    (format t "~A~A~A~%"
            (bl-corner) (make-string inner-width :initial-element (aref (dash-char) 0))
            (br-corner))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 8: Core Dashboard — The Agent Table
;; ───────────────────────────────────────────────────────────────────────────
;;
;; This is the visual centerpiece of LISPMIND: a beautiful ASCII table
;; showing every registered agent, its vital signs, and its last heartbeat.
;;
;; Example output:
;; ╔══════════════════════════════════════════════════════════════════════╗
;; ║                 LISPMIND — AGENT ORCHESTRATOR v1.0.0               ║
;; ╠═════════════════╦════════╦════════════╦═════════════╦══════════════╣
;; ║   Agent ID      ║ Health ║   Status   ║ Error Count ║  Heartbeat   ║
;; ╠═════════════════╬════════╬════════════╬═════════════╬══════════════╣
;; ║ SCRAPER-1234    ║  100   ║ :running   ║      0      ║   2s ago     ║
;; ║ ANALYST-5678    ║   85   ║ :running   ║      2      ║   5s ago     ║
;; ╚═════════════════╩════════╩════════════╩═════════════╩══════════════╝

(defun print-dashboard (orchestrator)
  "Print a beautiful ASCII table showing all registered agents.

This is the static snapshot function — call it anytime for a current
view of the orchestrator's agent registry. For a live updating display,
use START-DASHBOARD instead.

The table shows: Agent ID, Health (with color coding), Status, Error
Count, and Heartbeat age. Agents are sorted by ID for stable display.

Health color coding (ANSI):
  100   → green   (perfect health)
  75-99 → yellow  (minor issues)
  50-74 → orange  (significant degradation)
  <50   → red     (critical — healing needed)

Arguments:
  ORCHESTRATOR — the orchestrator instance to display (defaults to
                 *DEFAULT-ORCHESTRATOR* via START-DASHBOARD).

Returns:
  The number of agents displayed (as a secondary value, prints to *STANDARD-OUTPUT*)."
  (let ((agents '()))
    ;; Collect all agents from the registry
    (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
      (maphash (lambda (id agent)
                 (declare (ignore id))
                 (push agent agents))
               (orchestrator-agents orchestrator)))
    ;; Sort by agent-id for stable display
    (setf agents (sort agents #'string< :key (lambda (a) (symbol-name (agent-id a)))))
    ;; Print the dashboard
    (print-dashboard-header)
    (print-dashboard-column-headers)
    (print-dashboard-separator-line)
    (if (null agents)
        (print-dashboard-empty-row)
        (dolist (agent agents)
          (print-dashboard-agent-row agent)))
    (print-dashboard-bottom-line)
    (print-dashboard-footer)
    (values (length agents))))

(defun print-dashboard-column-headers ()
  "Print the column header row for the agent table.

Columns: Agent ID (16), Health (8), Status (12), Error Count (13), Heartbeat (14)."
  (format t "~A ~16A ~A ~8A ~A ~12A ~A ~13A ~A ~14A ~A~%"
          (vert-char) "Agent ID"
          (vert-char) "Health"
          (vert-char) "Status"
          (vert-char) "Error Count"
          (vert-char) "Heartbeat"
          (vert-char)))

(defun print-dashboard-separator-line ()
  "Print a horizontal separator line between header and data rows."
  (format t "~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~A~%"
          (l-junction)
          (make-string 16 :initial-element (aref (dash-char) 0))
          (cross-junction)
          (make-string 8 :initial-element (aref (dash-char) 0))
          (cross-junction)
          (make-string 12 :initial-element (aref (dash-char) 0))
          (cross-junction)
          (make-string 13 :initial-element (aref (dash-char) 0))
          (cross-junction)
          (make-string 14 :initial-element (aref (dash-char) 0))
          (r-junction)))

(defun print-dashboard-bottom-line ()
  "Print the bottom border line of the agent table."
  (format t "~A~A~A~A~A~A~A~A~A~A~A~%"
          (bl-corner)
          (make-string 16 :initial-element (aref (dash-char) 0))
          (b-junction)
          (make-string 8 :initial-element (aref (dash-char) 0))
          (b-junction)
          (make-string 12 :initial-element (aref (dash-char) 0))
          (b-junction)
          (make-string 13 :initial-element (aref (dash-char) 0))
          (b-junction)
          (make-string 14 :initial-element (aref (dash-char) 0))
          (br-corner)))

(defun print-dashboard-empty-row ()
  "Print a row indicating no agents are registered."
  (format t "~A ~68A ~A~%"
          (vert-char)
          "  [No agents registered — use (register-agent orch (make-agent))]"
          (vert-char)))

(defun print-dashboard-agent-row (agent)
  "Print a single agent's data row in the dashboard table.

Applies ANSI color to the health value based on thresholds. Formats
the heartbeat as a relative time string ('2s ago', 'just now')."
  (let ((id-str (symbol-name (agent-id agent)))
        (health (agent-health agent))
        (status (agent-status agent))
        (errors (agent-error-count agent))
        (heartbeat-str (format-time-ago (agent-heartbeat agent))))
    (format t "~A ~16A ~A ~A~4D~A ~A ~12A ~A ~13D ~A ~14A ~A~%"
            (vert-char) id-str
            (vert-char) (health-color health) health (ansi-reset)
            (vert-char) status
            (vert-char) errors
            (vert-char) heartbeat-str
            (vert-char))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 9: Agent Introspection
;; ───────────────────────────────────────────────────────────────────────────

;; NOTE: INSPECT-AGENT and LIST-AGENTS are defined in orchestrator.lisp
;; and provide the canonical implementations. The dashboard enhances them
;; through method specializations on notify-health-change and
;; notify-status-change, plus the print-dashboard function below.


;; ───────────────────────────────────────────────────────────────────────────
;; Section 11: Failure Simulation
;; ───────────────────────────────────────────────────────────────────────────
;;
;; This function injects synthetic conditions into the system for testing
;; and demonstration purposes. It is the primary tool for showing that
;; the self-healing machinery actually works.

(defun simulate-failure (agent-id condition-type)
  "Simulate a failure on an agent for testing and demonstration.

Looks up the agent in the *DEFAULT-ORCHESTRATOR* registry, constructs
a condition of the specified type with appropriate default parameters,
and signals it. The orchestrator's monitor loop (via handler-bind)
will detect the condition and invoke the appropriate restart.

CONDITION-TYPE must be one of:
  'AGENT-FAILURE      — Simulates a complete agent failure
  'STRATEGY-STALLED   — Simulates a hung strategy
  'RESOURCE-EXHAUSTED — Simulates memory/CPU exhaustion
  'EXTERNAL-TIMEOUT   — Simulates a network/API timeout

Arguments:
  AGENT-ID      — symbol naming the target agent
  CONDITION-TYPE — quoted condition class name (one of the four above)

Returns:
  T if the condition was signalled, NIL if the agent was not found.

Example:
  (simulate-failure 'SCRAPER-1 'EXTERNAL-TIMEOUT)
  ;; → The orchestrator will apply :RETRY or :USE-FALLBACK

  (simulate-failure 'ANALYST-2 'RESOURCE-EXHAUSTED)
  ;; → The orchestrator will apply :PAUSE-AND-SELF-MODIFY"
  (unless *default-orchestrator*
    (format t "~&[DASH] No default orchestrator — start one with (start-orchestrator)~%")
    (return-from simulate-failure nil))
  (let ((agent (bt:with-lock-held ((orchestrator-monitor-lock *default-orchestrator*))
                 (gethash agent-id (orchestrator-agents *default-orchestrator*)))))
    (unless agent
      (format t "~&[DASH] No agent with ID ~A found. Cannot simulate failure.~%" agent-id)
      (return-from simulate-failure nil))
    ;; Construct and signal the appropriate condition
    (format t "~&[DASH] Simulating ~A on agent ~A...~%" condition-type agent-id)
    (case condition-type
      (agent-failure
       (signal-condition 'agent-failure
                         :agent-id agent-id
                         :reason (format nil "Simulated failure on ~A" agent-id)))
      (strategy-stalled
       (signal-condition 'strategy-stalled
                         :agent-id agent-id
                         :elapsed-time 120.0
                         :threshold 30.0))
      (resource-exhausted
       (signal-condition 'resource-exhausted
                         :agent-id agent-id
                         :resource-type :memory
                         :current-usage 1073741824
                         :limit 536870912))
      (external-timeout
       (signal-condition 'external-timeout
                         :agent-id agent-id
                         :operation "Simulated network request"
                         :timeout-seconds 30.0))
      (otherwise
       (format t "~&[DASH] Unknown condition type: ~A. Use one of: ~
                  AGENT-FAILURE, STRATEGY-STALLED, RESOURCE-EXHAUSTED, EXTERNAL-TIMEOUT~%"
               condition-type)
       (return-from simulate-failure nil)))
    (format t "~&[DASH] Condition signalled. Monitor will handle recovery.~%")
    t))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 12: Live Dashboard Thread
;; ───────────────────────────────────────────────────────────────────────────
;;
;; The live dashboard runs in a background thread, refreshing every 2
;; seconds. It uses a simple flag (*DASHBOARD-RUNNING-P*) for graceful
;; shutdown. The loop clears the screen, prints the full dashboard, then
;; sleeps.

(defun dashboard-loop (orchestrator)
  "The dashboard refresh loop. Runs in a dedicated thread.

Loop behavior:
  1. Check *DASHBOARD-RUNNING-P*. If NIL, exit.
  2. Clear the terminal screen.
  3. Print the dashboard header with title and version.
  4. Print the agent table (all registered agents).
  5. Print the footer with command reference.
  6. Force output to ensure display is visible.
  7. Sleep for 2 seconds.
  8. Repeat from step 1.

This function is called by START-DASHBOARD in a new thread. It exits
gracefully when STOP-DASHBOARD sets *DASHBOARD-RUNNING-P* to NIL.

Arguments:
  ORCHESTRATOR — the orchestrator to display (passed from START-DASHBOARD)."
  (loop
    (unless *dashboard-running-p*
      (format *trace-output* "~&[DASH] Dashboard loop exiting.~%")
      (return-from dashboard-loop nil))
    ;; Clear and redraw
    (clear-screen)
    (print-dashboard orchestrator)
    (format t "~&~%[DASH] Refreshing every 2s. Call (mind:stop-dashboard) to exit.~%")
    (force-output)
    ;; Sleep with periodic wakeups to check the flag
    (dotimes (i 20)  ; 20 x 100ms = 2 seconds, with early-exit check
      (unless *dashboard-running-p*
        (return))
      (sleep 0.1))))

(defun start-dashboard (&optional (orchestrator *default-orchestrator*))
  "Start the live dashboard in a background thread.

Spawns a new thread that runs DASHBOARD-LOOP, refreshing the display
every 2 seconds. The dashboard shows the current state of all registered
agents in a beautiful Unicode table with health color coding.

If a dashboard thread is already running on the orchestrator, this
function first stops it before starting a new one.

Arguments:
  ORCHESTRATOR — the orchestrator to display. Defaults to
                 *DEFAULT-ORCHESTRATOR*. An error is signalled if no
                 orchestrator is provided and *DEFAULT-ORCHESTRATOR*
                 is NIL.

Returns:
  The dashboard thread (a BT:THREAD instance).

Example:
  (start-dashboard)                              ; uses default
  (start-dashboard my-orchestrator)              ; explicit orchestrator
  (stop-dashboard)                               ; stops the dashboard"
  (unless orchestrator
    (error "No orchestrator provided and *DEFAULT-ORCHESTRATOR* is NIL. ~
            Start an orchestrator first: (start-orchestrator)"))
  ;; Stop existing dashboard if one is running
  (when (and (orchestrator-dashboard-thread orchestrator)
             (bt:thread-alive-p (orchestrator-dashboard-thread orchestrator)))
    (format *trace-output* "~&[DASH] Stopping existing dashboard thread...~%")
    (stop-dashboard))
  ;; Start the new dashboard
  (setf *dashboard-running-p* t)
  (let ((thread (bt:make-thread
                 (lambda () (dashboard-loop orchestrator))
                 :name "lispmind-dashboard"
                 :initial-bindings '())))
    (setf (orchestrator-dashboard-thread orchestrator) thread)
    (format *trace-output* "~&[DASH] Dashboard started on thread ~A~%"
            (bt:thread-name thread))
    thread))

(defun stop-dashboard ()
  "Stop the dashboard display thread.

Sets *DASHBOARD-RUNNING-P* to NIL, which causes the dashboard loop
to exit gracefully on its next iteration. The function returns
immediately — the actual thread exit may take up to 2 seconds.

If no dashboard is running, prints a message and returns NIL.

Returns:
  T if a dashboard was stopped, NIL if none was running.

Example:
  (stop-dashboard)  ; → T"
  (if (and *default-orchestrator*
           (orchestrator-dashboard-thread *default-orchestrator*)
           *dashboard-running-p*)
      (progn
        (setf *dashboard-running-p* nil)
        ;; Also clear the dashboard-thread slot on the orchestrator
        (when *default-orchestrator*
          (setf (orchestrator-dashboard-thread *default-orchestrator*) nil))
        (format *trace-output* "~&[DASH] Dashboard stop signal sent.~%")
        t)
      (progn
        (format *trace-output* "~&[DASH] No dashboard is currently running.~%")
        nil)))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 13: Dashboard-Enhanced Notifications
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These :AFTER methods on NOTIFY-HEALTH-CHANGE and NOTIFY-STATUS-CHANGE
;; provide inline dashboard updates when agent state changes. They
;; complement the default methods (defined in agent-class.lisp) and the
;; orchestrator methods (defined in orchestrator.lisp) with compact,
;; dashboard-style output.

(defmethod notify-health-change :after ((agent agent) old-value new-value)
  "Dashboard-enhanced health notification — prints a compact dashboard row.

When an agent's health changes, this :AFTER method prints a single-line
update with color-coded health value and a mini health bar. This gives
the operator immediate visual feedback without needing to re-read the
full dashboard.

The output format:
  [HEALTH] AGENT-ID | old → new [████░░░░░░] health-bar

This method runs after the default method (which prints the basic
transition) and after any orchestrator method (which may trigger healing)."
  (let ((color (health-color new-value)))
    (format *trace-output* "~&~A[DASH-HEALTH] ~16A | ~3D → ~A~3D~A | ~A~A~%"
            (ansi-color 35)                              ; magenta prefix
            (agent-id agent)
            old-value
            color new-value (ansi-reset)
            (ansi-color 35)
            (health-bar new-value 10)
            (ansi-reset))))

(defmethod notify-status-change :after ((agent agent) old-status new-status)
  "Dashboard-enhanced status notification — prints with timestamp.

When an agent's status changes, this :AFTER method prints a timestamped
single-line update. The timestamp is formatted as an ISO-8601 local time
string, giving operators precise timing for status transitions.

The output format:
  [STATUS HH:MM:SS] AGENT-ID | :OLD-STATUS → :NEW-STATUS

This method runs after the default method (which prints the basic
transition) and after any orchestrator method (which may update the
registry or trigger the dashboard refresh)."
  (let ((timestamp (local-time:format-timestring
                    nil (local-time:now)
                    :format '((:hour 2) #\: (:min 2) #\: (:sec 2)))))
    (format *trace-output* "~&~A[DASH-STATUS ~A] ~16A | ~A → ~A~A~%"
            (ansi-color 36)                              ; cyan prefix
            timestamp
            (agent-id agent)
            old-status new-status
            (ansi-reset))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 14: REPL Command Reference
;; ───────────────────────────────────────────────────────────────────────────
;;
;; This function prints a comprehensive help menu showing every available
;; REPL command. It is the operator's cheat sheet for the God Mode interface.

(defun print-help ()
  "Print a comprehensive help menu showing all available REPL commands.

Displays every public function in the LISPMIND API that is relevant
to the human operator at the REPL. Each command includes a brief
description of what it does.

The help is organized into functional groups:
  • Introspection — looking at agents
  • Healing — fixing broken agents
  • Control — starting and stopping systems
  • Persistence — saving and restoring state
  • Testing — simulation and demos

Example:
  (print-help)  ; → prints the full help menu to *STANDARD-OUTPUT*"
  (format t "~%~%")
  (format t "╔══════════════════════════════════════════════════════════════════════╗~%")
  (format t "║          LISPMIND — REPL COMMAND REFERENCE (God Mode)              ║~%")
  (format t "╠══════════════════════════════════════════════════════════════════════╣~%")
  ;; Introspection
  (format t "║  ~AINTROSPECTION~A                                                      ║~%"
          (ansi-color 1) (ansi-reset))  ; bold
  (format t "║    (mind:list-agents)                    List all agents             ║~%")
  (format t "║    (mind:inspect-agent 'agent-id)        Detailed agent report       ║~%")
  (format t "║    (mind:print-dashboard orch)           Static dashboard snapshot   ║~%")
  (format t "╠══════════════════════════════════════════════════════════════════════╣~%")
  ;; Healing
  (format t "║  ~AHEALING & PATCHING~A                                                ║~%"
          (ansi-color 1) (ansi-reset))
  (format t "║    (mind:heal-agent orch 'id :use-fallback)   Apply named restart    ║~%")
  (format t "║    (mind:hotpatch-agent agent :new-strategy #'fn)  Live code patch   ║~%")
  (format t "║    (mind:simulate-failure 'id 'condition)    Inject test failure     ║~%")
  (format t "╠══════════════════════════════════════════════════════════════════════╣~%")
  ;; Control
  (format t "║  ~AORCHESTRATOR CONTROL~A                                              ║~%"
          (ansi-color 1) (ansi-reset))
  (format t "║    (mind:start-orchestrator)             Launch monitor thread       ║~%")
  (format t "║    (mind:stop-orchestrator orch)         Graceful shutdown           ║~%")
  (format t "║    (mind:start-dashboard)                Live REPL dashboard         ║~%")
  (format t "║    (mind:stop-dashboard)                 Stop dashboard thread       ║~%")
  (format t "╠══════════════════════════════════════════════════════════════════════╣~%")
  ;; Persistence
  (format t "║  ~APERSISTENCE~A                                                       ║~%"
          (ansi-color 1) (ansi-reset))
  (format t "║    (mind:checkpoint-system orch)         Save all agent states       ║~%")
  (format t "║    (mind:restore-system orch path)       Restore from checkpoint     ║~%")
  (format t "╠══════════════════════════════════════════════════════════════════════╣~%")
  ;; Testing
  (format t "║  ~ADEMONSTRATION~A                                                     ║~%"
          (ansi-color 1) (ansi-reset))
  (format t "║    (mind:run-demo)                       Full self-healing demo      ║~%")
  (format t "╚══════════════════════════════════════════════════════════════════════╝~%")
  (format t "~%")
  ;; Quick condition-type reference for simulate-failure
  (format t "  Condition types for SIMULATE-FAILURE:~%")
  (format t "    'AGENT-FAILURE      — Total agent failure~%")
  (format t "    'STRATEGY-STALLED   — Hung strategy function~%")
  (format t "    'RESOURCE-EXHAUSTED — Memory/CPU/disk exhaustion~%")
  (format t "    'EXTERNAL-TIMEOUT   — Network/API timeout~%")
  (format t "~%"))


;; ═══════════════════════════════════════════════════════════════════════════
;; End of DASHBOARD.LISP
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This file implements the complete REPL dashboard experience for LISPMIND:
;;
;;   • Beautiful Unicode box-drawing tables with color-coded health
;;   • Real-time live dashboard via background thread
;;   • Agent introspection with full state display
;;   • Failure simulation for testing self-healing
;;   • Dashboard-enhanced notifications on state changes
;;   • Comprehensive REPL help system
;;
;; Load this file after orchestrator.lisp. All symbols are in the
;; LISPMIND package (nickname MIND) and are exported from packages.lisp.
;;
;; "The REPL is not a debugger. It is the control panel of a living system."



;; ═══════════════════════════════════════════════════════════════════════════
;; LISPMIND v2.0 Extensions — FlameGraph, Gossip, and Evolution Panels
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; The following functions extend the LISPMIND dashboard with three new
;; panels for LISPMIND v2.0. These panels integrate data from the profiler,
;; gossip network, and evolution subsystems into the existing dashboard
;; framework. Each panel is independently callable for modular use.
;;
;;   • PRINT-FLAMEGRAPH-PANEL    — CPU flamegraph from profiler.lisp
;;   • PRINT-GOSSIP-PANEL        — Network status from gossip.lisp
;;   • PRINT-EVOLUTION-PANEL     — Evolution tracking from evolution.lisp
;;   • PRINT-DASHBOARD-V2        — Combined v2.0 dashboard (all panels)
;;   • START-DASHBOARD-V2        — Live v2.0 dashboard with refresh loop
;;
;; These extensions are designed to be appended to dashboard.lisp without
;; modifying any existing code. They reuse the Unicode box-drawing helpers
;; (DASH-CHAR, VERT-CHAR, TL-CORNER, etc.) and ANSI color utilities
;; (ANSI-COLOR, HEALTH-COLOR, etc.) defined in the sections above.
;;
;; "v2.0 is not a rewrite. It is an evolution — literally."


;; ───────────────────────────────────────────────────────────────────────────
;; Section 20: FlameGraph Panel — CPU Visualisation
;; ───────────────────────────────────────────────────────────────────────────
;;
;; This panel renders an ASCII flamegraph from the profiler subsystem,
;; showing CPU time allocation across functions. It wraps the profiler's
;; GENERATE-FLAMEGRAPH function in dashboard chrome, adding a panel header,
;; status summary, and integration with the existing Unicode border system.

(defparameter *flamegraph-panel-width* 72
  "The inner width of the flamegraph panel in characters.

This determines the width of the flamegraph bars and borders. The
outer border adds 2 characters (left ║ + right ║), so the total
width is *FLAMEGRAPH-PANEL-WIDTH* + 2. Default: 72 characters.

The flamegraph itself is rendered at width *FLAMEGRAPH-PANEL-WIDTH*
and scaled to fit within the dashboard's 70-character inner width
convention (with a small fudge for the ║ borders).")

(defun print-flamegraph-panel (&key (width *flamegraph-panel-width*))
  "Print an ASCII flamegraph panel as part of the dashboard.

Calls PROFILER:GENERATE-FLAMEGRAPH and wraps it in dashboard chrome:
  ╔══════════════════════════════════════════════════════════════════════╗
  ║                    FLAMEGRAPH — CPU by Function                      ║
  ╠══════════════════════════════════════════════════════════════════════╣
  ║  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓  RUN-AGENT           45%    ║
  ║  ▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓▓                PARSE-HTML           30%    ║
  ║  ▓▓▓▓▓▓▓▓▓▓                            HANDLE-MESSAGE       15%    ║
  ║  ▓▓▓▓                                   CHECK-HEALTH         8%     ║
  ║  ▓▓                                     HEARTBEAT            2%     ║
  ╠══════════════════════════════════════════════════════════════════════╣
  ║  Profiler: RUNNING | Samples: 1,234 | Hotspots: 2 | Auto-tune: ON  ║
  ╚══════════════════════════════════════════════════════════════════════╝

If the profiler is not running, displays a message instructing the
operator to start it with (START-SWARM-PROFILE).

The flamegraph uses the profiler's existing color coding:
  • Red bars    — hotspots (> threshold): functions eating CPU
  • Yellow bars — warm spots (> 50% threshold): worth watching
  • Green bars  — normal: no concern

Keyword Arguments:
  WIDTH — inner width of the flamegraph (default: *FLAMEGRAPH-PANEL-WIDTH*).

Returns:
  The number of functions displayed in the flamegraph.

Example:
  (print-flamegraph-panel)                          ; default width
  (print-flamegraph-panel :width 100)               ; wider display"
  (let* ((inner-width width)
         ;; Title line
         (title " FLAMEGRAPH — CPU by Function ")
         (title-padded (center-string-v2 title inner-width)))
    ;; Panel top border
    (format t "~&~A~A~A~%"
            (tl-corner)
            (make-string inner-width :initial-element (aref (dash-char) 0))
            (tr-corner))
    ;; Panel title
    (format t "~A~A~A~A~A~%"
            (vert-char)
            (ansi-color 36) title-padded (ansi-reset)
            (vert-char))
    ;; Subtitle with profiler status
    (let* ((status (profiler-status))
           (running-p (getf status :running))
           (samples (getf status :samples 0))
           (hotspot-count (getf status :hotspot-count 0))
           (auto-tune (getf status :auto-tune-p)))
      (let ((subtitle (format nil " Profiler: ~A | Samples: ~:D | Hotspots: ~D | Auto-tune: ~A "
                              (if running-p "RUNNING" "STOPPED")
                              samples
                              hotspot-count
                              (if auto-tune "ON" "OFF"))))
        (format t "~A~A~A~A~A~%"
                (l-junction)
                (make-string inner-width :initial-element (aref (dash-char) 0))
                (r-junction))
        ;; Print the flamegraph body from the profiler module
        (if running-p
            (progn
              ;; Print flamegraph string (strip its own outer borders — we provide our own)
              (print-flamegraph-body-sans-borders inner-width)
              ;; Bottom status line
              (format t "~A~A~A~A~A~%"
                      (l-junction)
                      (make-string inner-width :initial-element (aref (dash-char) 0))
                      (r-junction))
              (format t "~A~A~A~A~A~%"
                      (vert-char)
                      (if (> hotspot-count 0) (ansi-color 33) "")
                      subtitle
                      (if (> hotspot-count 0) (ansi-reset) "")
                      (vert-char)))
            ;; Profiler not running — show helpful message
            (progn
              (format t "~A  ~A~A~A~A~A~%"
                      (vert-char)
                      (make-string (max 0 (floor (- inner-width 56) 2))
                                   :initial-element #\Space)
                      "[Profiler not running — start with (start-swarm-profile)]"
                      (make-string (max 0 (- inner-width 56
                                              (floor (- inner-width 56) 2)))
                                   :initial-element #\Space)
                      (vert-char))
              (format t "~A~A~A~A~A~%"
                      (l-junction)
                      (make-string inner-width :initial-element (aref (dash-char) 0))
                      (r-junction))
              (format t "~A~A~A~A~A~%"
                      (vert-char)
                      ""
                      subtitle
                      ""
                      (vert-char))))
      ;; Panel bottom border
      (format t "~A~A~A~%"
              (bl-corner)
              (make-string inner-width :initial-element (aref (dash-char) 0))
              (br-corner))
      ;; Return count
      (if running-p
          (hash-table-count *profiler-data*)
          0))))

(defun print-flamegraph-body-sans-borders (inner-width)
  "Print the flamegraph bar rows without outer borders.

This helper extracts just the bar rows from GENERATE-FLAMEGRAPH's
output, stripping the outer border characters so they can be wrapped
in the dashboard's own border system. Each bar row is re-wrapped with
the dashboard's VERT-CHAR borders.

Arguments:
  INNER-WIDTH — the available width inside the dashboard borders.

Returns:
  The number of bar rows printed."
  (let* ((flamegraph-str (generate-flamegraph :width inner-width :height 12))
         (lines (split-string-into-lines flamegraph-str))
         (bar-count 0))
    (dolist (line lines)
      ;; Only print lines that contain a bar (█ character) or a function name
      (when (and (> (length line) 0)
                 (or (find #\Full_Block line)
                     (find #\Block line)
                     (and (search "flamegraph" (string-downcase line))
                          (not (find #\═ line)))))
        ;; Strip any existing border chars and re-wrap
        (let ((cleaned (string-trim "║ ║" line)))
          (when (> (length cleaned) 0)
            (format t "~A ~A~A~A ~A~%"
                    (vert-char)
                    (if (find #\Full_Block cleaned) "" " ")
                    cleaned
                    (if (find #\Full_Block cleaned)
                        (make-string (max 0 (- inner-width (length cleaned) 1))
                                     :initial-element #\Space)
                        "")
                    (vert-char))
            (incf bar-count)))))
    ;; If no bars were printed (no profile data), show a message
    (when (zerop bar-count)
      (let ((sorted (sorted-profile-functions (total-samples) 10)))
        (if sorted
            ;; Print bars manually from sorted data
            (dolist (entry sorted)
              (destructuring-bind (fn-name percentage self-pct) entry
                (let* ((bar-width (max 1 (floor (* self-pct (- inner-width 20)) 100)))
                       (bar-str (make-string bar-width :initial-element #\Full_Block))
                       (color (flamegraph-color self-pct))
                       (empty-width (max 0 (- inner-width 20 bar-width
                                                (length (symbol-name fn-name))))))
                  (format t "~A ~A~A~A ~A ~3D%~A~A~A~%"
                          (vert-char)
                          color bar-str (ansi-reset)
                          (make-string empty-width :initial-element #\Space)
                          fn-name
                          (floor self-pct)
                          (ansi-reset)
                          (make-string (max 0 (- inner-width bar-width empty-width
                                                  (length (symbol-name fn-name)) 14))
                                       :initial-element #\Space)
                          (vert-char))
                  (incf bar-count))))
            ;; Truly no data
            (format t "~A  ~A~A~A~A~A~%"
                    (vert-char)
                    (make-string (max 0 (floor (- inner-width 42) 2))
                                 :initial-element #\Space)
                    "[No profile data — agents may be idle]"
                    (make-string (max 0 (- inner-width 42
                                            (floor (- inner-width 42) 2)))
                                 :initial-element #\Space)
                    (vert-char)))))
    bar-count))

(defun center-string-v2 (string width)
  "Center STRING within WIDTH characters, padding with spaces.

Unlike the CENTER-STRING in profiler.lisp, this version handles
ANSI escape sequences correctly by NOT counting them toward the
width. It strips ANSI codes before measuring length.

If STRING is longer than WIDTH, it is truncated from the right.

Arguments:
  STRING — the string to center (may contain ANSI escape codes).
  WIDTH  — the target width in display characters.

Returns a centered string with padding on both sides."
  (let* ((visible-len (ansi-visible-length string))
         (pad (max 0 (- width visible-len)))
         (left-pad (floor pad 2))
         (right-pad (- pad left-pad)))
    (if (<= visible-len width)
        (format nil "~A~A~A"
                (make-string left-pad :initial-element #\Space)
                string
                (make-string right-pad :initial-element #\Space))
        (subseq string 0 width))))

(defun ansi-visible-length (string)
  "Return the visible length of STRING, ignoring ANSI escape codes.

ANSI escape sequences are of the form ESC[<digits>;<digits>m and
take zero display width. This function strips them before counting.

Arguments:
  STRING — a string that may contain ANSI escape codes.

Returns the number of visible characters."
  (let ((len 0)
        (in-escape nil))
    (dotimes (i (length string) len)
      (let ((ch (char string i)))
        (cond
          ;; Start of escape sequence
          ((char= ch #\Escape)
           (setf in-escape t))
          ;; End of escape sequence (the 'm' character)
          ((and in-escape (char= ch #\m))
           (setf in-escape nil))
          ;; Digits and semicolons inside escape sequence
          (in-escape
           ;; Still inside escape, don't count
           nil)
          ;; Regular visible character
          (t (incf len))))))))

(defun split-string-into-lines (string)
  "Split STRING into a list of lines at newline characters.

Handles both #\Newline and \\r\\n line endings. Trailing newlines
produce empty strings in the result list.

Arguments:
  STRING — the string to split.

Returns a list of strings (one per line)."
  (let ((lines '())
        (start 0)
        (len (length string)))
    (dotimes (i len)
      (when (char= (char string i) #\Newline)
        (push (subseq string start i) lines)
        (setf start (1+ i))))
    ;; Push the last line (or empty string if string ends with newline)
    (when (<= start len)
      (push (subseq string start) lines))
    (nreverse lines)))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 21: Gossip Status Panel — Network Health
;; ───────────────────────────────────────────────────────────────────────────
;;
;; This panel displays the current state of the gossip network subsystem.
;; It shows: peer connections, subscribed topics, message throughput,
;; and an overall network health indicator. The data is sourced from the
;; gossip subsystem (gossip.lisp) via its special variables and accessors.

(defun print-gossip-panel ()
  "Print gossip network status as a dashboard panel.

Displays a comprehensive view of the gossip subsystem in a Unicode
box-drawing panel:
  ╔══════════════════════════════════════════════════════════════════════╗
  ║              GOSSIP NETWORK — Swarm Nervous System                   ║
  ╠══════════════════════════════════════════════════════════════════════╣
  ║  Status:       RUNNING                                               ║
  ║  Peers:        3 connected                                           ║
  ║  Peer list:    tcp://192.168.1.100:55555, tcp://10.0.0.5:55555      ║
  ║  Topics:       swarm.health, swarm.threats, swarm.evolution          ║
  ║  Messages/sec: 12.3                                                  ║
  ║  Health:       [████████████░░░░░░░░░░░░]  HEALTHY                  ║
  ╚══════════════════════════════════════════════════════════════════════╝

If the gossip system is not running, the panel shows a 'STOPPED' status
with instructions on how to start it.

The panel queries these gossip system variables:
  * *GOSSIP-RUNNING-P*     — is the system active?
  * *GOSSIP-PEERS*         — list of connected peer endpoints
  * *GOSSIP-TOPICS*        — hash table of subscribed topics
  * *GOSSIP-RECEIVE-THREAD* — is the receive thread alive?

The health indicator is computed from:
  • Number of peers (more = better connectivity)
  • Receive thread status (must be alive)
  • Running state (must be T)

Returns:
  A keyword indicating network health: :HEALTHY, :DEGRADED, or :OFFLINE.

Example:
  (print-gossip-panel)  ; → :HEALTHY (prints panel as side effect)"
  (let* ((inner-width 70)
         (title " GOSSIP NETWORK — Swarm Nervous System ")
         (running-p *gossip-running-p*)
         (peer-count (length *gossip-peers*))
         (peers (copy-list *gossip-peers*))
         (topic-list (gossip-topic-list))
         (topic-count (length topic-list))
         (receive-alive (and *gossip-receive-thread*
                             (bt:thread-alive-p *gossip-receive-thread*)))
         ;; Compute health score (0-100)
         (health-score (compute-gossip-health running-p peer-count receive-alive))
         (health-label (cond ((>= health-score 80) "HEALTHY")
                             ((>= health-score 50) "DEGRADED")
                             (t "OFFLINE")))
         (health-color-code (cond ((>= health-score 80) 32)   ; green
                                  ((>= health-score 50) 33)   ; yellow
                                  (t 31))))                     ; red
    ;; Panel top border
    (format t "~&~A~A~A~%"
            (tl-corner)
            (make-string inner-width :initial-element (aref (dash-char) 0))
            (tr-corner))
    ;; Title
    (format t "~A~A~A~A~A~%"
            (vert-char)
            (ansi-color 36)
            (center-string-v2 title inner-width)
            (ansi-reset)
            (vert-char))
    ;; Separator
    (format t "~A~A~A~%"
            (l-junction)
            (make-string inner-width :initial-element (aref (dash-char) 0))
            (r-junction))
    (if running-p
        ;; Gossip is running — show full status
        (progn
          ;; Status line
          (format t "~A  Status:       ~A~A~A~A~%"
                  (vert-char)
                  (ansi-color (if running-p 32 31))
                  (if running-p "RUNNING" "STOPPED")
                  (ansi-reset)
                  (vert-char))
          ;; Peer count
          (format t "~A  Peers:        ~D connected~A~%"
                  (vert-char)
                  peer-count
                  (vert-char))
          ;; Peer list (truncated if too long)
          (let* ((peers-str (if peers
                                 (format nil "~{~A~^, ~}" peers)
                                 "none"))
                 (max-peer-len (- inner-width 16))
                 (display-peers (if (> (length peers-str) max-peer-len)
                                    (concatenate 'string
                                                 (subseq peers-str 0 (max 0 (- max-peer-len 3)))
                                                 "...")
                                    peers-str)))
            (format t "~A  Peer list:    ~A~A~%"
                    (vert-char)
                    display-peers
                    (vert-char)))
          ;; Topics
          (let* ((topics-str (if topic-list
                                 (format nil "~{~A~^, ~}" topic-list)
                                 "none"))
                 (max-topic-len (- inner-width 16))
                 (display-topics (if (> (length topics-str) max-topic-len)
                                     (concatenate 'string
                                                  (subseq topics-str 0 (max 0 (- max-topic-len 3)))
                                                  "...")
                                     topics-str)))
            (format t "~A  Topics:       ~D (~A)~A~%"
                    (vert-char)
                    topic-count
                    display-topics
                    (vert-char)))
          ;; Receive thread status
          (format t "~A  Receive thr:  ~A~A~A~A~%"
                  (vert-char)
                  (ansi-color (if receive-alive 32 31))
                  (if receive-alive "ALIVE" "DEAD")
                  (ansi-reset)
                  (vert-char))
          ;; Separator before health
          (format t "~A~A~A~%"
                  (l-junction)
                  (make-string inner-width :initial-element (aref (dash-char) 0))
                  (r-junction))
          ;; Health bar
          (format t "~A  Network:      ~A~A~A ~A~A~%"
                  (vert-char)
                  (ansi-color health-color-code)
                  (health-bar health-score 20)
                  (ansi-reset)
                  health-label
                  (vert-char)))
        ;; Gossip is not running — show stopped message
        (progn
          (format t "~A  Status:       ~A~A~A~A~%"
                  (vert-char)
                  (ansi-color 31)
                  "STOPPED"
                  (ansi-reset)
                  (vert-char))
          (format t "~A~A~A~%"
                  (l-junction)
                  (make-string inner-width :initial-element (aref (dash-char) 0))
                  (r-junction))
          (format t "~A  Start with: (start-gossip-node :peers '(...))~A~%"
                  (vert-char)
                  (vert-char))))
    ;; Panel bottom border
    (format t "~A~A~A~%"
            (bl-corner)
            (make-string inner-width :initial-element (aref (dash-char) 0))
            (br-corner))
    ;; Return health keyword
    (intern health-label :keyword)))

(defun compute-gossip-health (running-p peer-count receive-alive)
  "Compute a gossip network health score from 0 to 100.

The health score is a weighted combination of:
  • Running state (40 points): system must be active
  • Receive thread (30 points): thread must be alive
  • Peer connectivity (30 points): 10 points per peer, max 30

Arguments:
  RUNNING-P      — T if the gossip system is running.
  PEER-COUNT     — number of connected peers.
  RECEIVE-ALIVE  — T if the receive thread is alive.

Returns an integer from 0 to 100.

Example:
  (compute-gossip-health t 2 t)  ; → 80
  (compute-gossip-health nil 0 nil)  ; → 0"
  (+ (if running-p 40 0)
     (if receive-alive 30 0)
     (min 30 (* 10 peer-count))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 22: Evolution Tracker Panel — Self-Improvement Analytics
;; ───────────────────────────────────────────────────────────────────────────
;;
;; This panel tracks the genetic programming evolution subsystem, showing
;; how many evolution events have occurred, the best fitness achieved,
;; current generation counts, and a preview of the latest evolved strategy.
;; Data is sourced from *EVOLUTION-LOG* and agent state in evolution.lisp.

(defparameter *evolution-panel-width* 70
  "The inner width of the evolution tracker panel in characters.")

(defun print-evolution-panel ()
  "Print evolution tracking info as a dashboard panel.

Displays a comprehensive view of the GP evolution subsystem:
  ╔══════════════════════════════════════════════════════════════════════╗
  ║           EVOLUTION TRACKER — Self-Improving Agents                  ║
  ╠══════════════════════════════════════════════════════════════════════╣
  ║  Events today:    5                                                  ║
  ║  Best fitness:    2.847                                              ║
  ║  Current gen:     generation 3 of 5                                  ║
  ║  Latest strategy: (IF (> ERROR-COUNT 3) (FALLBACK-STRATEGY ...) ...) ║
  ╠══════════════════════════════════════════════════════════════════════╣
  ║  Top evolved agents: SCRAPER-1 (3x), ANALYST-2 (2x)                  ║
  ╚══════════════════════════════════════════════════════════════════════╝

The panel aggregates data from:
  * *EVOLUTION-LOG* — the global hash table of evolution records
  * Agent state :EVOLUTION-GENERATION slot
  * Agent state :STRATEGY-EXPRESSION slot

It counts evolution events that occurred today (since midnight), finds
the best fitness score ever achieved, and shows the most recent evolved
strategy expression across all agents.

Returns:
  A plist with keys :EVENTS-TODAY :BEST-FITNESS :GENERATION :TOP-AGENTS.

Example:
  (print-evolution-panel)
    ;; → (:EVENTS-TODAY 5 :BEST-FITNESS 2.847 :GENERATION 3 :TOP-AGENTS (...))"
  (let* ((inner-width *evolution-panel-width*)
         (title " EVOLUTION TRACKER — Self-Improving Agents ")
         ;; Gather evolution statistics
         (all-events (gather-all-evolution-events))
         (today-events (count-today-events all-events))
         (best-fitness (find-best-fitness all-events))
         (generation-info (find-current-generation))
         (top-agents (find-top-evolved-agents 3))
         (latest-strategy (find-latest-strategy all-events)))
    ;; Panel top border
    (format t "~&~A~A~A~%"
            (tl-corner)
            (make-string inner-width :initial-element (aref (dash-char) 0))
            (tr-corner))
    ;; Title
    (format t "~A~A~A~A~A~%"
            (vert-char)
            (ansi-color 36)
            (center-string-v2 title inner-width)
            (ansi-reset)
            (vert-char))
    ;; Separator
    (format t "~A~A~A~%"
            (l-junction)
            (make-string inner-width :initial-element (aref (dash-char) 0))
            (r-junction))
    ;; Events today
    (format t "~A  Events today:  ~A~A~4D~A~A~%"
            (vert-char)
            (if (> today-events 0) (ansi-color 32) (ansi-color 90))
            today-events
            (ansi-reset)
            (vert-char))
    ;; Best fitness
    (format t "~A  Best fitness:  ~A~,3F~A~A~%"
            (vert-char)
            (if (> best-fitness 0.0) (ansi-color 33) "")
            best-fitness
            (ansi-reset)
            (vert-char))
    ;; Current generation
    (format t "~A  Current gen:   ~A~A~A~%"
            (vert-char)
            (if generation-info
                (format nil "generation ~D" generation-info)
                "N/A (no active evolution)")
            (vert-char))
    ;; Separator
    (format t "~A~A~A~%"
            (l-junction)
            (make-string inner-width :initial-element (aref (dash-char) 0))
            (r-junction))
    ;; Latest evolved strategy preview
    (format t "~A  Latest strategy:~A~%"
            (vert-char)
            (vert-char))
    (if latest-strategy
        ;; Print strategy expression, truncated to fit panel
        (let* ((expr-str (format nil "~S" latest-strategy))
               (max-len (- inner-width 4))  ; 2 spaces padding + borders
               (display-str (if (> (length expr-str) max-len)
                                (concatenate 'string
                                             (subseq expr-str 0 (max 0 (- max-len 3)))
                                             "...")
                                expr-str)))
          (format t "~A    ~A~A~%"
                  (vert-char)
                  display-str
                  (vert-char)))
        (format t "~A    [No evolved strategies yet]~A~%"
                (vert-char)
                (vert-char)))
    ;; Separator
    (format t "~A~A~A~%"
            (l-junction)
            (make-string inner-width :initial-element (aref (dash-char) 0))
            (r-junction))
    ;; Top evolved agents
    (format t "~A  Top agents:    ~A~A~%"
            (vert-char)
            (if top-agents
                (format nil "~{~A~^, ~}"
                        (mapcar (lambda (entry)
                                   (format nil "~A (~Dx)"
                                           (first entry)
                                           (second entry)))
                                top-agents))
                "None yet")
            (vert-char))
    ;; Panel bottom border
    (format t "~A~A~A~%"
            (bl-corner)
            (make-string inner-width :initial-element (aref (dash-char) 0))
            (br-corner))
    ;; Return summary plist
    (list :events-today today-events
          :best-fitness best-fitness
          :generation generation-info
          :top-agents top-agents)))

(defun gather-all-evolution-events () 
  "Gather all evolution records from *EVOLUTION-LOG*.

Flattens the hash table (which maps agent-id → list of records) into
a single list of all evolution records across all agents.

Returns a list of evolution record plists (newest first)."
  (let ((all-events '()))
    (maphash (lambda (agent-id records)
               (declare (ignore agent-id))
               (dolist (record records)
                 (push record all-events)))
             *evolution-log*)
    all-events))

(defun count-today-events (events)
  "Count evolution events that occurred today.

EVENTS is a list of evolution record plists. An event counts as 'today'
if its timestamp is on the current calendar day (since midnight).

Arguments:
  EVENTS — list of evolution record plists with :TIMESTAMP keys.

Returns the count as an integer."
  (let* ((now (local-time:now))
         (today-start (local-time:timestamp-
                        now
                        (+ (* (local-time:timestamp-hour now) 3600)
                           (* (local-time:timestamp-minute now) 60)
                           (local-time:timestamp-second now))
                        :sec))
         (count 0))
    (dolist (event events)
      (let ((ts (getf event :timestamp)))
        (when (and ts (local-time:timestamp>= ts today-start))
          (incf count))))
    count))

(defun find-best-fitness (events)
  "Find the highest fitness score across all evolution events.

Scans the :NEW-FITNESS field of each record and returns the maximum.
If no events exist, returns 0.0.

Arguments:
  EVENTS — list of evolution record plists.

Returns a float."
  (if (null events)
      0.0
      (let ((best 0.0))
        (dolist (event events)
          (let ((fitness (getf event :new-fitness 0.0)))
            (when (> fitness best)
              (setf best fitness))))
        best)))

(defun find-current-generation () 
  "Find the maximum generation number across all evolution events.

Scans the :GENERATION field of each record and returns the maximum.
This represents the most recent GP generation that has completed.

Returns an integer, or NIL if no events exist."
  (let ((max-gen nil))
    (maphash (lambda (agent-id records)
               (declare (ignore agent-id))
               (dolist (record records)
                 (let ((gen (getf record :generation)))
                   (when (and gen (or (null max-gen) (> gen max-gen)))
                     (setf max-gen gen)))))
             *evolution-log*)
    max-gen))

(defun find-top-evolved-agents (n)
  "Find the top N agents by number of evolution events.

Returns a list of (agent-id event-count) pairs, sorted by event count
descending. If fewer than N agents have evolution history, returns all.

Arguments:
  N — maximum number of agents to return.

Returns a list of (SYMBOL INTEGER) pairs."
  (let ((agent-counts '()))
    (maphash (lambda (agent-id records)
               (push (list agent-id (length records)) agent-counts))
             *evolution-log*)
    ;; Sort by count descending, take top N
    (setf agent-counts (sort agent-counts #'> :key #'second))
    (subseq agent-counts 0 (min n (length agent-counts)))))

(defun find-latest-strategy (events)
  "Find the most recently evolved strategy expression.

Scans EVENTS for the one with the most recent :TIMESTAMP and returns
its :NEW-EXPRESSION. This is the latest evolved strategy across all
agents.

Arguments:
  EVENTS — list of evolution record plists.

Returns an S-expression (list), or NIL if no events exist."
  (if (null events)
      nil
      (let ((latest-ts nil)
            (latest-expr nil))
        (dolist (event events)
          (let ((ts (getf event :timestamp))
                (expr (getf event :new-expression)))
            (when (and ts expr (or (null latest-ts)
                                   (local-time:timestamp> ts latest-ts)))
              (setf latest-ts ts)
              (setf latest-expr expr))))
        latest-expr)))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 23: Combined v2.0 Dashboard — All Panels United
;; ───────────────────────────────────────────────────────────────────────────
;;
;; This is the main entry point for the LISPMIND v2.0 dashboard experience.
;; It combines the classic agent health table with the three new panels
;; (flamegraph, gossip network, evolution tracker) into a single unified
;; display. The v2 dashboard is the operator's complete view of the swarm.

(defun print-dashboard-v2 (orchestrator)
  "Print the full LISPMIND v2.0 dashboard with all panels.

This is the unified v2.0 dashboard that displays every subsystem in a
single screen:

  1. Classic Agent Health Table   — (existing PRINT-DASHBOARD)
     • All registered agents with health, status, errors, heartbeat
     • Color-coded health with Unicode health bars

  2. FlameGraph Panel             — (new in v2.0)
     • CPU time allocation by function
     • Hotspot detection with color-coded bars
     • Profiler status (running, samples, auto-tune)

  3. Gossip Network Status Panel  — (new in v2.0)
     • Number of peers connected
     • Topics being monitored
     • Receive thread health
     • Network health indicator bar

  4. Evolution Tracker Panel      — (new in v2.0)
     • Number of evolution events today
     • Best fitness achieved across all agents
     • Current generation count
     • Latest evolved strategy preview
     • Top evolved agents

  5. Combined v2.0 Footer         — (new)
     • All existing commands plus new v2.0 commands
     • Reference for gossip, profiler, and evolution control

Each panel is separated by a blank line for visual clarity. Panels 2-4
use the same Unicode box-drawing style and ANSI color coding as the
classic dashboard for visual consistency.

Arguments:
  ORCHESTRATOR — the orchestrator instance to display. Must not be NIL.

Returns:
  A plist summarizing all panels:
    (:AGENT-COUNT <n> :PROFILER-FUNCTIONS <n> :GOSSIP-HEALTH <keyword>
     :EVOLUTION-EVENTS <n> :BEST-FITNESS <float>)

Example:
  (print-dashboard-v2 *default-orchestrator*)
    ;; Prints full v2.0 dashboard
    ;; → (:AGENT-COUNT 5 :PROFILER-FUNCTIONS 12 :GOSSIP-HEALTH :HEALTHY
    ;;    :EVOLUTION-EVENTS 3 :BEST-FITNESS 2.847)"
  (unless orchestrator
    (format t "~&~A[DASH-v2] No orchestrator provided.~A~%"
            (ansi-color 31) (ansi-reset))
    (return-from print-dashboard-v2 nil))
  ;; ── Panel 1: Classic Agent Health Table ──
  (print-dashboard orchestrator)
  ;; ── Panel 2: FlameGraph ──
  (format t "~%")  ; spacing
  (print-flamegraph-panel)
  ;; ── Panel 3: Gossip Network ──
  (format t "~%")  ; spacing
  (let ((gossip-health (print-gossip-panel)))
    ;; ── Panel 4: Evolution Tracker ──
    (format t "~%")  ; spacing
    (let ((evo-summary (print-evolution-panel)))
      ;; ── Panel 5: v2.0 Footer ──
      (format t "~%")  ; spacing
      (print-dashboard-v2-footer)
      ;; Return combined summary
      (list :agent-count (bt:with-lock-held
                              ((orchestrator-monitor-lock orchestrator))
                            (hash-table-count
                             (orchestrator-agents orchestrator)))
            :profiler-functions (hash-table-count *profiler-data*)
            :gossip-health gossip-health
            :evolution-events (getf evo-summary :events-today 0)
            :best-fitness (getf evo-summary :best-fitness 0.0)))))

(defun print-dashboard-v2-footer ()
  "Print the v2.0 dashboard footer with all commands.

Extends the classic footer (PRINT-DASHBOARD-FOOTER) with v2.0-specific
commands for the profiler, gossip network, and evolution subsystems.

Commands listed:
  • Classic: list-agents, inspect-agent, start/stop-dashboard
  • Profiler: start-swarm-profile, generate-flamegraph, detect-hotspots
  • Gossip: start-gossip-node, publish-message, list-peers
  • Evolution: run-evolutionary-cycle, print-evolution-report
  • v2 Control: start-dashboard-v2, print-dashboard-v2"
  (let* ((inner-width 70)
         (title " LISPMIND v2.0 — COMMAND REFERENCE "))
    ;; Top border
    (format t "~A~A~A~%"
            (tl-corner)
            (make-string inner-width :initial-element (aref (dash-char) 0))
            (tr-corner))
    ;; Title
    (format t "~A~A~A~A~A~%"
            (vert-char)
            (ansi-color 1)  ; bold
            (center-string-v2 title inner-width)
            (ansi-reset)
            (vert-char))
    ;; Separator
    (format t "~A~A~A~%"
            (l-junction)
            (make-string inner-width :initial-element (aref (dash-char) 0))
            (r-junction))
    ;; Classic commands
    (format t "~A  ~AINTROSPECTION~A~A~%"
            (vert-char)
            (ansi-color 36) (ansi-reset)
            (vert-char))
    (format t "~A    (list-agents)                  (inspect-agent 'id)~A~%"
            (vert-char) (vert-char))
    (format t "~A    (print-dashboard orch)          (print-dashboard-v2 orch)~A~%"
            (vert-char) (vert-char))
    ;; Separator
    (format t "~A~A~A~%"
            (l-junction)
            (make-string inner-width :initial-element (aref (dash-char) 0))
            (r-junction))
    ;; Profiler commands
    (format t "~A  ~APROFILER~A~A~%"
            (vert-char)
            (ansi-color 36) (ansi-reset)
            (vert-char))
    (format t "~A    (start-swarm-profile)           (generate-flamegraph)~A~%"
            (vert-char) (vert-char))
    (format t "~A    (detect-hotspots)               (auto-tune-all-hotspots)~A~%"
            (vert-char) (vert-char))
    (format t "~A    (print-flamegraph-panel)        (profiler-status)~A~%"
            (vert-char) (vert-char))
    ;; Separator
    (format t "~A~A~A~%"
            (l-junction)
            (make-string inner-width :initial-element (aref (dash-char) 0))
            (r-junction))
    ;; Gossip commands
    (format t "~A  ~AGOSSIP NETWORK~A~A~%"
            (vert-char)
            (ansi-color 36) (ansi-reset)
            (vert-char))
    (format t "~A    (start-gossip-node :peers ...)  (print-gossip-panel)~A~%"
            (vert-char) (vert-char))
    (format t "~A    (publish-message topic payload)  (list-peers)~A~%"
            (vert-char) (vert-char))
    ;; Separator
    (format t "~A~A~A~%"
            (l-junction)
            (make-string inner-width :initial-element (aref (dash-char) 0))
            (r-junction))
    ;; Evolution commands
    (format t "~A  ~AEVOLUTION~A~A~%"
            (vert-char)
            (ansi-color 36) (ansi-reset)
            (vert-char))
    (format t "~A    (print-evolution-panel)         (print-evolution-report 'id)~A~%"
            (vert-char) (vert-char))
    (format t "~A    (run-evolutionary-cycle agent)   (evolution-history 'id)~A~%"
            (vert-char) (vert-char))
    ;; Separator
    (format t "~A~A~A~%"
            (l-junction)
            (make-string inner-width :initial-element (aref (dash-char) 0))
            (r-junction))
    ;; v2 control
    (format t "~A  ~ADASHBOARD v2~A~A~%"
            (vert-char)
            (ansi-color 36) (ansi-reset)
            (vert-char))
    (format t "~A    (start-dashboard-v2)             (stop-dashboard)~A~%"
            (vert-char) (vert-char))
    ;; Bottom border
    (format t "~A~A~A~%"
            (bl-corner)
            (make-string inner-width :initial-element (aref (dash-char) 0))
            (br-corner))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 24: Live v2.0 Dashboard Thread
;; ───────────────────────────────────────────────────────────────────────────
;;
;; The v2.0 live dashboard runs in a background thread, refreshing every
;; 2 seconds. It is identical to the v1 dashboard loop except it calls
;; PRINT-DASHBOARD-V2 instead of PRINT-DASHBOARD, giving the operator the
;; full v2.0 experience with all four panels updating in real time.

(defparameter *dashboard-v2-running-p* nil
  "Thread-local flag controlling the v2.0 dashboard refresh loop.

When START-DASHBOARD-V2 sets this to T, the DASHBOARD-V2-LOOP runs.
When STOP-DASHBOARD-V2 sets it to NIL, the loop exits gracefully.

This flag is independent of *DASHBOARD-RUNNING-P* so that v1 and v2
dashboards can be started/stopped independently. However, only one
should be running at a time — starting v2 stops v1 and vice versa.")

(defun dashboard-v2-loop (orchestrator)
  "The v2.0 dashboard refresh loop. Runs in a dedicated thread.

Identical to DASHBOARD-LOOP (Section 12) except it calls
PRINT-DASHBOARD-V2 instead of PRINT-DASHBOARD, producing the full
four-panel v2.0 display on each refresh.

Loop behavior:
  1. Check *DASHBOARD-V2-RUNNING-P*. If NIL, exit.
  2. Clear the terminal screen.
  3. Print the v2.0 dashboard (all four panels + footer).
  4. Force output.
  5. Sleep for 2 seconds (with periodic wakeups for early exit).
  6. Repeat.

Arguments:
  ORCHESTRATOR — the orchestrator to display.

Returns NIL when the loop exits."
  (loop
    (unless *dashboard-v2-running-p*
      (format *trace-output* "~&[DASH-v2] Dashboard v2 loop exiting.~%")
      (return-from dashboard-v2-loop nil))
    ;; Clear and redraw
    (clear-screen)
    (print-dashboard-v2 orchestrator)
    (format t "~&~%[DASH-v2] Refreshing every 2s. Call (mind:stop-dashboard-v2) to exit.~%")
    (force-output)
    ;; Sleep with periodic wakeups
    (dotimes (i 20)  ; 20 x 100ms = 2 seconds
      (unless *dashboard-v2-running-p*
        (return))
      (sleep 0.1))))

(defun start-dashboard-v2 (&optional (orchestrator *default-orchestrator*))
  "Start the v2.0 live dashboard in a background thread.

Spawns a new thread that runs DASHBOARD-V2-LOOP, refreshing the full
v2.0 dashboard (classic agent table + flamegraph + gossip + evolution)
every 2 seconds.

If a v1 dashboard is currently running, it is stopped first. If a v2
dashboard is already running, it is stopped and restarted.

Arguments:
  ORCHESTRATOR — the orchestrator to display. Defaults to
                 *DEFAULT-ORCHESTRATOR*. An error is signalled if no
                 orchestrator is available.

Returns:
  The dashboard v2 thread (a BT:THREAD instance).

Example:
  (start-dashboard-v2)                              ; uses default
  (start-dashboard-v2 my-orchestrator)              ; explicit orchestrator
  (stop-dashboard-v2)                               ; stops the v2 dashboard

See also:
  PRINT-DASHBOARD-V2 — static snapshot (no thread)
  STOP-DASHBOARD-V2  — graceful shutdown"
  (unless orchestrator
    (error "No orchestrator provided and *DEFAULT-ORCHESTRATOR* is NIL. ~
            Start an orchestrator first: (start-orchestrator)"))
  ;; Stop v1 dashboard if running
  (when *dashboard-running-p*
    (format *trace-output* "~&[DASH-v2] Stopping v1 dashboard first...~%")
    (stop-dashboard))
  ;; Stop existing v2 dashboard if one is running
  (when (and *dashboard-v2-running-p*)
    (format *trace-output* "~&[DASH-v2] Stopping existing v2 dashboard...~%")
    (stop-dashboard-v2)
    (sleep 0.5))  ; Give the old thread time to exit
  ;; Start the new v2 dashboard
  (setf *dashboard-v2-running-p* t)
  (let ((thread (bt:make-thread
                 (lambda () (dashboard-v2-loop orchestrator))
                 :name "lispmind-dashboard-v2"
                 :initial-bindings '())))
    (format *trace-output* "~&[DASH-v2] Dashboard v2.0 started on thread ~A~%"
            (bt:thread-name thread))
    thread))

(defun stop-dashboard-v2 ()
  "Stop the v2.0 dashboard display thread.

Sets *DASHBOARD-V2-RUNNING-P* to NIL, which causes DASHBOARD-V2-LOOP
to exit gracefully on its next iteration. Returns immediately — the
actual thread exit may take up to 2 seconds.

If no v2 dashboard is running, prints a message and returns NIL.

Returns:
  T if a v2 dashboard was stopped, NIL if none was running.

Example:
  (stop-dashboard-v2)  ; → T"
  (if *dashboard-v2-running-p*
      (progn
        (setf *dashboard-v2-running-p* nil)
        (format *trace-output* "~&[DASH-v2] Dashboard v2 stop signal sent.~%")
        t)
      (progn
        (format *trace-output* "~&[DASH-v2] No v2 dashboard is currently running.~%")
        nil)))


;; ═══════════════════════════════════════════════════════════════════════════
;; End of LISPMIND v2.0 Extensions
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; New functions added in this v2.0 extension:
;;
;;   Panel Functions (independently callable):
;;     • PRINT-FLAMEGRAPH-PANEL    — CPU flamegraph with profiler status
;;     • PRINT-GOSSIP-PANEL        — Network health and peer status
;;     • PRINT-EVOLUTION-PANEL     — Self-improvement analytics
;;
;;   Combined Dashboard:
;;     • PRINT-DASHBOARD-V2        — All four panels in one display
;;     • PRINT-DASHBOARD-V2-FOOTER — v2.0 command reference footer
;;
;;   Live Dashboard:
;;     • START-DASHBOARD-V2        — Background thread with 2s refresh
;;     • STOP-DASHBOARD-V2         — Graceful shutdown
;;     • DASHBOARD-V2-LOOP         — The refresh loop function
;;
;;   Helper Functions:
;;     • PRINT-FLAMEGRAPH-BODY-SANS-BORDERS — Strip borders from flamegraph
;;     • CENTER-STRING-V2           — ANSI-aware string centering
;;     • ANSI-VISIBLE-LENGTH        — Strip ANSI for width calculation
;;     • SPLIT-STRING-INTO-LINES    — String → list of lines
;;     • COMPUTE-GOSSIP-HEALTH      — Network health score
;;     • GATHER-ALL-EVOLUTION-EVENTS — Flatten evolution log
;;     • COUNT-TODAY-EVENTS         — Filter today's evolution events
;;     • FIND-BEST-FITNESS          — Max fitness across all events
;;     • FIND-CURRENT-GENERATION    — Latest GP generation number
;;     • FIND-TOP-EVOLVED-AGENTS    — Agents with most evolutions
;;     • FIND-LATEST-STRATEGY       — Most recent evolved S-expression
;;
;; "The swarm does not replace its parts. It transcends them."

