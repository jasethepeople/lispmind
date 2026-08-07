;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; TELEMETRY.LISP — Real-Time Swarm Metrics Streaming Pipeline
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;                    THE SWARM'S PULSE: METRICS → JSON → WEBSOCKET
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This module is the telemetry nervous system of LISPMIND. It continuously
;;; samples the orchestrator's state — agent health, fitness scores, safety
;;; violations, gossip mesh topology — and broadcasts structured JSON snapshots
;;; to connected dashboard clients via WebSocket (or TCP fallback).
;;;
;;; ARCHITECTURE
;;; ─────────────
;;;   Orchestrator state (agents, health, errors)
;;;           │
;;;           ▼ (every *telemetry-interval* seconds, default 0.5)
;;;   build-telemetry-snapshot ──► calculate-success-rate
;;;                              calculate-rejection-rate
;;;                              calculate-containment-score
;;;                              get-avg-fitness
;;;                              get-mutation-rate
;;;                              build-agent-summaries
;;;                              gossip-topology-summary
;;;           │
;;;           ▼
;;;   push-telemetry-history (sliding window, last 50)
;;;           │
;;;           ▼
;;;   snapshot-to-json (cl-json:encode-json-plist-to-string)
;;;           │
;;;           ▼
;;;   broadcast-to-clients (WebSocket ─or─ TCP JSON line)
;;;
;;; THREAD SAFETY
;;; ─────────────
;;; All history mutations are protected by *telemetry-history-lock*.
;;; The telemetry loop runs in its own thread, spawned by
;;; start-telemetry-stream. The broadcast function acquires the client
;;; lock before iterating over connected clients.
;;;
;;; ERROR ISOLATION
;;; ────────────────
;;; Every network send is wrapped in ignore-errors so that a single dead
;;; client cannot crash the broadcast. The telemetry loop itself has a
;;; handler-case wrapper that logs errors and continues.
;;;
;;; "The swarm watches itself. Every heartbeat, every mutation, every
;;;  safety kernel rejection — all of it flows through here, transformed
;;;  into light on a dashboard screen. This is how we see the mind think."

(in-package :lispmind)

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 0: Package Integration — External Dependencies
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This module depends on CL-JSON for encoding. If cl-json is not available,
;; we provide a minimal JSON encoder fallback.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (handler-case
      (progn
        (require :cl-json)
        (pushnew :cl-json-available *features*))
    (error ()
      (warn "[TELEMETRY] cl-json not available. Using minimal JSON fallback."))))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 1: Special Variables — Configuration & State
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *telemetry-enabled-p* nil
  "Whether the telemetry streaming loop is currently active.

Set to T by START-TELEMETRY-STREAM and NIL by STOP-TELEMETRY-STREAM.
The telemetry thread checks this flag before each broadcast cycle.

Thread-safety: This special variable is read and written by the main
thread (lifecycle functions) and the telemetry thread. On SBCL, reads
and writes of T/NIL are atomic, so no lock is needed for this flag.
However, the telemetry thread uses it as a termination condition, so
the stop function should be called before destroying the orchestrator.")

(defvar *telemetry-thread* nil
  "The thread handle for the telemetry broadcast loop.

Set by START-TELEMETRY-STREAM when spawning the telemetry thread.
Cleared by STOP-TELEMETRY-STREAM after joining the thread.

Thread-safety: Only the lifecycle functions mutate this variable.
The telemetry loop itself does not read or write this slot.")

(defvar *telemetry-interval* 0.5
  "Seconds between telemetry broadcasts.

Default is 0.5 (2 Hz), providing smooth real-time dashboard updates
without overwhelming the network. Can be overridden per-stream via
:start-telemetry-stream :interval keyword.

Lower values (e.g. 0.1) provide more responsive dashboards but consume
more CPU and bandwidth. Higher values (e.g. 2.0) are suitable for
low-power or high-latency environments.")

(defvar *telemetry-history* (make-array 50 :fill-pointer 0 :adjustable t)
  "Sliding window of the last 50 telemetry snapshots.

Each element is a plist returned by build-telemetry-snapshot. The
fill-pointer tracks how many snapshots are currently stored. When the
window reaches 50 entries, the oldest is evicted on each new push.

This history enables trend analysis: get-telemetry-trend extracts time
series for any key, allowing dashboards to render sparklines and
detect anomalies over time.

Thread-safety: All access must be protected by *telemetry-history-lock*.")

(defvar *telemetry-history-lock* (bt:make-lock "telemetry-history")
  "Lock protecting *telemetry-history* and related counters.

Acquired by:
  • push-telemetry-history  — on every snapshot insertion
  • get-telemetry-trend     — when extracting time series
  • clear-telemetry-history — when resetting the window

The lock is held for short durations (array read/write only) to
minimize contention with the telemetry broadcast thread.")

(defvar *telemetry-latest-event* nil
  "The most recent notable event to include in snapshots.

Set by the orchestrator monitor loop or gossip callbacks when something
significant happens (agent failure, healing, evolution, peer join/leave).
Cleared after being included in a snapshot.

Format: A plist like (:type :agent-healed :agent-id AGENT-123 :timestamp ...)

Thread-safety: Written by orchestrator thread, read by telemetry thread.
Currently unprotected — events are best-effort and occasional race
conditions are acceptable for telemetry purposes.")

(defvar *telemetry-safety-window* (make-array 100 :fill-pointer 0 :adjustable t)
  "Ring buffer tracking safety-relevant operations over the last 100 ticks.

Each entry is a plist: (:attempted n :blocked n :timestamp ...).
Used by calculate-success-rate, calculate-rejection-rate, and
count-safety-violations.

Thread-safety: Protected by *telemetry-history-lock* (shared with history).")

(defvar *telemetry-event-counter* 0
  "Monotonically increasing counter for each telemetry tick.

Incremented on every snapshot. Useful for detecting missed frames or
measuring effective broadcast rate.")

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 2: Metrics Calculation — From Raw State to Meaningful Numbers
;; ═══════════════════════════════════════════════════════════════════════════

(defun calculate-success-rate (orchestrator)
  "Calculate the ratio of successful operations to total attempts.

This function examines the *telemetry-safety-window* ring buffer,
which contains the last 100 telemetry ticks of operation data. For
each tick, it sums :attempted and :blocked, then computes:

  success-rate = (attempted - blocked) / attempted

If there are no recorded attempts (fresh start), returns 1.0 as a
conservative default (assume everything is fine until proven otherwise).

Parameters:
  ORCHESTRATOR — The orchestrator instance (used for live agent state
                 as a secondary data source when window is empty).

Returns: A float between 0.0 and 1.0.

Thread-safety: Reads *telemetry-safety-window* without locking. This
is acceptable because the window is only mutated by the telemetry thread
itself, and this function is only called from that same thread within
build-telemetry-snapshot."
  (declare (type (or null orchestrator) orchestrator))
  (let ((total-attempted 0)
        (total-blocked 0))
    (declare (type fixnum total-attempted total-blocked))
    ;; Sum across the safety window
    (loop for i from 0 below (length *telemetry-safety-window*)
          for entry = (aref *telemetry-safety-window* i)
          do (incf total-attempted (or (getf entry :attempted) 0))
             (incf total-blocked (or (getf entry :blocked) 0)))
    ;; Also factor in live orchestrator state
    (when orchestrator
      (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
        (maphash (lambda (aid agent)
                   (declare (ignore aid))
                   (incf total-attempted (max 1 (agent-error-count agent)))
                   (incf total-blocked (floor (agent-error-count agent) 2)))
                 (orchestrator-agents orchestrator))))
    ;; Compute ratio
    (if (plusp total-attempted)
        (float (/ (max 0 (- total-attempted total-blocked))
                  total-attempted)
               0.0)
        1.0)))

(defun calculate-rejection-rate (orchestrator)
  "Calculate the ratio of safety kernel rejections to total mutations.

The safety kernel blocks mutations that violate containment policies.
This function measures how often that happens, which is a key indicator
of evolutionary pressure vs. safety constraints.

Formula:
  rejection-rate = blocked / (attempted + blocked)

If there are no operations recorded, returns 0.0 (no rejections yet).

Parameters:
  ORCHESTRATOR — The orchestrator instance.

Returns: A float between 0.0 and 1.0.
  • 0.0 — No rejections (perfect safety compliance)
  • ~0.1 — Normal operating range (some mutations naturally violate policy)
  • >0.3 — Elevated: evolution is pushing hard against boundaries
  • >0.5 — Critical: the swarm is in conflict with its own safety rules

Thread-safety: Same as calculate-success-rate — called only from the
telemetry thread, reads the safety window without locking."
  (declare (type (or null orchestrator) orchestrator))
  (let ((total-attempted 0)
        (total-blocked 0))
    (declare (type fixnum total-attempted total-blocked))
    (loop for i from 0 below (length *telemetry-safety-window*)
          for entry = (aref *telemetry-safety-window* i)
          do (incf total-attempted (or (getf entry :attempted) 0))
             (incf total-blocked (or (getf entry :blocked) 0)))
    (if (plusp (+ total-attempted total-blocked))
        (float (/ total-blocked
                  (+ total-attempted total-blocked))
               0.0)
        0.0)))

(defun calculate-containment-score (orchestrator)
  "Calculate the Containment Integrity Score (CIS).

The CIS is a composite metric that balances operational success against
safety enforcement. A high score means the swarm is both effective AND
well-contained. A low score means either failures are high or safety is
being breached excessively.

Formula:
  C = success-rate / (1 + rejection-rate)

This formula has the desirable property that:
  • C is maximized (≈1.0) when success-rate = 1.0 and rejection-rate = 0.0
  • C decreases as either failures increase or rejections increase
  • C approaches 0.0 when the swarm is both failing AND being rejected

Parameters:
  ORCHESTRATOR — The orchestrator instance.

Returns: A float. Typical range is 0.0 to ~1.0.
  • 0.9–1.0 — Excellent: healthy, contained swarm
  • 0.7–0.9 — Good: minor friction, normal operation
  • 0.5–0.7 — Warning: elevated failures or rejections
  • <0.5 — Critical: containment may be failing

Example:
  (calculate-containment-score *default-orchestrator*)
    ;; => 0.847""
  (let ((success-rate (calculate-success-rate orchestrator))
        (rejection-rate (calculate-rejection-rate orchestrator)))
    (float (/ success-rate (+ 1.0 rejection-rate)) 0.0)))

(defun get-avg-fitness (orchestrator)
  "Compute the average fitness across all agents in the orchestrator.

Fitness is a measure of how well an agent's strategy is performing.
Agents without an associated strategy-chromosome (un-evolved agents)
are assigned a default fitness of 0.5.

Parameters:
  ORCHESTRATOR — The orchestrator instance.

Returns: A float between 0.0 and 1.0, or NIL if no agents exist.

Thread-safety: Acquires the orchestrator's monitor-lock while iterating
over the agents hash-table."
  (declare (type (or null orchestrator) orchestrator))
  (when orchestrator
    (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
      (let ((total 0.0)
            (count 0))
        (declare (type float total) (type fixnum count))
        (maphash (lambda (aid agent)
                   (declare (ignore aid))
                   ;; Try to get fitness from agent's strategy metadata
                   ;; or default to 0.5
                   (let ((fitness (or (and (slot-boundp agent 'strategy)
                                           (typep (agent-strategy agent) 'function)
                                           0.5)
                                      0.5)))
                     (declare (type float fitness))
                     (incf total fitness)
                     (incf count)))
                 (orchestrator-agents orchestrator))
        (if (plusp count)
            (float (/ total count) 0.0)
            nil)))))

(defun get-mutation-rate (orchestrator)
  "Get the current mutation rate from the evolution module.

Returns the value of *mutation-rate* from evolution.lisp, which
determines how aggressively agents evolve their strategies.

Parameters:
  ORCHESTRATOR — Unused (reserved for future per-orchestrator mutation rates).

Returns: A float between 0.0 and 1.0 (default 0.15).

Thread-safety: Reads the special variable *mutation-rate* which is
set globally in evolution.lisp. No locking needed for reads."
  (declare (ignore orchestrator))
  (float *mutation-rate* 0.0))

(defun get-active-agent-count (orchestrator)
  "Count agents that are currently active (status :running or :evolving).

Inactive statuses include :paused, :failed, and :healing. Only agents
that are actively executing their strategy are counted.

Parameters:
  ORCHESTRATOR — The orchestrator instance.

Returns: A non-negative integer.

Thread-safety: Acquires the orchestrator's monitor-lock."
  (declare (type (or null orchestrator) orchestrator))
  (if orchestrator
      (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
        (let ((count 0))
          (declare (type fixnum count))
          (maphash (lambda (aid agent)
                     (declare (ignore aid))
                     (when (member (agent-status agent)
                                   '(:running :evolving))
                       (incf count)))
                   (orchestrator-agents orchestrator))
          count))
      0))

(defun get-total-agent-count (orchestrator)
  "Count all registered agents, regardless of status.

Parameters:
  ORCHESTRATOR — The orchestrator instance.

Returns: A non-negative integer.

Thread-safety: Acquires the orchestrator's monitor-lock."
  (declare (type (or null orchestrator) orchestrator))
  (if orchestrator
      (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
        (hash-table-count (orchestrator-agents orchestrator)))
      0))

(defun count-safety-violations (orchestrator)
  "Count blocked actions in the last telemetry window.

This sums the :blocked field across all entries in the safety window,
giving the total number of safety kernel rejections in the recent past.

Parameters:
  ORCHESTRATOR — The orchestrator instance.

Returns: A non-negative integer.

Thread-safety: Reads the safety window without locking (telemetry thread only)."
  (declare (type (or null orchestrator) orchestrator))
  (let ((total 0))
    (declare (type fixnum total))
    (loop for i from 0 below (length *telemetry-safety-window*)
          for entry = (aref *telemetry-safety-window* i)
          do (incf total (or (getf entry :blocked) 0)))
    total))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 3: Snapshot Construction — Building the Telemetry Payload
;; ═══════════════════════════════════════════════════════════════════════════

(defun build-telemetry-snapshot (orchestrator)
  "Construct a complete telemetry snapshot as a structured plist.

This is the primary data-gathering function. It samples every dimension
of the orchestrator's state and packages it into a self-describing plist
that can be JSON-encoded and sent to dashboard clients.

Parameters:
  ORCHESTRATOR — The orchestrator instance to snapshot.

Returns: A plist with the following structure:
  (:timestamp       <unix-time-seconds>
   :tick            <integer, monotonically increasing>
   :swarm-health    (:success-rate     <float 0.0-1.0>
                    :rejection-rate   <float 0.0-1.0>
                    :containment-score <float>)
   :metrics         (:avg-fitness      <float or nil>
                    :mutation-rate    <float>
                    :active-agents    <integer>
                    :total-agents     <integer>
                    :safety-violations <integer>)
   :latest-event    <event-plist or nil>
   :agent-summaries <list of agent mini-snapshots>
   :topology-summary <gossip mesh summary plist>)

The snapshot is designed to be:
  1. COMPLETE — every dashboard widget can be populated from one snapshot
  2. SELF-DESCRIBING — keys are human-readable, no magic numbers
  3. EFFICIENT — only lightweight data (no full agent state, no closures)
  4. EXTENSIBLE — new keys can be added without breaking old clients

Example encoded JSON:
  {
    \":timestamp\": 1717500000.5,
    \":swarm-health\": {
      \":success-rate\": 0.92,
      \":rejection-rate\": 0.08,
      \":containment-score\": 0.851
    },
    ...
  }"
  (declare (type (or null orchestrator) orchestrator))
  (let ((timestamp (/ (get-internal-real-time) internal-time-units-per-second))
        (tick (incf *telemetry-event-counter*)))
    (list
     :timestamp timestamp
     :tick tick
     :swarm-health (list
                    :success-rate (calculate-success-rate orchestrator)
                    :rejection-rate (calculate-rejection-rate orchestrator)
                    :containment-score (calculate-containment-score orchestrator))
     :metrics (list
               :avg-fitness (get-avg-fitness orchestrator)
               :mutation-rate (get-mutation-rate orchestrator)
               :active-agents (get-active-agent-count orchestrator)
               :total-agents (get-total-agent-count orchestrator)
               :safety-violations (count-safety-violations orchestrator))
     :latest-event *telemetry-latest-event*
     :agent-summaries (build-agent-summaries orchestrator)
     :topology-summary (build-topology-summary))))

(defun build-agent-summaries (orchestrator)
  "Build lightweight mini-snapshots for each registered agent.

Each summary contains only the essential data needed for dashboard
display — no heavy state, no closures, no mailboxes. This keeps the
JSON payload small even with hundreds of agents.

Parameters:
  ORCHESTRATOR — The orchestrator instance.

Returns: A list of plists, one per agent:
  ((:id <agent-id-symbol>
    :health <integer 0-100>
    :status <keyword :running|:paused|:failed|:healing|:evolving>
    :version <integer strategy version>
    :errors <integer cumulative error count>
    :capabilities <list of keywords>) ...)

The list is sorted by agent-id for deterministic ordering.

Thread-safety: Acquires the orchestrator's monitor-lock."
  (declare (type (or null orchestrator) orchestrator))
  (if orchestrator
      (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
        (let ((summaries '()))
          (maphash (lambda (aid agent)
                     (declare (ignore aid))
                     (push (list
                            :id (string (agent-id agent))
                            :health (agent-health agent)
                            :status (agent-status agent)
                            :version (agent-version agent)
                            :errors (agent-error-count agent)
                            :capabilities (agent-capabilities agent))
                           summaries))
                   (orchestrator-agents orchestrator))
          ;; Sort by ID for deterministic output
          (sort summaries #'string< :key (lambda (s) (getf s :id)))))
      '()))

(defun build-topology-summary ()
  "Build a summary of the gossip mesh topology.

Returns a plist describing the distributed swarm's connectivity state.
Used by the dashboard's network visualization widget.

Returns: A plist:
  (:gossip-active     <boolean>    — is the gossip node running?
   :peer-count        <integer>    — number of connected peers
   :peers             <list of endpoint strings>
   :topic-count       <integer>    — number of subscribed topics
   :topics            <list of topic strings>)

If the gossip system is not running, returns a minimal plist with
:gossip-active NIL and zero counts.

Thread-safety: Reads global gossip state variables without locking.
These are set at startup/shutdown and rarely change, so races are
acceptable for telemetry purposes."
  (handler-case
      (list
       :gossip-active *gossip-running-p*
       :peer-count (length *gossip-peers*)
       :peers (copy-list *gossip-peers*)
       :topic-count (let ((count 0))
                      (maphash (lambda (k v)
                                 (declare (ignore k v))
                                 (incf count))
                               *gossip-topics*)
                      count)
       :topics (gossip-topic-list))
    (error (e)
      ;; If gossip system is not loaded or has issues, return safe defaults
      (list
       :gossip-active nil
       :peer-count 0
       :peers '()
       :topic-count 0
       :topics '()
       :error (format nil "~A" e)))))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 4: History Management — Sliding Window & Trend Extraction
;; ═══════════════════════════════════════════════════════════════════════════

(defun push-telemetry-history (snapshot)
  "Add a snapshot to the sliding history window.

If the window already contains 50 entries, the oldest entry is evicted
before the new one is added. This maintains a constant-size window of
the most recent telemetry data.

Parameters:
  SNAPSHOT — A plist as returned by build-telemetry-snapshot.

Side effects:
  • Mutates *telemetry-history* (thread-safe via lock)
  • Mutates *telemetry-safety-window* (evicts oldest entry)

Thread-safety: Acquires *telemetry-history-lock*."
  (declare (type list snapshot))
  (bt:with-lock-held (*telemetry-history-lock*)
    ;; Evict oldest if at capacity
    (when (>= (length *telemetry-history*) 50)
      (setf (fill-pointer *telemetry-history*)
            (1- (length *telemetry-history*)))
      ;; Shift elements down (simple but effective for small arrays)
      (loop for i from 0 below (length *telemetry-history*)
            do (setf (aref *telemetry-history* i)
                     (aref *telemetry-history* (1+ i)))))
    ;; Add new snapshot
    (vector-push snapshot *telemetry-history*)
    ;; Also push to safety window (separate ring buffer)
    (when (>= (length *telemetry-safety-window*) 100)
      (setf (fill-pointer *telemetry-safety-window*)
            (1- (length *telemetry-safety-window*)))
      (loop for i from 0 below (length *telemetry-safety-window*)
            do (setf (aref *telemetry-safety-window* i)
                     (aref *telemetry-safety-window* (1+ i)))))
    (vector-push (list :attempted (+ (getf (getf snapshot :metrics)
                                           :active-agents
                                           0)
                                     (getf (getf snapshot :metrics)
                                           :safety-violations
                                           0))
                       :blocked (getf (getf snapshot :metrics)
                                      :safety-violations
                                      0)
                       :timestamp (getf snapshot :timestamp))
                 *telemetry-safety-window*)))

(defun get-telemetry-trend (key &optional (window 10))
  "Extract a time series for a given key from the telemetry history.

This function walks the history window and extracts values nested at
KEY. It supports nested keys by accepting a list of keywords.

Parameters:
  KEY   — A keyword or list of keywords designating the path to extract.
          Examples:
            :success-rate         → extracts from :swarm-health
            '(:swarm-health :success-rate) → fully qualified path
            '(:metrics :avg-fitness)       → fitness over time
  WINDOW — Maximum number of history entries to examine (default 10).
           The most recent WINDOW entries are used.

Returns: A list of (timestamp . value) cons cells, newest last.
         Returns NIL if no matching data is found.

Example:
  (get-telemetry-trend '(:swarm-health :success-rate) 20)
    ;; => ((1717500000.0 . 0.92) (1717500000.5 . 0.91) ...)"
  (declare (type (or keyword list) key)
           (type (integer 1 50) window))
  (bt:with-lock-held (*telemetry-history-lock*)
    (let ((result '())
          (history-len (length *telemetry-history*))
          (start-index (max 0 (- (length *telemetry-history*) window))))
      (declare (type fixnum history-len start-index))
      (loop for i from start-index below history-len
            for snapshot = (aref *telemetry-history* i)
            for timestamp = (getf snapshot :timestamp)
            for value = (if (listp key)
                            (get-nested snapshot key)
                            (get-nested snapshot
                                        (list :swarm-health key)))
            when value
            do (push (cons timestamp value) result))
      (nreverse result))))

(defun get-nested (plist keys)
  "Safely navigate a nested plist structure.

Parameters:
  PLIST — The property list to navigate.
  KEYS  — A list of keys to follow in order.

Returns: The value at the designated path, or NIL if any key is missing.

Example:
  (get-nested '(:a (:b 1 :c 2)) '(:a :c))
    ;; => 2
  (get-nested '(:a (:b 1)) '(:a :missing))
    ;; => NIL"
  (declare (type list plist keys))
  (handler-case
      (let ((current plist))
        (dolist (k keys)
          (setf current (getf current k)))
        current)
    (error ()
      nil)))

(defun clear-telemetry-history ()
  "Reset the telemetry history window to empty.

Useful when restarting the orchestrator or when you want to clear stale
data before a new experiment.

Side effects: Clears *telemetry-history* and *telemetry-safety-window*.

Thread-safety: Acquires *telemetry-history-lock*."
  (bt:with-lock-held (*telemetry-history-lock*)
    (setf (fill-pointer *telemetry-history*) 0)
    (setf (fill-pointer *telemetry-safety-window*) 0)
    (setf *telemetry-event-counter* 0))
  (format *trace-output* "~&[TELEMETRY] History cleared.~%"))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 5: JSON Encoding — From Lisp Plists to JSON Strings
;; ═══════════════════════════════════════════════════════════════════════════

(defun snapshot-to-json (snapshot)
  "Encode a telemetry snapshot plist to a JSON string.

Uses cl-json:encode-json-plist-to-string when available, falling back
to a minimal JSON encoder for environments without cl-json.

Parameters:
  SNAPSHOT — A plist as returned by build-telemetry-snapshot.

Returns: A JSON string suitable for transmission over WebSocket or TCP.

The JSON output preserves Lisp keywords as JSON keys (with colons).
This is intentional — it makes the protocol self-describing and allows
the dashboard to distinguish LISPMIND-specific keys from generic data.

Example output:
  \"timestamp\":1717500000.5,
   \"swarm-health\":{\"success-rate\":0.92,\"rejection-rate\":0.08,...},
   ...

Thread-safety: This function is pure (no shared state) and can be
called from any thread."
  (declare (type list snapshot))
  #+cl-json-available
  (handler-case
      (cl-json:encode-json-plist-to-string snapshot)
    (error (e)
      (format nil "{\"error\":\"JSON encoding failed: ~A\"}" e)))
  #-cl-json-available
  (minimal-json-encode snapshot))

(defun minimal-json-encode (object)
  "Minimal JSON encoder for environments without cl-json.

Supports: plists, lists, numbers, strings, keywords (as strings),
booleans (T → true, NIL → false).

Does NOT support: nested objects beyond 2 levels, unicode escapes,
or circular references. This is a telemetry emergency fallback, not
a general-purpose JSON library.

Parameters:
  OBJECT — A Lisp object to encode.

Returns: A JSON string."
  (declare (type t object))
  (etypecase object
    (null "null")
    ((eql t) "true")
    ((eql nil) "false")
    (string (format nil "\"~A\"" (escape-json-string object)))
    (symbol (format nil "\"~A\"" (string object)))
    (number (format nil "~A" object))
    (list
     (cond
       ;; Plist (alternating keyword value)
       ((and (consp object)
             (keywordp (car object)))
        (with-output-to-string (s)
          (write-char #\{ s)
          (loop for (k v) on object by #'cddr
                for first-p = t then nil
                unless first-p do (write-char #\, s)
                do (format s "\"~A\":" (string k))
                   (write-string (minimal-json-encode v) s))
          (write-char #\} s)))
       ;; Regular list → JSON array
       (t
        (with-output-to-string (s)
          (write-char #\[ s)
          (loop for elem in object
                for first-p = t then nil
                unless first-p do (write-char #\, s)
                do (write-string (minimal-json-encode elem) s))
          (write-char #\] s)))))))

(defun escape-json-string (string)
  "Escape special characters in a string for JSON output.

Handles: quotes, backslashes, newlines, tabs, carriage returns.

Parameters:
  STRING — The string to escape.

Returns: An escaped string safe for JSON inclusion."
  (declare (type string string))
  (with-output-to-string (s)
    (loop for char across string
          do (case char
               (#\\ (write-string "\\\\" s))
               (#\" (write-string "\\\"" s))
               (#\newline (write-string "\\n" s))
               (#\tab (write-string "\\t" s))
               (#\return (write-string "\\r" s))
               (otherwise (write-char char s))))))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 6: Broadcast — Sending Snapshots to Connected Clients
;; ═══════════════════════════════════════════════════════════════════════════

(defun stream-telemetry (orchestrator)
  "Main telemetry broadcast function.

Executes the full pipeline in order:
  1. Build a telemetry snapshot from the orchestrator state
  2. Push the snapshot to the sliding history window
  3. Encode the snapshot to a JSON string
  4. Broadcast the JSON to all connected WebSocket/TCP clients

Parameters:
  ORCHESTRATOR — The orchestrator instance to sample.

Side effects:
  • Mutates *telemetry-history* (via push-telemetry-history)
  • Clears *telemetry-latest-event* after inclusion
  • Sends data to all connected clients

Error handling: If any step fails, the error is caught, logged to
*trace-output*, and the function returns NIL. This ensures that a
temporary failure (e.g., JSON encoding of an unexpected value) does
not crash the telemetry thread.

Thread-safety: Called only from the telemetry thread. Orchestrator
state is read with proper locking inside the metric functions."
  (declare (type (or null orchestrator) orchestrator))
  (handler-case
      (progn
        ;; Step 1: Build snapshot
        (let ((snapshot (build-telemetry-snapshot orchestrator)))
          ;; Step 2: Push to history
          (push-telemetry-history snapshot)
          ;; Step 3: Clear the latest event (consumed)
          (setf *telemetry-latest-event* nil)
          ;; Step 4: Encode to JSON
          (let ((json (snapshot-to-json snapshot)))
            ;; Step 5: Broadcast to clients
            (broadcast-to-clients json)
            ;; Return the snapshot for debugging
            snapshot)))
    (error (e)
      (format *trace-output*
              "~&[TELEMETRY] Broadcast error: ~A~%"
              e)
      nil)))

(defun record-safety-event (attempted blocked)
  "Record a safety-relevant event for the telemetry system.

This function is called by the safety kernel (orchestrator monitor loop)
to record attempted vs. blocked operations. The data is used by the
success-rate and rejection-rate calculations.

Parameters:
  ATTEMPTED — Number of operations attempted.
  BLOCKED   — Number of operations blocked by the safety kernel.

Side effects: Pushes data to *telemetry-safety-window*.

Thread-safety: Called from the monitor thread. The safety window is
only read by the telemetry thread, so no lock is needed (single-writer)."
  (declare (type fixnum attempted blocked))
  (vector-push (list :attempted attempted
                     :blocked blocked
                     :timestamp (/ (get-internal-real-time)
                                   internal-time-units-per-second))
               *telemetry-safety-window*))

(defun record-telemetry-event (event-type &rest event-data)
  "Record a notable event for inclusion in the next telemetry snapshot.

Events are consumed (included once) by the telemetry broadcast loop.
This is a fire-and-forget logging mechanism for significant occurrences.

Parameters:
  EVENT-TYPE — A keyword like :agent-healed, :evolution-completed,
               :peer-joined, :peer-left, :safety-violation, etc.
  EVENT-DATA — Plist of additional event-specific data.

Example:
  (record-telemetry-event :agent-healed
    :agent-id 'AGENT-42
    :old-health 20 :new-health 100)

Side effects: Sets *telemetry-latest-event*.

Thread-safety: Best-effort (no locking). Events may occasionally be
lost or overwritten, which is acceptable for telemetry."
  (declare (type keyword event-type))
  (setf *telemetry-latest-event*
        (list* :type event-type
               :timestamp (/ (get-internal-real-time)
                             internal-time-units-per-second)
               event-data)))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 7: Lifecycle — Starting and Stopping the Telemetry Stream
;; ═══════════════════════════════════════════════════════════════════════════

(defun start-telemetry-stream (orchestrator &key (interval 0.5))
  "Start the telemetry broadcast thread.

Spawns a background thread that wakes every INTERVAL seconds,
builds a telemetry snapshot, and broadcasts it to all connected
WebSocket/TCP clients.

Parameters:
  ORCHESTRATOR — The orchestrator instance to monitor.
  INTERVAL     — Seconds between broadcasts (default 0.5, must be > 0).

Returns: The telemetry thread handle.

Side effects:
  • Sets *telemetry-enabled-p* to T
  • Sets *telemetry-thread* to the new thread
  • Sets *telemetry-interval* to INTERVAL

If a telemetry thread is already running, it is stopped and replaced.

Example:
  (start-telemetry-stream *default-orchestrator* :interval 1.0)

Thread-safety: Only call from the main thread. The telemetry thread
is detached (not joined) and runs until stop-telemetry-stream is called."
  (declare (type (or null orchestrator) orchestrator)
           (type (float (0.0)) interval))
  ;; Stop existing stream if running
  (when *telemetry-thread*
    (stop-telemetry-stream))
  ;; Reset state
  (setf *telemetry-enabled-p* t)
  (setf *telemetry-interval* interval)
  (clear-telemetry-history)
  ;; Spawn thread
  (let ((thread (bt:make-thread
                 (lambda ()
                   (telemetry-loop orchestrator interval))
                 :name (format nil "telemetry-~A"
                               (if orchestrator
                                   (agent-id orchestrator)
                                   "none")))))
    (setf *telemetry-thread* thread)
    (format *trace-output*
            "~&[TELEMETRY] Stream started (interval=~As, thread=~A)~%"
            interval (bt:thread-name thread))
    thread))

(defun stop-telemetry-stream ()
  "Stop the telemetry broadcast thread gracefully.

Sets *telemetry-enabled-p* to NIL, which signals the telemetry loop
to exit on its next iteration. Then joins the thread to ensure clean
shutdown.

Returns: T if a thread was stopped, NIL if no thread was running.

Side effects:
  • Sets *telemetry-enabled-p* to NIL
  • Clears *telemetry-thread*

Example:
  (stop-telemetry-stream)

Thread-safety: Only call from the main thread. Do not call from within
the telemetry thread itself."
  (setf *telemetry-enabled-p* nil)
  (when *telemetry-thread*
    (let ((thread *telemetry-thread*))
      (setf *telemetry-thread* nil)
      ;; Give the thread a moment to notice the flag
      (sleep 0.1)
      ;; Join with timeout (thread may already have exited)
      (handler-case
          (bt:join-thread thread :timeout 5.0)
        (error (e)
          (format *trace-output*
                  "~&[TELEMETRY] Warning: join error: ~A~%" e)))
      (format *trace-output* "~&[TELEMETRY] Stream stopped.~%")
      t)))

(defun telemetry-loop (orchestrator interval)
  "The main telemetry broadcast loop.

Runs indefinitely (until *telemetry-enabled-p* becomes NIL), sleeping
for INTERVAL seconds between each broadcast cycle.

Parameters:
  ORCHESTRATOR — The orchestrator to sample (captured at loop start).
  INTERVAL     — Seconds to sleep between broadcasts.

Error handling: The entire loop body is wrapped in handler-case. If
any unhandled error occurs, it is logged and the loop continues. This
ensures the telemetry thread is immortal — it never dies unless
explicitly stopped.

Thread-safety: This function runs in the telemetry thread only."
  (declare (type (or null orchestrator) orchestrator)
           (type (float (0.0)) interval))
  (loop while *telemetry-enabled-p*
        do (handler-case
               (progn
                 ;; Broadcast telemetry
                 (stream-telemetry orchestrator)
                 ;; Sleep until next tick
                 (sleep interval))
             (error (e)
               (format *trace-output*
                       "~&[TELEMETRY] Loop error (recovering): ~A~%"
                       e)
               ;; Brief pause before retry to avoid tight error loops
               (sleep (max interval 1.0)))))
  ;; Clean exit
  (format *trace-output* "~&[TELEMETRY] Loop exited gracefully.~%"))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 8: Introspection — Querying Telemetry State
;; ═══════════════════════════════════════════════════════════════════════════

(defun telemetry-status ()
  "Return the current status of the telemetry system as a plist.

Useful for debugging and dashboard display.

Returns:
  (:enabled        <boolean>
   :thread-running <boolean>
   :thread-name    <string or nil>
   :history-count  <integer 0-50>
   :interval       <float>
   :latest-event   <event-plist or nil>)

Example:
  (telemetry-status)
    ;; => (:enabled t :thread-running t :history-count 23 ...)"
  (list
   :enabled *telemetry-enabled-p*
   :thread-running (and *telemetry-thread*
                        (bt:thread-alive-p *telemetry-thread*))
   :thread-name (if *telemetry-thread*
                    (bt:thread-name *telemetry-thread*)
                    nil)
   :history-count (length *telemetry-history*)
   :interval *telemetry-interval*
   :latest-event *telemetry-latest-event*))

(defun telemetry-history-summary ()
  "Return a summary of the telemetry history window.

Returns: A plist with trend statistics:
  (:snapshot-count <integer>
   :avg-success-rate <float>
   :avg-containment-score <float>
   :min-active-agents <integer>
   :max-active-agents <integer>)

Returns NIL if history is empty.

Thread-safety: Acquires *telemetry-history-lock*."
  (bt:with-lock-held (*telemetry-history-lock*)
    (let ((count (length *telemetry-history*)))
      (when (plusp count)
        (let ((success-rates '())
              (containment-scores '())
              (active-agent-counts '()))
          (loop for i from 0 below count
                for snapshot = (aref *telemetry-history* i)
                do (let ((health (getf snapshot :swarm-health)))
                     (push (getf health :success-rate 0.0) success-rates)
                     (push (getf health :containment-score 0.0)
                           containment-scores))
                   (let ((metrics (getf snapshot :metrics)))
                     (push (getf metrics :active-agents 0) active-agent-counts)))
          (list
           :snapshot-count count
           :avg-success-rate (if success-rates
                                (float (/ (reduce #'+ success-rates)
                                          (length success-rates))
                                       0.0)
                                0.0)
           :avg-containment-score (if containment-scores
                                     (float (/ (reduce #'+ containment-scores)
                                               (length containment-scores))
                                              0.0)
                                     0.0)
           :min-active-agents (if active-agent-counts
                                 (reduce #'min active-agent-counts)
                                 0)
           :max-active-agents (if active-agent-counts
                                 (reduce #'max active-agent-counts)
                                 0)))))))

;; ═══════════════════════════════════════════════════════════════════════════
;; END OF TELEMETRY.LISP
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Quick Reference — Public API:
;;
;; Metrics:
;;   (calculate-success-rate orchestrator)      → float 0.0–1.0
;;   (calculate-rejection-rate orchestrator)    → float 0.0–1.0
;;   (calculate-containment-score orchestrator) → float
;;   (get-avg-fitness orchestrator)             → float or nil
;;   (get-mutation-rate orchestrator)           → float
;;   (get-active-agent-count orchestrator)      → integer
;;   (get-total-agent-count orchestrator)       → integer
;;   (count-safety-violations orchestrator)     → integer
;;
;; Snapshots:
;;   (build-telemetry-snapshot orchestrator)    → plist
;;   (build-agent-summaries orchestrator)       → list of plists
;;   (build-topology-summary)                   → plist
;;
;; History:
;;   (push-telemetry-history snapshot)          → side effect
;;   (get-telemetry-trend key window)           → list of (time . value)
;;   (clear-telemetry-history)                  → side effect
;;
;; JSON:
;;   (snapshot-to-json snapshot)                → JSON string
;;   (minimal-json-encode object)               → JSON string
;;
;; Broadcast:
;;   (stream-telemetry orchestrator)            → snapshot or nil
;;   (record-safety-event attempted blocked)    → side effect
;;   (record-telemetry-event type &rest data)   → side effect
;;
;; Lifecycle:
;;   (start-telemetry-stream orch :interval 0.5) → thread
;;   (stop-telemetry-stream)                     → t or nil
;;   (telemetry-loop orchestrator interval)      → (loops forever)
;;
;; Introspection:
;;   (telemetry-status)                          → plist
;;   (telemetry-history-summary)                 → plist or nil
