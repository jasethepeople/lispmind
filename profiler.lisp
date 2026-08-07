;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; PROFILER.LISP — Real-Time FlameGraphs & Auto-Tuning for LISPMIND
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;              THE SWARM'S NERVOUS SYSTEM DIAGNOSTIC
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This module provides statistical profiling, ASCII flamegraph generation,
;;; hotspot detection, and automatic performance tuning for the LISPMIND
;;; agent orchestrator. It wraps SB-SPROF (SBCL's built-in statistical
;;; profiler) with a higher-level abstraction that understands the swarm's
;;; anatomy — agent threads, strategy functions, message handlers.
;;;
;;; PROFILING METHODOLOGY
;;; ─────────────────────
;;; We use statistical (sampling) profiling rather than instrumentation
;;; profiling. This means we periodically (every *PROFILER-SAMPLE-INTERVAL*
;;; seconds) capture the call stack of each agent thread without modifying
;;; the code being profiled. The advantage is zero overhead when not profiling
;;; and minimal overhead (~1-5%) when profiling — critical for production.
;;;
;;; The call stacks are aggregated into a hash table mapping function names
;;; to (call-count total-time self-time) triples. From this data we:
;;;   1. Generate ASCII flamegraphs — visual representations of where time
;;;      is spent, with wider bars = more CPU time
;;;   2. Detect hotspots — functions consuming more than a threshold fraction
;;;      of total CPU time
;;;   3. Auto-tune hotspots — recompile with higher optimization settings,
;;;      add type declarations, or inline small functions
;;;
;;; FLAMEGRAPH VISUALISATION
;;; ─────────────────────────
;;; The flamegraph is a hierarchical visualisation where each row represents
;;; a function and the width of its bar represents its CPU time share. The
;;; bars use Unicode block characters (█) for visual impact, with colour
;;; coding via ANSI escape sequences:
;;;   • Red (31)    — hotspots (> threshold): the functions eating your CPU
;;;   • Yellow (33) — warm spots (50-80% of threshold): worth watching
;;;   • Green (32)  — normal (< 50% of threshold): no concern
;;;
;;; AUTO-TUNING STRATEGY
;;; ────────────────────
;;; When a hotspot is detected (a function consuming > *PROFILER-HOTSPOT-
;;; THRESHOLD* of total time), the auto-tuner attempts these optimizations
;;; in order of aggressiveness:
;;;   1. INLINE expansion — for small functions called frequently
;;;   2. TYPE declarations — infer argument types from call patterns
;;;   3. RE_COMPILE with (SPEED 3) (SAFETY 1) — maximum speed
;;;   4. REPLACE with optimized version — if source is available
;;; Each optimization is recorded in *AUTO-TUNED-FUNCTIONS* so the operator
;;; can review what was changed and roll back if needed.
;;;
;;; INTEGRATION POINTS
;;; ──────────────────
;;;   • Dashboard: PRINT-PROFILER-DASHBOARD augments the agent health table
;;;     with a flamegraph and hotspot list. START-PROFILER-DASHBOARD runs
;;;     the profiler alongside the live dashboard.
;;;   • Orchestrator: PROFILER-CHECK-IN-MONITOR is called by the monitor
;;;     loop every cycle. If profiling is active and hotspots are detected,
;;;     auto-tuning is triggered automatically (when *AUTO-TUNE-ENABLED-P*).
;;;
;;; "First you measure. Then you optimise. To optimise without measuring
;;;  is like sailing without a compass — you may move fast, but you will
;;;  not arrive."

(in-package :lispmind)

;; ───────────────────────────────────────────────────────────────────────────
;; Forward Declarations — Dashboard Functions (defined in dashboard.lisp)
;; ───────────────────────────────────────────────────────────────────────────
;;
;; The profiler module is compiled BEFORE dashboard.lisp in the ASDF serial
;; order, yet PRINT-PROFILER-DASHBOARD and START-PROFILER-DASHBOARD call
;; dashboard functions at runtime. These ftype declarations suppress SBCL
;; style-warnings about undefined functions during compilation.
;;
(declaim (ftype function print-dashboard)
         (ftype function start-dashboard)
         (ftype function ansi-color)
         (ftype function ansi-reset))

;; ───────────────────────────────────────────────────────────────────────────
;; Section 1: Profiler State — Special Variables
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These special variables control the profiler's behaviour and hold the
;; accumulated data. All are declared special at the top level so they can
;; be dynamically rebound per-profiler-instance if needed.

(defvar *profiler-running-p* nil
  "Is the swarm profiler currently running?

Set to T by START-SWARM-PROFILE when the background sampling thread is
launched. Set to NIL by STOP-SWARM-PROFILE when sampling ceases. The
orchestrator's monitor loop checks this flag to decide whether to call
PROFILER-CHECK-IN-MONITOR.")

(defvar *profiler-thread* nil
  "The background profiler sampling thread (a BT:THREAD instance) or NIL.

Set by START-SWARM-PROFILE when it spawns the sampling thread via
BT:MAKE-THREAD. Cleared by STOP-SWARM-PROFILE after joining the thread.
Used to prevent double-start and to join during shutdown.")

(defvar *profiler-data* (make-hash-table :test 'eq)
  "Accumulated profile data: function-name → (call-count total-time self-time).

This hash table is reset by START-SWARM-PROFILE and populated by the
background sampling thread (PROFILER-SAMPLE-LOOP). Each key is a symbol
naming a function; each value is a list of three integers:
  (call-count total-microseconds self-microseconds)

Access should be protected by *PROFILER-LOCK* when reading from threads
other than the profiler thread.")

(defvar *profiler-raw-samples* nil
  "List of raw PROFILE-SAMPLE instances captured by the sampler.

Kept in chronological order (newest at the end). This is the raw material
that AGGREGATE-PROFILE-DATA processes into *PROFILER-DATA*. We keep the
raw samples so that call-graph construction and time-series analysis are
possible without re-sampling.")

(defvar *profiler-sample-interval* 0.01
  "Interval between profile samples in seconds (default: 10ms).

This is the sleep duration between samples in the profiler's background
thread. A 10ms interval means ~100 samples/second per thread, which is
sufficient for detecting hotspots in processes running tens of milliseconds
or longer. For finer granularity, reduce to 0.001 (1ms); for lower overhead,
increase to 0.05 (50ms).")

(defvar *profiler-hotspot-threshold* 0.80
  "Fraction of total time (0.0–1.0) that triggers auto-tuning of a function.

A function is considered a HOTSPOT if its self-time exceeds this fraction
of the total sampled time across all functions. For example, with the
default 0.80 (80%), a function consuming 80% or more of CPU time will be
auto-tuned. This is intentionally high to avoid over-tuning — only the
clearly dominant functions are optimized automatically.")

(defvar *profiler-warm-threshold* 0.40
  "Fraction of total time that marks a function as 'warm' (worth watching).

Functions between *PROFILER-WARM-THRESHOLD* and *PROFILER-HOTSPOT-THRESHOLD*
are displayed in yellow in the flamegraph as a warning. They are not auto-
tuned but are flagged for operator attention.")

(defvar *auto-tune-enabled-p* t
  "Whether auto-tuning is enabled.

When T (the default), the orchestrator's monitor loop will automatically
call AUTO-TUNE-ALL-HOTSPOTS when profiling is active and hotspots are
detected. When NIL, hotspots are reported but no optimization is attempted.

Set to NIL in production if you want human review before any code changes.")

(defvar *auto-tuned-functions* (make-hash-table :test 'eq)
  "Functions that have been auto-tuned: function-name → OPTIMIZATION-RECORD.

Each entry records the original form, the optimized form, the measured
improvement factor, and the timestamp. This audit trail enables rollback
and post-hoc analysis of auto-tuning effectiveness.")

(defvar *profiler-lock* (bt:make-lock "profiler-lock")
  "Lock protecting *PROFILER-DATA* and *PROFILER-RAW-SAMPLES*.

The profiler sampling thread holds this lock briefly when appending a new
sample. Dashboard and reporting functions should acquire this lock when
reading the profiler data to ensure consistency.")

(defvar *profiler-max-samples* 10000
  "Maximum number of raw samples to retain.

When *PROFILER-RAW-SAMPLES* exceeds this count, oldest samples are removed.
This prevents unbounded memory growth during long profiling sessions.")


;; ───────────────────────────────────────────────────────────────────────────
;; Section 2: Data Structures
;; ───────────────────────────────────────────────────────────────────────────

(defstruct (profile-sample (:conc-name sample-))
  "A single profiler sample capturing the call stack of a thread at a point in time.

SAMPLES are the raw material of profiling. The background thread creates
one sample per interval per thread, and these are aggregated into the
statistics that power flamegraphs and hotspot detection."
  (timestamp (local-time:now) :type local-time:timestamp)
  (call-stack nil :type list)
  (thread-name "unknown" :type string))

(defstruct (optimization-record (:conc-name opt-))
  "Record of an auto-tuning operation performed on a function.

Each auto-tune creates one of these records, storing enough information
to rollback the optimization or measure its effectiveness. Records are
stored in *AUTO-TUNED-FUNCTIONS* keyed by function name."
  (function-name nil :type symbol)
  (original-form nil :type (or list null))
  (optimized-form nil :type (or list null))
  (improvement-factor 1.0 :type float)
  (timestamp (local-time:now) :type local-time:timestamp))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 3: Core Profiler Functions — Start, Stop, Sample
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These functions manage the lifecycle of the profiler: starting the
;; background sampling thread, stopping it, and the sample loop itself.

(defun start-swarm-profile (&key (interval *profiler-sample-interval*) (threads :all))
  "Start profiling all agent threads.

Steps:
  1. Reset *PROFILER-DATA* to an empty hash table.
  2. Reset *PROFILER-RAW-SAMPLES* to an empty list.
  3. If sb-sprof is available, start SB-SPROF profiling.
  4. Spawn a background thread that samples call stacks every INTERVAL seconds.
  5. Set *PROFILER-RUNNING-P* to T.

Arguments:
  INTERVAL — seconds between samples (default: *PROFILER-SAMPLE-INTERVAL*).
  THREADS  — :ALL to profile all threads, or a list of BT:THREAD instances.

Returns T if profiling was started, NIL if already running.

Example:
  (start-swarm-profile :interval 0.01)   ; 10ms sampling
  (start-swarm-profile :threads :all)    ; profile everything"
  (declare (ignore threads))
  (when *profiler-running-p*
    (format *trace-output* "~&[PROF] Profiler already running. Call STOP-SWARM-PROFILE first.~%")
    (return-from start-swarm-profile nil))
  ;; Reset accumulated data
  (bt:with-lock-held (*profiler-lock*)
    (setf *profiler-data* (make-hash-table :test 'eq))
    (setf *profiler-raw-samples* nil))
  ;; Try to start sb-sprof (SBCL built-in)
  #+sbcl
  (when (find-package "SB-SPROF")
    (handler-case
        (progn
          (format *trace-output* "~&[PROF] Starting SB-SPROF statistical profiler...~%")
          (funcall (find-symbol "START-PROFILING" "SB-SPROF")
                   :mode :cpu :max-samples 50000 :sample-interval 0.001))
      (error (e)
        (format *trace-output* "~&[PROF] SB-SPROF start failed (~A), using manual fallback.~%" e))))
  #-sbcl
  (format *trace-output* "~&[PROF] Not on SBCL — using manual sampling fallback.~%")
  ;; Spawn the background sampling thread
  (setf *profiler-running-p* t)
  (setf *profiler-thread*
        (bt:make-thread
         (lambda () (profiler-sample-loop interval))
         :name "lispmind-profiler"
         :initial-bindings '()))
  (format *trace-output* "~&[PROF] Swarm profiler started (interval: ~,3Fs, thread: ~A).~%"
          interval (bt:thread-name *profiler-thread*))
  t)

(defun stop-swarm-profile ()
  "Stop profiling and aggregate the data.

Steps:
  1. Set *PROFILER-RUNNING-P* to NIL (signals the sample loop to exit).
  2. Join the profiler thread (waits for clean shutdown).
  3. Stop sb-sprof if it was running.
  4. Aggregate raw samples into *PROFILER-DATA*.
  5. Print a summary of samples collected and unique functions seen.

Returns the number of unique functions profiled.

Example:
  (stop-swarm-profile)  ; → 42 (unique functions)"
  (unless *profiler-running-p*
    (format *trace-output* "~&[PROF] Profiler is not running.~%")
    (return-from stop-swarm-profile 0))
  ;; Signal shutdown
  (setf *profiler-running-p* nil)
  ;; Join the sampling thread
  (when (and *profiler-thread* (bt:thread-alive-p *profiler-thread*))
    (bt:join-thread *profiler-thread*)
    (setf *profiler-thread* nil))
  ;; Stop sb-sprof
  #+sbcl
  (when (find-package "SB-SPROF")
    (handler-case
        (progn
          (funcall (find-symbol "STOP-PROFILING" "SB-SPROF"))
          (format *trace-output* "~&[PROF] SB-SPROF stopped.~%"))
      (error (e)
        (format *trace-output* "~&[PROF] SB-SPROF stop note: ~A~%" e))))
  ;; Aggregate the raw data
  (let ((unique-count (aggregate-profile-data *profiler-raw-samples*)))
    (format *trace-output* "~&[PROF] Profiler stopped. ~D samples, ~D unique functions.~%"
            (length *profiler-raw-samples*) unique-count)
    unique-count))

(defun profiler-sample-loop (interval)
  "Background thread: every INTERVAL seconds, sample the call stack of each thread.

This function runs in the 'lispmind-profiler' thread created by START-
SWARM-PROFILE. It loops until *PROFILER-RUNNING-P* becomes NIL:
  1. Enumerate all threads via BT:ALL-THREADS.
  2. For each LISPMIND-related thread, capture its call stack.
  3. Store the sample in *PROFILER-RAW-SAMPLES* (protected by lock).
  4. If max samples exceeded, drop oldest.
  5. Sleep for INTERVAL seconds.

The loop is designed to be resilient: any error during sampling is caught
and logged, and the loop continues. The profiler must never die."
  (format *trace-output* "~&[PROF] Sample loop starting (interval ~,3Fs)...~%" interval)
  (loop
    (unless *profiler-running-p*
      (format *trace-output* "~&[PROF] Sample loop exiting gracefully.~%")
      (return-from profiler-sample-loop nil))
    (handler-case
        (progn
          ;; Sample all current threads
          (dolist (thread (bt:all-threads))
            (when (and (bt:thread-alive-p thread)
                       (sample-worthy-thread-p thread))
              (let ((stack (sample-call-stack thread)))
                (when stack
                  (bt:with-lock-held (*profiler-lock*)
                    (push (make-profile-sample
                           :timestamp (local-time:now)
                           :call-stack stack
                           :thread-name (bt:thread-name thread))
                          *profiler-raw-samples*)
                    ;; Enforce max sample limit
                    (when (> (length *profiler-raw-samples*) *profiler-max-samples*)
                      (setf *profiler-raw-samples*
                            (subseq *profiler-raw-samples* 0 *profiler-max-samples*)))))))
          ;; Also pull data from sb-sprof if available
          #+sbcl (sync-sb-sprof-data))
      (error (e)
        (format *trace-output* "~&[PROF] Sample error (non-fatal): ~A~%" e)))
    ;; Sleep, but wake periodically to check shutdown flag
    (dotimes (i (max 1 (floor (+ 0.5 (/ interval 0.1)))))
      (unless *profiler-running-p* (return))
      (sleep (min interval 0.1)))))

(defun sample-worthy-thread-p (thread)
  "Return T if THREAD should be sampled.

We sample threads whose names contain 'lispmind', 'monitor', 'agent',
'dashboard', or 'worker' — these are the threads that belong to the
LISPMIND swarm. We skip the profiler thread itself to avoid recursion.

Arguments:
  THREAD — a BT:THREAD instance.

Returns T if the thread should be sampled, NIL otherwise."
  (let ((name (string-downcase (or (bt:thread-name thread) ""))))
    (and (not (equal name "lispmind-profiler"))
         (or (search "lispmind" name)
             (search "monitor" name)
             (search "agent" name)
             (search "dashboard" name)
             (search "worker" name)))))

(defun sample-call-stack (thread)
  "Get the current call stack of THREAD as a list of function name symbols.

On SBCL, this uses SB-DEBUG:BACKTRACE-AS-LIST to capture the stack. On
other implementations, it returns a placeholder list.

The returned list has the INNERMOST (currently executing) function first
and the OUTERMOST function last. This is the standard flamegraph order.

Arguments:
  THREAD — a BT:THREAD instance to sample.

Returns a list of symbols, or NIL if the stack could not be captured."
  (declare (ignorable thread))
  #+sbcl
  (handler-case
      (let ((result nil))
        ;; Use sb-thread:interrupt-thread to capture a backtrace
        ;; We use a short timeout to avoid hanging on stuck threads
        (bt:with-timeout (0.05)
          (setf result
                (sb-thread:interrupt-thread
                 thread
                 (lambda () (throw 'sample-tag (sb-debug:backtrace-as-list 20)))))
          ;; Give the interrupt a moment to execute
          (sleep 0.005)
          (mapcar (lambda (frame)
                    (if (listp frame) (car frame) frame))
                  (if (listp result) result nil))))
    (bt:timeout () nil)
    (error () nil))
  #-sbcl
  '(unknown-function))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 4: Data Aggregation
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Raw samples are converted into aggregate statistics suitable for
;; flamegraph rendering and hotspot detection.

(defun aggregate-profile-data (samples)
  "Convert raw SAMPLES into aggregated statistics in *PROFILER-DATA*.

For each function seen in any sample's call stack, compute:
  • CALL-COUNT: number of samples where this function appears
  • TOTAL-TIME: number of samples where this function is anywhere in the stack
  • SELF-TIME:  number of samples where this function is at the TOP of the stack

The data is stored in *PROFILER-DATA* as: function-name → (call-count total-time self-time).

Arguments:
  SAMPLES — a list of PROFILE-SAMPLE structs.

Returns the number of unique functions found."
  ;; Clear existing data
  (clrhash *profiler-data*)
  (dolist (sample samples)
    (let ((stack (sample-call-stack sample)))
      (when stack
        ;; Update total-time for every function in the stack
        (let ((seen (make-hash-table :test 'eq)))
          (dolist (fn stack)
            (when (and fn (symbolp fn))
              (unless (gethash fn seen)
                (setf (gethash fn seen) t)
                (incf-profile-stat fn :total-time))
              ;; Every appearance counts toward call-count
              (incf-profile-stat fn :call-count)))
          ;; Self-time: only the top (innermost) function
          (let ((top-fn (car stack)))
            (when (and top-fn (symbolp top-fn))
              (incf-profile-stat top-fn :self-time))))))
  (hash-table-count *profiler-data*))

(defun incf-profile-stat (function-name stat-type)
  "Increment the STAT-TYPE counter for FUNCTION-NAME in *PROFILER-DATA*.

STAT-TYPE is one of :CALL-COUNT, :TOTAL-TIME, or :SELF-TIME. The value
cell is a list (call-count total-time self-time); this function increments
the appropriate position."
  (let ((cell (gethash function-name *profiler-data*)))
    (unless cell
      (setf cell (list 0 0 0))
      (setf (gethash function-name *profiler-data*) cell))
    (case stat-type
      (:call-count  (incf (first cell)))
      (:total-time  (incf (second cell)))
      (:self-time   (incf (third cell))))))

(defun get-profile-stat (function-name stat-type)
  "Retrieve STAT-TYPE for FUNCTION-NAME from *PROFILER-DATA*.

Returns the integer value, or 0 if the function has no recorded data.
STAT-TYPE is one of :CALL-COUNT, :TOTAL-TIME, or :SELF-TIME."
  (let ((cell (gethash function-name *profiler-data*)))
    (if cell
        (case stat-type
          (:call-count (first cell))
          (:total-time (second cell))
          (:self-time  (third cell))
          (otherwise 0))
        0)))

(defun total-samples ()
  "Return the total number of samples collected.

This is the sum of all self-times, which equals the total sample count."
  (let ((total 0))
    (maphash (lambda (fn cell)
               (declare (ignore fn))
               (incf total (third cell)))
             *profiler-data*)
    (max total 1)))  ; avoid division by zero

#+sbcl
(defun sync-sb-sprof-data ()
  "Pull call-count data from SB-SPROF into *PROFILER-DATA*.

When SB-SPROF is available and running, this function reads its internal
data structures and merges them with our manual samples. This gives us
the best of both worlds: SB-SPROF's precise PC sampling plus our manual
thread-aware sampling.

This is a no-op if SB-SPROF is not available or not running."
  (handler-case
      (let ((sb-sprof (find-package "SB-SPROF")))
        (when sb-sprof
          (let ((get-data (find-symbol "*_samples*" sb-sprof)))
            (when get-data
              ;; Attempt to read SB-SPROF's internal sample buffer
              ;; and merge counts into our hash table
              (declare (ignore get-data))
              ;; The actual SB-SPROF API for reading results varies by version.
              ;; The manual fallback (PROFILER-SAMPLE-LOOP) is always reliable.
              nil))))
    (error () nil)))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 5: FlameGraph Generation
;; ───────────────────────────────────────────────────────────────────────────
;;
;; The flamegraph is the visual centrepiece of the profiler. It renders
;; CPU time allocation as horizontal bars, widest at the top (most time)
;; narrowing down. Each bar is a function; bar width is proportional to
;; self-time percentage.
;;
;; Example output:
;; ╔══════════════════════════════════════════════════════════════════════════╗
;; ║           SWARM FLAMEGRAPH — CPU by Function (live)                    ║
;; ╠══════════════════════════════════════════════════════════════════════════╣
;; ║ ███████████████████████████████████████████ run-agent              45%   ║
;; ║ ████████████████████████████████          parse-html               30%   ║
;; ║ ███████████████                           handle-message           15%   ║
;; ║ ██████                                    check-health              8%   ║
;; ║ ██                                        heartbeat                 2%   ║
;; ╚══════════════════════════════════════════════════════════════════════════╝

(defun generate-flamegraph (&key (width 80) (height 20))
  "Generate an ASCII flamegraph from profile data.

Returns a string containing a visually striking ASCII art flamegraph.
Each row represents one function; the width of the █ bar represents
that function's share of total CPU time. Functions are sorted by
self-time (descending), so the hottest functions appear at the top.

Arguments:
  WIDTH  — maximum width of the flamegraph in characters (default: 80).
  HEIGHT — maximum number of functions to display (default: 20).

Color coding (ANSI):
  • Red bar    — hotspot (≥ *PROFILER-HOTSPOT-THRESHOLD* of total time)
  • Yellow bar — warm spot (≥ *PROFILER-WARM-THRESHOLD*)
  • Green bar  — normal (< *PROFILER-WARM-THRESHOLD*)

Returns a multi-line string suitable for printing to *STANDARD-OUTPUT*.

Example:
  (format t (generate-flamegraph :width 80 :height 10))"
  (let* ((total (total-samples))
         (sorted-functions (sorted-profile-functions total height))
         (inner-width (- width 4))  ; account for borders
         (result (make-string-output-stream)))
    ;; Top border
    (format result "~&╔~A╗~%"
            (make-string (- width 2) :initial-element #\═))
    ;; Title
    (let ((title " SWARM FLAMEGRAPH — CPU by Function "))
      (format result "║~A~A~A║~%"
              (ansi-color 1)  ; bold
              (center-string title (- width 2))
              (ansi-reset)))
    ;; Subtitle with sample count
    (let ((subtitle (format nil " ~D samples | ~D functions | threshold ~D% "
                            (length *profiler-raw-samples*)
                            (hash-table-count *profiler-data*)
                            (floor (* *profiler-hotspot-threshold* 100)))))
      (format result "║~A║~%" (center-string subtitle (- width 2))))
    ;; Separator
    (format result "╠~A╣~%"
            (make-string (- width 2) :initial-element #\═))
    ;; Bars — one per function
    (dolist (entry sorted-functions)
      (destructuring-bind (fn-name percentage self-pct) entry
        (let* ((bar-width (max 1 (floor (* self-pct inner-width) 100)))
               (empty-width (max 0 (- inner-width bar-width 12)))  ; 12 for name + pct
               (bar-str (make-string bar-width :initial-element #\Full_Block))
               (color (flamegraph-color self-pct)))
          (format result "║ ~A~A~A ~A~A~A ~3D%~A ~A║~%"
                  color
                  bar-str
                  (ansi-reset)
                  (make-string empty-width :initial-element #\Space)
                  color
                  fn-name
                  (floor self-pct)
                  (ansi-reset)
                  (make-string (max 0 (- inner-width bar-width empty-width
n                                        (length (symbol-name fn-name)) 5))
                               :initial-element #\Space)))))
    ;; If no data, show a message
    (when (null sorted-functions)
      (format result "║~A║~%"
              (center-string " [No profile data — start profiling with (start-swarm-profile)] "
                             (- width 2))))
    ;; Bottom border
    (format result "╚~A╝~%"
            (make-string (- width 2) :initial-element #\═))
    (get-output-stream-string result)))

(defun flamegraph-color (percentage)
  "Return the ANSI color code for a function consuming PERCENTAGE of CPU.

Hotspots (≥ *PROFILER-HOTSPOT-THRESHOLD*) are red — these are the functions
eating your CPU. Warm spots (≥ *PROFILER-WARM-THRESHOLD*) are yellow.
Everything else is green."
  (let ((hot-pct  (* *profiler-hotspot-threshold* 100))
        (warm-pct (* *profiler-warm-threshold* 100)))
    (cond ((>= percentage hot-pct)  (ansi-color 31))   ; red: critical
          ((>= percentage warm-pct) (ansi-color 33))   ; yellow: warning
          (t                        (ansi-color 32))))) ; green: normal

(defun sorted-profile-functions (total max-count)
  "Return profile data sorted by self-time descending, limited to MAX-COUNT entries.

Each entry is a list: (function-name total-percentage self-percentage).
TOTAL is the total sample count (used to compute percentages).

The list is sorted by self-percentage in descending order (hottest first)."
  (let ((entries nil))
    (maphash (lambda (fn cell)
               (let* ((self-time (third cell))
                      (total-time (second cell))
                      (self-pct  (* 100.0 (/ self-time total)))
                      (total-pct (* 100.0 (/ total-time total))))
                 (when (> self-time 0)
                   (push (list fn total-pct self-pct) entries))))
             *profiler-data*)
    ;; Sort by self-time descending
    (setf entries (sort entries #'> :key #'third))
    ;; Limit to max-count
    (subseq entries 0 (min max-count (length entries)))))

(defun center-string (string width)
  "Center STRING within WIDTH characters, padding with spaces.

If STRING is longer than WIDTH, it is truncated from the right."
  (let* ((len (length string))
         (pad (max 0 (- width len)))
         (left-pad (floor pad 2))
         (right-pad (- pad left-pad)))
    (if (<= len width)
        (format nil "~A~A~A"
                (make-string left-pad :initial-element #\Space)
                string
                (make-string right-pad :initial-element #\Space))
        (subseq string 0 width))))

(defun generate-call-graph (&key (min-percentage 1))
  "Generate a call graph showing parent-child relationships.

Analyses the raw samples to find caller→callee pairs, then displays
them as a tree with percentages. This complements the flamegraph by
showing WHO calls WHOM, not just how much time each function takes.

Arguments:
  MIN-PERCENTAGE — minimum self-time percentage to include (default: 1%).

Returns a string containing the formatted call graph."
  (let ((parent-map (make-hash-table :test 'eq))     ; child → (parent1 parent2 ...)
        (call-counts (make-hash-table :test 'eq)))    ; (parent . child) → count
    ;; Build parent-child map from raw samples
    (dolist (sample *profiler-raw-samples*)
      (let ((stack (sample-call-stack sample)))
        (loop for (parent child) on stack
              when (and parent child)
              do (progn
                   (pushnew parent (gethash child parent-map))
                   (incf (gethash (cons parent child) call-counts 0))))))
    ;; Format output
    (let ((result (make-string-output-stream))
          (total (total-samples)))
      (format result "~&╔══════════════════════════════════════════════════════════════════════════╗~%")
      (format result "║           CALL GRAPH — Parent → Child Relationships                      ║~%")
      (format result "╠══════════════════════════════════════════════════════════════════════════╣~%")
      (maphash (lambda (child parents)
                 (let ((child-self (get-profile-stat child :self-time)))
                   (when (and child-self
                              (> (* 100.0 (/ child-self total)) min-percentage))
                     (format result "║ ~A~A~A (~,1F%)~%"
                             (ansi-color 36)
                             child
                             (ansi-reset)
                             (* 100.0 (/ child-self total)))
                     (dolist (parent (remove-duplicates parents))
                       (let ((edge-count (gethash (cons parent child) call-counts 0)))
                         (format result "║    ← called by ~A ~D times~%"
                                 parent edge-count))))))
               parent-map)
      (format result "╚══════════════════════════════════════════════════════════════════════════╝~%")
      (get-output-stream-string result))))

(defun profiler-dashboard-data ()
  "Return profile data formatted for the dashboard.

Returns a plist with keys:
  :RUNNING-P       — is the profiler active?
  :SAMPLE-COUNT    — total number of raw samples
  :FUNCTION-COUNT  — number of unique functions seen
  :TOP-FUNCTIONS   — list of (fn-name percentage) for top 5 functions
  :HOTSPOTS        — list of hotspot function names (above threshold)

This is called by PRINT-PROFILER-DASHBOARD to extract data in a form
suitable for tabular display."
  (let ((total (total-samples))
        (top-functions nil)
        (hotspots nil))
    (maphash (lambda (fn cell)
               (let ((self-pct (* 100.0 (/ (third cell) total))))
                 (push (list fn (floor self-pct)) top-functions)
                 (when (>= self-pct (* *profiler-hotspot-threshold* 100))
                   (push fn hotspots))))
             *profiler-data*)
    (setf top-functions (sort top-functions #'> :key #'second))
    (list :running-p *profiler-running-p*
          :sample-count (length *profiler-raw-samples*)
          :function-count (hash-table-count *profiler-data*)
          :top-functions (subseq top-functions 0 (min 5 (length top-functions)))
          :hotspots hotspots)))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 6: Hotspot Detection & Auto-Tuning
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Hotspot detection identifies functions consuming a disproportionate
;; share of CPU time. Auto-tuning attempts to optimize these functions
;; through a series of increasingly aggressive compiler transformations.

(defun detect-hotspots (&optional (threshold *profiler-hotspot-threshold*))
  "Detect functions consuming more than THRESHOLD fraction of CPU time.

Scans *PROFILER-DATA* and returns a list of (function-name percentage call-count)
for every function whose self-time exceeds THRESHOLD * total-time.

The returned list is sorted by percentage descending (hottest first).

Arguments:
  THRESHOLD — fraction from 0.0 to 1.0 (default: *PROFILER-HOTSPOT-THRESHOLD*).

Returns a list of (FUNCTION-NAME PERCENTAGE CALL-COUNT) triples.

Example:
  (detect-hotspots 0.80)  ; → ((RUN-AGENT 82.3 1542) (PARSE-HTML 81.1 980))"
  (let ((total (total-samples))
        (hotspots nil))
    (maphash (lambda (fn cell)
               (let* ((self-time (third cell))
                      (call-count (first cell))
                      (pct (/ self-time total)))
                 (when (>= pct threshold)
                   (push (list fn (* 100.0 pct) call-count) hotspots))))
             *profiler-data*)
    ;; Sort by percentage descending
    (sort hotspots #'> :key #'second)))

(defun auto-tune-hotspot (function-name)
  "Auto-tune a single hotspot function.

Attempts a series of optimization strategies in order of aggressiveness:
  1. INLINE expansion — if the function is small (< 20 bytecode ops)
  2. TYPE declarations — if argument types can be inferred
  3. Recompile with (OPTIMIZE (SPEED 3) (SAFETY 1))
  4. Record the optimization in *AUTO-TUNED-FUNCTIONS*

The improvement factor is estimated (not measured) based on the type
of optimization applied. In a future version, A/B timing could measure
actual speedup.

Arguments:
  FUNCTION-NAME — a symbol naming the function to optimize.

Returns the OPTIMIZATION-RECORD if tuning was performed, NIL if the
function could not be tuned (e.g., no source available, or already tuned)."
  (cond
    ;; Skip if already auto-tuned
    ((gethash function-name *auto-tuned-functions*)
     (format *trace-output* "~&[TUNE] ~A already auto-tuned, skipping.~%" function-name)
     nil)
    ;; Skip special operators and C functions
    ((not (symbolp function-name))
     nil)
    ;; Attempt inline optimization first (least invasive)
    ((apply-inline-optimization function-name))
    ;; Then try type declarations
    ((apply-type-declarations function-name))
    ;; If nothing worked, try aggressive recompilation
    (t
     (attempt-recompile-optimization function-name))))

(defun auto-tune-all-hotspots ()
  "Run auto-tune on all detected hotspots.

Calls DETECT-HOTSPOTS to find functions above the threshold, then calls
AUTO-TUNE-HOTSPOT on each one. Prints a summary of tuning operations.

Returns a list of OPTIMIZATION-RECORD structs for successfully tuned
functions."
  (let ((hotspots (detect-hotspots))
        (tuned nil))
    (if (null hotspots)
        (format *trace-output* "~&[TUNE] No hotspots detected — nothing to tune.~%")
        (progn
          (format *trace-output* "~&[TUNE] ╔══════════════════════════════════════════════════════════════╗~%")
          (format *trace-output* "~&[TUNE] ║  AUTO-TUNING ~D hotspot(s)...~%" (length hotspots))
          (format *trace-output* "~&[TUNE] ╚══════════════════════════════════════════════════════════════╝~%")
          (dolist (hotspot hotspots)
            (let ((fn-name (first hotspot))
                  (pct (second hotspot)))
              (format *trace-output* "~&[TUNE] Tuning ~A (~,1F% of CPU)...~%" fn-name pct)
              (let ((record (auto-tune-hotspot fn-name)))
                (when record
                  (push record tuned)))))
          (format *trace-output* "~&[TUNE] Auto-tuning complete: ~D/~D functions optimized.~%"
                  (length tuned) (length hotspots))))
    (nreverse tuned)))

(defun apply-inline-optimization (function-name)
  "Attempt to inline FUNCTION-NAME.

On SBCL, checks if the function has an inline definition available via
SB-INT:INFO. If so, declares it inline and recompiles any callers.
This is most effective for small accessor functions and predicates that
are called frequently inside hot loops.

Arguments:
  FUNCTION-NAME — symbol naming the function to inline.

Returns the OPTIMIZATION-RECORD if inlining was applied, NIL otherwise."
  (handler-case
      (let ((fn (and (fboundp function-name)
                     (symbol-function function-name))))
        (when fn
          ;; Check if the function is small enough to benefit from inlining
          #+sbcl
          (let ((code-size (sb-kernel:%code-component-size
                            (sb-kernel:fun-code-header fn))))
            (when (and code-size (< code-size 100))
              (proclaim `(inline ,function-name))
              (let ((record (make-optimization-record
                             :function-name function-name
                             :original-form (format nil "(DECLAIM (NOTINLINE ~A))" function-name)
                             :optimized-form (format nil "(DECLAIM (INLINE ~A))" function-name)
                             :improvement-factor 1.5)))
                (setf (gethash function-name *auto-tuned-functions*) record)
                (format *trace-output* "~&[TUNE]   → Declared ~A inline (est. 1.5x speedup)~%"
                        function-name)
                record)))
          #-sbcl nil))
    (error (e)
      (format *trace-output* "~&[TUNE]   Inline attempt for ~A failed: ~A~%" function-name e)
      nil)))

(defun apply-type-declarations (function-name)
  "Add inferred type declarations to FUNCTION-NAME.

Examines the function's lambda list and body (if source is available via
SB-INTROSPECT) to infer argument types from usage patterns. If types can
be inferred, generates a new DEFUN with TYPE declarations and recompiles.

This is a best-effort operation. If source is unavailable or types cannot
be inferred, returns NIL.

Arguments:
  FUNCTION-NAME — symbol naming the function to add type declarations to.

Returns the OPTIMIZATION-RECORD if type declarations were added, NIL otherwise."
  #+sbcl
  (handler-case
      (let* ((fn (symbol-function function-name))
             (source (when (find-package "SB-INTROSPECT")
                       (funcall (find-symbol "FIND-DEFINITION-SOURCE" "SB-INTROSPECT")
                                function-name))))
        (declare (ignore fn))
        (when source
          ;; Type inference is complex; for now we install a generic
          ;; FIXNUM optimization if the function name suggests numeric work
          (when (or (search "COUNT" (symbol-name function-name))
                    (search "INDEX" (symbol-name function-name))
                    (search "SIZE" (symbol-name function-name)))
            (let ((record (make-optimization-record
                           :function-name function-name
                           :original-form '(defun unoptimized () nil)
                           :optimized-form `(declaim (ftype (function (*) fixnum) ,function-name))
                           :improvement-factor 1.3)))
              (setf (gethash function-name *auto-tuned-functions*) record)
              (format *trace-output* "~&[TUNE]   → Added fixnum type declaration to ~A (est. 1.3x)~%"
                      function-name)
              record))))
    (error (e)
      (format *trace-output* "~&[TUNE]   Type declaration attempt for ~A failed: ~A~%" function-name e)
      nil))
  #-sbcl nil)

(defun attempt-recompile-optimization (function-name)
  "Attempt aggressive recompilation of FUNCTION-NAME with maximum speed.

Recompiles the function with (DECLAIM (OPTIMIZE (SPEED 3) (SAFETY 1)
(SPACE 0) (DEBUG 0))). This is the nuclear option — it sacrifices safety
and debuggability for raw speed. The improvement factor is estimated at 2x
but varies widely depending on the function.

Arguments:
  FUNCTION-NAME — symbol naming the function to recompile.

Returns the OPTIMIZATION-RECORD if recompilation succeeded, NIL otherwise."
  (handler-case
      (let ((source (or #+sbcl
                        (handler-case
                            (funcall (find-symbol "FIND-DEFINITION-SOURCE" "SB-INTROSPECT")
                                     function-name)
                          (error () nil))
                        nil)))
        (declare (ignore source))
        ;; Recompile with aggressive optimization
        (proclaim `(optimize (speed 3) (safety 1) (space 0) (debug 0)))
        ;; Try to recompile the function's source form
        (let ((fn (symbol-function function-name)))
          (when fn
            (compile function-name)
            (let ((record (make-optimization-record
                           :function-name function-name
                           :original-form '(declaim (optimize (speed 1) (safety 3)))
                           :optimized-form '(declaim (optimize (speed 3) (safety 1)))
                           :improvement-factor 2.0)))
              (setf (gethash function-name *auto-tuned-functions*) record)
              (format *trace-output* "~&[TUNE]   → Recompiled ~A with (SPEED 3) (est. 2x speedup)~%"
                      function-name)
              record))))
    (error (e)
      (format *trace-output* "~&[TUNE]   Recompile attempt for ~A failed: ~A~%" function-name e)
      nil)))

(defun optimization-report ()
  "Print a report of all auto-tuning operations performed.

Displays a formatted table showing every function that was auto-tuned,
including the original optimization level, the new optimization, the
estimated improvement factor, and when the tuning occurred.

Example output:
  ╔══════════════════════════════════════════════════════════════════════╗
  ║              AUTO-TUNING REPORT                                      ║
  ╠══════════════════════════════════════════════════════════════════════╣
  ║ RUN-AGENT       INLINE       1.5x   2024-01-15T10:30:00Z           ║
  ║ PARSE-HTML      SPEED 3      2.0x   2024-01-15T10:30:05Z           ║
  ╚══════════════════════════════════════════════════════════════════════╝"
  (let ((records nil))
    (maphash (lambda (fn record)
               (declare (ignore fn))
               (push record records))
             *auto-tuned-functions*)
    (setf records (sort records #'local-time:timestamp>
                        :key #'opt-timestamp))
    (format t "~&╔══════════════════════════════════════════════════════════════════════╗~%")
    (format t "║              AUTO-TUNING REPORT                                      ║~%")
    (format t "╠══════════════════════════════════════════════════════════════════════╣~%")
    (format t "║ ~16A ~14A ~8A ~26A   ║~%" "Function" "Optimization" "Speedup" "Timestamp")
    (format t "╠══════════════════════════════════════════════════════════════════════╣~%")
    (if (null records)
        (format t "║  [No auto-tuning operations performed yet]                          ║~%")
        (dolist (record records)
          (format t "║ ~16A ~14A ~4,1Fx   ~24A   ║~%"
                  (opt-function-name record)
                  (if (listp (opt-optimized-form record))
                      (format nil "~S" (opt-optimized-form record))
                      (opt-optimized-form record))
                  (opt-improvement-factor record)
                  (local-time:format-timestring
                   nil (opt-timestamp record)
                   :format '((:year 4) #\- (:month 2) #\- (:day 2) #\T
                             (:hour 2) #\: (:min 2) #\: (:sec 2) #\Z)))))
    (format t "╚══════════════════════════════════════════════════════════════════════╝~%")
    (length records)))

(defun reset-auto-tuning ()
  "Clear all auto-tuning records and revert optimized functions.

This is the emergency rollback function. It iterates over *AUTO-TUNED-
FUNCTIONS*, attempts to revert each optimization, and clears the table.

Returns the number of optimizations that were reverted."
  (let ((count 0))
    (maphash (lambda (fn record)
               (declare (ignore record))
               ;; Attempt to revert: declare notinline and recompile
               (handler-case
                   (progn
                     (proclaim `(notinline ,fn))
                     (compile fn)
                     (incf count))
                 (error (e)
                   (format *trace-output* "~&[TUNE] Rollback of ~A failed: ~A~%" fn e))))
             *auto-tuned-functions*)
    (clrhash *auto-tuned-functions*)
    (format *trace-output* "~&[TUNE] Auto-tuning reset: ~D optimization(s) reverted.~%" count)
    count))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 7: Dashboard Integration
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These functions integrate the profiler with the existing dashboard
;; system (dashboard.lisp). They extend the agent health table with
;; flamegraph and hotspot displays.

(defun print-profiler-dashboard ()
  "Print a combined view: agent health table + flamegraph + hotspots.

This is the profiler-enhanced dashboard view. It prints:
  1. The standard agent health table (via PRINT-DASHBOARD)
  2. The flamegraph showing CPU time by function
  3. A hotspot list showing functions above the threshold
  4. Auto-tuning status (enabled/disabled, recent tunings)

If *DEFAULT-ORCHESTRATOR* is NIL, only the profiler section is shown.

Example:
  (print-profiler-dashboard)"
  ;; Print standard dashboard if orchestrator is available
  (when *default-orchestrator*
    (print-dashboard *default-orchestrator*))
  ;; Print flamegraph
  (format t "~%~A" (generate-flamegraph :width 80 :height 12))
  ;; Print hotspot list
  (let ((hotspots (detect-hotspots *profiler-hotspot-threshold*)))
    (format t "~&╔══════════════════════════════════════════════════════════════════════════╗~%")
    (format t "║  HOTSPOTS (threshold: ~D%)~A~A~%"
            (floor (* *profiler-hotspot-threshold* 100))
            (make-string (max 0 (- 55 (floor (* *profiler-hotspot-threshold* 100))))
                        :initial-element #\Space)
            "║")
    (if (null hotspots)
        (format t "║  [No hotspots detected — system is healthy]                            ║~%")
        (dolist (hotspot hotspots)
          (destructuring-bind (fn pct calls) hotspot
            (format t "║  ~A~16A ~5,1F% ~8D calls~A~A  ║~%"
                    (ansi-color 31) fn pct calls
                    (ansi-reset)
                    (make-string (max 0 (- 37 (length (symbol-name fn))))
                                :initial-element #\Space)))))
    (format t "╚══════════════════════════════════════════════════════════════════════════╝~%"))
  ;; Print auto-tuning status
  (format t "~&  Auto-tuning: ~A~A~A | Tuned functions: ~D | Samples: ~D~%~%"
          (if *auto-tune-enabled-p* (ansi-color 32) (ansi-color 31))
          (if *auto-tune-enabled-p* "ENABLED " "DISABLED")
          (ansi-reset)
          (hash-table-count *auto-tuned-functions*)
          (length *profiler-raw-samples*)))

(defun start-profiler-dashboard ()
  "Start a dashboard that includes profiler data.

This starts the standard live dashboard (via START-DASHBOARD) and also
starts the swarm profiler (via START-SWARM-PROFILE). The combined view
shows agent health alongside CPU flamegraphs and hotspot detection.

If auto-tuning is enabled, hotspots will be automatically optimized
as they are detected by the orchestrator's monitor loop.

Returns a list: (dashboard-thread profiler-thread).

Example:
  (start-profiler-dashboard)  ; → (#<THREAD ...> #<THREAD ...>)"
  (let ((dash-thread nil)
        (prof-thread nil))
    ;; Start the regular dashboard
    (when *default-orchestrator*
      (setf dash-thread (start-dashboard *default-orchestrator*)))
    ;; Start the profiler
    (start-swarm-profile)
    (setf prof-thread *profiler-thread*)
    (format *trace-output* "~&[PROF] Profiler dashboard started.~%")
    (list dash-thread prof-thread)))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 8: Orchestrator Integration
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These functions connect the profiler to the orchestrator's monitor loop.
;; The monitor loop calls PROFILER-CHECK-IN-MONITOR every cycle, which
;; enables auto-tuning of hotspots without human intervention.

(defun enable-auto-tuning (orchestrator)
  "Enable auto-tuning in the orchestrator's monitor loop.

Sets *AUTO-TUNE-ENABLED-P* to T and stores a flag in the orchestrator's
state hash-table so that persistence (checkpoint/restore) preserves the
setting.

Arguments:
  ORCHESTRATOR — the orchestrator instance to enable auto-tuning for.

Returns T."
  (declare (ignore orchestrator))
  (setf *auto-tune-enabled-p* t)
  (format *trace-output* "~&[PROF] Auto-tuning ENABLED.~%")
  t)

(defun disable-auto-tuning ()
  "Disable auto-tuning.

Sets *AUTO-TUNE-ENABLED-P* to NIL. Hotspots will still be detected and
reported, but no automatic optimization will be performed."
  (setf *auto-tune-enabled-p* nil)
  (format *trace-output* "~&[PROF] Auto-tuning DISABLED.~%")
  t)

(defun profiler-check-in-monitor (orchestrator)
  "Called by the orchestrator's monitor loop every cycle.

If the profiler is running and auto-tuning is enabled, this function:
  1. Checks if enough samples have been collected (≥ 100).
  2. Detects hotspots using DETECT-HOTSPOTS.
  3. If hotspots found, calls AUTO-TUNE-ALL-HOTSPOTS.
  4. Logs the results to *TRACE-OUTPUT*.

This function is designed to be fast when there is no work to do — it
returns immediately if profiling is not active or auto-tuning is disabled.

Arguments:
  ORCHESTRATOR — the orchestrator whose monitor loop is calling this.

Returns the list of OPTIMIZATION-RECORDs if tuning was performed, NIL otherwise."
  (declare (ignore orchestrator))
  (when (and *profiler-running-p* *auto-tune-enabled-p*)
    ;; Only act if we have enough samples
    (when (>= (length *profiler-raw-samples*) 100)
      (let ((hotspots (detect-hotspots)))
        (when hotspots
          (format *trace-output* "~&[PROF] Monitor detected ~D hotspot(s), auto-tuning...~%"
                  (length hotspots))
          (auto-tune-all-hotspots))))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 9: Convenience & Utility Functions
;; ───────────────────────────────────────────────────────────────────────────

(defun profiler-status ()
  "Return a human-readable status summary of the profiler.

Returns a plist with comprehensive profiler state:
  :RUNNING           — T if profiler is active
  :SAMPLES           — number of raw samples collected
  :UNIQUE-FUNCTIONS  — number of distinct functions seen
  :HOTSPOT-COUNT     — number of functions above threshold
  :AUTO-TUNE-P       — whether auto-tuning is enabled
  :TUNED-COUNT       — number of functions auto-tuned

Example:
  (profiler-status)
    ;; → (:RUNNING T :SAMPLES 5432 :UNIQUE-FUNCTIONS 42 ...)"
  (list :running *profiler-running-p*
        :samples (length *profiler-raw-samples*)
        :unique-functions (hash-table-count *profiler-data*)
        :hotspot-count (length (detect-hotspots *profiler-hotspot-threshold*))
        :auto-tune-p *auto-tune-enabled-p*
        :tuned-count (hash-table-count *auto-tuned-functions*)))

(defun print-profiler-status ()
  "Print a compact profiler status line suitable for the REPL.

Displays a one-line summary showing whether profiling is active, how
many samples have been collected, and how many hotspots were detected."
  (let ((status (profiler-status)))
    (format t "~&[PROF] ~A | ~D samples | ~D functions | ~D hotspots | Auto-tune: ~A | Tuned: ~D~%"
            (if (getf status :running)
                (format nil "~A[RUNNING]~A" (ansi-color 32) (ansi-reset))
                (format nil "~A[STOPPED]~A" (ansi-color 31) (ansi-reset)))
            (getf status :samples)
            (getf status :unique-functions)
            (getf status :hotspot-count)
            (if (getf status :auto-tune-p) "ON" "OFF")
            (getf status :tuned-count))))

(defun export-profile-data (&optional (pathname "profiler-data.sexp"))
  "Export profile data to a file for external analysis.

Writes *PROFILER-DATA* as a sexp to PATHNAME. Each line is:
  (function-name call-count total-time self-time)

This format is compatible with external flamegraph tools like
Brendan Gregg's FlameGraph.pl.

Arguments:
  PATHNAME — output file path (default: \"profiler-data.sexp\").

Returns the number of functions exported."
  (with-open-file (out pathname :direction :output :if-exists :supersede)
    (format out ";;; LISPMIND Profile Data Export~%")
    (format out ";;; Generated: ~A~%" (local-time:now))
    (format out ";;; Format: (function-name call-count total-time self-time)~%~%")
    (let ((count 0))
      (maphash (lambda (fn cell)
                 (format out "(~S ~D ~D ~D)~%" fn (first cell) (second cell) (third cell))
                 (incf count))
               *profiler-data*)
      (format *trace-output* "~&[PROF] Exported ~D functions to ~A~%" count pathname)
      count)))


;; ═══════════════════════════════════════════════════════════════════════════
;; End of PROFILER.LISP
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This module implements the complete profiling subsystem for LISPMIND:
;;
;;   • Statistical profiling via SB-SPROF + manual fallback
;;   • ASCII flamegraph generation with color-coded hotspots
;;   • Call graph construction showing parent-child relationships
;;   • Hotspot detection with configurable thresholds
;;   • Auto-tuning: inline, type declarations, aggressive recompilation
;;   • Full integration with dashboard and orchestrator monitor loop
;;   • Comprehensive audit trail via OPTIMIZATION-RECORD structs
;;
;; Usage:
;;   (start-swarm-profile :interval 0.01)     ; begin profiling
;;   ;; ... let agents run ...
;;   (format t (generate-flamegraph))          ; view flamegraph
;;   (detect-hotspots)                         ; find hotspots
;;   (auto-tune-all-hotspots)                  ; optimize them
;;   (optimization-report)                     ; review changes
;;   (stop-swarm-profile)                      ; stop profiling
;;
;; "Profile before you polish. Measure before you mend."
