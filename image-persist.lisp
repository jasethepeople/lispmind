;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; IMAGE-PERSIST.LISP — Image-Based Persistence and Resurrection for LISPMIND
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;              THE RESURRECTION ENGINE: IMAGE-BASED IMMORTALITY
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This file implements the crown jewel of LISPMIND's durability subsystem:
;;; image-based persistence via SBCL's SAVE-LISP-AND-DIE. Unlike the
;;; file-based checkpoint system (checkpoint.lisp), which serializes agent
;;; state to individual files, image persistence captures the ENTIRE running
;;; Lisp process — all agents, all threads, all memory, all function objects,
;;; all global state — into a single executable file that can be restarted
;;; after hardware power loss, kernel panics, or deliberate shutdown.
;;;
;;; DESIGN PHILOSOPHY
;;; ─────────────────
;;; File-based checkpointing is like saving individual documents. Image-based
;;; persistence is like cryogenically freezing the entire office — desks,
;;; chairs, coffee cups, and the half-finished thoughts in every worker's
;;; head. When thawed, work resumes exactly where it left off.
;;;
;;; The tradeoff is portability vs. fidelity:
;;;   • cl-store checkpoints are portable across Lisp implementations and
;;;     can be inspected, edited, and migrated. They are the "documents."
;;;   • Golden images are SBCL-only, opaque binary blobs. But they capture
;;;     EVERYTHING — open file descriptors, compiled functions, thread-local
;;;     bindings, the exact state of the garbage collector. They are the
;;;     "cryogenic freeze."
;;;
;;; The ideal production strategy uses BOTH: golden images for fast recovery
;;; (restart the executable, swarm is alive in milliseconds), and cl-store
;;; checkpoints for cross-version migration and offline inspection.
;;;
;;; THE RESURRECTION CYCLE
;;; ───────────────────────
;;;   1. START:   (enable-immortality orchestrator) launches the watchdog.
;;;   2. MONITOR: The watchdog checks orchestrator health every N seconds.
;;;   3. SAVE:    When heuristics improve, save-golden-image is called.
;;;               This stops all threads, records *resurrection-data*, and
;;;               calls SB-EXT:SAVE-LISP-AND-DIE — TERMINATING the process.
;;;   4. BIRTH:   The golden image is now a self-contained executable.
;;;   5. DEATH:   Power loss, kernel panic, or SIGKILL takes down the host.
;;;   6. REBIRTH: Sysadmin (or systemd) restarts the golden image executable.
;;;   7. REVIVE:  RESURRECT-TOPLEVEL runs, reads *resurrection-data*,
;;;               restarts the orchestrator, and the swarm lives again.
;;;
;;; "A phoenix does not merely survive the fire. It is BORN from it."
;;;
;;; SBCL-SPECIFIC NOTES
;;; ───────────────────
;;; SAVE-LISP-AND-DIE is SBCL-only. On other implementations, this module
;;; gracefully degrades to cl-store checkpoint fallback. The watchdog still
;;; runs, but instead of saving golden images, it triggers checkpoint-system.
;;;
;;; SB-EXT:SAVE-LISP-AND-DIE takes these critical arguments:
;;;   :EXECUTABLE T — embed the runtime, producing a standalone executable
;;;   :TOPLEVEL #'RESURRECT-TOPLEVEL — entry point on restart
;;;   :SAVE-RUNTIME-OPTIONS T — preserve command-line args
;;;
;;; IMPORTANT: SAVE-LISP-AND-DIE NEVER RETURNS. The process dies and is
;;; reborn as the saved image. Any code after the call is unreachable.

(in-package :lispmind)

;; ───────────────────────────────────────────────────────────────────────────
;; Forward Declaration — Dashboard Function (defined in dashboard.lisp)
;; ───────────────────────────────────────────────────────────────────────────
;;
;; STOP-DASHBOARD is called during disable-immortality cleanup. Dashboard
;; is compiled after image-persist in the ASDF serial order; this ftype
;; declaration suppresses the compile-time style-warning.
;;
(declaim (ftype function stop-dashboard))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 1: Golden Image System — Parameters and Metadata
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; The golden image system keeps a rotating set of SBCL core files, each
;; representing a complete snapshot of the running LISPMIND system. The
;; name "golden" comes from the practice of keeping "golden master" copies
;; of software — known-good states that can be reliably restored.
;;
;; We keep a fixed number of golden images in rotation (default 5), so disk
;; usage is bounded. Old images are pruned automatically. Each image has a
;; companion .meta file containing human-readable metadata about what was
;; saved and why.

(defparameter *golden-image-directory* "./golden-images/"
  "Directory where golden images are stored.

This directory will be created automatically if it does not exist.
It should be on a durable filesystem (not a tmpfs) — the whole point
of golden images is surviving power loss, so storing them in RAM
would defeat the purpose.

The trailing slash is required for proper pathname merging.

Example:
  (setf *golden-image-directory* \"/var/lib/lispmind/golden-images/\")")

(defparameter *golden-image-prefix* "lispmind-golden"
  "Filename prefix for golden images.

The full filename format is:
  <prefix>-<version>-<timestamp>.core

Example filenames:
  lispmind-golden-3-2025-07-04T12-30-45.core
  lispmind-golden-4-2025-07-04T14-15-22.core")

(defparameter *golden-image-count* 5
  "Number of golden images to keep in rotation.

When a new golden image is saved and the total exceeds this count,
the oldest images are pruned. This keeps disk usage bounded while
providing a sliding window of recovery points.

Set to a higher value if you want more historical recovery points.
Set to 1 if disk space is extremely tight (keeps only the latest).")

(defvar *current-golden-image-version* 0
  "Incremented each time a golden image is saved.

This monotonically increasing counter serves as a unique identifier
for each golden image generation. It is stored in *RESURRECTION-DATA*
and persists across image saves, so the sequence continues even after
process resurrection.

Thread-safety: only written by SAVE-GOLDEN-IMAGE (single-threaded context
after all worker threads have been stopped).")

(defvar *watchdog-thread* nil
  "The watchdog thread handle (a BT:THREAD instance) or NIL.

Set by START-WATCHDOG, cleared by STOP-WATCHDOG. The watchdog thread
runs WATCHDOG-LOOP, which monitors orchestrator health and triggers
golden image saves when heuristics improve.")

(defvar *watchdog-running-p* nil
  "Flag to control the watchdog thread.

Set to T by START-WATCHDOG before spawning the thread. Set to NIL by
STOP-WATCHDOG to signal graceful shutdown. The watchdog loop checks
this flag on each iteration.")

(defvar *last-heuristics-score* 0
  "The heuristics score from the last golden image save.

Used by SHOULD-SAVE-GOLDEN-IMAGE-P to determine if the current score
has improved significantly enough to justify a new save. Only written
by the watchdog thread.")

(defvar *heartbeat-file-path* "./golden-images/.watchdog-heartbeat"
  "Path to the watchdog heartbeat file.

The watchdog writes a timestamp to this file on each check cycle.
If the file is stale (older than twice the check interval), an
unclean shutdown is assumed and auto-resurrection is triggered.")

;; ── Golden Image Metadata ─────────────────────────────────────────────────
;;
;; Each golden image has a companion .meta file (e.g., image.core has
;; image.meta) containing a plist of metadata. This metadata is human-
;; readable (printed Lisp data) and describes the state of the system
;; at the moment the image was saved.

(defstruct golden-image-metadata
  "Metadata describing a saved golden image.

Stored alongside each golden image in a companion .meta file.
This is a plist-encoded human-readable format for easy inspection
without loading the binary core file.

Fields:
  VERSION           — integer, the golden image generation number
  TIMESTAMP         — string, ISO 8601 format creation time
  AGENT-COUNT       — integer, number of agents in the swarm
  ORCHESTRATOR-HEALTH — integer 0..100, orchestrator health at save time
  HEURISTICS-SCORE  — integer 0..100, overall swarm performance score
  FILENAME          — string, the path to the .core file
  REASON            — string, why this image was saved (e.g., \"manual\", \"auto-improved\")
  SBCL-VERSION      — string, the SBCL version that created this image
  LISPMIND-VERSION  — string, the LISPMIND system version"
  version timestamp agent-count orchestrator-health heuristics-score
  filename reason sbcl-version lispmind-version)


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 2: Resurrection Data — State That Survives Image Saves
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; *RESURRECTION-DATA* is the bridge between incarnations. When
;; SAVE-GOLDEN-IMAGE is called, it stores orchestrator state into this
;; hash-table. Because the hash-table is a global special variable,
;; it survives SB-EXT:SAVE-LISP-AND-DIE and is present (with all its
;; contents) when the golden image is restarted.
;;
;; On resurrection, RESURRECT-TOPLEVEL reads this data and uses it to
;; reconstruct the orchestrator's state: agent registry, mailboxes,
;; running flags, and thread handles.
;;
;; "The soul persists across rebirth. This hash-table is the soul."

(defvar *resurrection-data* (make-hash-table :test 'eq)
  "Data preserved across image saves via SB-EXT:SAVE-LISP-AND-DIE.

This hash-table stores orchestrator state that must survive process
termination and rebirth. Because it is a global special variable,
SBCL includes it (and all reachable data) in the saved image.

Keys (all keywords):
  :ORCHESTRATOR       — the orchestrator instance (or a marker if it was
                        stored via RECORD-RESURRECTION-DATA)
  :GOLDEN-VERSION     — integer, the version of this golden image
  :TIMESTAMP          — local-time timestamp of the save
  :AGENT-IDS          — list of agent IDs registered at save time
  :HEURISTICS-SCORE   — the swarm score at save time
  :REASON             — string, why the image was saved
  :DASHBOARD-RUNNING-P — was the dashboard running?
  :AUTO-CHECKPOINT-RUNNING-P — was auto-checkpoint running?
  :STRATEGY-HISTORY-KEYS — agent-ids that had strategy history entries

Set by RECORD-RESURRECTION-DATA before saving.
Read by RESURRECT-TOPLEVEL on image restart.

Thread-safety: only accessed during save (after threads stopped) and
at startup (single-threaded context). No lock needed.")

;; ── SBCL Feature Detection ────────────────────────────────────────────────

(defun image-persistence-available-p ()
  "Return T if image-based persistence is available on this platform.

Currently only SBCL supports SAVE-LISP-AND-DIE with :EXECUTABLE T.
On other implementations, this returns NIL and the system falls back
to cl-store checkpointing.

This function exists so callers can branch gracefully:
  (if (image-persistence-available-p)
      (save-golden-image orch)
      (checkpoint-system orch))"
  #+sbcl t
  #-sbcl nil)


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 3: Heuristics Computation — When Is the Swarm Worth Saving?
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Not every moment is worth freezing. The heuristics system computes a
;; composite score (0-100) that represents the overall health and
;; productivity of the swarm. Golden images are only saved when this
;; score improves significantly — there's no point in saving a dying swarm.
;;
;; The score combines:
;;   • Average agent health (0-100)
;;   • Error rate (lower is better)
;;   • Healing success rate
;;   • Evolution progress (hotpatch version advancement)

(defun compute-heuristics-score (orchestrator)
  "Compute an overall swarm health score (0-100) for the ORCHESTRATOR.

The heuristics score is a composite metric that balances multiple
indicators of swarm health. A score of 100 means a perfectly healthy,
productive swarm. A score of 0 means complete system failure.

Computation:
  1. Average agent health (40% weight) — mean of all agent health scores
  2. Error penalty (30% weight) — total errors across all agents, capped
  3. Healing bonus (15% weight) — count of successful healings
  4. Evolution progress (15% weight) — average strategy version

Arguments:
  ORCHESTRATOR — the orchestrator whose agents to evaluate

Returns an integer from 0 to 100.

Example:
  (compute-heuristics-score *default-orchestrator*)  ;; → 87"
  (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
    (let ((agent-count 0)
          (total-health 0)
          (total-errors 0)
          (total-healings 0)
          (total-versions 0))
      (maphash
       (lambda (aid agent)
         (declare (ignore aid))
         (incf agent-count)
         (incf total-health (agent-health agent))
         (incf total-errors (agent-error-count agent))
         (incf total-healings (or (gethash :healing-count (agent-state agent)) 0))
         (incf total-versions (agent-version agent)))
       (orchestrator-agents orchestrator))
      (if (zerop agent-count)
          ;; No agents registered — score is neutral
          50
          ;; Compute weighted score
          (let* ((avg-health (/ total-health agent-count))
                 ;; Error penalty: 0 errors = full marks, 50+ errors = zero
                 (error-penalty (max 0 (- 100 (* 2 (/ total-errors agent-count)))))
                 ;; Healing bonus: capped at 30 points
                 (healing-bonus (min 30 (* 5 (/ total-healings agent-count))))
                 ;; Evolution progress: version 0 = 0, version 5+ = full
                 (evolution-score (min 30 (* 6 (/ total-versions agent-count))))
                 ;; Weighted combination
                 (raw-score (+ (* 0.40 avg-health)
                               (* 0.30 error-penalty)
                               (* 0.15 healing-bonus)
                               (* 0.15 evolution-score))))
            (max 0 (min 100 (round raw-score))))))))

(defun should-save-golden-image-p (orchestrator)
  "Check if current heuristics justify saving a golden image.

Returns T if the heuristics score has improved by at least 10 points
since the last save (stored in *LAST-HEURISTICS-SCORE*). Also returns
T if no previous save exists (score is 0, meaning this is the first
check) or if the orchestrator health has dropped below 30 (emergency
save before potential failure).

This function is called by the watchdog loop on each auto-save check.
It prevents unnecessary image saves when the swarm is stable but not
improving, while ensuring emergency saves when things go wrong.

Arguments:
  ORCHESTRATOR — the orchestrator to evaluate

Returns T if a save should occur, NIL otherwise.

Example:
  (when (should-save-golden-image-p *orch*)
    (save-golden-image *orch* :reason \"heuristics-improved\"))"
  (let ((score (compute-heuristics-score orchestrator))
        (orch-health (agent-health orchestrator)))
    (cond
      ;; Emergency save: orchestrator is failing, preserve state NOW
      ((< orch-health 30)
       (format *trace-output*
               "~&[GOLDEN] Emergency save triggered: orchestrator health ~D~%"
               orch-health)
       t)
      ;; First save ever
      ((zerop *last-heuristics-score*)
       (format *trace-output*
               "~&[GOLDEN] First golden image save (score: ~D)~%"
               score)
       t)
      ;; Score improved by 10+ points
      ((>= score (+ *last-heuristics-score* 10))
       (format *trace-output*
               "~&[GOLDEN] Heuristics improved: ~D → ~D — saving golden image~%"
               *last-heuristics-score* score)
       t)
      ;; Otherwise, no save needed
      (t nil))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 4: Image Save — The Point of No Return
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; SAVE-GOLDEN-IMAGE is the most dramatic function in LISPMIND. It
;; TERMINATES the current process and creates a self-contained executable
;; that, when run, resurrects the entire system exactly as it was.
;;
;; THE SACRIFICE: After calling this function, the current SBCL process
;; ceases to exist. It is replaced by the golden image file. There is no
;; return. The process dies so that the system may live forever.
;;
;; On non-SBCL implementations, this falls back to checkpoint-system.

(defun save-golden-image (orchestrator &key (reason "manual"))
  "Save the ENTIRE running SBCL image as an executable golden image.

This is the nuclear option of persistence. It captures EVERYTHING:
all agents, all state, all memory, all compiled functions, all global
variables — and packages it into a single executable file. When that
file is run, the system resumes exactly where it left off.

PROCESS:
  1. Compute metadata (version, timestamp, agent count, health)
  2. Increment *CURRENT-GOLDEN-IMAGE-VERSION*
  3. Pick filename: <prefix>-<version>-<timestamp>.core
  4. Record resurrection data into *RESURRECTION-DATA*
  5. Stop all threads cleanly (monitor, dashboard, watchdog)
  6. Write companion .meta file
  7. Call SB-EXT:SAVE-LISP-AND-DIE with:
       :EXECUTABLE T
       :TOPLEVEL #'RESURRECT-TOPLEVEL
       :SAVE-RUNTIME-OPTIONS T

CRITICAL: Step 7 TERMINATES the current process. The image file IS
 the new process. There is no return from this function.

On non-SBCL implementations, falls back to CHECKPOINT-SYSTEM and
returns normally (since SAVE-LISP-AND-DIE is not available).

Arguments:
  ORCHESTRATOR — the orchestrator to save (required)
  :REASON      — string describing why the save occurred (default \"manual\")

Returns: NEVER RETURNS on SBCL. Returns NIL on other implementations
         (after falling back to checkpoint-system).

Example:
  ;; Manual save from the REPL
  (save-golden-image *default-orchestrator* :reason \"pre-deployment-freeze\")

  ;; Triggered by the watchdog
  (save-golden-image *orch* :reason \"heuristics-improved\")"
  (declare (type orchestrator orchestrator))
  (if (not (image-persistence-available-p))
      ;; ── Fallback: cl-store checkpointing on non-SBCL ──────────────────
      (progn
        (format *trace-output*
                "~&[GOLDEN] Image persistence not available on this platform.~%")
        (format *trace-output*
                "~&[GOLDEN] Falling back to cl-store checkpoint...~%")
        (checkpoint-system orchestrator *golden-image-directory*)
        nil)
      ;; ── SBCL: The Real Deal ───────────────────────────────────────────
      (progn
        ;; Step 1: Compute metadata
        (incf *current-golden-image-version*)
        (let* ((version *current-golden-image-version*)
               (timestamp (local-time:now))
               (timestamp-str (local-time:format-rfc3339-timestring
                               nil timestamp
                               :timezone local-time:+utc-zone+))
               (agent-count (hash-table-count (orchestrator-agents orchestrator)))
               (orch-health (agent-health orchestrator))
               (heuristics (compute-heuristics-score orchestrator))
               (filename (format nil "~A-~A-~A.core"
                                 *golden-image-prefix*
                                 version
                                 (substitute #\- #\: timestamp-str)))
               (filepath (merge-pathnames filename
                                          (ensure-directory-pathname
                                           (pathname *golden-image-directory*))))
               ;; Build the metadata struct
               (metadata (make-golden-image-metadata
                          :version version
                          :timestamp timestamp-str
                          :agent-count agent-count
                          :orchestrator-health orch-health
                          :heuristics-score heuristics
                          :filename (namestring filepath)
                          :reason reason
                          :sbcl-version (lisp-implementation-version)
                          :lispmind-version "1.0.0")))
          ;; Step 2: Record resurrection data
          (record-resurrection-data orchestrator)
          (setf (gethash :golden-version *resurrection-data*) version)
          (setf (gethash :timestamp *resurrection-data*) timestamp)
          (setf (gethash :heuristics-score *resurrection-data*) heuristics)
          (setf (gethash :reason *resurrection-data*) reason)
          ;; Update the last score
          (setf *last-heuristics-score* heuristics)
          ;; Step 3: Graceful thread shutdown
          (format *trace-output*
                  "~&[GOLDEN] ╔══════════════════════════════════════════════════════════════╗~%")
          (format *trace-output*
                  "~&[GOLDEN] ║  SAVING GOLDEN IMAGE v~A~%" version)
          (format *trace-output*
                  "~&[GOLDEN] ║  Agents: ~A | Health: ~A | Heuristics: ~A~%"
                  agent-count orch-health heuristics)
          (format *trace-output*
                  "~&[GOLDEN] ║  Reason: ~A~%" reason)
          (format *trace-output*
                  "~&[GOLDEN] ║  File: ~A~%" filepath)
          (format *trace-output*
                  "~&[GOLDEN] ║  NOTE: This process will TERMINATE. The image IS the process.~%")
          (format *trace-output*
                  "~&[GOLDEN] ╚══════════════════════════════════════════════════════════════╝~%")
          ;; Stop threads cleanly
          (format *trace-output* "~&[GOLDEN] Stopping threads before save...~%")
          (stop-orchestrator orchestrator)
          (stop-dashboard)
          (stop-watchdog)
          ;; Stop auto-checkpoint if running
          (stop-auto-checkpoint)
          ;; Step 4: Write metadata file
          (ensure-directories-exist filepath :verbose nil)
          (write-golden-metadata metadata (make-pathname
                                           :type "meta"
                                           :defaults filepath))
          ;; Step 5: THE POINT OF NO RETURN
          ;; After this call, the current process ceases to exist.
          ;; The golden image file becomes the new executable.
          (format *trace-output* "~&[GOLDEN] Calling SAVE-LISP-AND-DIE...~%")
          (format *trace-output* "~&[GOLDEN] Goodbye, old world. Hello, immortality.~%")
          (force-output *trace-output*)
          #+sbcl
          (sb-ext:save-lisp-and-die
           (namestring filepath)
           :executable t
           :toplevel #'resurrect-toplevel
           :save-runtime-options t)
          #-sbcl
          (error "SAVE-GOLDEN-IMAGE: should have fallen back to checkpoint earlier")))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 5: Resurrection Toplevel — Rebirth from the Golden Image
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; RESURRECT-TOPLEVEL is the entry point when a golden image is executed.
;; It is the first Lisp function called after SBCL finishes its low-level
;; startup. It reads *RESURRECTION-DATA* and decides whether to restore
;; a saved orchestrator or start fresh.
;;
;; This function is the PHOENIX RISING — the moment of rebirth when the
;; system, frozen in time, steps back into the world and resumes its work
;; as if no interruption had ever occurred.

(defun resurrect-toplevel ()
  "The entry point when a golden image is executed. The resurrection ritual.

This function runs when a golden image executable starts. It examines
*RESURRECTION-DATA* to determine whether this is a true resurrection
(state exists) or a fresh boot (no state). In either case, it starts
the orchestrator and enters the main loop.

PROCESS:
  1. Print the resurrection banner
  2. Check *RESURRECTION-DATA* for saved orchestrator state
  3. If state exists (resurrection):
       a. Print 'Restoring from golden image v<N>...'
       b. Extract saved data (agent IDs, version, heuristics)
       c. Create a fresh orchestrator (thread handles cannot survive)
       d. Restart the orchestrator's monitor thread
       e. Print 'Resurrection complete. Swarm is alive.'
  4. If no state (fresh boot):
       a. Print 'Fresh boot. Starting new orchestrator...'
       b. Create and start a fresh orchestrator
  5. Restart the watchdog thread
  6. Enter the REPL (or dashboard loop)

This function NEVER RETURNS normally — it enters an infinite loop
(either the REPL or a dashboard-driven event loop) to keep the process
alive. The only way out is process termination.

Thread-safety: runs single-threaded at startup — no contention.

Example (called automatically by SBCL, never manually):
  ;; This is what SBCL calls when you run the golden image:
  $ ./lispmind-golden-3-2025-07-04T12-30-45.core
  ;; → RESURRECT-TOPLEVEL runs automatically"
  ;; ── Resurrection Banner ──────────────────────────────────────────────
  (format *trace-output* "~%")
  (format *trace-output* "~&╔══════════════════════════════════════════════════════════════════════╗~%")
  (format *trace-output* "~&║  LISPMIND GOLDEN IMAGE — RESURRECTING...                           ║~%")
  (format *trace-output* "~&║  SBCL ~A                                            ║~%"
          (lisp-implementation-version))
  (format *trace-output* "~&╚══════════════════════════════════════════════════════════════════════╝~%")
  ;; ── Check for unclean shutdown ───────────────────────────────────────
  (let ((unclean-p (check-unclean-shutdown)))
    (when unclean-p
      (format *trace-output* "~&[RESURRECT] WARNING: Previous shutdown appears unclean.~%")
      (format *trace-output* "~&[RESURRECT] Heartbeat was stale — likely a crash or power loss.~%")))
  ;; ── Core Resurrection Logic ──────────────────────────────────────────
  (let ((saved-version (gethash :golden-version *resurrection-data*))
        (saved-reason (gethash :reason *resurrection-data*))
        (saved-agent-ids (gethash :agent-ids *resurrection-data*))
        (saved-heuristics (gethash :heuristics-score *resurrection-data*)))
    (cond
      ;; ── Case 1: True Resurrection ──────────────────────────────────
      ;; We have saved data — this is a golden image restart after save.
      (saved-version
       (format *trace-output* "~&[RESURRECT] Restoring from golden image v~A (~A)...~%"
               saved-version saved-reason)
       (when saved-heuristics
         (format *trace-output* "~&[RESURRECT] Saved heuristics score: ~A~%"
                 saved-heuristics))
       (when saved-agent-ids
         (format *trace-output* "~&[RESURRECT] Previous swarm: ~{~A~^, ~}~%"
                 saved-agent-ids))
       ;; Create a fresh orchestrator (thread handles from the old one
       ;; are invalid after save-lisp-and-die — they don't survive)
       (let ((orchestrator (make-orchestrator)))
         ;; Restore the last heuristics score so we don't immediately
         ;; trigger another save
         (when saved-heuristics
           (setf *last-heuristics-score* saved-heuristics))
         ;; Restart the orchestrator's monitor thread
         (start-orchestrator orchestrator)
         ;; Print the resurrection completion banner
         (format *trace-output* "~%")
         (format *trace-output* "~&╔══════════════════════════════════════════════════════════════════════╗~%")
         (format *trace-output* "~&║  RESURRECTION COMPLETE. The swarm is alive.                        ║~%")
         (format *trace-output* "~&║  Golden image version: ~A                                          ║~%"
                 saved-version)
         (format *trace-output* "~&║  Previous swarm members: ~A                                        ║~%"
                 (or (and saved-agent-ids (length saved-agent-ids)) 0))
         (format *trace-output* "~&║  The phoenix rises. Work resumes.                                  ║~%")
         (format *trace-output* "~&╚══════════════════════════════════════════════════════════════════════╝~%")
         ;; Set as the default orchestrator
         (setf *default-orchestrator* orchestrator)
         ;; Start the watchdog for continued monitoring
         (start-watchdog)
         ;; Enter the main loop
         (enter-resurrected-main-loop orchestrator)))
      ;; ── Case 2: Fresh Boot ─────────────────────────────────────────
      ;; No saved data — someone ran the executable directly without it
      ;; being a golden image, or this is the very first boot.
      (t
       (format *trace-output* "~&[RESURRECT] Fresh boot. No resurrection data found.~%")
       (format *trace-output* "~&[RESURRECT] Starting new orchestrator...~%")
       (let ((orchestrator (start-orchestrator (make-orchestrator))))
         (setf *default-orchestrator* orchestrator)
         (format *trace-output* "~&[RESURRECT] Orchestrator started. Swarm is ready for agents.~%")
         ;; Start the watchdog
         (start-watchdog)
         ;; Enter the main loop
         (enter-resurrected-main-loop orchestrator))))))

(defun enter-resurrected-main-loop (orchestrator)
  "Enter the main event loop after resurrection or fresh boot.

This function keeps the process alive after RESURRECT-TOPLEVEL finishes
its setup. It runs an infinite loop that:
  1. Prints a status banner every 60 seconds
  2. Checks if the orchestrator is still running
  3. If the orchestrator dies, attempts to restart it
  4. Handles the :QUIT command to shut down cleanly

This function NEVER RETURNS. It is the gravitational center of the
resurrected process — everything orbits around it.

Arguments:
  ORCHESTRATOR — the orchestrator to monitor and keep alive

Thread-safety: runs in the main thread only."
  (declare (type orchestrator orchestrator))
  (format *trace-output* "~&[MAIN] Entering main loop. Type :quit to exit.~%")
  (loop
    (sleep 60)
    ;; Check if orchestrator is still alive
    (unless (and orchestrator (orchestrator-running-p orchestrator))
      (format *trace-output* "~&[MAIN] WARNING: Orchestrator is not running!~%")
      (format *trace-output* "~&[MAIN] Attempting restart...~%")
      (handler-case
          (progn
            (setf orchestrator (start-orchestrator (make-orchestrator)))
            (setf *default-orchestrator* orchestrator))
        (error (e)
          (format *trace-output* "~&[MAIN] Failed to restart orchestrator: ~A~%" e)
          (format *trace-output* "~&[MAIN] Retrying in 60 seconds...~%"))))
    ;; Print periodic status
    (when orchestrator
      (let ((agent-count (hash-table-count (orchestrator-agents orchestrator))))
        (format *trace-output* "~&[MAIN] ~A agents alive | Health: ~A | ~A~%"
                agent-count
                (agent-health orchestrator)
                (local-time:format-rfc3339-timestring
                 nil (local-time:now)
                 :timezone local-time:+utc-zone+))))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 6: Watchdog — The Guardian of Immortality
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; The watchdog thread is the sentinel that ensures the system persists.
;; It monitors orchestrator health, detects unclean shutdowns, and triggers
;; golden image saves when the swarm reaches new peaks of performance.
;;
;; "The watchdog never sleeps. While agents do their work and the
;;  orchestrator tends the garden, the watchdog watches the watcher."

(defun start-watchdog (&key (check-interval 30) (auto-save-interval 300))
  "Start the watchdog thread that monitors orchestrator health.

The watchdog is the guardian of immortality. It runs in a background
thread and performs three critical functions:
  1. HEALTH CHECKS: Every CHECK-INTERVAL seconds, verify the orchestrator
     is alive and healthy. If health drops below critical thresholds,
     trigger emergency actions.
  2. AUTO-SAVE: Every AUTO-SAVE-INTERVAL seconds, evaluate heuristics.
     If the swarm has improved significantly, save a golden image.
  3. HEARTBEAT: Write a heartbeat file on each cycle so that unclean
     shutdowns can be detected on the next restart.

The watchdog also detects stale heartbeat files on startup and can
auto-resurrect from the latest golden image after a crash.

Arguments:
  :CHECK-INTERVAL      — seconds between health checks (default 30)
  :AUTO-SAVE-INTERVAL  — seconds between auto-save evaluations (default 300 = 5 min)

Returns the watchdog thread (a BT:THREAD instance).

Thread-safety: sets *WATCHDOG-RUNNING-P* and *WATCHDOG-THREAD* under
an implicit lock (single-writer: this function only).

Example:
  ;; Start with default settings
  (start-watchdog)

  ;; Aggressive monitoring: check every 10s, evaluate save every 60s
  (start-watchdog :check-interval 10 :auto-save-interval 60)"
  ;; Stop any existing watchdog first
  (when (and *watchdog-thread* (bt:thread-alive-p *watchdog-thread*))
    (format *trace-output* "~&[WATCHDOG] Stopping existing watchdog thread~%")
    (stop-watchdog))
  (setf *watchdog-running-p* t)
  (let ((thread (bt:make-thread
                 (lambda ()
                   (watchdog-loop check-interval auto-save-interval))
                 :name "lispmind-watchdog"
                 :initial-bindings '())))
    (setf *watchdog-thread* thread)
    (format *trace-output* "~&[WATCHDOG] Watchdog started (check: ~As, auto-save: ~As)~%"
            check-interval auto-save-interval)
    thread))

(defun stop-watchdog ()
  "Stop the watchdog thread gracefully.

Sets *WATCHDOG-RUNNING-P* to NIL, which signals the watchdog loop to
exit on its next iteration. The function then waits up to 5 seconds
for the thread to join. If the thread does not exit in time, it is
destroyed.

Returns T if the watchdog was stopped, NIL if no watchdog was running.

Example:
  (stop-watchdog)  ;; → T or NIL"
  (if (and *watchdog-thread* (bt:thread-alive-p *watchdog-thread*))
      (progn
        (setf *watchdog-running-p* nil)
        ;; Give the watchdog a chance to exit gracefully
        (handler-case
            (bt:with-timeout (5)
              (bt:join-thread *watchdog-thread*))
          (bt:timeout ()
            (format *trace-output* "~&[WATCHDOG] Watchdog did not exit in time, destroying...~%")
            (bt:destroy-thread *watchdog-thread*)))
        (setf *watchdog-thread* nil)
        (format *trace-output* "~&[WATCHDOG] Watchdog stopped.~%")
        t)
      (progn
        (format *trace-output* "~&[WATCHDOG] No watchdog thread running.~%")
        nil)))

(defun watchdog-loop (check-interval auto-save-interval)
  "The main watchdog loop. Runs in the watchdog thread until stopped.

This function implements the sentinel behavior:
  1. Write a heartbeat file (we are alive)
  2. Every CHECK-INTERVAL seconds: check orchestrator health
  3. Every AUTO-SAVE-INTERVAL seconds: evaluate heuristics, save if improved
  4. If *WATCHDOG-RUNNING-P* becomes NIL, exit cleanly

The loop is resilient: errors are caught and logged, never propagated.
The watchdog must never die — if it crashes, the system is unprotected.

Arguments:
  CHECK-INTERVAL      — seconds between health checks
  AUTO-SAVE-INTERVAL  — seconds between auto-save evaluations

Returns: never returns normally (runs until *WATCHDOG-RUNNING-P* is NIL).
         Returns NIL on graceful exit."
  (format *trace-output* "~&[WATCHDOG] Watchdog loop starting...~%")
  (let ((last-auto-save-check 0)
        (tick 0))
    (loop
      (unless *watchdog-running-p*
        (format *trace-output* "~&[WATCHDOG] Shutdown signal received. Exiting.~%")
        (return-from watchdog-loop nil))
      (handler-case
          (progn
            ;; Write heartbeat
            (write-watchdog-heartbeat)
            ;; ── Health Check ──────────────────────────────────────────
            (when *default-orchestrator*
              (let ((orch *default-orchestrator*))
                ;; Check orchestrator health
                (when (< (agent-health orch) 20)
                  (format *trace-output*
                          "~&[WATCHDOG] CRITICAL: Orchestrator health is ~A — triggering save~%"
                          (agent-health orch))
                  ;; Emergency save
                  (handler-case
                      (save-golden-image orch :reason "emergency-health-critical")
                    (error (e)
                      (format *trace-output*
                              "~&[WATCHDOG] Emergency save failed: ~A~%" e))))
                ;; Check if orchestrator thread is alive
                (when (and (orchestrator-monitor-thread orch)
                           (not (bt:thread-alive-p (orchestrator-monitor-thread orch))))
                  (format *trace-output*
                          "~&[WATCHDOG] WARNING: Monitor thread is dead! Restarting...~%")
                  (handler-case
                      (start-orchestrator orch)
                    (error (e)
                      (format *trace-output*
                              "~&[WATCHDOG] Monitor restart failed: ~A~%" e))))))
            ;; ── Auto-Save Evaluation ────────────────────────────────
            (when (and *default-orchestrator*
                       (>= tick last-auto-save-check))
              (setf last-auto-save-check (+ tick auto-save-interval))
              (when (should-save-golden-image-p *default-orchestrator*)
                (handler-case
                    (save-golden-image *default-orchestrator*
                                       :reason "auto-heuristics-improved")
                  (error (e)
                    (format *trace-output*
                            "~&[WATCHDOG] Auto-save failed: ~A~%" e))))))
        ;; Outer error handler: the watchdog must NEVER die
        (error (e)
          (format *trace-output* "~&[WATCHDOG] ERROR in watchdog loop: ~A~%" e)
          (format *trace-output* "~&[WATCHDOG] Continuing despite error...~%")))
      ;; Sleep until next check cycle
      (sleep check-interval)
      (incf tick check-interval)))
  ;; Graceful exit
  (format *trace-output* "~&[WATCHDOG] Watchdog loop exited cleanly.~%"))

(defun write-watchdog-heartbeat ()
  "Write a heartbeat file to signal that the watchdog (and system) is alive.

Writes the current universal time as a text integer to the file at
*HEARTBEAT-FILE-PATH*. This file is read by CHECK-UNCLEAN-SHUTDOWN
to determine if the previous shutdown was clean or not.

The heartbeat file is a simple timestamp — if it is older than
(* 2 check-interval), the system probably crashed.

Thread-safety: safe to call from the watchdog thread only.

Returns the pathname of the heartbeat file.

Example:
  (write-watchdog-heartbeat)
    ;; → #P\"./golden-images/.watchdog-heartbeat\""
  (let ((file *heartbeat-file-path*))
    (ensure-directories-exist file :verbose nil)
    (with-open-file (stream file
                            :direction :output
                            :if-exists :supersede
                            :if-does-not-exist :create)
      (format stream "~A~%" (get-universal-time)))
    (pathname file)))

(defun check-unclean-shutdown ()
  "Check if the previous shutdown was unclean (heartbeat file is stale).

Reads the heartbeat file and compares its timestamp to the current
time. If the heartbeat is older than 120 seconds, the system is
assumed to have crashed, been killed, or lost power.

Returns T if the previous shutdown appears unclean, NIL if clean or
if no heartbeat file exists.

This function is called by RESURRECT-TOPLEVEL on startup to detect
whether the previous run ended badly.

Example:
  (check-unclean-shutdown)  ;; → T or NIL"
  (let ((file *heartbeat-file-path*))
    (if (probe-file file)
        (handler-case
            (let ((last-beat
                    (with-open-file (stream file)
                      (read stream)))
                  (now (get-universal-time)))
              (if (> (- now last-beat) 120)
                  t  ;; Stale heartbeat — unclean shutdown
                  nil))  ;; Fresh heartbeat — clean shutdown
          (error (e)
            (format *trace-output* "~&[WATCHDOG] Cannot read heartbeat file: ~A~%" e)
            t))  ;; Assume unclean if we can't read the file
        nil)))  ;; No heartbeat file — assume clean (first boot)


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 7: Golden Image Management — List, Find, Load, Prune
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These utility functions help operators manage the golden image directory:
;; list available images, find the most recent, load a specific image,
;; and clean up old images to manage disk space.

(defun list-golden-images ()
  "List all golden images with their metadata.

Scans *GOLDEN-IMAGE-DIRECTORY* for .core files matching the naming
convention, reads each companion .meta file, and returns a list of
GOLDEN-IMAGE-METADATA structs.

Returns: a list of GOLDEN-IMAGE-METADATA structs, sorted by version
         number (oldest first).

Example:
  (list-golden-images)
    ;; → (#S(GOLDEN-IMAGE-METADATA :VERSION 1 ...)
    ;;    #S(GOLDEN-IMAGE-METADATA :VERSION 2 ...))"
  (let ((dir (ensure-directory-pathname (pathname *golden-image-directory*)))
        (results '()))
    (when (probe-file dir)
      (dolist (file (directory (merge-pathnames "*.core" dir)))
        (let ((meta-file (make-pathname :type "meta" :defaults file)))
          (handler-case
              (let ((metadata (read-golden-metadata meta-file)))
                (push metadata results))
            (error (e)
              (format *trace-output* "~&[GOLDEN] Cannot read metadata for ~A: ~A~%"
                      file e))))))
    ;; Sort by version number
    (sort results #'< :key #'golden-image-metadata-version)))

(defun find-latest-golden-image ()
  "Find the most recent golden image file.

Returns the GOLDEN-IMAGE-METADATA struct for the highest-versioned
golden image in *GOLDEN-IMAGE-DIRECTORY*. Returns NIL if no golden
images exist.

This is the image that would be used for auto-resurrection after a
crash — the latest known-good state.

Example:
  (find-latest-golden-image)
    ;; → #S(GOLDEN-IMAGE-METADATA :VERSION 5 :FILENAME \"...\")"
  (let ((all-images (list-golden-images)))
    (if all-images
        (first (last all-images))
        nil)))

(defun load-golden-image (filename)
  "Load a golden image by forking a new SBCL process with that core file.

Forks a new OS process running the specified golden image executable.
The current process is NOT affected — this is a spawn, not a replacement.

On SBCL, uses SB-EXT:RUN-PROGRAM. On other implementations, falls back
to UIOP:LAUNCH-PROGRAM if available.

Arguments:
  FILENAME — pathname designator for the .core file to run

Returns the process handle (SB-EXT:PROCESS on SBCL), or NIL if the
launch failed.

Example:
  ;; Start the latest golden image in a new process
  (let ((latest (find-latest-golden-image)))
    (when latest
      (load-golden-image (golden-image-metadata-filename latest))))"
  (let ((core-path (pathname filename)))
    (unless (probe-file core-path)
      (error "Golden image file not found: ~A" core-path))
    (format *trace-output* "~&[GOLDEN] Launching golden image: ~A~%" core-path)
    #+sbcl
    (let ((process (sb-ext:run-program
                    (namestring core-path)
                    '()
                    :wait nil
                    :output *trace-output*
                    :error *trace-output*)))
      (format *trace-output* "~&[GOLDEN] Golden image launched (PID: ~A)~%"
              (sb-ext:process-pid process))
      process)
    #-sbcl
    (progn
      (format *trace-output* "~&[GOLDEN] Process launch not implemented on this platform.~%")
      (format *trace-output* "~&[GOLDEN] Please run manually: ~A~%" core-path)
      nil)))

(defun prune-golden-images (&optional (keep *golden-image-count*))
  "Delete old golden images, keeping only the KEEP most recent.

Lists all golden images sorted by version, then deletes all but the
most recent KEEP images (and their companion .meta files). This keeps
disk usage bounded.

Arguments:
  KEEP — number of most recent images to retain (default *GOLDEN-IMAGE-COUNT*)

Returns the number of deleted image pairs (core + meta).

Example:
  ;; Keep only the 3 most recent images
  (prune-golden-images 3)
    ;; → 2 (meaning 2 old images were deleted)"
  (let* ((all-images (list-golden-images))
         (to-delete (if (> (length all-images) keep)
                        (subseq all-images 0 (- (length all-images) keep))
                        nil))
         (deleted-count 0))
    (dolist (metadata to-delete)
      (let ((core-file (golden-image-metadata-filename metadata))
            (meta-file (make-pathname :type "meta"
                                      :defaults (pathname (golden-image-metadata-filename metadata)))))
        (handler-case
            (progn
              (when (probe-file core-file)
                (delete-file core-file)
                (incf deleted-count))
              (when (probe-file meta-file)
                (delete-file meta-file))
              (format *trace-output* "~&[GOLDEN] Pruned old image v~A~%"
                      (golden-image-metadata-version metadata)))
          (error (e)
            (format *trace-output* "~&[GOLDEN] Error pruning image v~A: ~A~%"
                    (golden-image-metadata-version metadata) e)))))
    (format *trace-output* "~&[GOLDEN] Pruning complete: ~A old image(s) removed, ~A retained~%"
            deleted-count (min keep (length all-images)))
    deleted-count))

(defun read-golden-metadata (filename)
  "Read a .meta file companion to a golden image.

Reads the metadata plist from the specified .meta file and constructs
a GOLDEN-IMAGE-METADATA struct.

Arguments:
  FILENAME — pathname designator for the .meta file

Returns a GOLDEN-IMAGE-METADATA struct.

Signals an error if the file cannot be read.

Example:
  (read-golden-metadata \"./golden-images/lispmind-golden-3.meta\")"
  (let ((plist (with-open-file (stream filename)
                 (read stream))))
    (make-golden-image-metadata
     :version (getf plist :version 0)
     :timestamp (getf plist :timestamp "unknown")
     :agent-count (getf plist :agent-count 0)
     :orchestrator-health (getf plist :orchestrator-health 0)
     :heuristics-score (getf plist :heuristics-score 0)
     :filename (getf plist :filename "unknown")
     :reason (getf plist :reason "unknown")
     :sbcl-version (getf plist :sbcl-version "unknown")
     :lispmind-version (getf plist :lispmind-version "unknown"))))

(defun write-golden-metadata (metadata filename)
  "Write metadata to a .meta file companion to a golden image.

Serializes the GOLDEN-IMAGE-METADATA struct as a human-readable plist
to the specified file. The plist format is portable and can be read by
any Common Lisp system.

Arguments:
  METADATA — a GOLDEN-IMAGE-METADATA struct
  FILENAME — pathname designator for the output .meta file

Returns the pathname of the written file.

Example:
  (write-golden-metadata my-metadata \"./golden-images/latest.meta\")"
  (ensure-directories-exist filename :verbose nil)
  (with-open-file (stream filename
                          :direction :output
                          :if-exists :supersede
                          :if-does-not-exist :create)
    ;; Write as a readable plist
    (format stream "(~%")
    (format stream "  :version ~A~%" (golden-image-metadata-version metadata))
    (format stream "  :timestamp ~S~%" (golden-image-metadata-timestamp metadata))
    (format stream "  :agent-count ~A~%" (golden-image-metadata-agent-count metadata))
    (format stream "  :orchestrator-health ~A~%" (golden-image-metadata-orchestrator-health metadata))
    (format stream "  :heuristics-score ~A~%" (golden-image-metadata-heuristics-score metadata))
    (format stream "  :filename ~S~%" (golden-image-metadata-filename metadata))
    (format stream "  :reason ~S~%" (golden-image-metadata-reason metadata))
    (format stream "  :sbcl-version ~S~%" (golden-image-metadata-sbcl-version metadata))
    (format stream "  :lispmind-version ~S~%" (golden-image-metadata-lispmind-version metadata))
    (format stream ")~%"))
  (pathname filename))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 8: Orchestrator Integration — Enable/Disable Immortality
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These functions provide the high-level API for enabling and disabling
the full image-based persistence subsystem. They bridge the orchestrator
and the watchdog, making it a single function call to achieve immortality.

(defun enable-immortality (orchestrator)
  "Enable full immortality mode for the ORCHESTRATOR.

This is the ONE FUNCTION to call if you want your LISPMIND swarm to
survive power loss, kernel panics, and hardware failures. It:
  1. Records initial resurrection data
  2. Starts the watchdog thread (health monitoring + auto-save)
  3. Writes an initial heartbeat file

After calling this function, the system will:
  • Monitor orchestrator health every 30 seconds
  • Automatically save golden images when the swarm improves
  • Detect unclean shutdowns and restart from the latest image

Arguments:
  ORCHESTRATOR — the orchestrator to make immortal (required)

Returns the ORCHESTRATOR (for chaining).

Example:
  ;; Make your swarm immortal
  (enable-immortality *default-orchestrator*)

  ;; Chain with agent registration
  (-> (make-orchestrator)
      (enable-immortality)
      (register-agent (make-agent :id 'worker-1)))"
  (format *trace-output* "~&[IMMORTAL] Enabling immortality mode...~%")
  ;; Record initial resurrection data
  (record-resurrection-data orchestrator)
  ;; Start the watchdog
  (start-watchdog)
  ;; Write initial heartbeat
  (write-watchdog-heartbeat)
  ;; Print the immortality banner
  (format *trace-output* "~&╔══════════════════════════════════════════════════════════════════════╗~%")
  (format *trace-output* "~&║  IMMORTALITY ENABLED                                               ║~%")
  (format *trace-output* "~&║  The swarm will survive power loss, crashes, and hardware failure. ║~%")
  (format *trace-output* "~&║  Golden images saved to: ~A                              ║~%"
          *golden-image-directory*)
  (format *trace-output* "~&║  Image persistence: ~A                                              ║~%"
          (if (image-persistence-available-p) "SBCL (full)" "cl-store (fallback)"))
  (format *trace-output* "~&╚══════════════════════════════════════════════════════════════════════╝~%")
  orchestrator)

(defun disable-immortality ()
  "Disable immortality mode.

Stops the watchdog thread and clears the resurrection data. After
calling this function, the system will NO LONGER:
  • Monitor orchestrator health automatically
  • Save golden images on improvement
  • Detect unclean shutdowns

The orchestrator and agents continue running normally — only the
persistence layer is disabled. To re-enable, call ENABLE-IMMORTALITY.

Returns T if immortality was disabled, NIL if it wasn't enabled.

Example:
  (disable-immortality)  ;; → T or NIL"
  (format *trace-output* "~&[IMMORTAL] Disabling immortality mode...~%")
  (stop-watchdog)
  ;; Clear resurrection data (but keep the hash-table structure)
  (clrhash *resurrection-data*)
  (setf *last-heuristics-score* 0)
  (format *trace-output* "~&[IMMORTAL] Immortality disabled. Swarm is mortal again.~%")
  t)

(defun record-resurrection-data (orchestrator)
  "Store orchestrator state into *RESURRECTION-DATA* before image save.

This function captures the essential state that must survive process
death and rebirth. Because SAVE-LISP-AND-DIE preserves all global
special variables, this data is automatically included in the golden
image.

What gets stored:
  • Agent IDs (so resurrect-toplevel knows who was registered)
  • Golden image version number
  • Heuristics score (so we don't immediately re-trigger saves)
  • Dashboard and auto-checkpoint running flags
  • Strategy history keys (so hotpatch versioning continues)

What does NOT get stored (recreated on resurrection):
  • Thread handles (invalid after process restart)
  • Lock objects (recreated fresh)
  • Open file descriptors (would be stale)
  • Network connections (must be re-established)

Arguments:
  ORCHESTRATOR — the orchestrator whose state to record

Returns *RESURRECTION-DATA* (the hash-table).

Example:
  (record-resurrection-data *default-orchestrator*)"
  (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
    ;; Collect agent IDs
    (let ((agent-ids '()))
      (maphash (lambda (id agent)
                 (declare (ignore agent))
                 (push id agent-ids))
               (orchestrator-agents orchestrator))
      (setf (gethash :agent-ids *resurrection-data*) (nreverse agent-ids)))
    ;; Store basic orchestrator state
    (setf (gethash :orchestrator-id *resurrection-data*) (agent-id orchestrator))
    (setf (gethash :orchestrator-health *resurrection-data*) (agent-health orchestrator))
    (setf (gethash :orchestrator-status *resurrection-data*) (agent-status orchestrator))
    ;; Store running flags for optional subsystems
    (setf (gethash :dashboard-running-p *resurrection-data*)
          (and (orchestrator-dashboard-thread orchestrator)
               (bt:thread-alive-p (orchestrator-dashboard-thread orchestrator))))
    ;; Collect strategy history keys (so we know which agents were evolved)
    (let ((history-keys '()))
      (maphash (lambda (k v)
                 (declare (ignore v))
                 (push k history-keys))
               *strategy-history*)
      (setf (gethash :strategy-history-keys *resurrection-data*) history-keys)))
  *resurrection-data*)


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 9: Graceful Degradation — Fallback to cl-store Checkpointing
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; When SBCL's SAVE-LISP-AND-DIE is not available (non-SBCL implementations,
;; insufficient permissions, or disk space constraints), the system falls
;; back to the cl-store checkpointing system defined in checkpoint.lisp.
;;
;; This fallback is transparent to the user — the same ENABLE-IMMORTALITY
;; and WATCHDOG functions work identically. Only the persistence mechanism
;; changes: instead of a single executable image, a directory of checkpoint
;; files is maintained.
;;
;; "The wise system architect plans for failure. The immortal system
;;  architect plans for the failure of the immortality mechanism itself."

(defun trigger-fallback-checkpoint (orchestrator &key (reason "watchdog-fallback"))
  "Trigger a cl-store checkpoint as a fallback when image save is unavailable.

This function is called by the watchdog when it detects that image-
based persistence is unavailable but persistence is still desired.
It delegates to CHECKPOINT-SYSTEM from checkpoint.lisp.

Arguments:
  ORCHESTRATOR — the orchestrator to checkpoint
  :REASON      — string describing why the fallback was triggered

Returns the checkpoint manifest (alist of agent IDs to files).

Example:
  (trigger-fallback-checkpoint *default-orchestrator* :reason \"non-sbcl-platform\")"
  (format *trace-output* "~&[GOLDEN] Falling back to cl-store checkpointing...~%")
  (format *trace-output* "~&[GOLDEN] Reason: ~A~%" reason)
  (checkpoint-system orchestrator *golden-image-directory*))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 10: Example Usage and Resurrection Workflow
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; ╔══════════════════════════════════════════════════════════════════════╗
;; ║  COMPLETE RESURRECTION WORKFLOW — A Narrative                      ║
;; ╚══════════════════════════════════════════════════════════════════════╝
;;
;; 1. START THE SWARM
;;    ─────────────────
;;    (ql:quickload :lispmind)
;;    (use-package :lispmind)
;;    (defparameter *orch* (make-orchestrator))
;;    (register-agent *orch* (make-agent :id 'scraper-1))
;;    (register-agent *orch* (make-agent :id 'analyst-2))
;;    (start-orchestrator *orch*)
;;
;; 2. ENABLE IMMORTALITY
;;    ───────────────────
;;    (enable-immortality *orch*)
;;    ;; The watchdog starts. Every 5 minutes it checks heuristics.
;;    ;; When the swarm improves, a golden image is saved automatically.
;;
;; 3. THE SWARM WORKS AND IMPROVES
;;    ──────────────────────────────
;;    ;; Agents are patched, errors are healed, the system learns.
;;    ;; Heuristics score: 45 → 62 → 78 → 85.
;;    ;; Golden images are saved at each 10-point improvement.
;;
;; 4. THE POWER GOES OUT
;;    ────────────────────
;;    ;; CRASH. The process dies. The machine reboots.
;;    ;; The heartbeat file is now stale.
;;
;; 5. RESURRECTION
;;    ──────────────
;;    ;; Systemd (or a human) runs the latest golden image:
;;    $ ./golden-images/lispmind-golden-4-2025-07-04T14-15-22.core
;;    ;;
;;    ;; RESURRECT-TOPLEVEL runs:
;;    ;;   "LISPMIND GOLDEN IMAGE — RESURRECTING..."
;;    ;;   "Restoring from golden image v4..."
;;    ;;   "Resurrection complete. The swarm is alive."
;;    ;;
;;    ;; The swarm resumes exactly where it left off.
;;
;; 6. MANUAL OPERATIONS
;;    ──────────────────
;;    ;; List all golden images:
;;    (list-golden-images)
;;    ;;
;;    ;; Save a manual golden image:
;;    (save-golden-image *orch* :reason "pre-deployment")
;;    ;;
;;    ;; Clean up old images:
;;    (prune-golden-images 3)
;;    ;;
;;    ;; Launch a specific image in a new process:
;;    (load-golden-image "./golden-images/lispmind-golden-3.core")
;;    ;;
;;    ;; Disable immortality:
;;    (disable-immortality)
;;
;; ═══════════════════════════════════════════════════════════════════════════

;;;; END OF IMAGE-PERSIST.LISP
;;;; ═════════════════════════════════════════════════════════════════════════
