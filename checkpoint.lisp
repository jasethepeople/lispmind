;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; CHECKPOINT.LISP — State Serialization and Resurrection for LISPMIND
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;              PERSISTENCE LAYER: AGENTS THAT SURVIVE RESTARTS
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This file implements LISPMIND's durability subsystem.  It captures the
;;; complete state of every agent to disk, using cl-store for fast binary
;;; serialization, and reconstructs agents faithfully when the system comes
;;; back online.
;;;
;;; DESIGN PHILOSOPHY
;;; ─────────────────
;;; Agents are living, breathing entities — but their *essence* is data.
;;; The strategy function is merely code; what makes an agent unique is its
;;; accumulated state, its error history, its health trajectory, and the
;;; contents of its local state hash-table.  We save that essence and let
;;; the code be reattached on resurrection.
;;;
;;; WHAT WE SAVE
;;; ─────────────
;;;   • id — the agent's identity (gensym'd symbol)
;;;   • health — current vitality score
;;;   • capabilities — what the agent can do
;;;   • error-count — accumulated failure history
;;;   • status — :running, :paused, :failed, :healing
;;;   • version — strategy version counter (for rollback awareness)
;;;   • state-data — the agent's private hash-table, serialized as an alist
;;;
;;; WHAT WE DO NOT SAVE (and why)
;;; ──────────────────────────────
;;;   • strategy function — functions are code, not data.  Restored agents
;;;     get #'default-strategy.  Re-hotpatching is the operator's
;;;     responsibility post-resurrection.
;;;   • restart-policy function — same reasoning as strategy.
;;;   • heartbeat timestamp — stale timestamps are meaningless; a fresh
;;;     heartbeat is generated on resurrection.
;;;   • lock object — mutexes cannot cross process boundaries.  A fresh
;;;     lock is created for each resurrected agent.
;;;
;;; SERIALIZATION FORMAT
;;; ───────────────────
;;; Each agent is stored as an AGENT-CHECKPOINT struct via cl-store:store.
;;; The file is named <agent-id>.lisp-checkpoint in the checkpoint
;;; directory.  cl-store handles symbols, lists, hash-tables (when
;;; converted), numbers, and keywords automatically — making it ideal for
;;; this use case.
;;;
;;; A system-wide manifest file ("manifest.lisp-checkpoint") lists all
;;; checkpointed agents with their original IDs and the timestamp of the
;;; checkpoint operation.  This manifest is used by RESTORE-SYSTEM to
;;; reconstruct the full agent colony.
;;;
;;; THREAD SAFETY
;;; ─────────────
;;; All checkpoint operations that inspect agents acquire the agent's lock
;;; before reading mutable slots (state, error-count, version).  The
;;; orchestrator's monitor-lock is acquired when iterating over agents
;;; for system-wide checkpoints.  Auto-checkpoint runs in its own thread
;;; and follows the same locking discipline.
;;;
;;; EXAMPLE USAGE
;;; ─────────────
;;;   ;; Save a single agent
;;;   (checkpoint-agent my-agent "./checkpoints/")
;;;
;;;   ;; Save the entire orchestrator colony
;;;   (checkpoint-system *default-orchestrator* "./checkpoints/")
;;;
;;;   ;; Restore from disk
;;;   (restore-system *default-orchestrator* "./checkpoints/")
;;;
;;;   ;; Automatic periodic checkpointing
;;;   (start-auto-checkpoint *default-orchestrator* :interval 60)
;;;   (stop-auto-checkpoint)
;;;
;;;   ;; Housekeeping
;;;   (list-checkpoints "./checkpoints/")
;;;   (cleanup-old-checkpoints "./checkpoints/" :keep 5)
;;;   (delete-checkpoint 'scraper-1 "./checkpoints/")

(in-package :lispmind)


;; ───────────────────────────────────────────────────────────────────────────
;; Section 1: Agent Checkpoint Data Structure
;; ───────────────────────────────────────────────────────────────────────────
;;
;; The agent-checkpoint struct is the serializable snapshot of an agent's
;; essence.  Everything in this struct is pure data — no functions, no
;; threads, no locks — so cl-store can serialize it without complaint.
;;
;; The state-data field holds an alist representation of the agent's
;; hash-table.  We convert hash-table → alist for serialization because
;; cl-store's support for hash-tables can vary across implementations,
;; whereas an alist of (key . value) pairs is universally portable.

(defstruct agent-checkpoint
  "Serializable snapshot of an agent's mutable state.

Captures everything needed to faithfully recreate an agent EXCEPT
non-serializable objects (functions, locks, threads).  The strategy
function is restored to #'DEFAULT-STRATEGY; a fresh lock is created
on resurrection.  The state hash-table is stored as an alist for
maximum portability across Lisp implementations.

Fields:
  ID          — symbol, the agent's unique identifier
  HEALTH      — integer 0..100, vitality score at checkpoint time
  CAPABILITIES — list of keywords, e.g. (:FETCH :PARSE :STORE)
  ERROR-COUNT — integer, cumulative errors since birth
  STATUS      — keyword :RUNNING :PAUSED :FAILED :HEALING
  VERSION     — integer, strategy version counter
  STATE-DATA  — alist of (key . value), the agent's private state store"
  id health capabilities error-count status version state-data)


;; ───────────────────────────────────────────────────────────────────────────
;; Section 2: Core Checkpoint Function — Serialize a Single Agent
;; ───────────────────────────────────────────────────────────────────────────
;;
;; CHECKPOINT-AGENT is the fundamental persistence primitive.  It reads
;; the agent's mutable state (holding the lock), converts the hash-table
;; to an alist, packages everything into an AGENT-CHECKPOINT struct, and
;; writes it to disk via cl-store.
;;
;; The checkpoint filename encodes the agent-id to make recovery
;; deterministic: <agent-id>.lisp-checkpoint

(defun checkpoint-agent (agent &optional (path "./checkpoints/"))
  "Serialize an agent's state to disk.

Saves the agent's id, health, capabilities, error-count, status,
version, and state hash-table contents (as an alist for reliable
serialization).  Does NOT save the strategy function, restart-policy,
or lock — these are recreated with sensible defaults on restoration.

Uses cl-store:store to write a binary checkpoint to:
  <path>/<agent-id>.lisp-checkpoint

Creates the checkpoint directory if it does not exist.

Arguments:
  AGENT — the agent instance to checkpoint
  PATH  — directory path string (default: \"./checkpoints/\")

Returns the full pathname of the written checkpoint file.

Thread-safety: acquires the agent's lock before reading mutable slots.

Example:
  (checkpoint-agent my-agent \"/var/lib/lispmind/checkpoints/\")
    ;; → #P\"/var/lib/lispmind/checkpoints/AGENT-1234.lisp-checkpoint\""
  (ensure-directories-exist path :verbose nil)
  (let* ((agent-id (agent-id agent))
         (checkpoint-file (merge-pathnames
                           (make-pathname :name (string agent-id)
                                          :type "lisp-checkpoint")
                           (pathname (ensure-directory-pathname path))))
         ;; Read mutable state under lock
         (checkpoint-data
           (bt:with-lock-held ((agent-lock agent))
             (make-agent-checkpoint
              :id agent-id
              :health (agent-health agent)
              :capabilities (copy-list (agent-capabilities agent))
              :error-count (agent-error-count agent)
              :status (agent-status agent)
              :version (agent-version agent)
              :state-data (let ((alist '()))
                            (maphash (lambda (k v)
                                       (push (cons k v) alist))
                                     (agent-state agent))
                            (nreverse alist))))))
    ;; Write the checkpoint via cl-store
    (cl-store:store checkpoint-data checkpoint-file)
    (format *trace-output* "~&[CHECKPOINT] Agent ~A checkpointed to ~A~%"
            agent-id checkpoint-file)
    checkpoint-file))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 3: Restore Function — Resurrect a Single Agent from Disk
;; ───────────────────────────────────────────────────────────────────────────
;;
;; RESTORE-AGENT-FROM-CHECKPOINT is the inverse of CHECKPOINT-AGENT.  It
;; reads an AGENT-CHECKPOINT struct from disk, reconstructs the state
;; hash-table from the alist, and creates a new agent instance with all
;; the saved data.  The strategy is set to #'default-strategy — the
;; operator must re-hotpatch if custom behaviour is needed.
;;
;; This is resurrection: the agent dies, its essence is preserved on
;; disk, and a new body is created with the same soul.

(defun restore-agent-from-checkpoint (checkpoint-path)
  "Deserialize and recreate an agent from a checkpoint file.

Process:
  1. Read the AGENT-CHECKPOINT struct via cl-store:restore
  2. Create a new agent instance with the saved data
  3. Reconstruct the state hash-table from the serialized alist
  4. Set strategy to #'DEFAULT-STRATEGY (must be re-hotpatched)
  5. Create a fresh lock for thread-safe access
  6. Set heartbeat to now (the old heartbeat is meaningless)
  7. Return the resurrected agent

Arguments:
  CHECKPOINT-PATH — pathname designator for the .lisp-checkpoint file

Returns the newly created agent instance.

Signals an error if the checkpoint file does not exist or cannot be read.

Thread-safety: the returned agent has a fresh lock — it is safe to use
immediately.

Example:
  (restore-agent-from-checkpoint \"./checkpoints/AGENT-1234.lisp-checkpoint\")
    ;; → #<AGENT {ID: AGENT-1234, HEALTH: 87, STATUS: :RUNNING}>"
  (unless (probe-file checkpoint-path)
    (error "Checkpoint file not found: ~A" checkpoint-path))
  (let* ((checkpoint-data (cl-store:restore checkpoint-path))
         (state-ht (make-hash-table :test 'eq)))
    ;; Reconstruct the state hash-table from the alist
    (dolist (pair (agent-checkpoint-state-data checkpoint-data))
      (setf (gethash (car pair) state-ht) (cdr pair)))
    ;; Create a new agent with the saved essence
    (let ((agent
            (make-agent
             :id (agent-checkpoint-id checkpoint-data)
             :health (agent-checkpoint-health checkpoint-data)
             :capabilities (agent-checkpoint-capabilities checkpoint-data)
             :error-count (agent-checkpoint-error-count checkpoint-data)
             :status (agent-checkpoint-status checkpoint-data)
             :version (agent-checkpoint-version checkpoint-data)
             :state state-ht
             :strategy #'default-strategy
             :heartbeat (local-time:now))))
      (format *trace-output* "~&[CHECKPOINT] Agent ~A restored from ~A (version ~D, health ~D)~%"
              (agent-id agent)
              checkpoint-path
              (agent-version agent)
              (agent-health agent))
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 4: System-Wide Checkpoint — Save the Entire Colony
;; ───────────────────────────────────────────────────────────────────────────
;;
;; CHECKPOINT-SYSTEM iterates over all registered agents in the
;; orchestrator, checkpoints each one individually, and writes a manifest
;; file that records which agents were saved and when.  The manifest is
;; the entry point for RESTORE-SYSTEM.
;;
;; The manifest format is a plist: (:timestamp <timestamp> :agents <list>)
;; where <list> is an alist of (agent-id . checkpoint-filename).

(defun checkpoint-system (orchestrator &optional (path "./checkpoints/"))
  "Checkpoint ALL agents in the orchestrator, plus orchestrator metadata.

Creates individual .lisp-checkpoint files for each registered agent,
and a manifest file (manifest.lisp-checkpoint) listing all checkpointed
agents with timestamps.

Acquires the orchestrator's monitor-lock during the iteration to ensure
a consistent snapshot of the agent registry.

Arguments:
  ORCHESTRATOR — the orchestrator whose agents to checkpoint
  PATH         — directory path string (default: \"./checkpoints/\")

Returns an alist of (AGENT-ID . CHECKPOINT-FILE-PATHNAME) for each
successfully checkpointed agent.

Example:
  (checkpoint-system *default-orchestrator* \"/backup/lispmind/\")
    ;; → ((SCRAPER-1 . #P\"/backup/lispmind/SCRAPER-1.lisp-checkpoint\") ...)"
  (ensure-directories-exist path :verbose nil)
  (let ((checkpoint-dir (ensure-directory-pathname (pathname path)))
        (manifest '()))
    (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
      (maphash
       (lambda (aid agent)
         (declare (ignore aid))
         (handler-case
             (let ((cp-file (checkpoint-agent agent path)))
               (push (cons (agent-id agent) cp-file) manifest))
           (error (e)
             (format *trace-output*
                     "~&[CHECKPOINT] ERROR checkpointing agent ~A: ~A~%"
                     (agent-id agent) e))))
       (orchestrator-agents orchestrator)))
    ;; Write the manifest
    (let ((manifest-file (merge-pathnames
                          (make-pathname :name "manifest"
                                         :type "lisp-checkpoint")
                          checkpoint-dir))
          (manifest-data
            (list :timestamp (local-time:now)
                  :agent-count (length manifest)
                  :agents (nreverse manifest))))
      (cl-store:store manifest-data manifest-file)
      (format *trace-output*
              "~&[CHECKPOINT] System checkpoint complete: ~D agents saved to ~A~%"
              (length manifest) checkpoint-dir))
    (nreverse manifest)))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 5: System-Wide Restore — Resurrect the Entire Colony
;; ───────────────────────────────────────────────────────────────────────────
;;
;; RESTORE-SYSTEM reads the manifest file, then for each agent listed
;; calls RESTORE-AGENT-FROM-CHECKPOINT and registers the resurrected
;; agent with the orchestrator.  The orchestrator must already exist
;; (typically freshly created via MAKE-ORCHESTRATOR).
;;
;; If an individual agent's checkpoint fails to load, an error message
;; is printed and the agent is skipped — partial restoration is better
;; than total failure.

(defun restore-system (orchestrator path)
  "Restore all agents from a checkpoint directory.

Process:
  1. Read the manifest file (manifest.lisp-checkpoint)
  2. For each agent entry in the manifest: call RESTORE-AGENT-FROM-CHECKPOINT
  3. Register each restored agent with the orchestrator via REGISTER-AGENT
  4. Print a summary of restored agents

Arguments:
  ORCHESTRATOR — the orchestrator to register restored agents with
  PATH         — directory path string containing checkpoint files

Returns a list of the restored agent instances.

If the manifest file does not exist, signals an error.
Individual agent restore failures are logged but do not abort the process.

Example:
  (defparameter *orch* (make-orchestrator))
  (restore-system *orch* \"./checkpoints/\")
    ;; → (#<AGENT SCRAPER-1> #<AGENT ANALYST-2> ...)"
  (let* ((checkpoint-dir (ensure-directory-pathname (pathname path)))
         (manifest-file (merge-pathnames
                         (make-pathname :name "manifest"
                                        :type "lisp-checkpoint")
                         checkpoint-dir))
         (restored '()))
    (unless (probe-file manifest-file)
      (error "No manifest file found at ~A — cannot restore system." manifest-file))
    (let ((manifest-data (cl-store:restore manifest-file)))
      (format *trace-output*
              "~&[CHECKPOINT] Restoring ~D agents from checkpoint (~A)...~%"
              (getf manifest-data :agent-count 0)
              (getf manifest-data :timestamp))
      ;; Restore each agent from its checkpoint file
      (dolist (entry (getf manifest-data :agents))
        (let ((agent-id (car entry))
              (cp-file (cdr entry)))
          (handler-case
              (let ((agent (restore-agent-from-checkpoint cp-file)))
                (register-agent orchestrator agent)
                (push agent restored))
            (error (e)
              (format *trace-output*
                      "~&[CHECKPOINT] FAILED to restore agent ~A: ~A — skipping~%"
                      agent-id e))))))
    (format *trace-output*
            "~&[CHECKPOINT] ╔══════════════════════════════════════════════════════════════╗~%")
    (format *trace-output*
            "~&[CHECKPOINT] ║  RESTORE COMPLETE: ~D/~D agents resurrected~%"
            (length restored)
            (max (length restored) 1))
    (format *trace-output*
            "~&[CHECKPOINT] ║  Restored agents: ~{~A~^, ~}~%"
            (mapcar #'agent-id (nreverse restored)))
    (format *trace-output*
            "~&[CHECKPOINT] ╚══════════════════════════════════════════════════════════════╝~%")
    (nreverse restored)))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 6: Checkpoint Management — Listing, Deletion, Cleanup
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These utility functions help operators manage the checkpoint directory:
;; list what's available, delete stale checkpoints, and keep disk usage
;; under control by pruning old files.

(defun list-checkpoints (&optional (path "./checkpoints/"))
  "List all available checkpoint files with timestamps and agent IDs.

Scans the checkpoint directory for .lisp-checkpoint files (excluding
manifest.lisp-checkpoint), reads each one to extract the agent ID and
checkpoint metadata, and returns a formatted list.

Arguments:
  PATH — directory path string (default: \"./checkpoints/\")

Returns an alist of
  ((AGENT-ID FILE-PATHNAME WRITE-DATE) ...)
sorted by write-date (oldest first).

Example:
  (list-checkpoints \"./checkpoints/\")
    ;; → ((SCRAPER-1 #P\".../SCRAPER-1.lisp-checkpoint\") (ANALYST-2 ...) ...)"
  (let ((checkpoint-dir (ensure-directory-pathname (pathname path)))
        (result '()))
    (when (probe-file checkpoint-dir)
      (dolist (file (directory (merge-pathnames "*.lisp-checkpoint" checkpoint-dir)))
        (let ((name (pathname-name file)))
          ;; Skip the manifest file
          (unless (string-equal name "manifest")
            (let ((agent-id (intern (string-upcase name) :keyword)))
              (push (list agent-id
                          file
                          (when (probe-file file)
                            (file-write-date file)))
                    result))))))
    ;; Sort by write date (oldest first)
    (sort result #'< :key #'third)))

(defun delete-checkpoint (agent-id &optional (path "./checkpoints/"))
  "Delete a specific agent's checkpoint file.

Constructs the filename <agent-id>.lisp-checkpoint in the checkpoint
directory and deletes it if it exists.  Also deletes the manifest file
if present (since it is now stale).

Arguments:
  AGENT-ID — symbol, the ID of the agent whose checkpoint to delete
  PATH     — directory path string (default: \"./checkpoints/\")

Returns T if a file was deleted, NIL if no file existed.

Example:
  (delete-checkpoint 'scraper-1 \"./checkpoints/\")  ;; → T or NIL"
  (let* ((checkpoint-dir (ensure-directory-pathname (pathname path)))
         (cp-file (merge-pathnames
                   (make-pathname :name (string agent-id)
                                  :type "lisp-checkpoint")
                   checkpoint-dir))
         (manifest-file (merge-pathnames
                         (make-pathname :name "manifest"
                                        :type "lisp-checkpoint")
                         checkpoint-dir))
         (deleted nil))
    (when (probe-file cp-file)
      (delete-file cp-file)
      (setf deleted t)
      (format *trace-output* "~&[CHECKPOINT] Deleted checkpoint for agent ~A~%"
              agent-id))
    ;; Manifest is now stale — remove it too
    (when (probe-file manifest-file)
      (delete-file manifest-file))
    deleted))

(defun cleanup-old-checkpoints (&optional (path "./checkpoints/") (keep 10))
  "Keep only the KEEP most recent checkpoint files, delete older ones.

Lists all checkpoint files sorted by write date (oldest first), then
deletes all but the most recent KEEP files.  The manifest file is also
removed since it becomes stale.

Arguments:
  PATH — directory path string (default: \"./checkpoints/\")
  KEEP — integer, number of most recent checkpoints to retain (default: 10)

Returns the number of deleted files.

Example:
  (cleanup-old-checkpoints \"./checkpoints/\" 5)  ;; → 3 (files deleted)"
  (let* ((all-checkpoints (list-checkpoints path))
         (to-delete (if (> (length all-checkpoints) keep)
                        (subseq all-checkpoints 0 (- (length all-checkpoints) keep))
                        nil))
         (deleted-count 0))
    (dolist (entry to-delete)
      (let ((file (second entry)))
        (when (probe-file file)
          (delete-file file)
          (incf deleted-count)
          (format *trace-output*
                  "~&[CHECKPOINT] Cleaned up old checkpoint: ~A~%"
                  file))))
    ;; Remove stale manifest
    (let ((manifest-file (merge-pathnames
                          (make-pathname :name "manifest"
                                         :type "lisp-checkpoint")
                          (ensure-directory-pathname (pathname path)))))
      (when (probe-file manifest-file)
        (delete-file manifest-file)))
    (format *trace-output*
            "~&[CHECKPOINT] Cleanup complete: ~D old checkpoints removed, ~D retained~%"
            deleted-count (min keep (length all-checkpoints)))
    deleted-count))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 7: Auto-Checkpoint — Background Persistence Thread
;; ───────────────────────────────────────────────────────────────────────────
;;
;; The auto-checkpoint system runs a background thread that periodically
;; checkpoints all agents.  This ensures that even if the system crashes,
;; at most INTERVAL seconds of agent state are lost.  The thread is
;; stoppable via STOP-AUTO-CHECKPOINT.
;;
;; WHY A SEPARATE THREAD?
;; ───────────────────────
;; Checkpointing is I/O-heavy and can pause for disk writes.  We don't
;; want the monitor loop (which must respond within 2 seconds) to block
;; on cl-store:store calls.  A dedicated thread isolates the latency.
;;
;; WHY SLEEP RATHER THAN A TIMER?
;; ────────────────────────────────
;; A simple sleep loop is robust, portable across SBCL versions, and
;; trivial to interrupt (the thread can be destroyed).  Condition-variable
;; based wakeups would be cleaner but add complexity for marginal benefit.

(defvar *auto-checkpoint-thread* nil
  "The background auto-checkpoint thread, or NIL if not running.

Set by START-AUTO-CHECKPOINT, cleared by STOP-AUTO-CHECKPOINT.
This is an internal variable — do not modify directly.")

(defun start-auto-checkpoint (orchestrator &key (interval 60) (path "./checkpoints/"))
  "Start a background thread that checkpoints all agents every INTERVAL seconds.

If an auto-checkpoint thread is already running, it is stopped and
replaced (with a warning).  The thread runs until STOP-AUTO-CHECKPOINT
is called.

Arguments:
  ORCHESTRATOR — the orchestrator whose agents to checkpoint
  :INTERVAL    — seconds between checkpoints (default: 60)
  :PATH        — directory path string (default: \"./checkpoints/\")

Returns the background thread.

Thread-safety: the checkpoint thread acquires the orchestrator's
monitor-lock during each checkpoint cycle, same as CHECKPOINT-SYSTEM.

Example:
  ;; Checkpoint every minute
  (start-auto-checkpoint *default-orchestrator* :interval 60)

  ;; Checkpoint every 5 minutes to a custom path
  (start-auto-checkpoint *orch* :interval 300 :path \"/var/lib/lispmind/\")"
  ;; Stop any existing thread
  (when (and *auto-checkpoint-thread*
             (bt:thread-alive-p *auto-checkpoint-thread*))
    (format *trace-output*
            "~&[CHECKPOINT] Stopping existing auto-checkpoint thread~%")
    (bt:destroy-thread *auto-checkpoint-thread*)
    (setf *auto-checkpoint-thread* nil))
  ;; Spawn a new checkpoint thread
  (let ((thread
          (bt:make-thread
           (lambda ()
             (format *trace-output*
                     "~&[CHECKPOINT] Auto-checkpoint thread started (every ~Ds)~%"
                     interval)
             (loop
               (sleep interval)
               (when (and orchestrator
                          (orchestrator-running-p orchestrator))
                 (handler-case
                     (checkpoint-system orchestrator path)
                   (error (e)
                     (format *trace-output*
                             "~&[CHECKPOINT] Auto-checkpoint error: ~A~%"
                             e))))))
           :name "auto-checkpoint"
           :initial-bindings '())))
    (setf *auto-checkpoint-thread* thread)
    thread))

(defun stop-auto-checkpoint ()
  "Stop the auto-checkpoint thread.

Destroys the background checkpoint thread (if running) and clears
*AUTO-CHECKPOINT-THREAD*.  This is safe: the thread only sleeps and
performs checkpointing — no critical work is lost by interrupting it.

Returns T if a thread was stopped, NIL if no thread was running.

Example:
  (stop-auto-checkpoint)  ;; → T or NIL"
  (if (and *auto-checkpoint-thread*
           (bt:thread-alive-p *auto-checkpoint-thread*))
      (progn
        (bt:destroy-thread *auto-checkpoint-thread*)
        (setf *auto-checkpoint-thread* nil)
        (format *trace-output* "~&[CHECKPOINT] Auto-checkpoint thread stopped.~%")
        t)
      (progn
        (format *trace-output* "~&[CHECKPOINT] No auto-checkpoint thread running.~%")
        nil)))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 8: Convenience Utilities
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These are thin wrappers for the most common checkpoint operations,
;; making the REPL experience more pleasant.

(defun checkpoint-directory-exists-p (&optional (path "./checkpoints/"))
  "Return T if the checkpoint directory exists and is readable.

A quick predicate for dashboards and scripts to verify checkpoint
infrastructure before attempting save/load operations."
  (let ((dir (ensure-directory-pathname (pathname path))))
    (and (probe-file dir)
         t)))

(defun latest-checkpoint-timestamp (&optional (path "./checkpoints/"))
  "Return the write-date of the most recent checkpoint file, or NIL.

Useful for dashboards to display 'Last checkpointed: 5 minutes ago'.

Arguments:
  PATH — directory path string (default: \"./checkpoints/\")

Returns a universal-time integer or NIL."
  (let ((checkpoints (list-checkpoints path)))
    (when checkpoints
      ;; list-checkpoints returns oldest first, so last is newest
      (third (first (last checkpoints))))))


;;;; ═════════════════════════════════════════════════════════════════════════
;;;; END OF CHECKPOINT.LISP
;;;; ═════════════════════════════════════════════════════════════════════════
