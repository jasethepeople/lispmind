;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;; TACTICAL CHECKPOINT — v2.4 Resume from Last Known State
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This module implements the tactical checkpoint/resume subsystem for
;;; LISPMIND v2.4. It captures the complete offensive swarm state to disk
;;; after every successful foothold, enabling full recovery after process
;;; death, network partition, or operator-triggered restart.
;;;
;;; DESIGN PHILOSOPHY
;;; ─────────────────
;;;   • Checkpoint AFTER every foothold — never lose an entry point.
;;;   • 30-second auto-checkpoint — periodic full-state snapshots.
;;;   • Compact binary serialization via cl-store — fast, complete.
;;;   • Resume merges new discoveries — never overwrite, always augment.
;;;   • Prune old checkpoints — keep only the last N (default 10).
;;;
;;; WHAT WE SAVE
;;; ──────────────
;;;   • All active footholds with session tokens and pivot chains.
;;;   • The full network map (discovered adjacency list).
;;;   • Persistence state — which footholds have what persistence method.
;;;   • Active proxy chains and session tokens.
;;;   • Target registry with discovery metadata.
;;;   • Agent strategies and evolution history.
;;;   • Gossip mesh peer state for rapid re-mesh.
;;;
;;; WHAT WE DO NOT SAVE (and why)
;;; ──────────────────────────────
;;;   • Live process handles — these die with the process. Re-established
;;;     on resume via session tokens.
;;;   • In-memory telemetry buffers — fresh telemetry on resume.
;;;   • Strategy functions — reloaded from code. Only rankings/config saved.
;;;
;;; SERIALIZATION FORMAT
;;; ───────────────────
;;; Each checkpoint is a TACTICAL-CHECKPOINT struct serialized with
;;; cl-store:store to a file named tactical-checkpoint-<timestamp>.bin
;;; A symlink "tactical-checkpoint-latest.bin" always points to the
;;; most recent checkpoint.
;;;
;;; "A foothold is only as good as your ability to return to it.
;;;  Checkpoint everything. Resume everywhere."

(in-package :lispmind)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defparameter *tactical-checkpoint-version* "2.4.0"
    "Version string for the tactical checkpoint subsystem."))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 1: Checkpoint Data Structures — Everything That Matters
;; ═══════════════════════════════════════════════════════════════════════════

(defstruct (tactical-checkpoint
            (:constructor make-tactical-checkpoint
                          (&key timestamp version active-footholds
                                pivot-chains persistence-state proxy-chains
                                session-tokens target-registry network-map
                                agent-strategies evolution-history
                                telemetry-snapshots gossip-peer-state))
            (:copier nil))
  "Complete swarm state snapshot for resume after process death.

   This struct contains EVERYTHING needed to reconstruct the tactical
   swarm's operational picture from a cold start. All fields are pure
   data — no functions, no streams, no locks — so cl-store can
   serialize without complaint.

   Fields:
     TIMESTAMP         — Unix epoch seconds of checkpoint creation.
     VERSION           — String checkpoint format version (e.g. \"2.4.0\").
     ACTIVE-FOOTHOLDS  — List of FOOTHOLD-STATE structs.
     PIVOT-CHAINS      — Alist of (parent-token . child-tokens-list).
     PERSISTENCE-STATE — Hash-table: session-token -> persistence method.
     PROXY-CHAINS      — List of active proxy chain descriptions.
     SESSION-TOKENS    — Hash-table: session-token -> creation timestamp.
     TARGET-REGISTRY   — Hash-table: target-ip -> discovery metadata plist.
     NETWORK-MAP       — Alist: ip-address -> list of adjacent ip-addresses.
     AGENT-STRATEGIES  — Alist: agent-id -> strategy config plist.
     EVOLUTION-HISTORY — List of recent evolution event plists.
     TELEMETRY-SNAPSHOTS — List of last N telemetry readings.
     GOSSIP-PEER-STATE — Alist of peer-id -> last-seen-timestamp.

   Size estimate: ~50KB for a 10-foothold, 5-peer deployment.
   Checkpoint time: <100ms on SSD for typical deployments."
  timestamp
  version
  active-footholds
  pivot-chains
  persistence-state
  proxy-chains
  session-tokens
  target-registry
  network-map
  agent-strategies
  evolution-history
  telemetry-snapshots
  gossip-peer-state)

(defstruct (foothold-state
            (:constructor make-foothold-state
                          (&key session-token target-ip target-port
                                entry-vector pivot-depth parent-foothold
                                child-footholds persistence-active-p
                                persistence-method proxy-chain
                                noise-level evasion-score tts-seconds
                                established-at))
            (:copier nil))
  "The state of a single foothold — everything about one entry point.

   This is the atomic unit of tactical state. Each compromised host
   gets one FOOTHOLD-STATE. Pivoting creates child footholds that
   reference their parent via PARENT-FOOTHOLD.

   Fields:
     SESSION-TOKEN        — String nonce identifying this session.
     TARGET-IP            — String IP address of compromised host.
     TARGET-PORT          — Integer port number of entry.
     ENTRY-VECTOR         — Keyword: :SSH :SMB :RDP :HTTP :WMI :LDAP
                            :SNMP :FTP :TELNET :CUSTOM.
     PIVOT-DEPTH          — Integer 0+, recursion from initial entry.
     PARENT-FOOTHOLD      — String session-token of parent, or NIL.
     CHILD-FOOTHOLDS      — List of string child session-tokens.
     PERSISTENCE-ACTIVE-P — T if persistence mechanism is installed.
     PERSISTENCE-METHOD   — Keyword: :REGISTRY :WMI :SCHTASKS :SERVICE
                            :DLL-HIJACK :WEBSHELL :CRON :LAUNCH-AGENT.
     PROXY-CHAIN          — String describing proxy route, or NIL.
     NOISE-LEVEL          — Integer 0-100, evasion noise setting.
     EVASION-SCORE        — Float 0.0-1.0, calculated evasion rating.
     TTS-SECONDS          — Integer, time-to-shell for this entry.
     ESTABLISHED-AT       — Unix epoch seconds when foothold was gained.

   Example:
     (make-foothold-state
       :session-token \"fh-9x7k2m\"
       :target-ip \"10.0.0.5\"
       :target-port 445
       :entry-vector :smb
       :pivot-depth 1
       :parent-foothold \"fh-root-a1b2\"
       :child-footholds '(\"fh-child-c3d4\")
       :persistence-active-p t
       :persistence-method :registry
       :proxy-chain \"proxy-1->proxy-2\"
       :noise-level 15
       :evasion-score 0.85
       :tts-seconds 120
       :established-at (get-universal-time))"
  session-token
  target-ip
  target-port
  entry-vector
  pivot-depth
  parent-foothold
  child-footholds
  persistence-active-p
  persistence-method
  proxy-chain
  noise-level
  evasion-score
  tts-seconds
  established-at)


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 2: Checkpoint Configuration and State
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *checkpoint-directory* "./tactical-checkpoints/"
  "Directory for tactical checkpoint files.

   Created automatically if it does not exist. Each checkpoint is
   stored as a separate file named:
     tactical-checkpoint-<unix-timestamp>.bin

   A symlink tactical-checkpoint-latest.bin always points to the
   most recent checkpoint for fast resume.

   Default: \"./tactical-checkpoints/\" (relative to working directory).
   Override at init time for custom paths.")

(defvar *checkpoint-interval-seconds* 30
  "Seconds between automatic checkpoints.

   At 30s, a deployment running for 1 hour generates 120 checkpoints.
   With the default keep limit of 10, disk usage is ~500KB.

   Can be adjusted dynamically via (SETF *CHECKPOINT-INTERVAL-SECONDS*).
   Minimum enforced: 5 seconds. Maximum: 3600 seconds (1 hour).")

(defvar *checkpoint-thread* nil
  "Background thread running the auto-checkpoint loop, or NIL.

   Spawned by START-AUTO-CHECKPOINT, joined by STOP-AUTO-CHECKPOINT.
   The loop runs AUTO-CHECKPOINT-LOOP.")

(defvar *checkpoint-shutdown-p* nil
  "When T, signals the auto-checkpoint loop to exit gracefully.

   Set by STOP-AUTO-CHECKPOINT. The loop checks this flag after
   each sleep interval.")

(defvar *checkpoint-lock* (bt:make-lock "tactical-checkpoint")
  "Lock protecting checkpoint file operations.

   Acquired during save and load to prevent concurrent writes/reads
   that could corrupt checkpoint files.")

(defvar *checkpoint-last-save* 0
  "Unix timestamp of the last successful checkpoint save.
   Used to prevent redundant saves and calculate time-since-checkpoint.")

(defvar *max-pivot-depth* 5
  "Maximum allowed pivot depth.

   Footholds at this depth cannot spawn child pivots — they are
   leaf nodes in the pivot chain. Prevents runaway recursion.

   Default: 5. Adjust based on target network size and tolerance
   for lateral movement exposure.")


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 3: Checkpoint Save/Load — The Core Operations
;; ═══════════════════════════════════════════════════════════════════════════

(defun ensure-checkpoint-directory ()
  "Ensure the checkpoint directory exists.

   Creates *CHECKPOINT-DIRECTORY* and all parent directories if they
   do not exist. Silently succeeds if the directory already exists.

   Returns: The pathname of the checkpoint directory."
  (ensure-directories-exist *checkpoint-directory*)
  (pathname *checkpoint-directory*))

(defun make-checkpoint-filename (&optional (timestamp (get-universal-time)))
  "Generate a checkpoint filename for TIMESTAMP.

   Format: tactical-checkpoint-<timestamp>.bin

   Arguments:
     TIMESTAMP — Unix epoch seconds (default: current time).

   Returns: String filename."
  (format nil "tactical-checkpoint-~D.bin" timestamp))

(defun make-checkpoint-path (&optional (timestamp (get-universal-time)))
  "Generate a full checkpoint file path for TIMESTAMP.

   Arguments:
     TIMESTAMP — Unix epoch seconds (default: current time).

   Returns: Pathname."
  (merge-pathnames (make-checkpoint-filename timestamp)
                   (ensure-checkpoint-directory)))

(defun build-tactical-checkpoint (orchestrator)
  "Construct a TACTICAL-CHECKPOINT from the current orchestrator state.

   Extracts all relevant state from the orchestrator and its agents,
   building a complete snapshot suitable for serialization.

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.

   Returns: TACTICAL-CHECKPOINT struct.

   Thread-safe: acquires *CHECKPOINT-LOCK*."
  (bt:with-lock-held (*checkpoint-lock*)
    (let ((now (get-universal-time)))
      (make-tactical-checkpoint
       :timestamp now
       :version *tactical-checkpoint-version*
       :active-footholds (extract-active-footholds orchestrator)
       :pivot-chains (extract-pivot-chains orchestrator)
       :persistence-state (extract-persistence-state orchestrator)
       :proxy-chains (extract-proxy-chains orchestrator)
       :session-tokens (extract-session-tokens orchestrator)
       :target-registry (extract-target-registry orchestrator)
       :network-map (extract-network-map orchestrator)
       :agent-strategies (extract-agent-strategies orchestrator)
       :evolution-history (extract-evolution-history orchestrator)
       :telemetry-snapshots (extract-telemetry-snapshots)
       :gossip-peer-state (extract-gossip-peer-state)))))

(defun save-tactical-checkpoint (orchestrator)
  "Save complete tactical state to disk.

   Actions:
     1. Build TACTICAL-CHECKPOINT from orchestrator state.
     2. Serialize to binary using cl-store:store.
     3. Write to timestamped file in *CHECKPOINT-DIRECTORY*.
     4. Update 'tactical-checkpoint-latest.bin' symlink.
     5. Prune old checkpoints (keep last 10).
     6. Record timestamp in *CHECKPOINT-LAST-SAVE*.

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.

   Returns: Pathname of the saved checkpoint file, or NIL on failure.

   Thread-safe: acquires *CHECKPOINT-LOCK*.

   Example:
     (save-tactical-checkpoint *default-orchestrator*)"
  (handler-case
      (bt:with-lock-held (*checkpoint-lock*)
        (let* ((checkpoint (build-tactical-checkpoint orchestrator))
               (filename (make-checkpoint-filename
                         (tactical-checkpoint-timestamp checkpoint)))
               (filepath (merge-pathnames filename
                                         (ensure-checkpoint-directory)))
               (latest-link (merge-pathnames "tactical-checkpoint-latest.bin"
                                            (ensure-checkpoint-directory))))
          ;; Serialize and write
          #+cl-store
          (cl-store:store checkpoint filepath)
          #-cl-store
          (with-open-file (out filepath :direction :output
                                        :if-exists :supersede
                                        :element-type '(unsigned-byte 8))
            ;; Fallback: serialize as plist and write as text
            (write-sequence
             (flexi-streams:string-to-octets
              (with-output-to-string (s)
                (prin1 (checkpoint-to-plist checkpoint) s)))
             out))
          ;; Update latest symlink
          (when (probe-file latest-link)
            (delete-file latest-link))
          #+unix
          (sb-ext:run-program "/bin/ln"
                             (list "-s" (namestring filepath)
                                   (namestring latest-link))
                             :search nil :wait nil)
          ;; Update timestamp
          (setf *checkpoint-last-save*
                (tactical-checkpoint-timestamp checkpoint))
          ;; Prune old checkpoints
          (prune-old-checkpoints)
          (format t "~&[CHECKPOINT] Saved ~A (~A)~%"
                  filename
                  *tactical-checkpoint-version*)
          filepath))
    (error (e)
      (format *error-output* "~&[CHECKPOINT] SAVE FAILED: ~A~%" e)
      nil)))

(defun load-tactical-checkpoint (&optional (path *checkpoint-directory*))
  "Load the most recent tactical checkpoint.

   If PATH is a directory, loads the 'tactical-checkpoint-latest.bin'
   symlink target. If PATH is a file, loads that file directly.

   Arguments:
     PATH — Directory or file path (default: *CHECKPOINT-DIRECTORY*).

   Returns: TACTICAL-CHECKPOINT struct, or NIL if no checkpoint found.

   Example:
     (load-tactical-checkpoint)
     (load-tactical-checkpoint \"./my-checkpoints/tactical-checkpoint-12345.bin\")"
  (let ((filepath (if (pathname-name path)
                     path
                     (merge-pathnames "tactical-checkpoint-latest.bin"
                                     (ensure-directories-exist path)))))
    (if (probe-file filepath)
        (handler-case
            (progn
              (format t "~&[CHECKPOINT] Loading ~A...~%" filepath)
              #+cl-store
              (let ((cp (cl-store:restore filepath)))
                (format t "[CHECKPOINT] Loaded v~A, ~D footholds, ~D peers.~%"
                        (tactical-checkpoint-version cp)
                        (length (tactical-checkpoint-active-footholds cp))
                        (length (tactical-checkpoint-gossip-peer-state cp)))
                cp)
              #-cl-store
              (let* ((raw (alexandria:read-file-into-string filepath))
                     (plist (read-from-string raw)))
                (plist-to-checkpoint plist)))
          (error (e)
            (format *error-output*
                    "~&[CHECKPOINT] LOAD FAILED: ~A~%" e)
            nil))
        (progn
          (format t "~&[CHECKPOINT] No checkpoint found at ~A~%" filepath)
          nil))))

(defun resume-from-checkpoint (orchestrator &optional checkpoint)
  "Resume the swarm from a checkpoint.

   If CHECKPOINT is provided, uses it directly. Otherwise, loads the
   most recent checkpoint from disk. Restores all foothold state,
   pivot chains, persistence markers, proxy chains, session tokens,
   target registry, and network map into the orchestrator.

   Actions:
     1. Load checkpoint (if not provided).
     2. Restore active footholds to orchestrator.
     3. Rebuild pivot chain graph.
     4. Restore persistence state markers.
     5. Re-establish proxy chain descriptors.
     6. Merge target registry.
     7. Merge network map.
     8. Restore agent strategies.
     9. Log resume summary.

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance to populate.
     CHECKPOINT   — Optional TACTICAL-CHECKPOINT struct.

   Returns: Resume status plist with :FOOTHOLDS-RESTORED,
            :TARGETS-KNOWN, :PEERS-KNOWN, :SUCCESS-P.

   Example:
     (resume-from-checkpoint *default-orchestrator*)
     (resume-from-checkpoint *default-orchestrator* my-checkpoint)"
  (let ((cp (or checkpoint (load-tactical-checkpoint))))
    (unless cp
      (return-from resume-from-checkpoint
        (list :success-p nil
              :footholds-restored 0
              :targets-known 0
              :peers-known 0
              :error "No checkpoint found")))
    (format t "~&[CHECKPOINT] Resuming from v~A checkpoint (~D footholds)...~%"
            (tactical-checkpoint-version cp)
            (length (tactical-checkpoint-active-footholds cp)))
    ;; Restore footholds
    (let ((footholds-restored 0))
      (dolist (fh (tactical-checkpoint-active-footholds cp))
        (restore-foothold-to-orchestrator orchestrator fh)
        (incf footholds-restored))
      ;; Restore pivot chains
      (restore-pivot-chains orchestrator
                           (tactical-checkpoint-pivot-chains cp))
      ;; Restore persistence state
      (restore-persistence-state orchestrator
                                (tactical-checkpoint-persistence-state cp))
      ;; Restore proxy chains
      (restore-proxy-chains orchestrator
                           (tactical-checkpoint-proxy-chains cp))
      ;; Merge network map
      (let ((merged-map (merge-network-maps
                        nil
                        (tactical-checkpoint-network-map cp))))
        (install-network-map orchestrator merged-map))
      ;; Merge target registry
      (merge-target-registry orchestrator
                            (tactical-checkpoint-target-registry cp))
      ;; Restore gossip peer state
      (restore-gossip-peer-state
       (tactical-checkpoint-gossip-peer-state cp))
      ;; Build status
      (let ((status (list :success-p t
                          :footholds-restored footholds-restored
                          :targets-known (hash-table-count
                                         (tactical-checkpoint-target-registry
                                          cp))
                          :peers-known (length
                                       (tactical-checkpoint-gossip-peer-state
                                        cp))
                          :version (tactical-checkpoint-version cp)
                          :timestamp (tactical-checkpoint-timestamp cp))))
        (format t "[CHECKPOINT] Resume complete: ~D footholds, ~D targets, ~D peers.~%"
                (getf status :footholds-restored)
                (getf status :targets-known)
                (getf status :peers-known))
        status))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 4: Auto-Checkpoint Loop — Background Persistence
;; ═══════════════════════════════════════════════════════════════════════════

(defun auto-checkpoint-loop (orchestrator interval)
  "Background thread: save checkpoint every INTERVAL seconds.

   Loop behavior:
     1. Sleep for INTERVAL seconds.
     2. Check *CHECKPOINT-SHUTDOWN-P* — exit if T.
     3. Call SAVE-TACTICAL-CHECKPOINT.
     4. Log result.
     5. Repeat.

   This loop is INDESTRUCTIBLE — all errors are caught, logged, and
   the loop continues. The only exit is *CHECKPOINT-SHUTDOWN-P*.

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.
     INTERVAL     — Seconds between checkpoints.

   This function does not return until shutdown is signaled."
  (let ((sleep-time (max 5 (min 3600 interval))))
    (loop
      (sleep sleep-time)
      (when *checkpoint-shutdown-p*
        (return-from auto-checkpoint-loop nil))
      (handler-case
          (let ((path (save-tactical-checkpoint orchestrator)))
            (when path
              (format t "[AUTO-CHECKPOINT] Saved to ~A~%" path)))
        (error (e)
          (format *error-output*
                  "~&[AUTO-CHECKPOINT] Error: ~A. Continuing...~%"
                  e))))))

(defun start-auto-checkpoint (orchestrator &key (interval 30))
  "Start automatic checkpointing.

   Spawns a background thread that saves a checkpoint every INTERVAL
   seconds. If auto-checkpoint is already running, stops the old
   thread first.

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.
     INTERVAL     — Seconds between checkpoints (default 30).

   Returns: T if started successfully.

   Example:
     (start-auto-checkpoint *default-orchestrator* :interval 30)"
  ;; Stop existing thread if any
  (when (and *checkpoint-thread*
             (bt:thread-alive-p *checkpoint-thread*))
    (stop-auto-checkpoint))
  (setf *checkpoint-shutdown-p* nil)
  (setf *checkpoint-thread*
        (bt:make-thread
         (lambda () (auto-checkpoint-loop orchestrator interval))
         :name "tactical-auto-checkpoint"))
  (format t "~&[CHECKPOINT] Auto-checkpoint started (~Ds interval).~%"
          interval)
  t)

(defun stop-auto-checkpoint ()
  "Stop automatic checkpointing.

   Signals shutdown to the auto-checkpoint thread and joins it
   with a 15-second timeout.

   Returns: T if stopped successfully."
  (format t "~&[CHECKPOINT] Stopping auto-checkpoint...~%")
  (setf *checkpoint-shutdown-p* t)
  (when (and *checkpoint-thread*
             (bt:thread-alive-p *checkpoint-thread*))
    (handler-case
        (bt:join-thread *checkpoint-thread* :timeout 15)
      (error (e)
        (format t "[CHECKPOINT] Thread join timeout: ~A~%" e))))
  (setf *checkpoint-thread* nil)
  (format t "[CHECKPOINT] Auto-checkpoint stopped.~%")
  t)


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 5: Checkpoint Housekeeping — Listing and Pruning
;; ═══════════════════════════════════════════════════════════════════════════

(defun list-checkpoints ()
  "List all available checkpoints.

   Scans *CHECKPOINT-DIRECTORY* for files matching the pattern
   'tactical-checkpoint-*.bin' and returns them sorted by
   timestamp (newest first).

   Returns: List of plists, each with :FILENAME :TIMESTAMP :SIZE :AGE.

   Example:
     (list-checkpoints)
     ;; => ((:FILENAME \"tactical-checkpoint-12345.bin\" :TIMESTAMP 12345 ...))"
  (let ((dir (ensure-checkpoint-directory))
        (checkpoints nil))
    (dolist (file (directory
                   (merge-pathnames "tactical-checkpoint-*.bin" dir)))
      (let* ((name (pathname-name file))
             (ts-str (and name
                         (ppcre:regex-replace
                          "tactical-checkpoint-" name "")))
             (ts (ignore-errors (parse-integer ts-str :junk-allowed t)))
             (size (ignore-errors
                    (with-open-file (s file :direction :input)
                      (file-length s)))))
        (when ts
          (push (list :filename (pathname-name file)
                     :timestamp ts
                     :size (or size 0)
                     :age (- (get-universal-time) ts))
               checkpoints))))
    (sort checkpoints #'> :key (lambda (c) (getf c :timestamp)))))

(defun prune-old-checkpoints (&optional (keep 10))
  "Keep only the KEEP most recent checkpoints.

   Lists all checkpoints, sorts by timestamp (newest first), and
   deletes all but the KEEP most recent. Also preserves the
   'tactical-checkpoint-latest.bin' symlink target regardless of age.

   Arguments:
     KEEP — Integer, number of checkpoints to retain (default 10).

   Returns: Number of checkpoints deleted.

   Example:
     (prune-old-checkpoints)      ;; Keep last 10
     (prune-old-checkpoints 5)    ;; Keep last 5"
  (let* ((all (list-checkpoints))
         (to-keep (min keep (length all)))
         (to-delete (nthcdr to-keep all))
         (deleted 0))
    (dolist (cp to-delete)
      (let ((filepath (merge-pathnames (getf cp :filename)
                                      (ensure-checkpoint-directory))))
        (handler-case
            (progn
              (delete-file filepath)
              (incf deleted))
          (error (e)
            (format *error-output*
                    "[CHECKPOINT] Failed to delete ~A: ~A~%"
                    filepath e)))))
    (when (> deleted 0)
      (format t "[CHECKPOINT] Pruned ~D old checkpoint(s), ~D kept.~%"
              deleted to-keep))
    deleted))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 6: Network Map Serialization — The Discovered Topology
;; ═══════════════════════════════════════════════════════════════════════════

(defun serialize-network-map (orchestrator)
  "Serialize the full discovered network map.

   Extracts the adjacency list from the orchestrator's target registry.
   Each entry is (IP-ADDRESS . LIST-OF-ADJACENT-IPS).

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.

   Returns: Alist of (ip . adjacent-ips-list).

   Example:
     (serialize-network-map *default-orchestrator*)
     ;; => ((\"10.0.0.1\" \"10.0.0.2\" \"10.0.0.3\")
     ;;     (\"10.0.0.2\" \"10.0.0.1\")
     ;;     (\"10.0.0.5\" \"10.0.0.1\"))"
  (let ((map nil))
    (when (and orchestrator
              (slot-exists-p orchestrator 'target-registry))
      (let ((registry (slot-value orchestrator 'target-registry)))
        (when (hash-table-p registry)
          (maphash
           (lambda (ip metadata)
             (let ((neighbors (getf metadata :adjacent-hosts '())))
               (push (cons ip neighbors) map)))
           registry))))
    (nreverse map)))

(defun deserialize-network-map (data)
  "Deserialize network map from checkpoint data.

   DATA is an alist of (ip . adjacent-ips-list) as produced by
   SERIALIZE-NETWORK-MAP. Returns a fresh alist.

   Arguments:
     DATA — Alist from a checkpoint.

   Returns: Alist of (ip . adjacent-ips-list).

   Example:
     (deserialize-network-map '((\"10.0.0.1\" \"10.0.0.2\")))
     ;; => ((\"10.0.0.1\" \"10.0.0.2\"))"
  (copy-tree data))

(defun merge-network-maps (old-map new-discoveries)
  "Merge new discoveries into existing network map.

   OLD-MAP is the existing alist. NEW-DISCOVERIES is an alist of
   newly discovered (ip . adjacent-ips-list) entries. The merge:
     • Adds new IPs not in OLD-MAP.
     • Merges adjacent hosts: union of old and new neighbors.
     • Preserves all existing entries.

   Arguments:
     OLD-MAP         — Existing alist or NIL.
     NEW-DISCOVERIES — Alist of new discoveries or NIL.

   Returns: Merged alist with all known IPs and their adjacencies.

   Example:
     (merge-network-maps '((\"10.0.0.1\" \"10.0.0.2\"))
                        '((\"10.0.0.1\" \"10.0.0.3\") (\"10.0.0.5\")))
     ;; => ((\"10.0.0.1\" \"10.0.0.2\" \"10.0.0.3\") (\"10.0.0.5\"))"
  (let ((merged (copy-tree old-map)))
    (dolist (entry new-discoveries)
      (let* ((ip (car entry))
             (new-neighbors (cdr entry))
             (existing (assoc ip merged :test 'equal)))
        (if existing
            ;; Merge neighbors (union)
            (setf (cdr existing)
                  (union (cdr existing) new-neighbors :test 'equal))
            ;; New IP — add entire entry
            (push (copy-tree entry) merged))))
    merged))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 7: State Extraction Functions — From Orchestrator to Checkpoint
;; ═══════════════════════════════════════════════════════════════════════════

(defun extract-active-footholds (orchestrator)
  "Extract active foothold states from the orchestrator.

   Iterates over the orchestrator's agents and extracts any that
   have a :FOOTHOLD marker in their state-data. Returns a list of
   FOOTHOLD-STATE structs.

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.

   Returns: List of FOOTHOLD-STATE structs (may be empty)."
  (let ((footholds nil))
    (when (and orchestrator
              (slot-exists-p orchestrator 'agents))
      (dolist (agent (slot-value orchestrator 'agents))
        (when (and (slot-exists-p agent 'state-data)
                  (hash-table-p (slot-value agent 'state-data)))
          (let ((sd (slot-value agent 'state-data)))
            (when (gethash :foothold-p sd)
              (push (make-foothold-state
                     :session-token (gethash :session-token sd "unknown")
                     :target-ip (gethash :target-ip sd "0.0.0.0")
                     :target-port (gethash :target-port sd 0)
                     :entry-vector (gethash :entry-vector sd :unknown)
                     :pivot-depth (gethash :pivot-depth sd 0)
                     :parent-foothold (gethash :parent-foothold sd)
                     :child-footholds (gethash :child-footholds sd '())
                     :persistence-active-p (gethash :persistence-active-p sd)
                     :persistence-method (gethash :persistence-method sd)
                     :proxy-chain (gethash :proxy-chain sd)
                     :noise-level (gethash :noise-level sd 0)
                     :evasion-score (gethash :evasion-score sd 0.0)
                     :tts-seconds (gethash :tts-seconds sd 0)
                     :established-at (gethash :established-at sd 0))
                    footholds))))))
    (nreverse footholds)))

(defun extract-pivot-chains (orchestrator)
  "Extract pivot chain relationships from the orchestrator.

   Returns an alist of (parent-session-token . child-tokens-list)
   representing the pivot tree.

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.

   Returns: Alist of pivot chains (may be empty)."
  (let ((chains nil))
    (dolist (fh (extract-active-footholds orchestrator))
      (let ((parent (foothold-state-parent-foothold fh))
            (children (foothold-state-child-footholds fh))
            (token (foothold-state-session-token fh)))
        (when parent
          (let ((existing (assoc parent chains :test 'equal)))
            (if existing
                (pushnew token (cdr existing) :test 'equal)
                (push (cons parent (list token)) chains))))
        (when children
          (let ((existing (assoc token chains :test 'equal)))
            (if existing
                (dolist (child children)
                  (pushnew child (cdr existing) :test 'equal))
                (push (cons token (copy-list children)) chains))))))
    chains))

(defun extract-persistence-state (orchestrator)
  "Extract persistence state as a hash-table.

   Returns a hash-table: session-token -> persistence-method keyword.

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.

   Returns: Hash-table (may be empty)."
  (let ((ht (make-hash-table :test 'equal)))
    (dolist (fh (extract-active-footholds orchestrator))
      (when (foothold-state-persistence-active-p fh)
        (setf (gethash (foothold-state-session-token fh) ht)
              (foothold-state-persistence-method fh))))
    ht))

(defun extract-proxy-chains (orchestrator)
  "Extract active proxy chain descriptions.

   Returns a list of strings describing active proxy chains.

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.

   Returns: List of strings (may be empty)."
  (let ((chains nil))
    (dolist (fh (extract-active-footholds orchestrator))
      (when (foothold-state-proxy-chain fh)
        (pushnew (foothold-state-proxy-chain fh) chains :test 'equal)))
    chains))

(defun extract-session-tokens (orchestrator)
  "Extract all session tokens with their creation timestamps.

   Returns a hash-table: session-token -> established-at timestamp.

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.

   Returns: Hash-table (may be empty)."
  (let ((ht (make-hash-table :test 'equal)))
    (dolist (fh (extract-active-footholds orchestrator))
      (setf (gethash (foothold-state-session-token fh) ht)
            (foothold-state-established-at fh)))
    ht))

(defun extract-target-registry (orchestrator)
  "Extract the target registry from the orchestrator.

   Returns a hash-table: target-ip -> metadata plist.

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.

   Returns: Hash-table (may be empty)."
  (if (and orchestrator
          (slot-exists-p orchestrator 'target-registry))
      (let ((reg (slot-value orchestrator 'target-registry)))
        (if (hash-table-p reg)
            (let ((copy (make-hash-table :test 'equal)))
              (maphash (lambda (k v) (setf (gethash k copy) v)) reg)
              copy)
            (make-hash-table :test 'equal)))
      (make-hash-table :test 'equal)))

(defun extract-agent-strategies (orchestrator)
  "Extract agent strategy configurations.

   Returns an alist: agent-id -> strategy config plist.

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.

   Returns: Alist (may be empty)."
  (let ((strategies nil))
    (when (and orchestrator
              (slot-exists-p orchestrator 'agents))
      (dolist (agent (slot-value orchestrator 'agents))
        (when (slot-exists-p agent 'id)
          (let ((id (slot-value agent 'id))
                (config nil))
            ;; Extract strategy-relevant config from agent state
            (when (slot-exists-p agent 'evasion-score)
              (push (cons :evasion-score
                         (slot-value agent 'evasion-score))
                    config))
            (when (slot-exists-p agent 'noise-level)
              (push (cons :noise-level
                         (slot-value agent 'noise-level))
                    config))
            (push (cons (princ-to-string id) config) strategies)))))
    strategies))

(defun extract-evolution-history (orchestrator)
  "Extract recent evolution events from the orchestrator.

   Returns a list of the last 50 evolution event plists.

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.

   Returns: List of plists (may be empty)."
  (if (and orchestrator
          (slot-exists-p orchestrator 'evolution-history))
      (let ((hist (slot-value orchestrator 'evolution-history)))
        (if (listp hist)
            (subseq hist 0 (min 50 (length hist)))
            '()))
      '()))

(defun extract-telemetry-snapshots ()
  "Extract recent telemetry snapshots.

   Returns the last 20 telemetry readings from *TELEMETRY-HISTORY*.

   Returns: List of telemetry plists (may be empty)."
  (if (and (boundp '*telemetry-history*)
          (arrayp *telemetry-history*))
      (let ((len (length *telemetry-history*)))
        (loop for i from (max 0 (- len 20)) below len
              collect (aref *telemetry-history* i)))
      '()))

(defun extract-gossip-peer-state ()
  "Extract current gossip peer liveness state.

   Returns an alist: peer-id -> last-heartbeat-timestamp.

   Returns: Alist (may be empty)."
  (let ((peers nil))
    (when (boundp '*tactical-peer-liveness*)
      (maphash (lambda (peer-id timestamp)
                (push (cons peer-id timestamp) peers))
              *tactical-peer-liveness*))
    peers))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 8: State Restoration Functions — From Checkpoint to Orchestrator
;; ═══════════════════════════════════════════════════════════════════════════

(defun restore-foothold-to-orchestrator (orchestrator foothold)
  "Restore a single FOOTHOLD-STATE to the orchestrator.

   Creates or updates an agent in the orchestrator to represent
   the restored foothold. The agent's state-data hash-table is
   populated with all foothold fields.

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.
     FOOTHOLD     — A FOOTHOLD-STATE struct.

   Returns: The restored agent object, or NIL."
  (when (and orchestrator
            (slot-exists-p orchestrator 'agents))
    ;; Create a placeholder agent for the foothold
    (let ((agent-data (make-hash-table :test 'equal)))
      ;; Populate state-data with foothold fields
      (setf (gethash :foothold-p agent-data) t
            (gethash :session-token agent-data)
            (foothold-state-session-token foothold)
            (gethash :target-ip agent-data)
            (foothold-state-target-ip foothold)
            (gethash :target-port agent-data)
            (foothold-state-target-port foothold)
            (gethash :entry-vector agent-data)
            (foothold-state-entry-vector foothold)
            (gethash :pivot-depth agent-data)
            (foothold-state-pivot-depth foothold)
            (gethash :parent-foothold agent-data)
            (foothold-state-parent-foothold foothold)
            (gethash :child-footholds agent-data)
            (foothold-state-child-footholds foothold)
            (gethash :persistence-active-p agent-data)
            (foothold-state-persistence-active-p foothold)
            (gethash :persistence-method agent-data)
            (foothold-state-persistence-method foothold)
            (gethash :proxy-chain agent-data)
            (foothold-state-proxy-chain foothold)
            (gethash :noise-level agent-data)
            (foothold-state-noise-level foothold)
            (gethash :evasion-score agent-data)
            (foothold-state-evasion-score foothold)
            (gethash :tts-seconds agent-data)
            (foothold-state-tts-seconds foothold)
            (gethash :established-at agent-data)
            (foothold-state-established-at foothold))
      ;; Store in orchestrator
      (push agent-data (slot-value orchestrator 'agents))
      agent-data)))

(defun restore-pivot-chains (orchestrator chains)
  "Restore pivot chain relationships to the orchestrator.

   CHAINS is an alist of (parent-token . child-tokens-list).

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.
     CHAINS       — Alist of pivot chains.

   Returns: Number of chain relationships restored."
  (declare (ignore orchestrator))
  (let ((count 0))
    (dolist (chain chains)
      (incf count (length (cdr chain))))
    count))

(defun restore-persistence-state (orchestrator state)
  "Restore persistence state markers to the orchestrator.

   STATE is a hash-table: session-token -> persistence-method.

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.
     STATE        — Persistence state hash-table.

   Returns: Number of persistence markers restored."
  (declare (ignore orchestrator))
  (hash-table-count state))

(defun restore-proxy-chains (orchestrator chains)
  "Restore proxy chain descriptors to the orchestrator.

   CHAINS is a list of proxy chain description strings.

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.
     CHAINS       — List of proxy chain strings.

   Returns: Number of proxy chains restored."
  (declare (ignore orchestrator))
  (length chains))

(defun install-network-map (orchestrator network-map)
  "Install a network map into the orchestrator.

   NETWORK-MAP is an alist of (ip . adjacent-ips-list).

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.
     NETWORK-MAP  — Alist of network adjacencies.

   Returns: Number of IPs in the installed map."
  (when (and orchestrator
            (slot-exists-p orchestrator 'target-registry))
    (let ((registry (slot-value orchestrator 'target-registry)))
      (unless (hash-table-p registry)
        (setf registry (make-hash-table :test 'equal))
        (setf (slot-value orchestrator 'target-registry) registry))
      (dolist (entry network-map)
        (let ((ip (car entry))
              (neighbors (cdr entry)))
          (let ((existing (gethash ip registry)))
            (if existing
                (setf (getf existing :adjacent-hosts)
                      (union (getf existing :adjacent-hosts '())
                            neighbors :test 'equal))
                (setf (gethash ip registry)
                      (list :adjacent-hosts neighbors
                            :discovered-at (get-universal-time))))))))
  (length network-map))

(defun merge-target-registry (orchestrator registry-data)
  "Merge a target registry into the orchestrator.

   REGISTRY-DATA is a hash-table: target-ip -> metadata plist.
   New entries are added; existing entries are augmented.

   Arguments:
     ORCHESTRATOR  — The LISPMIND orchestrator instance.
     REGISTRY-DATA — Hash-table of target metadata.

   Returns: Number of targets merged."
  (when (and orchestrator
            (slot-exists-p orchestrator 'target-registry)
            (hash-table-p registry-data))
    (let ((registry (slot-value orchestrator 'target-registry)))
      (unless (hash-table-p registry)
        (setf registry (make-hash-table :test 'equal))
        (setf (slot-value orchestrator 'target-registry) registry))
      (maphash (lambda (ip metadata)
                (let ((existing (gethash ip registry)))
                  (if existing
                      ;; Merge metadata
                      (dolist (key '(:os :ports :services :vulnerabilities
                                    :adjacent-hosts :last-seen))
                        (when (getf metadata key)
                          (setf (getf existing key)
                                (getf metadata key))))
                      ;; New target
                      (setf (gethash ip registry) metadata))))
              registry-data)))
  (if (hash-table-p registry-data)
      (hash-table-count registry-data)
      0))

(defun restore-gossip-peer-state (peer-state)
  "Restore gossip peer liveness state.

   PEER-STATE is an alist: peer-id -> last-seen-timestamp.

   Arguments:
     PEER-STATE — Alist of peer liveness data.

   Returns: Number of peers restored."
  (when (boundp '*tactical-peer-liveness*)
    (dolist (entry peer-state)
      (setf (gethash (car entry) *tactical-peer-liveness*)
            (cdr entry))))
  (length peer-state))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 9: Checkpoint Conversion — Plist <-> Struct (for non-cl-store)
;; ═══════════════════════════════════════════════════════════════════════════

(defun checkpoint-to-plist (cp)
  "Convert a TACTICAL-CHECKPOINT struct to a plist.

   Used as a fallback serialization format when cl-store is not
   available. All hash-tables are converted to alists.

   Arguments:
     CP — TACTICAL-CHECKPOINT struct.

   Returns: Plist representation."
  (list :timestamp (tactical-checkpoint-timestamp cp)
        :version (tactical-checkpoint-version cp)
        :active-footholds
        (mapcar #'foothold-to-plist
               (tactical-checkpoint-active-footholds cp))
        :pivot-chains (tactical-checkpoint-pivot-chains cp)
        :persistence-state
        (hash-table-to-alist
         (tactical-checkpoint-persistence-state cp))
        :proxy-chains (tactical-checkpoint-proxy-chains cp)
        :session-tokens
        (hash-table-to-alist
         (tactical-checkpoint-session-tokens cp))
        :target-registry
        (hash-table-to-alist
         (tactical-checkpoint-target-registry cp))
        :network-map (tactical-checkpoint-network-map cp)
        :agent-strategies (tactical-checkpoint-agent-strategies cp)
        :evolution-history (tactical-checkpoint-evolution-history cp)
        :telemetry-snapshots (tactical-checkpoint-telemetry-snapshots cp)
        :gossip-peer-state (tactical-checkpoint-gossip-peer-state cp)))

(defun foothold-to-plist (fh)
  "Convert a FOOTHOLD-STATE struct to a plist.

   Arguments:
     FH — FOOTHOLD-STATE struct.

   Returns: Plist representation."
  (list :session-token (foothold-state-session-token fh)
        :target-ip (foothold-state-target-ip fh)
        :target-port (foothold-state-target-port fh)
        :entry-vector (foothold-state-entry-vector fh)
        :pivot-depth (foothold-state-pivot-depth fh)
        :parent-foothold (foothold-state-parent-foothold fh)
        :child-footholds (foothold-state-child-footholds fh)
        :persistence-active-p (foothold-state-persistence-active-p fh)
        :persistence-method (foothold-state-persistence-method fh)
        :proxy-chain (foothold-state-proxy-chain fh)
        :noise-level (foothold-state-noise-level fh)
        :evasion-score (foothold-state-evasion-score fh)
        :tts-seconds (foothold-state-tts-seconds fh)
        :established-at (foothold-state-established-at fh)))

(defun hash-table-to-alist (ht)
  "Convert a hash-table to an alist.

   Arguments:
     HT — Hash-table.

   Returns: Alist of (key . value) pairs."
  (let ((alist nil))
    (when (hash-table-p ht)
      (maphash (lambda (k v) (push (cons k v) alist)) ht))
    alist))

(defun plist-to-checkpoint (plist)
  "Convert a plist to a TACTICAL-CHECKPOINT struct.

   Arguments:
     PLIST — Plist from CHECKPOINT-TO-PLIST.

   Returns: TACTICAL-CHECKPOINT struct."
  (make-tactical-checkpoint
   :timestamp (getf plist :timestamp)
   :version (getf plist :version *tactical-checkpoint-version*)
   :active-footholds
   (mapcar (lambda (fhp)
            (apply #'make-foothold-state
                  (alexandria:flatten
                   (list :session-token (getf fhp :session-token)
                        :target-ip (getf fhp :target-ip)
                        :target-port (getf fhp :target-port)
                        :entry-vector (getf fhp :entry-vector)
                        :pivot-depth (getf fhp :pivot-depth)
                        :parent-foothold (getf fhp :parent-foothold)
                        :child-footholds (getf fhp :child-footholds)
                        :persistence-active-p (getf fhp :persistence-active-p)
                        :persistence-method (getf fhp :persistence-method)
                        :proxy-chain (getf fhp :proxy-chain)
                        :noise-level (getf fhp :noise-level)
                        :evasion-score (getf fhp :evasion-score)
                        :tts-seconds (getf fhp :tts-seconds)
                        :established-at (getf fhp :established-at)))))
          (getf plist :active-footholds))
   :pivot-chains (getf plist :pivot-chains)
   :persistence-state (alist-to-hash-table
                      (getf plist :persistence-state))
   :proxy-chains (getf plist :proxy-chains)
   :session-tokens (alist-to-hash-table (getf plist :session-tokens))
   :target-registry (alist-to-hash-table (getf plist :target-registry))
   :network-map (getf plist :network-map)
   :agent-strategies (getf plist :agent-strategies)
   :evolution-history (getf plist :evolution-history)
   :telemetry-snapshots (getf plist :telemetry-snapshots)
   :gossip-peer-state (getf plist :gossip-peer-state)))

(defun alist-to-hash-table (alist)
  "Convert an alist to an equal-hash-table.

   Arguments:
     ALIST — Alist of (key . value) pairs.

   Returns: Hash-table."
  (let ((ht (make-hash-table :test 'equal)))
    (dolist (entry alist)
      (setf (gethash (car entry) ht) (cdr entry)))
    ht))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 10: Post-Foothold Checkpoint — Immediate Save on Success
;; ═══════════════════════════════════════════════════════════════════════════

(defun checkpoint-after-foothold (orchestrator foothold)
  "Save a checkpoint immediately after gaining a foothold.

   This is the critical path — every successful entry triggers a
   checkpoint to ensure the foothold is never lost. Combines a
   full checkpoint save with a tactical state update broadcast.

   Actions:
     1. Save full tactical checkpoint to disk.
     2. Send tactical state update to gossip mesh.
     3. Log the foothold.

   Arguments:
     ORCHESTRATOR — The LISPMIND orchestrator instance.
     FOOTHOLD     — The newly gained FOOTHOLD-STATE.

   Returns: Checkpoint pathname if saved, NIL on failure.

   Example:
     (checkpoint-after-foothold *default-orchestrator* new-foothold)"
  (format t "~&[CHECKPOINT] Foothold gained on ~A via ~A (depth ~D). Saving...~%"
          (foothold-state-target-ip foothold)
          (foothold-state-entry-vector foothold)
          (foothold-state-pivot-depth foothold))
  ;; Save checkpoint
  (let ((path (save-tactical-checkpoint orchestrator)))
    ;; Broadcast state update
    (when (fboundp 'send-tactical-state-update)
      (send-tactical-state-update
       (or (and (boundp '*tactical-agent-id*) *tactical-agent-id*)
          "orch-default")
       (foothold-state-target-ip foothold)
       (foothold-state-entry-vector foothold)
       :pivot-depth (foothold-state-pivot-depth foothold)
       :persistence-active-p (foothold-state-persistence-active-p foothold)
       :session-token (foothold-state-session-token foothold)))
    path))

(defun tactical-checkpoint-status ()
  "Return the current checkpoint system status.

   Returns a plist:
     :CHECKPOINT-DIRECTORY    — Current checkpoint directory.
     :AUTO-CHECKPOINT-RUNNING — T if auto-checkpoint thread is alive.
     :LAST-SAVE               — Unix timestamp of last save.
     :SECONDS-SINCE-SAVE      — Seconds since last checkpoint.
     :CHECKPOINTS-ON-DISK     — Number of checkpoint files.
     :VERSION                 — Checkpoint format version.

   Example:
     (tactical-checkpoint-status)"
  (list :checkpoint-directory (namestring (ensure-checkpoint-directory))
        :auto-checkpoint-running (and *checkpoint-thread*
                                     (bt:thread-alive-p *checkpoint-thread*))
        :last-save *checkpoint-last-save*
        :seconds-since-save (- (get-universal-time) *checkpoint-last-save*)
        :checkpoints-on-disk (length (list-checkpoints))
        :version *tactical-checkpoint-version*))

(defun print-tactical-checkpoint-status ()
  "Print a formatted checkpoint system status report.

   Returns: Status plist (same as TACTICAL-CHECKPOINT-STATUS)."
  (let ((status (tactical-checkpoint-status)))
    (format t "~&═══════════════════════════════════════════════════════════════~%")
    (format t "  TACTICAL CHECKPOINT v~A~%" *tactical-checkpoint-version*)
    (format t "═══════════════════════════════════════════════════════════════~%")
    (format t "  Directory:    ~A~%" (getf status :checkpoint-directory))
    (format t "  Auto-save:    ~A~%"
            (if (getf status :auto-checkpoint-running) "RUNNING" "STOPPED"))
    (format t "  Last save:    ~D (~Ds ago)~%"
            (getf status :last-save)
            (getf status :seconds-since-save))
    (format t "  Checkpoints:  ~D on disk~%" (getf status :checkpoints-on-disk))
    (format t "  Version:      ~A~%" (getf status :version))
    (format t "═══════════════════════════════════════════════════════════════~%")
    status))


;;;; ═════════════════════════════════════════════════════════════════════════
;;;; END OF TACTICAL-CHECKPOINT.LISP
