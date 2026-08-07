;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; WEBSOCKET.LISP — Real-Time Dashboard Communication Server
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;                THE DASHBOARD LIFELINE: WEBSOCKET + TCP FALLBACK
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This module provides the network transport layer for LISPMIND's telemetry
;;; system. It implements two complementary server modes:
;;;
;;;   1. WebSocket Server — Full-duplex, browser-native dashboard protocol.
;;;       Powered by websocket-driver (if available) or a minimal built-in
;;;       WebSocket handshake parser for environments where the library is
;;;       not installed.
;;;
;;;   2. TCP JSON Line Server — Fallback for air-gapped environments where
;;;       WebSocket libraries are unavailable or where netcat/telnet access
;;;       is preferred. Sends newline-delimited JSON — any TCP client can
;;;       connect and receive telemetry.
;;;
;;; CLIENT MANAGEMENT
;;; ─────────────────
;;; All connected clients are tracked in *dashboard-clients*, a hash-table
;;; keyed by a unique client ID. The table is protected by *clients-lock*.
;;; The broadcast function iterates over all clients and sends to each,
;;; wrapping individual sends in ignore-errors so one dead client cannot
;;; crash the broadcast for everyone else.
;;;
;;; DESIGN DECISIONS
;;; ────────────────
;;; • Two separate server sockets (WebSocket and TCP) can run simultaneously.
;;; • The TCP server always works — it uses only usocket, a minimal
;;;   dependency that is widely available.
;;; • The WebSocket server requires websocket-driver OR a minimal handshake
;;;   parser that we include inline.
;;; • Clients are fungible — the broadcast function doesn't care whether a
;;;   client is WebSocket or TCP, it just sends a string.
;;;
;;; "Every thought the swarm thinks is echoed here — translated into light,
;;;  compressed into JSON, and sent hurtling across the wire to waiting
;;;  screens. This is the window through which we watch the mind think."

(in-package :lispmind)

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 0: Feature Detection — What Networking Libraries Are Available?
;; ═══════════════════════════════════════════════════════════════════════════

(eval-when (:compile-toplevel :load-toplevel :execute)
  ;; Detect websocket-driver
  (handler-case
      (progn
        (require :websocket-driver)
        (pushnew :websocket-driver-available *features*)
        (format *trace-output* "[WEBSOCKET] websocket-driver detected.~%"))
    (error ()
      (format *trace-output* "[WEBSOCKET] websocket-driver not available.~%")))
  ;; Detect usocket (for TCP fallback — widely available)
  (handler-case
      (progn
        (require :usocket)
        (pushnew :usocket-available *features*)
        (format *trace-output* "[WEBSOCKET] usocket detected.~%"))
    (error ()
      (format *trace-output* "[WEBSOCKET] WARNING: usocket not available. TCP fallback disabled.~%"))))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 1: Special Variables — Configuration & Global State
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *websocket-server* nil
  "The WebSocket server thread or usocket server instance.

When using websocket-driver, this holds the server object.
When using the TCP fallback, this holds the usocket server.
Set by start-websocket-server, cleared by stop-websocket-server.

Thread-safety: Only mutated by lifecycle functions (start/stop).")

(defvar *dashboard-clients* (make-hash-table :test 'eq)
  "Registry of all connected dashboard clients.

Keys are unique symbols (gensym'd CLIENT-IDs).
Values are client descriptor plists:
  (:socket     <usocket or websocket object>
   :type       <:websocket | :tcp>
   :lock       <bt:lock for this client>
   :connected  <unix-timestamp>
   :last-ping  <unix-timestamp>)

Thread-safety: All access must be protected by *clients-lock*.")

(defvar *clients-lock* (bt:make-lock "dashboard-clients")
  "Lock protecting *dashboard-clients* hash-table.

Acquired by:
  • register-client   — when adding a new client
  • unregister-client — when removing a client
  • broadcast-to-clients — when iterating and sending
  • client-count      — when counting clients
  • cleanup-dead-clients — when removing stale entries")

(defvar *websocket-port* 8080
  "Default port for the WebSocket server.

Can be overridden via the :port keyword argument to start-websocket-server.
The TCP fallback server uses this port + 1 by default (8081) to avoid
conflicts, but can be configured independently.")

(defvar *tcp-fallback-port* 8081
  "Default port for the TCP JSON line fallback server.

This is separate from *websocket-port* so both servers can run
simultaneously. Set to NIL to disable the TCP fallback.")

(defvar *tcp-server* nil
  "The TCP fallback server socket (usocket).

Set by start-tcp-json-server, cleared by stop-tcp-json-server.
Thread-safety: Only mutated by lifecycle functions.")

(defvar *tcp-clients* (make-hash-table :test 'eq)
  "Separate registry for TCP fallback clients.

Same structure as *dashboard-clients* but only contains :tcp type clients.
This separation simplifies cleanup and debugging.

Thread-safety: Protected by *clients-lock* (shared with WebSocket clients).")

(defvar *server-running-p* nil
  "Flag indicating whether the server subsystem is active.

Set to T when either WebSocket or TCP server is running.
Cleared when both are stopped.

Thread-safety: Set/cleared by lifecycle functions only.")

(defvar *client-id-counter* 0
  "Monotonically increasing counter for generating client IDs.

Thread-safety: Protected by *clients-lock*.")

(defvar *broadcast-dropped-count* 0
  "Count of messages that failed to send to any client.

Incremented when broadcast-to-clients encounters errors.
Useful for monitoring dashboard health.

Thread-safety: Written only by the telemetry thread.")

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 2: Client Management — Register, Unregister, Count
;; ═══════════════════════════════════════════════════════════════════════════

(defun register-client (socket &key (type :tcp))
  "Register a new dashboard client.

Parameters:
  SOCKET — The client socket object (usocket socket-stream or
           websocket-driver ws object).
  TYPE   — Either :websocket or :tcp (default :tcp).

Returns: The client ID symbol (e.g., CLIENT-42).

Side effects: Adds an entry to *dashboard-clients*.

Thread-safety: Acquires *clients-lock*."
  (declare (type keyword type))
  (bt:with-lock-held (*clients-lock*)
    (let ((client-id (intern (format nil "CLIENT-~D"
                                     (incf *client-id-counter*))
                             :lispmind)))
      (setf (gethash client-id *dashboard-clients*)
            (list :socket socket
                  :type type
                  :lock (bt:make-lock (format nil "client-~A" client-id))
                  :connected (/ (get-internal-real-time)
                                internal-time-units-per-second)
                  :last-ping (/ (get-internal-real-time)
                                internal-time-units-per-second)))
      (format *trace-output*
              "~&[WEBSOCKET] Client ~A connected (~A)~%"
              client-id type)
      client-id)))

(defun unregister-client (client-id)
  "Remove a client from the registry.

Parameters:
  CLIENT-ID — The symbol returned by register-client.

Returns: T if the client was found and removed, NIL otherwise.

Side effects:
  • Removes entry from *dashboard-clients*
  • Closes the client's socket (best-effort, wrapped in ignore-errors)

Thread-safety: Acquires *clients-lock*."
  (declare (type symbol client-id))
  (bt:with-lock-held (*clients-lock*)
    (let ((client-info (gethash client-id *dashboard-clients*)))
      (when client-info
        ;; Close socket (best effort)
        (ignore-errors
          (let ((socket (getf client-info :socket)))
            (case (getf client-info :type)
              (:tcp
               #+usocket-available
               (usocket:socket-close socket))
              (:websocket
               ;; Close websocket (if driver available)
               #+websocket-driver-available
               (websocket-driver:close-connection socket)))))
        ;; Remove from registry
        (remhash client-id *dashboard-clients*)
        (format *trace-output*
                "~&[WEBSOCKET] Client ~A disconnected~%"
                client-id)
        t))))

(defun lookup-client (client-id)
  "Look up a client's information.

Parameters:
  CLIENT-ID — The symbol returned by register-client.

Returns: The client plist, or NIL if not found.

Thread-safety: Acquires *clients-lock* for the duration of the lookup."
  (declare (type symbol client-id))
  (bt:with-lock-held (*clients-lock*)
    (copy-list (gethash client-id *dashboard-clients*))))

(defun client-count ()
  "Return the number of currently connected dashboard clients.

Returns: A non-negative integer.

Thread-safety: Acquires *clients-lock*."
  (bt:with-lock-held (*clients-lock*)
    (hash-table-count *dashboard-clients*)))

(defun list-clients ()
  "Return a list of all connected client IDs.

Returns: A list of symbols like (CLIENT-1 CLIENT-3 CLIENT-7).

Thread-safety: Acquires *clients-lock*."
  (bt:with-lock-held (*clients-lock*)
    (let ((ids '()))
      (maphash (lambda (k v)
                 (declare (ignore v))
                 (push k ids))
               *dashboard-clients*)
      ids)))

(defun cleanup-dead-clients ()
  "Remove clients that haven't been heard from recently.

A client is considered dead if its last-ping timestamp is more than
60 seconds old. This is a garbage collection function that should be
called periodically (the WebSocket ping/pong or TCP read timeout
should catch most disconnects, but this is a safety net).

Returns: The number of clients removed.

Side effects: Removes dead entries from *dashboard-clients* and
closes their sockets.

Thread-safety: Acquires *clients-lock*."
  (let ((now (/ (get-internal-real-time) internal-time-units-per-second))
        (dead-clients '()))
    ;; Identify dead clients (read-only pass)
    (bt:with-lock-held (*clients-lock*)
      (maphash (lambda (client-id info)
                 (let ((last-ping (getf info :last-ping 0)))
                   (when (> (- now last-ping) 60)
                     (push client-id dead-clients))))
               *dashboard-clients*))
    ;; Remove them (each unregister acquires the lock)
    (dolist (client-id dead-clients)
      (unregister-client client-id))
    (when dead-clients
      (format *trace-output*
              "~&[WEBSOCKET] Cleaned up ~D dead client(s)~%"
              (length dead-clients)))
    (length dead-clients)))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 3: Broadcast — Sending Messages to All Clients
;; ═══════════════════════════════════════════════════════════════════════════

(defun broadcast-to-clients (message)
  "Send a message string to all connected dashboard clients.

This is the primary broadcast function called by the telemetry system.
It iterates over all registered clients and sends the message to each,
wrapping individual sends in ignore-errors so one dead client cannot
kill the broadcast for everyone else.

Parameters:
  MESSAGE — A string (typically JSON) to send to all clients.

Returns: The number of clients that successfully received the message.

Side effects: Sends network data. May remove dead clients if sends fail.

Error isolation: Each client send is independently wrapped in
ignore-errors. A failure for one client does not affect others.
If ALL sends fail, *broadcast-dropped-count* is incremented.

Thread-safety: Acquires *clients-lock* for the iteration. Individual
client sends may acquire per-client locks (WebSocket driver does this
internally).

Example:
  (broadcast-to-clients \"{\\\"tick\\\":42,\\\"status\\\":\\\"ok\\\"}\")
    ;; => 3  (sent to 3 clients)"
  (declare (type string message))
  (let ((success-count 0)
        (dead-clients '()))
    (bt:with-lock-held (*clients-lock*)
      (maphash (lambda (client-id info)
                 (handler-case
                     (progn
                       (case (getf info :type)
                         (:tcp
                          ;; TCP: write string + newline
                          #+usocket-available
                          (let ((stream (usocket:socket-stream
                                         (getf info :socket))))
                            (write-line message stream)
                            (finish-output stream))
                          #-usocket-available
                          nil)
                         (:websocket
                          ;; WebSocket: send text frame
                          #+websocket-driver-available
                          (websocket-driver:send
                           (getf info :socket) message)
                          #-websocket-driver-available
                          (websocket-fallback-send
                           (getf info :socket) message))
                         (otherwise
                          ;; Unknown type — mark for cleanup
                          (push client-id dead-clients)))
                       (incf success-count))
                   (error (e)
                     ;; Client send failed — mark for removal
                     (format *trace-output*
                             "~&[WEBSOCKET] Send failed for ~A: ~A~%"
                             client-id e)
                     (push client-id dead-clients))))
               *dashboard-clients*))
    ;; Clean up dead clients outside the lock
    (dolist (client-id dead-clients)
      (unregister-client client-id))
    ;; Track drops
    (when (and (plusp (client-count)) (zerop success-count))
      (incf *broadcast-dropped-count*))
    success-count))

(defun broadcast-excluding (message excluded-client-id)
  "Send a message to all clients EXCEPT the specified one.

Useful for echo suppression — e.g., when a client sends a command
and shouldn't receive its own message back.

Parameters:
  MESSAGE          — The string to broadcast.
  EXCLUDED-CLIENT-ID — The client ID to skip.

Returns: Number of successful sends.

Thread-safety: Same as broadcast-to-clients."
  (declare (type string message)
           (type symbol excluded-client-id))
  (let ((success-count 0)
        (dead-clients '()))
    (bt:with-lock-held (*clients-lock*)
      (maphash (lambda (client-id info)
                 (unless (eq client-id excluded-client-id)
                   (handler-case
                       (progn
                         (case (getf info :type)
                           (:tcp
                            #+usocket-available
                            (let ((stream (usocket:socket-stream
                                           (getf info :socket))))
                              (write-line message stream)
                              (finish-output stream)))
                           (:websocket
                            #+websocket-driver-available
                            (websocket-driver:send
                             (getf info :socket) message)
                            #-websocket-driver-available
                            (websocket-fallback-send
                             (getf info :socket) message)))
                         (incf success-count))
                     (error ()
                       (push client-id dead-clients)))))
               *dashboard-clients*))
    (dolist (client-id dead-clients)
      (unregister-client client-id))
    success-count))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 4: WebSocket Server — Primary Dashboard Transport
;; ═══════════════════════════════════════════════════════════════════════════

(defun start-websocket-server (&optional (port *websocket-port*))
  "Start the WebSocket server on the given port.

This function attempts to start a WebSocket server using the best
available method:
  1. If websocket-driver is available, use it (full RFC 6455 compliance).
  2. Otherwise, fall back to the TCP JSON line server on the same port.

Parameters:
  PORT — The TCP port to listen on (default *websocket-port* = 8080).

Returns: The server instance (type depends on implementation).

Side effects:
  • Sets *websocket-server*
  • Sets *server-running-p* to T

If a server is already running, it is stopped and restarted.

Example:
  (start-websocket-server 8080)   ; Standard dashboard port
  (start-websocket-server 9000)   ; Custom port"
  (declare (type (integer 1 65535) port))
  ;; Stop existing server
  (when *websocket-server*
    (stop-websocket-server))
  #+websocket-driver-available
  (progn
    (setf *websocket-server*
          (websocket-driver:make-server
           (make-instance 'clack.handler.hunchentoot:handler
                          :port port)))
    ;; Configure connection handler
    (setf (websocket-driver:on :open *websocket-server*)
          (lambda (ws)
            (declare (ignorable ws))
            (register-client ws :type :websocket)))
    (setf (websocket-driver:on :message *websocket-server*)
          (lambda (ws message)
            (declare (ignorable ws message))
            ;; Dashboard clients are read-only for now
            ;; Future: handle commands from dashboard
            nil))
    (setf (websocket-driver:on :close *websocket-server*)
          (lambda (ws)
            ;; Find and unregister the client by socket
            (bt:with-lock-held (*clients-lock*)
              (maphash (lambda (client-id info)
                         (when (eq (getf info :socket) ws)
                           (unregister-client client-id)))
                       *dashboard-clients*))))
    (websocket-driver:start *websocket-server*)
    (setf *server-running-p* t)
    (format *trace-output*
            "~&[WEBSOCKET] Server started on port ~D (websocket-driver)~%"
            port))
  #-websocket-driver-available
  (progn
    (format *trace-output*
            "~&[WEBSOCKET] websocket-driver not available.~%")
    (format *trace-output*
            "~&[WEBSOCKET] Use (start-tcp-json-server ~D) for TCP fallback.~%"
            port)
    ;; Start TCP fallback automatically as a convenience
    (start-tcp-json-server port))
  *websocket-server*)

(defun stop-websocket-server ()
  "Stop the WebSocket server gracefully.

Disconnects all WebSocket clients and stops accepting new connections.
TCP fallback clients (if any) are handled separately via
stop-tcp-json-server.

Returns: T if a server was stopped, NIL if none was running.

Side effects:
  • Clears *websocket-server*
  • Unregisters all :websocket type clients
  • May set *server-running-p* to NIL if TCP server also stopped"
  (let ((had-server (not (null *websocket-server*))))
    ;; Unregister all websocket clients
    (let ((ws-clients '()))
      (bt:with-lock-held (*clients-lock*)
        (maphash (lambda (client-id info)
                   (when (eq (getf info :type) :websocket)
                     (push client-id ws-clients)))
                 *dashboard-clients*))
      (dolist (client-id ws-clients)
        (unregister-client client-id)))
    ;; Stop the server
    #+websocket-driver-available
    (when *websocket-server*
      (ignore-errors
        (websocket-driver:stop *websocket-server*)))
    (setf *websocket-server* nil)
    ;; Check if we should clear the running flag
    (unless *tcp-server*
      (setf *server-running-p* nil))
    (when had-server
      (format *trace-output* "~&[WEBSOCKET] Server stopped.~%"))
    had-server))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 5: Fallback TCP JSON Line Server — Air-Gapped Environments
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This is the MOST IMPORTANT part of the module for production deployments.
;; When websocket-driver is not available (common in air-gapped environments,
;; Docker containers, or minimal SBCL installations), this TCP server
;; provides identical functionality using only usocket.
;;
;; NETCAT CLIENT EXAMPLE:
;;   $ nc localhost 8081
;;   {"tick":1,"swarm-health":{"success-rate":0.92,...}}
;;   {"tick":2,"swarm-health":{"success-rate":0.91,...}}
;;   ^C
;;
;; PYTHON CLIENT EXAMPLE:
;;   import socket, json
;;   sock = socket.create_connection(("localhost", 8081))
;;   for line in sock.makefile():
;;       data = json.loads(line)
;;       print(f"Success rate: {data['swarm-health']['success-rate']}")

(defvar *tcp-server-thread* nil
  "The thread running the TCP accept loop.")

(defvar *tcp-shutdown-p* nil
  "Flag to signal the TCP server to shut down.")

(defun start-tcp-json-server (&optional (port *tcp-fallback-port*))
  "Start a simple TCP server that sends newline-delimited JSON.

Any TCP client can connect and receive a continuous stream of JSON
telemetry snapshots, one per line. This requires only usocket (no
WebSocket libraries).

Parameters:
  PORT — The TCP port to listen on (default *tcp-fallback-port* = 8081).

Returns: The usocket server object, or NIL if usocket is unavailable.

Side effects:
  • Creates a server socket
  • Spawns a thread running tcp-server-loop
  • Sets *tcp-server* and *server-running-p*

The server accepts connections indefinitely until stop-tcp-json-server
is called. Each client connection spawns its own handler thread.

NETCAT EXAMPLE:
  $ nc localhost 8081
  # You'll see a stream of JSON lines, one per telemetry tick.
  # Press Ctrl-C to disconnect.

PYTHON EXAMPLE:
  import socket, json
  sock = socket.create_connection(('localhost', 8081))
  for line in sock.makefile():
      snapshot = json.loads(line)
      print(snapshot['swarm-health']['success-rate'])

BASH ONE-LINER:
  $ nc localhost 8081 | while read line; do echo "$line" | jq '.swarm-health.containment-score'; done"
  (declare (type (integer 1 65535) port))
  #+usocket-available
  (progn
    ;; Stop existing server
    (when *tcp-server*
      (stop-tcp-json-server))
    (setf *tcp-shutdown-p* nil)
    (let ((server (usocket:socket-listen "0.0.0.0" port
                                          :reuse-address t
                                          :element-type 'character)))
      (setf *tcp-server* server)
      (setf *server-running-p* t)
      ;; Spawn accept loop
      (setf *tcp-server-thread*
            (bt:make-thread
             (lambda ()
               (tcp-server-loop server port))
             :name (format nil "tcp-json-server-~D" port)))
      (format *trace-output*
              "~&[WEBSOCKET] TCP JSON server started on port ~D~%"
              port)
      (format *trace-output*
              "~&[WEBSOCKET] Connect with: nc localhost ~D~%" port)
      server))
  #-usocket-available
  (progn
    (warn "[WEBSOCKET] usocket not available. TCP server cannot start.")
    (format *trace-output*
            "~&[WEBSOCKET] ERROR: usocket is required for TCP fallback.~%")
    nil))

(defun stop-tcp-json-server ()
  "Stop the TCP JSON server gracefully.

Signals the accept loop to exit, closes the server socket, and
unregisters all TCP clients.

Returns: T if a server was stopped, NIL if none was running.

Side effects:
  • Clears *tcp-server* and *tcp-server-thread*
  • Unregisters all :tcp type clients
  • May set *server-running-p* to NIL"
  (let ((had-server (not (null *tcp-server*))))
    ;; Signal shutdown
    (setf *tcp-shutdown-p* t)
    ;; Unregister all TCP clients
    (let ((tcp-clients '()))
      (bt:with-lock-held (*clients-lock*)
        (maphash (lambda (client-id info)
                   (when (eq (getf info :type) :tcp)
                     (push client-id tcp-clients)))
                 *dashboard-clients*))
      (dolist (client-id tcp-clients)
        (unregister-client client-id)))
    ;; Close server socket
    #+usocket-available
    (when *tcp-server*
      (ignore-errors
        (usocket:socket-close *tcp-server*)))
    ;; Join the server thread
    (when *tcp-server-thread*
      (handler-case
          (bt:join-thread *tcp-server-thread* :timeout 5.0)
        (error (e)
          (format *trace-output*
                  "~&[WEBSOCKET] TCP thread join warning: ~A~%" e)))
      (setf *tcp-server-thread* nil))
    (setf *tcp-server* nil)
    ;; Check running flag
    (unless *websocket-server*
      (setf *server-running-p* nil))
    (when had-server
      (format *trace-output* "~&[WEBSOCKET] TCP JSON server stopped.~%"))
    had-server))

(defun tcp-server-loop (server port)
  "The TCP server accept loop.

Runs indefinitely (until *tcp-shutdown-p* becomes T), accepting new
client connections and spawning a handler thread for each.

Parameters:
  SERVER — The usocket server object.
  PORT   — The port number (for logging).

Error handling: The entire loop is wrapped in handler-case. If the
server socket fails, the error is logged and the loop exits.

Thread-safety: Runs in its own thread. Each client gets its own thread."
  (declare (type t server)
           (type (integer 1 65535) port))
  (handler-case
      (loop until *tcp-shutdown-p*
            do (handler-case
                   #+usocket-available
                   (let ((client-socket (usocket:socket-accept
                                         server
                                         :element-type 'character)))
                     ;; Spawn client handler thread
                     (bt:make-thread
                      (lambda ()
                        (tcp-client-handler client-socket))
                      :name (format nil "tcp-client-~A"
                                    (usocket:get-peer-address
                                     client-socket))))
                 #-usocket-available
                 nil
                 (error (e)
                   ;; Accept failed — brief pause and retry
                   (format *trace-output*
                           "~&[WEBSOCKET] Accept error: ~A (retrying)~%"
                           e)
                   (sleep 1.0))))
    (error (e)
      (format *trace-output*
              "~&[WEBSOCKET] TCP server loop exited: ~A~%"
              e)))
  (format *trace-output*
          "~&[WEBSOCKET] TCP accept loop on port ~D ended.~%"
          port))

(defun tcp-client-handler (socket)
  "Handle a single TCP client connection.

Registers the client, then enters a loop reading from the socket
and responding to simple commands. The primary output is the
broadcast stream (handled by broadcast-to-clients), but this loop
also handles client-initiated actions like ping requests.

Parameters:
  SOCKET — The usocket client socket.

Error handling: All socket operations are wrapped in ignore-errors.
When any operation fails, the client is unregistered and the thread exits.

Thread-safety: Calls register-client and unregister-client which
acquire *clients-lock*."
  #+usocket-available
  (let* ((stream (usocket:socket-stream socket))
         (client-id (register-client socket :type :tcp)))
    (unwind-protect
         (handler-case
             (loop
               ;; Read with timeout to allow periodic cleanup checks
               #+usocket-available
               (when (usocket:wait-for-input socket :timeout 5 :ready-only t)
                 (let ((line (read-line stream nil nil)))
                   (when line
                     ;; Handle client commands (optional)
                     (cond
                       ((string= line "ping")
                        (write-line "pong" stream)
                        (finish-output stream))
                       ((string= line "status")
                        (write-line
                         (snapshot-to-json (telemetry-status))
                         stream)
                        (finish-output stream))
                       ;; Ignore unknown commands
                       (t nil))))
               ;; Check if server is shutting down
               (when *tcp-shutdown-p*
                 (return)))
           (end-of-file ()
             ;; Client disconnected cleanly
             nil)
           (error (e)
             ;; Any other error — client is dead
             (format *trace-output*
                     "~&[WEBSOCKET] TCP client ~A error: ~A~%"
                     client-id e)))
      ;; Cleanup
      (unregister-client client-id))))

(defun broadcast-tcp (message)
  "Send a message to all TCP-connected clients only.

This is a convenience wrapper around broadcast-to-clients that filters
for TCP clients. Used when you want to send a message exclusively to
TCP clients (e.g., a welcome message).

Parameters:
  MESSAGE — The string to send.

Returns: Number of successful sends.

Thread-safety: Acquires *clients-lock*."
  (declare (type string message))
  (let ((success-count 0)
        (dead-clients '()))
    (bt:with-lock-held (*clients-lock*)
      (maphash (lambda (client-id info)
                 (when (eq (getf info :type) :tcp)
                   (handler-case
                       (progn
                         #+usocket-available
                         (let ((stream (usocket:socket-stream
                                        (getf info :socket))))
                           (write-line message stream)
                           (finish-output stream))
                         (incf success-count))
                     (error ()
                       (push client-id dead-clients)))))
               *dashboard-clients*))
    (dolist (client-id dead-clients)
      (unregister-client client-id))
    success-count))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 6: Minimal WebSocket Fallback — Built-in Handshake Parser
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; When websocket-driver is NOT available but usocket IS, we provide a
;; minimal built-in WebSocket handshake parser. This is NOT a full
;; WebSocket implementation — it handles the initial HTTP upgrade and
;; can send/receive text frames. It is sufficient for dashboard clients
;; that only need to receive telemetry data (one-way communication).
;;
;; This is a best-effort implementation for environments where installing
;; websocket-driver is not possible. For production use with bidirectional
;; WebSocket, install websocket-driver.

(defvar *websocket-fallback-clients* (make-hash-table :test 'eq)
  "Clients connected via the minimal WebSocket fallback.

Keys are client IDs, values are usocket streams.
These are kept separate from TCP clients because the protocol differs.")

(defun websocket-fallback-send (socket message)
  "Send a text frame using the minimal WebSocket fallback protocol.

If websocket-driver is not available, this function implements a
minimal text frame encoder for unmasked server-to-client frames.

Parameters:
  SOCKET  — The usocket or stream object.
  MESSAGE — The string to send.

Frame format (RFC 6455, server-to-client, unmasked):
  FIN=1, opcode=0x1 (text)  →  0x81
  Payload length:
    < 126   → 0x00 | len
    126-65535 → 0x7E + 16-bit length
  Payload data (unmasked, as-is)

Returns: T on success.

Thread-safety: Should be called with the client lock held or from
the telemetry thread only."
  (let* ((bytes (trivial-utf-8:string-to-utf-8-bytes message))
         (len (length bytes))
         (header (make-array 10 :fill-pointer 0 :element-type '(unsigned-byte 8))))
    ;; FIN=1, opcode=text (0x01) → 0x81
    (vector-push #x81 header)
    ;; Payload length
    (cond
      ((< len 126)
       (vector-push len header))
      ((< len 65536)
       (vector-push 126 header)
       (vector-push (ldb (byte 8 8) len) header)
       (vector-push (ldb (byte 8 0) len) header))
      (t
       ;; Frame too large — shouldn't happen with telemetry JSON
       (error "WebSocket frame too large: ~D bytes" len)))
    ;; Write header + payload
    #+usocket-available
    (let ((stream (if (typep socket 'usocket:stream-usocket)
                      (usocket:socket-stream socket)
                      socket)))
      (write-sequence header stream)
      (write-sequence bytes stream)
      (finish-output stream))
    t))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 7: Integration — One-Call Startup and Shutdown
;; ═══════════════════════════════════════════════════════════════════════════

(defun start-telemetry-server (orchestrator &key (port 8080) (interval 0.5))
  "One-call startup for the entire telemetry server subsystem.

Starts the appropriate server(s) and the telemetry broadcast stream:
  1. Attempts to start the WebSocket server on PORT.
  2. If that fails or websocket-driver is unavailable, starts the TCP
     JSON fallback server on PORT.
  3. Starts the telemetry broadcast thread with the given INTERVAL.

Parameters:
  ORCHESTRATOR — The orchestrator instance to monitor and stream.
  PORT         — The port for WebSocket/TCP server (default 8080).
  INTERVAL     — Seconds between telemetry broadcasts (default 0.5).

Returns: A plist with the status of each subsystem:
  (:websocket <server-or-nil>
   :tcp       <server-or-nil>
   :telemetry <thread-or-nil>
   :port      <integer>
   :interval  <float>)

Side effects: Starts background threads and network listeners.

Example:
  ;; Full dashboard with WebSocket:
  (start-telemetry-server *default-orchestrator* :port 8080 :interval 0.5)

  ;; Minimal TCP-only in air-gapped environment:
  (start-telemetry-server *default-orchestrator* :port 8081 :interval 1.0)

  ;; Then connect with:
  ;;   $ nc localhost 8081"
  (declare (type (or null orchestrator) orchestrator)
           (type (integer 1 65535) port)
           (type (float (0.0)) interval))
  (format *trace-output*
          "~&[WEBSOCKET] Starting telemetry server (port=~D, interval=~As)...~%"
          port interval)
  ;; Start server
  #+websocket-driver-available
  (handler-case
      (start-websocket-server port)
    (error (e)
      (format *trace-output*
              "~&[WEBSOCKET] WebSocket failed (~A), trying TCP fallback...~%"
              e)
      (start-tcp-json-server port)))
  #-websocket-driver-available
  (start-tcp-json-server port)
  ;; Start telemetry stream
  (let ((telemetry-thread (start-telemetry-stream orchestrator
                                                    :interval interval)))
    ;; Report status
    (let ((status (list
                   :websocket *websocket-server*
                   :tcp *tcp-server*
                   :telemetry telemetry-thread
                   :port port
                   :interval interval
                   :clients (client-count))))
      (format *trace-output*
              "~&[WEBSOCKET] Telemetry server ready. Status: ~S~%"
              status)
      status)))

(defun stop-telemetry-server ()
  "One-call shutdown for the entire telemetry server subsystem.

Stops everything in the correct order:
  1. Stop the telemetry broadcast stream (no more data generated).
  2. Stop the WebSocket server (disconnect WebSocket clients).
  3. Stop the TCP JSON server (disconnect TCP clients).

This order ensures that no new data is generated while we're shutting
down, preventing "orphaned" messages that can't be delivered.

Returns: A plist with the status of each shutdown:
  (:telemetry-stopped <boolean>
   :websocket-stopped <boolean>
   :tcp-stopped       <boolean>)

Side effects: Stops all background threads and closes all sockets.

Example:
  (stop-telemetry-server)"
  (format *trace-output* "~&[WEBSOCKET] Stopping telemetry server...~%")
  (let ((telemetry-stopped (stop-telemetry-stream))
        (websocket-stopped (stop-websocket-server))
        (tcp-stopped (stop-tcp-json-server)))
    ;; Clear running flag
    (setf *server-running-p* nil)
    ;; Clear counters
    (setf *broadcast-dropped-count* 0)
    (setf *client-id-counter* 0)
    (let ((status (list
                   :telemetry-stopped telemetry-stopped
                   :websocket-stopped websocket-stopped
                   :tcp-stopped tcp-stopped)))
      (format *trace-output*
              "~&[WEBSOCKET] Telemetry server stopped. Status: ~S~%"
              status)
      status)))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 8: Server Status & Introspection
;; ═══════════════════════════════════════════════════════════════════════════

(defun websocket-server-status ()
  "Return the current status of the WebSocket/TCP server subsystem.

Useful for debugging and health checks.

Returns: A plist:
  (:running          <boolean>
   :websocket-active <boolean>
   :tcp-active       <boolean>
   :client-count     <integer>
   :clients          <list of client plists (without sockets)>
   :port             <integer or nil>
   :dropped-messages <integer>)

Thread-safety: Acquires *clients-lock* for client enumeration."
  (let ((clients '()))
    (bt:with-lock-held (*clients-lock*)
      (maphash (lambda (client-id info)
                 (push (list
                        :id client-id
                        :type (getf info :type)
                        :connected (getf info :connected)
                        :last-ping (getf info :last-ping))
                       clients))
               *dashboard-clients*))
    (list
     :running *server-running-p*
     :websocket-active (not (null *websocket-server*))
     :tcp-active (not (null *tcp-server*))
     :client-count (client-count)
     :clients clients
     :port (or (and *tcp-server*
                   #+usocket-available
                   (usocket:get-local-port *tcp-server*))
               *websocket-port*)
     :dropped-messages *broadcast-dropped-count*)))

(defun server-heartbeat ()
  "Send a heartbeat/ping to all connected clients.

This helps detect dead clients early (before the 60-second cleanup
timeout). The heartbeat is a minimal JSON object that clients can
ignore or use to measure latency.

Returns: Number of clients that received the heartbeat.

Thread-safety: Uses broadcast-to-clients (which acquires *clients-lock*)."
  (let ((heartbeat-json (format nil "{\"type\":\"heartbeat\",\"time\":~A}"
                                (/ (get-internal-real-time)
                                   internal-time-units-per-second))))
    (broadcast-to-clients heartbeat-json)))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 9: WebSocket Handshake Parser (Minimal Fallback)
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This section provides a minimal HTTP upgrade parser for the WebSocket
;; handshake. It is used only when websocket-driver is not available.
;; The parser is deliberately simple — it handles only the essentials.

(defun parse-websocket-handshake (stream)
  "Parse an HTTP upgrade request from a stream.

Reads lines from the stream until a blank line is encountered,
accumulating headers. Returns the headers as an alist.

Parameters:
  STREAM — A character input stream.

Returns: An alist of (header-name . header-value) strings, or NIL if
the request is not a valid WebSocket upgrade.

Example:
  (parse-websocket-handshake stream)
    ;; => ((\"GET\" . \"/\") (\"Host\" . \"localhost:8080\")
    ;;     (\"Upgrade\" . \"websocket\") ...)"
  (declare (type stream stream))
  (let ((headers '())
        (first-line nil))
    ;; Read first line (request line)
    (setf first-line (read-line stream nil nil))
    (unless first-line
      (return-from parse-websocket-handshake nil))
    (push (cons "REQUEST" first-line) headers)
    ;; Read header lines until blank line
    (loop for line = (read-line stream nil nil)
          while (and line (plusp (length line)) (not (string= line "")))
          do (let ((colon-pos (position #\: line)))
               (when colon-pos
                 (push (cons (string-trim " " (subseq line 0 colon-pos))
                             (string-trim " " (subseq line (1+ colon-pos))))
                       headers))))
    (nreverse headers)))

(defun generate-websocket-accept (key)
  "Generate the Sec-WebSocket-Accept response value.

Per RFC 6455, the accept value is:
  BASE64(SHA1(key + \"258EAFA5-E914-47DA-95CA-C5AB0DC85B11\"))

Parameters:
  KEY — The Sec-WebSocket-Key header value from the client.

Returns: The base64-encoded SHA1 hash string.

Note: This requires ironclad for SHA1 and cl-base64 for base64 encoding.
If those libraries are not available, returns a fixed string (which will
cause the handshake to fail, falling back to TCP)."
  (declare (type string key))
  (handler-case
      (let* ((magic-string "258EAFA5-E914-47DA-95CA-C5AB0DC85B11")
             (concatenated (concatenate 'string key magic-string)))
        ;; Use ironclad for SHA1 if available
        (let ((digest (ironclad:digest-sequence
                       'ironclad:sha1
                       (ironclad:ascii-string-to-byte-array concatenated))))
          (cl-base64:usb8-array-to-base64-string digest)))
    (error ()
      ;; Fallback: return a dummy value (handshake will fail, client
      ;; should fall back to TCP or retry)
      "dGhlIHNhbXBsZSBub25jZQ==")))

(defun send-websocket-handshake-response (stream headers)
  "Send the HTTP 101 Switching Protocols response.

Parameters:
  STREAM  — The output stream to write to.
  HEADERS — The parsed headers alist from parse-websocket-handshake.

Returns: T if a valid WebSocket handshake response was sent, NIL otherwise."
  (declare (type stream stream)
           (type list headers))
  (let ((key (cdr (assoc "Sec-WebSocket-Key" headers :test #'string-equal))))
    (unless key
      (return-from send-websocket-handshake-response nil))
    ;; Send 101 response
    (format stream "HTTP/1.1 101 Switching Protocols\r\n")
    (format stream "Upgrade: websocket\r\n")
    (format stream "Connection: Upgrade\r\n")
    (format stream "Sec-WebSocket-Accept: ~A\r\n"
            (generate-websocket-accept key))
    (format stream "\r\n")
    (finish-output stream)
    t))

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 10: Convenience Functions
;; ═══════════════════════════════════════════════════════════════════════════

(defun send-dashboard-command (command &rest args)
  "Send a command to all connected dashboard clients.

This is a higher-level wrapper around broadcast-to-clients that
formats commands as JSON messages with a :command field.

Parameters:
  COMMAND — A keyword naming the command.
  ARGS    — Additional key-value pairs for the command payload.

Example:
  (send-dashboard-command :highlight-agent :agent-id 'AGENT-42)
  ;; Sends: {\"command\":\"highlight-agent\",\"agent-id\":\"AGENT-42\"}

Returns: Number of clients that received the command.

Thread-safety: Uses broadcast-to-clients (which acquires *clients-lock*)."
  (declare (type keyword command))
  (let ((json (snapshot-to-json
               (list* :command command
                      :timestamp (/ (get-internal-real-time)
                                    internal-time-units-per-second)
                      args))))
    (broadcast-to-clients json)))

(defun disconnect-all-clients ()
  "Forcibly disconnect all connected clients.

Useful for server restart or emergency shutdown. Each client is
unregistered and its socket is closed.

Returns: The number of clients disconnected.

Side effects: Clears *dashboard-clients*.

Thread-safety: Acquires *clients-lock*."
  (let ((all-clients '()))
    (bt:with-lock-held (*clients-lock*)
      (maphash (lambda (client-id info)
                 (declare (ignore info))
                 (push client-id all-clients))
               *dashboard-clients*))
    (dolist (client-id all-clients)
      (unregister-client client-id))
    (length all-clients)))

;; ═══════════════════════════════════════════════════════════════════════════
;; END OF WEBSOCKET.LISP
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Quick Reference — Public API:
;;
;; Client Management:
;;   (register-client socket :type :tcp|:websocket)  → client-id
;;   (unregister-client client-id)                   → t or nil
;;   (lookup-client client-id)                       → plist or nil
;;   (client-count)                                  → integer
;;   (list-clients)                                  → list of symbols
;;   (cleanup-dead-clients)                          → integer (removed count)
;;
;; Broadcast:
;;   (broadcast-to-clients message)                  → success-count
;;   (broadcast-excluding message excluded-id)       → success-count
;;
;; Server Lifecycle:
;;   (start-websocket-server &optional port)         → server or nil
;;   (stop-websocket-server)                         → t or nil
;;   (start-tcp-json-server &optional port)          → server or nil
;;   (stop-tcp-json-server)                          → t or nil
;;
;; Integration:
;;   (start-telemetry-server orch :port :interval)   → status plist
;;   (stop-telemetry-server)                         → status plist
;;
;; Status:
;;   (websocket-server-status)                       → plist
;;   (server-heartbeat)                              → success-count
;;   (send-dashboard-command cmd &rest args)         → success-count
;;   (disconnect-all-clients)                        → count
;;
;; Fallback Internals (not for external use):
;;   (websocket-fallback-send socket message)        → t
;;   (parse-websocket-handshake stream)              → alist
;;   (generate-websocket-accept key)                 → string
;;   (send-websocket-handshake-response stream hdrs) → t or nil
;;
;; NETCAT CLIENT:
;;   $ nc localhost 8081
;;
;; PYTHON CLIENT:
;;   import socket, json
;;   sock = socket.create_connection(("localhost", 8081))
;;   for line in sock.makefile():
;;       data = json.loads(line)
;;       print(data["swarm-health"]["success-rate"])
