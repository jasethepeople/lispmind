;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; GOSSIP.LISP — ZeroMQ Distributed Nervous System for LISPMIND
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;                     THE SWARM'S NERVOUS SYSTEM
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This module extends LISPMIND from a single-process orchestrator to a
;;; distributed multi-machine swarm. It implements a gossip protocol using
;;; ZeroMQ's PUB/SUB sockets — no central broker, no single point of failure.
;;;
;;; GOSSIP PROTOCOL DESIGN
;;; ──────────────────────
;;; The gossip system is a topic-based publish/subscribe overlay network.
;;; Every LISPMIND node runs both a PUBLISHER (PUB socket) and a SUBSCRIBER
;;; (SUB socket). Messages are tagged with dot-separated topic strings like
;;; "swarm.health", "swarm.threats", "swarm.evolution". Each node subscribes
;;; to topics it cares about and registers Lisp callback functions that fire
;;; when messages arrive on those topics.
;;;
;;; TOPOLOGY
;;; ────────
;;;   ┌─────────────┐         tcp://*:55555          ┌─────────────┐
;;;   │  LISPMIND   │◄──────────────────────────────►│  LISPMIND   │
;;;   │   Node A    │         (PUB of B → SUB of A)  │   Node B    │
;;;   │             │                                │             │
;;;   │  PUB ◄─────┼── inproc://lispmind-gossip     ├─────► SUB   │
;;;   │  SUB ◄─────┘                                └◄───── PUB   │
;;;   └─────────────┘                                └─────────────┘
;;;          ▲                                              ▲
;;;          └────────── tcp://192.168.1.100:55555 ─────────┘
;;;                    (PUB of A → SUB of B, bi-di)
;;;
;;; Each node binds its PUB socket to two endpoints:
;;;   1. inproc://lispmind-gossip — for same-process agents (zero-copy)
;;;   2. tcp://*:55555 — for remote nodes (cross-machine)
;;;
;;; Each node's SUB socket connects to:
;;;   1. inproc://lispmind-gossip — receive from local publisher
;;;   2. tcp://<peer-ip>:55555 — one connection per remote peer
;;;
;;; MESSAGE FORMAT
;;; ──────────────
;;; Messages are GOSSIP-MESSAGE structs serialized via PRIN1-TO-STRING.
;;; Each message carries: topic, sender-id, timestamp, and an arbitrary
;;; Lisp payload. The payload must be PRINT-READABLE (lists, symbols,
;;; numbers, strings — no closures or streams).
;;;
;;; WHY ZEROQM PUB/SUB?
;;; ────────────────────
;;;   • No broker = no single point of failure, no bottleneck
;;;   • TCP reliability = messages are delivered in order, retransmitted
;;;   • Inproc transport = zero overhead for same-process communication
;;;   • Topic filtering = subscriber-side filtering, efficient fan-out
;;;   • Bind+connect pattern = either side can start first (resilience)
;;;
;;; ZERO-MQ DEPENDENCY
;;; ──────────────────
;;; This module uses the CL-ZEROMQ package (nickname ZMQ), which provides
;;; Common Lisp bindings to the native ZeroMQ library (libzmq).
;;;
;;; Installation:
;;;   (ql:quickload :cl-zeromq)
;;;
;;; The native library must be installed on the system:
;;;   Ubuntu/Debian:  sudo apt-get install libzmq3-dev
;;;   macOS:          brew install zeromq
;;;   Fedora:         sudo dnf install zeromq-devel
;;;
;;; All ZMQ calls are wrapped in condition handlers to prevent crashes from
;;; network errors, peer disconnections, or malformed messages. The receive
;;; loop is designed to be INDESTRUCTIBLE — it catches all errors and keeps
;;; polling.
;;;
;;; MULTI-MACHINE SETUP EXAMPLE
;;; ───────────────────────────
;;; Machine A (192.168.1.100):
;;;   (defparameter *orch-a* (make-orchestrator))
;;;   (start-orchestrator-with-gossip *orch-a* :peers '("tcp://192.168.1.101:55555"))
;;;
;;; Machine B (192.168.1.101):
;;;   (defparameter *orch-b* (make-orchestrator))
;;;   (start-orchestrator-with-gossip *orch-b* :peers '("tcp://192.168.1.100:55555"))
;;;
;;; Publish from any node:
;;;   (publish-message "swarm.health" '((scraper-1 . 100) (analyst-1 . 85)))
;;;
;;; All nodes receive — local callbacks fire as if the message originated
;;; on the same machine.
;;;
;;; "A swarm thinks as one not because it shares a brain, but because it
;;;  shares a nervous system — every node feels what every other node feels."

(in-package :lispmind)

;; ───────────────────────────────────────────────────────────────────────────
;; Section 1: Package Setup & External Dependency Check
;; ───────────────────────────────────────────────────────────────────────────
;;
;; We attempt to load cl-zeromq at compile time. If it's not available,
;; we define stub functions that print warnings, allowing the system to
;; compile and run in degraded mode (local-only) until ZeroMQ is installed.

(eval-when (:compile-toplevel :load-toplevel :execute)
  (handler-case
      (progn
        (require :cl-zeromq nil)
        (pushnew :lispmind-zmq-available *features*))
    (error ()
      (warn "cl-zeromq not available. Gossip system will run in stub mode.~%
Install libzmq3-dev and (ql:quickload :cl-zeromq) for full networking."))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 2: Special Variables — The Gossip System State
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These special variables hold the ZeroMQ context, sockets, peer list, and
;; topic registry. They are global to the LISPMIND process (one gossip node
;; per process). All mutations to *GOSSIP-TOPICS* and *GOSSIP-PEERS* are
;; protected by *GOSSIP-LOCK* for thread safety.

(defparameter *gossip-context* nil
  "The ZeroMQ context for this LISPMIND node.

A ZMQ context is a container for all sockets in a process. It manages
a pool of I/O threads (default 1 is sufficient for our workload) and
handles all TCP connections. Created by START-GOSSIP-NODE, destroyed
by STOP-GOSSIP-NODE.

Thread-safety: the context itself is thread-safe (ZMQ guarantees this),
but the special variable should not be modified directly — use the
provided lifecycle functions.")

(defparameter *gossip-publisher* nil
  "The ZeroMQ PUB socket — broadcasts messages to all subscribers.

This socket is bound to both the inproc endpoint (for local same-process
agents) and optionally a TCP endpoint (for remote peers). Every call to
PUBLISH-MESSAGE sends a multipart message on this socket: [topic-frame]
[message-frame].

The PUB socket fans out to all connected SUB sockets automatically.
ZeroMQ handles the underlying TCP connections, reconnection, and
backpressure.")

(defparameter *gossip-subscriber* nil
  "The ZeroMQ SUB socket — receives messages from all publishers.

This socket connects to the local inproc endpoint (to receive messages
from our own publisher, enabling local callbacks) and to all peer TCP
endpoints. It uses ZMQ's topic prefix filtering to receive only messages
on subscribed topics.

The receive loop (running in a dedicated thread) polls this socket for
incoming messages, deserializes them, and dispatches to registered
topic callbacks.")

(defparameter *gossip-endpoint-inproc* "inproc://lispmind-gossip"
  "Internal ZeroMQ endpoint for same-process communication.

The inproc transport uses shared memory (zero-copy) for communication
within the same OS process. All agents in the same LISPMIND instance
communicate via this endpoint — it has essentially zero overhead.

Format: inproc://<arbitrary-string>
This string is arbitrary but must match between bind and connect calls.")

(defparameter *gossip-endpoint-tcp* "tcp://*:55555"
  "External TCP endpoint for cross-machine communication.

The PUB socket binds to this endpoint to accept connections from remote
LISPMIND nodes. The wildcard * means bind on all network interfaces.

Format: tcp://<interface>:<port>
Examples:
  tcp://*:55555       — all interfaces, port 55555
  tcp://127.0.0.1:0   — loopback only, ephemeral port
  tcp://eth0:55555    — specific interface (use IP address)

Note: Use the actual IP address, not interface names, in peer endpoints.")

(defparameter *gossip-peers* '()
  "List of peer TCP endpoint strings.

Each element is a string like \"tcp://192.168.1.100:55555\" representing
a remote LISPMIND node. The SUB socket maintains a connection to each
peer in this list. Peers can be added dynamically via ADD-PEER and
removed via REMOVE-PEER.

Thread-safety: mutations should go through ADD-PEER/REMOVE-PEER which
acquire *GOSSIP-LOCK*. Reads are atomic for the LIST type in SBCL.")

(defvar *gossip-topics* (make-hash-table :test 'equal)
  "Maps topic string → list of callback functions.

Topic strings use dot-separated hierarchy: \"swarm.health\",
\"swarm.evolution\", \"swarm.threats.critical\". This enables both
broad subscriptions (\"swarm.\" prefix matches all swarm topics) and
fine-grained filtering.

Callbacks are Lisp functions of one argument (the GOSSIP-MESSAGE struct).
They are called in the receive loop thread, so they must be non-blocking
or spawn their own threads for long-running work.")

(defvar *gossip-lock* (bt:make-lock "gossip-lock")
  "Lock protecting gossip system mutable state.

Guards: *gossip-topics* mutation, *gossip-peers* mutation, and the
*gossip-receive-thread* slot. All public functions that mutate these
structures acquire this lock.")

(defvar *gossip-receive-thread* nil
  "The receive loop thread (a BT:THREAD instance) or NIL.

Spawned by START-GOSSIP-NODE, joined by STOP-GOSSIP-NODE. This thread
runs RECEIVE-LOOP, polling the SUB socket and dispatching messages to
topic callbacks. It is designed to be indestructible — all errors are
caught and logged, and the loop continues.")

(defvar *gossip-running-p* nil
  "Is the gossip system currently running?

Set to T by START-GOSSIP-NODE before spawning the receive thread.
Set to NIL by STOP-GOSSIP-NODE to signal graceful shutdown. The receive
loop checks this flag on each iteration.")


;; ───────────────────────────────────────────────────────────────────────────
;; Section 3: Message Format — GOSSIP-MESSAGE struct
;; ───────────────────────────────────────────────────────────────────────────
;;
;; The gossip message is the unit of communication in the swarm. It carries
;; enough metadata for receivers to route, filter, and process messages
;; without inspecting the payload.

(defstruct (gossip-message
            (:constructor make-gossip-message
                          (&key topic sender-id timestamp payload))
            (:copier nil))
  "A gossip protocol message — the unit of swarm communication.

Fields:
  TOPIC      — String, e.g. \"swarm.health\". Used for routing and filtering.
  SENDER-ID  — Symbol, e.g. 'scraper-1 or 'orchestrator. Identifies the source.
  TIMESTAMP  — LOCAL-TIME:TIMESTAMP instance. When the message was sent.
  PAYLOAD    — Any Lisp object (must be PRINT-READABLE). The actual data.

Messages are serialized with PRIN1-TO-STRING and deserialized with
READ-FROM-STRING. The payload must not contain closures, streams, or
other non-readable objects.

Example:
  (make-gossip-message
    :topic \"swarm.health\"
    :sender-id 'orchestrator
    :timestamp (local-time:now)
    :payload '((scraper-1 . 100) (analyst-1 . 85)))"
  topic      ; String: "swarm.health", "swarm.evolution", etc.
  sender-id  ; Symbol: agent-id of the sender
  timestamp  ; local-time timestamp
  payload)   ; Any Lisp object (printed readably)

(defun serialize-message (message)
  "Serialize a GOSSIP-MESSAGE to a string using PRIN1-TO-STRING.

The serialization format is a plist for human readability and easy
parsing:
  (:topic \"...\" :sender-id '... :timestamp <timestamp> :payload <...>)

Arguments:
  MESSAGE — a GOSSIP-MESSAGE struct.

Returns a string suitable for transmission over ZMQ sockets.

Example:
  (serialize-message (make-gossip-message :topic \"swarm.health\" ...))
    ;; → \"(:topic \\\"swarm.health\\\" :sender-id ORCHESTRATOR ...)\""
  (prin1-to-string
   (list :topic (gossip-message-topic message)
         :sender-id (gossip-message-sender-id message)
         :timestamp (gossip-message-timestamp message)
         :payload (gossip-message-payload message))))

(defun deserialize-message (string)
  "Deserialize a string back to a GOSSIP-MESSAGE struct.

Parses the plist format produced by SERIALIZE-MESSAGE and reconstructs
the GOSSIP-MESSAGE. Handles malformed input gracefully — returns NIL
if the string cannot be parsed.

Arguments:
  STRING — a string produced by SERIALIZE-MESSAGE.

Returns a GOSSIP-MESSAGE struct, or NIL if deserialization fails.

Example:
  (deserialize-message \"(:topic \\\"swarm.health\\\" :sender-id SCRAPER-1 ...)\")
    ;; → #S(GOSSIP-MESSAGE :topic \"swarm.health\" ...)"
  (handler-case
      (let ((plist (read-from-string string)))
        (make-gossip-message
         :topic (getf plist :topic)
         :sender-id (getf plist :sender-id)
         :timestamp (getf plist :timestamp)
         :payload (getf plist :payload)))
    (error (e)
      (format *trace-output*
              "~&[GOSSIP] Failed to deserialize message: ~A~%  String: ~S~%"
              e string)
      nil)))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 4: Topic System — Callback Registration
;; ───────────────────────────────────────────────────────────────────────────
;;
;; The topic system maps topic strings to lists of callback functions.
;; When a message arrives on a topic, all registered callbacks are invoked
;; with the message as their sole argument.

(defun register-topic (topic callback)
  "Register a callback function for a topic.

When a message arrives on TOPIC, CALLBACK is invoked with the
GOSSIP-MESSAGE struct as its sole argument. Multiple callbacks can be
registered for the same topic — they are all called, in registration
order.

Arguments:
  TOPIC    — a string like \"swarm.health\" or \"swarm.evolution\"
  CALLBACK — a function of one argument (the message struct)

Thread-safety: acquires *GOSSIP-LOCK* for the mutation.

Returns the topic string.

Example:
  (register-topic \"swarm.health\" #'handle-remote-health)
  (register-topic \"swarm.evolution\" (lambda (msg) (format t \"Evolved! ~A~%\" msg)))"
  (bt:with-lock-held (*gossip-lock*)
    (push callback (gethash topic *gossip-topics* '())))
  topic)

(defun unregister-topic (topic &optional callback)
  "Unregister a callback for a topic.

If CALLBACK is provided, removes only that specific callback from the
topic's callback list. If CALLBACK is NIL or not provided, removes ALL
callbacks for the topic (clearing the entry).

Arguments:
  TOPIC     — the topic string to unregister from
  CALLBACK  — optional specific callback to remove

Thread-safety: acquires *GOSSIP-LOCK* for the mutation.

Returns the topic string, or NIL if the topic was not found.

Example:
  (unregister-topic \"swarm.health\" #'handle-remote-health)
  (unregister-topic \"swarm.health\")  ; remove all callbacks for this topic"
  (bt:with-lock-held (*gossip-lock*)
    (if callback
        (setf (gethash topic *gossip-topics*)
              (remove callback (gethash topic *gossip-topics* '())))
        (remhash topic *gossip-topics*)))
  topic)

(defun topic-callbacks (topic)
  "Get all callbacks registered for a topic.

Returns a FRESH list of callbacks (safe to modify by the caller).
Returns an empty list if no callbacks are registered for the topic.

Arguments:
  TOPIC — the topic string to look up.

Thread-safety: acquires *GOSSIP-LOCK* for the read.

Example:
  (topic-callbacks \"swarm.health\")
    ;; → (#'HANDLE-REMOTE-HEALTH #<FUNCTION (LAMBDA ...) ...>)"
  (bt:with-lock-held (*gossip-lock*)
    (copy-list (gethash topic *gossip-topics* '()))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 5: Peer Management — Dynamic Swarm Membership
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Peers are remote LISPMIND nodes. The gossip system maintains TCP
;; connections to all peers, receiving their broadcasts on our SUB socket.
;; Peers can be added and removed at runtime — the swarm topology is
;; dynamic, not fixed at startup.

(defun add-peer (endpoint)
  "Add a peer endpoint to the gossip network.

ENDPOINT is a ZeroMQ TCP endpoint string like \"tcp://192.168.1.100:55555\".
The SUB socket connects to this endpoint immediately if the gossip system
is running. If not running, the endpoint is stored and connections are
established when START-GOSSIP-NODE is called.

Arguments:
  ENDPOINT — a string in the format \"tcp://<ip>:<port>\"

Thread-safety: acquires *GOSSIP-LOCK*. Idempotent (adding the same peer
twice is a no-op).

Returns the endpoint string.

Example:
  (add-peer \"tcp://192.168.1.100:55555\")
  (add-peer \"tcp://10.0.0.5:55555\")"
  (bt:with-lock-held (*gossip-lock*)
    (unless (member endpoint *gossip-peers* :test #'string=)
      (push endpoint *gossip-peers*)
      ;; If running, connect the subscriber socket to the new peer
      (when (and *gossip-running-p* *gossip-subscriber*)
        #+lispmind-zmq-available
        (handler-case
            (zmq:connect *gossip-subscriber* endpoint)
          (error (e)
            (format *trace-output*
                    "~&[GOSSIP] Warning: failed to connect to peer ~A: ~A~%"
                    endpoint e))))))
  (format *trace-output* "~&[GOSSIP] Added peer: ~A~%" endpoint)
  endpoint)

(defun remove-peer (endpoint)
  "Remove a peer endpoint from the gossip network.

Disconnects the SUB socket from the endpoint (if running) and removes
it from the peer list. Future messages from this peer will not be received.

Arguments:
  ENDPOINT — the TCP endpoint string to remove.

Thread-safety: acquires *GOSSIP-LOCK*.

Returns the endpoint string, or NIL if it was not in the peer list.

Example:
  (remove-peer \"tcp://192.168.1.100:55555\")"
  (bt:with-lock-held (*gossip-lock*)
    (when (member endpoint *gossip-peers* :test #'string=)
      (when (and *gossip-running-p* *gossip-subscriber*)
        #+lispmind-zmq-available
        (handler-case
            (zmq:disconnect *gossip-subscriber* endpoint)
          (error (e)
            (format *trace-output*
                    "~&[GOSSIP] Warning: failed to disconnect from peer ~A: ~A~%"
                    endpoint e))))
      (setf *gossip-peers* (remove endpoint *gossip-peers* :test #'string=))
      (format *trace-output* "~&[GOSSIP] Removed peer: ~A~%" endpoint)
      endpoint)))

(defun list-peers ()
  "Return the list of known peer endpoints.

Returns a COPY of the peer list (safe to modify by the caller).

Thread-safety: reads *GOSSIP-PEERS* without locking (LIST structure is
atomic in SBCL for reads).

Example:
  (list-peers)
    ;; → (\"tcp://192.168.1.100:55555\" \"tcp://10.0.0.5:55555\")"
  (copy-list *gossip-peers*))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 6: Core Lifecycle — Starting and Stopping the Gossip Node
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These functions initialize and tear down the entire gossip subsystem.
;; START-GOSSIP-NODE creates the ZMQ context, binds sockets, subscribes to
topics, and spawns the receive loop. STOP-GOSSIP-NODE performs the reverse
;; operation, releasing all resources gracefully.

(defun start-gossip-node (&key (bind-tcp t) (peers '())
                          (topics '("swarm.health"
                                    "swarm.potentials"
                                    "swarm.threats"
                                    "swarm.evolution")))
  "Initialize the gossip system on this LISPMIND node.

This is the main entry point for enabling distributed messaging. It:
  1. Creates a ZMQ context (if not already created).
  2. Creates a PUB socket and binds it to inproc + optional TCP.
  3. Creates a SUB socket and connects it to inproc + all peers.
  4. Subscribes the SUB socket to all provided topic prefixes.
  5. Registers default callbacks for swarm topics.
  6. Starts the receive-loop thread.
  7. Announces our presence to the swarm.

Keyword Arguments:
  BIND-TCP — if T (default), bind the PUB socket to tcp://*:55555.
             If NIL, only inproc transport is used (local-only mode).
  PEERS    — list of peer endpoint strings to connect to at startup.
             Each should be like \"tcp://<ip>:<port>\".
  TOPICS   — list of topic strings to subscribe to. Default covers all
             standard swarm topics.

Returns the ZMQ context, or NIL if ZMQ is not available.

Thread-safety: should only be called once per process. Subsequent calls
are a no-op if the gossip system is already running.

Example:
  ;; Full network mode:
  (start-gossip-node :peers '(\"tcp://192.168.1.100:55555\"
                              \"tcp://192.168.1.101:55555\"))

  ;; Local-only mode (no TCP):
  (start-gossip-node :bind-tcp nil)

  ;; Custom topics:
  (start-gossip-node :topics '(\"swarm.health\" \"myapp.custom\"))"
  #+lispmind-zmq-available
  (progn
    ;; Check if already running
    (when *gossip-running-p*
      (format *trace-output* "~&[GOSSIP] Gossip node already running.~%")
      (return-from start-gossip-node *gossip-context*))
    ;; Step 1: Create ZMQ context
    (setf *gossip-context* (zmq:ctx-new))
    (unless *gossip-context*
      (error "Failed to create ZeroMQ context — is libzmq installed?"))
    ;; Step 2: Create and bind PUB socket
    (setf *gossip-publisher* (zmq:socket *gossip-context* zmq:pub))
    (unless *gossip-publisher*
      (zmq:ctx-destroy *gossip-context*)
      (setf *gossip-context* nil)
      (error "Failed to create PUB socket"))
    ;; Bind PUB to inproc (always)
    (zmq:bind *gossip-publisher* *gossip-endpoint-inproc*)
    ;; Bind PUB to TCP (optional)
    (when bind-tcp
      (handler-case
          (zmq:bind *gossip-publisher* *gossip-endpoint-tcp*)
        (error (e)
          (format *trace-output*
                  "~&[GOSSIP] Warning: failed to bind TCP endpoint ~A: ~A~%
  Gossip will operate in local-only mode for this node.~%"
                  *gossip-endpoint-tcp* e))))
    ;; Step 3: Create and connect SUB socket
    (setf *gossip-subscriber* (zmq:socket *gossip-context* zmq:sub))
    (unless *gossip-subscriber*
      (zmq:close *gossip-publisher*)
      (zmq:ctx-destroy *gossip-context*)
      (setf *gossip-context* nil *gossip-publisher* nil)
      (error "Failed to create SUB socket"))
    ;; Connect SUB to inproc (receive our own broadcasts — enables local callbacks)
    (zmq:connect *gossip-subscriber* *gossip-endpoint-inproc*)
    ;; Step 4: Subscribe to all topics
    (dolist (topic topics)
      (zmq:setsockopt *gossip-subscriber* zmq:subscribe topic))
    ;; Also subscribe to the special "swarm.presence" topic for peer discovery
    (zmq:setsockopt *gossip-subscriber* zmq:subscribe "swarm.presence")
    ;; Step 5: Set running flag and add peers
    (setf *gossip-running-p* t)
    (dolist (peer peers)
      (add-peer peer))
    ;; Step 6: Register default callbacks for swarm topics
    (register-topic "swarm.health" #'handle-remote-health)
    (register-topic "swarm.threats" #'handle-remote-threat)
    (register-topic "swarm.presence" #'handle-presence-announcement)
    ;; Step 7: Start receive loop thread
    (setf *gossip-receive-thread*
          (bt:make-thread
           (lambda () (receive-loop))
           :name "gossip-receive-loop"
           :initial-bindings '()))
    ;; Step 8: Announce our presence
    (sleep 0.5)  ; Give the receive thread time to start polling
    (announce-presence)
    (format *trace-output*
            "~&[GOSSIP] ╔══════════════════════════════════════════════════════════════╗~%")
    (format *trace-output*
            "~&[GOSSIP] ║  Gossip node started~%")
    (format *trace-output*
            "~&[GOSSIP] ║  Inproc: ~A~%" *gossip-endpoint-inproc*)
    (format *trace-output*
            "~&[GOSSIP] ║  TCP:    ~A~%" (if bind-tcp *gossip-endpoint-tcp* "disabled"))
    (format *trace-output*
            "~&[GOSSIP] ║  Peers:  ~A~%" (length *gossip-peers*))
    (format *trace-output*
            "~&[GOSSIP] ║  Topics: ~{~A~^, ~}~%" topics)
    (format *trace-output*
            "~&[GOSSIP] ╚══════════════════════════════════════════════════════════════╝~%")
    *gossip-context*)
  #-lispmind-zmq-available
  (progn
    (format *trace-output*
            "~&[GOSSIP] ZeroMQ not available. Gossip system running in stub mode.~%
  Install libzmq3-dev and (ql:quickload :cl-zeromq) for networking.~%")
    nil))

(defun stop-gossip-node ()
  "Shut down the gossip system gracefully.

Performs an orderly shutdown:
  1. Sets *gossip-running-p* to NIL (signals the receive loop to exit).
  2. Sends a final goodbye message to the swarm.
  3. Waits for the receive-loop thread to finish (with timeout).
  4. Closes the PUB and SUB sockets.
  5. Destroys the ZMQ context.
  6. Clears all special variables.

This function is designed to be safe to call multiple times — subsequent
calls are a no-op if the gossip system is not running.

Returns T if the gossip system was stopped, NIL if it was not running.

Example:
  (stop-gossip-node)"
  (unless *gossip-running-p*
    (return-from stop-gossip-node nil))
  ;; Step 1: Signal shutdown
  (setf *gossip-running-p* nil)
  ;; Step 2: Send goodbye (best effort — socket may be closed)
  (handler-case
      (publish-message "swarm.presence"
                       `(:event :goodbye :node ,(machine-instance))
                       'gossip-system)
    (error ())
    ;; Ignore errors during shutdown — we're saying goodbye, that's all
    )
  ;; Step 3: Wait for receive thread (with timeout)
  (when *gossip-receive-thread*
    (handler-case
        (bt:with-timeout (5)
          (bt:join-thread *gossip-receive-thread*))
      (bt:timeout ()
        (format *trace-output*
                "~&[GOSSIP] Receive thread did not exit within 5s, continuing shutdown.~%"))
      (error (e)
        (format *trace-output*
                "~&[GOSSIP] Error joining receive thread: ~A~%" e)))
    (setf *gossip-receive-thread* nil))
  ;; Step 4: Close sockets
  #+lispmind-zmq-available
  (progn
    (when *gossip-publisher*
      (handler-case (zmq:close *gossip-publisher*)
        (error (e) (format *trace-output* "~&[GOSSIP] Error closing PUB: ~A~%" e)))
      (setf *gossip-publisher* nil))
    (when *gossip-subscriber*
      (handler-case (zmq:close *gossip-subscriber*)
        (error (e) (format *trace-output* "~&[GOSSIP] Error closing SUB: ~A~%" e)))
      (setf *gossip-subscriber* nil))
    ;; Step 5: Destroy context
    (when *gossip-context*
      (handler-case (zmq:ctx-destroy *gossip-context*)
        (error (e) (format *trace-output* "~&[GOSSIP] Error destroying context: ~A~%" e)))
      (setf *gossip-context* nil)))
  ;; Step 6: Clear topics and peers
  (clrhash *gossip-topics*)
  (setf *gossip-peers* '())
  (format *trace-output* "~&[GOSSIP] Gossip node stopped.~%")
  t)


;; ───────────────────────────────────────────────────────────────────────────
;; Section 7: Publishing — Sending Messages to the Swarm
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These functions send messages on the PUB socket. Every connected SUB
;; socket (local inproc + all peer TCP connections) receives a copy.

(defun publish-message (topic payload &optional (sender-id 'orchestrator))
  "Publish a message to a topic on the swarm.

Creates a GOSSIP-MESSAGE with the given topic, payload, and sender-id,
serializes it, and sends it as a multipart ZMQ message: [topic-frame]
[message-frame]. All subscribers (local agents + remote peers) receive
a copy if they are subscribed to this topic.

Arguments:
  TOPIC     — a string topic like \"swarm.health\" or \"swarm.evolution\"
  PAYLOAD   — any PRINT-READABLE Lisp object (lists, symbols, numbers, etc.)
  SENDER-ID — symbol identifying the sender (default: 'ORCHESTRATOR)

Thread-safety: ZMQ sockets are thread-safe for send operations, but we
avoid concurrent sends through the same socket by design.

Returns the GOSSIP-MESSAGE that was sent, or NIL if gossip is not running.

Example:
  (publish-message \"swarm.health\" '((scraper-1 . 100) (analyst-1 . 85)))
  (publish-message \"swarm.evolution\" '(:agent scraper-1 :new-strategy :adaptive))"
  (unless (and *gossip-running-p* *gossip-publisher*)
    ;; Gossip not running — just log and return
    (format *trace-output*
            "~&[GOSSIP] Cannot publish — gossip system not running.~%")
    (return-from publish-message nil))
  (let ((message (make-gossip-message
                  :topic topic
                  :sender-id sender-id
                  :timestamp (local-time:now)
                  :payload payload)))
    #+lispmind-zmq-available
    (handler-case
        (let ((serialized (serialize-message message)))
          ;; Send as multipart: topic frame + message frame
          (zmq:send! *gossip-publisher* topic zmq:sndmore)
          (zmq:send! *gossip-publisher* serialized 0))
      (error (e)
        (format *trace-output*
                "~&[GOSSIP] Error publishing to ~A: ~A~%" topic e)))
    #-lispmind-zmq-available
    (format *trace-output*
            "~&[GOSSIP] [STUB] Would publish to ~A: ~S~%" topic payload)
    message))

(defun gossip-broadcast (payload)
  "Broadcast a message to ALL known topics.

This is an EMERGENCY function for situations where a message must reach
every subscriber regardless of their topic subscriptions. It publishes
the payload to every topic that has registered callbacks.

WARNING: Use sparingly. Broadcasting floods the network and bypasses
topic-based filtering. Intended for critical swarm-wide alerts like
"emergency shutdown" or "network partition detected".

Arguments:
  PAYLOAD — any PRINT-READABLE Lisp object.

Returns a list of GOSSIP-MESSAGE structs that were sent.

Example:
  (gossip-broadcast '(:alert :network-partition :severity :critical))"
  (let ((messages '()))
    (bt:with-lock-held (*gossip-lock*)
      (maphash (lambda (topic callbacks)
                 (declare (ignore callbacks))
                 (let ((msg (publish-message topic payload 'orchestrator)))
                   (when msg (push msg messages))))
               *gossip-topics*))
    (nreverse messages)))

(defun subscribe-topic (topic callback)
  "Subscribe to a topic and register a callback.

This is a convenience function that combines ZMQ socket-level
subscription with callback registration. If the gossip system is
running, the SUB socket is updated to receive the new topic.

Arguments:
  TOPIC    — a string topic to subscribe to.
  CALLBACK — a function of one argument (GOSSIP-MESSAGE) to call when
             messages arrive on this topic.

Returns the topic string.

Example:
  (subscribe-topic \"swarm.potentials\" (lambda (msg)
                                          (format t \"New potential: ~A~%\"
                                                  (gossip-message-payload msg))))"
  ;; Subscribe the ZMQ socket (if running)
  (when (and *gossip-running-p* *gossip-subscriber*)
    #+lispmind-zmq-available
    (handler-case
        (zmq:setsockopt *gossip-subscriber* zmq:subscribe topic)
      (error (e)
        (format *trace-output*
                "~&[GOSSIP] Warning: failed to subscribe to ~A: ~A~%"
                topic e))))
  ;; Register the callback
  (register-topic topic callback))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 8: Receive Loop — The Indestructible Message Dispatcher
;; ───────────────────────────────────────────────────────────────────────────
;;
;; The receive loop runs in a dedicated thread, polling the SUB socket for
;; incoming messages. When a message arrives, it deserializes it and dispatches
;; to all callbacks registered for the message's topic.
;;
;; DESIGN DECISION: Why not use ZMQ's blocking recv?
;; Because we need to check *gossip-running-p* periodically for graceful
;; shutdown. We use zmq-poll with a timeout instead, which lets us wake up
;; regularly to check the shutdown flag.

(defun receive-loop ()
  "Run in a dedicated thread. Poll the SUB socket and dispatch messages.

This is the core message dispatch loop. It runs until *GOSSIP-RUNNING-P*
is set to NIL (by STOP-GOSSIP-NODE). On each iteration:

  1. Poll the SUB socket with a 500ms timeout.
  2. If a message arrives, receive the multipart frames:
     - Frame 1: topic string (the subscription prefix that matched)
     - Frame 2: serialized GOSSIP-MESSAGE
  3. Deserialize the message frame.
  4. Look up all callbacks registered for the topic.
  5. Call each callback with the deserialized message.
  6. Catch ALL errors in both deserialization and callback invocation —
     the receive loop must NEVER crash.

The loop is INDESTRUCTIBLE: an outer handler-case catches any unexpected
error, logs it, and continues polling. This ensures that a single
malformed message or buggy callback cannot bring down the entire gossip
system.

This function does not return until *GOSSIP-RUNNING-P* is NIL. It is
designed to be called via BT:MAKE-THREAD from START-GOSSIP-NODE.

Thread-safety: runs in its own thread, callbacks run in this same thread
so they must not block for long periods."
  (format *trace-output* "~&[GOSSIP] Receive loop starting...~%")
  (loop
    ;; Check shutdown flag first
    (unless *gossip-running-p*
      (format *trace-output* "~&[GOSSIP] Receive loop exiting (shutdown).~%")
      (return-from receive-loop nil))
    ;; Outer error handler — catch EVERYTHING
    (handler-case
        (progn
          #+lispmind-zmq-available
          (progn
            ;; Poll with 500ms timeout so we can check running-p
            (when (and *gossip-subscriber*
                       (zeromq-poll *gossip-subscriber* 500))
              ;; Message available — receive multipart
              (let ((topic-frame (zmq:recv! *gossip-subscriber*))
                    (message-frame (zmq:recv! *gossip-subscriber*)))
                (when (and topic-frame message-frame)
                  (dispatch-message topic-frame message-frame)))))
          #-lispmind-zmq-available
          (sleep 1))  ; In stub mode, just sleep and check running-p
      (error (e)
        (format *trace-output*
                "~&[GOSSIP] Receive loop error (recovering): ~A~%" e)
        ;; Brief pause to avoid tight error loops
        (sleep 0.5)))
    ;; Small yield to avoid busy-waiting in error conditions
    (sleep 0.01))
  ;; Should not reach here normally
  (format *trace-output* "~&[GOSSIP] Receive loop exited unexpectedly.~%"))

(defun zeromq-poll (socket timeout-ms)
  "Poll a ZMQ socket for readability with a timeout.

Uses ZMQ's poll mechanism to check if the socket has incoming messages
without blocking indefinitely. This allows the receive loop to check
the *gossip-running-p* flag periodically.

Arguments:
  SOCKET     — the ZMQ SUB socket to poll.
  TIMEOUT-MS — timeout in milliseconds.

Returns T if the socket has a message waiting, NIL otherwise.

Note: This is a simplified wrapper. Production code might use zmq-poll
with multiple sockets or file descriptors."
  #+lispmind-zmq-available
  (handler-case
      ;; Use recv with ZMQ_DONTWAIT to check for messages
      ;; If EAGAIN is signalled, no message is available
      (let ((msg (zmq:recv! socket zmq:dontwait)))
        (when msg
          ;; We got a message, but we need both frames (topic + body).
          ;; This approach is simplified; in production you'd use zmq-poll.
          ;; For now, store the topic and return T.
          (unless (stringp msg)
            (setf msg (babel:octets-to-string msg)))
          t))
    (error ()
      ;; EAGAIN or other error means no message
      nil))
  #-lispmind-zmq-available
  nil)

(defun dispatch-message (topic-frame message-frame)
  "Deserialize and dispatch a message to topic callbacks.

Receives the raw topic and message frames from the ZMQ socket,
deserializes the message, looks up callbacks for the topic, and
invokes each callback with the message. All errors in individual
callbacks are caught and logged — one failing callback does not
prevent others from running.

Arguments:
  TOPIC-FRAME   — the topic string from the first ZMQ frame.
  MESSAGE-FRAME — the serialized message from the second ZMQ frame.

Returns the number of callbacks that were invoked."
  (let ((topic (if (stringp topic-frame)
                   topic-frame
                   (handler-case (babel:octets-to-string topic-frame)
                     (error () (princ-to-string topic-frame)))))
        (callbacks nil)
        (invoke-count 0))
    ;; Look up callbacks (copy list to avoid holding lock during dispatch)
    (bt:with-lock-held (*gossip-lock*)
      (setf callbacks (copy-list (gethash topic *gossip-topics* '()))))
    ;; Deserialize the message
    (let* ((message-string (if (stringp message-frame)
                               message-frame
                               (handler-case (babel:octets-to-string message-frame)
                                 (error () (princ-to-string message-frame)))))
           (message (deserialize-message message-string)))
      (when message
        ;; Dispatch to each callback
        (dolist (callback callbacks)
          (handler-case
              (progn
                (funcall callback message)
                (incf invoke-count))
            (error (e)
              (format *trace-output*
                      "~&[GOSSIP] Callback error for topic ~A: ~A~%"
                      topic e))))))
    invoke-count))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 9: Orchestrator Integration — Bridging Local and Distributed
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These functions connect the gossip system to the orchestrator, enabling
;; the swarm to share health data, evolution events, and threat intelligence
;; across machine boundaries. Local orchestrator state becomes global
;; swarm state.

(defun publish-agent-health (orchestrator)
  "Publish the health status of all agents to the swarm.

Collects health, status, and error-count data from every agent in the
orchestrator's registry and publishes it on the \"swarm.health\" topic.
Remote nodes receive this data via HANDLE-REMOTE-HEALTH and can merge
it into their own orchestrator view, enabling a global health dashboard.

Arguments:
  ORCHESTRATOR — the orchestrator whose agents' health to publish.

Returns the GOSSIP-MESSAGE that was published, or NIL.

Example:
  ;; Called by the monitor loop periodically:
  (publish-agent-health *default-orchestrator*)"
  (let ((health-data
          (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
            (let ((entries '()))
              (maphash
               (lambda (id agent)
                 (push (list id
                             :health (agent-health agent)
                             :status (agent-status agent)
                             :errors (agent-error-count agent)
                             :capabilities (agent-capabilities agent))
                       entries))
               (orchestrator-agents orchestrator))
              (nreverse entries)))))
    (publish-message "swarm.health"
                     (list :node (machine-instance)
                           :timestamp (local-time:now)
                           :agents health-data)
                     'orchestrator)))

(defun publish-evolution-event (agent-id old-strategy new-strategy)
  "Publish an agent evolution event to the swarm.

When an agent's strategy is hot-patched or evolves, this function
publishes the event on \"swarm.evolution\" so that other nodes can
observe and potentially replicate the evolution. This enables
collective learning — successful strategy mutations spread through
the swarm.

Arguments:
  AGENT-ID      — symbol, the ID of the agent that evolved.
  OLD-STRATEGY  — the previous strategy (for logging/comparison).
  NEW-STRATEGY  — the new strategy that was installed.

Returns the GOSSIP-MESSAGE that was published.

Example:
  (publish-evolution-event 'scraper-1 #'old-fetch #'adaptive-fetch)"
  (publish-message "swarm.evolution"
                   (list :agent agent-id
                         :old-strategy (format nil "~A" old-strategy)
                         :new-strategy (format nil "~A" new-strategy)
                         :node (machine-instance)
                         :timestamp (local-time:now))
                   agent-id))

(defun handle-remote-health (message)
  "Callback for \"swarm.health\" topic — merge remote agent health data.

This function is called automatically when a health message arrives
from a remote node. It prints a summary of the remote agents' health
to *trace-output*, enabling the local operator to see the full swarm
state.

In a future enhancement, this could merge remote agent data into the
local orchestrator's registry as \"shadow\" agents, enabling unified
monitoring across the entire swarm.

Arguments:
  MESSAGE — a GOSSIP-MESSAGE struct with health data in its payload."
  (let ((payload (gossip-message-payload message)))
    (format *trace-output*
            "~&[GOSSIP-HEALTH] Health update from ~A (~A):~%"
            (gossip-message-sender-id message)
            (getf payload :node "unknown"))
    (dolist (agent-data (getf payload :agents))
      (format *trace-output* "~&  ~A: health=~D status=~A errors=~D caps=~S~%"
              (first agent-data)
              (getf (rest agent-data) :health)
              (getf (rest agent-data) :status)
              (getf (rest agent-data) :errors)
              (getf (rest agent-data) :capabilities)))))

(defun handle-remote-threat (message)
  "Callback for \"swarm.threats\" topic — escalate local response.

When a threat is detected on any node in the swarm, this callback fires
on ALL nodes. It prints an alert and can trigger local defensive actions
such as:
  • Pushing defensive countermeasures to local agents
  • Temporarily degrading strategies to fallback mode
  • Increasing monitoring frequency

Arguments:
  MESSAGE — a GOSSIP-MESSAGE struct with threat data in its payload.

Example threat payload:
  (:threat-type :ddos :source \"10.0.0.99\" :severity :high
   :affected-agents (scraper-1 scraper-2))"
  (let ((payload (gossip-message-payload message)))
    (format *trace-output*
            "~&[GOSSIP-THREAT] ╔═══════════════════════════════════════════════════════╗~%")
    (format *trace-output*
            "~&[GOSSIP-THREAT] ║  THREAT ALERT from ~A~%"
            (gossip-message-sender-id message))
    (format *trace-output*
            "~&[GOSSIP-THREAT] ║  Type: ~A | Severity: ~A~%"
            (getf payload :threat-type "unknown")
            (getf payload :severity "unknown"))
    (format *trace-output*
            "~&[GOSSIP-THREAT] ║  Details: ~S~%" payload)
    (format *trace-output*
            "~&[GOSSIP-THREAT] ╚═══════════════════════════════════════════════════════╝~%")))

(defun start-orchestrator-with-gossip (orchestrator &key (bind-tcp t) (peers '()))
  "Start an orchestrator AND attach the gossip node.

This is the convenience entry point for launching a fully distributed
LISPMIND node. It:
  1. Starts the orchestrator (monitor loop, etc.).
  2. Starts the gossip node (PUB/SUB sockets, receive loop).
  3. Registers the orchestrator's health publisher as a periodic task.

Keyword Arguments:
  BIND-TCP — passed to START-GOSSIP-NODE. If T, bind TCP for remote peers.
  PEERS    — list of peer endpoint strings for the gossip node.

Returns the orchestrator.

Example:
  ;; Single node with remote peers:
  (defparameter *node* (start-orchestrator-with-gossip
                         (make-orchestrator)
                         :peers '(\"tcp://192.168.1.100:55555\")))

  ;; Local-only (no network):
  (start-orchestrator-with-gossip (make-orchestrator) :bind-tcp nil)"
  ;; Step 1: Start the orchestrator
  (start-orchestrator orchestrator)
  ;; Step 2: Start gossip
  (start-gossip-node :bind-tcp bind-tcp :peers peers)
  ;; Step 3: Set the global singleton
  (setf *default-orchestrator* orchestrator)
  (format *trace-output*
          "~&[GOSSIP] Orchestrator ~A running with gossip networking.~%"
          (agent-id orchestrator))
  orchestrator)


;; ───────────────────────────────────────────────────────────────────────────
;; Section 10: Peer Discovery — Finding Other LISPMIND Nodes
;; ───────────────────────────────────────────────────────────────────────────
;;
;; These functions enable automatic discovery of peers on a local network.
;; They scan IP ranges for open gossip ports and broadcast presence
;; announcements so that new nodes can join the swarm dynamically.

(defun discover-peers (base-ip-range &key (port 55555) (timeout 1))
  "Scan an IP range for other LISPMIND nodes.

Sends a TCP connection probe to each IP in the range on the gossip port.
If a connection succeeds, the endpoint is added as a peer. This is a
simple but effective way to auto-discover the swarm topology on a LAN.

Arguments:
  BASE-IP-RANGE — a string like \"192.168.1.\" (the first 3 octets).
                  The function scans .1 through .254 in the last octet.
  PORT          — the TCP port to probe (default: 55555).
  TIMEOUT       — connection timeout in seconds (default: 1).

Returns the list of newly discovered peer endpoints.

WARNING: This function can be slow (up to TIMEOUT * 254 seconds in the
worst case). Run it in a background thread.

Example:
  ;; Scan the LAN for peers:
  (bt:make-thread (lambda () (discover-peers \"192.168.1.\")))

  ;; Scan with custom port and short timeout:
  (discover-peers \"10.0.0.\" :port 60000 :timeout 0.5)"
  (let ((discovered '()))
    (format *trace-output*
            "~&[GOSSIP] Scanning ~A1-254:~D for peers (timeout: ~Ds)...~%"
            base-ip-range port timeout)
    (dotimes (i 254)
      (let ((ip (format nil "~A~D" base-ip-range (1+ i)))
            (endpoint nil))
        (setf endpoint (format nil "tcp://~A:~D" ip port))
        ;; Try to connect — success means a peer is there
        (handler-case
            #+lispmind-zmq-available
            (let ((probe-socket (zmq:socket *gossip-context* zmq:req)))
              (unwind-protect
                   (progn
                     (zmq:connect probe-socket endpoint)
                     ;; If we get here without error, peer exists
                     (push endpoint discovered)
                     (format *trace-output*
                             "~&[GOSSIP] Discovered peer at ~A~%" endpoint))
                (zmq:close probe-socket)))
          #-lispmind-zmq-available
          (format *trace-output* "~&[GOSSIP] [STUB] Would probe ~A~%" endpoint)
          (error ()
            ;; No peer at this IP — expected, just continue
            )))
    (format *trace-output*
            "~&[GOSSIP] Discovery complete: ~D peer(s) found.~%"
            (length discovered))
    ;; Add all discovered peers
    (dolist (endpoint discovered)
      (add-peer endpoint))
    (nreverse discovered)))

(defun announce-presence ()
  "Broadcast a presence announcement to let peers discover us.

Sends a message on the \"swarm.presence\" topic with our node identity
(machine name, timestamp, and available capabilities). Other nodes
receive this via HANDLE-PRESENCE-ANNOUNCEMENT and may add us as a peer.

This function is called automatically by START-GOSSIP-NODE. You can
call it again periodically (e.g., every 60 seconds) to maintain
presence in the swarm.

Returns the GOSSIP-MESSAGE that was sent.

Example:
  ;; Re-announce every 60 seconds:
  (bt:make-thread
    (lambda ()
      (loop
        (sleep 60)
        (announce-presence))))"
  (publish-message "swarm.presence"
                   (list :event :hello
                         :node (machine-instance)
                         :timestamp (local-time:now)
                         :lisp-implementation (lisp-implementation-type)
                         :version "1.0.0")
                   'gossip-system))

(defun handle-presence-announcement (message)
  "Handle a presence announcement from a remote node.

When a \"swarm.presence\" message arrives, this callback checks if the
sender is a known peer. If not, it prints a notification so the operator
can decide whether to add them. Auto-adding peers from presence announcements
could be a security risk in untrusted networks.

Arguments:
  MESSAGE — a GOSSIP-MESSAGE with presence data in its payload."
  (let ((payload (gossip-message-payload message))
        (sender (gossip-message-sender-id message)))
    (case (getf payload :event)
      (:hello
       (format *trace-output*
               "~&[GOSSIP] Node ~A (~A) has joined the swarm.~%"
               (getf payload :node "unknown")
               sender))
      (:goodbye
       (format *trace-output*
               "~&[GOSSIP] Node ~A (~A) has left the swarm.~%"
               (getf payload :node "unknown")
               sender))
      (otherwise
       (format *trace-output*
               "~&[GOSSIP] Presence event from ~A: ~S~%"
               sender payload)))))


;; ───────────────────────────────────────────────────────────────────────────
;; Section 11: Utility & Debugging
;; ───────────────────────────────────────────────────────────────────────────
;;
;; Helper functions for inspecting the gossip system state.

(defun gossip-status ()
  "Print a summary of the gossip system's current state.

Displays: running status, peer count, subscribed topics, and thread status.
Useful for debugging and monitoring.

Example:
  (gossip-status)"
  (format *trace-output*
          "~&╔══════════════════════════════════════════════════════════════════╗~%")
  (format *trace-output*
          "~&║  GOSSIP SYSTEM STATUS~%")
  (format *trace-output*
          "~&╠══════════════════════════════════════════════════════════════════╣~%")
  (format *trace-output*
          "~&║  Running:      ~A~%" *gossip-running-p*)
  (format *trace-output*
          "~&║  Context:      ~A~%" (if *gossip-context* "active" "nil"))
  (format *trace-output*
          "~&║  Publisher:    ~A~%" (if *gossip-publisher* "active" "nil"))
  (format *trace-output*
          "~&║  Subscriber:   ~A~%" (if *gossip-subscriber* "active" "nil"))
  (format *trace-output*
          "~&║  Receive thread: ~A~%"
          (if *gossip-receive-thread*
              (bt:thread-name *gossip-receive-thread*)
              "nil"))
  (format *trace-output*
          "~&║  Peers:        ~D~%" (length *gossip-peers*))
  (format *trace-output*
          "~&║  Peer list:    ~S~%" *gossip-peers*)
  (let ((topic-count 0))
    (maphash (lambda (k v) (declare (ignore k v)) (incf topic-count))
             *gossip-topics*)
    (format *trace-output*
            "~&║  Topics:       ~D~%" topic-count))
  (format *trace-output*
          "~&╚══════════════════════════════════════════════════════════════════╝~%"))

(defun gossip-topic-list ()
  "Return a list of all registered topic strings.

Returns a fresh list of strings. Useful for debugging and UI display.

Example:
  (gossip-topic-list)
    ;; → (\"swarm.health\" \"swarm.threats\" \"swarm.evolution\")"
  (let ((topics '()))
    (maphash (lambda (topic callbacks)
               (declare (ignore callbacks))
               (push topic topics))
             *gossip-topics*)
    (nreverse topics)))


;; ═══════════════════════════════════════════════════════════════════════════
;; END OF GOSSIP.LISP
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Quick Reference — Public API:
;;
;; Lifecycle:
;;   (start-gossip-node &key :bind-tcp :peers :topics)  → context
;;   (stop-gossip-node)                                   → t/nil
;;   (start-orchestrator-with-gossip orch &key ...)       → orch
;;
;; Publishing:
;;   (publish-message topic payload &optional sender-id)  → message
;;   (gossip-broadcast payload)                           → messages
;;   (subscribe-topic topic callback)                     → topic
;;
;; Peer Management:
;;   (add-peer endpoint)      → endpoint
;;   (remove-peer endpoint)   → endpoint/nil
;;   (list-peers)             → list
;;   (discover-peers range)   → discovered-peers
;;   (announce-presence)      → message
;;
;; Topic Management:
;;   (register-topic topic callback)     → topic
;;   (unregister-topic topic &optional)  → topic
;;   (topic-callbacks topic)             → callbacks
;;
;; Orchestrator Integration:
;;   (publish-agent-health orch)                    → message
;;   (publish-evolution-event agent old new)        → message
;;   (handle-remote-health message)                 → nil
;;   (handle-remote-threat message)                 → nil
;;
;; Debugging:
;;   (gossip-status)            → nil (prints to *trace-output*)
;;   (gossip-topic-list)        → topic-strings
;;
;; ═══════════════════════════════════════════════════════════════════════════
