;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; MCP-BRIDGE.LISP — Model Context Protocol Server for LISPMIND
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;           THE SWARM'S VOICE: LISPMIND SPEAKS MCP TO THE WORLD
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This module transforms LISPMIND into a fully-compliant MCP (Model Context
;;; Protocol) server, exposing the swarm's capabilities as discoverable, typed
;;; tools that any MCP client can invoke. It implements JSON-RPC 2.0 over both
;;; stdio (for local integration) and Server-Sent Events (for remote access).
;;;
;;; MCP SPECIFICATION COMPLIANCE
;;; ────────────────────────────
;;; This implementation follows the Model Context Protocol specification
;;; (https://modelcontextprotocol.io/specification) providing:
;;;   • tools/list   — Discovery of available tools with JSON Schema parameters
;;;   • tools/call   — Invocation of tools with typed arguments
;;;   • resources/list — Discovery of exposed resources
;;;   • resources/read — Reading resource data via URI templates
;;;   • initialize   — Server capability handshake
;;;   • notifications/* — Asymmetric server→client events
;;;
;;; DESIGN PHILOSOPHY
;;; ─────────────────
;;; The MCP bridge is not a separate service — it is a LISPMIND agent in its
;;; own right. It monitors the orchestrator's state and translates between
;;; the Lisp world (symbols, S-expressions, CLOS objects) and the JSON-RPC
;;; world (strings, arrays, objects). Every exposed tool is a window into
;;; the swarm's nervous system.
;;;
;;; "The bridge does not merely translate — it interprets, adapting the
;;;  richness of the Lisp machine to the structured expectations of the
;;;  protocol, so that external minds may commune with the swarm."
;;;
;;; TRANSPORT LAYERS
;;; ────────────────
;;;   STDIO (default) — JSON-RPC messages delimited by newlines on stdin/stdout.
;;;                     Used by local MCP clients (Claude Desktop, Cursor, etc.)
;;;   SSE (optional)  — Server-Sent Events over HTTP for remote browser clients.
;;;                     Runs on a configurable port (default 8082).
;;;
;;; ERROR HANDLING
;;; ──────────────
;;; All JSON-RPC errors follow the spec: -32700 (parse), -32600 (invalid request),
;;; -32601 (method not found), -32602 (invalid params), -32603 (internal error).
;;; Tool handlers are wrapped in handler-case to prevent any Lisp condition
;;; from escaping to the transport layer.

(in-package :lispmind)

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 0: Package Integration — External Dependencies
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; We require cl-json for JSON encoding/decoding. If unavailable, a minimal
;; fallback encoder is provided (inherited from telemetry.lisp).

(eval-when (:compile-toplevel :load-toplevel :execute)
  (handler-case
      (progn
        (require :cl-json)
        (unless (member :cl-json-available *features*)
          (pushnew :cl-json-available *features*)))
    (error ()
      (warn "[MCP] cl-json not available. Using minimal JSON fallback."))))

;; ---------------------------------------------------------------------------
;; Conditional Hunchentoot loading for SSE transport
;; ---------------------------------------------------------------------------
(eval-when (:compile-toplevel :load-toplevel :execute)
  (handler-case
      (progn
        (require :hunchentoot)
        (pushnew :hunchentoot-available *features*))
    (error ()
      (warn "[MCP] hunchentoot not available. SSE transport disabled."))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 1: Special Variables — Server State
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *mcp-server-running-p* nil
  "Is the MCP server currently accepting connections?

Set to T by START-MCP-BRIDGE and NIL by STOP-MCP-BRIDGE.
Both stdio and SSE transports check this flag.

Thread-safety: Special variable, read by main thread and server threads.
T/NIL reads are atomic on SBCL.")

(defvar *mcp-server-thread* nil
  "The stdio MCP server thread handle (a BT:THREAD instance) or NIL.

Set by START-MCP-STDIO-SERVER when spawning the stdio loop thread.
Cleared by STOP-MCP-BRIDGE after joining the thread.

The stdio transport runs in its own thread so that it does not block
the REPL or other LISPMIND operations.")

(defvar *mcp-sse-thread* nil
  "The SSE MCP server thread handle or NIL.

Set by START-MCP-SSE-SERVER when spawning the Hunchentoot server.
Cleared by STOP-MCP-BRIDGE on shutdown.")

(defvar *mcp-tools* (make-hash-table :test 'eq)
  "Registry of exposed MCP tools: symbol name → MCP-TOOL struct.

All tool registrations are stored here. The tools/list method returns
the contents of this table as JSON Schema descriptions.

Thread-safety: Writes (register/unregister) should be serialized.
Reads (tool calls, listing) are safe because hash-table reads are
atomic on SBCL for simple values.")

(defvar *mcp-resources* (make-hash-table :test 'eq)
  "Registry of exposed MCP resources: symbol name → MCP-RESOURCE struct.

Resources are data sources identified by URI templates (e.g.,
'swarm://agents/{id}'). They provide read-only access to swarm state.

Thread-safety: Same as *MCP-TOOLS*.")

(defvar *mcp-request-counter* 0
  "Monotonically increasing counter for JSON-RPC request IDs.

Used to correlate notifications sent from the server to the client.
Each notification gets a unique ID derived from this counter.

Thread-safety: Incremented atomically via INCF (SBCL).")

(defvar *mcp-log-level* :info
  "Logging verbosity for the MCP bridge.

One of :DEBUG :INFO :WARN :ERROR. Set to :DEBUG for troubleshooting
protocol issues.")

(defvar *mcp-sse-port* 8082
  "Default TCP port for the SSE transport server.")

(defvar *mcp-sse-acceptor* nil
  "Hunchentoot acceptor instance for SSE transport, or NIL.")

(defvar *mcp-client-capabilities* nil
  "Capabilities reported by the client during initialize.

Stored as a plist. Used to determine which protocol features the
client supports (e.g., streaming, roots, sampling).")

(defvar *mcp-server-info*
  '(:name "lispmind-mcp"
    :version "2.0.0"
    :vendor "LISPMIND"
    :homepage "https://github.com/lispmind/lispmind")
  "Server identification metadata sent during the initialize handshake.

Follows the MCP spec's ServerInfo structure.")


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 2: Data Structures — Tool and Resource Definitions
;; ═══════════════════════════════════════════════════════════════════════════

(defstruct (mcp-tool (:conc-name mcp-tool-))
  "An MCP tool definition following the Model Context Protocol specification.

Each tool has:
  • NAME — A symbol uniquely identifying this tool
  • DESCRIPTION — Human-readable explanation for LLM consumption
  • PARAMETERS — A JSON Schema object (as a plist) describing the arguments
  • HANDLER — A Lisp function (lambda (args-alist)) → result-plist
  • REQUIRED-PERMS — List of permission keywords (reserved for future ACL)

The PARAMETERS field follows JSON Schema Draft 2020-12, using plists
for compatibility with cl-json. Example:
  (:type "object"
   :properties (:agent-id (:type "string" :description "The agent ID")
                :restart  (:type "string" :enum ["retry" "fallback"]))
   :required ["agent-id"])

Reference: MCP Spec §3.2 — Tools"
  name
  description
  parameters
  handler
  required-perms)

(defstruct (mcp-resource (:conc-name mcp-resource-))
  "An MCP resource definition following the Model Context Protocol specification.

Resources are read-only data sources identified by URI templates.
They allow MCP clients to read swarm state without invoking tools.

Each resource has:
  • NAME — A symbol uniquely identifying this resource
  • DESCRIPTION — Human-readable explanation
  • URI-TEMPLATE — A URI template string (e.g., 'swarm://agents/{id}')
  • HANDLER — A Lisp function (lambda (params-alist)) → content-string

Reference: MCP Spec §3.1 — Resources"
  name
  description
  uri-template
  mime-type
  handler)


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 3: Tool Registration API
;; ═══════════════════════════════════════════════════════════════════════════

(defun register-mcp-tool (name description parameters handler
                          &optional (required-perms nil))
  "Register an MCP tool in the global *MCP-TOOLS* registry.

Arguments:
  NAME        — A symbol naming the tool (e.g., 'LIST-AGENTS)
  DESCRIPTION — A string describing what the tool does. LLMs use this
                to decide which tool to call, so be precise and complete.
  PARAMETERS  — A plist describing the tool's arguments in JSON Schema.
                Use :TYPE 'OBJECT', :PROPERTIES, and :REQUIRED keys.
  HANDLER     — A function of one argument (an alist of parsed JSON args)
                that returns a plist with :content and optional :is-error.
  REQUIRED-PERMS — List of permission keywords (reserved, pass NIL).

Returns the registered MCP-TOOL struct.

Example:
  (register-mcp-tool
    'echo-test
    "Echoes back the input message. Useful for connectivity testing."
    '(:type "object"
      :properties (:message (:type "string" :description "Message to echo"))
      :required ("message"))
    (lambda (args)
      (list :content (cdr (assoc :message args :test #'string-equal))))

Thread-safety: Safe to call from any thread. Uses the global hash-table.

Reference: MCP Spec §3.2 — Tool Registration"
  (let ((tool (make-mcp-tool :name name
                             :description description
                             :parameters parameters
                             :handler handler
                             :required-perms required-perms)))
    (setf (gethash name *mcp-tools*) tool)
    (mcp-log :debug "Registered MCP tool: ~A" name)
    tool))

(defun unregister-mcp-tool (name)
  "Remove an MCP tool from the registry.

Arguments:
  NAME — The symbol name of the tool to remove.

Returns T if the tool was found and removed, NIL if not found.

Example:
  (unregister-mcp-tool 'echo-test)  ; → T"
  (if (gethash name *mcp-tools*)
      (progn (remhash name *mcp-tools*)
             (mcp-log :debug "Unregistered MCP tool: ~A" name)
             t)
      nil))

(defun list-mcp-tools () 
  "Return all registered MCP tools as JSON-schema-compatible plists.

Returns a list of plists, one per tool:
  ((:name "tool-name"
    :description "..."
    :parameters <json-schema-plist>) ...)

This format is directly usable by the tools/list JSON-RPC response.

Example:
  (list-mcp-tools)
    ;; → ((:name "list-agents" :description "..." :parameters ...)
    ;;    (:name "inspect-agent" :description "..." :parameters ...))"
  (let ((result '()))
    (maphash (lambda (name tool)
               (declare (ignore name))
               (push (list :name (string (mcp-tool-name tool))
                           :description (mcp-tool-description tool)
                           :parameters (mcp-tool-parameters tool))
                     result))
             *mcp-tools*)
    (nreverse result)))

(defun find-mcp-tool (name)
  "Look up an MCP tool by name (symbol or string).

Returns the MCP-TOOL struct, or NIL if not found.

Example:
  (find-mcp-tool 'list-agents)   ; → #S(MCP-TOOL ...)
  (find-mcp-tool "list-agents")  ; → #S(MCP-TOOL ...)"
  (etypecase name
    (symbol (gethash name *mcp-tools*))
    (string (let ((sym (find-symbol (string-upcase name) :lispmind)))
              (if sym
                  (gethash sym *mcp-tools*)
                  ;; Try direct string lookup
                  (block found
                    (maphash (lambda (k v)
                               (declare (ignore k))
                               (when (string-equal (string (mcp-tool-name v))
                                                  name)
                                 (return-from found v)))
                             *mcp-tools*)
                    nil))))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 4: Resource Registration API
;; ═══════════════════════════════════════════════════════════════════════════

(defun register-mcp-resource (name description uri-template handler
                              &optional (mime-type "application/json"))
  "Register an MCP resource in the global *MCP-RESOURCES* registry.

Arguments:
  NAME         — A symbol naming the resource (e.g., 'AGENT-LIST)
  DESCRIPTION  — Human-readable description of the resource.
  URI-TEMPLATE — A URI template string following RFC 6570.
                 Example: 'swarm://agents/{id}'
  HANDLER      — A function (lambda (params-alist)) → content-string
  MIME-TYPE    — Content type string (default 'application/json')

Returns the registered MCP-RESOURCE struct.

Example:
  (register-mcp-resource
    'agent-list
    "List of all registered agents in the swarm"
    "swarm://agents"
    (lambda (params)
      (declare (ignore params))
      (snapshot-to-json (build-agent-summaries *default-orchestrator*)))

Reference: MCP Spec §3.1 — Resource Registration"
  (let ((resource (make-mcp-resource :name name
                                     :description description
                                     :uri-template uri-template
                                     :mime-type mime-type
                                     :handler handler)))
    (setf (gethash name *mcp-resources*) resource)
    (mcp-log :debug "Registered MCP resource: ~A (~A)" name uri-template)
    resource))

(defun unregister-mcp-resource (name)
  "Remove an MCP resource from the registry.

Arguments:
  NAME — The symbol name of the resource to remove.

Returns T if found and removed, NIL otherwise."
  (if (gethash name *mcp-resources*)
      (progn (remhash name *mcp-resources*)
             (mcp-log :debug "Unregistered MCP resource: ~A" name)
             t)
      nil))

(defun list-mcp-resources ()
  "Return all registered MCP resources as JSON-compatible plists.

Returns a list of plists:
  ((:name "resource-name"
    :description "..."
    :uri-template "swarm://..."
    :mime-type "application/json") ...)

This format is directly usable by the resources/list JSON-RPC response."
  (let ((result '()))
    (maphash (lambda (name resource)
               (declare (ignore name))
               (push (list :name (string (mcp-resource-name resource))
                           :description (mcp-resource-description resource)
                           :uri-template (mcp-resource-uri-template resource)
                           :mime-type (mcp-resource-mime-type resource))
                     result))
             *mcp-resources*)
    (nreverse result)))

(defun find-mcp-resource-by-uri (uri)
  "Find a resource handler that matches the given URI.

Performs simple template matching: if the resource's URI-TEMPLATE contains
a '{param}' segment, it is treated as a prefix match and the parameter
value is extracted.

Returns: (values resource params-alist) or (values nil nil) if no match.

Example:
  (find-mcp-resource-by-uri 'swarm://agents/agent-42')
    ;; → #S(MCP-RESOURCE ...), ((:ID . 'agent-42'))"
  (block found
    (maphash
     (lambda (k resource)
       (declare (ignore k))
       (let ((template (mcp-resource-uri-template resource)))
         (cond
           ;; Exact match
           ((string-equal template uri)
            (return-from found (values resource nil)))
           ;; Template with parameters — extract them
           ((and (search "{" template)
                 (template-matches-p template uri))
            (return-from found
              (values resource (extract-template-params template uri)))))))
     *mcp-resources*)
    (values nil nil)))

(defun template-matches-p (template uri)
  "Check if a URI template matches a concrete URI.

Does simple prefix/suffix matching on template segments.
Example: 'swarm://agents/{id}' matches 'swarm://agents/agent-42'.

This is a simplified implementation — full RFC 6570 compliance is
left as a future enhancement."
  (let ((template-parts (split-template template))
        (uri-parts (split-template uri)))
    (when (= (length template-parts) (length uri-parts))
      (every (lambda (tp up)
               (or (starts-with "{" tp)
                   (string-equal tp up)))
             template-parts uri-parts))))

(defun split-template (template)
  "Split a URI template into path segments.

Example: 'swarm://agents/{id}' → '("swarm:" "" "agents" "{id}")"
  (let ((parts '())
        (start 0))
    (loop for i from 0 below (length template)
          when (char= (char template i) #\/)
          do (push (subseq template start i) parts)
             (setf start (1+ i)))
    (push (subseq template start) parts)
    (nreverse parts)))

(defun extract-template-params (template uri)
  "Extract parameter values from a URI based on a template.

Returns an alist of (param-name . value) pairs.

Example:
  (extract-template-params 'swarm://agents/{id}' 'swarm://agents/agent-42')
    ;; → ((:ID . 'agent-42'))"
  (let ((template-parts (split-template template))
        (uri-parts (split-template uri))
        (params '()))
    (mapc (lambda (tp up)
            (when (starts-with "{" tp)
              (let ((param-name (intern (string-upcase
                                          (subseq tp 1 (1- (length tp))))
                                        :keyword)))
                (push (cons param-name up) params))))
          template-parts uri-parts)
    (nreverse params)))

(defun starts-with (prefix string)
  "Check if STRING starts with PREFIX."
  (and (>= (length string) (length prefix))
       (string-equal (subseq string 0 (length prefix)) prefix)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 5: Utility Functions
;; ═══════════════════════════════════════════════════════════════════════════

(defun mcp-log (level format-string &rest args)
  "Write a log message to *TRACE-OUTPUT* if LEVEL is at or above
*MCP-LOG-LEVEL*.

LEVEL is one of :DEBUG :INFO :WARN :ERROR, in increasing severity.

Example:
  (mcp-log :info "Server started on port ~A" 8082)"
  (when (>= (log-level-value level) (log-level-value *mcp-log-level*))
    (format *trace-output* "~&[MCP-~A] ~?~%"
            (string-upcase (symbol-name level))
            format-string args)))

(defun log-level-value (level)
  "Convert a log level keyword to a numeric value for comparison."
  (case level
    (:debug 0)
    (:info 1)
    (:warn 2)
    (:error 3)
    (otherwise 1)))

(defun json-to-lisp (json-string)
  "Parse a JSON string into a Lisp object.

Uses cl-json when available, otherwise signals an error (the minimal
encoder in telemetry.lisp only handles encoding, not parsing).

Arguments:
  JSON-STRING — A string containing valid JSON.

Returns: A Lisp object (alist, plist, string, number, etc.)."
  #+cl-json-available
  (handler-case
      (cl-json:decode-json-from-string json-string)
    (error (e)
      (mcp-log :error "JSON parse error: ~A" e)
      (error "JSON parse error: ~A" e)))
  #-cl-json-available
  (error "JSON parsing requires cl-json. Please install it."))

(defun lisp-to-json (lisp-object)
  "Encode a Lisp object to a JSON string.

Arguments:
  LISP-OBJECT — A Lisp object to encode.

Returns: A JSON string."
  #+cl-json-available
  (handler-case
      (cl-json:encode-json-to-string lisp-object)
    (error (e)
      (mcp-log :warn "cl-json encode failed (~A), using fallback" e)
      (minimal-json-encode lisp-object)))
  #-cl-json-available
  (minimal-json-encode lisp-object))

(defun make-json-rpc-response (id result)
  "Construct a JSON-RPC 2.0 success response object.

Arguments:
  ID     — The request ID (string, number, or null)
  RESULT — The result payload (any Lisp object)

Returns: An alist suitable for JSON encoding.

Reference: JSON-RPC 2.0 Spec §4.1 — Response Object"
  (list (cons :jsonrpc "2.0")
        (cons :id id)
        (cons :result result)))

(defun make-json-rpc-error (id code message &optional data)
  "Construct a JSON-RPC 2.0 error response object.

Arguments:
  ID      — The request ID (string, number, or null)
  CODE    — Integer error code (see *MCP-ERROR-CODES*)
  MESSAGE — Human-readable error description
  DATA    — Optional additional error data

Returns: An alist suitable for JSON encoding.

Standard error codes:
  -32700 — Parse error
  -32600 — Invalid Request
  -32601 — Method not found
  -32602 — Invalid params
  -32603 — Internal error

Reference: JSON-RPC 2.0 Spec §5.1 — Error Object"
  (let ((error-obj (list (cons :code code)
                         (cons :message message))))
    (when data
      (push (cons :data data) error-obj))
    (list (cons :jsonrpc "2.0")
          (cons :id id)
          (cons :error error-obj))))

(defun make-json-rpc-notification (method params)
  "Construct a JSON-RPC 2.0 notification object (no ID field).

Notifications are one-way messages that do not expect a response.
Used by the server to inform clients of events (e.g., capability changes).

Arguments:
  METHOD — The notification method name (string)
  PARAMS — Notification parameters (alist or plist)

Returns: An alist suitable for JSON encoding.

Reference: JSON-RPC 2.0 Spec §4.2 — Notification"
  (list (cons :jsonrpc "2.0")
        (cons :method method)
        (cons :params params)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 6: Core Request Handler — JSON-RPC Dispatch
;; ═══════════════════════════════════════════════════════════════════════════

(defun handle-mcp-request (request-alist)
  "Handle a single JSON-RPC 2.0 request and return a response alist.

This is the central dispatch function. It examines the :METHOD field
and routes to the appropriate handler. All MCP-specified methods are
supported, plus any registered tool names.

Arguments:
  REQUEST-ALIST — Parsed JSON request as an alist with keys:
                  :JSONRPC, :METHOD, :PARAMS (optional), :ID (optional)

Returns: A response alist (for requests) or NIL (for notifications).

Supported methods:
  • initialize      — Server capability handshake
  • tools/list      — List all available tools
  • tools/call      — Call a tool by name
  • resources/list  — List all available resources
  • resources/read  — Read a resource by URI
  • notifications/cancelled — Cancel an in-flight request

Reference: MCP Spec §2.3 — Message Types, JSON-RPC 2.0 Spec §4"
  (let* ((method (cdr (assoc :method request-alist :test #'string-equal)))
         (params (cdr (assoc :params request-alist)))
         (id (cdr (assoc :id request-alist)))
         (jsonrpc (cdr (assoc :jsonrpc request-alist))))
    ;; Validate JSON-RPC version
    (unless (and jsonrpc (string-equal jsonrpc "2.0"))
      (return-from handle-mcp-request
        (make-json-rpc-error id -32600 "Invalid Request: jsonrpc must be '2.0'")))
    ;; Dispatch by method
    (handler-case
        (cond
          ;; ── Lifecycle ──
          ((string-equal method "initialize")
           (handle-initialize id params))
          ((string-equal method "notifications/initialized")
           ;; Client initialized notification — no response needed
           (mcp-log :info "Client initialized")
           nil)
          ((string-equal method "notifications/cancelled")
           (mcp-log :debug "Request cancelled: ~A" (cdr (assoc :request-id params)))
           nil)

          ;; ── Tool Methods ──
          ((string-equal method "tools/list")
           (handle-tools-list id))
          ((string-equal method "tools/call")
           (handle-tool-call id params))

          ;; ── Resource Methods ──
          ((string-equal method "resources/list")
           (handle-resources-list id))
          ((string-equal method "resources/read")
           (handle-resource-read id params))

          ;; ── Prompt Methods (stub — not yet implemented) ──
          ((string-equal method "prompts/list")
           (make-json-rpc-response id (list :prompts '())))
          ((string-equal method "prompts/get")
           (make-json-rpc-error id -32601 "Prompt not found"))

          ;; ── Unknown method ──
          (t
           (mcp-log :warn "Unknown method: ~A" method)
           (make-json-rpc-error id -32601
                                (format nil "Method not found: ~A" method))))
      (error (e)
        (mcp-log :error "Internal error handling ~A: ~A" method e)
        (make-json-rpc-error id -32603
                             "Internal error"
                             (format nil "~A" e))))))

(defun handle-initialize (id params)
  "Handle the MCP initialize method — the protocol handshake.

The client sends its protocol version and capabilities. We respond
with our server info and capabilities. This is the first exchange
in every MCP session.

Arguments:
  ID     — The request ID
  PARAMS — Client initialize params with :protocolVersion and :capabilities

Returns: JSON-RPC response with server capabilities.

Reference: MCP Spec §2.1 — Initialization"
  (let ((client-version (cdr (assoc :protocol-version params))))
    (mcp-log :info "Client initialize (protocol version: ~A)" client-version)
    ;; Store client capabilities for later reference
    (setf *mcp-client-capabilities* (cdr (assoc :capabilities params)))
    ;; Respond with server capabilities
    (make-json-rpc-response
     id
     (list :protocol-version "2024-11-05"
           :capabilities (list :tools (list :list-changed t)
                               :resources (list :list-changed t
                                               :subscribe t))
           :server-info *mcp-server-info*))))

(defun handle-tools-list (id)
  "Handle the tools/list method — return all registered tools.

Returns: JSON-RPC response with a :tools array containing all
registered MCP tools with their schemas.

Reference: MCP Spec §3.2.1 — Tool Discovery"
  (mcp-log :debug "tools/list requested")
  (make-json-rpc-response id (list :tools (list-mcp-tools))))

(defun handle-tool-call (id params)
  "Handle the tools/call method — execute a tool and return results.

Arguments:
  ID     — The request ID
  PARAMS — Alist with :name (tool name) and :arguments (argument alist)

Returns: JSON-RPC response with the tool's result content.

The result format follows MCP Spec §3.2.2:
  (:content ((:type "text" :text "result string")) :is-error nil)

Reference: MCP Spec §3.2.2 — Tool Invocation"
  (let* ((tool-name (cdr (assoc :name params)))
         (arguments (cdr (assoc :arguments params)))
         (tool (find-mcp-tool tool-name)))
    (unless tool
      (return-from handle-tool-call
        (make-json-rpc-error id -32602
                             (format nil "Tool not found: ~A" tool-name))))
    (mcp-log :info "Tool call: ~A(~A)" tool-name arguments)
    ;; Execute the tool handler with error isolation
    (handler-case
        (let ((result (funcall (mcp-tool-handler tool) arguments)))
          ;; Normalize result to MCP content format
          (let ((content (if (and (listp result)
                                  (assoc :content result))
                             result
                             (list :content
                                   (list (list :type "text"
                                               :text (format nil "~A" result)))))))
            (make-json-rpc-response id content)))
      (error (e)
        (mcp-log :error "Tool ~A failed: ~A" tool-name e)
        (make-json-rpc-response
         id
         (list :content
               (list (list :type "text"
                           :text (format nil "Tool error: ~A" e)))
               :is-error t))))))

(defun handle-resources-list (id)
  "Handle the resources/list method — return all registered resources.

Returns: JSON-RPC response with a :resources array.

Reference: MCP Spec §3.1.1 — Resource Discovery"
  (mcp-log :debug "resources/list requested")
  (make-json-rpc-response id (list :resources (list-mcp-resources))))

(defun handle-resource-read (id params)
  "Handle the resources/read method — read a resource by URI.

Arguments:
  ID     — The request ID
  PARAMS — Alist with :uri (the resource URI to read)

Returns: JSON-RPC response with resource contents.

The response format follows MCP Spec §3.1.2:
  (:contents ((:uri "..." :mime-type "..." :text "...")))

Reference: MCP Spec §3.1.2 — Resource Reading"
  (let ((uri (cdr (assoc :uri params))))
    (unless uri
      (return-from handle-resource-read
        (make-json-rpc-error id -32602 "Missing required parameter: uri")))
    (mcp-log :debug "resources/read: ~A" uri)
    (multiple-value-bind (resource template-params)
        (find-mcp-resource-by-uri uri)
      (unless resource
        (return-from handle-resource-read
          (make-json-rpc-error id -32602
                               (format nil "Resource not found: ~A" uri))))
      ;; Execute the resource handler
      (handler-case
          (let ((content (funcall (mcp-resource-handler resource) template-params)))
            (make-json-rpc-response
             id
             (list :contents
                   (list (list :uri uri
                               :mime-type (mcp-resource-mime-type resource)
                               :text (if (stringp content)
                                         content
                                         (lisp-to-json content)))))))
        (error (e)
          (mcp-log :error "Resource read failed for ~A: ~A" uri e)
          (make-json-rpc-error id -32603
                               (format nil "Failed to read resource: ~A" e))))))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 7: stdio Transport — JSON-RPC over Standard Input/Output
;; ═══════════════════════════════════════════════════════════════════════════

(defun start-mcp-stdio-server ()
  "Start the MCP stdio server in a background thread.

The stdio transport reads newline-delimited JSON-RPC requests from
*STANDARD-INPUT* and writes JSON-RPC responses to *STANDARD-OUTPUT*.
This is the standard transport for local MCP clients like Claude Desktop.

This function spawns a new thread and returns immediately. The server
runs until STOP-MCP-BRIDGE is called or *MCP-SERVER-RUNNING-P* becomes NIL.

Returns: The server thread handle.

Example:
  (start-mcp-stdio-server)

Side effects:
  • Sets *MCP-SERVER-RUNNING-P* to T
  • Sets *MCP-SERVER-THREAD* to the new thread

Reference: MCP Spec §2.2 — stdio Transport"
  (setf *mcp-server-running-p* t)
  (let ((thread (bt:make-thread
                 #'mcp-stdio-loop
                 :name "mcp-stdio-server"
                 :initial-bindings '())))
    (setf *mcp-server-thread* thread)
    (mcp-log :info "MCP stdio server started (thread: ~A)"
             (bt:thread-name thread))
    thread))

(defun mcp-stdio-loop ()
  "The main stdio server loop — reads JSON-RPC, dispatches, writes responses.

Runs indefinitely until *MCP-SERVER-RUNNING-P* becomes NIL. Each iteration:
  1. Reads a line from *STANDARD-INPUT*
  2. Parses it as JSON
  3. Dispatches via HANDLE-MCP-REQUEST
  4. Writes the JSON response to *STANDARD-OUTPUT*
  5. Flushes the output stream

Error isolation: Parse errors and dispatch errors are caught and returned
as JSON-RPC error responses. The loop never dies.

Buffer handling: Lines longer than 1MB are rejected with a parse error
to prevent memory exhaustion attacks."
  (mcp-log :info "MCP stdio loop running")
  (loop while *mcp-server-running-p*
        do (handler-case
               (progn
                 ;; Read a line from stdin
                 (let ((line (read-line *standard-input* nil nil)))
                   (cond
                     ((null line)
                      ;; EOF reached — exit
                      (mcp-log :info "EOF on stdin, exiting stdio loop")
                      (return-from mcp-stdio-loop))
                     ((string= line "")
                      ;; Empty line — skip
                      nil)
                     ((> (length line) 1000000)
                      ;; Line too long — reject
                      (write-mcp-stdio-line
                       (lisp-to-json
                        (make-json-rpc-error nil -32700 "Parse error: line too long"))))
                     (t
                      ;; Parse and dispatch
                      (let* ((request (json-to-lisp line))
                             (response (handle-mcp-request request)))
                        (when response
                          (write-mcp-stdio-line
                           (lisp-to-json response))))))))
             (end-of-file ()
               (mcp-log :info "EOF on stdin")
               (return-from mcp-stdio-loop))
             (error (e)
               ;; Unhandled error — log and continue
               (mcp-log :error "stdio loop error: ~A" e)
               (write-mcp-stdio-line
                (lisp-to-json
                 (make-json-rpc-error nil -32603
                                      "Internal error in stdio loop"
                                      (format nil "~A" e)))))))
  (mcp-log :info "MCP stdio loop exited"))

(defun write-mcp-stdio-line (json-string)
  "Write a JSON-RPC response line to *STANDARD-OUTPUT* and flush.

Ensures that responses are immediately visible to the client without
buffering delays. This is critical for real-time MCP communication."
  (write-line json-string *standard-output*)
  (force-output *standard-output*))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 8: SSE Transport — JSON-RPC over Server-Sent Events
;; ═══════════════════════════════════════════════════════════════════════════

(defun start-mcp-sse-server (&optional (port 8082))
  "Start the MCP SSE server on the specified port.

The SSE transport provides JSON-RPC access via Server-Sent Events over
HTTP. This enables remote clients (browsers, other services) to connect
to the LISPMIND MCP server.

Requires Hunchentoot (available via Quicklisp). If Hunchentoot is not
installed, this function signals a warning and returns NIL.

Arguments:
  PORT — TCP port to listen on (default 8082)

Returns: The acceptor instance, or NIL if Hunchentoot is unavailable.

Example:
  (start-mcp-sse-server 8082)  ; → #<EASY-ACCEPTOR ...>

Side effects:
  • Sets *MCP-SSE-PORT* to PORT
  • Sets *MCP-SSE-ACCEPTOR* to the Hunchentoot acceptor

Reference: MCP Spec §2.4 — HTTP with SSE Transport"
  #+hunchentoot-available
  (progn
    (setf *mcp-sse-port* port)
    (setf *mcp-server-running-p* t)
    ;; Define the MCP endpoint
    (eval `(hunchentoot:define-easy-handler (mcp-sse :uri "/mcp") ()
             (mcp-sse-handler)))
    (eval `(hunchentoot:define-easy-handler (mcp-post :uri "/mcp/message") ()
             (mcp-post-handler)))
    ;; Start the server
    (let ((acceptor (make-instance 'hunchentoot:easy-acceptor
                                   :port port
                                   :document-root nil
                                   :access-log-destination nil)))
      (hunchentoot:start acceptor)
      (setf *mcp-sse-acceptor* acceptor)
      (mcp-log :info "MCP SSE server started on port ~A" port)
      acceptor))
  #-hunchentoot-available
  (progn
    (warn "[MCP] Hunchentoot not available. SSE transport disabled. Install via: (ql:quickload :hunchentoot)")
    nil))

(defun mcp-sse-handler ()
  "Handle an SSE connection request.

Sets up the HTTP response headers for SSE and begins streaming
JSON-RPC messages as 'data: <json>\\n\\n' formatted events.

This runs inside a Hunchentoot handler thread. It streams until
the client disconnects or *MCP-SERVER-RUNNING-P* becomes NIL.

Returns: The HTTP response body (empty, as events are streamed)."
  #+hunchentoot-available
  (progn
    (setf (hunchentoot:content-type*) "text/event-stream")
    (setf (hunchentoot:header-out "Cache-Control") "no-cache")
    (setf (hunchentoot:header-out "Connection") "keep-alive")
    (let ((stream (hunchentoot:send-headers)))
      ;; Send initial endpoint event
      (format stream "event: endpoint\ndata: /mcp/message\n\n")
      (force-output stream)
      ;; Stream until disconnect or shutdown
      (loop while (and *mcp-server-running-p*
                       (open-stream-p stream))
            do (progn
                 (sleep 1)
                 ;; Send heartbeat to keep connection alive
                 (handler-case
                     (progn
                       (format stream "event: heartbeat\ndata: {}\n\n")
                       (force-output stream))
                   (error ()
                     ;; Client disconnected
                     (return-from mcp-sse-handler "")))))
      ""))
  #-hunchentoot-available
  "SSE transport not available")

(defun mcp-post-handler ()
  "Handle a POST request containing a JSON-RPC message.

Reads the request body, parses it as JSON-RPC, dispatches via
HANDLE-MCP-REQUEST, and returns the JSON response.

Returns: JSON string response with Content-Type: application/json."
  #+hunchentoot-available
  (handler-case
      (let* ((raw-body (hunchentoot:raw-post-data :force-text t))
             (request (json-to-lisp raw-body))
             (response (handle-mcp-request request)))
        (setf (hunchentoot:content-type*) "application/json")
        (if response
            (lisp-to-json response)
            "{}"))
    (error (e)
      (setf (hunchentoot:content-type*) "application/json")
      (setf (hunchentoot:return-code*) 500)
      (lisp-to-json (make-json-rpc-error nil -32603
                                         "Internal server error"
                                         (format nil "~A" e)))))
  #-hunchentoot-available
  "{\"error\":\"SSE transport not available\"}")

(defun open-stream-p (stream)
  "Check if a stream is still open and writable.

Best-effort check using STREAM-ERROR handling."
  (handler-case
      (progn (write-char #\null stream) t)
    (stream-error () nil)
    (error () nil)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 9: Swarm Tool Exposure — LISPMIND → MCP Tools
;; ═══════════════════════════════════════════════════════════════════════════

(defun expose-swarm-tools ()
  "Register all LISPMIND capabilities as MCP tools.

This is the main integration point. It exposes the following tools:

  list-agents      — Return all registered agents
  inspect-agent    — Get detailed info about a specific agent
  heal-agent       — Apply a restart to heal an agent
  hotpatch-agent   — Replace an agent's strategy at runtime
  spawn-tool       — Create a new tool dynamically
  list-tools       — List all active MCP tools
  kill-tool        — Remove an MCP tool
  checkpoint-system — Save orchestrator state to disk
  start-dashboard  — Launch the ASCII dashboard
  get-telemetry    — Get the latest telemetry snapshot
  trigger-halt     — Emergency stop all agents

Each tool has a JSON Schema parameter definition and a handler function
that calls the corresponding LISPMIND function.

Returns: A list of the registered tool name symbols.

Example:
  (expose-swarm-tools)
    ;; → (LIST-AGENTS INSPECT-AGENT HEAL-AGENT ...)

Side effects: Populates *MCP-TOOLS* with tool definitions."
  (let ((registered '()))
    ;; ── Tool: list-agents ──
    (push (mcp-tool-name
           (register-mcp-tool
            'list-agents
            "List all agents registered in the LISPMIND orchestrator. Returns each agent's ID, health, status, version, error count, and capabilities."
            '(:type "object"
              :properties ())
            (lambda (args)
              (declare (ignore args))
              (if (and (boundp '*default-orchestrator*) *default-orchestrator*)
                  (let ((agents (build-agent-summaries *default-orchestrator*)))
                    (list :content
                          (list (list :type "text"
                                      :text (format nil "Registered agents (~A):~%~{~S~^~%~}"
                                                    (length agents)
                                                    agents)))))
                  (list :content
                        (list (list :type "text"
                                    :text "No orchestrator is currently running. Start one with (mind:start-orchestrator)."))))))))
          registered)

    ;; ── Tool: inspect-agent ──
    (push (mcp-tool-name
           (register-mcp-tool
            'inspect-agent
            "Get detailed information about a specific agent including its full state, strategy, health history, and mailbox contents."
            '(:type "object"
              :properties (:agent-id (:type "string"
                                      :description "The unique identifier of the agent to inspect"))
              :required ("agent-id"))
            (lambda (args)
              (let* ((agent-id-str (cdr (assoc :agent-id args :test #'string-equal)))
                     (agent-id (when agent-id-str
                                 (intern (string-upcase agent-id-str) :keyword))))
                (if (and agent-id
                         (boundp '*default-orchestrator*)
                         *default-orchestrator*)
                    (handler-case
                        (let ((report (inspect-agent *default-orchestrator* agent-id)))
                          (list :content
                                (list (list :type "text"
                                            :text (format nil "~A" report)))))
                      (error (e)
                        (list :content
                              (list (list :type "text"
                                          :text (format nil "Error inspecting agent ~A: ~A" agent-id e)))
                              :is-error t)))
                    (list :content
                          (list (list :type "text"
                                      :text "Invalid agent ID or no orchestrator running."))
                          :is-error t))))))
          registered)

    ;; ── Tool: heal-agent ──
    (push (mcp-tool-name
           (register-mcp-tool
            'heal-agent
            "Apply a healing restart to an agent. Available restarts: :retry, :use-fallback, :escalate, :replace-agent, :hotfix-and-continue, :pause-and-self-modify."
            '(:type "object"
              :properties (:agent-id (:type "string" :description "Agent to heal")
                          :restart (:type "string"
                                    :description "Restart name"
                                    :enum ["retry" "fallback" "escalate"
                                           "replace-agent" "hotfix-and-continue"
                                           "pause-and-self-modify"]))
              :required ("agent-id" "restart"))
            (lambda (args)
              (let* ((agent-id-str (cdr (assoc :agent-id args :test #'string-equal)))
                     (restart-str (cdr (assoc :restart args :test #'string-equal)))
                     (agent-id (when agent-id-str
                                 (intern (string-upcase agent-id-str) :keyword)))
                     (restart (when restart-str
                                (intern (string-upcase (substitute #\- #\_ restart-str))
                                        :keyword))))
                (if (and agent-id restart
                         (boundp '*default-orchestrator*)
                         *default-orchestrator*)
                    (handler-case
                        (progn
                          (heal-agent *default-orchestrator* agent-id restart)
                          (list :content
                                (list (list :type "text"
                                            :text (format nil "Healed agent ~A with restart ~A"
                                                          agent-id restart)))))
                      (error (e)
                        (list :content
                              (list (list :type "text"
                                          :text (format nil "Error healing agent ~A: ~A"
                                                        agent-id e)))
                              :is-error t)))
                    (list :content
                          (list (list :type "text"
                                      :text "Invalid parameters or no orchestrator running."))
                          :is-error t))))))
          registered)

    ;; ── Tool: hotpatch-agent ──
    (push (mcp-tool-name
           (register-mcp-tool
            'hotpatch-agent
            "Replace an agent's strategy function at runtime with zero downtime. The new strategy must be a valid Lisp function name."
            '(:type "object"
              :properties (:agent-id (:type "string" :description "Agent to patch")
                          :strategy (:type "string"
                                     :description "Name of the new strategy function"))
              :required ("agent-id" "strategy"))
            (lambda (args)
              (let* ((agent-id-str (cdr (assoc :agent-id args :test #'string-equal)))
                     (strategy-str (cdr (assoc :strategy args :test #'string-equal)))
                     (agent-id (when agent-id-str
                                 (intern (string-upcase agent-id-str) :keyword)))
                     (strategy-sym (when strategy-str
                                     (find-symbol (string-upcase strategy-str)))))
                (if (and agent-id strategy-sym (fboundp strategy-sym)
                         (boundp '*default-orchestrator*)
                         *default-orchestrator*)
                    (handler-case
                        (progn
                          (hotpatch-agent *default-orchestrator* agent-id strategy-sym)
                          (list :content
                                (list (list :type "text"
                                            :text (format nil "Hot-patched agent ~A with strategy ~A"
                                                          agent-id strategy-sym)))))
                      (error (e)
                        (list :content
                              (list (list :type "text"
                                          :text (format nil "Error hot-patching agent ~A: ~A"
                                                        agent-id e)))
                              :is-error t)))
                    (list :content
                          (list (list :type "text"
                                      :text "Invalid parameters: check agent ID exists and strategy function is defined."))
                          :is-error t))))))
          registered)

    ;; ── Tool: spawn-tool ──
    (push (mcp-tool-name
           (register-mcp-tool
            'spawn-tool
            "Dynamically register a new MCP tool at runtime. This creates a new tool that any MCP client can then discover and invoke."
            '(:type "object"
              :properties (:name (:type "string" :description "Tool name (will be uppercased)")
                          :description (:type "string" :description "Tool description")
                          :lisp-form (:type "string"
                                      :description "Lisp lambda form string, e.g., '(lambda (args) ...)'"))
              :required ("name" "description" "lisp-form"))
            (lambda (args)
              (let* ((name-str (cdr (assoc :name args :test #'string-equal)))
                     (description (cdr (assoc :description args :test #'string-equal)))
                     (lisp-form-str (cdr (assoc :lisp-form args :test #'string-equal)))
                     (name-sym (when name-str
                                 (intern (string-upcase name-str) :lispmind))))
                (if (and name-sym description lisp-form-str)
                    (handler-case
                        (let ((handler (read-from-string lisp-form-str)))
                          (if (and (listp handler)
                                   (eq (car handler) 'lambda))
                              (progn
                                (register-mcp-tool name-sym description
                                                   '(:type "object" :properties ())
                                                   (eval handler))
                                (list :content
                                      (list (list :type "text"
                                                  :text (format nil "Tool '~A' registered successfully."
                                                                name-sym)))))
                              (list :content
                                    (list (list :type "text"
                                                :text "Invalid handler: must be a lambda form"))
                                    :is-error t)))
                      (error (e)
                        (list :content
                              (list (list :type "text"
                                          :text (format nil "Error spawning tool: ~A" e)))
                              :is-error t)))
                    (list :content
                          (list (list :type "text"
                                      :text "Missing required parameters: name, description, lisp-form"))
                          :is-error t))))))
          registered)

    ;; ── Tool: list-tools ──
    (push (mcp-tool-name
           (register-mcp-tool
            'list-tools
            "List all currently registered MCP tools, including dynamically spawned ones."
            '(:type "object" :properties ())
            (lambda (args)
              (declare (ignore args))
              (let ((tools (list-mcp-tools)))
                (list :content
                      (list (list :type "text"
                                  :text (format nil "MCP Tools (~A registered):~%~{• ~A~^~%~}"
                                                (length tools)
                                                (mapcar (lambda (t)
                                                          (getf t :name))
                                                        tools)))))))))
          registered)

    ;; ── Tool: kill-tool ──
    (push (mcp-tool-name
           (register-mcp-tool
            'kill-tool
            "Remove an MCP tool from the registry. Use with caution — this affects all connected clients."
            '(:type "object"
              :properties (:name (:type "string" :description "Name of the tool to remove"))
              :required ("name"))
            (lambda (args)
              (let* ((name-str (cdr (assoc :name args :test #'string-equal)))
                     (name-sym (when name-str
                                 (intern (string-upcase name-str) :lispmind))))
                (if (and name-sym (find-mcp-tool name-sym))
                    (progn
                      (unregister-mcp-tool name-sym)
                      (list :content
                            (list (list :type "text"
                                        :text (format nil "Tool '~A' has been unregistered."
                                                      name-sym)))))
                    (list :content
                          (list (list :type "text"
                                      :text (format nil "Tool '~A' not found." name-str)))
                          :is-error t))))))
          registered)

    ;; ── Tool: checkpoint-system ──
    (push (mcp-tool-name
           (register-mcp-tool
            'checkpoint-system
            "Save the entire orchestrator state to disk for later restoration. Creates a timestamped checkpoint file."
            '(:type "object" :properties ())
            (lambda (args)
              (declare (ignore args))
              (if (and (boundp '*default-orchestrator*) *default-orchestrator*)
                  (handler-case
                      (let ((path (checkpoint-system *default-orchestrator*)))
                        (list :content
                              (list (list :type "text"
                                          :text (format nil "Checkpoint saved to: ~A" path)))))
                    (error (e)
                      (list :content
                            (list (list :type "text"
                                        :text (format nil "Checkpoint failed: ~A" e)))
                            :is-error t)))
                  (list :content
                        (list (list :type "text"
                                    :text "No orchestrator running. Start one first."))
                        :is-error t)))))
          registered)

    ;; ── Tool: start-dashboard ──
    (push (mcp-tool-name
           (register-mcp-tool
            'start-dashboard
            "Launch the ASCII dashboard in a background thread. Displays real-time agent health, status, and telemetry."
            '(:type "object" :properties ())
            (lambda (args)
              (declare (ignore args))
              (handler-case
                  (progn
                    (start-dashboard)
                    (list :content
                          (list (list :type "text"
                                      :text "Dashboard started. Check *TRACE-OUTPUT* for display."))))
                (error (e)
                  (list :content
                        (list (list :type "text"
                                    :text (format nil "Dashboard error: ~A" e)))
                        :is-error t))))))
          registered)

    ;; ── Tool: get-telemetry ──
    (push (mcp-tool-name
           (register-mcp-tool
            'get-telemetry
            "Get the latest telemetry snapshot including swarm health metrics, agent summaries, and safety statistics."
            '(:type "object"
              :properties (:format (:type "string"
                                    :description "Output format: 'json' or 'plist'"
                                    :enum ["json" "plist"]
                                    :default "json")))
            (lambda (args)
              (let ((format-type (or (cdr (assoc :format args :test #'string-equal))
                                     "json")))
                (if (and (boundp '*default-orchestrator*) *default-orchestrator*)
                    (handler-case
                        (let* ((snapshot (build-telemetry-snapshot *default-orchestrator*))
                               (text (if (string-equal format-type "json")
                                         (snapshot-to-json snapshot)
                                         (format nil "~S" snapshot))))
                          (list :content
                                (list (list :type "text" :text text))))
                      (error (e)
                        (list :content
                              (list (list :type "text"
                                          :text (format nil "Telemetry error: ~A" e)))
                              :is-error t)))
                    (list :content
                          (list (list :type "text"
                                      :text "No orchestrator running."))
                          :is-error t))))))
          registered)

    ;; ── Tool: trigger-halt ──
    (push (mcp-tool-name
           (register-mcp-tool
            'trigger-halt
            "Trigger an emergency halt of the orchestrator. This stops all monitoring and agent supervision immediately. Use with extreme caution."
            '(:type "object"
              :properties (:reason (:type "string"
                                    :description "Reason for the emergency halt"
                                    :default "Emergency stop triggered via MCP")))
            (lambda (args)
              (let ((reason (or (cdr (assoc :reason args :test #'string-equal))
                                "Emergency stop triggered via MCP")))
                (if (and (boundp '*default-orchestrator*) *default-orchestrator*)
                    (handler-case
                        (progn
                          (stop-orchestrator *default-orchestrator*)
                          (mcp-log :warn "Emergency halt: ~A" reason)
                          (list :content
                                (list (list :type "text"
                                            :text (format nil "EMERGENCY HALT triggered: ~A~%Orchestrator stopped."
                                                          reason)))))
                      (error (e)
                        (list :content
                              (list (list :type "text"
                                          :text (format nil "Halt error: ~A" e)))
                              :is-error t)))
                    (list :content
                          (list (list :type "text"
                                      :text "No orchestrator running."))))))))
          registered)

    ;; ── Tool: get-mcp-capabilities ──
    (push (mcp-tool-name
           (register-mcp-tool
            'get-mcp-capabilities
            "Return the full MCP capability list including all registered tools, resources, and their schemas. This is the self-describing capability endpoint."
            '(:type "object" :properties ())
            (lambda (args)
              (declare (ignore args))
              (let ((caps (get-mcp-capabilities)))
                (list :content
                      (list (list :type "text"
                                  :text (snapshot-to-json caps))))))))
          registered)

    (mcp-log :info "Exposed ~A swarm tools as MCP tools" (length registered))
    (nreverse registered)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 10: Swarm Resource Exposure — LISPMIND → MCP Resources
;; ═══════════════════════════════════════════════════════════════════════════

(defun expose-swarm-resources ()
  "Register swarm state as MCP resources accessible via URI templates.

Exposes the following resources:
  swarm://agents           — List of all registered agents
  swarm://agents/{id}      — Specific agent details
  swarm://health           — Swarm health metrics
  swarm://telemetry/latest — Latest telemetry snapshot
  swarm://telemetry/history — Telemetry history
  swarm://evolution/{agent-id} — Evolution history for an agent
  swarm://policies         — All active policies
  swarm://logs             — Recent log entries

Returns: A list of the registered resource name symbols.

Example:
  (expose-swarm-resources)
    ;; → (AGENT-LIST AGENT-DETAIL SWARM-HEALTH ...)

Reference: MCP Spec §3.1 — Resources"
  (let ((registered '()))
    ;; ── Resource: swarm://agents ──
    (push (mcp-resource-name
           (register-mcp-resource
            'agent-list
            "List of all agents registered in the LISPMIND orchestrator"
            "swarm://agents"
            (lambda (params)
              (declare (ignore params))
              (if (and (boundp '*default-orchestrator*) *default-orchestrator*)
                  (lisp-to-json (build-agent-summaries *default-orchestrator*))
                  (lisp-to-json (list :error "No orchestrator running"))))))
          registered)

    ;; ── Resource: swarm://agents/{id} ──
    (push (mcp-resource-name
           (register-mcp-resource
            'agent-detail
            "Detailed information about a specific agent"
            "swarm://agents/{id}"
            (lambda (params)
              (let ((agent-id-str (cdr (assoc :id params))))
                (if (and agent-id-str
                         (boundp '*default-orchestrator*)
                         *default-orchestrator*)
                    (let ((agent-id (intern (string-upcase agent-id-str) :keyword)))
                      (handler-case
                          (let ((agent (bt:with-lock-held
                                           ((orchestrator-monitor-lock
                                             *default-orchestrator*))
                                         (gethash agent-id
                                                  (orchestrator-agents
                                                   *default-orchestrator*)))))
                            (if agent
                                (lisp-to-json
                                 (list :id (string (agent-id agent))
                                       :health (agent-health agent)
                                       :status (agent-status agent)
                                       :version (agent-version agent)
                                       :errors (agent-error-count agent)
                                       :capabilities (agent-capabilities agent)
                                       :heartbeat (agent-heartbeat agent)))
                                (lisp-to-json (list :error "Agent not found"
                                                    :id agent-id-str))))
                        (error (e)
                          (lisp-to-json (list :error (format nil "~A" e))))))
                    (lisp-to-json (list :error "No orchestrator running")))))))
          registered)

    ;; ── Resource: swarm://health ──
    (push (mcp-resource-name
           (register-mcp-resource
            'swarm-health
            "Swarm health metrics including success rate, rejection rate, and containment score"
            "swarm://health"
            (lambda (params)
              (declare (ignore params))
              (if (and (boundp '*default-orchestrator*) *default-orchestrator*)
                  (lisp-to-json
                   (list :success-rate (calculate-success-rate *default-orchestrator*)
                         :rejection-rate (calculate-rejection-rate *default-orchestrator*)
                         :containment-score (calculate-containment-score *default-orchestrator*)
                         :timestamp (/ (get-internal-real-time)
                                       internal-time-units-per-second)))
                  (lisp-to-json (list :error "No orchestrator running"))))))
          registered)

    ;; ── Resource: swarm://telemetry/latest ──
    (push (mcp-resource-name
           (register-mcp-resource
            'telemetry-latest
            "Latest telemetry snapshot of the entire swarm"
            "swarm://telemetry/latest"
            (lambda (params)
              (declare (ignore params))
              (if (and (boundp '*default-orchestrator*) *default-orchestrator*)
                  (snapshot-to-json (build-telemetry-snapshot *default-orchestrator*))
                  (lisp-to-json (list :error "No orchestrator running"))))))
          registered)

    ;; ── Resource: swarm://telemetry/history ──
    (push (mcp-resource-name
           (register-mcp-resource
            'telemetry-history
            "Telemetry history (last 50 snapshots) for trend analysis"
            "swarm://telemetry/history"
            (lambda (params)
              (declare (ignore params))
              (bt:with-lock-held (*telemetry-history-lock*)
                (let ((history '()))
                  (loop for i from 0 below (length *telemetry-history*)
                        do (push (aref *telemetry-history* i) history))
                  (lisp-to-json (nreverse history)))))))
          registered)

    ;; ── Resource: swarm://evolution/{agent-id} ──
    (push (mcp-resource-name
           (register-mcp-resource
            'evolution-history
            "Genetic programming evolution history for a specific agent"
            "swarm://evolution/{agent-id}"
            (lambda (params)
              (let ((agent-id-str (cdr (assoc :agent-id params))))
                (if agent-id-str
                    (handler-case
                        (let* ((agent-id (intern (string-upcase agent-id-str) :keyword))
                               (history (evolution-history agent-id)))
                          (lisp-to-json (or history
                                            (list :note "No evolution history for this agent"
                                                  :agent-id agent-id-str))))
                      (error (e)
                        (lisp-to-json (list :error (format nil "~A" e)))))
                    (lisp-to-json (list :error "Missing agent-id parameter")))))))
          registered)

    ;; ── Resource: swarm://policies ──
    (push (mcp-resource-name
           (register-mcp-resource
            'active-policies
            "All active safety and restart policies in the swarm"
            "swarm://policies"
            (lambda (params)
              (declare (ignore params))
              (if (and (boundp '*default-orchestrator*) *default-orchestrator*)
                  (lisp-to-json
                   (list :restart-policies
                         (list :retry "Retry failed operation"
                               :use-fallback "Switch to safe fallback strategy"
                               :escalate "Delegate to orchestrator policy"
                               :replace-agent "Create fresh agent instance"
                               :hotfix-and-continue "Live-patch strategy"
                               :pause-and-self-modify "Pause for introspection")
                         :safety-kernel "Active — blocks unsafe mutations"
                         :auto-tuning *auto-tune-enabled-p*
                         :immortality (and (boundp '*watchdog-running-p*)
                                           *watchdog-running-p*)))
                  (lisp-to-json (list :error "No orchestrator running"))))))
          registered)

    ;; ── Resource: swarm://logs ──
    (push (mcp-resource-name
           (register-mcp-resource
            'recent-logs
            "Recent system log entries and notable events"
            "swarm://logs"
            (lambda (params)
              (declare (ignore params))
              (lisp-to-json
               (list :note "Log retrieval via MCP resources is best-effort"
                     :latest-event (or *telemetry-latest-event* "None")
                     :mcp-server-running *mcp-server-running-p*
                     :registered-tools (hash-table-count *mcp-tools*)
                     :registered-resources (hash-table-count *mcp-resources*))))))
          registered)

    (mcp-log :info "Exposed ~A swarm resources as MCP resources" (length registered))
    (nreverse registered)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 11: Dynamic Capability Discovery
;; ═══════════════════════════════════════════════════════════════════════════

(defun get-mcp-capabilities ()
  "Return the full capability list: tools + resources + server metadata.

This is the self-describing endpoint that gives a complete picture of
everything the MCP server can do. Useful for diagnostics, testing, and
for LLMs that need to understand the full API surface.

Returns: A plist with keys:
  :server-info     — Server identification (name, version, vendor)
  :tools           — List of all registered tools with schemas
  :resources       — List of all registered resources with URI templates
  :tool-count      — Number of registered tools
  :resource-count  — Number of registered resources
  :server-running  — Is the server currently active?
  :timestamp       — Unix timestamp of the capability snapshot

Example:
  (get-mcp-capabilities)
    ;; → (:server-info (:name 'lispmind-mcp' ...) :tools [...] :resources [...])"
  (list :server-info *mcp-server-info*
        :tools (list-mcp-tools)
        :resources (list-mcp-resources)
        :tool-count (hash-table-count *mcp-tools*)
        :resource-count (hash-table-count *mcp-resources*)
        :server-running *mcp-server-running-p*
        :timestamp (/ (get-internal-real-time)
                      internal-time-units-per-second)))

(defun refresh-mcp-capabilities ()
  "Re-scan the swarm state and update the capability list.

This function:
  1. Clears existing tool/resource registrations
  2. Re-registers all swarm tools via EXPOSE-SWARM-TOOLS
  3. Re-registers all swarm resources via EXPOSE-SWARM-RESOURCES
  4. Sends a notification to connected clients about the update

Call this after adding new agents, evolving strategies, or making any
change that affects the available capabilities.

Returns: The updated capability plist.

Side effects:
  • Clears and repopulates *MCP-TOOLS* and *MCP-RESOURCES*
  • Sends tools/list_changed notification (stdio)"
  (clrhash *mcp-tools*)
  (clrhash *mcp-resources*)
  (let ((tools (expose-swarm-tools))
        (resources (expose-swarm-resources)))
    ;; Notify clients of the update
    (when *mcp-server-running-p*
      (let ((notification (make-json-rpc-notification
                           "notifications/tools/list_changed" nil)))
        (write-mcp-stdio-line (lisp-to-json notification)))
      (let ((notification (make-json-rpc-notification
                           "notifications/resources/list_changed" nil)))
        (write-mcp-stdio-line (lisp-to-json notification))))
    (mcp-log :info "Refreshed capabilities: ~A tools, ~A resources"
             (length tools) (length resources))
    (get-mcp-capabilities)))

(defun on-agent-evolved (agent old-strategy new-strategy)
  "Hook called when an agent evolves its strategy via genetic programming.

This function dynamically registers the new strategy capability as an
MCP tool so that external clients can discover and invoke it. It also
logs the evolution event and refreshes the capability list.

Arguments:
  AGENT         — The agent that evolved
  OLD-STRATEGY  — The previous strategy (function or symbol)
  NEW-STRATEGY  — The new evolved strategy (function or symbol)

Returns: The newly registered tool name, or NIL if registration failed.

Side effects:
  • Registers a new MCP tool for the evolved strategy
  • Logs the evolution event
  • May refresh capabilities

Integration point: This function should be called by the evolution
module (evolution.lisp) after a successful strategy evolution."
  (let* ((agent-id (agent-id agent))
         (tool-name (intern (format nil "EVOLVED-STRATEGY-~A-~A"
                                    agent-id
                                    (agent-version agent))
                            :lispmind))
         (description (format nil "Auto-generated tool for evolved strategy of agent ~A (v~A). Formerly ~S."
                              agent-id (agent-version agent) old-strategy)))
    (mcp-log :info "Agent ~A evolved strategy ~S → ~S, registering as tool ~A"
             agent-id old-strategy new-strategy tool-name)
    ;; Register the evolved strategy as a callable tool
    (handler-case
        (progn
          (register-mcp-tool
           tool-name
           description
           '(:type "object"
             :properties (:input (:type "string" :description "Input data for the strategy")))
           (lambda (args)
             (let ((input (cdr (assoc :input args :test #'string-equal))))
               (handler-case
                   (let ((result (funcall new-strategy input)))
                     (list :content
                           (list (list :type "text"
                                       :text (format nil "Evolved strategy result: ~A" result)))))
                 (error (e)
                   (list :content
                         (list (list :type "text"
                                     :text (format nil "Strategy error: ~A" e)))
                         :is-error t))))))
          ;; Send capability changed notification
          (when *mcp-server-running-p*
            (let ((notification (make-json-rpc-notification
                                 "notifications/tools/list_changed" nil)))
              (write-mcp-stdio-line (lisp-to-json notification))))
          tool-name)
      (error (e)
        (mcp-log :error "Failed to register evolved strategy for ~A: ~A"
                 agent-id e)
        nil))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 12: Server Lifecycle — Start and Stop
;; ═══════════════════════════════════════════════════════════════════════════

(defun start-mcp-bridge (&key (stdio t) (sse nil) (port 8082))
  "Start the full MCP bridge server.

This is the main entry point. It initializes the tool and resource
registries, exposes all LISPMIND capabilities, and starts the requested
transport(s).

Arguments:
  STDIO — If T (default), start the stdio JSON-RPC transport.
  SSE   — If T, start the SSE HTTP transport on the given port.
  PORT  — TCP port for SSE transport (default 8082).

Returns: A plist describing the started transports.

Example:
  ;; Start stdio only (for Claude Desktop)
  (start-mcp-bridge)

  ;; Start both stdio and SSE
  (start-mcp-bridge :stdio t :sse t :port 8082)

  ;; Start SSE only (for remote access)
  (start-mcp-bridge :stdio nil :sse t :port 9090)

Side effects:
  • Clears and repopulates *MCP-TOOLS* and *MCP-RESOURCES*
  • Sets *MCP-SERVER-RUNNING-P* to T
  • May spawn up to 2 threads (stdio + SSE)

Reference: MCP Spec §2 — Transports"
  (mcp-log :info "Starting MCP bridge (stdio=~A, sse=~A, port=~A)" stdio sse port)
  ;; Reset state
  (setf *mcp-server-running-p* t)
  ;; Expose all capabilities
  (expose-swarm-tools)
  (expose-swarm-resources)
  ;; Start requested transports
  (let ((result (list :stdio nil :sse nil)))
    (when stdio
      (start-mcp-stdio-server)
      (setf (getf result :stdio) t))
    (when sse
      (let ((acceptor (start-mcp-sse-server port)))
        (setf (getf result :sse) (if acceptor t nil))))
    (mcp-log :info "MCP bridge started: ~A" result)
    result))

(defun stop-mcp-bridge ()
  "Stop the MCP bridge gracefully.

Stops all running transports and clears server state:
  1. Sets *MCP-SERVER-RUNNING-P* to NIL
  2. Stops the stdio thread (if running)
  3. Stops the SSE server (if running)
  4. Clears tool and resource registries

Returns: A plist describing what was stopped.

Example:
  (stop-mcp-bridge)
    ;; → (:stdio T :sse NIL :tools-cleared 11 :resources-cleared 8)

Side effects:
  • Sets *MCP-SERVER-RUNNING-P* to NIL
  • Joins the stdio server thread
  • Stops the Hunchentoot acceptor (SSE)
  • Clears *MCP-TOOLS* and *MCP-RESOURCES*"
  (mcp-log :info "Stopping MCP bridge...")
  (setf *mcp-server-running-p* nil)
  (let ((result (list :stdio nil :sse nil
                      :tools-cleared 0 :resources-cleared 0)))
    ;; Stop stdio thread
    (when *mcp-server-thread*
      (handler-case
          (bt:join-thread *mcp-server-thread* :timeout 5.0)
        (error (e)
          (mcp-log :warn "Stdio thread join error: ~A" e)))
      (setf *mcp-server-thread* nil)
      (setf (getf result :stdio) t))
    ;; Stop SSE server
    #+hunchentoot-available
    (when *mcp-sse-acceptor*
      (handler-case
          (hunchentoot:stop *mcp-sse-acceptor*)
        (error (e)
          (mcp-log :warn "SSE server stop error: ~A" e)))
      (setf *mcp-sse-acceptor* nil)
      (setf *mcp-sse-thread* nil)
      (setf (getf result :sse) t))
    ;; Clear registries
    (setf (getf result :tools-cleared) (hash-table-count *mcp-tools*))
    (setf (getf result :resources-cleared) (hash-table-count *mcp-resources*))
    (clrhash *mcp-tools*)
    (clrhash *mcp-resources*)
    (mcp-log :info "MCP bridge stopped: ~A" result)
    result))

(defun mcp-bridge-status ()
  "Return the current status of the MCP bridge as a plist.

Useful for health checks and diagnostics.

Returns:
  (:running      <boolean>
   :stdio-thread <boolean>
   :sse-active   <boolean>
   :tool-count   <integer>
   :resource-count <integer>
   :port         <integer or nil>)"
  (list :running *mcp-server-running-p*
        :stdio-thread (not (null *mcp-server-thread*))
        :sse-active (not (null *mcp-sse-acceptor*))
        :tool-count (hash-table-count *mcp-tools*)
        :resource-count (hash-table-count *mcp-resources*)
        :port *mcp-sse-port*))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 13: Built-in Diagnostic Tools
;; ═══════════════════════════════════════════════════════════════════════════

(defun register-diagnostic-tools ()
  "Register built-in diagnostic tools that are always available.

These tools provide meta-information about the MCP server itself and
the underlying LISPMIND system. They are independent of the orchestrator
state and can be called even when no orchestrator is running.

Tools registered:
  echo         — Connectivity test
  ping         — Latency measurement
  system-info  — SBCL and system information
  mcp-status   — Current MCP bridge status

Returns: List of registered tool name symbols."
  (let ((registered '()))
    ;; ── Tool: echo ──
    (push (mcp-tool-name
           (register-mcp-tool
            'echo
            "Echo the input back. Used for connectivity testing and verifying that the MCP bridge is responsive."
            '(:type "object"
              :properties (:message (:type "string" :description "Message to echo back"))
              :required ("message"))
            (lambda (args)
              (let ((message (cdr (assoc :message args :test #'string-equal))))
                (list :content
                      (list (list :type "text"
                                  :text (format nil "Echo: ~A" message))))))))
          registered)

    ;; ── Tool: ping ──
    (push (mcp-tool-name
           (register-mcp-tool
            'ping
            "Measure round-trip latency of the MCP bridge. Returns the current Lisp universal time."
            '(:type "object" :properties ())
            (lambda (args)
              (declare (ignore args))
              (list :content
                    (list (list :type "text"
                                :text (format nil "Pong! Universal time: ~A"
                                              (get-universal-time))))))))
          registered)

    ;; ── Tool: system-info ──
    (push (mcp-tool-name
           (register-mcp-tool
            'system-info
            "Return information about the SBCL runtime environment including version, features, and memory usage."
            '(:type "object" :properties ())
            (lambda (args)
              (declare (ignore args))
              (list :content
                    (list (list :type "text"
                                :text (format nil "SBCL ~A~%Features: ~S~%Mem: ~A bytes"
                                              (lisp-implementation-version)
                                              (subseq *features* 0 (min 20 (length *features*)))
                                              #+sbcl (sb-ext:get-bytes-consed)
                                              #-sbcl "N/A"))))))))
          registered)

    ;; ── Tool: mcp-status ──
    (push (mcp-tool-name
           (register-mcp-tool
            'mcp-status
            "Get the current MCP bridge status including running transports, registered tools, and resources."
            '(:type "object" :properties ())
            (lambda (args)
              (declare (ignore args))
              (list :content
                    (list (list :type "text"
                                :text (lisp-to-json (mcp-bridge-status))))))))
          registered)

    (mcp-log :debug "Registered ~A diagnostic tools" (length registered))
    (nreverse registered)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 13.5: MCP Wi-Fi Tools -- v2.2.1 Wi-Fi Capability Registration
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; "The Wi-Fi tools bridge extends the MCP surface into the wireless domain.
;;  Each registered tool represents a controlled capability -- recon, audit,
;;  stress test, monitor -- that an MCP client can discover and invoke.
;;  Every tool is guarded by the Gatekeeper. Every resource is live data
;;  from the Wi-Fi safety subsystem."
;;
;; TOOLS EXPOSED:
;;   wifi-recon    -- bettercap recon scan (discovery)
;;   wifi-audit    -- airgeddon WPA3 audit (analysis)
;;   wifi-stress   -- controlled stress test (destructive, needs confirmation)
;;   wifi-monitor  -- start tshark monitor mode capture (passive)
;;   wifi-pair     -- spawn Air-Monitor-Shadow-Pair (cooperative)
;;   wifi-halt     -- emergency halt all Wi-Fi tools (kill-switch)
;;
;; RESOURCES EXPOSED:
;;   swarm://wifi/aps         -- discovered access points
;;   swarm://wifi/handshakes  -- captured handshakes
;;   swarm://wifi/signals     -- signal strength readings
;;   swarm://wifi/stability   -- network stability status

(defun expose-wifi-mcp-tools () 
  "Register Wi-Fi tools as MCP capabilities.

This function exposes 6 Wi-Fi tools for MCP client discovery and invocation:
  wifi-recon    -- Discovery scan using bettercap. Lists nearby APs.
  wifi-audit    -- WPA3 security audit using airgeddon. Requires confirmation.
  wifi-stress   -- Controlled stress test. Requires explicit confirmation.
  wifi-monitor  -- Passive monitor mode capture using tshark.
  wifi-pair     -- Spawn cooperative Air-Monitor-Shadow-Pair agents.
  wifi-halt     -- Emergency halt: kill all Wi-Fi tools immediately.

Each tool has JSON Schema parameters and a handler function.
All destructive operations require confirmation via the Gatekeeper.
The wifi-halt tool is always available as the escape hatch.

Returns: A list of the registered tool name symbols.

Example:
  (expose-wifi-mcp-tools)
    ;; => (WIFI-RECON WIFI-AUDIT WIFI-STRESS WIFI-MONITOR WIFI-PAIR WIFI-HALT)"
  (let ((registered '()))
    ;; ── Tool: wifi-recon ──
    (push (mcp-tool-name
           (register-mcp-tool
            'wifi-recon
            "Perform Wi-Fi reconnaissance scan using bettercap. Discovers nearby access points, their BSSIDs, channels, encryption types, and signal strengths. Returns a list of discovered APs."
            '(:type "object"
              :properties (:interface (:type "string"
                                      :description "Wi-Fi interface (default: wlan1)"
                                      :default "wlan1")
                          :duration (:type "integer"
                                    :description "Scan duration in seconds (default: 30)"
                                    :default 30
                                    :minimum 5
                                    :maximum 300))
              :required ())
            (lambda (args)
              (let* ((iface (or (cdr (assoc :interface args :test #'string-equal))
                                "wlan1"))
                     (duration (or (cdr (assoc :duration args :test #'string-equal))
                                   30))
                     (result (handler-case
                                 (uiop:run-program
                                  (format nil "timeout ~D bettercap -iface ~A -eval 'wifi.recon on; sleep ~D; wifi.recon off; q' 2>&1"
                                          (+ duration 10) iface duration)
                                  :output '(:string :stripped t)
                                  :ignore-error-status t)
                               (error (e)
                                 (format nil "Wi-Fi recon error: ~A" e)))))
                (list :content
                      (list (list :type "text"
                                  :text (format nil "Wi-Fi Recon on ~A (~Ds):~%~A"
                                                iface duration result))))))))
          registered)

    ;; ── Tool: wifi-audit ──
    (push (mcp-tool-name
           (register-mcp-tool
            'wifi-audit
            "Perform WPA3 security audit using airgeddon. Analyzes target access point for known vulnerabilities, weak configurations, and downgrade attack vectors. Requires operator confirmation due to :critical risk level."
            '(:type "object"
              :properties (:bssid (:type "string"
                                  :description "Target BSSID (e.g., AA:BB:CC:DD:EE:FF)")
                          :channel (:type "integer"
                                   :description "Wi-Fi channel number (1-14 for 2.4GHz)")
                          :interface (:type "string"
                                     :description "Wi-Fi interface (default: wlan1)"
                                     :default "wlan1")
                          :wpa3 (:type "boolean"
                                :description "Enable WPA3-specific tests"
                                :default t))
              :required ("bssid" "channel"))
            (lambda (args)
              (let* ((bssid (cdr (assoc :bssid args :test #'string-equal)))
                     (channel (cdr (assoc :channel args :test #'string-equal)))
                     (iface (or (cdr (assoc :interface args :test #'string-equal))
                                "wlan1"))
                     (wpa3-p (or (cdr (assoc :wpa3 args :test #'string-equal)) t)))
                (if (and bssid channel)
                    (list :content
                          (list (list :type "text"
                                      :text (format nil "Wi-Fi Audit requested:~%  BSSID: ~A~%  Channel: ~A~%  Interface: ~A~%  WPA3: ~A~%~%This is a :critical risk operation. The Gatekeeper will require explicit confirmation before launching airgeddon."
                                                    bssid channel iface wpa3-p))))
                    (list :content
                          (list (list :type "text"
                                      :text "Missing required parameters: bssid and channel are required."))
                          :is-error t))))))
          registered)

    ;; ── Tool: wifi-stress ──
    (push (mcp-tool-name
           (register-mcp-tool
            'wifi-stress
            "Run controlled Wi-Fi stress test. Tests AP resilience under load with strict time limits and automatic safety cutoffs. DESTRUCTIVE: requires explicit operator confirmation. Automatically paused if signal drops below threshold or network becomes unstable."
            '(:type "object"
              :properties (:bssid (:type "string"
                                  :description "Target BSSID for stress test")
                          :interface (:type "string"
                                     :description "Wi-Fi interface (default: wlan1)"
                                     :default "wlan1")
                          :duration (:type "integer"
                                    :description "Test duration in seconds (max: 60)"
                                    :default 30
                                    :minimum 5
                                    :maximum 60)
                          : intensity (:type "string"
                                      :description "Test intensity: low, medium, high"
                                      :default "low"
                                      :enum ["low" "medium" "high"]))
              :required ("bssid"))
            (lambda (args)
              (let* ((bssid (cdr (assoc :bssid args :test #'string-equal)))
                     (iface (or (cdr (assoc :interface args :test #'string-equal))
                                "wlan1"))
                     (duration (min (or (cdr (assoc :duration args :test #'string-equal))
                                        30)
                                    60))
                     (intensity (or (cdr (assoc :intensity args :test #'string-equal))
                                    "low")))
                (if bssid
                    (list :content
                          (list (list :type "text"
                                      :text (format nil "Wi-Fi Stress Test requested:~%  BSSID: ~A~%  Interface: ~A~%  Duration: ~As~%  Intensity: ~A~%~%WARNING: This is a destructive operation. The Gatekeeper requires confirmation. The stability monitor will auto-halt if RTT exceeds ~Dms or signal drops below ~D dBm."
                                                    bssid iface duration intensity
                                                    *gateway-rtt-critical-ms*
                                                    *wifi-signal-threshold-dbm*))))
                    (list :content
                          (list (list :type "text"
                                      :text "Missing required parameter: bssid is required."))
                          :is-error t))))))
          registered)

    ;; ── Tool: wifi-monitor ──
    (push (mcp-tool-name
           (register-mcp-tool
            'wifi-monitor
            "Start passive Wi-Fi monitor mode capture using tshark. Captures 802.11 frames on specified interface without injecting traffic. Non-destructive. Auto-stops after duration."
            '(:type "object"
              :properties (:interface (:type "string"
                                      :description "Monitor interface (default: wlan1mon)"
                                      :default "wlan1mon")
                          :channel (:type "integer"
                                   :description "Channel to monitor (optional)")
                          :duration (:type "integer"
                                    :description "Capture duration in seconds (default: 60, max: 300)"
                                    :default 60
                                    :minimum 10
                                    :maximum 300)
                          :filter (:type "string"
                                  :description "Display filter (e.g., 'wlan.fc.type == 0')"
                                  :default ""))
              :required ())
            (lambda (args)
              (let* ((iface (or (cdr (assoc :interface args :test #'string-equal))
                                "wlan1mon"))
                     (channel (cdr (assoc :channel args :test #'string-equal)))
                     (duration (min (or (cdr (assoc :duration args :test #'string-equal))
                                        60)
                                    300))
                     (filter (or (cdr (assoc :filter args :test #'string-equal)) ""))
                     (chan-cmd (if channel
                                   (format nil "iw dev ~A set channel ~A 2>/dev/null; " iface channel)
                                   ""))
                     (result (handler-case
                                 (uiop:run-program
                                  (format nil "~Atimeout ~D tshark -i ~A -I -f 'type mgt' -a duration:~D ~A 2>&1 | head -200"
                                          chan-cmd duration iface duration
                                          (if (> (length filter) 0)
                                              (format nil "-Y '~A'" filter)
                                              ""))
                                  :output '(:string :stripped t)
                                  :ignore-error-status t)
                               (error (e)
                                 (format nil "Monitor error: ~A" e)))))
                (list :content
                      (list (list :type "text"
                                  :text (format nil "Wi-Fi Monitor on ~A (~As):~%~A"
                                                iface duration result))))))))
          registered)

    ;; ── Tool: wifi-pair ──
    (push (mcp-tool-name
           (register-mcp-tool
            'wifi-pair
            "Spawn a cooperative Air-Monitor-Shadow-Pair for coordinated Wi-Fi observation. Creates two agents: one monitoring the air, one analyzing. Used for persistent surveillance of a target area."
            '(:type "object"
              :properties (:area (:type "string"
                                :description "Target area name or BSSID prefix")
                          :channel (:type "integer"
                                   :description "Primary channel to monitor")
                          :duration (:type "integer"
                                    :description "Pair operation duration in seconds (default: 300, max: 1800)"
                                    :default 300
                                    :minimum 60
                                    :maximum 1800))
              :required ("area"))
            (lambda (args)
              (let* ((area (cdr (assoc :area args :test #'string-equal)))
                     (channel (cdr (assoc :channel args :test #'string-equal)))
                     (duration (min (or (cdr (assoc :duration args :test #'string-equal))
                                        300)
                                    1800)))
                (if area
                    (list :content
                          (list (list :type "text"
                                      :text (format nil "Air-Monitor-Shadow-Pair spawn requested:~%  Area: ~A~%  Channel: ~A~%  Duration: ~As~%~%The Gatekeeper will validate and spawn the pair if policies permit."
                                                    area (or channel "auto") duration))))
                    (list :content
                          (list (list :type "text"
                                      :text "Missing required parameter: area is required."))
                          :is-error t))))))
          registered)

    ;; ── Tool: wifi-halt ──
    (push (mcp-tool-name
           (register-mcp-tool
            'wifi-halt
            "Emergency halt all Wi-Fi tools immediately. Kills bettercap, airgeddon, aircrack-ng, airodump-ng, and all related processes. This is the Wi-Fi kill-switch -- use when stability is critical or operations have gone wrong."
            '(:type "object"
              :properties (:reason (:type "string"
                                    :description "Reason for emergency halt"
                                    :default "Emergency Wi-Fi halt via MCP"))
              :required ())
            (lambda (args)
              (let ((reason (or (cdr (assoc :reason args :test #'string-equal))
                                "Emergency Wi-Fi halt via MCP")))
                (handler-case
                    (let ((result (wifi-emergency-halt)))
                      (mcp-log :warn "Wi-Fi halt: ~A" reason)
                      (list :content
                            (list (list :type "text"
                                        :text (format nil "WI-FI EMERGENCY HALT~%Reason: ~A~%Processes killed: ~D~%PIDs: ~{~A~^, ~}"
                                                      reason
                                                      (getf result :killed-count)
                                                      (getf result :pids))))))
                  (error (e)
                    (list :content
                          (list (list :type "text"
                                      :text (format nil "Wi-Fi halt error: ~A" e)))
                          :is-error t))))))
          registered)

    (mcp-log :info "Exposed ~A Wi-Fi tools as MCP tools" (length registered))
    (nreverse registered)))

(defun expose-wifi-mcp-resources () 
  "Register Wi-Fi resources as MCP capabilities accessible via URI templates.

Exposes the following resources:
  swarm://wifi/aps         -- Discovered access points from recon
  swarm://wifi/handshakes  -- Captured handshakes and PMKIDs
  swarm://wifi/signals     -- Signal strength readings
  swarm://wifi/stability   -- Network stability status (RTT, safe mode)

Each resource handler returns JSON content suitable for MCP clients.
The stability resource includes the full Wi-Fi safety subsystem state.

Returns: A list of the registered resource name symbols.

Example:
  (expose-wifi-mcp-resources)
    ;; => (WIFI-APS WIFI-HANDSHAKES WIFI-SIGNALS WIFI-STABILITY)"
  (let ((registered '()))
    ;; ── Resource: swarm://wifi/aps ──
    (push (mcp-resource-name
           (register-mcp-resource
            'wifi-aps
            "Discovered Wi-Fi access points from reconnaissance scans"
            "swarm://wifi/aps"
            (lambda (params)
              (declare (ignore params))
              (lisp-to-json
               (list :note "Access AP discovery data via wifi-recon tool"
                     :last-recon nil
                     :aps-discovered 0
                     :timestamp (local-time:now))))))
          registered)

    ;; ── Resource: swarm://wifi/handshakes ──
    (push (mcp-resource-name
           (register-mcp-resource
            'wifi-handshakes
            "Captured Wi-Fi handshakes, PMKIDs, and authentication frames"
            "swarm://wifi/handshakes"
            (lambda (params)
              (declare (ignore params))
              (lisp-to-json
               (list :note "Handshake captures from wifi-audit operations"
                     :captures '()
                     :pmkid-count 0
                     :handshake-count 0
                     :timestamp (local-time:now))))))
          registered)

    ;; ── Resource: swarm://wifi/signals ──
    (push (mcp-resource-name
           (register-mcp-resource
            'wifi-signals
            "Wi-Fi signal strength readings and threshold status"
            "swarm://wifi/signals"
            (lambda (params)
              (declare (ignore params))
              (lisp-to-json
               (list :signal-threshold-dbm *wifi-signal-threshold-dbm*
                     :threshold-active t
                     :last-measurement nil
                     :status "Signal monitoring active"
                     :timestamp (local-time:now))))))
          registered)

    ;; ── Resource: swarm://wifi/stability ──
    (push (mcp-resource-name
           (register-mcp-resource
            'wifi-stability
            "Network stability status including RTT measurements, consecutive high readings, safe mode state, and Wi-Fi agent count"
            "swarm://wifi/stability"
            (lambda (params)
              (declare (ignore params))
              (lisp-to-json (wifi-gatekeeper-status)))))
          registered)

    (mcp-log :info "Registered ~A Wi-Fi MCP resources" (length registered))
    (nreverse registered)))


;; ═══════════════════════════════════════════════════════════════════════════
;; END OF MCP WIFI TOOLS v2.2.1
;; ═══════════════════════════════════════════════════════════════════════════


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 14: Auto-Initialization
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; When this file is loaded, register the diagnostic tools immediately.
;; Swarm tools and resources are registered when START-MCP-BRIDGE is called.

(register-diagnostic-tools)

(mcp-log :info "MCP-BRIDGE module loaded. ~A diagnostic tools available. Call (mind:start-mcp-bridge) to start the server."
         (hash-table-count *mcp-tools*))


;; ═══════════════════════════════════════════════════════════════════════════
;; MCP OFFENSIVE TOOL REGISTRATION — v2.3.1
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This section exposes the offensive safety framework as MCP tools and
;; resources. MCP clients (Claude Desktop, Cursor, etc.) can discover
;; and invoke ARM/DISARM commands, spawn offensive tools, and query
;; policy status through the standard MCP protocol.
;;
;; SECURITY NOTE: These tools are POWERFUL. The MCP server validates
;; MCP-client requests against the same categorical gatekeeper that
;; internal agents use. There is no special backdoor for MCP — it goes
;; through the same 6-layer validation.
;;
;; Tools exposed:
;;   arm-category          — Arm a tool category
;;   disarm-category       — Disarm a tool category (emergency stop)
;;   arm-all-categories    — Arm all categories
;;   disarm-all-categories — Disarm all categories (global emergency stop)
;;   set-override-lock     — Set override safety lock
;;   release-override-lock — Release override safety lock
;;   spawn-offensive-tool  — Spawn any registered offensive tool
;;   list-armed-categories — Show armed categories
;;   get-policy-status     — Get comprehensive policy status
;;
;; Resources exposed:
;;   swarm://offensive/tools       — All registered offensive tools
;;   swarm://offensive/categories  — All categories with profiles
;;   swarm://offensive/arm-status  — Current ARM/DISARM state
;;   swarm://offensive/policy/{category} — Policy for specific category


(defun expose-offensive-mcp-tools ()
  "Register ARM/DISARM and offensive tool control as MCP tools.

This function exposes 9 tools for MCP client discovery and invocation:
  arm-category          -- Arm a single offensive tool category.
  disarm-category       -- Disarm a category (emergency stop for cat).
  arm-all-categories    -- Arm all categories at once.
  disarm-all-categories -- GLOBAL EMERGENCY STOP. Disarm everything.
  set-override-lock     -- Engage override safety lock for critical cats.
  release-override-lock -- Release override safety lock.
  spawn-offensive-tool  -- Spawn an offensive tool with full validation.
  list-armed-categories -- List currently armed categories.
  get-policy-status     -- Full offensive safety status report.

Each tool follows the standard MCP tool pattern: JSON Schema parameters
with a handler function that calls the corresponding LISPMIND function.

Returns: A list of the registered tool name symbols.

Example:
  (expose-offensive-mcp-tools)
    ;; => (ARM-CATEGORY DISARM-CATEGORY ARM-ALL-CATEGORIES ...)

SECURITY: The spawn-offensive-tool handler performs ALL 6 validation
layers before spawning. Critical categories require the override lock.
There are no shortcuts."
  (let ((registered '()))

    ;; ── Tool: arm-category ──
    (push (mcp-tool-name
           (register-mcp-tool
            'arm-category
            "Arm an offensive tool category, enabling execution of tools in that category. Categories start DISARMED (fail-closed). Non-critical categories (:recon, :web, :lolbin, :wireless, :social-engineering) can be armed without a passphrase. Critical categories (:post-exploit, :creds, :lateral) require both the override safety lock AND the correct passphrase."
            '(:type "object"
              :properties (:category
                           (:type "string"
                            :description "Category to arm: lolbin, creds, lateral, post-exploit, recon, web, wireless, social-engineering"
                            :enum ("lolbin" "creds" "lateral" "post-exploit"
                                   "recon" "web" "wireless" "social-engineering"))
                          :passphrase
                          (:type "string"
                           :description "Override passphrase (required for post-exploit, creds)"
                           :default ""))
              :required ("category"))
            (lambda (args)
              (let* ((category-str (cdr (assoc :category args :test #'string-equal)))
                     (passphrase (or (cdr (assoc :passphrase args :test #'string-equal)) ""))
                     (category (when category-str
                                 (intern (string-upcase category-str) :keyword))))
                (if category
                    (handler-case
                        (let ((result (arm-category category
                                                    :passphrase (unless (string= passphrase "")
                                                                  passphrase))))
                          (list :content
                                (list (list :type "text"
                                            :text (format nil "Category ~S arm result: ~A"
                                                          category result)))))
                      (error (e)
                        (list :content
                              (list (list :type "text"
                                          :text (format nil "Error arming category ~S: ~A"
                                                        category e)))
                              :is-error t)))
                    (list :content
                          (list (list :type "text"
                                      :text "Invalid category. Use one of: lolbin, creds, lateral, post-exploit, recon, web, wireless, social-engineering"))
                          :is-error t))))))
          registered)

    ;; ── Tool: disarm-category ──
    (push (mcp-tool-name
           (register-mcp-tool
            'disarm-category
            "Disarm an offensive tool category. This is the EMERGENCY STOP for a single category. All running agents in that category are immediately killed (SIGTERM → SIGKILL). The category cannot be used until re-armed."
            '(:type "object"
              :properties (:category
                           (:type "string"
                            :description "Category to disarm"
                            :enum ("lolbin" "creds" "lateral" "post-exploit"
                                   "recon" "web" "wireless" "social-engineering")))
              :required ("category"))
            (lambda (args)
              (let* ((category-str (cdr (assoc :category args :test #'string-equal)))
                     (category (when category-str
                                 (intern (string-upcase category-str) :keyword))))
                (if category
                    (handler-case
                        (let ((result (disarm-category category)))
                          (list :content
                                (list (list :type "text"
                                            :text (format nil "Category ~S disarmed.~%Agents killed: ~D/~D~%State: ~S"
                                                          category
                                                          (getf result :agents-killed)
                                                          (getf result :agents-total)
                                                          (getf result :state))))))
                      (error (e)
                        (list :content
                              (list (list :type "text"
                                          :text (format nil "Error disarming category ~S: ~A"
                                                        category e)))
                              :is-error t)))
                    (list :content
                          (list (list :type "text" :text "Invalid category."))
                          :is-error t))))))
          registered)

    ;; ── Tool: arm-all-categories ──
    (push (mcp-tool-name
           (register-mcp-tool
            'arm-all-categories
            "Arm ALL offensive tool categories at once. Non-critical categories (:recon, :web, :lolbin, :wireless, :social-engineering) are armed immediately. Critical categories (:post-exploit, :creds, :lateral) require the override safety lock to be active AND the correct passphrase. Without the passphrase, critical categories are skipped."
            '(:type "object"
              :properties (:passphrase
                           (:type "string"
                            :description "Override passphrase for critical categories"
                            :default ""))
              :required ())
            (lambda (args)
              (let ((passphrase (or (cdr (assoc :passphrase args :test #'string-equal)) "")))
                (handler-case
                    (let ((result (arm-all-categories
                                   :passphrase (unless (string= passphrase "")
                                                 passphrase))))
                      (list :content
                            (list (list :type "text"
                                        :text (format nil "ARM ALL RESULT:~%  Armed:    ~{~S~^, ~}~%  Skipped:  ~{~S~^, ~}~%  Denied:   ~{~S~^, ~}"
                                                      (getf result :armed)
                                                      (getf result :skipped)
                                                      (getf result :denied))))))
                  (error (e)
                    (list :content
                          (list (list :type "text"
                                      :text (format nil "Error in arm-all: ~A" e)))
                          :is-error t))))))
          registered)

    ;; ── Tool: disarm-all-categories ──
    (push (mcp-tool-name
           (register-mcp-tool
            'disarm-all-categories
            "GLOBAL EMERGENCY STOP. Disarm ALL offensive categories simultaneously. This kills EVERY running offensive tool subprocess across ALL categories. This is the BIG RED BUTTON. Use when: unexpected targets detected, network anomalies, collateral damage suspected, or operator orders stand-down."
            '(:type "object"
              :properties ()
              :required ())
            (lambda (args)
              (declare (ignore args))
              (handler-case
                  (let ((result (disarm-all-categories)))
                    (list :content
                          (list (list :type "text"
                                      :text (format nil "*** GLOBAL DISARM COMPLETE ***~%Categories disarmed: ~{~S~^, ~}~%Total agents killed: ~D"
                                                    (getf result :categories)
                                                    (getf result :total-agents-killed))))))
                (error (e)
                  (list :content
                        (list (list :type "text"
                                    :text (format nil "Error in disarm-all: ~A" e)))
                        :is-error t))))))
          registered)

    ;; ── Tool: set-override-lock ──
    (push (mcp-tool-name
           (register-mcp-tool
            'set-override-lock
            "Set (engage) the override safety lock. This enables arming of critical categories (:post-exploit, :creds, :lateral). Requires the correct passphrase. The override does NOT auto-expire — you must explicitly release it."
            '(:type "object"
              :properties (:passphrase
                           (:type "string"
                            :description "The override safety passphrase (min 16 chars)"
                            :minLength 16))
              :required ("passphrase"))
            (lambda (args)
              (let ((passphrase (cdr (assoc :passphrase args :test #'string-equal))))
                (if (and passphrase (>= (length passphrase) 16))
                    (handler-case
                        (let ((result (require-override-safety-lock passphrase)))
                          (list :content
                                (list (list :type "text"
                                            :text (format nil "Override lock: ~A"
                                                          (if result "ENGAGED" "DENIED (wrong passphrase)"))))))
                      (error (e)
                        (list :content
                              (list (list :type "text"
                                          :text (format nil "Error setting override: ~A" e)))
                              :is-error t)))
                    (list :content
                          (list (list :type "text"
                                      :text "Passphrase required (min 16 characters)."))
                          :is-error t))))))
          registered)

    ;; ── Tool: release-override-lock ──
    (push (mcp-tool-name
           (register-mcp-tool
            'release-override-lock
            "Release (clear) the override safety lock. This automatically DISARMS all critical categories (:post-exploit, :creds, :lateral) as a safety measure. You cannot have a released override with armed critical categories."
            '(:type "object"
              :properties ()
              :required ())
            (lambda (args)
              (declare (ignore args))
              (handler-case
                  (let ((result (release-override-safety-lock)))
                    (list :content
                          (list (list :type "text"
                                      :text (format nil "Override lock: ~A~%Critical categories auto-disarmed."
                                                    (if result "RELEASED (was active)"
                                                        "Not active (nothing to release)"))))))
                (error (e)
                  (list :content
                        (list (list :type "text"
                                    :text (format nil "Error releasing override: ~A" e)))
                        :is-error t))))))
          registered)

    ;; ── Tool: spawn-offensive-tool ──
    (push (mcp-tool-name
           (register-mcp-tool
            'spawn-offensive-tool
            "Spawn an offensive tool with full categorical policy validation. All 6 validation layers are applied: (1) category armed check, (2) override for critical, (3) forbidden pattern scan, (4) target whitelist, (5) max concurrent limit, (6) root availability. The tool is only spawned if ALL layers pass."
            '(:type "object"
              :properties (:category
                           (:type "string"
                            :description "Tool category"
                            :enum ("lolbin" "creds" "lateral" "post-exploit"
                                   "recon" "web" "wireless" "social-engineering"))
                          :binary
                           (:type "string"
                            :description "Binary name or path (e.g., 'nmap', 'mimikatz')")
                          :args
                           (:type "array"
                            :items (:type "string")
                            :description "Command-line arguments as array of strings"
                            :default ())
                          :target
                           (:type "string"
                            :description "Target host, IP, or CIDR (optional)"
                            :default "")
                          :confirm
                           (:type "boolean"
                            :description "Explicit confirmation (required for post-exploit)"
                            :default nil))
              :required ("category" "binary"))
            (lambda (args)
              (let* ((category-str (cdr (assoc :category args :test #'string-equal)))
                     (binary (cdr (assoc :binary args :test #'string-equal)))
                     (args-list (or (cdr (assoc :args args :test #'string-equal)) '()))
                     (target (or (cdr (assoc :target args :test #'string-equal)) ""))
                     (confirm (cdr (assoc :confirm args :test #'string-equal)))
                     (category (when category-str
                                 (intern (string-upcase category-str) :keyword))))
                (cond
                  ((not category)
                   (list :content
                         (list (list :type "text" :text "Invalid category."))
                         :is-error t))
                  ((not binary)
                   (list :content
                         (list (list :type "text" :text "Binary is required."))
                         :is-error t))
                  (t
                   (handler-case
                       (let ((agent (spawn-offensive-tool
                                     category binary args-list
                                     :target (unless (string= target "") target)
                                     :confirm confirm)))
                         (list :content
                               (list (list :type "text"
                                           :text (format nil "Offensive tool spawned successfully.~%Agent: ~A~%Category: ~S~%Binary: ~A~%Target: ~S"
                                                         (agent-id agent)
                                                         category
                                                         binary
                                                         (unless (string= target "") target))))))
                     (category-disarmed-error (e)
                       (list :content
                             (list (list :type "text"
                                         :text (format nil "DENIED: Category ~S is DISARMED. Arm it first with arm-category."
                                                       (error-category e))))
                             :is-error t))
                     (override-required-error (e)
                       (list :content
                             (list (list :type "text"
                                         :text (format nil "DENIED: Category ~S requires override safety lock. Set it with set-override-lock."
                                                       (error-category e))))
                             :is-error t))
                     (forbidden-pattern-error (e)
                       (list :content
                             (list (list :type "text"
                                         :text (format nil "DENIED: Forbidden pattern '~A' found in argument '~A'."
                                                       (error-pattern e) (error-arg e))))
                             :is-error t))
                     (target-not-whitelisted-error (e)
                       (list :content
                             (list (list :type "text"
                                         :text (format nil "DENIED: Target '~A' is not in the whitelist."
                                                       (error-target e))))
                             :is-error t))
                     (max-concurrent-exceeded-error (e)
                       (list :content
                             (list (list :type "text"
                                         :text (format nil "DENIED: Max concurrent exceeded for ~S. Current: ~D, Maximum: ~D"
                                                       (error-category e)
                                                       (error-current-count e)
                                                       (error-maximum e))))
                             :is-error t))
                     (root-required-error (e)
                       (list :content
                             (list (list :type "text"
                                         :text (format nil "DENIED: Category ~S requires root access. Run with sudo or as root."
                                                       (error-category e))))
                             :is-error t))
                     (error (e)
                       (list :content
                             (list (list :type "text"
                                         :text (format nil "Spawn failed: ~A" e)))
                             :is-error t))))))))
          registered)

    ;; ── Tool: list-armed-categories ──
    (push (mcp-tool-name
           (register-mcp-tool
            'list-armed-categories
            "List all currently ARMED offensive categories. Returns which categories are armed, which are disarmed, override lock status, and active agent counts."
            '(:type "object"
              :properties ()
              :required ())
            (lambda (args)
              (declare (ignore args))
              (handler-case
                  (let ((summary (get-category-arm-summary))
                        (override (override-active-p)))
                    (list :content
                          (list (list :type "text"
                                      :text (format nil "ARM STATUS:~%~{~S: ~A~%~}~%Override Lock: ~A"
                                                    (let (pairs)
                                                      (dolist (cat '(:lolbin :creds :lateral :post-exploit
                                                                          :recon :web :wireless :social-engineering))
                                                        (push (symbol-name cat) pairs)
                                                        (push (if (eq (getf summary cat :disarmed) :armed)
                                                                  "ARMED"
                                                                  "disarmed")
                                                              pairs))
                                                      (nreverse pairs))
                                                    (if override "ACTIVE" "inactive"))))))
                (error (e)
                  (list :content
                        (list (list :type "text"
                                    :text (format nil "Error listing armed categories: ~A" e)))
                        :is-error t))))))
          registered)

    ;; ── Tool: get-policy-status ──
    (push (mcp-tool-name
           (register-mcp-tool
            'get-policy-status
            "Get comprehensive offensive safety policy status. Returns: armed/disarmed categories, override lock state, number of loaded profiles, active agent counts per category, target whitelist configuration, and root access status."
            '(:type "object"
              :properties ()
              :required ())
            (lambda (args)
              (declare (ignore args))
              (handler-case
                  (let ((status (get-offensive-status)))
                    (list :content
                          (list (list :type "text"
                                      :text (format nil "OFFENSIVE POLICY STATUS:~%  Armed:     ~{~S~^, ~}~%  Disarmed:  ~{~S~^, ~}~%  Override:  ~A~%  Profiles:  ~D~%  Agents:    ~D total~%  Whitelist: ~A~%  Root:      ~A"
                                                    (getf status :categories-armed)
                                                    (getf status :categories-disarmed)
                                                    (if (getf status :override-active-p) "ACTIVE" "inactive")
                                                    (getf status :profiles-loaded)
                                                    (getf status :active-agents)
                                                    (if (getf status :whitelist-configured) "yes" "no")
                                                    (if (getf status :root-available) "yes" "no"))))))
                (error (e)
                  (list :content
                        (list (list :type "text"
                                    :text (format nil "Error getting policy status: ~A" e)))
                        :is-error t))))))
          registered)

    (mcp-log :info "Registered ~D offensive MCP tools: ~S"
             (length registered) (reverse registered))
    (nreverse registered)))


(defun expose-offensive-mcp-resources ()
  "Register offensive safety state as MCP resources accessible via URI templates.

Exposes the following resources:
  swarm://offensive/tools       — All registered offensive tool names
  swarm://offensive/categories  — All categories with profile summaries
  swarm://offensive/arm-status  — Current ARM/DISARM state for all categories
  swarm://offensive/policy/{category} — Full policy profile for a category

Returns: A list of the registered resource name symbols.

Example:
  (expose-offensive-mcp-resources)
    ;; => (OFFENSIVE-TOOLS OFFENSIVE-CATEGORIES OFFENSIVE-ARM-STATUS OFFENSIVE-POLICY)"
  (let ((registered '()))

    ;; ── Resource: swarm://offensive/tools ──
    (push (mcp-resource-name
           (register-mcp-resource
            'offensive-tools
            "All registered offensive tool names organized by category"
            "swarm://offensive/tools"
            (lambda (params)
              (declare (ignore params))
              (lisp-to-json
               (list :tools
                     (list :recon '("nmap" "masscan" "dnsrecon" "enum4linux" "snmp-check")
                           :web '("sqlmap" "burpsuite" "nikto" "dirb" "gobuster")
                           :lolbin '("certutil" "netsh" "bitsadmin" "mshta" "rundll32")
                           :creds '("mimikatz" "secretsdump" "hashdump" "lsadump")
                           :lateral '("psexec" "wmiexec" "crackmapexec" "smbexec")
                           :post-exploit '("meterpreter" "empire" "bloodhound" "powerview")
                           :wireless '("aircrack-ng" "bettercap" "wifite" "kismet")
                           :social-engineering '("gophish" "setoolkit" "evilginx")))))))
          registered)

    ;; ── Resource: swarm://offensive/categories ──
    (push (mcp-resource-name
           (register-mcp-resource
            'offensive-categories
            "All offensive tool categories with profile summaries"
            "swarm://offensive/categories"
            (lambda (params)
              (declare (ignore params))
              (handler-case
                  (bt:with-lock-held (*offensive-policy-lock*)
                    (let ((cats '()))
                      (maphash
                       (lambda (k profile)
                         (push (list :category k
                                     :name (policy-profile-name profile)
                                     :description (policy-profile-description profile)
                                     :risk-level (policy-profile-risk-level profile)
                                     :max-concurrent (policy-profile-max-concurrent profile)
                                     :timeout-seconds (policy-profile-timeout-seconds profile)
                                     :requires-override (policy-profile-requires-override-p profile)
                                     :requires-root (policy-profile-requires-root-p profile))
                               cats))
                       *offensive-policy-profiles*)
                      (lisp-to-json (list :categories cats))))
                (error (e)
                  (lisp-to-json (list :error (format nil "~A" e))))))))
          registered)

    ;; ── Resource: swarm://offensive/arm-status ──
    (push (mcp-resource-name
           (register-mcp-resource
            'offensive-arm-status
            "Current ARM/DISARM state for all offensive categories"
            "swarm://offensive/arm-status"
            (lambda (params)
              (declare (ignore params))
              (handler-case
                  (let ((summary (get-category-arm-summary)))
                    (lisp-to-json
                     (list :categories
                           (list :lolbin (getf summary :lolbin :disarmed)
                                 :creds (getf summary :creds :disarmed)
                                 :lateral (getf summary :lateral :disarmed)
                                 :post-exploit (getf summary :post-exploit :disarmed)
                                 :recon (getf summary :recon :disarmed)
                                 :web (getf summary :web :disarmed)
                                 :wireless (getf summary :wireless :disarmed)
                                 :social-engineering (getf summary :social-engineering :disarmed))
                           :override-active (override-active-p)
                           :timestamp (format nil "~A" (local-time:now)))))
                (error (e)
                  (lisp-to-json (list :error (format nil "~A" e))))))))
          registered)

    ;; ── Resource: swarm://offensive/policy/{category} ──
    (push (mcp-resource-name
           (register-mcp-resource
            'offensive-policy
            "Full policy profile for a specific offensive category"
            "swarm://offensive/policy/{category}"
            (lambda (params)
              (let ((category-str (cdr (assoc :category params))))
                (if category-str
                    (let ((category (intern (string-upcase category-str) :keyword)))
                      (handler-case
                          (let ((profile (get-policy-profile category)))
                            (if profile
                                (lisp-to-json
                                 (list :category (policy-profile-category profile)
                                       :name (policy-profile-name profile)
                                       :description (policy-profile-description profile)
                                       :forbidden-patterns (policy-profile-forbidden-patterns profile)
                                       :forbidden-targets (policy-profile-forbidden-targets profile)
                                       :max-concurrent (policy-profile-max-concurrent profile)
                                       :timeout-seconds (policy-profile-timeout-seconds profile)
                                       :requires-override (policy-profile-requires-override-p profile)
                                       :requires-root (policy-profile-requires-root-p profile)
                                       :log-all-executions (policy-profile-log-all-executions-p profile)
                                       :network-pause (policy-profile-network-pause-p profile)
                                       :risk-level (policy-profile-risk-level profile)))
                                (lisp-to-json (list :error "Category not found"
                                                    :category category-str
                                                    :available '("lolbin" "creds" "lateral" "post-exploit"
                                                                 "recon" "web" "wireless" "social-engineering")))))
                        (error (e)
                          (lisp-to-json (list :error (format nil "~A" e))))))
                    (lisp-to-json (list :error "Category parameter required")))))))
          registered)

    (mcp-log :info "Registered ~D offensive MCP resources: ~S"
             (length registered) (reverse registered))
    (nreverse registered)))


;; NOTE: Offensive MCP tools are NOT auto-registered on load.
;; Call (mind:expose-offensive-mcp-tools) and (mind:expose-offensive-mcp-resources)
;; explicitly after (mind:start-mcp-bridge) to register them.
;; This prevents accidental exposure of offensive capabilities before
;; the safety system is fully initialized.
;;
;; Example:
;;   (mind:init-offensive-safety-system)
;;   (mind:expose-offensive-mcp-tools)
;;   (mind:expose-offensive-mcp-resources)


;; ═══════════════════════════════════════════════════════════════════════════
;;                          END OF MCP OFFENSIVE TOOL REGISTRATION v2.3.1
;; ═══════════════════════════════════════════════════════════════════════════


;; ═══════════════════════════════════════════════════════════════════════════
;;                          END OF MCP-BRIDGE.LISP
;; ═══════════════════════════════════════════════════════════════════════════
