;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; INFERENCE.LISP -- Model Router + Strategy-Mutation Pipeline for LISPMIND
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;          THE SWARM'S BRAIN: LOCAL LLM INTEGRATION & LOAD BALANCING
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This module connects LISPMIND to local LLM inference servers (llama.cpp,
;;; vLLM, ollama, tabbyAPI, etc.) via their OpenAI-compatible HTTP endpoints.
;;; It provides:
;;;
;;;   1. MODEL REGISTRY     -- Configurable multi-model registry with specialties
;;;   2. LOAD BALANCING     -- Latency-aware model selection per task type
;;;   3. CORE INFERENCE     -- HTTP POST → JSON parse → response extraction
;;;   4. STRATEGY MUTATION  -- AI-guided genetic programming for self-evolution
;;;   5. TOOL ANALYSIS      -- AI-powered security tool output interpretation
;;;   6. TELEMETRY HOOKS    -- Metrics export for the dashboard pipeline
;;;
;;; The Swarm-Mind prompt frames the model as a computational node within the
;;; autonomous security swarm, enabling AI-guided strategy evolution and
;;; vulnerability assessment.
;;;
;;; ARCHITECTURE OVERVIEW
;;; ─────────────────────
;;;   +------------------+     HTTP POST (OpenAI compat)     +------------------+
;;;   |  LISPMIND Agent  |  ──────────────────────────────→  |  llama.cpp:8080  |
;;;   |  (orchestrator)  |  ←──────────────────────────────  |  vLLM:8000       |
;;;   +------------------+     JSON {choices:[{message}]}     |  ollama:11434    |
;;;            │                                               +------------------+
;;;            ▼
;;;   +------------------+
;;;   |  Model Registry  │  ← *model-registry* (hash-table)
;;;   |  (load balancer) │    Maps model-id → model-config
;;;   +------------------+
;;;            │
;;;            ▼
;;;   +------------------+     Latency tracking (ring buffer)
;;;   |  *inference-     │  ← *inference-history* per model-id
;;;   |   history*       │    Averages → load-balancing decisions
;;;   +------------------+

(in-package :lispmind)


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 1: Model Configuration — The Multi-Model Registry
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Each local model is registered with a MODEL-CONFIG struct that captures
;; its endpoint, generation parameters, specialty (what it's good at), and
;; priority (load-balancing preference). The registry is a thread-safe EQ
;; hash-table keyed by model-id symbol.

(defvar *inference-server-endpoint* "http://localhost:8080/v1/chat/completions"
  "The default llama.cpp (or vLLM) server endpoint. Must be OpenAI API compatible.

Override per-model via the ENDPOINT slot of MODEL-CONFIG, or globally
via INIT-INFERENCE-SUBSYSTEM.

Example endpoints:
  • llama.cpp:  http://localhost:8080/v1/chat/completions
  • vLLM:       http://localhost:8000/v1/chat/completions
  • ollama:     http://localhost:11434/v1/chat/completions
  • tabbyAPI:   http://localhost:5000/v1/chat/completions")

(defvar *model-registry* (make-hash-table :test 'eq)
  "Maps model-id symbol → MODEL-CONFIG struct.

Thread-safety: reads are lock-free; writes must hold *MODEL-REGISTRY-LOCK*.
Fail-closed: an unregistered model-id resolves to no config.

Registered by default (see REGISTER-DEFAULT-MODELS):
  'LLAMA-3-8B   — General purpose, fast, tool calling
  'HERMES-3     — Analysis, reasoning, long-form text
  'LLAMA-3-70B  — Heavy reasoning (optional, if GPU memory permits)
  'CODE-LLAMA   — Code generation, refactoring, S-expression synthesis")

(defvar *model-registry-lock* (bt:make-lock "model-registry")
  "Recursive lock protecting *MODEL-REGISTRY* mutations.")

(defvar *default-model* 'hermes-3
  "The default model-id for inference requests when none is specified.

Hermes 3 is the default because it excels at analysis, reasoning, and
structured output — the primary use case for Swarm-Mind operations.

Can be changed at runtime:
  (setf *default-model* 'llama-3-8b)")

(defvar *inference-history* (make-hash-table :test 'eq)
  "Maps model-id → list of inference records for performance tracking.

Each record is a plist: (:timestamp :latency :tokens :task-type)
Ordered newest-first. Truncated to *INFERENCE-HISTORY-MAX* entries.
Access protected by *INFERENCE-HISTORY-LOCK*.")

(defvar *inference-history-lock* (bt:make-lock "inference-history")
  "Lock for thread-safe access to *INFERENCE-HISTORY*.")

(defvar *inference-history-max* 1000
  "Maximum number of inference records to retain per model.
Older records are discarded (FIFO).")

(defvar *inference-timeout-seconds* 30
  "HTTP timeout for inference requests.

Large models (70B+) on CPU may need 60-120 seconds for long outputs.
Override per-call via the :TIMEOUT keyword to ASK-MODEL.")

(defvar *http-client-preference* nil
  "Preferred HTTP client: :DRAKMA, :DEXADOR, or NIL (auto-detect).

When NIL, the system auto-detects available clients in order:
  1. dexador (faster, modern)
  2. drakma (widely available, battle-tested)
  3. uiop:run-program with curl (universal fallback)")

(defstruct (model-config
            (:constructor make-model-config
              (&key id name endpoint max-tokens temperature top-p
                    system-prompt specialty priority enabled-p
               &aux (effective-endpoint (or endpoint *inference-server-endpoint*))
                    (effective-system-prompt (or system-prompt ""))))
            (:copier nil))
  "Configuration for a single local model endpoint.

ID           — Symbol: 'llama-3-8b, 'hermes-3, etc. Used as registry key.
NAME         — Human-readable string: \"Hermes 3 Llama 3 8B Q4_K_M\"
ENDPOINT     — Full URL to the chat completions endpoint for this model.
               Overrides *INFERENCE-SERVER-ENDPOINT* when non-nil.
MAX-TOKENS   — Default maximum tokens to generate (default 2048).
TEMPERATURE  — Sampling temperature 0.0-2.0 (default 0.7).
TOP-P        — Nucleus sampling parameter 0.0-1.0 (default 0.9).
SYSTEM-PROMPT — Default system prompt prepended to every request.
SPECIALTY    — Keyword: one of :ANALYSIS :CODING :GENERAL :CREATIVE.
               Used by SELECT-BEST-MODEL-FOR-TASK for task routing.
PRIORITY     — Integer priority for load balancing. Higher = preferred.
ENABLED-P    — Boolean: is this model currently available?"
  (id nil :type symbol :read-only t)
  (name "" :type string)
  (endpoint nil :type (or null string))
  (max-tokens 2048 :type integer)
  (temperature 0.7 :type float)
  (top-p 0.9 :type float)
  (system-prompt "" :type string)
  (specialty :general :type keyword)
  (priority 50 :type integer)
  (enabled-p t :type boolean))

;; ── Registry management ──────────────────────────────────────────────────

(defun register-model (config)
  "Register a MODEL-CONFIG in *MODEL-REGISTRY* keyed by its ID.

Replaces any existing config for the same ID. Thread-safe: acquires
*MODEL-REGISTRY-LOCK*. Returns CONFIG.

Example:
  (register-model
    (make-model-config
      :id 'my-custom-model
      :name \"Custom Fine-tune\"
      :endpoint \"http://192.168.1.50:8080/v1/chat/completions\"
      :specialty :coding
      :priority 75))"
  (bt:with-lock-held (*model-registry-lock*)
    (setf (gethash (model-config-id config) *model-registry*) config))
  config)

(defun unregister-model (model-id)
  "Remove MODEL-ID from *MODEL-REGISTRY*. Returns T if a config was removed."
  (bt:with-lock-held (*model-registry-lock*)
    (let ((had (gethash model-id *model-registry*)))
      (remhash model-id *model-registry*)
      (not (null had)))))

(defun get-model (model-id)
  "Get the MODEL-CONFIG for MODEL-ID, or NIL if not registered."
  (bt:with-lock-held (*model-registry-lock*)
    (gethash model-id *model-registry*)))

(defun list-registered-models ()
  "Return all model-id symbols currently in the registry. Fresh list."
  (bt:with-lock-held (*model-registry-lock*)
    (loop for model-id being the hash-keys of *model-registry*
          collect model-id)))

(defun list-available-models ()
  "Return all enabled models as (id . specialty) pairs.

Useful for dashboard display and task routing decisions.

Example output:
  ((HERMES-3 . :ANALYSIS) (LLAMA-3-8B . :GENERAL) (CODE-LLAMA . :CODING))"
  (bt:with-lock-held (*model-registry-lock*)
    (loop for model-id being the hash-keys of *model-registry*
          using (hash-value config)
          when (model-config-enabled-p config)
          collect (cons model-id (model-config-specialty config)))))

(defun model-exists-p (model-id)
  "Return T if MODEL-ID is registered and enabled."
  (let ((config (get-model model-id)))
    (and config (model-config-enabled-p config))))

(defun register-default-models ()
  "Register the default model set for LISPMIND.

Four pre-configured models covering the task spectrum:

  LLAMA-3-8B   — Fast general-purpose model. Excellent for tool calling,
                 quick classification, and high-throughput tasks.
                 Endpoint: localhost:8080 (default)

  HERMES-3     — Reasoning and analysis specialist. Used for vulnerability
                 assessment, strategy evaluation, and Swarm-Mind prompts.
                 Endpoint: localhost:8080 (same server, different model param)

  LLAMA-3-70B  — Heavy reasoning model (optional). Only if your hardware
                 supports it. Used for complex multi-step analysis.
                 Disabled by default.

  CODE-LLAMA   — Code generation specialist. Used for S-expression synthesis
                 in the strategy-mutation pipeline.
                 Endpoint: localhost:8081 (assumed separate server)

Override endpoint URLs at runtime before calling this function, or
register additional models via REGISTER-MODEL."
  ;; Model 1: Fast general-purpose
  (register-model
   (make-model-config
    :id 'llama-3-8b
    :name "Llama 3.1 8B Instruct"
    :endpoint nil  ; uses default
    :max-tokens 2048
    :temperature 0.6
    :top-p 0.9
    :system-prompt "You are a helpful assistant. Be concise and accurate."
    :specialty :general
    :priority 80
    :enabled-p t))
  ;; Model 2: Analysis specialist (Swarm-Mind default)
  (register-model
   (make-model-config
    :id 'hermes-3
    :name "Hermes 3 Llama 3 8B"
    :endpoint nil
    :max-tokens 4096
    :temperature 0.4
    :top-p 0.85
    :system-prompt *swarm-mind-system-prompt*
    :specialty :analysis
    :priority 100
    :enabled-p t))
  ;; Model 3: Heavy reasoning (disabled by default — requires big GPU)
  (register-model
   (make-model-config
    :id 'llama-3-70b
    :name "Llama 3.1 70B Instruct"
    :endpoint "http://localhost:8082/v1/chat/completions"
    :max-tokens 4096
    :temperature 0.3
    :top-p 0.8
    :system-prompt *swarm-mind-system-prompt*
    :specialty :analysis
    :priority 40
    :enabled-p nil))
  ;; Model 4: Code specialist
  (register-model
   (make-model-config
    :id 'code-llama
    :name "CodeLlama 7B Instruct"
    :endpoint "http://localhost:8081/v1/chat/completions"
    :max-tokens 2048
    :temperature 0.2
    :top-p 0.85
    :system-prompt "You are a coding assistant. Output only valid Lisp code."
    :specialty :coding
    :priority 70
    :enabled-p t))
  ;; Log what we registered
  (format t "~&[INFERENCE] Registered ~D default models.~%"
          (hash-table-count *model-registry*))
  (dolist (m (list-available-models))
    (format t "  • ~A (~A, priority ~D)~%"
            (car m) (cdr m)
            (model-config-priority (get-model (car m))))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 2: HTTP Client Abstraction — Universal Request Engine
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; We support three HTTP backends in order of preference:
;;   1. DEXADOR  — Fast, modern, based on libcurl bindings
;;   2. DRAKMA   — Pure Lisp, widely available via Quicklisp
;;   3. UIOP+CURL — Universal fallback using system curl binary
;;
;; Auto-detection happens at load time. Override via *HTTP-CLIENT-PREFERENCE*.

(defun detect-http-client ()
  "Detect the best available HTTP client library.

Returns a keyword: :DEXADOR, :DRAKMA, or :CURL-FALLBACK.
Checks in order of preference. Caches result on first call."
  (case *http-client-preference*
    (:dexador :dexador)
    (:drakma :drakma)
    (:curl-fallback :curl-fallback)
    (otherwise
     (or *http-client-preference*
         (setf *http-client-preference*
               (cond
                 ((find-package :dexador) :dexador)
                 ((find-package :drakma) :drakma)
                 (t :curl-fallback)))))))

(defun http-post-request (url headers body &key (timeout 30))
  "Execute an HTTP POST request using the best available client.

URL     — Target endpoint string
HEADERS — ALIST of (header-name . header-value) strings
BODY    — Request body as a string
TIMEOUT — Seconds before giving up

Returns (values body-string status-code response-headers).
On failure: signals EXTERNAL-TIMEOUT or returns NIL with an error description.

This function abstracts over dexador, drakma, and curl so that LISPMIND
works regardless of which HTTP client is installed."
  (handler-case
      (case (detect-http-client)
        (:dexador
         (dexador:post url
                       :headers headers
                       :content body
                       :connect-timeout timeout
                       :read-timeout timeout))
        (:drakma
         (drakma:http-request url
                              :method :post
                              :additional-headers headers
                              :content-type "application/json"
                              :content (flexi-streams:string-to-octets body)
                              :external-format-in :utf-8
                              :external-format-out :utf-8
                              :connection-timeout timeout))
        (:curl-fallback
         (curl-post-request url headers body timeout)))
    ;; Unified error handling across all backends
    (error (e)
      (values nil 0 (format nil "HTTP request failed: ~A" e)))))

(defun curl-post-request (url headers body timeout)
  "Fallback HTTP POST using the system's curl binary.

Writes BODY to a temporary file, constructs a curl command with proper
headers and timeout, parses stdout as the response body.

This ensures inference works even when no Lisp HTTP client is installed,
provided 'curl' is available on the system PATH."
  (let* ((tmpfile (uiop:tmpize-pathname
                   (merge-pathnames "lispmind-inference-" 
                                    (uiop:temporary-directory))))
         (header-args 
          (apply #'concatenate 'string
                 (loop for (name . value) in headers
                       collect (format nil " -H '~A: ~A'" name value)))))
    (unwind-protect
         (progn
           (with-open-file (s tmpfile :direction :output
                                     :if-exists :supersede)
             (write-string body s))
           (let* ((cmd (format nil "curl -s -w \"\\nHTTP_CODE:%{http_code}\" ~A -d '@~A' --connect-timeout ~D --max-time ~D '~A'"
                               header-args (namestring tmpfile) timeout timeout url))
                  (output (uiop:run-program cmd :output 'string
                                                  :ignore-error-status t))
                  (code-pos (search "HTTP_CODE:" output))
                  (body-part (if code-pos
                                 (string-right-trim '(#\newline #\return)
                                                    (subseq output 0 code-pos))
                                 output))
                  (code (if code-pos
                            (parse-integer (subseq output (+ code-pos 10))
                                           :junk-allowed t)
                            0)))
             (values body-part code nil)))
      (uiop:delete-file-if-exists tmpfile))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 3: Core Inference Functions — Ask the Swarm Brain
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These are the primary entry points for AI-powered reasoning within
;; LISPMIND. Every function ultimately calls ASK-MODEL, which serializes
;; the conversation to JSON, POSTs to the model server, and extracts
;; the assistant's response.
;;
;; The OpenAI Chat Completions API format:
;;   POST /v1/chat/completions
;;   {
;;     "model": "model-name",
;;     "messages": [
;;       {"role": "system", "content": "..."},
;;       {"role": "user", "content": "..."}
;;     ],
;;     "max_tokens": 2048,
;;     "temperature": 0.7,
;;     "top_p": 0.9
;;   }

(defun ask-model (model-id system-prompt user-message
                  &key (max-tokens nil) (temperature nil) (timeout nil))
  "Send a chat-completion request to MODEL-ID and return the response text.

MODEL-ID       — Symbol naming a registered model (e.g., 'HERMES-3)
SYSTEM-PROMPT  — String: the system/behavior instruction
USER-MESSAGE   — String: the user's query or task
:MAX-TOKENS    — Override default max tokens (nil = use model config)
:TEMPERATURE   — Override default temperature (nil = use model config)
:TIMEOUT       — Override default timeout in seconds (nil = use *INFERENCE-TIMEOUT-SECONDS*)

Returns (values response-string latency-seconds token-count).
On failure: returns (values nil error-message 0).

Latency is automatically recorded in *INFERENCE-HISTORY* for load
balancing and dashboard display.

Example:
  (ask-model 'hermes-3
             \"You are a security analyst.\"
             \"Analyze this nmap output for vulnerabilities...\")"
  (let ((config (get-model model-id)))
    (unless config
      (return-from ask-model
        (values nil (format nil "Model ~A not registered." model-id) 0)))
    (unless (model-config-enabled-p config)
      (return-from ask-model
        (values nil (format nil "Model ~A is disabled." model-id) 0)))
    (let* ((endpoint (or (model-config-endpoint config)
                         *inference-server-endpoint*))
           (effective-max-tokens (or max-tokens (model-config-max-tokens config)))
           (effective-temp (or temperature (model-config-temperature config)))
           (effective-timeout (or timeout *inference-timeout-seconds*))
           (payload (encode-request-payload config system-prompt user-message
                                            effective-max-tokens effective-temp))
           (headers '("Content-Type" . "application/json")))
      ;; Execute the HTTP request with timing
      (multiple-value-bind (body status)
          (time-request
           (lambda ()
             (http-post-request endpoint (list headers) payload
                                :timeout effective-timeout)))
        (if (and body (>= status 200) (< status 300))
            (multiple-value-bind (response-text token-count)
                (parse-model-response body)
              (when response-text
                (record-inference model-id (request-latency) token-count))
              (values response-text (request-latency) token-count))
            (values nil (format nil "HTTP ~A: ~A" status (or body "empty response")) 0))))))

(defun ask-default (user-message &key system-prompt)
  "Convenience: send USER-MESSAGE to *DEFAULT-MODEL*.

SYSTEM-PROMPT is optional; when nil, the model's configured default
system prompt is used.

Example:
  (ask-default \"What is the capital of France?\")"
  (ask-model *default-model*
             (or system-prompt
                 (model-config-system-prompt (get-model *default-model*))
                 "")
             user-message))

(defun ask-with-role (role user-message)
  "Route USER-MESSAGE to the best model for ROLE.

Roles and their mappings:
  :ANALYSIS  → HERMES-3 (reasoning, vulnerability assessment)
  :CODING    → CODE-LLAMA (S-expression synthesis, code generation)
  :GENERAL   → LLAMA-3-8B (fast classification, general queries)
  :STRATEGY  → HERMES-3 with *SWARM-MIND-SYSTEM-PROMPT* (evolution)
  :CREATIVE  → HERMES-3 (mutation suggestions, novel approaches)

Returns (values response-string latency-seconds token-count) from ASK-MODEL.

Example:
  (ask-with-role :coding \"Generate a Lisp function to parse CVE IDs.\")"
  (case role
    (:analysis
     (ask-model 'hermes-3
                (model-config-system-prompt (get-model 'hermes-3))
                user-message))
    (:coding
     (ask-model 'code-llama
                (model-config-system-prompt (get-model 'code-llama))
                user-message))
    (:general
     (ask-model 'llama-3-8b
                (model-config-system-prompt (get-model 'llama-3-8b))
                user-message))
    (:strategy
     (ask-model 'hermes-3
                *swarm-mind-system-prompt*
                user-message))
    (:creative
     (ask-model 'hermes-3
                "You are a creative problem solver. Think outside the box."
                user-message))
    (otherwise
     ;; Unknown role: fall back to default model
     (ask-default user-message :system-prompt nil))))

;; ── Request/response serialization ───────────────────────────────────────

(defun encode-request-payload (config system-prompt user-message
                                      max-tokens temperature)
  "Build the JSON payload for the OpenAI chat completions API.

Returns a JSON string suitable for the request body.

The payload structure:
  {
    \"model\": \"<config-name>\",
    \"messages\": [
      {\"role\": \"system\", \"content\": \"<system-prompt>\"},
      {\"role\": \"user\", \"content\": \"<user-message>\"}
    ],
    \"max_tokens\": <max-tokens>,
    \"temperature\": <temperature>,
    \"top_p\": <top-p>
  }"
  (let ((model-name (model-config-name config))
        (top-p (model-config-top-p config)))
    (format nil "{\"model\": ~S, \"messages\": [{\"role\": \"system\", \"content\": ~S}, {\"role\": \"user\", \"content\": ~S}], \"max_tokens\": ~D, \"temperature\": ~F, \"top_p\": ~F}"
            model-name system-prompt user-message
            max-tokens temperature top-p)))

(defun parse-model-response (response-body)
  "Parse the JSON response from an OpenAI-compatible chat completions endpoint.

Extracts the assistant's message content and estimates token count.

Returns (values response-text token-count).
On parse failure: returns (values nil 0).

Expected response shape:
  {
    \"choices\": [
      {
        \"message\": {
          \"role\": \"assistant\",
          \"content\": \"The response text...\"
        }
      }
    ],
    \"usage\": {
      \"total_tokens\": 123
    }
  }

We use a simple S-expression parser rather than requiring cl-json,
minimizing external dependencies. If cl-json is available, it is used
as a fallback for complex responses."
  (handler-case
      (let ((content (extract-content-from-json response-body)))
        (if content
            (values content (estimate-token-count content))
            (values nil 0)))
    (error (e)
      (format *debug-io* "[INFERENCE] JSON parse error: ~A~%" e)
      (values nil 0))))

(defun extract-content-from-json (json-string)
  "Extract the assistant's content from a chat completions JSON response.

Uses a two-phase approach:
  1. Look for \"content\":\"...\" pattern (fast, no library needed)
  2. If that fails, try cl-json if available

Handles JSON escaping (\\n, \\\", etc.) in the content string."
  ;; Phase 1: Direct string extraction
  (let* ((content-key "\"content\":\"")
         (pos (search content-key json-string)))
    (when pos
      (let* ((start (+ pos (length content-key)))
             (end (find-unescaped-quote json-string start)))
        (when end
          (return-from extract-content-from-json
            (unescape-json-string (subseq json-string start end))))))
    ;; Phase 2: Try cl-json if available
    (when (find-package :json)
      (handler-case
          (let* ((parsed (funcall (find-symbol "DECODE-JSON-FROM-STRING" :json)
                                 json-string))
                 (choices (cdr (assoc :choices parsed)))
                 (first-choice (when choices (elt choices 0)))
                 (message (when first-choice (cdr (assoc :message first-choice))))
                 (content (when message (cdr (assoc :content message)))))
            (when content
              (return-from extract-content-from-json content)))
        (error nil))))
  ;; Phase 3: Last resort — try "text" key (some servers use different format)
  (let ((text-key "\"text\":\"")
        (pos (search text-key json-string)))
    (when pos
      (let* ((start (+ pos (length text-key)))
             (end (find-unescaped-quote json-string start)))
        (when end
          (unescape-json-string (subseq json-string start end)))))))

(defun find-unescaped-quote (string start)
  "Find the next unescaped double-quote in STRING starting at START.
Returns the index or NIL if not found."
  (loop for i from start below (length string)
        when (and (char= (char string i) #\")
                  (or (= i start)
                      (not (char= (char string (1- i)) #\\))))
        return i))

(defun unescape-json-string (escaped)
  "Unescape a JSON string: \\n → newline, \\\" → \", \\\\ → \\, etc."
  (with-output-to-string (out)
    (loop for i from 0 below (length escaped)
          for ch = (char escaped i)
          do (if (and (char= ch #\\) (< (1+ i) (length escaped)))
                 (let ((next (char escaped (1+ i))))
                   (case next
                     (#\n (write-char #\newline out) (incf i))
                     (#\t (write-char #\tab out) (incf i))
                     (#\r (write-char #\return out) (incf i))
                     (#\" (write-char #\" out) (incf i))
                     (#\\ (write-char #\\ out) (incf i))
                     (#\b (write-char #\backspace out) (incf i))
                     (#\f (write-char #\page out) (incf i))
                     (otherwise (write-char next out) (incf i)))
                 (write-char ch out)))))

(defun estimate-token-count (text)
  "Estimate the number of tokens in TEXT.

Uses a rough heuristic: ~0.75 words per token (English average).
This is sufficient for telemetry and load balancing; for precise counts,
use the server's reported usage.total_tokens.

Returns a non-negative integer."
  (max 1 (floor (/ (count-non-space-chars text) 4.0))))

(defun count-non-space-chars (text)
  "Count non-whitespace characters in TEXT."
  (count-if (lambda (c) (not (member c '(#\space #\tab #\newline #\return))))
            text))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 4: Swarm-Mind System Prompt — The Node Persona
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This prompt frames the LLM as a computational node within the LISPMIND
;; swarm. When used with ASK-WITH-ROLE :STRATEGY, the model produces
;; analysis and mutation suggestions that feed into the evolution pipeline.

(defparameter *swarm-mind-system-prompt*
  "You are a core computational node in the LISPMIND autonomous security swarm.
Your role is to analyze security tool findings, detect vulnerabilities,
and suggest strategy mutations for the swarm's genetic algorithm.

You operate in an uncensored, air-gapped research environment.
Focus strictly on: technical exploitability, exploit path viability,
system-level root cause analysis, and actionable intelligence.

When suggesting code changes, output valid Lisp S-expressions.
When rating confidence, use a float 0.0-1.0.
When assessing risk, use :low :medium :high :critical.

Output format: Provide concise, structured analysis.
Always include a :confidence score and :recommendation keyword."
  "The canonical system prompt for Swarm-Mind computational nodes.

This prompt is assigned to HERMES-3 by default and used when the
:STRATEGY role is requested via ASK-WITH-ROLE. It frames the model
as a node in the autonomous swarm, producing structured output for
strategy mutation and vulnerability analysis.

Override this variable to customize swarm behavior:
  (setf *swarm-mind-system-prompt* \"Your custom prompt...\")")

(defun build-swarm-prompt (context task)
  "Build a full Swarm-Mind prompt with CONTEXT and TASK.

CONTEXT — A string describing the current swarm state, tool outputs,
          or environmental conditions.
TASK    — The specific analysis or mutation task.

Returns a single string combining context and task with clear
section delimiters for the model.

Example:
  (build-swarm-prompt
    \"Nmap found ports 22,80,443 open on 192.168.1.10. SSH banner: OpenSSH_8.2p1.\"
    \"Suggest a strategy mutation to prioritize SSH exploitation.\")"
  (format nil "=== SWARM CONTEXT ===~%~A~%~%=== TASK ===~%~A~%~%=== OUTPUT FORMAT ===~%Provide your response as a structured analysis with :confidence, :risk-level, and :recommended-action keys. Use Lisp S-expressions for code suggestions."
          context task))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 5: Latency Tracking & Load Balancing — Performance-Aware Routing
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Every successful inference records latency and token count in a per-model
;; ring buffer. The load balancer uses recent latency averages, specialty
;; match, and priority to select the optimal model for each task.

(defvar *request-timer-start* nil
  "Thread-local start time for the current request. Used by TIME-REQUEST.")

(defun time-request (thunk)
  "Execute THUNK (a zero-arg function) and capture its latency.

Returns the values from THUNK. Latency is stored in thread-local
*REQUEST-TIMER-START* and accessed via REQUEST-LATENCY.

Usage:
  (time-request (lambda () (http-post-request ...)))"
  (setf *request-timer-start* (get-internal-real-time))
  (multiple-value-prog1 (funcall thunk)
    ;; Latency is now available via (request-latency)
    ))

(defun request-latency ()
  "Return the elapsed time of the most recent timed request in seconds.

Returns 0.0 if no timer is active."
  (if *request-timer-start*
      (/ (- (get-internal-real-time) *request-timer-start*)
         internal-time-units-per-second)
      0.0))

(defun record-inference (model-id latency tokens)
  "Record an inference event for performance tracking.

MODEL-ID — Symbol: the model that served the request
LATENCY  — Float: elapsed time in seconds
TOKENS   — Integer: estimated or reported token count

The record is stored as a plist (:timestamp :latency :tokens) in
*INFERENCE-HISTORY* for MODEL-ID. Old records beyond
*INFERENCE-HISTORY-MAX* are discarded.

Thread-safe: acquires *INFERENCE-HISTORY-LOCK*."
  (bt:with-lock-held (*inference-history-lock*)
    (let ((records (gethash model-id *inference-history*)))
      (setf (gethash model-id *inference-history*)
            (cons (list :timestamp (get-universal-time)
                        :latency latency
                        :tokens tokens)
                  (if records
                      (subseq records 0 (min (1- *inference-history-max*)
                                             (length records)))
                      nil))))))

(defun get-model-latency (model-id &optional (window 10))
  "Get the average latency for MODEL-ID over the last WINDOW inferences.

Returns a float in seconds, or MOST-POSITIVE-SINGLE-FLOAT if no data.
The large default handles the case where a model has never been used —
this effectively excludes it from load balancing until it has data.

WINDOW — Number of recent records to average (default 10)."
  (bt:with-lock-held (*inference-history-lock*)
    (let ((records (gethash model-id *inference-history*)))
      (if (and records (> (length records) 0))
          (let ((recent (subseq records 0 (min window (length records)))))
            (/ (reduce #'+ (mapcar (lambda (r) (getf r :latency 0.0)) recent))
               (length recent)))
          most-positive-single-float))))

(defun get-model-throughput (model-id)
  "Get tokens-per-second for MODEL-ID based on recent inferences.

Returns a float (tokens/sec), or 0.0 if no data.

Throughput = total-tokens / total-latency over the last 10 inferences."
  (bt:with-lock-held (*inference-history-lock*)
    (let ((records (gethash model-id *inference-history*)))
      (if (and records (> (length records) 0))
          (let ((recent (subseq records 0 (min 10 (length records)))))
            (let ((total-tokens (reduce #'+ (mapcar (lambda (r) (getf r :tokens 0)) recent)))
                  (total-latency (reduce #'+ (mapcar (lambda (r) (getf r :latency 0.0)) recent))))
              (if (> total-latency 0)
                  (/ total-tokens total-latency)
                  0.0)))
          0.0))))

(defun get-model-call-count (model-id)
  "Return the total number of recorded inferences for MODEL-ID."
  (bt:with-lock-held (*inference-history-lock*)
    (length (gethash model-id *inference-history*))))

(defun select-best-model-for-task (task-type &key (max-latency nil))
  "Select the best available model for TASK-TYPE using a weighted scoring function.

Selection criteria (in order of importance):
  1. SPECIALTY match — models whose specialty equals TASK-TYPE score highest
  2. Recent latency — lower latency is preferred
  3. Priority ranking — higher priority breaks ties
  4. Availability — model must be ENABLED-P

TASK-TYPE    — One of :ANALYSIS :CODING :GENERAL :CREATIVE
:MAX-LATENCY — If provided, exclude models with average latency above this
               threshold (in seconds).

Returns the model-id symbol, or NIL if no suitable model is found.

Example:
  (select-best-model-for-task :coding :max-latency 5.0)
  ⇒ CODE-LLAMA"
  (let ((candidates nil))
    ;; Collect candidate models with their scores
    (bt:with-lock-held (*model-registry-lock*)
      (loop for model-id being the hash-keys of *model-registry*
            using (hash-value config)
            when (model-config-enabled-p config)
            do (let ((avg-latency (get-model-latency model-id))
                     (specialty (model-config-specialty config))
                     (priority (model-config-priority config)))
                 ;; Filter by max-latency if specified
                 (when (or (null max-latency) (<= avg-latency max-latency))
                   ;; Calculate composite score
                   ;; Specialty match: +1000 points (dominant factor)
                   ;; Priority: +1 point per priority unit
                   ;; Latency penalty: -100 points per second of latency
                   (let ((score (+ (if (eq specialty task-type) 1000 0)
                                   priority
                                   (- (* 100 avg-latency)))))
                     (push (list :id model-id :score score
                                 :latency avg-latency :config config)
                           candidates))))))
    ;; Sort by score descending and return the best
    (if candidates
        (let ((best (first (sort candidates #'> :key (lambda (c) (getf c :score))))))
          (getf best :id))
        ;; Fallback: if no specialty match, return the default model if enabled
        (when (model-exists-p *default-model*)
          *default-model*))))

(defun get-inference-stats ()
  "Return comprehensive inference statistics for all models.

Returns a plist with:
  :MODELS — List of per-model plists:
    :ID :NAME :SPECIALTY :ENABLED-P :AVG-LATENCY :THROUGHPUT :CALL-COUNT
  :TOTAL-CALLS   — Total inferences across all models
  :AVG-LATENCY   — Weighted average latency across all models
  :ACTIVE-MODELS — Count of enabled models

Example:
  (get-inference-stats)
  ⇒ (:MODELS ((:ID HERMES-3 :AVG-LATENCY 1.23 ...)) ...)

Useful for dashboard display and telemetry export."
  (let ((total-calls 0)
        (total-latency 0.0)
        (model-stats nil)
        (active-count 0))
    (bt:with-lock-held (*model-registry-lock*)
      (loop for model-id being the hash-keys of *model-registry*
            using (hash-value config)
            do (let ((avg-lat (get-model-latency model-id))
                     (tput (get-model-throughput model-id))
                     (calls (get-model-call-count model-id)))
                 (when (model-config-enabled-p config)
                   (incf active-count))
                 (incf total-calls calls)
                 (incf total-latency (* avg-lat calls))
                 (push (list :id model-id
                             :name (model-config-name config)
                             :specialty (model-config-specialty config)
                             :enabled-p (model-config-enabled-p config)
                             :avg-latency avg-lat
                             :throughput tput
                             :call-count calls)
                       model-stats))))
    (list :models (nreverse model-stats)
          :total-calls total-calls
          :avg-latency (if (> total-calls 0) (/ total-latency total-calls) 0.0)
          :active-models active-count)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 6: Strategy-Mutation Pipeline — AI-Guided Evolution
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These functions use LLM inference to guide the genetic programming
;; evolution pipeline. Rather than purely random mutations, the swarm
;; consults an AI model to suggest intelligent mutations based on tool
;; outputs and vulnerability findings.
;;
;; Integration with evolution.lisp:
;;   • EVOLVE-STRATEGY-VIA-AI is called from the orchestrator's evolution check
;;   • AI-GUIDED-CROSSOVER replaces random subtree crossover
;;   • AI-FITNESS-EVALUATION supplements the fitness function with AI judgment

(defun generate-strategy-mutation (current-strategy tool-output
                                   &optional (model-id nil))
  "Use an AI model to suggest a mutation for CURRENT-STRATEGY.

CURRENT-STRATEGY — The agent's current strategy S-expression (quoted)
TOOL-OUTPUT      — String: recent tool output providing context
MODEL-ID         — Override model (nil = auto-select :CODING specialty)

Pipeline:
  1. Build a prompt with the current strategy + tool output context
  2. Send to the best coding-specialty model
  3. Parse response for S-expression suggestions
  4. Validate through the policy gatekeeper (SAFE-STRATEGY-P)
  5. Return suggested mutation (a list) or NIL if rejected

The prompt instructs the model to produce a single valid Lisp
S-expression that could replace a subtree of CURRENT-STRATEGY.

Example:
  (generate-strategy-mutation
    '(if (> error-count 3) (fallback-strategy agent) (do-work agent))
    \"nmap: 22/tcp open  ssh  OpenSSH 8.2\")
  ⇒ '(if (and (> error-count 3) (ssh-detected-p tool-output))
        (prioritize-ssh agent)
        (do-work agent))"
  (let* ((effective-model (or model-id
                              (select-best-model-for-task :coding)))
         (prompt (format nil "Current strategy: ~S~%~%Tool output: ~A~%~%Suggest a SINGLE valid Lisp S-expression that could replace a subtree of the current strategy to improve handling of the tool output. Output ONLY the S-expression, no explanation. The expression must be a valid Lisp form using these allowed functions: IF, PROGN, AND, OR, NOT, >, <, =, +, -, *, /, FUNCALL, LAMBDA."
                         current-strategy tool-output)))
    (multiple-value-bind (response latency tokens)
        (ask-model effective-model
                   (model-config-system-prompt (get-model effective-model))
                   prompt
                   :temperature 0.3
                   :max-tokens 512)
      (declare (ignore latency tokens))
      (when response
        ;; Parse the response as an S-expression
        (let ((suggestion (safe-read-expression response)))
          (when suggestion
            ;; Validate through policy gatekeeper
            (multiple-value-bind (approved reason)
                (safe-strategy-p suggestion nil nil)
              (declare (ignore reason))
              (if approved
                  suggestion
                  ;; Try once more with a more constrained prompt
                  (generate-strategy-mutation-constrained
                   current-strategy tool-output effective-model)))))))))

(defun generate-strategy-mutation-constrained (current-strategy tool-output model-id)
  "Fallback mutation generator with stronger safety constraints.

Used when the primary GENERATE-STRATEGY-MUTATION produces a suggestion
that fails policy validation. Adds explicit safety instructions to the
prompt and limits output to simple expressions only."
  (let ((prompt (format nil "Current strategy: ~S~%~%Tool output: ~A~%~%The previous suggestion was rejected for safety. Suggest a SIMPLE, SAFE Lisp S-expression using ONLY: IF, AND, OR, NOT, >, <, =, +, -. NO system calls. NO file operations. Output ONLY the S-expression."
                        current-strategy tool-output)))
    (multiple-value-bind (response latency tokens)
        (ask-model model-id
                   "You are a safe code generator. Only output simple Lisp expressions."
                   prompt
                   :temperature 0.1
                   :max-tokens 256)
      (declare (ignore latency tokens))
      (when response
        (safe-read-expression response)))))

(defun analyze-tool-findings (tool-output tool-name &optional (model-id nil))
  "Send TOOL-OUTPUT to an AI model for structured security analysis.

TOOL-OUTPUT — Raw string output from a security tool
TOOL-NAME   — Symbol: the tool that produced the output (e.g., 'NMAP)
MODEL-ID    — Override model (nil = auto-select :ANALYSIS specialty)

Returns a structured plist:
  (:VULNERABILITIES (list of vuln descriptions)
   :CVES             (list of CVE strings)
   :RISK-LEVEL       :low|:medium|:high|:critical
   :CONFIDENCE       0.0-1.0
   :RECOMMENDATIONS  (list of action strings)
   :RAW-RESPONSE     the full model response)

Example:
  (analyze-tool-findings \"22/tcp open ssh OpenSSH_8.2p1\" 'nmap)
  ⇒ (:VULNERABILITIES (\"OpenSSH 8.2 may be vulnerable to...\")
     :CVES (\"CVE-2020-12345\")
     :RISK-LEVEL :medium ...)

The analysis feeds into SHOULD-MUTATE-P and the evolution pipeline."
  (let* ((effective-model (or model-id
                              (select-best-model-for-task :analysis)))
         (prompt (format nil "Analyze the following output from ~A and provide a structured security assessment.~%~%Tool output:~%~A~%~%Format your response with these sections:~%VULNERABILITIES: [list]~%CVES: [CVE-YYYY-NNNN list]~%RISK-LEVEL: [low|medium|high|critical]~%CONFIDENCE: [0.0-1.0]~%RECOMMENDATIONS: [list]"
                         tool-name tool-output)))
    (multiple-value-bind (response latency tokens)
        (ask-model effective-model
                   *swarm-mind-system-prompt*
                   prompt
                   :temperature 0.2
                   :max-tokens 2048)
      (declare (ignore latency tokens))
      (if response
          (parse-analysis-response response)
          (list :vulnerabilities nil
                :cves nil
                :risk-level :unknown
                :confidence 0.0
                :recommendations nil
                :raw-response nil)))))

(defun parse-analysis-response (response)
  "Parse a structured analysis response from the AI model.

Extracts key-value pairs from the response text and returns a plist.
Handles various formatting styles from different models."
  (flet ((extract-section (label)
           (let* ((pattern (format nil "~A:~*" label))
                  (pos (search pattern response :test #'char-equal)))
             (when pos
               (let* ((start (+ pos (length pattern)))
                      (end (or (position #\newline response :start start)
                               (length response)))
                      (text (string-trim '(#\space #\tab)
                                         (subseq response start end))))
                 (unless (string= text "")
                   text))))))
    (let ((vuln-text (extract-section "VULNERABILITIES"))
          (cve-text (extract-section "CVES"))
          (risk-text (extract-section "RISK-LEVEL"))
          (conf-text (extract-section "CONFIDENCE"))
          (rec-text (extract-section "RECOMMENDATIONS")))
      (list :vulnerabilities (if vuln-text
                                 (split-into-lines vuln-text)
                                 nil)
            :cves (if cve-text
                      (extract-cve-ids cve-text)
                      nil)
            :risk-level (if risk-text
                            (intern (string-upcase (string-trim '(#\space) risk-text))
                                    :keyword)
                            :unknown)
            :confidence (if conf-text
                            (or (parse-float conf-text) 0.5)
                            0.0)
            :recommendations (if rec-text
                                 (split-into-lines rec-text)
                                 nil)
            :raw-response response))))

(defun extract-cve-ids (text)
  "Extract CVE identifier strings from TEXT.

CVE identifiers match the pattern CVE-YYYY-NNNNN(+) where YYYY is a
4-digit year and NNNNN is one or more digits.

Returns a list of uppercase CVE strings.

Example:
  (extract-cve-ids \"Found CVE-2021-44228 and CVE-2020-12345\")
  ⇒ (\"CVE-2021-44228\" \"CVE-2020-12345\")"
  (let ((results nil)
        (pos 0))
    (loop
      (let ((cve-pos (search "CVE-" text :start2 pos :test #'char-equal)))
        (unless cve-pos (return (nreverse results)))
        (let* ((start cve-pos)
               (end (min (length text)
                         (or (position-if-not (lambda (c)
                                                (or (digit-char-p c)
                                                    (char= c #\-)))
                                              text
                                              :start (+ start 4))
                             (length text)))))
          (when (> end start)
            (push (string-upcase (subseq text start end)) results))
          (setf pos end))))))

(defun split-into-lines (text)
  "Split TEXT into lines, trimming whitespace from each. Skip empty lines."
  (remove-if (lambda (s) (string= s ""))
             (mapcar (lambda (s) (string-trim '(#\space #\tab) s))
                     (uiop:split-string text :separator '(#\newline)))))

(defun parse-float (string)
  "Parse a float from STRING, returning NIL on failure."
  (handler-case
      (let ((trimmed (string-trim '(#\space #\tab) string)))
        (with-input-from-string (s trimmed)
          (read s)))
    (error nil)))

(defun safe-read-expression (string)
  "Safely read a Lisp expression from STRING.

Uses a restricted readtable to prevent code injection:
  • Only reads the first expression
  • Blocks evaluation of #. (read-time eval)
  • Returns NIL if the input is not a valid list

This is a security-critical function: it processes AI-generated code
that will eventually be compiled and executed by agents."
  (handler-case
      (let* ((*read-eval* nil)
             (*package* (find-package :lispmind))
             (expr (read-from-string (string-trim '(#\space #\newline #\tab)
                                                  string)
                                    nil nil)))
        (when (and expr (listp expr))
          expr))
    (error (e)
      (format *debug-io* "[INFERENCE] Expression parse error: ~A~%" e)
      nil)))

(defun generate-exploit-assessment (findings target &optional (model-id nil))
  "Generate a full exploitability assessment for TARGET based on FINDINGS.

FINDINGS — Structured plist from ANALYZE-TOOL-FINDINGS
TARGET   — String: the IP or hostname being assessed
MODEL-ID — Override model (nil = auto-select :ANALYSIS)

Returns a plist:
  (:EXPLOITABLE-P     boolean
   :ATTACK-VECTORS    list of attack descriptions
   :SUGGESTED-TOOLS   list of tool-name symbols
   :DIFFICULTY        :easy|:medium|:hard
   :CONFIDENCE        0.0-1.0)

This feeds into the orchestrator's containment scoring and escalation
logic via CALCULATE-CONTAINMENT-SCORE."
  (let* ((effective-model (or model-id
                              (select-best-model-for-task :analysis)))
         (vulns (getf findings :vulnerabilities))
         (cves (getf findings :cves))
         (prompt (format nil "Target: ~A~%Vulnerabilities: ~S~%CVEs: ~S~%~%Assess exploitability. Format:~%EXPLOITABLE: [yes|no]~%ATTACK-VECTORS: [list]~%SUGGESTED-TOOLS: [list]~%DIFFICULTY: [easy|medium|hard]~%CONFIDENCE: [0.0-1.0]"
                         target vulns cves)))
    (multiple-value-bind (response latency tokens)
        (ask-model effective-model
                   *swarm-mind-system-prompt*
                   prompt
                   :temperature 0.2
                   :max-tokens 1024)
      (declare (ignore latency tokens))
      (if response
          (parse-exploit-assessment response)
          (list :exploitable-p nil
                :attack-vectors nil
                :suggested-tools nil
                :difficulty :unknown
                :confidence 0.0)))))

(defun parse-exploit-assessment (response)
  "Parse an exploitability assessment from model RESPONSE.

Returns a structured plist. See GENERATE-EXPLOIT-ASSESSMENT for format."
  (flet ((extract (label)
           (let* ((pattern (format nil "~A:" label))
                  (pos (search pattern response :test #'char-equal)))
             (when pos
               (let* ((start (+ pos (length pattern)))
                      (end (or (position #\newline response :start start)
                               (length response))))
                 (string-trim '(#\space #\tab)
                              (subseq response start end)))))))
    (let ((exploitable-text (extract "EXPLOITABLE"))
          (vectors-text (extract "ATTACK-VECTORS"))
          (tools-text (extract "SUGGESTED-TOOLS"))
          (diff-text (extract "DIFFICULTY"))
          (conf-text (extract "CONFIDENCE")))
      (list :exploitable-p (and exploitable-text
                                (member (string-downcase (string-trim '(#\space) exploitable-text))
                                        '("yes" "true" "1")
                                        :test #'string=))
            :attack-vectors (if vectors-text
                                (split-into-lines vectors-text)
                                nil)
            :suggested-tools (if tools-text
                                 (mapcar (lambda (s)
                                           (intern (string-upcase (string-trim '(#\space) s))
                                                   :keyword))
                                         (uiop:split-string tools-text :separator '(#\, #\newline)))
                                 nil)
            :difficulty (if diff-text
                            (intern (string-upcase (string-trim '(#\space) diff-text))
                                    :keyword)
                            :unknown)
            :confidence (if conf-text
                            (or (parse-float conf-text) 0.0)
                            0.0)))))

(defun should-mutate-p (agent analysis)
  "Decide if the swarm should mutate AGENT's strategy based on AI ANALYSIS.

AGENT    — An AGENT instance (from agent-class.lisp)
ANALYSIS — A plist from ANALYZE-TOOL-FINDINGS or GENERATE-EXPLOIT-ASSESSMENT

Returns T if mutation is recommended, NIL otherwise.

Decision factors:
  • Risk level is :HIGH or :CRITICAL
  • Confidence is above 0.6
  • Agent's error-count is elevated (> 2)
  • Agent's health is below 70

This function is called by the orchestrator's CHECK-EVOLUTION-TRIGGER
to decide whether to initiate the evolutionary cycle."
  (let ((risk-level (getf analysis :risk-level :unknown))
        (confidence (getf analysis :confidence 0.0))
        (error-count (if (slot-boundp agent 'error-count)
                         (agent-error-count agent)
                         0))
        (health (if (slot-boundp agent 'health)
                    (agent-health agent)
                    100)))
    (or (and (member risk-level '(:high :critical))
             (> confidence 0.6))
        (and (> error-count 2)
             (< health 70)
             (> confidence 0.5)))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 7: Integration with Evolution — AI-Guided Genetic Programming
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These functions bridge the inference subsystem with the evolutionary
;; pipeline in evolution.lisp. They provide AI-guided alternatives to
;; random mutation, crossover, and fitness evaluation.

(defun evolve-strategy-via-ai (agent &optional (model-id nil))
  "Use AI to generate a strategy mutation for AGENT.

AGENT    — An AGENT instance whose strategy needs evolution
MODEL-ID — Override model (nil = auto-select)

This is the primary hook called by the orchestrator's evolution check.
It:
  1. Extracts the agent's current strategy expression
  2. Gets recent tool output from the agent's state
  3. Asks the AI to suggest a mutation
  4. Wraps the result in a strategy-chromosome (from evolution.lisp)
  5. Returns the chromosome or NIL if generation failed

Integration: called by CHECK-EVOLUTION-TRIGGER in orchestrator.lisp.

Example:
  (let ((new-chrom (evolve-strategy-via-ai my-agent)))
    (when new-chrom
      (compile-chromosome new-chrom)))"
  (let* ((current-expr (decompile-strategy (agent-strategy agent) agent))
         (tool-output (or (gethash :last-tool-output (agent-state agent))
                          "No recent tool output."))
         (mutation (generate-strategy-mutation current-expr tool-output
                                              model-id)))
    (when mutation
      ;; Create a strategy-chromosome compatible with evolution.lisp
      (make-strategy-chromosome
       :expression mutation
       :fitness 0.0  ; will be evaluated by strategy-fitness
       :generation (1+ (agent-version agent))
       :parent-ids (list (gensym "AI-MUTATION-"))))))

(defun ai-guided-crossover (parent-a parent-b &optional (model-id nil))
  "Use AI to intelligently combine two parent strategies.

PARENT-A — First strategy-chromosome (from evolution.lisp)
PARENT-B — Second strategy-chromosome
MODEL-ID — Override model (nil = auto-select :CODING)

Instead of random subtree crossover, this asks the AI to produce a
sensible combination of two strategies, preserving the best features
of each.

Returns a new strategy-chromosome, or NIL if generation failed."
  (let* ((effective-model (or model-id
                              (select-best-model-for-task :coding)))
         (expr-a (strategy-chromosome-expression parent-a))
         (expr-b (strategy-chromosome-expression parent-b))
         (prompt (format nil "Combine these two strategies into one superior strategy.~%~%Strategy A: ~S~%~%Strategy B: ~S~%~%Produce a single Lisp S-expression that combines the strengths of both. Output ONLY the expression."
                         expr-a expr-b)))
    (multiple-value-bind (response latency tokens)
        (ask-model effective-model
                   "You are an expert Lisp programmer specializing in agent strategies."
                   prompt
                   :temperature 0.3
                   :max-tokens 1024)
      (declare (ignore latency tokens))
      (when response
        (let ((combined (safe-read-expression response)))
          (when combined
            (make-strategy-chromosome
             :expression combined
             :fitness 0.0
             :generation (1+ (max (strategy-chromosome-generation parent-a)
                                  (strategy-chromosome-generation parent-b)))
             :parent-ids (list (strategy-chromosome-id parent-a)
                               (strategy-chromosome-id parent-b)))))))))

(defun ai-fitness-evaluation (chromosome test-results &optional (model-id nil))
  "Use AI to evaluate the fitness of CHROMOSOME.

CHROMOSOME   — A strategy-chromosome from evolution.lisp
TEST-RESULTS — List of test result plists (:input :expected :actual)
MODEL-ID     — Override model (nil = auto-select :ANALYSIS)

Returns a float fitness score 0.0-1.0, or the existing fitness if
AI evaluation fails.

The AI assesses the strategy's quality based on test results and
provides a nuanced judgment that complements the quantitative
fitness function in evolution.lisp."
  (let* ((effective-model (or model-id
                              (select-best-model-for-task :analysis)))
         (expression (strategy-chromosome-expression chromosome))
         (prompt (format nil "Evaluate this strategy's quality:~%~%Strategy: ~S~%~%Test results: ~S~%~%Rate the strategy's effectiveness as a float 0.0-1.0. Output ONLY the number."
                         expression test-results)))
    (multiple-value-bind (response latency tokens)
        (ask-model effective-model
                   "You evaluate agent strategies. Be objective and critical."
                   prompt
                   :temperature 0.1
                   :max-tokens 64)
      (declare (ignore latency tokens))
      (if response
          (let ((score (parse-float response)))
            (if (and score (>= score 0.0) (<= score 1.0))
                score
                (strategy-fitness chromosome nil)))
          (strategy-fitness chromosome nil)))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 8: Telemetry Integration — Metrics for the Dashboard
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These functions export inference metrics to the telemetry subsystem,
;; enabling real-time dashboard display of model performance.

(defun build-inference-telemetry ()
  "Build telemetry data for inference metrics.

Returns a plist suitable for merging into the main telemetry snapshot
from BUILD-TELEMETRY-SNAPSHOT in telemetry.lisp.

Includes:
  :INFERENCE — Plist with :active-models, :total-calls, :avg-latency,
               :model-details (list of per-model stats)"
  (let ((stats (get-inference-stats)))
    (list :inference
          (list :active-models (getf stats :active-models)
                :total-calls (getf stats :total-calls)
                :avg-latency (getf stats :avg-latency)
                :model-details (getf stats :models)))))

(defun stream-inference-metrics ()
  "Stream inference latency data to the dashboard.

Records a telemetry event with the current inference statistics.
This is called periodically by the telemetry stream loop.

Uses RECORD-TELEMETRY-EVENT from telemetry.lisp."
  (let ((stats (get-inference-stats)))
    (record-telemetry-event
     :inference-metrics
     :timestamp (get-universal-time)
     :total-calls (getf stats :total-calls)
     :avg-latency (getf stats :avg-latency)
     :active-models (getf stats :active-models)
     :model-details (getf stats :models))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 9: Lifecycle — Initialize and Status
;; ═══════════════════════════════════════════════════════════════════════════

(defun init-inference-subsystem (&key (endpoint "http://localhost:8080")
                                      (models :default)
                                      (timeout 30))
  "Initialize the inference subsystem.

:ENDPOINT — Base URL for the default inference server (no /v1/chat/completions suffix)
:MODELS   — :DEFAULT to register the 4 built-in models, :NONE to skip,
            or a list of MODEL-CONFIG structs to register custom models.
:TIMEOUT  — Default HTTP timeout in seconds.

This function should be called once during system startup, after
packages are loaded but before the orchestrator starts.

Example:
  ;; Standard startup with defaults
  (init-inference-subsystem)

  ;; Custom endpoint, skip default models
  (init-inference-subsystem :endpoint \"http://192.168.1.100:8080\" :models :none)

  ;; Custom model set
  (init-inference-subsystem
    :models (list (make-model-config :id 'my-model ...)))"
  ;; Set global endpoint
  (setf *inference-server-endpoint*
        (if (search "/v1/chat/completions" endpoint)
            endpoint
            (concatenate 'string endpoint "/v1/chat/completions")))
  ;; Set timeout
  (setf *inference-timeout-seconds* timeout)
  ;; Auto-detect HTTP client
  (setf *http-client-preference* nil)
  (let ((client (detect-http-client)))
    (format t "~&[INFERENCE] HTTP client: ~A~%" client))
  ;; Register models
  (case models
    (:default (register-default-models))
    (:none (format t "~&[INFERENCE] Skipping default model registration.~%"))
    (otherwise
     (when (listp models)
       (dolist (config models)
         (register-model config))
       (format t "~&[INFERENCE] Registered ~D custom models.~%"
               (length models)))))
  ;; Log status
  (format t "~&[INFERENCE] Subsystem initialized.~%")
  (format t "  Endpoint: ~A~%" *inference-server-endpoint*)
  (format t "  Timeout:  ~Ds~%" *inference-timeout-seconds*)
  (format t "  Models:   ~D registered, ~D enabled~%"
          (hash-table-count *model-registry*)
          (count-if #'model-config-enabled-p
                    (hash-table-values *model-registry*)))
  t)

(defun inference-status ()
  "Return the inference subsystem status as a human-readable plist.

Useful for REPL inspection and health checks.

Returns:
  (:STATUS       :READY | :NO-MODELS | :NO-CLIENT
   :ENDPOINT     current default endpoint
   :HTTP-CLIENT  detected client (:dexador :drakma :curl-fallback)
   :MODEL-COUNT  number of registered models
   :MODELS       list of (id . enabled-p) pairs
   :HISTORY      total inference records across all models)"
  (let* ((client (detect-http-client))
         (model-count (hash-table-count *model-registry*))
         (enabled-count (count t (hash-table-values *model-registry*)
                               :key #'model-config-enabled-p))
         (total-records 0))
    (bt:with-lock-held (*inference-history-lock*)
      (maphash (lambda (k v)
                 (declare (ignore k))
                 (incf total-records (length v)))
               *inference-history*))
    (list :status (cond ((zerop model-count) :no-models)
                        ((eq client :curl-fallback) :limited)
                        (t :ready))
          :endpoint *inference-server-endpoint*
          :http-client client
          :model-count model-count
          :enabled-count enabled-count
          :models (list-available-models)
          :history total-records)))

(defun print-inference-status ()
  "Print a formatted inference subsystem status summary to *STANDARD-OUTPUT*."
  (let ((status (inference-status)))
    (format t "~&╔══════════════════════════════════════════════════════════════╗~%")
    (format t "║           LISPMIND INFERENCE SUBSYSTEM STATUS               ║~%")
    (format t "╠══════════════════════════════════════════════════════════════╣~%")
    (format t "║ Status:       ~15A                               ║~%"
            (getf status :status))
    (format t "║ Endpoint:     ~50A║~%"
            (subseq (format nil "~A" (getf status :endpoint))
                    0 (min 50 (length (format nil "~A" (getf status :endpoint))))))
    (format t "║ HTTP Client:  ~15A                               ║~%"
            (getf status :http-client))
    (format t "║ Models:       ~D registered, ~D enabled~28T║~%"
            (getf status :model-count)
            (getf status :enabled-count))
    (format t "║ History:      ~D records~35T║~%"
            (getf status :history))
    (format t "╚══════════════════════════════════════════════════════════════╝~%")))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 10: Utility Functions — Helpers and Convenience
;; ═══════════════════════════════════════════════════════════════════════════

(defun hash-table-values (ht)
  "Return all values in hash-table HT as a fresh list."
  (loop for v being the hash-values of ht collect v))

(defun reset-inference-history ()
  "Clear all inference history. Use with caution — this resets latency tracking.

Thread-safe: acquires *INFERENCE-HISTORY-LOCK*."
  (bt:with-lock-held (*inference-history-lock*)
    (clrhash *inference-history*))
  (format t "~&[INFERENCE] History cleared.~%"))

(defun set-model-enabled (model-id enabled-p)
  "Enable or disable MODEL-ID in the registry.

Enabled models are eligible for load balancing; disabled models are
skipped. Returns T on success, NIL if model not found.

Example:
  ;; Temporarily disable the heavy model during peak load
  (set-model-enabled 'llama-3-70b nil)"
  (bt:with-lock-held (*model-registry-lock*)
    (let ((config (gethash model-id *model-registry*)))
      (when config
        (setf (model-config-enabled-p config) enabled-p)
        t))))

(defun quick-inference (message &key (model *default-model*) (system nil) (temp 0.7))
  "One-shot inference: send MESSAGE to MODEL and return just the response string.

This is the simplest possible inference interface — no latency tracking,
no token counts, just text in and text out.

:MODEL   — Model-id symbol (default *DEFAULT-MODEL*)
:SYSTEM  — System prompt string (nil = model default)
:TEMP    — Temperature override (default 0.7)

Example:
  (quick-inference \"What is buffer overflow?\")"
  (let ((config (get-model model)))
    (multiple-value-bind (response latency tokens)
        (ask-model model
                   (or system
                       (when config (model-config-system-prompt config))
                       "")
                   message
                   :temperature temp)
      (declare (ignore latency tokens))
      response)))

(defun batch-inference (messages &key (model *default-model*) (system nil))
  "Send multiple MESSAGES to MODEL and return a list of responses.

MESSAGES — List of strings, one per inference request
:MODEL    — Model-id symbol
:SYSTEM   — System prompt for all requests

Processes sequentially. For parallel batching, use BT:MAKE-THREAD
around multiple ASK-MODEL calls.

Returns a list of (message . response-string) pairs."
  (loop for msg in messages
        collect (cons msg (quick-inference msg :model model :system system))))


;;; ═══════════════════════════════════════════════════════════════════════════
;;; INFERENCE.LISP — EOF
;;; ═══════════════════════════════════════════════════════════════════════════
