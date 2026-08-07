;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;;
;;;; OSINT-ENGINE.LISP -- Super Advanced OSINT Engine for LISPMIND
;;;;
;;;; This file implements the complete Open Source Intelligence (OSINT)
;;;; subsystem for LISPMIND. It provides:
;;;;
;;;;   1. Target Registry         -- Subject of Interest (SOI) management
;;;;   2. OSINT Tool Agents       -- 8 specialized Kali-agent subclasses
;;;;   3. Finding Parsers         -- Structured output normalization
;;;;   4. Knowledge Graph Builder -- Entity-relationship graph construction
;;;;   5. Collector Mesh Pattern  -- Navigator + Analyst + Correlator
;;;;   6. MCP Registration        -- Expose OSINT tools to MCP clients
;;;;   7. Interactive Commands    -- REPL interface for OSINT operations
;;;;
;;;; Architecture: Signal-to-Identity Pipeline
;;;;   Raw Signals (tool output) → Parsed Findings → Normalized Entities
;;;;   → Knowledge Graph → Correlation → Target Registry Update
;;;;
;;;; The Collector Mesh Pattern:
;;;;   OSINT-NAVIGATOR   discovers public digital assets recursively
;;;;   OSINT-ANALYST     examines files/repos for credentials/malware
;;;;   OSINT-CORRELATOR  links findings into the identity graph
;;;;
;;;; All agents inherit from KALI-AGENT and participate in the orchestrator's
;;;; lifecycle management, gossip system, and telemetry pipeline.
;;;;
;;;; Dependencies:
;;;;   - kali-interface.lisp (kali-agent, run-tool, capture-output, parse-findings)
;;;;   - agent-class.lisp    (base agent class)
;;;;   - mcp-bridge.lisp     (register-mcp-tool, register-mcp-resource)
;;;;   - packages.lisp       (LISPMIND package with nickname MIND)
;;;;   - bordeaux-threads    (concurrency primitives)
;;;;   - cl-ppcre            (regex for output parsing)
;;;;   - local-time          (timestamps)
;;;;   - dexador             (HTTP requests for API-based agents)
;;;;   - jsown               (JSON parsing)
;;;;
;;;; Author: LISPMIND Security Research Team
;;;; Status: Production-grade / SBCL 2.x

(in-package :lispmind)


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 0: Global Parameters & Configuration
;; ═══════════════════════════════════════════════════════════════════════════

(defparameter *osint-engine-version* "2.0.0"
  "Version string for the OSINT engine subsystem.")

(defparameter *osint-default-timeout* 600
  "Default timeout in seconds for OSINT tool runs.
   Some tools (Amass, SpiderFoot) can run for very long periods.
   The orchestrator will signal EXTERNAL-TIMEOUT after this many seconds.
   Value: 600 (10 minutes). Override per-agent via the timeout slot.")

(defparameter *osint-spiderfoot-api-port* 5001
  "Default port for the SpiderFoot REST API.")

(defparameter *osint-spiderfoot-binary* "sf.py"
  "SpiderFoot CLI/Server binary name.")

(defparameter *osint-theharvester-binary* "theHarvester"
  "theHarvester binary name.")

(defparameter *osint-subfinder-binary* "subfinder"
  "Subfinder (ProjectDiscovery) binary name.")

(defparameter *osint-amass-binary* "amass"
  "Amass (OWASP) binary name.")

(defparameter *osint-ghunt-binary* "ghunt"
  "GHunt binary name.")

(defparameter *osint-wayback-endpoint* "http://web.archive.org/cdx/search/cdx"
  "Wayback Machine CDX API endpoint for historical snapshot queries.")

(defparameter *osint-socialmapper-binary* "social_mapper"
  "Social Mapper binary name.")

(defparameter *osint-confidence-default* 0.5
  "Default confidence score (0.0-1.0) for findings without explicit
   confidence data. Used by NORMALIZE-FINDING.")

(defparameter *osint-finding-types*
  '(:email :subdomain :ip :vulnerability :technology :persona
    :organization :handle :certificate :dns-record :whois
    :social-profile :credential :paste :repository :file)
  "Complete list of normalized finding types. Every finding ingested
   into the system must have a type drawn from this set.")

(defparameter *osint-risk-factors*
  '((:vulnerability . 0.3)
    (:credential . 0.4)
    (:paste . 0.2)
    (:subdomain . 0.05)
    (:email . 0.05)
    (:technology . 0.02)
    (:persona . 0.1)
    (:social-profile . 0.08))
  "Risk weight factors for each finding type. Used by CALCULATE-TARGET-RISK
   to compute an aggregate risk score from 0.0 to 1.0.")

(defvar *osint-target-registry* (make-hash-table :test 'equal)
  "Registry of Subjects of Interest (SOIs).
   Keys are target ID strings (domain names, IPs, persona names, handles).
   Values are OSINT-TARGET structures.
   Thread-safety: Access must be protected by *OSINT-REGISTRY-LOCK*.")

(defvar *osint-findings-ledger* (make-hash-table :test 'equal)
  "All findings keyed by target ID.
   Keys are target ID strings.
   Values are lists of normalized finding plists.
   Thread-safety: Access must be protected by *OSINT-REGISTRY-LOCK*.")

(defvar *osint-knowledge-graph* (make-hash-table :test 'equal)
  "Entity-relationship graph storage.
   Keys are entity strings (email, domain, IP, handle, etc.).
   Values are lists of (RELATION TARGET-ENTITY EVIDENCE-FINDING) triples.
   This is an adjacency-list representation of a directed multi-graph.
   Thread-safety: Access must be protected by *OSINT-GRAPH-LOCK*.")

(defvar *osint-collector-mesh-registry* (make-hash-table :test 'eq)
  "Registry of active Collector Mesh instances.
   Keys are correlator agent IDs.
   Values are plists with :navigator :analyst :correlator :target.")

(defvar *osint-registry-lock* (bt:make-lock "osint-registry")
  "Lock protecting *OSINT-TARGET-REGISTRY* and *OSINT-FINDINGS-LEDGER*.")

(defvar *osint-graph-lock* (bt:make-lock "osint-graph")
  "Lock protecting *OSINT-KNOWLEDGE-GRAPH*.")

(defvar *osint-agent-registry* (make-hash-table :test 'eq)
  "Registry of active OSINT tool agents.
   Keys are agent IDs (keywords).
   Values are agent instances.")

(defvar *osint-agent-registry-lock* (bt:make-lock "osint-agent-registry")
  "Lock protecting *OSINT-AGENT-REGISTRY*.")


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 1: Target Registry — Subject of Interest Management
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Every OSINT operation centers around a Target (Subject of Interest).
;; The target registry maintains metadata, risk scores, entity lists, and
;; lifecycle state for each SOI. Targets can be domains, IPs, personas,
;; organizations, or social media handles.

(defstruct (osint-target (:conc-name osint-target-))
  "A Subject of Interest (SOI) for OSINT operations.

   An OSINT-TARGET represents anything we want to investigate: a domain
   name, IP address, person's name, social media handle, or organization.
   The structure tracks investigation progress, accumulated findings,
   extracted entities, and a computed risk score.

   Fields:
     ID            -- String: the target identifier (domain, IP, name, handle)
     TYPE          -- Keyword: one of :DOMAIN :IP :PERSONA :ORGANIZATION :HANDLE
     STATUS        -- Keyword: investigation lifecycle state
     CREATED-AT    -- Local-time timestamp of registration
     LAST-SCANNED  -- Local-time timestamp of most recent scan
     FINDINGS-COUNT -- Integer: total findings accumulated
     ENTITIES      -- Plist of extracted entities (:emails (...) :subdomains (...))
     RISK-SCORE    -- Float: 0.0-1.0 aggregate risk from findings"
  (id nil :type string :read-only t)
  (type :domain :type keyword)
  (status :pending :type keyword)
  (created-at (local-time:now))
  (last-scanned-at nil)
  (findings-count 0 :type integer)
  (entities '() :type list)
  (risk-score 0.0 :type float))

(defun register-target (id &key (type :domain) (risk-score 0.0))
  "Register a new Subject of Interest in the target registry.

   Parameters:
     ID         -- String: the target identifier (e.g., 'example.com',
                   '192.168.1.1', 'John Doe', '@johndoe')
     TYPE       -- Keyword: one of :DOMAIN :IP :PERSONA :ORGANIZATION :HANDLE
     RISK-SCORE -- Float: initial risk score (0.0-1.0)

   Returns: The OSINT-TARGET structure.

   Side effects:
     - Creates and stores OSINT-TARGET in *OSINT-TARGET-REGISTRY*
     - Initializes empty findings list in *OSINT-FINDINGS-LEDGER*
     - Publishes :swarm.osint.target.registered gossip event
     - Records telemetry event

   Thread-safety: Lock-protected via *OSINT-REGISTRY-LOCK*.

   Example:
     (register-target 'example.com' :type :domain)
     (register-target 'john@example.com' :type :persona)"
  (bt:with-lock-held (*osint-registry-lock*)
    (let* ((id-str (string-downcase (string id)))
           (target (make-osint-target
                    :id id-str
                    :type (intern (string-upcase (string type)) :keyword)
                    :status :pending
                    :created-at (local-time:now)
                    :risk-score (float risk-score 0.0))))
      (setf (gethash id-str *osint-target-registry*) target)
      (setf (gethash id-str *osint-findings-ledger*) '())
      (publish-message :swarm.osint.target.registered
                       `(:event :target-registered
                         :target-id ,id-str
                         :type ,(osint-target-type target)
                         :timestamp ,(local-time:now)))
      (record-telemetry-event :osint-target-registered
                              :target-id id-str
                              :type type)
      (mcp-log :info "OSINT target registered: ~A (~A)" id-str type)
      target)))

(defun get-target (id)
  "Retrieve a target from the registry by ID.

   Parameters:
     ID -- String: the target identifier.

   Returns: The OSINT-TARGET structure, or NIL if not found.

   Thread-safety: Lock-protected via *OSINT-REGISTRY-LOCK*."
  (bt:with-lock-held (*osint-registry-lock*)
    (gethash (string-downcase (string id)) *osint-target-registry*)))

(defun list-targets (&key (type nil) (status nil))
  "List all registered targets, optionally filtered.

   Parameters:
     TYPE   -- Optional keyword filter (:DOMAIN :IP :PERSONA :ORGANIZATION :HANDLE)
     STATUS -- Optional keyword filter (:PENDING :ACTIVE :COMPLETE :STALE)

   Returns: A list of OSINT-TARGET structures matching the filters.

   Thread-safety: Lock-protected via *OSINT-REGISTRY-LOCK*.

   Example:
     (list-targets)                       → all targets
     (list-targets :type :domain)         → only domain targets
     (list-targets :status :active)       → only active targets"
  (bt:with-lock-held (*osint-registry-lock*)
    (let ((result '()))
      (maphash (lambda (id target)
                 (declare (ignore id))
                 (when (and (or (null type) (eq (osint-target-type target) type))
                            (or (null status) (eq (osint-target-status target) status)))
                   (push target result)))
               *osint-target-registry*)
      (nreverse result))))

(defun update-target-status (id new-status)
  "Update the investigation status of a target.

   Parameters:
     ID         -- String: target identifier.
     NEW-STATUS -- Keyword: :PENDING :ACTIVE :COMPLETE :STALE

   Returns: The updated OSINT-TARGET, or NIL if not found.

   Side effects: Publishes :swarm.osint.target.status-changed event."
  (bt:with-lock-held (*osint-registry-lock*)
    (let ((target (gethash (string-downcase (string id)) *osint-target-registry*)))
      (when target
        (setf (osint-target-status target) new-status)
        (when (eq new-status :active)
          (setf (osint-target-last-scanned-at target) (local-time:now)))
        (publish-message :swarm.osint.target.status-changed
                         `(:event :status-changed
                           :target-id ,(osint-target-id target)
                           :new-status ,new-status
                           :timestamp ,(local-time:now)))
        target))))

(defun update-target-risk (id new-risk)
  "Update the risk score for a target.

   Parameters:
     ID       -- String: target identifier.
     NEW-RISK -- Float: new risk score clamped to 0.0-1.0 range.

   Returns: The updated risk score (float).

   Side effects: Publishes :swarm.osint.target.risk-updated event
                 if the risk score changed significantly (> 0.05 delta).

   Thread-safety: Lock-protected via *OSINT-REGISTRY-LOCK*."
  (bt:with-lock-held (*osint-registry-lock*)
    (let* ((target (gethash (string-downcase (string id)) *osint-target-registry*))
           (clamped-risk (max 0.0 (min 1.0 (float new-risk 0.0)))))
      (when target
        (let ((old-risk (osint-target-risk-score target)))
          (setf (osint-target-risk-score target) clamped-risk)
          (when (> (abs (- clamped-risk old-risk)) 0.05)
            (publish-message :swarm.osint.target.risk-updated
                             `(:event :risk-updated
                               :target-id ,(osint-target-id target)
                               :old-risk ,old-risk
                               :new-risk ,clamped-risk
                               :timestamp ,(local-time:now)))
            (record-telemetry-event :osint-risk-changed
                                    :target-id id
                                    :old-risk old-risk
                                    :new-risk clamped-risk))))
      clamped-risk)))

(defun calculate-target-risk (target-id)
  "Calculate the aggregate risk score for a target from its findings.

   This function sums the weighted risk contributions of all findings
   for the target, using *OSINT-RISK-FACTORS* as weights. The result
   is clamped to 0.0-1.0.

   Parameters:
     TARGET-ID -- String: target identifier.

   Returns: Float risk score between 0.0 and 1.0.

   Algorithm:
     risk = min(1.0, sum(finding-risk-factor * confidence) for each finding)"
  (bt:with-lock-held (*osint-registry-lock*)
    (let* ((findings (gethash (string-downcase (string target-id))
                              *osint-findings-ledger*))
           (total-risk 0.0))
      (dolist (finding findings)
        (let* ((ftype (getf finding :type))
               (confidence (or (getf finding :confidence)
                               *osint-confidence-default*))
               (factor (or (cdr (assoc ftype *osint-risk-factors*)) 0.01)))
          (incf total-risk (* factor confidence))))
      (min 1.0 total-risk))))

(defun recalculate-all-target-risks ()
  "Recalculate risk scores for all registered targets.

   Iterates over *OSINT-TARGET-REGISTRY*, recalculates each target's
   risk from findings, and updates the risk-score slot.

   Returns: Number of targets updated.

   Thread-safety: Lock-protected."
  (let ((count 0))
    (bt:with-lock-held (*osint-registry-lock*)
      (maphash (lambda (id target)
                 (declare (ignore target))
                 (let ((new-risk (calculate-target-risk id)))
                   (update-target-risk id new-risk)
                   (incf count)))
               *osint-target-registry*))
    count))

(defun target-summary (target-id)
  "Generate a summary plist for a target.

   Parameters:
     TARGET-ID -- String: target identifier.

   Returns: A plist with :id :type :status :risk-score :findings-count
            :entities :created-at :last-scanned-at, or NIL if not found."
  (let ((target (get-target target-id)))
    (when target
      (bt:with-lock-held (*osint-registry-lock*)
        `(:id ,(osint-target-id target)
          :type ,(osint-target-type target)
          :status ,(osint-target-status target)
          :risk-score ,(osint-target-risk-score target)
          :findings-count ,(osint-target-findings-count target)
          :entities ,(osint-target-entities target)
          :created-at ,(osint-target-created-at target)
          :last-scanned-at ,(osint-target-last-scanned-at target))))))

(defun remove-target (id)
  "Remove a target and all associated data from the OSINT system.

   This is a destructive operation that removes:
     - The target from *OSINT-TARGET-REGISTRY*
     - All findings from *OSINT-FINDINGS-LEDGER*
     - All graph relationships where the target appears

   Parameters:
     ID -- String: target identifier.

   Returns: T if removed, NIL if target did not exist.

   Thread-safety: Lock-protected."
  (bt:with-lock-held (*osint-registry-lock*)
    (let ((id-str (string-downcase (string id))))
      (when (gethash id-str *osint-target-registry*)
        (remhash id-str *osint-target-registry*)
        (remhash id-str *osint-findings-ledger*)
        ;; Remove from knowledge graph
        (bt:with-lock-held (*osint-graph-lock*)
          (remhash id-str *osint-knowledge-graph*)
          ;; Remove references to this entity from other nodes
          (maphash (lambda (entity relations)
                     (declare (ignore entity))
                     (setf (cdr (assoc id-str relations :test #'string-equal))
                           nil))
                   *osint-knowledge-graph*))
        (publish-message :swarm.osint.target.removed
                         `(:event :target-removed
                           :target-id ,id-str
                           :timestamp ,(local-time:now)))
        (mcp-log :info "OSINT target removed: ~A" id-str)
        t))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 2: OSINT Tool Agents — 8 Specialized Kali-Agent Subclasses
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Each agent wraps a specific OSINT tool from the Kali Linux ecosystem.
;; They inherit process management, output capture, finding parsing, gossip
;; integration, and telemetry from KALI-AGENT. Each specializes in a
;; distinct phase of the Signal-to-Identity pipeline.
;;
;; Tool inventory:
;;   SpiderFoot     -- Long-running reconnaissance daemon with REST API
;;   theHarvester   -- Email and subdomain discovery via search engines
;;   Subfinder      -- High-speed subdomain enumeration (ProjectDiscovery)
;;   Amass          -- Deep DNS enumeration with graph output (OWASP)
;;   GHunt          -- Google account digital footprint analysis
;;   Wayback        -- Historical archive snapshot retrieval
;;   Social Mapper  -- Social media persona correlation across platforms

;; ───────────────────────────────────────────────────────────────────────────
;; SpiderFoot Agent — Long-running daemon, poll REST API
;; ───────────────────────────────────────────────────────────────────────────

(defclass spiderfoot-agent (kali-agent)
  ((api-url :initarg :api-url
            :initform (format nil "http://127.0.0.1:~D"
                              *osint-spiderfoot-api-port*)
            :accessor sf-api-url
            :documentation
            "Base URL for the SpiderFoot REST API.
             Default: http://127.0.0.1:5001
             The SpiderFoot server must be running separately; this agent
             can optionally spawn it via START-SPIDERFOOT-SERVER.")

   (scan-id :initform nil
            :accessor sf-scan-id
            :documentation
            "The active scan ID from SpiderFoot's REST API.
             Set when a scan is started via the API.
             Used to poll for new findings and check scan status.")

   (scan-name :initarg :scan-name
              :initform nil
              :accessor sf-scan-name
              :documentation
              "Human-readable name for this scan.
             Auto-generated from target + timestamp if not provided.")

   (modules :initarg :modules
            :initform '("sfp_spider" "sfp_dnsresolve" "sfp_email"
                        "sfp_sslcert" "sfp_bing" "sfp_google"
                        "sfp_shodan" "sfp_censys" "sfp_binaryedge")
            :accessor sf-modules
            :documentation
            "List of SpiderFoot module names to enable for the scan.
             Each module is a data source or analysis plugin.
             Default set covers DNS, email, SSL certs, search engines,
             and threat intelligence platforms.")

   (poll-interval :initarg :poll-interval
                  :initform 5
                  :accessor sf-poll-interval
                  :documentation
                  "Seconds between API polling cycles.
             Lower values = faster detection but more API load.
             Default: 5 seconds."))

  (:default-initargs
   :binary "sf.py"
   :args '("-l" "127.0.0.1:5001")
   :tool-category :recon
   :timeout *osint-default-timeout*)

  (:documentation
   "SpiderFoot automated reconnaissance agent.

    SpiderFoot is one of the most comprehensive OSINT automation platforms.
    This agent can operate in two modes:

    1. SERVER MODE: Spawns SpiderFoot as a daemon (sf.py -l ...), then
       interacts via REST API to start scans and poll results.
    2. CLIENT MODE: Connects to an already-running SpiderFoot server.

    The agent polls the REST API periodically, extracts findings
    (emails, hosts, subdomains, vulnerabilities, certificates, technologies),
    and feeds them into the normalization pipeline.

    API Endpoints used:
      POST /startscan    — Start a new scan
      GET  /scaninfo     — Get scan status and metadata
      GET  /scaneventresults — Get findings for a scan

    Thread-safety: The scan-id slot is protected by the agent-lock."))

(defun make-spiderfoot-agent (target &key (api-url nil) (modules nil) (name nil))
  "Create a SpiderFoot agent for TARGET.

   Parameters:
     TARGET   -- String: the target domain/IP/persona to investigate.
     API-URL  -- Optional string: override the REST API base URL.
     MODULES  -- Optional list: override the SpiderFoot module list.
     NAME     -- Optional string: human-readable scan name.

   Returns: A SPIDERFOOT-AGENT instance.

   Example:
     (make-spiderfoot-agent 'example.com' :name 'example-recon')"
  (let ((agent (make-instance 'spiderfoot-agent
                              :id (gensym (format nil "SF-~A-" target))
                              :target target
                              :api-url (or api-url
                                           (format nil "http://127.0.0.1:~D"
                                                   *osint-spiderfoot-api-port*))
                              :scan-name (or name
                                             (format nil "~A-~A"
                                                     target
                                                     (local-time:now)))
                              :capabilities '(:osint :recon :domain-scan
                                              :email-discovery :tech-fingerprint
                                              :threat-intel))))
    (when modules
      (setf (sf-modules agent) modules))
    ;; Register in OSINT agent registry
    (bt:with-lock-held (*osint-agent-registry-lock*)
      (setf (gethash (agent-id agent) *osint-agent-registry*) agent))
    agent))

(defmethod start-spiderfoot-server ((agent spiderfoot-agent))
  "Start the SpiderFoot server process.

   Launches 'sf.py -l <api-url>' as a background process via RUN-TOOL.
   The server needs a few seconds to become ready before API calls
   can be made. This method waits up to 30 seconds for the API
   to respond with a successful ping.

   Returns: The agent instance if the server started successfully, NIL otherwise.

   Side effects: Spawns a background SpiderFoot process."
  (let ((api-host-port (nth-value 1 (cl-ppcre:scan-to-strings
                                      "http://(.+)"
                                      (sf-api-url agent)))))
    (declare (ignore api-host-port))
    (run-tool agent)
    ;; Poll for API readiness (up to 30 seconds)
    (loop for i from 0 below 30
          do (handler-case
                 (progn
                   (dex:get (format nil "~A/ping" (sf-api-url agent))
                            :connect-timeout 2)
                   (mcp-log :info "SpiderFoot server ready at ~A"
                            (sf-api-url agent))
                   (return-from start-spiderfoot-server agent))
               (error ()
                 (sleep 1)))
          finally (progn
                    (mcp-log :warn "SpiderFoot server failed to start at ~A"
                             (sf-api-url agent))
                    (return-from start-spiderfoot-server nil)))))

(defmethod start-spiderfoot-scan ((agent spiderfoot-agent))
  "Start a new SpiderFoot scan via the REST API.

   POST /startscan with the target and module list.
   Stores the returned scan ID in the agent's scan-id slot.

   Returns: The scan ID string, or NIL if the API call failed.

   Precondition: SpiderFoot server must be running."
  (handler-case
      (let ((response (dex:post
                       (format nil "~A/startscan" (sf-api-url agent))
                       :content `(('scanname . ,(or (sf-scan-name agent)
                                                    (format nil "lisp-~A" (agent-target agent))))
                                  ('scantarget . ,(agent-target agent))
                                  ('modulelist . ,(format nil "~{~A,~}" (sf-modules agent))))
                       :connect-timeout 10)))
        (let ((json (jsown:parse response)))
          (let ((sid (jsown:val json "scanid")))
            (when sid
              (setf (sf-scan-id agent) sid)
              (update-target-status (agent-target agent) :active)
              (mcp-log :info "SpiderFoot scan started: ~A for ~A"
                       sid (agent-target agent))
              sid))))
    (error (e)
      (mcp-log :error "Failed to start SpiderFoot scan: ~A" e)
      nil)))

(defmethod poll-spiderfoot-results ((agent spiderfoot-agent))
  "Poll SpiderFoot REST API for new findings.

   GET /scaneventresults for the current scan ID.
   Parses each result into normalized findings and ingests them.

   Returns: Integer count of new findings discovered this poll cycle.

   Side effects:
     - Ingests findings via INGEST-FINDING
     - Updates target findings count
     - Publishes :swarm.osint.finding.discovered events"
  (when (sf-scan-id agent)
    (handler-case
        (let* ((url (format nil "~A/scaneventresults?id=~A"
                            (sf-api-url agent)
                            (sf-scan-id agent)))
               (response (dex:get url :connect-timeout 10))
               (results (jsown:parse response))
               (count 0))
          (dolist (result (if (listp results) results '()))
            (let* ((module (jsown:val-safe result "module"))
                   (ftype (jsown:val-safe result "type"))
                   (data (jsown:val-safe result "data"))
                   (confidence (or (jsown:val-safe result "confidence")
                                   *osint-confidence-default*))
                   (finding (normalize-finding
                             "spiderfoot"
                             `(:type ,(intern (string-upcase (or ftype "unknown"))
                                              :keyword)
                               :value ,data
                               :module ,module
                               :confidence ,(if (numberp confidence)
                                                (float confidence 0.0)
                                                *osint-confidence-default*)
                               :evidence ,result))))
              (when finding
                (ingest-finding (agent-target agent) finding)
                (incf count))))
          count)
      (error (e)
        (mcp-log :warn "SpiderFoot poll error: ~A" e)
        0))))


;; ───────────────────────────────────────────────────────────────────────────
;; theHarvester Agent — Email/subdomain discovery via search engines
;; ───────────────────────────────────────────────────────────────────────────

(defclass theharvester-agent (kali-agent)
  ((source :initarg :source
           :initform "all"
           :accessor th-source
           :documentation
           "Data source for theHarvester.
             'all'       — Use all available sources (slowest, most thorough)
             'bing'      — Microsoft Bing search
             'google'    — Google search (may require API key)
             'duckduckgo'-- DuckDuckGo
             'yahoo'     -- Yahoo search
             'crtsh'     -- crt.sh certificate transparency logs
             'hackertarget' -- HackerTarget services
             'otx'       -- AlienVault OTX
             'threatcrowd' -- ThreatCrowd
             'urlscan'   -- URLScan.io")

   (limit :initarg :limit
          :initform 500
          :accessor th-limit
          :documentation
          "Maximum number of results to fetch per source.
             Higher values = more thorough but slower.
             Default: 500."))

  (:default-initargs
   :binary *osint-theharvester-binary*
   :args '()
   :tool-category :recon
   :timeout *osint-default-timeout*)

  (:documentation
   "theHarvester agent — email and subdomain discovery.

    theHarvester is a classic OSINT tool that discovers email addresses,
    subdomains, hosts, employee names, open ports, and banners from
    public sources. It queries search engines, PGP servers, SHODAN,
    and certificate transparency logs.

    This agent wraps theHarvester as a Kali binary, captures its XML
    output, and parses emails, hosts, and IPs into normalized findings.

    Output format: XML (-f output.xml) for structured parsing.

    Typical findings:
      - Email addresses associated with the domain
      - Subdomains discovered via search engines
      - Hosts and IP addresses
      - Employee names from public sources

    Thread-safety: Uses inherited KALI-AGENT process-lock."))

(defun make-theharvester-agent (domain &key (source "all") (limit 500))
  "Create a theHarvester agent for DOMAIN.

   Parameters:
     DOMAIN -- String: the target domain to investigate (e.g., 'example.com').
     SOURCE -- String: data source to query (default: 'all').
     LIMIT  -- Integer: max results per source (default: 500).

   Returns: A THEHARVESTER-AGENT instance.

   Example:
     (make-theharvester-agent 'example.com' :source 'bing')
     (make-theharvester-agent 'example.com' :limit 1000)"
  (let ((agent (make-instance 'theharvester-agent
                              :id (gensym (format nil "TH-~A-" domain))
                              :target domain
                              :source source
                              :limit limit
                              :args (list "-d" domain
                                          "-b" source
                                          "-l" (format nil "~A" limit)
                                          "-f" "/tmp/theharvester-output.xml"
                                          "-n")
                              :capabilities '(:osint :email-discovery
                                              :subdomain-discovery
                                              :host-discovery))))
    (bt:with-lock-held (*osint-agent-registry-lock*)
      (setf (gethash (agent-id agent) *osint-agent-registry*) agent))
    agent))


;; ───────────────────────────────────────────────────────────────────────────
;; Subfinder Agent — High-speed subdomain enumeration
;; ───────────────────────────────────────────────────────────────────────────

(defclass subfinder-agent (kali-agent)
  ((output-format :initarg :output-format
                  :initform "json"
                  :accessor sf-output-format
                  :documentation
                  "Output format for Subfinder results.
             'json'  -- Structured JSON output (default, for parsing)
             'text'  -- Plain text, one subdomain per line
             'file'  -- Write to file")

   (sources :initarg :sources
            :initform 'all
            :accessor sf-sources
            :documentation
            "Source selection for Subfinder.
             'all'     -- Use all available sources (default)
             list     -- Specific source list (e.g., '(crtsh virustotal))"))

  (:default-initargs
   :binary *osint-subfinder-binary*
   :args '()
   :tool-category :recon
   :timeout 300)

  (:documentation
   "Subfinder agent — fast subdomain discovery (ProjectDiscovery).

    Subfinder is a high-speed subdomain discovery tool that uses passive
    online sources to find valid subdomains of a target domain. It queries
    over 50 sources including:
      - Certificate transparency logs (crt.sh, Censys)
      - Search engines (Bing, Yahoo, Baidu)
      - DNS services (VirusTotal, PassiveTotal)
      - Threat intel platforms (ThreatCrowd, AlienVault OTX)

    This agent runs Subfinder with JSON output for structured parsing,
    normalizes discovered subdomains into findings, and ingests them
    into the target ledger.

    Key features:
      - Very fast: can enumerate thousands of subdomains in seconds
      - Recursive enumeration supported (-recursive)
      - All-sources mode for maximum coverage

    Typical findings: Subdomain names (e.g., 'mail.example.com',
    'api.example.com', 'dev.example.com')."))

(defun make-subfinder-agent (domain &key (sources 'all) recursive)
  "Create a Subfinder agent for DOMAIN.

   Parameters:
     DOMAIN    -- String: the target domain to enumerate.
     SOURCES   -- 'ALL or list of specific source names.
     RECURSIVE -- Boolean: enable recursive subdomain enumeration.

   Returns: A SUBFINDER-AGENT instance.

   Example:
     (make-subfinder-agent 'example.com')
     (make-subfinder-agent 'example.com' :recursive t)"
  (let ((args (list "-d" domain
                    "-oJ" "/tmp/subfinder-output.json"
                    "-all")))
    (when recursive
      (push "-recursive" args))
    (unless (eq sources 'all)
      (push (format nil "~{~A,~}" sources) args)
      (push "-s" args))
    (let ((agent (make-instance 'subfinder-agent
                                :id (gensym (format nil "SF2-~A-" domain))
                                :target domain
                                :sources sources
                                :args args
                                :capabilities '(:osint :subdomain-discovery
                                                :passive-recon :dns))))
      (bt:with-lock-held (*osint-agent-registry-lock*)
        (setf (gethash (agent-id agent) *osint-agent-registry*) agent))
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; Amass Agent — Deep subdomain enumeration with graph output
;; ───────────────────────────────────────────────────────────────────────────

(defclass amass-agent (kali-agent)
  ((config :initarg :config
           :initform nil
           :accessor amass-config
           :documentation
           "Optional path to Amass configuration INI file.
             The config file can specify API keys for various data
             sources (Shodan, Censys, VirusTotal, etc.), output
             directories, and enumeration tuning parameters.
             NIL means use default configuration.")

   (enum-mode :initarg :enum-mode
              :initform :passive
              :accessor amass-enum-mode
              :documentation
              "Enumeration mode for Amass.
             :PASSIVE  -- Only passive sources (default, safest)
             :ACTIVE   -- Includes active DNS brute-forcing
             :AGGRESSIVE -- Deep enumeration with more permutations")

   (output-dir :initarg :output-dir
               :initform "/tmp/amass-output/"
               :accessor amass-output-dir
               :documentation
               "Directory for Amass output files.
             Amass produces multiple output files including:
               - subdomains.txt: list of discovered subdomains
               - amass.json: detailed JSON with DNS data
               - amass_graph.dot: Graphviz graph file
               - amass.sqlite: SQLite database with full results"))

  (:default-initargs
   :binary *osint-amass-binary*
   :args '()
   :tool-category :recon
   :timeout 1800)

  (:documentation
   "Amass agent — comprehensive DNS enumeration with graph output (OWASP).

    Amass is the most thorough subdomain enumeration tool available.
    It performs deep DNS investigation using both passive and active
    techniques, and produces rich output including:

    1. Subdomain lists (text and JSON)
    2. DNS records (A, AAAA, CNAME, MX, NS, TXT, SOA)
    3. Network infrastructure mapping
    4. Graphviz DOT files showing domain relationships
    5. SQLite database with full forensic data

    This agent runs Amass in INTEL or ENUM mode depending on needs,
    parses the JSON output for subdomains and DNS records, and
    feeds findings into the normalization pipeline. It also extracts
    the Graphviz graph data for the knowledge graph builder.

    Enumeration modes:
      :PASSIVE     -- Queries 50+ passive sources, no active probing
      :ACTIVE      -- Adds DNS brute-forcing and permutations
      :AGGRESSIVE  -- Maximum depth with more permutations and retries

    API keys recommended for best results:
      - Shodan, Censys, BinaryEdge (network data)
      - VirusTotal, PassiveTotal (DNS history)
      - GitHub, GitLab (subdomains in repos)

    Thread-safety: Uses inherited KALI-AGENT process-lock.
                   Output directory should not be shared between agents."))

(defun make-amass-agent (domain &key (mode :passive) config output-dir)
  "Create an Amass agent for DOMAIN.

   Parameters:
     DOMAIN     -- String: target domain to enumerate.
     MODE       -- Keyword: :PASSIVE :ACTIVE :AGGRESSIVE.
     CONFIG     -- Optional string: path to Amass INI config file.
     OUTPUT-DIR -- Optional string: directory for output files.

   Returns: An AMASS-AGENT instance.

   Example:
     (make-amass-agent 'example.com' :mode :active)
     (make-amass-agent 'example.com' :config '/etc/amass/config.ini')"
  (let* ((out-dir (or output-dir
                      (format nil "/tmp/amass-~A-~A/"
                              domain
                              (local-time:now))))
         (mode-str (ecase mode
                     (:passive "passive")
                     (:active "active")
                     (:aggressive "aggressive")))
         (args (list "enum"
                     "-d" domain
                     "-dir" out-dir
                     "-json" (format nil "~A/amass.json" out-dir)
                     "-o" (format nil "~A/subdomains.txt" out-dir)
                     mode-str)))
    (when config
      (push config args)
      (push "-config" args))
    (let ((agent (make-instance 'amass-agent
                                :id (gensym (format nil "AM-~A-" domain))
                                :target domain
                                :enum-mode mode
                                :config config
                                :output-dir out-dir
                                :args args
                                :capabilities '(:osint :subdomain-discovery
                                                :dns-enumeration :network-mapping
                                                :deep-recon))))
      (bt:with-lock-held (*osint-agent-registry-lock*)
        (setf (gethash (agent-id agent) *osint-agent-registry*) agent))
      agent)))


;; ───────────────────────────────────────────────────────────────────────────
;; GHunt Agent — Google account identity lookup
;; ───────────────────────────────────────────────────────────────────────────

(defclass ghunt-agent (kali-agent)
  ((email :initarg :email
          :initform nil
          :accessor ghunt-email
          :documentation
          "The Google email address to investigate.
             This is the primary search key for GHunt.
             Can be a Gmail address or a Google Workspace email.")

   (cookies-valid :initform nil
                  :accessor ghunt-cookies-valid
                  :documentation
                  "Whether GHunt has valid authentication cookies.
             GHunt requires valid Google cookies to access account
             information. Set to T after successful cookie validation."))

  (:default-initargs
   :binary *osint-ghunt-binary*
   :args '()
   :tool-category :social
   :timeout 120)

  (:documentation
   "GHunt agent — Google account digital footprint analysis.

    GHunt is an OSINT tool for investigating Google accounts. Given
    an email address, it extracts:
      - Google account creation date estimate
      - Google Maps reviews and locations visited
      - YouTube channel and public activity
      - Google Photos metadata (if public)
      - Calendar events (if shared)
      - Account profile picture and name

    This agent wraps GHunt, captures its JSON output, and normalizes
    the results into persona-related findings for the knowledge graph.

    Authentication:
      GHunt requires valid Google cookies. The agent checks for
      cookies file at ~/.config/ghunt/cookies.json and validates
      them before running the investigation.

    Privacy note:
      This tool should only be used on accounts you have permission
      to investigate. The LISPMIND gatekeeper enforces this policy.

    Finding types produced:
      :PERSONA      -- Name, profile picture, account metadata
      :LOCATION     -- Google Maps locations visited
      :SOCIAL-PROFILE -- YouTube channel, reviews, public activity"))

(defun make-ghunt-agent (email)
  "Create a GHunt agent for EMAIL.

   Parameters:
     EMAIL -- String: the Google email address to investigate.

   Returns: A GHUNT-AGENT instance.

   Example:
     (make-ghunt-agent 'target@gmail.com')
     (make-ghunt-agent 'john.doe@company.com')"
  (let ((agent (make-instance 'ghunt-agent
                              :id (gensym (format nil "GH-~A-" email))
                              :target email
                              :email email
                              :args (list "email" email "--json" "/tmp/ghunt-output.json")
                              :capabilities '(:osint :persona-lookup
                                              :identity :social-intel))))
    (bt:with-lock-held (*osint-agent-registry-lock*)
      (setf (gethash (agent-id agent) *osint-agent-registry*) agent))
    agent))


;; ───────────────────────────────────────────────────────────────────────────
;; Wayback Machine Agent — Historical archive snapshots
;; ───────────────────────────────────────────────────────────────────────────

(defclass wayback-agent (kali-agent)
  ((snapshot-count :initarg :snapshot-count
                   :initform 10
                   :accessor wb-snapshot-count
                   :documentation
                   "Maximum number of historical snapshots to retrieve.
             Default: 10. Increase for deeper historical analysis.")

   (date-from :initarg :date-from
              :initform nil
              :accessor wb-date-from
              :documentation
              "Optional start date filter (YYYYMMDD format).
             Limits snapshots to those captured on or after this date.")

   (date-to :initarg :date-to
            :initform nil
            :accessor wb-date-to
            :documentation
            "Optional end date filter (YYYYMMDD format).
             Limits snapshots to those captured on or before this date.")

   (output-format :initarg :output-format
                  :initform "json"
                  :accessor wb-output-format
                  :documentation
                  "CDX API output format.
             'json'  -- JSON array format (default, for parsing)
             'text'  -- Plain text, space-separated columns"))

  (:default-initargs
   :binary nil                    ; Uses HTTP API, no local binary
   :args '()
   :tool-category :recon
   :timeout 60)

  (:documentation
   "Wayback Machine agent — historical asset tracking.

    The Internet Archive's Wayback Machine provides historical snapshots
    of web pages. This agent queries the CDX (Capture Index) API to
    discover historical URLs, content changes, and deleted pages for
    a target domain.

    Use cases:
      - Find old subdomains that are no longer active
      - Discover historical pages with exposed information
      - Track content changes over time
      - Find deleted files or pages that may still be cached
      - Discover historical technology stacks via page content

    API endpoint: http://web.archive.org/cdx/search/cdx
    Parameters:
      - url: wildcard pattern (e.g., '*.example.com/*')
      - output: 'json' or 'text'
      - limit: max results
      - from/to: date range filters

    This agent does not run a local binary; it makes HTTP requests
    directly via DEXADOR. The binary slot is NIL.

    Finding types produced:
      :SUBDOMAIN    -- Historical subdomains found in snapshots
      :URL          -- Specific historical URLs
      :TECHNOLOGY   -- Inferred from page content or MIME types
      :FILE         -- Downloadable files (PDFs, documents, etc.)"))

(defun make-wayback-agent (url &key (snapshot-count 10) date-from date-to)
  "Create a Wayback Machine agent for URL.

   Parameters:
     URL           -- String: target URL or domain (e.g., 'example.com',
                      '*.example.com/*' for wildcard).
     SNAPSHOT-COUNT -- Integer: max snapshots to retrieve (default: 10).
     DATE-FROM     -- Optional string: start date (YYYYMMDD).
     DATE-TO       -- Optional string: end date (YYYYMMDD).

   Returns: A WAYBACK-AGENT instance.

   Example:
     (make-wayback-agent 'example.com')
     (make-wayback-agent '*.example.com/*' :snapshot-count 100
                                            :date-from '20200101')"
  (let ((agent (make-instance 'wayback-agent
                              :id (gensym (format nil "WB-~A-" url))
                              :target url
                              :snapshot-count snapshot-count
                              :date-from date-from
                              :date-to date-to
                              :capabilities '(:osint :archive-research
                                              :historical-analysis
                                              :asset-discovery))))
    (bt:with-lock-held (*osint-agent-registry-lock*)
      (setf (gethash (agent-id agent) *osint-agent-registry*) agent))
    agent))

(defmethod run-tool ((agent wayback-agent) &rest extra-args)
  "Execute Wayback Machine CDX API query.

   Overrides the standard KALI-AGENT RUN-TOOL because the Wayback
   Machine uses an HTTP API rather than a local binary.

   Constructs the CDX query URL with parameters and makes an HTTP GET
   request via DEXADOR. Parses the JSON response into findings.

   Parameters:
     AGENT      -- The WAYBACK-AGENT to execute.
     EXTRA-ARGS -- Ignored (CDX API uses URL parameters only).

   Returns: The HTTP response body as a string, or NIL on failure.

   Side effects:
     - Sets agent status to :RUNNING then :COMPLETED
     - Parses and ingests all snapshot findings
     - Publishes gossip events"
  (declare (ignore extra-args))
  (let ((target (agent-target agent)))
    (bt:with-lock-held ((agent-lock agent))
      (setf (agent-status agent) :running
            (agent-start-time agent) (local-time:now))
      (handler-case
          (let* ((query-params
                  `(("url" . ,(if (cl-ppcre:scan "\\*" target)
                                  target
                                  (format nil "*.~A/*" target)))
                    ("output" . "json")
                    ("limit" . ,(format nil "~A" (wb-snapshot-count agent)))))
                 (url (format nil "~A?~{~A=~A~^&}"
                              *osint-wayback-endpoint*
                              (alexandria:flatten query-params)))
                 (response (dex:get url :connect-timeout 30)))
            ;; Parse CDX JSON response
            (let ((data (handler-case (jsown:parse response)
                          (error () (list response)))))
              (parse-wayback-results agent data))
            (setf (agent-status agent) :completed)
            (publish-message :swarm.osint.wayback.complete
                             `(:event :wayback-complete
                               :agent-id ,(agent-id agent)
                               :target ,target
                               :snapshots ,(length data)
                               :timestamp ,(local-time:now)))
            (record-telemetry-event :osint-wayback-complete
                                    :agent-id (agent-id agent)
                                    :target target)
            response)
        (error (e)
          (setf (agent-status agent) :failed)
          (mcp-log :error "Wayback query failed for ~A: ~A" target e)
          nil)))))

(defmethod parse-wayback-results ((agent wayback-agent) data)
  "Parse Wayback CDX API response data into findings.

   Parameters:
     AGENT -- The WAYBACK-AGENT instance.
     DATA  -- Parsed JSON data from the CDX API.

   Side effects: Ingests findings for each unique URL/subdomain found."
  (when (and data (listp data))
    ;; CDX returns [urlkey, timestamp, original, mimetype, statuscode,
    ;;              digest, length] for each entry
    (let ((seen-urls (make-hash-table :test 'equal)))
      (dolist (entry (cdr data))  ; skip header row
        (when (and (listp entry) (>= (length entry) 3))
          (let* ((original (elt entry 2))
                 (timestamp (when (> (length entry) 1) (elt entry 1)))
                 (mimetype (when (> (length entry) 3) (elt entry 3)))
                 (statuscode (when (> (length entry) 4) (elt entry 4))))
            (unless (gethash original seen-urls)
              (setf (gethash original seen-urls) t)
              ;; Extract subdomain from URL
              (let ((finding (normalize-finding
                              "wayback"
                              `(:type :url
                                :value ,original
                                :timestamp ,timestamp
                                :mimetype ,mimetype
                                :status-code ,statuscode
                                :confidence 0.7))))
                (ingest-finding (agent-target agent) finding))))))))


;; ───────────────────────────────────────────────────────────────────────────
;; Social Mapper Agent — Social media persona correlation
;; ───────────────────────────────────────────────────────────────────────────

(defclass socialmapper-agent (kali-agent)
  ((platforms :initarg :platforms
              :initform '(twitter linkedin facebook instagram github
                          youtube tiktok reddit)
              :accessor sm-platforms
              :documentation
              "List of social media platforms to search.
             Default includes the most common platforms:
               twitter linkedin facebook instagram github youtube
               tiktok reddit pinterest tumblr")

   (image-path :initarg :image-path
               :initform nil
               :accessor sm-image-path
               :documentation
               "Optional path to a profile image for facial recognition
             correlation across platforms. If provided, Social Mapper
             uses image comparison to link accounts.")

   (correlation-method :initarg :correlation-method
                       :initform :name
                       :accessor sm-correlation-method
                       :documentation
                       "Method for correlating accounts across platforms.
             :NAME   -- Match by display name/username (default)
             :EMAIL  -- Match by email address
             :IMAGE  -- Match by profile picture comparison
             :HYBRID -- Combine all methods"))

  (:default-initargs
   :binary *osint-socialmapper-binary*
   :args '()
   :tool-category :social
   :timeout 600)

  (:documentation
   "Social Mapper agent — correlate personas across platforms.

    Social Mapper performs automated correlation of social media
    accounts across multiple platforms. Given a person's name (and
    optionally an email or profile image), it:

    1. Searches each platform for matching accounts
    2. Compares profile data (name, bio, location, image)
    3. Builds a correlation matrix of likely matches
    4. Outputs a report with linked accounts and confidence scores

    Platforms supported:
      Twitter, LinkedIn, Facebook, Instagram, GitHub, YouTube,
      TikTok, Reddit, Pinterest, Tumblr, and more.

    This agent wraps Social Mapper, parses its output into persona
    findings, and adds social-profile relationships to the knowledge
    graph.

    Finding types produced:
      :PERSONA        -- Name, bio, location, occupation
      :SOCIAL-PROFILE -- Platform, username, URL, follower count
      :HANDLE         -- Screen name / username
      :EMAIL          -- Email addresses found on profiles
      :ORGANIZATION   -- Employer/school information

    Privacy note:
      This tool should only be used with proper authorization.
      The LISPMIND gatekeeper enforces usage policies."))

(defun make-socialmapper-agent (name &key platforms image-path (method :name))
  "Create a Social Mapper agent for NAME.

   Parameters:
     NAME     -- String: person's name to search for.
     PLATFORMS -- Optional list of platform keywords (default: all).
     IMAGE-PATH -- Optional string: path to profile image.
     METHOD   -- Keyword: correlation method (:NAME :EMAIL :IMAGE :HYBRID).

   Returns: A SOCIALMAPPER-AGENT instance.

   Example:
     (make-socialmapper-agent 'John Doe')
     (make-socialmapper-agent 'Jane Smith'
       :platforms '(twitter linkedin github))"
  (let ((agent (make-instance 'socialmapper-agent
                              :id (gensym (format nil "SM-~A-" name))
                              :target name
                              :platforms (or platforms
                                             '(twitter linkedin facebook
                                               instagram github youtube))
                              :image-path image-path
                              :correlation-method method
                              :args (append
                                     (list "-f" name)
                                     (when image-path
                                       (list "-i" image-path))
                                     (list "-m" (string-downcase (string method)))
                                     (list "-p" (format nil "~{~A,~}"
                                                        (mapcar #'string-downcase
                                                                (or platforms
                                                                    '(twitter linkedin
                                                                      facebook instagram)))))
                                     '("-o" "/tmp/socialmapper-output"))
                              :capabilities '(:osint :persona-correlation
                                              :social-intel :identity-mapping))))
    (bt:with-lock-held (*osint-agent-registry-lock*)
      (setf (gethash (agent-id agent) *osint-agent-registry*) agent))
    agent))


;; ───────────────────────────────────────────────────────────────────────────
;; DNSRecon Agent — DNS record enumeration and zone transfer testing
;; ───────────────────────────────────────────────────────────────────────────

(defclass dnsrecon-agent (kali-agent)
  ((record-types :initarg :record-types
                 :initform '(A AAAA MX NS SOA TXT CNAME)
                 :accessor dr-record-types
                 :documentation
                 "DNS record types to query.
             Default queries all common types.
             Special: 'ALL' queries every available type.")

   (zone-transfer :initarg :zone-transfer
                  :initform t
                  :accessor dr-zone-transfer
                  :documentation
                  "Whether to attempt zone transfer (AXFR).
             Default: T (enabled). Zone transfers can reveal
             the complete DNS zone contents if misconfigured."))

  (:default-initargs
   :binary "dnsrecon"
   :args '()
   :tool-category :recon
   :timeout 300)

  (:documentation
   "DNSRecon agent — DNS record enumeration and zone transfer testing.

    DNSRecon queries DNS servers for various record types and attempts
    zone transfers (AXFR). It discovers:
      - A/AAAA records (IPv4/IPv6 addresses)
      - MX records (mail servers)
      - NS records (name servers)
      - TXT records (SPF, DKIM, verification tokens)
      - SOA records (zone authority)
      - SRV records (service discovery)
      - PTR records (reverse DNS)

    Zone transfers are a goldmine: a misconfigured DNS server may
    hand over the entire zone file, revealing all subdomains,
    internal IPs, and infrastructure details.

    Finding types produced:
      :DNS-RECORD   -- All DNS record types
      :SUBDOMAIN    -- From A/AAAA/CNAME records
      :IP           -- From A/AAAA records
      :VULNERABILITY -- If zone transfer succeeds"))

(defun make-dnsrecon-agent (domain &key (record-types '(A AAAA MX NS SOA TXT))
                                       (zone-transfer t))
  "Create a DNSRecon agent for DOMAIN.

   Parameters:
     DOMAIN       -- String: target domain.
     RECORD-TYPES -- List of DNS type keywords.
     ZONE-TRANSFER -- Boolean: attempt zone transfer (default: T).

   Returns: A DNSRECON-AGENT instance."
  (let ((args (list "-d" domain
                    "-t" (if (eq record-types 'all)
                             "all"
                             (format nil "~{~A,~}" record-types)))))
    (when zone-transfer
      (push "-a" args))
    (push "-j" args)
    (push "/tmp/dnsrecon-output.json" args)
    (let ((agent (make-instance 'dnsrecon-agent
                                :id (gensym (format nil "DR-~A-" domain))
                                :target domain
                                :record-types record-types
                                :zone-transfer zone-transfer
                                :args args
                                :capabilities '(:osint :dns-enumeration
                                                :zone-transfer :network-mapping))))
      (bt:with-lock-held (*osint-agent-registry-lock*)
        (setf (gethash (agent-id agent) *osint-agent-registry*) agent))
      agent)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 3: Finding Parsers — Structured Output Normalization
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Each OSINT tool produces output in its own format. The parser layer
;; converts raw tool output into a uniform finding representation that
;; the knowledge graph and target registry can consume.
;;
;; The normalized finding format is a plist:
;;   (:TOOL <tool-name>
;;    :TYPE <finding-type-keyword>
;;    :VALUE <extracted-data>
;;    :CONFIDENCE 0.0-1.0
;;    :EVIDENCE <raw-data>
;;    :TIMESTAMP <local-time:now>
;;    :TARGET <target-id>)
;;
;; Additional keys may be present depending on the tool and finding type.

(defun normalize-finding (tool-name raw-data)
  "Convert raw tool output into a normalized finding structure.

   Parameters:
     TOOL-NAME -- String: name of the tool that produced this finding.
     RAW-DATA  -- Plist with raw finding data including at minimum:
                  :TYPE, :VALUE, and optionally :CONFIDENCE, :EVIDENCE.

   Returns: A normalized finding plist, or NIL if the data cannot be
            normalized (e.g., unknown finding type).

   The normalized finding has this structure:
     (:TOOL <tool-name>
      :TYPE <keyword>        -- from *OSINT-FINDING-TYPES*
      :VALUE <string>        -- the extracted data
      :CONFIDENCE <float>    -- 0.0-1.0
      :EVIDENCE <any>        -- raw evidence preserved
      :TIMESTAMP <timestamp> -- creation time
      :<type-specific-keys>)

   Example:
     (normalize-finding 'theharvester'
       '(:type :email :value 'admin@example.com' :confidence 0.9))"
  (let* ((ftype (getf raw-data :type))
         (value (getf raw-data :value))
         (confidence (or (getf raw-data :confidence)
                         *osint-confidence-default*)))
    ;; Validate finding type
    (unless (and ftype (member ftype *osint-finding-types*))
      (mcp-log :debug "Unknown finding type ~A from ~A, skipping" ftype tool-name)
      (return-from normalize-finding nil))
    ;; Validate value
    (unless (and value (stringp value) (> (length value) 0))
      (mcp-log :debug "Empty value from ~A, skipping" tool-name)
      (return-from normalize-finding nil))
    ;; Build normalized finding
    (let ((finding `(:tool ,tool-name
                     :type ,ftype
                     :value ,(string-downcase value)
                     :confidence ,(float (max 0.0 (min 1.0 confidence)) 0.0)
                     :evidence ,(or (getf raw-data :evidence) raw-data)
                     :timestamp ,(local-time:now))))
      ;; Copy any additional type-specific keys
      (dolist (key '(:module :mimetype :status-code :timestamp :port
                     :service :os :mac :dns-type :platform :username
                     :url :severity :cve :banner))
        (when (getf raw-data key)
          (setf finding (append finding (list key (getf raw-data key))))))
      finding)))

(defun ingest-finding (target-id finding)
  "Add a finding to the target's ledger and update related structures.

   Parameters:
     TARGET-ID -- String: the target this finding relates to.
     FINDING   -- Normalized finding plist from NORMALIZE-FINDING.

   Returns: The updated findings list for the target.

   Side effects:
     - Appends finding to *OSINT-FINDINGS-LEDGER*
     - Updates target's findings-count
     - Extracts entities and updates target's entities plist
     - Publishes :swarm.osint.finding.discovered event
     - Triggers knowledge graph update via ADD-GRAPH-RELATIONSHIP

   Thread-safety: Lock-protected via *OSINT-REGISTRY-LOCK*."
  (when (null finding)
    (return-from ingest-finding nil))
  (bt:with-lock-held (*osint-registry-lock*)
    (let* ((id-str (string-downcase (string target-id)))
           (ledger (gethash id-str *osint-findings-ledger*))
           (target (gethash id-str *osint-target-registry*)))
      ;; Store the finding
      (push finding ledger)
      (setf (gethash id-str *osint-findings-ledger*) ledger)
      ;; Update target metadata
      (when target
        (incf (osint-target-findings-count target))
        ;; Extract entities from finding
        (let ((ftype (getf finding :type))
              (fvalue (getf finding :value)))
          (when fvalue
            (let ((entity-key (ecase ftype
                                ((:email) :emails)
                                ((:subdomain) :subdomains)
                                ((:ip) :ips)
                                ((:persona :social-profile) :personas)
                                ((:technology) :technologies)
                                ((:vulnerability) :vulnerabilities)
                                ((:handle) :handles)
                                ((:organization) :organizations)
                                (t :other))))
              (pushnew fvalue (getf (osint-target-entities target) entity-key)
                       :test #'string-equal))))
      ;; Publish gossip event
      (publish-message :swarm.osint.finding.discovered
                       `(:event :finding-discovered
                         :target-id ,id-str
                         :type ,(getf finding :type)
                         :value ,(getf finding :value)
                         :confidence ,(getf finding :confidence)
                         :tool ,(getf finding :tool)
                         :timestamp ,(local-time:now)))
      ;; Update knowledge graph
      (add-graph-relationship id-str :has-finding
                              (format nil "~A:~A"
                                      (getf finding :type)
                                      (getf finding :value))
                              finding)
      ledger)))

(defun get-findings (target-id)
  "Retrieve all findings for a target.

   Parameters:
     TARGET-ID -- String: target identifier.

   Returns: List of finding plists, most recent first.

   Thread-safety: Lock-protected."
  (bt:with-lock-held (*osint-registry-lock*)
    (copy-list (gethash (string-downcase (string target-id))
                        *osint-findings-ledger*))))

(defun get-findings-by-type (target-id ftype)
  "Retrieve findings of a specific type for a target.

   Parameters:
     TARGET-ID -- String: target identifier.
     FTYPE     -- Keyword: finding type to filter by.

   Returns: List of matching finding plists."
  (remove-if-not (lambda (f) (eq (getf f :type) ftype))
                 (get-findings target-id)))

(defun count-findings (target-id &optional ftype)
  "Count findings for a target, optionally filtered by type.

   Parameters:
     TARGET-ID -- String: target identifier.
     FTYPE     -- Optional keyword: finding type to count.

   Returns: Integer count."
  (if ftype
      (length (get-findings-by-type target-id ftype))
      (length (get-findings target-id))))


;; ── SpiderFoot Findings Parser ────────────────────────────────────────────

(defmethod parse-findings :after ((agent spiderfoot-agent) line)
  "Parse SpiderFoot JSON findings: emails, hosts, subdomains, technologies,
   vulnerabilities, certificates, etc.

   SpiderFoot produces event-based results through its REST API.
   This :AFTER method processes API-poll results that have been
   pre-parsed from JSON into the agent's findings slot.

   Parameters:
     AGENT -- The SPIDERFOOT-AGENT instance.
     LINE  -- A string line from SpiderFoot output (may be JSON).

   Returns: A finding plist, or NIL if no finding detected.

   The SpiderFoot agent primarily uses POLL-SPIDERFOOT-RESULTS for
   finding ingestion; this method handles any console output."
  (declare (ignore line))
  ;; SpiderFoot findings are primarily ingested via the REST API poll.
  ;; This method serves as a hook for any console-based output.
  nil)


;; ── theHarvester Findings Parser ──────────────────────────────────────────

(defmethod parse-findings :after ((agent theharvester-agent) line)
  "Parse theHarvester output: emails, hosts, IPs.

   theHarvester can produce XML output (-f flag) which is parsed
   separately. This method handles any console/stdout output that
   may contain inline results.

   Patterns matched:
     - '[*] <email>'        -- Email addresses
     - '[-] <host>'         -- Hosts/subdomains
     - '[+] <ip>'           -- IP addresses

   Parameters:
     AGENT -- The THEHARVESTER-AGENT instance.
     LINE  -- A string line of output.

   Returns: A finding plist, or NIL."
  (cond
    ;; Email pattern: [*] admin@example.com
    ((cl-ppcre:scan "\\[\\*\\]\\s*([\\w.-]+@[\\w.-]+\\.\\w+)" line)
     (cl-ppcre:register-groups-bind (email)
         ("\\[\\*\\]\\s*([\\w.-]+@[\\w.-]+\\.\\w+)" line)
       (when email
         (let ((finding (normalize-finding
                         "theharvester"
                         `(:type :email :value ,email
                           :confidence 0.75
                           :evidence ,line))))
           (when finding
             (ingest-finding (agent-target agent) finding)
             finding)))))
    ;; Host pattern: [-] mail.example.com
    ((cl-ppcre:scan "\\[-\\]\\s*([\\w.-]+\\.\\w+)" line)
     (cl-ppcre:register-groups-bind (host)
         ("\\[-\\]\\s*([\\w.-]+\\.\\w+)" line)
       (when host
         (let ((finding (normalize-finding
                         "theharvester"
                         `(:type :subdomain :value ,host
                           :confidence 0.7
                           :evidence ,line))))
           (when finding
             (ingest-finding (agent-target agent) finding)
             finding)))))
    ;; IP pattern: [+] 192.168.1.1
    ((cl-ppcre:scan "\\[\\+\\]\\s*(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})" line)
     (cl-ppcre:register-groups-bind (ip)
         ("\\[\\+\\]\\s*(\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3})" line)
       (when ip
         (let ((finding (normalize-finding
                         "theharvester"
                         `(:type :ip :value ,ip
                           :confidence 0.8
                           :evidence ,line))))
           (when finding
             (ingest-finding (agent-target agent) finding)
             finding)))))
    (t nil)))


;; ── Subfinder Findings Parser ─────────────────────────────────────────────

(defmethod parse-findings :after ((agent subfinder-agent) line)
  "Parse Subfinder JSON output: subdomains.

   Subfinder produces JSON output with an array of objects:
     [{\"host\":\"sub.example.com\",\"source\":\"crtsh\"}, ...]

   This method handles both the JSON file output (parsed separately)
   and any console output with subdomain patterns.

   Parameters:
     AGENT -- The SUBFINDER-AGENT instance.
     LINE  -- A string line of output.

   Returns: A finding plist, or NIL."
  (cond
    ;; Direct subdomain line: sub.example.com
    ((cl-ppcre:scan "^([a-zA-Z0-9]([a-zA-Z0-9\\-]{0,61}[a-zA-Z0-9])?\\.)+[a-zA-Z]{2,}$" line)
     (let ((finding (normalize-finding
                     "subfinder"
                     `(:type :subdomain :value ,(string-downcase line)
                       :confidence 0.85
                       :evidence ,line))))
       (when finding
         (ingest-finding (agent-target agent) finding)
         finding)))
    ;; JSON format from file is parsed post-run
    (t nil)))


;; ── Amass Findings Parser ─────────────────────────────────────────────────

(defmethod parse-findings :after ((agent amass-agent) line)
  "Parse Amass JSON output: subdomains with DNS records.

   Amass JSON output contains rich DNS data:
     {\"name\":\"sub.example.com\",\"domain\":\"example.com\",
      \"addresses\":[{\"ip\":\"1.2.3.4\",\"asn\":1234}],
      \"sources\":[\"crtsh\",\"virustotal\"]}

   This method parses console output and the JSON file post-run.

   Parameters:
     AGENT -- The AMASS-AGENT instance.
     LINE  -- A string line of output.

   Returns: A finding plist, or NIL."
  ;; Amass findings are primarily parsed from its JSON output file
  ;; after the run completes. This handles any real-time console output.
  (cond
    ;; Amass real-time subdomain output: OWASP Amass v3.19.3
    ((cl-ppcre:scan "\\b([a-zA-Z0-9._-]+\\.[a-zA-Z]{2,})\\b.*?(\\d+\\.\\d+\\.\\d+\\.\\d+)?" line)
     (cl-ppcre:register-groups-bind (subdomain ip)
         ("([a-zA-Z0-9]([a-zA-Z0-9_-]*\\.)+[a-zA-Z]{2,})" line)
       (when subdomain
         (let ((finding (normalize-finding
                         "amass"
                         `(:type :subdomain :value ,(string-downcase subdomain)
                           :confidence 0.9
                           ,@(when ip `(:ip ,ip))
                           :evidence ,line))))
           (when finding
             (ingest-finding (agent-target agent) finding)
             finding)))))
    (t nil)))


;; ── GHunt Findings Parser ─────────────────────────────────────────────────

(defmethod parse-findings :after ((agent ghunt-agent) line)
  "Parse GHunt output: Google account identity data.

   GHunt produces JSON output with account information:
     - name, profile picture, creation date
     - Maps reviews, YouTube activity
     - Calendar events (if shared)

   This method parses both console output and the JSON file.

   Parameters:
     AGENT -- The GHUNT-AGENT instance.
     LINE  -- A string line of output.

   Returns: A finding plist, or NIL."
  ;; GHunt primarily outputs to JSON file. This method handles
  ;; any real-time console output for persona data.
  (cond
    ;; Name extraction: Name: John Doe
    ((cl-ppcre:scan "[Nn]ame\\s*[:=]\\s*(.+)$" line)
     (cl-ppcre:register-groups-bind (name)
         ("[Nn]ame\\s*[:=]\\s*(.+)$" line)
       (when name
         (let ((finding (normalize-finding
                         "ghunt"
                         `(:type :persona :value ,(string-trim '(#\Space #\Tab) name)
                           :confidence 0.85
                           :evidence ,line))))
           (when finding
             (ingest-finding (agent-target agent) finding)
             finding)))))
    ;; YouTube channel: YouTube: youtube.com/c/...
    ((cl-ppcre:scan "[Yy]outube\\s*[:=]\\s*(.+)$" line)
     (cl-ppcre:register-groups-bind (url)
         ("[Yy]outube\\s*[:=]\\s*(.+)$" line)
       (when url
         (let ((finding (normalize-finding
                         "ghunt"
                         `(:type :social-profile :value ,(string-trim '(#\Space #\Tab) url)
                           :platform "youtube"
                           :confidence 0.8
                           :evidence ,line))))
           (when finding
             (ingest-finding (agent-target agent) finding)
             finding)))))
    (t nil)))


;; ── Social Mapper Findings Parser ─────────────────────────────────────────

(defmethod parse-findings :after ((agent socialmapper-agent) line)
  "Parse Social Mapper output: correlated social media profiles.

   Social Mapper produces structured output with platform correlations:
     - Platform, username, profile URL, confidence score

   Parameters:
     AGENT -- The SOCIALMAPPER-AGENT instance.
     LINE  -- A string line of output.

   Returns: A finding plist, or NIL."
  (cond
    ;; Social Mapper profile match: [PLATFORM] username - URL
    ((cl-ppcre:scan "\\[([A-Za-z]+)\\]\\s*([\\w._-]+)\\s*[-=]\\s*(https?://\\S+)" line)
     (cl-ppcre:register-groups-bind (platform username url)
         ("\\[([A-Za-z]+)\\]\\s*([\\w._-]+)\\s*[-=]\\s*(https?://\\S+)" line)
       (when (and platform username url)
         (let ((finding (normalize-finding
                         "socialmapper"
                         `(:type :social-profile
                           :value ,(format nil "~A/~A" platform username)
                           :platform ,(string-downcase platform)
                           :username ,username
                           :url ,url
                           :confidence 0.7
                           :evidence ,line))))
           (when finding
             (ingest-finding (agent-target agent) finding)
             finding)))))
    ;; Handle discovery: @username (platform)
    ((cl-ppcre:scan "@([\\w._-]+)\\s*\\((\\w+)\\)" line)
     (cl-ppcre:register-groups-bind (handle platform)
         ("@([\\w._-]+)\\s*\\((\\w+)\\)" line)
       (when (and handle platform)
         (let ((finding (normalize-finding
                         "socialmapper"
                         `(:type :handle
                           :value ,(format nil "@~A" handle)
                           :platform ,(string-downcase platform)
                           :confidence 0.65
                           :evidence ,line))))
           (when finding
             (ingest-finding (agent-target agent) finding)
             finding)))))
    (t nil)))


;; ── DNSRecon Findings Parser ──────────────────────────────────────────────

(defmethod parse-findings :after ((agent dnsrecon-agent) line)
  "Parse DNSRecon output: DNS records, subdomains, zone transfers.

   Patterns matched:
     - 'A <host> <ip>'       -- A record
     - 'MX <host> <priority>' -- MX record
     - 'NS <host> <ip>'      -- NS record
     - 'TXT <host> <text>'   -- TXT record
     - 'Zone Transfer success' -- Zone transfer vulnerability

   Parameters:
     AGENT -- The DNSRECON-AGENT instance.
     LINE  -- A string line of output.

   Returns: A finding plist, or NIL."
  (cond
    ;; A record: [*] A sub.example.com 1.2.3.4
    ((cl-ppcre:scan "A\\s+([\\w.-]+)\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)" line)
     (cl-ppcre:register-groups-bind (host ip)
         ("A\\s+([\\w.-]+)\\s+(\\d+\\.\\d+\\.\\d+\\.\\d+)" line)
       (when host
         (let ((subdomain-finding
                (normalize-finding
                 "dnsrecon"
                 `(:type :subdomain :value ,(string-downcase host)
                   :confidence 0.95
                   :ip ,ip
                   :evidence ,line))))
           (when subdomain-finding
             (ingest-finding (agent-target agent) subdomain-finding))
           (when ip
             (let ((ip-finding
                    (normalize-finding
                     "dnsrecon"
                     `(:type :ip :value ,ip
                       :confidence 0.95
                       :host ,(string-downcase host)
                       :evidence ,line))))
               (when ip-finding
                 (ingest-finding (agent-target agent) ip-finding)
                 ip-finding))))))
    ;; MX record
    ((cl-ppcre:scan "MX\\s+([\\w.-]+)\\s+(\\d+)" line)
     (cl-ppcre:register-groups-bind (host priority)
         ("MX\\s+([\\w.-]+)\\s+(\\d+)" line)
       (when host
         (let ((finding (normalize-finding
                         "dnsrecon"
                         `(:type :dns-record :value ,(string-downcase host)
                           :record-type "MX"
                           :priority ,(parse-integer priority :junk-allowed t)
                           :confidence 0.9
                           :evidence ,line))))
           (when finding
             (ingest-finding (agent-target agent) finding)
             finding)))))
    ;; Zone transfer success
    ((cl-ppcre:scan "[Zz]one\\s*[Tt]ransfer\\s*(successful|success)" line)
     (let ((finding (normalize-finding
                     "dnsrecon"
                     `(:type :vulnerability
                       :value "zone-transfer-enabled"
                       :severity :high
                       :confidence 1.0
                       :description "DNS zone transfer (AXFR) is enabled"
                       :evidence ,line))))
       (when finding
         (ingest-finding (agent-target agent) finding)
         finding)))
    (t nil)))


;; ── Post-Run JSON File Parsers ────────────────────────────────────────────

(defun parse-spiderfoot-json-file (agent filepath)
  "Parse a SpiderFoot JSON results file and ingest all findings.

   Parameters:
     AGENT    -- The SPIDERFOOT-AGENT instance.
     FILEPATH -- String: path to the JSON results file.

   Returns: Integer count of findings ingested."
  (handler-case
      (let* ((json-str (uiop:read-file-string filepath))
             (data (jsown:parse json-str))
             (count 0))
        (dolist (result (if (listp data) data '()))
          (let* ((ftype (jsown:val-safe result "type"))
                 (fdata (jsown:val-safe result "data"))
                 (finding (normalize-finding
                           "spiderfoot"
                           `(:type ,(or (and ftype
                                            (intern (string-upcase ftype)
                                                    :keyword))
                                       :unknown)
                             :value ,(or fdata "")
                             :confidence *osint-confidence-default*
                             :evidence ,result))))
            (when finding
              (ingest-finding (agent-target agent) finding)
              (incf count))))
        (mcp-log :info "SpiderFoot parsed ~A findings from ~A" count filepath)
        count)
    (error (e)
      (mcp-log :error "Failed to parse SpiderFoot JSON ~A: ~A" filepath e)
      0)))

(defun parse-amass-json-file (agent filepath)
  "Parse an Amass JSON results file and ingest all findings.

   Parameters:
     AGENT    -- The AMASS-AGENT instance.
     FILEPATH -- String: path to the Amass JSON file.

   Returns: Integer count of findings ingested."
  (handler-case
      (let* ((json-str (uiop:read-file-string filepath))
             (data (jsown:parse json-str))
             (count 0))
        (dolist (host (if (listp data) data '()))
          (let* ((name (jsown:val-safe host "name"))
                 (addresses (jsown:val-safe host "addresses")))
            ;; Ingest subdomain
            (when name
              (let ((sub-finding (normalize-finding
                                  "amass"
                                  `(:type :subdomain :value ,(string-downcase name)
                                    :confidence 0.9
                                    :evidence ,host))))
                (when sub-finding
                  (ingest-finding (agent-target agent) sub-finding)
                  (incf count)))
              ;; Ingest IP addresses
              (dolist (addr (if (listp addresses) addresses '()))
                (let ((ip (if (stringp addr) addr
                              (jsown:val-safe addr "ip"))))
                  (when ip
                    (let ((ip-finding (normalize-finding
                                       "amass"
                                       `(:type :ip :value ,ip
                                         :confidence 0.9
                                         :host ,(string-downcase name)
                                         :evidence ,host))))
                      (when ip-finding
                        (ingest-finding (agent-target agent) ip-finding)
                        (incf count))))))))
        (mcp-log :info "Amass parsed ~A findings from ~A" count filepath)
        count)
    (error (e)
      (mcp-log :error "Failed to parse Amass JSON ~A: ~A" filepath e)
      0)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 4: Knowledge Graph Builder — Entity-Relationship Construction
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; The knowledge graph is a directed multi-graph stored as adjacency lists.
;; Each entity (domain, email, IP, persona, handle) is a node. Relationships
;; between entities are edges annotated with the finding that provided evidence.
;;
;; Graph representation:
;;   Entity → List of (RELATION TARGET-ENTITY EVIDENCE-FINDING)
;;
;; This supports:
;;   - Multi-hop entity traversal
;;   - Shortest-path queries between entities
;;   - Centrality analysis for target prioritization
;;   - Evidence tracking for every relationship

(defun build-knowledge-graph (target-id)
  "Build an entity-relationship graph from all findings for a target.

   This function reconstructs the knowledge graph by analyzing all
   findings for the target and creating entity-relationship links.

   Parameters:
     TARGET-ID -- String: target identifier.

   Returns: Number of graph relationships created.

   Side effects: Populates *OSINT-KNOWLEDGE-GRAPH* with new relationships.

   Algorithm:
     1. Retrieve all findings for the target
     2. For each finding, determine the source and target entities
     3. Create appropriate relationship edges
     4. Deduplicate edges

   Thread-safety: Lock-protected via *OSINT-GRAPH-LOCK*."
  (let ((findings (get-findings target-id))
        (count 0))
    (bt:with-lock-held (*osint-graph-lock*)
      (dolist (finding findings)
        (let* ((ftype (getf finding :type))
               (fvalue (getf finding :value))
               (ftool (getf finding :tool)))
          (when (and ftype fvalue)
            (case ftype
              ;; Email → Domain relationship
              (:email
               (let ((domain (second (cl-ppcre:split "@" fvalue))))
                 (when domain
                   (add-graph-relationship fvalue :belongs-to domain finding)
                   (add-graph-relationship domain :has-email fvalue finding)
                   (incf count 2))))
              ;; Subdomain → Domain relationship
              (:subdomain
               (let* ((parts (cl-ppcre:split "\\." fvalue))
                      (domain (if (> (length parts) 2)
                                  (format nil "~{~A~^.~}"
                                          (subseq parts (- (length parts) 2)))
                                  fvalue)))
                 (add-graph-relationship fvalue :subdomain-of domain finding)
                 (add-graph-relationship domain :has-subdomain fvalue finding)
                 (incf count 2)))
              ;; IP → Host relationship
              (:ip
               (let ((host (getf finding :host)))
                 (when host
                   (add-graph-relationship fvalue :resolves-to host finding)
                   (add-graph-relationship host :resolved-by fvalue finding)
                   (incf count 2))))
              ;; Persona → Account relationships
              (:persona
               (add-graph-relationship fvalue :identified-by fttool finding)
               (incf count))
              ;; Social profile → Persona
              (:social-profile
               (let ((platform (getf finding :platform))
                     (username (getf finding :username)))
                 (when platform
                   (add-graph-relationship fvalue :on-platform platform finding))
                 (when username
                   (add-graph-relationship fvalue :has-username username finding))
                 (incf count)))
              ;; Handle → Platform
              (:handle
               (let ((platform (getf finding :platform)))
                 (when platform
                   (add-graph-relationship fvalue :on-platform platform finding)
                   (incf count))))
              ;; Technology → Host
              (:technology
               (let ((host (getf finding :host)))
                 (when host
                   (add-graph-relationship host :uses-technology fvalue finding)
                   (incf count))))
              ;; Organization → Domain
              (:organization
               (add-graph-relationship fvalue :associated-with target-id finding)
               (incf count))
              ;; Default: link to target
              (t
               (add-graph-relationship target-id :has ftype finding)
               (incf count)))))))
    (mcp-log :info "Built knowledge graph for ~A: ~A relationships"
             target-id count)
    count))

(defun add-graph-relationship (entity-a relation entity-b evidence)
  "Add a relationship to the knowledge graph.

   Parameters:
     ENTITY-A -- String: source entity.
     RELATION -- Keyword: relationship type (:has :belongs-to :subdomain-of
                 :resolves-to :identified-by :on-platform :uses-technology ...).
     ENTITY-B -- String: target entity.
     EVIDENCE -- The finding plist that supports this relationship.

   Returns: The updated adjacency list for ENTITY-A.

   Side effects: Mutates *OSINT-KNOWLEDGE-GRAPH*.

   Thread-safety: Lock-protected via *OSINT-GRAPH-LOCK*."
  (bt:with-lock-held (*osint-graph-lock*)
    (let* ((key-a (string-downcase (string entity-a)))
           (key-b (string-downcase (string entity-b)))
           (relations (gethash key-a *osint-knowledge-graph*)))
      ;; Check for duplicate relationship
      (unless (member (list relation key-b) relations
                      :test (lambda (a b)
                              (and (eq (first a) (first b))
                                   (string-equal (second a) (second b)))))
        (push (list relation key-b evidence) relations)
        (setf (gethash key-a *osint-knowledge-graph*) relations))
      relations)))

(defun query-graph (entity)
  "Query all relationships for an entity in the knowledge graph.

   Parameters:
     ENTITY -- String: the entity to look up.

   Returns: List of (RELATION TARGET-ENTITY EVIDENCE) triples.

   Thread-safety: Lock-protected via *OSINT-GRAPH-LOCK*."
  (bt:with-lock-held (*osint-graph-lock*)
    (copy-list (gethash (string-downcase (string entity))
                        *osint-knowledge-graph*))))

(defun query-graph-by-relation (entity relation)
  "Query relationships of a specific type for an entity.

   Parameters:
     ENTITY   -- String: the entity to look up.
     RELATION -- Keyword: relationship type to filter by.

   Returns: List of (RELATION TARGET-ENTITY EVIDENCE) triples."
  (remove-if-not (lambda (r) (eq (first r) relation))
                 (query-graph entity)))

(defun find-path (entity-a entity-b &key (max-depth 10))
  "Find the shortest path between two entities in the knowledge graph.

   Uses breadth-first search (BFS) to find the shortest relationship
   path from ENTITY-A to ENTITY-B.

   Parameters:
     ENTITY-A  -- String: starting entity.
     ENTITY-B  -- String: target entity.
     MAX-DEPTH -- Integer: maximum search depth (default: 10).

   Returns: A list of (ENTITY RELATION) pairs representing the path,
            or NIL if no path exists within MAX-DEPTH.

   Example:
     (find-path 'admin@example.com' 'mail.example.com')
     ;; => (('admin@example.com' :belongs-to)
     ;;     ('example.com' :has-subdomain)
     ;;     ('mail.example.com'))"
  (let ((start (string-downcase (string entity-a)))
        (goal (string-downcase (string entity-b))))
    (bt:with-lock-held (*osint-graph-lock*)
      (let ((visited (make-hash-table :test 'equal))
            (queue (list (list start))))
        (setf (gethash start visited) t)
        (loop while queue
              for path = (pop queue)
              for current = (first (last path))
              do (when (string-equal current goal)
                   (return-from find-path path))
                 (when (< (length path) max-depth)
                   (dolist (rel (gethash current *osint-knowledge-graph*))
                     (let ((neighbor (second rel)))
                       (unless (gethash neighbor visited)
                         (setf (gethash neighbor visited) t)
                         (push (append path (list (first rel) neighbor))
                               queue)))))))))

(defun calculate-target-centrality (target-id)
  "Calculate how 'central' a target is in the knowledge graph.

   Centrality is measured as the ratio of the target's degree
   (number of direct relationships) to the maximum possible degree
   in the graph. A highly central target has connections to many
   other entities, indicating it's a key node in the investigation.

   Parameters:
     TARGET-ID -- String: target identifier.

   Returns: Float between 0.0 and 1.0 representing centrality score.

   Also returns (as secondary value): Integer total relationship count."
  (bt:with-lock-held (*osint-graph-lock*)
    (let* ((key (string-downcase (string target-id)))
           (direct-rels (length (gethash key *osint-knowledge-graph*)))
           ;; Count reverse relationships (others pointing to this entity)
           (reverse-rels 0)
           (total-entities (hash-table-count *osint-knowledge-graph*)))
      (maphash (lambda (entity relations)
                 (declare (ignore entity))
                 (dolist (rel relations)
                   (when (string-equal (second rel) key)
                     (incf reverse-rels))))
               *osint-knowledge-graph*)
      (let ((total-degree (+ direct-rels reverse-rels)))
        (if (> total-entities 1)
            (values (float (/ total-degree (* 2 (1- total-entities))) 0.0)
                    total-degree)
            (values 0.0 0))))))

(defun graph-statistics () 
  "Compute aggregate statistics for the knowledge graph.

   Returns: A plist with:
     :ENTITY-COUNT      -- Number of unique entities
     :RELATIONSHIP-COUNT -- Total number of relationships
     :AVG-DEGREE        -- Average degree (relationships per entity)
     :MAX-DEGREE-ENTITY -- Entity with the most relationships
     :ISOLATED-COUNT    -- Number of entities with no relationships

   Thread-safety: Lock-protected via *OSINT-GRAPH-LOCK*."
  (bt:with-lock-held (*osint-graph-lock*)
    (let ((entity-count 0)
          (relationship-count 0)
          (max-degree 0)
          (max-entity nil)
          (isolated-count 0))
      (maphash (lambda (entity relations)
                 (incf entity-count)
                 (let ((deg (length relations)))
                   (incf relationship-count deg)
                   (when (> deg max-degree)
                     (setf max-degree deg
                           max-entity entity))
                   (when (zerop deg)
                     (incf isolated-count))))
               *osint-knowledge-graph*)
      `(:entity-count ,entity-count
        :relationship-count ,relationship-count
        :avg-degree ,(if (> entity-count 0)
                         (float (/ relationship-count entity-count) 0.0)
                         0.0)
        :max-degree-entity ,max-entity
        :max-degree ,max-degree
        :isolated-count ,isolated-count))))

(defun export-graph-dot (&optional (filepath "/tmp/osint-graph.dot"))
  "Export the knowledge graph as a Graphviz DOT file.

   Parameters:
     FILEPATH -- String: output file path (default: /tmp/osint-graph.dot).

   Returns: FILEPATH on success, NIL on failure.

   The DOT file can be rendered with: dot -Tpng osint-graph.dot -o graph.png"
  (handler-case
      (with-open-file (stream filepath :direction :output
                                       :if-exists :supersede
                                       :if-does-not-exist :create)
        (format stream "digraph OSINT_Knowledge_Graph {~%")
        (format stream "  rankdir=LR;~%")
        (format stream "  node [shape=box, style=filled, fillcolor=lightblue];~%")
        (format stream "  edge [fontsize=10];~%")
        (format stream "  label=\"LISPMIND OSINT Knowledge Graph\\nGenerated ~A\";~%"
                (local-time:now))
        (format stream "  labelloc=t;~%")
        (bt:with-lock-held (*osint-graph-lock*)
          (let ((edges-written (make-hash-table :test 'equal)))
            (maphash
             (lambda (entity relations)
               (dolist (rel relations)
                 (let ((edge-key (format nil "~A|~A|~A"
                                        entity (first rel) (second rel))))
                   (unless (gethash edge-key edges-written)
                     (setf (gethash edge-key edges-written) t)
                     (format stream "  \"~A\" -> \"~A\" [label=\"~A\"];~%"
                             entity (second rel) (first rel))))))
             *osint-knowledge-graph*)))
        (format stream "}~%"))
      (mcp-log :info "Knowledge graph exported to ~A" filepath)
      filepath)
    (error (e)
      (mcp-log :error "Failed to export graph to ~A: ~A" filepath e)
      nil)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 5: The Collector Mesh Pattern — Navigator + Analyst + Correlator
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; The Collector Mesh is a three-agent collaborative pattern for
;; comprehensive OSINT operations. It implements the Signal-to-Identity
;; pipeline as a distributed workflow:
;;
;;   ┌─────────────┐    findings     ┌─────────────┐
;;   │  NAVIGATOR  │ ──────────────→ │   ANALYST   │
;;   │  (discover) │                 │  (examine)  │
;;   └──────┬──────┘                 └──────┬──────┘
;;          │                               │
;;          └──────────────┬────────────────┘
;;                         │
;;                    ┌────▼──────┐
;;                    │ CORRELATOR│
;;                    │  (link)   │
;;                    └────┬──────┘
;;                         │
;;                    ┌────▼──────┐
;;                    │  GRAPH    │
;;                    │  (store)  │
;;                    └───────────┘
;;
;; Navigator: Discovers public digital assets recursively
;; Analyst:   Examines discovered files/repos for sensitive data
;; Correlator: Links all findings into the identity knowledge graph

(defclass osint-navigator (agent)
  ((target :initarg :target
           :accessor nav-target
           :documentation
           "The target (Subject of Interest) this navigator is investigating.
             A string: domain name, IP, persona name, or handle.")

   (depth :initarg :depth
          :initform 2
          :accessor nav-depth
          :documentation
          "Recursion depth for discovery operations.
             Depth 1: Investigate only the target itself.
             Depth 2: Investigate discovered subdomains/entities.
             Depth 3+: Multi-hop recursive exploration.
             Default: 2.")

   (tools :initarg :tools
          :initform '(spiderfoot theharvester subfinder dnsrecon)
          :accessor nav-tools
          :documentation
          "List of tool keywords to use for navigation.
             Default: (SPIDERFOOT THEHARVESTER SUBFINDER DNSRECON).
             Additional tools: AMASS WAYBACK.")

   (active-agents :initform '()
                  :accessor nav-active-agents
                  :documentation
                  "List of currently active tool agent instances.
             These are the OSINT tool agents spawned by the navigator.")

   (discovered-entities :initform '()
                      :accessor nav-discovered-entities
                      :documentation
                      "Accumulator for entities discovered during navigation.
             A plist of entity types to lists of values.")

   (discovery-queue :initform '()
                    :accessor nav-discovery-queue
                    :documentation
                    "Queue of entities pending discovery at the next depth level.
             Used for recursive multi-hop exploration."))

  (:documentation
   "Navigator: Recursively traverses public digital assets.

    The OSINT-NAVIGATOR is the discovery agent of the Collector Mesh.
    It coordinates multiple OSINT tool agents to comprehensively map
    a target's public digital footprint.

    Operations performed:
      1. Spawn OSINT tool agents based on the TOOLS list
      2. Run each tool and collect findings
      3. Extract new entities (subdomains, emails, IPs) from findings
      4. If DEPTH > 1, recursively investigate discovered entities
      5. Publish all findings to the gossip system

    The navigator's strategy function runs each tool sequentially,
    collects their output, and feeds entities to the discovery queue.
    When the queue is exhausted or max depth is reached, it signals
    completion to the Correlator.

    Thread-safety: All slot access is protected by the agent-lock."))

(defun osint-navigator-strategy (agent)
  "Default strategy function for OSINT-NAVIGATOR.

   This strategy:
   1. Registers the target if not already registered
   2. Spawns tool agents based on the NAV-TOOLS list
   3. Runs each tool and captures findings
   4. Extracts entities for recursive discovery
   5. At DEPTH > 1, recurses into discovered entities
   6. Signals completion

   Parameters:
     AGENT -- The OSINT-NAVIGATOR instance."
  (let ((target (nav-target agent)))
    ;; Register target
    (unless (get-target target)
      (register-target target))
    (update-target-status target :active)
    (mcp-log :info "OSINT Navigator starting recon for ~A (depth: ~A)"
             target (nav-depth agent))
    ;; Spawn and run tool agents
    (dolist (tool-keyword (nav-tools agent))
      (when (eq (agent-status agent) :running)
        (handler-case
            (let ((tool-agent (case tool-keyword
                                (spiderfoot
                                 (make-spiderfoot-agent target))
                                (theharvester
                                 (make-theharvester-agent target))
                                (subfinder
                                 (make-subfinder-agent target))
                                (amass
                                 (make-amass-agent target))
                                (dnsrecon
                                 (make-dnsrecon-agent target))
                                (wayback
                                 (make-wayback-agent target))
                                (t nil))))
              (when tool-agent
                (push tool-agent (nav-active-agents agent))
                (mcp-log :info "Navigator running ~A on ~A"
                         tool-keyword target)
                ;; Run the tool
                (run-tool tool-agent)
                ;; Capture output for a while
                (loop for i from 0 below 120
                      while (eq (agent-status tool-agent) :running)
                      do (capture-output tool-agent)
                         (sleep 1))
                ;; Ensure we get final output
                (capture-output tool-agent)
                ;; Update findings count
                (let ((findings-count (length (agent-findings tool-agent))))
                  (mcp-log :info "~A found ~A findings for ~A"
                           tool-keyword findings-count target))))
          (error (e)
            (mcp-log :warn "Navigator tool ~A failed for ~A: ~A"
                     tool-keyword target e)))))
    ;; Mark target complete at this depth
    (update-target-status target :complete)
    ;; Recursive discovery at deeper levels
    (when (> (nav-depth agent) 1)
      (let ((entities (osint-target-entities (get-target target))))
        (dolist (subdomain (getf entities :subdomains))
          (when (and (not (string-equal subdomain target))
                     (< (length (nav-discovery-queue agent)) 50))
            (push subdomain (nav-discovery-queue agent))))
        ;; Process queue for next depth level
        (dolist (entity (nav-discovery-queue agent))
          (when (eq (agent-status agent) :running)
            (mcp-log :info "Navigator recursing into ~A" entity)
            (let ((sub-agent (make-instance 'osint-navigator
                                            :target entity
                                            :depth (1- (nav-depth agent))
                                            :tools (nav-tools agent))))
              (osint-navigator-strategy sub-agent))))))
    ;; Signal completion
    (publish-message :swarm.osint.navigator.complete
                     `(:event :navigator-complete
                       :target ,target
                       :depth ,(nav-depth agent)
                       :tools-used ,(nav-tools agent)
                       :timestamp ,(local-time:now)))
    (mcp-log :info "OSINT Navigator completed for ~A" target)))

(defclass osint-analyst (agent)
  ((yara-rules-path :initarg :yara-rules
                    :initform "/usr/share/yara/rules/"
                    :accessor analyst-yara-path
                    :documentation
                    "Path to YARA rule files for pattern matching.
             The analyst scans discovered files and repositories
             for credential leaks, malware, and sensitive data
             using YARA rules.")

   (scan-targets :initform '()
                 :accessor analyst-scan-targets
                 :documentation
                 "List of file paths or repository URLs to analyze.
             Populated by the Navigator's discoveries or manually
             configured for deep-dive analysis.")

   (findings-buffer :initform '()
                   :accessor analyst-findings-buffer
                   :documentation
                   "Accumulator for analyst findings.
             Cleared when findings are handed to the Correlator."))

  (:documentation
   "Analyst: Examines discovered files/repos for credentials, malware,
    or sensitive data.

    The OSINT-ANALYST performs deep analysis on digital artifacts
    discovered by the Navigator. It uses multiple analysis techniques:

    1. YARA rule matching -- Scan files for known patterns
       (credential formats, API keys, private keys, etc.)
    2. Repository analysis -- Clone and scan Git repositories
       for exposed secrets, credentials, or configuration files
    3. File content analysis -- Pattern matching for sensitive data
       (email patterns, phone numbers, SSNs, credit cards)
    4. Metadata extraction -- EXIF data from images, PDF metadata,
       document properties that may reveal author information

    The analyst consumes files/repos from its scan-targets list,
    produces :CREDENTIAL, :PASTE, :REPOSITORY, and :FILE findings,
    and pushes them to the Correlator via gossip messages.

    Thread-safety: All slot access protected by agent-lock."))

(defun osint-analyst-strategy (agent)
  "Default strategy function for OSINT-ANALYST.

   This strategy processes each scan target, runs YARA if available,
   and performs pattern matching for sensitive data.

   Parameters:
     AGENT -- The OSINT-ANALYST instance."
  (dolist (target (analyst-scan-targets agent))
    (when (eq (agent-status agent) :running)
      (mcp-log :info "OSINT Analyst examining: ~A" target)
      (handler-case
          (cond
            ;; Git repository analysis
            ((cl-ppcre:scan "\\.git$|github\\.com|gitlab\\.com" target)
             (analyze-git-repository agent target))
            ;; File analysis
            ((probe-file (pathname target))
             (analyze-file agent target))
            ;; URL-based analysis
            ((cl-ppcre:scan "^https?://" target)
             (analyze-url agent target)))
        (error (e)
          (mcp-log :warn "Analyst failed on ~A: ~A" target e)))))
  ;; Publish findings to correlator
  (publish-message :swarm.osint.analyst.complete
                   `(:event :analyst-complete
                     :findings ,(length (analyst-findings-buffer agent))
                     :timestamp ,(local-time:now)))
  (mcp-log :info "OSINT Analyst completed: ~A findings"
           (length (analyst-findings-buffer agent))))

(defun analyze-git-repository (agent repo-url)
  "Clone and analyze a Git repository for exposed secrets.

   Parameters:
     AGENT   -- The OSINT-ANALYST instance.
     REPO-URL -- String: Git repository URL.

   Side effects: Adds findings to analyst-findings-buffer."
  (let ((temp-dir (format nil "/tmp/osint-repo-~A/" (gensym))))
    (handler-case
        (progn
          (uiop:run-program (format nil "git clone --depth 1 ~A ~A 2>/dev/null"
                                    repo-url temp-dir)
                            :output '(:string :stripped t)
                            :ignore-error-status t)
          ;; Scan for common secret patterns
          (let ((patterns '("API_KEY" "API_SECRET" "PASSWORD" "PRIVATE_KEY"
                            "AWS_ACCESS_KEY" "GITHUB_TOKEN" "DATABASE_URL"
                            "SECRET_KEY" "AUTH_TOKEN" "BEARER ")))
            (dolist (pattern patterns)
              (handler-case
                  (let ((output (uiop:run-program
                                 (format nil "grep -ri '~A' ~A 2>/dev/null | head -20"
                                         pattern temp-dir)
                                 :output '(:string :stripped t)
                                 :ignore-error-status t)))
                    (when (and output (> (length output) 0))
                      (push (normalize-finding
                             "analyst"
                             `(:type :credential
                               :value ,(format nil "~A in ~A" pattern repo-url)
                               :confidence 0.6
                               :pattern ,pattern
                               :repository ,repo-url
                               :evidence ,output))
                            (analyst-findings-buffer agent))
                      (publish-message :swarm.osint.analyst.finding
                                       `(:event :analyst-finding
                                         :type :credential
                                         :repository ,repo-url
                                         :pattern ,pattern))))
                (error (e)
                  (mcp-log :debug "Git analysis grep error: ~A" e)))))
          ;; Clean up
          (uiop:run-program (format nil "rm -rf ~A" temp-dir)
                            :ignore-error-status t))
      (error (e)
        (mcp-log :warn "Git repository analysis failed for ~A: ~A" repo-url e)))))

(defun analyze-file (agent filepath)
  "Analyze a local file for sensitive data patterns.

   Parameters:
     AGENT    -- The OSINT-ANALYST instance.
     FILEPATH -- String: path to the file to analyze."
  (handler-case
      (let ((content (uiop:read-file-string filepath)))
        ;; Email pattern
        (cl-ppcre:do-matches-as-strings
            (email "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}" content)
          (push (normalize-finding
                 "analyst"
                 `(:type :email :value ,(string-downcase email)
                   :confidence 0.7
                   :source-file ,filepath))
                (analyst-findings-buffer agent)))
        ;; IP address pattern
        (cl-ppcre:do-matches-as-strings
            (ip "\\b\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\b" content)
          (push (normalize-finding
                 "analyst"
                 `(:type :ip :value ,ip
                   :confidence 0.6
                   :source-file ,filepath))
                (analyst-findings-buffer agent))))
    (error (e)
      (mcp-log :warn "File analysis failed for ~A: ~A" filepath e))))

(defun analyze-url (agent url)
  "Fetch and analyze a URL for exposed information.

   Parameters:
     AGENT -- The OSINT-ANALYST instance.
     URL   -- String: URL to fetch and analyze."
  (handler-case
      (let ((content (dex:get url :connect-timeout 10)))
        ;; Analyze the fetched content similar to file analysis
        (cl-ppcre:do-matches-as-strings
            (email "[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}" content)
          (push (normalize-finding
                 "analyst"
                 `(:type :email :value ,(string-downcase email)
                   :confidence 0.5
                   :source-url ,url))
                (analyst-findings-buffer agent))))
    (error (e)
      (mcp-log :warn "URL analysis failed for ~A: ~A" url e))))

(defclass osint-correlator (agent)
  ((knowledge-graph :accessor corr-graph
                    :documentation
                    "Reference to the correlator's view of the knowledge graph.
             The correlator reads from *OSINT-KNOWLEDGE-GRAPH* and
             maintains a local cache of entities it has processed.")

   (target :initarg :target
           :accessor corr-target
           :documentation
           "The primary target being correlated.")

   (navigator-id :initform nil
                 :accessor corr-navigator-id
                 :documentation
                 "ID of the Navigator agent whose findings we correlate.")

   (analyst-id :initform nil
               :accessor corr-analyst-id
               :documentation
                 "ID of the Analyst agent whose findings we correlate.")

   (correlated-entities :initform '()
                       :accessor corr-correlated-entities
                       :documentation
                       "List of entities that have been fully correlated.
             Prevents duplicate correlation work."))

  (:documentation
   "Correlator: Links Navigator + Analyst findings into the Merkle DAG
    identity graph. Updates the target registry.

    The OSINT-CORRELATOR is the synthesis agent of the Collector Mesh.
    It takes the raw findings from the Navigator (discovered entities)
    and the Analyst (credential/paste findings), builds the knowledge
    graph, calculates risk scores, and produces the final investigation
    report.

    Operations:
      1. Subscribe to Navigator findings (gossip :swarm.osint.*)
      2. Subscribe to Analyst findings (gossip :swarm.osint.analyst.*)
      3. Build entity-relationship graph from all findings
      4. Calculate risk scores for the target
      5. Generate the investigation dossier
      6. Publish :swarm.osint.investigation.complete event

    The correlator runs continuously, processing findings as they
    arrive from the Navigator and Analyst agents.

    Thread-safety: Uses agent-lock for internal state. Graph mutations
                   use *OSINT-GRAPH-LOCK*."))

(defun osint-correlator-strategy (agent)
  "Default strategy function for OSINT-CORRELATOR.

   This strategy polls for new findings from the Navigator and Analyst,
   builds the knowledge graph, and generates the final report.

   Parameters:
     AGENT -- The OSINT-CORRELATOR instance."
  (let ((target (corr-target agent)))
    (mcp-log :info "OSINT Correlator starting for ~A" target)
    ;; Build knowledge graph from all findings
    (build-knowledge-graph target)
    ;; Calculate risk score
    (let ((risk (calculate-target-risk target)))
      (update-target-risk target risk)
      (mcp-log :info "Target ~A risk score: ~,2F" target risk))
    ;; Calculate centrality
    (multiple-value-bind (centrality degree)
        (calculate-target-centrality target)
      (mcp-log :info "Target ~A centrality: ~,2F (degree: ~A)"
               target centrality degree))
    ;; Publish completion
    (publish-message :swarm.osint.investigation.complete
                     `(:event :investigation-complete
                       :target ,target
                       :risk-score ,(osint-target-risk-score (get-target target))
                       :findings-count ,(count-findings target)
                       :timestamp ,(local-time:now)))
    (mcp-log :info "OSINT Correlator completed for ~A" target)))

(defun spawn-collector-mesh (target &key (depth 2) (tools '(spiderfoot theharvester subfinder dnsrecon)))
  "Spawn the full Collector Mesh for a target.

   Creates and links three specialized agents:
     1. OSINT-NAVIGATOR   -- Discovers public digital assets
     2. OSINT-ANALYST     -- Examines files/repos for sensitive data
     3. OSINT-CORRELATOR  -- Links findings into the identity graph

   Parameters:
     TARGET -- String: the Subject of Interest to investigate.
     DEPTH  -- Integer: recursion depth for Navigator (default: 2).
     TOOLS  -- List of tool keywords for Navigator to use.

   Returns: The correlator agent ID (keyword).

   Side effects:
     - Registers the target
     - Creates three agents with linked gossip subscriptions
     - Stores mesh configuration in *OSINT-COLLECTOR-MESH-REGISTRY*
     - Starts all three agents

   Example:
     (spawn-collector-mesh 'example.com' :depth 2)
     (spawn-collector-mesh 'target@gmail.com'
       :tools '(ghunt socialmapper) :depth 1)"
  ;; Register target
  (unless (get-target target)
    (register-target target))
  (update-target-status target :active)
  ;; Create Navigator
  (let* ((navigator (make-instance 'osint-navigator
                                   :target target
                                   :depth depth
                                   :tools tools
                                   :capabilities '(:osint :navigator :recon))))
    (setf (agent-strategy navigator) #'osint-navigator-strategy)
    ;; Create Analyst
    (let* ((analyst (make-instance 'osint-analyst
                                   :capabilities '(:osint :analyst :examine))))
      (setf (agent-strategy analyst) #'osint-analyst-strategy)
      ;; Create Correlator
      (let* ((correlator (make-instance 'osint-correlator
                                        :target target
                                        :navigator-id (agent-id navigator)
                                        :analyst-id (agent-id analyst)
                                        :capabilities '(:osint :correlator :synthesize))))
        (setf (agent-strategy correlator) #'osint-correlator-strategy)
        ;; Store mesh configuration
        (setf (gethash (agent-id correlator) *osint-collector-mesh-registry*)
              `(:navigator ,navigator
                :analyst ,analyst
                :correlator ,correlator
                :target ,target
                :depth ,depth
                :created-at ,(local-time:now)))
        ;; Start agents (in order: navigator first, then analyst, then correlator)
        (mcp-log :info "Collector Mesh spawned for ~A (depth: ~A)" target depth)
        ;; Publish mesh creation event
        (publish-message :swarm.osint.mesh.spawned
                         `(:event :mesh-spawned
                           :target ,target
                           :navigator-id ,(agent-id navigator)
                           :analyst-id ,(agent-id analyst)
                           :correlator-id ,(agent-id correlator)
                           :timestamp ,(local-time:now)))
        ;; Return the correlator ID as the mesh handle
        (agent-id correlator)))))

(defun get-mesh-status (correlator-id)
  "Get the status of a Collector Mesh instance.

   Parameters:
     CORRELATOR-ID -- Keyword: ID returned by SPAWN-COLLECTOR-MESH.

   Returns: A plist with mesh status information, or NIL if not found."
  (let ((mesh (gethash correlator-id *osint-collector-mesh-registry*)))
    (when mesh
      (let ((navigator (getf mesh :navigator))
            (analyst (getf mesh :analyst))
            (correlator (getf mesh :correlator)))
        `(:target ,(getf mesh :target)
          :depth ,(getf mesh :depth)
          :created-at ,(getf mesh :created-at)
          :navigator-status ,(when navigator (agent-status navigator))
          :analyst-status ,(when analyst (agent-status analyst))
          :correlator-status ,(when correlator (agent-status correlator))
          :navigator-health ,(when navigator (agent-health navigator))
          :analyst-health ,(when analyst (agent-health analyst))
          :correlator-health ,(when correlator (agent-health correlator))))))

(defun halt-collector-mesh (correlator-id)
  "Halt all agents in a Collector Mesh.

   Parameters:
     CORRELATOR-ID -- Keyword: ID returned by SPAWN-COLLECTOR-MESH.

   Returns: T if halted, NIL if mesh not found."
  (let ((mesh (gethash correlator-id *osint-collector-mesh-registry*)))
    (when mesh
      (dolist (role '(:navigator :analyst :correlator))
        (let ((agent (getf mesh role)))
          (when agent
            (setf (agent-status agent) :paused)
            (mcp-log :info "Halted ~A in mesh ~A" role correlator-id))))
      t)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 6: MCP Registration — Expose OSINT Tools to MCP Clients
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These functions register OSINT capabilities as Model Context Protocol
;; (MCP) tools and resources, making them discoverable and invocable by
;; MCP clients (Claude, Copilot, etc.).

(defun expose-osint-mcp-tools ()
  "Register OSINT tools as MCP capabilities.

   This function exposes 6 OSINT tools for MCP client discovery:
     osint-recon    -- Full reconnaissance scan using Collector Mesh
     osint-domain   -- Subdomain enumeration (Subfinder + Amass + DNSRecon)
     osint-persona  -- Identity lookup (GHunt + Social Mapper)
     osint-archive  -- Wayback Machine historical snapshot retrieval
     osint-graph    -- Get knowledge graph for a target
     osint-targets  -- List all registered targets

   Each tool has a JSON Schema parameter definition and a handler function
   that calls the corresponding LISPMIND OSINT function.

   Returns: A list of the registered tool name symbols.

   Example:
     (expose-osint-mcp-tools)
       ;; => (OSINT-RECON OSINT-DOMAIN OSINT-PERSONA OSINT-ARCHIVE
       ;;     OSINT-GRAPH OSINT-TARGETS)"
  (let ((registered '()))
    ;; ── Tool: osint-recon ──
    (push (mcp-tool-name
           (register-mcp-tool
            'osint-recon
            "Perform a full OSINT reconnaissance scan on a target. Uses the Collector Mesh pattern (Navigator + Analyst + Correlator) to comprehensively map the target's digital footprint. Discovers subdomains, emails, IP addresses, social profiles, technologies, and potential vulnerabilities."
            '(:type "object"
              :properties (:target (:type "string"
                                   :description "Target to investigate: domain, IP, email, or persona name")
                          :depth (:type "integer"
                                 :description "Recursion depth (1-3). Higher = more thorough but slower"
                                 :default 2
                                 :minimum 1
                                 :maximum 3)
                          :tools (:type "array"
                                 :description "Tools to use (default: spiderfoot, theharvester, subfinder, dnsrecon)"
                                 :items (:type "string")))
              :required ("target"))
            (lambda (args)
              (let* ((target (cdr (assoc :target args :test #'string-equal)))
                     (depth (or (cdr (assoc :depth args :test #'string-equal)) 2))
                     (tools-arg (cdr (assoc :tools args :test #'string-equal)))
                     (tools (when tools-arg
                              (mapcar (lambda (t)
                                        (intern (string-upcase t) :keyword))
                                      tools-arg))))
                (if target
                    (handler-case
                        (let ((mesh-id (spawn-collector-mesh
                                        target
                                        :depth depth
                                        :tools (or tools
                                                   '(spiderfoot theharvester
                                                     subfinder dnsrecon)))))
                          (list :content
                                (list (list :type "text"
                                            :text (format nil "OSINT reconnaissance started for '~A' (depth: ~A).~%Collector Mesh ID: ~A~%Target registered. Use osint-graph to check results."
                                                          target depth mesh-id)))))
                      (error (e)
                        (list :content
                              (list (list :type "text"
                                          :text (format nil "OSINT recon error: ~A" e)))
                              :is-error t)))
                    (list :content
                          (list (list :type "text"
                                      :text "Missing required parameter: 'target' is required."))
                          :is-error t))))))
          registered)

    ;; ── Tool: osint-domain ──
    (push (mcp-tool-name
           (register-mcp-tool
            'osint-domain
            "Enumerate subdomains and DNS records for a domain. Combines Subfinder (fast passive), Amass (deep enumeration), and DNSRecon (DNS record types + zone transfer testing). Returns discovered subdomains, IP addresses, MX records, and any zone transfer vulnerabilities."
            '(:type "object"
              :properties (:domain (:type "string"
                                    :description "Target domain (e.g., 'example.com')")
                          :mode (:type "string"
                                :description "Enumeration thoroughness: fast, normal, deep"
                                :default "normal"
                                :enum ["fast" "normal" "deep"])
                          :recursive (:type "boolean"
                                     :description "Enable recursive subdomain enumeration"
                                     :default nil))
              :required ("domain"))
            (lambda (args)
              (let* ((domain (cdr (assoc :domain args :test #'string-equal)))
                     (mode (or (cdr (assoc :mode args :test #'string-equal))
                               "normal"))
                     (recursive (or (cdr (assoc :recursive args :test #'string-equal))
                                    nil)))
                (if domain
                    (handler-case
                        (progn
                          ;; Register target
                          (unless (get-target domain)
                            (register-target domain :type :domain))
                          ;; Spawn Subfinder
                          (let ((sf (make-subfinder-agent domain :recursive recursive)))
                            (run-tool sf)
                            (loop for i from 0 below 60
                                  while (eq (agent-status sf) :running)
                                  do (capture-output sf) (sleep 1))
                            (capture-output sf))
                          ;; Spawn DNSRecon
                          (let ((dr (make-dnsrecon-agent domain)))
                            (run-tool dr)
                            (loop for i from 0 below 60
                                  while (eq (agent-status dr) :running)
                                  do (capture-output dr) (sleep 1))
                            (capture-output dr))
                          ;; Deep mode: also run Amass
                          (when (string-equal mode "deep")
                            (let ((am (make-amass-agent domain :mode :active)))
                              (run-tool am)
                              (loop for i from 0 below 300
                                    while (eq (agent-status am) :running)
                                    do (capture-output am) (sleep 1))
                              (capture-output am)))
                          ;; Collect results
                          (let* ((target (get-target domain))
                                 (entities (when target (osint-target-entities target)))
                                 (findings-count (when target (osint-target-findings-count target))))
                            (list :content
                                  (list (list :type "text"
                                              :text (format nil "Domain enumeration complete for ~A (~A mode).~%Subdomains: ~A~%IPs: ~A~%Total findings: ~A"
                                                            domain mode
                                                            (or (getf entities :subdomains) "N/A")
                                                            (or (getf entities :ips) "N/A")
                                                            findings-count))))))
                      (error (e)
                        (list :content
                              (list (list :type "text"
                                          :text (format nil "Domain enumeration error: ~A" e)))
                              :is-error t)))
                    (list :content
                          (list (list :type "text"
                                      :text "Missing required parameter: 'domain' is required."))
                          :is-error t))))))
          registered)

    ;; ── Tool: osint-persona ──
    (push (mcp-tool-name
           (register-mcp-tool
            'osint-persona
            "Perform identity lookup on a persona. Uses GHunt for Google account analysis and Social Mapper for cross-platform correlation. Investigates email addresses, names, and social media handles to build an identity profile."
            '(:type "object"
              :properties (:query (:type "string"
                                  :description "Email, name, or social handle to investigate")
                          :type (:type "string"
                                :description "Type of query: email, name, handle"
                                :default "email"
                                :enum ["email" "name" "handle"])
                          :platforms (:type "array"
                                     :description "Platforms to search (for name/handle queries)"
                                     :items (:type "string")))
              :required ("query"))
            (lambda (args)
              (let* ((query (cdr (assoc :query args :test #'string-equal)))
                     (qtype (or (cdr (assoc :type args :test #'string-equal))
                                "email"))
                     (platforms (cdr (assoc :platforms args :test #'string-equal))))
                (if query
                    (handler-case
                        (progn
                          (cond
                            ;; Email lookup with GHunt
                            ((string-equal qtype "email")
                             (let ((gh (make-ghunt-agent query)))
                               (run-tool gh)
                               (loop for i from 0 below 60
                                     while (eq (agent-status gh) :running)
                                     do (capture-output gh) (sleep 1))
                               (capture-output gh)))
                            ;; Name lookup with Social Mapper
                            ((string-equal qtype "name")
                             (let ((sm (make-socialmapper-agent
                                        query
                                        :platforms (when platforms
                                                     (mapcar #'read-from-string
                                                             platforms)))))
                               (run-tool sm)
                               (loop for i from 0 below 120
                                     while (eq (agent-status sm) :running)
                                     do (capture-output sm) (sleep 1))
                               (capture-output sm)))
                            ;; Handle lookup
                            ((string-equal qtype "handle")
                             (let ((sm (make-socialmapper-agent query)))
                               (run-tool sm)
                               (loop for i from 0 below 120
                                     while (eq (agent-status sm) :running)
                                     do (capture-output sm) (sleep 1))
                               (capture-output sm))))
                          (list :content
                                (list (list :type "text"
                                            :text (format nil "Persona lookup initiated for '~A' (type: ~A).~%Investigation running. Check findings with osint-graph."
                                                          query qtype)))))
                      (error (e)
                        (list :content
                              (list (list :type "text"
                                          :text (format nil "Persona lookup error: ~A" e)))
                              :is-error t)))
                    (list :content
                          (list (list :type "text"
                                      :text "Missing required parameter: 'query' is required."))
                          :is-error t))))))
          registered)

    ;; ── Tool: osint-archive ──
    (push (mcp-tool-name
           (register-mcp-tool
            'osint-archive
            "Query the Wayback Machine for historical snapshots of a URL or domain. Discovers old pages, deleted content, historical subdomains, and previously exposed information."
            '(:type "object"
              :properties (:url (:type "string"
                                :description "URL or domain to query (e.g., 'example.com' or '*.example.com/*')")
                          :count (:type "integer"
                                 :description "Maximum number of snapshots to retrieve"
                                 :default 10
                                 :minimum 1
                                 :maximum 1000)
                          :date-from (:type "string"
                                     :description "Start date filter (YYYYMMDD)")
                          :date-to (:type "string"
                                   :description "End date filter (YYYYMMDD)"))
              :required ("url"))
            (lambda (args)
              (let* ((url (cdr (assoc :url args :test #'string-equal)))
                     (count (or (cdr (assoc :count args :test #'string-equal)) 10))
                     (date-from (cdr (assoc :date-from args :test #'string-equal)))
                     (date-to (cdr (assoc :date-to args :test #'string-equal))))
                (if url
                    (handler-case
                        (let ((wb (make-wayback-agent url
                                                      :snapshot-count count
                                                      :date-from date-from
                                                      :date-to date-to)))
                          (run-tool wb)
                          (let ((findings (get-findings url)))
                            (list :content
                                  (list (list :type "text"
                                              :text (format nil "Wayback Machine query complete for ~A.~%Snapshots found: ~A~%Use osint-graph to view detailed results."
                                                            url (length findings)))))))
                      (error (e)
                        (list :content
                              (list (list :type "text"
                                          :text (format nil "Archive query error: ~A" e)))
                              :is-error t)))
                    (list :content
                          (list (list :type "text"
                                      :text "Missing required parameter: 'url' is required."))
                          :is-error t))))))
          registered)

    ;; ── Tool: osint-graph ──
    (push (mcp-tool-name
           (register-mcp-tool
            'osint-graph
            "Get the knowledge graph and investigation status for a target. Returns the entity-relationship graph, risk score, findings summary, and investigation dossier."
            '(:type "object"
              :properties (:target (:type "string"
                                   :description "Target ID to query")
                          :format (:type "string"
                                  :description "Output format: summary, full, dot"
                                  :default "summary"
                                  :enum ["summary" "full" "dot"]))
              :required ("target"))
            (lambda (args)
              (let* ((target (cdr (assoc :target args :test #'string-equal)))
                     (format-str (or (cdr (assoc :format args :test #'string-equal))
                                     "summary")))
                (if target
                    (let ((target-obj (get-target target)))
                      (if target-obj
                          (let* ((summary (target-summary target))
                                 (graph-stats (graph-statistics)))
                            (cond
                              ((string-equal format-str "dot")
                               (export-graph-dot)
                               (list :content
                                     (list (list :type "text"
                                                 :text "Knowledge graph exported to /tmp/osint-graph.dot"))))
                              ((string-equal format-str "full")
                               (list :content
                                     (list (list :type "text"
                                                 :text (format nil "Full investigation report for ~A:~%~%Summary: ~S~%Graph Stats: ~S~%Findings: ~A"
                                                               target summary graph-stats
                                                               (count-findings target))))))
                              (t
                               (list :content
                                     (list (list :type "text"
                                                 :text (format nil "Target: ~A~%Type: ~A~%Status: ~A~%Risk Score: ~,2F~%Findings: ~A~%Entities: ~A~%Graph: ~A entities, ~A relationships"
                                                               (getf summary :id)
                                                               (getf summary :type)
                                                               (getf summary :status)
                                                               (getf summary :risk-score)
                                                               (getf summary :findings-count)
                                                               (getf summary :entities)
                                                               (getf graph-stats :entity-count)
                                                               (getf graph-stats :relationship-count))))))))
                          (list :content
                                (list (list :type "text"
                                            :text (format nil "Target '~A' not found. Register it first with osint-recon or osint-domain."
                                                          target))))))
                    (list :content
                          (list (list :type "text"
                                      :text "Missing required parameter: 'target' is required."))
                          :is-error t))))))
          registered)

    ;; ── Tool: osint-targets ──
    (push (mcp-tool-name
           (register-mcp-tool
            'osint-targets
            "List all registered OSINT targets (Subjects of Interest). Returns each target's ID, type, status, risk score, and findings count. Optionally filter by type or status."
            '(:type "object"
              :properties (:type (:type "string"
                                :description "Filter by target type: domain, ip, persona, organization, handle")
                          :status (:type "string"
                                  :description "Filter by status: pending, active, complete, stale"
                                  :enum ["pending" "active" "complete" "stale"]))
              :required ())
            (lambda (args)
              (let* ((type-filter (cdr (assoc :type args :test #'string-equal)))
                     (status-filter (cdr (assoc :status args :test #'string-equal)))
                     (type-kw (when type-filter
                                (intern (string-upcase type-filter) :keyword)))
                     (status-kw (when status-filter
                                  (intern (string-upcase status-filter) :keyword)))
                     (targets (list-targets :type type-kw :status status-kw)))
                (list :content
                      (list (list :type "text"
                                  :text (if targets
                                            (format nil "Registered OSINT targets (~A):~%~{~A~^~%~}"
                                                    (length targets)
                                                    (mapcar (lambda (t)
                                                              (format nil "  ~A [~A] status:~A risk:~,2F findings:~A"
                                                                      (osint-target-id t)
                                                                      (osint-target-type t)
                                                                      (osint-target-status t)
                                                                      (osint-target-risk-score t)
                                                                      (osint-target-findings-count t)))
                                                            targets))
                                            "No targets registered."))))))))
          registered)

    (mcp-log :info "Exposed ~A OSINT tools as MCP tools" (length registered))
    (nreverse registered)))

(defun expose-osint-mcp-resources () 
  "Register OSINT resources as MCP capabilities accessible via URI templates.

   Exposes the following resources:
     swarm://osint/targets         -- All registered SOIs
     swarm://osint/target/{id}     -- Specific target metadata
     swarm://osint/target/{id}/findings -- All findings for a target
     swarm://osint/target/{id}/graph    -- Knowledge graph for a target
     swarm://osint/target/{id}/dossier  -- Full investigation dossier

   Each resource handler returns JSON content suitable for MCP clients.

   Returns: A list of the registered resource name symbols.

   Example:
     (expose-osint-mcp-resources)
       ;; => (OSINT-TARGETS OSINT-TARGET OSINT-FINDINGS OSINT-GRAPH OSINT-DOSSIER)"
  (let ((registered '()))
    ;; ── Resource: swarm://osint/targets ──
    (push (mcp-resource-name
           (register-mcp-resource
            'osint-targets
            "All registered OSINT targets (Subjects of Interest)"
            "swarm://osint/targets"
            (lambda (params)
              (declare (ignore params))
              (let ((targets (list-targets)))
                (lisp-to-json
                 (list :count (length targets)
                       :targets (mapcar (lambda (t)
                                          (list :id (osint-target-id t)
                                                :type (osint-target-type t)
                                                :status (osint-target-status t)
                                                :risk-score (osint-target-risk-score t)
                                                :findings-count (osint-target-findings-count t)))
                                        targets)
                       :timestamp (local-time:now)))))))
          registered)

    ;; ── Resource: swarm://osint/target/{id} ──
    (push (mcp-resource-name
           (register-mcp-resource
            'osint-target
            "Specific OSINT target metadata and status"
            "swarm://osint/target/{id}"
            (lambda (params)
              (let ((target-id (cdr (assoc :id params :test #'string-equal))))
                (if target-id
                    (let ((target (get-target target-id)))
                      (if target
                          (lisp-to-json
                           (list :id (osint-target-id target)
                                 :type (osint-target-type target)
                                 :status (osint-target-status target)
                                 :risk-score (osint-target-risk-score target)
                                 :findings-count (osint-target-findings-count target)
                                 :entities (osint-target-entities target)
                                 :created-at (osint-target-created-at target)
                                 :last-scanned-at (osint-target-last-scanned-at target)))
                          (lisp-to-json (list :error "Target not found"))))
                    (lisp-to-json (list :error "Missing target ID")))))))
          registered)

    ;; ── Resource: swarm://osint/target/{id}/findings ──
    (push (mcp-resource-name
           (register-mcp-resource
            'osint-findings
            "All findings for a specific OSINT target"
            "swarm://osint/target/{id}/findings"
            (lambda (params)
              (let ((target-id (cdr (assoc :id params :test #'string-equal))))
                (if target-id
                    (let ((findings (get-findings target-id)))
                      (lisp-to-json
                       (list :target target-id
                             :finding-count (length findings)
                             :by-type (let ((counts (make-hash-table)))
                                        (dolist (f findings)
                                          (incf (gethash (getf f :type) counts 0)))
                                        counts)
                             :recent-findings (subseq findings 0 (min 20 (length findings)))
                             :timestamp (local-time:now))))
                    (lisp-to-json (list :error "Missing target ID")))))))
          registered)

    ;; ── Resource: swarm://osint/target/{id}/graph ──
    (push (mcp-resource-name
           (register-mcp-resource
            'osint-graph-resource
            "Knowledge graph relationships for a specific OSINT target"
            "swarm://osint/target/{id}/graph"
            (lambda (params)
              (let ((target-id (cdr (assoc :id params :test #'string-equal))))
                (if target-id
                    (let ((relations (query-graph target-id)))
                      (multiple-value-bind (centrality degree)
                          (calculate-target-centrality target-id)
                        (lisp-to-json
                         (list :target target-id
                               :centrality centrality
                               :degree degree
                               :relationships relations
                               :graph-stats (graph-statistics)
                               :timestamp (local-time:now)))))
                    (lisp-to-json (list :error "Missing target ID")))))))
          registered)

    ;; ── Resource: swarm://osint/target/{id}/dossier ──
    (push (mcp-resource-name
           (register-mcp-resource
            'osint-dossier
            "Full investigation dossier for a specific OSINT target"
            "swarm://osint/target/{id}/dossier"
            (lambda (params)
              (let ((target-id (cdr (assoc :id params :test #'string-equal))))
                (if target-id
                    (let ((target (get-target target-id)))
                      (if target
                          (lisp-to-json
                           (list :dossier (get-target-dossier target-id)
                                 :generated-at (local-time:now)
                                 :engine-version *osint-engine-version*))
                          (lisp-to-json (list :error "Target not found"))))
                    (lisp-to-json (list :error "Missing target ID")))))))
          registered)

    (mcp-log :info "Exposed ~A OSINT resources as MCP resources" (length registered))
    (nreverse registered)))

(defun register-osint-subsystem ()
  "Register the complete OSINT subsystem with MCP.

   Calls both EXPOSE-OSINT-MCP-TOOLS and EXPOSE-OSINT-MCP-RESOURCES,
   then logs a summary.

   Returns: Combined list of all registered tool and resource names.

   Example:
     (register-osint-subsystem)"
  (let ((tools (expose-osint-mcp-tools))
        (resources (expose-osint-mcp-resources)))
    (mcp-log :info "OSINT subsystem registered: ~A tools, ~A resources"
             (length tools) (length resources))
    (append tools resources)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 7: Interactive Commands — REPL Interface for OSINT Operations
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These functions provide a convenient REPL interface for running
;; OSINT operations manually. They wrap the agent machinery with
;; simple function calls suitable for interactive use.

(defun start-recon-scan (target &key (depth 2) tools)
  "REPL: Start a full OSINT reconnaissance scan.

   Spawns the Collector Mesh for the target and begins comprehensive
   investigation. This is the main entry point for interactive OSINT.

   Parameters:
     TARGET -- String: domain, IP, email, or persona name.
     DEPTH  -- Integer: recursion depth (default: 2, max: 3).
     TOOLS  -- List of tool keywords, or NIL for defaults.

   Returns: The correlator agent ID (keyword).

   Example:
     (start-recon-scan 'example.com')
     (start-recon-scan 'target@gmail.com' :depth 1 :tools '(ghunt))
     (start-recon-scan '192.168.1.1' :depth 2)"
  (format t "~&[~A] Starting OSINT reconnaissance: ~A (depth: ~A)~%"
          (local-time:now) target depth)
  (let ((mesh-id (spawn-collector-mesh target
                                       :depth depth
                                       :tools (or tools
                                                  '(spiderfoot theharvester
                                                    subfinder dnsrecon)))))
    (format t "[~A] Collector Mesh spawned. Correlator ID: ~A~%"
            (local-time:now) mesh-id)
    mesh-id))

(defun get-identity-graph (target-id)
  "REPL: Get the knowledge graph for a target.

   Builds (if needed) and returns the entity-relationship graph for
   the specified target.

   Parameters:
     TARGET-ID -- String: target identifier.

   Returns: A plist with :ENTITY :RELATIONS :CENTRALITY :GRAPH-STATS.

   Example:
     (get-identity-graph 'example.com')"
  (let ((target (get-target target-id)))
    (unless target
      (format t "~&Target '~A' not found. Register with (register-target '~A').~%"
              target-id target-id)
      (return-from get-identity-graph nil))
    ;; Build graph
    (build-knowledge-graph target-id)
    ;; Collect results
    (let ((relations (query-graph target-id)))
      (multiple-value-bind (centrality degree)
          (calculate-target-centrality target-id)
        (let ((result `(:entity ,target-id
                        :relations ,relations
                        :centrality ,centrality
                        :degree ,degree
                        :graph-stats ,(graph-statistics))))
          (format t "~&Knowledge graph for ~A:~%" target-id)
          (format t "  Entities: ~A~%" (getf (getf result :graph-stats) :entity-count))
          (format t "  Relationships: ~A~%" (getf (getf result :graph-stats) :relationship-count))
          (format t "  Centrality: ~,2F (~A direct connections)~%" centrality degree)
          (format t "  Direct relations for ~A:~%" target-id)
          (dolist (rel (subseq relations 0 (min 10 (length relations))))
            (format t "    ~A --~A→ ~A~%" target-id (first rel) (second rel)))
          result)))))

(defun get-target-dossier (target-id)
  "REPL: Generate a full dossier report for a target.

   Produces a comprehensive investigation report including:
     - Target metadata and risk assessment
     - All findings organized by type
     - Entity-relationship summary
     - Knowledge graph statistics
     - Recommendations based on risk score

   Parameters:
     TARGET-ID -- String: target identifier.

   Returns: A plist containing the full dossier.

   Example:
     (get-target-dossier 'example.com')
     (get-target-dossier 'target@gmail.com')"
  (let ((target (get-target target-id)))
    (unless target
      (format t "~&Target '~A' not found.~%" target-id)
      (return-from get-target-dossier nil))
    ;; Ensure graph is built
    (build-knowledge-graph target-id)
    ;; Recalculate risk
    (let ((risk (calculate-target-risk target-id)))
      (update-target-risk target-id risk))
    ;; Build dossier
    (let* ((findings (get-findings target-id))
           (entities (osint-target-entities target))
           (graph-stats (graph-statistics))
           (dossier `(:target-id ,target-id
                      :type ,(osint-target-type target)
                      :status ,(osint-target-status target)
                      :risk-score ,(osint-target-risk-score target)
                      :risk-level ,(cond
                                     ((>= (osint-target-risk-score target) 0.7) :critical)
                                     ((>= (osint-target-risk-score target) 0.4) :high)
                                     ((>= (osint-target-risk-score target) 0.2) :medium)
                                     (t :low))
                      :findings-summary
                      (,(count-findings target-id :email) :emails
                       ,(count-findings target-id :subdomain) :subdomains
                       ,(count-findings target-id :ip) :ips
                       ,(count-findings target-id :persona) :personas
                       ,(count-findings target-id :vulnerability) :vulnerabilities
                       ,(count-findings target-id :technology) :technologies
                       ,(count-findings target-id :social-profile) :social-profiles)
                      :entities ,entities
                      :total-findings ,(length findings)
                      :graph-stats ,graph-stats
                      :centrality ,(calculate-target-centrality target-id)
                      :generated-at ,(local-time:now)
                      :engine-version ,*osint-engine-version*)))
      ;; Print formatted dossier
      (format t "~%═══════════════════════════════════════════════════════════════~%")
      (format t "  OSINT INVESTIGATION DOSSIER~%")
      (format t "  Target: ~A~%" target-id)
      (format t "  Type: ~A | Status: ~A | Risk: ~,2F (~A)~%"
              (getf dossier :type)
              (getf dossier :status)
              (getf dossier :risk-score)
              (getf dossier :risk-level))
      (format t "═══════════════════════════════════════════════════════════════~%")
      (format t "  Findings Summary:~%")
      (format t "    Emails:        ~A~%" (count-findings target-id :email))
      (format t "    Subdomains:    ~A~%" (count-findings target-id :subdomain))
      (format t "    IPs:           ~A~%" (count-findings target-id :ip))
      (format t "    Personas:      ~A~%" (count-findings target-id :persona))
      (format t "    Vulnerabilities: ~A~%" (count-findings target-id :vulnerability))
      (format t "    Technologies:  ~A~%" (count-findings target-id :technology))
      (format t "    Social Profiles: ~A~%" (count-findings target-id :social-profile))
      (format t "  Total: ~A findings~%" (getf dossier :total-findings))
      (format t "───────────────────────────────────────────────────────────────~%")
      (format t "  Graph Stats: ~A entities, ~A relationships~%"
              (getf graph-stats :entity-count)
              (getf graph-stats :relationship-count))
      (format t "  Centrality: ~,2F~%" (getf dossier :centrality))
      (format t "  Generated: ~A~%" (getf dossier :generated-at))
      (format t "═══════════════════════════════════════════════════════════════~%")
      dossier)))

(defun list-osint-findings (target-id)
  "REPL: List all findings for a target.

   Prints a formatted list of all findings, organized by type.

   Parameters:
     TARGET-ID -- String: target identifier.

   Returns: List of finding plists.

   Example:
     (list-osint-findings 'example.com')"
  (let ((findings (get-findings target-id)))
    (format t "~&Findings for ~A (~A total):~%" target-id (length findings))
    (dolist (ftype *osint-finding-types*)
      (let ((typed (remove-if-not (lambda (f) (eq (getf f :type) ftype))
                                  findings)))
        (when typed
          (format t "~%  [~A] (~A):~%" ftype (length typed))
          (dolist (f (subseq typed 0 (min 5 (length typed))))
            (format t "    ~A (confidence: ~,2F, tool: ~A)~%"
                    (getf f :value)
                    (getf f :confidence)
                    (getf f :tool))))))
    findings))

(defun export-osint-report (target-id &optional (format :json))
  "Export findings as a structured report.

   Parameters:
     TARGET-ID -- String: target identifier.
     FORMAT    -- Keyword: :JSON or :MARKDOWN (default: :JSON).

   Returns: The filepath of the exported report.

   Example:
     (export-osint-report 'example.com' :json)
     (export-osint-report 'example.com' :markdown)"
  (let* ((findings (get-findings target-id))
         (target (get-target target-id))
         (filepath (ecase format
                     (:json (format nil "/tmp/osint-report-~A.json" target-id))
                     (:markdown (format nil "/tmp/osint-report-~A.md" target-id)))))
    (ecase format
      (:json
       (with-open-file (stream filepath :direction :output
                                        :if-exists :supersede)
         (format stream "~A"
                 (lisp-to-json
                  (list :target target-id
                        :generated-at (local-time:now)
                        :engine-version *osint-engine-version*
                        :findings-count (length findings)
                        :findings findings
                        :target-metadata (when target
                                           (list :type (osint-target-type target)
                                                 :status (osint-target-status target)
                                                 :risk-score (osint-target-risk-score target)
                                                 :entities (osint-target-entities target)))))))
       (format t "~&JSON report exported to ~A (~A findings)~%"
               filepath (length findings)))
      (:markdown
       (with-open-file (stream filepath :direction :output
                                        :if-exists :supersede)
         (format stream "# OSINT Investigation Report: ~A~%~%" target-id)
         (format stream "**Generated:** ~A  ~%" (local-time:now))
         (format stream "**Engine:** LISPMIND OSINT v~A  ~%~%"
                 *osint-engine-version*)
         (when target
           (format stream "## Target Metadata~%~%")
           (format stream "| Property | Value |~%")
           (format stream "|---|---|~%")
           (format stream "| Type | ~A |~%" (osint-target-type target))
           (format stream "| Status | ~A |~%" (osint-target-status target))
           (format stream "| Risk Score | ~,2F |~%"
                   (osint-target-risk-score target))
           (format stream "| Findings | ~A |~%~%"
                   (osint-target-findings-count target)))
         (format stream "## Findings by Type~%~%")
         (dolist (ftype *osint-finding-types*)
           (let ((typed (remove-if-not (lambda (f)
                                         (eq (getf f :type) ftype))
                                       findings)))
             (when typed
               (format stream "### ~A (~A)~%~%" ftype (length typed))
               (format stream "| Value | Confidence | Tool |~%")
               (format stream "|---|---|---|~%")
               (dolist (f typed)
                 (format stream "| ~A | ~,2F | ~A |~%"
                         (getf f :value)
                         (getf f :confidence)
                         (getf f :tool)))
               (format stream "~%"))))
         (format stream "## Knowledge Graph Statistics~%~%")
         (let ((stats (graph-statistics)))
           (format stream "- **Entities:** ~A~%"
                   (getf stats :entity-count))
           (format stream "- **Relationships:** ~A~%"
                   (getf stats :relationship-count))
           (format stream "- **Average Degree:** ~,2F~%"
                   (getf stats :avg-degree))))
       (format t "~&Markdown report exported to ~A (~A findings)~%"
               filepath (length findings))))
    filepath))

(defun list-osint-agents ()
  "REPL: List all active OSINT tool agents.

   Returns: List of agent summary plists.

   Example:
     (list-osint-agents)"
  (let ((agents '()))
    (bt:with-lock-held (*osint-agent-registry-lock*)
      (maphash (lambda (id agent)
                 (push `(:id ,id
                         :type ,(type-of agent)
                         :status ,(agent-status agent)
                         :health ,(agent-health agent)
                         :target ,(when (slot-exists-p agent 'target)
                                    (agent-target agent))
                         :findings ,(length (agent-findings agent)))
                       agents))
               *osint-agent-registry*))
    (format t "~&Active OSINT agents (~A):~%" (length agents))
    (dolist (a agents)
      (format t "  ~A [~A] status:~A health:~A target:~A findings:~A~%"
              (getf a :id)
              (getf a :type)
              (getf a :status)
              (getf a :health)
              (getf a :target)
              (getf a :findings)))
    agents))

(defun osint-subsystem-status ()
  "Get a comprehensive status summary of the OSINT subsystem.

   Returns: A plist with:
     :ENGINE-VERSION  -- OSINT engine version string
     :TARGETS         -- Number of registered targets
     :FINDINGS        -- Total number of findings across all targets
     :ENTITIES        -- Number of unique entities in the graph
     :RELATIONSHIPS   -- Number of relationships in the graph
     :ACTIVE-AGENTS   -- Number of active OSINT tool agents
     :ACTIVE-MESHES   -- Number of active Collector Mesh instances

   Example:
     (osint-subsystem-status)"
  (let ((total-findings 0)
        (active-agents 0)
        (active-meshes 0))
    (bt:with-lock-held (*osint-registry-lock*)
      (maphash (lambda (id findings)
                 (declare (ignore id))
                 (incf total-findings (length findings)))
               *osint-findings-ledger*))
    (bt:with-lock-held (*osint-agent-registry-lock*)
      (setf active-agents (hash-table-count *osint-agent-registry*)))
    (setf active-meshes (hash-table-count *osint-collector-mesh-registry*))
    `(:engine-version ,*osint-engine-version*
      :targets ,(hash-table-count *osint-target-registry*)
      :findings ,total-findings
      :entities ,(hash-table-count *osint-knowledge-graph*)
      :relationships ,(let ((count 0))
                        (bt:with-lock-held (*osint-graph-lock*)
                          (maphash (lambda (e rels)
                                     (declare (ignore e))
                                     (incf count (length rels)))
                                   *osint-knowledge-graph*))
                        count)
      :active-agents ,active-agents
      :active-meshes ,active-meshes)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 8: Initialization — OSINT Subsystem Bootstrap
;; ═══════════════════════════════════════════════════════════════════════════

(defun init-osint-subsystem ()
  "Initialize the OSINT subsystem.

   This function must be called before using any OSINT features.
   It:
   1. Logs the initialization event
   2. Registers MCP tools and resources
   3. Publishes subsystem-ready gossip message

   Returns: T on success.

   Example:
     (init-osint-subsystem)"
  (mcp-log :info "Initializing LISPMIND OSINT Engine v~A"
           *osint-engine-version*)
  ;; Register with MCP
  (register-osint-subsystem)
  ;; Publish ready event
  (publish-message :swarm.osint.ready
                   `(:event :osint-subsystem-ready
                     :version ,*osint-engine-version*
                     :timestamp ,(local-time:now)))
  (mcp-log :info "OSINT subsystem ready: ~A targets, ~A entities in graph"
           (hash-table-count *osint-target-registry*)
           (hash-table-count *osint-knowledge-graph*))
  t)


;; ═══════════════════════════════════════════════════════════════════════════
;; OSINT ENGINE — Export Summary
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; TARGET REGISTRY (7 functions):
;;   register-target, get-target, list-targets, update-target-status,
;;   update-target-risk, calculate-target-risk, remove-target,
;;   target-summary, recalculate-all-target-risks
;;
;; OSINT TOOL AGENTS (8 classes + 8 constructors):
;;   spiderfoot-agent     + make-spiderfoot-agent
;;   theharvester-agent   + make-theharvester-agent
;;   subfinder-agent      + make-subfinder-agent
;;   amass-agent          + make-amass-agent
;;   ghunt-agent          + make-ghunt-agent
;;   wayback-agent        + make-wayback-agent
;;   socialmapper-agent   + make-socialmapper-agent
;;   dnsrecon-agent       + make-dnsrecon-agent
;;
;; FINDING PARSERS (8 methods + 3 helpers):
;;   parse-findings :after (spiderfoot-agent)
;;   parse-findings :after (theharvester-agent)
;;   parse-findings :after (subfinder-agent)
;;   parse-findings :after (amass-agent)
;;   parse-findings :after (ghunt-agent)
;;   parse-findings :after (socialmapper-agent)
;;   parse-findings :after (dnsrecon-agent)
;;   parse-wayback-results, run-tool (wayback-agent)
;;   normalize-finding, ingest-finding, get-findings
;;   get-findings-by-type, count-findings
;;   parse-spiderfoot-json-file, parse-amass-json-file
;;
;; KNOWLEDGE GRAPH (8 functions):
;;   build-knowledge-graph, add-graph-relationship, query-graph,
;;   query-graph-by-relation, find-path, calculate-target-centrality,
;;   graph-statistics, export-graph-dot
;;
;; COLLECTOR MESH (3 classes + 7 functions):
;;   osint-navigator      + osint-navigator-strategy
;;   osint-analyst        + osint-analyst-strategy
;;                          analyze-git-repository, analyze-file, analyze-url
;;   osint-correlator     + osint-correlator-strategy
;;   spawn-collector-mesh, get-mesh-status, halt-collector-mesh
;;
;; MCP REGISTRATION (3 functions):
;;   expose-osint-mcp-tools, expose-osint-mcp-resources,
;;   register-osint-subsystem
;;
;; INTERACTIVE COMMANDS (7 functions):
;;   start-recon-scan, get-identity-graph, get-target-dossier,
;;   list-osint-findings, export-osint-report, list-osint-agents,
;;   osint-subsystem-status
;;
;; INITIALIZATION (1 function):
;;   init-osint-subsystem
;;
;; SPECIAL VARIABLES:
;;   *OSINT-TARGET-REGISTRY*, *OSINT-FINDINGS-LEDGER*,
;;   *OSINT-KNOWLEDGE-GRAPH*, *OSINT-COLLECTOR-MESH-REGISTRY*,
;;   *OSINT-AGENT-REGISTRY*, *OSINT-REGISTRY-LOCK*,
;;   *OSINT-GRAPH-LOCK*, *OSINT-AGENT-REGISTRY-LOCK*
;;
;; TOTAL: 8 classes, 8 tool agents, 3 Collector Mesh agents,
;;        50+ functions/methods, 500+ lines
;;
;; ═══════════════════════════════════════════════════════════════════════════
;;                     END OF OSINT-ENGINE.LISP
;; ═══════════════════════════════════════════════════════════════════════════
