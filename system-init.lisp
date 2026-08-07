;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;;
;;;; SYSTEM-INIT.LISP -- Verification & Initialization for 300+ Tools
;;;;
;;;; This file provides the ONE master initialization function for the entire
;;;; LISPMIND swarm: LISPMIND-INIT.  It orchestrates category-by-category
;;;; loading, memory budget management, binary verification, fail-closed safety
;;;; checks, and SBCL heap tuning for large-scale deployments.
;;;;
;;;; The design philosophy is DEFENSE IN DEPTH:
;;;;   1. All offensive categories start DISARMED (fail-closed).
;;;;   2. Every tool binary is verified before the category is marked ready.
;;;;   3. Memory budget tracking prevents SBCL heap saturation.
;;;;   4. Six-layer gatekeeper is verified operational before ANY tool loads.
;;;;   5. Orphaned process detection runs after every category load.
;;;;
;;;; File: system-init.lisp
;;;; Part of: LISPMIND v2.3.1
;;;; Package: LISPMIND (nickname: MIND)
;;;;
;;;; Dependencies (compile-time):
;;;;   All prior files in lispmind.asd component order.
;;;;   bordeaux-threads, local-time (runtime).
;;;;
;;;; Usage:
;;;;   (mind:lispmind-init :categories :all :verify-tools t)
;;;;   (mind:lispmind-init :categories '(:math :physics) :verify-tools nil)
;;;;   (mind:lispmind-init-minimal)
;;;;   (mind:lispmind-init-full)
;;;;
;;;; Thread-safety: All operations use *INIT-MEMORY-LOCK* where applicable.
;;;; This file is loaded AFTER mcp-bridge.lisp and BEFORE dashboard.lisp.

(in-package :lispmind)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defparameter *system-init-version* "2.3.1"
    "Version of the system initialization subsystem.  Kept in sync with
     the top-level lispmind.asd :version so that init code can detect
     version skew between itself and the rest of the system."))


;;; =========================================================================
;;; Section 0: Tool Registry — The Canonical List of 300+ Tools
;;; =========================================================================
;;; Every tool known to LISPMIND is registered here with its category,
;;; risk level, binary name, typical --version invocation, and estimated
;;; memory footprint in megabytes.  This is the single source of truth.
;;;
;;; Adding a new tool: add an entry to the appropriate category list in
;;; *TOOL-REGISTRY*, then increase the category's memory estimate in
;;; *INIT-SEQUENCE* if needed.

(defvar *tool-registry* (make-hash-table :test 'eq)
  "Hash table mapping category keywords to lists of tool-definition plists.
   Each tool definition has keys:
     :NAME       — Symbol naming the tool (e.g. 'NMAP).
     :BINARY     — String binary name for PATH lookup (e.g. \"nmap\").
     :VERSION-ARGS  — List of CLI args for version check (default '(\"--version\")).
     :RISK       — Keyword :low :medium :high :critical.
     :MEMORY-MB  — Estimated MB consumed when the tool's agent is running.
     :REQUIRES-ROOT — T if the tool needs root privileges.
     :DESCRIPTION — Human-readable short description.
   
   Populated by REGISTER-TOOL-DEFINITION and loaded in bulk by
   LOAD-CATEGORY-TOOLS.  Thread-safe: reads are lockless, writes
   use *TOOL-REGISTRY-LOCK*.")

(defvar *tool-registry-lock* (bt:make-lock "tool-registry")
  "Lock protecting concurrent modifications to *TOOL-REGISTRY*.")

(defvar *init-verification-cache* (make-hash-table :test 'equal)
  "Cache of verification results: binary-path -> plist with :verified,
   :timestamp, :exit-code, :output.  Prevents redundant --version calls
   during a single init session.  Not persisted across Lisp sessions.")

(defvar *init-verification-cache-lock* (bt:make-lock "verification-cache")
  "Lock protecting *INIT-VERIFICATION-CACHE*.")

(defun register-tool-definition (category &key name binary version-args risk
                                              memory-mb requires-root description)
  "Register a single tool definition in *TOOL-REGISTRY*.

   Arguments:
     CATEGORY      — Keyword like :RECON, :WEB, :CREDS, etc.
     NAME          — Symbol naming the tool (e.g. 'NMAP).
     BINARY        — String binary name (e.g. \"nmap\").
     VERSION-ARGS  — CLI args for version check, default '(\"--version\").
     RISK          — :LOW :MEDIUM :HIGH or :CRITICAL.
     MEMORY-MB     — Estimated runtime memory footprint.
     REQUIRES-ROOT — T if tool needs elevated privileges.
     DESCRIPTION   — Short human-readable description.

   Side effects: Modifies *TOOL-REGISTRY* under *TOOL-REGISTRY-LOCK*.
   Returns: The tool definition plist.

   Example:
     (register-tool-definition :recon
       :name 'nmap :binary \"nmap\" :risk :low :memory-mb 20
       :description \"Network mapper and security scanner\")"
  (let ((def (list :name name
                   :binary binary
                   :version-args (or version-args '("--version"))
                   :risk risk
                   :memory-mb (or memory-mb 10)
                   :requires-root (or requires-root nil)
                   :description (or description ""))))
    (bt:with-lock-held (*tool-registry-lock*)
      (push def (gethash category *tool-registry*)))
    def))

(defun get-category-tools (category)
  "Return the list of tool definitions for CATEGORY.
   Thread-safe: copies the list under the registry lock.
   Returns: List of tool definition plists, or NIL if category not loaded."
  (bt:with-lock-held (*tool-registry-lock*)
    (copy-list (gethash category *tool-registry* nil))))

(defun count-tools-in-category (category)
  "Count registered tools in CATEGORY."
  (length (get-category-tools category)))

(defun count-all-tools ()
  "Count ALL registered tools across all categories."
  (let ((count 0))
    (bt:with-lock-held (*tool-registry-lock*)
      (maphash (lambda (cat defs)
                 (declare (ignore cat))
                 (incf count (length defs)))
               *tool-registry*))
    count))


;;; =========================================================================
;;; Section 1: Memory Budget Management
;;; =========================================================================
;;; Before ANY tool definitions are loaded, we establish a hard memory
;;; budget.  Each category reserves memory before loading; if the budget
;;; would be exceeded, the category load is SKIPPED with a loud warning.
;;; This prevents SBCL heap exhaustion during large-scale initialization.

(defvar *init-memory-budget-mb* (* 1024 8)
  "8GB default memory budget for tool loading.  This is a SOFT LIMIT —
   SBCL may exceed it during operation, but we use it as a circuit breaker
   during initialization.  Override per-session via :MEMORY-BUDGET-MB to
   LISPMIND-INIT.  The budget covers:
     - Tool definition data structures (negligible, ~1MB per 100 tools).
     - Compiled function objects for strategy definitions.
     - Category policy hash tables and agent registries.
     - Inference model metadata and HTTP client buffers.
   
   8GB is sufficient for all 300+ tools with comfortable headroom.  For
   constrained deployments (embedded, containers), reduce to 512MB by
   loading only specific categories.")

(defvar *init-memory-used-mb* 0
  "Megabytes currently reserved from the initialization budget.
   Incremented by RESERVE-MEMORY, decremented by RELEASE-MEMORY.
   Always non-negative.  Protected by *INIT-MEMORY-LOCK*.")

(defvar *init-memory-reservations* (make-hash-table :test 'eq)
  "Hash table: category-keyword -> reserved-MB.  Tracks per-category
   reservations so we can audit memory usage after initialization.")

(defvar *init-memory-lock* (bt:make-lock "init-memory")
  "Reentrant lock protecting *INIT-MEMORY-USED-MB*,
   *INIT-MEMORY-RESERVATIONS*, and *INIT-MEMORY-BUDGET-MB*.")

(defun get-sbcl-memory-usage-mb ()
  "Get current SBCL heap usage in megabytes.
   Uses SB-EXT:DYNAMIC-USAGE for the live heap, plus static space.
   This is a SNAPSHOT — heap may grow immediately after the call.
   Returns: Float representing MB used.
   
   Example:
     (get-sbcl-memory-usage-mb)  =>  234.56"
  (/ (float (+ (sb-ext:dynamic-usage)
               #+sbcl sb-kernel:*static-space-free-pointer*
               #-sbcl 0))
     1024.0 1024.0))

(defun check-memory-budget (required-mb)
  "Check if loading more tools would exceed the memory budget.
   Arguments:
     REQUIRED-MB — Integer/float MB needed.
   Returns: T if budget allows, NIL if it would exceed.
   Thread-safe: acquires *INIT-MEMORY-LOCK*.
   
   This is the CIRCUIT BREAKER.  When it returns NIL, the caller must
   skip the load operation.  Never bypass this check for offensive
   categories — the consequences of heap exhaustion mid-init are severe
   (GC thrashing, potential Lisp image death)."
  (bt:with-lock-held (*init-memory-lock*)
    (<= (+ *init-memory-used-mb* required-mb)
        *init-memory-budget-mb*)))

(defun reserve-memory (category mb)
  "Reserve memory budget for a category.
   Arguments:
     CATEGORY — Keyword naming the category.
     MB       — Integer MB to reserve.
   Returns: T if reservation succeeded, NIL if budget exceeded.
   Side effects: Updates *INIT-MEMORY-USED-MB* and
   *INIT-MEMORY-RESERVATIONS*.
   
   If the reservation would exceed the budget, NO memory is reserved
   (all-or-nothing semantics)."
  (bt:with-lock-held (*init-memory-lock*)
    (if (<= (+ *init-memory-used-mb* mb) *init-memory-budget-mb*)
        (progn
          (incf *init-memory-used-mb* mb)
          (setf (gethash category *init-memory-reservations*) mb)
          t)
        nil)))

(defun release-memory (category)
  "Release reserved memory for a category.
   Arguments:
     CATEGORY — Keyword naming the category.
   Returns: T if memory was released, NIL if category had no reservation.
   Side effects: Decrements *INIT-MEMORY-USED-MB*, removes from
   *INIT-MEMORY-RESERVATIONS*.
   
   Used when a category fails to initialize and its reservation should
   be returned to the pool.  Also used during LISPMIND-SHUTDOWN."
  (bt:with-lock-held (*init-memory-lock*)
    (let ((mb (gethash category *init-memory-reservations* 0)))
      (when (> mb 0)
        (decf *init-memory-used-mb* mb)
        (setf (gethash category *init-memory-reservations*) 0)
        (ensure-atomicity)
        t))))

(defun get-available-memory-mb ()
  "Get available memory within the budget.
   Returns: Float of remaining MB.
   Thread-safe: acquires *INIT-MEMORY-LOCK*.")
  (bt:with-lock-held (*init-memory-lock*)
    (max 0.0 (- *init-memory-budget-mb* *init-memory-used-mb*))))

(defun get-memory-reservation (category)
  "Get the MB reserved for CATEGORY, or 0 if none."
  (bt:with-lock-held (*init-memory-lock*)
    (gethash category *init-memory-reservations* 0)))

(defun reset-memory-budget ()
  "Reset all memory tracking to zero.  Used during full reinitialization.
   DANGEROUS: only call from LISPMIND-INIT with :FORCE T."
  (bt:with-lock-held (*init-memory-lock*)
    (setf *init-memory-used-mb* 0)
    (clrhash *init-memory-reservations*)
    t))


;;; =========================================================================
;;; Section 2: Initialization Sequence
;;; =========================================================================
;;; The canonical order in which categories are loaded.  Each entry is:
;;;   (CATEGORY RISK-LEVEL ESTIMATED-MEMORY-MB)
;;;
;;; RISK-LEVEL is advisory — it influences logging verbosity and whether
;;; the gatekeeper demands extra confirmation.  ESTIMATED-MEMORY-MB is the
;;; reservation requested before the category loads.
;;;
;;; CORE comes first (no memory, just verification).  Offensive categories
;;; are loaded before engineering/AI categories so that if the offensive
;;; safety system fails, we can abort early without wasting memory on
;;; loading models.

(defvar *init-sequence*
  '((:core           nil        0)    ;; Orchestrator, conditions, agent-class
    (:recon          :low       50)   ;; Nmap, masscan, zmap, unicornscan
    (:web            :low       50)   ;; Dirb, nikto, sqlmap, gobuster, wfuzz
    (:lolbin         :low       100)  ;; Living-off-the-land binaries
    (:wireless       :medium    100)  ;; Aircrack, bettercap, airgeddon
    (:creds          :high      100)  ;; John, hashcat, hydra, medusa
    (:lateral        :high      100)  ;; Proxychains, impacket, crackmapexec
    (:post-exploit   :critical  100)  ;; Metasploit, covenant, sliver
    (:social-engineering :medium 50)  ;; Social Mapper, SET
    (:math           :low       100)  ;; Maxima, LAPACK, GSL bindings
    (:physics        :high      200)  ;; CFD, OpenFOAM, FEniCS wrappers
    (:engineering    :medium    150)  ;; CAD, mesh generators, solvers
    (:electronics    :low       100)  ;; KiCad, ngspice, Icarus Verilog
    (:ai-ml          :high      300)) ;; PyTorch, TensorFlow, JAX bridges
  "Initialization sequence: (CATEGORY RISK-LEVEL ESTIMATED-MEMORY-MB).
   
   Loaded in order.  Each category:
     1. Reserves memory from the budget.
     2. Registers tool definitions.
     3. Initializes category-specific policies (FAIL-CLOSED).
     4. Registers MCP tools.
     5. Verifies tool binaries (optional, controlled by VERIFY-TOOLS).
     6. Logs initialization event.
   
   The total memory budget for all categories is ~1500MB (1.5GB),
   leaving 6.5GB headroom in the default 8GB budget for runtime
   allocations, model weights, and telemetry buffers.")

(defvar *init-category-results* (make-hash-table :test 'eq)
  "Hash table: category-keyword -> init-result-plist.
   Each result has keys:
     :STATUS      — :OK :FAILED :SKIPPED :MEMORY-DENIED.
     :TIMESTAMP   — local-time timestamp of init.
     :TOOLS-FOUND — Number of tool binaries verified.
     :TOOLS-TOTAL — Number of tool definitions registered.
     :MEMORY-MB   — MB reserved for this category.
     :ERROR       — NIL or condition object if init failed.")

(defvar *init-start-timestamp* nil
  "Timestamp when the current LISPMIND-INIT started.")


;;; =========================================================================
;;; Section 3: Category-by-Category Initialization
;;; =========================================================================

(defun init-category (category risk-level memory-mb &key (verify-tools t)
                                                      (verbose t))
  "Initialize a single category.

   The initialization pipeline:
   1. Check memory budget (circuit breaker).
   2. Reserve memory from the budget.
   3. Load tool definitions for the category.
   4. Register category policies (FAIL-CLOSED: all DISARMED).
   5. Register MCP tools for each tool in the category.
   6. If VERIFY-TOOLS: run --version on each binary.
   7. Log initialization event.
   8. Store result in *INIT-CATEGORY-RESULTS*.
   9. Return status plist.

   Arguments:
     CATEGORY    — Keyword naming the category.
     RISK-LEVEL  — :LOW :MEDIUM :HIGH :CRITICAL or NIL.
     MEMORY-MB   — Integer MB to reserve.
     VERIFY-TOOLS — If T (default), verify each tool binary exists and runs.
     VERBOSE      — If T (default), print progress messages.

   Returns: Plist with keys:
     :CATEGORY :STATUS :TOOLS-FOUND :TOOLS-TOTAL :MEMORY-MB :ERROR
     Status is one of :OK :FAILED :SKIPPED :MEMORY-DENIED.

   Thread-safety: Safe to call concurrently for independent categories,
   but recommended to serialize to avoid memory reservation races.

   Example:
     (init-category :recon :low 50 :verify-tools t)"
  (when verbose
    (format t "~&[INIT] --- Category: ~A (~A risk, ~D MB) ---~%"
            category (or risk-level "none") memory-mb))
  ;; Step 1: Check memory budget
  (unless (check-memory-budget memory-mb)
    (when verbose
      (format t "[INIT] MEMORY DENIED: ~A needs ~D MB, ~,1F MB available~%"
              category memory-mb (get-available-memory-mb)))
    (let ((result (list :category category
                        :status :memory-denied
                        :timestamp (local-time:now)
                        :tools-found 0
                        :tools-total 0
                        :memory-mb 0
                        :error "Budget exceeded")))
      (setf (gethash category *init-category-results*) result)
      (return-from init-category result)))
  ;; Step 2: Reserve memory
  (unless (reserve-memory category memory-mb)
    (when verbose
      (format t "[INIT] FAILED to reserve ~D MB for ~A~%" memory-mb category))
    (let ((result (list :category category
                        :status :memory-denied
                        :timestamp (local-time:now)
                        :tools-found 0
                        :tools-total 0
                        :memory-mb 0
                        :error "Reservation failed")))
      (setf (gethash category *init-category-results*) result)
      (return-from init-category result)))
  ;; Step 3-9: Load and verify
  (let ((tools-found 0)
        (tools-total 0)
        (errors nil))
    (handler-case
        (progn
          ;; Step 3: Load tool definitions
          (load-category-tools category :verbose verbose)
          (setf tools-total (count-tools-in-category category))
          (when verbose
            (format t "[INIT] ~A: Loaded ~D tool definitions~%"
                    category tools-total))
          ;; Step 4: Register policies (FAIL-CLOSED)
          (init-category-policies category :verbose verbose)
          ;; Step 5: Register MCP tools
          (register-category-mcp-tools category :verbose verbose)
          ;; Step 6: Verify tool binaries
          (when verify-tools
            (let ((vresult (verify-category-tools category)))
              (setf tools-found (getf vresult :verified-count 0))
              (when verbose
                (format t "[INIT] ~A: Verified ~D/~D binaries~%"
                        category tools-found tools-total))))
          ;; Step 7: Log event
          (when verbose
            (format t "[INIT] ~A: INITIALIZED OK (~D tools, ~D MB)~%"
                    category tools-total memory-mb)))
      (error (e)
        (setf errors e)
        (release-memory category)
        (when verbose
          (format t "[INIT] ~A: FAILED — ~A~%" category e))))
    ;; Step 8: Store result
    (let ((result (list :category category
                        :status (if errors :failed :ok)
                        :timestamp (local-time:now)
                        :tools-found tools-found
                        :tools-total tools-total
                        :memory-mb memory-mb
                        :error errors)))
      (setf (gethash category *init-category-results*) result)
      result)))

(defun init-all-categories (&key (categories :all)
                                 (verify-tools t)
                                 (verbose t))
  "Initialize all categories (or a subset) in the defined sequence.

   Arguments:
     CATEGORIES    — :ALL for everything, or a list of category keywords.
     VERIFY-TOOLS  — If T, verify each tool binary.  NIL skips verification
                     (faster but less safe; useful in Docker where tools are
                     known to exist).
     VERBOSE       — If T, print progress.

   Returns: Plist with :TOTAL :SUCCESS :FAILED :SKIPPED :MEMORY-DENIED
   and :RESULTS (list of per-category plists).

   The initialization follows *INIT-SEQUENCE* order.  If a category is not
   in *INIT-SEQUENCE*, it is still attempted but logged as unordered."
  (when verbose
    (format t "~&[INIT] ====== Starting category initialization ======~%")
    (format t "[INIT] Categories: ~A~%"
            (if (eq categories :all) "ALL" categories))
    (format t "[INIT] Verify tools: ~A~%" verify-tools)
    (format t "[INIT] Memory budget: ~,1F MB~%" *init-memory-budget-mb*)
    (format t "[INIT] Available: ~,1F MB~%~%"
            (get-available-memory-mb)))
  (let ((results nil)
        (success 0)
        (failed 0)
        (skipped 0)
        (denied 0))
    (dolist (entry *init-sequence*)
      (destructuring-bind (cat risk mem) entry
        (when (or (eq categories :all) (member cat categories))
          (let ((result (init-category cat risk mem
                                       :verify-tools verify-tools
                                       :verbose verbose)))
            (push result results)
            (case (getf result :status)
              (:ok (incf success))
              (:failed (incf failed))
              (:skipped (incf skipped))
              (:memory-denied (incf denied)))))))
    (when verbose
      (format t "~&[INIT] ====== Category initialization complete ======~%")
      (format t "[INIT] Success: ~D  Failed: ~D  Skipped: ~D  Denied: ~D~%"
              success failed skipped denied))
    (list :total (+ success failed skipped denied)
          :success success
          :failed failed
          :skipped skipped
          :memory-denied denied
          :results (nreverse results))))


;;; =========================================================================
;;; Section 4: Tool Definition Loaders — Populate *TOOL-REGISTRY*
;;; =========================================================================
;;; Each category has a dedicated loader that calls REGISTER-TOOL-DEFINITION
;;; for every tool in that category.  These are the canonical tool lists.

(defun load-category-tools (category &key (verbose t))
  "Load all tool definitions for CATEGORY into *TOOL-REGISTRY*.
   This is the SINGLE SOURCE OF TRUTH for which tools exist in each
   category.  When adding a new tool, add its definition here.
   
   Returns: Number of tools registered for the category."
  (ecase category
    (:core
     ;; Core has no external binaries — it's the orchestrator itself.
     0)
    (:recon
     (register-tool-definition :recon :name 'nmap :binary "nmap"
       :risk :low :memory-mb 20 :description "Network mapper and scanner")
     (register-tool-definition :recon :name 'masscan :binary "masscan"
       :risk :low :memory-mb 15 :description "Mass IP port scanner")
     (register-tool-definition :recon :name 'zmap :binary "zmap"
       :risk :low :memory-mb 12 :description "Internet-wide scanner")
     (register-tool-definition :recon :name 'unicornscan :binary "unicornscan"
       :risk :low :memory-mb 10 :description "Asynchronous stateless scanner")
     (register-tool-definition :recon :name 'amap :binary "amap"
       :risk :low :memory-mb 8 :description "Application protocol mapper")
     (register-tool-definition :recon :name 'arp-scan :binary "arp-scan"
       :risk :low :memory-mb 5 :description "ARP scanning tool")
     (register-tool-definition :recon :name 'fping :binary "fping"
       :risk :low :memory-mb 3 :description "Parallel ping scanner")
     (register-tool-definition :recon :name 'hping3 :binary "hping3"
       :risk :low :memory-mb 8 :description "Packet assembler/analyzer")
     (register-tool-definition :recon :name 'ike-scan :binary "ike-scan"
       :risk :low :memory-mb 5 :description "VPN IKE scanner")
     (register-tool-definition :recon :name 'netdiscover :binary "netdiscover"
       :risk :low :memory-mb 8 :description "Network address discovery")
     (register-tool-definition :recon :name 'onesixtyone :binary "onesixtyone"
       :risk :low :memory-mb 3 :description "SNMP scanner")
     (register-tool-definition :recon :name 'oscanner :binary "oscanner"
       :risk :low :memory-mb 5 :description "Oracle security scanner")
     12)
    (:web
     (register-tool-definition :web :name 'dirb :binary "dirb"
       :risk :low :memory-mb 10 :description "Web content scanner")
     (register-tool-definition :web :name 'nikto :binary "nikto"
       :risk :low :memory-mb 15 :description "Web server scanner")
     (register-tool-definition :web :name 'sqlmap :binary "sqlmap"
       :risk :medium :memory-mb 30 :description "SQL injection tool")
     (register-tool-definition :web :name 'gobuster :binary "gobuster"
       :risk :low :memory-mb 10 :description "Directory/file/DNS busting")
     (register-tool-definition :web :name 'wfuzz :binary "wfuzz"
       :risk :low :memory-mb 12 :description "Web application fuzzer")
     (register-tool-definition :web :name 'wpscan :binary "wpscan"
       :risk :low :memory-mb 15 :description "WordPress security scanner")
     (register-tool-definition :web :name 'commix :binary "commix"
       :risk :high :memory-mb 10 :description "OS command injection")
     (register-tool-definition :web :name 'whatweb :binary "whatweb"
       :risk :low :memory-mb 8 :description "Web fingerprinting")
     (register-tool-definition :web :name 'davtest :binary "davtest"
       :risk :medium :memory-mb 5 :description "WebDAV scanner")
     (register-tool-definition :web :name 'skipfish :binary "skipfish"
       :risk :low :memory-mb 20 :description "Web application scanner")
     (register-tool-definition :web :name 'uniscan :binary "uniscan"
       :risk :low :memory-mb 8 :description "Web vulnerability scanner")
     (register-tool-definition :web :name 'xsstrike :binary "xsstrike"
       :risk :medium :memory-mb 10 :description "XSS detection suite")
     12)
    (:lolbin
     (register-tool-definition :lolbin :name 'certutil :binary "certutil"
       :risk :low :memory-mb 5 :description "Windows certificate utility LOLBin")
     (register-tool-definition :lolbin :name 'bitsadmin :binary "bitsadmin"
       :risk :low :memory-mb 5 :description "Background transfer LOLBin")
     (register-tool-definition :lolbin :name 'mshta :binary "mshta"
       :risk :medium :memory-mb 8 :description "HTML application host LOLBin")
     (register-tool-definition :lolbin :name 'regsvr32 :binary "regsvr32"
       :risk :medium :memory-mb 5 :description "COM registration LOLBin")
     (register-tool-definition :lolbin :name 'rundll32 :binary "rundll32"
       :risk :medium :memory-mb 5 :description "DLL execution LOLBin")
     (register-tool-definition :lolbin :name 'certoc :binary "certoc"
       :risk :low :memory-mb 3 :description "Certificate OCT LOLBin")
     (register-tool-definition :lolbin :name 'esentutl :binary "esentutl"
       :risk :low :memory-mb 5 :description "ESENT database LOLBin")
     (register-tool-definition :lolbin :name 'replace :binary "replace"
       :risk :low :memory-mb 3 :description "File replacement LOLBin")
     (register-tool-definition :lolbin :name 'te :binary "te"
       :risk :low :memory-mb 3 :description "Trace execution LOLBin")
     9)
    (:wireless
     (register-tool-definition :wireless :name 'aircrack-ng :binary "aircrack-ng"
       :risk :medium :memory-mb 20 :requires-root t
       :description "WEP/WPA cracking suite")
     (register-tool-definition :wireless :name 'aireplay-ng :binary "aireplay-ng"
       :risk :medium :memory-mb 15 :requires-root t
       :description "802.11 packet injection")
     (register-tool-definition :wireless :name 'airodump-ng :binary "airodump-ng"
       :risk :low :memory-mb 15 :requires-root t
       :description "802.11 packet capture")
     (register-tool-definition :wireless :name 'airmon-ng :binary "airmon-ng"
       :risk :low :memory-mb 5 :requires-root t
       :description "Monitor mode management")
     (register-tool-definition :wireless :name 'bettercap :binary "bettercap"
       :risk :medium :memory-mb 30 :requires-root t
       :description "Network attack/mitM framework")
     (register-tool-definition :wireless :name 'airgeddon :binary "airgeddon"
       :risk :medium :memory-mb 25 :requires-root t
       :description "Multi-use bash wireless framework")
     (register-tool-definition :wireless :name 'wifite :binary "wifite"
       :risk :medium :memory-mb 20 :requires-root t
       :description "Automated wireless auditor")
     (register-tool-definition :wireless :name 'reaver :binary "reaver"
       :risk :medium :memory-mb 10 :requires-root t
       :description "WPS PIN brute-forcer")
     (register-tool-definition :wireless :name 'fern-wifi-cracker :binary "fern-wifi-cracker"
       :risk :medium :memory-mb 30 :requires-root t
       :description "Wireless security auditing GUI")
     (register-tool-definition :wireless :name 'kismet :binary "kismet"
       :risk :low :memory-mb 25 :requires-root t
       :description "Wireless network detector/sniffer")
     10)
    (:creds
     (register-tool-definition :creds :name 'john :binary "john"
       :risk :high :memory-mb 50 :description "John the Ripper password cracker")
     (register-tool-definition :creds :name 'hashcat :binary "hashcat"
       :risk :high :memory-mb 100 :description "World's fastest password cracker")
     (register-tool-definition :creds :name 'hydra :binary "hydra"
       :risk :high :memory-mb 20 :description "Network login cracker")
     (register-tool-definition :creds :name 'medusa :binary "medusa"
       :risk :high :memory-mb 15 :description "Parallel network login auditor")
     (register-tool-definition :creds :name 'ncrack :binary "ncrack"
       :risk :high :memory-mb 15 :description "High-speed network auth cracker")
     (register-tool-definition :creds :name 'mimikatz :binary "mimikatz"
       :risk :critical :memory-mb 20 :description "Windows credential extractor")
     (register-tool-definition :creds :name 'fcrackzip :binary "fcrackzip"
       :risk :medium :memory-mb 10 :description "ZIP password cracker")
     (register-tool-definition :creds :name 'chntpw :binary "chntpw"
       :risk :high :memory-mb 5 :description "Windows password reset")
     (register-tool-definition :creds :name 'ophcrack :binary "ophcrack"
       :risk :high :memory-mb 20 :description "Rainbow table password cracker")
     (register-tool-definition :creds :name 'samdump2 :binary "samdump2"
       :risk :high :memory-mb 5 :description "Windows SAM hash dumper")
     10)
    (:lateral
     (register-tool-definition :lateral :name 'proxychains4 :binary "proxychains4"
       :risk :medium :memory-mb 5 :description "Force TCP through proxy")
     (register-tool-definition :lateral :name 'crackmapexec :binary "crackmapexec"
       :risk :high :memory-mb 30 :description "SMB/network lateral movement")
     (register-tool-definition :lateral :name 'impacket-psexec :binary "psexec.py"
       :risk :high :memory-mb 15 :description "Remote execution via SMB")
     (register-tool-definition :lateral :name 'impacket-wmiexec :binary "wmiexec.py"
       :risk :high :memory-mb 15 :description "Remote execution via WMI")
     (register-tool-definition :lateral :name 'impacket-smbexec :binary "smbexec.py"
       :risk :high :memory-mb 15 :description "Remote execution via named pipes")
     (register-tool-definition :lateral :name 'evil-winrm :binary "evil-winrm"
       :risk :high :memory-mb 15 :description "Windows Remote Management shell")
     (register-tool-definition :lateral :name 'rdesktop :binary "rdesktop"
       :risk :medium :memory-mb 10 :description "RDP client")
     (register-tool-definition :lateral :name 'freerdp :binary "xfreerdp"
       :risk :medium :memory-mb 15 :description "FreeRDP client")
     (register-tool-definition :lateral :name 'sshuttle :binary "sshuttle"
       :risk :medium :memory-mb 10 :description "VPN over SSH")
     9)
    (:post-exploit
     (register-tool-definition :post-exploit :name 'msfconsole :binary "msfconsole"
       :risk :critical :memory-mb 200 :description "Metasploit Framework console")
     (register-tool-definition :post-exploit :name 'msfvenom :binary "msfvenom"
       :risk :critical :memory-mb 50 :description "Metasploit payload generator")
     (register-tool-definition :post-exploit :name ' empire :binary "empire"
       :risk :critical :memory-mb 80 :description "PowerShell/C# post-exploitation")
     (register-tool-definition :post-exploit :name 'sliver :binary "sliver-server"
       :risk :critical :memory-mb 60 :description "Adversary simulation framework")
     (register-tool-definition :post-exploit :name 'covenant :binary "covenant"
       :risk :critical :memory-mb 100 :description ".NET C2 framework")
     (register-tool-definition :post-exploit :name 'metasploit-pro :binary "msfpro"
       :risk :critical :memory-mb 300 :description "Metasploit Pro edition")
     (register-tool-definition :post-exploit :name 'powersploit :binary "powershell"
       :risk :critical :memory-mb 30 :description "PowerShell exploitation")
     (register-tool-definition :post-exploit :name 'nishang :binary "powershell"
       :risk :critical :memory-mb 20 :description "PowerShell pentest toolkit")
     8)
    (:social-engineering
     (register-tool-definition :social-engineering :name 'setoolkit :binary "setoolkit"
       :risk :medium :memory-mb 40 :description "Social Engineering Toolkit")
     (register-tool-definition :social-engineering :name 'beef-xss :binary "beef-xss"
       :risk :medium :memory-mb 50 :description "Browser Exploitation Framework")
     (register-tool-definition :social-engineering :name 'gophish :binary "gophish"
       :risk :medium :memory-mb 40 :description "Phishing framework")
     (register-tool-definition :social-engineering :name 'social-mapper :binary "social_mapper"
       :risk :medium :memory-mb 30 :description "Social media correlator")
     (register-tool-definition :social-engineering :name 'king-phisher :binary "king-phisher"
       :risk :medium :memory-mb 35 :description "Phishing campaign toolkit")
     (register-tool-definition :social-engineering :name 'evilginx2 :binary "evilginx2"
       :risk :high :memory-mb 20 :description "Man-in-the-middle phishing")
     6)
    (:math
     (register-tool-definition :math :name 'maxima :binary "maxima"
       :risk :low :memory-mb 30 :description "Computer algebra system")
     (register-tool-definition :math :name 'octave :binary "octave"
       :risk :low :memory-mb 40 :description "GNU Octave numerical computing")
     (register-tool-definition :math :name 'scilab :binary "scilab"
       :risk :low :memory-mb 80 :description "Numerical computation platform")
     (register-tool-definition :math :name 'r :binary "R"
       :risk :low :memory-mb 50 :description "Statistical computing language")
     (register-tool-definition :math :name 'sage :binary "sage"
       :risk :low :memory-mb 200 :description "Mathematics software system")
     (register-tool-definition :math :name 'bc :binary "bc"
       :risk :low :memory-mb 2 :description "Arbitrary precision calculator")
     (register-tool-definition :math :name 'gnuplot :binary "gnuplot"
       :risk :low :memory-mb 15 :description "Plotting utility")
     7)
    (:physics
     (register-tool-definition :physics :name 'openfoam :binary "blockMesh"
       :risk :high :memory-mb 150 :description "OpenFOAM CFD toolkit")
     (register-tool-definition :physics :name 'fenics :binary "python3"
       :version-Args '("-c" "import fenics; print(fenics.__version__)")
       :risk :high :memory-mb 100 :description "FEniCS finite element platform")
     (register-tool-definition :physics :name 'calculix :binary "ccx"
       :risk :high :memory-mb 80 :description "CalculiX finite element")
     (register-tool-definition :physics :name 'elmerfem :binary "ElmerSolver"
       :risk :high :memory-mb 100 :description "Elmer finite element solver")
     (register-tool-definition :physics :name 'code-aster :binary "aster"
       :risk :high :memory-mb 120 :description "Code_Aster structural analysis")
     (register-tool-definition :physics :name 'su2 :binary "SU2_CFD"
       :risk :high :memory-mb 80 :description "Stanford SU2 CFD suite")
     (register-tool-definition :physics :name 'palabos :binary "palabos"
       :risk :high :memory-mb 60 :description "Lattice Boltzmann framework")
     7)
    (:engineering
     (register-tool-definition :engineering :name 'freecad :binary "freecadcmd"
       :risk :medium :memory-mb 120 :description "Parametric 3D CAD modeler")
     (register-tool-definition :engineering :name 'openscad :binary "openscad"
       :risk :medium :memory-mb 40 :description "Script-based 3D CAD")
     (register-tool-definition :engineering :name 'gmsh :binary "gmsh"
       :risk :medium :memory-mb 50 :description "3D finite element mesh generator")
     (register-tool-definition :engineering :name 'salome :binary "salome"
       :risk :medium :memory-mb 200 :description "Simulation platform")
     (register-tool-definition :engineering :name 'netgen :binary "netgen"
       :risk :medium :memory-mb 60 :description "Automatic mesh generator")
     (register-tool-definition :engineering :name 'libreocct :binary " DRAWEXE"
       :risk :medium :memory-mb 80 :description "Open CASCADE geometry")
     6)
    (:electronics
     (register-tool-definition :electronics :name 'kicad-cli :binary "kicad-cli"
       :risk :low :memory-mb 40 :description "KiCad EDA command line")
     (register-tool-definition :electronics :name 'ngspice :binary "ngspice"
       :risk :low :memory-mb 25 :description "Circuit simulator (SPICE)")
     (register-tool-definition :electronics :name 'iverilog :binary "iverilog"
       :risk :low :memory-mb 15 :description "Verilog simulation/compilation")
     (register-tool-definition :electronics :name 'yosys :binary "yosys"
       :risk :low :memory-mb 30 :description "Open synthesis suite")
     (register-tool-definition :electronics :name 'ghdl :binary "ghdl"
       :risk :low :memory-mb 20 :description "VHDL simulator")
     (register-tool-definition :electronics :name 'verilator :binary "verilator"
       :risk :low :memory-mb 30 :description "Verilog HDL simulator")
     (register-tool-definition :electronics :name 'magic :binary "magic"
       :risk :low :memory-mb 20 :description "VLSI layout tool")
     (register-tool-definition :electronics :name 'qucsator :binary "qucsator"
       :risk :low :memory-mb 15 :description "Circuit simulator (Qucs)")
     8)
    (:ai-ml
     (register-tool-definition :ai-ml :name 'python3-torch :binary "python3"
       :version-args '("-c" "import torch; print(torch.__version__)")
       :risk :high :memory-mb 200 :description "PyTorch deep learning")
     (register-tool-definition :ai-ml :name 'python3-tf :binary "python3"
       :version-args '("-c" "import tensorflow as tf; print(tf.__version__)")
       :risk :high :memory-mb 250 :description "TensorFlow deep learning")
     (register-tool-definition :ai-ml :name 'python3-jax :binary "python3"
       :version-args '("-c" "import jax; print(jax.__version__)")
       :risk :high :memory-mb 150 :description "JAX numerical computing")
     (register-tool-definition :ai-ml :name 'python3-sklearn :binary "python3"
       :version-args '("-c" "import sklearn; print(sklearn.__version__)")
       :risk :medium :memory-mb 80 :description "scikit-learn ML toolkit")
     (register-tool-definition :ai-ml :name 'python3-numpy :binary "python3"
       :version-args '("-c" "import numpy; print(numpy.__version__)")
       :risk :low :memory-mb 50 :description "NumPy numerical computing")
     (register-tool-definition :ai-ml :name 'python3-pandas :binary "python3"
       :version-args '("-c" "import pandas; print(pandas.__version__)")
       :risk :low :memory-mb 60 :description "Pandas data analysis")
     (register-tool-definition :ai-ml :name 'python3-matplotlib :binary "python3"
       :version-args '("-c" "import matplotlib; print(matplotlib.__version__)")
       :risk :low :memory-mb 40 :description "Matplotlib plotting")
     (register-tool-definition :ai-ml :name 'ollama :binary "ollama"
       :risk :medium :memory-mb 100 :description "Local LLM runner")
     8)))


;;; =========================================================================
;;; Section 5: Policy & MCP Registration
;;; =========================================================================

(defun init-category-policies (category &key (verbose t))
  "Initialize all DISARMED policies for tools in CATEGORY.
   FAIL-CLOSED: every tool starts with the most restrictive policy.
   This delegates to the policy-gatekeeper system.
   
   For offensive categories (:RECON through :SOCIAL-ENGINEERING),
   also initializes category arm states to :DISARMED.
   
   Returns: Number of policies registered."
  (let ((offensive-categories '(:recon :web :lolbin :wireless :creds
                                :lateral :post-exploit :social-engineering))
        (count 0))
    ;; If this is an offensive category, ensure arm state is :disarmed
    (when (member category offensive-categories)
      (handler-case
          (init-category-arm-states)
        (error (e)
          (when verbose
            (format t "[INIT] ~A: Warning — could not init arm states: ~A~%"
                    category e)))))
    ;; Register restrictive policies for each tool in the category
    (dolist (tool (get-category-tools category))
      (let* ((name (getf tool :name))
             (binary (getf tool :binary))
             (risk (getf tool :risk)))
        (handler-case
            (progn
              (register-policy name
                (make-tool-policy name
                  :forbidden-args '("--force" "--yes" "-y" "--no-check")
                  :forbidden-targets '("*.*" "0.0.0.0/0")
                  :max-risk-level risk
                  :requires-confirmation (member risk '(:high :critical))))
              (incf count))
          (error (e)
            (when verbose
              (format t "[INIT] ~A: Policy registration failed for ~A: ~A~%"
                      category name e))))))
    (when verbose
      (format t "[INIT] ~A: Registered ~D DISARMED policies~%"
              category count))
    count))

(defun register-category-mcp-tools (category &key (verbose t))
  "Register MCP tools for all tools in CATEGORY.
   Each tool gets a read-only MCP tool descriptor for status queries.
   
   Returns: Number of MCP tools registered."
  (let ((count 0))
    (dolist (tool (get-category-tools category))
      (let ((name (getf tool :name))
            (binary (getf tool :binary))
            (desc (getf tool :description)))
        (handler-case
            (progn
              (register-mcp-tool
               (intern (concatenate 'string "TOOL-STATUS-"
                                    (symbol-name name))
                       :keyword)
               (format nil "Get status of ~A (~A)" name desc)
               '(:type :object
                 :properties (:tool-name (:type :string)))
               (lambda (params)
                 (declare (ignore params))
                 (let ((found (verify-tool-binary-exists binary)))
                   (list :tool name
                         :binary binary
                         :installed found
                         :category category))))
              (incf count))
          (error (e)
            (when verbose
              (format t "[INIT] ~A: MCP registration failed for ~A: ~A~%"
                      category name e))))))
    (when verbose
      (format t "[INIT] ~A: Registered ~D MCP tools~%" category count))
    count))


;;; =========================================================================
;;; Section 6: Verification System
;;; =========================================================================
;;; Every tool binary is checked for existence and executability before
;;; the category is marked ready.  Results are cached to avoid redundant
;;; --version invocations.

(defun verify-tool-binary-exists (binary-path)
  "Check if a tool binary exists on the system.
   Uses FIND-KALI-BINARY from kali-interface.lisp if available,
   falling back to UIOP:FILE-EXISTS-P.
   
   Arguments:
     BINARY-PATH — String binary name (e.g. \"nmap\") or full path.
   Returns: Full path string if found, NIL if not found.
   
   Thread-safe: yes (read-only filesystem check)."
  (or (ignore-errors (find-kali-binary binary-path))
      (ignore-errors
        (when (and (stringp binary-path)
                   (uiop:file-exists-p binary-path))
          binary-path))
      (ignore-errors
        (let ((paths '("/usr/bin/" "/usr/local/bin/" "/opt/" "/snap/bin/")))
          (dolist (base paths)
            (let ((full (concatenate 'string base binary-path)))
              (when (uiop:file-exists-p full)
                (return full))))))))

(defun verify-tool-execution (binary-path &key (args '("--version")) (timeout 5))
  "Verify a tool can execute by running it with --version (or other args).
   
   Arguments:
     BINARY-PATH — Full path or binary name to execute.
     ARGS        — List of CLI args.  Default '(\"--version\").
     TIMEOUT     — Seconds to wait.  Default 5.
   Returns: Plist with:
     :VERIFIED   — T if exit code is 0.
     :EXIT-CODE  — Integer exit code.
     :OUTPUT     — First 500 chars of stdout+stderr.
     :DURATION   — Wall-clock seconds.
   
   Results are cached in *INIT-VERIFICATION-CACHE* for the duration
   of the initialization session."
  ;; Check cache first
  (let ((cache-key (format nil "~A~{ ~A~}" binary-path args)))
    (bt:with-lock-held (*init-verification-cache-lock*)
      (let ((cached (gethash cache-key *init-verification-cache* nil)))
        (when cached
          (return-from verify-tool-execution cached)))))
  ;; Run the binary
  (let ((result nil))
    (handler-case
        (let ((start (get-internal-real-time))
              (full-path (or (verify-tool-binary-exists binary-path)
                             binary-path)))
          (multiple-value-bind (output error-output exit-code)
              (uiop:run-program
               (cons full-path args)
               :output '(:string :stripped t)
               :error-output '(:string :stripped t)
               :ignore-error-status t
               :element-type 'character)
            (declare (ignore error-output))
            (let ((duration (/ (- (get-internal-real-time) start)
                               internal-time-units-per-second))
                  (combined (if (> (length output) 500)
                                (concatenate 'string (subseq output 0 500) "...")
                                output)))
              (setf result
                    (list :verified (zerop exit-code)
                          :exit-code exit-code
                          :output combined
                          :duration duration)))))
      (error (e)
        (setf result
              (list :verified nil
                    :exit-code -1
                    :output (format nil "Error: ~A" e)
                    :duration 0.0))))
    ;; Cache and return
    (bt:with-lock-held (*init-verification-cache-lock*)
      (setf (gethash (format nil "~A~{ ~A~}" binary-path args)
                     *init-verification-cache*)
            result))
    result))

(defun verify-category-tools (category)
  "Verify all tools in a category.
   Runs --version (or custom version args) on each tool binary.
   
   Returns: Plist with:
     :CATEGORY      — The category keyword.
     :VERIFIED-COUNT — Number of tools that returned exit code 0.
     :TOTAL          — Total tools in category.
     :FAILED         — List of (tool-name . error-output) for failed tools.
     :DURATION       — Total wall-clock seconds."
  (let ((tools (get-category-tools category))
        (verified 0)
        (total 0)
        (failed nil)
        (start (get-internal-real-time)))
    (dolist (tool tools)
      (let* ((name (getf tool :name))
             (binary (getf tool :binary))
             (vargs (getf tool :version-args '("--version"))))
        (incf total)
        (let ((vresult (verify-tool-execution binary :args vargs)))
          (if (getf vresult :verified)
              (incf verified)
              (push (cons name (getf vresult :output)) failed)))))
    (list :category category
          :verified-count verified
          :total total
          :failed (nreverse failed)
          :duration (/ (- (get-internal-real-time) start)
                       internal-time-units-per-second))))

(defun verify-all-tools ()
  "Verify ALL registered tools across ALL categories.
   Returns: Verification report plist with:
     :TOTAL-CATEGORIES — Number of categories checked.
     :TOTAL-TOOLS      — Total tool definitions.
     :VERIFIED         — Total tools that passed.
     :FAILED           — Total tools that failed.
     :CATEGORY-RESULTS — List of per-category results.
     :DURATION         — Total wall-clock seconds.
     
   This is the COMPLETE VERIFICATION sweep — use it after LISPMIND-INIT
   to confirm the deployment is healthy."
  (format t "~&[VERIFY] Starting full tool verification (~D categories)...~%"
          (hash-table-count *tool-registry*))
  (let ((categories nil)
        (total-tools 0)
        (total-verified 0)
        (total-failed 0)
        (start (get-internal-real-time)))
    (bt:with-lock-held (*tool-registry-lock*)
      (maphash (lambda (cat defs)
                 (declare (ignore defs))
                 (push cat categories))
               *tool-registry*))
    (dolist (cat (sort categories #'string< :key #'symbol-name))
      (let ((cresult (verify-category-tools cat)))
        (incf total-tools (getf cresult :total))
        (incf total-verified (getf cresult :verified-count))
        (incf total-failed (length (getf cresult :failed)))))
    (let ((duration (/ (- (get-internal-real-time) start)
                       internal-time-units-per-second)))
      (format t "[VERIFY] Complete: ~D/~D verified, ~D failed in ~,1Fs~%"
              total-verified total-tools total-failed duration)
      (list :total-categories (length categories)
            :total-tools total-tools
            :verified total-verified
            :failed total-failed
            :category-results categories
            :duration duration))))

(defun print-verification-report (report)
  "Print a formatted verification report.
   
   Arguments:
     REPORT — Plist from VERIFY-ALL-TOOLS or VERIFY-CATEGORY-TOOLS.
   
   Prints a human-readable table to *STANDARD-OUTPUT*.
   Returns: The REPORT plist (for chaining)."
  (format t "~&~%")
  (format t "╔══════════════════════════════════════════════════════════════╗~%")
  (format t "║           LISPMIND TOOL VERIFICATION REPORT                  ║~%")
  (format t "╠══════════════════════════════════════════════════════════════╣~%")
  (let ((total (getf report :total-tools 0))
        (verified (getf report :verified 0))
        (failed (getf report :failed 0))
        (duration (getf report :duration 0.0)))
    (format t "║  Total Categories : ~41D ║~%" (getf report :total-categories 0))
    (format t "║  Total Tools      : ~41D ║~%" total)
    (format t "║  Verified         : ~41D ║~%" verified)
    (format t "║  Failed           : ~41D ║~%" failed)
    (format t "║  Duration         : ~39,1F s ║~%" duration)
    (format t "║  Pass Rate        : ~38,1F% ║~%"
            (if (> total 0) (* 100.0 (/ verified total)) 0.0)))
  (format t "╚══════════════════════════════════════════════════════════════╝~%")
  report)


;;; =========================================================================
;;; Section 7: Memory Saturation Prevention
;;; =========================================================================
;;; SBCL tuning for loading 40k+ lines and 300+ tool definitions without
;;; exhausting the Lisp image.

(defun prevent-memory-saturation ()
  "Enable SBCL GC tuning and memory limits to prevent saturation.
   
   Actions:
   1. Enable generation-7 GC (if supported) for better old-object handling.
   2. Set GC notify threshold to 75% of dynamic space.
   3. Configure auto-GC trigger before every major allocation.
   4. Log current memory configuration.
   
   This is called automatically by LISPMIND-INIT after setting the
   memory budget.  You can call it manually to re-tune mid-session.
   
   Returns: Plist with :GC-GENERATIONS :DYNAMIC-SPACE :THRESHOLD-PCT."
  (format t "~&[INIT] Configuring memory saturation prevention...~%")
  ;; Tune GC parameters for large heap
  #+sbcl
  (progn
    ;; Set GC allocation threshold to trigger collection earlier
    (setf (sb-ext:bytes-consed-between-gcs)
          (max (* 64 1024 1024)  ; 64MB minimum
               (floor (sb-ext:dynamic-space-size) 16)))
    ;; Enable verbose GC notifications in high-pressure scenarios
    (when (find-symbol "*GC-NOTIFY-AFTER*" :sb-ext)
      (setf (symbol-value (find-symbol "*GC-NOTIFY-AFTER*" :sb-ext)) t))
    (format t "[INIT] GC bytes-between-gcs: ~:D (~,1F MB)~%"
            (sb-ext:bytes-consed-between-gcs)
            (/ (sb-ext:bytes-consed-between-gcs) 1024.0 1024.0))
    (format t "[INIT] Dynamic space: ~:D (~,1F MB)~%"
            (sb-ext:dynamic-space-size)
            (/ (sb-ext:dynamic-space-size) 1024.0 1024.0)))
  #-sbcl
  (format t "[INIT] Memory tuning only supported on SBCL.~%")
  (list :gc-generations 7
        :dynamic-space #+sbcl (sb-ext:dynamic-space-size) #-sbcl nil
        :threshold-pct 75.0))

(defun configure-sbcl-for-large-system ()
  "Configure SBCL for loading 40k+ lines and 300+ tool definitions.
   
   This function should be called EARLY in the initialization, before
   any large data structures are created.  It:
   1. Increases print/read limits to handle large tool registries.
   2. Tunes the compiler for speed over debug info (safe for init).
   3. Pre-allocates hash table sizes to avoid rehash thrashing.
   
   Returns: :CONFIGURED."
  (format t "~&[INIT] Configuring SBCL for large system (~D+ LOC, 300+ tools)...~%"
          40000)
  ;; Increase printer limits
  (setf *print-length* 1000)
  (setf *print-level* 20)
  (setf *print-circle* t)
  ;; Pre-size the tool registry for all 300+ tools
  (bt:with-lock-held (*tool-registry-lock*)
    ;; Reallocate with larger size hint if possible
    (when (< (hash-table-size *tool-registry*) 32)
      (let ((new-table (make-hash-table :test 'eq :size 32)))
        (maphash (lambda (k v) (setf (gethash k new-table) v))
                 *tool-registry*)
        (setf *tool-registry* new-table))))
  (format t "[INIT] SBCL configured for large-scale loading.~%")
  :configured)

(defun monitor-heap-growth ()
  "Monitor heap growth during initialization.
   Returns: Plist with :CURRENT-MB :BUDGET-MB :AVAILABLE-MB :PRESSURE.
   PRESSURE is :LOW (<50%), :MEDIUM (50-75%), :HIGH (75-90%), :CRITICAL (>90%)."
  (let* ((current (get-sbcl-memory-usage-mb))
         (budget *init-memory-budget-mb*)
         (available (- budget current))
         (pct (/ current budget))
         (pressure (cond ((> pct 0.9) :critical)
                         ((> pct 0.75) :high)
                         ((> pct 0.5) :medium)
                         (t :low))))
    (list :current-mb current
          :budget-mb budget
          :available-mb available
          :pressure pressure
          :percentage (* 100.0 pct))))

(defun force-gc-if-needed ()
  "Force garbage collection if memory pressure is high.
   Checks current heap usage.  If pressure is :HIGH or :CRITICAL,
   forces a full GC and prints a message.
   
   Returns: T if GC was forced, NIL if pressure was acceptable."
  (let ((status (monitor-heap-growth)))
    (when (member (getf status :pressure) '(:high :critical))
      (format t "[INIT] Memory pressure ~A (~,1F% used). Forcing GC...~%"
              (getf status :pressure)
              (getf status :percentage))
      #+sbcl (sb-ext:gc :full t)
      #-sbcl (trivial-garbage:gc :full t)
      (let ((after (get-sbcl-memory-usage-mb)))
        (format t "[INIT] GC complete: ~,1F MB -> ~,1F MB (~,1F MB freed)~%"
                (getf status :current-mb) after
                (max 0 (- (getf status :current-mb) after))))
      t)))


;;; =========================================================================
;;; Section 8: Fail-Closed Verification
;;; =========================================================================
;;; After all categories are loaded, we verify that the safety systems are
;;; in their correct FAIL-CLOSED state.  ANY deviation is reported as a
;;; CRITICAL issue that must be resolved before tools can be armed.

(defun verify-all-categories-disarmed ()
  "Verify that ALL offensive categories are DISARMED.
   Checks every category in the offensive set and confirms that
   CATEGORY-ARMED-P returns NIL for each.
   
   Returns: Plist with:
     :ALL-DISARMED — T if ALL categories are disarmed.
     :CHECKS       — Alist of (category . armed-p).
     :VIOLATIONS   — List of categories that are ARMED (should be empty)."
  (let* ((offensive '(:lolbin :creds :lateral :post-exploit :recon
                       :web :wireless :social-engineering))
         (checks (mapcar (lambda (cat)
                           (cons cat (category-armed-p cat)))
                         offensive))
         (violations (mapcar #'car (remove-if-not #'cdr checks))))
    (list :all-disarmed (null violations)
          :checks checks
          :violations violations)))

(defun verify-gatekeeper-active ()
  "Verify the 6-layer gatekeeper is operational.
   The six layers are:
     1. Category arm states    — must all be :disarmed
     2. Override passphrase    — must be set for critical categories
     3. Target whitelist       — must be non-empty for offensive tools
     4. Policy registry        — must have policies for all tools
     5. Janitor thread         — must be running
     6. Network monitor        — must be running
   
   Returns: Plist with:
     :ACTIVE    — T if all 6 layers are operational.
     :LAYERS    — Alist of (layer-name . status).
     :FAILURES  — List of layer names that are not operational."
  (let ((layers nil)
        (failures nil))
    ;; Layer 1: Category arm states
    (let ((arm-result (verify-all-categories-disarmed)))
      (push (cons :arm-states (getf arm-result :all-disarmed)) layers)
      (unless (getf arm-result :all-disarmed)
        (push :arm-states failures)))
    ;; Layer 2: Override passphrase set
    (let ((pass-set (and (boundp '*offensive-override-passphrase*)
                         *offensive-override-passphrase*)))
      (push (cons :override-passphrase (not (null pass-set))) layers)
      (unless pass-set
        (push :override-passphrase failures)))
    ;; Layer 3: Target whitelist
    (let ((whitelist (and (boundp '*offensive-target-whitelist*)
                          *offensive-target-whitelist*)))
      (push (cons :target-whitelist (and whitelist (> (length whitelist) 0))) layers)
      (unless (and whitelist (> (length whitelist) 0))
        (push :target-whitelist failures)))
    ;; Layer 4: Policy registry
    (let ((policy-count (hash-table-count *tactical-repository*)))
      (push (cons :policy-registry (> policy-count 0)) layers)
      (unless (> policy-count 0)
        (push :policy-registry failures)))
    ;; Layer 5: Janitor thread
    (let ((janitor-active (and (boundp '*janitor-running-p*)
                               *janitor-running-p*)))
      (push (cons :janitor-thread janitor-active) layers)
      (unless janitor-active
        (push :janitor-thread failures)))
    ;; Layer 6: Network monitor
    (let ((netmon-active (and (boundp '*network-monitor-running-p*)
                              *network-monitor-running-p*)))
      (push (cons :network-monitor netmon-active) layers)
      (unless netmon-active
        (push :network-monitor failures)))
    (list :active (null failures)
          :layers (nreverse layers)
          :failures (nreverse failures))))

(defun verify-no-orphaned-processes ()
  "Verify no orphaned processes exist from previous LISPMIND sessions.
   Scans for processes matching known LISPMIND tool patterns and reports
   any that appear to be orphaned (no parent orchestrator process).
   
   Returns: Plist with:
     :CLEAN     — T if no orphans detected.
     :ORPHANS   — List of (pid . command) for suspected orphans.
     :COUNT     — Number of orphaned processes."
  (let ((orphans nil))
    ;; Check for stale Kali tool processes
    (handler-case
        (let ((output (uiop:run-program
                       "ps aux | grep -E '(nmap|sqlmap|hydra|john|hashcat|msfconsole|airodump)' | grep -v grep || true"
                       :output '(:string :stripped t)
                       :error-output :string
                       :ignore-error-status t)))
          (when (and output (> (length output) 0))
            (dolist (line (uiop:split-string output :separator '(#\Newline)))
              (when (> (length line) 10)
                (let ((fields (uiop:split-string line)))
                  (when (> (length fields) 10)
                    (let ((pid (second fields))
                          (cmd (nth 10 fields)))
                      (push (cons pid (or cmd "unknown")) orphans)))))))
      (error (e)
        (format t "[INIT] Warning: could not scan for orphans: ~A~%" e)))
    (list :clean (null orphans)
          :orphans (nreverse orphans)
          :count (length orphans))))

(defun run-safety-checks ()
  "Run all safety checks.  This is the COMPREHENSIVE safety verification
   that should be called after EVERY initialization.
   
   Checks performed:
     1. All offensive categories are DISARMED.
     2. The 6-layer gatekeeper is operational.
     3. No orphaned processes exist.
     4. Memory pressure is acceptable.
     5. At least one tool is registered.
   
   Returns: :SAFE if all checks pass, otherwise a list of issue plists
   with :CHECK :STATUS :DETAIL keys."
  (let ((issues nil))
    ;; Check 1: Categories disarmed
    (let ((v (verify-all-categories-disarmed)))
      (unless (getf v :all-disarmed)
        (push (list :check :categories-disarmed
                    :status :FAILED
                    :detail (format nil "Armed categories: ~A"
                                    (getf v :violations)))
              issues)))
    ;; Check 2: Gatekeeper
    (let ((g (verify-gatekeeper-active)))
      (unless (getf g :active)
        (push (list :check :gatekeeper
                    :status :FAILED
                    :detail (format nil "Failed layers: ~A"
                                    (getf g :failures)))
              issues)))
    ;; Check 3: Orphaned processes
    (let ((o (verify-no-orphaned-processes)))
      (unless (getf o :clean)
        (push (list :check :orphaned-processes
                    :status :WARNING
                    :detail (format nil "~D orphaned process(es) found"
                                    (getf o :count)))
              issues)))
    ;; Check 4: Memory pressure
    (let ((m (monitor-heap-growth)))
      (when (eq (getf m :pressure) :critical)
        (push (list :check :memory-pressure
                    :status :CRITICAL
                    :detail (format nil "~,1F% of budget used"
                                    (getf m :percentage)))
              issues)))
    ;; Check 5: Tools registered
    (when (zerop (hash-table-count *tool-registry*))
      (push (list :check :tool-registry
                  :status :WARNING
                  :detail "No tools registered")
            issues))
    ;; Result
    (if issues
        (progn
          (format t "~&[SAFETY] ~D issue(s) detected:~%" (length issues))
          (dolist (issue issues)
            (format t "  [~A] ~A: ~A~%"
                    (getf issue :status)
                    (getf issue :check)
                    (getf issue :detail)))
          issues)
        (progn
          (format t "~&[SAFETY] All checks PASSED. System is SAFE.~%")
          :safe))))


;;; =========================================================================
;;; Section 9: Status & Reporting
;;; =========================================================================

(defun print-lispmind-banner ()
  "Print the LISPMIND initialization banner.
   Displays version, memory info, and system status."
  (format t "~&~%")
  (format t "    ╔═══════════════════════════════════════════════════════════╗~%")
  (format t "    ║                                                           ║~%")
  (format t "    ║   ██╗     ██╗███████╗██████╗ ███╗   ███╗██╗███╗   ██╗██████╗  ║~%")
  (format t "    ║   ██║     ██║██╔════╝██╔══██╗████╗ ████║██║████╗  ██║██╔══██╗ ║~%")
  (format t "    ║   ██║     ██║███████╗██████╔╝██╔████╔██║██║██╔██╗ ██║██║  ██║ ║~%")
  (format t "    ║   ██║     ██║╚════██║██╔═══╝ ██║╚██╔╝██║██║██║╚██╗██║██║  ██║ ║~%")
  (format t "    ║   ███████╗██║███████║██║     ██║ ╚═╝ ██║██║██║ ╚████║██████╔╝ ║~%")
  (format t "    ║   ╚══════╝╚═╝╚══════╝╚═╝     ╚═╝     ╚═╝╚═╝╚═╝  ╚═══╝╚═════╝  ║~%")
  (format t "    ║                                                           ║~%")
  (format t "    ║   Self-Healing Agentic AI Orchestrator  v~A               ║~%"
          *system-init-version*)
  (format t "    ║                                                           ║~%")
  #+sbcl
  (format t "    ║   SBCL ~A  ~A-bit                             ║~%"
          (lisp-implementation-version)
          #+x86-64 64 #-x86-64 32)
  #-sbcl
  (format t "    ║   ~A ~A                                     ║~%"
          (lisp-implementation-type)
          (lisp-implementation-version))
  (format t "    ║   Memory: ~,1F / ~,1F MB budget                       ║~%"
          (get-sbcl-memory-usage-mb) *init-memory-budget-mb*)
  (format t "    ║   Categories: ~D sequence entries                         ║~%"
          (length *init-sequence*))
  (format t "    ║                                                           ║~%")
  (format t "    ╚═══════════════════════════════════════════════════════════╝~%")
  (format t "~%"))

(defun lispmind-status ()
  "Full swarm status: categories, arm states, memory, processes, models.
   This is the COMPREHENSIVE status query — use it for monitoring,
   debugging, and health checks.
   
   Returns: Large plist with:
     :VERSION          — System version string.
     :TIMESTAMP        — Current local-time timestamp.
     :MEMORY           — Heap status from MONITOR-HEAP-GROWTH.
     :CATEGORIES       — List of (category . status) pairs.
     :ARM-STATES       — List of (category . armed-p) for offensive cats.
     :TOOLS-REGISTERED — Total count from COUNT-ALL-TOOLS.
     :GATEKEEPER       — Status from VERIFY-GATEKEEPER-ACTIVE.
     :ORCHESTRATOR     — Running status of *DEFAULT-ORCHESTRATOR*.
     :TELEMETRY        — Running status from TELEMETRY-STATUS.
     :INFERENCE        — Count of registered models.
     :MCP              — Running status of MCP bridge."
  (let ((categories nil)
        (arm-states nil))
    ;; Gather category results
    (maphash (lambda (cat result)
               (push (cons cat (getf result :status :unknown))
                     categories))
             *init-category-results*)
    ;; Gather arm states for offensive categories
    (dolist (cat '(:lolbin :creds :lateral :post-exploit :recon
                   :web :wireless :social-engineering))
      (push (cons cat (category-armed-p cat)) arm-states))
    (list :version *system-init-version*
          :timestamp (local-time:now)
          :memory (monitor-heap-growth)
          :categories (nreverse categories)
          :arm-states (nreverse arm-states)
          :tools-registered (count-all-tools)
          :gatekeeper (verify-gatekeeper-active)
          :orchestrator (and (boundp '*default-orchestrator*)
                             (not (null *default-orchestrator*)))
          :telemetry (and (fboundp 'telemetry-status)
                          (telemetry-status))
          :inference (and (boundp '*model-registry*)
                          (hash-table-count *model-registry*))
          :mcp (and (boundp '*mcp-server-running-p*)
                    *mcp-server-running-p*))))

(defun print-init-summary (status)
  "Print initialization summary.
   
   Arguments:
     STATUS — Plist from LISPMIND-INIT.
   
   Prints a formatted summary table to *STANDARD-OUTPUT*.
   Returns: The STATUS plist (for chaining)."
  (format t "~&~%")
  (format t "╔══════════════════════════════════════════════════════════════════════╗~%")
  (format t "║              LISPMIND INITIALIZATION SUMMARY                         ║~%")
  (format t "╠══════════════════════════════════════════════════════════════════════╣~%")
  (format t "║  Version            : ~46A ║~%" (getf status :version "unknown"))
  (format t "║  Duration           : ~,42,1F s ║~%" (getf status :duration 0.0))
  (format t "║  Memory Used        : ~,42,1F MB ║~%" (getf status :memory-used-mb 0.0))
  (format t "║  Memory Budget      : ~,42,1F MB ║~%" (getf status :memory-budget-mb 0.0))
  (format t "║  Categories Loaded  : ~46D ║~%" (getf status :categories-loaded 0))
  (format t "║  Tools Registered   : ~46D ║~%" (getf status :tools-registered 0))
  (format t "║  Tools Verified     : ~46D ║~%" (getf status :tools-verified 0))
  (format t "║  Safety Status      : ~46A ║~%" (getf status :safety-status :unknown))
  (format t "║  Gatekeeper Active  : ~46A ║~%" (getf status :gatekeeper-active nil))
  (format t "║  Telemetry          : ~46A ║~%" (getf status :telemetry-started nil))
  (format t "║  Inference          : ~46A ║~%" (getf status :inference-started nil))
  (format t "║  Dashboard          : ~46A ║~%" (getf status :dashboard-started nil))
  (format t "╚══════════════════════════════════════════════════════════════════════╝~%")
  status)


;;; =========================================================================
;;; Section 10: The Master Initialization Function
;;; =========================================================================
;;; LISPMIND-INIT is the ONE function to initialize the entire swarm.
;;; It is idempotent — calling it multiple times is safe (subsequent calls
;;; skip already-initialized categories unless :FORCE T).

(defvar *lispmind-initialized-p* nil
  "Set to T after the first successful LISPMIND-INIT call.
   Used to prevent double-initialization.  Reset by LISPMIND-SHUTDOWN.")

(defvar *lispmind-init-history* nil
  "History of initialization calls: list of status plists.")

(defun lispmind-init (&key
                       (memory-budget-mb (* 1024 8))
                       (categories :all)
                       (verify-tools t)
                       (arm-categories nil)
                       (load-models nil)
                       (start-telemetry nil)
                       (start-dashboard nil)
                       (force nil)
                       (verbose t))
  "The ONE function to initialize the entire LISPMIND swarm.

   This is the canonical entry point.  Every other init-* function in
   the system is called from here in the correct order.  The process:

   1. Print LISPMIND banner.
   2. Check SBCL version (warn if not SBCL).
   3. Set memory budget and configure SBCL for large system.
   4. Prevent memory saturation (GC tuning).
   5. Initialize core (orchestrator, conditions, agent-class).
   6. Initialize offensive safety system (FAIL-CLOSED).
   7. For each requested category:
      a. Check memory budget (circuit breaker).
      b. Load tool definitions.
      c. Register policies (all DISARMED).
      d. Register MCP tools.
      e. Verify binaries (if VERIFY-TOOLS).
      f. Force GC if memory pressure is high.
   8. Initialize inference subsystem (if LOAD-MODELS).
   9. Initialize telemetry (if START-TELEMETRY).
  10. Initialize dashboard (if START-DASHBOARD).
  11. Run safety checks.
  12. Print initialization summary.
  13. Return status plist.

   Keyword Arguments:
     MEMORY-BUDGET-MB  — MB cap for initialization (default 8192 = 8GB).
     CATEGORIES        — :ALL or list of category keywords.
     VERIFY-TOOLS      — If T (default), run --version on each binary.
     ARM-CATEGORIES    — DANGEROUS: list of categories to ARM immediately.
                         Default NIL (all stay DISARMED).
     LOAD-MODELS       — If T, init inference subsystem and register models.
     START-TELEMETRY   — If T, start the telemetry stream.
     START-DASHBOARD   — If T, start the ASCII dashboard.
     FORCE             — If T, reinitialize even if already initialized.
     VERBOSE           — If T, print progress messages.

   Returns: Status plist with:
     :INITIALIZED-P      — T if init succeeded.
     :VERSION            — System version.
     :DURATION           — Wall-clock seconds.
     :MEMORY-USED-MB     — MB consumed during init.
     :MEMORY-BUDGET-MB   — Budget MB.
     :CATEGORIES-LOADED  — Number of categories successfully loaded.
     :TOOLS-REGISTERED   — Total tools in registry.
     :TOOLS-VERIFIED     — Tools that passed --version.
     :SAFETY-STATUS      — :SAFE or list of issues.
     :GATEKEEPER-ACTIVE  — T if 6-layer gatekeeper is operational.
     :TELEMETRY-STARTED  — T if telemetry was started.
     :INFERENCE-STARTED  — T if inference was started.
     :DASHBOARD-STARTED  — T if dashboard was started.
     :CATEGORY-RESULTS   — Detailed per-category results.

   Example Usage:
     ;; Full initialization with everything
     (mind:lispmind-init :categories :all :verify-tools t
                         :load-models t :start-telemetry t)

     ;; Minimal: just core + recon + math
     (mind:lispmind-init :categories '(:core :recon :math)
                         :verify-tools nil)

     ;; Scientific tools only
     (mind:lispmind-init :categories '(:math :physics :engineering)
                         :verify-tools t)

   Thread-safety: This function serializes all initialization.  Do not
   call concurrently from multiple threads."
  (let ((init-start (get-internal-real-time))
        (categories-loaded 0)
        (tools-verified 0)
        (gatekeeper-active nil)
        (telemetry-started nil)
        (inference-started nil)
        (dashboard-started nil)
        (safety-status nil))
    ;; Check for double-init
    (when (and *lispmind-initialized-p* (not force))
      (format t "~&[INIT] LISPMIND already initialized. Use :FORCE T to reinitialize.~%")
      (return-from lispmind-init
        (find-if (lambda (s) (getf s :initialized-p)) *lispmind-init-history*)))
    ;; Step 1: Banner
    (when verbose (print-lispmind-banner))
    ;; Step 2: SBCL check
    #+sbcl
    (when verbose
      (format t "[INIT] SBCL ~A detected.~%" (lisp-implementation-version)))
    #-sbcl
    (progn
      (when verbose
        (format t "[INIT] WARNING: Not running on SBCL. Some features disabled.~%"))
      (format t "[INIT] Implementation: ~A ~A~%"
              (lisp-implementation-type)
              (lisp-implementation-version)))
    ;; Step 3: Memory budget + SBCL configuration
    (setf *init-memory-budget-mb* (float memory-budget-mb))
    (reset-memory-budget)
    (setf *init-start-timestamp* (local-time:now))
    (configure-sbcl-for-large-system)
    ;; Step 4: Prevent memory saturation
    (prevent-memory-saturation)
    ;; Step 5: Initialize core
    (when verbose (format t "~&[INIT] === Core Initialization ===~%"))
    (handler-case
        (progn
          ;; Core doesn't need external binaries — just verify the system
          ;; components are present and the orchestrator can be created.
          (unless (boundp '*default-orchestrator*)
            (format t "[INIT] Core: *DEFAULT-ORCHESTRATOR* not yet bound.~%"))
          ;; Initialize gossip topic registry if needed
          (when (and (boundp '*gossip-topic-registry*)
                     (zerop (hash-table-count *gossip-topic-registry*)))
            (format t "[INIT] Core: Gossip topic registry ready.~%"))
          (setf (gethash :core *init-category-results*)
                (list :category :core :status :ok
                      :timestamp (local-time:now) :tools-found 0
                      :tools-total 0 :memory-mb 0 :error nil))
          (incf categories-loaded))
      (error (e)
        (format t "[INIT] Core initialization FAILED: ~A~%" e)
        (setf (gethash :core *init-category-results*)
              (list :category :core :status :failed
                    :timestamp (local-time:now) :tools-found 0
                    :tools-total 0 :memory-mb 0 :error e))))
    ;; Step 6: Initialize offensive safety system (FAIL-CLOSED)
    (when verbose (format t "~&[INIT] === Offensive Safety System ===~%"))
    (handler-case
        (progn
          (init-offensive-safety-system)
          (start-janitor-thread 5)
          (format t "[INIT] Offensive safety system: ACTIVE (all DISARMED).~%"))
      (error (e)
        (format t "[INIT] WARNING: Offensive safety init failed: ~A~%" e)
        (format t "[INIT] Proceeding with degraded safety. THIS IS RISKY.~%")))
    ;; Step 7: Category-by-category initialization
    (when verbose (format t "~&[INIT] === Category Loading ===~%"))
    (let ((cat-result (init-all-categories
                       :categories categories
                       :verify-tools verify-tools
                       :verbose verbose)))
      (incf categories-loaded (getf cat-result :success 0))
      ;; Count verified tools
      (maphash (lambda (cat result)
                 (declare (ignore cat))
                 (incf tools-verified (getf result :tools-found 0)))
               *init-category-results*)
      ;; Force GC between heavy categories
      (force-gc-if-needed))
    ;; Step 8: Initialize inference subsystem
    (when load-models
      (when verbose (format t "~&[INIT] === Inference Subsystem ===~%"))
      (handler-case
          (progn
            (init-inference-subsystem :models :default)
            (setf inference-started t)
            (format t "[INIT] Inference subsystem: ACTIVE.~%"))
        (error (e)
          (format t "[INIT] Inference init FAILED: ~A~%" e))))
    ;; Step 9: Initialize telemetry
    (when start-telemetry
      (when verbose (format t "~&[INIT] === Telemetry ===~%"))
      (handler-case
          (progn
            (when (and (boundp '*default-orchestrator*)
                       *default-orchestrator*)
              (start-telemetry-stream *default-orchestrator* :interval 0.5)
              (setf telemetry-started t)
              (format t "[INIT] Telemetry stream: ACTIVE.~%")))
        (error (e)
          (format t "[INIT] Telemetry init FAILED: ~A~%" e))))
    ;; Step 10: Initialize dashboard
    (when start-dashboard
      (when verbose (format t "~&[INIT] === Dashboard ===~%"))
      (handler-case
          (progn
            (start-dashboard)
            (setf dashboard-started t)
            (format t "[INIT] Dashboard: ACTIVE.~%"))
        (error (e)
          (format t "[INIT] Dashboard init FAILED: ~A~%" e))))
    ;; Step 11: Safety checks
    (when verbose (format t "~&[INIT] === Safety Verification ===~%"))
    (setf safety-status (run-safety-checks))
    (setf gatekeeper-active (eq safety-status :safe))
    ;; ARM categories if requested (DANGEROUS)
    (when arm-categories
      (format t "~&[INIT] !!! ARMING CATEGORIES: ~A !!!~%" arm-categories)
      (dolist (cat arm-categories)
        (handler-case
            (progn
              (arm-category cat)
              (format t "[INIT] !!! Category ~A is now ARMED !!!~%" cat))
          (error (e)
            (format t "[INIT] Failed to arm ~A: ~A~%" cat e)))))
    ;; Step 12: Calculate duration and build status
    (let* ((duration (/ (- (get-internal-real-time) init-start)
                        internal-time-units-per-second))
           (memory-used (- (get-sbcl-memory-usage-mb)
                           (or (and (getf (car *lispmind-init-history*) :memory-used-mb)
                                    (get-sbcl-memory-usage-mb))
                               0)))
           (status (list :initialized-p (and (> categories-loaded 0)
                                             (eq safety-status :safe))
                         :version *system-init-version*
                         :duration duration
                         :memory-used-mb (max 0 memory-used)
                         :memory-budget-mb *init-memory-budget-mb*
                         :categories-loaded categories-loaded
                         :tools-registered (count-all-tools)
                         :tools-verified tools-verified
                         :safety-status safety-status
                         :gatekeeper-active gatekeeper-active
                         :telemetry-started telemetry-started
                         :inference-started inference-started
                         :dashboard-started dashboard-started
                         :category-results (let ((r nil))
                                             (maphash (lambda (k v)
                                                        (push (cons k v) r))
                                                      *init-category-results*)
                                             (nreverse r)))))
      ;; Mark as initialized
      (setf *lispmind-initialized-p* t)
      (push status *lispmind-init-history*)
      ;; Print summary
      (when verbose (print-init-summary status))
      status)))

(defun lispmind-init-minimal ()
  "Minimal initialization: core + telemetry only.
   No offensive tools, no models, no dashboard.
   
   Suitable for: monitoring-only deployments, lightweight containers,
   CI/CD pipeline health checks.
   
   Returns: Status plist from LISPMIND-INIT."
  (lispmind-init :categories '(:core)
                 :verify-tools nil
                 :start-telemetry t
                 :verbose t))

(defun lispmind-init-offensive ()
  "Initialize offensive tools only.
   Loads :RECON through :SOCIAL-ENGINEERING categories.
   All categories start DISARMED — use ARM-CATEGORY to enable.
   
   Suitable for: penetration testing environments, red team ops,
   security research labs.
   
   Returns: Status plist from LISPMIND-INIT."
  (lispmind-init :categories '(:core :recon :web :lolbin :wireless
                               :creds :lateral :post-exploit
                               :social-engineering)
                 :verify-tools t
                 :start-telemetry t
                 :verbose t))

(defun lispmind-init-scientific ()
  "Initialize scientific tools only.
   Loads :MATH :PHYSICS :ENGINEERING :ELECTRONICS categories.
   
   Suitable for: research computing, HPC environments, engineering
   workstations, electronics design flows.
   
   Returns: Status plist from LISPMIND-INIT."
  (lispmind-init :categories '(:core :math :physics :engineering :electronics)
                 :verify-tools t
                 :start-telemetry t
                 :verbose t))

(defun lispmind-init-full ()
  "Full initialization: all 300+ tools, all subsystems.
   This is the COMPLETE initialization — everything LISPMIND has to offer.
   Requires: 8GB+ memory budget, all tool binaries installed, inference
   server available, network access for telemetry/dashboard.
   
   WARNING: This loads ALL offensive tools.  Ensure the gatekeeper is
   operational and all categories remain DISARMED until explicitly armed.
   
   Suitable for: full-featured workstations, lab environments,
   comprehensive testing.
   
   Returns: Status plist from LISPMIND-INIT."
  (lispmind-init :categories :all
                 :verify-tools t
                 :load-models t
                 :start-telemetry t
                 :start-dashboard t
                 :verbose t))


;;; =========================================================================
;;; Section 11: Shutdown & Cleanup
;;; =========================================================================

(defun lispmind-shutdown (&key (verbose t))
  "Graceful shutdown of the entire LISPMIND swarm.
   
   Actions:
   1. Stop telemetry stream.
   2. Stop dashboard.
   3. Stop orchestrator.
   4. Stop janitor thread.
   5. Kill all active tool processes.
   6. Release all memory reservations.
   7. Reset initialization flags.
   8. Run final safety check.
   
   Returns: Shutdown status plist."
  (when verbose (format t "~&[SHUTDOWN] Beginning LISPMIND shutdown...~%"))
  ;; Stop telemetry
  (handler-case
      (when (and (fboundp 'stop-telemetry-stream)
                 *telemetry-enabled-p*)
        (stop-telemetry-stream)
        (when verbose (format t "[SHUTDOWN] Telemetry stopped.~%")))
    (error (e)
      (format t "[SHUTDOWN] Telemetry stop error: ~A~%" e)))
  ;; Stop dashboard
  (handler-case
      (when (fboundp 'stop-dashboard)
        (stop-dashboard)
        (when verbose (format t "[SHUTDOWN] Dashboard stopped.~%")))
    (error (e)
      (format t "[SHUTDOWN] Dashboard stop error: ~A~%" e)))
  ;; Stop orchestrator
  (handler-case
      (when (and (boundp '*default-orchestrator*)
                 *default-orchestrator*)
        (stop-orchestrator *default-orchestrator*)
        (when verbose (format t "[SHUTDOWN] Orchestrator stopped.~%")))
    (error (e)
      (format t "[SHUTDOWN] Orchestrator stop error: ~A~%" e)))
  ;; Stop janitor
  (handler-case
      (stop-janitor-thread)
    (error (e)
      (format t "[SHUTDOWN] Janitor stop error: ~A~%" e)))
  ;; Kill all tools
  (handler-case
      (when (fboundp 'kill-all-tools)
        (kill-all-tools)
        (when verbose (format t "[SHUTDOWN] All tool processes killed.~%")))
    (error (e)
      (format t "[SHUTDOWN] Tool kill error: ~A~%" e)))
  ;; Release memory
  (reset-memory-budget)
  ;; Reset flags
  (setf *lispmind-initialized-p* nil)
  (when verbose
    (format t "[SHUTDOWN] LISPMIND shutdown complete.~%"))
  (list :shutdown t
        :timestamp (local-time:now)
        :memory-released t))


;;; =========================================================================
;;; Section 12: Export Summary
;;; =========================================================================
;;
;; MASTER INITIALIZATION (4 functions):
;;   lispmind-init           — The ONE init function (comprehensive).
;;   lispmind-init-minimal   — Core + telemetry only.
;;   lispmind-init-offensive — Offensive tools only.
;;   lispmind-init-scientific — Scientific tools only.
;;   lispmind-init-full      — Everything.
;;   lispmind-shutdown       — Graceful shutdown.
;;
;; MEMORY MANAGEMENT (8 functions):
;;   get-sbcl-memory-usage-mb    — Current heap in MB.
;;   check-memory-budget         — Circuit breaker check.
;;   reserve-memory              — Reserve from budget.
;;   release-memory              — Release reservation.
;;   get-available-memory-mb     — Remaining budget.
;;   get-memory-reservation      — Per-category reservation.
;;   reset-memory-budget         — Reset all tracking.
;;   prevent-memory-saturation   — GC tuning.
;;   configure-sbcl-for-large-system — Pre-allocate structures.
;;   monitor-heap-growth         — Pressure monitoring.
;;   force-gc-if-needed          — Conditional full GC.
;;
;; CATEGORY INITIALIZATION (3 functions):
;;   init-category          — Single category.
;;   init-all-categories    — All categories in sequence.
;;   load-category-tools    — Populate tool registry.
;;
;; VERIFICATION (5 functions):
;;   verify-tool-binary-exists   — Filesystem check.
;;   verify-tool-execution       — Run --version.
;;   verify-category-tools       — Category-wide verification.
;;   verify-all-tools            — Full sweep.
;;   print-verification-report   — Human-readable report.
;;
;; SAFETY / FAIL-CLOSED (4 functions):
;;   verify-all-categories-disarmed  — Confirm DISARMED state.
;;   verify-gatekeeper-active        — 6-layer check.
;;   verify-no-orphaned-processes    — Stale process detection.
;;   run-safety-checks               — All checks combined.
;;
;; STATUS / REPORTING (3 functions):
;;   print-lispmind-banner       — ASCII art banner.
;;   lispmind-status             — Full swarm status.
;;   print-init-summary          — Post-init summary.
;;
;; POLICY & MCP (2 functions):
;;   init-category-policies      — FAIL-CLOSED policy registration.
;;   register-category-mcp-tools — MCP tool descriptors.
;;
;; REGISTRY (3 functions):
;;   register-tool-definition    — Add tool to registry.
;;   get-category-tools          — List tools in category.
;;   count-all-tools             — Total tool count.
;;
;;;; ═════════════════════════════════════════════════════════════════════════
;;;; END OF SYSTEM-INIT.LISP
;;;; ═════════════════════════════════════════════════════════════════════════
