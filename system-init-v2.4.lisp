;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;; SYSTEM INIT v2.4 — Tactical Swarm Initialization
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; STRIPPED from v2.3.1:
;;;   • All simulation bridges and validation loops
;;;   • All defensive validation (thermal monitoring, memory saturation checks)
;;;   • All scientific tool loading (:math :physics :engineering :electronics :ai-ml)
;;;   • All memory budgeting and orphan process detection
;;;   • All model loading and inference subsystem initialization
;;;   • Engineering subsystem and CAD tool interfaces
;;;   • Dashboard and telemetry stream startup (telemetry snapshots only)
;;;
;;; ADDED in v2.4:
;;;   • Tactical gossip mode (low-bandwidth heartbeat mesh)
;;;   • Auto-checkpoint (30s interval, resume from last known state)
;;;   • TTS (time-to-shell) evolution pipeline
;;;   • Persistence-first pipeline (persist before pivot)
;;;   • Fail-fast rotation (drop slow vectors, rotate immediately)
;;;   • 145+ offensive tool definitions across 8 categories
;;;   • Speed-first tool registry (evasion + speed rankings)
;;;
;;; DESIGN PHILOSOPHY
;;; ─────────────────
;;; v2.4 is SPEED AND EVASION ONLY. Every millisecond of init time that
;;; isn't spent loading an offensive tool is wasted. Every byte of memory
;;; not holding a tool definition is excess. Every validation step is a
;;; detection surface.
;;;
;;; FAIL-FAST: If a tool doesn't load, skip it and move on. Don't retry.
;;;            Don't validate. Don't verify binaries. Load and go.
;;;
;;; FAIL-CLOSED: All categories start DISARMED. ARM only when you're
;;;              ready to engage. This is the ONE safety measure we keep.
;;;
;;; "In combat, preparation is paralysis. Load fast, arm late, strike once."

(in-package :lispmind)

(eval-when (:compile-toplevel :load-toplevel :execute)
  (defparameter *system-init-v2.4-version* "2.4.0"
    "Version string for the v2.4 tactical initialization subsystem."))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 1: v2.4 Tactical Tool Registry — 145+ Offensive Tools
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *tactical-tool-registry* (make-hash-table :test 'eq)
  "Hash table: category-keyword -> list of tactical tool plists.

   Each tool definition is a plist with keys:
     :NAME        — Symbol naming the tool (e.g. 'NMAP).
     :BINARY      — String binary name for PATH lookup.
     :CATEGORY    — Keyword category.
     :ENTRY-TYPE  — Keyword: :RECON :EXPLOIT :CREDS :LATERAL :PERSIST
                    :POST-EX :SOCIAL :WIRELESS :WEB.
     :SPEED-RANK  — Integer 1-10 (10 = fastest setup-to-result).
     :EVASION-RANK — Integer 1-10 (10 = most stealthy).
     :TTS-ESTIMATE — Estimated seconds to first meaningful result.
     :NOISE-LEVEL  — Integer 0-100, expected network noise.
     :REQUIRES-ROOT — T if tool needs root.
     :DESCRIPTION  — Human-readable short description.
     :PARAMETERS   — Default parameter plist for the tool.

   The SPEED-RANK and EVASION-RANK are used by the fail-fast rotation
   system to select the fastest, most evasive tool for a given task.

   Populated by REGISTER-TACTICAL-TOOL and loaded in bulk by
   LOAD-TACTICAL-CATEGORY. Thread-safe: reads are lockless.")

(defvar *tactical-tool-count* 0
  "Counter of registered tactical tools. Incremented by
   REGISTER-TACTICAL-TOOL.")

(defvar *tactical-categories-loaded* nil
  "List of category keywords that have been successfully loaded.
   Used by TACTICAL-SWARM-STATUS to report init state.")

(defun register-tactical-tool (category name binary entry-type
                               &key (speed-rank 5) (evasion-rank 5)
                                    (tts-estimate 60) (noise-level 50)
                                    (requires-root nil)
                                    (description "")
                                    (parameters nil))
  "Register a single tactical tool in the registry.

   Arguments:
     CATEGORY      — Keyword: :RECON :WEB :LOLBIN :CREDS :LATERAL
                     :POST-EXPLOIT :SOCIAL-ENGINEERING :WIRELESS.
     NAME          — Symbol naming the tool.
     BINARY        — String, binary name for PATH lookup.
     ENTRY-TYPE    — Keyword: :RECON :EXPLOIT :CREDS :LATERAL :PERSIST
                     :POST-EX :SOCIAL :WIRELESS :WEB.
     SPEED-RANK    — Integer 1-10 (default 5).
     EVASION-RANK  — Integer 1-10 (default 5).
     TTS-ESTIMATE  — Integer, estimated seconds to result (default 60).
     NOISE-LEVEL   — Integer 0-100, expected network noise (default 50).
     REQUIRES-ROOT — T if tool needs root privileges.
     DESCRIPTION   — String, human-readable description.
     PARAMETERS    — Plist of default parameters.

   Returns: The tool plist.

   Example:
     (register-tactical-tool :recon 'NMAP \"nmap\" :recon
       :speed-rank 8 :evasion-rank 6 :tts-estimate 30
       :noise-level 40 :description \"Network scanner\")"
  (let ((tool (list :name name
                    :binary binary
                    :category category
                    :entry-type entry-type
                    :speed-rank speed-rank
                    :evasion-rank evasion-rank
                    :tts-estimate tts-estimate
                    :noise-level noise-level
                    :requires-root requires-root
                    :description description
                    :parameters parameters)))
    (push tool (gethash category *tactical-tool-registry*))
    (incf *tactical-tool-count*)
    tool))

(defun load-tactical-category (category &key (verbose t))
  "Load all tool definitions for a tactical category.

   FAIL-FAST: If any tool registration fails, the error is caught,
   logged, and loading continues. No retries, no validation.

   Arguments:
     CATEGORY — Keyword naming the category.
     VERBOSE  — If T (default), print a one-line summary.

   Returns: Integer count of tools registered for this category.

   Example:
     (load-tactical-category :recon)"
  (when verbose
    (format t "[TACTICAL] Loading ~A tools... " category))
  (let ((count 0)
        (errors 0))
    (dolist (tool-def (get-tactical-tool-definitions category))
      (handler-case
          (progn
            (apply #'register-tactical-tool tool-def)
            (incf count))
        (error (e)
          (incf errors)
          (when verbose
            (format *error-output* "~&[TACTICAL] Tool error in ~A: ~A~%"
                    (car tool-def) e)))))
    (when verbose
      (format t "~D tools (~D errors)~%" count errors))
    (pushnew category *tactical-categories-loaded*)
    count))

(defun get-tactical-tool-definitions (category)
  "Return the raw tool definition lists for CATEGORY.

   Each definition is a list suitable for APPLY with
   REGISTER-TACTICAL-TOOL.

   Arguments:
     CATEGORY — Keyword naming the category.

   Returns: List of tool definition lists."
  (case category
    (:recon (get-recon-tool-definitions))
    (:web (get-web-tool-definitions))
    (:lolbin (get-lolbin-tool-definitions))
    (:creds (get-creds-tool-definitions))
    (:lateral (get-lateral-tool-definitions))
    (:post-exploit (get-post-exploit-tool-definitions))
    (:social-engineering (get-social-tool-definitions))
    (:wireless (get-wireless-tool-definitions))
    (otherwise nil)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 2: Tool Definitions by Category — 145+ Tools
;; ═══════════════════════════════════════════════════════════════════════════

(defun get-recon-tool-definitions ()
  "Return tool definitions for the :RECON category (28 tools).

   Focus: Network discovery, host enumeration, service identification.
   Speed-first selection for rapid target acquisition."
  '((:recon nmap "nmap" :recon
     :speed-rank 8 :evasion-rank 6 :tts-estimate 30 :noise-level 40
     :requires-root t
     :description "The network mapper — port scanning, OS detection, version detection."
     :parameters (:flags "-sS -O --top-ports 1000"))
    (:recon masscan "masscan" :recon
     :speed-rank 10 :evasion-rank 3 :tts-estimate 10 :noise-level 80
     :requires-root t
     :description "Internet-scale port scanner — 10M packets/sec."
     :parameters (:rate 10000))
    (:recon zmap "zmap" :recon
     :speed-rank 10 :evasion-rank 2 :tts-estimate 15 :noise-level 90
     :requires-root t
     :description "Internet-wide network scanner — single-probe architecture."
     :parameters (:bandwidth "10M"))
    (:recon unicornscan "unicornscan" :recon
     :speed-rank 7 :evasion-rank 5 :tts-estimate 45 :noise-level 45
     :requires-root t
     :description "Asynchronous stateless port scanner with OS fingerprinting."
     :parameters (:mode "U"))
    (:recon rustscan "rustscan" :recon
     :speed-rank 10 :evasion-rank 4 :tts-estimate 5 :noise-level 70
     :requires-root t
     :description "Modern port scanner — scans all ports in <3 seconds."
     :parameters (:timeout 1500))
    (:recon naabu "naabu" :recon
     :speed-rank 9 :evasion-rank 5 :tts-estimate 20 :noise-level 50
     :description "Fast port scanner written in Go by ProjectDiscovery."
     :parameters (:top-ports 1000))
    (:recon amass "amass" :recon
     :speed-rank 5 :evasion-rank 8 :tts-estimate 300 :noise-level 30
     :description "In-depth attack surface mapping and asset discovery."
     :parameters (:active t))
    (:recon subfinder "subfinder" :recon
     :speed-rank 8 :evasion-rank 9 :tts-estimate 60 :noise-level 20
     :description "Fast passive subdomain discovery."
     :parameters (:all-sources t))
    (:recon assetfinder "assetfinder" :recon
     :speed-rank 7 :evasion-rank 9 :tts-estimate 45 :noise-level 15
     :description "Find domains and subdomains related to a given domain."
     :parameters ())
    (:recon findomain "findomain" :recon
     :speed-rank 8 :evasion-rank 9 :tts-estimate 30 :noise-level 15
     :description "Fastest cross-platform subdomain enumerator."
     :parameters (:quiet t))
    (:recon dnsx "dnsx" :recon
     :speed-rank 9 :evasion-rank 8 :tts-estimate 15 :noise-level 25
     :description "Fast DNS toolkit — resolve, wildcard check, bruteforce."
     :parameters (:retry 2))
    (:recon shuffledns "shuffledns" :recon
     :speed-rank 7 :evasion-rank 7 :tts-estimate 120 :noise-level 35
     :description "MassDNS wrapper for wildcard filtering."
     :parameters (:massdns "massdns"))
    (:recon dnsrecon "dnsrecon" :recon
     :speed-rank 6 :evasion-rank 7 :tts-estimate 90 :noise-level 30
     :description "DNS enumeration and zone transfer testing."
     :parameters (:type "std,brt"))
    (:recon fierce "fierce" :recon
     :speed-rank 6 :evasion-rank 7 :tts-estimate 120 :noise-level 35
     :description "DNS reconnaissance and subdomain enumeration."
     :parameters ())
    (:recon theharvester "theHarvester" :recon
     :speed-rank 5 :evasion-rank 9 :tts-estimate 180 :noise-level 10
     :description "Email harvesting and subdomain discovery via OSINT."
     :parameters (:source "all"))
    (:recon netdiscover "netdiscover" :recon
     :speed-rank 7 :evasion-rank 5 :tts-estimate 60 :noise-level 50
     :requires-root t
     :description "Active/passive ARP reconnaissance tool."
     :parameters (:range "auto"))
    (:recon arp-scan "arp-scan" :recon
     :speed-rank 8 :evasion-rank 4 :tts-estimate 15 :noise-level 60
     :requires-root t
     :description "ARP scanning and fingerprinting."
     :parameters (:localnet t))
    (:recon fierce-dns "fierce.pl" :recon
     :speed-rank 6 :evasion-rank 7 :tts-estimate 120 :noise-level 30
     :description "Perl-based DNS reconnaissance tool."
     :parameters ())
    (:recon dnsenum "dnsenum.pl" :recon
     :speed-rank 6 :evasion-rank 7 :tts-estimate 90 :noise-level 30
     :description "Perl multithreaded DNS enumeration."
     :parameters ())
    (:recon recon-ng "recon-ng" :recon
     :speed-rank 4 :evasion-rank 9 :tts-estimate 300 :noise-level 10
     :description "Full-featured web reconnaissance framework."
     :parameters ())
    (:recon spiderfoot "spiderfoot" :recon
     :speed-rank 4 :evasion-rank 9 :tts-estimate 600 :noise-level 10
     :description "Automated OSINT and reconnaissance platform."
     :parameters (:modules "all"))
    (:recon maltego "maltego" :recon
     :speed-rank 3 :evasion-rank 10 :tts-estimate 600 :noise-level 5
     :description "Visual link analysis and OSINT platform (GUI)."
     :parameters ())
    (:recon osintgram "osintgram" :recon
     :speed-rank 5 :evasion-rank 8 :tts-estimate 120 :noise-level 15
     :description "Instagram OSINT tool — photos, comments, followers."
     :parameters ())
    (:recon photon "photon" :recon
     :speed-rank 7 :evasion-rank 8 :tts-estimate 60 :noise-level 20
     :description "Incredibly fast crawler designed for OSINT."
     :parameters (:level 3))
    (:recon waybackurls "waybackurls" :recon
     :speed-rank 9 :evasion-rank 9 :tts-estimate 10 :noise-level 5
     :description "Fetch URLs from Wayback Machine for a domain."
     :parameters ())
    (:recon gau "gau" :recon
     :speed-rank 9 :evasion-rank 9 :tts-estimate 15 :noise-level 10
     :description "GetAllUrls — fetch known URLs from AlienVault, Wayback, CommonCrawl."
     :parameters (:subs t))
    (:recon httpx "httpx" :recon
     :speed-rank 9 :evasion-rank 8 :tts-estimate 10 :noise-level 20
     :description "Fast multi-purpose HTTP toolkit by ProjectDiscovery."
     :parameters (:follow-redirects t :status-code t))
    (:recon tlsx "tlsx" :recon
     :speed-rank 8 :evasion-rank 8 :tts-estimate 20 :noise-level 20
     :description "TLS certificate scanner and analyzer."
     :parameters (:json t))))

(defun get-web-tool-definitions ()
  "Return tool definitions for the :WEB category (22 tools).

   Focus: Web application testing, directory discovery, parameter fuzzing."
  '((:web dirb "dirb" :web
     :speed-rank 6 :evasion-rank 6 :tts-estimate 120 :noise-level 40
     :description "Web content scanner — directory and file brute-forcing."
     :parameters (:wordlist "/usr/share/dirb/wordlists/common.txt"))
    (:web gobuster "gobuster" :web
     :speed-rank 8 :evasion-rank 6 :tts-estimate 60 :noise-level 45
     :description "Fast directory/file DNS and VHost busting tool."
     :parameters (:threads 50))
    (:web ffuf "ffuf" :web
     :speed-rank 9 :evasion-rank 6 :tts-estimate 30 :noise-level 50
     :description "Fast web fuzzer written in Go."
     :parameters (:threads 40 :mc 200))
    (:web wfuzz "wfuzz" :web
     :speed-rank 7 :evasion-rank 6 :tts-estimate 90 :noise-level 45
     :description "Web application fuzzer with payload support."
     :parameters ())
    (:web nikto "nikto" :web
     :speed-rank 5 :evasion-rank 5 :tts-estimate 300 :noise-level 50
     :description "Web server scanner — checks for dangerous files/CGIs."
     :parameters (:output "/tmp/nikto-out.txt"))
    (:web sqlmap "sqlmap" :web
     :speed-rank 4 :evasion-rank 7 :tts-estimate 180 :noise-level 35
     :description "Automatic SQL injection and database takeover."
     :parameters (:batch t :level 1))
    (:web dalfox "dalfox" :web
     :speed-rank 7 :evasion-rank 7 :tts-estimate 60 :noise-level 35
     :description "Modern XSS scanner and parameter analyzer."
     :parameters (:blind "/tmp/xss.txt"))
    (:web xsstrike "XSStrike" :web
     :speed-rank 6 :evasion-rank 7 :tts-estimate 120 :noise-level 35
     :description "Advanced XSS detection suite with intelligent payload generation."
     :parameters (:crawl t))
    (:web commix "commix" :web
     :speed-rank 5 :evasion-rank 6 :tts-estimate 180 :noise-level 40
     :description "Automated command injection and OS command exploitation."
     :parameters (:batch t))
    (:web wpscan "wpscan" :web
     :speed-rank 7 :evasion-rank 7 :tts-estimate 90 :noise-level 35
     :description "WordPress security scanner — vulnerabilities, plugins, users."
     :parameters (:enumerate "vp,vt,tt,cb,dbe,u,m"))
    (:web cmseek "cmseek" :web
     :speed-rank 8 :evasion-rank 8 :tts-estimate 30 :noise-level 20
     :description "CMS detection and exploitation suite."
     :parameters (:batch t))
    (:web droopescan "droopescan" :web
     :speed-rank 7 :evasion-rank 7 :tts-estimate 60 :noise-level 30
     :description "Plugin-based CMS scanner for Drupal, SilverStripe, WordPress."
     :parameters ())
    (:web aquatone "aquatone" :web
     :speed-rank 6 :evasion-rank 8 :tts-estimate 120 :noise-level 25
     :description "Visual inspection of websites across large sets of hosts."
     :parameters ())
    (:web whatweb "whatweb" :web
     :speed-rank 9 :evasion-rank 8 :tts-estimate 10 :noise-level 20
     :description "Next-gen web scanner — identifies CMS, blogs, JavaScript."
     :parameters (:aggression 3))
    (:web eyewitness "EyeWitness" :web
     :speed-rank 5 :evasion-rank 8 :tts-estimate 180 :noise-level 25
     :description "Screenshot and info gatherer for web services."
     :parameters (:web t))
    (:web gowitness "gowitness" :web
     :speed-rank 8 :evasion-rank 8 :tts-estimate 45 :noise-level 25
     :description "Fast web screenshot tool written in Go."
     :parameters (:threads 4))
    (:web hakrawler "hakrawler" :web
     :speed-rank 8 :evasion-rank 7 :tts-estimate 30 :noise-level 30
     :description "Fast web crawler for discovering endpoints and JavaScript files."
     :parameters (:subs t))
    (:web katana "katana" :web
     :speed-rank 8 :evasion-rank 7 :tts-estimate 45 :noise-level 35
     :description "Next-generation crawling and spidering framework."
     :parameters (:js-crawl t))
    (:web nuclei "nuclei" :web
     :speed-rank 7 :evasion-rank 7 :tts-estimate 120 :noise-level 35
     :description "Fast vulnerability scanner based on templates."
     :parameters (:templates "~/nuclei-templates"))
    (:web wafw00f "wafw00f" :web
     :speed-rank 9 :evasion-rank 8 :tts-estimate 15 :noise-level 20
     :description "Web Application Firewall fingerprinting tool."
     :parameters ())
    (:web arjun "arjun" :web
     :speed-rank 7 :evasion-rank 7 :tts-estimate 60 :noise-level 30
     :description "HTTP parameter discovery suite."
     :parameters (:stable t))
    (:web paramspider "ParamSpider" :web
     :speed-rank 7 :evasion-rank 8 :tts-estimate 45 :noise-level 25
     :description "Mining parameters from dark corners of Web Archives."
     :parameters ())))

(defun get-lolbin-tool-definitions ()
  "Return tool definitions for the :LOLBIN category (18 tools).

   Focus: Living-off-the-land binaries — native tools abused for attack.
   Maximum evasion — these ARE the system."
  '((:lolbin certutil "certutil" :persist
     :speed-rank 9 :evasion-rank 10 :tts-estimate 15 :noise-level 5
     :description "Windows cert tool — download, decode, install."
     :parameters (:action "-urlcache -split -f"))
    (:lolbin bitsadmin "bitsadmin" :persist
     :speed-rank 8 :evasion-rank 10 :tts-estimate 20 :noise-level 5
     :description "Background Intelligent Transfer — download files quietly."
     :parameters (:action "/transfer"))
    (:lolbin mshta "mshta" :persist
     :speed-rank 8 :evasion-rank 9 :tts-estimate 15 :noise-level 10
     :description "HTML Application host — executes .hta payloads."
     :parameters ())
    (:lolbin regsvr32 "regsvr32" :persist
     :speed-rank 8 :evasion-rank 10 :tts-estimate 10 :noise-level 5
     :description "Register COM objects — runs DLLs/SCT scripts."
     :parameters (:action "/s /n /i"))
    (:lolbin rundll32 "rundll32" :persist
     :speed-rank 9 :evasion-rank 10 :tts-estimate 5 :noise-level 5
     :description "Run DLL entry points — universal execution primitive."
     :parameters ())
    (:lolbin wmic "wmic" :lateral
     :speed-rank 7 :evasion-rank 9 :tts-estimate 30 :noise-level 15
     :description "WMI command-line — remote process creation, info gathering."
     :parameters (:namespace "\\\\\\\\.\\root\\cimv2"))
    (:lolbin powershell "powershell" :persist
     :speed-rank 9 :evasion-rank 8 :tts-estimate 5 :noise-level 15
     :description "PowerShell — script execution, download cradle, encoding."
     :parameters (:noprofile t :windowstyle "hidden"))
    (:lolbin cmd "cmd" :persist
     :speed-rank 10 :evasion-rank 10 :tts-estimate 1 :noise-level 5
     :description "Command prompt — the most LOL of LOLBins."
     :parameters (:c ""))
    (:lolbin schtasks "schtasks" :persist
     :speed-rank 7 :evasion-rank 9 :tts-estimate 20 :noise-level 10
     :description "Task scheduler — persistence via scheduled tasks."
     :parameters (:create t :tn "update"))
    (:lolbin sc "sc" :persist
     :speed-rank 7 :evasion-rank 9 :tts-estimate 15 :noise-level 10
     :description "Service control — create/query/start/stop services."
     :parameters (:action "create"))
    (:lolbin netsh "netsh" :recon
     :speed-rank 8 :evasion-rank 9 :tts-estimate 10 :noise-level 10
     :description "Network shell — firewall config, port proxying."
     :parameters (:action "advfirewall"))
    (:lolbin cscript "cscript" :persist
     :speed-rank 8 :evasion-rank 9 :tts-estimate 10 :noise-level 10
     :description "Windows Script Host — executes .js/.vbs scripts."
     :parameters ())
    (:lolbin bash "bash" :persist
     :speed-rank 10 :evasion-rank 10 :tts-estimate 1 :noise-level 5
     :description "Bourne Again Shell — universal execution on *nix."
     :parameters (:c ""))
    (:lolbin python "python" :persist
     :speed-rank 9 :evasion-rank 8 :tts-estimate 5 :noise-level 10
     :description "Python interpreter — script execution, reverse shells."
     :parameters (:c ""))
    (:lolbin perl "perl" :persist
     :speed-rank 9 :evasion-rank 8 :tts-estimate 5 :noise-level 10
     :description "Perl interpreter — one-liners, reverse shells."
     :parameters (:e ""))
    (:lolbin awk "awk" :persist
     :speed-rank 9 :evasion-rank 9 :tts-estimate 5 :noise-level 5
     :description "Pattern scanning — can spawn shells via system()."
     :parameters ())
    (:lolbin find "find" :persist
     :speed-rank 9 :evasion-rank 9 :tts-estimate 5 :noise-level 5
     :description "File search — -exec can launch arbitrary commands."
     :parameters (:exec ""))
    (:lolbin cp "cp" :persist
     :speed-rank 10 :evasion-rank 10 :tts-estimate 1 :noise-level 5
     :description "Copy files — abuse for payload placement."
     :parameters ())))

(defun get-creds-tool-definitions ()
  "Return tool definitions for the :CREDS category (20 tools).

   Focus: Password attacks, hash cracking, credential harvesting."
  '((:creds john "john" :creds
     :speed-rank 7 :evasion-rank 5 :tts-estimate 300 :noise-level 60
     :description "John the Ripper — password hash cracker."
     :parameters (:wordlist "/usr/share/wordlists/rockyou.txt"))
    (:creds hashcat "hashcat" :creds
     :speed-rank 8 :evasion-rank 4 :tts-estimate 120 :noise-level 70
     :description "World's fastest password recovery tool — GPU accelerated."
     :parameters (:attack-mode 0))
    (:creds hydra "hydra" :creds
     :speed-rank 7 :evasion-rank 5 :tts-estimate 180 :noise-level 65
     :description "Parallelized login cracker — supports 50+ protocols."
     :parameters (:tasks 16))
    (:creds medusa "medusa" :creds
     :speed-rank 7 :evasion-rank 5 :tts-estimate 180 :noise-level 60
     :description "Speedy brute-force parallel network login auditor."
     :parameters (:threads 10))
    (:creds crackmapexec "crackmapexec" :creds
     :speed-rank 7 :evasion-rank 6 :tts-estimate 90 :noise-level 50
     :description "Swiss army knife for pentesting Windows/AD environments."
     :parameters ())
    (:creds impacket-secretsdump "secretsdump.py" :creds
     :speed-rank 6 :evasion-rank 6 :tts-estimate 120 :noise-level 45
     :description "Dump SAM, LSA secrets, and NTDS.dit hashes remotely."
     :parameters ())
    (:creds mimikatz "mimikatz" :creds
     :speed-rank 6 :evasion-rank 5 :tts-estimate 60 :noise-level 50
     :description "Extract plaintext passwords, hashes, Kerberos tickets."
     :parameters (:privilege "::debug"))
    (:creds laZagne "laZagne" :creds
     :speed-rank 7 :evasion-rank 6 :tts-estimate 45 :noise-level 40
     :description "Credentials recovery from various software."
     :parameters (:all t))
    (:creds creddump7 "creddump7" :creds
     :speed-rank 6 :evasion-rank 6 :tts-estimate 90 :noise-level 40
     :description "Extract credentials from Windows registry hives."
     :parameters ())
    (:creds pypykatz "pypykatz" :creds
     :speed-rank 7 :evasion-rank 6 :tts-estimate 60 :noise-level 40
     :description "Pure-python Mimikatz implementation."
     :parameters ())
    (:creds evil-winrm "evil-winrm" :creds
     :speed-rank 8 :evasion-rank 6 :tts-estimate 30 :noise-level 45
     :description "WinRM shell for penetration testing."
     :parameters ())
    (:creds bloodhound-python "bloodhound-python" :creds
     :speed-rank 6 :evasion-rank 7 :tts-estimate 180 :noise-level 35
     :description "BloodHound data collector — pure Python."
     :parameters (:collection-method "All"))
    (:creds ldapdomaindump "ldapdomaindump" :creds
     :speed-rank 7 :evasion-rank 7 :tts-estimate 60 :noise-level 35
     :description "Active Directory information dumper via LDAP."
     :parameters ())
    (:creds enum4linux-ng "enum4linux-ng" :creds
     :speed-rank 7 :evasion-rank 6 :tts-estimate 90 :noise-level 45
     :description "Next generation of enum4linux — Windows/AD enumeration."
     :parameters (:A t))
    (:creds smbmap "smbmap" :creds
     :speed-rank 8 :evasion-rank 6 :tts-estimate 30 :noise-level 45
     :description "SMB share enumerator and file access tester."
     :parameters ())
    (:creds smbclient "smbclient" :creds
     :speed-rank 8 :evasion-rank 6 :tts-estimate 20 :noise-level 45
     :description "SMB client for file access and share enumeration."
     :parameters (:L t))
    (:creds rpcclient "rpcclient" :creds
     :speed-rank 7 :evasion-rank 6 :tts-estimate 45 :noise-level 45
     :description "MS-RPC client — user enum, policy retrieval."
     :parameters (:c ""))
    (:creds kerbrute "kerbrute" :creds
     :speed-rank 8 :evasion-rank 6 :tts-estimate 45 :noise-level 50
     :description "Kerberos bruteforce and user enumeration — FAST."
     :parameters (:threads 10))
    (:creds asrepcatcher "asrepcatcher" :creds
     :speed-rank 7 :evasion-rank 7 :tts-estimate 60 :noise-level 40
     :description "Catch AS-REP roastable accounts via network sniffing."
     :parameters ())
    (:creds pre2k "pre2k" :creds
     :speed-rank 7 :evasion-rank 7 :tts-estimate 45 :noise-level 40
     :description "Test for Pre-Windows 2000 computer account vulnerability."
     :parameters ())))

(defun get-lateral-tool-definitions ()
  "Return tool definitions for the :LATERAL category (16 tools).

   Focus: Lateral movement, proxy chains, tunneling, pivoting."
  '((:lateral proxychains "proxychains" :lateral
     :speed-rank 8 :evasion-rank 7 :tts-estimate 10 :noise-level 40
     :description "Force any TCP connection through proxy chain."
     :parameters (:config "/etc/proxychains.conf"))
    (:lateral chisel "chisel" :lateral
     :speed-rank 8 :evasion-rank 7 :tts-estimate 30 :noise-level 40
     :description "Fast TCP tunnel over HTTP — pivot through firewalls."
     :parameters (:server t :port 8080))
    (:lateral ligolo-ng "ligolo-ng" :lateral
     :speed-rank 8 :evasion-rank 7 :tts-estimate 30 :noise-level 40
     :description "Advanced tunneling tool — multiple connections, SOCKS."
     :parameters (:laddr "0.0.0.0:11601"))
    (:lateral socat "socat" :lateral
     :speed-rank 9 :evasion-rank 7 :tts-estimate 10 :noise-level 45
     :description "Multipurpose relay — port forwarding, reverse shells."
     :parameters ())
    (:lateral netcat "nc" :lateral
     :speed-rank 10 :evasion-rank 7 :tts-estimate 5 :noise-level 50
     :description "TCP/UDP network swiss army knife."
     :parameters (:v t :l t))
    (:lateral ncat "ncat" :lateral
     :speed-rank 9 :evasion-rank 7 :tts-estimate 10 :noise-level 45
     :description "Nmap's netcat — SSL, proxy, connection brokering."
     :parameters (:ssl t))
    (:lateral ssh "ssh" :lateral
     :speed-rank 9 :evasion-rank 8 :tts-estimate 10 :noise-level 35
     :description "OpenSSH client — port forwarding, proxy, tunneling."
     :parameters (:N t :D "1080"))
    (:lateral sshuttle "sshuttle" :lateral
     :speed-rank 8 :evasion-rank 7 :tts-estimate 20 :noise-level 40
     :description "VPN-like tunnel over SSH — transparent proxy."
     :parameters (:dns t))
    (:lateral plink "plink" :lateral
     :speed-rank 8 :evasion-rank 7 :tts-estimate 15 :noise-level 40
     :description "PuTTY command-line — SSH tunneling from Windows."
     :parameters (-N t -D "1080"))
    (:lateral stunnel "stunnel" :lateral
     :speed-rank 7 :evasion-rank 7 :tts-estimate 30 :noise-level 40
     :description "SSL tunneling proxy — wrap any protocol in TLS."
     :parameters ())
    (:lateral dnscat2 "dnscat2" :lateral
     :speed-rank 6 :evasion-rank 9 :tts-estimate 60 :noise-level 15
     :description "Command and control over DNS — stealth tunneling."
     :parameters (:domain "dns.example.com"))
    (:lateral iodine "iodine" :lateral
     :speed-rank 6 :evasion-rank 9 :tts-estimate 60 :noise-level 15
     :description "IP over DNS tunneling — exfiltration and C2."
     :parameters ())
    (:lateral ptunnel "ptunnel" :lateral
     :speed-rank 7 :evasion-rank 8 :tts-estimate 30 :noise-level 30
     :description "ICMP tunneling — ping-based tunnel for bypass."
     :parameters ())
    (:lateral evilginx2 "evilginx2" :social
     :speed-rank 6 :evasion-rank 7 :tts-estimate 120 :noise-level 30
     :description "Phishing framework with real-time 2FA bypass."
     :parameters (:phishlets "/usr/share/evilginx/phishlets"))
    (:lateral metasploit-pivot "msfconsole" :lateral
     :speed-rank 5 :evasion-rank 5 :tts-estimate 60 :noise-level 55
     :description "Metasploit Framework — pivot, route, portfwd."
     :parameters (:resource "pivot.rc"))
    (:lateral cobaltstrike-teamserver "teamserver" :lateral
     :speed-rank 5 :evasion-rank 6 :tts-estimate 120 :noise-level 50
     :description "Cobalt Strike team server — commercial C2 and pivoting."
     :parameters (:port 50050))))

(defun get-post-exploit-tool-definitions ()
  "Return tool definitions for the :POST-EXPLOIT category (20 tools).

   Focus: Post-exploitation frameworks, privilege escalation, persistence."
  '((:post-exploit metasploit "msfconsole" :post-ex
     :speed-rank 5 :evasion-rank 5 :tts-estimate 60 :noise-level 55
     :description "The Metasploit Framework — exploitation and post-ex."
     :parameters ())
    (:post-exploit meterpreter "meterpreter" :post-ex
     :speed-rank 6 :evasion-rank 5 :tts-estimate 30 :noise-level 55
     :description "Metasploit payload — advanced post-exploitation."
     :parameters ())
    (:post-exploit covenant "Covenant" :post-ex
     :speed-rank 5 :evasion-rank 6 :tts-estimate 120 :noise-level 50
     :description ".NET C2 framework — reflective assembly loading."
     :parameters ())
    (:post-exploit sliver "sliver-server" :post-ex
     :speed-rank 6 :evasion-rank 7 :tts-estimate 90 :noise-level 45
     :description "Cross-platform implant framework — mTLS, WireGuard."
     :parameters ())
    (:post-exploit Havoc "havoc" :post-ex
     :speed-rank 6 :evasion-rank 7 :tts-estimate 90 :noise-level 45
     :description "Modern post-exploitation C2 framework."
     :parameters ())
    (:post-exploit linpeas "linpeas.sh" :post-ex
     :speed-rank 7 :evasion-rank 6 :tts-estimate 120 :noise-level 50
     :description "Linux privilege escalation awesome script."
     :parameters (:fast t))
    (:post-exploit winpeas "winPEAS.exe" :post-ex
     :speed-rank 7 :evasion-rank 6 :tts-estimate 120 :noise-level 50
     :description "Windows privilege escalation awesome script."
     :parameters (:quiet t))
    (:post-exploit pspy "pspy" :post-ex
     :speed-rank 8 :evasion-rank 6 :tts-estimate 30 :noise-level 45
     :description "Monitor Linux processes without root permissions."
     :parameters ())
    (:post-exploit unix-privesc-check "unix-privesc-check" :post-ex
     :speed-rank 7 :evasion-rank 6 :tts-estimate 90 :noise-level 50
     :description "Automated Unix privilege escalation checker."
     :parameters (:verbose t))
    (:post-exploit powersploit "PowerSploit" :post-ex
     :speed-rank 6 :evasion-rank 6 :tts-estimate 60 :noise-level 50
     :description "PowerShell post-exploitation framework."
     :parameters ())
    (:post-exploit sharpsploit "SharpSploit" :post-ex
     :speed-rank 6 :evasion-rank 6 :tts-estimate 60 :noise-level 50
     :description ".NET post-exploitation library (C#)."
     :parameters ())
    (:post-exploit bloodhound "bloodhound" :post-ex
     :speed-rank 6 :evasion-rank 7 :tts-estimate 180 :noise-level 35
     :description "Active Directory attack path visualization."
     :parameters (:collection-method "All"))
    (:post-exploit sharphound "SharpHound" :post-ex
     :speed-rank 7 :evasion-rank 7 :tts-estimate 90 :noise-level 35
     :description "C# BloodHound data ingester — faster than Python."
     :parameters (:collection-method "All"))
    (:post-exploit seatbelt "Seatbelt" :post-ex
     :speed-rank 7 :evasion-rank 6 :tts-estimate 60 :noise-level 45
     :description "C# project for performing security oriented host survey."
     :parameters (:full t))
    (:post-exploit watson "Watson" :post-ex
     :speed-rank 8 :evasion-rank 6 :tts-estimate 30 :noise-level 45
     :description "Enumerate missing KBs and suggest exploits for Windows."
     :parameters ())
    (:post-exploit sherlock "Sherlock" :post-ex
     :speed-rank 7 :evasion-rank 6 :tts-estimate 60 :noise-level 45
     :description "PowerShell script to find missing patches."
     :parameters ())
    (:post-exploit jaws "jaws-enum.ps1" :post-ex
     :speed-rank 7 :evasion-rank 6 :tts-estimate 60 :noise-level 45
     :description "Just Another Windows Enum Script."
     :parameters ())
    (:post-exploit exploitation-graeculus "graeculus" :post-ex
     :speed-rank 5 :evasion-rank 5 :tts-estimate 120 :noise-level 55
     :description "Automated exploitation framework."
     :parameters ())
    (:post-exploit empire "empire" :post-ex
     :speed-rank 5 :evasion-rank 6 :tts-estimate 120 :noise-level 50
     :description "Post-exploitation agent — PowerShell/Python."
     :parameters ())
    (:post-exploit starkiller "starkiller" :post-ex
     :speed-rank 5 :evasion-rank 6 :tts-estimate 120 :noise-level 50
     :description "Empire GUI frontend."
     :parameters ())))

(defun get-social-tool-definitions ()
  "Return tool definitions for the :SOCIAL-ENGINEERING category (12 tools).

   Focus: Phishing, social manipulation, credential harvesting."
  '((:social-engineering setoolkit "setoolkit" :social
     :speed-rank 5 :evasion-rank 6 :tts-estimate 180 :noise-level 40
     :description "Social-Engineer Toolkit — phishing, spear-phishing."
     :parameters ())
    (:social-engineering gophish "gophish" :social
     :speed-rank 6 :evasion-rank 7 :tts-estimate 120 :noise-level 30
     :description "Open-source phishing framework — campaign management."
     :parameters (:admin-url "127.0.0.1:3333"))
    (:social-engineering king-phisher "KingPhisher" :social
     :speed-rank 5 :evasion-rank 6 :tts-estimate 180 :noise-level 40
     :description "Phishing campaign toolkit — server and client."
     :parameters ())
    (:social-engineering evilginx2 "evilginx2" :social
     :speed-rank 6 :evasion-rank 7 :tts-estimate 120 :noise-level 30
     :description "Phishing framework with real-time 2FA bypass."
     :parameters ())
    (:social-engineering modlishka "modlishka" :social
     :speed-rank 6 :evasion-rank 7 :tts-estimate 120 :noise-level 30
     :description "Reverse proxy phishing tool — transparent 2FA bypass."
     :parameters ())
    (:social-engineering social-engineer-toolkit "se-toolkit" :social
     :speed-rank 5 :evasion-rank 6 :tts-estimate 180 :noise-level 40
     :description "Social engineering attack framework."
     :parameters ())
    (:social-engineering socialmapper "social_mapper" :social
     :speed-rank 4 :evasion-rank 8 :tts-estimate 600 :noise-level 20
     :description "Social media enumeration and correlation tool."
     :parameters ())
    (:social-engineering twint "twint" :social
     :speed-rank 6 :evasion-rank 8 :tts-estimate 120 :noise-level 20
     :description "Twitter intelligence tool — no API limits, no auth."
     :parameters (:limit 100))
    (:social-engineering sherlock-osint "sherlock" :social
     :speed-rank 7 :evasion-rank 9 :tts-estimate 60 :noise-level 15
     :description "Hunt down social media accounts by username."
     :parameters ())
    (:social-engineering profil3r "Profil3r" :social
     :speed-rank 6 :evasion-rank 8 :tts-estimate 90 :noise-level 20
     :description "OSINT tool for finding profiles and emails."
     :parameters ())
    (:social-engineering dephault "DePhault" :social
     :speed-rank 5 :evasion-rank 8 :tts-estimate 120 :noise-level 20
     :description "Default password hunter for web applications."
     :parameters ())
    (:social-engineering reconspider "reconspider" :social
     :speed-rank 5 :evasion-rank 8 :tts-estimate 180 :noise-level 15
     :description "Most advanced Open Source Intelligence (OSINT) Framework."
     :parameters ())))

(defun get-wireless-tool-definitions ()
  "Return tool definitions for the :WIRELESS category (11 tools).

   Focus: WiFi testing, Bluetooth, RF analysis."
  '((:wireless aircrack-ng "aircrack-ng" :wireless
     :speed-rank 7 :evasion-rank 5 :tts-estimate 300 :noise-level 70
     :requires-root t
     :description "Complete suite for 802.11 WEP/WPA cracking."
     :parameters ())
    (:wireless aireplay-ng "aireplay-ng" :wireless
     :speed-rank 7 :evasion-rank 4 :tts-estimate 60 :noise-level 80
     :requires-root t
     :description "Packet injection for 802.11 networks — deauth, replay."
     :parameters (:deauth 10))
    (:wireless airodump-ng "airodump-ng" :wireless
     :speed-rank 8 :evasion-rank 5 :tts-estimate 30 :noise-level 65
     :requires-root t
     :description "802.11 packet capture — AP and station discovery."
     :parameters (:write "/tmp/capture"))
    (:wireless wifite "wifite" :wireless
     :speed-rank 7 :evasion-rank 5 :tts-estimate 300 :noise-level 70
     :requires-root t
     :description "Automated wireless attack tool — WEP/WPA/WPS."
     :parameters (:all t))
    (:wireless reaver "reaver" :wireless
     :speed-rank 6 :evasion-rank 5 :tts-estimate 600 :noise-level 70
     :requires-root t
     :description "WPS PIN brute force attack — recover WPA passphrase."
     :parameters (:verbose t))
    (:wireless bully "bully" :wireless
     :speed-rank 7 :evasion-rank 5 :tts-estimate 300 :noise-level 70
     :requires-root t
     :description "Modern WPS PIN attack — faster than Reaver."
     :parameters ())
    (:wireless bettercap "bettercap" :wireless
     :speed-rank 7 :evasion-rank 6 :tts-estimate 60 :noise-level 60
     :requires-root t
     :description "Swiss army knife for network attacks and monitoring."
     :parameters (:iface "wlan0mon"))
    (:wireless kismet "kismet" :wireless
     :speed-rank 6 :evasion-rank 6 :tts-estimate 30 :noise-level 55
     :requires-root t
     :description "Wireless network detector, sniffer, and IDS."
     :parameters ())
    (:wireless hcxdumptool "hcxdumptool" :wireless
     :speed-rank 7 :evasion-rank 5 :tts-estimate 60 :noise-level 70
     :requires-root t
     :description "Small tool to capture packets from WLAN devices."
     :parameters (:enable_status 1))
    (:wireless hcxtools "hcxpcapngtool" :wireless
     :speed-rank 7 :evasion-rank 5 :tts-estimate 30 :noise-level 60
     :description "Convert captures for hashcat/john processing."
     :parameters ())
    (:wireless bluetooth-hci "hcitool" :wireless
     :speed-rank 8 :evasion-rank 6 :tts-estimate 15 :noise-level 50
     :requires-root t
     :description "Bluetooth device configuration and discovery."
     :parameters (:scan t))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 3: Tactical Speed Registry — Fast Tool Selection
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *speed-ranked-tools* nil
  "Cached list of all tools sorted by SPEED-RANK (descending).
   Recomputed when tools are loaded. Used by SELECT-FASTEST-TOOL.")

(defvar *evasion-ranked-tools* nil
  "Cached list of all tools sorted by EVASION-RANK (descending).
   Recomputed when tools are loaded. Used by SELECT-MOST-EVASIVE-TOOL.")

(defun recompute-tool-rankings ()
  "Recompute the speed and evasion ranked tool lists.

   Should be called after loading all tool categories. Sorts all
   registered tools by their speed-rank and evasion-rank fields.

   Returns: Plist with :SPEED-COUNT and :EVASION-COUNT."
  (let ((all-tools nil))
    (maphash (lambda (cat tools)
              (declare (ignore cat))
              (dolist (tool tools)
                (push tool all-tools)))
            *tactical-tool-registry*)
    (setf *speed-ranked-tools*
          (sort (copy-list all-tools) #'> :key (lambda (tool)
                                                (getf tool :speed-rank 0)))
          *evasion-ranked-tools*
          (sort (copy-list all-tools) #'> :key (lambda (tool)
                                                (getf tool :evasion-rank 0))))
    (list :speed-count (length *speed-ranked-tools*)
          :evasion-count (length *evasion-ranked-tools*))))

(defun select-fastest-tool (category &key (min-evasion 0))
  "Select the fastest tool in CATEGORY with evasion >= MIN-EVASION.

   Arguments:
     CATEGORY     — Keyword naming the category.
     MIN-EVASION  — Minimum evasion rank (default 0 = no filter).

   Returns: Tool plist or NIL if none matches.

   Example:
     (select-fastest-tool :recon :min-evasion 5)"
  (let ((candidates (gethash category *tactical-tool-registry*)))
    (let ((filtered (remove-if (lambda (tool)
                                (< (getf tool :evasion-rank 0) min-evasion))
                              candidates)))
      (car (sort (copy-list filtered) #'> :key (lambda (tool)
                                                 (getf tool :speed-rank 0)))))))

(defun select-most-evasive-tool (category &key (min-speed 0))
  "Select the most evasive tool in CATEGORY with speed >= MIN-SPEED.

   Arguments:
     CATEGORY  — Keyword naming the category.
     MIN-SPEED — Minimum speed rank (default 0 = no filter).

   Returns: Tool plist or NIL if none matches.

   Example:
     (select-most-evasive-tool :recon :min-speed 5)"
  (let ((candidates (gethash category *tactical-tool-registry*)))
    (let ((filtered (remove-if (lambda (tool)
                                (< (getf tool :speed-rank 0) min-speed))
                              candidates)))
      (car (sort (copy-list filtered) #'> :key (lambda (tool)
                                                 (getf tool :evasion-rank 0)))))))

(defun get-tools-by-entry-type (entry-type)
  "Return all tools matching ENTRY-TYPE across all categories.

   Arguments:
     ENTRY-TYPE — Keyword: :RECON :EXPLOIT :CREDS :LATERAL :PERSIST
                  :POST-EX :SOCIAL :WIRELESS :WEB.

   Returns: List of tool plists.

   Example:
     (get-tools-by-entry-type :persist)"
  (let ((matches nil))
    (maphash (lambda (cat tools)
              (declare (ignore cat))
              (dolist (tool tools)
                (when (eq (getf tool :entry-type) entry-type)
                  (push tool matches))))
            *tactical-tool-registry*)
    (nreverse matches)))

(defun get-category-tool-count (category)
  "Return the number of tools registered for CATEGORY.

   Arguments:
     CATEGORY — Keyword naming the category.

   Returns: Integer count."
  (length (gethash category *tactical-tool-registry*)))

(defun get-total-tool-count ()
  "Return the total number of registered tactical tools.

   Returns: Integer count."
  (let ((count 0))
    (maphash (lambda (cat tools)
              (declare (ignore cat))
              (incf count (length tools)))
            *tactical-tool-registry*)
    count))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 4: TTS (Time-to-Shell) Evolution — Adaptive Timing
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *tts-evolution-enabled-p* nil
  "When T, the TTS evolution system is active.
   Tracks actual time-to-shell for each tool/vector combination
   and adjusts estimates to improve prediction accuracy.")

(defvar *tts-history* (make-hash-table :test 'equal)
  "Hash table: (tool-name . entry-vector) -> list of actual TTS values.
   Used to compute rolling averages for adaptive estimates.")

(defvar *tts-rolling-window-size* 10
  "Number of TTS samples to keep per tool/vector combination.
   Older samples are discarded.")

(defun enable-tts-evolution ()
  "Enable TTS (time-to-shell) evolution tracking.

   The TTS system tracks actual time-to-shell for each tool and
   entry vector combination, maintaining a rolling average. This
   enables adaptive tool selection based on real performance data
   rather than static estimates.

   Returns: T if enabled."
  (setf *tts-evolution-enabled-p* t)
  (clrhash *tts-history*)
  (format t "[TTS] Evolution tracking ENABLED.~%")
  t)

(defun record-tts-result (tool-name entry-vector actual-seconds)
  "Record an actual TTS result for adaptive estimates.

   Arguments:
     TOOL-NAME      — Symbol naming the tool.
     ENTRY-VECTOR   — Keyword: :SSH :SMB :RDP :HTTP :WMI :LDAP.
     ACTUAL-SECONDS — Integer, actual time to shell.

   Returns: Updated rolling average for this tool/vector pair.

   Example:
     (record-tts-result 'NMAP :smb 45)"
  (let ((key (cons tool-name entry-vector)))
    (let ((samples (gethash key *tts-history* '())))
      (push actual-seconds samples)
      ;; Keep only the last N samples
      (when (> (length samples) *tts-rolling-window-size*)
        (setf samples (subseq samples 0 *tts-rolling-window-size*)))
      (setf (gethash key *tts-history*) samples)
      ;; Return rolling average
      (/ (reduce #'+ samples) (length samples)))))

(defun get-adaptive-tts-estimate (tool-name entry-vector)
  "Get the adaptive TTS estimate for a tool/vector combination.

   If no historical data exists, falls back to the tool's static
   TTS-ESTIMATE from the registry.

   Arguments:
     TOOL-NAME    — Symbol naming the tool.
     ENTRY-VECTOR — Keyword: :SSH :SMB :RDP :HTTP :WMI :LDAP.

   Returns: Integer, estimated seconds to shell.

   Example:
     (get-adaptive-tts-estimate 'NMAP :smb)"
  (let ((key (cons tool-name entry-vector))
        (static-tts (or (and (gethash (find-symbol (symbol-name tool-name)
                                                  :lispmind)
                                     *tactical-tool-registry*)
                            (getf (car (gethash :recon
n                                               *tactical-tool-registry*))
                                  :tts-estimate))
                       60)))
    (let ((samples (gethash key *tts-history*)))
      (if (and samples (> (length samples) 0))
          (round (/ (reduce #'+ samples) (length samples)))
          static-tts))))

(defun select-fastest-vector (target-ip available-vectors)
  "Select the fastest entry vector for TARGET-IP based on TTS history.

   Arguments:
     TARGET-IP       — String IP address.
     AVAILABLE-VECTORS — List of keywords: :SSH :SMB :RDP :HTTP :WMI.

   Returns: Keyword, the recommended entry vector.

   Example:
     (select-fastest-vector \"10.0.0.5\" '(:smb :ssh :rdp))"
  (declare (ignore target-ip))
  (if (and *tts-evolution-enabled-p* available-vectors)
      (let ((best-vector (car available-vectors))
            (best-tts most-positive-fixnum))
        (dolist (vec available-vectors)
          (let ((avg-tts (get-adaptive-tts-estimate 'NMAP vec)))
            (when (< avg-tts best-tts)
              (setf best-tts avg-tts
                    best-vector vec))))
        best-vector)
      (car available-vectors)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 5: Persistence-First Pipeline — Persist Before Pivot
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *persistence-first-enabled-p* nil
  "When T, the persistence-first pipeline is active.
   Every new foothold automatically triggers persistence installation
   before any pivoting is allowed.")

(defvar *persistence-pipeline-queue* nil
  "List of foothold states awaiting persistence installation.
   Processed by the persistence pipeline worker.")

(defvar *persistence-methods* '(:registry :wmi :schtasks :service
                                :dll-hijack :webshell :cron
                                :launch-agent)
  "Ordered list of persistence methods to try.
   Methods are attempted in order until one succeeds.")

(defun enable-persistence-first-pipeline ()
  "Enable the persistence-first pipeline.

   In persistence-first mode, every new foothold is automatically
   queued for persistence installation. The foothold cannot spawn
   child pivots until persistence is confirmed active.

   This ensures that even if the initial session dies, the foothold
   remains accessible via the persistence mechanism.

   Returns: T if enabled."
  (setf *persistence-first-enabled-p* t)
  (setf *persistence-pipeline-queue* nil)
  (format t "[PERSISTENCE] First-pipeline ENABLED.~%")
  (format t "[PERSISTENCE] Methods: ~A~%" *persistence-methods*)
  t)

(defun queue-foothold-for-persistence (foothold)
  "Queue a foothold for automatic persistence installation.

   Arguments:
     FOOTHOLD — A FOOTHOLD-STATE struct.

   Returns: The queued foothold.

   Example:
     (queue-foothold-for-persistence new-foothold)"
  (push foothold *persistence-pipeline-queue*)
  (format t "[PERSISTENCE] Queued ~A for persistence (depth ~D).~%"
          (foothold-state-target-ip foothold)
          (foothold-state-pivot-depth foothold))
  foothold)

(defun install-persistence (foothold &optional (methods *persistence-methods*))
  "Install persistence on a foothold using the first successful method.

   Attempts each persistence method in order until one succeeds.
   Updates the foothold's PERSISTENCE-ACTIVE-P and PERSISTENCE-METHOD
   slots on success.

   Arguments:
     FOOTHOLD — A FOOTHOLD-STATE struct to persist.
     METHODS  — List of persistence method keywords (default all).

   Returns: T if persistence installed, NIL if all methods failed.

   Example:
     (install-persistence foothold '(:registry :schtasks :service))"
  (format t "[PERSISTENCE] Installing persistence on ~A...~%"
          (foothold-state-target-ip foothold))
  (dolist (method methods)
    (handler-case
        (progn
          (format t "[PERSISTENCE] Trying ~A on ~A...~%"
                  method (foothold-state-target-ip foothold))
          ;; Execute persistence method
          (execute-persistence-method foothold method)
          ;; Mark as persisted
          (setf (foothold-state-persistence-active-p foothold) t
                (foothold-state-persistence-method foothold) method)
          (format t "[PERSISTENCE] ~A persistence ACTIVE on ~A.~%"
                  method (foothold-state-target-ip foothold))
          (return-from install-persistence t))
      (error (e)
        (format t "[PERSISTENCE] ~A failed: ~A~%" method e))))
  (format t "[PERSISTENCE] ALL methods failed on ~A.~%"
          (foothold-state-target-ip foothold))
  nil)

(defun execute-persistence-method (foothold method)
  "Execute a single persistence method on a foothold.

   Arguments:
     FOOTHOLD — A FOOTHOLD-STATE struct.
     METHOD   — Keyword naming the persistence method.

   Signals: ERROR if the method fails.

   Example:
     (execute-persistence-method foothold :registry)"
  (ecase method
    (:registry
     ;; Windows registry run key persistence
     (format t "[PERSISTENCE] Registry: HKCU\\Run\\Update~%"))
    (:wmi
     ;; WMI event subscription persistence
     (format t "[PERSISTENCE] WMI: Event subscription~%"))
    (:schtasks
     ;; Scheduled task persistence
     (format t "[PERSISTENCE] Schtasks: Daily trigger~%"))
    (:service
     ;; Windows service persistence
     (format t "[PERSISTENCE] Service: SystemUpdate~%"))
    (:dll-hijack
     ;; DLL hijacking persistence
     (format t "[PERSISTENCE] DLL-Hijack: Targeting vulnerable app~%"))
    (:webshell
     ;; Web shell persistence
     (format t "[PERSISTENCE] WebShell: Uploading shell~%"))
    (:cron
     ;; Unix cron job persistence
     (format t "[PERSISTENCE] Cron: */5 * * * * payload~%"))
    (:launch-agent
     ;; macOS LaunchAgent persistence
     (format t "[PERSISTENCE] LaunchAgent: com.apple.update.plist~%"))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 6: Fail-Fast Rotation — Drop Slow, Rotate Immediately
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *fail-fast-rotation-enabled-p* nil
  "When T, fail-fast rotation is active.
   Tools and entry vectors that exceed their TTS estimate are
   immediately abandoned and the next-fastest alternative is tried.")

(defvar *fail-fast-timeout-multiplier* 2.0
  "Multiplier for TTS estimate to determine abandonment threshold.
   A tool is abandoned if actual time exceeds
   (* TTS-ESTIMATE *FAIL-FAST-TIMEOUT-MULTIPLIER*).
   Default: 2.0 (double the estimated time).")

(defvar *rotation-history* nil
  "List of rotation events: (TIMESTAMP OLD-TOOL NEW-TOOL REASON).
   Used for post-op analysis and TTS estimate refinement.")

(defun enable-fail-fast-rotation ()
  "Enable fail-fast rotation.

   In fail-fast mode, any tool or entry vector that exceeds its
   adaptive TTS estimate by *FAIL-FAST-TIMEOUT-MULTIPLIER* is
   immediately abandoned. The next-fastest alternative is selected
   and started without delay.

   This prevents "hung" operations from stalling the entire pipeline.
   A tool that would have taken 10 minutes is abandoned at 2x its
   estimate and something faster is tried immediately.

   Returns: T if enabled."
  (setf *fail-fast-rotation-enabled-p* t)
  (setf *rotation-history* nil)
  (format t "[FAIL-FAST] Rotation ENABLED (timeout multiplier: ~,1Fx).~%"
          *fail-fast-timeout-multiplier*)
  t)

(defun should-abandon-tool-p (tool-name entry-vector elapsed-seconds)
  "Check if a tool should be abandoned based on elapsed time.

   Arguments:
     TOOL-NAME      — Symbol naming the tool.
     ENTRY-VECTOR   — Keyword naming the entry vector.
     ELAPSED-SECONDS — Integer, seconds since tool started.

   Returns: T if the tool should be abandoned.

   Example:
     (should-abandon-tool-p 'NMAP :smb 120)"
  (when *fail-fast-rotation-enabled-p*
    (let ((estimated-tts (get-adaptive-tts-estimate tool-name entry-vector)))
      (> elapsed-seconds (* estimated-tts *fail-fast-timeout-multiplier*)))))

(defun record-rotation (old-tool new-tool reason)
  "Record a tool rotation event.

   Arguments:
     OLD-TOOL — Symbol, the abandoned tool.
     NEW-TOOL — Symbol, the replacement tool.
     REASON   — String, why the rotation occurred.

   Returns: The rotation event plist."
  (let ((event (list :timestamp (get-universal-time)
                     :old-tool old-tool
                     :new-tool new-tool
                     :reason reason)))
    (push event *rotation-history*)
    (format t "[FAIL-FAST] Rotated: ~A -> ~A (~A)~%"
            old-tool new-tool reason)
    event))

(defun get-last-rotations (&optional (n 10))
  "Return the last N rotation events.

   Arguments:
     N — Integer, number of events to return (default 10).

   Returns: List of rotation event plists."
  (subseq *rotation-history* 0 (min n (length *rotation-history*))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 7: Policy Gatekeeper — ARM/DISARM (The ONE Safety Measure)
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *tactical-category-armed-state* (make-hash-table :test 'eq)
  "Hash table: category-keyword -> T (armed) or NIL (disarmed).
   ALL categories start NIL (disarmed) — fail-closed.")

(defvar *tactical-armed-categories* nil
  "List of currently armed category keywords.
   Modified only by ARM-CATEGORY-V2.4 and DISARM-CATEGORY-V2.4.")

(defun init-tactical-policies (&key (verbose t))
  "Initialize the tactical policy gatekeeper.

   Sets ALL categories to DISARMED (fail-closed). This is the ONE
   safety measure retained in v2.4 — nothing fires until explicitly
   armed.

   Actions:
     1. Reset all category armed states to NIL.
     2. Reset *TACTICAL-ARMED-CATEGORIES* to NIL.
     3. Log initialization.

   Arguments:
     VERBOSE — If T (default), print status.

   Returns: T if initialized.

   Example:
     (init-tactical-policies)"
  (clrhash *tactical-category-armed-state*)
  (setf *tactical-armed-categories* nil)
  ;; Initialize all known categories as DISARMED
  (dolist (cat '(:recon :web :lolbin :creds :lateral :post-exploit
                 :social-engineering :wireless))
    (setf (gethash cat *tactical-category-armed-state*) nil))
  (when verbose
    (format t "[TACTICAL-POLICY] Gatekeeper initialized.~%")
    (format t "[TACTICAL-POLICY] All categories DISARMED (fail-closed).~%"))
  t)

(defun arm-category-v2.4 (category)
  "ARM a tactical category — ENABLE its tools for use.

   DANGEROUS: This enables the offensive tools in the category.
   Only arm when you are ready to engage targets.

   Arguments:
     CATEGORY — Keyword naming the category to arm.

   Returns: T if armed, NIL if category not found.

   Example:
     (arm-category-v2.4 :recon)
     (arm-category-v2.4 '(:recon :web))  ;; Arm multiple"
  (if (listp category)
      (dolist (cat category) (arm-category-v2.4 cat))
      (progn
        (setf (gethash category *tactical-category-armed-state*) t)
        (pushnew category *tactical-armed-categories*)
        (format t "~&[TACTICAL-POLICY] !!! CATEGORY ~A ARMED !!!~%" category))))

(defun disarm-category-v2.4 (category)
  "DISARM a tactical category — DISABLE its tools.

   Safe: This prevents the category's tools from being used.
   All categories start disarmed.

   Arguments:
     CATEGORY — Keyword naming the category to disarm.

   Returns: T if disarmed.

   Example:
     (disarm-category-v2.4 :recon)"
  (setf (gethash category *tactical-category-armed-state*) nil)
  (setf *tactical-armed-categories*
        (remove category *tactical-armed-categories*))
  (format t "[TACTICAL-POLICY] Category ~A DISARMED.~%" category)
  t)

(defun disarm-all-categories-v2.4 ()
  "DISARM ALL tactical categories — emergency stop.

   This is the emergency brake. All categories are immediately
   disarmed. No offensive tools can be used until re-armed.

   Returns: T if all disarmed."
  (clrhash *tactical-category-armed-state*)
  (setf *tactical-armed-categories* nil)
  (format t "~&[TACTICAL-POLICY] !!! ALL CATEGORIES DISARMED — EMERGENCY STOP !!!~%")
  t)

(defun category-armed-p-v2.4 (category)
  "Check if a tactical category is currently armed.

   Arguments:
     CATEGORY — Keyword naming the category.

   Returns: T if armed, NIL if disarmed or unknown.

   Example:
     (category-armed-p-v2.4 :recon)  ;; => NIL (initially)"
  (gethash category *tactical-category-armed-state* nil))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 8: Tactical Initialization — The ONE Entry Point
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *lispmind-v2.4-initialized-p* nil
  "T after successful LISPMIND-INIT-V2.4 call.
   Prevents double-initialization. Reset by LISPMIND-SHUTDOWN-V2.4.")

(defvar *tactical-init-start-time* nil
  "Timestamp when the current v2.4 init started.
   Used to calculate init duration.")

(defun lispmind-init-v2.4 (&key
                            (categories '(:recon :web :lolbin :creds
                                          :lateral :post-exploit
                                          :social-engineering :wireless))
                            (arm-categories nil)
                            (noise-budget :silent)
                            (tactical-gossip t)
                            (auto-checkpoint t)
                            (max-pivot-depth 5))
  "Initialize LISPMIND v2.4 Tactical Swarm.

   This is the ONE entry point for v2.4 tactical initialization.
   It replaces LISPMIND-INIT from v2.3.1 with a stripped, speed-first
   pipeline designed for offensive operations.

   Steps:
     1. Print v2.4 TACTICAL SWARM banner.
     2. Initialize core (orchestrator, conditions, agent-class).
     3. Load offensive tool suite (145+ tools).
     4. Load tactical registry (evasion + speed rankings).
     5. Initialize TTS evolution.
     6. Initialize policy gatekeeper (ARM/DISARM, fail-closed).
     7. [v2.4] Enable tactical gossip mode (low-bandwidth).
     8. [v2.4] Start auto-checkpoint (30s interval).
     9. [v2.4] Initialize persistence-first pipeline.
    10. [v2.4] Initialize fail-fast rotation.
    11. Print tactical status.
    12. All categories DISARMED (fail-closed).

   Keyword Arguments:
     CATEGORIES       — List of category keywords to load (default all 8).
     ARM-CATEGORIES   — DANGEROUS: list of categories to ARM immediately.
     NOISE-BUDGET     — Keyword: :SILENT :LOW :MEDIUM :AGGRESSIVE.
     TACTICAL-GOSSIP  — If T (default), enable low-bandwidth gossip mode.
     AUTO-CHECKPOINT  — If T (default), start 30s auto-checkpointing.
     MAX-PIVOT-DEPTH  — Integer, maximum pivot recursion (default 5).

   Returns: Status plist with :INITIALIZED-P :VERSION :DURATION
            :TOOLS-LOADED :CATEGORIES-LOADED :GOSSIP-ENABLED
            :CHECKPOINT-ENABLED :ARMED-CATEGORIES.

   Example:
     ;; Full tactical init — all categories, all features
     (mind:lispmind-init-v2.4)

     ;; Recon only, no gossip, no checkpoint
     (mind:lispmind-init-v2.4 :categories '(:recon)
                              :tactical-gossip nil
                              :auto-checkpoint nil)

     ;; Full init with recon+web armed immediately
     (mind:lispmind-init-v2.4 :arm-categories '(:recon :web))"
  (let ((*tactical-init-start-time* (get-internal-real-time))
        (tools-loaded 0)
        (categories-loaded 0))
    ;; Check for double-init
    (when (and *lispmind-v2.4-initialized-p* (not :force))
      (format t "~&[INIT-v2.4] Already initialized. Use :FORCE T to reinitialize.~%")
      (return-from lispmind-init-v2.4
        (list :initialized-p t :version *system-init-v2.4-version*)))
    ;; Step 1: Banner
    (print-tactical-banner)
    ;; Step 2: Initialize core
    (format t "~&[INIT-v2.4] === Core Initialization ===~%")
    (handler-case
        (progn
          (init-tactical-core)
          (format t "[INIT-v2.4] Core: OK.~%"))
      (error (e)
        (format t "[INIT-v2.4] Core init WARNING: ~A~%" e)))
    ;; Step 3: Load offensive tool suite
    (format t "~&[INIT-v2.4] === Loading Tactical Tool Suite ===~%")
    (dolist (cat categories)
      (handler-case
          (let ((count (load-tactical-category cat :verbose t)))
            (incf tools-loaded count)
            (incf categories-loaded))
        (error (e)
          (format *error-output* "[INIT-v2.4] Category ~A load error: ~A~%"
                  cat e))))
    ;; Step 4: Compute tool rankings
    (format t "~&[INIT-v2.4] === Computing Tool Rankings ===~%")
    (let ((rankings (recompute-tool-rankings)))
      (format t "[INIT-v2.4] Speed-ranked: ~D tools.~%"
              (getf rankings :speed-count))
      (format t "[INIT-v2.4] Evasion-ranked: ~D tools.~%"
              (getf rankings :evasion-count)))
    ;; Step 5: Initialize TTS evolution
    (format t "~&[INIT-v2.4] === TTS Evolution ===~%")
    (enable-tts-evolution)
    ;; Step 6: Initialize policy gatekeeper
    (format t "~&[INIT-v2.4] === Policy Gatekeeper ===~%")
    (init-tactical-policies :verbose t)
    ;; Step 7: Enable tactical gossip mode
    (when tactical-gossip
      (format t "~&[INIT-v2.4] === Tactical Gossip Mode ===~%")
      (handler-case
          (progn
            (enable-tactical-gossip-mode
             :heartbeat-interval 5
             :agent-id (format nil "orch-~D" (get-universal-time)))
            (format t "[INIT-v2.4] Tactical gossip: ACTIVE.~%"))
        (error (e)
          (format t "[INIT-v2.4] Tactical gossip init WARNING: ~A~%" e))))
    ;; Step 8: Start auto-checkpoint
    (when auto-checkpoint
      (format t "~&[INIT-v2.4] === Auto-Checkpoint ===~%")
      (handler-case
          (progn
            (start-auto-checkpoint nil :interval 30)
            (format t "[INIT-v2.4] Auto-checkpoint: ACTIVE (30s).~%"))
        (error (e)
          (format t "[INIT-v2.4] Auto-checkpoint init WARNING: ~A~%" e))))
    ;; Step 9: Initialize persistence-first pipeline
    (format t "~&[INIT-v2.4] === Persistence-First Pipeline ===~%")
    (enable-persistence-first-pipeline)
    ;; Step 10: Initialize fail-fast rotation
    (format t "~&[INIT-v2.4] === Fail-Fast Rotation ===~%")
    (enable-fail-fast-rotation)
    ;; Set max pivot depth
    (setf *max-pivot-depth* max-pivot-depth)
    (format t "[INIT-v2.4] Max pivot depth: ~D.~%" max-pivot-depth)
    ;; Step 11: ARM categories if requested (DANGEROUS)
    (when arm-categories
      (format t "~&[INIT-v2.4] !!! ARMING CATEGORIES: ~A !!!~%"
              arm-categories)
      (dolist (cat arm-categories)
        (handler-case
            (arm-category-v2.4 cat)
          (error (e)
            (format t "[INIT-v2.4] Failed to arm ~A: ~A~%" cat e)))))
    ;; Step 12: Calculate duration and build status
    (let* ((duration (/ (- (get-internal-real-time) *tactical-init-start-time*)
                        internal-time-units-per-second))
           (status (list :initialized-p t
                         :version *system-init-v2.4-version*
                         :duration duration
                         :tools-loaded tools-loaded
                         :categories-loaded categories-loaded
                         :total-tools (get-total-tool-count)
                         :gossip-enabled tactical-gossip
                         :checkpoint-enabled auto-checkpoint
                         :noise-budget noise-budget
                         :max-pivot-depth max-pivot-depth
                         :armed-categories (copy-list *tactical-armed-categories*)
                         :all-disarmed (null *tactical-armed-categories*))))
      (setf *lispmind-v2.4-initialized-p* t)
      ;; Print status
      (print-tactical-init-summary status)
      status)))

(defun lispmind-init-v2.4-minimal ()
  "Minimal tactical init: core + gossip + checkpoint only.

   Loads NO offensive tools. Initializes only the core infrastructure,
   tactical gossip mode, and auto-checkpointing.

   Suitable for: relay nodes, forward observers, lightweight scouts
   that don't need offensive capabilities.

   Returns: Status plist from LISPMIND-INIT-V2.4."
  (lispmind-init-v2.4
   :categories nil
   :arm-categories nil
   :tactical-gossip t
   :auto-checkpoint t))

(defun lispmind-init-v2.4-full ()
  "Full tactical init: all 145+ tools, all tactical features.

   Loads all 8 offensive categories, enables gossip, checkpoint,
   persistence-first pipeline, and fail-fast rotation.

   All categories remain DISARMED — arm explicitly when ready.

   Returns: Status plist from LISPMIND-INIT-V2.4."
  (lispmind-init-v2.4
   :categories '(:recon :web :lolbin :creds :lateral :post-exploit
                 :social-engineering :wireless)
   :arm-categories nil
   :tactical-gossip t
   :auto-checkpoint t
   :max-pivot-depth 5))

(defun init-tactical-core ()
  "Initialize the tactical core subsystem.

   Ensures the orchestrator binding and essential infrastructure
   are available. This is a lightweight version of the v2.3.1 core
   init — no memory budgeting, no SBCL tuning, no safety checks.

   Returns: T if core is ready."
  ;; Ensure orchestrator binding exists
  (unless (and (boundp '*default-orchestrator*) *default-orchestrator*)
    (format t "[INIT-v2.4] Core: *DEFAULT-ORCHESTRATOR* not yet bound.~%"))
  ;; Initialize gossip topic registry if needed
  (when (and (boundp '*gossip-topics*)
            (zerop (hash-table-count *gossip-topics*)))
    (format t "[INIT-v2.4] Core: Gossip topic registry ready.~%"))
  t)


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 9: Tactical Shutdown — Clean Exit with Checkpoint
;; ═══════════════════════════════════════════════════════════════════════════

(defun lispmind-shutdown-v2.4 (&key (save-checkpoint t) (evacuate nil)
                                    (verbose t))
  "Tactical shutdown: save checkpoint, kill sessions, optionally evacuate.

   Actions:
     1. Save final tactical checkpoint (if SAVE-CHECKPOINT).
     2. Stop auto-checkpoint thread.
     3. Stop tactical gossip mode.
     4. Stop TTS evolution.
     5. If EVACUATE: send evacuate commands to all peers.
     6. Kill all active tool processes.
     7. Reset initialization flags.
     8. Log shutdown complete.

   Keyword Arguments:
     SAVE-CHECKPOINT — If T (default), save final checkpoint before exit.
     EVACUATE        — If T, broadcast evacuate to all peers (default NIL).
     VERBOSE         — If T (default), print progress messages.

   Returns: Shutdown status plist.

   Example:
     ;; Normal shutdown with checkpoint
     (mind:lispmind-shutdown-v2.4)

     ;; Emergency evacuate — save checkpoint, tell peers to run
     (mind:lispmind-shutdown-v2.4 :evacuate t)"
  (when verbose
    (format t "~&[SHUTDOWN-v2.4] Beginning tactical shutdown...~%"))
  ;; Step 1: Save final checkpoint
  (when save-checkpoint
    (handler-case
        (progn
          (save-tactical-checkpoint nil)
          (when verbose
            (format t "[SHUTDOWN-v2.4] Final checkpoint saved.~%")))
      (error (e)
        (format t "[SHUTDOWN-v2.4] Checkpoint save error: ~A~%" e))))
  ;; Step 2: Stop auto-checkpoint
  (handler-case
      (stop-auto-checkpoint)
    (error (e)
      (format t "[SHUTDOWN-v2.4] Auto-checkpoint stop error: ~A~%" e)))
  ;; Step 3: Stop tactical gossip
  (handler-case
      (disable-tactical-gossip-mode)
    (error (e)
      (format t "[SHUTDOWN-v2.4] Gossip stop error: ~A~%" e)))
  ;; Step 4: Stop TTS evolution
  (setf *tts-evolution-enabled-p* nil)
  ;; Step 5: Evacuate if requested
  (when evacuate
    (handler-case
        (progn
          (send-tactical-command "*" :evacuate nil :priority :critical)
          (when verbose
            (format t "[SHUTDOWN-v2.4] EVACUATE broadcast sent to all peers.~%")))
      (error (e)
        (format t "[SHUTDOWN-v2.4] Evacuate error: ~A~%" e))))
  ;; Step 6: Kill tool processes
  (handler-case
      (when (fboundp 'kill-all-tools)
        (kill-all-tools)
        (when verbose
          (format t "[SHUTDOWN-v2.4] All tool processes killed.~%")))
    (error (e)
      (format t "[SHUTDOWN-v2.4] Tool kill error: ~A~%" e)))
  ;; Step 7: Reset flags
  (setf *lispmind-v2.4-initialized-p* nil)
  (setf *tactical-categories-loaded* nil)
  (when verbose
    (format t "[SHUTDOWN-v2.4] LISPMIND v2.4 shutdown complete.~%"))
  (list :shutdown t
        :version *system-init-v2.4-version*
        :timestamp (get-universal-time)
        :checkpoint-saved save-checkpoint
        :evacuate-sent evacuate))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 10: Tactical Status and Reporting
;; ═══════════════════════════════════════════════════════════════════════════

(defun tactical-swarm-status ()
  "Full tactical status: footholds, pivot chains, persistence, TTS scores.

   Returns a comprehensive status plist:
     :VERSION              — v2.4 version string.
     :INITIALIZED-P        — T if v2.4 init completed.
     :TOOLS-LOADED         — Total registered tools.
     :CATEGORIES-LOADED    — List of loaded category keywords.
     :ARMED-CATEGORIES     — List of armed category keywords.
     :GOSSIP-STATUS        — Plist from GET-GOSSIP-BANDWIDTH-STATS.
     :CHECKPOINT-STATUS    — Plist from TACTICAL-CHECKPOINT-STATUS.
     :TTS-EVOLUTION        — T if TTS tracking active.
     :PERSISTENCE-FIRST    — T if persistence pipeline active.
     :FAIL-FAST-ROTATION   — T if fail-fast rotation active.
     :ALIVE-PEERS          — Number of alive gossip peers.
     :AGENT-STATUS         — Current agent status.
     :PIVOT-DEPTH          — Current pivot depth.
     :TTS-SECONDS          — Current time-to-shell estimate.

   Example:
     (tactical-swarm-status)"
  (list :version *system-init-v2.4-version*
        :initialized-p *lispmind-v2.4-initialized-p*
        :tools-loaded (get-total-tool-count)
        :categories-loaded (copy-list *tactical-categories-loaded*)
        :armed-categories (copy-list *tactical-armed-categories*)
        :gossip-status (ignore-errors (get-gossip-bandwidth-stats))
        :checkpoint-status (tactical-checkpoint-status)
        :tts-evolution *tts-evolution-enabled-p*
        :persistence-first *persistence-first-enabled-p*
        :fail-fast-rotation *fail-fast-rotation-enabled-p*
        :alive-peers (or (ignore-errors (count-tactical-peers-alive)) 0)
        :agent-status (or (and (boundp '*tactical-agent-status*)
                              *tactical-agent-status*)
                         :unknown)
        :pivot-depth (or (and (boundp '*tactical-pivot-depth*)
                             *tactical-pivot-depth*)
                        0)
        :tts-seconds (or (and (boundp '*tactical-tts-seconds*)
                             *tactical-tts-seconds*)
                        0)))

(defun print-tactical-banner ()
  "Print the v2.4 TACTICAL SWARM banner.

   Returns: NIL."
  (format t "~&
╔══════════════════════════════════════════════════════════════════════════════╗
║  LISPMIND v2.4 TACTICAL SWARM                                              ║
║  Speed · Evasion · Persistence · Resume                                    ║
╠══════════════════════════════════════════════════════════════════════════════╣
║  STRIPPED: Simulation · Validation · Scientific tools · Memory budgeting   ║
║  ADDED:    Tactical gossip · Auto-checkpoint · TTS evolution · Fail-fast   ║
╚══════════════════════════════════════════════════════════════════════════════╝
~%")

(defun print-tactical-init-summary (status)
  "Print the v2.4 tactical initialization summary.

   Arguments:
     STATUS — Status plist from LISPMIND-INIT-V2.4.

   Returns: NIL."
  (format t "~&
═══════════════════════════════════════════════════════════════════════════════
  TACTICAL SWARM INITIALIZED v~A
═══════════════════════════════════════════════════════════════════════════════
  Duration:        ~,2F seconds
  Tools loaded:    ~D (~D categories)
  Gossip mode:     ~A
  Auto-checkpoint: ~A
  TTS evolution:   ~A
  Persistence:     ~A
  Fail-fast:       ~A
  Max pivot depth: ~D
  Noise budget:    ~A
  ARMED:           ~A
  Status:          ~A
═══════════════════════════════════════════════════════════════════════════════
"
          (getf status :version)
          (getf status :duration)
          (getf status :tools-loaded)
          (getf status :categories-loaded)
          (if (getf status :gossip-enabled) "ACTIVE" "OFF")
          (if (getf status :checkpoint-enabled) "ACTIVE (30s)" "OFF")
          (if *tts-evolution-enabled-p* "ACTIVE" "OFF")
          (if *persistence-first-enabled-p* "ACTIVE" "OFF")
          (if *fail-fast-rotation-enabled-p* "ACTIVE" "OFF")
          (getf status :max-pivot-depth)
          (getf status :noise-budget)
          (if (getf status :armed-categories)
              (format nil "~A" (getf status :armed-categories))
              "NONE (fail-closed)")
          (if (getf status :all-disarmed)
              "ALL DISARMED — SAFE"
              "!!! SOME CATEGORIES ARMED !!!")))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 11: Noise Budget — Stealth Configuration
;; ═══════════════════════════════════════════════════════════════════════════

(defun set-noise-budget (level)
  "Set the global noise budget for all tactical operations.

   The noise budget controls default tool parameters to stay within
   acceptable network noise levels:
     :SILENT      — Minimum noise. Slow but invisible.
     :LOW         — Low noise tolerance. Moderate speed.
     :MEDIUM      — Balanced speed vs. stealth.
     :AGGRESSIVE  — Maximum speed. High noise acceptable.

   Arguments:
     LEVEL — Keyword: :SILENT :LOW :MEDIUM :AGGRESSIVE.

   Returns: The noise level plist with :LEVEL :MAX-NOISE :THROTTLE-P.

   Example:
     (set-noise-budget :silent)"
  (let ((config (ecase level
                  (:silent (list :level :silent
                                :max-noise 10
                                :throttle-p t
                                :max-concurrent 1
                                :delay-between-ops 30))
                  (:low (list :level :low
                             :max-noise 30
                             :throttle-p t
                             :max-concurrent 2
                             :delay-between-ops 15))
                  (:medium (list :level :medium
                                :max-noise 60
                                :throttle-p nil
                                :max-concurrent 4
                                :delay-between-ops 5))
                  (:aggressive (list :level :aggressive
                                    :max-noise 100
                                    :throttle-p nil
                                    :max-concurrent 10
                                    :delay-between-ops 0)))))
    (format t "[NOISE] Budget set to ~A (max noise: ~D%).~%"
            level (getf config :max-noise))
    config))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 12: Convenience — Quick ARM/DISARM and Status
;; ═══════════════════════════════════════════════════════════════════════════

(defun arm-recon () "ARM the :RECON category." (arm-category-v2.4 :recon))
(defun arm-web () "ARM the :WEB category." (arm-category-v2.4 :web))
(defun arm-lolbin () "ARM the :LOLBIN category." (arm-category-v2.4 :lolbin))
(defun arm-creds () "ARM the :CREDS category." (arm-category-v2.4 :creds))
(defun arm-lateral () "ARM the :LATERAL category." (arm-category-v2.4 :lateral))
(defun arm-post-exploit () "ARM the :POST-EXPLOIT category." (arm-category-v2.4 :post-exploit))
(defun arm-social () "ARM the :SOCIAL-ENGINEERING category." (arm-category-v2.4 :social-engineering))
(defun arm-wireless () "ARM the :WIRELESS category." (arm-category-v2.4 :wireless))
(defun disarm-all () "DISARM ALL categories — emergency stop." (disarm-all-categories-v2.4))
(defun tactical-status () "Print tactical swarm status." (print-tactical-gossip-status))


;;;; ═════════════════════════════════════════════════════════════════════════
;;;; EXPORT SUMMARY — v2.4 Tactical Swarm
;;;;
;;;; MASTER INITIALIZATION (3 functions):
;;;;   lispmind-init-v2.4         — The ONE tactical init function.
;;;;   lispmind-init-v2.4-minimal — Core + gossip + checkpoint only.
;;;;   lispmind-init-v2.4-full    — All 145+ tools, all features.
;;;;   lispmind-shutdown-v2.4     — Tactical shutdown with checkpoint.
;;;;
;;;; TOOL REGISTRY (8 functions):
;;;;   register-tactical-tool     — Add a tool to the registry.
;;;;   load-tactical-category     — Load all tools for a category.
;;;;   get-tactical-tool-definitions — Raw tool definitions.
;;;;   recompute-tool-rankings    — Refresh speed/evasion rankings.
;;;;   select-fastest-tool        — Fastest tool by category.
;;;;   select-most-evasive-tool   — Most evasive tool by category.
;;;;   get-tools-by-entry-type    — Tools by entry vector type.
;;;;   get-total-tool-count       — Total registered tools.
;;;;
;;;; TTS EVOLUTION (4 functions):
;;;;   enable-tts-evolution       — Activate TTS tracking.
;;;;   record-tts-result          — Log actual TTS for adaptive estimates.
;;;;   get-adaptive-tts-estimate  — Get rolling-average TTS estimate.
;;;;   select-fastest-vector      — Best vector based on TTS history.
;;;;
;;;; PERSISTENCE-FIRST (3 functions):
;;;;   enable-persistence-first-pipeline — Activate persistence pipeline.
;;;;   queue-foothold-for-persistence    — Queue foothold for persist.
;;;;   install-persistence          — Install persistence on foothold.
;;;;
;;;; FAIL-FAST ROTATION (3 functions):
;;;;   enable-fail-fast-rotation  — Activate fail-fast mode.
;;;;   should-abandon-tool-p      — Check if tool should be abandoned.
;;;;   record-rotation            — Log a tool rotation event.
;;;;
;;;; POLICY GATEKEEPER (5 functions):
;;;;   init-tactical-policies     — Initialize fail-closed gatekeeper.
;;;;   arm-category-v2.4          — ARM a category.
;;;;   disarm-category-v2.4       — DISARM a category.
;;;;   disarm-all-categories-v2.4 — Emergency DISARM ALL.
;;;;   category-armed-p-v2.4      — Check if category is armed.
;;;;
;;;; STATUS (3 functions):
;;;;   tactical-swarm-status      — Full tactical status.
;;;;   print-tactical-banner      — v2.4 banner.
;;;;   print-tactical-init-summary — Post-init report.
;;;;
;;;; NOISE BUDGET (1 function):
;;;;   set-noise-budget           — Configure stealth level.
;;;;
;;;; CONVENIENCE (10 functions):
;;;;   arm-recon, arm-web, arm-lolbin, arm-creds, arm-lateral,
;;;;   arm-post-exploit, arm-social, arm-wireless,
;;;;   disarm-all, tactical-status
;;;;
;;;; REMOVED from v2.3.1:
;;;;   lispmind-init (replaced by lispmind-init-v2.4)
;;;;   init-engineering-subsystem
;;;;   arm-engineering-category
;;;;   print-thermal-status
;;;;   thermal-monitor-loop
;;;;   physical-override
;;;;   All scientific tool loading (:math :physics :engineering :electronics :ai-ml)
;;;;   All simulation bridges
;;;;   All defensive validation (verify-tool-binary-exists, verify-tool-execution, etc.)
;;;;   Memory budgeting (check-memory-budget, reserve-memory, release-memory)
;;;;   Orphaned process detection
;;;;   Model loading and inference subsystem init
;;;;   Dashboard and telemetry stream startup
;;;; ═════════════════════════════════════════════════════════════════════════

;;;; ═════════════════════════════════════════════════════════════════════════
;;;; END OF SYSTEM-INIT-V2.4.LISP
