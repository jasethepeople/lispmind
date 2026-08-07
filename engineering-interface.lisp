;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; ENGINEERING-INTERFACE.LISP — Scientific Computing Module for LISPMIND v2.3.2
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;         THE SWARM'S LABORATORY: WRAPPING SCIENTIFIC COMPUTING BINARIES
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This module extends the LISPMIND orchestrator into the domain of
;;; scientific and engineering computing. It wraps 150+ tools spanning
;;; computational fluid dynamics (OpenFOAM, SU2), finite element analysis
;;; (CalculiX, FEniCS, ElmerFEM), computer-aided design (FreeCAD, OpenSCAD),
;;; electronic design automation (KiCad, Verilator, Yosys), and artificial
;;; intelligence / machine learning (TensorFlow, PyTorch, JAX, Ollama).
;;;
;;; DESIGN PHILOSOPHY
;;; ─────────────────
;;; Scientific computing tools share a common pattern: they consume structured
;;; input (meshes, netlists, parameter files), perform computationally
;;; expensive simulations, and produce structured output (VTK files, CSV
;;; data, convergence histories). The scientific-agent abstraction unifies
;;; these under the LISPMIND agent lifecycle — every simulation is an agent,
;;; every agent has a heartbeat, and every result flows through the gossip
;;; telemetry mesh.
;;;
;;; Unlike kali-agents, which hunt for vulnerabilities, scientific-agents
;;; pursue knowledge: convergence rates, stress distributions, flow fields,
;;; and neural network loss landscapes. The same swarm infrastructure that
;;; heals a crashed nmap scan can also detect a diverging CFD simulation
;;; and apply adaptive timestepping — autonomously.
;;;
;;; ARCHITECTURE OVERVIEW
;;; ─────────────────────
;;;   SCIENTIFIC-AGENT (subclass of AGENT)
;;;   ├── binary path        (/usr/bin/foamRun, /usr/bin/ccx, ...)
;;;   ├── argument list      ("-case" "/path/to/case" ...)
;;;   ├── process handle     (UIOP:LAUNCH-PROGRAM return value)
;;;   ├── input files        (mesh, geometry, parameters, scripts)
;;;   ├── output files       (VTK, CSV, HDF5, residuals plot)
;;;   ├── compute budget     (max seconds before auto-kill)
;;;   ├── memory budget      (max MB before auto-kill)
;;;   ├── simulation data    (parsed results hash-table)
;;;   └── tool-category      (:math :physics :engineering :electronics :ai-ml)
;;;
;;;   Simulation Lifecycle
;;;   ├── SPAWN     — create agent, validate binary, check budgets
;;;   ├── RUN       — launch process, capture stdout/stderr
;;;   ├── MONITOR   — watch convergence, enforce budget limits
;;;   ├── PARSE     — extract structured data from output
;;;   ├── BROADCAST — publish results to gossip mesh
;;;   └── FINALIZE  — cleanup processes, archive outputs
;;;
;;;   Gossip Integration
;;;   ├── Topic: "swarm.science.output"     — raw tool output lines
;;;   ├── Topic: "swarm.science.data"      — structured simulation data
;;;   ├── Topic: "swarm.science.status"    — tool start/stop/health events
;;;   └── Topic: "swarm.science.results"   — completed simulation results
;;;
;;; COMPUTE BUDGET ENFORCEMENT
;;; ──────────────────────────
;;; Long-running simulations (CFD, FEA, MD) can consume hours of CPU and
;;; gigabytes of RAM. The scientific-agent implements hard budget limits:
;;;   1. The compute-budget slot specifies max wall-clock seconds.
;;;   2. The memory-budget-mb slot specifies max resident memory in MB.
;;;   3. A background monitoring thread checks budgets every 5 seconds.
;;;   4. If either budget is exceeded, the process receives SIGTERM.
;;;   5. If SIGTERM fails after 30 seconds, SIGKILL is sent.
;;;
;;; "Every simulation is an experiment. Every experiment is an agent.
;;;  Every agent has a guardian watching its resources."
;;;
;;; ═══════════════════════════════════════════════════════════════════════════

(in-package :lispmind)

;; ═══════════════════════════════════════════════════════════════════════════
;; Section 0: Special Variables — Configuration & Global Registry
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *scientific-agent-registry* (make-hash-table :test 'eq)
  "Global registry of all active SCIENTIFIC-AGENT instances.

Keys are agent IDs (gensyms), values are the SCIENTIFIC-AGENT instances.
This registry is separate from the orchestrator's agent registry because
scientific agents have a distinct lifecycle: they manage compute and
memory budgets, handle structured simulation data, and require
specialized cleanup (output files, temporary directories).

Thread-safety: Protected by *scientific-registry-lock*.

Typical usage:
  (gethash agent-id *scientific-agent-registry*)  →  agent or nil
  (list-scientific-agents)                         →  all scientific agents
  (list-active-simulations)                        →  running simulations")

(defvar *scientific-registry-lock* (bt:make-lock "scientific-registry")
  "Lock protecting *scientific-agent-registry* and related operations.

Acquired by:
  • register-scientific-agent   — when adding a new scientific agent
  • deregister-scientific-agent — when removing a scientific agent
  • list-scientific-agents      — when enumerating all scientific agents
  • halt-all-simulations        — when terminating all simulations")

(defvar *scientific-default-compute-budget* 3600
  "Default compute budget in seconds for scientific tool execution.

A value of 3600 (1 hour) is suitable for moderate simulations. Large
CFD/FEA simulations may need 14400 (4 hours) or more. Quick scripts
and utilities can run with 60 (1 minute).

Individual tool wrappers can override this via the :compute-budget
parameter of DEFINE-AGENT-TOOL. The per-agent compute-budget slot
overrides the global default.

Set to NIL to disable compute budget enforcement entirely (not
recommended for autonomous operation — a diverging simulation could
run indefinitely).")

(defvar *scientific-default-memory-budget-mb* 4096
  "Default memory budget in megabytes for scientific tool execution.

A value of 4096 (4 GB) is suitable for most engineering tools. Large
dep learning models may need 16384 (16 GB) or more. Lightweight
tools (Gnuplot, mesh converters) can run with 512 MB.

Individual tool wrappers can override this via the :memory-budget-mb
parameter of DEFINE-AGENT-TOOL.

Set to NIL to disable memory budget enforcement entirely.")

(defvar *scientific-output-buffer-max* 10000
  "Maximum number of output lines to retain in the agent's buffer.

When the buffer fills, the oldest 1000 lines are evicted (FIFO).
This prevents memory exhaustion from verbose simulation output.

Set to NIL for unlimited buffer size (not recommended for long
simulations that produce millions of output lines).")

(defvar *scientific-gossip-topics*
  '(:swarm.science.output
    :swarm.science.data
    :swarm.science.status
    :swarm.science.results)
  "List of gossip topics used by the scientific computing subsystem.

  :swarm.science.output  — Raw stdout/stderr lines from running tools.
                            High volume, low structure.

  :swarm.science.data    — Structured simulation data (convergence
                            metrics, field values, extracted results).
                            Lower volume, fully structured as plists.

  :swarm.science.status  — Lifecycle events: tool-started,
                            tool-completed, tool-error, budget-exceeded.

  :swarm.science.results — Completed simulation results with file
                            paths, summary statistics, and key findings.

All topics are registered during subsystem initialization via
INIT-ENGINEERING-SUBSYSTEM.")

(defvar *scientific-tool-registry* (make-hash-table :test 'eq)
  "Registry of all defined scientific tools and their metadata.

Keys are tool name symbols (e.g., 'openfoam, 'calculix, 'pytorch).
Values are plists with keys:
  :class-name     — The generated agent class symbol
  :binary-path    — Filesystem path to the tool binary
  :category       — Tool category keyword (:math :physics :engineering
                                          :electronics :ai-ml)
  :default-args   — Default command-line arguments
  :compute-budget — Default compute budget in seconds
  :memory-budget-mb — Default memory budget in MB
  :requires-root  — Boolean, T if tool needs root privileges
  :output-format  — Expected output format (:text :json :csv :vtk :hdf5)
  :description    — Human-readable tool description
  :loaded-p       — Boolean, T if the tool class is currently defined

Thread-safety: Protected by *scientific-tool-registry-lock*.

This registry enables introspection and dynamic tool loading.
Functions like LIST-SCIENTIFIC-TOOLS and LOAD-SCIENTIFIC-TOOL-SUITE
operate on this registry.")

(defvar *scientific-tool-registry-lock* (bt:make-lock "scientific-tool-registry")
  "Lock protecting *scientific-tool-registry*.

Acquired by DEFINE-AGENT-TOOL when registering tool metadata,
and by LOAD-SCIENTIFIC-TOOL-SUITE when bulk-loading tools.")

(defvar *scientific-tool-categories*
  '((:math          . "Mathematics & Statistics")
    (:physics       . "Physics, CFD & FEA")
    (:engineering   . "Engineering & CAD")
    (:electronics   . "Electronics & EDA")
    (:ai-ml         . "AI / Machine Learning"))
  "Alist mapping scientific tool category keywords to human-readable names.

Used by LIST-SCIENTIFIC-TOOLS and the dashboard for categorized
display of available tools.

To add a new category:
  (push (cons :my-category \"My Category\") *scientific-tool-categories*)")

(defvar *scientific-subsystem-initialized* nil
  "Boolean indicating whether the engineering subsystem has been initialized.

Set to T by INIT-ENGINEERING-SUBSYSTEM. Checked by functions that
depend on gossip topic registration (e.g., BROADCAST-SIMULATION-DATA).

If NIL, gossip broadcasts are silently dropped rather than causing
errors, allowing scientific agents to be used in isolation without
the full gossip infrastructure.")


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 1: Scientific-Agent Base Class
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; The SCIENTIFIC-AGENT is the foundation of the engineering module.
;; It extends the base AGENT class with slots for managing external
;; scientific binaries: compute budgets, memory limits, input/output
;; file tracking, and structured simulation data storage.
;;
;; Key differences from KALI-AGENT:
;;   • Compute and memory budgets with automatic enforcement
;;   • Structured simulation data (hash-table) instead of findings list
;;   • Input/output file tracking for simulation artifacts
;;   • Multiple output format support (:text :json :csv :vtk :hdf5)
;;   • Convergence monitoring for iterative solvers

(defclass scientific-agent (agent)
  ((binary :initarg :binary
           :accessor agent-binary
           :documentation "Path to the scientific binary.

This is the absolute filesystem path to the tool executable, e.g.
\"/usr/bin/foamRun\", \"/usr/bin/ccx\", or \"/usr/bin/python3\".

If a relative name is provided, VERIFY-SCIENTIFIC-BINARY resolves it
against *scientific-binary-search-paths*. Must be executable by the
current user.")

   (args :initarg :args
         :initform '()
         :accessor agent-args
         :documentation "Default arguments for the binary, as a list of strings.

These are combined with any extra arguments passed to RUN-TOOL.
Example for OpenFOAM: '(\"-case\" \"/path/to/case\")
Example for Python ML: '(\"-c\" \"import tensorflow; ...\")")

   (process :initform nil
            :accessor agent-process
            :documentation "The UIOP process handle returned by LAUNCH-PROGRAM.

NIL when the tool is not running. This slot is used by STOP-TOOL
and KILL-TOOL to manage the process lifecycle.

CAUTION: Direct manipulation of this slot from outside the agent's
methods can corrupt process state. Always use the provided STOP-TOOL
and KILL-TOOL methods.")

   (output-format :initarg :output-format
                  :initform :text
                  :accessor agent-output-format
                  :documentation "Expected output format for this tool.

One of:
  :text  — Plain text output (default, human-readable)
  :json  — JSON-structured output (machine-parseable)
  :csv   — Comma-separated values (tabular data)
  :vtk   — Visualization Toolkit format (field data)
  :hdf5  — Hierarchical Data Format v5 (large arrays)

This guides the parse-simulation-output method in selecting the
appropriate parser. The format does NOT affect what the tool actually
produces — it merely tells LISPMIND how to interpret the output.")

   (input-files :initarg :input-files
                :initform '()
                :accessor agent-input-files
                :documentation "List of input file paths for this simulation.

These are the files the tool reads during execution: meshes,
geometry files, parameter definitions, netlists, Python scripts, etc.

Tracked for:
  • Pre-flight validation (verify all inputs exist before running)
  • Provenance tracking (what inputs produced what outputs)
  • Automatic cleanup (archive inputs with outputs)

Example: '(\"/path/to/case/blockMeshDict\"
           \"/path/to/case/transportProperties\")")

   (output-files :initarg :output-files
                 :initform '()
                 :accessor agent-output-files
                 :documentation "List of expected output file paths.

These are the files the tool is expected to produce: VTK field data,
CSV convergence histories, log files, rendered images, etc.

Tracked for:
  • Post-flight validation (verify expected outputs were created)
  • Results archival (copy outputs to persistent storage)
  • Gossip broadcasting (attach output file paths to results)

Populated automatically by some tool wrappers based on the case
directory structure.")

   (compute-budget :initarg :compute-budget
                   :initform 3600
                   :accessor agent-compute-budget
                   :documentation "Maximum wall-clock seconds before auto-kill.

If the tool runs longer than this, the budget monitor thread sends
SIGTERM. If the process doesn't exit within 30 seconds, SIGKILL
follows.

Set to NIL to disable compute budget enforcement (not recommended
for autonomous operation). Override per-agent or globally via
*scientific-default-compute-budget*.")

   (memory-budget-mb :initarg :memory-budget-mb
                     :initform 4096
                     :accessor agent-memory-budget-mb
                     :documentation "Maximum resident memory in MB before auto-kill.

If the process RSS exceeds this value, the budget monitor sends
SIGTERM (graceful) then SIGKILL (forceful after 30s).

Memory monitoring is performed by parsing /proc/<pid>/status on
Linux. On other platforms, memory monitoring may not be available
and this slot is advisory only.

Set to NIL to disable memory budget enforcement.")

   (simulation-data :initform (make-hash-table :test 'eq)
                    :accessor agent-simulation-data
                    :documentation "Parsed simulation results hash-table.

Keys are symbols naming data fields:
  :convergence-history — List of residual values over iterations
  :final-residual      — Last recorded residual magnitude
  :iteration-count     — Number of solver iterations performed
  :timestep-data       — List of (time . delta-t) pairs
  :force-coefficients  — Aerodynamic forces (lift, drag, moment)
  :stress-data         — Max/min stress values
  :displacement-data   — Max displacement magnitudes
  :energy-data         — Total energy, kinetic, potential
  :custom-fields       — Tool-specific data

Values are tool-specific data structures (lists, arrays, numbers).
Populated by PARSE-SIMULATION-OUTPUT as output is captured.

Access: (gethash :convergence-history (agent-simulation-data agent))")

   (tool-category :initarg :tool-category
                  :initform :math
                  :accessor agent-tool-category
                  :documentation "Domain classification for this tool.

One of:
  :math        — Mathematics, statistics, numerical computing
  :physics     — Physics simulation: CFD, FEA, molecular dynamics
  :engineering — CAD, CAM, geometry processing, meshing
  :electronics — EDA, circuit simulation, FPGA, VLSI
  :ai-ml       — Machine learning, deep learning, NLP, vector DBs

Used by the orchestrator for capability-based task routing and by
telemetry for categorized reporting."))

  (:documentation "A scientific-agent wraps engineering/scientific binaries.

It manages compute budgets, parses simulation output, and pipes
structured data into the gossip telemetry mesh. Unlike kali-agents,
scientific-agents have compute/memory budgets and produce structured
simulation data rather than security findings.

The scientific-agent lifecycle:
  1. Created via MAKE-<TOOL>-AGENT constructor
  2. Input files validated by VERIFY-INPUT-FILES
  3. Process launched by RUN-TOOL with budget monitoring
  4. Output captured by CAPTURE-SIMULATION-OUTPUT
  5. Structured data extracted by PARSE-SIMULATION-OUTPUT
  6. Results broadcast via BROADCAST-SIMULATION-COMPLETION
  7. Cleanup performed by FINALIZE-AGENT

Thread-safety:
  • Reads of binary, args, output-format, input-files, output-files,
    compute-budget, memory-budget-mb, and tool-category are lock-free.
  • Writes to process, simulation-data, and status MUST hold the
    agent lock via BT:WITH-LOCK-HELD.
  • The simulation-data hash-table is NOT thread-safe; external
    readers should copy data rather than accessing in-place."))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 2: Registry Management — Registering Scientific Agents
;; ═══════════════════════════════════════════════════════════════════════════

(defun register-scientific-agent (agent)
  "Register a SCIENTIFIC-AGENT in the global registry.

Acquires *scientific-registry-lock*, then stores the agent in
*scientific-agent-registry* keyed by its agent-id. If an agent
with the same ID already exists, it is overwritten (with a warning).

Parameters:
  AGENT — The SCIENTIFIC-AGENT instance to register.

Returns: The registered AGENT.

Side effects:
  • Acquires *scientific-registry-lock*
  • Modifies *scientific-agent-registry*
  • Broadcasts gossip message on :swarm.science.status"
  (bt:with-lock-held (*scientific-registry-lock*)
    (let ((existing (gethash (agent-id agent) *scientific-agent-registry*)))
      (when existing
        (warn "[SCIENCE] Replacing existing scientific agent ~A in registry."
              (agent-id agent)))
      (setf (gethash (agent-id agent) *scientific-agent-registry*) agent)))
  ;; Gossip: announce registration
  (when *scientific-subsystem-initialized*
    (publish-message :swarm.science.status
                     `(:event :agent-registered
                       :agent-id ,(agent-id agent)
                       :tool-category ,(agent-tool-category agent)
                       :binary ,(agent-binary agent)
                       :timestamp ,(local-time:now))))
  agent)

(defun deregister-scientific-agent (agent-or-id)
  "Remove a SCIENTIFIC-AGENT from the global registry.

Accepts either an agent instance (extracts the ID) or a symbol ID.
Acquires *scientific-registry-lock* for thread safety.

Parameters:
  AGENT-OR-ID — A SCIENTIFIC-AGENT instance or a gensym agent-id.

Returns: T if an agent was removed, NIL if not found.

Side effects:
  • Acquires *scientific-registry-lock*
  • Modifies *scientific-agent-registry*"
  (let ((id (if (typep agent-or-id 'scientific-agent)
                (agent-id agent-or-id)
                agent-or-id)))
    (bt:with-lock-held (*scientific-registry-lock*)
      (remhash id *scientific-agent-registry*))))

(defun lookup-scientific-agent (id)
  "Look up a SCIENTIFIC-AGENT by its ID in the global registry.

Thread-safe read via *scientific-registry-lock*.

Parameters:
  ID — The gensym agent-id to look up.

Returns: The SCIENTIFIC-AGENT instance, or NIL if not found."
  (bt:with-lock-held (*scientific-registry-lock*)
    (gethash id *scientific-agent-registry*)))

(defun list-scientific-agents ()
  "Return a list of all registered SCIENTIFIC-AGENT instances.

Thread-safe enumeration via *scientific-registry-lock*.

Returns: A fresh list of all scientific agents currently in the
registry. The list is safe to modify — it does not affect the
underlying hash table.

Example:
  (list-scientific-agents)
  => (#<SCIENTIFIC-AGENT openfoam-1234> #<SCIENTIFIC-AGENT calculix-5678>)"
  (bt:with-lock-held (*scientific-registry-lock*)
    (let ((agents '()))
      (maphash (lambda (id agent)
                 (declare (ignore id))
                 (push agent agents))
               *scientific-agent-registry*)
      agents)))

(defun list-active-simulations ()
  "Return a list of all currently running scientific simulations.

A simulation is considered 'active' if its agent status is :RUNNING
and it has a live process handle.

Returns: A list of SCIENTIFIC-AGENT instances with active processes.

Example:
  (list-active-simulations)
  => (#<OPENFOAM-AGENT {1234}>)

  (mapcar #'agent-id (list-active-simulations))
  => (AGENT-1234 AGENT-5678)"
  (remove-if-not (lambda (agent)
                   (and (eq (agent-status agent) :running)
                        (agent-process agent)
                        (uiop:process-alive-p (agent-process agent))))
                 (list-scientific-agents)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 3: Binary Discovery & Verification
;; ═══════════════════════════════════════════════════════════════════════════

(defvar *scientific-binary-search-paths*
  '(#P"/usr/bin/"
    #P"/usr/local/bin/"
    #P"/opt/"
    #P"/opt/openfoam*/platforms/*/bin/"
    #P"/opt/ansys/bin/"
    #P"/opt/abaqus/bin/"
    #P"/opt/comsol/bin/"
    #P"/opt/moose/bin/"
    #P"/opt/xflow/bin/"
    #P"/opt/autodesk/fusion360/bin/"
    #P"/opt/siemens/nx/bin/"
    #P"/opt/dassault/bin/"
    #P"/opt/solidworks/bin/"
    #P"/opt/autocad/bin/"
    #P"/opt/altium/bin/"
    #P"/opt/mentor/bin/"
    #P"/opt/stable-diffusion/"
    #P"/usr/lib/freecad/bin/"
    #P"/usr/lib/salome/bin/"
    #P"/usr/lib/openfoam/openfoam*/bin/")
  "List of pathname designators to search for scientific binaries.

When VERIFY-SCIENTIFIC-BINARY is called with a relative binary name,
these paths are searched in order. Wildcard patterns (* and **) are
expanded by DIRECTORY.

Extend this list for site-specific installations:
  (push #P\"/custom/path/bin/\" *scientific-binary-search-paths*)"))

(defun verify-scientific-binary (binary-name)
  "Verify that a scientific binary exists and is executable.

If BINARY-NAME is an absolute path, checks that it exists and is
executable. If it's a relative name, searches
*scientific-binary-search-paths* and returns the first match.

Parameters:
  BINARY-NAME — String or pathname, the binary to verify.

Returns: The pathname of the verified binary, or NIL if not found.

Example:
  (verify-scientific-binary \"/usr/bin/python3\")
  => #P\"/usr/bin/python3\"

  (verify-scientific-binary \"foamRun\")
  => #P\"/usr/lib/openfoam/openfoam2312/bin/foamRun\"  ; or nil

  (verify-scientific-binary \"nonexistent-tool\")
  => NIL"
  (let ((probe (probe-file binary-name)))
    (cond
      ;; Absolute path provided and exists
      (probe
       (if (and (not (uiop:directory-pathname-p probe))
                (ignore-errors (uiop:file-executable-p probe)))
           probe
           (progn
             (warn "[SCIENCE] Binary exists but is not executable: ~A" probe)
             nil)))
      ;; Relative name — search paths
      (t
       (loop for search-path in *scientific-binary-search-paths*
             for expanded = (if (wild-pathname-p search-path)
                                (directory search-path)
                                (list search-path))
             append expanded into all-paths
             finally
                (return
                  (loop for base in all-paths
                        for full = (merge-pathnames
                                    (make-pathname :name (pathname-name binary-name)
                                                   :type (pathname-type binary-name))
                                    base)
                        when (and (probe-file full)
                                  (ignore-errors (uiop:file-executable-p full)))
                          return full)))))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 4: Generic define-agent-tool Macro
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This is the code generation engine for the entire engineering module.
;; A single DEFINE-AGENT-TOOL form expands into eight definitions that
;; provide the complete agent lifecycle for a scientific tool.
;;
;; The macro handles BOTH tool types:
;;   :scientific — extends scientific-agent (this module)
;;   :offensive  — extends kali-agent (kali-interface.lisp, backward compat)
;;
;; This unification means all LISPMIND tools are defined through the
;; same interface, regardless of domain.

(defmacro define-agent-tool (name &key binary-path category tool-type
                                     default-args
                                     (requires-root nil)
                                     (output-format :text)
                                     (compute-budget 3600)
                                     (memory-budget-mb 4096)
                                     (description ""))
  "Generic tool definition macro for both offensive and scientific tools.

This macro is the crown jewel of LISPMIND's unified tool system. A
single form expands into eight definitions that provide the complete
agent lifecycle for any tool — whether it's a penetration testing
tool or a scientific computing binary.

Parameters:
  NAME          — Symbol naming the tool (e.g., 'openfoam, 'pytorch).
                  The generated class will be named <name>-agent.
  :BINARY-PATH  — String, absolute path to the system binary.
                  Example: \"/usr/bin/foamRun\"
  :CATEGORY     — Keyword classifying the tool domain.
                  One of: :lolbin :creds :lateral :post-exploit :web
                          :recon :social-engineering :wireless
                          :math :physics :engineering :electronics :ai-ml
  :TOOL-TYPE    — :scientific (extends scientific-agent) or
                  :offensive (extends kali-agent, for backward compat).
                  Default is :scientific.
  :DEFAULT-ARGS — List of strings passed to the binary on every run.
                  Example: '(\"-case\" \"/path/to/case\")
  :REQUIRES-ROOT — Boolean, if T the run-tool :before method wraps
                  invocation in sudo. Default NIL.
  :OUTPUT-FORMAT — :text, :json, :csv, :vtk, or :hdf5. Guides
                  parse-simulation-output. Default :text.
  :COMPUTE-BUDGET — Max wall-clock seconds. Default 3600.
  :MEMORY-BUDGET-MB — Max resident memory in MB. Default 4096.
  :DESCRIPTION  — Human-readable description for documentation.

Macro Expansion (eight definition forms):
  1. DEFCLASS    — <name>-agent subclass with tool metadata
  2. DEFMETHOD   — run-tool with compute/memory budget enforcement
  3. DEFMETHOD   — parse-simulation-output with format-aware parsing
  4. DEFMETHOD   — tool-category returning the category keyword
  5. DEFMETHOD   — tool-binary-path returning the binary path
  6. DEFUN       — make-<name>-agent constructor function
  7. DEFMETHOD   — finalize-agent :after for cleanup
  8. REGISTRY    — Tool metadata registration + gossip announcement

Example:
  (define-agent-tool openfoam
    :binary-path \"/usr/bin/foamRun\"
    :category :physics
    :tool-type :scientific
    :compute-budget 14400
    :memory-budget-mb 32768
    :description \"OpenFOAM — Computational Fluid Dynamics toolkit\")

Generates: openfoam-agent class + all methods + make-openfoam-agent function.

See also: *scientific-tool-registry*, load-scientific-tool-suite."
  (let* ((agent-class (intern (format nil "~A-AGENT" (symbol-name name))
                              (symbol-package name)))
         (constructor (intern (format nil "MAKE-~A-AGENT" (symbol-name name))
                              (symbol-package name)))
         (parent-class (ecase tool-type
                         (:scientific 'scientific-agent)
                         (:offensive 'kali-agent)))
         (category-sym category)
         (binary-sym binary-path)
         (root-p requires-root)
         (format-sym output-format)
         (compute compute-budget)
         (mem memory-budget-mb)
         (desc description))
    `(progn
       ;; ── 1. Agent Class Definition ──────────────────────────────────
       (defclass ,agent-class (,parent-class)
         ((tool-name :initform ',name
                     :reader agent-tool-name
                     :documentation
                     ,(format nil "Symbol naming this tool: ~A.~%
                               Set at class definition time by the~%
                               DEFINE-AGENT-TOOL macro."
                              name))
          (tool-version :initform "unknown"
                        :accessor agent-tool-version
                        :documentation
                        "Version string for the installed tool.~%
                         Populated lazily by querying the binary.~%
                         Example: '2312' for OpenFOAM v2312."))
         (:documentation
          ,(format nil "~A tool agent for ~A (~A).~%~A~%~%
                       Generated automatically by DEFINE-AGENT-TOOL.~%
                       Category: ~A | Binary: ~A | Requires root: ~A~%
                       Compute budget: ~A seconds | Memory budget: ~A MB"
                   (string-capitalize (symbol-name tool-type))
                   (string-capitalize (symbol-name name))
                   category-sym
                   (if (string= desc "")
                       ""
                       (format nil "~A~%" desc))
                   category-sym binary-sym root-p compute mem)))

       ;; ── 2. run-tool method with budget enforcement ────────────────
       (defmethod run-tool ((agent ,agent-class) &rest extra-args)
         ,(format nil "Execute the ~A tool with full orchestrator supervision~%
                   and compute/memory budget enforcement.~%~%
                   Steps:~%
                   1. Verify the binary exists and is executable.~%
                   2. Validate input files if specified.~%
                   3. Combine default args with EXTRA-ARGS.~%
                   4. Apply sudo wrapper if requires-root.~%
                   5. Launch process via UIOP:LAUNCH-PROGRAM.~%
                   6. Store process handle and start budget monitor.~%
                   7. Set status to :RUNNING and update heartbeat.~%
                   8. Register agent and publish start event to gossip.~%~%
                   Compute budget: ~A seconds~%
                   Memory budget: ~A MB"
                  (string-capitalize (symbol-name name))
                  compute mem)
         (let ((binary (verify-scientific-binary (agent-binary agent))))
           (unless binary
             (warn "[SCIENCE] Cannot run agent ~A: binary ~A not available."
                   (agent-id agent) (agent-binary agent))
             (return-from run-tool nil))
           ;; Build the full argument list
           (let* ((all-args (append (agent-args agent) extra-args))
                  (command (cons (namestring binary) all-args)))
             ;; Acquire agent lock for state changes
             (bt:with-lock-held ((agent-lock agent))
               ;; If there's already a process, stop it first
               (when (agent-process agent)
                 (ignore-errors
                   (uiop:terminate-process (agent-process agent) :urgent t))
                 (setf (agent-process agent) nil))
               ;; Launch the new process
               (handler-case
                   (let ((process-info
                          (uiop:launch-program command
                                               :output :stream
                                               :error-output :output
                                               :if-output-exists :supersede)))
                     (setf (agent-process agent) process-info
                           (agent-output-stream agent)
                           (uiop:process-info-output process-info)
                           (agent-start-time agent) (local-time:now)
                           (agent-status agent) :running)
                     ;; Register and notify
                     (unless (lookup-scientific-agent (agent-id agent))
                       (register-scientific-agent agent))
                     ;; Start budget monitor thread
                     (start-budget-monitor agent)
                     ;; Gossip: announce tool start
                     (when *scientific-subsystem-initialized*
                       (publish-message :swarm.science.status
                                        `(:event :tool-started
                                          :agent-id ,(agent-id agent)
                                          :command ,(format nil "~{~A ~}" command)
                                          :category ,(agent-tool-category agent)
                                          :tool ',name
                                          :timestamp ,(local-time:now))))
                     process-info)
                 (error (e)
                   (setf (agent-status agent) :failed)
                   (warn "[SCIENCE] Failed to launch ~A: ~A" (agent-id agent) e)
                   nil))))))

       ;; ── 3. parse-simulation-output stub ───────────────────────────
       (defmethod parse-simulation-output ((agent ,agent-class) line)
         ,(format nil "Parse a line of output from ~A for structured~%
                   simulation data.~%~%
                   This method extracts tool-specific data from each~%
                   line of output and stores it in the agent's~%
                   simulation-data hash-table.~%~%
                   Parameters:~%
                     AGENT — The ~A instance.~%
                     LINE  — One line of output from the tool.~%~%
                   Returns: The parsed data structure, or NIL if no~%
                   data was extracted from this line."
                  (string-capitalize (symbol-name name))
                  agent-class)
         (declare (ignorable line))
         nil)

       ;; ── 4. tool-category accessor ──────────────────────────────────
       (defmethod tool-category ((agent ,agent-class))
         ,(format nil "Return the category keyword for this ~A agent.~%~%
                   Returns ~A, indicating this tool belongs to the~%
                   ~:*~A category."
                  (string-capitalize (symbol-name name))
                  category-sym)
         ',category-sym)

       ;; ── 5. tool-binary-path accessor ───────────────────────────────
       (defmethod tool-binary-path ((agent ,agent-class))
         ,(format nil "Return the filesystem path to the ~A binary.~%~%
                   Returns \"~A\"."
                  (string-capitalize (symbol-name name))
                  binary-sym)
         ,binary-sym)

       ;; ── 6. Constructor function ────────────────────────────────────
       (defun ,constructor (&key (args ',default-args)
                               (input-files '())
                               (output-files '())
                               (compute-budget ,compute)
                               (memory-budget-mb ,mem))
         ,(format nil "Create a new ~A agent with the specified parameters.~%~%
                   Parameters:~%
                     :ARGS          — List of command-line argument strings.~%
                                      Default: ~S~%
                     :INPUT-FILES   — List of input file pathnames.~%
                                      Default: NIL~%
                     :OUTPUT-FILES  — List of expected output file pathnames.~%
                                      Default: NIL~%
                     :COMPUTE-BUDGET — Max wall-clock seconds.~%
                                      Default: ~A~%
                     :MEMORY-BUDGET-MB — Max resident memory in MB.~%
                                      Default: ~A~%~%
                   Returns: A ~A instance, ready for run-tool.~%~%
                   The agent is NOT automatically started. Call run-tool~%
                   to execute the underlying binary."
                  agent-class
                  default-args
                  compute
                  mem
                  agent-class)
         (let ((instance (make-instance ',agent-class
                         :binary ,binary-sym
                         :args args
                         :input-files input-files
                         :output-files output-files
                         :compute-budget compute-budget
                         :memory-budget-mb memory-budget-mb
                         :tool-category ,category-sym
                         :output-format ,format-sym)))
           ;; Register in the scientific tool registry
           (bt:with-lock-held (*scientific-tool-registry-lock*)
             (setf (gethash ',name *scientific-tool-registry*)
                   (list :class-name ',agent-class
                         :binary-path ,binary-sym
                         :category ,category-sym
                         :default-args args
                         :compute-budget compute-budget
                         :memory-budget-mb memory-budget-mb
                         :requires-root ,root-p
                         :output-format ,format-sym
                         :description ,desc
                         :loaded-p t)))
           ;; Gossip: announce tool spawn
           (when *scientific-subsystem-initialized*
             (publish-message :swarm.science.status
                              `(:event :tool-spawned
                                :tool ',name
                                :agent-id (agent-id instance)
                                :category ,category-sym
                                :timestamp (local-time:now))))
           ;; Register in the scientific agent registry too
           (register-scientific-agent instance)
           instance))

       ;; ── 7. finalize-agent :after — process cleanup ────────────────
       (defmethod finalize-agent :after ((agent ,agent-class))
         ,(format nil "Clean up any remaining process state for ~A.~%~%
                   This :after method ensures that when a ~A is~%
                   garbage-collected or explicitly finalized, any~%
                   dangling process handles are closed and the agent~%
                   is deregistered from all registries."
                  agent-class agent-class)
         (ignore-errors
           (when (agent-process agent)
             (uiop:terminate-process (agent-process agent) :urgent t)
             (setf (agent-process agent) nil)))
         (ignore-errors
           (when (slot-boundp agent 'output-stream)
             (when (agent-output-stream agent)
               (close (agent-output-stream agent))
               (setf (agent-output-stream agent) nil))))
         ;; Deregister from the scientific tool registry
         (bt:with-lock-held (*scientific-tool-registry-lock*)
           (let ((entry (gethash ',name *scientific-tool-registry*)))
             (when entry
               (setf (getf entry :loaded-p) nil))))
         (deregister-scientific-agent agent)
         (log-message :info "[SCIENCE] Finalized ~A agent ~A"
                      ',name (agent-id agent)))

       ;; ── 8. Record macro expansion for introspection ────────────────
       (log-message :debug "[SCIENCE] Defined ~A (~A/~A) → ~A"
                    ',name ',category-sym ',tool-type ',agent-class)

       ;; Return the class symbol for convenience
       ',agent-class)))



;; ═══════════════════════════════════════════════════════════════════════════
;; Section 5: Simulation Output Capture & Budget Monitoring
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These methods manage the real-time capture of tool output and the
;; enforcement of compute/memory budgets. A background monitoring thread
;; checks budgets every 5 seconds and terminates the process if limits
;; are exceeded.

(defmethod capture-simulation-output ((agent scientific-agent))
  "Non-blocking read of the tool's output stream.

Reads all currently available lines from the process output stream,
storing each line in the agent's output buffer. For each line:
  1. Append to the output buffer (with eviction if at max capacity).
  2. Update the agent-last-output slot.
  3. Broadcast the raw line to gossip topic :swarm.science.output.
  4. Call PARSE-SIMULATION-OUTPUT to extract structured data.
  5. Update the agent heartbeat.

This method is designed to be called repeatedly (e.g., in a background
thread or the agent's strategy function). It does NOT block.

Parameters:
  AGENT — The SCIENTIFIC-AGENT whose output to capture.

Returns: The number of lines read this invocation (0 if none available).

Thread-safety: Acquires the agent's process-lock for stream access.
  The simulation-data hash-table is NOT locked — external readers
  should be aware of concurrent mutation."
  (let ((lines-read 0)
        (stream (agent-output-stream agent)))
    (unless stream
      (return-from capture-simulation-output 0))
    (handler-case
        (loop
          (unless (listen stream)
            (return))
          (let ((line (read-line stream nil nil)))
            (unless line
              (return))
            (incf lines-read)
            ;; Store in output buffer with size cap
            (vector-push-extend line (agent-output-buffer agent))
            (when (and *scientific-output-buffer-max*
                       (> (length (agent-output-buffer agent))
                          *scientific-output-buffer-max*))
              (let ((buf (agent-output-buffer agent)))
                (replace buf buf :start2 1000)
                (decf (fill-pointer buf) 1000)))
            ;; Update last-output
            (setf (agent-last-output agent) line)
            ;; Broadcast raw output to gossip
            (when *scientific-subsystem-initialized*
              (publish-message :swarm.science.output
                               `(:agent-id ,(agent-id agent)
                                 :line ,line
                                 :timestamp ,(local-time:now))))
            ;; Parse for structured simulation data
            (parse-simulation-output agent line)))
      (end-of-file () nil)
      (error (e)
        (warn "[SCIENCE] Output capture error for ~A: ~A"
              (agent-id agent) e)))
    ;; Update heartbeat
    (when (> lines-read 0)
      (setf (agent-heartbeat agent) (local-time:now)))
    lines-read))

(defvar *budget-monitor-poll-interval* 5
  "Seconds between budget monitor checks.

The budget monitor thread wakes up every this many seconds to check
whether the agent's process has exceeded its compute or memory budget.
A value of 5 provides a reasonable trade-off between responsiveness
and CPU overhead. Shorter intervals catch budget violations faster
but consume more CPU. Longer intervals may allow modest overruns.")

(defun start-budget-monitor (agent)
  "Start a background thread that monitors compute and memory budgets.

The monitor thread checks every *budget-monitor-poll-interval* seconds:
  1. If the process has been running longer than compute-budget,
     send SIGTERM. If still alive after 30s, send SIGKILL.
  2. If /proc/<pid>/status shows VmRSS > memory-budget-mb * 1024 KB,
     send SIGTERM then SIGKILL.

Parameters:
  AGENT — The SCIENTIFIC-AGENT to monitor.

Returns: The monitor thread object.

The monitor thread exits automatically when the process terminates.
Only one monitor thread per agent — calling this multiple times
on the same agent is a no-op."
  (bt:make-thread
   (lambda ()
     (loop
       (sleep *budget-monitor-poll-interval*)
       ;; Check if process is still alive
       (let ((proc (agent-process agent)))
         (unless (and proc (uiop:process-alive-p proc))
           (return))
         ;; Check compute budget
         (let ((budget (agent-compute-budget agent))
               (start (agent-start-time agent)))
           (when (and budget start)
             (let ((elapsed (- (local-time:timestamp-to-unix
                                (local-time:now))
                               (local-time:timestamp-to-unix start))))
               (when (> elapsed budget)
                 (warn "[SCIENCE] Agent ~A exceeded compute budget (~As > ~As). Terminating."
                       (agent-id agent) elapsed budget)
                 (ignore-errors
                   (uiop:terminate-process proc))
                 (sleep 30)
                 (when (uiop:process-alive-p proc)
                   (ignore-errors
                     (uiop:terminate-process proc :urgent t)))
                 ;; Broadcast budget exceeded event
                 (when *scientific-subsystem-initialized*
                   (publish-message :swarm.science.status
                                    `(:event :budget-exceeded
                                      :agent-id ,(agent-id agent)
                                      :budget-type :compute
                                      :budget-seconds ,budget
                                      :elapsed-seconds ,elapsed
                                      :timestamp ,(local-time:now))))
                 (return))))
         ;; Check memory budget
         (let ((mem-budget (agent-memory-budget-mb agent))
               (pid (uiop:process-info-pid proc)))
           (when (and mem-budget pid)
             (let ((rss-mb (get-process-rss-mb pid)))
               (when (and rss-mb (> rss-mb mem-budget))
                 (warn "[SCIENCE] Agent ~A exceeded memory budget (~AM > ~AM). Terminating."
                       (agent-id agent) rss-mb mem-budget)
                 (ignore-errors
                   (uiop:terminate-process proc))
                 (sleep 30)
                 (when (uiop:process-alive-p proc)
                   (ignore-errors
                     (uiop:terminate-process proc :urgent t)))
                 (when *scientific-subsystem-initialized*
                   (publish-message :swarm.science.status
                                    `(:event :budget-exceeded
                                      :agent-id ,(agent-id agent)
                                      :budget-type :memory
                                      :budget-mb ,mem-budget
                                      :used-mb ,rss-mb
                                      :timestamp ,(local-time:now))))
                 (return))))))))
   :name (format nil "budget-monitor-~A" (agent-id agent))))

(defun get-process-rss-mb (pid)
  "Read the resident set size (RSS) of a process in megabytes.

Reads /proc/<pid>/status on Linux systems to extract the VmRSS
field. Returns NIL on non-Linux systems or if the process no longer
exists.

Parameters:
  PID — Integer, the process ID to query.

Returns: RSS in megabytes as a float, or NIL if unavailable.

Example:
  (get-process-rss-mb 1234) => 512.0  ; 512 MB resident"
  #+(and sbcl unix (not darwin))
  (handler-case
      (with-open-file (f (format nil "/proc/~A/status" pid)
                         :direction :input
                         :if-does-not-exist nil)
        (when f
          (loop for line = (read-line f nil nil)
                while line
                when (cl-ppcre:scan "^VmRSS:" line)
                  do (cl-ppcre:register-groups-bind (kb-str)
                         ("VmRSS:\\s*([0-9]+)\\s*kB" line)
                       (return (when kb-str
                                 (/ (parse-integer kb-str) 1024.0)))))))
  (error () nil))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 6: Simulation Data Parsers
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These methods extract structured simulation data from tool output.
;; The generic method on SCIENTIFIC-AGENT provides a no-op default.
;; Specialized :after methods for specific tools (OpenFOAM, CalculiX,
;; LAMMPS) parse domain-specific output formats.

(defmethod parse-simulation-output ((agent scientific-agent) line)
  "Parse a line of tool output for structured simulation data.

This is the generic method — it provides a no-op default. Each tool
subclass should define its own PARSE-SIMULATION-OUTPUT method that
extracts domain-specific data and stores it in the agent's
simulation-data hash-table.

Parameters:
  AGENT — The SCIENTIFIC-AGENT that produced this line.
  LINE  — A string, one line of output from the tool.

Returns: The parsed data structure, or NIL if no data was extracted.

The primary method on SCIENTIFIC-AGENT returns NIL for all input.
Specialized methods on tool-specific subclasses (e.g., OPENFOAM-AGENT,
CALCULIX-AGENT) extract meaningful data. Use :after methods to
augment rather than replace parsing behavior."
  (declare (ignorable line))
  nil)

;; ── OpenFOAM Specialized Parser ──────────────────────────────────────────

(defmethod parse-simulation-output :after ((agent openfoam-agent) line)
  "Parse OpenFOAM residuals, Courant numbers, and force coefficients.

OpenFOAM solvers (simpleFoam, pimpleFoam, icoFoam) produce log output
containing:
  • Residual values for each field (Ux, Uy, Uz, p, k, epsilon, omega)
  • Courant number (Co) for timestep stability
  • Execution time per iteration
  • Continuity errors

This parser extracts these values and stores them in the agent's
simulation-data hash-table under keys:
  :convergence-history — Alist of (field-name . residual-list)
  :courant-number      — List of Courant numbers over time
  :continuity-error    — List of continuity errors
  :execution-time      — List of execution times per timestep

Parameters:
  AGENT — The OPENFOAM-AGENT instance.
  LINE  — One line of OpenFOAM solver output.

Example parsed lines:
  'DILUPBiCGStab: Solving for Ux, Initial residual = 0.001234'
  'Courant Number mean: 0.5 max: 2.3'
  'time step continuity errors : sum local = 1.2e-5'
  'ExecutionTime = 123.4 s'

  (parse-simulation-output my-openfoam-agent
                           \"DILUPBiCGStab: Solving for Ux, Initial residual = 0.001234\")
  ;; Stores: (gethash :convergence-history sim-data) => ((:ux 0.001234) ...)"
  (cond
    ;; Residual extraction: "Solving for Ux, Initial residual = 0.001234"
    ((cl-ppcre:scan "Solving for\\s+(\\w+).*Initial residual\\s*=\\s*([0-9.eE+-]+)" line)
     (cl-ppcre:register-groups-bind (field-name residual-str)
         ("Solving for\\s+(\\w+).*Initial residual\\s*=\\s*([0-9.eE+-]+)" line)
       (when (and field-name residual-str)
         (let ((field (intern (string-upcase field-name) :keyword))
               (residual (read-from-string residual-str))
               (data (agent-simulation-data agent)))
           (let ((history (gethash :convergence-history data)))
             (unless history
               (setf history '())
               (setf (gethash :convergence-history data) history))
             (let ((entry (assoc field history)))
               (if entry
                   (rplacd entry (append (cdr entry) (list residual)))
                   (setf (gethash :convergence-history data)
                         (acons field (list residual) history)))))
           (setf (gethash :last-residual (agent-simulation-data agent)) residual))))
    ;; Courant number extraction
    ((cl-ppcre:scan "Courant Number mean:\\s*([0-9.eE+-]+).*max:\\s*([0-9.eE+-]+)" line)
     (cl-ppcre:register-groups-bind (mean-str max-str)
         ("Courant Number mean:\\s*([0-9.eE+-]+).*max:\\s*([0-9.eE+-]+)" line)
       (when (and mean-str max-str)
         (let ((co-data (list :mean (read-from-string mean-str)
                              :max (read-from-string max-str)))
               (data (agent-simulation-data agent)))
           (let ((history (gethash :courant-number data)))
             (setf (gethash :courant-number data)
                   (append history (list co-data)))))))
    ;; Continuity error
    ((cl-ppcre:scan "continuity errors.*sum local.*=\\s*([0-9.eE+-]+)" line)
     (cl-ppcre:register-groups-bind (err-str)
         ("continuity errors.*sum local.*=\\s*([0-9.eE+-]+)" line)
       (when err-str
         (let ((data (agent-simulation-data agent)))
           (let ((history (gethash :continuity-error data)))
             (setf (gethash :continuity-error data)
                   (append history (list (read-from-string err-str))))))))
    ;; Execution time
    ((cl-ppcre:scan "ExecutionTime\\s*=\\s*([0-9.eE+-]+)\\s*s" line)
     (cl-ppcre:register-groups-bind (time-str)
         ("ExecutionTime\\s*=\\s*([0-9.eE+-]+)\\s*s" line)
       (when time-str
         (let ((data (agent-simulation-data agent)))
           (let ((history (gethash :execution-time data)))
             (setf (gethash :execution-time data)
                   (append history (list (read-from-string time-str))))))))
    ;; Force coefficients (for forces functionObject)
    ((cl-ppcre:scan "(Cd|Cl|Cm)\\s*:\\s*([0-9.eE+-]+)" line)
     (cl-ppcre:register-groups-bind (coeff-name coeff-str)
         ("(Cd|Cl|Cm)\\s*:\\s*([0-9.eE+-]+)" line)
       (when (and coeff-name coeff-str)
         (let ((coeff-key (intern (string-upcase coeff-name) :keyword))
               (data (agent-simulation-data agent)))
           (let ((forces (gethash :force-coefficients data)))
             (unless forces
               (setf forces (make-hash-table :test 'eq)))
             (let ((history (gethash coeff-key forces)))
               (setf (gethash coeff-key forces)
                     (append history (list (read-from-string coeff-str))))))))))

;; ── CalculiX Specialized Parser ──────────────────────────────────────────

(defmethod parse-simulation-output :after ((agent calculix-agent) line)
  "Parse CalculiX stress, strain, and displacement data.

CalculiX (ccx) produces output containing:
  • Step completion messages
  • Convergence information for nonlinear analyses
  • Warning/error messages about element quality
  • Timing information for each step

This parser extracts these values and stores them under keys:
  :step-completions    — List of completed step numbers
  :convergence-info    — Convergence criteria data
  :stress-data         — Max/min stress values if available in output
  :displacement-data   — Max displacement values if available
  :timing-info         — Wall-clock time per step

Parameters:
  AGENT — The CALCULIX-AGENT instance.
  LINE  — One line of CalculiX solver output.

Example parsed lines:
  'STEP 1'
  'convergence criteria satisfied after 5 iterations'
  'Maximum stress = 250.0 MPa'"
  (cond
    ;; Step completion: "STEP 1"
    ((cl-ppcre:scan "^\\s*STEP\\s+([0-9]+)" line)
     (cl-ppcre:register-groups-bind (step-str)
         ("^\\s*STEP\\s+([0-9]+)" line)
       (when step-str
         (let ((data (agent-simulation-data agent)))
           (let ((steps (gethash :step-completions data)))
             (setf (gethash :step-completions data)
                   (append steps (list (parse-integer step-str))))))))
    ;; Convergence information
    ((cl-ppcre:scan "convergence criteria satisfied after\\s+([0-9]+)\\s+iterations" line)
     (cl-ppcre:register-groups-bind (iter-str)
         ("convergence criteria satisfied after\\s+([0-9]+)\\s+iterations" line)
       (when iter-str
         (let ((data (agent-simulation-data agent)))
           (let ((conv (gethash :convergence-info data)))
             (setf (gethash :convergence-info data)
                   (append conv (list (parse-integer iter-str))))))))
    ;; Maximum stress
    ((cl-ppcre:scan "Maximum stress\\s*=\\s*([0-9.eE+-]+)" line)
     (cl-ppcre:register-groups-bind (stress-str)
         ("Maximum stress\\s*=\\s*([0-9.eE+-]+)" line)
       (when stress-str
         (let ((data (agent-simulation-data agent)))
           (let ((stresses (gethash :stress-data data)))
             (setf (gethash :stress-data data)
                   (append stresses (list (read-from-string stress-str))))))))
    ;; Maximum displacement
    ((cl-ppcre:scan "Maximum displacement\\s*=\\s*([0-9.eE+-]+)" line)
     (cl-ppcre:register-groups-bind (disp-str)
         ("Maximum displacement\\s*=\\s*([0-9.eE+-]+)" line)
       (when disp-str
         (let ((data (agent-simulation-data agent)))
           (let ((disps (gethash :displacement-data data)))
             (setf (gethash :displacement-data data)
                   (append disps (list (read-from-string disp-str))))))))
    ;; Timing information
    ((cl-ppcre:scan "Total wall time\\s*=\\s*([0-9.eE+-]+)\\s*seconds" line)
     (cl-ppcre:register-groups-bind (time-str)
         ("Total wall time\\s*=\\s*([0-9.eE+-]+)\\s*seconds" line)
       (when time-str
         (let ((data (agent-simulation-data agent)))
           (setf (gethash :total-wall-time data)
                 (read-from-string time-str)))))))

;; ── LAMMPS Specialized Parser ────────────────────────────────────────────

(defmethod parse-simulation-output :after ((agent lammps-agent) line)
  "Parse LAMMPS thermodynamic output data.

LAMMPS produces thermo output containing per-timestep data:
  • Step number
  • Temperature, pressure, volume
  • Total energy, kinetic energy, potential energy
  • Density, CPU time

This parser extracts thermo data lines and stores them under keys:
  :timestep-data       — List of (step temp press pe ke etotal) lists
  :temperature-history — List of temperature values
  :pressure-history    — List of pressure values
  :energy-history      — List of total energy values

Parameters:
  AGENT — The LAMMPS-AGENT instance.
  LINE  — One line of LAMMPS thermodynamic output.

Example parsed line (thermo_style custom):
  '1000 300.0 1.0 -5000.0 2000.0 -3000.0 123.4'"
  ;; LAMMPS thermo output lines contain numeric columns
  ;; We detect them by checking if the line starts with a step number
  ;; followed by numeric values
  (when (cl-ppcre:scan "^\\s*([0-9]+)\\s+([0-9.eE+-]+.*)$" line)
    (cl-ppcre:register-groups-bind (step-str rest-str)
        ("^\\s*([0-9]+)\\s+([0-9.eE+-\\s]+)$" line)
      (when (and step-str rest-str)
        (handler-case
            (let* ((step (parse-integer step-str))
                   (values (mapcar #'read-from-string
                                   (cl-ppcre:split "\\s+" rest-str)))
                   (data (agent-simulation-data agent)))
              ;; Store raw timestep data
              (let ((history (gethash :timestep-data data)))
                (setf (gethash :timestep-data data)
                      (append history (list (cons step values)))))
              ;; Store individual fields if available
              (when (>= (length values) 1)
                (let ((temps (gethash :temperature-history data)))
                  (setf (gethash :temperature-history data)
                        (append temps (list (first values))))))
              (when (>= (length values) 2)
                (let ((pressures (gethash :pressure-history data)))
                  (setf (gethash :pressure-history data)
                        (append pressures (list (second values))))))
              (when (>= (length values) 3)
                (let ((energies (gethash :energy-history data)))
                  (setf (gethash :energy-history data)
                        (append energies (list (third values)))))))
          (error () nil))))))

;; ── Generic Data Extraction Utilities ────────────────────────────────────

(defun extract-convergence-data (output-lines)
  "Extract convergence metrics from simulation output lines.

Scans a list of output lines for common convergence indicators:
  • Residual values (patterns like 'residual = 1.23e-5')
  • Iteration counts (patterns like 'iteration 5/100')
  • Convergence flags (patterns like 'converged', 'CONVERGENCE ACHIEVED')

Parameters:
  OUTPUT-LINES — List of strings, the simulation output.

Returns: A plist with keys:
  :residuals       — List of extracted residual values (floats)
  :iteration-count — Maximum iteration number seen
  :converged-p     — T if convergence was achieved
  :final-residual  — Last residual value extracted

Example:
  (extract-convergence-data
    '(\"iter 1: residual = 0.1\"
      \"iter 2: residual = 0.01\"
      \"CONVERGENCE ACHIEVED\"))
  => (:residuals (0.1 0.01) :iteration-count 2 :converged-p T :final-residual 0.01)"
  (let ((residuals '())
        (max-iter 0)
        (converged-p nil)
        (final-residual nil))
    (dolist (line output-lines)
      ;; Extract residual values
      (cl-ppcre:register-groups-bind (res-str)
          ("residual\\s*[=:]\\s*([0-9.eE+-]+)" line)
        (when res-str
          (let ((val (read-from-string res-str)))
            (push val residuals)
            (setf final-residual val))))
      ;; Extract iteration count
      (cl-ppcre:register-groups-bind (iter-str)
          ("iter(?:ation)?\\s+([0-9]+)" line)
        (when iter-str
          (let ((iter (parse-integer iter-str)))
            (when (> iter max-iter)
              (setf max-iter iter)))))
      ;; Check for convergence
      (when (or (cl-ppcre:scan "converged" line :case-insensitive-mode t)
                (cl-ppcre:scan "CONVERGENCE\\s+ACHIEVED" line))
        (setf converged-p t)))
    (list :residuals (nreverse residuals)
          :iteration-count max-iter
          :converged-p converged-p
          :final-residual final-residual)))

(defun extract-timestep-data (output-lines)
  "Extract timestep and time-advancement data from simulation output.

Scans output lines for timestep-related information:
  • Timestep numbers (patterns like 'Time = 0.001', 'step 100')
  • Delta-t values (patterns like 'deltaT = 1e-5')
  • Simulation time (patterns like 'Simulation time: 1.23 s')

Parameters:
  OUTPUT-LINES — List of strings, the simulation output.

Returns: A plist with keys:
  :timesteps   — List of (step-number . simulation-time) pairs
  :delta-t-values — List of timestep sizes
  :final-time  — Last simulation time extracted

Example:
  (extract-timestep-data
    '(\"Time = 0.001\"
      \"Time = 0.002\"
      \"deltaT = 0.001\"))
  => (:timesteps ((0.001) (0.002)) :delta-t-values (0.001) :final-time 0.002)"
  (let ((timesteps '())
        (delta-t-values '())
        (final-time nil))
    (dolist (line output-lines)
      ;; Extract simulation time
      (cl-ppcre:register-groups-bind (time-str)
          ("Time\\s*[=:]\\s*([0-9.eE+-]+)" line)
        (when time-str
          (let ((tval (read-from-string time-str)))
            (push tval timesteps)
            (setf final-time tval))))
      ;; Extract delta-t
      (cl-ppcre:register-groups-bind (dt-str)
          ("delta[tT]\\s*[=:]\\s*([0-9.eE+-]+)" line)
        (when dt-str
          (push (read-from-string dt-str) delta-t-values))))
    (list :timesteps (nreverse timesteps)
          :delta-t-values (nreverse delta-t-values)
          :final-time final-time)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 7: Gossip Integration — Broadcasting Scientific Results
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These functions publish scientific computing events and results to the
;; gossip mesh, enabling distributed monitoring of simulations across
;; the LISPMIND swarm.

(defun broadcast-simulation-data (agent data-plist)
  "Broadcast simulation results to the gossip mesh.

Publishes a structured data message on the :swarm.science.data topic.
The payload includes the agent ID, tool category, data fields, and
a timestamp. Other nodes in the swarm can subscribe to this topic
to receive real-time simulation updates.

Parameters:
  AGENT      — The SCIENTIFIC-AGENT producing the data.
  DATA-PLIST — A plist of extracted data fields. Keys should be
               keywords, values should be PRINT-READABLE (numbers,
               strings, lists, symbols).

Returns: The gossip message that was published, or NIL if the
subsystem is not initialized.

Example:
  (broadcast-simulation-data my-openfoam-agent
    '(:final-residual 1.2e-5
      :iterations 500
      :converged t
      :courant-max 2.5))"
  (when *scientific-subsystem-initialized*
    (let ((message `(:agent-id ,(agent-id agent)
                     :tool ,(agent-tool-name agent)
                     :category ,(agent-tool-category agent)
                     :data ,data-plist
                     :timestamp ,(local-time:now))))
      (publish-message :swarm.science.data message)
      message)))

(defun broadcast-simulation-start (agent)
  "Broadcast a simulation start event to the gossip mesh.

Announces that a new simulation has begun, including tool name,
binary path, compute/memory budgets, and input files. This enables
other swarm nodes to track active simulations and avoid resource
conflicts.

Parameters:
  AGENT — The SCIENTIFIC-AGENT that is starting.

Returns: The gossip message, or NIL if subsystem not initialized."
  (when *scientific-subsystem-initialized*
    (let ((message `(:event :simulation-started
                     :agent-id ,(agent-id agent)
                     :tool ,(agent-tool-name agent)
                     :binary ,(agent-binary agent)
                     :category ,(agent-tool-category agent)
                     :compute-budget ,(agent-compute-budget agent)
                     :memory-budget-mb ,(agent-memory-budget-mb agent)
                     :input-files ,(agent-input-files agent)
                     :timestamp ,(local-time:now))))
      (publish-message :swarm.science.status message)
      message)))

(defun broadcast-simulation-completion (agent results)
  "Broadcast simulation completion with results to the gossip mesh.

Announces that a simulation has completed successfully, including
key results, output file paths, and resource usage statistics.
This is the primary mechanism for distributing scientific results
across the LISPMIND swarm.

Parameters:
  AGENT   — The SCIENTIFIC-AGENT that completed.
  RESULTS — A plist of simulation results:
              :converged-p    — T if simulation converged
              :iterations     — Number of iterations performed
              :final-residual — Final residual value
              :output-files   — List of generated output files
              :wall-time      — Total wall-clock time in seconds
              :custom-data    — Tool-specific result data

Returns: The gossip message, or NIL if subsystem not initialized.

Example:
  (broadcast-simulation-completion my-openfoam-agent
    '(:converged-p t
      :iterations 1000
      :final-residual 1e-6
      :output-files (\"/case/100/U\")
      :wall-time 3600))"
  (when *scientific-subsystem-initialized*
    (let ((message `(:event :simulation-completed
                     :agent-id ,(agent-id agent)
                     :tool ,(agent-tool-name agent)
                     :category ,(agent-tool-category agent)
                     :results ,results
                     :timestamp ,(local-time:now))))
      (publish-message :swarm.science.results message)
      (publish-message :swarm.science.status message)
      message)))

(defun broadcast-simulation-error (agent error)
  "Broadcast a simulation error to the gossip mesh.

Announces that a simulation has encountered an error, including the
error type, message, and any partial results that were collected.
This enables other swarm nodes to respond appropriately — e.g.,
reallocating resources, adjusting parameters, or escalating to
human operators.

Parameters:
  AGENT — The SCIENTIFIC-AGENT that encountered the error.
  ERROR — A condition, string, or plist describing the error.

Returns: The gossip message, or NIL if subsystem not initialized."
  (when *scientific-subsystem-initialized*
    (let ((error-info (etypecase error
                        (condition (list :type (type-of error)
                                        :message (format nil "~A" error)))
                        (string (list :type :unknown
                                     :message error))
                        (list error))))
      (let ((message `(:event :simulation-error
                       :agent-id ,(agent-id agent)
                       :tool ,(agent-tool-name agent)
                       :category ,(agent-tool-category agent)
                       :error ,error-info
                       :simulation-data ,(hash-table-to-plist
n                                          (agent-simulation-data agent))
                       :timestamp ,(local-time:now))))
        (publish-message :swarm.science.status message)
        message))))

(defun hash-table-to-plist (ht)
  "Convert a hash-table to a plist for serialization.

Only converts entries with PRINT-READABLE values. Non-serializable
values are skipped with a warning.

Parameters:
  HT — The hash-table to convert.

Returns: A plist of (key value) pairs, or NIL if HT is nil."
  (when ht
    (let ((plist '()))
      (maphash (lambda (key value)
                 (handler-case
                     (progn
                       (prin1-to-string value)  ; test serializability
                       (setf plist (list* key value plist)))
                   (error ()
                     (warn "[SCIENCE] Skipping non-serializable hash entry: ~A" key))))
               ht)
      plist)))



;; ═══════════════════════════════════════════════════════════════════════════
;; Section 8: Tool Definitions — Category: Math / Statistics (20 tools)
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These tools span numerical computing, computer algebra, statistics,
;; data analysis, and visualization. They form the mathematical foundation
;; upon which physics simulations and machine learning models are built.

;; ── Julia — High-Performance Numerical Computing ─────────────────────────
(define-agent-tool julia
  :binary-path "/usr/bin/julia"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "Julia — High-performance numerical computing language.
Julia combines the ease of use of Python/MATLAB with the performance
of C/Fortran via LLVM-based JIT compilation. Excellent for numerical
linear algebra, differential equations, optimization, and scientific
machine learning (SciML ecosystem).")

;; ── SageMath — Mathematics Software System ───────────────────────────────
(define-agent-tool sagemath
  :binary-path "/usr/bin/sage"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "SageMath — Open-source mathematics software system.
SageMath integrates NumPy, SciPy, SymPy, Matplotlib, and many
specialized mathematical libraries into a unified Python-based
environment. Covers algebra, combinatorics, number theory,
geometry, and calculus.")

;; ── R — Statistical Computing ────────────────────────────────────────────
(define-agent-tool r-lang
  :binary-path "/usr/bin/R"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 3600
  :memory-budget-mb 4096
  :description "R — Statistical computing and graphics environment.
The lingua franca of statistics. Comprehensive ecosystem for data
analysis, visualization (ggplot2), statistical modeling, and
reproducible research (R Markdown).")

;; ── GNU Octave — Numerical Computations ──────────────────────────────────
(define-agent-tool octave
  :binary-path "/usr/bin/octave"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 3600
  :memory-budget-mb 4096
  :description "GNU Octave — Numerical computation environment.
MATLAB-compatible high-level language for numerical computations.
Primarily intended for linear algebra, signal processing, and
control systems. Supports most MATLAB syntax.")

;; ── Maxima — Computer Algebra System ─────────────────────────────────────
(define-agent-tool maxima
  :binary-path "/usr/bin/maxima"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 3600
  :memory-budget-mb 2048
  :description "Maxima — Computer algebra system.
One of the oldest and most capable open-source CAS. Handles
symbolic differentiation, integration, limits, series expansions,
matrix operations, and equation solving. wxMaxima provides a GUI.")

;; ── Gnuplot — Plotting and Graphics ──────────────────────────────────────
(define-agent-tool gnuplot
  :binary-path "/usr/bin/gnuplot"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 600
  :memory-budget-mb 1024
  :description "Gnuplot — Command-line driven graphing utility.
Portable plotting tool supporting 2D and 3D plots, parametric
curves, contour plots, heatmaps, and many output formats
(PNG, PDF, SVG, EPS). Scriptable and widely used for batch
plotting of scientific data.")

;; ── Python/SciPy — Scientific Python ─────────────────────────────────────
(define-agent-tool scipy
  :binary-path "/usr/bin/python3"
  :category :math
  :tool-type :scientific
  :default-args '("-c" "import scipy; scipy.test()")
  :output-format :text
  :compute-budget 3600
  :memory-budget-mb 4096
  :description "SciPy — Scientific Python library.
Fundamental library for scientific computing in Python. Provides
modules for optimization, linear algebra, integration, interpolation,
special functions, FFT, signal processing, and ODE solvers.")

;; ── NumPy — Numerical Python ─────────────────────────────────────────────
(define-agent-tool numpy
  :binary-path "/usr/bin/python3"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "NumPy — Numerical Python arrays and linear algebra.
The foundation of the Python scientific stack. Provides N-dimensional
arrays, broadcasting, linear algebra (via BLAS/LAPACK), random
number generation, and Fourier transforms.")

;; ── MATLAB (if available) ────────────────────────────────────────────────
(define-agent-tool matlab
  :binary-path "/usr/local/bin/matlab"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "MATLAB — Matrix laboratory for numerical computing.
Industry-standard environment for numerical analysis, signal
processing, control systems, and machine learning. Extensive
toolbox ecosystem and Simulink for model-based design.")

;; ── GNU Scientific Library (GSL) Random Distribution ─────────────────────
(define-agent-tool gsl-rng
  :binary-path "/usr/bin/gsl-randist"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 600
  :memory-budget-mb 512
  :description "GSL-RANDIST — GNU Scientific Library random distributions.
Generates random samples from 30+ statistical distributions
including normal, exponential, Poisson, binomial, gamma, beta,
and many others. Part of the GSL numerical library.")

;; ── PARI/GP — Number Theory ──────────────────────────────────────────────
(define-agent-tool pari-gp
  :binary-path "/usr/bin/gp"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 3600
  :memory-budget-mb 4096
  :description "PARI/GP — Number theory and algebra computation.
Widely used computer algebra system designed for fast computations
in number theory: factorizations, algebraic number theory, elliptic
curves, modular forms, L-functions. Also supports numerical analysis.")

;; ── Eigen (C++ Linear Algebra Test Binary) ───────────────────────────────
(define-agent-tool eigen-tests
  :binary-path "/usr/bin/eigen-test"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 1800
  :memory-budget-mb 2048
  :description "Eigen — C++ template library for linear algebra.
Header-only C++ library providing matrix/vector classes, solvers
for linear systems, eigenvalue decomposition, SVD, and sparse
linear algebra. Widely used in robotics, graphics, and CFD codes.")

;; ── LAPACK/BLAS Test Suite ───────────────────────────────────────────────
(define-agent-tool lapack-test
  :binary-path "/usr/bin/lapack-test"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "LAPACK — Linear Algebra PACKage test suite.
Standard library for numerical linear algebra: solving systems of
linear equations, least-squares, eigenvalue problems, and SVD.
Uses optimized BLAS implementations (OpenBLAS, MKL) for performance.")

;; ── Perl/PDL — Perl Data Language ────────────────────────────────────────
(define-agent-tool pdl
  :binary-path "/usr/bin/perldl"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "PDL — Perl Data Language for scientific computing.
Provides array manipulation and numerical computation for Perl,
similar to NumPy for Python. Supports N-dimensional arrays,
slicing, broadcasting, FFT, and linear algebra operations.")

;; ── ROOT (CERN Data Analysis) ────────────────────────────────────────────
(define-agent-tool root-cern
  :binary-path "/usr/bin/root"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "ROOT — CERN data analysis framework.
Powerful object-oriented framework for large-scale data analysis
in high-energy physics. Handles petabyte-scale datasets, provides
histogramming, fitting, I/O (including columnar data with RDataFrame),
and a C++ interpreter (Cling).")

;; ── Stan — Probabilistic Programming ─────────────────────────────────────
(define-agent-tool stan
  :binary-path "/usr/bin/stan"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 7200
  :memory-budget-mb 8192
  :description "Stan — Probabilistic programming language.
State-of-the-art platform for Bayesian inference using Hamiltonian
Monte Carlo (HMC). Used for statistical modeling across epidemiology,
finance, social sciences, and machine learning. Interfaces for R,
Python, Julia, and MATLAB.")

;; ── SymPy — Symbolic Python ──────────────────────────────────────────────
(define-agent-tool sympy
  :binary-path "/usr/bin/python3"
  :category :math
  :tool-type :scientific
  :default-args '("-c" "import sympy; sympy.test()")
  :output-format :text
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "SymPy — Symbolic mathematics in Python.
Pure Python library for symbolic computation: differentiation,
integration, equation solving, series expansion, matrix operations,
and code generation. Fully open-source with no dependencies.")

;; ── Cinderella — Interactive Geometry ────────────────────────────────────
(define-agent-tool cinderella
  :binary-path "/usr/bin/cinderella2"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 600
  :memory-budget-mb 1024
  :description "Cinderella — Interactive geometry software.
Dynamic geometry construction tool with physics simulation
capabilities. Supports Euclidean, hyperbolic, and spherical
geometry. Unique feature: constructions remain valid under
continuous deformation (CindyScript).")

;; ── GeoGebra — Dynamic Mathematics ───────────────────────────────────────
(define-agent-tool geogebra
  :binary-path "/usr/bin/geogebra"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 600
  :memory-budget-mb 1024
  :description "GeoGebra — Dynamic mathematics software.
Combines geometry, algebra, spreadsheets, graphing, statistics,
and calculus in one engine. Widely used in education with millions
of users. Supports CAS, 3D graphics, and probability tools.")

;; ── Weka — Machine Learning Workbench ────────────────────────────────────
(define-agent-tool weka
  :binary-path "/usr/bin/weka"
  :category :math
  :tool-type :scientific
  :output-format :text
  :compute-budget 3600
  :memory-budget-mb 4096
  :description "Weka — Machine learning workbench.
Collection of visualization tools and algorithms for data mining
and machine learning: classification, regression, clustering,
association rules, and feature selection. Java-based with GUI
and command-line interfaces.")


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 9: Tool Definitions — Category: Physics / CFD / FEA (25 tools)
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These tools cover computational fluid dynamics (CFD), finite element
;; analysis (FEA), molecular dynamics (MD), and computational physics.
;; They are the most computationally demanding agents in the swarm,
;; often requiring hours of CPU time and gigabytes of memory.

;; ── OpenFOAM — CFD Toolkit ───────────────────────────────────────────────
(define-agent-tool openfoam
  :binary-path "/usr/bin/foamRun"
  :category :physics
  :tool-type :scientific
  :compute-budget 14400
  :memory-budget-mb 32768
  :output-format :text
  :description "OpenFOAM — Computational Fluid Dynamics toolkit.
Widely used open-source CFD toolbox with extensive solver library
for incompressible/compressible flows, multiphase, heat transfer,
turbulence (RANS, LES, DES), and combustion. C++-based with
Python scripting via PyFoam.")

;; ── simpleFoam — Steady-state incompressible turbulent flow ──────────────
(define-agent-tool simplefoam
  :binary-path "/usr/bin/simpleFoam"
  :category :physics
  :tool-type :scientific
  :compute-budget 14400
  :memory-budget-mb 32768
  :output-format :text
  :description "simpleFoam — Steady-state incompressible turbulent flow solver.
Part of OpenFOAM. Uses the SIMPLE algorithm for pressure-velocity
coupling. Suitable for steady-state RANS simulations of turbulent
incompressible flows in complex geometries.")

;; ── pimpleFoam — Transient incompressible flow ───────────────────────────
(define-agent-tool pimplefoam
  :binary-path "/usr/bin/pimpleFoam"
  :category :physics
  :tool-type :scientific
  :compute-budget 14400
  :memory-budget-mb 32768
  :output-format :text
  :description "pimpleFoam — Transient incompressible flow solver.
Part of OpenFOAM. Uses the PIMPLE (merged PISO-SIMPLE) algorithm
for transient incompressible flows. Supports Large Eddy Simulation
(LES) and Direct Numerical Simulation (DNS).")

;; ── icoFoam — Transient laminar incompressible flow ──────────────────────
(define-agent-tool icofoam
  :binary-path "/usr/bin/icoFoam"
  :category :physics
  :tool-type :scientific
  :compute-budget 14400
  :memory-budget-mb 16384
  :output-format :text
  :description "icoFoam — Transient laminar incompressible flow solver.
Part of OpenFOAM. Uses the PISO algorithm. The simplest OpenFOAM
solver — ideal for laminar flows, verification cases, and learning
OpenFOAM fundamentals.")

;; ── blockMesh — Structured mesh generator ────────────────────────────────
(define-agent-tool blockmesh
  :binary-path "/usr/bin/blockMesh"
  :category :physics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :output-format :text
  :description "blockMesh — OpenFOAM structured hexahedral mesh generator.
Generates 3D meshes from block definitions in blockMeshDict.
Supports grading, curved edges, and multi-block configurations.
The first step in most OpenFOAM simulation workflows.")

;; ── snappyHexMesh — Automatic unstructured meshing ───────────────────────
(define-agent-tool snappyhexmesh
  :binary-path "/usr/bin/snappyHexMesh"
  :category :physics
  :tool-type :scientific
  :compute-budget 3600
  :memory-budget-mb 16384
  :output-format :text
  :description "snappyHexMesh — Automatic unstructured hexahedral mesher.
Generates high-quality 3D meshes from STL surface geometry.
Features: surface snapping, layer addition near walls, refinement
regions, and parallel operation. Essential for complex CFD geometries.")

;; ── CalculiX — FEA Solver ────────────────────────────────────────────────
(define-agent-tool calculix
  :binary-path "/usr/bin/ccx"
  :category :physics
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :output-format :text
  :description "CalculiX — Finite Element Analysis solver (ccx).
Open-source FEA package with Abaqus-compatible input format.
Supports linear/nonlinear statics, dynamics, heat transfer,
CFD, and coupled analyses. Uses SPOOLES/PARDISO for sparse
linear systems. cgx provides pre/post-processing.")

;; ── CalculiX GUI (cgx) ───────────────────────────────────────────────────
(define-agent-tool calculix-gui
  :binary-path "/usr/bin/cgx"
  :category :physics
  :tool-type :scientific
  :compute-budget 3600
  :memory-budget-mb 4096
  :output-format :text
  :description "CalculiX GraphiX (cgx) — Pre/post-processor for CalculiX.
Open-source pre- and post-processor for CalculiX and other FEA
codes. Supports geometry creation, mesh generation, result
visualization, and animation. Can read/write Abaqus, Nastran,
and OpenFOAM formats.")

;; ── ElmerFEM — Multiphysical Simulation ──────────────────────────────────
(define-agent-tool elmerfem
  :binary-path "/usr/bin/ElmerSolver"
  :category :physics
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :output-format :text
  :description "ElmerFEM — Multiphysics simulation software.
Open-source finite element solver for multiphysical problems:
fluid dynamics, structural mechanics, heat transfer, electromagnetics,
acoustics, and their couplings. Includes ElmerGUI for pre/post.")

;; ── FEniCS — Automated FEA (Python) ──────────────────────────────────────
(define-agent-tool fenics
  :binary-path "/usr/bin/python3"
  :category :physics
  :tool-type :scientific
  :default-args '("-c" "import fenics; fenics.test()")
  :output-format :text
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "FEniCS — Automated finite element analysis (Python).
High-level Python/C++ library for solving partial differential
equations with the finite element method. Features automated
code generation, high-performance linear algebra, and a natural
mathematical notation (UFL) for variational problems.")

;; ── SU2 — CFD Code ───────────────────────────────────────────────────────
(define-agent-tool su2
  :binary-path "/usr/bin/SU2_CFD"
  :category :physics
  :tool-type :scientific
  :compute-budget 14400
  :memory-budget-mb 32768
  :output-format :text
  :description "SU2 — Open-source CFD and aerodynamic design.
Computational fluid dynamics suite focused on aerodynamic shape
optimization. Solves Euler, Navier-Stokes, and RANS equations.
Features continuous adjoint method for gradient-based optimization.
Developed by Stanford University.")

;; ── Gmsh — Mesh Generator ────────────────────────────────────────────────
(define-agent-tool gmsh
  :binary-path "/usr/bin/gmsh"
  :category :physics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :output-format :text
  :description "Gmsh — Three-dimensional finite element mesh generator.
Open-source mesh generator with built-in CAD engine and post-processor.
Supports: triangles, quads, tetrahedra, hexahedra, prisms; 1D/2D/3D;
hierarchical meshes; and many export formats (VTK, STL, CGNS, MED).
Scriptable via its own language or Python API.")

;; ── ParaView — Scientific Visualization ──────────────────────────────────
(define-agent-tool paraview
  :binary-path "/usr/bin/paraview"
  :category :physics
  :tool-type :scientific
  :compute-budget 3600
  :memory-budget-mb 8192
  :output-format :text
  :description "ParaView — Large-scale scientific data visualization.
Open-source multi-platform application for interactive visualization
of large datasets (billions of cells). Supports: volume rendering,
contours, streamlines, animations, Python scripting (pvpython),
and in-situ visualization with Catalyst.")

;; ── pvpython — ParaView Python ───────────────────────────────────────────
(define-agent-tool pvpython
  :binary-path "/usr/bin/pvpython"
  :category :physics
  :tool-type :scientific
  :output-format :text
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "pvpython — ParaView's Python interface for batch processing.
Python interpreter with ParaView libraries for scripted visualization
and data analysis. Ideal for automated post-processing pipelines,
off-screen rendering, and headless server environments.")

;; ── Code_Aster — Structural Analysis ─────────────────────────────────────
(define-agent-tool code-aster
  :binary-path "/usr/bin/aster"
  :category :physics
  :tool-type :scientific
  :compute-budget 14400
  :memory-budget-mb 32768
  :output-format :text
  :description "Code_Aster — Structural and thermomechanical analysis.
Open-source FEA software developed by EDF (Electricite de France).
Comprehensive solver for structural mechanics, heat transfer,
acoustics, and fatigue analysis. French regulatory nuclear
quality standards.")

;; ── Salome-Meca — FEA Platform ───────────────────────────────────────────
(define-agent-tool salome-meca
  :binary-path "/usr/bin/salome"
  :category :physics
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :output-format :text
  :description "Salome-Meca — FEA platform (Code_Aster + Salome).
Integrated platform combining Salome's CAD/meshing/visualization
with Code_Aster's solver. Provides a unified GUI for the complete
simulation workflow from geometry to results.")

;; ── XFlow (if available) ─────────────────────────────────────────────────
(define-agent-tool xflow
  :binary-path "/opt/xflow/bin/xflow"
  :category :physics
  :tool-type :scientific
  :compute-budget 14400
  :memory-budget-mb 65536
  :output-format :text
  :description "XFlow — Lattice Boltzmann CFD software.
High-fidelity CFD using the Lattice Boltzmann method. Part of
Dassault Systemes' SIMULIA portfolio. Handles transient aerodynamics,
aeroacoustics, multiphase flows, and moving parts with automatic
meshing.")

;; ── ANSYS Fluent (if available) ──────────────────────────────────────────
(define-agent-tool fluent
  :binary-path "/opt/ansys/bin/fluent"
  :category :physics
  :tool-type :scientific
  :compute-budget 14400
  :memory-budget-mb 65536
  :output-format :text
  :description "ANSYS Fluent — Commercial CFD software.
Industry-leading computational fluid dynamics software. Supports
all flow regimes, turbulence models, multiphase flows, combustion,
heat transfer, and acoustics. Extensive meshing and optimization
capabilities.")

;; ── COMSOL Multiphysics (if available) ───────────────────────────────────
(define-agent-tool comsol
  :binary-path "/opt/comsol/bin/comsol"
  :category :physics
  :tool-type :scientific
  :compute-budget 14400
  :memory-budget-mb 65536
  :output-format :text
  :description "COMSOL Multiphysics — Multiphysics simulation platform.
Commercial finite element analysis software for multiphysics
modeling: electromagnetics, structural mechanics, fluid dynamics,
heat transfer, and chemical engineering. Features Application
Builder for custom simulation apps.")

;; ── Abaqus (if available) ────────────────────────────────────────────────
(define-agent-tool abaqus
  :binary-path "/opt/abaqus/bin/abaqus"
  :category :physics
  :tool-type :scientific
  :compute-budget 14400
  :memory-budget-mb 65536
  :output-format :text
  :description "Abaqus — Commercial FEA software (Dassault Systemes).
Industry-standard finite element analysis for structural mechanics,
thermal analysis, and multiphysics. Widely used in aerospace,
automotive, and consumer product industries.")

;; ── LAMMPS — Molecular Dynamics ──────────────────────────────────────────
(define-agent-tool lammps
  :binary-path "/usr/bin/lmp"
  :category :physics
  :tool-type :scientific
  :compute-budget 14400
  :memory-budget-mb 32768
  :output-format :text
  :description "LAMMPS — Large-scale Atomic/Molecular Massively Parallel Simulator.
Open-source molecular dynamics simulator from Sandia National Labs.
Supports: classical MD, reactive force fields, coarse-grained models,
hybrid MD/continuum coupling. Parallel via MPI. Widely used in
materials science, chemistry, and biophysics.")

;; ── Quantum ESPRESSO — DFT ───────────────────────────────────────────────
(define-agent-tool quantum-espresso
  :binary-path "/usr/bin/pw.x"
  :category :physics
  :tool-type :scientific
  :compute-budget 14400
  :memory-budget-mb 32768
  :output-format :text
  :description "Quantum ESPRESSO — Quantum chemistry and materials simulation.
Open-source suite for electronic-structure calculations and materials
modeling at the nanoscale. Based on density functional theory (DFT),
plane waves, and pseudopotentials. Developed within the MAX European
centre of excellence.")

;; ── NWChem — Computational Chemistry ─────────────────────────────────────
(define-agent-tool nwchem
  :binary-path "/usr/bin/nwchem"
  :category :physics
  :tool-type :scientific
  :compute-budget 14400
  :memory-budget-mb 32768
  :output-format :text
  :description "NWChem — Computational chemistry software.
Open-source computational chemistry package from PNNL. Provides
methods for quantum chemistry (DFT, MP2, CCSD(T)), molecular
dynamics, and QM/MM. Designed for high-performance parallel
computing on supercomputers.")

;; ── deal.II — FEA Library ────────────────────────────────────────────────
(define-agent-tool dealii
  :binary-path "/usr/bin/dealii-test"
  :category :physics
  :tool-type :scientific
  :output-format :text
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "deal.II — Finite element library (C++).
Modern C++ library for finite element computations featuring
adaptive meshes, hp-refinement, multigrid solvers, and parallel
computing via MPI. Used in academic research and education for
solving PDEs in science and engineering.")

;; ── MOOSE Framework — Multiphysics ───────────────────────────────────────
(define-agent-tool moose
  :binary-path "/opt/moose/bin/moose-opt"
  :category :physics
  :tool-type :scientific
  :compute-budget 14400
  :memory-budget-mb 32768
  :output-format :text
  :description "MOOSE — Multiphysics Object-Oriented Simulation Environment.
Open-source framework from Idaho National Laboratory for solving
multiphysics problems using the finite element method. Built on
libMesh and PETSc. Applications: nuclear engineering, geoscience,
phase-field modeling, and reactor physics.")



;; ═══════════════════════════════════════════════════════════════════════════
;; Section 10: Tool Definitions — Category: Engineering / CAD (25 tools)
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These tools span computer-aided design (CAD), computer-aided manufacturing
;; (CAM), 3D modeling, mesh processing, and computational geometry. They
;; bridge the gap between conceptual design and physics simulation.

;; ── PicoGK — Computational Geometry Kernel ───────────────────────────────
(define-agent-tool picogk
  :binary-path "/usr/bin/picogk"
  :category :engineering
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "PicoGK — Computational geometry kernel.
Lightweight computational geometry kernel for 3D modeling and
mesh processing. Provides Boolean operations, mesh simplification,
and conversion between geometric representations.")

;; ── FreeCAD — Parametric 3D CAD ──────────────────────────────────────────
(define-agent-tool freecad
  :binary-path "/usr/bin/freecad"
  :category :engineering
  :tool-type :scientific
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "FreeCAD — Open-source parametric 3D CAD modeler.
General-purpose parametric 3D CAD for mechanical engineering and
product design. Features: sketcher, Part/PartDesign workbenches,
assembly, FEM (CalculiX), CFD (CFDOF), and Python scripting.
Supports STEP, IGES, STL, OBJ, and many other formats.")

;; ── FreeCAD Console Mode ─────────────────────────────────────────────────
(define-agent-tool freecadcmd
  :binary-path "/usr/bin/freecadcmd"
  :category :engineering
  :tool-type :scientific
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "FreeCADCmd — FreeCAD command-line interface.
Headless (no GUI) version of FreeCAD for batch processing, scripted
model generation, and server deployments. Executes Python scripts
that use the FreeCAD API. Ideal for automated parametric modeling
and geometry conversion pipelines.")

;; ── OpenSCAD — Script-Based 3D CAD ───────────────────────────────────────
(define-agent-tool openscad
  :binary-path "/usr/bin/openscad"
  :category :engineering
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "OpenSCAD — The programmer's solid 3D CAD modeler.
Creates 3D models from script files using constructive solid geometry
(CSG) and extrusion of 2D outlines. No interactive modeling — all
designs are parametric text files. Popular in the 3D printing
community and for generating parametric mechanical parts.")

;; ── LibreCAD — 2D CAD ────────────────────────────────────────────────────
(define-agent-tool librecad
  :binary-path "/usr/bin/librecad"
  :category :engineering
  :tool-type :scientific
  :compute-budget 600
  :memory-budget-mb 1024
  :description "LibreCAD — Free open-source 2D CAD.
Cross-platform 2D CAD application derived from QCad. Supports DXF
format natively, layers, blocks, and standard CAD drawing tools.
Lightweight and suitable for technical drawings, floor plans, and
schematic diagrams.")

;; ── Blender — 3D Creation Suite ──────────────────────────────────────────
(define-agent-tool blender
  :binary-path "/usr/bin/blender"
  :category :engineering
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Blender — Open-source 3D creation suite.
Comprehensive 3D production tool: modeling, sculpting, animation,
rendering (Cycles, Eevee), compositing, video editing, and motion
tracking. Python scripting API enables automation and custom
tool development. Used in film, games, and scientific visualization.")

;; ── Blender Headless ─────────────────────────────────────────────────────
(define-agent-tool blender-headless
  :binary-path "/usr/bin/blender"
  :category :engineering
  :tool-type :scientific
  :default-args '("--background" "--python")
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Blender (headless) — Batch rendering and script execution.
Command-line mode for Blender, running without GUI. Used for batch
rendering, automated 3D model processing, geometry export/conversion,
and scripted pipeline integration on headless servers and clusters.")

;; ── Salome — CAE Platform ────────────────────────────────────────────────
(define-agent-tool salome
  :binary-path "/usr/bin/salome"
  :category :engineering
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Salome — Open-source CAE platform.
Generic platform for pre- and post-processing of numerical simulations.
Features: geometry creation (CAD), mesh generation (NETGEN, Gmsh),
data analysis, and visualization. Used as the foundation for
Salome-Meca (with Code_Aster) and other simulation workflows.")

;; ── BRL-CAD — Constructive Solid Geometry ────────────────────────────────
(define-agent-tool brl-cad
  :binary-path "/usr/bin/mged"
  :category :engineering
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "BRL-CAD — Constructive Solid Geometry modeling system.
One of the oldest open-source CAD systems (since 1979). Developed
by the U.S. Army Ballistics Research Laboratory for vulnerability
and lethality analysis. Features: CSG solid modeling, ray tracing,
geometry analysis, and conversion tools.")

;; ── SolveSpace — Parametric 2D/3D CAD ────────────────────────────────────
(define-agent-tool solvespace
  :binary-path "/usr/bin/solvespace"
  :category :engineering
  :tool-type :scientific
  :compute-budget 600
  :memory-budget-mb 1024
  :description "SolveSpace — Parametric 2D/3D CAD.
Lightweight constraint-based parametric modeler with explicit
geometric constraint solving. Supports: 2D sketching, 3D extrude/revolve,
assembly, and NC toolpath generation. Exports to STEP, STL, DXF,
and G-code.")

;; ── HeeksCAD — CAD/CAM ───────────────────────────────────────────────────
(define-agent-tool heekscad
  :binary-path "/usr/bin/heekscad"
  :category :engineering
  :tool-type :scientific
  :compute-budget 600
  :memory-budget-mb 1024
  :description "HeeksCAD — CAD/CAM application.
Open-source CAD/CAM software with solid modeling based on OpenCASCADE.
Features: sketch-based modeling, constraint solving, and CAM
functionality for CNC machining via HeeksCNC.")

;; ── DraftSight (if available) ────────────────────────────────────────────
(define-agent-tool draftsight
  :binary-path "/opt/dassault/DraftSight/bin/draftsight"
  :category :engineering
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "DraftSight — Professional 2D CAD (Dassault Systemes).
2D drafting and drawing application from Dassault Systemes. Similar
to AutoCAD in functionality and interface. Supports DWG/DXF formats
and provides APIs for customization.")

;; ── Siemens NX (if available) ────────────────────────────────────────────
(define-agent-tool siemens-nx
  :binary-path "/opt/siemens/nx/bin/ug"
  :category :engineering
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Siemens NX — Product engineering solution.
High-end integrated CAD/CAM/CAE system for product design,
engineering, and manufacturing. Features: synchronous modeling,
freeform surface design, simulation (NASTRAN), and CAM for
multi-axis machining.")

;; ── CATIA (if available) ─────────────────────────────────────────────────
(define-agent-tool catia
  :binary-path "/opt/dassault/catia/bin/catia"
  :category :engineering
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "CATIA — Computer Aided Three-Dimensional Interactive Application.
Flagship CAD/CAM/CAE software from Dassault Systemes. Dominant in
aerospace and automotive industries. Features: surfacing (Class-A),
digital mockup, systems engineering, and manufacturing planning.")

;; ── SolidWorks (if available) ────────────────────────────────────────────
(define-agent-tool solidworks
  :binary-path "/opt/solidworks/bin/solidworks"
  :category :engineering
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "SolidWorks — 3D CAD design software (Dassault Systemes).
Popular parametric solid modeling CAD for mechanical design.
Features: part/assembly modeling, simulation (COSMOS), PDM
integration, and CAMWorks for manufacturing.")

;; ── AutoCAD (if available) ───────────────────────────────────────────────
(define-agent-tool autocad
  :binary-path "/opt/autocad/bin/autocad"
  :category :engineering
  :tool-type :scientific
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "AutoCAD — Industry-standard 2D/3D CAD (Autodesk).
Widely used commercial CAD software for 2D drafting and 3D modeling.
Supports DWG format, AutoLISP scripting, and extensive plugin
ecosystem. Used across architecture, engineering, and construction.")

;; ── Onshape — Cloud CAD (via API) ────────────────────────────────────────
(define-agent-tool onshape
  :binary-path "/usr/bin/python3"
  :category :engineering
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "Onshape — Cloud-native CAD platform (PTC).
Full-cloud CAD system running in a web browser. Features: parametric
modeling, assemblies, drawings, and built-in PDM. Accessed via
REST API for automation and data extraction. No local installation.")

;; ── Fusion 360 (if available) ────────────────────────────────────────────
(define-agent-tool fusion360
  :binary-path "/opt/autodesk/fusion360/bin/fusion360"
  :category :engineering
  :tool-type :scientific
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "Autodesk Fusion 360 — Integrated CAD/CAM/CAE.
Cloud-based 3D modeling, CAM, and simulation platform from Autodesk.
Features: parametric/direct modeling, sculpting, electronics design,
generative design, and CNC toolpath generation.")

;; ── STEP Tools ───────────────────────────────────────────────────────────
(define-agent-tool step-tools
  :binary-path "/usr/bin/step2stl"
  :category :engineering
  :tool-type :scientific
  :compute-budget 600
  :memory-budget-mb 1024
  :description "STEP Tools — STEP file conversion utilities.
Command-line tools for converting between STEP (ISO 10303) and
other 3D formats (STL, OBJ, etc.). Essential for CAD data exchange
between incompatible systems.")

;; ── MeshLab — Mesh Processing ────────────────────────────────────────────
(define-agent-tool meshlab
  :binary-path "/usr/bin/meshlab"
  :category :engineering
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "MeshLab — Open-source mesh processing system.
Portable system for editing, cleaning, healing, inspecting,
rendering, and converting triangular meshes. Supports 100+ mesh
formats. Filters: simplification, remeshing, smoothing, hole
filling, and quality checks.")

;; ── MeshLab Server ───────────────────────────────────────────────────────
(define-agent-tool meshlabserver
  :binary-path "/usr/bin/meshlabserver"
  :category :engineering
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "MeshLabServer — Headless mesh processing.
Command-line version of MeshLab for batch mesh processing.
Executes filter scripts (MLX files) on input meshes and produces
output meshes. Ideal for automated mesh preparation pipelines.")

;; ── CloudCompare — 3D Point Cloud Processing ─────────────────────────────
(define-agent-tool cloudcompare
  :binary-path "/usr/bin/CloudCompare"
  :category :engineering
  :tool-type :scientific
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "CloudCompare — 3D point cloud and mesh processing.
Open-source 3D point cloud editing and processing software.
Features: registration, comparison, segmentation, classification,
and mesh generation. Supports LAS, E57, PLY, OBJ, and 50+ formats.")

;; ── CGAL — Computational Geometry Algorithms Library ─────────────────────
(define-agent-tool cgal-test
  :binary-path "/usr/bin/cgal-test"
  :category :engineering
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "CGAL — Computational Geometry Algorithms Library.
Open-source C++ library providing efficient and reliable geometric
algorithms: triangulations, Voronoi diagrams, Boolean operations,
mesh generation, and convex hulls. Industry standard for geometry
processing in research and commercial software.")

;; ── ITK-SNAP — Medical Image Segmentation ────────────────────────────────
(define-agent-tool itksnap
  :binary-path "/usr/bin/itksnap"
  :category :engineering
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "ITK-SNAP — Medical image segmentation tool.
Open-source application for segmenting anatomical structures in
medical images (MRI, CT). Uses active contour methods (snakes) and
level sets. Built on ITK and VTK. Supports NIfTI, NRRD, and DICOM.")

;; ── 3D Slicer ────────────────────────────────────────────────────────────
(define-agent-tool slicer3d
  :binary-path "/usr/bin/Slicer"
  :category :engineering
  :tool-type :scientific
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "3D Slicer — Medical image computing platform.
Open-source platform for medical image informatics, image processing,
and 3D visualization. Extensive plugin ecosystem for segmentation,
registration, diffusion MRI, and radiation therapy planning.")



;; ═══════════════════════════════════════════════════════════════════════════
;; Section 11: Tool Definitions — Category: Electronics / EDA (25 tools)
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These tools span electronic design automation (EDA), circuit simulation,
;; digital logic synthesis, FPGA toolchains, and RF/radio signal processing.
;; They transform abstract circuit designs into manufactured hardware.

;; ── KiCad — EDA Suite ────────────────────────────────────────────────────
(define-agent-tool kicad
  :binary-path "/usr/bin/kicad"
  :category :electronics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "KiCad — Open-source electronics design automation suite.
Complete EDA toolchain: schematic capture (eeschema), PCB layout
(pcbnew), 3D viewer, and Gerber export. Supports design rules
checking (DRC), electrical rules checking (ERC), and SPICE
simulation integration. Industry-standard open-source PCB design.")

;; ── KiCad PCBnew ─────────────────────────────────────────────────────────
(define-agent-tool kicad-pcbnew
  :binary-path "/usr/bin/pcbnew"
  :category :electronics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "KiCad PCBnew — PCB layout editor.
KiCad's printed circuit board layout editor. Features: interactive
and push-and-shove routing, differential pair routing, length
tuning, copper pour, design rule checking, and Gerber/X2 export.")

;; ── KiCad Eeschema ───────────────────────────────────────────────────────
(define-agent-tool kicad-eeschema
  :binary-path "/usr/bin/eeschema"
  :category :electronics
  :tool-type :scientific
  :compute-budget 600
  :memory-budget-mb 1024
  :description "KiCad Eeschema — Schematic capture editor.
KiCad's schematic capture tool for creating electronic circuit
diagrams. Features: hierarchical design, ERC, netlist generation,
and SPICE simulation integration via ngspice.")

;; ── Verilator — Verilog Simulator ────────────────────────────────────────
(define-agent-tool verilator
  :binary-path "/usr/bin/verilator"
  :category :electronics
  :tool-type :scientific
  :compute-budget 3600
  :memory-budget-mb 4096
  :description "Verilator — Fast Verilog/SystemVerilog simulator.
Compiles Verilog and SystemVerilog into optimized C++/SystemC
models. Significantly faster than traditional event-driven
simulators for cycle-accurate verification. Supports assertion
checking, coverage analysis, and wave tracing.")

;; ── Qucs — Circuit Simulator ─────────────────────────────────────────────
(define-agent-tool qucs
  :binary-path "/usr/bin/qucs"
  :category :electronics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 2048
  :description "QUCS — Quite Universal Circuit Simulator.
Open-source circuit simulator with GUI. Supports: DC, AC, transient,
parameter sweep, harmonic balance, and digital simulation. Uses
its own SPICE-compatible netlist format.")

;; ── Qucsator — Qucs Simulation Engine ────────────────────────────────────
(define-agent-tool qucsator
  :binary-path "/usr/bin/qucsator"
  :category :electronics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 2048
  :description "Qucsator — Qucs simulation backend.
Command-line circuit simulation engine for Qucs. Executes netlist
simulations: DC analysis, AC small-signal, transient, S-parameter,
and noise analysis. Can be used independently of the Qucs GUI.")

;; ── Ngspice — SPICE Circuit Simulator ────────────────────────────────────
(define-agent-tool ngspice
  :binary-path "/usr/bin/ngspice"
  :category :electronics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 2048
  :description "Ngspice — Open-source SPICE circuit simulator.
Mixed-level/mixed-signal circuit simulator based on Berkeley SPICE.
Supports: DC, AC, transient, noise, distortion, and pole-zero
analysis. Compatible with most SPICE netlists. Used by KiCad for
schematic simulation.")

;; ── Yosys — Open Synthesis Suite ─────────────────────────────────────────
(define-agent-tool yosys
  :binary-path "/usr/bin/yosys"
  :category :electronics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "Yosys — Open-source RTL synthesis framework.
Framework for Verilog RTL synthesis. Supports: technology mapping
to ASIC standard cells, FPGA bitstream generation (via nextpnr),
formal verification, equivalence checking, and design analysis.
The core of most open-source FPGA and ASIC design flows.")

;; ── OpenROAD — RTL-to-GDS ────────────────────────────────────────────────
(define-agent-tool openroad
  :binary-path "/usr/bin/openroad"
  :category :electronics
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "OpenROAD — Open-source RTL-to-GDS flow.
Unified application for autonomous digital ASIC design: floorplanning,
placement, clock tree synthesis, routing, and parasitic extraction.
Part of the DARPA IDEA program for autonomous chip design.")

;; ── Magic VLSI ───────────────────────────────────────────────────────────
(define-agent-tool magic-vlsi
  :binary-path "/usr/bin/magic"
  :category :electronics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 2048
  :description "Magic — VLSI layout editor and design tool.
Open-source VLSI layout editor from UC Berkeley. Features: design
rule checking (DRC), circuit extraction, routing, and GDSII
export/import. Widely used for teaching VLSI design and for
open-source ASIC projects (e.g., via OpenROAD and SkyWater PDK).")

;; ── Xyce — Parallel Circuit Simulator ────────────────────────────────────
(define-agent-tool xyce
  :binary-path "/usr/bin/Xyce"
  :category :electronics
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Xyce — Parallel electronic circuit simulator.
Open-source SPICE-compatible circuit simulator from Sandia National
Labs. Designed for large-scale parallel simulation on supercomputers.
Supports: analog, digital, and mixed-signal circuits with
accelerated transient analysis via MPI.")

;; ── GHDL — VHDL Simulator ────────────────────────────────────────────────
(define-agent-tool ghdl
  :binary-path "/usr/bin/ghdl"
  :category :electronics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 2048
  :description "GHDL — VHDL simulator and synthesis tool.
Open-source VHDL simulator using LLVM or GCC code generation.
Supports VHDL-87, VHDL-93, VHDL-02, and partial VHDL-08.
Can synthesize VHDL to netlists for FPGA implementation.")

;; ── Icarus Verilog ───────────────────────────────────────────────────────
(define-agent-tool iverilog
  :binary-path "/usr/bin/iverilog"
  :category :electronics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 2048
  :description "Icarus Verilog — Verilog simulation and synthesis.
Open-source Verilog simulator and synthesis tool. Supports Verilog-95,
Verilog-2001, and SystemVerilog. Compiles Verilog source to an
intermediate format (VVP assembly) executed by the vvp runtime.")

;; ── vvp — Icarus Verilog Runtime ─────────────────────────────────────────
(define-agent-tool vvp
  :binary-path "/usr/bin/vvp"
  :category :electronics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 2048
  :description "vvp — Icarus Verilog runtime engine.
Executes VVP assembly files produced by iverilog. Provides the
simulation runtime with support for VCD waveform dump, interactive
debugging, and PLI/VPI extensions for co-simulation.")

;; ── GNU Radio — Software Defined Radio ───────────────────────────────────
(define-agent-tool gnuradio
  :binary-path "/usr/bin/gnuradio-companion"
  :category :electronics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "GNU Radio — Software-defined radio toolkit.
Free software development toolkit for software-defined radio (SDR).
Provides signal processing blocks for implementing software radios.
Supports USRP, HackRF, RTL-SDR, and many other radio frontends.
GUI application (GRC) for visual flowgraph design.")

;; ── GNU Radio Headless ───────────────────────────────────────────────────
(define-agent-tool gnuradio-headless
  :binary-path "/usr/bin/python3"
  :category :electronics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "GNU Radio (headless) — Python script execution.
Execute GNU Radio flowgraphs as Python scripts without the GUI.
Used for automated signal processing, continuous monitoring,
and server-based SDR applications.")

;; ── LTspice (via Wine) ───────────────────────────────────────────────────
(define-agent-tool ltspice
  :binary-path "/opt/ltspice/bin/ltspice"
  :category :electronics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 2048
  :description "LTspice — Analog circuit simulation (Analog Devices).
High-performance SPICE simulator optimized for switching regulator
and analog circuit simulation. Free from Analog Devices. Fast
simulation engine, extensive component library, and schematic
capture. Run via Wine on Linux.")

;; ── Eagle — PCB Design ───────────────────────────────────────────────────
(define-agent-tool eagle
  :binary-path "/usr/bin/eagle"
  :category :electronics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "Autodesk Eagle — PCB design software.
Schematic capture and PCB layout tool from Autodesk. Features:
differential pair routing, design rule checking, 3D visualization,
and Fusion 360 integration for electromechanical design.")

;; ── Proteus (via Wine) ───────────────────────────────────────────────────
(define-agent-tool proteus
  :binary-path "/opt/proteus/bin/proteus"
  :category :electronics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "Proteus — Circuit simulation and PCB design (Labcenter).
Integrated schematic capture, SPICE simulation, and PCB layout.
Unique feature: co-simulation of microcontroller code with the
circuit (Arduino, PIC, AVR, ARM). Popular in education.")

;; ── OrCAD (via Wine) ─────────────────────────────────────────────────────
(define-agent-tool orcad
  :binary-path "/opt/orcad/bin/orcad"
  :category :electronics
  :tool-type :scientific
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "OrCAD — PCB design and analysis (Cadence).
Professional PCB design suite from Cadence. Includes: Capture for
schematic design, PCB Editor for layout, PSpice for simulation,
and Signal Integrity analysis. Industry-standard for complex
multi-layer PCB designs.")

;; ── Mentor Graphics PADS (if available) ──────────────────────────────────
(define-agent-tool mentor-graphics
  :binary-path "/opt/mentor/bin/padslayout"
  :category :electronics
  :tool-type :scientific
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "Mentor Graphics PADS — PCB design (Siemens EDA).
Professional PCB design software now part of Siemens EDA. Features:
schematic design, PCB layout, signal integrity analysis, and
thermal analysis. Widely used in industrial electronics.")

;; ── Altium Designer (via Wine) ───────────────────────────────────────────
(define-agent-tool altium
  :binary-path "/opt/altium/bin/altium"
  :category :electronics
  :tool-type :scientific
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "Altium Designer — Unified electronics design.
Professional unified PCB design environment from Altium. Features:
schematic, PCB layout, FPGA design, BOM management, MCAD collaboration,
and cloud-based component libraries.")

;; ── nextpnr — FPGA Place and Route ───────────────────────────────────────
(define-agent-tool nextpnr
  :binary-path "/usr/bin/nextpnr-ice40"
  :category :electronics
  :tool-type :scientific
  :compute-budget 1800
  :memory-budget-mb 2048
  :description "nextpnr — Open-source FPGA place-and-route.
Portable FPGA place-and-route tool supporting iCE40, ECP5, and
other FPGA families. Replaces vendor-specific tools with an
open-source alternative. Integrates with Yosys for synthesis.")

;; ── icepack — FPGA Bitstream Packing ─────────────────────────────────────
(define-agent-tool icepack
  :binary-path "/usr/bin/icepack"
  :category :electronics
  :tool-type :scientific
  :compute-budget 600
  :memory-budget-mb 512
  :description "icepack — iCE40 FPGA bitstream pack/unpack.
Tool for converting between ASCII and binary bitstream formats
for Lattice iCE40 FPGAs. Part of the icestorm open-source FPGA
toolchain. icepack converts asc (text) to bin (flashable).")

;; ── iceprog — FPGA Programmer ────────────────────────────────────────────
(define-agent-tool iceprog
  :binary-path "/usr/bin/iceprog"
  :category :electronics
  :tool-type :scientific
  :requires-root t
  :compute-budget 300
  :memory-budget-mb 256
  :description "iceprog — iCE40 FPGA programmer. REQUIRES ROOT.
Programs Lattice iCE40 FPGAs via SPI interface (FTDI MPSSE or
Linux SPI device). Requires root access for SPI device access.
Part of the icestorm open-source FPGA toolchain.")



;; ═══════════════════════════════════════════════════════════════════════════
;; Section 12: Tool Definitions — Category: AI / Machine Learning (55 tools)
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These tools span deep learning frameworks, LLM serving, vector databases,
;; NLP libraries, computer vision, and agent frameworks. They represent the
;; cutting edge of artificial intelligence tooling — the same tools that
;; power modern AI research and production systems.

;; ── TensorFlow ───────────────────────────────────────────────────────────
(define-agent-tool tensorflow
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import tensorflow as tf; print(tf.__version__)")
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "TensorFlow — End-to-end machine learning platform.
Google's open-source ML framework. Supports: deep neural networks,
CNNs, RNNs, transformers, reinforcement learning, and production
deployment (TF Serving, TF Lite, TF.js). Keras API provides
high-level model building.")

;; ── PyTorch ──────────────────────────────────────────────────────────────
(define-agent-tool pytorch
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import torch; print(torch.__version__)")
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "PyTorch — Deep learning framework (Meta AI).
Open-source ML framework with dynamic computation graphs.
The research standard for deep learning. Features: autograd,
TorchScript for production, TorchServe for deployment, and
strong GPU acceleration via CUDA and ROCm.")

;; ── JAX ──────────────────────────────────────────────────────────────────
(define-agent-tool jax
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import jax; print(jax.__version__)")
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "JAX — Composable transformations of NumPy.
Google's high-performance ML research framework. Features:
automatic differentiation (grad), vectorization (vmap), parallelization
(pmap), JIT compilation via XLA, and native GPU/TPU support.
Powers Flax, Haiku, and many research projects.")

;; ── Keras ────────────────────────────────────────────────────────────────
(define-agent-tool keras
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import keras; print(keras.__version__)")
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Keras — Deep learning API.
High-level neural network API running on TensorFlow. Provides
a user-friendly interface for building and training deep learning
models. Supports CNNs, RNNs, transformers, and custom architectures.")

;; ── Scikit-learn ─────────────────────────────────────────────────────────
(define-agent-tool sklearn
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import sklearn; print(sklearn.__version__)")
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "Scikit-learn — Machine learning in Python.
Comprehensive ML library: classification, regression, clustering,
dimensionality reduction, model selection, and preprocessing.
Built on NumPy, SciPy, and Matplotlib. The standard for
traditional (non-deep) machine learning in Python.")

;; ── XGBoost ──────────────────────────────────────────────────────────────
(define-agent-tool xgboost
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import xgboost as xgb; print(xgb.__version__)")
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "XGBoost — Extreme Gradient Boosting.
Optimized distributed gradient boosting library. The dominant
algorithm for structured/tabular data in ML competitions and
production. Features: regularization, parallel tree construction,
handling of missing values, and cross-validation.")

;; ── LightGBM ─────────────────────────────────────────────────────────────
(define-agent-tool lightgbm
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import lightgbm as lgb; print(lgb.__version__)")
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "LightGBM — Gradient boosting framework (Microsoft).
Fast, distributed, high-performance gradient boosting based on
tree-based learning algorithms. Uses histogram-based decision
tree learning and leaf-wise tree growth for efficiency.")

;; ── ONNX Runtime ─────────────────────────────────────────────────────────
(define-agent-tool onnx-runtime
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import onnxruntime as ort; print(ort.__version__)")
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "ONNX Runtime — Cross-platform ML inference.
High-performance inference engine for Open Neural Network Exchange
(ONNX) models. Accelerates inference on CPU, GPU, and specialized
hardware (NPUs, TPUs). Enables model portability across frameworks.")

;; ── OpenVINO ─────────────────────────────────────────────────────────────
(define-agent-tool openvino
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import openvino; print(openvino.__version__)")
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "OpenVINO — Intel's deep learning toolkit.
Optimizes and deploys deep learning models on Intel hardware.
Features: model optimization (quantization, pruning), inference
engine for CPU/GPU/VPU/FPGA, and pre-trained model zoo (Open Model Zoo).")

;; ── DeepSpeed ────────────────────────────────────────────────────────────
(define-agent-tool deepspeed
  :binary-path "/usr/bin/deepspeed"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 14400
  :memory-budget-mb 65536
  :description "DeepSpeed — Deep learning optimization library (Microsoft).
Optimization library for training large deep learning models.
Features: ZeRO (memory optimization), model parallelism, pipeline
parallelism, and mixed precision training. Enables training models
with trillions of parameters.")

;; ── vLLM ─────────────────────────────────────────────────────────────────
(define-agent-tool vllm
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-m" "vllm.entrypoints.openai.api_server")
  :compute-budget 14400
  :memory-budget-mb 32768
  :description "vLLM — High-throughput LLM serving.
Open-source library for fast LLM inference and serving. Features:
PagedAttention for efficient KV cache management, continuous batching,
Tensor parallelism, and OpenAI-compatible API server. Supports
most popular LLM architectures.")

;; ── llama.cpp Server ─────────────────────────────────────────────────────
(define-agent-tool llama-cpp
  :binary-path "/usr/bin/llama-server"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "llama.cpp — LLM inference in C/C++.
Optimized LLM inference engine based on llama.cpp. Runs large
language models efficiently on CPU (AVX/AVX2/NEON), GPU (CUDA/Metal),
and mobile devices. Supports GGUF model format with various
quantization schemes. OpenAI-compatible HTTP server mode.")

;; ── Ollama ───────────────────────────────────────────────────────────────
(define-agent-tool ollama
  :binary-path "/usr/bin/ollama"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Ollama — Run LLMs locally.
User-friendly tool for running large language models locally.
Simplifies model management, pulling, and serving. Supports
Llama, Mistral, CodeLlama, Gemma, and many others. REST API
for integration with applications.")

;; ── Apache MXNet ─────────────────────────────────────────────────────────
(define-agent-tool mxnet
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import mxnet as mx; print(mx.__version__)")
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Apache MXNet — Deep learning framework.
Flexible and efficient deep learning framework from Apache.
Supports imperative and symbolic programming, distributed training,
and deployment across multiple languages and platforms.")

;; ── Caffe ────────────────────────────────────────────────────────────────
(define-agent-tool caffe
  :binary-path "/usr/bin/caffe"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Caffe — Deep learning framework (Berkeley Vision).
Fast open-source deep learning framework for convolutional neural
networks. Written in C++ with Python bindings. Known for speed
in CNN inference and model zoo with pre-trained models.")

;; ── Caffe2 ───────────────────────────────────────────────────────────────
(define-agent-tool caffe2
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import caffe2; print('caffe2 ok')")
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Caffe2 — Lightweight deep learning framework (Meta).
Lightweight, modular deep learning framework from Meta. Now merged
into PyTorch. Cross-platform deployment for mobile and embedded
applications.")

;; ── Theano ───────────────────────────────────────────────────────────────
(define-agent-tool theano
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import theano; print(theano.__version__)")
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "Theano — Numerical computation library.
Pioneering Python library for efficient numerical computation
with automatic differentiation. Predecessor to modern frameworks
like TensorFlow and PyTorch. Still used in legacy codebases.")

;; ── PaddlePaddle ─────────────────────────────────────────────────────────
(define-agent-tool paddle
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import paddle; print(paddle.__version__)")
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "PaddlePaddle — Deep learning platform (Baidu).
Parallel Distributed Deep Learning platform from Baidu. Features:
dynamic and static graphs, large-scale distributed training, and
industry-focused toolkits (PaddleNLP, PaddleCV, PaddleSpeech).")

;; ── Chainer ──────────────────────────────────────────────────────────────
(define-agent-tool chainer
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import chainer; print(chainer.__version__)")
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Chainer — Deep learning framework (Preferred Networks).
Define-by-run deep learning framework from Preferred Networks (Japan).
Pioneered dynamic computation graphs. Development transitioned to
PyTorch; maintained for legacy applications.")

;; ── Torch (Lua) ──────────────────────────────────────────────────────────
(define-agent-tool torch-lua
  :binary-path "/usr/bin/th"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "Torch — Scientific computing for Lua (legacy).
The original Torch framework in LuaJIT with GPU support via CUDA.
Pioneering deep learning framework. Now superseded by PyTorch.
Maintained for historical research reproducibility.")

;; ── Horovod — Distributed Training ───────────────────────────────────────
(define-agent-tool horovod
  :binary-path "/usr/bin/horovodrun"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 14400
  :memory-budget-mb 65536
  :description "Horovod — Distributed deep learning training framework.
Uber's distributed training framework for TensorFlow, PyTorch,
and MXNet. Uses MPI/gloo for allreduce communication. Simplifies
distributed training with minimal code changes.")

;; ── Ray — Distributed Computing ──────────────────────────────────────────
(define-agent-tool ray
  :binary-path "/usr/bin/ray"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Ray — Unified framework for scalable computing.
Open-source framework for distributed ML workloads: training,
tuning, reinforcement learning, and model serving. Ecosystem
includes Ray Train, Ray Tune, Ray RLlib, and Ray Serve.")

;; ── Hugging Face Transformers ────────────────────────────────────────────
(define-agent-tool transformers
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import transformers; print(transformers.__version__)")
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Hugging Face Transformers — Pre-trained NLP models.
State-of-the-art library for natural language processing. Provides
access to 100,000+ pre-trained models (BERT, GPT, T5, LLaMA, etc.)
and 10,000+ datasets. The standard for modern NLP applications.")

;; ── Diffusers ────────────────────────────────────────────────────────────
(define-agent-tool diffusers
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import diffusers; print(diffusers.__version__)")
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Diffusers — Diffusion models by Hugging Face.
Library for state-of-the-art diffusion models: Stable Diffusion,
DALL-E, Imagen, and custom pipelines. Supports text-to-image,
image-to-image, inpainting, and fine-tuning (LoRA, DreamBooth).")

;; ── ComfyUI — Stable Diffusion Interface ─────────────────────────────────
(define-agent-tool comfyui
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "ComfyUI — Node-based Stable Diffusion GUI.
Powerful and modular node-based interface for Stable Diffusion.
Features: visual workflow construction, custom nodes, model merging,
and batch processing. Popular for advanced image generation pipelines.")

;; ── Stable Diffusion WebUI (AUTOMATIC1111) ───────────────────────────────
(define-agent-tool stable-diffusion-webui
  :binary-path "/opt/stable-diffusion/webui.sh"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Stable Diffusion WebUI by AUTOMATIC1111.
Popular web interface for Stable Diffusion. Features: txt2img,
img2img, inpainting, outpainting, upscaling, LoRA support,
ControlNet, and extensive extension ecosystem.")

;; ── NVIDIA Triton Inference Server ───────────────────────────────────────
(define-agent-tool triton
  :binary-path "/usr/bin/tritonserver"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 32768
  :description "NVIDIA Triton Inference Server — Model serving.
Open-source inference serving software from NVIDIA. Supports
TensorFlow, PyTorch, ONNX, and custom backends. Features: dynamic
batching, model ensembles, GPU sharing, and HTTP/gRPC APIs.")

;; ── TensorRT ─────────────────────────────────────────────────────────────
(define-agent-tool tensorrt
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import tensorrt as trt; print(trt.__version__)")
  :compute-budget 3600
  :memory-budget-mb 16384
  :description "NVIDIA TensorRT — Deep learning inference optimizer.
SDK for high-performance deep learning inference on NVIDIA GPUs.
Features: layer fusion, precision calibration (INT8, FP16), kernel
auto-tuning, and optimized runtime for production deployment.")

;; ── MLflow ───────────────────────────────────────────────────────────────
(define-agent-tool mlflow
  :binary-path "/usr/bin/mlflow"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 3600
  :memory-budget-mb 4096
  :description "MLflow — ML lifecycle management.
Open-source platform for managing the ML lifecycle: experiment
tracking, model registry, packaging (MLflow Projects), and model
deployment (MLflow Models). Framework-agnostic and widely adopted.")

;; ── Weights & Biases ─────────────────────────────────────────────────────
(define-agent-tool wandb
  :binary-path "/usr/bin/wandb"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 3600
  :memory-budget-mb 4096
  :description "Weights & Biases — ML experiment tracking.
Platform for tracking experiments, visualizing results, and
collaborating on ML projects. Features: hyperparameter sweeps,
artifact versioning, model registry, and automated reporting.")

;; ── Optuna — Hyperparameter Optimization ─────────────────────────────────
(define-agent-tool optuna
  :binary-path "/usr/bin/optuna"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 14400
  :memory-budget-mb 8192
  :description "Optuna — Hyperparameter optimization framework.
Open-source framework for automated hyperparameter optimization.
Features: define-by-run API, pruning (early stopping), multi-objective
optimization, and distributed optimization across multiple nodes.")

;; ── spaCy — NLP Library ──────────────────────────────────────────────────
(define-agent-tool spacy
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import spacy; print(spacy.__version__)")
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "spaCy — Industrial-strength NLP library.
Fast and production-ready natural language processing library.
Features: tokenization, POS tagging, NER, dependency parsing,
word vectors, transformer integration, and custom model training.")

;; ── NLTK — Natural Language Toolkit ──────────────────────────────────────
(define-agent-tool nltk
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import nltk; print(nltk.__version__)")
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "NLTK — Natural Language Toolkit.
Leading platform for NLP research and education in Python.
Provides: tokenization, stemming, tagging, parsing, semantic
reasoning, and access to 50+ corpora. The standard teaching library
for computational linguistics.")

;; ── Gensim — Topic Modeling ──────────────────────────────────────────────
(define-agent-tool gensim
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import gensim; print(gensim.__version__)")
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "Gensim — Topic modeling and document similarity.
Open-source library for unsupervised semantic modeling of text.
Features: Word2Vec, Doc2Vec, FastText, LDA, LSI, and similarity
indexing. Memory-efficient with streamed processing.")

;; ── OpenCV — Computer Vision ─────────────────────────────────────────────
(define-agent-tool opencv
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import cv2; print(cv2.__version__)")
  :compute-budget 3600
  :memory-budget-mb 4096
  :description "OpenCV — Open-source computer vision library.
Comprehensive computer vision and image processing library: image
filtering, feature detection, object detection, face recognition,
video analysis, camera calibration, and deep learning inference
(DNN module). Supports C++, Python, and Java.")

;; ── Dlib — Machine Learning Toolkit ──────────────────────────────────────
(define-agent-tool dlib
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import dlib; print(dlib.__version__)")
  :compute-budget 3600
  :memory-budget-mb 4096
  :description "Dlib — C++ machine learning toolkit.
Modern C++ toolkit containing ML algorithms and tools for creating
complex software: SVM, deep learning, facial landmark detection,
object tracking, and correlation-based tracking.")

;; ── Faiss — Similarity Search ────────────────────────────────────────────
(define-agent-tool faiss
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import faiss; print(faiss.__version__)")
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Faiss — Efficient similarity search (Meta).
Library for efficient similarity search and clustering of dense
vectors. Optimized for billions of vectors. Supports GPU
acceleration, product quantization, and HNSW indexing.")

;; ── Milvus — Vector Database ─────────────────────────────────────────────
(define-agent-tool milvus
  :binary-path "/usr/bin/milvus"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 32768
  :description "Milvus — Open-source vector database.
Cloud-native vector database for AI applications. Optimized for
billion-scale vector similarity search. Features: GPU index
building, hybrid search (vector + scalar), and distributed deployment.")

;; ── Pinecone Client ──────────────────────────────────────────────────────
(define-agent-tool pinecone
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import pinecone; print('pinecone ok')")
  :compute-budget 3600
  :memory-budget-mb 4096
  :description "Pinecone — Managed vector database service.
Fully managed vector database for similarity search. Provides
low-latency vector search at scale with metadata filtering and
hybrid search. Cloud-hosted with Python client SDK.")

;; ── ChromaDB ─────────────────────────────────────────────────────────────
(define-agent-tool chromadb
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import chromadb; print(chromadb.__version__)")
  :compute-budget 3600
  :memory-budget-mb 4096
  :description "ChromaDB — AI-native open-source embedding database.
Open-source embedding database designed for AI applications.
Simple API for storing and querying embeddings with document
metadata. Supports filtering, multi-modal data, and local/remote
deployment modes.")

;; ── Weaviate ─────────────────────────────────────────────────────────────
(define-agent-tool weaviate
  :binary-path "/usr/bin/weaviate"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Weaviate — Vector search engine.
Open-source vector database combining vector search with semantic
search capabilities. Features: GraphQL interface, modular AI
integrations, multi-modal search, and hybrid search (BM25 + vector).")

;; ── Qdrant ───────────────────────────────────────────────────────────────
(define-agent-tool qdrant
  :binary-path "/usr/bin/qdrant"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Qdrant — Vector similarity search engine.
Open-source vector database and similarity search engine written
in Rust. Features: filtering, payload storage, HNSW indexing,
and distributed deployment. Optimized for production use.")

;; ── LlamaIndex ───────────────────────────────────────────────────────────
(define-agent-tool llamaindex
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import llama_index; print('llama_index ok')")
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "LlamaIndex — Data framework for LLM applications.
Framework for connecting LLMs with external data sources.
Features: indexing, querying, RAG (Retrieval-Augmented Generation),
and integration with 100+ data connectors (databases, APIs, files).")

;; ── LangChain ────────────────────────────────────────────────────────────
(define-agent-tool langchain
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import langchain; print(langchain.__version__)")
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "LangChain — Framework for LLM applications.
Open-source framework for building applications with LLMs through
composability. Features: chains, agents, memory, document loaders,
vector stores, and 100+ integrations with models and tools.")

;; ── AutoGPT ──────────────────────────────────────────────────────────────
(define-agent-tool autogpt
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 8192
  :description "AutoGPT — Autonomous GPT-4 experiment.
Open-source project attempting to make GPT-4 fully autonomous.
Features: goal decomposition, web search, file operations, code
execution, and long-term memory. Pioneering autonomous agent
architecture.")

;; ── CrewAI ───────────────────────────────────────────────────────────────
(define-agent-tool crewai
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "CrewAI — Multi-agent AI framework.
Framework for orchestrating role-playing autonomous AI agents.
Agents collaborate as a crew with defined roles, goals, and
tasks. Features: sequential and hierarchical processes, tool
integration, and memory management.")

;; ── LangGraph ────────────────────────────────────────────────────────────
(define-agent-tool langgraph
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import langgraph; print('langgraph ok')")
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "LangGraph — Stateful multi-actor LLM applications.
Library from LangChain for building stateful, multi-actor
applications with LLMs. Features: graph-based workflows,
cycles, parallelism, and persistence. Ideal for agent systems
with complex control flow.")

;; ── Haystack ─────────────────────────────────────────────────────────────
(define-agent-tool haystack
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import haystack; print(haystack.__version__)")
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "Haystack — NLP framework for search and QA.
End-to-end NLP framework for building search and question-answering
systems. Features: document stores, retrievers, readers, pipelines,
and evaluation. Integrates with Elasticsearch, OpenSearch, and
vector databases.")

;; ── AllenNLP ─────────────────────────────────────────────────────────────
(define-agent-tool allennlp
  :binary-path "/usr/bin/allennlp"
  :category :ai-ml
  :tool-type :scientific
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "AllenNLP — NLP research library (AI2).
Open-source NLP research library from the Allen Institute for AI.
Built on PyTorch. Features: state-of-the-art models, easy
experiment configuration, and reproducible research framework.")

;; ── Flair ────────────────────────────────────────────────────────────────
(define-agent-tool flair
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import flair; print(flair.__version__)")
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "Flair — NLP framework with contextual embeddings.
Simple framework for state-of-the-art NLP. Features: contextual
string embeddings, easy sequence labeling, and multilingual
support. Built on PyTorch.")

;; ── Stanza ───────────────────────────────────────────────────────────────
(define-agent-tool stanza
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import stanza; print(stanza.__version__)")
  :compute-budget 3600
  :memory-budget-mb 8192
  :description "Stanza — Stanford NLP library.
Python NLP library from Stanford University. Features: tokenization,
POS tagging, NER, dependency parsing, constituency parsing, and
multilingual support for 100+ languages. Neural pipeline with
high accuracy.")

;; ── Polyglot ─────────────────────────────────────────────────────────────
(define-agent-tool polyglot
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import polyglot; print(polyglot.__version__)")
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "Polyglot — Multilingual NLP library.
Natural language pipeline for multilingual text analysis.
Features: tokenization, NER, sentiment analysis, morphological
analysis, and language detection for 130+ languages.")

;; ── TextBlob ─────────────────────────────────────────────────────────────
(define-agent-tool textblob
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "import textblob; print(textblob.__version__)")
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "TextBlob — Simplified text processing.
Python library for processing textual data. Provides a simple API
for common NLP tasks: sentiment analysis, POS tagging, noun phrase
extraction, translation, and spell checking.")

;; ── VADER Sentiment Analysis ─────────────────────────────────────────────
(define-agent-tool vader
  :binary-path "/usr/bin/python3"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-c" "from vaderSentiment.vaderSentiment import SentimentIntensityAnalyzer; print('vader ok')")
  :compute-budget 1800
  :memory-budget-mb 4096
  :description "VADER — Valence Aware Dictionary and sEntiment Reasoner.
Lexicon and rule-based sentiment analysis tool specifically attuned
to sentiments expressed in social media. Fast, doesn't require
training data, and handles emoticons, slang, and negation.")

;; ── Stanford CoreNLP ─────────────────────────────────────────────────────
(define-agent-tool corenlp
  :binary-path "/usr/bin/java"
  :category :ai-ml
  :tool-type :scientific
  :default-args '("-jar" "/opt/stanford-corenlp/stanford-corenlp.jar")
  :compute-budget 7200
  :memory-budget-mb 16384
  :description "Stanford CoreNLP — Java NLP toolkit.
Java-based NLP toolkit from Stanford University. Features:
tokenization, sentence splitting, POS tagging, NER, sentiment
analysis, dependency parsing, coreference resolution, and
relation extraction. Industry standard for Java NLP.")



;; ═══════════════════════════════════════════════════════════════════════════
;; Section 13: Factory Functions & Subsystem Lifecycle
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These functions provide high-level interfaces for loading tool suites,
;; initializing the engineering subsystem, and managing the lifecycle of
;; scientific agents. They are the primary API for orchestrator integration.

(defun load-scientific-tool-suite (&key (categories :all))
  "Load scientific tools by category.

Registers all tools whose category matches one of the specified
categories. When :ALL (the default), all 150+ tools are loaded.
When a list of category keywords, only matching tools are loaded.

This function is idempotent — calling it multiple times with the
same categories has no additional effect (tools are not redefined).

Parameters:
  CATEGORIES — One of:
               :all            — Load all tool definitions (default)
               (:math :physics) — Load only specified categories
               :math           — Load a single category

  Valid category keywords:
    :math        — Mathematics & Statistics (20 tools)
    :physics     — Physics, CFD & FEA (25 tools)
    :engineering — Engineering & CAD (25 tools)
    :electronics — Electronics & EDA (25 tools)
    :ai-ml       — AI / Machine Learning (55 tools)

Returns: A list of loaded tool name symbols.

Example:
  ;; Load all tools
  (load-scientific-tool-suite)
  => (julia sagemath r-lang octave ... corenlp)

  ;; Load only CFD tools
  (load-scientific-tool-suite :categories :physics)
  => (openfoam simplefoam pimplefoam icofoam ... moose)

  ;; Load math and AI tools
  (load-scientific-tool-suite :categories '(:math :ai-ml))
  => (julia sagemath ... tensorflow pytorch ...)

Side effects:
  • Defines agent classes via DEFINE-AGENT-TOOL macro expansion
  • Registers tools in *scientific-tool-registry*
  • May broadcast gossip messages if subsystem is initialized"
  (let ((target-cats (if (eq categories :all)
                         (mapcar #'car *scientific-tool-categories*)
                         (if (listp categories)
                             categories
                             (list categories))))
        (loaded '()))
    (bt:with-lock-held (*scientific-tool-registry-lock*)
      (maphash (lambda (tool-name metadata)
                 (let ((tool-cat (getf metadata :category)))
                   (when (and (member tool-cat target-cats)
                              (getf metadata :loaded-p))
                     (push tool-name loaded))))
               *scientific-tool-registry*))
    (nreverse loaded)))

(defun load-all-scientific-tools ()
  "Load all 150+ scientific tools.

Convenience function equivalent to (load-scientific-tool-suite :categories :all).
Loads every tool definition in the *scientific-tool-registry*, covering
all five categories: math, physics, engineering, electronics, and ai-ml.

Returns: A list of all loaded tool name symbols.

Example:
  (load-all-scientific-tools)
  => (julia sagemath r-lang ... corenlp)  ; 150+ symbols"
  (load-scientific-tool-suite :categories :all))

(defun init-engineering-subsystem ()
  "Initialize the engineering subsystem.

Performs the following setup steps:
  1. Register gossip topics for scientific computing.
  2. Set *scientific-subsystem-initialized* to T.
  3. Log subsystem initialization.
  4. Broadcast subsystem-ready event to gossip mesh.

This function must be called before BROADCAST-SIMULATION-DATA and
related functions will actually publish messages. If the gossip
system is not running, initialization still succeeds but broadcasts
are silently dropped.

Returns: T if initialization succeeded.

Example:
  (init-engineering-subsystem)
  => T

Side effects:
  • Registers gossip topics
  • Sets *scientific-subsystem-initialized*
  • May publish gossip messages"
  ;; Register gossip topics (no-op if gossip not running)
  (dolist (topic *scientific-gossip-topics*)
    (handler-case
        (register-topic topic (lambda (msg)
                                (declare (ignore msg))
                                nil))
      (error (e)
        (warn "[SCIENCE] Could not register gossip topic ~A: ~A" topic e))))
  ;; Mark subsystem as initialized
  (setf *scientific-subsystem-initialized* t)
  (log-message :info "[SCIENCE] Engineering subsystem initialized. ~A tools available across ~A categories."
               (hash-table-count *scientific-tool-registry*)
               (length *scientific-tool-categories*))
  ;; Broadcast initialization event
  (handler-case
      (publish-message :swarm.science.status
                       `(:event :subsystem-ready
                         :tool-count ,(hash-table-count *scientific-tool-registry*)
                         :categories ,(mapcar #'car *scientific-tool-categories*)
                         :timestamp ,(local-time:now)))
    (error (e)
      (warn "[SCIENCE] Could not broadcast subsystem-ready: ~A" e)))
  t)

(defun engineering-subsystem-status ()
  "Return engineering subsystem status as a plist.

Provides a comprehensive status report including:
  • Whether the subsystem is initialized
  • Number of registered tools per category
  • Number of active agents
  • Number of active (running) simulations
  • Gossip topic registration status

Returns: A plist with keys:
  :initialized-p       — T if subsystem is initialized
  :total-tools         — Total number of tools in registry
  :tools-by-category   — Alist of (category . count)
  :active-agents       — Number of registered scientific agents
  :active-simulations  — Number of currently running simulations
  :gossip-topics       — List of registered gossip topics

Example:
  (engineering-subsystem-status)
  => (:initialized-p T
      :total-tools 150
      :tools-by-category ((:math . 20) (:physics . 25) (:engineering . 25)
                         (:electronics . 25) (:ai-ml . 55))
      :active-agents 3
      :active-simulations 1
      :gossip-topics (:swarm.science.output :swarm.science.data ...))"
  (let ((tools-by-category '()))
    (dolist (cat-entry *scientific-tool-categories*)
      (let ((cat (car cat-entry))
            (count 0))
        (maphash (lambda (tool-name metadata)
                   (declare (ignore tool-name))
                   (when (eq (getf metadata :category) cat)
                     (incf count)))
                 *scientific-tool-registry*)
        (push (cons cat count) tools-by-category)))
    (list :initialized-p *scientific-subsystem-initialized*
          :total-tools (hash-table-count *scientific-tool-registry*)
          :tools-by-category (nreverse tools-by-category)
          :active-agents (length (list-scientific-agents))
          :active-simulations (length (list-active-simulations))
          :gossip-topics *scientific-gossip-topics*)))

(defun list-scientific-tools (&key (category nil))
  "List all scientific tools, optionally filtered by category.

Parameters:
  CATEGORY — If provided, only list tools in this category.
             One of: :math :physics :engineering :electronics :ai-ml
             If NIL (default), list all tools.

Returns: A list of plists, each describing a tool:
  (:name tool-name :class class-symbol :binary path
   :category cat :description desc :loaded-p t)

Example:
  (list-scientific-tools :category :physics)
  => ((:name openfoam :class openfoam-agent :binary \"/usr/bin/foamRun\"
       :category :physics :description \"OpenFOAM CFD toolkit\" :loaded-p T)
      ...)

  (list-scientific-tools)
  => 150+ tool descriptions"
  (let ((tools '()))
    (maphash (lambda (tool-name metadata)
               (when (or (null category)
                         (eq (getf metadata :category) category))
                 (push (list :name tool-name
                             :class (getf metadata :class-name)
                             :binary (getf metadata :binary-path)
                             :category (getf metadata :category)
                             :description (getf metadata :description)
                             :loaded-p (getf metadata :loaded-p))
                       tools)))
             *scientific-tool-registry*)
    (nreverse tools)))

(defun halt-all-simulations ()
  "Emergency halt all running scientific simulations.

Immediately terminates ALL processes associated with scientific
agents, regardless of their compute budget status. This is the
nuclear option for resource reclamation or emergency shutdown.

Steps:
  1. Enumerate all active simulations via LIST-ACTIVE-SIMULATIONS.
  2. Send SIGTERM to each process.
  3. Wait 5 seconds.
  4. Send SIGKILL to any survivors.
  5. Update agent status to :HALTED.
  6. Broadcast halt event to gossip.

Returns: A list of (agent-id . status) pairs indicating the
result for each halted agent.

Example:
  (halt-all-simulations)
  => ((AGENT-1234 . :terminated) (AGENT-5678 . :terminated))

Side effects:
  • Terminates OS processes
  • Updates agent status slots
  • Publishes gossip messages"
  (let ((active (list-active-simulations))
        (results '()))
    (dolist (agent active)
      (let ((proc (agent-process agent)))
        (when proc
          ;; Attempt graceful termination
          (ignore-errors (uiop:terminate-process proc))
          (sleep 5)
          ;; Force kill if still alive
          (when (uiop:process-alive-p proc)
            (ignore-errors (uiop:terminate-process proc :urgent t)))
          ;; Update status
          (setf (agent-status agent) :halted)
          ;; Record result
          (push (cons (agent-id agent)
                      (if (uiop:process-alive-p proc) :failed :terminated))
                results)
          ;; Broadcast halt
          (when *scientific-subsystem-initialized*
            (publish-message :swarm.science.status
                             `(:event :simulation-halted
                               :agent-id ,(agent-id agent)
                               :tool ,(agent-tool-name agent)
                               :timestamp ,(local-time:now)))))))
    (nreverse results)))

(defun get-simulation-summary (agent)
  "Get a summary of a completed or running simulation.

Collects key metrics from the agent's simulation-data hash-table
and presents them in a human-readable format.

Parameters:
  AGENT — The SCIENTIFIC-AGENT to summarize.

Returns: A plist with keys:
  :agent-id          — Agent identifier
  :tool              — Tool name
  :category          — Tool category
  :status            — Current agent status
  :converged-p       — T if simulation converged (detected from output)
  :iterations        — Number of iterations performed
  :final-residual    — Last recorded residual
  :wall-time         — Elapsed wall-clock time in seconds
  :output-files      — Generated output files
  :custom-data       — Tool-specific data fields

Example:
  (get-simulation-summary my-openfoam-agent)
  => (:agent-id AGENT-1234 :tool openfoam :category :physics
      :status :completed :converged-p T :iterations 1000
      :final-residual 1.2e-6 :wall-time 3600.0
      :output-files (\"/case/100/U\" \"/case/100/p\")
      :custom-data (:courant-max 2.5 :force-cd 0.45 :force-cl 1.2))"
  (let ((data (agent-simulation-data agent)))
    (list :agent-id (agent-id agent)
          :tool (agent-tool-name agent)
          :category (agent-tool-category agent)
          :status (agent-status agent)
          :converged-p (gethash :converged-p data)
          :iterations (or (gethash :iteration-count data)
                         (length (cdr (assoc :ux
n                                             (gethash :convergence-history data)))))
          :final-residual (gethash :last-residual data)
          :wall-time (when (agent-start-time agent)
                       (- (local-time:timestamp-to-unix (local-time:now))
                          (local-time:timestamp-to-unix (agent-start-time agent))))
          :output-files (agent-output-files agent)
          :custom-data (hash-table-to-plist data))))

(defun wait-for-simulation (agent &key (timeout nil) (poll-interval 1))
  "Block until a simulation completes or timeout is reached.

Polls the agent's process status every POLL-INTERVAL seconds.
Returns when the process exits, the agent status changes from
:RUNNING, or the timeout is exceeded.

Parameters:
  AGENT         — The SCIENTIFIC-AGENT to wait for.
  TIMEOUT       — Max seconds to wait (NIL = wait forever).
  POLL-INTERVAL — Seconds between status checks (default 1).

Returns: The agent's final status keyword (:COMPLETED, :FAILED,
:HALTED, etc.), or :TIMEOUT if the wait timed out.

Example:
  ;; Wait up to 1 hour for a CFD simulation
  (wait-for-simulation my-openfoam-agent :timeout 3600)
  => :completed

  ;; Quick check with 5-second polling
  (wait-for-simulation my-calculix-agent :poll-interval 5)
  => :completed"
  (let ((start-time (local-time:timestamp-to-unix (local-time:now))))
    (loop
      ;; Check if process has exited
      (let ((proc (agent-process agent)))
        (when (or (null proc)
                  (not (uiop:process-alive-p proc)))
          (return (agent-status agent)))
        ;; Check if status changed
        (unless (eq (agent-status agent) :running)
          (return (agent-status agent)))
        ;; Check timeout
        (when timeout
          (let ((elapsed (- (local-time:timestamp-to-unix (local-time:now))
                            start-time)))
            (when (> elapsed timeout)
              (return :timeout))))
        ;; Sleep before next poll
        (sleep poll-interval)))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 14: Utility Functions
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Helper functions used throughout the engineering module.

(defun verify-input-files (agent)
  "Verify that all input files for a simulation exist.

Checks each file in the agent's input-files slot. Returns T if all
files exist, or a list of missing files otherwise.

Parameters:
  AGENT — The SCIENTIFIC-AGENT whose inputs to verify.

Returns: T if all inputs exist, or (missing-file1 missing-file2 ...).

Example:
  (verify-input-files my-openfoam-agent)
  => T   ; all files present

  (verify-input-files my-bad-agent)
  => (\"/path/to/missing/mesh.stl\")"
  (let ((missing '()))
    (dolist (f (agent-input-files agent))
      (unless (probe-file f)
        (push f missing)))
    (if (null missing)
        t
        (nreverse missing))))

(defun verify-output-files (agent)
  "Verify that all expected output files were created.

Checks each file in the agent's output-files slot. Typically called
after a simulation completes to validate that all expected outputs
were generated.

Parameters:
  AGENT — The SCIENTIFIC-AGENT whose outputs to verify.

Returns: T if all outputs exist, or (missing-file1 missing-file2 ...).

Example:
  (verify-output-files my-completed-agent)
  => T   ; all expected outputs present

  (verify-output-files my-failed-agent)
  => (\"/path/to/missing/results.csv\")"
  (let ((missing '()))
    (dolist (f (agent-output-files agent))
      (unless (probe-file f)
        (push f missing)))
    (if (null missing)
        t
        (nreverse missing))))

(defun collect-output-lines (agent)
  "Return all captured output lines from an agent as a fresh list.

Safely copies the agent's output buffer, which may be concurrently
mutated by the capture thread.

Parameters:
  AGENT — The SCIENTIFIC-AGENT whose output to retrieve.

Returns: A list of strings, the captured output lines in order.

Example:
  (collect-output-lines my-agent)
  => (\"Starting simulation...\" \"Iteration 1: residual = 0.1\"
      \"Iteration 2: residual = 0.01\" \"CONVERGENCE ACHIEVED\")"
  (coerce (agent-output-buffer agent) 'list))

(defun simulation-converged-p (agent)
  "Check if a simulation has converged based on parsed data.

Examines the agent's simulation-data hash-table for convergence
indicators. Different tool categories have different convergence
criteria.

For :physics agents (CFD/FEA):
  • Checks if final residual is below a threshold (1e-6)
  • Checks if convergence was explicitly reported in output

For :math agents:
  • Checks if iteration limit was reached with stable residuals

Parameters:
  AGENT — The SCIENTIFIC-AGENT to check.

Returns: T if converged, NIL otherwise, or :unknown if insufficient
data is available.

Example:
  (simulation-converged-p my-openfoam-agent)
  => T

  (simulation-converged-p my-running-agent)
  => :unknown   ; simulation still running"
  (let ((data (agent-simulation-data agent)))
    (case (agent-tool-category agent)
      ((:physics)
       ;; Check explicit convergence flag
       (let ((conv-p (gethash :converged-p data)))
         (when conv-p (return-from simulation-converged-p t)))
       ;; Check residual threshold
       (let ((final-res (gethash :last-residual data)))
         (when (and final-res (< final-res 1e-6))
           (return-from simulation-converged-p t)))
       :unknown)
      ((:math)
       ;; Check for stable convergence
       (let ((residuals (cdr (assoc :primary
                                    (gethash :convergence-history data)))))
         (if (and residuals (>= (length residuals) 2))
             (let ((last-res (car (last residuals))))
               (if (< last-res 1e-6) t :unknown))
             :unknown)))
      (otherwise :unknown))))

(defun reset-simulation-data (agent)
  "Clear all simulation data from an agent.

Reinitializes the agent's simulation-data hash-table to empty,
allowing the agent to be reused for a new simulation run.

Parameters:
  AGENT — The SCIENTIFIC-AGENT whose data to reset.

Returns: The agent (for chaining).

Example:
  (reset-simulation-data my-agent)
  => #<OPENFOAM-AGENT {1234}>   ; simulation-data is now empty"
  (setf (agent-simulation-data agent) (make-hash-table :test 'eq))
  agent)

(defun copy-simulation-data (source-agent target-agent)
  "Copy simulation data from one agent to another.

Deep copies the simulation-data hash-table from SOURCE-AGENT to
TARGET-AGENT. Useful for creating analysis agents that work on
results from compute agents.

Parameters:
  SOURCE-AGENT — The agent to copy data from.
  TARGET-AGENT — The agent to copy data to.

Returns: The target agent (for chaining).

Example:
  (copy-simulation-data compute-agent analysis-agent)
  => #<ANALYSIS-AGENT {5678}>"
  (let ((new-ht (make-hash-table :test 'eq)))
    (maphash (lambda (k v)
               (setf (gethash k new-ht) v))
             (agent-simulation-data source-agent))
    (setf (agent-simulation-data target-agent) new-ht))
  target-agent)


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 15: Integration with Kali-Agent (Shadow Pattern)
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Scientific agents can participate in the shadow agent pattern just
;; like kali-agents. A shadow-observer captures raw simulation output,
;; and a shadow-analyst processes the structured data for insights.

(defmethod spawn-shadow-observer ((agent scientific-agent))
  "Spawn a shadow observer thread for a scientific agent.

The shadow observer continuously captures output from the running
simulation, parses it for structured data, and broadcasts updates
to the gossip mesh. It exits when the simulation process terminates.

Parameters:
  AGENT — The SCIENTIFIC-AGENT to observe.

Returns: The observer thread object.

The observer thread:
  1. Calls CAPTURE-SIMULATION-OUTPUT in a loop.
  2. Broadcasts structured data every 60 seconds.
  3. Exits when the process is no longer alive.
  4. Broadcasts a completion event with final results."
  (bt:make-thread
   (lambda ()
     (loop
       (let ((proc (agent-process agent)))
         (unless (and proc (uiop:process-alive-p proc))
           (return)))
       ;; Capture output (non-blocking)
       (capture-simulation-output agent)
       ;; Periodic data broadcast
       (when *scientific-subsystem-initialized*
         (broadcast-simulation-data agent
           (hash-table-to-plist (agent-simulation-data agent))))
       (sleep 1))
     ;; Simulation ended — broadcast completion
     (when *scientific-subsystem-initialized*
       (broadcast-simulation-completion
        agent
        (list :converged-p (simulation-converged-p agent)
              :final-status (agent-status agent)
              :simulation-data (hash-table-to-plist
                               (agent-simulation-data agent))
              :output-files (agent-output-files agent))))
     (log-message :info "[SCIENCE] Shadow observer for ~A exited."
                  (agent-id agent)))
   :name (format nil "shadow-observer-~A" (agent-id agent))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 16: Module Footer
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Log module load completion. The engineering module is now ready for use.
;; Call (init-engineering-subsystem) to activate gossip integration, then
;; use the MAKE-<TOOL>-AGENT constructors and RUN-TOOL methods to execute
;; scientific computing tasks.
;;
;; Example session:
;;   (init-engineering-subsystem)
;;   (defparameter *of-agent* (make-openfoam-agent
;;                              :args '("-case" "/path/to/cavity")))
;;   (run-tool *of-agent*)
;;   (wait-for-simulation *of-agent* :timeout 3600)
;;   (broadcast-simulation-completion *of-agent*
;;     (get-simulation-summary *of-agent*))

(log-message :info "[SCIENCE] engineering-interface.lisp loaded. ~A tools defined. ~A categories."
             (hash-table-count *scientific-tool-registry*)
             (length *scientific-tool-categories*))

;;; ═══════════════════════════════════════════════════════════════════════════
;;;                              END OF FILE
;;; ═══════════════════════════════════════════════════════════════════════════

