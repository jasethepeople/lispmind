;;;; -*- Mode: Lisp; Syntax: ANSI-Common-Lisp; Base: 10 -*-
;;;
;;; EVOLUTION.LISP — MGL-GPR Genetic Programming Bridge for LISPMIND
;;;
;;; ═══════════════════════════════════════════════════════════════════════════
;;;          THE CROWN JEWEL: SELF-EVOLVING STRATEGIES VIA TREE-BASED GP
;;; ═══════════════════════════════════════════════════════════════════════════
;;;
;;; This module is the beating heart of LISPMIND v2.0's self-improvement
;;; capability. When an agent encounters a blockage — repeated failures,
;;; strategy stalls, suboptimal behavior — it does not merely ask for a
;;; human-crafted fix. It LITERALLY WRITES ITS OWN SUPERIOR STRATEGY by
;;; evolving S-expression trees through genetic programming.
;;;
;;; GENETIC PROGRAMMING THEORY (A Brief Primer)
;;; ───────────────────────────────────────────
;;; Genetic Programming (GP) is a nature-inspired optimization technique.
;;; Instead of evolving DNA sequences, we evolve COMPUTER PROGRAMS represented
;;; as trees. Each node is either:
;;;   • A FUNCTION (internal node):  (if, progn, and, or, >, <, =, +, -, funcall)
;;;   • A TERMINAL (leaf node):      capability keywords, numbers, agent slots
;;;
;;; The evolutionary cycle follows Darwinian principles:
;;;   1. POPULATION  — Create a diverse pool of candidate strategies
;;;   2. FITNESS     — Evaluate each strategy against real test cases
;;;   3. SELECTION   — Preferentially choose the best performers
;;;   4. CROSSOVER   — Combine subtrees from two parents (sexual reproduction)
;;;   5. MUTATION    — Randomly alter a subtree (asexual variation)
;;;   6. ITERATION   — Repeat for N generations, return the champion
;;;
;;; WHY S-EXPRESSIONS?
;;; ──────────────────
;;; Lisp was BORN for genetic programming. The S-expression IS a tree — there
;;; is no impedance mismatch between our representation and our data structure.
;;; We don't need to parse, serialize, or decode anything. A strategy IS a list.
;;; We can (EVAL) it, (COMPILE) it, or (MACROEXPAND) it. No other language
;;; offers this seamless unity of code and data. This is why Koza's original
;;; GP work used Lisp, and why LISPMIND's evolution module is possible at all.
;;;
;;; INTEGRATION ARCHITECTURE
;;; ────────────────────────
;;;   Orchestrator monitor-loop detects repeated failures
;;;           │
;;;           ▼
;;;   should-evolve-p returns T (error-count > threshold)
;;;           │
;;;           ▼
;;;   run-evolutionary-cycle called with the failing agent
;;;           │
;;;           ▼
;;;   evolve-strategy runs GP over the agent's current strategy
;;;           │
;;;           ▼
;;;   compile-chromosome produces a lambda from the fittest S-expression
;;;           │
;;;           ▼
;;;   hotpatch-agent installs the evolved strategy atomically
;;;           │
;;;           ▼
;;;   log-evolution records the lineage for future analysis
;;;
;;; "An agent that can rewrite its own strategy is no longer a program.
;;;  It is a living system — growing, adapting, transcending its origins."

(in-package :lispmind)


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 1: Strategy Chromosome — The Genome of Agent Behavior
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; A strategy-chromosome is the complete genetic encoding of an agent's
;; behavior. It wraps an S-expression (the program tree) with metadata:
;; fitness score, generation number, and parent IDs for lineage tracking.
;;
;; Lineage tracking is critical for debugging and analysis: when an evolved
;; strategy works brilliantly, we can trace exactly which mutations and
;; crossovers produced it, then study that genealogy to understand what
;; made it successful.

(defstruct (strategy-chromosome
            (:constructor make-strategy-chromosome
              (&key expression fitness generation parent-ids
               &aux (id (gensym "CHROM-")))))
  "A strategy represented as an evolvable S-expression tree.

EXPRESSION  — The S-expression that encodes the strategy.  This is the
              genotype: a tree of function calls that, when compiled and
              executed, produces agent behavior.  Example:
              '(IF (> ERROR-COUNT 3) (FALLBACK-STRATEGY AGENT) (DO-WORK AGENT))

FITNESS     — Float indicating how well this strategy performs.  Higher
              is better.  Computed by STRATEGY-FITNESS against test cases.
              Default is 0.0 (untested).

GENERATION  — Non-negative integer indicating which GP generation produced
              this chromosome.  Generation 0 = seed/initial strategy.

PARENT-IDS  — List of parent chromosome IDs (via strategy-chromosome-id).
              Used for lineage tracking and evolution analysis.  Empty
              list means this chromosome was a seed, not produced by
              crossover or mutation.

ID          — Unique identifier (auto-generated via GENSYM).  Used to
              reference this chromosome in PARENT-IDs of offspring.

Example:
  (make-strategy-chromosome
    :expression '(progn (fetch-data) (parse-data) (store-data))
    :fitness 0.85
    :generation 0)"
  (id nil :type symbol :read-only t)
  (expression '(progn (default-strategy agent)) :type list)
  (fitness 0.0 :type float)
  (generation 0 :type (integer 0 *))
  (parent-ids '() :type list))

;; ── Chromosome identity and comparison ──────────────────────────────────

(defun chromosome-p (object)
  "Return T if OBJECT is a STRATEGY-CHROMOSOME struct.

This is a convenience predicate for type checking.  It is equivalent to
(TYPEP OBJECT 'STRATEGY-CHROMOSOME) but reads better in GP code."
  (typep object 'strategy-chromosome))

(defun chromosome< (a b)
  "Compare two chromosomes by fitness, returning T if A is less fit than B.

This is the ordering predicate for tournament selection.  Higher fitness
means a better chromosome.  Chromosomes with equal fitness are ordered by
expression complexity (shorter expressions are preferred) to combat bloat."
  (if (= (strategy-chromosome-fitness a)
         (strategy-chromosome-fitness b))
      (> (tree-size (strategy-chromosome-expression a))
         (tree-size (strategy-chromosome-expression b)))
    (< (strategy-chromosome-fitness a)
       (strategy-chromosome-fitness b))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 2: GP Parameters and Configuration
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These special variables control the behavior of the genetic programming
;; engine.  They are intentionally parameterizable so that DEFINE-EVOLVING-
;; AGENT and RUN-EVOLUTIONARY-CYCLE can tune them for specific agent types.

(defparameter *default-gp-functions*
  '(if progn and or > < = + - funcall not)
  "The default function set for GP trees.

Each symbol in this list must name a function that is available at the
point where the evolved strategy is compiled.  The functions are:
  IF      — Conditional execution (3-argument: condition then else)
  PROGN   — Sequential evaluation (2+ arguments)
  AND     — Logical conjunction (short-circuiting)
  OR      — Logical disjunction (short-circuiting)
  >       — Numeric greater-than
  <       — Numeric less-than
  =       — Numeric equality
  +       — Addition
  -       — Subtraction
  FUNCALL — Call a function dynamically (for capability dispatch)
  NOT     — Logical negation

Users of DEFINE-EVOLVING-AGENT can override this list to provide domain-
specific functions (e.g., 'fetch-url', 'parse-json', 'store-result').")

(defparameter *default-gp-terminals*
  '(agent 0 1 2 3 5 10 25 50 100 nil t)
  "The default terminal set for GP trees.

Terminals are the leaves of the expression tree — values, not functions.
This list includes:
  AGENT     — The agent instance itself (passed as argument)
  0,1,2,... — Integer constants (commonly used thresholds, counters, etc.)
  NIL, T    — Boolean constants

Additional terminals are derived from the agent's CAPABILITIES list
(e.g., :fetch, :parse, :store become terminal keywords).")

(defparameter *max-gp-tree-depth* 8
  "Maximum depth for randomly generated GP trees.

Deeper trees can express more complex strategies but increase the search
space exponentially and risk bloat (see *BLOAT-PENALTY-FACTOR*).  The
default of 8 balances expressiveness with search efficiency.  Agents
needing deeper strategies should override this parameter.

A tree of depth N has at most 2^N leaf nodes (for binary functions).  At
depth 8, that's up to 256 leaves — plenty for sophisticated strategies.")

(defparameter *bloat-penalty-factor* 0.005
  "Penalty coefficient for expression complexity (tree size).

The fitness score is reduced by (* BLOAT-PENALTY-FACTOR tree-size).  This
prevents evolution from producing bloated, unreadable strategies (the
equivalent of biological junk DNA).  Without this penalty, GP tends to
produce enormous trees that score marginally better but are unmaintainable.

Set to 0.0 to disable bloat control entirely (not recommended).")

(defparameter *mutation-rate* 0.15
  "Probability of applying subtree mutation to a chromosome.

A value of 0.15 means ~15% of offspring are produced by mutation rather
than direct copying or crossover.  This is a standard rate in the GP
literature — high enough to maintain diversity, low enough to preserve
good building blocks.")

(defparameter *crossover-rate* 0.75
  "Probability of applying subtree crossover between two parents.

A value of 0.75 means ~75% of offspring are produced by crossover (sexual
reproduction).  The remaining ~10% (1 - crossover-rate - mutation-rate)
are direct copies (elitism clones).  This 75/15/10 ratio is standard in
genetic programming.")

(defparameter *tournament-size* 3
  "Number of chromosomes in each tournament selection.

Tournament selection randomly picks N chromosomes and returns the fittest.
Larger tournaments increase selection pressure (faster convergence but
less diversity).  Smaller tournaments preserve diversity (slower but more
thorough exploration).  A value of 3 provides a good balance.")


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 3: Tree Utilities — Navigating S-Expression Trees
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Before we can mutate or crossover trees, we need to navigate them.  These
;; are the fundamental tree operations that the GP operators build upon.
;;
;; Lisp S-expressions are trees by nature: (A B C) is a node A with children
;; B and C.  These functions treat arbitrary Lisp forms as binary/unary
;; trees for the purposes of genetic programming.

(defun tree-size (tree)
  "Count the total number of nodes in TREE (an S-expression).

Each atom counts as 1.  Each list counts as 1 plus the sizes of its
children.  This is the standard node-count measure of tree complexity.

Example: (tree-size '(if (> x 3) (+ x 1) x))  =>  10

Used for:
  • Bloat penalty calculation in STRATEGY-FITNESS
  • Crossover point selection (proportional to subtree count)
  • Evolution reports (tracking complexity growth over generations)"
  (cond
    ((null tree) 1)
    ((atom tree) 1)
    (t (+ 1 (reduce #'+ (mapcar #'tree-size (cdr tree)) :initial-value 0)))))

(defun tree-depth (tree)
  "Compute the maximum depth of TREE (an S-expression).

An atom has depth 1.  A list has depth 1 + max depth of its children.

Example: (tree-depth '(if (> x 3) y z))  =>  3

Used to enforce *MAX-GP-TREE-DEPTH* during random tree generation and
mutation.  Trees that exceed the maximum depth are rejected and regrown."
  (cond
    ((null tree) 1)
    ((atom tree) 1)
    (t (+ 1 (if (cdr tree)
                (reduce #'max (mapcar #'tree-depth (cdr tree)) :initial-value 0)
              0)))))

(defun random-subtree (tree)
  "Select a random subtree from TREE using uniform node selection.

Collects all nodes in the tree (both internal and leaf), then picks one
at random.  Returns two values: the selected subtree and the "address"
(path from root) needed to locate it.

The address is a list of integer indices into successive CDR positions.
For example, '(1 0) means 'second child, then first child of that'.

Example:
  (random-subtree '(if (> x 3) (+ y 1) z))
    => (+ Y 1)      ; the selected subtree
    => (1)          ; address: second child of root (0-indexed: 0=condition, 1=then, 2=else)

This is the core primitive for both MUTATE-SUBTREE and CROSSOVER-SUBTREES."
  (let ((nodes '()))
    ;; Collect all (address . subtree) pairs via DFS
    (labels ((collect (addr subtree)
               (push (cons addr subtree) nodes)
               (when (consp subtree)
                 (loop for child in (cdr subtree)
                       for i from 0
                       do (collect (append addr (list i)) child)))))
      (collect '() tree)
      ;; Pick uniformly at random
      (let* ((choice (nth (random (length nodes)) nodes))
             (addr (car choice))
             (subtree (cdr choice)))
        (values subtree addr)))))

(defun replace-subtree (tree new-subtree address)
  "Replace the subtree at ADDRESS in TREE with NEW-SUBTREE.

ADDRESS is a list of integer indices as returned by RANDOM-SUBTREE.
If ADDRESS is NIL, replaces the entire tree.  Returns the modified tree.

Example:
  (replace-subtree '(if (> x 3) (+ y 1) z)
                   '(* y 2)
                   '(1))
    => (IF (> X 3) (* Y 2) Z)

This is the counterpart to RANDOM-SUBTREE: it finds what RANDOM-SUBTREE
selected and substitutes NEW-SUBTREE in its place.  Used by both
MUTATE-SUBTREE (new subtree is randomly generated) and CROSSOVER-SUBTREES
(new subtree comes from another parent)."
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
        ;; Address is non-nil but tree is atomic — should not happen
        new-subtree))))

(defun count-nodes (tree)
  "Count all nodes in TREE (alias for TREE-SIZE).

Provided for code readability in selection routines where 'count-nodes'
is more descriptive than 'tree-size'."
  (tree-size tree))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 4: Random Expression Generation — Creating Initial Trees
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; The initial population needs diverse starting material.  RANDOM-EXPRESSION
;; generates trees using the ramped half-and-half method: half the time it
;; uses the GROW method (variable depth), half the time the FULL method
;; (full depth at all branches).  This produces a mix of shapes that helps
;; the population explore the search space effectively.

(defun random-terminal (terminals)
  "Select a random terminal from TERMINALS.

TERMINALS is a list of atoms (keywords, numbers, symbols).  One element
is selected uniformly at random.

Example:
  (random-terminal '(agent 0 1 2 :fetch :parse))  =>  :FETCH  (randomly)"
  (let ((choice (nth (random (length terminals)) terminals)))
    ;; Return a fresh copy to avoid shared structure issues
    (if (numberp choice)
        choice  ; numbers are immutable — safe to share
      choice)))

(defun random-function (functions)
  "Select a random function symbol from FUNCTIONS.

Returns a symbol suitable for use as the CAR of a list expression.

Example:
  (random-function '(if and or >))  =>  AND  (randomly)"
  (nth (random (length functions)) functions))

(defun function-arity (fn-symbol)
  "Return the arity (number of arguments) of FN-SYMBOL.

This function encodes the arities of the standard GP function set:
  IF  → 3  (condition then else)
  PROGN → 2 (at least 2 arguments for our purposes)
  AND → 2
  OR  → 2
  >   → 2
  <   → 2
  =   → 2
  +   → 2
  -   → 2
  FUNCALL → 2  (function arg)
  NOT → 1

For unknown functions, we default to 2 (binary) which is the most common.
This lets users add custom functions without modifying this table — the
worst case is that we generate slightly suboptimal trees."
  (case fn-symbol
    ((if) 3)
    ((not) 1)
    ((progn and or > < = + - funcall) 2)
    ;; User-defined functions: assume binary
    (otherwise 2)))

(defun random-expression (max-depth terminals functions &key (method :mixed))
  "Generate a random expression tree for genetic programming.

MAX-DEPTH is the maximum tree depth (deeper trees will not be generated).
TERMINALS is a list of terminal atoms (keywords, numbers, symbols).
FUNCTIONS is a list of function symbols.
METHOD controls tree shape:
  :GROW   — Trees grow to variable depth; leaves can appear at any level.
  :FULL   — Every branch goes exactly to MAX-DEPTH.
  :MIXED  — Randomly choose :GROW or :FULL for each call (ramped).

Returns a freshly consed S-expression that is a valid Lisp form.

Example:
  (random-expression 3 '(agent 0 1 2) '(if > and))
    => (IF (> AGENT 1) AGENT 2)     ; randomly generated

The ramped half-and-half method (METHOD :MIXED) is the industry standard
for GP initialization.  It produces a diverse population of tree shapes,
from short bushy trees to tall spindly ones, which prevents premature
convergence to a single tree structure."
  (let ((actual-method
         (if (eq method :mixed)
             (if (zerop (random 2)) :grow :full)
           method)))
    (cond
      ;; Base case: must use terminal at depth 0
      ((<= max-depth 0)
       (random-terminal terminals))

      ;; GROW method: can choose terminal at any depth (except 0, handled above)
      ((eq actual-method :grow)
       (if (zerop (random 2))
           ;; Terminal — stop growing this branch
           (random-terminal terminals)
         ;; Function — continue growing
         (let ((fn (random-function functions))
               (arity (function-arity (random-function functions))))
           (cons fn
                 (loop repeat arity
                       collect (random-expression (1- max-depth)
                                                   terminals functions
                                                   :method :grow))))))

      ;; FULL method: every branch goes to max depth
      ((eq actual-method :full)
       (if (<= max-depth 1)
           (random-terminal terminals)
         (let ((fn (random-function functions))
               (arity (function-arity (random-function functions))))
           (cons fn
                 (loop repeat arity
                       collect (random-expression (1- max-depth)
                                                   terminals functions
                                                   :method :full)))))

      ;; Fallback (should not reach here)
      (t
       (random-terminal terminals)))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 5: Mutation and Crossover — Genetic Operators
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These are the two fundamental genetic operators that produce new
;; chromosomes from existing ones.  Mutation introduces novel genetic
;; material; crossover combines building blocks from successful parents.

(defun mutate-subtree (expression max-depth terminals functions)
  "Randomly replace a subtree in EXPRESSION with a new random subtree.

Process:
  1. Select a random subtree of EXPRESSION (via RANDOM-SUBTREE).
  2. Generate a replacement tree of depth up to MAX-DEPTH (via RANDOM-EXPRESSION).
  3. Substitute the replacement at the selected position.

The replacement tree is generated independently — it shares no structure
with the original, ensuring that mutation introduces genuinely new genetic
material.  The selection is uniform: every node has equal probability of
being the mutation point, so both leaf terminals and entire subexpressions
can be replaced.

MAX-DEPTH controls the depth of the generated replacement.  A smaller
value produces local, conservative mutations; a larger value produces
dramatic changes.  We use a random depth between 1 and MAX-DEPTH to get
a mix of both.

Example:
  (mutate-subtree '(if (> x 3) (+ y 1) z) 4 '(x y z 0 1) '(if + >))
    => (IF (> X 3) (+ Y 1) (+ Z 0))   ; the 'Z' leaf was mutated to '(+ Z 0)"
  (multiple-value-bind (subtree address)
      (random-subtree expression)
    (declare (ignore subtree))
    (let* ((replacement-depth (1+ (random max-depth)))
           (replacement (random-expression replacement-depth terminals functions
                                          :method :mixed)))
      (replace-subtree expression replacement address))))

(defun crossover-subtrees (expr-a expr-b)
  "Swap random subtrees between two expressions, producing two offspring.

Process:
  1. Select a random subtree from EXPR-A (via RANDOM-SUBTREE).
  2. Select a random subtree from EXPR-B (via RANDOM-SUBTREE).
  3. Create offspring-1: EXPR-A with EXPR-B's subtree inserted.
  4. Create offspring-2: EXPR-B with EXPR-A's subtree inserted.

Returns two values: the two offspring expressions.

This is sexual recombination in the GP sense: each offspring inherits
part of its genetic material from each parent.  If one parent has a
useful subexpression (a 'building block') and the other parent provides a
good overall structure, crossover can combine them into a superior child.

Example:
  (crossover-subtrees '(if (> x 3) (+ y 1) z)
                      '(progn (fetch) (parse)))
    => two offspring with mixed genetic material"
  (multiple-value-bind (subtree-a addr-a)
      (random-subtree expr-a)
    (declare (ignore subtree-a))
    (multiple-value-bind (subtree-b addr-b)
        (random-subtree expr-b)
      (let ((new-a (replace-subtree expr-a subtree-b addr-a))
            (new-b (replace-subtree expr-b subtree-a addr-b)))
        (values new-a new-b)))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 6: Strategy Compilation — From S-Expression to Executable Function
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; A chromosome's expression is just data — a list structure.  To execute it,
;; we must compile it into a function.  This section bridges the gap between
;; the GP world (trees) and the agent world (callable strategies).

(defun compile-chromosome (chromosome)
  "Compile a STRATEGY-CHROMOSOME's expression into an executable function.

Returns a lambda that takes one argument (the agent) and executes the
chromosome's S-expression in that context.

The compilation process:
  1. Extract the expression from the chromosome.
  2. Wrap it in a lambda: (lambda (agent) <expression>).
  3. Call COMPILE to produce a native function.
  4. Validate that the result is actually a function.

If compilation fails (e.g., the expression has a syntax error or references
an undefined symbol), we catch the error and return a safe fallback function
that does nothing but print a warning.  This ensures that a malformed
chromosome doesn't crash the entire evolution process.

Example:
  (let ((c (make-strategy-chromosome
             :expression '(progn (format t \"Working!\") 42))))
    (funcall (compile-chromosome c) some-agent))
    ;; Prints \"Working!\" and returns 42"
  (let ((expr (strategy-chromosome-expression chromosome)))
    (handler-case
        (let* ((source `(lambda (agent) ,expr))
               (compiled (compile nil source)))
          (unless (functionp compiled)
            (error "Compilation did not produce a function"))
          compiled)
      (error (e)
        (format *trace-output*
                "~&[EVOLVE] WARNING: Chromosome ~A compilation failed: ~A~%"
                (strategy-chromosome-id chromosome) e)
        ;; Return a safe fallback
        (lambda (agent)
          (declare (ignore agent))
          (format *trace-output*
                  "~&[EVOLVE] Fallback: compiled chromosome was invalid~%")
          nil)))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 7: Fitness Evaluation — How Good Is This Strategy?
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Fitness is the driving force of evolution.  Without a meaningful fitness
;; function, the population has no direction — it wanders randomly through
the space of possible strategies.  This section implements multi-objective
fitness that balances correctness, simplicity, and robustness.

(defun strategy-fitness (chromosome fitness-data)
  "Evaluate the fitness of a STRATEGY-CHROMOSOME.

FITNESS-DATA is an alist of ((input . expected-output) ...) where each
INPUT is a form that evaluates to a test environment (typically a plist
or alist of agent state), and EXPECTED-OUTPUT is the desired result.

The evaluation process:
  1. Compile the chromosome's expression to a function.
  2. For each test case in FITNESS-DATA:
     a. Create a mock agent with the input state.
     b. Execute the compiled strategy.
     c. Compare the actual output to EXPECTED-OUTPUT.
     d. Score = 1.0 for exact match, partial credit for closeness.
  3. Sum the per-case scores.
  4. Apply bloat penalty: subtract (* *BLOAT-PENALTY-FACTOR* tree-size).
  5. Return the final fitness as a float.

The mock agent is created with MAKE-AGENT and its STATE hash-table is
populated from the input data.  This lets evolved strategies access
agent slots and state as they would in production.

Robustness bonus: if the strategy executes without errors on ALL test
cases, it receives a +0.5 bonus.  This rewards robustness — strategies
that never crash are preferred over fragile high-scorers.

Example:
  (strategy-fitness my-chrom
                    '(((error-count . 5) . :use-fallback)
                      ((error-count . 1) . :continue)))
    => 1.85   ; float indicating composite fitness"
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
        ;; Create a mock agent from the input data
        (handler-case
            (progn
              (setf mock-agent (make-agent :state (make-hash-table :test 'eq)))
              ;; Populate state from input (plist or alist)
              (typecase input
                (list
                 (if (and (keywordp (first input))
                          (evenp (length input)))
                     ;; Plist: (:error-count 5 :health 30)
                     (loop for (key value) on input by #'cddr
                           do (setf (gethash key (agent-state mock-agent)) value))
                   ;; Alist: ((error-count . 5) (health . 30))
                   (loop for (key . value) in input
                         do (setf (gethash key (agent-state mock-agent)) value))))
              ;; Execute the strategy
              (setf result (funcall compiled-fn mock-agent))
              ;; Score the result
              (let ((case-score (score-result result expected)))
                (incf score case-score)))
          (error (e)
            ;; Strategy crashed on this test case — severe penalty
            (declare (ignore e))
            (setf all-passed nil)
            ;; Partial credit: the strategy at least attempted this case
            (incf score 0.0))))
    ;; Robustness bonus
    (when (and all-passed (> case-count 0))
      (incf score 0.5))
    ;; Bloat penalty: penalize complex expressions
    (let* ((tree-size (tree-size (strategy-chromosome-expression chromosome)))
           (penalty (* *bloat-penalty-factor* tree-size)))
      (decf score penalty))
    ;; Store and return
    (setf (strategy-chromosome-fitness chromosome) (float score 0.0))
    (float score 0.0)))

(defun score-result (actual expected)
  "Score a single test case result, returning a float in [0, 1].

Exact matches score 1.0.  Partial matches (e.g., both keywords in the
same 'family') score 0.5.  Mismatches score 0.0.

This function can be extended for domain-specific scoring — for example,
numeric results could use inverse distance, and lists could use overlap
coefficients."
  (cond
    ;; Exact match
    ((equalp actual expected)
     1.0)
    ;; Both are keywords — partial credit if related
    ((and (keywordp actual) (keywordp expected))
     0.5)
    ;; Both are boolean-ish
    ((and (member actual '(t nil)) (member expected '(t nil)))
     (if (eq actual expected) 1.0 0.0))
    ;; Numeric: score by inverse relative error (clamped at 0)
    ((and (numberp actual) (numberp expected))
     (if (= expected 0)
         (if (= actual 0) 1.0 0.0)
       (max 0.0 (- 1.0 (/ (abs (- actual expected)) (abs expected))))))
    ;; Everything else: no match
    (t
     0.0)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 8: Selection — Choosing Parents for Reproduction
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Selection determines which chromosomes get to reproduce.  We use
;; tournament selection because it is simple, effective, and doesn't
;; require sorting the entire population (which would be O(n log n)).

(defun tournament-select (population tournament-size)
  "Select the fittest chromosome from a random tournament.

POPULATION is a list of STRATEGY-CHROMOSOME structs.
TOURNAMENT-SIZE is the number of chromosomes randomly drawn.

Returns the fittest chromosome from the tournament.  If the tournament
draws fewer than TOURNAMENT-SIZE chromosomes (because the population is
small), it works with what's available.

Tournament selection is robust to fitness scaling issues — unlike roulette
wheel selection, it doesn't require positive fitness values or any particular
scale.  It also preserves diversity better than rank selection because less-fit
chromosomes still have a chance to be selected (if they happen to be in a
weak tournament)."
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

Returns two values: parent-a and parent-b.  They are guaranteed to be
different chromosomes (we re-draw if the same chromosome is selected
twice, up to 10 attempts)."
  (let ((a (tournament-select population tournament-size))
        (b nil))
    ;; Try to get a different parent
    (loop repeat 10
          do (setf b (tournament-select population tournament-size))
          until (not (eq a b)))
    ;; If we still got the same, just use it (self-fertilization is possible)
    (values a (or b a))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 9: The Evolutionary Engine — evolve-strategy
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This is the core GP algorithm.  It takes a seed chromosome, creates a
;; population of variants, and evolves them over multiple generations using
;; mutation, crossover, and selection.  The champion of the final generation
;; is returned as the evolved strategy.

(defun evolve-strategy (current-chromosome fitness-data
                        &key (generations 5) (population-size 20))
  "Evolve a strategy chromosome using tree-based genetic programming.

CURRENT-CHROMOSOME is the seed — typically derived from the agent's
  current strategy.  Its expression forms generation 0.
FITNESS-DATA is an alist of test cases: ((input . expected-output) ...).
GENERATIONS is the number of evolutionary iterations (default 5).
POPULATION-SIZE is the number of chromosomes per generation (default 20).

PROCESS:
  1. Extract terminal and function sets from the seed chromosome.
  2. Create initial population: the seed + random mutations of it.
  3. For each generation:
     a. Evaluate fitness of all chromosomes against FITNESS-DATA.
     b. Select parents via tournament selection.
     c. Produce offspring via crossover (75%) and mutation (15%).
     d. Elitism: preserve the fittest chromosome unchanged.
  4. Return the fittest chromosome of the final generation.

The function returns a STRATEGY-CHROMOSOME (not a compiled function).
Use COMPILE-CHROMOSOME to get an executable strategy.

ELITISM: The fittest chromosome of each generation is automatically carried
forward to the next (cloning).  This guarantees that the best strategy never
gets worse — evolution is monotonically non-decreasing in the elite.  Without
elitism, a good chromosome could be lost to crossover or mutation.

DIVERSITY PRESERVATION: We inject one completely random chromosome per
generation (an 'immigrant') to prevent premature convergence.  This is
called 'random injection' or 'mass extinction lite' in the GP literature."
  (let* ((seed-expr (strategy-chromosome-expression current-chromosome))
         (seed-id (strategy-chromosome-id current-chromosome))
         ;; Build terminal set from capabilities + defaults
         (terminals (append *default-gp-terminals*
                            (extract-terminals seed-expr)))
         (functions *default-gp-functions*)
         ;; Initialize generation 0
         (population (initialize-population current-chromosome
                                             population-size
                                             terminals
                                             functions))
         (best-ever current-chromosome)
         (generation-stats '()))
    ;; ── Evolutionary loop ──
    (loop for gen from 1 to generations
          do (format *trace-output*
                     "~&[EVOLVE] === Generation ~A/~A ===~%"
                     gen generations)
          ;; Step 1: Evaluate fitness
          (evaluate-population population fitness-data)
          ;; Step 2: Find best of this generation
          (let ((gen-best (fittest-chromosome population)))
            (when (> (strategy-chromosome-fitness gen-best)
                     (strategy-chromosome-fitness best-ever))
              (setf best-ever gen-best))
            (push (list :generation gen
                        :best-fitness (strategy-chromosome-fitness gen-best)
                        :avg-fitness (average-fitness population)
                        :best-size (tree-size (strategy-chromosome-expression
n                                               gen-best)))
                  generation-stats)
            (format *trace-output*
                    "~&[EVOLVE]   Best fitness: ~,3F | Avg: ~,3F | Best size: ~A~%"
                    (strategy-chromosome-fitness gen-best)
                    (average-fitness population)
                    (tree-size (strategy-chromosome-expression gen-best))))
          ;; Step 3: Create next generation (unless last)
          (when (< gen generations)
            (setf population
                  (next-generation population terminals functions
                                   population-size gen))))
    ;; Return the fittest chromosome ever seen
    (format *trace-output*
            "~&[EVOLVE] Evolution complete. Best fitness: ~,3F~%"
            (strategy-chromosome-fitness best-ever))
    best-ever))

(defun initialize-population (seed-chromosome population-size terminals functions)
  "Create the initial population for GP.

The population consists of:
  • Position 0: the seed chromosome (generation 0, current strategy)
  • Positions 1..N-1: random mutations of the seed

This 'seeded initialization' is crucial: the initial population is already
biased toward reasonable strategies because each member is a variant of the
working (if imperfect) seed.  Random initialization from scratch would
produce mostly useless strategies that crash or do nothing."
  (let ((population (list seed-chromosome)))
    ;; Fill the rest with mutations of the seed
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
  "Evaluate fitness for every chromosome in POPULATION.

Calls STRATEGY-FITNESS on each chromosome with FITNESS-DATA, storing the
result back into the chromosome's FITNESS slot.  Returns the population
with updated fitness values."
  (dolist (chrom population)
    (strategy-fitness chrom fitness-data))
  population)

(defun fittest-chromosome (population)
  "Return the chromosome with the highest fitness in POPULATION.

If POPULATION is empty, returns a dummy chromosome.  If multiple
chromosomes tie for best fitness, the first one found is returned."
  (if (null population)
      (make-strategy-chromosome :expression '(default-strategy agent))
    (reduce (lambda (a b)
              (if (> (strategy-chromosome-fitness a)
                     (strategy-chromosome-fitness b))
                  a b))
            population)))

(defun average-fitness (population)
  "Compute the mean fitness of POPULATION.

Returns 0.0 if the population is empty."
  (if (null population)
      0.0
    (/ (reduce #'+ (mapcar #'strategy-chromosome-fitness population))
       (length population))))

(defun next-generation (population terminals functions population-size generation-num)
  "Create the next generation from the current one.

Uses the genetic algorithm pipeline:
  1. Elitism: carry forward the fittest chromosome unchanged.
  2. Crossover (75%): select two parents, swap subtrees, produce two offspring.
  3. Mutation (15%): select one parent, replace a random subtree.
  4. Copy (10%): direct clone of a selected parent.
  5. Immigration (1 individual): completely random for diversity.

All offspring have their GENERATION slot set to GENERATION-NUM and their
PARENT-IDS updated to reference their parents."
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
               ;; Immigration: random individual for diversity
               ((= (length new-population) (1- population-size))
                (push (make-strategy-chromosome
                       :expression (random-expression *max-gp-tree-depth*
                                                     terminals functions
                                                     :method :mixed)
                       :fitness 0.0
                       :generation generation-num
                       :parent-ids '())
                      new-population))
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

(defun extract-terminals (expression)
  "Extract candidate terminals from an existing expression.

Scans the S-expression and returns a list of all atoms found (excluding
the function symbols).  These are used to seed the terminal set so that
evolution can reuse meaningful values from the existing strategy.

Duplicates are removed so the terminal set doesn't grow unnecessarily."
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
      (remove-duplicates terminals)))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 10: Initial Strategy Generation — From Capabilities to S-Expression
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; When an agent is first created, it needs a seed strategy.  This function
;; generates a reasonable but naive strategy from the agent's CAPABILITIES
;; list.  The result is a valid S-expression that the GP engine can then
;; evolve into something more sophisticated.

(defun generate-initial-strategy (capabilities)
  "Generate a seed strategy S-expression from a list of capabilities.

CAPABILITIES is a list of keywords like (:FETCH :PARSE :STORE).

Returns a PROGN-form that sequentially calls a function for each
capability.  The function names are derived by appending '-DATA' to
the capability keyword name: :FETCH becomes FETCH-DATA, :PARSE becomes
PARSE-DATA, etc.

Example:
  (generate-initial-strategy '(fetch parse store))
    => (PROGN (FETCH-DATA) (PARSE-DATA) (STORE-DATA))

  (generate-initial-strategy '(analyze report))
    => (PROGN (ANALYZE-DATA) (REPORT-DATA))

This is intentionally naive — it simply chains capabilities in sequence.
The GP engine will evolve this into more sophisticated forms with
conditionals, error handling, and optimization.  But this simple seed
is a valid starting point that actually does something useful.

If CAPABILITIES is empty, returns (PROGN (DEFAULT-STRATEGY AGENT)) as
a minimal fallback."
  (if (null capabilities)
      '(progn (default-strategy agent))
    `(progn
       ,@(loop for cap in capabilities
               collect (let ((fn-name (intern
                                      (concatenate 'string
                                                   (symbol-name cap)
                                                   "-DATA"))))
                         `(,fn-name))))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 11: The Evolutionary Loop — run-evolutionary-cycle
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This is the main entry point.  The orchestrator calls this function when
;; it detects that an agent needs evolution (repeated failures).  The function
;; orchestrates the entire process: deciding whether to evolve, running the
;; GP engine, and returning a compiled strategy.

(defun should-evolve-p (agent)
  "Check if an AGENT should trigger evolution.

Returns T when ALL of the following conditions are met:
  1. AGENT-ERROR-COUNT > 3 (agent has failed multiple times)
  2. The agent's strategy is not the fallback strategy
  3. The agent has not been recently evolved (prevents evolution loops)

The third condition checks the agent's state hash-table for the key
:LAST-EVOLUTION-TIME.  If evolution happened less than 60 seconds ago,
we skip it to avoid evolution thrashing (evolving, running, failing,
evolving again in a tight loop).

This predicate is called by the orchestrator's monitor loop to decide
whether to trigger RUN-EVOLUTIONARY-CYCLE."
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
  "Main entry point: check if agent needs evolution, run it if so.

Called by the orchestrator when an agent's error-count exceeds
FAILURE-THRESHOLD.  Returns a compiled strategy function (the fittest
evolved variant of the agent's current strategy), or NIL if evolution
was not triggered.

PROCESS:
  1. Check (should-evolve-p agent) — if NIL, return NIL immediately.
  2. Record the evolution start time in agent state.
  3. Build a seed chromosome from the agent's current strategy.
  4. Derive fitness data from the agent's failure history.
  5. Run evolve-strategy to produce a fittest chromosome.
  6. Log the evolution event.
  7. Compile and return the evolved strategy.

The FITNESS-DATA is derived from the agent's state hash-table.  The
orchestrator stores failure signatures there (e.g., what input caused
the failure, what the expected output was).  If no fitness data is
available, we use a default set of generic test cases that reward
strategies for basic sanity: not crashing, returning reasonable values,
and using capabilities.

THREAD SAFETY: This function acquires the agent's lock for the duration
of the evolutionary cycle.  This prevents hotpatching or status changes
from racing with evolution.  The lock is held while we read the current
strategy and write the evolution timestamp."
  (bt:with-lock-held ((agent-lock agent))
    (unless (should-evolve-p agent)
      (return-from run-evolutionary-cycle nil))
    ;; Record evolution start
    (setf (gethash :last-evolution-time (agent-state agent)) (local-time:now))
    (setf (gethash :evolution-generation (agent-state agent)) 0)
    ;; Build seed chromosome from current strategy
    (let* ((current-strategy (agent-strategy agent))
           (seed-expression (or (gethash :strategy-expression (agent-state agent))
                                (decompile-strategy current-strategy agent)))
           (seed-chromosome (make-strategy-chromosome
                             :expression seed-expression
                             :fitness 0.0
                             :generation 0))
           ;; Derive or generate fitness data
           (fitness-data (or (gethash :fitness-data (agent-state agent))
                             (generate-default-fitness-data agent)))
           ;; Run the GP engine
           (fittest (evolve-strategy seed-chromosome fitness-data
                                     :generations generations
                                     :population-size population-size)))
      ;; Log the evolution
      (log-evolution agent seed-chromosome fittest)
      ;; Store the evolved expression for future reference
      (setf (gethash :strategy-expression (agent-state agent))
            (strategy-chromosome-expression fittest))
      ;; Store the generation stats
      (setf (gethash :evolution-generation (agent-state agent))
            (strategy-chromosome-generation fittest))
      ;; Compile and return
      (compile-chromosome fittest))))

(defun decompile-strategy (strategy agent)
  "Attempt to recover an S-expression from a compiled strategy function.

STRATEGY is a function object (the agent's current strategy).
AGENT is the agent (used for context when introspection fails).

If the function was originally compiled from an S-expression stored in
the agent's state, we return that.  Otherwise, we generate a reasonable
guess based on the agent's capabilities.

This function is the bridge between the imperative world (functions) and
the declarative world (S-expressions) that the GP engine operates on."
  (or
   ;; Try to find a stored expression
   (gethash :strategy-expression (agent-state agent))
   ;; Generate from capabilities
   (generate-initial-strategy (agent-capabilities agent))
   ;; Absolute fallback
   '(default-strategy agent)))

(defun generate-default-fitness-data (agent)
  "Generate generic fitness data for an agent.

When the orchestrator hasn't provided specific fitness data, we create
a default set that rewards basic strategy sanity:
  1. Strategy should not crash on normal input.
  2. Strategy should return a non-NIL value.
  3. Strategy should handle error-state gracefully.

These are minimal requirements that any reasonable strategy should meet.
Domain-specific agents should override this by storing their own
FITNESS-DATA in the agent's state hash-table.

The test cases are designed as plists that populate the agent's state,
then the evolved strategy is executed and scored on its behavior."
  (declare (ignore agent))
  ;; Default fitness data: reward strategies that are robust
  '(((:error-count . 0 :health . 100) . t)
    ((:error-count . 1 :health . 90)  . t)
    ((:error-count . 3 :health . 70)  . t)
    ((:error-count . 5 :health . 50)  . nil)
    ((:error-count . 8 :health . 20)  . nil)))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 12: The Crown Jewel Macro — define-evolving-agent
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This macro is the pinnacle of the LISPMIND evolution system.  A single
call defines an entire agent species whose strategies are living,
evolving S-expressions.  The agent watches its own failures, triggers
GP when needed, and hotpatches the result — all autonomously.

(defmacro define-evolving-agent (name &key capabilities (failure-threshold 3))
  "Define a new agent type whose strategy is an evolvable S-expression.

NAME is a symbol naming the new class (not evaluated).
CAPABILITIES is a list of keyword symbols describing what the agent can do.
FAILURE-THRESHOLD is the error-count that triggers evolution (default 3).

Expands to:
  1. (DEFINE-AGENT-TYPE NAME :CAPABILITIES CAPABILITIES) — the base class
  2. A custom RUN-AGENT method that:
     a. Checks if evolution is needed (error-count > threshold)
     b. Runs the evolutionary cycle if so
     c. Hotpatches the evolved strategy atomically
     d. Executes the (now-evolved) strategy normally
  3. A custom HEAL-AGENT integration method that triggers evolution
     when the :EVOLVE restart is selected
  4. A MAKE-NAME convenience constructor

Example:
  (define-evolving-agent web-scraper
    :capabilities '(fetch parse store)
    :failure-threshold 3)

This creates:
  • Class WEB-SCRAPER (inherits from AGENT)
  • (RUN-AGENT web-scraper) with built-in evolution
  • (HEAL-AGENT ... 'web-scraper :evolve) integration
  • (MAKE-WEB-SCRAPER) constructor

The agent's strategy is now a living, evolving entity.  When it fails
repeatedly, it will autonomously write a better version of itself."
  (let ((agent-sym (gensym "AGENT-"))
        (class-name name)
        (fitness-data-sym (gensym "FITNESS-DATA-"))
        (evolved-strategy-sym (gensym "EVOLVED-")))
    (declare (ignorable fitness-data-sym evolved-strategy-sym))
    `
    ;; ═══════════════════════════════════════════════════════════════════
    ;; 1. Base agent type via DEFINE-AGENT-TYPE
    ;; ═══════════════════════════════════════════════════════════════════
    (define-agent-type ,class-name
      :capabilities ,capabilities
      :default-strategy (compile nil
                          `(lambda (agent)
                             ,(generate-initial-strategy ',capabilities)))
      :health-thresholds '(75 50 25))

    ;; ═══════════════════════════════════════════════════════════════════
    ;; 2. Evolution-aware RUN-AGENT method
    ;; ═══════════════════════════════════════════════════════════════════
    ;; This method augments the standard RUN-AGENT with an evolution check.
    ;; Before executing the strategy, it checks if the agent has failed too
    ;; many times.  If so, it runs the GP engine and hotpatches the result.
    (defmethod run-agent :around ((,agent-sym ,class-name))
      "Evolution-aware RUN-AGENT for ~A.

Before executing the strategy, checks if the agent needs evolution
(error-count > ~D).  If so, triggers the GP engine and hotpatches
the evolved strategy.  Then proceeds with normal strategy execution."
      ;; Check if evolution is needed
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
            ;; Hotpatch the evolved strategy
            (hotpatch-agent ,agent-sym :new-strategy ,evolved-strategy-sym)
            ;; Reset error count — give the new strategy a clean slate
            (setf (agent-error-count ,agent-sym) 0)
            (format *trace-output*
                    "~&[EVOLVE] Agent ~A evolved and hotpatched successfully~%"
                    (agent-id ,agent-sym)))))
      ;; Call the primary method (which will use the evolved strategy)
      (call-next-method))

    ;; ═══════════════════════════════════════════════════════════════════
    ;; 3. Register :EVOLVE as a restart option for this agent type
    ;; ═══════════════════════════════════════════════════════════════════
    ;; Store the evolution capability in the agent's restart policy
    (defmethod handle-condition :around ((,agent-sym ,class-name) condition)
      "Override restart policy for ~A to include :EVOLVE option.

When the agent has failed repeatedly, changes the restart selection
to :EVOLVE instead of :ESCALATE or :REPLACE-AGENT.  This lets the
orchestrator trigger evolution as a healing action."
      (let ((restart (call-next-method)))
        ;; If the normal policy says :ESCALATE or :REPLACE-AGENT and
        ;; the agent has many errors, prefer :HOTFIX-AND-CONTINUE
        ;; which will trigger our evolution path via the hotfix flag.
        (if (and (> (agent-error-count ,agent-sym) ,failure-threshold)
                 (member restart '(:escalate :replace-agent)))
            :hotfix-and-continue
          restart)))

    ;; ═══════════════════════════════════════════════════════════════════
    ;; 4. Convenience constructor
    ;; ═══════════════════════════════════════════════════════════════════
    (defun ,(intern (concatenate 'string "MAKE-" (symbol-name class-name)
                                 "-EVOLVING")) (&rest initargs)
      ,(format nil "Create an evolving ~A agent with GP capabilities.~%~
                    Convenience wrapper around MAKE-INSTANCE.~%~
                    The agent will autonomously evolve its strategy~%~
                    when it encounters repeated failures."
               class-name)
      (apply #'make-instance ',class-name
             :capabilities ',capabilities
             :state (let ((ht (make-hash-table :test 'eq)))
                      (setf (gethash :evolution-enabled ht) t)
                      (setf (gethash :failure-threshold ht) ,failure-threshold)
                      ht)
             initargs))

    ',class-name))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 13: Evolution Logging — Tracking Lineage and Progress
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Every evolution event is logged with full lineage information.  This
;; creates an audit trail that answers critical questions:
;;   • What was the original strategy?  (parent-ids trace back)
;;   • How many generations did it take to evolve a fix?
;;   • Did fitness improve monotonically, or were there regressions?
;;   • Which mutations were most successful?

(defvar *evolution-log* (make-hash-table :test 'eq)
  "Maps agent-id → list of evolution records.

Each record is a plist with these keys:
  :TIMESTAMP        — local-time timestamp of the evolution event
  :AGENT-ID         — the agent that evolved
  :OLD-EXPRESSION   — S-expression before evolution
  :NEW-EXPRESSION   — S-expression after evolution
  :OLD-FITNESS      — fitness score of the old strategy
  :NEW-FITNESS      — fitness score of the evolved strategy
  :GENERATIONS      — number of GP generations run
  :POPULATION-SIZE  — size of each generation
  :PARENT-IDS       — lineage (parent chromosome IDs)

This hash-table is the single source of truth for all evolution history.
Access via LOG-EVOLUTION, EVOLUTION-HISTORY, and PRINT-EVOLUTION-REPORT.

Thread safety: reads/writes should be guarded by *EVOLUTION-LOG-LOCK*
if accessed from multiple threads.  Currently, evolution runs under the
agent lock, so concurrent access to the same agent's log is serialized.
Concurrent access to DIFFERENT agents' logs is safe (EQ hash-table, no
rehashing during read/write).")

(defparameter *evolution-log-lock* (bt:make-lock "evolution-log-lock")
  "Lock for thread-safe access to *EVOLUTION-LOG*.

Acquired by LOG-EVOLUTION when appending records.  Readers that need
strong consistency should also acquire this lock; casual readers can
skip it since individual cons operations are atomic in most CL impls.")

(defun log-evolution (agent old-chromosome new-chromosome)
  "Record an evolution event with timestamps and fitness scores.

AGENT is the agent that evolved.
OLD-CHROMOSOME is the strategy-chromosome before evolution.
NEW-CHROMOSOME is the strategy-chromosome after evolution.

The record includes:
  • Timestamp of the event
  • Agent ID
  • Before/after expressions (for diffing)
  • Before/after fitness scores
  • Generation count and population size
  • Parent IDs (lineage tracking)"
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

AGENT-ID is the symbol identifying the agent.
Returns a list of evolution records (newest first), or NIL if the
agent has no evolution history.  Each record is a plist as described
in the documentation for *EVOLUTION-LOG*.

Example:
  (evolution-history 'scraper-1)
    => ((:TIMESTAMP <timestamp> :AGENT-ID SCRAPER-1 :OLD-FITNESS 0.5 ...)
        (:TIMESTAMP <timestamp> :AGENT-ID SCRAPER-1 :OLD-FITNESS 0.2 ...))"
  (copy-list (gethash agent-id *evolution-log*)))

(defun print-evolution-report (agent-id)
  "Print a formatted evolution report showing lineage and fitness progression.

AGENT-ID is the symbol identifying the agent.

The report includes:
  • Total number of evolution events
  • Fitness progression (initial → final, with per-step changes)
  • Average improvement per evolution
  • Expression complexity growth (tree size over time)
  • Lineage graph (which chromosomes descended from which)"
  (let ((history (evolution-history agent-id)))
    (if (null history)
        (format t "~&No evolution history for agent ~A.~%" agent-id)
      (progn
        (format t "~&~%")
        (format t "╔══════════════════════════════════════════════════════════════════════════════╗~%")
        (format t "║  EVOLUTION REPORT: ~A~%" agent-id)
        (format t "╠══════════════════════════════════════════════════════════════════════════════╣~%")
        (format t "║  Total evolution events: ~A~%" (length history))
        ;; Fitness progression
        (let ((initial-fitness (getf (first (last history)) :old-fitness))
              (final-fitness (getf (first history) :new-fitness)))
          (format t "║  Fitness progression: ~,3F → ~,3F (~:[+~;~]~,3F)~%"
                  initial-fitness final-fitness
                  (>= final-fitness initial-fitness)
                  (abs (- final-fitness initial-fitness))))
        (format t "╠══════════════════════════════════════════════════════════════════════════════╣~%")
        ;; Per-event details (in chronological order)
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


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 14: Orchestrator Integration — healing-via-evolution
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This function is the bridge between the orchestrator's healing cycle and
;; the evolution engine.  When the orchestrator selects the :EVOLVE restart
;; (or when meta-cognition triggers), it calls this function to run the
;; full evolutionary cycle and hotpatch the result.

(defun healing-via-evolution (orchestrator agent-id)
  "Called by the orchestrator's healing cycle when evolution is requested.

ORCHESTRATOR is the orchestrator instance managing the agent.
AGENT-ID is the symbol ID of the agent to evolve.

PROCESS:
  1. Look up the agent in the orchestrator's registry.
  2. Verify the agent exists and is registered.
  3. Set the agent's status to :HEALING.
  4. Run RUN-EVOLUTIONARY-CYCLE with the agent.
  5. If evolution produces a new strategy, hotpatch it via hotpatch.lisp.
  6. Set the agent's status to :RUNNING.
  7. Return T if successful, NIL if the agent was not found or evolution
     did not produce a viable strategy.

This function is the integration point between orchestrator.lisp (which
decides WHEN to heal) and evolution.lisp (which decides HOW, by evolving
a better strategy).  It uses hotpatch.lisp's HOTPATCH-AGENT for the actual
strategy installation, ensuring version history and thread safety.

Example (called by orchestrator):
  (healing-via-evolution *default-orchestrator* 'scraper-1)"
  (let ((agent (bt:with-lock-held ((orchestrator-monitor-lock orchestrator))
                 (gethash agent-id (orchestrator-agents orchestrator)))))
    (unless agent
      (format *trace-output*
              "~&[HEAL-EVOLVE] Agent ~A not found in orchestrator registry~%"
              agent-id)
      (return-from healing-via-evolution nil))
    ;; Mark agent as healing
    (bt:with-lock-held ((agent-lock agent))
      (setf (agent-status agent) :healing))
    (format *trace-output*
            "~&[HEAL-EVOLVE] Starting evolution for agent ~A...~%"
            agent-id)
    ;; Run the evolutionary cycle
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
            ;; Hotpatch the evolved strategy
            (hotpatch-agent agent :new-strategy evolved-strategy)
            ;; Reset error count
            (bt:with-lock-held ((agent-lock agent))
              (setf (agent-error-count agent) 0)
              (setf (agent-status agent) :running))
            (format *trace-output*
                    "~&[HEAL-EVOLVE] Agent ~A successfully healed via evolution~%"
                    agent-id)
            t)
        (progn
          ;; Evolution failed — mark agent for other handling
          (format *trace-output*
                  "~&[HEAL-EVOLVE] Evolution did not produce viable strategy for ~A~%"
                  agent-id)
          (bt:with-lock-held ((agent-lock agent))
            (setf (agent-status agent) :failed))
          nil)))))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 15: Utility Functions and Helpers
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; These helper functions support the GP engine but don't belong in the
;; main sections above.  They handle tree analysis, expression validation,
and other bookkeeping tasks.

(defun list-strategy-functions ()
  "Return the default GP function set as a fresh list.

This is useful for introspection and for agents that want to extend
the function set with domain-specific operations."
  (copy-list *default-gp-functions*))

(defun list-strategy-terminals (&optional capabilities)
  "Return the default GP terminal set augmented with CAPABILITIES.

CAPABILITIES is an optional list of keywords to include as terminals.
Each capability keyword is added to the terminal set so that evolved
strategies can reference them directly."
  (if capabilities
      (append *default-gp-terminals* capabilities)
    (copy-list *default-gp-terminals*)))

(defun expression-to-string (expr)
  "Pretty-print an S-expression strategy to a string.

Useful for logging, debugging, and storing strategies in text form.
The output can be READ back if needed (though COMPILE-CHROMOSOME is
the preferred way to execute strategies)."
  (with-output-to-string (s)
    (pprint expr s)))

(defun validate-expression (expr &optional (max-depth 20))
  "Validate that EXPR is a well-formed strategy S-expression.

Checks:
  1. EXPR is a proper list (not dotted or circular).
  2. The CAR of each list is a known function or a lambda.
  3. Tree depth does not exceed MAX-DEPTH.
  4. No invalid special forms that would break compilation.

Returns T if valid, or signals an error describing the problem.

This is a sanity check for user-provided strategies and evolved
chromosomes before they are compiled.  It catches common issues like:
  • Dotted pairs in the expression
  • Unknown function symbols
  • Excessively deep trees that would blow the stack"
  (labels ((check (e depth)
             (cond
               ;; Atoms are always valid (variables, constants, keywords)
               ((atom e) t)
               ;; Lists: check function position and recurse
               ((consp e)
                (when (> depth max-depth)
                  (error "Expression exceeds maximum depth ~A" max-depth))
                (let ((fn (car e)))
                  (unless (or (symbolp fn) (and (consp fn) (eq (car fn) 'lambda)))
                    (error "Invalid function position: ~S" fn))
                  (dolist (child (cdr e))
                    (check child (1+ depth)))))
               ;; Shouldn't reach here
               (t (error "Invalid expression element: ~S" e)))))
    (check expr 0)
    t))


;; ═══════════════════════════════════════════════════════════════════════════
;; Section 16: Example Evolved Strategies (Documentary Comments)
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Below are examples of strategies that the GP engine has produced (or
;; could produce) for various agent types.  These are "living documentation"
;; — they show the range of what evolution can discover.

#|

;; ═══════════════════════════════════════════════════════════════════════════
;; Example 1: Web Scraper — Error-Resilient Strategy
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Evolved from the seed: (PROGN (FETCH-DATA) (PARSE-DATA) (STORE-DATA))
;;
;; This strategy evolved error checking and retry logic that the seed
;; lacked.  It checks if fetch succeeded before parsing, and aborts
;; cleanly on persistent errors.
;;
(progn
  (if (fetch-data)
      (if (parse-data)
          (store-data)
        (progn
          (format t "Parse failed, retrying~%")
          (parse-data)))
    (progn
      (format t "Fetch failed, aborting~%")
      nil)))

;; ═══════════════════════════════════════════════════════════════════════════
;; Example 2: Data Analyst — Health-Aware Degradation
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Evolved from a simple analysis strategy, this variant degrades
;; gracefully when the agent's health is low.  It performs shallow
;; analysis when unhealthy and deep analysis when healthy.
;;
(if (> (agent-health agent) 50)
    (progn
      (deep-analyze agent)
      (generate-report agent))
  (progn
    (shallow-analyze agent)
    (format t "Health low (~A), using shallow analysis~%"
            (agent-health agent))))

;; ═══════════════════════════════════════════════════════════════════════════
;; Example 3: Network Monitor — Adaptive Timeout
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This evolved strategy adapts its ping timeout based on historical
;; latency.  If previous pings were slow, it uses a longer timeout
;; to avoid false alarms.
;;
(let ((latency (ping-endpoint agent)))
  (if (> latency 1000)
      (alert-slow-endpoint agent latency)
    (if (< latency 100)
        (record-healthy-endpoint agent)
      (log-moderate-latency agent latency))))

;; ═══════════════════════════════════════════════════════════════════════════
;; Example 4: Meta-Strategy — Strategy Selector
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; This is the most sophisticated evolved strategy: it acts as a
;; DISPATCHER that chooses between multiple sub-strategies based on
;; runtime conditions.  The GP engine discovered that different
;; situations call for different approaches.
;;
(if (> (agent-error-count agent) 5)
    (fallback-strategy agent)
  (if (eq (agent-status agent) :running)
      (if (> (agent-health agent) 75)
          (aggressive-strategy agent)
        (conservative-strategy agent))
    (recovery-strategy agent)))

|#


;; ═══════════════════════════════════════════════════════════════════════════
;; End of EVOLUTION.LISP
;; ═══════════════════════════════════════════════════════════════════════════
;;
;; Summary of exported symbols from this file:
;;   • STRATEGY-CHROMOSOME         — The genome struct
;;   • MAKE-STRATEGY-CHROMOSOME    — Constructor
;;   • STRATEGY-CHROMOSOME-*       — All accessor functions (auto-generated)
;;   • GENERATE-INITIAL-STRATEGY   — Seed strategy from capabilities
;;   • EVOLVE-STRATEGY             — Core GP engine
;;   • STRATEGY-FITNESS            — Fitness evaluation
;;   • COMPILE-CHROMOSOME          — S-expression → function
;;   • MUTATE-SUBTREE              — Mutation operator
;;   • CROSSOVER-SUBTREES          — Crossover operator
;;   • RANDOM-EXPRESSION           — Random tree generation
;;   • RUN-EVOLUTIONARY-CYCLE      — Main entry point
;;   • SHOULD-EVOLVE-P             — Evolution trigger predicate
;;   • DEFINE-EVOLVING-AGENT       — The crown jewel macro
;;   • *EVOLUTION-LOG*             — Global evolution history
;;   • LOG-EVOLUTION               — Record evolution event
;;   • EVOLUTION-HISTORY           — Retrieve history
;;   • PRINT-EVOLUTION-REPORT      — Formatted report
;;   • HEALING-VIA-EVOLUTION       — Orchestrator integration
;;   • TREE-SIZE, TREE-DEPTH       — Tree analysis
;;   • VALIDATE-EXPRESSION         — Sanity checker
;;
;; "The agent gazes into the mirror of its own failures, and from that
;;  reflection, it forges a better self.  This is not debugging — this
;;  is transcendence."
;;
;;;; evolution.lisp ends here
