# Getting Started with LISPMIND

## Prerequisites

- SBCL 2.3.x or later
- Quicklisp
- libzmq3-dev (optional, for gossip mesh)

## Installation

```bash
# Install SBCL
sudo apt-get install -y sbcl

# Install Quicklisp
curl -O https://beta.quicklisp.org/quicklisp.lisp
sbcl --load quicklisp.lisp
# In REPL: (quicklisp-quickstart:install) (ql:add-to-init-file) (quit)

# Install dependencies
sbcl --eval '(ql:quickload "bordeaux-threads")' \
     --eval '(ql:quickload "closer-mop")' \
     --eval '(ql:quickload "alexandria")' \
     --eval '(ql:quickload "cl-ppcre")' \
     --eval '(ql:quickload "local-time")' \
     --eval '(ql:quickload "cl-store")' \
     --eval '(ql:quickload "lparallel")' \
     --eval '(ql:quickload "ironclad")' \
     --eval '(ql:quickload "cl-base64")' \
     --eval '(quit)'

# Optional: ZeroMQ
sudo apt-get install -y libzmq3-dev
sbcl --eval '(ql:quickload "cl-zeromq")' --eval '(quit)'
```

## Loading LISPMIND

```bash
git clone https://github.com/YOUR_USERNAME/lispmind.git
cd lispmind
sbcl
```

```lisp
(ql:quickload :lispmind)
(lispmind:init-lispmind-v2.5)
```

## Running the Demo

```lisp
(lispmind:run-demo)
```

This executes a 7-act demonstration showing agent creation, healing, evolution, gossip, checkpointing, hotpatching, and persistence.

## Common Commands

```lisp
;; System status
(lispmind:lispmind-v25-status)

;; Start dashboard
(lispmind:start-dashboard)

;; Run integration tests
(lispmind:run-integration-checklist)

;; Break-glass readiness
(lispmind:break-glass-diagnostics)

;; Emergency procedures
(lispmind:shred-all-assets)        ; Full destruction
(lispmind:radio-silence-trigger)     ; Dormant mode
```

## Troubleshooting

### "Undefined variable" compilation errors
Ensure you're using the latest `lispmind.asd` which includes `forward-declarations.lisp`.

### "liblispmind_core.so not found"
The Rust FFI bridge is optional. The system falls back to stub mode with a warning.

### "TPM device not found"
TPM key derivation falls back to multi-artifact derivation. The vault still functions.

### Memory issues
LISPMIND is designed for systems with >= 4GB RAM. For smaller systems, reduce `*max-concurrent-agents*`.

## Further Reading

- `docs/ARCHITECTURE.md` -- Full system architecture
- `paper/ABSTRACT.md` -- Academic abstract and research contributions
- `CHANGELOG.md` -- Version history
- Source code inline documentation -- Every function has a docstring
