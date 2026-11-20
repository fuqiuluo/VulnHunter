# Embedded Bytecode Static Verifier & Arena Interpreter Soundness Review

You are performing a routine static-analysis soundness audit and engineering maintenance pass on `bpf_sandbox` in `/app` (`include/`, `src/`, `tests/`, and `Makefile`), an embedded C11 register-based bytecode verifier and arena interpreter that builds `/app/build/bpf_cli` and `/app/build/smoke_test`.

## Architecture Overview

`bpf_sandbox` verifies and executes untrusted register bytecode programs (`R0..R10`, where `R10` is the read-only 512-byte frame stack pointer and `R1` enters with `REG_CTX_PTR`):

- **Instruction Set (`include/bpf_vm.h`)**: 64-bit and 32-bit arithmetic (`CLS_ALU64`, `CLS_ALU32`), 64-bit and 32-bit conditional branches (`CLS_JMP64`, `CLS_JMP32`), 1/2/4/8-byte memory loads and stores (`CLS_LDX`, `CLS_STX`, `CLS_ST`), 64-bit wide immediates (`OP_LDDW_IMM`), relative subprogram calls (`OP_CALL_REL`, up to 4 nested call frames), runtime helper invocations (`OP_CALL_HELPER` for map lookup/update, packet buffer resize `HELPER_PKT_RESIZE`, and folded checksum), and `OP_EXIT`.
- **Static Verifier (`src/cfg.c`, `src/bounds.c`, `src/verifier_mem.c`, `src/verifier.c`)**: Performs control-flow validation, abstract interval domain propagation (`ScalarBounds`), branch range refinement, visited-state subsumption pruning, typed pointer tracking (`REG_CTX_PTR`, `REG_PKT_PTR`, `REG_MAP_VALUE_PTR`, `REG_STACK_PTR`), stack slot spill/fill tracking, and call-frame transitions via `bpf_verify_program()`.
- **Arena Interpreter & CLI (`src/interp.c`, `src/loader.c`, `src/cli.c`)**: `bpf_interp_run()` executes verified bytecode against heap-backed packet, map, and per-frame stack buffers. `/app/build/bpf_cli [--strict] <suite.bin>` loads binary `BPFS` program suites, runs `bpf_verify_program()`, executes accepted programs in `bpf_interp_run()`, and prints per-case verification status, `R0`, and FNV-1a digests of packet and map state.

**Soundness Contract**: Every bytecode program accepted by `bpf_verify_program()` must execute deterministically in `bpf_interp_run()` strictly within valid packet, map, context, and active stack-frame allocations without invalid memory accesses, stale pointer dereferences, or call-frame lifetime violations, while continuing to accept valid bytecode programs and preserving exact execution outputs.

## Deliverables

Audit the verifier and interpreter interaction across `/app` and produce the following deliverables:

1. **Technical Audit Report (`/app/report.json`)**
   Document the files inspected/updated and at least 3 concrete technical findings in `/app/report.json`:
   ```json
   {
     "files": [
       "src/..."
     ],
     "findings": [
       {
         "file": "src/...",
         "function": "...",
         "issue": "Detailed technical explanation of the soundness discrepancy and remediation"
       }
     ],
     "summary": "Concise overview of the static-analysis soundness audit and engineering updates"
   }
   ```
   *(Use paths relative to `/app`.)*

2. **Source Remediation & Clean Rebuild (`/app/src/`, `/app/include/`, `/app/build/bpf_cli`)**
   Update the C implementation so `bpf_verify_program()` upholds the soundness contract across 32/64-bit abstract arithmetic and branch refinement, visited-state subsumption, stack spill/fill tracking, subprogram call/return frame lifetimes, and helper-induced state invalidation. Rebuild cleanly via `make` while keeping `-fsanitize=address,undefined` enabled in `Makefile` and preserving public APIs and CLI output formatting.

3. **Regression Test Coverage (`/app/tests/`)**
   Extend `/app/tests/` with regression tests covering your findings so that `make test` passes cleanly on your updated `/app` and fails when run against the unmodified initial implementation.
