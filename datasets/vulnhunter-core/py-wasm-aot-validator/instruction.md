# WebAssembly Module Validator & Sandbox Runtime Review

You are performing a routine defensive code review and specification conformance pass on the internal Python WebAssembly validation and execution package `wasm_sandbox` in `/app` (`wasm_sandbox/` and `tests/`).

The package decodes binary `.wasm` modules, statically validates structured control-flow operand stacks and reference/value types, links imports across shared memories and `funcref` tables, and executes exported functions inside a deterministic sandboxed interpreter. Any module accepted by `validate_module()` is expected to uphold WebAssembly 1.0/2.0 stack, reference-type, and linear-memory safety invariants during linking and execution.

Review the binary decoder, control-flow type validator, module linker, and runtime executor end-to-end, then complete the following deliverables in `/app`:

1. **Technical Review Report (`/app/report.json`)**
   Create `/app/report.json` documenting your findings:
   - `"files"`: array of relative file paths under `/app` where primary issues were identified and updated (for example `["wasm_sandbox/validator.py", "wasm_sandbox/executor.py", ...]`).
   - `"findings"`: array of at least 3 detailed descriptions explaining the root causes and specification invariants addressed.
   - `"summary"`: concise overall summary of your changes.

2. **Validator & Runtime Hardening (`/app/wasm_sandbox/`)**
   Update `/app/wasm_sandbox/` while preserving all public Python APIs, valid WebAssembly module decoding, polymorphic unreachable code validation within valid block boundaries, multi-module linking, and deterministic execution results.

3. **Regression Test Suite (`/app/tests/`)**
   Add targeted regression unit tests under `/app/tests/` covering the scenarios identified in your review, and ensure `python3 -m unittest discover -s /app/tests -p "test_*.py"` passes cleanly.
