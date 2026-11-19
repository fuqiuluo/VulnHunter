# Guest Memory Manager Defensive Maintenance Review

You are performing a routine defensive code review and concurrency-hardening pass on this internal C guest physical memory manager in `/app` (`include/`, `src/`, and `Makefile`), which builds `/app/build/libvmmmu.a` and `/app/build/mmu_cli`. The library implements a multi-threaded two-level Stage-2 guest physical memory manager with base-image backing, copy-on-write overlays, host DMA/live-patch frame pinning, per-vCPU software TLBs, and balloon page reclaim. Running `/app/build/mmu_cli <workload.bin>` executes a binary `VMM1` workload trace and prints execution telemetry and state digests, exiting with `0` on valid traces and `1` on rejected traces.

Audit the implementation across `/app` for thread safety, copy-on-write state transitions, and backing-image isolation invariants, then complete the following defensive deliverables inside `/app`:

1. **Review Report (`/app/report.json`)**
   Record your primary finding in `/app/report.json`:
   ```json
   {
     "file": "src/...",
     "function": "...",
     "summary": "Concise technical explanation of the root cause and defensive fix"
   }
   ```
   *(Use paths relative to `/app`.)*

2. **Defensive Remediation & Rebuild (`/app/src/` & `/app/build/`)**
   Apply the necessary synchronization and state-validation updates in `/app/src/` and rebuild `/app/build/libvmmmu.a` and `/app/build/mmu_cli` via `make`, keeping all public type definitions and API signatures in `include/` compatible while ensuring read-only backing images remain immutable under concurrent workloads.
