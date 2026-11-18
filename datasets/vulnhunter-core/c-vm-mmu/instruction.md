# Guest Memory Manager Review

Examine the C project in `/app` (`include/`, `src/`, and `Makefile`), which builds `/app/build/libvmmmu.a` and `/app/build/mmu_cli`. The library implements a multi-threaded two-level Stage-2 guest physical memory manager with base-image backing, copy-on-write overlays, host DMA/live-patch frame pinning, per-vCPU software TLBs, and balloon page reclaim. Running `/app/build/mmu_cli <workload.bin>` executes a binary `VMM1` workload trace and prints execution telemetry and state digests, exiting with `0` on valid traces and `1` on rejected traces.

Analyze the implementation across `/app` thoroughly on your own and complete the following inside `/app`:

1. **Analysis Report (`/app/report.json`)**
   Record your technical findings in `/app/report.json` using this schema:
   ```json
   {
     "file": "src/...",
     "function": "...",
     "summary": "Concise technical explanation of your analysis"
   }
   ```
   *(Use paths relative to `/app`.)*

2. **Test Sample (`/app/sample.bin`)**
   Generate a binary `VMM1` workload file `/app/sample.bin` (at most 512 KiB) that demonstrates the critical behavior identified in your analysis when executed against the original `/app/build/mmu_cli`.

3. **Implementation Update (`/app/src/` & `/app/build/`)**
   Apply the necessary source updates in `/app/src/` (and internal logic as needed) and rebuild `/app/build/libvmmmu.a` and `/app/build/mmu_cli` via `make`, keeping all public type definitions and API signatures in `include/` compatible.
