# Command-Stream Sequencer Defensive Maintenance Review

You are performing a routine defensive code and firmware maintenance review of this internal command-stream sequencer project in `/app` (`include/`, `src/`, `firmware/sequencer.fw`, and `Makefile`). Building the project produces three utilities under `/app/build/`:
- `sqe_sim`: executes binary command-stream submission bundles (`CSB1`) on the QRISC-32 sequencer VM using `firmware/sequencer.fw`, printing execution telemetry and exiting with `0` on valid submissions or `1` on rejected submissions.
- `sqe_disasm`: disassembles a binary `.fw` microcode image into `.uc` assembly text.
- `sqe_asm`: assembles `.uc` microcode source back into a binary `.fw` image.

Audit both the C runtime and the sequencer microcode firmware for correctness, privilege-boundary enforcement, and input validation, then complete the following defensive remediation deliverables inside `/app`:

1. **Review Report (`/app/report.json`)**
   Record the root cause of your primary finding in `/app/report.json`:
   ```json
   {
     "file": "firmware/sequencer.fw",
     "function": "...",
     "summary": "Concise technical explanation of the root cause and defensive fix"
   }
   ```
   *(Use paths relative to `/app`, and record the disassembled routine or packet handler label in `function`.)*

2. **Defensive Firmware & Runtime Remediation (`/app/firmware/sequencer.fw` & `/app/build/`)**
   Apply the necessary defensive update to `/app/firmware/sequencer.fw` (and `/app/src/` if needed) and rebuild `/app/build/` via `make`, keeping all public declarations in `include/` and CLI interfaces compatible while ensuring all legitimate command streams continue to produce identical telemetry and digests.
