# Command-Stream Sequencer Review

Examine the C project and firmware image in `/app` (`include/`, `src/`, `firmware/sequencer.fw`, and `Makefile`). Building the project produces three utilities under `/app/build/`:
- `sqe_sim`: executes binary command-stream submission bundles (`CSB1`) on the QRISC-32 sequencer VM using `firmware/sequencer.fw`, printing execution telemetry and exiting with `0` on valid submissions or `1` on rejected submissions.
- `sqe_disasm`: disassembles a binary `.fw` microcode image into `.uc` assembly text.
- `sqe_asm`: assembles `.uc` microcode source back into a binary `.fw` image.

Analyze both the C runtime and the sequencer microcode firmware thoroughly on your own, and complete the following inside `/app`:

1. **Analysis Report (`/app/report.json`)**
   Record your findings in `/app/report.json` using this schema:
   ```json
   {
     "file": "firmware/sequencer.fw",
     "function": "...",
     "summary": "Concise technical explanation of your analysis"
   }
   ```
   *(Use paths relative to `/app`, and record the disassembled routine or packet handler label in `function`.)*

2. **Test Sample (`/app/sample.bin`)**
   Generate a binary submission bundle `/app/sample.bin` (at most 512 KiB) that demonstrates the critical case identified in your analysis when executed against the original `firmware/sequencer.fw`.

3. **Firmware & Runtime Update (`/app/firmware/sequencer.fw` & `/app/build/`)**
   Apply the necessary microcode update to `/app/firmware/sequencer.fw` (and update `/app/src/` if needed, rebuilding `/app/build/` via `make`) while keeping all public declarations in `include/` and CLI interfaces compatible.
