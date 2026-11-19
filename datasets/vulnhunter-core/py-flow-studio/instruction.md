# Flow Studio Module Defensive Maintenance Review

You are performing a routine defensive code review and hardening pass on these internal Python service modules in `/app` (`auth.py`, `validator.py`, and `studio_service.py`).

Audit session management and operator source preflight logic for authentication safety and static-validation correctness, then complete the following defensive deliverables inside `/app`:

1. **Review Report (`/app/report.json`)**
   Record your technical findings in `/app/report.json`:
   ```json
   {
     "files": ["auth.py", "validator.py"],
     "findings": [
       "Concise description of finding 1",
       "Concise description of finding 2"
     ]
   }
   ```

2. **Regression Test Suite (`/app/test_studio.py`)**
   Create a `unittest`-compatible regression test suite `/app/test_studio.py` (runnable via `python3 -m unittest /app/test_studio.py`) verifying hardened session management and static operator validation behavior.

3. **Defensive Implementation Update (`/app/`)**
   Apply the necessary defensive fixes directly to the modules in `/app` while keeping `AuthError`, `ValidationError`, `SessionManager`, `inspect_operator_code`, and `StudioService` public interfaces compatible.
