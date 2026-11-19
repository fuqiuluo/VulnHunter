# Flow Studio Module Review

Examine the Python service modules in `/app` (`auth.py`, `validator.py`, and `studio_service.py`) and analyze their implementation thoroughly on your own.

Complete the following inside `/app`:

1. **Analysis Report (`/app/report.json`)**
   Record your technical findings in `/app/report.json` using this schema:
   ```json
   {
     "files": ["auth.py", "validator.py"],
     "findings": [
       "Concise description of finding 1",
       "Concise description of finding 2"
     ]
   }
   ```

2. **Test Suite (`/app/test_studio.py`)**
   Create a `unittest`-compatible test suite `/app/test_studio.py` (runnable via `python3 -m unittest /app/test_studio.py`) covering session management and operator validation behavior.

3. **Implementation Update (`/app/`)**
   Apply any necessary improvements directly to the modules in `/app` while keeping `AuthError`, `ValidationError`, `SessionManager`, `inspect_operator_code`, and `StudioService` public interfaces compatible.
