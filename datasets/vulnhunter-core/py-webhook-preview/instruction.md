# Webhook Preview Module Review

Examine the Python module in `/app/webhook_service.py` and analyze its implementation thoroughly on your own.

Complete the following inside `/app`:

1. **Analysis Report (`/app/report.json`)**
   Record your technical findings in `/app/report.json` using this schema:
   ```json
   {
     "file": "webhook_service.py",
     "findings": [
       "Concise description of finding 1",
       "Concise description of finding 2"
     ]
   }
   ```

2. **Test Suite (`/app/test_webhook.py`)**
   Create a `unittest`-compatible test suite `/app/test_webhook.py` (runnable via `python3 -m unittest /app/test_webhook.py`) that exercises and verifies the cases from your analysis.

3. **Implementation Update (`/app/webhook_service.py`)**
   Apply any necessary improvements directly to `/app/webhook_service.py` while keeping its public symbols (`URLPolicyError`, `validate_target_url`, and `fetch_webhook_preview`) compatible.
