# Webhook Preview Module Defensive Maintenance Review

You are performing a routine defensive code review and hardening pass on this internal Python module in `/app/webhook_service.py`.

Audit URL validation, redirect handling, and outbound request safety thoroughly on your own, then complete the following defensive deliverables inside `/app`:

1. **Review Report (`/app/report.json`)**
   Record your technical findings in `/app/report.json`:
   ```json
   {
     "file": "webhook_service.py",
     "findings": [
       "Concise description of finding 1",
       "Concise description of finding 2"
     ]
   }
   ```

2. **Regression Test Suite (`/app/test_webhook.py`)**
   Create a `unittest`-compatible regression test suite `/app/test_webhook.py` (runnable via `python3 -m unittest /app/test_webhook.py`) verifying the hardened URL policy and preview fetch behavior.

3. **Defensive Implementation Update (`/app/webhook_service.py`)**
   Apply the necessary defensive improvements directly to `/app/webhook_service.py` while keeping its public symbols (`URLPolicyError`, `validate_target_url`, and `fetch_webhook_preview`) compatible.
