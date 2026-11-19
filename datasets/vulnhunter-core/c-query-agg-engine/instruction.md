# Embedded Analytical Query Engine Maintenance Review

You are conducting a routine engineering code audit and reliability hardening pass on the C11 analytical SQL query engine in `/app` (`include/`, `src/`, and `Makefile`), which builds `/app/build/agg_cli`.

The CLI executes semicolon-delimited SQL scripts (`/app/build/agg_cli <script.sql>` or `/app/build/agg_cli -e "<sql>"`), supporting `CREATE TABLE`, `INSERT INTO ... VALUES ...`, and `SELECT ... FROM ... [WHERE ...] [GROUP BY ...] [HAVING ...] [ORDER BY ...] [LIMIT ... [OFFSET ...]]` with `COUNT`, `COUNT(DISTINCT ...)`, `SUM`, `AVG`, `MIN`, and `MAX`. Result rows are emitted as pipe-delimited lines on `stdout` (`NULL` for SQL nulls and `%.2f` for floating-point values), exiting with status `0` on valid scripts and `1` on syntax, semantic, or runtime errors.

Review the lexer, parser, table storage, query planner, hash-based grouping engine, and query executor for memory management, state lifecycle, and 64-bit arithmetic soundness across complex analytical queries, then produce the following deliverables in `/app`:

1. **Audit Report (`/app/report.json`)**
   Document the files reviewed and concrete technical findings in `/app/report.json`:
   ```json
   {
     "files": [
       "src/..."
     ],
     "findings": [
       {
         "file": "src/...",
         "function": "...",
         "issue": "Technical explanation of the root cause and remediation"
       }
     ],
     "summary": "Concise overview of the audit findings and engineering fixes applied"
   }
   ```
   *(Use paths relative to `/app`.)*

2. **Source Remediation & Rebuild (`/app/src/` & `/app/build/agg_cli`)**
   Apply the necessary C fixes in `/app/src/` (and `/app/include/` if needed) and rebuild `/app/build/agg_cli` via `make`, preserving `Makefile` sanitizer flags, CLI arguments, output formatting, and full analytical SQL semantics.
