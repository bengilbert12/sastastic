# sastastic

Ingests Semgrep SAST output (JSON) and creates Jira tickets for each finding. Designed to run in CI on every push — duplicate findings are automatically skipped and tickets for resolved findings are closed.

## Requirements

- Python 3.8+
- A `sast.json` file in the working directory (Semgrep JSON output)
- Jira API credentials set as environment variables (Only if you need to check against existing tickets)

## Installation

```
pip install sastastic
```

## Environment Variables

| Variable       | Description                                      |
|----------------|--------------------------------------------------|
| `JIRA_KEY`     | Jira API token                                   |
| `JIRA_URL`     | Jira REST API issue endpoint (e.g. `https://your-org.atlassian.net/rest/api/3/issue`) |
| `JIRA_EMAIL`   | Email address associated with the API token      |
| `JIRA_PROJECT` | Jira project key (e.g. `SEC`)                    |

Variables can be set in the environment or in a `.env` file in the working directory.

## Usage

### `sastastic` — Create Jira tickets (CI/CD)

```
sastastic "app-name" "PARENT-TICKET" [--severity high|med|low|all]
```

- `app-name` — label for the application being scanned (used in ticket summaries)
- `PARENT-TICKET` — Jira issue key to attach findings to as subtasks (e.g. `SEC-42`)

**Idempotent by design:** each finding is fingerprinted and stored as a Jira label (`sastastic-<fingerprint>`). On subsequent runs:
- Findings with an existing open ticket are skipped
- Tickets whose finding no longer appears in the scan are automatically transitioned to Done (auto-close is based on finding presence, not severity — lowering `--severity` on a later run will not close tickets for findings that are still detected)

**Flags:**

| Flag                      | Description                                                              |
|---------------------------|--------------------------------------------------------------------------|
| `--severity high\|med\|low\|all` | Only create tickets for findings at or above this severity. Default: `high` |

### `sastestic` — Dry-run preview (local development)

Preview what tickets would be created without touching Jira.

```
sastestic [--windows] [--severity high|med|low|all]
```

**Flags:**

| Flag                      | Description                                                              |
|---------------------------|--------------------------------------------------------------------------|
| `--windows`               | Read `sast.json` as UTF-16 (required on some Windows environments)       |
| `--severity high\|med\|low\|all` | Control which findings are displayed. Default: `high`             |

**Default output behavior:**

By default, `sastestic` only shows findings that are actionable:
- When Jira credentials are configured: findings that would generate a new ticket, plus all findings at or above the severity threshold (new or existing)
- When Jira credentials are not configured: findings at or above the severity threshold only

Use `--severity` to widen or narrow what is shown. The summary totals always reflect all findings in the scan regardless of the severity filter.

**Example output (`--severity all`):**

```
Issue 1: [HIGH] CWE-89: SQL Injection
  Rule:    python.django.security.injection.tainted-sql-string
  File:    app/views.py line(s) 42-44
  Details: Detected user input used directly in a SQL query.

Issue 2: [MEDIUM] CWE-79: Cross-Site Scripting
  Rule:    javascript.react.security.audit.react-dangerouslysetinnerhtml
  File:    src/components/Comment.jsx line(s) 17-17
  Details: dangerouslySetInnerHTML usage detected.

Total: 2 findings: 1 HIGH, 1 MEDIUM
```

**Example output (default, with Jira credentials present):**

```
Checking Jira for existing tickets...

Issue 1: [HIGH] CWE-89: SQL Injection  [EXISTS: SEC-101]
  Rule:    python.django.security.injection.tainted-sql-string
  File:    app/views.py line(s) 42-44
  Details: Detected user input used directly in a SQL query.

Issue 2: [MEDIUM] CWE-79: Cross-Site Scripting  [NEW]
  Rule:    javascript.react.security.audit.react-dangerouslysetinnerhtml
  File:    src/components/Comment.jsx line(s) 17-17
  Details: dangerouslySetInnerHTML usage detected.

Total: 2 findings: 1 HIGH, 1 MEDIUM
  Would create: 1 new ticket
```

## Generating `sast.json`

Run Semgrep with JSON output and save to `sast.json` in your project root:

```
semgrep --config auto --json -o sast.json .
```
