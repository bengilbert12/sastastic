# sastastic

Ingests Semgrep SAST output (JSON) and creates Jira tickets for each finding. Designed to run in CI on every push — duplicate findings are automatically skipped and tickets for resolved findings are closed.

## Requirements

- Python 3.8+
- A `sast.json` file in the working directory (Semgrep JSON output)
- Jira API credentials set as environment variables

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
sastastic "app-name" "PARENT-TICKET"
```

- `app-name` — label for the application being scanned (used in ticket summaries)
- `PARENT-TICKET` — Jira issue key to attach findings to as subtasks (e.g. `SEC-42`)

**Idempotent by design:** each finding is fingerprinted and stored as a Jira label (`sastastic-<fingerprint>`). On subsequent runs:
- Findings with an existing open ticket are skipped
- Tickets whose finding no longer appears in the scan are automatically transitioned to Done

### `sastestic` — Dry-run preview (local development)

Preview what tickets would be created without touching Jira.

```
sastestic [w] [--check-jira]
```

**Flags:**

| Flag            | Description                                                                 |
|-----------------|-----------------------------------------------------------------------------|
| *(none)*        | Parse `sast.json` and display all findings, sorted by severity              |
| `w`             | Read `sast.json` as UTF-16 (required on some Windows environments)          |
| `--check-jira`  | Connect to Jira and mark each finding as `[NEW]` or `[EXISTS: KEY]`        |

**Example output (no flags):**

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

**Example output (`--check-jira`):**

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
