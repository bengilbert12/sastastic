import json
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
import os
import sys
from sastastic.utils import get_fingerprint, fetch_existing_tickets

IMPACT_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SEVERITY_THRESHOLD = {"high": 0, "med": 1, "low": 2, "all": float('inf')}



load_dotenv()
try:
    jira_key = os.environ["JIRA_KEY"]
    url = os.environ["JIRA_URL"]
    email = os.environ["JIRA_EMAIL"]
    project = os.environ["JIRA_PROJECT"]
except KeyError:
    print('ENV values not set')
    sys.exit(1)

headers = {
    "Accept": "application/json",
    "Content-Type": "application/json"
}
auth = HTTPBasicAuth(email, jira_key)
base_url = url.rsplit('/issue', 1)[0]
search_url = f"{base_url}/search"




def get_open_sast_tickets(app):
    """Return list of Jira issue dicts (key + labels) for all open SASTASTIC tickets for this app."""
    jql = f'project = "{project}" AND summary ~ "[SASTASTIC] [{app}]" AND statusCategory != Done'
    all_issues = []
    start = 0
    while True:
        response = requests.get(
            search_url,
            params={"jql": jql, "fields": "labels", "maxResults": 100, "startAt": start},
            headers=headers,
            auth=auth
        )
        data = response.json()
        issues = data.get("issues", [])
        all_issues.extend(issues)
        if start + len(issues) >= data.get("total", 0):
            break
        start += len(issues)
    return all_issues


def close_ticket(issue_key):
    transitions_url = f"{base_url}/issue/{issue_key}/transitions"
    response = requests.get(transitions_url, headers=headers, auth=auth)
    transitions = response.json().get("transitions", [])
    done_id = next(
        (t["id"] for t in transitions if t.get("to", {}).get("statusCategory", {}).get("key") == "done"),
        None
    )
    if not done_id:
        print(f"  Warning: no Done transition found for {issue_key}, skipping")
        return
    payload = json.dumps({"transition": {"id": done_id}})
    requests.post(transitions_url, data=payload, headers=headers, auth=auth)
    print(f"  Closed {issue_key} (finding no longer detected)")


def publish():
    _args = sys.argv[1:]
    positional = [a for a in _args if not a.startswith('-')]
    if len(positional) < 2:
        print("Usage: sastastic <app-name> <parent-ticket> [--severity high|med|low|all]")
        sys.exit(1)
    app, parent = positional[0], positional[1]

    _sev_arg = next((a[len('--severity='):] if a.startswith('--severity=') else _args[i+1]
                     for i, a in enumerate(_args)
                     if a == '--severity' or a.startswith('--severity=')), 'high')
    if _sev_arg.lower() not in SEVERITY_THRESHOLD:
        print(f"Error: invalid --severity value '{_sev_arg}'. Use: high, med, low, all")
        sys.exit(1)
    severity_threshold = SEVERITY_THRESHOLD[_sev_arg.lower()]

    with open('sast.json', 'r') as f:
        data = json.load(f)

    # Build finding metadata and fingerprint labels upfront
    findings = []
    for issue in data.get('results'):
        fingerprint = get_fingerprint(issue)
        label = f"sastastic-{fingerprint}"
        impact = issue.get('extra').get('metadata').get('impact')
        cwe = issue.get('extra').get('metadata').get('cwe')
        message = issue.get('extra').get('message')
        path = issue.get('path')
        start = issue.get('start').get('line')
        end = issue.get('end').get('line')
        findings.append({
            "label": label,
            "summary": f"[SASTASTIC] [{app}] [{impact}] {cwe}",
            "impact": impact,
            "cwe": cwe,
            "message": message,
            "path": path,
            "start": start,
            "end": end,
        })

    unknown = [f for f in findings if not (f["impact"] or '').upper() in IMPACT_ORDER]
    if unknown:
        print(f"Warning: {len(unknown)} finding{'s' if len(unknown) != 1 else ''} with no impact rating — use --severity all to include them")

    # Single batch query for all fingerprints
    all_labels = [f["label"] for f in findings]
    existing_tickets = fetch_existing_tickets(all_labels, search_url, project, headers, auth)
    current_labels = set(all_labels)

    for finding in findings:
        label = finding["label"]
        impact = (finding["impact"] or '').upper()
        if IMPACT_ORDER.get(impact, 99) > severity_threshold:
            continue
        if label in existing_tickets:
            print(f"Skipping (exists: {existing_tickets[label]}): {finding['cwe']} at {finding['path']}")
            continue

        desc = {
            "version": 1,
            "type": "doc",
            "content": [
                {
                    "type": "paragraph",
                    "content": [
                        {"type": "text", "text": "path: "},
                        {"type": "text", "text": finding["path"], "marks": [{"type": "code"}]}
                    ]
                },
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": finding["message"]}]
                },
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": f"line(s) {finding['start']} - {finding['end']}"}]
                },
                {
                    "type": "paragraph",
                    "content": [{"type": "text", "text": f"IMPACT: {finding['impact']}"}]
                }
            ]
        }
        payload = json.dumps({
            "fields": {
                "project": {"key": project},
                "parent": {"key": parent},
                "issuetype": {"name": "Task"},
                "summary": finding["summary"],
                "description": desc,
                "labels": [label]
            }
        })
        response = requests.request("POST", url=url, data=payload, headers=headers, auth=auth)
        result = json.loads(response.text)
        if response.status_code in (200, 201):
            print(f"Created {result.get('key')}: {finding['summary']}")
        else:
            print(f"Error creating ticket for {finding['cwe']} at {finding['path']}:")
            print(json.dumps(result, sort_keys=True, indent=4, separators=(",", ": ")))

    # Auto-close tickets for findings no longer in the current scan
    print("\nChecking for resolved findings...")
    open_tickets = get_open_sast_tickets(app)
    for ticket in open_tickets:
        ticket_sast_labels = {l for l in ticket["fields"].get("labels", []) if l.startswith("sastastic-")}
        if not ticket_sast_labels:
            print(f"  Warning: {ticket['key']} has no sastastic label, skipping auto-close")
        elif ticket_sast_labels.isdisjoint(current_labels):
            close_ticket(ticket["key"])
