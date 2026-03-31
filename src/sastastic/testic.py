import json
import os
import sys
from collections import Counter

RED    = "\033[91m"
YELLOW = "\033[93m"
GREEN  = "\033[92m"
BOLD   = "\033[1m"
DIM    = "\033[2m"
RESET  = "\033[0m"

IMPACT_ORDER = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
SEVERITY_THRESHOLD = {"high": 0, "med": 1, "low": 2, "all": float('inf')}


def impact_color(impact):
    return {"HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}.get(impact, RESET)


def test():
    args = sys.argv[1:]
    encoding = 'utf-16' if '--windows' in args else 'utf-8'
    severity_arg = next((args[i+1] for i, a in enumerate(args) if a == '--severity' and i+1 < len(args)), 'high')
    if severity_arg.lower() not in SEVERITY_THRESHOLD:
        print(f"Error: invalid --severity value '{severity_arg}'. Use: high, med, low, all")
        sys.exit(1)
    severity_threshold = SEVERITY_THRESHOLD[severity_arg.lower()]

    from dotenv import load_dotenv
    load_dotenv()
    _jira_vars = all(os.environ.get(v) for v in ("JIRA_KEY", "JIRA_URL", "JIRA_EMAIL", "JIRA_PROJECT"))
    check_jira = _jira_vars

    with open('sast.json', 'r', encoding=encoding) as f:
        data = json.load(f, strict=False) if encoding == 'utf-16' else json.load(f)

    from sastastic.utils import get_fingerprint

    findings = []
    for issue in data.get('results', []):
        impact = (issue.get('extra', {}).get('metadata', {}).get('impact') or 'UNKNOWN').upper()
        fingerprint = get_fingerprint(issue)
        findings.append({
            "cwe":         issue.get('extra', {}).get('metadata', {}).get('cwe', 'Unknown'),
            "impact":      impact,
            "message":     issue.get('extra', {}).get('message', ''),
            "path":        issue.get('path', ''),
            "start":       issue.get('start', {}).get('line', '?'),
            "end":         issue.get('end', {}).get('line', '?'),
            "check_id":    issue.get('check_id', ''),
            "label":       f"sastastic-{fingerprint}",
        })

    findings.sort(key=lambda f: IMPACT_ORDER.get(f["impact"], 99))

    existing_tickets = {}
    if check_jira:
        try:
            import requests
            from requests.auth import HTTPBasicAuth
            from sastastic.utils import fetch_existing_tickets
            jira_key   = os.environ["JIRA_KEY"]
            jira_url   = os.environ["JIRA_URL"]
            jira_email = os.environ["JIRA_EMAIL"]
            project    = os.environ["JIRA_PROJECT"]
            base_url   = jira_url.rsplit('/issue', 1)[0]
            search_url = f"{base_url}/search/jql"
            headers    = {"Accept": "application/json", "Content-Type": "application/json"}
            auth       = HTTPBasicAuth(jira_email, jira_key)
            print("Checking Jira for existing tickets...")
            existing_tickets = fetch_existing_tickets(
                [f["label"] for f in findings], search_url, project, headers, auth
            )
        except (KeyError, requests.exceptions.RequestException) as e:
            print(f"{YELLOW}Warning: Jira check failed ({e}), skipping{RESET}")
            check_jira = False

    print()
    for i, f in enumerate(findings, 1):
        meets_severity = IMPACT_ORDER.get(f["impact"], 99) <= severity_threshold
        if check_jira:
            is_new = f["label"] not in existing_tickets
            if not (is_new or meets_severity):
                continue
        else:
            if not meets_severity:
                continue

        color = impact_color(f["impact"])

        if check_jira:
            ticket_key = existing_tickets.get(f["label"])
            status = f"  {DIM}[EXISTS: {ticket_key}]{RESET}" if ticket_key else f"  {BOLD}[NEW]{RESET}"
        else:
            status = ""

        print(f"{color}{BOLD}Issue {i}: [{f['impact']}] {f['cwe']}{RESET}{status}")
        if f["check_id"]:
            print(f"  Rule:    {f['check_id']}")
        print(f"  File:    {f['path']} line(s) {f['start']}-{f['end']}")
        print(f"  Details: {f['message']}")
        print()

    unknown = [f for f in findings if f["impact"] == "UNKNOWN"]
    if unknown:
        print(f"{YELLOW}Warning: {len(unknown)} finding{'s' if len(unknown) != 1 else ''} with no impact rating — use --severity all to include them{RESET}\n")

    counts = Counter(f["impact"] for f in findings)
    total  = len(findings)
    breakdown = ", ".join(
        f"{impact_color(impact)}{count} {impact}{RESET}"
        for impact, count in sorted(counts.items(), key=lambda x: IMPACT_ORDER.get(x[0], 99))
    )
    label = f"finding{'s' if total != 1 else ''}"
    print(f"{BOLD}Total: {total} {label}{RESET}" + (f": {breakdown}" if findings else ""))

    if check_jira and findings:
        new_count = sum(1 for f in findings if f["label"] not in existing_tickets)
        print(f"  Would create: {BOLD}{new_count} new ticket{'s' if new_count != 1 else ''}{RESET}")
