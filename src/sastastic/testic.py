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


def impact_color(impact):
    return {"HIGH": RED, "MEDIUM": YELLOW, "LOW": GREEN}.get(impact, RESET)


def test():
    args = sys.argv[1:]
    encoding = 'utf-16' if 'w' in args else 'utf-8'
    check_jira = '--check-jira' in args

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
            from dotenv import load_dotenv
            from sastastic.utils import fetch_existing_tickets
            load_dotenv()
            jira_key   = os.environ["JIRA_KEY"]
            jira_url   = os.environ["JIRA_URL"]
            jira_email = os.environ["JIRA_EMAIL"]
            project    = os.environ["JIRA_PROJECT"]
            base_url   = jira_url.rsplit('/issue', 1)[0]
            search_url = f"{base_url}/search"
            headers    = {"Accept": "application/json", "Content-Type": "application/json"}
            auth       = HTTPBasicAuth(jira_email, jira_key)
            print("Checking Jira for existing tickets...")
            existing_tickets = fetch_existing_tickets(
                [f["label"] for f in findings], search_url, project, headers, auth
            )
        except KeyError as e:
            print(f"{YELLOW}Warning: missing env var {e}, skipping Jira check{RESET}")

    print()
    for i, f in enumerate(findings, 1):
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
