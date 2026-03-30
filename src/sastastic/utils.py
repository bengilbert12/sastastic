import hashlib
import requests


def get_fingerprint(issue):
    fp = issue.get('fingerprint')
    if fp:
        return fp[:24]
    key = f"{issue.get('check_id', '')}:{issue.get('path', '')}:{issue.get('start', {}).get('line', '')}"
    return hashlib.sha256(key.encode()).hexdigest()[:24]


def fetch_existing_tickets(labels, search_url, project, headers, auth):
    """Batch-query Jira for open tickets matching any of the given sastastic labels.
    Returns {label: issue_key} for all matches."""
    if not labels:
        return {}
    label_list = ", ".join(f'"{l}"' for l in labels)
    jql = f'project = "{project}" AND labels in ({label_list}) AND statusCategory != Done'
    existing = {}
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
        for issue in issues:
            for label in issue["fields"].get("labels", []):
                if label.startswith("sastastic-"):
                    existing[label] = issue["key"]
        if start + len(issues) >= data.get("total", 0):
            break
        start += len(issues)
    return existing
