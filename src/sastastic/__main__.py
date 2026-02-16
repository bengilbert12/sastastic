import json
import requests
from requests.auth import HTTPBasicAuth
from dotenv import load_dotenv
import os
import sys



load_dotenv()
try:
    jira_key = os.environ["JIRA_KEY"]
    url = os.environ["JIRA_URL"]
    email = os.environ["JIRA_EMAIL"]
    project = os.environ["JIRA_PROJECT"]
    parent = os.environ["JIRA_PARENT"]
except KeyError:
    print('ENV values not set')
headers = {
"Accept": "application/json",
"Content-Type": "application/json"
}
auth = HTTPBasicAuth(email, jira_key)



def publish(app=str(sys.argv[1])):
    with open('sast.json', 'r') as f:
        data = json.load(f)





    for issue in data.get('results'):
        summary = f"[SASTASTIC] [{app}] [{issue.get('extra').get('metadata').get('impact')}] {issue.get('extra').get('metadata').get('cwe')}"
        impact = issue.get('extra').get('metadata').get('impact')
        message = issue.get('extra').get('message')
        path = issue.get('path')
        start = issue.get('start').get('line')
        end = issue.get('end').get('line')
        desc = {
        "version": 1,
        "type": "doc",
        "content": [
            {
            "type": "paragraph",
            "content": [
                {
                "type": "text",
                "text": "path: "
                },
                {
                "type": "text",
                "text": path,
                "marks": [
                    {
                    "type": "code"
                    }
                ]
                }]
            },
            {
            "type": "paragraph",
            "content": [
                {
                "type": "text",
                "text": message
                }
            ]
            },
            {
            "type": "paragraph",
            "content": [
                {
                "type": "text",
                "text": f'line(s) {start} - {end}'
                }
            ]
            },
            {
            "type": "paragraph",
            "content": [
                {
                "type": "text",
                "text": f'IMPACT: {impact}'
                }
            ]
            }
        ]
        }
        payload = json.dumps({
            'fields': {
                'project': {
                    "key": project
                },
                'parent': {
                    'key': parent
                },
                'issuetype': {
                    'name': 'Task'
                },
                'summary': summary,
                'description': desc


                }
            }
        )
        response = requests.request("POST", url=url ,data=payload,headers=headers,auth=auth)
        print(json.dumps(json.loads(response.text), sort_keys=True, indent=4, separators=(",", ": ")))


