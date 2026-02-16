import json
import os
import sys


def test():
    with open('sast.json', 'r') as f:
        data = json.load(f)
    
    i = 1

    for issue in data.get('results'):
        title = issue.get('extra').get('metadata').get('cwe')
        path = issue.get('path')
        print(f'Issue {i}: {title} at {path}')
        i += 1