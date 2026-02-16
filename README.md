This is a package to ingest semgrep outfiles in json format and create JIRA tickets based on findings. env must be configured for use with JIRA_KEY, JIRA_URL, JIRA_PROJECT, JIRA_PARENT, and JIRA_EMAIL. Sastastic will pull these variables from the environment. call using "sastastic app_name". semgrep findings must be in root directory named 'sast.json'

Can be run in cli for dry-run testing by using "sastestic". no arguments required, but does require sast.json to be present

TO USE:
pip install sastastic
in directory containint sast.json: sastastic "app_name" OR sastestic