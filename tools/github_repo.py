"""Publish this project using the current Git Credential Manager login.

Credentials remain in memory and are never printed or written to this repository.
"""
import argparse
import json
import os
import subprocess
import urllib.error
import urllib.request


def request(token, endpoint, body=None):
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(
        "https://api.github.com" + endpoint,
        data=data,
        headers={"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json", "Content-Type": "application/json", "User-Agent": "wireguardJS-publisher"},
    )
    try:
        with urllib.request.urlopen(req, timeout=30) as response:
            return response.status, json.load(response)
    except urllib.error.HTTPError as error:
        return error.code, json.load(error)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=["inspect", "create", "status"])
    args = parser.parse_args()
    result = subprocess.run(
        ["git", "credential", "fill"], input="protocol=https\nhost=github.com\n\n", text=True, capture_output=True,
        env={**os.environ, "GIT_TERMINAL_PROMPT": "0", "GCM_INTERACTIVE": "never"}, timeout=20,
    )
    credential = dict(line.split("=", 1) for line in result.stdout.splitlines() if "=" in line)
    token = credential.get("password")
    if not token:
        raise SystemExit("GitHub login is unavailable in Git Credential Manager.")
    code, user = request(token, "/user")
    if code != 200:
        raise SystemExit(f"GitHub login check failed: HTTP {code}")
    repo = user["login"] + "/wireguardJS"
    if args.action == "status":
        code, data = request(token, "/repos/" + repo + "/actions/runs?per_page=5")
        if code != 200:
            raise SystemExit(f"Workflow lookup failed: HTTP {code}")
        for run in data.get("workflow_runs", []):
            print(json.dumps({key: run.get(key) for key in ["id", "event", "status", "conclusion", "html_url", "head_sha"]}))
        return
    code, data = request(token, "/repos/" + repo)
    if code == 404 and args.action == "create":
        code, data = request(token, "/user/repos", {"name": "wireguardJS", "description": "WireGuard management plugin for the KANO Android device UI", "private": True, "auto_init": False})
    if code not in (200, 201):
        raise SystemExit(f"Repository {repo}: HTTP {code}")
    print(json.dumps({key: data.get(key) for key in ["full_name", "private", "html_url", "clone_url", "default_branch", "size"]}))


if __name__ == "__main__":
    main()
