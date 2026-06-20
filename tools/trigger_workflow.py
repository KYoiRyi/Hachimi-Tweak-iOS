#!/usr/bin/env python3
import os
import sys
import json
import urllib.request
import urllib.error

def trigger_workflow():
    print("=== GitHub Actions Workflow Trigger ===")
    
    # 1. Get Personal Access Token
    token = os.environ.get("GITHUB_TOKEN")
    if not token:
        token = input("Enter your GitHub Personal Access Token (PAT): ").strip()
        if not token:
            print("Error: GitHub Token is required to trigger the workflow.")
            sys.exit(1)

    # 2. Get Owner and Repo
    owner = input("Enter repository owner [default: KYoiRyi]: ").strip() or "KYoiRyi"
    repo = input("Enter repository name [default: Hachimi-Toolkit]: ").strip() or "Hachimi-Toolkit"
    ref = input("Enter branch/ref name [default: main]: ").strip() or "main"

    url = f"https://api.github.com/repos/{owner}/{repo}/actions/workflows/build_ios.yml/dispatches"
    
    headers = {
        "Accept": "application/vnd.github+json",
        "Authorization": f"Bearer {token}",
        "X-GitHub-Api-Version": "2022-11-28",
        "User-Agent": "Hachimi-Toolkit-Trigger",
        "Content-Type": "application/json"
    }

    data = json.dumps({"ref": ref}).encode("utf-8")

    req = urllib.request.Request(url, data=data, headers=headers, method="POST")

    print(f"\nSending POST request to trigger workflow on {owner}/{repo} (ref: {ref})...")
    
    try:
        with urllib.request.urlopen(req) as response:
            status = response.status
            if status == 204:
                print("Success! Workflow successfully triggered.")
            else:
                print(f"Workflow trigger returned unexpected status code: {status}")
    except urllib.error.HTTPError as e:
        print(f"\nHTTP Error {e.code}: {e.reason}")
        try:
            error_body = e.read().decode("utf-8")
            print(f"Response: {error_body}")
        except Exception:
            pass
        sys.exit(1)
    except urllib.error.URLError as e:
        print(f"\nConnection Error: {e.reason}")
        sys.exit(1)

if __name__ == "__main__":
    trigger_workflow()
