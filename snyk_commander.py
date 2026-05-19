#!/usr/bin/env python3
"""
Snyk Commander - Scan Snyk orgs for vulnerabilities and open fix PRs.

Supports authentication via:
  - Snyk Personal Access Token (PAT)
  - Snyk Service Account Token

Usage:
  export SNYK_TOKEN=<your-token>
  python snyk_commander.py
  # or
  python -m snyk_commander
"""

import sys
from snyk_commander.__main__ import main
from snyk_commander.config import console

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Interrupted. Exiting gracefully.[/yellow]")
        sys.exit(0)

