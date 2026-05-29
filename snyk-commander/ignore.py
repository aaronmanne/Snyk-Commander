"""Manage .snyk file ignores interactively."""

from datetime import datetime, timedelta
from pathlib import Path

import yaml
from rich.prompt import Prompt, Confirm

from .config import console


SNYK_FILE = Path(".snyk")


def _load_snyk_policy() -> dict:
    """Load existing .snyk file or return empty policy."""
    if SNYK_FILE.exists():
        with open(SNYK_FILE) as f:
            data = yaml.safe_load(f) or {}
    else:
        data = {}
    data.setdefault("version", "v1.5.0")
    data.setdefault("ignore", {})
    return data


def _save_snyk_policy(policy: dict, vuln_metadata: dict | None = None) -> None:
    """Write policy back to .snyk file with comments for each vulnerability.
    
    vuln_metadata: dict mapping vuln_id -> vuln dict with context info.
    """
    meta = vuln_metadata or {}

    with open(SNYK_FILE, "w") as f:
        f.write(f"# Snyk policy file — managed by Snyk Commander\n")
        f.write(f"version: {policy.get('version', 'v1.5.0')}\n")
        f.write("ignore:\n")

        for vuln_id, entries in policy.get("ignore", {}).items():
            # Write comment block if we have metadata for this vuln
            if vuln_id in meta:
                v = meta[vuln_id]
                cwe_str = ", ".join(v.get("cwe", [])) or "N/A"
                risk_display = v.get("risk_score") if _has_risk_score(v) else "N/A"
                projects = v.get("projects", [])
                f.write(f"  # {v.get('title', vuln_id)}\n")
                f.write(f"  # ID: {vuln_id}\n")
                f.write(f"  # CWE: {cwe_str}\n")
                f.write(f"  # Severity: {v.get('severity', 'unknown')}\n")
                f.write(f"  # Risk Score: {risk_display}\n")
                f.write(f"  # Fixable: {'Yes' if v.get('fixable') else 'No'}\n")
                f.write(f"  # Affected projects ({len(projects)}):\n")
                for p in projects:
                    f.write(f"  #   - {p}\n")

            f.write(f"  {vuln_id}:\n")
            for entry in entries:
                for path_key, details in entry.items():
                    f.write(f"    - '{path_key}':\n")
                    f.write(f"        reason: {details.get('reason', '')}\n")
                    f.write(f"        expires: {details.get('expires', '')}\n")
                    if "created" in details:
                        f.write(f"        created: {details['created']}\n")

    console.print(f"\n[green]✓ Updated {SNYK_FILE}[/green]")


def _severity_to_suggested_days(severity: str) -> int:
    """Fallback: map severity to suggested days when no risk score available."""
    mapping = {"critical": 7, "high": 14, "medium": 30, "low": 60}
    return mapping.get(severity, 30)


def _score_to_suggested_days(score, severity: str = "medium") -> int:
    """Map risk score to suggested ignore duration. Higher risk = fewer days. Max 90.
    
    If score is None/invalid, fall back to severity-based suggestion.
    """
    if score is None:
        return _severity_to_suggested_days(severity)
    try:
        s = int(score)
    except (ValueError, TypeError):
        return _severity_to_suggested_days(severity)
    # 0-200 -> 90 days, 201-400 -> 60, 401-600 -> 30, 601-800 -> 14, 801+ -> 7
    if s <= 200:
        return 90
    elif s <= 400:
        return 60
    elif s <= 600:
        return 30
    elif s <= 800:
        return 14
    else:
        return 7


def _has_risk_score(vuln: dict) -> bool:
    """Return True if the vulnerability has a valid numeric risk score."""
    score = vuln.get("risk_score")
    if score is None:
        return False
    try:
        int(score)
        return True
    except (ValueError, TypeError):
        return False


def _extract_unique_vulns(results: list[dict]) -> list[dict]:
    """Extract unique vulnerabilities across all projects with full context."""
    seen: dict[str, dict] = {}
    for proj in results:
        for issue in proj.get("issues", []):
            issue_data = issue.get("issueData", {})
            vuln_id = issue_data.get("id") or issue.get("id", "")
            if not vuln_id:
                continue

            is_fixable = (
                issue.get("isUpgradable") or issue.get("isPatchable") or issue.get("isPinnable")
                or issue.get("fixInfo", {}).get("isUpgradable")
                or issue.get("fixInfo", {}).get("isPatchable")
                or issue.get("fixInfo", {}).get("isPinnable")
            )

            priority = issue.get("priority", {})
            raw_score = priority.get("score", issue_data.get("cvssScore"))
            severity = issue_data.get("severity", "medium")

            if vuln_id in seen:
                if raw_score and raw_score > (seen[vuln_id].get("risk_score") or 0):
                    seen[vuln_id]["risk_score"] = raw_score
                    seen[vuln_id]["suggested_days"] = _score_to_suggested_days(raw_score, severity)
                seen[vuln_id]["project_count"] += 1
                seen[vuln_id]["projects"].append(proj.get("name", "Unknown"))
            else:
                cwe = issue_data.get("identifiers", {}).get("CWE", [])
                seen[vuln_id] = {
                    "id": vuln_id,
                    "title": issue_data.get("title", vuln_id),
                    "severity": severity,
                    "package": issue.get("pkgName", "unknown"),
                    "version": issue.get("pkgVersions", ["?"])[0] if issue.get("pkgVersions") else issue_data.get("nearestFixedInVersion", "?"),
                    "fixable": bool(is_fixable),
                    "risk_score": raw_score,
                    "suggested_days": _score_to_suggested_days(raw_score, severity),
                    "cwe": cwe,
                    "project_count": 1,
                    "projects": [proj.get("name", "Unknown")],
                }
    return list(seen.values())


def _build_reason(vuln: dict) -> str:
    """Build default reason string based on risk score."""
    if _has_risk_score(vuln):
        return f"Accepted due to low risk score of {vuln['risk_score']}"
    else:
        return f"Accepted risk - no risk score available (severity: {vuln['severity']})"


def _auto_ignore_vulns(vulns: list[dict], policy: dict, vuln_metadata: dict) -> int:
    """Auto-ignore all vulns that have a risk score. Returns count added."""
    ignores = policy["ignore"]
    added = 0

    for v in vulns:
        if not _has_risk_score(v):
            continue

        days = v["suggested_days"]
        reason = _build_reason(v)
        expires = (datetime.utcnow() + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        entry = {
            "*": {
                "reason": reason,
                "expires": expires,
                "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            }
        }
        ignores[v["id"]] = [entry]
        vuln_metadata[v["id"]] = v
        added += 1
        console.print(
            f"  [green]✓[/green] {v['id']} - {v['title'][:50]} "
            f"([cyan]{days} days[/cyan], score: {v['risk_score']})"
        )

    return added


def _review_vulns_one_by_one(vulns: list[dict], policy: dict, vuln_metadata: dict) -> tuple[int, int]:
    """Walk through vulns interactively. Returns (added, skipped)."""
    ignores = policy["ignore"]
    added = 0
    skipped = 0

    for v in vulns:
        cwe_str = ", ".join(v.get("cwe", [])) or "N/A"
        fixable_str = "[green]Yes[/green]" if v["fixable"] else "[red]No[/red]"
        projects_list = "\n".join(f"    • {p}" for p in v["projects"])
        risk_display = v["risk_score"] if _has_risk_score(v) else "N/A"

        console.print(
            f"\n[bold]{v['title']}[/bold]\n"
            f"  ID: {v['id']}\n"
            f"  CWE: {cwe_str}\n"
            f"  Severity: [yellow]{v['severity']}[/yellow]  "
            f"Risk Score: [cyan]{risk_display}[/cyan]\n"
            f"  Package: {v['package']}  Fixable: {fixable_str}\n"
            f"  Suggested ignore: [cyan]{v['suggested_days']} days[/cyan]\n"
            f"  Affected projects ({v['project_count']}):\n{projects_list}"
        )

        if not Confirm.ask("  Ignore this vulnerability?", default=False):
            skipped += 1
            console.print("  [dim]Skipped.[/dim]")
            continue

        days_str = Prompt.ask(
            "  How many days to ignore?",
            default=str(v["suggested_days"]),
        )
        try:
            days = int(days_str)
        except ValueError:
            console.print(f"  [red]Invalid number, using suggested {v['suggested_days']} days.[/red]")
            days = v["suggested_days"]

        default_reason = _build_reason(v)
        reason = Prompt.ask("  Reason (optional)", default=default_reason)

        expires = (datetime.utcnow() + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

        entry = {
            "*": {
                "reason": reason,
                "expires": expires,
                "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
            }
        }

        ignores[v["id"]] = [entry]
        vuln_metadata[v["id"]] = v
        added += 1
        console.print(f"  [green]✓ Will ignore {v['id']} for {days} days[/green]")

    return added, skipped


def _get_reachability(issue: dict) -> str:
    """Extract reachability status from priority factors. Returns 'No', 'Yes', or 'No data'."""
    factors = issue.get("priority", {}).get("factors", [])
    for f in factors:
        if f.get("name") == "Reachable":
            desc = f.get("description", "")
            if ":" in desc:
                return desc.split(":", 1)[1].strip()
    return "No data"


def _is_low_risk_score(issue: dict) -> bool:
    """Return True if risk score is low or very low (≤ 400)."""
    score = issue.get("priority", {}).get("score")
    if score is None:
        return False
    try:
        return int(score) <= 400
    except (ValueError, TypeError):
        return False


def _is_not_fixable(issue: dict) -> bool:
    """Return True if the issue has no supported fix."""
    if issue.get("isUpgradable") or issue.get("isPatchable") or issue.get("isPinnable"):
        return False
    fix_info = issue.get("fixInfo", {})
    if fix_info.get("isUpgradable") or fix_info.get("isPatchable") or fix_info.get("isPinnable") or fix_info.get("isFixable"):
        return False
    return True


def _get_project_folder(project_name: str) -> str:
    """Extract a folder path from the Snyk project name.

    Snyk project names look like: org/repo(branch):subpath/to/manifest.txt
    We produce: repo/subpath/to (the directory containing the manifest).
    For names like: ms-reports:env-dev:/home/nonroot/app/datadog
    We produce: ms-reports/home/nonroot/app/datadog
    """
    name = project_name

    # Strip org prefix (before first /)
    if "/" in name.split("(")[0].split(":")[0]:
        name = name.split("/", 1)[1]

    # Extract repo (before branch parens or first colon)
    repo = name
    subpath = ""

    if "(" in name:
        repo = name.split("(", 1)[0]
        remainder = name.split(")", 1)[1] if ")" in name else ""
        if remainder.startswith(":"):
            subpath = remainder[1:]
    elif ":" in name:
        parts = name.split(":", 1)
        repo = parts[0]
        subpath = parts[1]
        # Handle double-colon patterns like ms-reports:env-dev:/path
        if subpath.startswith("env-") and ":" in subpath:
            subpath = subpath.split(":", 1)[1]
            if subpath.startswith("/"):
                subpath = subpath[1:]

    # subpath is like "lambdas/data_extract/requirements.txt" — take the directory
    if subpath:
        # Remove the manifest filename (last component if it has an extension)
        parts = subpath.rsplit("/", 1)
        if len(parts) == 2 and "." in parts[1]:
            subpath = parts[0]
        elif "." in subpath and "/" not in subpath:
            subpath = ""

    repo = repo.strip()
    subpath = subpath.strip().strip("/")

    if subpath:
        return f"{repo}/{subpath}"
    return repo or "unknown_project"


def _get_project_display_path(project_name: str) -> str:
    """Extract a display path from the Snyk project name including the manifest.

    Snyk project names look like: org/repo(branch):subpath/to/manifest.txt
    We produce: repo/subpath/to/manifest.txt
    For names like: ms-reports:env-dev:/home/nonroot/app/datadog
    We produce: ms-reports/home/nonroot/app/datadog
    """
    name = project_name

    # Strip org prefix (before first /)
    if "/" in name.split("(")[0].split(":")[0]:
        name = name.split("/", 1)[1]

    # Extract repo (before branch parens or first colon)
    repo = name
    subpath = ""

    if "(" in name:
        repo = name.split("(", 1)[0]
        remainder = name.split(")", 1)[1] if ")" in name else ""
        if remainder.startswith(":"):
            subpath = remainder[1:]
    elif ":" in name:
        parts = name.split(":", 1)
        repo = parts[0]
        subpath = parts[1]
        # Handle double-colon patterns like ms-reports:env-dev:/path
        if subpath.startswith("env-") and ":" in subpath:
            subpath = subpath.split(":", 1)[1]
            if subpath.startswith("/"):
                subpath = subpath[1:]

    repo = repo.strip()
    subpath = subpath.strip().strip("/")

    if subpath:
        return f"{repo}/{subpath}"
    return repo or "unknown_project"


def _save_project_snyk_file(folder: Path, policy: dict, vuln_metadata: dict) -> None:
    """Write a .snyk file for a specific project folder."""
    folder.mkdir(parents=True, exist_ok=True)
    snyk_path = folder / ".snyk"

    with open(snyk_path, "w") as f:
        f.write("# Snyk policy file — auto-generated by Snyk Commander\n")
        f.write(f"version: {policy.get('version', 'v1.5.0')}\n")
        f.write("ignore:\n")

        for vuln_id, entries in policy.get("ignore", {}).items():
            if vuln_id in vuln_metadata:
                v = vuln_metadata[vuln_id]
                cwe_str = ", ".join(v.get("cwe", [])) or "N/A"
                risk_display = v.get("risk_score") if v.get("risk_score") is not None else "N/A"
                f.write(f"  # {v.get('title', vuln_id)}\n")
                f.write(f"  # ID: {vuln_id}\n")
                f.write(f"  # CWE: {cwe_str}\n")
                f.write(f"  # Severity: {v.get('severity', 'unknown')}\n")
                f.write(f"  # Risk Score: {risk_display}\n")
                f.write(f"  # Reachability: {v.get('reachability', 'N/A')}\n")
                f.write(f"  # Fixable: {'Yes' if v.get('fixable') else 'No'}\n")

            f.write(f"  {vuln_id}:\n")
            for entry in entries:
                for path_key, details in entry.items():
                    f.write(f"    - '{path_key}':\n")
                    f.write(f"        reason: {details.get('reason', '')}\n")
                    f.write(f"        expires: {details.get('expires', '')}\n")
                    if "created" in details:
                        f.write(f"        created: {details['created']}\n")


def _prompt_min_risk_score(prompt_text: str = "Minimum Snyk risk score (0–1000, default 0 = no threshold)") -> int:
    """Ask the user for a minimum risk score threshold. Returns 0–1000."""
    raw = Prompt.ask(prompt_text, default="0")
    try:
        val = int(raw)
        if 0 <= val <= 1000:
            return val
        console.print("[yellow]Value out of range — using 0 (no threshold).[/yellow]")
        return 0
    except (ValueError, TypeError):
        console.print("[yellow]Invalid input — using 0 (no threshold).[/yellow]")
        return 0


def _generate_per_project_ignores(
    results: list[dict],
    filter_mode: str = "non_fixable",
    min_risk_score: int = 0,
) -> None:
    """Generate a .snyk file per project under snyk-ignores/.

    filter_mode options:
        "all"                    – every vulnerability
        "fixable"                – only fixable vulnerabilities
        "non_fixable"            – only non-fixable vulnerabilities
        "non_fixable_above_score"– non-fixable with risk score >= min_risk_score
    """
    mode_labels = {
        "all": "all vulnerabilities",
        "fixable": "fixable vulnerabilities",
        "non_fixable": "non-fixable vulnerabilities",
        "non_fixable_above_score": f"non-fixable vulnerabilities with risk score ≥ {min_risk_score}",
    }
    console.print(f"\n[bold cyan]Generating .snyk ignores per project…[/bold cyan]")
    console.print(f"[dim]Criteria: {mode_labels.get(filter_mode, filter_mode)}[/dim]\n")

    projects_written = 0
    total_ignores = 0

    try:
        for proj in results:
            issues = proj.get("issues", [])
            if not issues:
                continue

            project_name = proj.get("name", "unknown")
            folder_name = _get_project_folder(project_name)

            policy = {"version": "v1.5.0", "ignore": {}}
            vuln_metadata: dict[str, dict] = {}
            proj_ignore_count = 0

            for issue in issues:
                issue_data = issue.get("issueData", {})
                vuln_id = issue_data.get("id") or issue.get("id", "")
                if not vuln_id:
                    continue

                not_fixable = _is_not_fixable(issue)
                priority = issue.get("priority", {})
                score = priority.get("score")

                # Apply filter
                if filter_mode == "all":
                    passes = True
                elif filter_mode == "fixable":
                    passes = not not_fixable
                elif filter_mode == "non_fixable":
                    passes = not_fixable
                elif filter_mode == "non_fixable_above_score":
                    if not not_fixable:
                        passes = False
                    elif score is None:
                        passes = False
                    else:
                        try:
                            passes = int(score) >= min_risk_score
                        except (ValueError, TypeError):
                            passes = False
                else:
                    passes = False

                if not passes:
                    continue

                days = _score_to_suggested_days(score, issue_data.get("severity", "medium"))
                reason = (
                    f"Accepted due to risk score of {score}"
                    if score is not None
                    else "Accepted - not fixable"
                )
                expires = (datetime.utcnow() + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

                entry = {
                    "*": {
                        "reason": reason,
                        "expires": expires,
                        "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    }
                }

                policy["ignore"][vuln_id] = [entry]
                reachability = _get_reachability(issue)
                vuln_metadata[vuln_id] = {
                    "id": vuln_id,
                    "title": issue_data.get("title", vuln_id),
                    "severity": issue_data.get("severity", "unknown"),
                    "risk_score": score,
                    "cwe": issue_data.get("identifiers", {}).get("CWE", []),
                    "reachability": reachability,
                    "fixable": not not_fixable,
                }
                proj_ignore_count += 1

            if proj_ignore_count > 0:
                folder = Path("snyk-ignores") / folder_name
                _save_project_snyk_file(folder, policy, vuln_metadata)
                projects_written += 1
                total_ignores += proj_ignore_count
                console.print(
                    f"  [green]✓[/green] snyk-ignores/{folder_name}/.snyk — "
                    f"{proj_ignore_count} ignore(s)"
                )

    except KeyboardInterrupt:
        console.print("\n\n[yellow]Interrupted — files written so far are saved.[/yellow]")

    if projects_written > 0:
        console.print(
            f"\n[bold green]Done:[/bold green] {total_ignores} ignore(s) across "
            f"{projects_written} project .snyk file(s)"
        )
    else:
        console.print("\n[yellow]No vulnerabilities matched the criteria for any project.[/yellow]")


def _update_allowed_ignored(
    results: list[dict],
    client=None,
    org: dict | None = None,
    min_risk_score: int = 0,
    cache=None,
) -> None:
    """Ignore non-fixable vulns via the Snyk API.

    min_risk_score=0  → all non-fixable vulns qualify (no score threshold).
    min_risk_score>0  → only non-fixable vulns with risk score >= min_risk_score qualify.

    Shows the user a summary table of what will be ignored/updated/unignored, then
    calls the Snyk API after confirmation.
    Each vuln+project combination is treated individually.
    """
    from rich.table import Table
    from concurrent.futures import ThreadPoolExecutor, as_completed
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn

    if client is None or org is None:
        console.print("[red]Error: API client and org are required for this option.[/red]")
        return

    org_id = org["id"]

    if min_risk_score > 0:
        console.print(f"\n[bold cyan]Ignore Non-Fixable (risk score ≥ {min_risk_score})[/bold cyan]")
        console.print(f"[dim]Criteria: no fix available AND risk score ≥ {min_risk_score}[/dim]")
    else:
        console.print("\n[bold cyan]Ignore All Non-Fixable[/bold cyan]")
        console.print("[dim]Criteria: no fix available (any risk score)[/dim]")
    console.print("[dim]Action: ignore temporarily for 90 days or until fix is available[/dim]\n")

    # Build a flat list of (vuln, project) entries — no deduplication across projects
    entries: list[dict] = []
    for proj in results:
        project_id = proj.get("id", "")
        project_name = proj.get("name", "Unknown")
        for issue in proj.get("issues", []):
            issue_data = issue.get("issueData", {})
            vuln_id = issue_data.get("id") or issue.get("id", "")
            if not vuln_id:
                continue

            priority = issue.get("priority", {})
            score = priority.get("score")
            fixable = not _is_not_fixable(issue)

            entries.append({
                "vuln_id": vuln_id,
                "title": issue_data.get("title", vuln_id),
                "severity": issue_data.get("severity", "medium"),
                "risk_score": score,
                "fixable": fixable,
                "project_id": project_id,
                "project_name": project_name,
                "display_path": _get_project_display_path(project_name),
            })

    # Categorize entries into actions
    to_ignore: list[dict] = []   # new ignores
    to_update: list[dict] = []   # existing ignores that need date refresh
    to_unignore: list[dict] = [] # previously ignored but fix now available

    # Load existing .snyk to detect already-ignored vulns
    policy = _load_snyk_policy()
    existing_ignores = policy.get("ignore", {})

    for entry in entries:
        score = entry["risk_score"]
        fixable = entry["fixable"]

        # Determine if this entry qualifies for ignoring
        if min_risk_score > 0:
            score_qualifies = False
            if score is not None:
                try:
                    score_qualifies = int(score) >= min_risk_score
                except (ValueError, TypeError):
                    pass
            qualifies = not fixable and score_qualifies
        else:
            qualifies = not fixable

        already_ignored = entry["vuln_id"] in existing_ignores

        if qualifies:
            if already_ignored:
                to_update.append(entry)
            else:
                to_ignore.append(entry)
        elif already_ignored and fixable:
            to_unignore.append(entry)

    # Show summary to user
    if not to_ignore and not to_update and not to_unignore:
        console.print("[dim]No changes needed — no vulnerabilities matched criteria.[/dim]")
        return

    if to_ignore:
        console.print(f"\n[bold green]Will IGNORE ({len(to_ignore)} entries):[/bold green]")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Project", max_width=50)
        table.add_column("Vuln ID", style="dim", max_width=30)
        table.add_column("Title", max_width=45)
        table.add_column("Score", justify="right")
        table.add_column("Severity")
        for e in sorted(to_ignore, key=lambda e: (e["display_path"], -(e["risk_score"] or 0))):
            table.add_row(e["display_path"], e["vuln_id"], e["title"][:45],
                          str(e["risk_score"]), e["severity"])
        console.print(table)

    if to_update:
        console.print(f"\n[bold yellow]Will UPDATE expiration ({len(to_update)} entries):[/bold yellow]")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Project", max_width=50)
        table.add_column("Vuln ID", style="dim", max_width=30)
        table.add_column("Title", max_width=45)
        table.add_column("Score", justify="right")
        table.add_column("Severity")
        table.add_column("Fixable?")
        for e in sorted(to_update, key=lambda e: (e["display_path"], -(e["risk_score"] or 0))):
            fixable_str = "[green]Yes[/green]" if e["fixable"] else "[red]No[/red]"
            table.add_row(e["display_path"], e["vuln_id"], e["title"][:45],
                          str(e["risk_score"]), e["severity"], fixable_str)
        console.print(table)

    if to_unignore:
        console.print(f"\n[bold red]Will UNIGNORE (fix now available) ({len(to_unignore)} entries):[/bold red]")
        table = Table(show_header=True, header_style="bold")
        table.add_column("Project", max_width=50)
        table.add_column("Vuln ID", style="dim", max_width=30)
        table.add_column("Title", max_width=45)
        table.add_column("Score", justify="right")
        table.add_column("Severity")
        for e in sorted(to_unignore, key=lambda e: (e["display_path"], -(e["risk_score"] or 0))):
            table.add_row(e["display_path"], e["vuln_id"], e["title"][:45],
                          str(e["risk_score"]), e["severity"])
        console.print(table)

    total = len(to_ignore) + len(to_update) + len(to_unignore)
    console.print(f"\n[bold]Total changes: {total}[/bold]")
    console.print(f"  Ignore: {len(to_ignore)} | Update: {len(to_update)} | Unignore: {len(to_unignore)}")

    if not Confirm.ask("\n[bold]Proceed and apply these changes via the Snyk API?[/bold]", default=False):
        console.print("[dim]Cancelled — no changes made.[/dim]")
        return

    # Apply changes via Snyk API
    reason = (
        f"No known fix available, risk score >= {min_risk_score}."
        if min_risk_score > 0
        else "No known fix available."
    )
    expires = (datetime.utcnow() + timedelta(days=90)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

    api_calls: list[tuple[str, str, str]] = []
    for e in to_ignore + to_update:
        api_calls.append(("ignore", e["vuln_id"], e["project_id"]))
    for e in to_unignore:
        api_calls.append(("unignore", e["vuln_id"], e["project_id"]))

    success = 0
    errors = 0

    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        MofNCompleteColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Applying ignores via Snyk API", total=len(api_calls))

        def _apply(call):
            action, vuln_id, project_id = call
            if action == "ignore":
                client.ignore_issue(org_id, project_id, vuln_id,
                                    reason=reason, expires=expires,
                                    disregard_if_fixable=True)
            else:
                client.unignore_issue(org_id, project_id, vuln_id)

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {executor.submit(_apply, c): c for c in api_calls}
            for future in as_completed(futures):
                call = futures[future]
                try:
                    future.result()
                    success += 1
                except Exception as e:
                    errors += 1
                    console.print(f"  [red]✗[/red] Failed {call[0]} {call[1]} in project {call[2]}: {e}")
                progress.advance(task)

    console.print(f"\n[bold green]Done![/bold green] {success} API call(s) succeeded, {errors} failed.")
    if errors:
        console.print("[yellow]Some operations failed — check errors above.[/yellow]")

    # Bust the ignored-issues cache so the next report run re-fetches fresh data
    if cache is not None and success > 0:
        cache.delete_ignored_data(org_id)
        console.print("[dim]Ignored-issues cache cleared — next report will fetch fresh data.[/dim]")


def _snyk_file_workflow(results: list[dict]) -> None:
    """Interactive sub-workflow for generating local .snyk ignore files."""
    console.print("\n[bold cyan]Generate Local .snyk Ignore Files[/bold cyan]")
    console.print("  [cyan]1[/cyan] - All vulnerabilities")
    console.print("  [cyan]2[/cyan] - All non-fixable vulnerabilities")
    console.print("  [cyan]3[/cyan] - Non-fixable vulnerabilities above a risk score")
    console.print("  [cyan]4[/cyan] - Fixable vulnerabilities only")
    console.print("  [cyan]5[/cyan] - Cancel")
    console.print()

    choice = Prompt.ask("Choose an option", default="1")

    if choice == "5" or not choice:
        return

    if choice == "1":
        _generate_per_project_ignores(results, filter_mode="all")

    elif choice == "2":
        _generate_per_project_ignores(results, filter_mode="non_fixable")

    elif choice == "3":
        min_score = _prompt_min_risk_score()
        _generate_per_project_ignores(results, filter_mode="non_fixable_above_score",
                                      min_risk_score=min_score)

    elif choice == "4":
        _generate_per_project_ignores(results, filter_mode="fixable")

    else:
        console.print("[yellow]Unknown option — returning.[/yellow]")


def manage_ignores(results: list[dict], client=None, org: dict | None = None, cache=None) -> None:
    """Interactive workflow to review vulnerabilities and add ignores."""

    console.print("\n[bold cyan]Manage SNYK Ignores[/bold cyan]")
    console.print("  [cyan]1[/cyan] - [API] Ignore Non-Fixable")
    console.print("  [cyan]2[/cyan] - [.snyk] Generate local ignore files")
    console.print("  [cyan]3[/cyan] - Previous menu")
    console.print()

    top_choice = Prompt.ask("Choose an option", default="1")

    if top_choice == "3":
        return

    # ── Option 1: API ignore non-fixable with optional risk score threshold ──
    if top_choice == "1":
        min_score = _prompt_min_risk_score(
            "Minimum risk score to include (0–1000, default 0 = all non-fixable)"
        )
        _update_allowed_ignored(results, client=client, org=org,
                                min_risk_score=min_score, cache=cache)
        return

    # ── Option 2: .snyk file generation sub-workflow ──
    if top_choice == "2":
        _snyk_file_workflow(results)
        return
