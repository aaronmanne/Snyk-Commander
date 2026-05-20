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
            vuln_id = issue.get("id") or issue_data.get("id", "")
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
    """Extract a folder-friendly name from the Snyk project name.

    Snyk project names look like: org/repo(branch):path/to/manifest.txt
    We use the repo name as the folder.
    """
    name = project_name
    if "/" in name:
        name = name.split("/", 1)[1]
    if "(" in name:
        name = name.split("(", 1)[0]
    if ":" in name:
        name = name.split(":", 1)[0]
    return name.strip() or "unknown_project"


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

            f.write(f"  {vuln_id}:\n")
            for entry in entries:
                for path_key, details in entry.items():
                    f.write(f"    - '{path_key}':\n")
                    f.write(f"        reason: {details.get('reason', '')}\n")
                    f.write(f"        expires: {details.get('expires', '')}\n")
                    if "created" in details:
                        f.write(f"        created: {details['created']}\n")


def _generate_per_project_ignores(results: list[dict]) -> None:
    """Generate a .snyk file per project with default ignores.

    Criteria: low/very low risk score (≤400), no reachability path found, and not fixable.
    """
    console.print("\n[bold cyan]Generating default .snyk ignores per project…[/bold cyan]")
    console.print("[dim]Criteria: risk score ≤ 400, no reachability path, not fixable[/dim]\n")

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
                vuln_id = issue.get("id") or issue.get("issueData", {}).get("id", "")
                if not vuln_id:
                    continue

                if not _is_low_risk_score(issue):
                    continue
                if not _is_not_fixable(issue):
                    continue

                reachability = _get_reachability(issue)
                if reachability.lower() not in ("no", "no data"):
                    continue

                issue_data = issue.get("issueData", {})
                priority = issue.get("priority", {})
                score = priority.get("score")
                days = _score_to_suggested_days(score, issue_data.get("severity", "medium"))

                reason = f"Accepted due to low risk score of {score}" if score else "Accepted - low risk, no reachability path, not fixable"
                expires = (datetime.utcnow() + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%S.000Z")

                entry = {
                    "*": {
                        "reason": reason,
                        "expires": expires,
                        "created": datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%S.000Z"),
                    }
                }

                policy["ignore"][vuln_id] = [entry]
                vuln_metadata[vuln_id] = {
                    "id": vuln_id,
                    "title": issue_data.get("title", vuln_id),
                    "severity": issue_data.get("severity", "unknown"),
                    "risk_score": score,
                    "cwe": issue_data.get("identifiers", {}).get("CWE", []),
                    "reachability": reachability,
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


def manage_ignores(results: list[dict]) -> None:
    """Interactive workflow to review vulnerabilities and add ignores to .snyk."""

    # Top-level choice: per-unique-vuln or per-project defaults
    console.print("\n[bold cyan]Manage .snyk Ignores[/bold cyan]")
    console.print("  [cyan]1[/cyan] - Fixable vulnerabilities only")
    console.print("  [cyan]2[/cyan] - Non-fixable vulnerabilities only")
    console.print("  [cyan]3[/cyan] - All vulnerabilities")
    console.print("  [cyan]4[/cyan] - Generate default ignores for all projects")
    console.print()

    top_choice = Prompt.ask("Choose", choices=["1", "2", "3", "4"], default="3")

    if top_choice == "4":
        _generate_per_project_ignores(results)
        return

    all_vulns = _extract_unique_vulns(results)

    if not all_vulns:
        console.print("[green]No vulnerabilities found to ignore.[/green]")
        return

    if top_choice == "1":
        vulns = [v for v in all_vulns if v["fixable"]]
        label = "fixable"
    elif top_choice == "2":
        vulns = [v for v in all_vulns if not v["fixable"]]
        label = "non-fixable"
    else:
        vulns = all_vulns
        label = "all"

    if not vulns:
        console.print(f"[yellow]No {label} vulnerabilities found.[/yellow]")
        return

    console.print(f"\n[bold]{len(vulns)} {label} unique vulnerability(ies) to review.[/bold]\n")

    # Ask review mode
    console.print("[bold cyan]How would you like to proceed?[/bold cyan]")
    console.print("  [cyan]1[/cyan] - Review each vulnerability one by one")
    console.print("  [cyan]2[/cyan] - Accept all suggested ignores (auto-ignore based on risk score)")
    console.print()

    mode_choice = Prompt.ask("Choose", choices=["1", "2"], default="1")

    # Load existing policy
    policy = _load_snyk_policy()
    vuln_metadata: dict[str, dict] = {}
    added_count = 0
    skipped = 0

    try:
        if mode_choice == "2":
            # Auto-ignore everything with a risk score
            with_score = [v for v in vulns if _has_risk_score(v)]
            without_score = [v for v in vulns if not _has_risk_score(v)]

            if with_score:
                console.print(f"\n[bold green]Auto-ignoring {len(with_score)} vulnerability(ies) with risk scores…[/bold green]\n")
                added_count = _auto_ignore_vulns(with_score, policy, vuln_metadata)

            # Vulns without a score must be reviewed manually
            if without_score:
                console.print(
                    f"\n[bold yellow]{len(without_score)} vulnerability(ies) have no risk score "
                    f"and require manual review:[/bold yellow]"
                )
                manual_added, skipped = _review_vulns_one_by_one(without_score, policy, vuln_metadata)
                added_count += manual_added

        else:
            # Review all one by one
            added_count, skipped = _review_vulns_one_by_one(vulns, policy, vuln_metadata)

    except KeyboardInterrupt:
        console.print("\n\n[yellow]Interrupted — saving any ignores added so far.[/yellow]")

    if added_count > 0:
        _save_snyk_policy(policy, vuln_metadata)
        console.print(f"\n[bold]Results:[/bold] {added_count} ignored, {skipped} skipped")
    else:
        console.print("\n[dim]No ignores added.[/dim]")
