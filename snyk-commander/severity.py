"""Update issue severity via Snyk Security Policies API."""

from concurrent.futures import ThreadPoolExecutor, as_completed

from rich.prompt import Prompt, Confirm
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn

from .config import console, MAX_THREADS, API_REST, REST_VERSION, api_semaphore
from .api import SnykClient


def _score_to_severity(score) -> str | None:
    """Map a risk score to severity: low, medium, high, critical."""
    if score is None:
        return None
    try:
        s = int(score)
    except (ValueError, TypeError):
        return None
    if s <= 400:
        return "low"
    elif s <= 600:
        return "medium"
    elif s <= 800:
        return "high"
    else:
        return "critical"


def _build_override_list(results: list[dict]) -> list[dict]:
    """Build deduplicated list of issues needing severity change based on risk score.
    
    Since policies apply at the org level, the same vulnerability across multiple
    projects only needs one policy. We deduplicate by issue_id and keep the highest
    risk score seen.
    """
    seen: dict[str, dict] = {}
    for r in results:
        for issue in r.get("issues", []):
            issue_data = issue.get("issueData", {})
            issue_id = issue.get("id") or issue_data.get("id")
            if not issue_id:
                continue

            priority = issue.get("priority", {})
            raw_score = priority.get("score", issue_data.get("cvssScore"))
            new_sev = _score_to_severity(raw_score)
            if new_sev is None:
                continue

            original_sev = issue_data.get("severity", "unknown")
            if new_sev == original_sev:
                continue

            # Keep highest risk score if same issue seen multiple times
            if issue_id in seen:
                if raw_score and raw_score > (seen[issue_id].get("risk_score") or 0):
                    seen[issue_id]["risk_score"] = raw_score
                    seen[issue_id]["new_severity"] = new_sev
                seen[issue_id]["project_count"] += 1
                seen[issue_id]["projects"].append(r.get("name", "Unknown"))
            else:
                cwe = issue_data.get("identifiers", {}).get("CWE", [])
                seen[issue_id] = {
                    "issue_id": issue_id,
                    "title": issue_data.get("title", "Unknown"),
                    "original_severity": original_sev,
                    "new_severity": new_sev,
                    "risk_score": raw_score,
                    "project_count": 1,
                    "projects": [r.get("name", "Unknown")],
                    "cwe": cwe,
                }
    return list(seen.values())


def _create_severity_policy(client: SnykClient, org_id: str,
                            issue_id: str, new_severity: str,
                            reason: str) -> tuple[bool, str]:
    """Create a security policy to override severity for a specific Snyk issue ID.
    
    Uses the group-level policies API which supports severity-override action.
    Falls back to org-level if group is not available.
    """
    session = client._get_session()

    # Try org-level first with a rules-based format
    url = f"{API_REST}/orgs/{org_id}/policies"
    params = {"version": REST_VERSION}
    body = {
        "data": {
            "type": "policy",
            "attributes": {
                "name": f"Severity override: {issue_id} -> {new_severity}",
                "rules": [
                    {
                        "conditions": {
                            "snyk_id": {
                                "includes": [issue_id]
                            }
                        },
                        "actions": {
                            "change_severity": new_severity
                        }
                    }
                ],
            },
        }
    }
    try:
        with api_semaphore:
            resp = session.post(
                url,
                headers=client._headers_rest,
                json=body,
                params=params,
                timeout=60,
            )
        if resp.status_code in (200, 201):
            return True, f"{resp.status_code}"

        # If org-level fails, try the group-level format
        # Get group_id from org info
        org_url = f"{API_REST}/orgs/{org_id}"
        with api_semaphore:
            org_resp = session.get(
                org_url,
                headers=client._headers_rest,
                params={"version": REST_VERSION},
                timeout=60,
            )
        if org_resp.status_code != 200:
            return False, f"{resp.status_code}: {resp.text[:200]}"

        org_body = org_resp.json()
        group_id = (
            org_body.get("data", {}).get("attributes", {}).get("group_id")
            or org_body.get("data", {}).get("relationships", {}).get("group", {}).get("data", {}).get("id")
        )
        if not group_id:
            return False, f"Org-level failed ({resp.status_code}), no group_id found to try group-level"

        # Try group-level policy API
        group_url = f"{API_REST}/groups/{group_id}/policies"
        group_body = {
            "data": {
                "type": "policy",
                "attributes": {
                    "name": f"Severity override: {issue_id} -> {new_severity}",
                    "conditions_group": {
                        "logical_operator": "and",
                        "conditions": [
                            {
                                "field": "snyk-id",
                                "operator": "includes",
                                "value": [issue_id],
                            }
                        ],
                    },
                    "action_type": "severity-override",
                    "action": {
                        "data": {
                            "severity": new_severity,
                            "reason": reason,
                        }
                    },
                },
            }
        }
        with api_semaphore:
            group_resp = session.post(
                group_url,
                headers=client._headers_rest,
                json=group_body,
                params=params,
                timeout=60,
            )
        if group_resp.status_code in (200, 201):
            return True, f"{group_resp.status_code} (group-level)"
        else:
            return False, f"org: {resp.status_code}, group: {group_resp.status_code}: {group_resp.text[:200]}"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


def update_severity(client: SnykClient, org_id: str, results: list[dict]):
    """Interactive severity update workflow."""
    overrides = _build_override_list(results)

    if not overrides:
        console.print("\n[yellow]No severity changes needed — all issues match their risk score rating.[/yellow]")
        return

    console.print(f"\n[bold]{len(overrides)}[/bold] issue(s) have a severity that differs from their risk score rating.\n")

    choice = Prompt.ask(
        "[bold]Would you like to[/bold]\n"
        "  [cyan]1[/cyan] - Update ALL in bulk (threaded)\n"
        "  [cyan]2[/cyan] - Review and approve each one\n"
        "  [cyan]3[/cyan] - Skip\n"
        "Choose",
        choices=["1", "2", "3"],
        default="2",
    )

    if choice == "3":
        console.print("[dim]Skipped severity updates.[/dim]")
        return

    if choice == "1":
        console.print(f"\n[bold green]Updating {len(overrides)} issue severities in bulk…[/bold green]")
        succeeded, failed = 0, 0

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            MofNCompleteColumn(),
            TextColumn("[dim]{task.fields[status]}[/dim]"),
            console=console,
        ) as progress:
            task_id = progress.add_task("Updating", total=len(overrides), status="")

            with ThreadPoolExecutor(max_workers=MAX_THREADS) as executor:
                future_to_override = {
                    executor.submit(
                        _create_severity_policy, client, org_id,
                        o["issue_id"], o["new_severity"],
                        f"Risk score {o['risk_score']} maps to {o['new_severity']}"
                    ): o
                    for o in overrides
                }

                for future in as_completed(future_to_override):
                    o = future_to_override[future]
                    ok, msg = future.result()
                    if ok:
                        succeeded += 1
                        progress.update(task_id, advance=1,
                                        status=f"[green]OK[/green] {o['title'][:40]}")
                    else:
                        failed += 1
                        progress.update(task_id, advance=1,
                                        status=f"[red]FAIL[/red] {o['title'][:40]}")

        console.print(f"\n[bold]Results:[/bold] {succeeded} succeeded, {failed} failed")

    elif choice == "2":
        succeeded, failed, skipped = 0, 0, 0
        for o in overrides:
            cwe_str = ", ".join(o.get("cwe", [])) or "N/A"
            projects_list = "\n".join(f"    • {p}" for p in o["projects"])
            console.print(
                f"\n[bold]{o['title']}[/bold]\n"
                f"  ID: {o['issue_id']}\n"
                f"  CWE: {cwe_str}\n"
                f"  Severity: [yellow]{o['original_severity']}[/yellow] → "
                f"Proposed: [cyan]{o['new_severity']}[/cyan]  "
                f"(Risk Score: {o['risk_score']})\n"
                f"  Affected projects ({o['project_count']}):\n{projects_list}"
            )
            if Confirm.ask("  Apply this change?", default=False):
                ok, msg = _create_severity_policy(
                    client, org_id, o["issue_id"], o["new_severity"],
                    f"Risk score {o['risk_score']} maps to {o['new_severity']}"
                )
                if ok:
                    succeeded += 1
                    console.print(f"  [green]✓ Updated[/green]")
                else:
                    failed += 1
                    console.print(f"  [red]✗ Failed[/red] [dim]{msg}[/dim]")
            else:
                skipped += 1
                console.print("  [dim]Skipped.[/dim]")

        console.print(f"\n[bold]Results:[/bold] {succeeded} updated, {failed} failed, {skipped} skipped")
