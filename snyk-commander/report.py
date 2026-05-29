"""Report generation (display, markdown, CSV)."""

import csv
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from rich.table import Table

from .config import REPORTS_DIR, console


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def risk_rating(score) -> tuple[str, str]:
    """Convert a Snyk risk score (1-1000) to (score_str, rating_str)."""
    if score is None or score == "N/A":
        return ("N/A", "N/A")
    try:
        s = int(score)
    except (ValueError, TypeError):
        return ("N/A", "N/A")
    if s <= 200:
        return (str(s), "Very Low")
    elif s <= 400:
        return (str(s), "Low")
    elif s <= 600:
        return (str(s), "Moderate")
    elif s <= 800:
        return (str(s), "High")
    else:
        return (str(s), "Critical")


def _format_expires(expires_str: str) -> str:
    """Convert an ISO-8601 expires string to a readable date, e.g. '2025-06-01'."""
    if not expires_str:
        return ""
    try:
        dt = datetime.strptime(expires_str[:10], "%Y-%m-%d")
        return dt.strftime("%Y-%m-%d")
    except (ValueError, TypeError):
        return expires_str


def _is_fixable_issue(issue: dict) -> bool:
    return bool(
        issue.get("isUpgradable") or issue.get("isPatchable") or issue.get("isPinnable")
        or issue.get("fixInfo", {}).get("isUpgradable")
        or issue.get("fixInfo", {}).get("isPatchable")
        or issue.get("fixInfo", {}).get("isPinnable")
    )


def _issue_risk_score(issue: dict):
    """Return the numeric risk score of an issue, or None."""
    priority = issue.get("priority", {})
    raw = priority.get("score", issue.get("issueData", {}).get("cvssScore"))
    if raw is None:
        return None
    try:
        return int(raw)
    except (ValueError, TypeError):
        return None


# ---------------------------------------------------------------------------
# Row building
# ---------------------------------------------------------------------------

def _build_rows(results: list[dict], ignore_map: dict | None = None) -> list[tuple]:
    """Build flat vulnerability rows from results.

    Each row is a 9-tuple:
        (#, project, type, severity, title, fix_available, score_str, rating_str, ignored_until)

    ignore_map: {(project_id, vuln_id): expires_str}
    Issues already tagged with ``_ignored_until`` (fetched as ignored from the API)
    use that value directly.
    """
    rows = []
    row_num = 0
    for r in results:
        project_id = r.get("id", "")
        for issue in r.get("issues", []):
            row_num += 1
            issue_data = issue.get("issueData", {})
            vuln_id = issue_data.get("id") or issue.get("id", "")
            title = issue_data.get("title", "Unknown")
            severity = issue_data.get("severity", "unknown").capitalize()
            fix_str = "Yes" if _is_fixable_issue(issue) else "No"
            raw_score = _issue_risk_score(issue)
            score_str, rating_str = risk_rating(raw_score)

            ignored_until = ""
            if issue.get("_ignored_until"):
                ignored_until = _format_expires(issue["_ignored_until"])
            elif ignore_map:
                raw_expires = ignore_map.get((project_id, vuln_id), "")
                ignored_until = _format_expires(raw_expires)

            rows.append((row_num, r["name"], r.get("type", "unknown"),
                         severity, title, fix_str, score_str, rating_str, ignored_until))
    return rows


# ---------------------------------------------------------------------------
# Terminal display
# ---------------------------------------------------------------------------

def display_results(results: list[dict]):
    """Display vulnerability table in the terminal."""
    table = Table(title="Vulnerability Summary", show_lines=True)
    table.add_column("#", style="dim", width=4)
    table.add_column("Project", min_width=30)
    table.add_column("Type", width=12)
    table.add_column("Severity", width=10)
    table.add_column("Vulnerability", min_width=25)
    table.add_column("Fix Available", justify="center", width=13)
    table.add_column("Risk Score", justify="right", width=10)
    table.add_column("Risk", width=10)

    rows = _build_rows(results)
    for row in rows:
        severity = row[3]
        sev_style = {"Critical": "bold red", "High": "red", "Medium": "yellow", "Low": "dim"}.get(severity, "")
        sev_display = f"[{sev_style}]{severity}[/{sev_style}]" if sev_style else severity
        fix_display = "[green]Yes[/green]" if row[5] == "Yes" else "[dim]No[/dim]"
        table.add_row(str(row[0]), row[1], row[2], sev_display, row[4],
                      fix_display, row[6], row[7])
    console.print(table)


# ---------------------------------------------------------------------------
# Ignored-data fetching
# ---------------------------------------------------------------------------

def _fetch_project_ignored_data(client, org_id: str, project_id: str) -> tuple[list[dict], dict[str, str]]:
    """Fetch ignored issues and the ignore expiry map for a single project from the API."""
    try:
        ignored_issues = client.get_ignored_issues(org_id, project_id)
    except Exception:
        ignored_issues = []
    try:
        ignores_map = client.get_project_ignores(org_id, project_id)
    except Exception:
        ignores_map = {}
    return ignored_issues, ignores_map


def _load_or_fetch_ignored_data(
    client,
    org: dict,
    results: list[dict],
    cache=None,
) -> dict[str, dict]:
    """Return ignored-issues data for all projects, using the cache when available.

    Return shape:
        {
            "<project_id>": {
                "ignored_issues": [...],
                "ignores_map":    {"<vuln_id>": "<expires_str>"}
            }
        }

    If *cache* is provided and a warm entry exists it is returned immediately.
    Otherwise the Snyk API is called for every project in *results*, the data is
    stored in the cache, and then returned.
    """
    org_id = org["id"]

    # ── Cache hit ────────────────────────────────────────────────────────
    if cache is not None:
        cached = cache.load_ignored_data(org_id)
        if cached is not None:
            console.print("[dim]Using cached ignored-issues data.[/dim]")
            return cached

    # ── Cache miss — fetch from Snyk API ─────────────────────────────────
    console.print("[dim]Fetching ignored issues from Snyk API…[/dim]")
    ignored_data: dict[str, dict] = {}

    with ThreadPoolExecutor(max_workers=10) as executor:
        future_to_pid = {
            executor.submit(_fetch_project_ignored_data, client, org_id, r.get("id", "")): r.get("id", "")
            for r in results
        }
        for future in as_completed(future_to_pid):
            project_id = future_to_pid[future]
            try:
                ignored_issues, ignores_map = future.result()
            except Exception:
                ignored_issues, ignores_map = [], {}
            ignored_data[project_id] = {
                "ignored_issues": ignored_issues,
                "ignores_map": ignores_map,
            }

    # ── Persist to cache ─────────────────────────────────────────────────
    if cache is not None:
        cache.save_ignored_data(org_id, ignored_data)

    return ignored_data


# ---------------------------------------------------------------------------
# Row statistics (used by the executive summary)
# ---------------------------------------------------------------------------

def _compute_stats(rows: list[tuple]) -> dict:
    """Derive counts from the rows list for use in the executive summary.

    Row layout: (#, project, type, severity, title, fix_available, score_str, rating_str, ignored_until)
    """
    total = len(rows)
    sev_counts: dict[str, int] = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0}
    fixable = 0
    non_fixable = 0
    rating_counts: dict[str, int] = {
        "Very Low": 0, "Low": 0, "Moderate": 0, "High": 0, "Critical": 0, "N/A": 0
    }
    ignored_count = 0

    for row in rows:
        sev = row[3]
        sev_counts[sev] = sev_counts.get(sev, 0) + 1

        if row[5] == "Yes":
            fixable += 1
        else:
            non_fixable += 1

        rating = row[7]
        rating_counts[rating] = rating_counts.get(rating, 0) + 1

        if row[8]:  # ignored_until populated
            ignored_count += 1

    return {
        "total": total,
        "sev_counts": sev_counts,
        "fixable": fixable,
        "non_fixable": non_fixable,
        "rating_counts": rating_counts,
        "ignored_count": ignored_count,
    }


# ---------------------------------------------------------------------------
# Executive summary
# ---------------------------------------------------------------------------

def _build_executive_summary(
    org: dict,
    stats: dict,
    report_mode: str,
    min_risk_score: int,
    now: str,
    projects_scanned: int,
) -> list[str]:
    """Return a list of markdown lines forming the executive summary section."""

    total = stats["total"]
    sev = stats["sev_counts"]
    fixable = stats["fixable"]
    non_fixable = stats["non_fixable"]
    rating = stats["rating_counts"]
    ignored = stats["ignored_count"]

    low_risk_nf = rating.get("Very Low", 0) + rating.get("Low", 0)
    moderate_plus_nf = rating.get("Moderate", 0) + rating.get("High", 0) + rating.get("Critical", 0)

    # ── Mode label for the report scope sentence ──────────────────────────
    if report_mode == "non_fixable":
        scope_desc = "non-fixable vulnerabilities — findings for which no vendor patch or upgrade path currently exists"
    elif report_mode == "non_fixable_above_score":
        scope_desc = (
            f"non-fixable vulnerabilities with a Snyk risk score at or above **{min_risk_score}** — "
            f"findings that have no available fix but carry an elevated risk score"
        )
    else:
        scope_desc = "all vulnerabilities detected across the scanned projects"

    lines: list[str] = []
    lines += [
        "## Executive Summary",
        "",
        (
            f"This report was generated on **{now}** for the **{org['name']}** organization "
            f"and covers {scope_desc}. "
            f"A total of **{total}** finding(s) were identified across **{projects_scanned}** "
            f"project(s)."
        ),
        "",
    ]

    # ── Findings overview table ───────────────────────────────────────────
    lines += [
        "### Findings Overview",
        "",
        "| Metric | Count |",
        "|--------|-------|",
        f"| Total Findings | {total} |",
        f"| Critical Severity | {sev.get('Critical', 0)} |",
        f"| High Severity | {sev.get('High', 0)} |",
        f"| Medium Severity | {sev.get('Medium', 0)} |",
        f"| Low Severity | {sev.get('Low', 0)} |",
        f"| Fixable | {fixable} |",
        f"| Non-Fixable (no patch available) | {non_fixable} |",
        f"| Currently Ignored | {ignored} |",
        "",
    ]

    # ── Risk score distribution ───────────────────────────────────────────
    lines += [
        "### Snyk Risk Score Distribution",
        "",
        "| Risk Rating | Score Range | Count |",
        "|-------------|-------------|-------|",
        f"| Very Low | 0 – 200 | {rating.get('Very Low', 0)} |",
        f"| Low | 201 – 400 | {rating.get('Low', 0)} |",
        f"| Moderate | 401 – 600 | {rating.get('Moderate', 0)} |",
        f"| High | 601 – 800 | {rating.get('High', 0)} |",
        f"| Critical | 801 – 1000 | {rating.get('Critical', 0)} |",
        f"| No Score | N/A | {rating.get('N/A', 0)} |",
        "",
    ]

    # ── Likelihood of exploitation ────────────────────────────────────────
    lines.append("### Likelihood of Exploitation & Impact Assessment")
    lines.append("")

    if report_mode == "all":
        # Split fixable vs non-fixable narrative
        if fixable > 0:
            lines.append(
                f"**Fixable findings ({fixable}):** These represent the primary remediation priority. "
                "A fix — whether a dependency upgrade, patch, or pinned version — is available and should be applied. "
                "Critical and High severity fixable vulnerabilities in particular carry real exploit potential and "
                "should be addressed as soon as possible within your normal patching cadence."
            )
            lines.append("")

        if non_fixable > 0:
            lines.append(
                f"**Non-fixable findings ({non_fixable}):** No vendor patch or upgrade path currently exists for these "
                "vulnerabilities. The likelihood of successful exploitation is therefore significantly constrained — "
                "an attacker would need to develop or obtain a working exploit independently, without any public "
                "patch analysis to guide them."
            )
            lines.append("")
            if low_risk_nf > 0:
                lines.append(
                    f"Of the non-fixable findings, **{low_risk_nf}** carry a Very Low or Low Snyk risk score "
                    "(score ≤ 400). These exhibit virtually no practical exploitability. Snyk's risk score "
                    "incorporates exploit maturity, reachability, CVSS base score, and environmental factors. "
                    "A score in this range indicates that — even if a theoretical vulnerability exists — "
                    "real-world conditions for exploitation are absent or negligible. "
                    "**These findings can reasonably be treated as accepted risk and, for operational purposes, "
                    "are effectively false positives.** They are included here for completeness and audit traceability."
                )
                lines.append("")
            if moderate_plus_nf > 0:
                lines.append(
                    f"**{moderate_plus_nf}** non-fixable finding(s) carry a Moderate or higher risk score. "
                    "While no patch exists, the elevated score warrants monitoring. Apply compensating controls "
                    "(network segmentation, WAF rules, runtime protection) where feasible and re-evaluate "
                    "when a vendor fix becomes available."
                )
                lines.append("")

        if total == 0:
            lines.append("No vulnerabilities matched the selected criteria. The environment is clean for this scope.")
            lines.append("")

    elif report_mode == "non_fixable":
        lines.append(
            f"This report covers **{total}** non-fixable vulnerability(ies). "
            "Because no vendor patch or upgrade currently exists for any of these findings, the ability for an "
            "attacker to exploit them is fundamentally limited: there is no public fix to reverse-engineer, "
            "and in most cases no publicly available proof-of-concept exploit."
        )
        lines.append("")
        if low_risk_nf > 0:
            lines.append(
                f"**{low_risk_nf}** finding(s) have a Very Low or Low Snyk risk score (≤ 400). "
                "Snyk's risk score is a composite metric that weighs CVSS severity, exploit maturity, "
                "reachability within your codebase, and deployment context. Scores in the Very Low and Low "
                "bands indicate that — even theoretically — the conditions required for successful exploitation "
                "are unlikely to be met. **From an operational security standpoint these findings present "
                "negligible risk and are considered equivalent to false positives.** They are tracked here "
                "purely for compliance visibility."
            )
            lines.append("")
        if moderate_plus_nf > 0:
            lines.append(
                f"**{moderate_plus_nf}** non-fixable finding(s) have a Moderate or higher risk score. "
                "Despite the absence of a fix these warrant closer attention. Review whether the affected "
                "code path is reachable in your production environment and consider compensating controls "
                "such as input validation hardening, network-layer restrictions, or runtime protection tools."
            )
            lines.append("")
        if total == 0:
            lines.append("No non-fixable vulnerabilities were found. No immediate action required.")
            lines.append("")

    elif report_mode == "non_fixable_above_score":
        lines.append(
            f"This report focuses on **{total}** non-fixable vulnerability(ies) with a Snyk risk score "
            f"at or above **{min_risk_score}**. These represent the higher-risk subset of unfixable findings — "
            "ones where Snyk's scoring engine has identified factors such as elevated CVSS severity, known "
            "exploit maturity, or reachable code paths that increase the probability of exploitation relative "
            "to lower-scored peers."
        )
        lines.append("")
        lines.append(
            "Even so, the absence of a vendor fix is a meaningful mitigating factor. Without a public patch "
            "to analyse, attackers have fewer resources to develop a working exploit. The risk is real but "
            "not equivalent to a fixable vulnerability of the same severity. "
            "**Recommended actions:** monitor vendor advisories closely, apply compensating controls "
            "(WAF, network segmentation, least-privilege access), and configure Snyk notifications to alert "
            "immediately when a fix becomes available so patching can be prioritised."
        )
        lines.append("")
        if total == 0:
            lines.append(
                f"No non-fixable vulnerabilities with a risk score ≥ {min_risk_score} were found. "
                "No immediate action required."
            )
            lines.append("")

    # ── Recommendations ───────────────────────────────────────────────────
    lines.append("### Recommendations")
    lines.append("")

    recs: list[str] = []

    if report_mode == "all" and fixable > 0:
        recs.append(
            f"**Remediate fixable findings first.** {fixable} finding(s) have an available fix. "
            "Prioritise Critical and High severity items; target resolution within your SLA."
        )

    if non_fixable > 0 and low_risk_nf > 0:
        recs.append(
            f"**Accept or ignore low-risk non-fixable findings.** {low_risk_nf} finding(s) with a "
            "Very Low or Low risk score present negligible exploitability. Use the Snyk Commander "
            "'Manage Ignores' workflow to formally accept these in the Snyk dashboard, reducing noise "
            "and keeping your findings list focused on actionable items."
        )

    if non_fixable > 0 and moderate_plus_nf > 0:
        recs.append(
            f"**Monitor elevated non-fixable findings.** {moderate_plus_nf} non-fixable finding(s) carry a "
            "Moderate or higher risk score. Apply compensating controls and subscribe to vendor security "
            "advisories for the affected packages."
        )

    if ignored > 0:
        recs.append(
            f"**Review active ignores.** {ignored} finding(s) are currently set to ignored in Snyk. "
            "Ensure these ignores are still justified and that expiry dates are appropriate."
        )

    if not recs:
        recs.append("No findings matched the selected criteria. Continue regular scanning to maintain visibility.")

    for i, rec in enumerate(recs, 1):
        lines.append(f"{i}. {rec}")
        lines.append("")

    lines.append("---")
    lines.append("")

    return lines


# ---------------------------------------------------------------------------
# Main report generator
# ---------------------------------------------------------------------------

def generate_report(
    org: dict,
    results: list[dict],
    client=None,
    cache=None,
    report_mode: str = "all",
    min_risk_score: int = 0,
):
    """Generate markdown and CSV reports.

    report_mode:
        "all"                    – every vulnerability
        "non_fixable"            – only non-fixable
        "non_fixable_above_score"– non-fixable with risk score >= min_risk_score

    When *client* is provided the report also fetches currently-ignored issues
    and populates the 'Ignored Until' column. When *cache* is also provided the
    ignored-issues data is read from (and written to) the cache so subsequent
    report runs do not re-hit the API.
    """
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    mode_tag = {
        "all": "all",
        "non_fixable": "nonfixable",
        "non_fixable_above_score": f"nonfixable_score{min_risk_score}",
    }.get(report_mode, report_mode)
    base_name = f"vuln_report_{org.get('slug', org['id'])}_{mode_tag}_{timestamp}"
    md_path = REPORTS_DIR / f"{base_name}.md"
    csv_path = REPORTS_DIR / f"{base_name}.csv"

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # ── Enrich with ignored-issue data when a client is available ────────
    ignore_map: dict[tuple[str, str], str] = {}
    enriched_results = list(results)

    if client:
        ignored_data = _load_or_fetch_ignored_data(client, org, results, cache=cache)

        for project_id, proj_data in ignored_data.items():
            ignored_issues = proj_data.get("ignored_issues", [])
            proj_ignores   = proj_data.get("ignores_map", {})

            for vuln_id, expires in proj_ignores.items():
                ignore_map[(project_id, vuln_id)] = expires

            if ignored_issues:
                for issue in ignored_issues:
                    issue_data = issue.get("issueData", {})
                    vid = issue_data.get("id") or issue.get("id", "")
                    issue["_ignored_until"] = proj_ignores.get(vid, "")

                for idx, er in enumerate(enriched_results):
                    if er.get("id") == project_id:
                        enriched_results[idx] = {
                            **er,
                            "issues": list(er.get("issues", [])) + ignored_issues,
                        }
                        break

    # ── Apply report-mode filter ─────────────────────────────────────────
    filtered_results = []
    for r in enriched_results:
        if not r.get("issues"):
            continue
        filtered_issues = []
        for issue in r["issues"]:
            fixable = _is_fixable_issue(issue)
            score = _issue_risk_score(issue)

            if report_mode == "all":
                filtered_issues.append(issue)
            elif report_mode == "non_fixable":
                if not fixable:
                    filtered_issues.append(issue)
            elif report_mode == "non_fixable_above_score":
                if not fixable:
                    if score is not None and score >= min_risk_score:
                        filtered_issues.append(issue)
        if filtered_issues:
            filtered_results.append({**r, "issues": filtered_issues})

    rows = _build_rows(filtered_results, ignore_map=ignore_map if client else None)
    stats = _compute_stats(rows)

    # ── Markdown ─────────────────────────────────────────────────────────
    mode_titles = {
        "all": "Full Vulnerability Report",
        "non_fixable": "Non-Fixable Vulnerability Report",
        "non_fixable_above_score": f"Non-Fixable Vulnerability Report (Risk Score ≥ {min_risk_score})",
    }
    report_title = mode_titles.get(report_mode, "Vulnerability Report")

    exec_summary_lines = _build_executive_summary(
        org=org,
        stats=stats,
        report_mode=report_mode,
        min_risk_score=min_risk_score,
        now=now,
        projects_scanned=len(results),
    )

    header_lines = [
        f"# {report_title}",
        "",
        f"**Organization:** {org['name']}  ",
        f"**Date:** {now}  ",
        f"**Projects Scanned:** {len(results)}  ",
        "",
    ]

    detail_lines = [
        "## Vulnerability Detail",
        "",
        "| # | Project | Type | Severity | Vulnerability | Fix Available | Risk Score | Risk | Ignored Until |",
        "|---|---------|------|----------|---------------|---------------|------------|------|---------------|",
    ]
    for row in rows:
        detail_lines.append(
            f"| {row[0]} | {row[1]} | {row[2]} | {row[3]} | {row[4]} | "
            f"{row[5]} | {row[6]} | {row[7]} | {row[8]} |"
        )
    detail_lines += ["", "*Generated by Snyk Commander*"]

    all_lines = header_lines + exec_summary_lines + detail_lines
    md_path.write_text("\n".join(all_lines))
    console.print(f"\n[bold green]Report saved:[/bold green] {md_path}")

    # ── CSV ───────────────────────────────────────────────────────────────
    csv_headers = ["#", "Project", "Type", "Severity", "Vulnerability",
                   "Fix Available", "Risk Score", "Risk", "Ignored Until"]
    with open(csv_path, "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(csv_headers)
        for row in rows:
            writer.writerow(row)

    console.print(f"[bold green]CSV saved:[/bold green] {csv_path}")
    return md_path
