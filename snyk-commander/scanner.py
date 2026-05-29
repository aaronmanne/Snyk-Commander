"""Threaded org scanning workflow."""

import time
from concurrent.futures import ThreadPoolExecutor, as_completed

import requests
from rich.prompt import Confirm
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, MofNCompleteColumn

from .config import MAX_THREADS, MAX_RETRIES, console
from .api import SnykClient


class OrgScanner:
    """Scans all projects in a Snyk org for vulnerabilities."""

    def __init__(self, client: SnykClient, max_threads: int = MAX_THREADS):
        self.client = client
        self.max_threads = max_threads

    def _fetch_project_data(self, org_id: str, proj: dict) -> tuple[dict, list, dict]:
        """Fetch active issues, ignored issues, and ignore map for a single project.

        All three API calls run sequentially inside one worker thread; because
        every project gets its own thread the calls are effectively parallelised
        across projects at no extra wall-clock cost.

        Returns:
            (scan_result_dict, ignored_issues, ignores_map)

        Ignored-data failures are non-fatal — we fall back to empty collections
        so a permission error on the ignores endpoint never blocks a scan.
        """
        # ── Active (non-ignored) issues — failure is fatal for this project ──
        try:
            issues = self.client.get_issues(org_id, proj["id"])
        except (requests.ConnectionError, requests.Timeout) as exc:
            raise RuntimeError(f"Connection error for {proj['name']}: {exc}") from exc

        # ── Ignored issues — non-fatal ────────────────────────────────────────
        try:
            ignored_issues = self.client.get_ignored_issues(org_id, proj["id"])
        except Exception:
            ignored_issues = []

        # ── Ignore expiry map — non-fatal ─────────────────────────────────────
        try:
            ignores_map = self.client.get_project_ignores(org_id, proj["id"])
        except Exception:
            ignores_map = {}

        sev = self._count_by_severity(issues)
        fixable = self._check_fixable(issues)
        scan_result = {
            **proj,
            "issues": issues,
            "severity": sev,
            "fixable": fixable,
            "total_vulns": sum(sev.values()),
        }
        return scan_result, ignored_issues, ignores_map

    @staticmethod
    def _count_by_severity(issues: list[dict]) -> dict:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for i in issues:
            sev = i.get("issueData", {}).get("severity", "low")
            counts[sev] = counts.get(sev, 0) + 1
        return counts

    @staticmethod
    def _check_fixable(issues: list[dict]) -> bool:
        for i in issues:
            if i.get("isUpgradable") or i.get("isPatchable") or i.get("isPinnable"):
                return True
            fix_info = i.get("fixInfo", {})
            if fix_info.get("isUpgradable") or fix_info.get("isPatchable") or fix_info.get("isPinnable"):
                return True
        return False

    def scan(self, org: dict, cache=None) -> list[dict]:
        """Scan every project in an org using a thread pool with retry logic.

        When *cache* is provided the ignored-issues data collected during
        the scan is saved immediately so report generation never needs a
        separate API round-trip.
        """
        org_id = org["id"]
        console.print(f"\n[bold cyan]Scanning org:[/bold cyan] {org['name']} ({org_id})")

        with console.status("[bold green]Fetching project list…[/bold green]"):
            for attempt in range(1, MAX_RETRIES + 1):
                try:
                    projects = self.client.list_projects(org_id)
                    break
                except (requests.ConnectionError, requests.Timeout, requests.HTTPError) as exc:
                    if attempt < MAX_RETRIES:
                        wait = 2 ** attempt
                        console.print(f"  [yellow]Project list fetch failed (attempt {attempt}), retrying in {wait}s…[/yellow]")
                        time.sleep(wait)
                    else:
                        console.print(f"  [red]Failed to fetch project list after {MAX_RETRIES} attempts: {exc}[/red]")
                        return []

        if not projects:
            console.print("  [dim]No projects found.[/dim]")
            return []

        console.print(f"  Found [bold]{len(projects)}[/bold] projects. Scanning with {self.max_threads} threads…\n")

        results: list[dict] = []
        # Accumulate ignored data keyed by project_id for the cache
        ignored_data: dict[str, dict] = {}

        pending = list(projects)
        attempt_counts: dict[str, int] = {}
        permanently_failed: list[dict] = []

        round_num = 0
        while pending:
            round_num += 1
            if round_num > 1:
                wait = min(2 ** round_num, 30)
                console.print(f"\n[yellow]Retry round {round_num - 1}: retrying {len(pending)} failed project(s) after {wait}s cooldown…[/yellow]")
                time.sleep(wait)

            failed_this_round: list[dict] = []

            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                MofNCompleteColumn(),
                TextColumn("[dim]{task.fields[status]}[/dim]"),
                console=console,
            ) as progress:
                label = "Scanning" if round_num == 1 else f"Retry round {round_num - 1}"
                task_id = progress.add_task(label, total=len(pending), status="")

                with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                    future_to_proj = {
                        executor.submit(self._fetch_project_data, org_id, proj): proj
                        for proj in pending
                    }

                    for future in as_completed(future_to_proj):
                        proj = future_to_proj[future]
                        pid = proj["id"]
                        attempt_counts[pid] = attempt_counts.get(pid, 0) + 1

                        try:
                            scan_result, ignored_issues, ignores_map = future.result()
                            results.append(scan_result)
                            ignored_data[pid] = {
                                "ignored_issues": ignored_issues,
                                "ignores_map": ignores_map,
                            }
                            progress.update(task_id, advance=1, status=f"[green]OK[/green] {proj['name'][:40]}")
                        except Exception:
                            attempts = attempt_counts[pid]
                            if attempts >= MAX_RETRIES:
                                permanently_failed.append(proj)
                                progress.update(task_id, advance=1,
                                                status=f"[red]FAILED ({attempts}x)[/red] {proj['name'][:40]}")
                            else:
                                failed_this_round.append(proj)
                                progress.update(task_id, advance=1,
                                                status=f"[yellow]ERR ({attempts}x)[/yellow] {proj['name'][:40]}")

            pending = failed_this_round

        # ── Handle permanently failed projects ────────────────────────────
        if permanently_failed:
            console.print(
                f"\n[bold red]{len(permanently_failed)}[/bold red] project(s) failed after "
                f"{MAX_RETRIES} attempts each:"
            )
            for p in permanently_failed:
                console.print(f"  [red]✗[/red] {p['name']}")

            if Confirm.ask("\n[bold]Retry these failed projects one more time?[/bold]", default=False):
                console.print("[yellow]Retrying permanently failed projects…[/yellow]")
                still_failed: list[dict] = []

                with Progress(
                    SpinnerColumn(),
                    TextColumn("[progress.description]{task.description}"),
                    BarColumn(),
                    MofNCompleteColumn(),
                    TextColumn("[dim]{task.fields[status]}[/dim]"),
                    console=console,
                ) as progress:
                    task_id = progress.add_task("Final retry", total=len(permanently_failed), status="")

                    with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
                        future_to_proj = {
                            executor.submit(self._fetch_project_data, org_id, proj): proj
                            for proj in permanently_failed
                        }
                        for future in as_completed(future_to_proj):
                            proj = future_to_proj[future]
                            pid = proj["id"]
                            try:
                                scan_result, ignored_issues, ignores_map = future.result()
                                results.append(scan_result)
                                ignored_data[pid] = {
                                    "ignored_issues": ignored_issues,
                                    "ignores_map": ignores_map,
                                }
                                progress.update(task_id, advance=1,
                                                status=f"[green]OK[/green] {proj['name'][:40]}")
                            except Exception:
                                still_failed.append(proj)
                                progress.update(task_id, advance=1,
                                                status=f"[red]FAILED[/red] {proj['name'][:40]}")

                if still_failed:
                    console.print(
                        f"\n[red]{len(still_failed)} project(s) still failed. Continuing with "
                        f"{len(results)} successful results.[/red]"
                    )
            else:
                console.print(
                    f"[dim]Skipping failed projects. Continuing with "
                    f"{len(results)} successful results.[/dim]"
                )

        # ── Persist ignored data to cache alongside scan results ──────────
        if cache is not None and ignored_data:
            cache.save_ignored_data(org_id, ignored_data)

        return results
