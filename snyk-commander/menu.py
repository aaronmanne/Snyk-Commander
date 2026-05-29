"""Interactive options menu."""

from rich.prompt import Prompt

from .config import console
from .api import SnykClient
from .report import display_results, generate_report
from .ignore import manage_ignores


def _report_submenu(org: dict, results: list, client: SnykClient, cache=None) -> None:
    """Sub-menu: let the user choose which vulnerabilities to include in the report."""
    console.print("\n[bold cyan]Generate Report[/bold cyan]")
    console.print("  [cyan]1[/cyan] - All vulnerabilities")
    console.print("  [cyan]2[/cyan] - Non-fixable only")
    console.print("  [cyan]3[/cyan] - Non-fixable above a risk score")
    console.print("  [cyan]4[/cyan] - Cancel")
    console.print()

    choice = Prompt.ask("Choose an option", default="1")

    if choice == "4" or not choice:
        return

    report_mode = "all"
    min_risk_score = 0

    if choice == "1":
        report_mode = "all"

    elif choice == "2":
        report_mode = "non_fixable"

    elif choice == "3":
        report_mode = "non_fixable_above_score"
        raw = Prompt.ask("Minimum risk score (0–1000)", default="0")
        try:
            val = int(raw)
            min_risk_score = max(0, min(1000, val))
        except (ValueError, TypeError):
            console.print("[yellow]Invalid input — using 0.[/yellow]")
            min_risk_score = 0

    else:
        console.print("[yellow]Unknown option — returning.[/yellow]")
        return

    generate_report(org, results, client=client, cache=cache,
                    report_mode=report_mode, min_risk_score=min_risk_score)


class OptionsMenu:
    """Post-scan interactive options menu."""

    def __init__(self, client: SnykClient, cache=None):
        self.client = client
        self.cache = cache

    def show(self, org: dict, results: list[dict]) -> str:
        """Display the menu and loop until the user exits or rescans.

        Returns:
            "rescan" or "exit"
        """
        while True:
            console.print("\n[bold cyan]╔══════════════════════════════════╗[/bold cyan]")
            console.print("[bold cyan]║          Options Menu            ║[/bold cyan]")
            console.print("[bold cyan]╚══════════════════════════════════╝[/bold cyan]\n")
            console.print("  [cyan]1[/cyan] - View Vulnerability Summary")
            console.print("  [cyan]2[/cyan] - Manage Ignores")
            console.print("  [cyan]3[/cyan] - Generate report")
            console.print("  [cyan]4[/cyan] - Rescan Org")
            console.print("  [cyan]5[/cyan] - Exit")
            console.print()

            choice = Prompt.ask("Choose an option", default="1")

            if choice == "1":
                vuln_results = [r for r in results if r.get("total_vulns", 0) > 0]
                if vuln_results:
                    display_results(vuln_results)
                else:
                    console.print("[green]No vulnerabilities found![/green]")

            elif choice == "2":
                manage_ignores(results, client=self.client, org=org, cache=self.cache)

            elif choice == "3":
                _report_submenu(org, results, self.client, cache=self.cache)

            elif choice == "4":
                return "rescan"

            elif choice == "5":
                return "exit"
