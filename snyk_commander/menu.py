"""Interactive options menu."""

from rich.prompt import Prompt

from .config import console
from .api import SnykClient
from .report import display_results, generate_report
from .ignore import manage_ignores


class OptionsMenu:
    """Post-scan interactive options menu."""

    def __init__(self, client: SnykClient):
        self.client = client

    def show(self, org: dict, results: list[dict]) -> str:
        """Display the menu and loop until the user exits or rescans.

        Returns:
            "rescan" or "exit"
        """
        while True:
            console.print("\n[bold cyan]╔══════════════════════════════════╗[/bold cyan]")
            console.print("[bold cyan]║          Options Menu            ║[/bold cyan]")
            console.print("[bold cyan]╚══════════════════════════════════╝[/bold cyan]\n")
            console.print("  [cyan]1[/cyan] - View vulnerability summary table")
            console.print("  [cyan]2[/cyan] - Manage .snyk ignores")
            console.print("  [cyan]3[/cyan] - Generate report (Markdown + CSV)")
            console.print("  [cyan]4[/cyan] - Rescan org")
            console.print("  [cyan]5[/cyan] - Exit")
            console.print()

            choice = Prompt.ask("Choose an option", choices=["1", "2", "3", "4", "5"], default="1")

            if choice == "1":
                vuln_results = [r for r in results if r.get("total_vulns", 0) > 0]
                if vuln_results:
                    display_results(vuln_results)
                else:
                    console.print("[green]No vulnerabilities found![/green]")

            elif choice == "2":
                manage_ignores(results, client=self.client, org=org)

            elif choice == "3":
                generate_report(org, results)

            elif choice == "4":
                return "rescan"

            elif choice == "5":
                return "exit"
