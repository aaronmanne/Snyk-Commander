"""Fix PR triggering via Playwright browser automation."""

import time

from rich.prompt import Prompt, Confirm

from .config import console, safe_print


class FixPRManager:
    """Manages triggering fix PRs through the Snyk UI via Playwright."""

    def __init__(self, token: str):
        self.token = token

    def _create_browser_context(self, headless: bool = True):
        """Create a Playwright browser context authenticated with Snyk."""
        from playwright.sync_api import sync_playwright

        pw = sync_playwright().start()
        browser = pw.chromium.launch(headless=headless)
        context = browser.new_context()
        page = context.new_page()

        page.goto("https://app.snyk.io/login/token", wait_until="domcontentloaded", timeout=30000)
        time.sleep(2)

        safe_print(f"[dim]Login page URL: {page.url}[/dim]")

        token_input = None
        selectors = [
            'input[name="token"]',
            'input[type="password"]',
            'input[type="text"]',
            '#token',
            'input',
        ]
        for sel in selectors:
            try:
                loc = page.locator(sel)
                if loc.count() > 0:
                    token_input = loc.first
                    safe_print(f"[dim]Found input with selector: {sel}[/dim]")
                    break
            except Exception:
                continue

        if token_input is None:
            safe_print("[yellow]No token input found on login page. Trying cookie injection…[/yellow]")
            context.add_cookies([{
                "name": "snyk-token",
                "value": self.token,
                "domain": ".snyk.io",
                "path": "/",
            }])
            page.close()
        else:
            token_input.fill(self.token)
            submit = page.locator(
                'button[type="submit"], input[type="submit"], '
                'button:has-text("Log in"), button:has-text("Authenticate")'
            )
            if submit.count() > 0:
                submit.first.click()
            else:
                token_input.press("Enter")

            try:
                page.wait_for_url("**/org/**", timeout=30000)
                safe_print("[green]Browser authenticated successfully.[/green]")
            except Exception:
                safe_print(f"[yellow]Login redirect unclear (URL: {page.url}). Proceeding…[/yellow]")
            page.close()

        return pw, browser, context

    @staticmethod
    def _trigger_fix_pr(context, org_slug: str, project_id: str) -> tuple[bool, str]:
        """Trigger a fix PR for a single project."""
        page = context.new_page()
        try:
            fix_url = f"https://app.snyk.io/org/{org_slug}/fix/{project_id}"
            page.goto(fix_url, wait_until="networkidle", timeout=60000)

            result = page.evaluate("""
                async (args) => {
                    const [orgSlug, projectId] = args;
                    try {
                        const resp = await fetch(
                            `/registry/org/${orgSlug}/fix-request/v2/${projectId}`,
                            {
                                method: 'POST',
                                headers: {'Content-Type': 'application/json'},
                                body: '{}',
                                credentials: 'include',
                            }
                        );
                        const text = await resp.text();
                        return {status: resp.status, body: text.substring(0, 500)};
                    } catch (e) {
                        return {status: 0, body: e.toString()};
                    }
                }
            """, [org_slug, project_id])

            status = result.get("status", 0)
            body = result.get("body", "")
            if status in (200, 201):
                return True, f"{status}"
            else:
                return False, f"{status}: {body[:200]}"
        except Exception as exc:
            return False, f"{type(exc).__name__}: {exc}"
        finally:
            page.close()

    def handle_fix_prs(self, org_id: str, org_slug: str, results: list[dict]):
        """Interactive fix PR workflow."""
        fixable = [r for r in results if r.get("fixable")]
        if not fixable:
            console.print("\n[yellow]No projects have available fix PRs.[/yellow]")
            return

        console.print(f"\n[bold]{len(fixable)}[/bold] project(s) have fixable vulnerabilities.\n")
        choice = Prompt.ask(
            "[bold]Would you like to[/bold]\n"
            "  [cyan]1[/cyan] - Trigger fix PRs for ALL fixable projects\n"
            "  [cyan]2[/cyan] - Review each project one-by-one\n"
            "  [cyan]3[/cyan] - Skip\n"
            "Choose",
            choices=["1", "2", "3"],
            default="2",
        )

        headless = True
        if choice in ("1", "2"):
            headless = not Confirm.ask("[dim]Show browser window for debugging?[/dim]", default=False)

        if choice == "3":
            console.print("[dim]Skipped fix PRs.[/dim]")
            return

        safe_print(f"[dim]Launching {'headless ' if headless else ''}browser and authenticating…[/dim]")
        try:
            pw, browser, context = self._create_browser_context(headless=headless)
        except Exception as exc:
            console.print(f"[red]Failed to launch browser: {exc}[/red]")
            console.print("[yellow]Tip: Run 'playwright install chromium' if not installed.[/yellow]")
            return

        try:
            if choice == "1":
                console.print(f"\n[bold green]Triggering fix PRs for {len(fixable)} projects…[/bold green]")
                succeeded, failed = 0, 0
                for proj in fixable:
                    ok, msg = self._trigger_fix_pr(context, org_slug, proj["id"])
                    if ok:
                        succeeded += 1
                        console.print(f"  [green]✓[/green] {proj['name']}")
                    else:
                        failed += 1
                        console.print(f"  [red]✗[/red] {proj['name']} — [dim]{msg}[/dim]")
                    time.sleep(1.5)
                console.print(f"\n[bold]Results:[/bold] {succeeded} succeeded, {failed} failed")

            elif choice == "2":
                for r in fixable:
                    s = r.get("severity", {})
                    console.print(
                        f"\n[bold]{r['name']}[/bold]  "
                        f"C:{s.get('critical', 0)} H:{s.get('high', 0)} "
                        f"M:{s.get('medium', 0)} L:{s.get('low', 0)}"
                    )
                    if Confirm.ask("  Trigger fix PR?", default=False):
                        ok, msg = self._trigger_fix_pr(context, org_slug, r["id"])
                        if ok:
                            console.print(f"  [green]✓ Triggered[/green]")
                        else:
                            console.print(f"  [red]✗ Failed[/red] [dim]{msg}[/dim]")
                        time.sleep(1.5)
                    else:
                        console.print("  [dim]Skipped.[/dim]")
        finally:
            browser.close()
            pw.stop()
