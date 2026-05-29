"""Entry point for Snyk Commander."""

import sys
import subprocess
import importlib.metadata as metadata
from pathlib import Path


REQUIREMENTS_FILE = Path(__file__).parent.parent / "requirements.txt"


def _check_dependencies() -> None:
    """Check all requirements are installed using only stdlib. Exit if not."""
    if not REQUIREMENTS_FILE.exists():
        return

    # Try to use packaging for proper requirement parsing; fall back to simple name extraction
    try:
        from packaging.requirements import Requirement

        def get_name(line):
            return Requirement(line).name
    except ImportError:
        # packaging not installed — extract name manually (strip version specifiers)
        import re

        def get_name(line):
            return re.split(r"[><=!~;]", line)[0].strip()

    missing = []
    with open(REQUIREMENTS_FILE) as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            try:
                name = get_name(line)
                metadata.distribution(name)
            except metadata.PackageNotFoundError:
                missing.append(line)
            except Exception:
                missing.append(line)

    if not missing:
        return

    # Only use stdlib print here — rich is not available
    print("\n\033[1;31mMissing required packages:\033[0m")
    for pkg in missing:
        print(f"  ✗ {pkg}")

    print("\n\033[1mTo fix this, create a virtual environment and install dependencies:\033[0m\n")
    print("  python -m venv .venv")
    print("  source .venv/bin/activate    # On Windows: .venv\\Scripts\\activate")
    print(f"  pip install -r {REQUIREMENTS_FILE.name}\n")

    answer = input("\033[1mWould you like me to do this for you? [Y/n]: \033[0m").strip().lower()
    if answer in ("", "y", "yes"):
        venv_path = Path(".venv")
        try:
            if not venv_path.exists():
                print("\nCreating virtual environment…")
                subprocess.run([sys.executable, "-m", "venv", str(venv_path)], check=True)
                print("  ✓ Created .venv")
            else:
                print("  .venv already exists, reusing.")

            if sys.platform == "win32":
                pip_path = venv_path / "Scripts" / "pip"
            else:
                pip_path = venv_path / "bin" / "pip"

            print("Installing requirements…")
            subprocess.run(
                [str(pip_path), "install", "-r", str(REQUIREMENTS_FILE)],
                check=True,
            )
            print("  ✓ All packages installed\n")
            print("\033[1;33mPlease restart Snyk Commander using the venv Python:\033[0m\n")
            print("  source .venv/bin/activate && python -m snyk-commander\n")

        except subprocess.CalledProcessError as e:
            print(f"\nSetup failed: {e}")
        except Exception as e:
            print(f"\nError: {e}")

        sys.exit(0)
    else:
        print("Please install the missing packages and try again.")
        sys.exit(1)


# --- Dependency check BEFORE any third-party imports ---
_check_dependencies()

# --- Now safe to import third-party packages ---
import requests  # noqa: E402
from rich.prompt import Confirm, Prompt  # noqa: E402

from .config import console  # noqa: E402
from .api import SnykClient  # noqa: E402
from .cache import CacheManager  # noqa: E402
from .scanner import OrgScanner  # noqa: E402
from .report import display_results  # noqa: E402
from .menu import OptionsMenu  # noqa: E402


def main():
    console.print("[bold magenta]╔══════════════════════════════════╗[/bold magenta]")
    console.print("[bold magenta]║       Snyk Commander v2.0        ║[/bold magenta]")
    console.print("[bold magenta]╚══════════════════════════════════╝[/bold magenta]\n")

    token = SnykClient.get_token()
    client = SnykClient(token)
    cache = CacheManager()
    scanner = OrgScanner(client)
    menu = OptionsMenu(client, cache=cache)

    # Verify token
    with console.status("[bold]Verifying token…[/bold]"):
        try:
            orgs = client.list_orgs()
        except requests.HTTPError as e:
            console.print(f"[bold red]Authentication failed:[/bold red] {e}")
            sys.exit(1)

    if not orgs:
        console.print("[red]No organizations found for this token.[/red]")
        sys.exit(1)

    console.print(f"[green]Authenticated.[/green] Found {len(orgs)} org(s).\n")

    # Check for cached results
    cached_orgs = cache.load_all()
    use_cache = False
    if cached_orgs:
        console.print(f"[bold yellow]Found cached scan results for {len(cached_orgs)} org(s):[/bold yellow]")
        for c in cached_orgs:
            ts = c.get("timestamp", "unknown")
            c_org = c.get("org", {})
            c_results = c.get("results", [])
            fixable_count = sum(1 for r in c_results if r.get("fixable"))
            console.print(f"  • {c_org.get('name', '?')} — {ts}  |  "
                          f"{len(c_results)} projects  |  "
                          f"{fixable_count} fixable")
        if Confirm.ask("\n[bold]Resume from cache?[/bold]", default=True):
            use_cache = True
        else:
            cache.delete_all()

    if use_cache:
        for c in cached_orgs:
            org = c["org"]
            results = c["results"]
            action = _show_and_menu(org, results, scanner, cache, menu)
            if action == "exit":
                break
    else:
        # Let user pick an org
        for idx, o in enumerate(orgs, 1):
            console.print(f"  [cyan]{idx}[/cyan] - {o['name']}")
        console.print(f"  [cyan]A[/cyan] - Scan ALL orgs")

        pick = Prompt.ask("\nSelect an org (number) or [cyan]A[/cyan] for all", default="1")

        if pick.upper() == "A":
            selected_orgs = orgs
        else:
            try:
                selected_orgs = [orgs[int(pick) - 1]]
            except (ValueError, IndexError):
                console.print("[red]Invalid selection.[/red]")
                sys.exit(1)

        for org in selected_orgs:
            results = scanner.scan(org, cache=cache)
            if not results:
                continue
            cache.save(org, results)
            action = _show_and_menu(org, results, scanner, cache, menu)
            if action == "exit":
                break

    console.print("\n[bold magenta]Done. Stay secure! 🔒[/bold magenta]")


def _show_and_menu(org, results, scanner, cache, menu) -> str:
    """Display results and enter menu loop. Handles rescan."""
    vuln_results = [r for r in results if r.get("total_vulns", 0) > 0]
    console.print(f"\n[bold]{len(vuln_results)}/{len(results)}[/bold] projects have vulnerabilities.")
    if vuln_results:
        display_results(vuln_results)

    action = menu.show(org, results)
    if action == "rescan":
        cache.delete(org["id"])
        results = scanner.scan(org, cache=cache)
        if results:
            cache.save(org, results)
            return _show_and_menu(org, results, scanner, cache, menu)
    return action


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n\n[yellow]Interrupted. Exiting gracefully.[/yellow]")
        sys.exit(0)
