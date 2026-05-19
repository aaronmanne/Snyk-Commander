"""Cache management for scan results."""

import json
import time

from .config import CACHE_DIR, CACHE_FILE, console


class CacheManager:
    """Manages reading, writing, and deleting scan result caches."""

    def save(self, org: dict, results: list[dict]):
        """Save scan results to a JSON cache file preserving all issue data."""
        CACHE_DIR.mkdir(parents=True, exist_ok=True)
        cached_results = []
        for r in results:
            # Compute max risk score
            max_score = None
            for issue in r.get("issues", []):
                priority = issue.get("priority", {})
                score = priority.get("score")
                if score is None:
                    score = issue.get("issueData", {}).get("cvssScore")
                if score is not None:
                    try:
                        s = int(score)
                        if max_score is None or s > max_score:
                            max_score = s
                    except (ValueError, TypeError):
                        pass

            cached_results.append({
                "id": r["id"],
                "name": r["name"],
                "type": r["type"],
                "origin": r["origin"],
                "severity": r["severity"],
                "fixable": r["fixable"],
                "total_vulns": r["total_vulns"],
                "risk_score": max_score,
                "issues": r.get("issues", []),
            })
        payload = {
            "org": org,
            "results": cached_results,
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
        }
        CACHE_FILE.write_text(json.dumps(payload, indent=2))
        console.print(f"[dim]Cache saved to {CACHE_FILE}[/dim]")

    def load(self) -> dict | None:
        """Load cached scan results if they exist."""
        if not CACHE_FILE.exists():
            return None
        try:
            return json.loads(CACHE_FILE.read_text())
        except (json.JSONDecodeError, KeyError):
            return None

    def delete(self):
        """Delete the cache file."""
        if CACHE_FILE.exists():
            CACHE_FILE.unlink()
            console.print("[dim]Cache deleted.[/dim]")
