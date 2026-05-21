"""Cache management for scan results."""

import json
import time
from pathlib import Path

from .config import CACHE_DIR, console


def _org_cache_file(org_id: str) -> Path:
    """Return the cache file path for a specific org."""
    return CACHE_DIR / f"scan_{org_id}.json"


class CacheManager:
    """Manages reading, writing, and deleting scan result caches per org."""

    def save(self, org: dict, results: list[dict]):
        """Save scan results to a per-org JSON cache file preserving all issue data."""
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
        cache_file = _org_cache_file(org["id"])
        cache_file.write_text(json.dumps(payload, indent=2))
        console.print(f"[dim]Cache saved to {cache_file}[/dim]")

    def load(self, org_id: str) -> dict | None:
        """Load cached scan results for a specific org."""
        cache_file = _org_cache_file(org_id)
        if not cache_file.exists():
            return None
        try:
            return json.loads(cache_file.read_text())
        except (json.JSONDecodeError, KeyError):
            return None

    def load_all(self) -> list[dict]:
        """Load all cached org scan results. Returns list of cache payloads."""
        if not CACHE_DIR.exists():
            return []
        results = []
        for f in CACHE_DIR.glob("scan_*.json"):
            try:
                data = json.loads(f.read_text())
                if data and "org" in data:
                    results.append(data)
            except (json.JSONDecodeError, KeyError):
                continue
        return results

    def delete(self, org_id: str):
        """Delete the cache file for a specific org."""
        cache_file = _org_cache_file(org_id)
        if cache_file.exists():
            cache_file.unlink()
            console.print(f"[dim]Cache deleted for org {org_id}.[/dim]")

    def delete_all(self):
        """Delete all cache files."""
        if not CACHE_DIR.exists():
            return
        for f in CACHE_DIR.glob("scan_*.json"):
            f.unlink()
        console.print("[dim]All caches deleted.[/dim]")
