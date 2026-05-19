"""Configuration constants and shared resources."""

import threading
from pathlib import Path

from rich.console import Console

API_V1 = "https://api.snyk.io/v1"
API_REST = "https://api.snyk.io/rest"
REST_VERSION = "2024-10-15"
MAX_THREADS = 30
MAX_RETRIES = 3
REQUEST_TIMEOUT = 60
CONCURRENT_REQUESTS = 15
CACHE_DIR = Path(__file__).parent.parent / ".snyk_cache"
CACHE_FILE = CACHE_DIR / "scan_results.json"
REPORTS_DIR = Path(__file__).parent.parent / "reports"

console = Console()
print_lock = threading.Lock()
api_semaphore = threading.Semaphore(CONCURRENT_REQUESTS)


def safe_print(*args, **kwargs):
    """Thread-safe console.print."""
    with print_lock:
        console.print(*args, **kwargs)
