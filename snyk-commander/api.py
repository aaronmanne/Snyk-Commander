"""Snyk API client with connection pooling and pagination."""

import os
import threading

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
from rich.prompt import Prompt

from .config import (
    API_V1, API_REST, REST_VERSION, MAX_THREADS, REQUEST_TIMEOUT, api_semaphore
)

_thread_local = threading.local()


class SnykClient:
    """Handles all Snyk API interactions."""

    def __init__(self, token: str):
        self.token = token

    @staticmethod
    def get_token() -> str:
        """Retrieve token from environment or prompt the user."""
        token = os.environ.get("SNYK_TOKEN")
        if not token:
            token = Prompt.ask("[bold]Enter your Snyk API token[/bold]", password=True)
        return token

    @property
    def _headers_v1(self) -> dict:
        return {"Authorization": f"token {self.token}", "Content-Type": "application/json"}

    @property
    def _headers_rest(self) -> dict:
        return {"Authorization": f"token {self.token}", "Content-Type": "application/vnd.api+json"}

    def _get_session(self) -> requests.Session:
        """Get or create a thread-local session with retry logic."""
        if not hasattr(_thread_local, "session"):
            session = requests.Session()
            retries = Retry(
                total=5,
                backoff_factor=2,
                status_forcelist=[429, 500, 502, 503, 504],
                allowed_methods=["GET", "POST"],
                raise_on_status=False,
            )
            adapter = HTTPAdapter(
                max_retries=retries,
                pool_connections=MAX_THREADS,
                pool_maxsize=MAX_THREADS,
            )
            session.mount("https://", adapter)
            session.mount("http://", adapter)
            _thread_local.session = session
        return _thread_local.session

    def rest_get_all(self, path: str, params: dict | None = None) -> list:
        """Paginate through a Snyk REST endpoint and return all data items."""
        session = self._get_session()
        items: list = []
        url = f"{API_REST}{path}"
        p = {"version": REST_VERSION, "limit": 100, **(params or {})}
        while url:
            with api_semaphore:
                resp = session.get(url, headers=self._headers_rest, params=p, timeout=REQUEST_TIMEOUT)
            resp.raise_for_status()
            body = resp.json()
            items.extend(body.get("data", []))
            next_link = body.get("links", {}).get("next")
            if next_link:
                if next_link.startswith("http"):
                    url = next_link
                elif next_link.startswith("/rest/"):
                    url = f"https://api.snyk.io{next_link}"
                else:
                    url = f"{API_REST}{next_link}"
                p = {}
            else:
                url = None
        return items

    def list_orgs(self) -> list[dict]:
        """Return list of orgs the token has access to."""
        data = self.rest_get_all("/orgs")
        return [{"id": o["id"], "name": o["attributes"].get("name", o["id"]),
                 "slug": o["attributes"].get("slug", o["id"])} for o in data]

    def list_projects(self, org_id: str) -> list[dict]:
        """Return all projects in an org via REST API."""
        data = self.rest_get_all(f"/orgs/{org_id}/projects")
        projects = []
        for p in data:
            attrs = p.get("attributes", {})
            projects.append({
                "id": p["id"],
                "name": attrs.get("name", p["id"]),
                "type": attrs.get("type", "unknown"),
                "origin": attrs.get("origin", "unknown"),
            })
        return projects

    def get_issues(self, org_id: str, project_id: str) -> list[dict]:
        """Get aggregated issues for a project (v1 endpoint)."""
        session = self._get_session()
        url = f"{API_V1}/org/{org_id}/project/{project_id}/aggregated-issues"
        body = {
            "filters": {
                "severities": ["critical", "high", "medium", "low"],
                "types": ["vuln"],
                "ignored": False,
                "patched": False,
            }
        }
        with api_semaphore:
            resp = session.post(url, headers=self._headers_v1, json=body, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("issues", [])

    def ignore_issue(self, org_id: str, project_id: str, issue_id: str,
                     reason: str, expires: str, disregard_if_fixable: bool = True) -> dict:
        """Ignore a vulnerability in Snyk via the API.

        POST /org/{orgId}/project/{projectId}/ignore/{issueId}
        """
        session = self._get_session()
        url = f"{API_V1}/org/{org_id}/project/{project_id}/ignore/{issue_id}"
        body = {
            "ignorePath": "*",
            "reason": reason,
            "expires": expires,
            "disregardIfFixable": disregard_if_fixable,
            "reasonType": "temporary-ignore",
        }
        with api_semaphore:
            resp = session.post(url, headers=self._headers_v1, json=body, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json()

    def get_ignored_issues(self, org_id: str, project_id: str) -> list[dict]:
        """Get aggregated issues that are currently ignored for a project (v1 endpoint)."""
        session = self._get_session()
        url = f"{API_V1}/org/{org_id}/project/{project_id}/aggregated-issues"
        body = {
            "filters": {
                "severities": ["critical", "high", "medium", "low"],
                "types": ["vuln"],
                "ignored": True,
                "patched": False,
            }
        }
        with api_semaphore:
            resp = session.post(url, headers=self._headers_v1, json=body, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        return resp.json().get("issues", [])

    def get_project_ignores(self, org_id: str, project_id: str) -> dict[str, str]:
        """Return {vuln_id: expires_str} for all active ignores on a project.

        Calls GET /org/{orgId}/project/{projectId}/ignores.
        The Snyk response shape is:
            { "SNYK-JS-FOO-123": [ { "*": [ { "reason": "...", "expires": "...", ... } ] } ] }
        """
        session = self._get_session()
        url = f"{API_V1}/org/{org_id}/project/{project_id}/ignores"
        with api_semaphore:
            resp = session.get(url, headers=self._headers_v1, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
        data = resp.json()
        result: dict[str, str] = {}
        for vuln_id, path_list in data.items():
            # path_list is a list of {path_key: [detail_dicts]}
            for path_entry in path_list:
                for _path_key, details_list in path_entry.items():
                    items = details_list if isinstance(details_list, list) else [details_list]
                    for details in items:
                        expires = details.get("expires")
                        if expires and vuln_id not in result:
                            result[vuln_id] = expires
        return result

    def unignore_issue(self, org_id: str, project_id: str, issue_id: str) -> None:
        """Remove an ignore for a vulnerability in Snyk via the API.

        DELETE /org/{orgId}/project/{projectId}/ignore/{issueId}
        """
        session = self._get_session()
        url = f"{API_V1}/org/{org_id}/project/{project_id}/ignore/{issue_id}"
        with api_semaphore:
            resp = session.delete(url, headers=self._headers_v1, timeout=REQUEST_TIMEOUT)
        resp.raise_for_status()
