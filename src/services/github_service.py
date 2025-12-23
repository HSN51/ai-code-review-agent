"""
GitHub Service for AI Code Review Agent.

Provides GitHub API integration for fetching PRs, diffs, and posting reviews.
"""

import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

import httpx

from src.config import get_settings


@dataclass
class PRFile:
    """Represents a file changed in a PR."""

    filename: str
    status: str  # added, removed, modified, renamed
    additions: int
    deletions: int
    changes: int
    patch: Optional[str]
    contents_url: str
    raw_url: Optional[str] = None


@dataclass
class PRDetails:
    """Represents details of a Pull Request."""

    number: int
    title: str
    body: Optional[str]
    state: str
    user: str
    head_sha: str
    base_sha: str
    head_ref: str
    base_ref: str
    files: list[PRFile]
    diff_url: str
    html_url: str


class GitHubService:
    """
    GitHub API integration service.

    Provides methods to fetch PR details, changed files, diffs,
    and post review comments.
    """

    def __init__(
        self,
        token: Optional[str] = None,
        api_url: Optional[str] = None,
    ) -> None:
        """
        Initialize the GitHub Service.

        Args:
            token: GitHub personal access token. Uses settings if not provided.
            api_url: GitHub API base URL. Uses settings if not provided.
        """
        self._logger = logging.getLogger("ai_code_review.github_service")
        settings = get_settings()

        self._token = token or settings.github_token
        self._api_url = (api_url or settings.github_api_url).rstrip("/")

        # Rate limiting state
        self._rate_limit_remaining = 5000
        self._rate_limit_reset = 0

    @property
    def is_configured(self) -> bool:
        """Check if GitHub is properly configured."""
        return bool(self._token and self._token != "your_github_token_here")

    def _get_headers(self) -> dict[str, str]:
        """Get HTTP headers for GitHub API requests."""
        headers = {
            "Accept": "application/vnd.github.v3+json",
            "User-Agent": "AI-Code-Review-Agent/1.0",
        }
        if self._token and self._token != "your_github_token_here":
            headers["Authorization"] = f"token {self._token}"
        return headers

    async def _make_request(
        self,
        method: str,
        endpoint: str,
        **kwargs,
    ) -> Optional[dict | list]:
        """
        Make a request to the GitHub API.

        Args:
            method: HTTP method.
            endpoint: API endpoint.
            **kwargs: Additional arguments for httpx.

        Returns:
            Response JSON or None.
        """
        if not self.is_configured:
            self._logger.warning("GitHub token not configured")
            return None

        # Check rate limiting
        if self._rate_limit_remaining < 10:
            self._logger.warning("GitHub rate limit nearly exhausted")
            await asyncio.sleep(1)

        url = f"{self._api_url}{endpoint}"
        headers = self._get_headers()

        async with httpx.AsyncClient() as client:
            try:
                response = await client.request(
                    method,
                    url,
                    headers=headers,
                    timeout=30.0,
                    **kwargs,
                )

                # Update rate limit info
                self._rate_limit_remaining = int(
                    response.headers.get("X-RateLimit-Remaining", 5000)
                )
                self._rate_limit_reset = int(
                    response.headers.get("X-RateLimit-Reset", 0)
                )

                if response.status_code == 404:
                    self._logger.error(f"Resource not found: {endpoint}")
                    return None

                if response.status_code == 403:
                    self._logger.error("GitHub API rate limit exceeded or forbidden")
                    return None

                response.raise_for_status()
                return response.json()

            except httpx.HTTPStatusError as e:
                self._logger.error(f"GitHub API error: {e}")
                return None
            except httpx.RequestError as e:
                self._logger.error(f"Request failed: {e}")
                return None

    async def get_pr_details(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> Optional[PRDetails]:
        """
        Get details of a Pull Request.

        Args:
            owner: Repository owner.
            repo: Repository name.
            pr_number: PR number.

        Returns:
            PRDetails object or None.
        """
        endpoint = f"/repos/{owner}/{repo}/pulls/{pr_number}"
        pr_data = await self._make_request("GET", endpoint)

        if not pr_data:
            return None

        # Get files changed in PR
        files_endpoint = f"/repos/{owner}/{repo}/pulls/{pr_number}/files"
        files_data = await self._make_request("GET", files_endpoint)

        files = []
        if files_data:
            for file in files_data:
                files.append(PRFile(
                    filename=file.get("filename", ""),
                    status=file.get("status", "modified"),
                    additions=file.get("additions", 0),
                    deletions=file.get("deletions", 0),
                    changes=file.get("changes", 0),
                    patch=file.get("patch"),
                    contents_url=file.get("contents_url", ""),
                    raw_url=file.get("raw_url"),
                ))

        return PRDetails(
            number=pr_data.get("number", pr_number),
            title=pr_data.get("title", ""),
            body=pr_data.get("body"),
            state=pr_data.get("state", "open"),
            user=pr_data.get("user", {}).get("login", ""),
            head_sha=pr_data.get("head", {}).get("sha", ""),
            base_sha=pr_data.get("base", {}).get("sha", ""),
            head_ref=pr_data.get("head", {}).get("ref", ""),
            base_ref=pr_data.get("base", {}).get("ref", ""),
            files=files,
            diff_url=pr_data.get("diff_url", ""),
            html_url=pr_data.get("html_url", ""),
        )

    async def get_file_content(
        self,
        owner: str,
        repo: str,
        path: str,
        ref: str,
    ) -> Optional[str]:
        """
        Get content of a file at a specific ref.

        Args:
            owner: Repository owner.
            repo: Repository name.
            path: File path.
            ref: Git reference (branch, tag, commit SHA).

        Returns:
            File content or None.
        """
        endpoint = f"/repos/{owner}/{repo}/contents/{path}"
        params = {"ref": ref}

        data = await self._make_request("GET", endpoint, params=params)

        if not data:
            return None

        # Content is base64 encoded
        import base64

        content = data.get("content", "")
        encoding = data.get("encoding", "base64")

        if encoding == "base64" and content:
            try:
                return base64.b64decode(content).decode("utf-8")
            except Exception as e:
                self._logger.error(f"Failed to decode file content: {e}")
                return None

        return content

    async def get_diff(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> Optional[str]:
        """
        Get the diff of a Pull Request.

        Args:
            owner: Repository owner.
            repo: Repository name.
            pr_number: PR number.

        Returns:
            Diff string or None.
        """
        if not self.is_configured:
            return None

        url = f"{self._api_url}/repos/{owner}/{repo}/pulls/{pr_number}"
        headers = self._get_headers()
        headers["Accept"] = "application/vnd.github.v3.diff"

        async with httpx.AsyncClient() as client:
            try:
                response = await client.get(url, headers=headers, timeout=30.0)
                response.raise_for_status()
                return response.text
            except httpx.HTTPError as e:
                self._logger.error(f"Failed to get diff: {e}")
                return None

    async def post_review_comment(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        commit_sha: str,
        path: str,
        line: int,
        body: str,
        side: str = "RIGHT",
    ) -> bool:
        """
        Post a review comment on a PR.

        Args:
            owner: Repository owner.
            repo: Repository name.
            pr_number: PR number.
            commit_sha: Commit SHA to comment on.
            path: File path.
            line: Line number.
            body: Comment body.
            side: Which side of the diff (LEFT or RIGHT).

        Returns:
            True if successful, False otherwise.
        """
        endpoint = f"/repos/{owner}/{repo}/pulls/{pr_number}/comments"

        data = {
            "body": body,
            "commit_id": commit_sha,
            "path": path,
            "line": line,
            "side": side,
        }

        result = await self._make_request("POST", endpoint, json=data)
        return result is not None

    async def create_review(
        self,
        owner: str,
        repo: str,
        pr_number: int,
        commit_sha: str,
        body: str,
        event: str = "COMMENT",
        comments: Optional[list[dict]] = None,
    ) -> bool:
        """
        Create a PR review.

        Args:
            owner: Repository owner.
            repo: Repository name.
            pr_number: PR number.
            commit_sha: Commit SHA.
            body: Review body.
            event: Review event (APPROVE, REQUEST_CHANGES, COMMENT).
            comments: Optional list of review comments.

        Returns:
            True if successful, False otherwise.
        """
        endpoint = f"/repos/{owner}/{repo}/pulls/{pr_number}/reviews"

        data = {
            "commit_id": commit_sha,
            "body": body,
            "event": event,
        }

        if comments:
            data["comments"] = comments

        result = await self._make_request("POST", endpoint, json=data)
        return result is not None

    async def get_pr_comments(
        self,
        owner: str,
        repo: str,
        pr_number: int,
    ) -> list[dict]:
        """
        Get existing comments on a PR.

        Args:
            owner: Repository owner.
            repo: Repository name.
            pr_number: PR number.

        Returns:
            List of comment dictionaries.
        """
        endpoint = f"/repos/{owner}/{repo}/pulls/{pr_number}/comments"
        result = await self._make_request("GET", endpoint)
        return result if isinstance(result, list) else []

