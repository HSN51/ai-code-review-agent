"""
Tests for GitHub Service.

Tests GitHub API integration functionality.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

import httpx

from src.services.github_service import GitHubService, PRDetails, PRFile


class TestGitHubService:
    """Tests for GitHubService class."""

    def test_init(self):
        """Test GitHubService initialization."""
        service = GitHubService(token="test-token")
        assert service._token == "test-token"
        assert service.is_configured is True

    def test_init_without_token(self):
        """Test initialization without token."""
        with patch("src.services.github_service.get_settings") as mock_settings:
            mock_settings.return_value = MagicMock(github_token="")
            service = GitHubService()
            assert service.is_configured is False

    def test_init_with_placeholder_token(self):
        """Test initialization with placeholder token."""
        service = GitHubService(token="your_github_token_here")
        assert service.is_configured is False

    def test_get_headers(self):
        """Test header generation."""
        service = GitHubService(token="test-token")
        headers = service._get_headers()
        
        assert "Authorization" in headers
        assert "token test-token" in headers["Authorization"]
        assert headers["Accept"] == "application/vnd.github.v3+json"

    def test_get_headers_no_token(self):
        """Test headers without token."""
        service = GitHubService(token="")
        headers = service._get_headers()
        
        assert "Authorization" not in headers

    @pytest.mark.asyncio
    async def test_make_request_not_configured(self):
        """Test request when not configured."""
        service = GitHubService(token="")
        result = await service._make_request("GET", "/test")
        assert result is None

    @pytest.mark.asyncio
    async def test_make_request_success(self):
        """Test successful API request."""
        service = GitHubService(token="test-token")
        
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {"key": "value"}
        mock_response.headers = {"X-RateLimit-Remaining": "4999"}
        mock_response.raise_for_status = MagicMock()
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.request = AsyncMock(
                return_value=mock_response
            )
            
            result = await service._make_request("GET", "/test")
        
        assert result == {"key": "value"}

    @pytest.mark.asyncio
    async def test_make_request_404(self):
        """Test 404 response handling."""
        service = GitHubService(token="test-token")
        
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.headers = {"X-RateLimit-Remaining": "4999"}
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.request = AsyncMock(
                return_value=mock_response
            )
            
            result = await service._make_request("GET", "/test")
        
        assert result is None

    @pytest.mark.asyncio
    async def test_make_request_403(self):
        """Test 403 response handling (rate limit)."""
        service = GitHubService(token="test-token")
        
        mock_response = MagicMock()
        mock_response.status_code = 403
        mock_response.headers = {"X-RateLimit-Remaining": "0"}
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.request = AsyncMock(
                return_value=mock_response
            )
            
            result = await service._make_request("GET", "/test")
        
        assert result is None

    @pytest.mark.asyncio
    async def test_get_pr_details(self):
        """Test getting PR details."""
        service = GitHubService(token="test-token")
        
        pr_data = {
            "number": 1,
            "title": "Test PR",
            "body": "Description",
            "state": "open",
            "user": {"login": "testuser"},
            "head": {"sha": "abc123", "ref": "feature"},
            "base": {"sha": "def456", "ref": "main"},
            "diff_url": "https://diff",
            "html_url": "https://html",
        }
        
        files_data = [
            {
                "filename": "test.py",
                "status": "modified",
                "additions": 10,
                "deletions": 5,
                "changes": 15,
                "patch": "@@ -1 +1 @@",
                "contents_url": "https://contents",
            }
        ]
        
        with patch.object(service, "_make_request") as mock_request:
            mock_request.side_effect = [pr_data, files_data]
            
            result = await service.get_pr_details("owner", "repo", 1)
        
        assert isinstance(result, PRDetails)
        assert result.number == 1
        assert result.title == "Test PR"
        assert len(result.files) == 1
        assert result.files[0].filename == "test.py"

    @pytest.mark.asyncio
    async def test_get_pr_details_not_found(self):
        """Test PR not found."""
        service = GitHubService(token="test-token")
        
        with patch.object(service, "_make_request", return_value=None):
            result = await service.get_pr_details("owner", "repo", 999)
        
        assert result is None

    @pytest.mark.asyncio
    async def test_get_file_content(self):
        """Test getting file content."""
        service = GitHubService(token="test-token")
        
        import base64
        content = base64.b64encode(b"print('hello')").decode()
        
        with patch.object(service, "_make_request") as mock_request:
            mock_request.return_value = {
                "content": content,
                "encoding": "base64",
            }
            
            result = await service.get_file_content("owner", "repo", "test.py", "main")
        
        assert result == "print('hello')"

    @pytest.mark.asyncio
    async def test_get_file_content_not_found(self):
        """Test file content not found."""
        service = GitHubService(token="test-token")
        
        with patch.object(service, "_make_request", return_value=None):
            result = await service.get_file_content("owner", "repo", "nonexistent.py", "main")
        
        assert result is None

    @pytest.mark.asyncio
    async def test_get_diff(self):
        """Test getting PR diff."""
        service = GitHubService(token="test-token")
        
        mock_response = MagicMock()
        mock_response.text = "diff --git a/file.py b/file.py\n..."
        mock_response.raise_for_status = MagicMock()
        
        with patch("httpx.AsyncClient") as mock_client:
            mock_client.return_value.__aenter__.return_value.get = AsyncMock(
                return_value=mock_response
            )
            
            result = await service.get_diff("owner", "repo", 1)
        
        assert "diff" in result

    @pytest.mark.asyncio
    async def test_get_diff_not_configured(self):
        """Test diff when not configured."""
        service = GitHubService(token="")
        result = await service.get_diff("owner", "repo", 1)
        assert result is None

    @pytest.mark.asyncio
    async def test_post_review_comment(self):
        """Test posting review comment."""
        service = GitHubService(token="test-token")
        
        with patch.object(service, "_make_request", return_value={"id": 1}):
            result = await service.post_review_comment(
                owner="owner",
                repo="repo",
                pr_number=1,
                commit_sha="abc123",
                path="test.py",
                line=10,
                body="Fix this issue",
            )
        
        assert result is True

    @pytest.mark.asyncio
    async def test_post_review_comment_failure(self):
        """Test failed review comment posting."""
        service = GitHubService(token="test-token")
        
        with patch.object(service, "_make_request", return_value=None):
            result = await service.post_review_comment(
                owner="owner",
                repo="repo",
                pr_number=1,
                commit_sha="abc123",
                path="test.py",
                line=10,
                body="Fix this issue",
            )
        
        assert result is False

    @pytest.mark.asyncio
    async def test_create_review(self):
        """Test creating a PR review."""
        service = GitHubService(token="test-token")
        
        with patch.object(service, "_make_request", return_value={"id": 1}):
            result = await service.create_review(
                owner="owner",
                repo="repo",
                pr_number=1,
                commit_sha="abc123",
                body="Review summary",
                event="COMMENT",
            )
        
        assert result is True

    @pytest.mark.asyncio
    async def test_create_review_with_comments(self):
        """Test creating a PR review with inline comments."""
        service = GitHubService(token="test-token")
        
        comments = [
            {"path": "test.py", "line": 1, "body": "Comment 1"},
            {"path": "test.py", "line": 2, "body": "Comment 2"},
        ]
        
        with patch.object(service, "_make_request", return_value={"id": 1}) as mock:
            result = await service.create_review(
                owner="owner",
                repo="repo",
                pr_number=1,
                commit_sha="abc123",
                body="Review",
                comments=comments,
            )
            
            # Verify comments were passed
            call_kwargs = mock.call_args[1]
            assert "comments" in call_kwargs["json"]

    @pytest.mark.asyncio
    async def test_get_pr_comments(self):
        """Test getting PR comments."""
        service = GitHubService(token="test-token")
        
        comments = [
            {"id": 1, "body": "Comment 1"},
            {"id": 2, "body": "Comment 2"},
        ]
        
        with patch.object(service, "_make_request", return_value=comments):
            result = await service.get_pr_comments("owner", "repo", 1)
        
        assert len(result) == 2

    @pytest.mark.asyncio
    async def test_get_pr_comments_empty(self):
        """Test getting PR comments when none exist."""
        service = GitHubService(token="test-token")
        
        with patch.object(service, "_make_request", return_value=None):
            result = await service.get_pr_comments("owner", "repo", 1)
        
        assert result == []


class TestPRFile:
    """Tests for PRFile dataclass."""

    def test_pr_file_creation(self):
        """Test PRFile creation."""
        pr_file = PRFile(
            filename="test.py",
            status="modified",
            additions=10,
            deletions=5,
            changes=15,
            patch="@@ -1 +1 @@",
            contents_url="https://api.github.com/...",
        )
        
        assert pr_file.filename == "test.py"
        assert pr_file.status == "modified"
        assert pr_file.changes == 15


class TestPRDetails:
    """Tests for PRDetails dataclass."""

    def test_pr_details_creation(self):
        """Test PRDetails creation."""
        pr_file = PRFile(
            filename="test.py",
            status="modified",
            additions=0,
            deletions=0,
            changes=0,
            patch="",
            contents_url="",
        )
        
        pr_details = PRDetails(
            number=1,
            title="Test PR",
            body="Description",
            state="open",
            user="testuser",
            head_sha="abc123",
            base_sha="def456",
            head_ref="feature",
            base_ref="main",
            files=[pr_file],
            diff_url="https://...",
            html_url="https://...",
        )
        
        assert pr_details.number == 1
        assert pr_details.title == "Test PR"
        assert len(pr_details.files) == 1

