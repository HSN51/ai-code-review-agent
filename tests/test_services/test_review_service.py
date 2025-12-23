"""
Tests for Review Service.

Tests main review orchestration and GitHub PR integration.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

from src.agents.orchestrator import Orchestrator
from src.models.schemas import (
    CodeAnalysisRequest,
    Finding,
    FindingCategory,
    GitHubPRRequest,
    ReviewResult,
    ReviewStatus,
    Severity,
)
from src.services.github_service import GitHubService, PRDetails, PRFile
from src.services.review_service import ReviewService


class TestReviewService:
    """Tests for ReviewService class."""

    def test_init(self):
        """Test ReviewService initialization."""
        service = ReviewService()
        assert service._orchestrator is not None
        assert service._github_service is not None
        assert service._reviews == {}

    def test_init_with_custom_services(self):
        """Test initialization with custom services."""
        orchestrator = Orchestrator(agents=[])
        github = GitHubService(token="test")
        
        service = ReviewService(
            orchestrator=orchestrator,
            github_service=github,
        )
        
        assert service._orchestrator is orchestrator
        assert service._github_service is github

    @pytest.mark.asyncio
    async def test_review_code(self, review_service, sample_python_code):
        """Test code review."""
        request = CodeAnalysisRequest(
            code=sample_python_code,
            file_path="test.py",
            language="python",
        )
        
        result = await review_service.review_code(request)
        
        assert isinstance(result.id, UUID)
        assert result.status == ReviewStatus.COMPLETED
        # Result should be stored
        assert result.id in review_service._reviews

    @pytest.mark.asyncio
    async def test_review_code_stores_result(self, review_service):
        """Test that review results are stored."""
        request = CodeAnalysisRequest(
            code="x = 1",
            file_path="test.py",
        )
        
        result = await review_service.review_code(request)
        stored = await review_service.get_review(result.id)
        
        assert stored is not None
        assert stored.id == result.id

    @pytest.mark.asyncio
    async def test_review_github_pr_not_configured(self):
        """Test GitHub PR review when not configured."""
        github = GitHubService(token="")
        service = ReviewService(github_service=github)
        
        request = GitHubPRRequest(
            repo_owner="owner",
            repo_name="repo",
            pr_number=1,
        )
        
        result = await service.review_github_pr(request)
        
        assert result.status == ReviewStatus.FAILED
        assert "not configured" in result.summary.lower()

    @pytest.mark.asyncio
    async def test_review_github_pr_not_found(self):
        """Test GitHub PR review when PR not found."""
        mock_github = AsyncMock(spec=GitHubService)
        mock_github.is_configured = True
        mock_github.get_pr_details = AsyncMock(return_value=None)
        
        service = ReviewService(github_service=mock_github)
        
        request = GitHubPRRequest(
            repo_owner="owner",
            repo_name="repo",
            pr_number=999,
        )
        
        result = await service.review_github_pr(request)
        
        assert result.status == ReviewStatus.FAILED
        assert "not" in result.summary.lower() or "could" in result.summary.lower()

    @pytest.mark.asyncio
    async def test_review_github_pr_success(self):
        """Test successful GitHub PR review."""
        mock_github = AsyncMock(spec=GitHubService)
        mock_github.is_configured = True
        
        pr_file = PRFile(
            filename="test.py",
            status="modified",
            additions=10,
            deletions=5,
            changes=15,
            patch="@@ -1 +1 @@\n-old\n+new",
            contents_url="https://api.github.com/...",
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
        
        mock_github.get_pr_details = AsyncMock(return_value=pr_details)
        mock_github.get_file_content = AsyncMock(return_value="x = 1\ny = 2")
        mock_github.create_review = AsyncMock(return_value=True)
        
        mock_orchestrator = AsyncMock(spec=Orchestrator)
        mock_orchestrator.review = AsyncMock(return_value=ReviewResult(
            findings=[],
            status=ReviewStatus.COMPLETED,
        ))
        
        service = ReviewService(
            orchestrator=mock_orchestrator,
            github_service=mock_github,
        )
        
        request = GitHubPRRequest(
            repo_owner="owner",
            repo_name="repo",
            pr_number=1,
        )
        
        result = await service.review_github_pr(request)
        
        assert result.status == ReviewStatus.COMPLETED
        assert result.files_analyzed == 1

    @pytest.mark.asyncio
    async def test_review_github_pr_with_post_review(self):
        """Test GitHub PR review with posting."""
        mock_github = AsyncMock(spec=GitHubService)
        mock_github.is_configured = True
        
        pr_file = PRFile(
            filename="test.py",
            status="modified",
            additions=10,
            deletions=5,
            changes=15,
            patch="",
            contents_url="",
        )
        
        pr_details = PRDetails(
            number=1,
            title="Test PR",
            body="",
            state="open",
            user="testuser",
            head_sha="abc123",
            base_sha="def456",
            head_ref="feature",
            base_ref="main",
            files=[pr_file],
            diff_url="",
            html_url="",
        )
        
        finding = Finding(
            file_path="test.py",
            line_number=1,
            severity=Severity.HIGH,
            category=FindingCategory.CODE_SMELL,
            message="Test issue",
            agent_name="TestAgent",
        )
        
        mock_github.get_pr_details = AsyncMock(return_value=pr_details)
        mock_github.get_file_content = AsyncMock(return_value="x = 1")
        mock_github.create_review = AsyncMock(return_value=True)
        
        mock_orchestrator = AsyncMock(spec=Orchestrator)
        mock_orchestrator.review = AsyncMock(return_value=ReviewResult(
            findings=[finding],
            status=ReviewStatus.COMPLETED,
        ))
        
        service = ReviewService(
            orchestrator=mock_orchestrator,
            github_service=mock_github,
        )
        
        request = GitHubPRRequest(
            repo_owner="owner",
            repo_name="repo",
            pr_number=1,
            post_review=True,
        )
        
        result = await service.review_github_pr(request)
        
        mock_github.create_review.assert_called_once()

    @pytest.mark.asyncio
    async def test_review_github_pr_skips_non_python(self):
        """Test that non-Python files are skipped."""
        mock_github = AsyncMock(spec=GitHubService)
        mock_github.is_configured = True
        
        pr_files = [
            PRFile(filename="test.js", status="modified", additions=0, deletions=0, changes=0, patch="", contents_url=""),
            PRFile(filename="test.py", status="modified", additions=0, deletions=0, changes=0, patch="", contents_url=""),
        ]
        
        pr_details = PRDetails(
            number=1, title="", body="", state="open", user="",
            head_sha="abc", base_sha="def", head_ref="", base_ref="",
            files=pr_files, diff_url="", html_url="",
        )
        
        mock_github.get_pr_details = AsyncMock(return_value=pr_details)
        mock_github.get_file_content = AsyncMock(return_value="x = 1")
        
        mock_orchestrator = AsyncMock(spec=Orchestrator)
        mock_orchestrator.review = AsyncMock(return_value=ReviewResult(
            findings=[],
            status=ReviewStatus.COMPLETED,
        ))
        
        service = ReviewService(
            orchestrator=mock_orchestrator,
            github_service=mock_github,
        )
        
        request = GitHubPRRequest(repo_owner="o", repo_name="r", pr_number=1)
        result = await service.review_github_pr(request)
        
        # Only Python files should be analyzed
        assert mock_orchestrator.review.call_count == 1

    @pytest.mark.asyncio
    async def test_review_github_pr_skips_deleted(self):
        """Test that deleted files are skipped."""
        mock_github = AsyncMock(spec=GitHubService)
        mock_github.is_configured = True
        
        pr_files = [
            PRFile(filename="deleted.py", status="removed", additions=0, deletions=10, changes=10, patch="", contents_url=""),
            PRFile(filename="modified.py", status="modified", additions=5, deletions=0, changes=5, patch="", contents_url=""),
        ]
        
        pr_details = PRDetails(
            number=1, title="", body="", state="open", user="",
            head_sha="abc", base_sha="def", head_ref="", base_ref="",
            files=pr_files, diff_url="", html_url="",
        )
        
        mock_github.get_pr_details = AsyncMock(return_value=pr_details)
        mock_github.get_file_content = AsyncMock(return_value="x = 1")
        
        mock_orchestrator = AsyncMock(spec=Orchestrator)
        mock_orchestrator.review = AsyncMock(return_value=ReviewResult(
            findings=[],
            status=ReviewStatus.COMPLETED,
        ))
        
        service = ReviewService(
            orchestrator=mock_orchestrator,
            github_service=mock_github,
        )
        
        request = GitHubPRRequest(repo_owner="o", repo_name="r", pr_number=1)
        result = await service.review_github_pr(request)
        
        # Only modified file should be analyzed
        assert mock_orchestrator.review.call_count == 1

    @pytest.mark.asyncio
    async def test_get_review_not_found(self, review_service):
        """Test getting non-existent review."""
        from uuid import uuid4
        
        result = await review_service.get_review(uuid4())
        assert result is None

    def test_calculate_score_no_findings(self, review_service):
        """Test score calculation with no findings."""
        score = review_service._calculate_score([])
        assert score == 100.0

    def test_calculate_score_with_findings(self, review_service):
        """Test score calculation with findings."""
        findings = [
            Finding(
                file_path="test.py",
                line_number=1,
                severity=Severity.CRITICAL,
                category=FindingCategory.INJECTION,
                message="Critical",
                agent_name="Test",
            ),
        ]
        score = review_service._calculate_score(findings)
        assert score < 100.0

    def test_format_finding_comment(self, review_service, sample_finding):
        """Test finding comment formatting."""
        comment = review_service._format_finding_comment(sample_finding)
        
        assert sample_finding.severity.value.upper() in comment
        assert sample_finding.message in comment

    @pytest.mark.asyncio
    async def test_review_github_pr_exception(self):
        """Test exception handling in PR review."""
        mock_github = AsyncMock(spec=GitHubService)
        mock_github.is_configured = True
        mock_github.get_pr_details = AsyncMock(side_effect=Exception("API Error"))
        
        service = ReviewService(github_service=mock_github)
        
        request = GitHubPRRequest(repo_owner="o", repo_name="r", pr_number=1)
        result = await service.review_github_pr(request)
        
        assert result.status == ReviewStatus.FAILED
        assert "error" in result.summary.lower()

