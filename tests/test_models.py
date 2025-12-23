"""
Tests for Pydantic models/schemas.

Tests data validation and model behavior.
"""

import pytest
from datetime import datetime
from uuid import UUID

from src.models.schemas import (
    CodeAnalysisRequest,
    ErrorResponse,
    Finding,
    FindingCategory,
    GitHubPRRequest,
    HealthResponse,
    ReviewResult,
    ReviewStatus,
    Severity,
)


class TestSeverity:
    """Tests for Severity enum."""

    def test_severity_values(self):
        """Test all severity values exist."""
        assert Severity.CRITICAL.value == "critical"
        assert Severity.HIGH.value == "high"
        assert Severity.MEDIUM.value == "medium"
        assert Severity.LOW.value == "low"
        assert Severity.INFO.value == "info"


class TestFindingCategory:
    """Tests for FindingCategory enum."""

    def test_quality_categories(self):
        """Test quality-related categories."""
        assert FindingCategory.CODE_SMELL.value == "code_smell"
        assert FindingCategory.COMPLEXITY.value == "complexity"
        assert FindingCategory.NAMING.value == "naming"
        assert FindingCategory.STYLE.value == "style"

    def test_security_categories(self):
        """Test security-related categories."""
        assert FindingCategory.SQL_INJECTION.value == "sql_injection"
        assert FindingCategory.XSS.value == "xss"
        assert FindingCategory.HARDCODED_SECRET.value == "hardcoded_secret"
        assert FindingCategory.INJECTION.value == "injection"

    def test_testing_categories(self):
        """Test testing-related categories."""
        assert FindingCategory.MISSING_TEST.value == "missing_test"
        assert FindingCategory.LOW_COVERAGE.value == "low_coverage"
        assert FindingCategory.EDGE_CASE.value == "edge_case"


class TestFinding:
    """Tests for Finding model."""

    def test_finding_creation(self):
        """Test basic finding creation."""
        finding = Finding(
            file_path="test.py",
            line_number=10,
            severity=Severity.HIGH,
            category=FindingCategory.CODE_SMELL,
            message="Test message",
            agent_name="TestAgent",
        )
        
        assert finding.file_path == "test.py"
        assert finding.line_number == 10
        assert finding.severity == Severity.HIGH
        assert isinstance(finding.id, UUID)

    def test_finding_with_all_fields(self):
        """Test finding with all optional fields."""
        finding = Finding(
            file_path="test.py",
            line_number=10,
            end_line_number=15,
            column=5,
            severity=Severity.CRITICAL,
            category=FindingCategory.SQL_INJECTION,
            message="SQL injection detected",
            suggestion="Use parameterized queries",
            agent_name="SecurityAgent",
            rule_id="B608",
            code_snippet="query = f'SELECT * FROM users WHERE id = {id}'",
            owasp_category="A03:2021-Injection",
            confidence=0.95,
        )
        
        assert finding.end_line_number == 15
        assert finding.column == 5
        assert finding.owasp_category == "A03:2021-Injection"

    def test_finding_end_line_validation(self):
        """Test end_line_number is >= line_number."""
        finding = Finding(
            file_path="test.py",
            line_number=10,
            end_line_number=5,  # Less than line_number
            severity=Severity.LOW,
            category=FindingCategory.STYLE,
            message="Test",
            agent_name="Test",
        )
        
        # Should be corrected to be at least line_number
        assert finding.end_line_number >= finding.line_number

    def test_finding_default_confidence(self):
        """Test default confidence value."""
        finding = Finding(
            file_path="test.py",
            line_number=1,
            severity=Severity.LOW,
            category=FindingCategory.OTHER,
            message="Test",
            agent_name="Test",
        )
        
        assert finding.confidence == 1.0

    def test_finding_json_schema(self):
        """Test JSON schema example exists."""
        schema = Finding.model_json_schema()
        assert schema is not None


class TestReviewResult:
    """Tests for ReviewResult model."""

    def test_review_result_creation(self):
        """Test basic review result creation."""
        result = ReviewResult()
        
        assert isinstance(result.id, UUID)
        assert result.findings == []
        assert result.status == ReviewStatus.PENDING
        assert result.overall_score == 100.0

    def test_review_result_with_findings(self):
        """Test review result with findings."""
        finding = Finding(
            file_path="test.py",
            line_number=1,
            severity=Severity.HIGH,
            category=FindingCategory.CODE_SMELL,
            message="Test",
            agent_name="Test",
        )
        
        result = ReviewResult(
            findings=[finding],
            summary="Test summary",
            overall_score=85.0,
        )
        
        assert len(result.findings) == 1
        assert result.overall_score == 85.0

    def test_review_result_severity_counts(self):
        """Test severity count properties."""
        findings = [
            Finding(file_path="test.py", line_number=1, severity=Severity.CRITICAL, category=FindingCategory.INJECTION, message="1", agent_name="Test"),
            Finding(file_path="test.py", line_number=2, severity=Severity.CRITICAL, category=FindingCategory.INJECTION, message="2", agent_name="Test"),
            Finding(file_path="test.py", line_number=3, severity=Severity.HIGH, category=FindingCategory.CODE_SMELL, message="3", agent_name="Test"),
            Finding(file_path="test.py", line_number=4, severity=Severity.MEDIUM, category=FindingCategory.STYLE, message="4", agent_name="Test"),
            Finding(file_path="test.py", line_number=5, severity=Severity.LOW, category=FindingCategory.NAMING, message="5", agent_name="Test"),
        ]
        
        result = ReviewResult(findings=findings)
        
        assert result.critical_count == 2
        assert result.high_count == 1
        assert result.medium_count == 1
        assert result.low_count == 1

    def test_review_result_findings_by_severity(self):
        """Test grouping findings by severity."""
        findings = [
            Finding(file_path="test.py", line_number=1, severity=Severity.HIGH, category=FindingCategory.CODE_SMELL, message="1", agent_name="Test"),
            Finding(file_path="test.py", line_number=2, severity=Severity.HIGH, category=FindingCategory.CODE_SMELL, message="2", agent_name="Test"),
            Finding(file_path="test.py", line_number=3, severity=Severity.LOW, category=FindingCategory.STYLE, message="3", agent_name="Test"),
        ]
        
        result = ReviewResult(findings=findings)
        by_severity = result.findings_by_severity
        
        assert len(by_severity["high"]) == 2
        assert len(by_severity["low"]) == 1

    def test_review_result_findings_by_category(self):
        """Test grouping findings by category."""
        findings = [
            Finding(file_path="test.py", line_number=1, severity=Severity.HIGH, category=FindingCategory.CODE_SMELL, message="1", agent_name="Test"),
            Finding(file_path="test.py", line_number=2, severity=Severity.HIGH, category=FindingCategory.CODE_SMELL, message="2", agent_name="Test"),
            Finding(file_path="test.py", line_number=3, severity=Severity.LOW, category=FindingCategory.STYLE, message="3", agent_name="Test"),
        ]
        
        result = ReviewResult(findings=findings)
        by_category = result.findings_by_category
        
        assert len(by_category["code_smell"]) == 2
        assert len(by_category["style"]) == 1


class TestCodeAnalysisRequest:
    """Tests for CodeAnalysisRequest model."""

    def test_basic_creation(self):
        """Test basic request creation."""
        request = CodeAnalysisRequest(code="x = 1")
        
        assert request.code == "x = 1"
        assert request.file_path == "untitled.py"
        assert request.language == "python"

    def test_with_all_fields(self):
        """Test request with all fields."""
        request = CodeAnalysisRequest(
            code="const x = 1;",
            file_path="app.js",
            language="javascript",
        )
        
        assert request.file_path == "app.js"
        assert request.language == "javascript"

    def test_language_normalization(self):
        """Test language normalization."""
        request = CodeAnalysisRequest(code="x = 1", language="py")
        assert request.language == "python"
        
        request = CodeAnalysisRequest(code="x = 1", language="js")
        assert request.language == "javascript"

    def test_code_size_validation(self):
        """Test code size validation."""
        with pytest.raises(ValueError):
            CodeAnalysisRequest(code="x" * 2_000_000)  # 2MB


class TestGitHubPRRequest:
    """Tests for GitHubPRRequest model."""

    def test_basic_creation(self):
        """Test basic request creation."""
        request = GitHubPRRequest(
            repo_owner="octocat",
            repo_name="hello-world",
            pr_number=1,
        )
        
        assert request.repo_owner == "octocat"
        assert request.repo_name == "hello-world"
        assert request.pr_number == 1

    def test_full_repo_name(self):
        """Test full repo name property."""
        request = GitHubPRRequest(
            repo_owner="octocat",
            repo_name="hello-world",
            pr_number=1,
        )
        
        assert request.full_repo_name == "octocat/hello-world"

    def test_default_values(self):
        """Test default values."""
        request = GitHubPRRequest(
            repo_owner="owner",
            repo_name="repo",
            pr_number=1,
        )
        
        assert request.include_comments is False
        assert request.post_review is False

    def test_invalid_pr_number(self):
        """Test invalid PR number validation."""
        with pytest.raises(ValueError):
            GitHubPRRequest(
                repo_owner="owner",
                repo_name="repo",
                pr_number=0,
            )


class TestHealthResponse:
    """Tests for HealthResponse model."""

    def test_health_response_creation(self):
        """Test health response creation."""
        response = HealthResponse()
        
        assert response.status == "healthy"
        assert response.version == "1.0.0"
        assert isinstance(response.timestamp, datetime)


class TestErrorResponse:
    """Tests for ErrorResponse model."""

    def test_error_response_creation(self):
        """Test error response creation."""
        response = ErrorResponse(
            error="ValidationError",
            message="Invalid input",
        )
        
        assert response.error == "ValidationError"
        assert response.message == "Invalid input"
        assert isinstance(response.timestamp, datetime)

    def test_error_response_with_detail(self):
        """Test error response with detail."""
        response = ErrorResponse(
            error="InternalError",
            message="Something went wrong",
            detail="Stack trace here",
        )
        
        assert response.detail == "Stack trace here"

