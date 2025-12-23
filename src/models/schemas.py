"""
Pydantic schemas for AI Code Review Agent.

Defines data models for findings, reviews, and API requests/responses.
"""

from datetime import datetime
from enum import Enum
from typing import Optional
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, field_validator


class Severity(str, Enum):
    """Severity levels for findings."""

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class FindingCategory(str, Enum):
    """Categories for code review findings."""

    # Quality categories
    CODE_SMELL = "code_smell"
    COMPLEXITY = "complexity"
    NAMING = "naming"
    STYLE = "style"
    DUPLICATION = "duplication"
    MAINTAINABILITY = "maintainability"

    # Security categories
    SQL_INJECTION = "sql_injection"
    XSS = "xss"
    HARDCODED_SECRET = "hardcoded_secret"
    INSECURE_IMPORT = "insecure_import"
    AUTHENTICATION = "authentication"
    AUTHORIZATION = "authorization"
    CRYPTOGRAPHY = "cryptography"
    INJECTION = "injection"

    # Testing categories
    MISSING_TEST = "missing_test"
    LOW_COVERAGE = "low_coverage"
    EDGE_CASE = "edge_case"
    TEST_QUALITY = "test_quality"

    # General
    BEST_PRACTICE = "best_practice"
    PERFORMANCE = "performance"
    DOCUMENTATION = "documentation"
    ERROR_HANDLING = "error_handling"
    OTHER = "other"


class ReviewStatus(str, Enum):
    """Status of a code review."""

    PENDING = "pending"
    IN_PROGRESS = "in_progress"
    COMPLETED = "completed"
    FAILED = "failed"


class Finding(BaseModel):
    """
    Represents a single finding from code analysis.

    Attributes:
        id: Unique identifier for the finding.
        file_path: Path to the file containing the issue.
        line_number: Line number where the issue was found.
        end_line_number: Optional end line for multi-line issues.
        column: Optional column number.
        severity: Severity level of the finding.
        category: Category of the finding.
        message: Description of the issue.
        suggestion: Recommended fix or improvement.
        agent_name: Name of the agent that found the issue.
        rule_id: Optional rule/check identifier from the tool.
        code_snippet: Optional code snippet showing the issue.
        owasp_category: Optional OWASP category for security findings.
        confidence: Confidence level of the finding (0.0 to 1.0).
    """

    id: UUID = Field(default_factory=uuid4, description="Unique finding identifier")
    file_path: str = Field(..., min_length=1, description="Path to the file")
    line_number: int = Field(..., ge=1, description="Line number of the issue")
    end_line_number: Optional[int] = Field(None, ge=1, description="End line for multi-line issues")
    column: Optional[int] = Field(None, ge=0, description="Column number")
    severity: Severity = Field(..., description="Severity level")
    category: FindingCategory = Field(..., description="Finding category")
    message: str = Field(..., min_length=1, description="Issue description")
    suggestion: str = Field(default="", description="Recommended fix")
    agent_name: str = Field(..., min_length=1, description="Agent that found the issue")
    rule_id: Optional[str] = Field(None, description="Rule identifier from the tool")
    code_snippet: Optional[str] = Field(None, description="Code snippet showing the issue")
    owasp_category: Optional[str] = Field(None, description="OWASP category for security issues")
    confidence: float = Field(default=1.0, ge=0.0, le=1.0, description="Confidence level")

    @field_validator("end_line_number", mode="after")
    @classmethod
    def validate_end_line(cls, v: Optional[int], info) -> Optional[int]:
        """Ensure end_line_number is >= line_number if provided."""
        if v is not None:
            line_number = info.data.get("line_number")
            if line_number is not None and v < line_number:
                return line_number
        return v

    class Config:
        """Pydantic model configuration."""

        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440000",
                "file_path": "src/main.py",
                "line_number": 42,
                "severity": "high",
                "category": "sql_injection",
                "message": "Possible SQL injection vulnerability detected",
                "suggestion": "Use parameterized queries instead of string concatenation",
                "agent_name": "SecurityAgent",
                "rule_id": "B608",
                "owasp_category": "A03:2021-Injection",
                "confidence": 0.95,
            }
        }


class ReviewResult(BaseModel):
    """
    Complete result of a code review.

    Attributes:
        id: Unique identifier for the review.
        findings: List of all findings from the review.
        summary: AI-generated summary of the review.
        timestamp: When the review was performed.
        overall_score: Overall code quality score (0-100).
        status: Current status of the review.
        files_analyzed: Number of files analyzed.
        total_lines: Total lines of code analyzed.
        execution_time: Time taken for the review in seconds.
        agent_summaries: Summary from each agent.
    """

    id: UUID = Field(default_factory=uuid4, description="Unique review identifier")
    findings: list[Finding] = Field(default_factory=list, description="List of findings")
    summary: str = Field(default="", description="Review summary")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Review timestamp")
    overall_score: float = Field(default=100.0, ge=0.0, le=100.0, description="Overall score")
    status: ReviewStatus = Field(default=ReviewStatus.PENDING, description="Review status")
    files_analyzed: int = Field(default=0, ge=0, description="Number of files analyzed")
    total_lines: int = Field(default=0, ge=0, description="Total lines analyzed")
    execution_time: float = Field(default=0.0, ge=0.0, description="Execution time in seconds")
    agent_summaries: dict[str, str] = Field(
        default_factory=dict, description="Summary from each agent"
    )

    @property
    def critical_count(self) -> int:
        """Count of critical severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        """Count of high severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)

    @property
    def medium_count(self) -> int:
        """Count of medium severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.MEDIUM)

    @property
    def low_count(self) -> int:
        """Count of low severity findings."""
        return sum(1 for f in self.findings if f.severity == Severity.LOW)

    @property
    def findings_by_severity(self) -> dict[str, list[Finding]]:
        """Group findings by severity level."""
        result: dict[str, list[Finding]] = {s.value: [] for s in Severity}
        for finding in self.findings:
            result[finding.severity.value].append(finding)
        return result

    @property
    def findings_by_category(self) -> dict[str, list[Finding]]:
        """Group findings by category."""
        result: dict[str, list[Finding]] = {}
        for finding in self.findings:
            category = finding.category.value
            if category not in result:
                result[category] = []
            result[category].append(finding)
        return result

    class Config:
        """Pydantic model configuration."""

        json_schema_extra = {
            "example": {
                "id": "550e8400-e29b-41d4-a716-446655440001",
                "findings": [],
                "summary": "Code review completed. Found 3 issues: 1 high, 2 medium.",
                "timestamp": "2024-01-15T10:30:00Z",
                "overall_score": 85.5,
                "status": "completed",
                "files_analyzed": 5,
                "total_lines": 500,
                "execution_time": 12.5,
            }
        }


class CodeAnalysisRequest(BaseModel):
    """
    Request model for analyzing a code snippet.

    Attributes:
        code: The code content to analyze.
        file_path: Virtual file path for the code (used for context).
        language: Programming language of the code.
    """

    code: str = Field(..., min_length=1, description="Code content to analyze")
    file_path: str = Field(default="untitled.py", description="Virtual file path")
    language: str = Field(default="python", description="Programming language")

    @field_validator("code", mode="after")
    @classmethod
    def validate_code_size(cls, v: str) -> str:
        """Validate code size is within limits."""
        max_size = 1_000_000  # 1MB
        if len(v.encode("utf-8")) > max_size:
            raise ValueError(f"Code size exceeds maximum of {max_size} bytes")
        return v

    @field_validator("language", mode="before")
    @classmethod
    def normalize_language(cls, v: str) -> str:
        """Normalize language identifier."""
        language_map = {
            "py": "python",
            "js": "javascript",
            "ts": "typescript",
            "rb": "ruby",
            "rs": "rust",
            "go": "golang",
            "java": "java",
            "cpp": "c++",
            "c": "c",
        }
        if isinstance(v, str):
            normalized = v.lower().strip()
            return language_map.get(normalized, normalized)
        return v

    class Config:
        """Pydantic model configuration."""

        json_schema_extra = {
            "example": {
                "code": "def hello():\n    print('Hello, World!')",
                "file_path": "example.py",
                "language": "python",
            }
        }


class GitHubPRRequest(BaseModel):
    """
    Request model for analyzing a GitHub Pull Request.

    Attributes:
        repo_owner: Repository owner/organization.
        repo_name: Repository name.
        pr_number: Pull request number.
        include_comments: Whether to include existing PR comments.
        post_review: Whether to post review comments to GitHub.
    """

    repo_owner: str = Field(..., min_length=1, description="Repository owner")
    repo_name: str = Field(..., min_length=1, description="Repository name")
    pr_number: int = Field(..., ge=1, description="Pull request number")
    include_comments: bool = Field(default=False, description="Include existing comments")
    post_review: bool = Field(default=False, description="Post review to GitHub")

    @property
    def full_repo_name(self) -> str:
        """Get full repository name in owner/repo format."""
        return f"{self.repo_owner}/{self.repo_name}"

    class Config:
        """Pydantic model configuration."""

        json_schema_extra = {
            "example": {
                "repo_owner": "octocat",
                "repo_name": "hello-world",
                "pr_number": 42,
                "include_comments": False,
                "post_review": False,
            }
        }


class HealthResponse(BaseModel):
    """Health check response model."""

    status: str = Field(default="healthy", description="Service status")
    version: str = Field(default="1.0.0", description="Application version")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Check timestamp")
    openai_configured: bool = Field(default=False, description="OpenAI API configured")
    github_configured: bool = Field(default=False, description="GitHub API configured")


class ErrorResponse(BaseModel):
    """Error response model for API errors."""

    error: str = Field(..., description="Error type")
    message: str = Field(..., description="Error message")
    detail: Optional[str] = Field(None, description="Additional details")
    timestamp: datetime = Field(default_factory=datetime.utcnow, description="Error timestamp")

