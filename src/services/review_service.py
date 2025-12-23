"""
Review Service for AI Code Review Agent.

Main entry point for code reviews, coordinating the orchestrator and external services.
"""

import logging
from typing import Optional
from uuid import UUID

from src.agents.orchestrator import Orchestrator
from src.analyzers.llm_analyzer import LLMAnalyzer
from src.analyzers.static_analyzer import StaticAnalyzer
from src.models.schemas import (
    CodeAnalysisRequest,
    GitHubPRRequest,
    ReviewResult,
    ReviewStatus,
)
from src.services.github_service import GitHubService


class ReviewService:
    """
    Main service for code reviews.

    Provides a unified interface for reviewing code snippets
    and GitHub Pull Requests.
    """

    def __init__(
        self,
        orchestrator: Optional[Orchestrator] = None,
        github_service: Optional[GitHubService] = None,
    ) -> None:
        """
        Initialize the Review Service.

        Args:
            orchestrator: Orchestrator instance. Created if not provided.
            github_service: GitHub service instance. Created if not provided.
        """
        self._logger = logging.getLogger("ai_code_review.review_service")

        # Create shared analyzers
        self._static_analyzer = StaticAnalyzer()
        self._llm_analyzer = LLMAnalyzer()

        # Create orchestrator with shared analyzers
        self._orchestrator = orchestrator or Orchestrator(
            static_analyzer=self._static_analyzer,
            llm_analyzer=self._llm_analyzer,
        )

        # GitHub service
        self._github_service = github_service or GitHubService()

        # In-memory storage for review results
        self._reviews: dict[UUID, ReviewResult] = {}

    async def review_code(self, request: CodeAnalysisRequest) -> ReviewResult:
        """
        Review a code snippet.

        Args:
            request: Code analysis request with code content.

        Returns:
            ReviewResult with findings and summary.
        """
        self._logger.info(f"Starting code review for {request.file_path}")

        result = await self._orchestrator.review(
            code=request.code,
            file_path=request.file_path,
            language=request.language,
        )

        # Store result
        self._reviews[result.id] = result

        return result

    async def review_github_pr(self, request: GitHubPRRequest) -> ReviewResult:
        """
        Review a GitHub Pull Request.

        Args:
            request: GitHub PR request with repo and PR details.

        Returns:
            ReviewResult with findings and summary.
        """
        self._logger.info(
            f"Starting PR review for {request.full_repo_name}#{request.pr_number}"
        )

        # Check GitHub configuration
        if not self._github_service.is_configured:
            result = ReviewResult(
                status=ReviewStatus.FAILED,
                summary="GitHub token not configured. Please set GITHUB_TOKEN environment variable.",
            )
            self._reviews[result.id] = result
            return result

        try:
            # Fetch PR details
            pr_details = await self._github_service.get_pr_details(
                owner=request.repo_owner,
                repo=request.repo_name,
                pr_number=request.pr_number,
            )

            if not pr_details:
                result = ReviewResult(
                    status=ReviewStatus.FAILED,
                    summary=f"Could not fetch PR #{request.pr_number} from {request.full_repo_name}",
                )
                self._reviews[result.id] = result
                return result

            # Review each changed file
            all_findings = []
            files_analyzed = 0
            total_lines = 0

            for pr_file in pr_details.files:
                # Skip deleted files and non-Python files
                if pr_file.status == "removed":
                    continue

                if not pr_file.filename.endswith(".py"):
                    continue

                # Get file content
                content = await self._github_service.get_file_content(
                    owner=request.repo_owner,
                    repo=request.repo_name,
                    path=pr_file.filename,
                    ref=pr_details.head_sha,
                )

                if content:
                    # Review the file
                    file_result = await self._orchestrator.review(
                        code=content,
                        file_path=pr_file.filename,
                        language="python",
                    )

                    all_findings.extend(file_result.findings)
                    files_analyzed += 1
                    total_lines += len(content.splitlines())

            # Create combined result
            result = ReviewResult(
                status=ReviewStatus.COMPLETED,
                findings=all_findings,
                files_analyzed=files_analyzed,
                total_lines=total_lines,
            )

            # Calculate overall score
            result.overall_score = self._calculate_score(all_findings)

            # Generate summary
            result.summary = self._generate_pr_summary(
                pr_details, all_findings, result.overall_score
            )

            # Post review to GitHub if requested
            if request.post_review and all_findings:
                await self._post_github_review(
                    request, pr_details, all_findings, result.summary
                )

            # Store result
            self._reviews[result.id] = result

            return result

        except Exception as e:
            self._logger.error(f"Error reviewing PR: {e}", exc_info=True)
            result = ReviewResult(
                status=ReviewStatus.FAILED,
                summary=f"Error reviewing PR: {str(e)}",
            )
            self._reviews[result.id] = result
            return result

    async def get_review(self, review_id: UUID) -> Optional[ReviewResult]:
        """
        Get a review result by ID.

        Args:
            review_id: UUID of the review.

        Returns:
            ReviewResult or None if not found.
        """
        return self._reviews.get(review_id)

    def _calculate_score(self, findings: list) -> float:
        """Calculate overall score from findings."""
        if not findings:
            return 100.0

        from src.models.schemas import Severity

        weights = {
            Severity.CRITICAL: 15.0,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 3.0,
            Severity.LOW: 1.0,
            Severity.INFO: 0.5,
        }

        total_deduction = sum(
            weights.get(f.severity, 1.0) * f.confidence
            for f in findings
        )

        return max(0.0, round(100.0 - total_deduction, 1))

    def _generate_pr_summary(
        self,
        pr_details,
        findings: list,
        score: float,
    ) -> str:
        """Generate summary for PR review."""
        from src.models.schemas import Severity

        counts = {
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in findings if f.severity == Severity.LOW),
        }

        parts = []
        if counts["critical"]:
            parts.append(f"{counts['critical']} critical")
        if counts["high"]:
            parts.append(f"{counts['high']} high")
        if counts["medium"]:
            parts.append(f"{counts['medium']} medium")
        if counts["low"]:
            parts.append(f"{counts['low']} low")

        if not findings:
            return (
                f"✅ Code review completed for PR #{pr_details.number}: {pr_details.title}\n"
                f"No issues found. Score: {score}/100"
            )

        return (
            f"Code review completed for PR #{pr_details.number}: {pr_details.title}\n"
            f"Found {len(findings)} issues ({', '.join(parts)} severity).\n"
            f"Score: {score}/100"
        )

    async def _post_github_review(
        self,
        request: GitHubPRRequest,
        pr_details,
        findings: list,
        summary: str,
    ) -> bool:
        """Post review comments to GitHub."""
        try:
            # Build review comments
            comments = []
            for finding in findings[:20]:  # Limit to 20 comments
                comment = {
                    "path": finding.file_path,
                    "line": finding.line_number,
                    "body": self._format_finding_comment(finding),
                }
                comments.append(comment)

            # Create review
            success = await self._github_service.create_review(
                owner=request.repo_owner,
                repo=request.repo_name,
                pr_number=request.pr_number,
                commit_sha=pr_details.head_sha,
                body=summary,
                event="COMMENT",
                comments=comments if comments else None,
            )

            if success:
                self._logger.info(
                    f"Posted review with {len(comments)} comments to PR #{request.pr_number}"
                )
            else:
                self._logger.warning("Failed to post review to GitHub")

            return success

        except Exception as e:
            self._logger.error(f"Error posting review to GitHub: {e}")
            return False

    def _format_finding_comment(self, finding) -> str:
        """Format a finding as a GitHub comment."""
        severity_emoji = {
            "critical": "🚨",
            "high": "⚠️",
            "medium": "📝",
            "low": "💡",
            "info": "ℹ️",
        }

        emoji = severity_emoji.get(finding.severity.value, "📝")
        comment = f"{emoji} **{finding.severity.value.upper()}** - {finding.category.value}\n\n"
        comment += f"{finding.message}\n\n"

        if finding.suggestion:
            comment += f"**Suggestion:** {finding.suggestion}\n"

        if finding.rule_id:
            comment += f"\n_Rule: {finding.rule_id}_"

        return comment

