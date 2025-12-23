"""
Base agent module for AI Code Review Agent.

Defines the abstract base class that all agents must inherit from.
"""

import logging
from abc import ABC, abstractmethod
from typing import Optional

from src.models.schemas import Finding


class BaseAgent(ABC):
    """
    Abstract base class for all code review agents.

    All specialized agents (quality, security, testing) must inherit from this class
    and implement the analyze method.

    Attributes:
        name: The name of the agent.
        description: A description of what the agent analyzes.
        logger: Logger instance for the agent.
    """

    def __init__(self, name: str, description: str) -> None:
        """
        Initialize the base agent.

        Args:
            name: The name of the agent.
            description: A description of what the agent analyzes.
        """
        self._name = name
        self._description = description
        self._logger = logging.getLogger(f"ai_code_review.agents.{name}")

    @property
    def name(self) -> str:
        """Get the agent name."""
        return self._name

    @property
    def description(self) -> str:
        """Get the agent description."""
        return self._description

    @property
    def logger(self) -> logging.Logger:
        """Get the agent logger."""
        return self._logger

    @abstractmethod
    async def analyze(
        self,
        code: str,
        file_path: str = "untitled.py",
        language: str = "python",
    ) -> list[Finding]:
        """
        Analyze code and return findings.

        This method must be implemented by all subclasses.

        Args:
            code: The source code to analyze.
            file_path: Path to the file being analyzed.
            language: Programming language of the code.

        Returns:
            List of Finding objects representing issues found.
        """
        pass

    def _create_finding(
        self,
        file_path: str,
        line_number: int,
        severity: str,
        category: str,
        message: str,
        suggestion: str = "",
        rule_id: Optional[str] = None,
        code_snippet: Optional[str] = None,
        confidence: float = 1.0,
        **kwargs,
    ) -> Finding:
        """
        Create a Finding object with the agent name automatically set.

        Args:
            file_path: Path to the file containing the issue.
            line_number: Line number where the issue was found.
            severity: Severity level (critical/high/medium/low/info).
            category: Category of the finding.
            message: Description of the issue.
            suggestion: Recommended fix or improvement.
            rule_id: Optional rule identifier from the tool.
            code_snippet: Optional code snippet showing the issue.
            confidence: Confidence level (0.0 to 1.0).
            **kwargs: Additional fields for the Finding.

        Returns:
            A Finding object with all fields populated.
        """
        from src.models.schemas import FindingCategory, Severity as SeverityEnum

        # Convert string severity to enum
        try:
            severity_enum = SeverityEnum(severity.lower())
        except ValueError:
            severity_enum = SeverityEnum.MEDIUM

        # Convert string category to enum
        try:
            category_enum = FindingCategory(category.lower())
        except ValueError:
            category_enum = FindingCategory.OTHER

        return Finding(
            file_path=file_path,
            line_number=line_number,
            severity=severity_enum,
            category=category_enum,
            message=message,
            suggestion=suggestion,
            agent_name=self.name,
            rule_id=rule_id,
            code_snippet=code_snippet,
            confidence=confidence,
            **kwargs,
        )

    def _log_analysis_start(self, file_path: str) -> None:
        """Log the start of analysis."""
        self.logger.info(f"Starting analysis of {file_path}")

    def _log_analysis_complete(self, file_path: str, findings_count: int) -> None:
        """Log the completion of analysis."""
        self.logger.info(f"Completed analysis of {file_path}: {findings_count} findings")

    def _log_error(self, message: str, exc: Optional[Exception] = None) -> None:
        """Log an error."""
        if exc:
            self.logger.error(f"{message}: {exc}", exc_info=True)
        else:
            self.logger.error(message)

    def __repr__(self) -> str:
        """Return string representation of the agent."""
        return f"{self.__class__.__name__}(name='{self.name}')"

