"""
Orchestrator for AI Code Review Agent.

Coordinates all agents and aggregates findings into a comprehensive review.
"""

import asyncio
import logging
import time
from typing import Optional
from uuid import uuid4

from src.agents.base_agent import BaseAgent
from src.agents.quality_agent import QualityAgent
from src.agents.security_agent import SecurityAgent
from src.agents.testing_agent import TestingAgent
from src.analyzers.llm_analyzer import LLMAnalyzer
from src.analyzers.static_analyzer import StaticAnalyzer
from src.models.schemas import Finding, ReviewResult, ReviewStatus, Severity


class Orchestrator:
    """
    Orchestrates all code review agents.

    Coordinates the execution of quality, security, and testing agents,
    runs them in parallel, aggregates findings, removes duplicates,
    and generates an overall review summary.
    """

    def __init__(
        self,
        static_analyzer: Optional[StaticAnalyzer] = None,
        llm_analyzer: Optional[LLMAnalyzer] = None,
        agents: Optional[list[BaseAgent]] = None,
    ) -> None:
        """
        Initialize the Orchestrator.

        Args:
            static_analyzer: Shared static analyzer instance.
            llm_analyzer: Shared LLM analyzer instance.
            agents: List of agents to use. If not provided, default agents are created.
        """
        self._logger = logging.getLogger("ai_code_review.orchestrator")

        # Create shared analyzers
        self._static_analyzer = static_analyzer or StaticAnalyzer()
        self._llm_analyzer = llm_analyzer or LLMAnalyzer()

        # Create agents with shared analyzers
        if agents:
            self._agents = agents
        else:
            self._agents = [
                QualityAgent(self._static_analyzer, self._llm_analyzer),
                SecurityAgent(self._static_analyzer, self._llm_analyzer),
                TestingAgent(self._llm_analyzer),
            ]

    @property
    def agents(self) -> list[BaseAgent]:
        """Get list of registered agents."""
        return self._agents

    def add_agent(self, agent: BaseAgent) -> None:
        """
        Add an agent to the orchestrator.

        Args:
            agent: Agent to add.
        """
        self._agents.append(agent)
        self._logger.info(f"Added agent: {agent.name}")

    def remove_agent(self, agent_name: str) -> bool:
        """
        Remove an agent by name.

        Args:
            agent_name: Name of the agent to remove.

        Returns:
            True if agent was removed, False if not found.
        """
        for i, agent in enumerate(self._agents):
            if agent.name == agent_name:
                self._agents.pop(i)
                self._logger.info(f"Removed agent: {agent_name}")
                return True
        return False

    async def review(
        self,
        code: str,
        file_path: str = "untitled.py",
        language: str = "python",
    ) -> ReviewResult:
        """
        Perform a comprehensive code review.

        Runs all agents in parallel, aggregates findings, removes duplicates,
        prioritizes by severity, and generates an overall summary.

        Args:
            code: The source code to review.
            file_path: Path to the file being reviewed.
            language: Programming language of the code.

        Returns:
            ReviewResult with all findings and summary.
        """
        start_time = time.time()
        review_id = uuid4()

        self._logger.info(f"Starting review {review_id} for {file_path}")

        result = ReviewResult(
            id=review_id,
            status=ReviewStatus.IN_PROGRESS,
            files_analyzed=1,
            total_lines=len(code.splitlines()),
        )

        try:
            # Run all agents in parallel
            all_findings = await self._run_agents_parallel(code, file_path, language)

            # Deduplicate findings
            deduplicated = self._deduplicate_findings(all_findings)

            # Sort by severity (critical first)
            sorted_findings = self._sort_by_severity(deduplicated)

            # Generate agent summaries
            agent_summaries = self._generate_agent_summaries(sorted_findings)

            # Calculate overall score
            score = self._calculate_score(sorted_findings, len(code.splitlines()))

            # Generate overall summary
            summary = await self._generate_summary(
                code, file_path, sorted_findings, score
            )

            # Update result
            result.findings = sorted_findings
            result.summary = summary
            result.overall_score = score
            result.agent_summaries = agent_summaries
            result.status = ReviewStatus.COMPLETED

        except Exception as e:
            self._logger.error(f"Review {review_id} failed: {e}", exc_info=True)
            result.status = ReviewStatus.FAILED
            result.summary = f"Review failed: {str(e)}"

        result.execution_time = time.time() - start_time
        self._logger.info(
            f"Review {review_id} completed in {result.execution_time:.2f}s "
            f"with {len(result.findings)} findings"
        )

        return result

    async def _run_agents_parallel(
        self,
        code: str,
        file_path: str,
        language: str,
    ) -> list[Finding]:
        """
        Run all agents in parallel.

        Args:
            code: The source code.
            file_path: Path to the file.
            language: Programming language.

        Returns:
            Combined list of findings from all agents.
        """
        tasks = [
            agent.analyze(code, file_path, language)
            for agent in self._agents
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings = []
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self._logger.error(
                    f"Agent {self._agents[i].name} failed: {result}",
                    exc_info=True,
                )
            else:
                all_findings.extend(result)

        return all_findings

    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """
        Remove duplicate findings.

        Deduplication is based on file path, line number, and message similarity.

        Args:
            findings: List of findings to deduplicate.

        Returns:
            Deduplicated list of findings.
        """
        seen = set()
        deduplicated = []

        for finding in findings:
            # Create a key based on location and message content
            key = (
                finding.file_path,
                finding.line_number,
                finding.message[:100],  # First 100 chars of message
            )

            if key not in seen:
                seen.add(key)
                deduplicated.append(finding)
            else:
                # If duplicate, keep the one with higher confidence
                for i, existing in enumerate(deduplicated):
                    existing_key = (
                        existing.file_path,
                        existing.line_number,
                        existing.message[:100],
                    )
                    if existing_key == key and finding.confidence > existing.confidence:
                        deduplicated[i] = finding
                        break

        return deduplicated

    def _sort_by_severity(self, findings: list[Finding]) -> list[Finding]:
        """
        Sort findings by severity (critical first).

        Args:
            findings: List of findings to sort.

        Returns:
            Sorted list of findings.
        """
        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }

        return sorted(
            findings,
            key=lambda f: (severity_order.get(f.severity, 5), f.line_number),
        )

    def _generate_agent_summaries(self, findings: list[Finding]) -> dict[str, str]:
        """
        Generate summary for each agent.

        Args:
            findings: All findings.

        Returns:
            Dictionary mapping agent names to summaries.
        """
        summaries = {}
        agent_findings: dict[str, list[Finding]] = {}

        # Group findings by agent
        for finding in findings:
            if finding.agent_name not in agent_findings:
                agent_findings[finding.agent_name] = []
            agent_findings[finding.agent_name].append(finding)

        # Generate summary for each agent
        for agent_name, agent_list in agent_findings.items():
            critical = sum(1 for f in agent_list if f.severity == Severity.CRITICAL)
            high = sum(1 for f in agent_list if f.severity == Severity.HIGH)
            medium = sum(1 for f in agent_list if f.severity == Severity.MEDIUM)
            low = sum(1 for f in agent_list if f.severity == Severity.LOW)

            parts = []
            if critical:
                parts.append(f"{critical} critical")
            if high:
                parts.append(f"{high} high")
            if medium:
                parts.append(f"{medium} medium")
            if low:
                parts.append(f"{low} low")

            if parts:
                summaries[agent_name] = f"Found {', '.join(parts)} severity issues"
            else:
                summaries[agent_name] = "No issues found"

        # Add summary for agents with no findings
        for agent in self._agents:
            if agent.name not in summaries:
                summaries[agent.name] = "No issues found"

        return summaries

    def _calculate_score(self, findings: list[Finding], total_lines: int) -> float:
        """
        Calculate overall code quality score.

        Score starts at 100 and is reduced based on findings.

        Args:
            findings: List of findings.
            total_lines: Total lines of code.

        Returns:
            Score from 0 to 100.
        """
        if not findings:
            return 100.0

        # Deduction weights per severity
        weights = {
            Severity.CRITICAL: 15.0,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 3.0,
            Severity.LOW: 1.0,
            Severity.INFO: 0.5,
        }

        total_deduction = 0.0
        for finding in findings:
            deduction = weights.get(finding.severity, 1.0)
            # Reduce deduction slightly based on confidence
            deduction *= finding.confidence
            total_deduction += deduction

        # Scale deduction based on code size (more lenient for larger files)
        size_factor = max(1.0, total_lines / 100)
        scaled_deduction = total_deduction / size_factor

        score = max(0.0, 100.0 - scaled_deduction)
        return round(score, 1)

    async def _generate_summary(
        self,
        code: str,
        file_path: str,
        findings: list[Finding],
        score: float,
    ) -> str:
        """
        Generate an overall summary of the review.

        Args:
            code: The source code.
            file_path: Path to the file.
            findings: List of findings.
            score: Overall score.

        Returns:
            Summary string.
        """
        # Count by severity
        counts = {
            "critical": sum(1 for f in findings if f.severity == Severity.CRITICAL),
            "high": sum(1 for f in findings if f.severity == Severity.HIGH),
            "medium": sum(1 for f in findings if f.severity == Severity.MEDIUM),
            "low": sum(1 for f in findings if f.severity == Severity.LOW),
        }

        # Build basic summary
        if not findings:
            return f"Code review completed for {file_path}. No issues found. Score: {score}/100"

        parts = []
        if counts["critical"]:
            parts.append(f"{counts['critical']} critical")
        if counts["high"]:
            parts.append(f"{counts['high']} high")
        if counts["medium"]:
            parts.append(f"{counts['medium']} medium")
        if counts["low"]:
            parts.append(f"{counts['low']} low")

        basic_summary = (
            f"Code review completed for {file_path}. "
            f"Found {len(findings)} issues ({', '.join(parts)} severity). "
            f"Score: {score}/100"
        )

        # Try to enhance with AI summary
        try:
            ai_summary = await self._llm_analyzer.generate_review_summary(
                code=code,
                findings=[f.model_dump() for f in findings[:10]],  # Limit to top 10
                score=score,
            )
            if ai_summary:
                return f"{basic_summary}\n\n{ai_summary}"
        except Exception as e:
            self._logger.warning(f"Could not generate AI summary: {e}")

        return basic_summary

    async def review_multiple(
        self,
        files: dict[str, str],
        language: str = "python",
    ) -> list[ReviewResult]:
        """
        Review multiple files.

        Args:
            files: Dictionary mapping file paths to code content.
            language: Programming language.

        Returns:
            List of ReviewResult objects.
        """
        tasks = [
            self.review(code, file_path, language)
            for file_path, code in files.items()
        ]
        return await asyncio.gather(*tasks)

