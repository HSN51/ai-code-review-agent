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
from src.models.schemas import Finding, ReviewResult, ReviewStatus, Severity, ToolExecutionStatus, ScoreBreakdown
from src.normalization import normalize_finding, normalize_severity, normalize_category


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
            all_findings, tool_status = await self._run_agents_parallel(code, file_path, language)

            # Deduplicate findings
            deduplicated = self._deduplicate_findings(all_findings)

            # Sort by severity (critical first)
            sorted_findings = self._sort_by_severity(deduplicated)

            # Generate agent summaries
            agent_summaries = self._generate_agent_summaries(sorted_findings)

            # Calculate overall score
            score_data = self.calculate_score(sorted_findings, len(code.splitlines()))

            # Generate overall summary
            summary = await self._generate_summary(
                code, file_path, sorted_findings, score_data.final_score
            )

            # Update result
            result.findings = sorted_findings
            result.summary = summary
            result.overall_score = score_data.final_score
            result.score_breakdown = score_data
            result.agent_summaries = agent_summaries
            result.tool_status = tool_status
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
    ) -> tuple[list[Finding], dict[str, ToolExecutionStatus]]:
        """
        Run all agents in parallel.
        Returns (all_findings, aggregated_tool_status)
        """
        tasks = [
            agent.analyze(code, file_path, language)
            for agent in self._agents
        ]

        results = await asyncio.gather(*tasks, return_exceptions=True)

        all_findings = []
        tool_statuses = {}
        
        for i, result in enumerate(results):
            if isinstance(result, Exception):
                self._logger.error(
                    f"Agent {self._agents[i].name} failed: {result}",
                    exc_info=True,
                )
            else:
                # Expecting (list[Finding], dict[str, ToolExecutionStatus])
                findings, statuses = result
                all_findings.extend(findings)
                tool_statuses.update(statuses)

        return all_findings, tool_statuses

    def _deduplicate_findings(self, findings: list[Finding]) -> list[Finding]:
        """
        Remove duplicate findings using fingerprints and prioritization.
        """
        unique_map = {}
        
        for finding in findings:
            # 1. Normalize
            finding = normalize_finding(finding)
            fp = finding.fingerprint
            
            # 2. Add to sources
            if fp in unique_map:
                existing = unique_map[fp]
                if finding.agent_name not in existing.sources:
                    existing.sources.append(finding.agent_name)
                    
                # Conflict resolution:
                # Prefer SecurityAgent for security issues
                if finding.agent_name == "SecurityAgent" and existing.agent_name != "SecurityAgent":
                    # Swap
                    finding.sources = existing.sources
                    unique_map[fp] = finding
                # Else if same agent or independent, check confidence
                elif finding.confidence > existing.confidence:
                     finding.sources = existing.sources
                     unique_map[fp] = finding
            else:
                finding.sources = [finding.agent_name]
                unique_map[fp] = finding

        return list(unique_map.values())

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

    def calculate_score(self, findings: list[Finding], total_lines: int) -> ScoreBreakdown:
        """
        Calculate robust score with breakdown.
        """
        weights = {
            Severity.CRITICAL: 15.0,
            Severity.HIGH: 8.0,
            Severity.MEDIUM: 3.0,
            Severity.LOW: 1.0,
            Severity.INFO: 0.5,
        }
        
        deductions_by_severity = {s.value: 0.0 for s in Severity}
        total_deduction = 0.0
        
        for f in findings:
            weight = weights.get(f.severity, 1.0)
            deduction = weight * f.confidence
            deductions_by_severity[f.severity.value] += deduction
            total_deduction += deduction
            
        # Scale based on density
        density = len(findings) / max(50, total_lines)
        # density 0.0 -> scale 1.0
        # density 0.2 (10 issues in 50 lines) -> scale 1.1
        scale = max(0.8, min(1.2, 1.0 + (density - 0.05)))
        
        final_deduction = total_deduction * scale
        final_score = max(0.0, min(100.0, 100.0 - final_deduction))
        
        return ScoreBreakdown(
            base_score=100.0,
            total_deductions=round(final_deduction, 1),
            deductions_by_severity=deductions_by_severity,
            scale_factor=round(scale, 2),
            final_score=round(final_score, 1)
        )
            
    def _calculate_score(self, findings: list[Finding], total_lines: int) -> float:
        """Legacy wrapper"""
        return self.calculate_score(findings, total_lines).final_score

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

