"""
Quality Agent for AI Code Review Agent.

Analyzes code quality using ruff, pylint, and AI-powered suggestions.
"""

from typing import Optional

from src.agents.base_agent import BaseAgent
from src.analyzers.llm_analyzer import LLMAnalyzer
from src.analyzers.static_analyzer import StaticAnalyzer
from src.models.schemas import Finding, FindingCategory, Severity


class QualityAgent(BaseAgent):
    """
    Agent for analyzing code quality.

    Uses ruff and pylint for static analysis and OpenAI for contextual suggestions.
    Detects code smells, complexity issues, naming conventions, and PEP8 violations.
    """

    # Mapping of pylint/ruff codes to categories
    CATEGORY_MAP = {
        # Complexity
        "C901": FindingCategory.COMPLEXITY,
        "PLR0911": FindingCategory.COMPLEXITY,
        "PLR0912": FindingCategory.COMPLEXITY,
        "PLR0913": FindingCategory.COMPLEXITY,
        "PLR0915": FindingCategory.COMPLEXITY,
        # Naming
        "N801": FindingCategory.NAMING,
        "N802": FindingCategory.NAMING,
        "N803": FindingCategory.NAMING,
        "N806": FindingCategory.NAMING,
        "C0103": FindingCategory.NAMING,
        # Style
        "E": FindingCategory.STYLE,
        "W": FindingCategory.STYLE,
        "C0301": FindingCategory.STYLE,
        "C0303": FindingCategory.STYLE,
        # Code smells
        "R": FindingCategory.CODE_SMELL,
        "PLR": FindingCategory.CODE_SMELL,
        # Maintainability
        "C0114": FindingCategory.MAINTAINABILITY,
        "C0115": FindingCategory.MAINTAINABILITY,
        "C0116": FindingCategory.MAINTAINABILITY,
        # Duplication
        "PLR1714": FindingCategory.DUPLICATION,
        "PLR0801": FindingCategory.DUPLICATION,
    }

    # Mapping of codes to severity
    SEVERITY_MAP = {
        "E": Severity.HIGH,
        "F": Severity.CRITICAL,
        "W": Severity.MEDIUM,
        "C": Severity.LOW,
        "R": Severity.MEDIUM,
        "N": Severity.LOW,
        "PL": Severity.MEDIUM,
    }

    def __init__(
        self,
        static_analyzer: Optional[StaticAnalyzer] = None,
        llm_analyzer: Optional[LLMAnalyzer] = None,
    ) -> None:
        """
        Initialize the Quality Agent.

        Args:
            static_analyzer: Static analyzer instance. Created if not provided.
            llm_analyzer: LLM analyzer instance. Created if not provided.
        """
        super().__init__(
            name="QualityAgent",
            description="Analyzes code quality including style, complexity, and best practices",
        )
        self._static_analyzer = static_analyzer or StaticAnalyzer()
        self._llm_analyzer = llm_analyzer or LLMAnalyzer()

    async def analyze(
        self,
        code: str,
        file_path: str = "untitled.py",
        language: str = "python",
    ) -> list[Finding]:
        """
        Analyze code quality.

        Runs ruff and pylint for static analysis, then uses OpenAI to provide
        contextual suggestions for each finding.

        Args:
            code: The source code to analyze.
            file_path: Path to the file being analyzed.
            language: Programming language of the code.

        Returns:
            List of Finding objects representing quality issues.
        """
        self._log_analysis_start(file_path)
        findings: list[Finding] = []

        try:
            # Run static analysis with ruff
            ruff_results = await self._static_analyzer.run_ruff(code, file_path)
            for result in ruff_results:
                finding = self._convert_static_result(result, file_path, "ruff")
                findings.append(finding)

            # Run static analysis with pylint
            pylint_results = await self._static_analyzer.run_pylint(code, file_path)
            for result in pylint_results:
                finding = self._convert_static_result(result, file_path, "pylint")
                findings.append(finding)

            # Enhance findings with AI suggestions if there are findings
            if findings:
                findings = await self._enhance_with_ai_suggestions(code, findings)

            # If no static analysis findings, run AI-only analysis for deeper insights
            if not findings:
                ai_findings = await self._run_ai_quality_analysis(code, file_path)
                findings.extend(ai_findings)

        except Exception as e:
            self._log_error("Error during quality analysis", e)

        self._log_analysis_complete(file_path, len(findings))
        return findings

    def _convert_static_result(
        self,
        result: dict,
        file_path: str,
        tool: str,
    ) -> Finding:
        """
        Convert static analyzer result to Finding.

        Args:
            result: Raw result from static analyzer.
            file_path: Path to the analyzed file.
            tool: Name of the tool (ruff/pylint).

        Returns:
            Finding object.
        """
        rule_id = result.get("code", result.get("rule_id", ""))
        message = result.get("message", "Code quality issue detected")
        line_number = result.get("line", result.get("line_number", 1))

        # Determine category
        category = self._get_category(rule_id)

        # Determine severity
        severity = self._get_severity(rule_id)

        return self._create_finding(
            file_path=file_path,
            line_number=line_number,
            severity=severity.value,
            category=category.value,
            message=message,
            suggestion=result.get("suggestion", ""),
            rule_id=f"{tool}:{rule_id}",
            code_snippet=result.get("code_snippet"),
            confidence=0.9,
        )

    def _get_category(self, rule_id: str) -> FindingCategory:
        """Get category for a rule ID."""
        # Check exact match first
        if rule_id in self.CATEGORY_MAP:
            return self.CATEGORY_MAP[rule_id]

        # Check prefix match
        for prefix, category in self.CATEGORY_MAP.items():
            if rule_id.startswith(prefix):
                return category

        return FindingCategory.CODE_SMELL

    def _get_severity(self, rule_id: str) -> Severity:
        """Get severity for a rule ID."""
        # Check prefix match
        for prefix, severity in self.SEVERITY_MAP.items():
            if rule_id.startswith(prefix):
                return severity

        return Severity.MEDIUM

    async def _enhance_with_ai_suggestions(
        self,
        code: str,
        findings: list[Finding],
    ) -> list[Finding]:
        """
        Enhance findings with AI-generated suggestions.

        Args:
            code: The source code.
            findings: List of findings to enhance.

        Returns:
            Enhanced findings with AI suggestions.
        """
        try:
            enhanced_findings = []
            for finding in findings:
                suggestion = await self._llm_analyzer.get_suggestion(
                    code=code,
                    finding_message=finding.message,
                    finding_category=finding.category.value,
                    line_number=finding.line_number,
                )
                # Create new finding with suggestion
                enhanced = Finding(
                    id=finding.id,
                    file_path=finding.file_path,
                    line_number=finding.line_number,
                    end_line_number=finding.end_line_number,
                    column=finding.column,
                    severity=finding.severity,
                    category=finding.category,
                    message=finding.message,
                    suggestion=suggestion or finding.suggestion,
                    agent_name=finding.agent_name,
                    rule_id=finding.rule_id,
                    code_snippet=finding.code_snippet,
                    confidence=finding.confidence,
                )
                enhanced_findings.append(enhanced)
            return enhanced_findings
        except Exception as e:
            self._log_error("Error enhancing findings with AI", e)
            return findings

    async def _run_ai_quality_analysis(
        self,
        code: str,
        file_path: str,
    ) -> list[Finding]:
        """
        Run AI-only quality analysis when static tools find nothing.

        Args:
            code: The source code to analyze.
            file_path: Path to the file.

        Returns:
            List of AI-detected findings.
        """
        try:
            ai_findings = await self._llm_analyzer.analyze_code_quality(
                code=code,
                file_path=file_path,
            )
            findings = []
            for ai_finding in ai_findings:
                finding = self._create_finding(
                    file_path=file_path,
                    line_number=ai_finding.get("line_number", 1),
                    severity=ai_finding.get("severity", "medium"),
                    category=ai_finding.get("category", "code_smell"),
                    message=ai_finding.get("message", ""),
                    suggestion=ai_finding.get("suggestion", ""),
                    confidence=0.7,  # Lower confidence for AI-only findings
                )
                findings.append(finding)
            return findings
        except Exception as e:
            self._log_error("Error in AI quality analysis", e)
            return []

