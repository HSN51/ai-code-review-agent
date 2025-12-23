"""
Security Agent for AI Code Review Agent.

Analyzes code for security vulnerabilities using bandit and AI-powered detection.
"""

from typing import Optional

from src.agents.base_agent import BaseAgent
from src.analyzers.llm_analyzer import LLMAnalyzer
from src.analyzers.static_analyzer import StaticAnalyzer
from src.models.schemas import Finding, FindingCategory, Severity


class SecurityAgent(BaseAgent):
    """
    Agent for analyzing security vulnerabilities.

    Uses bandit for security scanning and OpenAI to explain vulnerabilities.
    Detects SQL injection, XSS, hardcoded secrets, and insecure imports.
    Maps findings to OWASP categories.
    """

    # Bandit test ID to OWASP category mapping
    OWASP_MAP = {
        # A01:2021 - Broken Access Control
        "B501": "A01:2021-Broken Access Control",
        "B502": "A01:2021-Broken Access Control",
        "B503": "A01:2021-Broken Access Control",
        # A02:2021 - Cryptographic Failures
        "B303": "A02:2021-Cryptographic Failures",
        "B304": "A02:2021-Cryptographic Failures",
        "B305": "A02:2021-Cryptographic Failures",
        "B311": "A02:2021-Cryptographic Failures",
        "B324": "A02:2021-Cryptographic Failures",
        # A03:2021 - Injection
        "B102": "A03:2021-Injection",
        "B103": "A03:2021-Injection",
        "B608": "A03:2021-Injection",
        "B609": "A03:2021-Injection",
        "B610": "A03:2021-Injection",
        "B611": "A03:2021-Injection",
        "B701": "A03:2021-Injection",
        "B702": "A03:2021-Injection",
        "B703": "A03:2021-Injection",
        # A04:2021 - Insecure Design
        "B104": "A04:2021-Insecure Design",
        "B105": "A04:2021-Insecure Design",
        "B106": "A04:2021-Insecure Design",
        "B107": "A04:2021-Insecure Design",
        # A05:2021 - Security Misconfiguration
        "B108": "A05:2021-Security Misconfiguration",
        "B110": "A05:2021-Security Misconfiguration",
        "B112": "A05:2021-Security Misconfiguration",
        "B201": "A05:2021-Security Misconfiguration",
        # A06:2021 - Vulnerable Components
        "B403": "A06:2021-Vulnerable Components",
        "B404": "A06:2021-Vulnerable Components",
        "B405": "A06:2021-Vulnerable Components",
        "B406": "A06:2021-Vulnerable Components",
        "B407": "A06:2021-Vulnerable Components",
        "B408": "A06:2021-Vulnerable Components",
        "B409": "A06:2021-Vulnerable Components",
        "B410": "A06:2021-Vulnerable Components",
        # A07:2021 - Identification and Authentication Failures
        "B105": "A07:2021-Auth Failures",
        "B106": "A07:2021-Auth Failures",
        "B107": "A07:2021-Auth Failures",
    }

    # Bandit severity mapping
    SEVERITY_MAP = {
        "HIGH": Severity.CRITICAL,
        "MEDIUM": Severity.HIGH,
        "LOW": Severity.MEDIUM,
    }

    # Bandit test ID to category mapping
    CATEGORY_MAP = {
        # SQL Injection
        "B608": FindingCategory.SQL_INJECTION,
        # Hardcoded secrets
        "B105": FindingCategory.HARDCODED_SECRET,
        "B106": FindingCategory.HARDCODED_SECRET,
        "B107": FindingCategory.HARDCODED_SECRET,
        # Insecure imports
        "B403": FindingCategory.INSECURE_IMPORT,
        "B404": FindingCategory.INSECURE_IMPORT,
        "B405": FindingCategory.INSECURE_IMPORT,
        "B406": FindingCategory.INSECURE_IMPORT,
        "B407": FindingCategory.INSECURE_IMPORT,
        "B408": FindingCategory.INSECURE_IMPORT,
        "B409": FindingCategory.INSECURE_IMPORT,
        "B410": FindingCategory.INSECURE_IMPORT,
        # Cryptography
        "B303": FindingCategory.CRYPTOGRAPHY,
        "B304": FindingCategory.CRYPTOGRAPHY,
        "B305": FindingCategory.CRYPTOGRAPHY,
        "B324": FindingCategory.CRYPTOGRAPHY,
        # Injection
        "B102": FindingCategory.INJECTION,
        "B103": FindingCategory.INJECTION,
        "B609": FindingCategory.INJECTION,
        "B610": FindingCategory.INJECTION,
        "B611": FindingCategory.INJECTION,
        "B701": FindingCategory.INJECTION,
        "B702": FindingCategory.INJECTION,
        "B703": FindingCategory.INJECTION,
    }

    def __init__(
        self,
        static_analyzer: Optional[StaticAnalyzer] = None,
        llm_analyzer: Optional[LLMAnalyzer] = None,
    ) -> None:
        """
        Initialize the Security Agent.

        Args:
            static_analyzer: Static analyzer instance. Created if not provided.
            llm_analyzer: LLM analyzer instance. Created if not provided.
        """
        super().__init__(
            name="SecurityAgent",
            description="Analyzes security vulnerabilities and maps to OWASP categories",
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
        Analyze code for security vulnerabilities.

        Runs bandit for security scanning and uses OpenAI to explain
        vulnerabilities in plain language.

        Args:
            code: The source code to analyze.
            file_path: Path to the file being analyzed.
            language: Programming language of the code.

        Returns:
            List of Finding objects representing security issues.
        """
        self._log_analysis_start(file_path)
        findings: list[Finding] = []

        try:
            # Run bandit security scan
            bandit_results = await self._static_analyzer.run_bandit(code, file_path)
            for result in bandit_results:
                finding = self._convert_bandit_result(result, file_path)
                findings.append(finding)

            # Enhance findings with AI explanations
            if findings:
                findings = await self._enhance_with_ai_explanations(code, findings)

            # Run AI-based security analysis for additional issues
            ai_findings = await self._run_ai_security_analysis(code, file_path)
            findings.extend(ai_findings)

        except Exception as e:
            self._log_error("Error during security analysis", e)

        self._log_analysis_complete(file_path, len(findings))
        return findings

    def _convert_bandit_result(self, result: dict, file_path: str) -> Finding:
        """
        Convert bandit result to Finding.

        Args:
            result: Raw result from bandit.
            file_path: Path to the analyzed file.

        Returns:
            Finding object with OWASP mapping.
        """
        test_id = result.get("test_id", "")
        severity_str = result.get("severity", "MEDIUM")
        message = result.get("message", result.get("issue_text", "Security issue detected"))
        line_number = result.get("line_number", result.get("line", 1))
        confidence = result.get("confidence", "MEDIUM")

        # Map to category
        category = self.CATEGORY_MAP.get(test_id, FindingCategory.INJECTION)

        # Map to severity
        severity = self.SEVERITY_MAP.get(severity_str, Severity.HIGH)

        # Map to OWASP
        owasp = self.OWASP_MAP.get(test_id, "A03:2021-Injection")

        # Calculate confidence score
        confidence_score = {"HIGH": 0.95, "MEDIUM": 0.75, "LOW": 0.5}.get(confidence, 0.75)

        return self._create_finding(
            file_path=file_path,
            line_number=line_number,
            severity=severity.value,
            category=category.value,
            message=message,
            suggestion="",  # Will be filled by AI
            rule_id=f"bandit:{test_id}",
            code_snippet=result.get("code"),
            owasp_category=owasp,
            confidence=confidence_score,
        )

    async def _enhance_with_ai_explanations(
        self,
        code: str,
        findings: list[Finding],
    ) -> list[Finding]:
        """
        Enhance security findings with AI explanations.

        Args:
            code: The source code.
            findings: List of findings to enhance.

        Returns:
            Enhanced findings with plain language explanations.
        """
        try:
            enhanced_findings = []
            for finding in findings:
                explanation = await self._llm_analyzer.explain_vulnerability(
                    code=code,
                    vulnerability_type=finding.category.value,
                    owasp_category=finding.owasp_category or "",
                    line_number=finding.line_number,
                )
                # Create new finding with explanation as suggestion
                enhanced = Finding(
                    id=finding.id,
                    file_path=finding.file_path,
                    line_number=finding.line_number,
                    end_line_number=finding.end_line_number,
                    column=finding.column,
                    severity=finding.severity,
                    category=finding.category,
                    message=finding.message,
                    suggestion=explanation or "Review and fix this security vulnerability.",
                    agent_name=finding.agent_name,
                    rule_id=finding.rule_id,
                    code_snippet=finding.code_snippet,
                    owasp_category=finding.owasp_category,
                    confidence=finding.confidence,
                )
                enhanced_findings.append(enhanced)
            return enhanced_findings
        except Exception as e:
            self._log_error("Error enhancing findings with AI explanations", e)
            return findings

    async def _run_ai_security_analysis(
        self,
        code: str,
        file_path: str,
    ) -> list[Finding]:
        """
        Run AI-based security analysis for additional vulnerabilities.

        This catches issues that static analysis might miss, like:
        - Hardcoded credentials in unusual formats
        - Logic-based security flaws
        - XSS vulnerabilities in web code

        Args:
            code: The source code to analyze.
            file_path: Path to the file.

        Returns:
            List of AI-detected security findings.
        """
        try:
            ai_findings = await self._llm_analyzer.analyze_security(
                code=code,
                file_path=file_path,
            )
            findings = []
            for ai_finding in ai_findings:
                # Get OWASP category if specified
                category_str = ai_finding.get("category", "injection")
                owasp = ai_finding.get("owasp_category")

                # Try to map category string to OWASP if not provided
                if not owasp:
                    owasp = self._infer_owasp_category(category_str)

                finding = self._create_finding(
                    file_path=file_path,
                    line_number=ai_finding.get("line_number", 1),
                    severity=ai_finding.get("severity", "high"),
                    category=category_str,
                    message=ai_finding.get("message", ""),
                    suggestion=ai_finding.get("suggestion", ""),
                    owasp_category=owasp,
                    confidence=0.7,  # Lower confidence for AI-only findings
                )
                findings.append(finding)
            return findings
        except Exception as e:
            self._log_error("Error in AI security analysis", e)
            return []

    def _infer_owasp_category(self, category: str) -> str:
        """
        Infer OWASP category from finding category.

        Args:
            category: The finding category.

        Returns:
            OWASP category string.
        """
        category_to_owasp = {
            "sql_injection": "A03:2021-Injection",
            "xss": "A03:2021-Injection",
            "injection": "A03:2021-Injection",
            "hardcoded_secret": "A07:2021-Auth Failures",
            "authentication": "A07:2021-Auth Failures",
            "authorization": "A01:2021-Broken Access Control",
            "cryptography": "A02:2021-Cryptographic Failures",
            "insecure_import": "A06:2021-Vulnerable Components",
        }
        return category_to_owasp.get(category.lower(), "A03:2021-Injection")

