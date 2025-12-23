"""
Tests for Security Agent.

Tests security vulnerability detection including bandit integration
and OWASP mapping.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.agents.security_agent import SecurityAgent
from src.analyzers.llm_analyzer import LLMAnalyzer
from src.analyzers.static_analyzer import StaticAnalyzer
from src.models.schemas import FindingCategory, Severity


class TestSecurityAgent:
    """Tests for SecurityAgent class."""

    def test_init(self):
        """Test SecurityAgent initialization."""
        agent = SecurityAgent()
        assert agent.name == "SecurityAgent"
        assert "security" in agent.description.lower()

    def test_init_with_custom_analyzers(self):
        """Test initialization with custom analyzers."""
        static = StaticAnalyzer()
        llm = LLMAnalyzer()
        agent = SecurityAgent(static_analyzer=static, llm_analyzer=llm)
        assert agent._static_analyzer is static
        assert agent._llm_analyzer is llm

    @pytest.mark.asyncio
    async def test_analyze_secure_code(self, security_agent, sample_python_code):
        """Test analysis of secure code."""
        findings = await security_agent.analyze(sample_python_code, "secure.py")
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_analyze_insecure_code(self, security_agent, sample_insecure_code):
        """Test analysis of insecure code."""
        findings = await security_agent.analyze(sample_insecure_code, "insecure.py")
        assert isinstance(findings, list)
        # All findings should have agent name set
        for finding in findings:
            assert finding.agent_name == "SecurityAgent"

    @pytest.mark.asyncio
    async def test_analyze_with_bandit_findings(self):
        """Test analysis when bandit returns findings."""
        mock_static = AsyncMock(spec=StaticAnalyzer)
        mock_static.run_bandit = AsyncMock(return_value=[
            {
                "test_id": "B608",
                "test_name": "hardcoded_sql_expressions",
                "message": "Possible SQL injection",
                "line_number": 5,
                "severity": "HIGH",
                "confidence": "MEDIUM",
            }
        ])

        mock_llm = AsyncMock(spec=LLMAnalyzer)
        mock_llm.explain_vulnerability = AsyncMock(
            return_value="This SQL query is vulnerable to injection attacks."
        )
        mock_llm.analyze_security = AsyncMock(return_value=[])

        agent = SecurityAgent(static_analyzer=mock_static, llm_analyzer=mock_llm)
        findings = await agent.analyze("query = f'SELECT * FROM users WHERE id = {x}'", "test.py")

        assert len(findings) >= 1
        assert findings[0].category == FindingCategory.SQL_INJECTION
        assert findings[0].owasp_category is not None

    @pytest.mark.asyncio
    async def test_analyze_with_ai_findings(self):
        """Test analysis when AI detects additional issues."""
        mock_static = AsyncMock(spec=StaticAnalyzer)
        mock_static.run_bandit = AsyncMock(return_value=[])

        mock_llm = AsyncMock(spec=LLMAnalyzer)
        mock_llm.analyze_security = AsyncMock(return_value=[
            {
                "line_number": 3,
                "severity": "high",
                "category": "hardcoded_secret",
                "message": "Hardcoded API key detected",
                "suggestion": "Use environment variables",
                "owasp_category": "A07:2021-Auth Failures",
            }
        ])

        agent = SecurityAgent(static_analyzer=mock_static, llm_analyzer=mock_llm)
        findings = await agent.analyze("api_key = 'abc123'", "test.py")

        assert len(findings) >= 1

    def test_owasp_mapping(self):
        """Test OWASP category mapping."""
        agent = SecurityAgent()
        
        # Test SQL injection mapping
        assert "Injection" in agent.OWASP_MAP.get("B608", "")
        
        # Test hardcoded secret mapping
        assert agent.OWASP_MAP.get("B105") is not None

    def test_severity_mapping(self):
        """Test severity mapping."""
        agent = SecurityAgent()
        
        assert agent.SEVERITY_MAP["HIGH"] == Severity.CRITICAL
        assert agent.SEVERITY_MAP["MEDIUM"] == Severity.HIGH
        assert agent.SEVERITY_MAP["LOW"] == Severity.MEDIUM

    def test_category_mapping(self):
        """Test category mapping."""
        agent = SecurityAgent()
        
        assert agent.CATEGORY_MAP["B608"] == FindingCategory.SQL_INJECTION
        assert agent.CATEGORY_MAP["B105"] == FindingCategory.HARDCODED_SECRET
        assert agent.CATEGORY_MAP["B303"] == FindingCategory.CRYPTOGRAPHY

    @pytest.mark.asyncio
    async def test_convert_bandit_result(self):
        """Test conversion of bandit results."""
        agent = SecurityAgent()
        result = {
            "test_id": "B608",
            "message": "SQL injection",
            "line_number": 10,
            "severity": "HIGH",
            "confidence": "HIGH",
        }
        finding = agent._convert_bandit_result(result, "test.py")
        
        assert finding.file_path == "test.py"
        assert finding.line_number == 10
        assert finding.rule_id == "bandit:B608"
        assert finding.owasp_category is not None

    def test_infer_owasp_category(self):
        """Test OWASP category inference."""
        agent = SecurityAgent()
        
        assert "Injection" in agent._infer_owasp_category("sql_injection")
        assert "Injection" in agent._infer_owasp_category("xss")
        assert "Auth" in agent._infer_owasp_category("hardcoded_secret")
        assert "Cryptographic" in agent._infer_owasp_category("cryptography")

    @pytest.mark.asyncio
    async def test_enhance_with_ai_explanations_error(self):
        """Test AI explanation error handling."""
        mock_static = AsyncMock(spec=StaticAnalyzer)
        mock_static.run_bandit = AsyncMock(return_value=[
            {"test_id": "B608", "message": "Test", "line_number": 1, "severity": "HIGH", "confidence": "HIGH"}
        ])

        mock_llm = AsyncMock(spec=LLMAnalyzer)
        mock_llm.explain_vulnerability = AsyncMock(side_effect=Exception("API Error"))
        mock_llm.analyze_security = AsyncMock(return_value=[])

        agent = SecurityAgent(static_analyzer=mock_static, llm_analyzer=mock_llm)
        # Should not raise, should return findings without AI enhancement
        findings = await agent.analyze("x = 1", "test.py")
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_analyze_exception_handling(self):
        """Test exception handling during analysis."""
        mock_static = AsyncMock(spec=StaticAnalyzer)
        mock_static.run_bandit = AsyncMock(side_effect=Exception("Tool error"))

        mock_llm = AsyncMock(spec=LLMAnalyzer)
        mock_llm.analyze_security = AsyncMock(return_value=[])

        agent = SecurityAgent(static_analyzer=mock_static, llm_analyzer=mock_llm)
        # Should not raise
        findings = await agent.analyze("x = 1", "test.py")
        assert isinstance(findings, list)

    def test_repr(self):
        """Test string representation."""
        agent = SecurityAgent()
        repr_str = repr(agent)
        assert "SecurityAgent" in repr_str

