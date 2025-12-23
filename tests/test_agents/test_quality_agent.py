"""
Tests for Quality Agent.

Tests code quality analysis functionality including ruff, pylint integration
and AI-powered suggestions.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.agents.quality_agent import QualityAgent
from src.analyzers.llm_analyzer import LLMAnalyzer
from src.analyzers.static_analyzer import StaticAnalyzer
from src.models.schemas import FindingCategory, Severity


class TestQualityAgent:
    """Tests for QualityAgent class."""

    def test_init(self):
        """Test QualityAgent initialization."""
        agent = QualityAgent()
        assert agent.name == "QualityAgent"
        assert "quality" in agent.description.lower()

    def test_init_with_custom_analyzers(self):
        """Test initialization with custom analyzers."""
        static = StaticAnalyzer()
        llm = LLMAnalyzer()
        agent = QualityAgent(static_analyzer=static, llm_analyzer=llm)
        assert agent._static_analyzer is static
        assert agent._llm_analyzer is llm

    @pytest.mark.asyncio
    async def test_analyze_empty_code(self, quality_agent):
        """Test analysis of empty code."""
        findings = await quality_agent.analyze("", "empty.py")
        # Empty code might not produce findings depending on tools
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_analyze_simple_code(self, quality_agent, sample_python_code):
        """Test analysis of simple Python code."""
        findings = await quality_agent.analyze(sample_python_code, "simple.py")
        assert isinstance(findings, list)
        # All findings should have agent name set
        for finding in findings:
            assert finding.agent_name == "QualityAgent"

    @pytest.mark.asyncio
    async def test_analyze_complex_code(self, quality_agent, sample_complex_code):
        """Test analysis of complex code."""
        findings = await quality_agent.analyze(sample_complex_code, "complex.py")
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_analyze_with_ruff_findings(self):
        """Test analysis when ruff returns findings."""
        mock_static = AsyncMock(spec=StaticAnalyzer)
        mock_static.run_ruff = AsyncMock(return_value=[
            {
                "code": "E501",
                "message": "Line too long",
                "line": 10,
                "column": 80,
            }
        ])
        mock_static.run_pylint = AsyncMock(return_value=[])

        mock_llm = AsyncMock(spec=LLMAnalyzer)
        mock_llm.get_suggestion = AsyncMock(return_value="Consider breaking this line.")
        mock_llm.analyze_code_quality = AsyncMock(return_value=[])

        agent = QualityAgent(static_analyzer=mock_static, llm_analyzer=mock_llm)
        findings = await agent.analyze("x = 1", "test.py")

        assert len(findings) >= 1
        assert findings[0].rule_id == "ruff:E501"

    @pytest.mark.asyncio
    async def test_analyze_with_pylint_findings(self):
        """Test analysis when pylint returns findings."""
        mock_static = AsyncMock(spec=StaticAnalyzer)
        mock_static.run_ruff = AsyncMock(return_value=[])
        mock_static.run_pylint = AsyncMock(return_value=[
            {
                "code": "C0301",
                "message": "Line too long",
                "line": 5,
                "symbol": "line-too-long",
            }
        ])

        mock_llm = AsyncMock(spec=LLMAnalyzer)
        mock_llm.get_suggestion = AsyncMock(return_value="Refactor the line.")
        mock_llm.analyze_code_quality = AsyncMock(return_value=[])

        agent = QualityAgent(static_analyzer=mock_static, llm_analyzer=mock_llm)
        findings = await agent.analyze("x = 1", "test.py")

        assert len(findings) >= 1

    @pytest.mark.asyncio
    async def test_analyze_with_ai_only_findings(self):
        """Test analysis when only AI finds issues."""
        mock_static = AsyncMock(spec=StaticAnalyzer)
        mock_static.run_ruff = AsyncMock(return_value=[])
        mock_static.run_pylint = AsyncMock(return_value=[])

        mock_llm = AsyncMock(spec=LLMAnalyzer)
        mock_llm.analyze_code_quality = AsyncMock(return_value=[
            {
                "line_number": 1,
                "severity": "medium",
                "category": "code_smell",
                "message": "Consider using a more descriptive name",
                "suggestion": "Rename variable",
            }
        ])

        agent = QualityAgent(static_analyzer=mock_static, llm_analyzer=mock_llm)
        findings = await agent.analyze("x = 1", "test.py")

        assert len(findings) >= 1
        # AI findings have lower confidence
        assert findings[0].confidence < 0.9

    def test_get_category_exact_match(self):
        """Test category mapping with exact match."""
        agent = QualityAgent()
        category = agent._get_category("C901")
        assert category == FindingCategory.COMPLEXITY

    def test_get_category_prefix_match(self):
        """Test category mapping with prefix match."""
        agent = QualityAgent()
        category = agent._get_category("E501")
        assert category == FindingCategory.STYLE

    def test_get_category_default(self):
        """Test category mapping default."""
        agent = QualityAgent()
        category = agent._get_category("UNKNOWN123")
        assert category == FindingCategory.CODE_SMELL

    def test_get_severity_prefix_match(self):
        """Test severity mapping."""
        agent = QualityAgent()
        
        assert agent._get_severity("E501") == Severity.HIGH
        assert agent._get_severity("F401") == Severity.CRITICAL
        assert agent._get_severity("W503") == Severity.MEDIUM
        assert agent._get_severity("C0103") == Severity.LOW

    def test_get_severity_default(self):
        """Test severity default."""
        agent = QualityAgent()
        severity = agent._get_severity("UNKNOWN")
        assert severity == Severity.MEDIUM

    @pytest.mark.asyncio
    async def test_enhance_with_ai_suggestions_error_handling(self):
        """Test AI suggestion enhancement error handling."""
        mock_static = AsyncMock(spec=StaticAnalyzer)
        mock_static.run_ruff = AsyncMock(return_value=[
            {"code": "E501", "message": "Test", "line": 1}
        ])
        mock_static.run_pylint = AsyncMock(return_value=[])

        mock_llm = AsyncMock(spec=LLMAnalyzer)
        mock_llm.get_suggestion = AsyncMock(side_effect=Exception("API Error"))
        mock_llm.analyze_code_quality = AsyncMock(return_value=[])

        agent = QualityAgent(static_analyzer=mock_static, llm_analyzer=mock_llm)
        # Should not raise, should return findings without AI enhancement
        findings = await agent.analyze("x = 1", "test.py")
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_convert_static_result(self):
        """Test conversion of static analyzer results."""
        agent = QualityAgent()
        result = {
            "code": "E501",
            "message": "Line too long",
            "line": 10,
            "column": 80,
        }
        finding = agent._convert_static_result(result, "test.py", "ruff")
        
        assert finding.file_path == "test.py"
        assert finding.line_number == 10
        assert finding.rule_id == "ruff:E501"
        assert finding.agent_name == "QualityAgent"

    def test_repr(self):
        """Test string representation."""
        agent = QualityAgent()
        repr_str = repr(agent)
        assert "QualityAgent" in repr_str

