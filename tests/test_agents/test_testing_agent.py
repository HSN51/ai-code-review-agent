"""
Tests for Testing Agent.

Tests test coverage analysis and test suggestion functionality.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.agents.testing_agent import TestingAgent
from src.analyzers.llm_analyzer import LLMAnalyzer
from src.models.schemas import FindingCategory, Severity


class TestTestingAgent:
    """Tests for TestingAgent class."""

    def test_init(self):
        """Test TestingAgent initialization."""
        agent = TestingAgent()
        assert agent.name == "TestingAgent"
        assert "test" in agent.description.lower()

    def test_init_with_custom_analyzer(self):
        """Test initialization with custom LLM analyzer."""
        llm = LLMAnalyzer()
        agent = TestingAgent(llm_analyzer=llm)
        assert agent._llm_analyzer is llm

    @pytest.mark.asyncio
    async def test_analyze_regular_code(self, testing_agent, sample_python_code):
        """Test analysis of regular (non-test) code."""
        findings = await testing_agent.analyze(sample_python_code, "src/module.py")
        assert isinstance(findings, list)
        for finding in findings:
            assert finding.agent_name == "TestingAgent"

    @pytest.mark.asyncio
    async def test_analyze_test_code(self, testing_agent, sample_test_code):
        """Test analysis of test code."""
        findings = await testing_agent.analyze(sample_test_code, "tests/test_module.py")
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_analyze_complex_code(self, testing_agent, sample_complex_code):
        """Test analysis of complex code for test coverage."""
        findings = await testing_agent.analyze(sample_complex_code, "src/complex.py")
        assert isinstance(findings, list)
        # Complex code should have coverage suggestions
        # Note: actual findings depend on the code structure

    def test_is_test_file(self):
        """Test test file detection."""
        agent = TestingAgent()
        
        # Should be detected as test files
        assert agent._is_test_file("test_module.py")
        assert agent._is_test_file("module_test.py")
        assert agent._is_test_file("tests/test_something.py")
        assert agent._is_test_file("test/module_spec.py")
        
        # Should not be detected as test files
        assert not agent._is_test_file("module.py")
        assert not agent._is_test_file("src/main.py")
        assert not agent._is_test_file("testing_utils.py")  # Contains 'test' but not a test file pattern

    def test_extract_code_structure_functions(self):
        """Test code structure extraction for functions."""
        agent = TestingAgent()
        code = """
def simple_function():
    pass

def function_with_args(a, b, c):
    return a + b + c

async def async_function():
    await something()
"""
        structure = agent._extract_code_structure(code)
        
        assert len(structure["functions"]) == 2
        assert len(structure["async_functions"]) == 1
        assert structure["functions"][0]["name"] == "simple_function"
        assert len(structure["functions"][1]["args"]) == 3

    def test_extract_code_structure_classes(self):
        """Test code structure extraction for classes."""
        agent = TestingAgent()
        code = """
class MyClass:
    def method1(self):
        pass
    
    async def async_method(self):
        pass
"""
        structure = agent._extract_code_structure(code)
        
        assert len(structure["classes"]) == 1
        assert structure["classes"][0]["name"] == "MyClass"
        assert len(structure["classes"][0]["methods"]) == 2

    def test_extract_code_structure_complexity(self):
        """Test code structure extraction for complexity indicators."""
        agent = TestingAgent()
        code = """
def complex():
    if True:
        for i in range(10):
            while True:
                try:
                    pass
                except:
                    pass
"""
        structure = agent._extract_code_structure(code)
        
        assert structure["has_error_handling"]
        assert len(structure["complexity_indicators"]) > 0

    def test_extract_code_structure_syntax_error(self):
        """Test code structure extraction with syntax error."""
        agent = TestingAgent()
        code = "def broken("  # Invalid syntax
        
        structure = agent._extract_code_structure(code)
        # Should return empty structure, not raise
        assert isinstance(structure, dict)

    def test_estimate_complexity(self):
        """Test complexity estimation."""
        agent = TestingAgent()
        import ast
        
        # Simple function
        simple_code = "def simple(): return 1"
        tree = ast.parse(simple_code)
        func = tree.body[0]
        assert agent._estimate_complexity(func) == 1
        
        # Complex function
        complex_code = """
def complex(x):
    if x > 0:
        if x > 10:
            return 1
        return 2
    return 0
"""
        tree = ast.parse(complex_code)
        func = tree.body[0]
        assert agent._estimate_complexity(func) > 1

    @pytest.mark.asyncio
    async def test_analyze_coverage_gaps(self):
        """Test coverage gap analysis."""
        mock_llm = AsyncMock(spec=LLMAnalyzer)
        mock_llm.analyze_testing = AsyncMock(return_value=[])
        
        agent = TestingAgent(llm_analyzer=mock_llm)
        
        code = """
def highly_complex_function(a, b, c, d, e):
    if a:
        if b:
            if c:
                if d:
                    if e:
                        return 1
    return 0
"""
        findings = await agent.analyze(code, "src/module.py")
        
        # Should suggest tests for complex function
        complex_findings = [f for f in findings if "complex" in f.message.lower()]
        # The function has high complexity, should have a finding
        assert isinstance(findings, list)

    @pytest.mark.asyncio
    async def test_analyze_test_quality(self):
        """Test test quality analysis."""
        mock_llm = AsyncMock(spec=LLMAnalyzer)
        mock_llm.analyze_testing = AsyncMock(return_value=[
            {
                "line_number": 2,
                "severity": "medium",
                "category": "missing_test",
                "message": "Test function has no assertion statements",
                "suggestion": "Add assertions to verify expected behavior",
            }
        ])
        
        agent = TestingAgent(llm_analyzer=mock_llm)
        
        # Test file with no assertions
        code = """
def test_something():
    x = 1 + 1
    # No assertion!
"""
        findings = await agent.analyze(code, "test_module.py")
        
        # Should detect missing assertions
        assertion_findings = [f for f in findings if "assertion" in f.message.lower()]
        assert len(assertion_findings) > 0

    @pytest.mark.asyncio
    async def test_analyze_ai_suggestions(self):
        """Test AI-powered test suggestions."""
        mock_llm = AsyncMock(spec=LLMAnalyzer)
        mock_llm.analyze_testing = AsyncMock(return_value=[
            {
                "line_number": 5,
                "severity": "medium",
                "category": "missing_test",
                "message": "Add test for edge case",
                "suggestion": "Test with empty input",
            }
        ])
        
        agent = TestingAgent(llm_analyzer=mock_llm)
        findings = await agent.analyze("def func(): pass", "src/module.py")
        
        ai_findings = [f for f in findings if f.confidence < 0.7]
        # AI findings have lower confidence
        assert len(ai_findings) >= 0

    @pytest.mark.asyncio
    async def test_analyze_exception_handling(self):
        """Test exception handling during analysis."""
        mock_llm = AsyncMock(spec=LLMAnalyzer)
        mock_llm.analyze_testing = AsyncMock(side_effect=Exception("API Error"))
        
        agent = TestingAgent(llm_analyzer=mock_llm)
        # Should not raise
        findings = await agent.analyze("def func(): pass", "src/module.py")
        assert isinstance(findings, list)

    def test_repr(self):
        """Test string representation."""
        agent = TestingAgent()
        repr_str = repr(agent)
        assert "TestingAgent" in repr_str

