"""
Tests for LLM Analyzer.

Tests OpenAI GPT integration with caching and retry logic.
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from src.analyzers.llm_analyzer import LLMAnalyzer
from src.config import Settings


class TestLLMAnalyzer:
    """Tests for LLMAnalyzer class."""

    def test_init_with_api_key(self):
        """Test initialization with API key."""
        analyzer = LLMAnalyzer(api_key="test-key")
        assert analyzer._api_key == "test-key"
        assert analyzer.is_configured is True

    def test_init_without_api_key(self):
        """Test initialization without API key."""
        with patch("src.analyzers.llm_analyzer.get_settings") as mock_settings:
            mock_settings.return_value = Settings(openai_api_key="")
            analyzer = LLMAnalyzer()
            assert analyzer.is_configured is False

    def test_init_with_placeholder_key(self):
        """Test initialization with placeholder API key."""
        analyzer = LLMAnalyzer(api_key="your_openai_api_key_here")
        assert analyzer.is_configured is False

    def test_get_cache_key(self):
        """Test cache key generation."""
        analyzer = LLMAnalyzer(api_key="test-key")
        key1 = analyzer._get_cache_key("arg1", "arg2")
        key2 = analyzer._get_cache_key("arg1", "arg2")
        key3 = analyzer._get_cache_key("arg1", "arg3")
        
        assert key1 == key2  # Same args should produce same key
        assert key1 != key3  # Different args should produce different key

    @pytest.mark.asyncio
    async def test_call_openai_not_configured(self):
        """Test OpenAI call when not configured."""
        with patch("src.analyzers.llm_analyzer.get_settings") as mock_settings:
            mock_settings.return_value = Settings(openai_api_key="")
            analyzer = LLMAnalyzer()
            result = await analyzer._call_openai("system", "user")
            assert result is None

    @pytest.mark.asyncio
    async def test_call_openai_cached_response(self):
        """Test OpenAI call with cached response."""
        analyzer = LLMAnalyzer(api_key="test-key")
        
        # Pre-populate cache
        cache_key = analyzer._get_cache_key("system", "user")
        analyzer._cache[cache_key] = "cached response"
        
        result = await analyzer._call_openai("system", "user", use_cache=True)
        assert result == "cached response"

    @pytest.mark.asyncio
    async def test_call_openai_success(self):
        """Test successful OpenAI call."""
        analyzer = LLMAnalyzer(api_key="test-key")
        
        mock_response = MagicMock()
        mock_response.choices = [MagicMock(message=MagicMock(content="AI response"))]
        
        with patch.object(analyzer._client.chat.completions, "create", new_callable=AsyncMock) as mock_create:
            mock_create.return_value = mock_response
            result = await analyzer._call_openai("system", "user", use_cache=False)
        
        assert result == "AI response"

    @pytest.mark.asyncio
    async def test_get_suggestion(self):
        """Test getting AI suggestion."""
        analyzer = LLMAnalyzer(api_key="test-key")
        
        with patch.object(analyzer, "_call_openai", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = "Use a more descriptive variable name."
            
            result = await analyzer.get_suggestion(
                code="x = 1",
                finding_message="Poor variable name",
                finding_category="naming",
                line_number=1,
            )
        
        assert result == "Use a more descriptive variable name."
        mock_call.assert_called_once()

    @pytest.mark.asyncio
    async def test_explain_vulnerability(self):
        """Test vulnerability explanation."""
        analyzer = LLMAnalyzer(api_key="test-key")
        
        with patch.object(analyzer, "_call_openai", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = "This SQL query is vulnerable to injection."
            
            result = await analyzer.explain_vulnerability(
                code="query = f'SELECT * FROM users WHERE id = {id}'",
                vulnerability_type="sql_injection",
                owasp_category="A03:2021-Injection",
                line_number=1,
            )
        
        assert result == "This SQL query is vulnerable to injection."

    @pytest.mark.asyncio
    async def test_analyze_code_quality(self):
        """Test code quality analysis."""
        analyzer = LLMAnalyzer(api_key="test-key")
        
        response = json.dumps([
            {
                "line_number": 1,
                "severity": "medium",
                "category": "naming",
                "message": "Variable name too short",
                "suggestion": "Use descriptive names",
            }
        ])
        
        with patch.object(analyzer, "_call_openai", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = response
            
            result = await analyzer.analyze_code_quality("x = 1", "test.py")
        
        assert len(result) == 1
        assert result[0]["category"] == "naming"

    @pytest.mark.asyncio
    async def test_analyze_security(self):
        """Test security analysis."""
        analyzer = LLMAnalyzer(api_key="test-key")
        
        response = json.dumps([
            {
                "line_number": 1,
                "severity": "high",
                "category": "sql_injection",
                "message": "SQL injection vulnerability",
                "suggestion": "Use parameterized queries",
                "owasp_category": "A03:2021-Injection",
            }
        ])
        
        with patch.object(analyzer, "_call_openai", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = response
            
            result = await analyzer.analyze_security("query = f'...'", "test.py")
        
        assert len(result) == 1
        assert result[0]["category"] == "sql_injection"

    @pytest.mark.asyncio
    async def test_analyze_testing(self):
        """Test testing analysis."""
        analyzer = LLMAnalyzer(api_key="test-key")
        
        response = json.dumps([
            {
                "line_number": 5,
                "severity": "medium",
                "category": "missing_test",
                "message": "Missing edge case test",
                "suggestion": "Test with empty input",
            }
        ])
        
        with patch.object(analyzer, "_call_openai", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = response
            
            result = await analyzer.analyze_testing(
                code="def func(): pass",
                file_path="src/module.py",
                is_test_file=False,
                functions=[{"name": "func"}],
            )
        
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_analyze_testing_test_file(self):
        """Test testing analysis for test files."""
        analyzer = LLMAnalyzer(api_key="test-key")
        
        response = json.dumps([
            {
                "line_number": 1,
                "severity": "high",
                "category": "test_quality",
                "message": "No assertions",
                "suggestion": "Add assertions",
            }
        ])
        
        with patch.object(analyzer, "_call_openai", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = response
            
            result = await analyzer.analyze_testing(
                code="def test_func(): pass",
                file_path="test_module.py",
                is_test_file=True,
                functions=[],
            )
        
        assert len(result) == 1

    @pytest.mark.asyncio
    async def test_generate_review_summary(self):
        """Test review summary generation."""
        analyzer = LLMAnalyzer(api_key="test-key")
        
        with patch.object(analyzer, "_call_openai", new_callable=AsyncMock) as mock_call:
            mock_call.return_value = "Overall, the code needs improvement."
            
            result = await analyzer.generate_review_summary(
                code="x = 1",
                findings=[{"severity": "high", "message": "Issue"}],
                score=75.0,
            )
        
        assert result == "Overall, the code needs improvement."

    def test_extract_context(self):
        """Test code context extraction."""
        analyzer = LLMAnalyzer(api_key="test-key")
        code = "line1\nline2\nline3\nline4\nline5"
        
        context = analyzer._extract_context(code, 3, context=1)
        
        assert "line2" in context
        assert "line3" in context
        assert "line4" in context
        assert ">>>" in context  # Marker for target line

    def test_parse_json_response_valid(self):
        """Test JSON response parsing with valid JSON."""
        analyzer = LLMAnalyzer(api_key="test-key")
        
        response = json.dumps([{"key": "value"}])
        result = analyzer._parse_json_response(response)
        
        assert result == [{"key": "value"}]

    def test_parse_json_response_with_markdown(self):
        """Test JSON response parsing with markdown code block."""
        analyzer = LLMAnalyzer(api_key="test-key")
        
        response = "```json\n[{\"key\": \"value\"}]\n```"
        result = analyzer._parse_json_response(response)
        
        assert result == [{"key": "value"}]

    def test_parse_json_response_invalid(self):
        """Test JSON response parsing with invalid JSON."""
        analyzer = LLMAnalyzer(api_key="test-key")
        
        response = "not json"
        result = analyzer._parse_json_response(response)
        
        assert result == []

    def test_parse_json_response_none(self):
        """Test JSON response parsing with None."""
        analyzer = LLMAnalyzer(api_key="test-key")
        
        result = analyzer._parse_json_response(None)
        
        assert result == []

    def test_parse_json_response_not_list(self):
        """Test JSON response parsing when result is not a list."""
        analyzer = LLMAnalyzer(api_key="test-key")
        
        response = json.dumps({"key": "value"})
        result = analyzer._parse_json_response(response)
        
        assert result == []

