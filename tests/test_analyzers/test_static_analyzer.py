"""
Tests for Static Analyzer.

Tests ruff, pylint, and bandit wrapper functionality.
"""

import json
import pytest
from unittest.mock import AsyncMock, MagicMock, patch
import asyncio

from src.analyzers.static_analyzer import StaticAnalyzer


class TestStaticAnalyzer:
    """Tests for StaticAnalyzer class."""

    def test_init(self):
        """Test StaticAnalyzer initialization."""
        analyzer = StaticAnalyzer()
        assert analyzer._tool_availability == {}

    @pytest.mark.asyncio
    async def test_check_tool_available_found(self):
        """Test tool availability check when tool exists."""
        analyzer = StaticAnalyzer()
        
        with patch("asyncio.create_subprocess_exec") as mock_exec:
            mock_process = AsyncMock()
            mock_process.returncode = 0
            mock_process.communicate = AsyncMock(return_value=(b"", b""))
            mock_exec.return_value = mock_process
            
            result = await analyzer._check_tool_available("python")
            
            assert result is True
            assert analyzer._tool_availability["python"] is True

    @pytest.mark.asyncio
    async def test_check_tool_available_not_found(self):
        """Test tool availability check when tool doesn't exist."""
        analyzer = StaticAnalyzer()
        
        with patch("asyncio.create_subprocess_exec", side_effect=FileNotFoundError()):
            result = await analyzer._check_tool_available("nonexistent")
            
            assert result is False
            assert analyzer._tool_availability["nonexistent"] is False

    @pytest.mark.asyncio
    async def test_check_tool_cached(self):
        """Test tool availability caching."""
        analyzer = StaticAnalyzer()
        analyzer._tool_availability["cached_tool"] = True
        
        result = await analyzer._check_tool_available("cached_tool")
        
        assert result is True

    @pytest.mark.asyncio
    async def test_write_temp_file(self):
        """Test temporary file creation."""
        analyzer = StaticAnalyzer()
        code = "print('hello')"
        
        path = await analyzer._write_temp_file(code)
        
        try:
            with open(path, "r") as f:
                content = f.read()
            assert content == code
        finally:
            await analyzer._cleanup_temp_file(path)

    @pytest.mark.asyncio
    async def test_cleanup_temp_file(self):
        """Test temporary file cleanup."""
        analyzer = StaticAnalyzer()
        code = "print('hello')"
        
        path = await analyzer._write_temp_file(code)
        await analyzer._cleanup_temp_file(path)
        
        import os
        assert not os.path.exists(path)

    @pytest.mark.asyncio
    async def test_cleanup_temp_file_nonexistent(self):
        """Test cleanup of non-existent file."""
        analyzer = StaticAnalyzer()
        # Should not raise
        await analyzer._cleanup_temp_file("/nonexistent/path.py")

    @pytest.mark.asyncio
    async def test_run_ruff_success(self):
        """Test successful ruff execution."""
        analyzer = StaticAnalyzer()
        
        ruff_output = json.dumps([
            {
                "code": "E501",
                "message": "Line too long",
                "location": {"row": 10, "column": 80},
                "end_location": {"row": 10, "column": 120},
            }
        ])
        
        with patch.object(analyzer, "_check_tool_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate = AsyncMock(
                    return_value=(ruff_output.encode(), b"")
                )
                mock_exec.return_value = mock_process
                
                results = await analyzer.run_ruff("x = 1", "test.py")
        
        assert len(results) == 1
        assert results[0]["code"] == "E501"
        assert results[0]["line"] == 10

    @pytest.mark.asyncio
    async def test_run_ruff_tool_not_available(self):
        """Test ruff when tool is not available."""
        analyzer = StaticAnalyzer()
        
        with patch.object(analyzer, "_check_tool_available", return_value=False):
            results = await analyzer.run_ruff("x = 1", "test.py")
        
        assert results == []

    @pytest.mark.asyncio
    async def test_run_ruff_timeout(self):
        """Test ruff timeout handling."""
        analyzer = StaticAnalyzer()
        
        async def slow_communicate():
            await asyncio.sleep(10)
            return (b"", b"")
        
        with patch.object(analyzer, "_check_tool_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate = slow_communicate
                mock_exec.return_value = mock_process
                
                results = await analyzer.run_ruff("x = 1", "test.py", timeout=0.1)
        
        assert results == []

    @pytest.mark.asyncio
    async def test_run_ruff_json_error(self):
        """Test ruff with invalid JSON output."""
        analyzer = StaticAnalyzer()
        
        with patch.object(analyzer, "_check_tool_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate = AsyncMock(
                    return_value=(b"invalid json", b"")
                )
                mock_exec.return_value = mock_process
                
                results = await analyzer.run_ruff("x = 1", "test.py")
        
        assert results == []

    @pytest.mark.asyncio
    async def test_run_pylint_success(self):
        """Test successful pylint execution."""
        analyzer = StaticAnalyzer()
        
        pylint_output = json.dumps([
            {
                "message-id": "C0301",
                "message": "Line too long",
                "line": 5,
                "column": 0,
                "type": "convention",
                "symbol": "line-too-long",
            }
        ])
        
        with patch.object(analyzer, "_check_tool_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate = AsyncMock(
                    return_value=(pylint_output.encode(), b"")
                )
                mock_exec.return_value = mock_process
                
                results = await analyzer.run_pylint("x = 1", "test.py")
        
        assert len(results) == 1
        assert results[0]["code"] == "C0301"

    @pytest.mark.asyncio
    async def test_run_pylint_tool_not_available(self):
        """Test pylint when tool is not available."""
        analyzer = StaticAnalyzer()
        
        with patch.object(analyzer, "_check_tool_available", return_value=False):
            results = await analyzer.run_pylint("x = 1", "test.py")
        
        assert results == []

    @pytest.mark.asyncio
    async def test_run_bandit_success(self):
        """Test successful bandit execution."""
        analyzer = StaticAnalyzer()
        
        bandit_output = json.dumps({
            "results": [
                {
                    "test_id": "B608",
                    "test_name": "hardcoded_sql_expressions",
                    "issue_text": "Possible SQL injection",
                    "line_number": 5,
                    "issue_severity": "HIGH",
                    "issue_confidence": "MEDIUM",
                }
            ]
        })
        
        with patch.object(analyzer, "_check_tool_available", return_value=True):
            with patch("asyncio.create_subprocess_exec") as mock_exec:
                mock_process = AsyncMock()
                mock_process.communicate = AsyncMock(
                    return_value=(bandit_output.encode(), b"")
                )
                mock_exec.return_value = mock_process
                
                results = await analyzer.run_bandit("x = 1", "test.py")
        
        assert len(results) == 1
        assert results[0]["test_id"] == "B608"

    @pytest.mark.asyncio
    async def test_run_bandit_tool_not_available(self):
        """Test bandit when tool is not available."""
        analyzer = StaticAnalyzer()
        
        with patch.object(analyzer, "_check_tool_available", return_value=False):
            results = await analyzer.run_bandit("x = 1", "test.py")
        
        assert results == []

    def test_ruff_severity_mapping(self):
        """Test ruff severity mapping."""
        analyzer = StaticAnalyzer()
        
        assert analyzer._ruff_severity("E501") == "high"
        assert analyzer._ruff_severity("F401") == "critical"
        assert analyzer._ruff_severity("W503") == "medium"
        assert analyzer._ruff_severity("C0103") == "low"
        assert analyzer._ruff_severity("UNKNOWN") == "medium"

    def test_pylint_severity_mapping(self):
        """Test pylint severity mapping."""
        analyzer = StaticAnalyzer()
        
        assert analyzer._pylint_severity("error") == "critical"
        assert analyzer._pylint_severity("warning") == "high"
        assert analyzer._pylint_severity("convention") == "low"
        assert analyzer._pylint_severity("refactor") == "medium"

    @pytest.mark.asyncio
    async def test_run_all(self):
        """Test running all analyzers."""
        analyzer = StaticAnalyzer()
        
        with patch.object(analyzer, "run_ruff", return_value=[{"code": "E501"}]):
            with patch.object(analyzer, "run_pylint", return_value=[{"code": "C0301"}]):
                with patch.object(analyzer, "run_bandit", return_value=[{"test_id": "B608"}]):
                    results = await analyzer.run_all("x = 1", "test.py")
        
        assert "ruff" in results
        assert "pylint" in results
        assert "bandit" in results
        assert len(results["ruff"]) == 1
        assert len(results["pylint"]) == 1
        assert len(results["bandit"]) == 1

    @pytest.mark.asyncio
    async def test_run_all_with_exceptions(self):
        """Test running all analyzers with exceptions."""
        analyzer = StaticAnalyzer()
        
        with patch.object(analyzer, "run_ruff", side_effect=Exception("Error")):
            with patch.object(analyzer, "run_pylint", return_value=[]):
                with patch.object(analyzer, "run_bandit", return_value=[]):
                    results = await analyzer.run_all("x = 1", "test.py")
        
        assert results["ruff"] == []
        assert results["pylint"] == []
        assert results["bandit"] == []

