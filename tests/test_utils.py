"""
Tests for utility functions.

Tests helper utilities used across the application.
"""

import pytest

from src.models.schemas import Finding, FindingCategory, Severity
from src.utils.helpers import (
    calculate_complexity_score,
    count_lines_of_code,
    detect_language,
    extract_code_context,
    format_finding_markdown,
    parse_github_url,
    sanitize_code,
    truncate_string,
)


class TestParseGitHubUrl:
    """Tests for parse_github_url function."""

    def test_full_url(self):
        """Test parsing full GitHub URL."""
        result = parse_github_url("https://github.com/octocat/hello-world/pull/123")
        
        assert result["owner"] == "octocat"
        assert result["repo"] == "hello-world"
        assert result["pr_number"] == 123

    def test_url_without_scheme(self):
        """Test parsing URL without scheme."""
        result = parse_github_url("github.com/octocat/hello-world/pull/123")
        
        assert result["owner"] == "octocat"
        assert result["repo"] == "hello-world"
        assert result["pr_number"] == 123

    def test_shorthand_format(self):
        """Test parsing shorthand format."""
        result = parse_github_url("octocat/hello-world#123")
        
        assert result["owner"] == "octocat"
        assert result["repo"] == "hello-world"
        assert result["pr_number"] == 123

    def test_invalid_url(self):
        """Test parsing invalid URL."""
        result = parse_github_url("not a url")
        assert result is None

    def test_non_github_url(self):
        """Test parsing non-GitHub URL."""
        result = parse_github_url("https://gitlab.com/user/repo/merge_requests/1")
        assert result is None

    def test_incomplete_url(self):
        """Test parsing incomplete URL."""
        result = parse_github_url("https://github.com/octocat/hello-world")
        assert result is None


class TestExtractCodeContext:
    """Tests for extract_code_context function."""

    def test_basic_extraction(self):
        """Test basic context extraction."""
        code = "line1\nline2\nline3\nline4\nline5"
        context = extract_code_context(code, 3, context_lines=1)
        
        assert "line2" in context
        assert "line3" in context
        assert "line4" in context
        assert ">>>" in context  # Target line marker

    def test_edge_case_first_line(self):
        """Test extraction at first line."""
        code = "line1\nline2\nline3"
        context = extract_code_context(code, 1, context_lines=2)
        
        assert "line1" in context
        assert ">>>" in context

    def test_edge_case_last_line(self):
        """Test extraction at last line."""
        code = "line1\nline2\nline3"
        context = extract_code_context(code, 3, context_lines=2)
        
        assert "line3" in context

    def test_includes_line_numbers(self):
        """Test that output includes line numbers."""
        code = "line1\nline2\nline3"
        context = extract_code_context(code, 2, context_lines=1)
        
        assert "1" in context
        assert "2" in context
        assert "3" in context


class TestFormatFindingMarkdown:
    """Tests for format_finding_markdown function."""

    def test_basic_formatting(self):
        """Test basic markdown formatting."""
        finding = Finding(
            file_path="test.py",
            line_number=10,
            severity=Severity.HIGH,
            category=FindingCategory.CODE_SMELL,
            message="Test issue",
            agent_name="TestAgent",
        )
        
        md = format_finding_markdown(finding)
        
        assert "HIGH" in md
        assert "test.py" in md
        assert "line 10" in md
        assert "Test issue" in md

    def test_with_suggestion(self):
        """Test formatting with suggestion."""
        finding = Finding(
            file_path="test.py",
            line_number=10,
            severity=Severity.MEDIUM,
            category=FindingCategory.STYLE,
            message="Style issue",
            suggestion="Fix the style",
            agent_name="TestAgent",
        )
        
        md = format_finding_markdown(finding)
        
        assert "Suggestion" in md
        assert "Fix the style" in md

    def test_with_code_snippet(self):
        """Test formatting with code snippet."""
        finding = Finding(
            file_path="test.py",
            line_number=10,
            severity=Severity.LOW,
            category=FindingCategory.NAMING,
            message="Naming issue",
            agent_name="TestAgent",
            code_snippet="x = 1",
        )
        
        md = format_finding_markdown(finding)
        
        assert "```python" in md
        assert "x = 1" in md

    def test_severity_icons(self):
        """Test severity icons in output."""
        for severity in Severity:
            finding = Finding(
                file_path="test.py",
                line_number=1,
                severity=severity,
                category=FindingCategory.OTHER,
                message="Test",
                agent_name="Test",
            )
            md = format_finding_markdown(finding)
            # Should have some icon
            assert any(icon in md for icon in ["🔴", "🟠", "🟡", "🔵", "⚪"])


class TestSanitizeCode:
    """Tests for sanitize_code function."""

    def test_removes_null_bytes(self):
        """Test removal of null bytes."""
        code = "hello\x00world"
        sanitized = sanitize_code(code)
        
        assert "\x00" not in sanitized

    def test_normalizes_line_endings(self):
        """Test line ending normalization."""
        code = "line1\r\nline2\rline3"
        sanitized = sanitize_code(code)
        
        assert "\r\n" not in sanitized
        assert "\r" not in sanitized
        assert "\n" in sanitized

    def test_strips_trailing_whitespace(self):
        """Test trailing whitespace removal."""
        code = "line1   \nline2\t\n"
        sanitized = sanitize_code(code)
        
        lines = sanitized.split("\n")
        for line in lines[:-1]:  # Exclude last empty line
            assert not line.endswith(" ")
            assert not line.endswith("\t")

    def test_adds_trailing_newline(self):
        """Test trailing newline addition."""
        code = "line1\nline2"
        sanitized = sanitize_code(code)
        
        assert sanitized.endswith("\n")


class TestTruncateString:
    """Tests for truncate_string function."""

    def test_no_truncation_needed(self):
        """Test when no truncation is needed."""
        text = "short"
        result = truncate_string(text, max_length=10)
        
        assert result == "short"

    def test_truncation(self):
        """Test basic truncation."""
        text = "this is a long string"
        result = truncate_string(text, max_length=10)
        
        assert len(result) == 10
        assert result.endswith("...")

    def test_custom_suffix(self):
        """Test custom suffix."""
        text = "this is a long string"
        result = truncate_string(text, max_length=15, suffix="…")
        
        assert result.endswith("…")


class TestCountLinesOfCode:
    """Tests for count_lines_of_code function."""

    def test_basic_count(self):
        """Test basic line counting."""
        code = "line1\nline2\nline3"
        counts = count_lines_of_code(code)
        
        assert counts["total"] == 3
        assert counts["code"] == 3
        assert counts["blank"] == 0
        assert counts["comments"] == 0

    def test_with_blank_lines(self):
        """Test counting with blank lines."""
        code = "line1\n\nline3\n\n"
        counts = count_lines_of_code(code)
        
        assert counts["blank"] == 2

    def test_with_comments(self):
        """Test counting with comments."""
        code = "# Comment\ncode\n# Another comment"
        counts = count_lines_of_code(code)
        
        assert counts["comments"] == 2
        assert counts["code"] == 1


class TestDetectLanguage:
    """Tests for detect_language function."""

    def test_python_extension(self):
        """Test Python detection by extension."""
        assert detect_language("test.py") == "python"
        assert detect_language("test.pyw") == "python"
        assert detect_language("test.pyi") == "python"

    def test_javascript_extension(self):
        """Test JavaScript detection by extension."""
        assert detect_language("test.js") == "javascript"
        assert detect_language("test.jsx") == "javascript"

    def test_typescript_extension(self):
        """Test TypeScript detection by extension."""
        assert detect_language("test.ts") == "typescript"
        assert detect_language("test.tsx") == "typescript"

    def test_other_languages(self):
        """Test other language detection."""
        assert detect_language("test.java") == "java"
        assert detect_language("test.rb") == "ruby"
        assert detect_language("test.go") == "go"
        assert detect_language("test.rs") == "rust"

    def test_shebang_detection(self):
        """Test detection by shebang."""
        python_code = "#!/usr/bin/env python\nprint('hello')"
        assert detect_language("script", python_code) == "python"
        
        node_code = "#!/usr/bin/env node\nconsole.log('hello')"
        assert detect_language("script", node_code) == "javascript"

    def test_unknown_extension(self):
        """Test unknown extension."""
        assert detect_language("test.unknown") == "unknown"


class TestCalculateComplexityScore:
    """Tests for calculate_complexity_score function."""

    def test_no_findings(self):
        """Test score with no findings."""
        score = calculate_complexity_score({})
        assert score == 100.0

    def test_with_critical_findings(self):
        """Test score with critical findings."""
        score = calculate_complexity_score({"critical": 1})
        assert score < 100.0

    def test_score_capped(self):
        """Test score is capped at 0."""
        score = calculate_complexity_score({"critical": 100})
        assert score >= 0.0
        assert score <= 100.0

    def test_severity_weights(self):
        """Test different severity weights."""
        critical_score = calculate_complexity_score({"critical": 1})
        high_score = calculate_complexity_score({"high": 1})
        low_score = calculate_complexity_score({"low": 1})
        
        assert critical_score < high_score < low_score

