"""
Helper utilities for AI Code Review Agent.

Contains common utility functions used across the application.
"""

import re
from typing import Optional
from urllib.parse import urlparse

from src.models.schemas import Finding


def parse_github_url(url: str) -> Optional[dict[str, str | int]]:
    """
    Parse a GitHub URL to extract owner, repo, and PR number.

    Supports formats:
    - https://github.com/owner/repo/pull/123
    - github.com/owner/repo/pull/123
    - owner/repo#123

    Args:
        url: GitHub URL or shorthand.

    Returns:
        Dictionary with owner, repo, and pr_number, or None if invalid.
    """
    # Try shorthand format: owner/repo#123
    shorthand_match = re.match(r"^([^/]+)/([^#]+)#(\d+)$", url.strip())
    if shorthand_match:
        return {
            "owner": shorthand_match.group(1),
            "repo": shorthand_match.group(2),
            "pr_number": int(shorthand_match.group(3)),
        }

    # Try full URL format
    try:
        # Handle URLs without scheme
        if not url.startswith(("http://", "https://")):
            url = f"https://{url}"

        parsed = urlparse(url)

        # Check if it's a GitHub URL
        if "github" not in parsed.netloc.lower():
            return None

        # Parse path: /owner/repo/pull/123
        path_parts = parsed.path.strip("/").split("/")

        if len(path_parts) >= 4 and path_parts[2] == "pull":
            return {
                "owner": path_parts[0],
                "repo": path_parts[1],
                "pr_number": int(path_parts[3]),
            }

    except (ValueError, IndexError):
        pass

    return None


def extract_code_context(
    code: str,
    line_number: int,
    context_lines: int = 3,
) -> str:
    """
    Extract code context around a specific line.

    Args:
        code: The full source code.
        line_number: The line to center on (1-based).
        context_lines: Number of lines before and after.

    Returns:
        Code snippet with line numbers.
    """
    lines = code.splitlines()
    start = max(0, line_number - context_lines - 1)
    end = min(len(lines), line_number + context_lines)

    result = []
    for i, line in enumerate(lines[start:end], start=start + 1):
        marker = ">>> " if i == line_number else "    "
        result.append(f"{marker}{i:4d} | {line}")

    return "\n".join(result)


def format_finding_markdown(finding: Finding) -> str:
    """
    Format a finding as Markdown.

    Args:
        finding: The finding to format.

    Returns:
        Markdown-formatted string.
    """
    severity_colors = {
        "critical": "🔴",
        "high": "🟠",
        "medium": "🟡",
        "low": "🔵",
        "info": "⚪",
    }

    icon = severity_colors.get(finding.severity.value, "⚪")
    md = f"### {icon} {finding.severity.value.upper()}: {finding.category.value}\n\n"
    md += f"**File:** `{finding.file_path}` (line {finding.line_number})\n\n"
    md += f"**Issue:** {finding.message}\n\n"

    if finding.suggestion:
        md += f"**Suggestion:** {finding.suggestion}\n\n"

    if finding.code_snippet:
        md += f"```python\n{finding.code_snippet}\n```\n\n"

    if finding.rule_id:
        md += f"_Rule: {finding.rule_id}_\n"

    if finding.owasp_category:
        md += f"_OWASP: {finding.owasp_category}_\n"

    return md


def sanitize_code(code: str) -> str:
    """
    Sanitize code for safe processing.

    Removes or escapes potentially dangerous content while
    preserving the code structure.

    Args:
        code: The code to sanitize.

    Returns:
        Sanitized code.
    """
    # Remove null bytes
    code = code.replace("\x00", "")

    # Normalize line endings
    code = code.replace("\r\n", "\n").replace("\r", "\n")

    # Remove trailing whitespace on each line
    lines = [line.rstrip() for line in code.splitlines()]
    code = "\n".join(lines)

    # Ensure file ends with newline
    if code and not code.endswith("\n"):
        code += "\n"

    return code


def truncate_string(
    text: str,
    max_length: int = 500,
    suffix: str = "...",
) -> str:
    """
    Truncate a string to a maximum length.

    Args:
        text: The text to truncate.
        max_length: Maximum length including suffix.
        suffix: Suffix to append when truncated.

    Returns:
        Truncated string.
    """
    if len(text) <= max_length:
        return text

    return text[: max_length - len(suffix)] + suffix


def count_lines_of_code(code: str) -> dict[str, int]:
    """
    Count lines of code statistics.

    Args:
        code: The source code.

    Returns:
        Dictionary with line counts.
    """
    lines = code.splitlines()
    total = len(lines)
    blank = sum(1 for line in lines if not line.strip())
    comments = sum(1 for line in lines if line.strip().startswith("#"))
    code_lines = total - blank - comments

    return {
        "total": total,
        "blank": blank,
        "comments": comments,
        "code": code_lines,
    }


def detect_language(file_path: str, code: Optional[str] = None) -> str:
    """
    Detect the programming language from file path or content.

    Args:
        file_path: Path to the file.
        code: Optional code content for heuristic detection.

    Returns:
        Language identifier string.
    """
    extension_map = {
        ".py": "python",
        ".pyw": "python",
        ".pyi": "python",
        ".js": "javascript",
        ".jsx": "javascript",
        ".ts": "typescript",
        ".tsx": "typescript",
        ".java": "java",
        ".rb": "ruby",
        ".go": "go",
        ".rs": "rust",
        ".cpp": "cpp",
        ".cc": "cpp",
        ".cxx": "cpp",
        ".c": "c",
        ".h": "c",
        ".hpp": "cpp",
        ".cs": "csharp",
        ".php": "php",
        ".swift": "swift",
        ".kt": "kotlin",
        ".kts": "kotlin",
        ".scala": "scala",
        ".r": "r",
        ".R": "r",
        ".sql": "sql",
        ".sh": "shell",
        ".bash": "shell",
        ".zsh": "shell",
        ".yml": "yaml",
        ".yaml": "yaml",
        ".json": "json",
        ".xml": "xml",
        ".html": "html",
        ".htm": "html",
        ".css": "css",
        ".scss": "scss",
        ".sass": "sass",
        ".less": "less",
        ".md": "markdown",
        ".markdown": "markdown",
    }

    # Check extension
    for ext, lang in extension_map.items():
        if file_path.lower().endswith(ext):
            return lang

    # Heuristic detection from content
    if code:
        # Check for shebang
        if code.startswith("#!/"):
            first_line = code.split("\n")[0]
            if "python" in first_line:
                return "python"
            if "node" in first_line or "js" in first_line:
                return "javascript"
            if "ruby" in first_line:
                return "ruby"
            if "bash" in first_line or "sh" in first_line:
                return "shell"

        # Check for common patterns
        if "def " in code and "import " in code:
            return "python"
        if "function " in code and ("const " in code or "let " in code or "var " in code):
            return "javascript"

    return "unknown"


def calculate_complexity_score(findings_count: dict[str, int]) -> float:
    """
    Calculate a complexity score based on findings.

    Args:
        findings_count: Dictionary with severity counts.

    Returns:
        Complexity score from 0 to 100.
    """
    weights = {
        "critical": 25,
        "high": 15,
        "medium": 5,
        "low": 2,
        "info": 1,
    }

    total_deduction = sum(
        count * weights.get(severity, 0)
        for severity, count in findings_count.items()
    )

    return max(0.0, min(100.0, 100.0 - total_deduction))

