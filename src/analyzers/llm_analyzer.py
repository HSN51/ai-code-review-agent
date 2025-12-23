"""
LLM Analyzer for AI Code Review Agent.

OpenAI GPT integration for AI-powered code analysis with caching and retry logic.
"""

import hashlib
import json
import logging
from typing import Any, Optional

from cachetools import TTLCache
from openai import AsyncOpenAI, OpenAIError
from tenacity import (
    retry,
    retry_if_exception_type,
    stop_after_attempt,
    wait_exponential,
)

from src.config import get_settings


class LLMAnalyzer:
    """
    OpenAI GPT integration for code analysis.

    Provides structured prompts for code review with caching
    and retry logic for reliability.
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        model: Optional[str] = None,
        temperature: Optional[float] = None,
    ) -> None:
        """
        Initialize the LLM Analyzer.

        Args:
            api_key: OpenAI API key. Uses settings if not provided.
            model: Model to use. Uses settings if not provided.
            temperature: Temperature for responses. Uses settings if not provided.
        """
        self._logger = logging.getLogger("ai_code_review.llm_analyzer")
        settings = get_settings()

        self._api_key = api_key or settings.openai_api_key
        self._model = model or settings.openai_model
        self._temperature = temperature if temperature is not None else settings.openai_temperature
        self._max_tokens = settings.openai_max_tokens

        # Initialize client if API key is available
        self._client: Optional[AsyncOpenAI] = None
        if self._api_key and self._api_key != "your_openai_api_key_here":
            self._client = AsyncOpenAI(api_key=self._api_key)

        # Cache for responses
        self._cache: TTLCache = TTLCache(
            maxsize=settings.cache_max_size,
            ttl=settings.cache_ttl,
        )

    @property
    def is_configured(self) -> bool:
        """Check if LLM is properly configured."""
        return self._client is not None

    def _get_cache_key(self, *args: Any) -> str:
        """Generate cache key from arguments."""
        content = json.dumps(args, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    @retry(
        retry=retry_if_exception_type(OpenAIError),
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    async def _call_openai(
        self,
        system_prompt: str,
        user_prompt: str,
        use_cache: bool = True,
    ) -> Optional[str]:
        """
        Call OpenAI API with retry logic.

        Args:
            system_prompt: System prompt for the model.
            user_prompt: User prompt with the request.
            use_cache: Whether to use cached responses.

        Returns:
            Response text or None if unavailable.
        """
        if not self._client:
            self._logger.debug("OpenAI client not configured")
            return None

        # Check cache
        cache_key = self._get_cache_key(system_prompt, user_prompt)
        if use_cache and cache_key in self._cache:
            self._logger.debug("Returning cached response")
            return self._cache[cache_key]

        try:
            response = await self._client.chat.completions.create(
                model=self._model,
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt},
                ],
                temperature=self._temperature,
                max_tokens=self._max_tokens,
            )

            result = response.choices[0].message.content

            # Cache the result
            if use_cache and result:
                self._cache[cache_key] = result

            return result

        except OpenAIError as e:
            self._logger.error(f"OpenAI API error: {e}")
            raise
        except Exception as e:
            self._logger.error(f"Unexpected error calling OpenAI: {e}")
            return None

    async def get_suggestion(
        self,
        code: str,
        finding_message: str,
        finding_category: str,
        line_number: int,
    ) -> Optional[str]:
        """
        Get AI suggestion for a finding.

        Args:
            code: The source code.
            finding_message: The finding message.
            finding_category: Category of the finding.
            line_number: Line number of the issue.

        Returns:
            AI-generated suggestion or None.
        """
        system_prompt = """You are a code review assistant. Provide a brief, actionable suggestion 
to fix the identified code issue. Be specific and provide example code when helpful.
Keep your response under 200 words."""

        user_prompt = f"""Code issue found at line {line_number}:
Category: {finding_category}
Issue: {finding_message}

Code snippet:
```python
{self._extract_context(code, line_number)}
```

Provide a specific suggestion to fix this issue."""

        return await self._call_openai(system_prompt, user_prompt)

    async def explain_vulnerability(
        self,
        code: str,
        vulnerability_type: str,
        owasp_category: str,
        line_number: int,
    ) -> Optional[str]:
        """
        Explain a security vulnerability in plain language.

        Args:
            code: The source code.
            vulnerability_type: Type of vulnerability.
            owasp_category: OWASP category.
            line_number: Line number of the issue.

        Returns:
            Plain language explanation or None.
        """
        system_prompt = """You are a security expert explaining vulnerabilities to developers.
Explain the security issue clearly and provide:
1. What the vulnerability is
2. Why it's dangerous
3. How to fix it with specific code example
Keep your response under 250 words."""

        user_prompt = f"""Security vulnerability detected at line {line_number}:
Type: {vulnerability_type}
OWASP Category: {owasp_category}

Code:
```python
{self._extract_context(code, line_number)}
```

Explain this vulnerability and how to fix it."""

        return await self._call_openai(system_prompt, user_prompt)

    async def analyze_code_quality(
        self,
        code: str,
        file_path: str,
    ) -> list[dict]:
        """
        Analyze code quality using AI.

        Args:
            code: The source code to analyze.
            file_path: Path to the file.

        Returns:
            List of findings as dictionaries.
        """
        system_prompt = """You are a code quality expert. Analyze the code for:
- Code smells and anti-patterns
- Complexity issues
- Naming convention problems
- Best practice violations

Return findings as a JSON array with objects containing:
- line_number: int
- severity: "critical"|"high"|"medium"|"low"
- category: "code_smell"|"complexity"|"naming"|"style"|"maintainability"
- message: string (description of the issue)
- suggestion: string (how to fix it)

Return only the JSON array, no other text."""

        user_prompt = f"""Analyze this Python code for quality issues:

File: {file_path}

```python
{code}
```"""

        result = await self._call_openai(system_prompt, user_prompt)
        return self._parse_json_response(result)

    async def analyze_security(
        self,
        code: str,
        file_path: str,
    ) -> list[dict]:
        """
        Analyze code security using AI.

        Args:
            code: The source code to analyze.
            file_path: Path to the file.

        Returns:
            List of security findings as dictionaries.
        """
        system_prompt = """You are a security expert. Analyze the code for:
- SQL injection vulnerabilities
- XSS vulnerabilities
- Hardcoded secrets/credentials
- Insecure cryptography
- Authentication/authorization issues
- Input validation problems

Return findings as a JSON array with objects containing:
- line_number: int
- severity: "critical"|"high"|"medium"|"low"
- category: "sql_injection"|"xss"|"hardcoded_secret"|"injection"|"authentication"|"cryptography"
- message: string (description of the vulnerability)
- suggestion: string (how to fix it)
- owasp_category: string (e.g., "A03:2021-Injection")

Return only the JSON array, no other text. If no issues found, return []."""

        user_prompt = f"""Analyze this Python code for security vulnerabilities:

File: {file_path}

```python
{code}
```"""

        result = await self._call_openai(system_prompt, user_prompt)
        return self._parse_json_response(result)

    async def analyze_testing(
        self,
        code: str,
        file_path: str,
        is_test_file: bool,
        functions: list[dict],
    ) -> list[dict]:
        """
        Analyze code for testing improvements.

        Args:
            code: The source code.
            file_path: Path to the file.
            is_test_file: Whether this is a test file.
            functions: List of functions in the code.

        Returns:
            List of testing suggestions.
        """
        if is_test_file:
            system_prompt = """You are a testing expert. Analyze this test file for:
- Missing assertions
- Test coverage gaps
- Edge cases not tested
- Test quality issues

Return findings as a JSON array with objects containing:
- line_number: int
- severity: "high"|"medium"|"low"
- category: "test_quality"|"missing_test"|"edge_case"
- message: string
- suggestion: string

Return only the JSON array, no other text. If no issues, return []."""
        else:
            system_prompt = """You are a testing expert. Analyze this code and suggest tests:
- Missing test cases
- Edge cases to test
- Error scenarios to cover

Return findings as a JSON array with objects containing:
- line_number: int
- severity: "medium"|"low"
- category: "missing_test"|"edge_case"|"low_coverage"
- message: string (what should be tested)
- suggestion: string (example test case)

Return only the JSON array, no other text. Limit to 5 most important suggestions."""

        func_names = [f["name"] for f in functions] if functions else []
        user_prompt = f"""Analyze this code for testing:

File: {file_path}
Functions: {', '.join(func_names) if func_names else 'None detected'}

```python
{code}
```"""

        result = await self._call_openai(system_prompt, user_prompt)
        return self._parse_json_response(result)

    async def generate_review_summary(
        self,
        code: str,
        findings: list[dict],
        score: float,
    ) -> Optional[str]:
        """
        Generate an overall review summary.

        Args:
            code: The source code.
            findings: List of findings.
            score: Overall score.

        Returns:
            Summary text or None.
        """
        system_prompt = """You are a code reviewer providing a summary.
Write a brief, constructive summary (2-3 sentences) highlighting:
- The main issues found
- Priority areas to address
- Any positive aspects

Be professional and constructive."""

        findings_summary = "\n".join([
            f"- [{f.get('severity', 'medium')}] {f.get('message', '')[:100]}"
            for f in findings[:10]
        ])

        user_prompt = f"""Code review completed with score {score}/100.

Key findings:
{findings_summary if findings_summary else 'No significant issues found.'}

Provide a brief summary for the developer."""

        return await self._call_openai(system_prompt, user_prompt)

    def _extract_context(self, code: str, line_number: int, context: int = 5) -> str:
        """Extract code context around a line."""
        lines = code.splitlines()
        start = max(0, line_number - context - 1)
        end = min(len(lines), line_number + context)

        context_lines = []
        for i, line in enumerate(lines[start:end], start=start + 1):
            marker = ">>> " if i == line_number else "    "
            context_lines.append(f"{marker}{i}: {line}")

        return "\n".join(context_lines)

    def _parse_json_response(self, response: Optional[str]) -> list[dict]:
        """Parse JSON response from LLM."""
        if not response:
            return []

        try:
            # Try to extract JSON from response
            response = response.strip()

            # Handle markdown code blocks
            if response.startswith("```"):
                lines = response.split("\n")
                json_lines = []
                in_json = False
                for line in lines:
                    if line.startswith("```") and not in_json:
                        in_json = True
                        continue
                    elif line.startswith("```") and in_json:
                        break
                    elif in_json:
                        json_lines.append(line)
                response = "\n".join(json_lines)

            result = json.loads(response)
            if isinstance(result, list):
                return result
            return []

        except json.JSONDecodeError as e:
            self._logger.warning(f"Failed to parse JSON response: {e}")
            return []

