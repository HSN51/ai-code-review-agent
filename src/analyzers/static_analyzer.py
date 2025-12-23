"""
Static Analyzer for AI Code Review Agent.

Wrapper for ruff, pylint, and bandit CLI tools with structured output parsing.
"""

import asyncio
import json
import logging
import os
import tempfile
from typing import Optional


class StaticAnalyzer:
    """
    Wrapper for static analysis tools (ruff, pylint, bandit).

    Provides async methods to run each tool and parse their output
    into a structured format.
    """

    def __init__(self) -> None:
        """Initialize the Static Analyzer."""
        self._logger = logging.getLogger("ai_code_review.static_analyzer")
        self._tool_availability: dict[str, bool] = {}

    async def _check_tool_available(self, tool: str) -> bool:
        """
        Check if a tool is available on the system.

        Args:
            tool: Name of the tool to check.

        Returns:
            True if available, False otherwise.
        """
        if tool in self._tool_availability:
            return self._tool_availability[tool]

        try:
            process = await asyncio.create_subprocess_exec(
                tool,
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            available = process.returncode == 0
        except (FileNotFoundError, OSError):
            available = False

        self._tool_availability[tool] = available
        if not available:
            self._logger.warning(f"Tool '{tool}' is not available")
        return available

    async def _write_temp_file(self, code: str, suffix: str = ".py") -> str:
        """
        Write code to a temporary file.

        Args:
            code: Code content to write.
            suffix: File suffix.

        Returns:
            Path to the temporary file.
        """
        fd, path = tempfile.mkstemp(suffix=suffix)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(code)
        except Exception:
            os.close(fd)
            raise
        return path

    async def _cleanup_temp_file(self, path: str) -> None:
        """Remove a temporary file."""
        try:
            os.unlink(path)
        except OSError:
            pass

    async def run_ruff(
        self,
        code: str,
        file_path: str = "untitled.py",
        timeout: float = 30.0,
    ) -> list[dict]:
        """
        Run ruff linter on the code.

        Args:
            code: The source code to analyze.
            file_path: Virtual file path for context.
            timeout: Timeout in seconds.

        Returns:
            List of dictionaries with findings.
        """
        if not await self._check_tool_available("ruff"):
            return []

        temp_path = await self._write_temp_file(code)
        try:
            process = await asyncio.create_subprocess_exec(
                "ruff",
                "check",
                "--output-format=json",
                "--select=ALL",
                "--ignore=D,ANN",  # Ignore docstring and annotation rules for now
                temp_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )

            results = []
            if stdout:
                try:
                    ruff_output = json.loads(stdout.decode("utf-8"))
                    for item in ruff_output:
                        results.append({
                            "code": item.get("code", ""),
                            "message": item.get("message", ""),
                            "line": item.get("location", {}).get("row", 1),
                            "column": item.get("location", {}).get("column", 0),
                            "end_line": item.get("end_location", {}).get("row"),
                            "severity": self._ruff_severity(item.get("code", "")),
                            "suggestion": item.get("fix", {}).get("message", ""),
                        })
                except json.JSONDecodeError as e:
                    self._logger.error(f"Failed to parse ruff output: {e}")

            return results

        except asyncio.TimeoutError:
            self._logger.error("Ruff analysis timed out")
            return []
        except Exception as e:
            self._logger.error(f"Ruff analysis failed: {e}")
            return []
        finally:
            await self._cleanup_temp_file(temp_path)

    async def run_pylint(
        self,
        code: str,
        file_path: str = "untitled.py",
        timeout: float = 60.0,
    ) -> list[dict]:
        """
        Run pylint on the code.

        Args:
            code: The source code to analyze.
            file_path: Virtual file path for context.
            timeout: Timeout in seconds.

        Returns:
            List of dictionaries with findings.
        """
        if not await self._check_tool_available("pylint"):
            return []

        temp_path = await self._write_temp_file(code)
        try:
            process = await asyncio.create_subprocess_exec(
                "pylint",
                "--output-format=json",
                "--disable=C0114,C0115,C0116",  # Disable docstring warnings
                "--max-line-length=120",
                temp_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )

            results = []
            if stdout:
                try:
                    pylint_output = json.loads(stdout.decode("utf-8"))
                    for item in pylint_output:
                        results.append({
                            "code": item.get("message-id", ""),
                            "message": item.get("message", ""),
                            "line": item.get("line", 1),
                            "column": item.get("column", 0),
                            "symbol": item.get("symbol", ""),
                            "severity": self._pylint_severity(item.get("type", "")),
                        })
                except json.JSONDecodeError as e:
                    self._logger.error(f"Failed to parse pylint output: {e}")

            return results

        except asyncio.TimeoutError:
            self._logger.error("Pylint analysis timed out")
            return []
        except Exception as e:
            self._logger.error(f"Pylint analysis failed: {e}")
            return []
        finally:
            await self._cleanup_temp_file(temp_path)

    async def run_bandit(
        self,
        code: str,
        file_path: str = "untitled.py",
        timeout: float = 30.0,
    ) -> list[dict]:
        """
        Run bandit security scanner on the code.

        Args:
            code: The source code to analyze.
            file_path: Virtual file path for context.
            timeout: Timeout in seconds.

        Returns:
            List of dictionaries with security findings.
        """
        if not await self._check_tool_available("bandit"):
            return []

        temp_path = await self._write_temp_file(code)
        try:
            process = await asyncio.create_subprocess_exec(
                "bandit",
                "-f",
                "json",
                "-ll",  # Low and above severity
                temp_path,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )

            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout,
            )

            results = []
            if stdout:
                try:
                    bandit_output = json.loads(stdout.decode("utf-8"))
                    for item in bandit_output.get("results", []):
                        results.append({
                            "test_id": item.get("test_id", ""),
                            "test_name": item.get("test_name", ""),
                            "message": item.get("issue_text", ""),
                            "line_number": item.get("line_number", 1),
                            "line_range": item.get("line_range", []),
                            "severity": item.get("issue_severity", "MEDIUM"),
                            "confidence": item.get("issue_confidence", "MEDIUM"),
                            "code": item.get("code", ""),
                            "cwe": item.get("issue_cwe", {}),
                        })
                except json.JSONDecodeError as e:
                    self._logger.error(f"Failed to parse bandit output: {e}")

            return results

        except asyncio.TimeoutError:
            self._logger.error("Bandit analysis timed out")
            return []
        except Exception as e:
            self._logger.error(f"Bandit analysis failed: {e}")
            return []
        finally:
            await self._cleanup_temp_file(temp_path)

    def _ruff_severity(self, code: str) -> str:
        """Map ruff error code to severity."""
        if not code:
            return "medium"

        prefix = code[0].upper()
        severity_map = {
            "E": "high",      # Error
            "F": "critical",  # Pyflakes (potential bugs)
            "W": "medium",    # Warning
            "C": "low",       # Convention
            "N": "low",       # Naming
            "I": "low",       # Import
            "B": "high",      # Bugbear (likely bugs)
            "A": "medium",    # Builtins
            "S": "high",      # Security
            "T": "low",       # Type
            "P": "medium",    # Pytest
            "R": "medium",    # Refactor
            "U": "medium",    # Upgrade
        }
        return severity_map.get(prefix, "medium")

    def _pylint_severity(self, msg_type: str) -> str:
        """Map pylint message type to severity."""
        severity_map = {
            "error": "critical",
            "fatal": "critical",
            "warning": "high",
            "convention": "low",
            "refactor": "medium",
            "information": "info",
        }
        return severity_map.get(msg_type.lower(), "medium")

    async def run_all(
        self,
        code: str,
        file_path: str = "untitled.py",
    ) -> dict[str, list[dict]]:
        """
        Run all static analysis tools.

        Args:
            code: The source code to analyze.
            file_path: Virtual file path for context.

        Returns:
            Dictionary with results from each tool.
        """
        ruff_task = self.run_ruff(code, file_path)
        pylint_task = self.run_pylint(code, file_path)
        bandit_task = self.run_bandit(code, file_path)

        ruff_results, pylint_results, bandit_results = await asyncio.gather(
            ruff_task,
            pylint_task,
            bandit_task,
            return_exceptions=True,
        )

        return {
            "ruff": ruff_results if isinstance(ruff_results, list) else [],
            "pylint": pylint_results if isinstance(pylint_results, list) else [],
            "bandit": bandit_results if isinstance(bandit_results, list) else [],
        }

