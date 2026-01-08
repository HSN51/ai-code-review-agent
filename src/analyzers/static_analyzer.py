"""
Static Analyzer for AI Code Review Agent.

Wrapper for ruff, pylint, and bandit CLI tools with structured output parsing.
"""

import asyncio
import json
import logging
import os
import shutil
import sys
import tempfile
from typing import Optional, List, Dict, Any


class StaticAnalyzer:
    """
    Wrapper for static analysis tools (ruff, pylint, bandit).

    Provides async methods to run each tool and parse their output
    into a structured format.
    """

    def __init__(self) -> None:
        """Initialize the Static Analyzer."""
        self._logger = logging.getLogger("ai_code_review.static_analyzer")
        self._tool_paths: Dict[str, Optional[str]] = {}

    async def _resolve_tool_path(self, tool: str) -> Optional[str]:
        """
        Resolve the executable path for a tool.
        
        Tries:
        1. shutil.which(tool)
        2. sys.executable + " -m " + tool (as a fallback command strategy)
        """
        if tool in self._tool_paths:
            return self._tool_paths[tool]

        # 1. Check PATH
        path = shutil.which(tool)
        if path:
            self._logger.debug(f"Found {tool} at {path}")
            self._tool_paths[tool] = path
            return path

        # 2. Check if it runs as a python module
        try:
            process = await asyncio.create_subprocess_exec(
                sys.executable,
                "-m",
                tool,
                "--version",
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            await process.communicate()
            if process.returncode == 0:
                self._logger.debug(f"Found {tool} as python module")
                # Return a marker to indicate module usage
                cmd = f"{sys.executable} -m {tool}"
                self._tool_paths[tool] = cmd
                return cmd
        except Exception:
            pass

        self._logger.warning(f"Tool '{tool}' not found in PATH or as python module")
        self._tool_paths[tool] = None
        return None

    async def _check_tool_available(self, tool: str) -> bool:
        """Check if a tool is available."""
        path = await self._resolve_tool_path(tool)
        return path is not None

    async def _write_temp_file(self, code: str, suffix: str = ".py") -> str:
        """
        Write code to a temporary file ensuring UTF-8 encoding and file closure.
        """
        # delete=False is required on Windows if another process will open it
        fd, path = tempfile.mkstemp(suffix=suffix)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                f.write(code)
            return path
        except Exception as e:
            self._logger.error(f"Failed to write temp file: {e}")
            # Try to close invalid fd if open
            try:
                os.close(fd)
            except OSError:
                pass
            # Try to cleanup
            if os.path.exists(path):
                os.unlink(path)
            raise

    async def _cleanup_temp_file(self, path: str) -> None:
        """Remove a temporary file."""
        if not path or not os.path.exists(path):
            return
        try:
            os.unlink(path)
        except OSError as e:
            self._logger.debug(f"Failed to delete temp file {path}: {e}")

    async def _run_tool(self, tool_name: str, args: List[str], temp_path: str, timeout: float = 30.0) -> str:
        """
        Helper to run a tool subprocess with correct path resolution.
        """
        resolved_cmd = await self._resolve_tool_path(tool_name)
        if not resolved_cmd:
            raise RuntimeError(f"Tool {tool_name} not available")

        # Handle "python -m tool" case
        if resolved_cmd.startswith(sys.executable):
            # Split "C:\Python\python.exe -m tool" -> ["C:\Python\python.exe", "-m", "tool"]
            # But resolved_cmd is just the string. We need accurate args.
            # Simplified: usage relies on _resolve_tool_path returning a runnable string?
            # No, asyncio.create_subprocess_exec needs the program as first arg.
            
            # If we detected module mode, we reconstruct the args
            # cmd_parts = [sys.executable, "-m", tool_name] + args
            program = sys.executable
            final_args = ["-m", tool_name] + args
        else:
            # Standard binary case
            program = resolved_cmd
            final_args = args

        # Ensure temp_path is in args if needed (logic passed by caller)
        # Append temp_path to final_args
        final_args.append(temp_path)

        # Set environment for UTF-8
        env = os.environ.copy()
        env["PYTHONIOENCODING"] = "utf-8"

        try:
            process = await asyncio.create_subprocess_exec(
                program,
                *final_args,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
                env=env
            )
            
            stdout, stderr = await asyncio.wait_for(
                process.communicate(),
                timeout=timeout
            )
            
            if stderr:
                self._logger.debug(f"{tool_name} stderr: {stderr.decode('utf-8', errors='replace')}")

            if stdout:
                return stdout.decode("utf-8", errors="replace")
            return ""

        except asyncio.TimeoutError:
            self._logger.error(f"{tool_name} analysis timed out after {timeout}s")
            # Try to kill
            try:
                process.kill()
            except Exception:
                pass
            raise
        except Exception as e:
            self._logger.error(f"{tool_name} execution failed: {e}")
            raise

    async def run_ruff(
        self,
        code: str,
        file_path: str = "untitled.py",
        timeout: float = 30.0,
    ) -> list[dict]:
        """Run ruff linter on the code."""
        if not await self._check_tool_available("ruff"):
            return []

        temp_path = await self._write_temp_file(code)
        try:
            # Arguments for ruff
            args = [
                "check",
                "--output-format=json",
                "--select=ALL",
                "--ignore=D,ANN",
                "--exit-zero"  # Important: ensures ruff doesn't return non-zero exit code on lint errors
            ]
            
            stdout = await self._run_tool("ruff", args, temp_path, timeout)
            
            results = []
            if stdout:
                try:
                    ruff_output = json.loads(stdout)
                    if isinstance(ruff_output, list):
                        for item in ruff_output:
                            if not isinstance(item, dict):
                                continue
                            results.append({
                                "code": item.get("code", ""),
                                "message": item.get("message", ""),
                                "line": item.get("location", {}).get("row", 1),
                                "column": item.get("location", {}).get("column", 0),
                                "end_line": item.get("end_location", {}).get("row"),
                                "severity": self._ruff_severity(item.get("code", "")),
                                "suggestion": item.get("fix", {}).get("message", ""),
                            })
                    else:
                        self._logger.warning(f"Unexpected ruff output format: {type(ruff_output)}")
                except json.JSONDecodeError as e:
                    self._logger.error(f"Failed to parse ruff output: {e}\nRaw output: {stdout[:100]}...")

            return results

        except Exception as e:
            self._logger.error(f"Error running ruff: {e}")
            return []
        finally:
            await self._cleanup_temp_file(temp_path)

    async def run_pylint(
        self,
        code: str,
        file_path: str = "untitled.py",
        timeout: float = 60.0,
    ) -> list[dict]:
        """Run pylint on the code."""
        if not await self._check_tool_available("pylint"):
            return []

        temp_path = await self._write_temp_file(code)
        try:
            args = [
                "--output-format=json",
                "--disable=C0114,C0115,C0116",
                "--max-line-length=120",
                "--from-stdin" if False else "--exit-zero" # pylint doesn't support --exit-zero specifically for json output the same way, but let's try standard
            ]
            # Pylint usually returns non-zero on issues. We must handle that.
            # _run_tool logs stderr but doesn't throw if returncode is non-zero (unless create_subprocess_exec fails). 
            # Wait, create_subprocess_exec doesn't throw on non-zero exit.
            
            stdout = await self._run_tool("pylint", args, temp_path, timeout)

            results = []
            if stdout:
                try:
                    pylint_output = json.loads(stdout)
                    if isinstance(pylint_output, list):
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
                    self._logger.error(f"Failed to parse pylint output: {e}\nRaw output: {stdout[:100]}...")

            return results

        except Exception as e:
            self._logger.error(f"Error running pylint: {e}")
            return []
        finally:
            await self._cleanup_temp_file(temp_path)

    async def run_bandit(
        self,
        code: str,
        file_path: str = "untitled.py",
        timeout: float = 30.0,
    ) -> list[dict]:
        """Run bandit security scanner on the code."""
        if not await self._check_tool_available("bandit"):
            return []

        temp_path = await self._write_temp_file(code)
        try:
            args = [
                "-f", "json",
                "-ll",
                "--exit-zero"  # Bandit returns 1 if issues found, ensure we just get output
            ]
            
            stdout = await self._run_tool("bandit", args, temp_path, timeout)

            results = []
            if stdout:
                try:
                    bandit_output = json.loads(stdout)
                    # Bandit json format: {"errors": [], "generated_at": "...", "metrics": {...}, "results": [...]}
                    if isinstance(bandit_output, dict):
                        for item in bandit_output.get("results", []) or []:
                            if not isinstance(item, dict):
                                continue
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
                    else:
                         self._logger.warning(f"Unexpected bandit output format: {type(bandit_output)}")

                except json.JSONDecodeError as e:
                    self._logger.error(f"Failed to parse bandit output: {e}\nRaw output: {stdout[:100]}...")

            return results

        except Exception as e:
            self._logger.error(f"Error running bandit: {e}")
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

