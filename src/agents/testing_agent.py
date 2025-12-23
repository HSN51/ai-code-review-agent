"""
Testing Agent for AI Code Review Agent.

Analyzes test coverage gaps and suggests missing test cases.
"""

import ast
import re
from typing import Optional

from src.agents.base_agent import BaseAgent
from src.analyzers.llm_analyzer import LLMAnalyzer
from src.models.schemas import Finding, FindingCategory, Severity


class TestingAgent(BaseAgent):
    """
    Agent for analyzing test coverage and suggesting improvements.

    Analyzes test coverage gaps, suggests missing test cases,
    and identifies untested edge cases using AI.
    """

    def __init__(
        self,
        llm_analyzer: Optional[LLMAnalyzer] = None,
    ) -> None:
        """
        Initialize the Testing Agent.

        Args:
            llm_analyzer: LLM analyzer instance. Created if not provided.
        """
        super().__init__(
            name="TestingAgent",
            description="Analyzes test coverage and suggests missing test cases",
        )
        self._llm_analyzer = llm_analyzer or LLMAnalyzer()

    async def analyze(
        self,
        code: str,
        file_path: str = "untitled.py",
        language: str = "python",
    ) -> list[Finding]:
        """
        Analyze code for testing gaps and improvements.

        Identifies functions without tests, missing edge cases,
        and suggests test improvements.

        Args:
            code: The source code to analyze.
            file_path: Path to the file being analyzed.
            language: Programming language of the code.

        Returns:
            List of Finding objects representing testing issues.
        """
        self._log_analysis_start(file_path)
        findings: list[Finding] = []

        try:
            # Extract code structure
            code_structure = self._extract_code_structure(code)

            # Check if this is a test file
            is_test_file = self._is_test_file(file_path)

            if is_test_file:
                # Analyze test quality
                test_findings = await self._analyze_test_quality(code, file_path, code_structure)
                findings.extend(test_findings)
            else:
                # Analyze coverage gaps
                coverage_findings = await self._analyze_coverage_gaps(
                    code, file_path, code_structure
                )
                findings.extend(coverage_findings)

                # Suggest edge case tests
                edge_case_findings = await self._suggest_edge_case_tests(
                    code, file_path, code_structure
                )
                findings.extend(edge_case_findings)

            # Run AI analysis for deeper insights
            ai_findings = await self._run_ai_testing_analysis(
                code, file_path, is_test_file, code_structure
            )
            findings.extend(ai_findings)

        except Exception as e:
            self._log_error("Error during testing analysis", e)

        self._log_analysis_complete(file_path, len(findings))
        return findings

    def _is_test_file(self, file_path: str) -> bool:
        """Check if the file is a test file."""
        test_patterns = [
            r"test_.*\.py$",
            r".*_test\.py$",
            r"tests?/.*\.py$",
            r".*_spec\.py$",
        ]
        return any(re.search(pattern, file_path) for pattern in test_patterns)

    def _extract_code_structure(self, code: str) -> dict:
        """
        Extract code structure (functions, classes, methods).

        Args:
            code: The source code.

        Returns:
            Dictionary with code structure information.
        """
        structure = {
            "functions": [],
            "classes": [],
            "methods": [],
            "async_functions": [],
            "has_error_handling": False,
            "complexity_indicators": [],
        }

        try:
            tree = ast.parse(code)

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    func_info = {
                        "name": node.name,
                        "line": node.lineno,
                        "args": [arg.arg for arg in node.args.args],
                        "has_return": any(
                            isinstance(n, ast.Return) and n.value is not None
                            for n in ast.walk(node)
                        ),
                        "complexity": self._estimate_complexity(node),
                    }
                    structure["functions"].append(func_info)

                elif isinstance(node, ast.AsyncFunctionDef):
                    func_info = {
                        "name": node.name,
                        "line": node.lineno,
                        "args": [arg.arg for arg in node.args.args],
                        "has_return": any(
                            isinstance(n, ast.Return) and n.value is not None
                            for n in ast.walk(node)
                        ),
                        "complexity": self._estimate_complexity(node),
                        "is_async": True,
                    }
                    structure["async_functions"].append(func_info)

                elif isinstance(node, ast.ClassDef):
                    class_info = {
                        "name": node.name,
                        "line": node.lineno,
                        "methods": [],
                    }
                    for item in node.body:
                        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                            method_info = {
                                "name": item.name,
                                "line": item.lineno,
                                "is_async": isinstance(item, ast.AsyncFunctionDef),
                            }
                            class_info["methods"].append(method_info)
                            structure["methods"].append(
                                {"class": node.name, **method_info}
                            )
                    structure["classes"].append(class_info)

                elif isinstance(node, (ast.Try, ast.ExceptHandler)):
                    structure["has_error_handling"] = True

                # Complexity indicators
                if isinstance(node, ast.If):
                    structure["complexity_indicators"].append({
                        "type": "conditional",
                        "line": node.lineno,
                    })
                elif isinstance(node, (ast.For, ast.While)):
                    structure["complexity_indicators"].append({
                        "type": "loop",
                        "line": node.lineno,
                    })

        except SyntaxError as e:
            self._log_error(f"Syntax error parsing code: {e}")

        return structure

    def _estimate_complexity(self, node: ast.AST) -> int:
        """Estimate cyclomatic complexity of a function."""
        complexity = 1
        for child in ast.walk(node):
            if isinstance(child, (ast.If, ast.While, ast.For, ast.ExceptHandler)):
                complexity += 1
            elif isinstance(child, ast.BoolOp):
                complexity += len(child.values) - 1
        return complexity

    async def _analyze_coverage_gaps(
        self,
        code: str,
        file_path: str,
        structure: dict,
    ) -> list[Finding]:
        """
        Analyze coverage gaps in the code.

        Args:
            code: The source code.
            file_path: Path to the file.
            structure: Extracted code structure.

        Returns:
            List of findings for coverage gaps.
        """
        findings = []

        # Check for functions that might need tests
        all_functions = structure["functions"] + structure["async_functions"]

        for func in all_functions:
            # Skip private/internal functions (single underscore is okay)
            if func["name"].startswith("__") and func["name"].endswith("__"):
                continue  # Skip dunder methods

            # Flag functions with high complexity
            if func["complexity"] > 5:
                findings.append(self._create_finding(
                    file_path=file_path,
                    line_number=func["line"],
                    severity=Severity.MEDIUM.value,
                    category=FindingCategory.LOW_COVERAGE.value,
                    message=f"Function '{func['name']}' has high complexity ({func['complexity']}) and should have comprehensive tests",
                    suggestion=f"Create tests covering all {func['complexity']} paths through this function",
                    confidence=0.8,
                ))

            # Flag functions with multiple arguments
            if len(func["args"]) > 3:
                findings.append(self._create_finding(
                    file_path=file_path,
                    line_number=func["line"],
                    severity=Severity.LOW.value,
                    category=FindingCategory.MISSING_TEST.value,
                    message=f"Function '{func['name']}' has {len(func['args'])} arguments - ensure all parameter combinations are tested",
                    suggestion="Consider testing boundary values and invalid inputs for each parameter",
                    confidence=0.7,
                ))

        return findings

    async def _suggest_edge_case_tests(
        self,
        code: str,
        file_path: str,
        structure: dict,
    ) -> list[Finding]:
        """
        Suggest edge case tests.

        Args:
            code: The source code.
            file_path: Path to the file.
            structure: Extracted code structure.

        Returns:
            List of findings for edge cases.
        """
        findings = []

        # Check for error handling that needs testing
        if structure["has_error_handling"]:
            findings.append(self._create_finding(
                file_path=file_path,
                line_number=1,
                severity=Severity.LOW.value,
                category=FindingCategory.EDGE_CASE.value,
                message="Code contains error handling - ensure exception paths are tested",
                suggestion="Add tests that trigger each exception handler and verify error behavior",
                confidence=0.75,
            ))

        # Check for loops that might have edge cases
        for indicator in structure["complexity_indicators"]:
            if indicator["type"] == "loop":
                findings.append(self._create_finding(
                    file_path=file_path,
                    line_number=indicator["line"],
                    severity=Severity.INFO.value,
                    category=FindingCategory.EDGE_CASE.value,
                    message="Loop structure detected - consider testing boundary conditions",
                    suggestion="Test with empty collections, single items, and large collections",
                    confidence=0.6,
                ))

        return findings

    async def _analyze_test_quality(
        self,
        code: str,
        file_path: str,
        structure: dict,
    ) -> list[Finding]:
        """
        Analyze quality of test code.

        Args:
            code: The test source code.
            file_path: Path to the test file.
            structure: Extracted code structure.

        Returns:
            List of findings for test quality issues.
        """
        findings = []

        # Check for assertion presence
        if "assert" not in code and "self.assert" not in code and "pytest" not in code:
            findings.append(self._create_finding(
                file_path=file_path,
                line_number=1,
                severity=Severity.HIGH.value,
                category=FindingCategory.TEST_QUALITY.value,
                message="Test file appears to have no assertions",
                suggestion="Add assertions to verify expected behavior",
                confidence=0.85,
            ))

        # Check for test function naming
        test_funcs = [f for f in structure["functions"] if f["name"].startswith("test_")]
        non_test_funcs = [f for f in structure["functions"] if not f["name"].startswith("test_") and not f["name"].startswith("_")]

        if non_test_funcs and not test_funcs:
            findings.append(self._create_finding(
                file_path=file_path,
                line_number=1,
                severity=Severity.MEDIUM.value,
                category=FindingCategory.TEST_QUALITY.value,
                message="Test file has functions that don't follow test naming convention",
                suggestion="Prefix test functions with 'test_' for pytest discovery",
                confidence=0.9,
            ))

        return findings

    async def _run_ai_testing_analysis(
        self,
        code: str,
        file_path: str,
        is_test_file: bool,
        structure: dict,
    ) -> list[Finding]:
        """
        Run AI analysis for testing suggestions.

        Args:
            code: The source code.
            file_path: Path to the file.
            is_test_file: Whether this is a test file.
            structure: Extracted code structure.

        Returns:
            List of AI-generated testing findings.
        """
        try:
            ai_findings = await self._llm_analyzer.analyze_testing(
                code=code,
                file_path=file_path,
                is_test_file=is_test_file,
                functions=structure["functions"] + structure["async_functions"],
            )
            findings = []
            for ai_finding in ai_findings:
                finding = self._create_finding(
                    file_path=file_path,
                    line_number=ai_finding.get("line_number", 1),
                    severity=ai_finding.get("severity", "low"),
                    category=ai_finding.get("category", "missing_test"),
                    message=ai_finding.get("message", ""),
                    suggestion=ai_finding.get("suggestion", ""),
                    confidence=0.65,  # Lower confidence for AI suggestions
                )
                findings.append(finding)
            return findings
        except Exception as e:
            self._log_error("Error in AI testing analysis", e)
            return []

