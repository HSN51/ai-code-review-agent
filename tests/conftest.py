"""
Pytest fixtures for AI Code Review Agent tests.

Provides reusable test fixtures, mocks, and sample data.
"""

import asyncio
from typing import AsyncGenerator, Generator
from unittest.mock import AsyncMock, MagicMock, patch

import pytest
from fastapi.testclient import TestClient

from src.agents.orchestrator import Orchestrator
from src.agents.quality_agent import QualityAgent
from src.agents.security_agent import SecurityAgent
from src.agents.testing_agent import TestingAgent
from src.analyzers.llm_analyzer import LLMAnalyzer
from src.analyzers.static_analyzer import StaticAnalyzer
from src.config import Settings, get_settings
from src.main import app
from src.models.schemas import Finding, FindingCategory, ReviewResult, Severity
from src.services.github_service import GitHubService
from src.services.review_service import ReviewService


# Sample code snippets for testing
SAMPLE_PYTHON_CODE = '''
def calculate_sum(a, b):
    """Calculate the sum of two numbers."""
    return a + b

def process_data(data):
    result = []
    for item in data:
        if item > 0:
            result.append(item * 2)
    return result

class Calculator:
    def __init__(self):
        self.history = []
    
    def add(self, a, b):
        result = a + b
        self.history.append(result)
        return result
'''

SAMPLE_INSECURE_CODE = '''
import pickle
import subprocess

def execute_command(user_input):
    # SQL injection vulnerability
    query = f"SELECT * FROM users WHERE id = {user_input}"
    
    # Command injection vulnerability
    subprocess.call(user_input, shell=True)
    
    # Hardcoded password
    password = "secret123"
    
    return query

def load_data(data):
    # Insecure deserialization
    return pickle.loads(data)
'''

SAMPLE_COMPLEX_CODE = '''
def complex_function(a, b, c, d, e, f):
    """A function with high complexity."""
    result = 0
    if a > 0:
        if b > 0:
            if c > 0:
                result += a + b + c
            else:
                result += a + b
        else:
            if d > 0:
                result += a + d
            else:
                result += a
    else:
        if e > 0:
            if f > 0:
                result += e + f
            else:
                result += e
        else:
            result = -1
    
    for i in range(10):
        for j in range(10):
            if i == j:
                result += 1
    
    return result
'''

SAMPLE_TEST_CODE = '''
import pytest

def test_addition():
    assert 1 + 1 == 2

def test_subtraction():
    assert 2 - 1 == 1

class TestCalculator:
    def test_add(self):
        assert True
    
    def test_subtract(self):
        pass  # No assertion
'''


@pytest.fixture
def sample_python_code() -> str:
    """Provide sample Python code."""
    return SAMPLE_PYTHON_CODE


@pytest.fixture
def sample_insecure_code() -> str:
    """Provide sample insecure code."""
    return SAMPLE_INSECURE_CODE


@pytest.fixture
def sample_complex_code() -> str:
    """Provide sample complex code."""
    return SAMPLE_COMPLEX_CODE


@pytest.fixture
def sample_test_code() -> str:
    """Provide sample test code."""
    return SAMPLE_TEST_CODE


@pytest.fixture
def mock_settings() -> Settings:
    """Provide mock settings."""
    return Settings(
        openai_api_key="test-api-key",
        github_token="test-github-token",
        log_level="DEBUG",
        debug=True,
    )


@pytest.fixture
def mock_static_analyzer() -> StaticAnalyzer:
    """Provide a mock static analyzer."""
    analyzer = StaticAnalyzer()
    return analyzer


@pytest.fixture
def mock_llm_analyzer() -> LLMAnalyzer:
    """Provide a mock LLM analyzer."""
    with patch.object(LLMAnalyzer, '_call_openai', new_callable=AsyncMock) as mock:
        mock.return_value = None
        analyzer = LLMAnalyzer(api_key="test-key")
        analyzer._call_openai = mock
        yield analyzer


@pytest.fixture
def mock_llm_analyzer_with_responses() -> LLMAnalyzer:
    """Provide a mock LLM analyzer that returns responses."""
    analyzer = LLMAnalyzer(api_key="test-key")
    
    async def mock_call(*args, **kwargs):
        return "This is a test suggestion for improving the code."
    
    analyzer._call_openai = AsyncMock(side_effect=mock_call)
    return analyzer


@pytest.fixture
def quality_agent(mock_static_analyzer, mock_llm_analyzer) -> QualityAgent:
    """Provide a quality agent with mocked dependencies."""
    return QualityAgent(
        static_analyzer=mock_static_analyzer,
        llm_analyzer=mock_llm_analyzer,
    )


@pytest.fixture
def security_agent(mock_static_analyzer, mock_llm_analyzer) -> SecurityAgent:
    """Provide a security agent with mocked dependencies."""
    return SecurityAgent(
        static_analyzer=mock_static_analyzer,
        llm_analyzer=mock_llm_analyzer,
    )


@pytest.fixture
def testing_agent(mock_llm_analyzer) -> TestingAgent:
    """Provide a testing agent with mocked dependencies."""
    return TestingAgent(llm_analyzer=mock_llm_analyzer)


@pytest.fixture
def orchestrator(mock_static_analyzer, mock_llm_analyzer) -> Orchestrator:
    """Provide an orchestrator with mocked dependencies."""
    return Orchestrator(
        static_analyzer=mock_static_analyzer,
        llm_analyzer=mock_llm_analyzer,
    )


@pytest.fixture
def mock_github_service() -> GitHubService:
    """Provide a mock GitHub service."""
    service = GitHubService(token="test-token")
    return service


@pytest.fixture
def review_service(orchestrator, mock_github_service) -> ReviewService:
    """Provide a review service with mocked dependencies."""
    return ReviewService(
        orchestrator=orchestrator,
        github_service=mock_github_service,
    )


@pytest.fixture
def sample_finding() -> Finding:
    """Provide a sample finding."""
    return Finding(
        file_path="test.py",
        line_number=10,
        severity=Severity.HIGH,
        category=FindingCategory.CODE_SMELL,
        message="Test finding message",
        suggestion="Test suggestion",
        agent_name="TestAgent",
        rule_id="TEST001",
        confidence=0.9,
    )


@pytest.fixture
def sample_review_result(sample_finding) -> ReviewResult:
    """Provide a sample review result."""
    return ReviewResult(
        findings=[sample_finding],
        summary="Test review summary",
        overall_score=85.0,
        files_analyzed=1,
        total_lines=100,
    )


@pytest.fixture
def test_client() -> Generator[TestClient, None, None]:
    """Provide a test client for API testing."""
    with TestClient(app) as client:
        yield client


@pytest.fixture
def mock_openai_response():
    """Mock OpenAI API response."""
    return {
        "choices": [
            {
                "message": {
                    "content": "Test response from OpenAI"
                }
            }
        ]
    }


@pytest.fixture
def mock_ruff_output():
    """Mock ruff tool output."""
    return [
        {
            "code": "E501",
            "message": "Line too long",
            "location": {"row": 10, "column": 80},
            "end_location": {"row": 10, "column": 120},
        }
    ]


@pytest.fixture
def mock_pylint_output():
    """Mock pylint tool output."""
    return [
        {
            "message-id": "C0301",
            "message": "Line too long",
            "line": 10,
            "column": 0,
            "type": "convention",
            "symbol": "line-too-long",
        }
    ]


@pytest.fixture
def mock_bandit_output():
    """Mock bandit tool output."""
    return {
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
    }


# Async fixture for event loop
@pytest.fixture(scope="session")
def event_loop():
    """Create event loop for async tests."""
    loop = asyncio.get_event_loop_policy().new_event_loop()
    yield loop
    loop.close()

