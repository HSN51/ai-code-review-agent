"""
Tests for Orchestrator.

Tests agent coordination, parallel execution, and result aggregation.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import UUID

from src.agents.base_agent import BaseAgent
from src.agents.orchestrator import Orchestrator
from src.agents.quality_agent import QualityAgent
from src.agents.security_agent import SecurityAgent
from src.agents.testing_agent import TestingAgent
from src.analyzers.llm_analyzer import LLMAnalyzer
from src.analyzers.static_analyzer import StaticAnalyzer
from src.models.schemas import Finding, FindingCategory, ReviewStatus, Severity


class MockAgent(BaseAgent):
    """Mock agent for testing."""

    def __init__(self, name: str, findings: list[Finding] = None):
        super().__init__(name=name, description=f"Mock {name}")
        self._mock_findings = findings or []

    async def analyze(self, code: str, file_path: str = "test.py", language: str = "python") -> list[Finding]:
        return self._mock_findings


class TestOrchestrator:
    """Tests for Orchestrator class."""

    def test_init_default_agents(self):
        """Test orchestrator initialization with default agents."""
        orchestrator = Orchestrator()
        
        assert len(orchestrator.agents) == 3
        agent_names = [a.name for a in orchestrator.agents]
        assert "QualityAgent" in agent_names
        assert "SecurityAgent" in agent_names
        assert "TestingAgent" in agent_names

    def test_init_custom_agents(self):
        """Test orchestrator initialization with custom agents."""
        mock_agent = MockAgent("TestAgent")
        orchestrator = Orchestrator(agents=[mock_agent])
        
        assert len(orchestrator.agents) == 1
        assert orchestrator.agents[0].name == "TestAgent"

    def test_add_agent(self):
        """Test adding an agent."""
        orchestrator = Orchestrator()
        mock_agent = MockAgent("NewAgent")
        
        orchestrator.add_agent(mock_agent)
        
        assert len(orchestrator.agents) == 4
        assert orchestrator.agents[-1].name == "NewAgent"

    def test_remove_agent(self):
        """Test removing an agent."""
        mock_agent = MockAgent("RemoveMe")
        orchestrator = Orchestrator(agents=[mock_agent])
        
        result = orchestrator.remove_agent("RemoveMe")
        
        assert result is True
        assert len(orchestrator.agents) == 0

    def test_remove_agent_not_found(self):
        """Test removing non-existent agent."""
        orchestrator = Orchestrator(agents=[])
        
        result = orchestrator.remove_agent("NonExistent")
        
        assert result is False

    @pytest.mark.asyncio
    async def test_review_empty_code(self, orchestrator):
        """Test review of empty code."""
        result = await orchestrator.review("", "empty.py")
        
        assert isinstance(result.id, UUID)
        assert result.status == ReviewStatus.COMPLETED
        assert isinstance(result.findings, list)

    @pytest.mark.asyncio
    async def test_review_simple_code(self, orchestrator, sample_python_code):
        """Test review of simple code."""
        result = await orchestrator.review(sample_python_code, "simple.py")
        
        assert result.status == ReviewStatus.COMPLETED
        assert result.files_analyzed == 1
        assert result.total_lines > 0
        assert 0 <= result.overall_score <= 100

    @pytest.mark.asyncio
    async def test_review_parallel_execution(self):
        """Test that agents run in parallel."""
        import asyncio
        
        call_times = []
        
        async def slow_analyze(code, file_path, language):
            call_times.append(asyncio.get_event_loop().time())
            await asyncio.sleep(0.1)
            return []
        
        mock_agent1 = MockAgent("Agent1")
        mock_agent1.analyze = slow_analyze
        mock_agent2 = MockAgent("Agent2")
        mock_agent2.analyze = slow_analyze
        
        orchestrator = Orchestrator(agents=[mock_agent1, mock_agent2])
        
        start = asyncio.get_event_loop().time()
        await orchestrator.review("code", "test.py")
        duration = asyncio.get_event_loop().time() - start
        
        # If parallel, duration should be ~0.1s, not ~0.2s
        assert duration < 0.2

    @pytest.mark.asyncio
    async def test_review_agent_failure(self):
        """Test handling of agent failure."""
        async def failing_analyze(code, file_path, language):
            raise Exception("Agent error")
        
        mock_agent = MockAgent("FailingAgent")
        mock_agent.analyze = failing_analyze
        
        orchestrator = Orchestrator(agents=[mock_agent])
        result = await orchestrator.review("code", "test.py")
        
        # Should complete despite agent failure
        assert result.status == ReviewStatus.COMPLETED

    @pytest.mark.asyncio
    async def test_deduplicate_findings(self):
        """Test finding deduplication."""
        finding1 = Finding(
            file_path="test.py",
            line_number=10,
            severity=Severity.HIGH,
            category=FindingCategory.CODE_SMELL,
            message="Duplicate issue",
            agent_name="Agent1",
            confidence=0.8,
        )
        finding2 = Finding(
            file_path="test.py",
            line_number=10,
            severity=Severity.HIGH,
            category=FindingCategory.CODE_SMELL,
            message="Duplicate issue",
            agent_name="Agent2",
            confidence=0.9,
        )
        
        orchestrator = Orchestrator(agents=[])
        deduplicated = orchestrator._deduplicate_findings([finding1, finding2])
        
        assert len(deduplicated) == 1
        # Should keep higher confidence one
        assert deduplicated[0].confidence == 0.9

    @pytest.mark.asyncio
    async def test_sort_by_severity(self):
        """Test finding sorting by severity."""
        findings = [
            Finding(file_path="test.py", line_number=1, severity=Severity.LOW, category=FindingCategory.STYLE, message="Low", agent_name="Test"),
            Finding(file_path="test.py", line_number=2, severity=Severity.CRITICAL, category=FindingCategory.INJECTION, message="Critical", agent_name="Test"),
            Finding(file_path="test.py", line_number=3, severity=Severity.HIGH, category=FindingCategory.CODE_SMELL, message="High", agent_name="Test"),
        ]
        
        orchestrator = Orchestrator(agents=[])
        sorted_findings = orchestrator._sort_by_severity(findings)
        
        assert sorted_findings[0].severity == Severity.CRITICAL
        assert sorted_findings[1].severity == Severity.HIGH
        assert sorted_findings[2].severity == Severity.LOW

    @pytest.mark.asyncio
    async def test_calculate_score_no_findings(self):
        """Test score calculation with no findings."""
        orchestrator = Orchestrator(agents=[])
        score = orchestrator._calculate_score([], 100)
        
        assert score == 100.0

    @pytest.mark.asyncio
    async def test_calculate_score_with_findings(self):
        """Test score calculation with findings."""
        findings = [
            Finding(file_path="test.py", line_number=1, severity=Severity.CRITICAL, category=FindingCategory.INJECTION, message="Critical", agent_name="Test"),
            Finding(file_path="test.py", line_number=2, severity=Severity.HIGH, category=FindingCategory.CODE_SMELL, message="High", agent_name="Test"),
        ]
        
        orchestrator = Orchestrator(agents=[])
        score = orchestrator._calculate_score(findings, 100)
        
        assert score < 100.0
        assert score >= 0.0

    @pytest.mark.asyncio
    async def test_generate_agent_summaries(self):
        """Test agent summary generation."""
        findings = [
            Finding(file_path="test.py", line_number=1, severity=Severity.HIGH, category=FindingCategory.CODE_SMELL, message="Issue 1", agent_name="QualityAgent"),
            Finding(file_path="test.py", line_number=2, severity=Severity.CRITICAL, category=FindingCategory.INJECTION, message="Issue 2", agent_name="SecurityAgent"),
        ]
        
        orchestrator = Orchestrator()
        summaries = orchestrator._generate_agent_summaries(findings)
        
        assert "QualityAgent" in summaries
        assert "SecurityAgent" in summaries
        assert "high" in summaries["QualityAgent"].lower()
        assert "critical" in summaries["SecurityAgent"].lower()

    @pytest.mark.asyncio
    async def test_review_multiple_files(self, orchestrator):
        """Test reviewing multiple files."""
        files = {
            "file1.py": "def func1(): pass",
            "file2.py": "def func2(): pass",
        }
        
        results = await orchestrator.review_multiple(files)
        
        assert len(results) == 2
        assert all(r.status == ReviewStatus.COMPLETED for r in results)

    @pytest.mark.asyncio
    async def test_generate_summary_no_findings(self):
        """Test summary generation with no findings."""
        mock_llm = AsyncMock(spec=LLMAnalyzer)
        mock_llm.generate_review_summary = AsyncMock(return_value=None)
        
        orchestrator = Orchestrator(llm_analyzer=mock_llm, agents=[])
        summary = await orchestrator._generate_summary("code", "test.py", [], 100.0)
        
        assert "No issues found" in summary
        assert "100" in summary

    @pytest.mark.asyncio
    async def test_generate_summary_with_findings(self):
        """Test summary generation with findings."""
        findings = [
            Finding(file_path="test.py", line_number=1, severity=Severity.HIGH, category=FindingCategory.CODE_SMELL, message="Issue", agent_name="Test"),
        ]
        
        mock_llm = AsyncMock(spec=LLMAnalyzer)
        mock_llm.generate_review_summary = AsyncMock(return_value="AI summary")
        
        orchestrator = Orchestrator(llm_analyzer=mock_llm, agents=[])
        summary = await orchestrator._generate_summary("code", "test.py", findings, 85.0)
        
        assert "1" in summary  # Number of findings
        assert "high" in summary.lower()

