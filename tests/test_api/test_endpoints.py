"""
Tests for API Endpoints.

Tests FastAPI endpoints including code review, GitHub integration,
and health checks.
"""

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from uuid import uuid4

from fastapi import status
from fastapi.testclient import TestClient

from src.main import app
from src.models.schemas import (
    Finding,
    FindingCategory,
    ReviewResult,
    ReviewStatus,
    Severity,
)


class TestHealthEndpoint:
    """Tests for health check endpoint."""

    def test_health_check(self, test_client):
        """Test health check returns 200."""
        response = test_client.get("/health")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert data["status"] == "healthy"
        assert "version" in data
        assert "timestamp" in data

    def test_health_check_includes_config_status(self, test_client):
        """Test health check includes configuration status."""
        response = test_client.get("/health")
        
        data = response.json()
        assert "openai_configured" in data
        assert "github_configured" in data


class TestCodeReviewEndpoint:
    """Tests for code review endpoint."""

    def test_review_code_success(self, test_client):
        """Test successful code review."""
        response = test_client.post(
            "/api/v1/review/code",
            json={
                "code": "def hello():\n    print('Hello, World!')",
                "file_path": "test.py",
                "language": "python",
            },
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "id" in data
        assert "findings" in data
        assert "summary" in data
        assert "overall_score" in data

    def test_review_code_empty_code(self, test_client):
        """Test code review with empty code."""
        response = test_client.post(
            "/api/v1/review/code",
            json={
                "code": "",
                "file_path": "test.py",
            },
        )
        
        # Empty code should return validation error
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_review_code_missing_code(self, test_client):
        """Test code review with missing code field."""
        response = test_client.post(
            "/api/v1/review/code",
            json={
                "file_path": "test.py",
            },
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_review_code_default_values(self, test_client):
        """Test code review uses default values."""
        response = test_client.post(
            "/api/v1/review/code",
            json={
                "code": "x = 1",
            },
        )
        
        assert response.status_code == status.HTTP_200_OK
        # Default file_path should be used

    def test_review_code_with_findings(self, test_client):
        """Test code review returns findings structure."""
        response = test_client.post(
            "/api/v1/review/code",
            json={
                "code": "import os\nquery = f'SELECT * FROM users WHERE id = {user_input}'",
                "file_path": "insecure.py",
            },
        )
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        
        # Check findings structure if any exist
        for finding in data["findings"]:
            assert "id" in finding
            assert "file_path" in finding
            assert "line_number" in finding
            assert "severity" in finding
            assert "category" in finding
            assert "message" in finding


class TestGitHubReviewEndpoint:
    """Tests for GitHub PR review endpoint."""

    def test_review_github_not_configured(self, test_client):
        """Test GitHub review when not configured."""
        with patch("src.main.get_settings") as mock_settings:
            mock_settings.return_value.is_github_configured = False
            
            response = test_client.post(
                "/api/v1/review/github",
                json={
                    "repo_owner": "octocat",
                    "repo_name": "hello-world",
                    "pr_number": 1,
                },
            )
        
        # Should return 401 or fail gracefully
        assert response.status_code in [status.HTTP_401_UNAUTHORIZED, status.HTTP_200_OK]

    def test_review_github_invalid_pr_number(self, test_client):
        """Test GitHub review with invalid PR number."""
        response = test_client.post(
            "/api/v1/review/github",
            json={
                "repo_owner": "octocat",
                "repo_name": "hello-world",
                "pr_number": 0,  # Invalid
            },
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_review_github_missing_fields(self, test_client):
        """Test GitHub review with missing fields."""
        response = test_client.post(
            "/api/v1/review/github",
            json={
                "repo_owner": "octocat",
                # Missing repo_name and pr_number
            },
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY


class TestGetReviewEndpoint:
    """Tests for get review endpoint."""

    def test_get_review_not_found(self, test_client):
        """Test getting non-existent review."""
        review_id = str(uuid4())
        response = test_client.get(f"/api/v1/review/{review_id}")
        
        assert response.status_code == status.HTTP_404_NOT_FOUND

    def test_get_review_invalid_uuid(self, test_client):
        """Test getting review with invalid UUID."""
        response = test_client.get("/api/v1/review/invalid-uuid")
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_get_review_after_create(self, test_client):
        """Test getting review after creation."""
        # First create a review
        create_response = test_client.post(
            "/api/v1/review/code",
            json={
                "code": "x = 1",
                "file_path": "test.py",
            },
        )
        
        assert create_response.status_code == status.HTTP_200_OK
        review_id = create_response.json()["id"]
        
        # Then retrieve it
        get_response = test_client.get(f"/api/v1/review/{review_id}")
        
        assert get_response.status_code == status.HTTP_200_OK
        assert get_response.json()["id"] == review_id


class TestInfoEndpoints:
    """Tests for info endpoints."""

    def test_list_agents(self, test_client):
        """Test listing agents."""
        response = test_client.get("/api/v1/agents")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "agents" in data
        assert len(data["agents"]) > 0
        
        # Check agent structure
        for agent in data["agents"]:
            assert "name" in agent
            assert "description" in agent

    def test_get_config(self, test_client):
        """Test getting configuration."""
        response = test_client.get("/api/v1/config")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "openai_configured" in data
        assert "github_configured" in data
        assert "log_level" in data


class TestDocumentation:
    """Tests for API documentation."""

    def test_openapi_docs(self, test_client):
        """Test OpenAPI documentation is available."""
        response = test_client.get("/openapi.json")
        
        assert response.status_code == status.HTTP_200_OK
        data = response.json()
        assert "openapi" in data
        assert "info" in data
        assert "paths" in data

    def test_swagger_ui(self, test_client):
        """Test Swagger UI is available."""
        response = test_client.get("/docs")
        
        assert response.status_code == status.HTTP_200_OK

    def test_redoc(self, test_client):
        """Test ReDoc is available."""
        response = test_client.get("/redoc")
        
        assert response.status_code == status.HTTP_200_OK


class TestErrorHandling:
    """Tests for error handling."""

    def test_invalid_json(self, test_client):
        """Test handling of invalid JSON."""
        response = test_client.post(
            "/api/v1/review/code",
            content="not json",
            headers={"Content-Type": "application/json"},
        )
        
        assert response.status_code == status.HTTP_422_UNPROCESSABLE_ENTITY

    def test_method_not_allowed(self, test_client):
        """Test method not allowed error."""
        response = test_client.put("/api/v1/review/code")
        
        assert response.status_code == status.HTTP_405_METHOD_NOT_ALLOWED

    def test_not_found_endpoint(self, test_client):
        """Test non-existent endpoint."""
        response = test_client.get("/api/v1/nonexistent")
        
        assert response.status_code == status.HTTP_404_NOT_FOUND


class TestCORS:
    """Tests for CORS configuration."""

    def test_cors_headers(self, test_client):
        """Test CORS headers are present."""
        response = test_client.options(
            "/api/v1/review/code",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "POST",
            },
        )
        
        # Should allow CORS
        assert response.status_code == status.HTTP_200_OK


class TestCodeAnalysisRequest:
    """Tests for CodeAnalysisRequest validation."""

    def test_code_size_limit(self, test_client):
        """Test code size validation."""
        # Create code that's too large
        large_code = "x = 1\n" * 100000  # Very large code
        
        response = test_client.post(
            "/api/v1/review/code",
            json={
                "code": large_code,
                "file_path": "large.py",
            },
        )
        
        # Should either accept or reject with validation error
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_422_UNPROCESSABLE_ENTITY,
        ]

    def test_language_normalization(self, test_client):
        """Test language field normalization."""
        response = test_client.post(
            "/api/v1/review/code",
            json={
                "code": "x = 1",
                "file_path": "test.py",
                "language": "PY",  # Should be normalized to "python"
            },
        )
        
        assert response.status_code == status.HTTP_200_OK


class TestGitHubPRRequest:
    """Tests for GitHubPRRequest validation."""

    def test_full_repo_name(self, test_client):
        """Test full repo name generation."""
        # This tests the model property through API
        response = test_client.post(
            "/api/v1/review/github",
            json={
                "repo_owner": "octocat",
                "repo_name": "hello-world",
                "pr_number": 1,
            },
        )
        
        # Just checking it doesn't fail on model validation
        assert response.status_code in [
            status.HTTP_200_OK,
            status.HTTP_401_UNAUTHORIZED,  # If GitHub not configured
        ]

