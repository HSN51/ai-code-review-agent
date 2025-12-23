"""
FastAPI Application Entry Point for AI Code Review Agent.

Provides REST API endpoints for code review functionality.
"""

import logging
from contextlib import asynccontextmanager
from datetime import datetime
from typing import AsyncGenerator
from uuid import UUID

from fastapi import FastAPI, HTTPException, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from src import __version__
from src.config import get_settings, setup_logging
from src.models.schemas import (
    CodeAnalysisRequest,
    ErrorResponse,
    GitHubPRRequest,
    HealthResponse,
    ReviewResult,
)
from src.services.review_service import ReviewService

# Setup logging
logger = setup_logging()

# Global review service instance
review_service: ReviewService


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncGenerator[None, None]:
    """
    Application lifespan manager.

    Initializes and cleans up resources on startup/shutdown.
    """
    global review_service

    logger.info("Starting AI Code Review Agent...")

    # Initialize services
    review_service = ReviewService()

    settings = get_settings()
    logger.info(f"OpenAI configured: {settings.is_openai_configured}")
    logger.info(f"GitHub configured: {settings.is_github_configured}")

    yield

    logger.info("Shutting down AI Code Review Agent...")


# Create FastAPI application
app = FastAPI(
    title="AI Code Review Agent",
    description="""
    AI-powered code review agent with multi-agent architecture.
    
    ## Features
    - **Quality Analysis**: Code quality checks using ruff and pylint
    - **Security Scanning**: Security vulnerability detection using bandit
    - **Testing Analysis**: Test coverage and suggestions
    - **AI Enhancement**: OpenAI GPT integration for intelligent suggestions
    - **GitHub Integration**: Direct PR review support
    
    ## Agents
    - **QualityAgent**: Detects code smells, complexity issues, style violations
    - **SecurityAgent**: Finds vulnerabilities, maps to OWASP categories
    - **TestingAgent**: Analyzes test coverage, suggests test cases
    """,
    version=__version__,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
)

# Configure CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# Exception handlers
@app.exception_handler(HTTPException)
async def http_exception_handler(request, exc: HTTPException):
    """Handle HTTP exceptions."""
    return JSONResponse(
        status_code=exc.status_code,
        content=ErrorResponse(
            error=exc.detail if isinstance(exc.detail, str) else "HTTP Error",
            message=str(exc.detail),
            timestamp=datetime.utcnow(),
        ).model_dump(mode="json"),
    )


@app.exception_handler(Exception)
async def general_exception_handler(request, exc: Exception):
    """Handle general exceptions."""
    logger.error(f"Unhandled exception: {exc}", exc_info=True)
    return JSONResponse(
        status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
        content=ErrorResponse(
            error="Internal Server Error",
            message="An unexpected error occurred",
            detail=str(exc) if get_settings().debug else None,
            timestamp=datetime.utcnow(),
        ).model_dump(mode="json"),
    )


# Health check endpoint
@app.get(
    "/health",
    response_model=HealthResponse,
    tags=["Health"],
    summary="Health Check",
    description="Check the health status of the API and its dependencies.",
)
async def health_check() -> HealthResponse:
    """
    Health check endpoint.

    Returns the current health status of the service including
    configuration status for OpenAI and GitHub integrations.
    """
    settings = get_settings()
    return HealthResponse(
        status="healthy",
        version=__version__,
        timestamp=datetime.utcnow(),
        openai_configured=settings.is_openai_configured,
        github_configured=settings.is_github_configured,
    )


# Code review endpoints
@app.post(
    "/api/v1/review/code",
    response_model=ReviewResult,
    tags=["Code Review"],
    summary="Review Code Snippet",
    description="Analyze a code snippet for quality, security, and testing issues.",
    responses={
        200: {"description": "Review completed successfully"},
        400: {"description": "Invalid request"},
        500: {"description": "Internal server error"},
    },
)
async def review_code(request: CodeAnalysisRequest) -> ReviewResult:
    """
    Review a code snippet.

    Analyzes the provided code using all available agents and returns
    a comprehensive review with findings and suggestions.

    Args:
        request: Code analysis request containing the code to review.

    Returns:
        ReviewResult with findings, summary, and overall score.
    """
    logger.info(f"Received code review request for {request.file_path}")

    try:
        result = await review_service.review_code(request)
        logger.info(
            f"Code review completed: {len(result.findings)} findings, "
            f"score: {result.overall_score}"
        )
        return result
    except Exception as e:
        logger.error(f"Code review failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Code review failed: {str(e)}",
        )


@app.post(
    "/api/v1/review/github",
    response_model=ReviewResult,
    tags=["Code Review"],
    summary="Review GitHub PR",
    description="Analyze a GitHub Pull Request for quality, security, and testing issues.",
    responses={
        200: {"description": "Review completed successfully"},
        400: {"description": "Invalid request"},
        401: {"description": "GitHub authentication failed"},
        404: {"description": "PR not found"},
        500: {"description": "Internal server error"},
    },
)
async def review_github_pr(request: GitHubPRRequest) -> ReviewResult:
    """
    Review a GitHub Pull Request.

    Fetches the PR details and changed files, analyzes each file using
    all available agents, and optionally posts review comments to GitHub.

    Args:
        request: GitHub PR request with repository and PR details.

    Returns:
        ReviewResult with findings, summary, and overall score.
    """
    logger.info(f"Received PR review request for {request.full_repo_name}#{request.pr_number}")

    settings = get_settings()
    if not settings.is_github_configured:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="GitHub token not configured",
        )

    try:
        result = await review_service.review_github_pr(request)
        logger.info(
            f"PR review completed: {len(result.findings)} findings, "
            f"score: {result.overall_score}"
        )
        return result
    except Exception as e:
        logger.error(f"PR review failed: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"PR review failed: {str(e)}",
        )


@app.get(
    "/api/v1/review/{review_id}",
    response_model=ReviewResult,
    tags=["Code Review"],
    summary="Get Review Results",
    description="Retrieve the results of a previous code review by ID.",
    responses={
        200: {"description": "Review found"},
        404: {"description": "Review not found"},
    },
)
async def get_review(review_id: UUID) -> ReviewResult:
    """
    Get review results by ID.

    Retrieves the results of a previously completed code review.

    Args:
        review_id: UUID of the review to retrieve.

    Returns:
        ReviewResult with findings and summary.
    """
    result = await review_service.get_review(review_id)

    if not result:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Review {review_id} not found",
        )

    return result


# Additional utility endpoints
@app.get(
    "/api/v1/agents",
    tags=["Info"],
    summary="List Agents",
    description="Get information about available code review agents.",
)
async def list_agents() -> dict:
    """
    List available agents.

    Returns information about all registered code review agents.
    """
    agents = []
    for agent in review_service._orchestrator.agents:
        agents.append({
            "name": agent.name,
            "description": agent.description,
        })

    return {"agents": agents}


@app.get(
    "/api/v1/config",
    tags=["Info"],
    summary="Get Configuration",
    description="Get current configuration status (non-sensitive info only).",
)
async def get_config() -> dict:
    """
    Get configuration status.

    Returns non-sensitive configuration information.
    """
    settings = get_settings()
    return {
        "openai_configured": settings.is_openai_configured,
        "openai_model": settings.openai_model if settings.is_openai_configured else None,
        "github_configured": settings.is_github_configured,
        "log_level": settings.log_level,
        "cache_ttl": settings.cache_ttl,
    }


# Run with uvicorn when executed directly
if __name__ == "__main__":
    import uvicorn

    settings = get_settings()
    uvicorn.run(
        "src.main:app",
        host=settings.host,
        port=settings.port,
        reload=settings.debug,
        log_level=settings.log_level.lower(),
    )

