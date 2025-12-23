"""
Configuration module for AI Code Review Agent.

Uses pydantic-settings for configuration management with environment variables.
"""

import logging
from functools import lru_cache
from typing import Literal

from pydantic import Field, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
        extra="ignore",
    )

    # OpenAI Configuration
    openai_api_key: str = Field(
        default="",
        description="OpenAI API key for GPT integration",
    )
    openai_model: str = Field(
        default="gpt-4",
        description="OpenAI model to use for analysis",
    )
    openai_temperature: float = Field(
        default=0.3,
        ge=0.0,
        le=2.0,
        description="Temperature for OpenAI responses (lower = more consistent)",
    )
    openai_max_tokens: int = Field(
        default=2000,
        ge=100,
        le=8000,
        description="Maximum tokens for OpenAI responses",
    )

    # GitHub Configuration
    github_token: str = Field(
        default="",
        description="GitHub personal access token",
    )
    github_api_url: str = Field(
        default="https://api.github.com",
        description="GitHub API base URL",
    )

    # Application Settings
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR", "CRITICAL"] = Field(
        default="INFO",
        description="Logging level",
    )
    debug: bool = Field(
        default=False,
        description="Enable debug mode",
    )

    # Server Configuration
    host: str = Field(
        default="0.0.0.0",
        description="Server host",
    )
    port: int = Field(
        default=8000,
        ge=1,
        le=65535,
        description="Server port",
    )

    # Cache Settings
    cache_ttl: int = Field(
        default=3600,
        ge=0,
        description="Cache TTL in seconds",
    )
    cache_max_size: int = Field(
        default=1000,
        ge=1,
        description="Maximum cache entries",
    )

    # Rate Limiting
    rate_limit_requests: int = Field(
        default=100,
        ge=1,
        description="Maximum requests per period",
    )
    rate_limit_period: int = Field(
        default=60,
        ge=1,
        description="Rate limit period in seconds",
    )

    # Analysis Settings
    max_file_size: int = Field(
        default=1_000_000,
        ge=1000,
        description="Maximum file size in bytes for analysis",
    )
    analysis_timeout: int = Field(
        default=300,
        ge=10,
        description="Analysis timeout in seconds",
    )

    @field_validator("log_level", mode="before")
    @classmethod
    def validate_log_level(cls, v: str) -> str:
        """Validate and normalize log level."""
        if isinstance(v, str):
            return v.upper()
        return v

    @property
    def is_openai_configured(self) -> bool:
        """Check if OpenAI is properly configured."""
        return bool(self.openai_api_key and self.openai_api_key != "your_openai_api_key_here")

    @property
    def is_github_configured(self) -> bool:
        """Check if GitHub is properly configured."""
        return bool(self.github_token and self.github_token != "your_github_token_here")


@lru_cache()
def get_settings() -> Settings:
    """
    Get cached application settings.

    Returns:
        Settings: Application settings instance.
    """
    return Settings()


def setup_logging(settings: Settings | None = None) -> logging.Logger:
    """
    Configure application logging.

    Args:
        settings: Optional settings instance. If not provided, uses cached settings.

    Returns:
        logging.Logger: Configured logger instance.
    """
    if settings is None:
        settings = get_settings()

    # Configure root logger
    logging.basicConfig(
        level=getattr(logging, settings.log_level),
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # Get logger for the application
    logger = logging.getLogger("ai_code_review")
    logger.setLevel(getattr(logging, settings.log_level))

    return logger


# Create default logger
logger = setup_logging()

