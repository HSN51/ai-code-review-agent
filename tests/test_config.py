"""
Tests for configuration module.

Tests settings loading and validation.
"""

import pytest
from unittest.mock import patch

from src.config import Settings, get_settings, setup_logging


class TestSettings:
    """Tests for Settings class."""

    def test_default_settings(self):
        """Test default settings values."""
        settings = Settings()
        
        assert settings.log_level == "INFO"
        assert settings.debug is False
        assert settings.host == "0.0.0.0"
        assert settings.port == 8000
        assert settings.openai_model == "gpt-4"
        assert settings.openai_temperature == 0.3

    def test_settings_with_values(self):
        """Test settings with custom values."""
        settings = Settings(
            openai_api_key="test-key",
            github_token="test-token",
            log_level="DEBUG",
            debug=True,
            port=9000,
        )
        
        assert settings.openai_api_key == "test-key"
        assert settings.github_token == "test-token"
        assert settings.log_level == "DEBUG"
        assert settings.debug is True
        assert settings.port == 9000

    def test_log_level_validation(self):
        """Test log level normalization."""
        settings = Settings(log_level="debug")
        assert settings.log_level == "DEBUG"
        
        settings = Settings(log_level="Info")
        assert settings.log_level == "INFO"

    def test_is_openai_configured_true(self):
        """Test OpenAI configuration check - configured."""
        settings = Settings(openai_api_key="real-api-key")
        assert settings.is_openai_configured is True

    def test_is_openai_configured_false_empty(self):
        """Test OpenAI configuration check - empty key."""
        settings = Settings(openai_api_key="")
        assert settings.is_openai_configured is False

    def test_is_openai_configured_false_placeholder(self):
        """Test OpenAI configuration check - placeholder."""
        settings = Settings(openai_api_key="your_openai_api_key_here")
        assert settings.is_openai_configured is False

    def test_is_github_configured_true(self):
        """Test GitHub configuration check - configured."""
        settings = Settings(github_token="ghp_realtoken")
        assert settings.is_github_configured is True

    def test_is_github_configured_false_empty(self):
        """Test GitHub configuration check - empty token."""
        settings = Settings(github_token="")
        assert settings.is_github_configured is False

    def test_is_github_configured_false_placeholder(self):
        """Test GitHub configuration check - placeholder."""
        settings = Settings(github_token="your_github_token_here")
        assert settings.is_github_configured is False

    def test_port_validation(self):
        """Test port number validation."""
        # Valid ports
        settings = Settings(port=8000)
        assert settings.port == 8000
        
        settings = Settings(port=1)
        assert settings.port == 1
        
        settings = Settings(port=65535)
        assert settings.port == 65535

    def test_temperature_validation(self):
        """Test temperature validation."""
        settings = Settings(openai_temperature=0.0)
        assert settings.openai_temperature == 0.0
        
        settings = Settings(openai_temperature=2.0)
        assert settings.openai_temperature == 2.0

    def test_cache_ttl_validation(self):
        """Test cache TTL validation."""
        settings = Settings(cache_ttl=0)
        assert settings.cache_ttl == 0
        
        settings = Settings(cache_ttl=7200)
        assert settings.cache_ttl == 7200


class TestGetSettings:
    """Tests for get_settings function."""

    def test_get_settings_returns_settings(self):
        """Test that get_settings returns Settings instance."""
        settings = get_settings()
        assert isinstance(settings, Settings)

    def test_get_settings_cached(self):
        """Test that get_settings returns cached instance."""
        settings1 = get_settings()
        settings2 = get_settings()
        
        # Should return same instance (cached)
        assert settings1 is settings2


class TestSetupLogging:
    """Tests for setup_logging function."""

    def test_setup_logging_returns_logger(self):
        """Test that setup_logging returns logger."""
        logger = setup_logging()
        
        assert logger is not None
        assert logger.name == "ai_code_review"

    def test_setup_logging_with_settings(self):
        """Test setup_logging with custom settings."""
        settings = Settings(log_level="DEBUG")
        logger = setup_logging(settings)
        
        import logging
        assert logger.level == logging.DEBUG

    def test_setup_logging_default_settings(self):
        """Test setup_logging with default settings."""
        logger = setup_logging()
        
        # Should use settings from get_settings()
        assert logger is not None

