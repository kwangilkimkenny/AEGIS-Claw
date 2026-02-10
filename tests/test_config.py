"""Tests for AegisClawConfig."""

import os
import pytest

from aegis_claw.core.config import AegisClawConfig


class TestConfigDefaults:
    """Test that default values are sensible."""

    def test_default_log_level(self):
        cfg = AegisClawConfig()
        assert cfg.log_level == "WARNING"

    def test_default_max_input_length(self):
        cfg = AegisClawConfig()
        assert cfg.max_input_length == 50000

    def test_default_safety_threshold(self):
        cfg = AegisClawConfig()
        assert cfg.safety_threshold == 0.5

    def test_default_rate_limit_disabled(self):
        cfg = AegisClawConfig()
        assert cfg.rate_limit_enabled is False


class TestConfigOverride:
    """Test that config values can be overridden."""

    def test_custom_values(self):
        cfg = AegisClawConfig(
            max_input_length=1000,
            safety_threshold=0.3,
            log_level="DEBUG",
        )
        assert cfg.max_input_length == 1000
        assert cfg.safety_threshold == 0.3
        assert cfg.log_level == "DEBUG"

    def test_config_is_frozen(self):
        cfg = AegisClawConfig()
        with pytest.raises(Exception):
            cfg.max_input_length = 999  # type: ignore

    def test_rate_limit_config(self):
        cfg = AegisClawConfig(
            rate_limit_enabled=True,
            rate_limit_max_requests=10,
            rate_limit_window_seconds=30,
            rate_limit_block_seconds=60,
        )
        assert cfg.rate_limit_enabled is True
        assert cfg.rate_limit_max_requests == 10
        assert cfg.rate_limit_window_seconds == 30
        assert cfg.rate_limit_block_seconds == 60


class TestConfigEnvVars:
    """Test environment variable overrides."""

    def test_env_log_level(self, monkeypatch):
        monkeypatch.setenv("AEGIS_CLAW_LOG_LEVEL", "DEBUG")
        cfg = AegisClawConfig()
        assert cfg.log_level == "DEBUG"

    def test_env_max_input_length(self, monkeypatch):
        monkeypatch.setenv("AEGIS_CLAW_MAX_INPUT_LENGTH", "5000")
        cfg = AegisClawConfig()
        assert cfg.max_input_length == 5000
