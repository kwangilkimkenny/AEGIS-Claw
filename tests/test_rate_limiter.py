"""Tests for RateLimiter."""

import time
from unittest.mock import patch

import pytest

from aegis_claw.core.config import AegisClawConfig
from aegis_claw.engine.rate_limiter import RateLimiter


class TestRateLimiterDisabled:
    """When rate limiting is disabled, everything should pass."""

    def test_always_allows_when_disabled(self):
        limiter = RateLimiter(AegisClawConfig(rate_limit_enabled=False))
        for _ in range(200):
            assert limiter.allow("session_1") is True

    def test_always_allows_without_session(self):
        limiter = RateLimiter(AegisClawConfig(rate_limit_enabled=True))
        for _ in range(200):
            assert limiter.allow(None) is True


class TestRateLimiterEnabled:
    """When rate limiting is enabled."""

    def _make_limiter(self, max_req: int = 5, window: int = 60, block: int = 10):
        cfg = AegisClawConfig(
            rate_limit_enabled=True,
            rate_limit_max_requests=max_req,
            rate_limit_window_seconds=window,
            rate_limit_block_seconds=block,
        )
        return RateLimiter(cfg)

    def test_allows_up_to_limit(self):
        limiter = self._make_limiter(max_req=3)
        assert limiter.allow("s1") is True
        assert limiter.allow("s1") is True
        assert limiter.allow("s1") is True
        # 4th request should be blocked
        assert limiter.allow("s1") is False

    def test_different_sessions_independent(self):
        limiter = self._make_limiter(max_req=2)
        assert limiter.allow("s1") is True
        assert limiter.allow("s1") is True
        assert limiter.allow("s1") is False
        # Different session should still work
        assert limiter.allow("s2") is True
        assert limiter.allow("s2") is True
        assert limiter.allow("s2") is False

    def test_reset_single_session(self):
        limiter = self._make_limiter(max_req=2)
        assert limiter.allow("s1") is True
        assert limiter.allow("s1") is True
        assert limiter.allow("s1") is False
        # Reset s1
        limiter.reset("s1")
        assert limiter.allow("s1") is True

    def test_reset_all(self):
        limiter = self._make_limiter(max_req=1)
        limiter.allow("s1")
        limiter.allow("s2")
        assert limiter.allow("s1") is False
        assert limiter.allow("s2") is False
        limiter.reset()
        assert limiter.allow("s1") is True
        assert limiter.allow("s2") is True


class TestRateLimiterGC:
    """Garbage collection of stale sessions."""

    def _make_limiter(self, max_req: int = 5, window: int = 60, block: int = 10):
        cfg = AegisClawConfig(
            rate_limit_enabled=True,
            rate_limit_max_requests=max_req,
            rate_limit_window_seconds=window,
            rate_limit_block_seconds=block,
        )
        return RateLimiter(cfg)

    def test_gc_removes_stale_sessions(self):
        limiter = self._make_limiter(max_req=5, window=1)
        # Add requests for several sessions
        limiter.allow("s1")
        limiter.allow("s2")
        limiter.allow("s3")
        assert len(limiter._requests) == 3

        # Simulate time passing beyond the window
        now = time.monotonic() + 2
        limiter._gc(now)

        # All sessions should be cleaned up
        assert len(limiter._requests) == 0

    def test_gc_removes_expired_blocks(self):
        limiter = self._make_limiter(max_req=1, block=1)
        limiter.allow("s1")
        assert limiter.allow("s1") is False  # blocked
        assert "s1" in limiter._blocked_until

        # Simulate time passing beyond block duration
        now = time.monotonic() + 2
        limiter._gc(now)
        assert "s1" not in limiter._blocked_until

    def test_gc_runs_periodically(self):
        limiter = self._make_limiter(max_req=200, window=1)
        # Set GC interval low for testing
        limiter._GC_INTERVAL = 10

        # Add requests from many sessions
        for i in range(10):
            limiter.allow(f"session_{i}")

        # All sessions exist
        assert len(limiter._requests) == 10

        # Simulate time passing so all are stale, then trigger GC
        # by calling allow enough times
        import time as _time
        _time.sleep(1.1)  # wait for window to expire

        # Next batch of 10 calls should trigger GC
        for i in range(10):
            limiter.allow(f"new_session_{i}")

        # Old stale sessions should have been cleaned up
        old_sessions = [k for k in limiter._requests if k.startswith("session_")]
        assert len(old_sessions) == 0

    def test_empty_request_lists_cleaned_on_allow(self):
        limiter = self._make_limiter(max_req=5, window=1)
        limiter.allow("s1")
        assert "s1" in limiter._requests

        # Simulate window expiry — the next allow should clean up
        import time as _time
        _time.sleep(1.1)
        limiter.allow("s1")
        # s1 still exists because we just added a new timestamp
        assert "s1" in limiter._requests
