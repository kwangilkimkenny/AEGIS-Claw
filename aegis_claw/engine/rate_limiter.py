"""
Rate Limiter — In-memory sliding window rate limiting.

Prevents repeated attack attempts from a single session by tracking
request counts within configurable time windows.

Usage:
    limiter = RateLimiter(config)
    if not limiter.allow("session_123"):
        # Block: too many requests
        ...
"""

from __future__ import annotations

import logging
import time
from collections import defaultdict

from aegis_claw.core.config import AegisClawConfig

logger = logging.getLogger("aegis_claw.engine.rate_limiter")


class RateLimiter:
    """In-memory sliding window rate limiter."""

    # Run GC every 100 allow() calls to keep memory bounded
    _GC_INTERVAL: int = 100

    def __init__(self, config: AegisClawConfig | None = None) -> None:
        self._config = config or AegisClawConfig()
        self._requests: dict[str, list[float]] = defaultdict(list)
        self._blocked_until: dict[str, float] = {}
        self._call_count: int = 0

    @property
    def enabled(self) -> bool:
        return self._config.rate_limit_enabled

    def allow(self, session_id: str | None) -> bool:
        """Check if a request from this session is allowed.

        Returns True if allowed, False if rate-limited.
        If rate limiting is disabled or no session_id, always returns True.
        """
        if not self.enabled or not session_id:
            return True

        now = time.monotonic()

        # Periodic garbage collection of stale sessions
        self._call_count += 1
        if self._call_count >= self._GC_INTERVAL:
            self._gc(now)
            self._call_count = 0

        # Check if session is in block period
        blocked_until = self._blocked_until.get(session_id, 0)
        if now < blocked_until:
            remaining = blocked_until - now
            logger.warning(
                "Rate limit: session '%s' blocked for %.0fs more",
                session_id,
                remaining,
            )
            return False

        # Clean up expired block
        if session_id in self._blocked_until:
            del self._blocked_until[session_id]

        # Sliding window: remove timestamps outside the window
        window = self._config.rate_limit_window_seconds
        cutoff = now - window
        timestamps = self._requests[session_id]
        self._requests[session_id] = [t for t in timestamps if t > cutoff]

        # Remove session entry if window is now empty (prevent stale keys)
        if not self._requests[session_id]:
            del self._requests[session_id]

        # Check rate
        max_requests = self._config.rate_limit_max_requests
        current_count = len(self._requests.get(session_id, []))
        if current_count >= max_requests:
            block_dur = self._config.rate_limit_block_seconds
            self._blocked_until[session_id] = now + block_dur
            logger.warning(
                "Rate limit exceeded: session '%s' — %d requests in %ds window, "
                "blocked for %ds",
                session_id,
                current_count,
                window,
                block_dur,
            )
            return False

        # Record this request
        self._requests[session_id].append(now)
        return True

    def _gc(self, now: float) -> None:
        """Remove stale sessions whose windows have fully expired."""
        window = self._config.rate_limit_window_seconds
        cutoff = now - window

        # Clean stale request lists
        stale_sessions = [
            sid for sid, timestamps in self._requests.items()
            if not timestamps or timestamps[-1] <= cutoff
        ]
        for sid in stale_sessions:
            del self._requests[sid]

        # Clean expired blocks
        expired_blocks = [
            sid for sid, until in self._blocked_until.items()
            if now >= until
        ]
        for sid in expired_blocks:
            del self._blocked_until[sid]

        if stale_sessions or expired_blocks:
            logger.debug(
                "Rate limiter GC: removed %d stale sessions, %d expired blocks",
                len(stale_sessions),
                len(expired_blocks),
            )

    def reset(self, session_id: str | None = None) -> None:
        """Reset rate limit state for a session (or all sessions)."""
        if session_id:
            self._requests.pop(session_id, None)
            self._blocked_until.pop(session_id, None)
        else:
            self._requests.clear()
            self._blocked_until.clear()
