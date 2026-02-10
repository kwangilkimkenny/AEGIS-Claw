"""
Async Guard Pipeline — asyncio wrapper for GuardPipeline.

Provides an async ``evaluate()`` method for non-blocking operation
in async applications (FastAPI, aiohttp, etc.).

Note: For most use-cases the ``AegisClaw.async_guard_*`` convenience
methods are sufficient.  Use this class only when you need direct
access to the lower-level pipeline with ``GuardRequest`` objects.

Usage:
    pipeline = AsyncGuardPipeline()
    result = await pipeline.evaluate(request)
"""

from __future__ import annotations

import asyncio

from aegis_claw.core.config import AegisClawConfig
from aegis_claw.core.schemas import GuardRequest, GuardResponse
from aegis_claw.pipeline.guard import GuardPipeline


class AsyncGuardPipeline:
    """Async wrapper for GuardPipeline using asyncio.to_thread.

    This is the low-level async interface.  For the high-level API
    prefer ``AegisClaw.async_guard_input()`` and friends.
    """

    def __init__(
        self,
        config: AegisClawConfig | None = None,
        pipeline: GuardPipeline | None = None,
    ) -> None:
        self._config = config or AegisClawConfig()
        self._pipeline = pipeline or GuardPipeline(config=self._config)

    @property
    def pipeline(self) -> GuardPipeline:
        """Access the underlying synchronous pipeline."""
        return self._pipeline

    async def evaluate(self, request: GuardRequest) -> GuardResponse:
        """Run the guard pipeline asynchronously."""
        return await asyncio.to_thread(self._pipeline.evaluate, request)
