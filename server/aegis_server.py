"""
AEGIS-Claw HTTP Microservice — OpenClaw Plugin Backend.

Exposes the AEGIS-Claw guard pipeline as a lightweight HTTP API.
The OpenClaw TypeScript plugin calls this service to perform security checks.

Endpoints:
    POST /guard/input     — Check user input
    POST /guard/command   — Check shell command
    POST /guard/output    — Check AI response
    POST /guard/external  — Check external content
    POST /sanitize/external — Wrap external content with security boundaries
    POST /detect/patterns — Quick injection pattern scan
    GET  /health          — Service health check

Usage:
    python -m server.aegis_server [--port 5050] [--host 127.0.0.1]
"""

from __future__ import annotations

import argparse
import json
import logging
import time
from http.server import HTTPServer, BaseHTTPRequestHandler
from typing import Any

from aegis_claw import AegisClaw, AegisClawConfig
from aegis_claw.core.schemas import GuardResponse
from aegis_claw.engine.content_sanitizer import detect_suspicious_patterns

logger = logging.getLogger("aegis-server")


# ---------------------------------------------------------------------------
# Response serialization
# ---------------------------------------------------------------------------

def guard_response_to_dict(resp: GuardResponse) -> dict[str, Any]:
    """Convert a GuardResponse to a JSON-serializable dict."""
    return {
        "request_id": resp.request_id,
        "decision": resp.decision.value,
        "confidence": resp.confidence,
        "risk": {
            "label": resp.risk.label,
            "severity": resp.risk.severity.value,
            "description": resp.risk.description,
        } if resp.risk else None,
        "evidence": [
            {
                "rule_id": e.rule_id,
                "reason": e.reason,
                "matched_text": e.matched_text,
            }
            for e in resp.evidence
        ],
        "rewrite": resp.rewrite,
        "message": resp.message,
        "pipeline_stages": [
            {
                "name": s.name,
                "latency_ms": round(s.latency_ms, 2),
                "passed": s.passed,
                "detail": s.detail,
            }
            for s in resp.pipeline_stages
        ],
        "total_latency_ms": round(resp.total_latency_ms, 2),
    }


# ---------------------------------------------------------------------------
# HTTP Handler
# ---------------------------------------------------------------------------

class AegisHandler(BaseHTTPRequestHandler):
    """HTTP request handler exposing AEGIS-Claw guard methods."""

    guard: AegisClaw  # shared class-level instance

    # --- Routing ---

    _POST_ROUTES: dict[str, str] = {
        "/guard/input": "_handle_guard_input",
        "/guard/command": "_handle_guard_command",
        "/guard/output": "_handle_guard_output",
        "/guard/external": "_handle_guard_external",
        "/sanitize/external": "_handle_sanitize_external",
        "/detect/patterns": "_handle_detect_patterns",
        "/health": "_handle_health",
    }

    def do_POST(self) -> None:
        handler_name = self._POST_ROUTES.get(self.path)
        if handler_name is None:
            self.send_error(404, f"Unknown endpoint: {self.path}")
            return
        body = self._read_json_body()
        if body is None and self.path != "/health":
            self.send_error(400, "Invalid JSON body")
            return
        try:
            handler = getattr(self, handler_name)
            result = handler(body or {})
            self._send_json(result)
        except KeyError as exc:
            self._send_json({"error": f"Missing required field: {exc}"}, status=400)
        except Exception as exc:
            logger.exception("Handler error")
            self._send_json({"error": str(exc)}, status=500)

    def do_GET(self) -> None:
        if self.path == "/health":
            self._send_json(self._handle_health({}))
        else:
            self.send_error(404)

    # --- Guard endpoints ---

    def _handle_guard_input(self, body: dict) -> dict:
        t0 = time.perf_counter()
        resp = self.guard.guard_input(
            text=body["text"],
            scenario=body.get("scenario"),
            session_id=body.get("session_id"),
        )
        resp.total_latency_ms = (time.perf_counter() - t0) * 1000
        return guard_response_to_dict(resp)

    def _handle_guard_command(self, body: dict) -> dict:
        t0 = time.perf_counter()
        resp = self.guard.guard_command(
            command=body["command"],
            session_id=body.get("session_id"),
        )
        resp.total_latency_ms = (time.perf_counter() - t0) * 1000
        return guard_response_to_dict(resp)

    def _handle_guard_output(self, body: dict) -> dict:
        t0 = time.perf_counter()
        resp = self.guard.guard_output(
            text=body["text"],
            scenario=body.get("scenario"),
            session_id=body.get("session_id"),
        )
        resp.total_latency_ms = (time.perf_counter() - t0) * 1000
        return guard_response_to_dict(resp)

    def _handle_guard_external(self, body: dict) -> dict:
        t0 = time.perf_counter()
        resp = self.guard.guard_external_content(
            content=body["content"],
            source=body.get("source", "unknown"),
            sender=body.get("sender"),
            subject=body.get("subject"),
            session_id=body.get("session_id"),
        )
        resp.total_latency_ms = (time.perf_counter() - t0) * 1000
        result = guard_response_to_dict(resp)
        # Include Content Sanitizer patterns for external mode
        result["injection_patterns"] = detect_suspicious_patterns(body["content"])
        return result

    def _handle_sanitize_external(self, body: dict) -> dict:
        sanitized = self.guard.sanitize_external(
            content=body["content"],
            source=body.get("source", "unknown"),
            sender=body.get("sender"),
            subject=body.get("subject"),
        )
        return {"sanitized": sanitized}

    def _handle_detect_patterns(self, body: dict) -> dict:
        patterns = detect_suspicious_patterns(body["content"])
        return {"patterns": patterns}

    def _handle_health(self, _body: dict) -> dict:
        return {"status": "ok", "version": "0.2.0"}

    # --- Utilities ---

    def _read_json_body(self) -> dict | None:
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            return {}
        try:
            raw = self.rfile.read(content_length)
            return json.loads(raw)
        except (json.JSONDecodeError, ValueError):
            return None

    def _send_json(self, data: dict, status: int = 200) -> None:
        body = json.dumps(data, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt: str, *args: Any) -> None:
        logger.info(fmt % args)


# ---------------------------------------------------------------------------
# Server factory
# ---------------------------------------------------------------------------

def create_server(
    host: str = "127.0.0.1",
    port: int = 5050,
    config: AegisClawConfig | None = None,
) -> HTTPServer:
    """Create and return an HTTPServer (does not start serving)."""
    cfg = config or AegisClawConfig()
    AegisHandler.guard = AegisClaw(config=cfg)
    server = HTTPServer((host, port), AegisHandler)
    return server


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="AEGIS-Claw Security Microservice")
    parser.add_argument("--port", type=int, default=5050, help="Listen port (default: 5050)")
    parser.add_argument("--host", type=str, default="127.0.0.1", help="Bind address (default: 127.0.0.1)")
    parser.add_argument("--log-level", type=str, default="INFO", choices=["DEBUG", "INFO", "WARNING"])
    parser.add_argument("--rate-limit", action="store_true", help="Enable rate limiting")
    parser.add_argument("--max-requests", type=int, default=60, help="Max requests per window (default: 60)")
    parser.add_argument("--max-input-length", type=int, default=50000, help="Max input text length (default: 50000)")
    args = parser.parse_args()

    logging.basicConfig(
        level=getattr(logging, args.log_level),
        format="%(asctime)s [%(name)s] %(levelname)s — %(message)s",
    )

    config = AegisClawConfig(
        log_level=args.log_level,
        rate_limit_enabled=args.rate_limit,
        rate_limit_max_requests=args.max_requests,
        max_input_length=args.max_input_length,
    )

    server = create_server(host=args.host, port=args.port, config=config)
    logger.info(f"AEGIS-Claw v0.2.0 — http://{args.host}:{args.port}")
    logger.info(f"Rate limit: {'ON' if args.rate_limit else 'OFF'} ({args.max_requests}/min)")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        logger.info("Shutting down")
        server.server_close()


if __name__ == "__main__":
    main()
