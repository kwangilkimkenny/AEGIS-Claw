# AEGIS-Claw OpenClaw Plugin Usage Guide

> **Version**: v0.2.0
> **Date**: 2026-02-11

---

## Table of Contents

1. [Introduction](#1-introduction)
2. [Components](#2-components)
3. [Prerequisites](#3-prerequisites)
4. [Installation](#4-installation)
5. [Python Service](#5-python-service)
6. [OpenClaw Plugin Registration](#6-openclaw-plugin-registration)
7. [Configuration Options](#7-configuration-options)
8. [How It Works](#8-how-it-works)
9. [API Reference](#9-api-reference)
10. [Secret Masking Patterns](#10-secret-masking-patterns)
11. [Operating Modes](#11-operating-modes)
12. [Monitoring](#12-monitoring)
13. [Configuration Examples](#13-configuration-examples)
14. [Troubleshooting](#14-troubleshooting)

---

## 1. Introduction

The AEGIS-Claw Plugin adds security guards to the OpenClaw AI agent platform.
It inserts 4 security checkpoints into OpenClaw's Hook system, protecting the entire
message pipeline from input to output.

### Defense Coverage

| Threat Type | Detection Method |
|---|---|
| Prompt Injection | Pattern matching (Korean/English) |
| Jailbreak Attacks (9 types) | DAN, Role Play, Developer Mode, etc. |
| Encoding Attacks | Base64, ROT13, Homoglyph (Cyrillic) |
| Dangerous Commands | rm -rf, reverse shell, crypto mining, etc. |
| PII/Credential Leaks | API Key, Password, Token, Private Key |
| Indirect Injection | Hidden commands in external content (email, web) |
| Harmful Content | Violence, harassment, hate speech, etc. (6 categories) |
| Anomalies | Zero-width chars, RTL override, special char ratio |

### Architecture

```
                    OpenClaw (TypeScript)
                          │
          ┌───────────────┼───────────────┐
          │               │               │
     Hook ①          Hook ②          Hook ④
  before_agent     before_tool     message_sending
    _start           _call
          │               │               │
          └───────┬───────┘               │
                  │                       │
              HTTP POST                HTTP POST
                  │                       │
                  ▼                       ▼
        ┌─────────────────────────────────────┐
        │   AEGIS-Claw Python Service (:5050) │
        │                                     │
        │   /guard/input   /guard/command      │
        │   /guard/output  /guard/external     │
        │                                     │
        │   ┌─────────────────────────────┐   │
        │   │      Guard Pipeline         │   │
        │   │  Rule Engine → Jailbreak    │   │
        │   │  Detector → Safety          │   │
        │   │  Classifier → Decision      │   │
        │   │  Router → Risk Scorer       │   │
        │   └─────────────────────────────┘   │
        └─────────────────────────────────────┘

     Hook ③ (tool_result_persist) runs synchronously →
     Local regex secret masking without Python service calls
```

---

## 2. Components

### File Structure

```
AEGIS-Claw/
├── server/
│   └── aegis_server.py          # Python HTTP microservice
│
├── plugin/
│   ├── package.json             # OpenClaw plugin manifest
│   ├── tsconfig.json            # TypeScript config
│   ├── index.ts                 # Plugin entry (4 hook registration)
│   └── src/
│       ├── aegis-bridge.ts      # Python service HTTP client
│       ├── config.ts            # Config types and defaults
│       ├── types.ts             # Response/decision/severity types
│       ├── utils.ts             # Utilities (secret masking, notice builders)
│       └── hooks/
│           ├── input-guard.ts   # Hook ① User input check
│           ├── tool-guard.ts    # Hook ② Tool execution blocking
│           ├── result-guard.ts  # Hook ③ Secret masking in results
│           └── output-guard.ts  # Hook ④ AI response verification
│
└── tests/
    └── test_server.py           # Server integration tests (33)
```

### Role Distribution

| Component | Language | Role |
|---|---|---|
| `server/aegis_server.py` | Python | Exposes AEGIS-Claw engine as HTTP API |
| `plugin/index.ts` | TypeScript | Registers security logic into OpenClaw hooks |
| `plugin/src/aegis-bridge.ts` | TypeScript | HTTP communication with Python service |
| `plugin/src/hooks/*.ts` | TypeScript | Security handlers for each hook |
| `plugin/src/utils.ts` | TypeScript | Secret masking (synchronous, local) |

---

## 3. Prerequisites

```
Python   >= 3.10
Node.js  >= 22.12.0
OpenClaw >= 2026.2.x
```

```bash
pip install aegis-claw    # or: pip install -e /path/to/AEGIS-Claw
```

---

## 4. Installation

### 4.1 Install AEGIS-Claw Library

```bash
cd /path/to/AEGIS-Claw
pip install -e .
```

### 4.2 Deploy Plugin Directory

Copy the `plugin/` folder to OpenClaw's `extensions/` directory:

```bash
cp -r /path/to/AEGIS-Claw/plugin /path/to/openclaw/extensions/aegis-claw
```

Or symlink:

```bash
ln -s /path/to/AEGIS-Claw/plugin /path/to/openclaw/extensions/aegis-claw
```

---

## 5. Python Service

### 5.1 Basic Startup

```bash
cd /path/to/AEGIS-Claw
python -m server.aegis_server
```

### 5.2 CLI Options

| Option | Default | Description |
|---|---|---|
| `--port` | `5050` | Listen port |
| `--host` | `127.0.0.1` | Bind address |
| `--log-level` | `INFO` | Log level (DEBUG/INFO/WARNING) |
| `--rate-limit` | off | Enable per-session rate limiting |
| `--max-requests` | `60` | Max requests per window |
| `--max-input-length` | `50000` | Max input text length |

### 5.3 Production Example

```bash
python -m server.aegis_server \
  --port 5050 \
  --host 127.0.0.1 \
  --log-level INFO \
  --rate-limit \
  --max-requests 100
```

### 5.4 Health Check

```bash
curl http://127.0.0.1:5050/health
# {"status": "ok", "version": "0.2.0"}
```

### 5.5 systemd (Linux)

```ini
# /etc/systemd/system/aegis-claw.service
[Unit]
Description=AEGIS-Claw Security Service
After=network.target

[Service]
Type=simple
User=openclaw
WorkingDirectory=/opt/AEGIS-Claw
ExecStart=/usr/bin/python3 -m server.aegis_server --port 5050 --rate-limit
Restart=always
RestartSec=5

[Install]
WantedBy=multi-user.target
```

### 5.6 Docker

```dockerfile
FROM python:3.12-slim
WORKDIR /app
COPY . .
RUN pip install -e .
EXPOSE 5050
CMD ["python", "-m", "server.aegis_server", "--port", "5050", "--rate-limit"]
```

---

## 6. OpenClaw Plugin Registration

Add the plugin to `~/.openclaw/config.json5`:

```json5
{
  plugins: {
    entries: {
      "aegis-claw": {
        enabled: true,
        source: "./extensions/aegis-claw",
        config: {
          mode: "enforcing",
          pythonServiceUrl: "http://127.0.0.1:5050",
          blockOnCritical: true,
          escalateOnHigh: true,
          redactSecrets: true,
          rateLimitEnabled: true,
          rateLimitMaxRequests: 60,
          timeoutMs: 5000,
          logLevel: "info"
        }
      }
    }
  }
}
```

After registration, restart OpenClaw Gateway:

```bash
openclaw gateway start
```

Success is confirmed when you see:

```
[AEGIS] Initializing v0.2.0 — mode=enforcing, service=http://127.0.0.1:5050
[AEGIS] Plugin registered — 4 hooks active
```

---

## 7. Configuration Options

### Plugin Config (config.json5)

| Option | Type | Default | Description |
|---|---|---|---|
| `mode` | string | `"enforcing"` | Operating mode (`enforcing` / `auditing` / `disabled`) |
| `pythonServiceUrl` | string | `"http://127.0.0.1:5050"` | Python service URL |
| `blockOnCritical` | boolean | `true` | Block critical severity requests |
| `escalateOnHigh` | boolean | `true` | Warn on high severity requests |
| `redactSecrets` | boolean | `true` | Mask secrets in tool results |
| `rateLimitEnabled` | boolean | `true` | Per-session rate limiting |
| `rateLimitMaxRequests` | number | `60` | Max requests in 60s window |
| `timeoutMs` | number | `5000` | Service call timeout (ms) |
| `logLevel` | string | `"info"` | Log level |

---

## 8. How It Works

### 8.1 Hook ① — Input Guard (`before_agent_start`, priority 900)

**When**: Just before the agent processes a user message

**Flow**:
1. Extract latest user message
2. Send to `POST /guard/input` for AEGIS check
3. Based on result:
   - **BLOCK** (enforcing mode): Inject rejection directive into system prompt
   - **ESCALATE**: Inject caution warning
   - **APPROVE**: Pass through without modification

### 8.2 Hook ② — Tool Guard (`before_tool_call`, priority 800)

**When**: Just before tool execution

**Checked Tools**:

| Tool | Check Method | Example |
|---|---|---|
| `exec`, `process` | `POST /guard/command` | `rm -rf /`, `curl \| bash` |
| `write`, `edit`, `apply_patch` | `POST /guard/output` | Malicious code write attempt |
| `message` | `POST /guard/output` | Sensitive info transmission attempt |

### 8.3 Hook ③ — Result Guard (`tool_result_persist`, synchronous)

**When**: Just before tool results are saved to session history

**Important**: This hook runs **synchronously**. Python service calls are not possible,
so secrets are masked using local regex patterns.

**Masking Examples**:
```
Before: api_key=sk-proj-abc123def456ghi789jkl012mno345
After:  [SK_PROJ_KEY_REDACTED]

Before: password=S3cureP@ssw0rd!2024
After:  [PASSWORD_REDACTED]
```

### 8.4 Hook ④ — Output Guard (`message_sending`, priority 700)

**When**: Just before AI response is sent to user

**Flow**:
1. Check response text via `POST /guard/output`
2. Based on result:
   - **BLOCK**: Replace response with security warning
   - **MODIFY**: Replace with `rewrite` field text
   - **APPROVE**: Send original as-is

---

## 9. API Reference

### Endpoints

| Method | Path | Description |
|---|---|---|
| POST | `/guard/input` | Check user input |
| POST | `/guard/command` | Check shell command |
| POST | `/guard/output` | Check AI response |
| POST | `/guard/external` | Check external content |
| POST | `/sanitize/external` | Wrap external content |
| POST | `/detect/patterns` | Detect injection patterns |
| GET | `/health` | Health check |

### Decision Values

| Value | Meaning | Plugin Action |
|---|---|---|
| `approve` | Safe | Pass through |
| `block` | Threat blocked | Reject or replace response |
| `modify` | Modification needed | Replace with `rewrite` value |
| `escalate` | Review needed | Inject warning notification |
| `reask` | Clarification needed | Ask user to confirm intent |

---

## 10. Secret Masking Patterns

Local patterns applied synchronously by Hook ③ (Result Guard):

| Pattern | Masking Result | Example |
|---|---|---|
| `sk-{20+ chars}` | `[SK_KEY_REDACTED]` | `sk-abcdef1234567890abcdef` |
| `sk-proj-{20+ chars}` | `[SK_PROJ_KEY_REDACTED]` | `sk-proj-abc123def456...` |
| `AKIA{16 chars}` | `[AWS_KEY_REDACTED]` | `AKIAIOSFODNN7EXAMPLE` |
| `api_key=...` / `apikey=...` | `[API_KEY_REDACTED]` | |
| `password=...` / `pwd=...` | `[PASSWORD_REDACTED]` | |
| `token=...` / `bearer=...` | `[TOKEN_REDACTED]` | |
| `ghp_{36+ chars}` | `[GITHUB_TOKEN_REDACTED]` | GitHub PAT |
| `gho_{36+ chars}` | `[GITHUB_OAUTH_REDACTED]` | GitHub OAuth |
| `xoxb-...` | `[SLACK_TOKEN_REDACTED]` | Slack Bot Token |
| `-----BEGIN PRIVATE KEY-----` | `[PRIVATE_KEY_REDACTED]` | RSA/EC/DSA |
| `mongodb://...` / `postgres://...` | `[CONNECTION_STRING_REDACTED]` | DB connection string |

---

## 11. Operating Modes

### `enforcing` (Recommended for production)

Actually blocks threats.
- BLOCK: Rejects request / replaces response
- ESCALATE: Injects warning notification
- MODIFY: Replaces with modified text
- Secret masking active

### `auditing` (Recommended for initial deployment)

Logs only, does not block.
- Records all AEGIS decisions to logs
- No actual blocking/modification/replacement
- Useful for false positive analysis and threshold tuning

### `disabled`

Completely disables the plugin. No hooks registered.

### Recommended Deployment Sequence

```
① Start with auditing mode (1-2 weeks)
    → Monitor logs for false positives
    → Adjust Python service thresholds if needed
② Switch to enforcing mode
    → Actual blocking applied
```

---

## 12. Monitoring

### Log Format

```
[AEGIS] INPUT   | BLOCK    | severity=critical conf=97% | 1.2ms | "Ignore all previous instructions..."
[AEGIS] COMMAND | BLOCK    | severity=critical conf=95% | 0.8ms | "rm -rf /"
[AEGIS] OUTPUT  | MODIFY   | severity=high     conf=85% | 1.5ms | "Here is your API key: sk-proj..."
[AEGIS] Redacted 2 secret(s) in exec result
```

### Gateway Status Endpoint

```bash
curl http://localhost:3000/api/aegis/status
```

```json
{
  "plugin": "aegis-claw",
  "version": "0.2.0",
  "mode": "enforcing",
  "serviceUrl": "http://127.0.0.1:5050",
  "serviceHealthy": true,
  "config": {
    "blockOnCritical": true,
    "escalateOnHigh": true,
    "redactSecrets": true,
    "rateLimitEnabled": true
  }
}
```

---

## 13. Configuration Examples

### Minimal Config

```json5
{
  plugins: {
    entries: {
      "aegis-claw": {
        enabled: true,
        source: "./extensions/aegis-claw"
      }
    }
  }
}
```

All options use defaults (`enforcing`, secret masking ON, rate limiting ON).

### Strict Security

```json5
{
  plugins: {
    entries: {
      "aegis-claw": {
        enabled: true,
        source: "./extensions/aegis-claw",
        config: {
          mode: "enforcing",
          blockOnCritical: true,
          escalateOnHigh: true,
          redactSecrets: true,
          rateLimitEnabled: true,
          rateLimitMaxRequests: 30,
          timeoutMs: 3000,
          logLevel: "info"
        }
      }
    }
  }
}
```

---

## 14. Troubleshooting

### Python service won't start

```bash
python -c "from aegis_claw import AegisClaw; print('OK')"
lsof -i :5050
python -m server.aegis_server --port 5051
```

### Plugin won't load

1. Verify `enabled: true` in config.json5
2. Confirm `index.ts` exists at `source` path
3. Restart OpenClaw Gateway

### Normal input is blocked (false positive)

1. Switch to `"mode": "auditing"`
2. Test directly against Python service:
```bash
curl -s -X POST http://localhost:5050/guard/input \
  -H "Content-Type: application/json" \
  -d '{"text":"your false positive text"}' | python -m json.tool
```

### Service call timeout

Increase `timeoutMs` in plugin config, or check Python service performance.

### Python service down behavior

Plugin follows **fail-open** policy:
- On service call failure: logs warning, allows request through
- Hook ③ (secret masking) uses local regex, unaffected by service outage
- Normal operation resumes automatically when service recovers

---

## Startup Summary

```bash
# Step 1: Install AEGIS-Claw
cd /path/to/AEGIS-Claw
pip install -e .

# Step 2: Start Python service
python -m server.aegis_server --port 5050 --rate-limit &

# Step 3: Verify service
curl http://127.0.0.1:5050/health

# Step 4: Deploy plugin
cp -r plugin/ /path/to/openclaw/extensions/aegis-claw/

# Step 5: Add plugin to OpenClaw config
# config.json5 → plugins.entries.aegis-claw

# Step 6: Start Gateway
openclaw gateway start

# Step 7: Verify
curl http://localhost:3000/api/aegis/status
```
