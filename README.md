# CALLISTO

**Causal And LLM-Level Invocation Sequence Temporal Observer**

A security detection system for real-time monitoring of LLM Agent API abuse and behavioral anomalies.

## Features

- **Real-time Detection** — Intercepts tool calls before execution via OpenClaw plugin hooks
- **Multi-layer Analysis** — Content safety, shell pattern matching, behavioral analysis, causal graph analysis
- **Circuit Breaker** — Automatically blocks execution after consecutive high-severity alerts
- **Web Dashboard** — Real-time monitoring with alert history, session management, and report export
- **Vulnerability Database** — 500+ vulnerability rules for OpenClaw security scanning
- **CLI Tool** — Offline scanning, real-time monitoring, fingerprint training, and evaluation

## Quick Start

```bash
# Install
pip install -e ".[full]"

# Run the web dashboard
python web_server.py

# CLI: scan session logs
callisto scan ./logs/

# CLI: real-time monitoring
callisto monitor ./logs/ --block
```

## Project Structure

```
callisto/           # Core Python engine (~13,700 lines)
├── engine.py       # Detection engine
├── monitor.py      # Real-time monitor
├── content_safety.py  # Content safety analyzer
├── collector/      # Session log parsers
├── detection/      # Detection algorithms
├── features/       # Feature extraction
├── response/       # Response & circuit breaker
├── vulndb/         # Vulnerability database
├── report/         # Report generation (HTML/MD/JSON)
├── evaluation/     # Benchmark evaluation
├── attacks/        # Attack simulation
└── cli.py          # Command-line interface

web/                # Web dashboard (HTML/CSS/JS)
web_server.py       # FastAPI web server

tests/              # Test suite
docs/               # Documentation
paper/              # Academic paper (LaTeX + PDF)
scripts/            # Utility scripts
```

## Detection Capabilities

| Category | Coverage |
|----------|----------|
| Privilege Escalation | sudo abuse, credential access, permission enumeration |
| Data Exfiltration | POST exfil, sensitive file access, cloud metadata (SSRF) |
| Shell Attacks | Reverse shells, download-execute, pipe injection, obfuscation |
| Behavioral Analysis | Rate anomalies, behavior drift, temporal violations |
| Config Security | Hardcoded tokens, insecure HTTP, plaintext passwords |
| Phishing | Prompt injection, credential extraction, social engineering |
| Vulnerability Scanning | 500+ OpenClaw CVE/GHSA rules |

## Integration with OpenClaw

CALLISTO integrates with [OpenClaw](https://github.com/openclaw/openclaw) as a plugin:

```json
// ~/.openclaw/openclaw.json
{
  "plugins": {
    "allow": ["callisto-plugin"]
  }
}
```

## Documentation

| Document | Description |
|----------|-------------|
| [OVERVIEW](docs/OVERVIEW.md) | Project architecture |
| [DETECTION_LOGIC](docs/DETECTION_LOGIC.md) | Detection algorithms |
| [CONTRIBUTING](docs/CONTRIBUTING.md) | Contribution guide |
| [API](docs/API.md) | API reference |

## License

MIT License — see [LICENSE](LICENSE)
