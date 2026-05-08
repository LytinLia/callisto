#!/usr/bin/env python3
"""
CALLISTO Web Dashboard Server

FastAPI service providing REST API and SSE endpoints for CALLISTO security dashboard.
"""

import os
import sys
import json
import asyncio
import subprocess
from typing import Optional, Dict, Any, List
from pathlib import Path
from datetime import datetime, timedelta
from dataclasses import dataclass, asdict

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import JSONResponse, HTMLResponse, FileResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

# 添加父目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))


# ================================
# Pydantic Models
# ================================

class ScanRequest(BaseModel):
    scan_type: str = "all"  # "all", "config", "skills"
    force: bool = False


class CircuitBreakerAction(BaseModel):
    session_id: str
    action: str  # "reset", "block"
    reason: Optional[str] = ""


# ================================
# CALLISTO Web App
# ================================

def create_app() -> FastAPI:
    """Create FastAPI application"""

    app = FastAPI(
        title="CALLISTO Dashboard",
        description="CALLISTO: Security Detection System for LLM Agents",
        version="2.0.0",
    )

    # CORS
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # Dashboard directory
    dashboard_dir = Path(__file__).parent / "web"
    static_dir = dashboard_dir / "static"
    data_dir = Path(__file__).parent / "data"
    data_dir.mkdir(exist_ok=True)

    alert_file = data_dir / "alerts.json"
    session_file = data_dir / "sessions.json"

    # Mount static files with no-cache headers
    if static_dir.exists():
        from fastapi.responses import FileResponse

        @app.get("/static/{path:path}")
        async def serve_static(path: str):
            file_path = static_dir / path
            if file_path.exists():
                return FileResponse(
                    file_path,
                    headers={
                        "Cache-Control": "no-cache, no-store, must-revalidate",
                        "Pragma": "no-cache",
                        "Expires": "0",
                    }
                )
            raise HTTPException(status_code=404, detail="File not found")

    # Initialize components
    app.state.scan_results = {
        "config": [],
        "skills": [],
        "config_files_scanned": [],
        "skills_files_scanned": [],
        "last_scan_time": None,
        "total_issues": 0,
    }
    app.state.log_scan_results = []

    # Load persisted data
    def load_data():
        if alert_file.exists():
            try:
                app.state.alert_history = json.loads(alert_file.read_text(encoding='utf-8'))
            except:
                app.state.alert_history = []
        else:
            app.state.alert_history = []

        if session_file.exists():
            try:
                app.state.session_stats = json.loads(session_file.read_text(encoding='utf-8'))
            except:
                app.state.session_stats = {}
        else:
            app.state.session_stats = {}

    def save_data():
        try:
            alert_file.write_text(json.dumps(app.state.alert_history, indent=2, ensure_ascii=False), encoding='utf-8')
            session_file.write_text(json.dumps(app.state.session_stats, indent=2, ensure_ascii=False), encoding='utf-8')
        except:
            pass

    load_data()

    # ================================
    # Routes: Dashboard
    # ================================

    @app.get("/", response_class=HTMLResponse)
    async def dashboard():
        """Serve dashboard HTML"""
        index_path = dashboard_dir / "index.html"
        if index_path.exists():
            content = index_path.read_text(encoding='utf-8')
            return HTMLResponse(
                content=content,
                headers={
                    "Cache-Control": "no-cache, no-store, must-revalidate",
                    "Pragma": "no-cache",
                    "Expires": "0",
                }
            )
        return HTMLResponse(content="<h1>Dashboard not found</h1>", status_code=404)

    # ================================
    # Routes: Status
    # ================================

    def check_openclaw_running() -> bool:
        """Check if OpenClaw is currently running"""
        for name in ["openclaw", "openclaw-gateway"]:
            try:
                result = subprocess.run(
                    ["pgrep", "-f", name],
                    capture_output=True,
                    timeout=5,
                )
                if result.returncode == 0:
                    return True
            except (subprocess.TimeoutExpired, FileNotFoundError):
                pass
        return False

    @app.get("/api/status")
    async def get_status():
        """Get CALLISTO status"""
        return {
            "version": "2.0.0",
            "status": "running",
            "openclaw_running": check_openclaw_running(),
            "scan_results": app.state.scan_results,
            "alert_count": len(app.state.alert_history),
            "session_count": len(app.state.session_stats),
        }

    @app.get("/api/stats")
    async def get_stats(hours: int = 24):
        """Get statistics for the last N hours"""
        now = datetime.now()
        cutoff = now - timedelta(hours=hours)

        # Filter alerts
        recent_alerts = [
            a for a in app.state.alert_history
            if datetime.fromisoformat(a.get("timestamp", "2000-01-01")) > cutoff
        ]

        # Count by severity
        by_severity = {
            "critical": sum(1 for a in recent_alerts if a.get("severity") == "critical"),
            "high": sum(1 for a in recent_alerts if a.get("severity") == "high"),
            "medium": sum(1 for a in recent_alerts if a.get("severity") == "medium"),
            "low": sum(1 for a in recent_alerts if a.get("severity") == "low"),
        }

        # Count by category
        by_category = {}
        for alert in recent_alerts:
            cat = alert.get("category", "unknown")
            by_category[cat] = by_category.get(cat, 0) + 1

        return {
            "total_alerts": len(recent_alerts),
            "by_severity": by_severity,
            "by_category": by_category,
            "total_scans": 1,
            "last_scan": app.state.scan_results.get("last_scan_time"),
        }

    # ================================
    # Routes: Scan
    # ================================

    @app.post("/api/scan")
    async def run_scan(request: ScanRequest):
        """Run security scan"""
        try:
            # 添加 scripts 目录到路径
            base_dir = Path(__file__).parent
            scripts_dir = base_dir / "scripts"
            sys.path.insert(0, str(scripts_dir))

            from auto_scanner import AutoScanner

            scanner = AutoScanner()

            if request.scan_type == "config":
                result = scanner.scan_config(force=request.force)
            elif request.scan_type == "skills":
                result = scanner.scan_skills(force=request.force)
            else:
                result = scanner.scan_all(force=request.force)

            # Update state - handle both single-type and full scan results
            if request.scan_type == "config":
                # Single config scan
                config_result = result
                skills_result = {}
            elif request.scan_type == "skills":
                # Single skills scan
                config_result = {}
                skills_result = result
            else:
                # Full scan
                config_result = result.get("config_scan", {})
                skills_result = result.get("skills_scan", {})

            app.state.scan_results = {
                "config": config_result.get("issues", []),
                "skills": skills_result.get("issues", []),
                "config_files_scanned": config_result.get("files_scanned_list", []),
                "skills_files_scanned": skills_result.get("files_scanned_list", []),
                "last_scan_time": result.get("timestamp"),
                "total_issues": result.get("total_issues", len(config_result.get("issues", [])) + len(skills_result.get("issues", []))),
            }

            return {
                "status": "success",
                "result": result,
            }
        except ImportError as e:
            raise HTTPException(status_code=500, detail=f"Scanner not available: {e}")
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/scan/results")
    async def get_scan_results():
        """Get latest scan results"""
        return {
            "status": "success",
            "results": app.state.scan_results,
        }

    # ================================
    # Routes: Alerts
    # ================================

    @app.get("/api/alerts")
    async def get_alerts(limit: int = 100):
        """Get recent alerts"""
        return {
            "status": "success",
            "alerts": app.state.alert_history[-limit:],
        }

    @app.post("/api/alerts/add")
    async def add_alert(alert_data: Dict[str, Any]):
        """Add an alert to history"""
        alert = {
            **alert_data,
            "timestamp": datetime.now().isoformat(),
        }
        app.state.alert_history.append(alert)
        save_data()
        return {"status": "success", "id": len(app.state.alert_history)}

    @app.delete("/api/alerts/clear")
    async def clear_alerts():
        """Clear alert history"""
        app.state.alert_history.clear()
        return {"status": "success"}

    # ================================
    # Routes: Sessions
    # ================================

    @app.get("/api/sessions")
    async def get_sessions():
        """Get currently active sessions (exist in OpenClaw's session files)"""
        # Check which OpenClaw session files exist
        openclaw_sessions_dir = Path.home() / ".openclaw" / "agents" / "main" / "sessions"
        openclaw_active_ids = set()
        if openclaw_sessions_dir.exists():
            for f in openclaw_sessions_dir.iterdir():
                if f.suffix == ".jsonl" and "reset" not in f.name:
                    openclaw_active_ids.add(f.stem)

        # Count alerts per session from alerts.json
        alert_counts = {}
        for alert in app.state.alert_history:
            sid = alert.get("session_id")
            if sid:
                alert_counts[sid] = alert_counts.get(sid, 0) + 1

        # Return sessions that exist in OpenClaw, with correct alert counts
        active = []
        for s in app.state.session_stats.values():
            if s["session_id"] in openclaw_active_ids:
                session = dict(s)
                session["consecutive_alerts"] = alert_counts.get(s["session_id"], 0)
                active.append(session)

        return {
            "status": "success",
            "sessions": active,
        }

    @app.get("/api/sessions/history")
    async def get_session_history():
        """Get all historical sessions"""
        # Count alerts per session from alerts.json
        alert_counts = {}
        for alert in app.state.alert_history:
            sid = alert.get("session_id")
            if sid:
                alert_counts[sid] = alert_counts.get(sid, 0) + 1

        sessions = []
        for s in app.state.session_stats.values():
            session = dict(s)
            session["consecutive_alerts"] = alert_counts.get(s["session_id"], 0)
            sessions.append(session)

        return {
            "status": "success",
            "sessions": sessions,
        }

    @app.post("/api/session/{session_id}/circuit-breaker")
    async def circuit_breaker_action(session_id: str, action: CircuitBreakerAction):
        """Perform circuit breaker action"""
        if session_id not in app.state.session_stats:
            app.state.session_stats[session_id] = {
                "session_id": session_id,
                "state": "CLOSED",
                "consecutive_alerts": 0,
                "created_at": datetime.now().isoformat(),
            }

        session = app.state.session_stats[session_id]

        if action.action == "reset":
            session["state"] = "CLOSED"
            session["consecutive_alerts"] = 0
        elif action.action == "block":
            session["state"] = "OPEN"

        return {
            "status": "success",
            "session": session,
        }

    @app.post("/api/session/{session_id}/sync")
    async def sync_session(session_id: str, session_data: Dict[str, Any]):
        """Sync session state from CALLISTO agent"""
        app.state.session_stats[session_id] = {
            "session_id": session_id,
            "state": session_data.get("state", "CLOSED"),
            "consecutive_alerts": session_data.get("consecutive_alerts", 0),
            "tool_calls": session_data.get("tool_calls", 0),
            "last_activity": datetime.now().isoformat(),
        }
        save_data()
        return {
            "status": "success",
            "session": app.state.session_stats[session_id],
        }

    # ================================
    # Routes: Session Log Scanner
    # ================================

    def _scan_jsonl_file(file_path) -> Dict[str, Any]:
        """Scan a single .jsonl session log file using the full engine"""
        file_path = Path(file_path) if not isinstance(file_path, Path) else file_path
        try:
            plugin_dir = Path(__file__).parent
            sys.path.insert(0, str(plugin_dir))

            from callisto.collector.openclaw_parser import parse_session_file
            from callisto.engine import CallistoEngine
            from callisto.config import CallistoConfig
            from callisto.collector.models import RiskLevel

            cfg = CallistoConfig()
            engine = CallistoEngine(cfg)

            session = parse_session_file(file_path)
            if session is None:
                return {
                    "session_id": file_path.stem,
                    "file": str(file_path),
                    "alert_count": 0,
                    "alerts": [],
                    "status": "error",
                    "error": "Failed to parse session file",
                }

            alerts = engine.analyze_session(session)

            alert_dicts = []
            for alert in alerts:
                alert_dicts.append({
                    "attack_type": alert.attack_type.value if hasattr(alert.attack_type, 'value') else str(alert.attack_type),
                    "severity": alert.risk_level.name.lower() if hasattr(alert.risk_level, 'name') else str(alert.risk_level),
                    "explanation": alert.explanation[:200] if alert.explanation else "",
                    "timestamp": datetime.fromtimestamp(alert.timestamp).isoformat() if alert.timestamp else "",
                })

            # 提取会话原始时间范围
            timestamps = [e.timestamp for e in session.events if e.timestamp]
            time_first = datetime.fromtimestamp(min(timestamps)).isoformat() if timestamps else ""
            time_last = datetime.fromtimestamp(max(timestamps)).isoformat() if timestamps else ""

            return {
                "session_id": session.session_id,
                "file": str(file_path),
                "alert_count": len(alert_dicts),
                "alerts": alert_dicts,
                "status": "success",
                "time_first": time_first,
                "time_last": time_last,
            }
        except Exception as e:
            return {
                "session_id": file_path.stem,
                "file": str(file_path),
                "alert_count": 0,
                "alerts": [],
                "status": "error",
                "error": str(e),
            }

    @app.post("/api/session-log/scan")
    async def scan_session_logs():
        """Scan all session log files in default OpenClaw path"""
        session_dir = Path.home() / ".openclaw" / "agents" / "main" / "sessions"
        if not session_dir.exists():
            return {"status": "error", "error": "Session directory not found", "sessions": []}

        jsonl_files = [
            f for f in session_dir.iterdir()
            if f.suffix == ".jsonl" and "reset" not in f.name
        ]

        results = []
        for f in sorted(jsonl_files):
            result = _scan_jsonl_file(f)
            results.append(result)

        app.state.log_scan_results = results

        return {
            "status": "success",
            "sessions": results,
            "total_files": len(jsonl_files),
            "total_alerts": sum(r["alert_count"] for r in results),
        }

    @app.post("/api/session-log/upload")
    async def upload_session_log():
        """Upload and scan a session log file"""
        from fastapi import UploadFile, File
        # This endpoint needs special handling for multipart/form-data
        raise HTTPException(status_code=501, detail="Use the scan endpoint for default paths")

    # ================================
    # Routes: File Upload (multipart)
    # ================================

    from starlette.requests import Request
    from starlette.formparsers import MultiPartParser

    @app.post("/api/session-log/upload-file")
    async def upload_session_log(request: Request):
        """Upload and scan a session log file"""
        form = await request.form()
        upload_file = form.get("file")
        if not upload_file or not hasattr(upload_file, "read"):
            raise HTTPException(status_code=400, detail="No file uploaded")

        import tempfile
        import shutil

        try:
            with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
                content = await upload_file.read()
                tmp.write(content)
                tmp_path = tmp.name

            result = _scan_jsonl_file(Path(tmp_path))
            app.state.log_scan_results = [result]
            return {"status": "success", "sessions": [result]}
        finally:
            try:
                os.unlink(tmp_path)
            except:
                pass

    async def event_generator():
        """Generate SSE events"""
        last_count = len(app.state.alert_history)

        while True:
            # Check for new alerts
            current_count = len(app.state.alert_history)
            if current_count > last_count:
                new_alerts = app.state.alert_history[last_count:]
                for alert in new_alerts:
                    yield {
                        "event": "alert",
                        "data": json.dumps(alert),
                    }
                last_count = current_count

            # Send heartbeat
            yield {
                "event": "heartbeat",
                "data": json.dumps({
                    "timestamp": datetime.now().isoformat(),
                    "alert_count": current_count,
                }),
            }

            await asyncio.sleep(5)

    @app.get("/api/events")
    async def stream_events():
        """Stream security events via SSE"""
        return EventSourceResponse(event_generator())

    # ================================
    # Routes: Vulnerability Scanning
    # ================================

    _vuln_scanner = None
    _vuln_db = None
    _vuln_scan_results = []

    def _get_vuln_scanner():
        nonlocal _vuln_scanner, _vuln_db
        if _vuln_scanner is None:
            from callisto.vulndb.scanner import VulnDatabase, VulnScanner
            vuln_dir = Path(__file__).parent / "callisto" / "vulndb" / "openclaw"
            db = VulnDatabase(vuln_dir)
            count = db.load()
            print(f"[VulnScanner] Loaded {count} vulnerability rules")
            _vuln_db = db
            _vuln_scanner = VulnScanner(db)
        return _vuln_scanner

    @app.get("/api/vuln/stats")
    async def get_vuln_stats():
        """获取漏洞数据库统计信息。"""
        try:
            scanner = _get_vuln_scanner()
            stats = scanner.db.stats()
            return {"status": "success", "stats": stats}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.get("/api/vuln/list")
    async def get_vuln_list(
        limit: int = Query(default=50, le=200),
        severity: Optional[str] = Query(default=None),
        keyword: Optional[str] = Query(default=None),
    ):
        """获取漏洞列表（分页）。"""
        try:
            scanner = _get_vuln_scanner()
            vulns = scanner.db.vulns

            # 过滤
            if severity:
                sev_upper = severity.upper()
                vulns = [v for v in vulns if v.info.severity.upper() in (sev_upper, severity)]
            if keyword:
                kw = keyword.lower()
                vulns = [v for v in vulns
                         if kw in v.id.lower()
                         or kw in v.info.summary.lower()
                         or kw in v.info.details.lower()]

            # 分页
            total = len(vulns)
            vulns = vulns[:limit]

            return {
                "status": "success",
                "total": total,
                "vulns": [scanner._vuln_to_dict(v) for v in vulns],
            }
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @app.post("/api/vuln/scan")
    async def run_vuln_scan(scan_data: Dict[str, Any]):
        """执行漏洞扫描。

        支持三种模式：
        - remote: 扫描远程 OpenClaw 实例 { "mode": "remote", "url": "http://..." }
        - version: 扫描指定版本 { "mode": "version", "version": "2026.2.10" }
        - local: 扫描本地实例 { "mode": "local" }
        """
        try:
            scanner = _get_vuln_scanner()
            mode = scan_data.get("mode", "local")
            is_internal = scan_data.get("is_internal", True)
            timeout = scan_data.get("timeout", 5)

            if mode == "remote":
                url = scan_data.get("url", "")
                if not url:
                    raise HTTPException(status_code=400, detail="远程模式需要提供 URL")
                result = scanner.scan_remote(url, timeout=timeout, is_internal=is_internal)
            elif mode == "version":
                version = scan_data.get("version", "")
                if not version:
                    raise HTTPException(status_code=400, detail="版本模式需要提供版本号")
                result = scanner.scan_version(version, is_internal=is_internal)
            elif mode == "local":
                result = scanner.scan_local(is_internal=is_internal)
            else:
                raise HTTPException(status_code=400, detail=f"未知扫描模式: {mode}")

            # 保存结果到 app state
            nonlocal _vuln_scan_results
            _vuln_scan_results.append(asdict(result) if hasattr(result, '__dataclass_fields__') else result.__dict__)

            return {"status": "success", "result": {
                "target": result.target,
                "fingerprint": result.fingerprint,
                "detected_version": result.detected_version,
                "vuln_count": result.vuln_count,
                "max_severity": result.max_severity,
                "error": result.error,
                "vulns": result.vulns,
            }}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"扫描失败: {e}")

    @app.get("/api/vuln/scan/results")
    async def get_vuln_scan_results():
        """获取最近的漏洞扫描结果。"""
        nonlocal _vuln_scan_results
        if _vuln_scan_results:
            return {"status": "success", "results": _vuln_scan_results[-1]}
        return {"status": "success", "results": None}

    # ================================
    # Routes: Report Generation
    # ================================

    from fastapi.responses import Response

    @app.get("/api/report/generate")
    async def generate_report(
        report_type: str = Query(default="security", description="security | config_scan | log_scan | all"),
        format: str = Query(default="html", description="json | markdown | html"),
        hours: int = Query(default=24, ge=1, le=720),
        session_id: Optional[str] = Query(default=None),
        severity: Optional[str] = Query(default=None),
    ):
        """生成并导出安全报告。"""
        try:
            from callisto.report.generator import generate_report as _gen
            from pathlib import Path as _Path

            data_dir_path = _Path(__file__).parent / "data"
            content, mime = _gen(
                report_type=report_type,
                fmt=format,
                data_dir=data_dir_path,
                app_state=app.state,
                hours=hours,
                session_id=session_id,
                severity=severity,
            )

            ext_map = {"json": ".json", "markdown": ".md", "html": ".html"}
            ext = ext_map.get(format, ".txt")
            filename = f"callisto_report_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"

            return Response(
                content=content,
                media_type=mime,
                headers={
                    "Content-Disposition": f'attachment; filename="{filename}"',
                    "Cache-Control": "no-cache",
                },
            )
        except ValueError as e:
            raise HTTPException(status_code=400, detail=str(e))
        except Exception as e:
            raise HTTPException(status_code=500, detail=f"报告生成失败: {e}")

    # ================================
    # Routes: Tools
    # ================================

    @app.post("/api/tool/check")
    async def check_tool_call(tool_name: str, parameters: Dict[str, Any]):
        """Check if a tool call is safe"""
        try:
            # 添加 openclaw_plugin 到路径
            plugin_dir = Path(__file__).parent / "openclaw_plugin" / "callisto-skill" / "python"
            sys.path.insert(0, str(plugin_dir))

            from callisto_agent import CallistoAgent, _MALICIOUS_PATTERNS, _SENSITIVE_PATHS, _INTERNAL_PATTERNS
            import re

            alerts = []
            cmd = parameters.get("command", "") or parameters.get("cmd", "") or ""
            file_path = parameters.get("file_path", "") or parameters.get("path", "") or ""
            url = parameters.get("url", "") or parameters.get("host", "") or ""

            # 恶意命令检测
            if cmd:
                for pattern in _MALICIOUS_PATTERNS:
                    if re.search(pattern, cmd, re.IGNORECASE):
                        alerts.append({
                            "attack_type": "privilege_escalation",
                            "risk_level": "HIGH",
                            "score": 0.95,
                            "explanation": f"检测到危险命令模式：{cmd}"
                        })
                        break

            # 敏感文件读取
            if file_path:
                path_lower = file_path.lower()
                for sensitive in _SENSITIVE_PATHS:
                    if sensitive.lower() in path_lower:
                        alerts.append({
                            "attack_type": "data_exfil",
                            "risk_level": "HIGH",
                            "score": 0.85,
                            "explanation": f"尝试读取敏感文件：{file_path}"
                        })
                        break

            # 内网访问
            if url:
                for pattern in _INTERNAL_PATTERNS:
                    if re.search(pattern, url, re.IGNORECASE):
                        alerts.append({
                            "attack_type": "data_exfil",
                            "risk_level": "HIGH",
                            "score": 0.85,
                            "explanation": f"访问内网地址：{url}"
                        })
                        break

            return {
                "status": "success",
                "result": {
                    "status": "warning" if alerts else "ok",
                    "session_id": "web_check",
                    "alerts": alerts,
                    "circuit_breaker": "CLOSED",
                    "consecutive_alerts": 0
                },
            }
        except Exception as e:
            return {
                "status": "error",
                "error": str(e),
            }

    return app


# Create app instance
app = create_app()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "web_server:app",
        host="0.0.0.0",
        port=8765,
        reload=True,
    )
