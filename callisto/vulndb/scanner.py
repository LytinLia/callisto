"""
CALLISTO 漏洞数据库加载与扫描引擎。

从 YAML 文件加载 518 条 OpenClaw 漏洞定义，
支持指纹识别（远程 HTTP 或本地版本）和漏洞匹配。
"""

import os
import re
import json
from pathlib import Path
from dataclasses import dataclass, field, asdict
from typing import Optional

import yaml

from .rule_parser import eval_rule, parse_version


# ================================
# 数据模型
# ================================

@dataclass
class VulnInfo:
    cve: str = ""
    summary: str = ""
    details: str = ""
    cvss: str = ""
    severity: str = "MEDIUM"
    security_advise: str = ""
    references: list[str] = field(default_factory=list)


@dataclass
class VulnRule:
    """一条漏洞规则，包含元数据和版本约束。"""
    id: str = ""           # CVE-ID 或 GHSA-ID
    product: str = ""      # 产品名（如 "OpenClaw"）
    info: VulnInfo = field(default_factory=VulnInfo)
    rule: str = ""         # 版本约束 DSL
    references: list[str] = field(default_factory=list)

    def matches(self, version: str, is_internal: bool = False) -> bool:
        """判断给定版本是否匹配此漏洞。"""
        if not self.rule or not self.rule.strip():
            # 空规则 = 所有版本都受影响
            return True
        try:
            return eval_rule(self.rule, version, is_internal)
        except Exception:
            # 解析失败时保守返回 True
            return True


@dataclass
class ScanTarget:
    """扫描目标。"""
    url: str = ""                          # HTTP URL（远程模式）
    version: str = ""                      # 手动指定版本
    is_internal: bool = False              # 是否为内网扫描


@dataclass
class ScanResult:
    """扫描结果。"""
    target: str = ""
    fingerprint: str = ""
    detected_version: str = ""
    vulns: list[dict] = field(default_factory=list)
    vuln_count: int = 0
    max_severity: str = "NONE"
    error: str = ""


# ================================
# 漏洞数据库
# ================================

class VulnDatabase:
    """加载和管理漏洞 YAML 定义。"""

    def __init__(self, vuln_dir: str | Path):
        self.vuln_dir = Path(vuln_dir)
        self.vulns: list[VulnRule] = []
        self._index: dict[str, list[VulnRule]] = {}  # product -> [VulnRule]

    def load(self) -> int:
        """加载所有 YAML 漏洞文件，返回加载数量。"""
        self.vulns = []
        self._index = {}

        if not self.vuln_dir.exists():
            return 0

        for yaml_path in sorted(self.vuln_dir.glob("*.yaml")):
            try:
                rule = self._load_one(yaml_path)
                if rule:
                    self.vulns.append(rule)
                    self._index.setdefault(rule.product, []).append(rule)
            except Exception:
                continue

        return len(self.vulns)

    def _load_one(self, yaml_path: Path) -> VulnRule | None:
        data = yaml.safe_load(yaml_path.read_text(encoding="utf-8"))
        if not data or not isinstance(data, dict):
            return None

        info_data = data.get("info", {})
        info = VulnInfo(
            cve=info_data.get("cve", ""),
            summary=info_data.get("summary", ""),
            details=info_data.get("details", ""),
            cvss=info_data.get("cvss", ""),
            severity=info_data.get("severity", "MEDIUM"),
            security_advise=info_data.get("security_advise", ""),
            references=info_data.get("references", []),
        )

        return VulnRule(
            id=info.cve or yaml_path.stem,
            product=info_data.get("name", ""),
            info=info,
            rule=data.get("rule", ""),
            references=data.get("references", []),
        )

    def query(self, product: str, version: str,
              is_internal: bool = False) -> list[VulnRule]:
        """查询匹配某产品+版本的漏洞列表。"""
        rules = self._index.get(product, [])
        matched = []
        for r in rules:
            if r.matches(version, is_internal):
                matched.append(r)
        return matched

    def stats(self) -> dict:
        """返回数据库统计信息。"""
        by_product = {}
        for r in self.vulns:
            by_product[r.product] = by_product.get(r.product, 0) + 1

        by_severity = {}
        for r in self.vulns:
            sev = self._normalize_severity_raw(r.info.severity)
            by_severity[sev] = by_severity.get(sev, 0) + 1

        return {
            "total": len(self.vulns),
            "by_product": by_product,
            "by_severity": by_severity,
        }

    @staticmethod
    def _normalize_severity_raw(sev: str) -> str:
        """将中文/混合格式的严重等级归一化为英文。"""
        mapping = {
            "高危": "HIGH",
            "中危": "MEDIUM",
            "低危": "LOW",
            "紧急": "CRITICAL",
            "危急": "CRITICAL",
        }
        return mapping.get(sev, sev.upper())


# ================================
# 指纹识别
# ================================

FINGERPRINT_PATTERNS = [
    ("<openclaw-app>", "body"),
    ("<title>OpenClaw Control</title>", "body"),
    ("<title>Clawdbot Control</title>", "body"),
]

VERSION_URL = "/__openclaw/control-ui-config.json"
VERSION_RE = re.compile(r'"serverVersion"\s*:\s*"([\d][^"]*)"')


def detect_fingerprint_remote(url: str, timeout: int = 5) -> dict:
    """通过 HTTP 请求检测目标是否为 OpenClaw 并提取版本。

    返回 {"found": bool, "product": str, "version": str, "error": str}
    """
    import urllib.request
    import urllib.error

    url = url.rstrip("/")
    result = {"found": False, "product": "", "version": "", "error": ""}

    # Step 1: 首页指纹匹配
    try:
        req = urllib.request.Request(url)
        req.add_header("User-Agent", "CALLISTO-Scanner/2.1")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        result["error"] = f"无法访问 {url}: {e}"
        return result

    for pattern, _ in FINGERPRINT_PATTERNS:
        if pattern.lower() in body.lower():
            result["found"] = True
            result["product"] = "OpenClaw"
            break

    if not result["found"]:
        return result

    # Step 2: 版本提取
    try:
        ver_url = url + VERSION_URL
        req = urllib.request.Request(ver_url)
        req.add_header("User-Agent", "CALLISTO-Scanner/2.1")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            ver_body = resp.read().decode("utf-8", errors="replace")
        m = VERSION_RE.search(ver_body)
        if m:
            result["version"] = m.group(1)
    except Exception:
        pass  # 版本提取失败不影响指纹识别

    return result


def detect_version_local() -> Optional[str]:
    """尝试检测本地 OpenClaw 版本。

    方法：
    1. 检查 package.json / __openclaw/control-ui-config.json
    2. 检查已安装的 npm 包版本
    """
    # 方法 1: 检查 OpenClaw 配置目录
    config_paths = [
        Path.home() / ".openclaw" / "control-ui-config.json",
        Path.home() / ".openclaw" / "config.json",
    ]
    for p in config_paths:
        if p.exists():
            try:
                data = json.loads(p.read_text())
                for key in ("serverVersion", "version"):
                    if key in data and data[key]:
                        return str(data[key])
            except Exception:
                pass

    # 方法 2: 检查 npm 全局安装
    import subprocess
    try:
        result = subprocess.run(
            ["npm", "list", "-g", "openclaw", "--json"],
            capture_output=True, text=True, timeout=10,
        )
        if result.returncode == 0:
            data = json.loads(result.stdout)
            deps = data.get("dependencies", {})
            if "openclaw" in deps:
                return deps["openclaw"].get("version", "")
    except Exception:
        pass

    return None


# ================================
# 扫描引擎
# ================================

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}


class VulnScanner:
    """OpenClaw 漏洞扫描器。"""

    def __init__(self, vuln_db: VulnDatabase):
        self.db = vuln_db

    def scan_remote(self, url: str, timeout: int = 5,
                    is_internal: bool = False) -> ScanResult:
        """扫描远程 OpenClaw 实例。"""
        result = ScanResult(target=url)

        # 指纹识别
        fp = detect_fingerprint_remote(url, timeout)
        if fp.get("error"):
            result.error = fp["error"]
            return result

        if not fp["found"]:
            result.error = "未检测到 OpenClaw 实例"
            result.fingerprint = "not_found"
            return result

        result.fingerprint = "OpenClaw"
        result.detected_version = fp["version"] or "unknown"

        # 漏洞匹配
        version = fp["version"] or ""
        vulns = self.db.query("OpenClaw", version, is_internal)

        result.vulns = [self._vuln_to_dict(v) for v in vulns]
        result.vuln_count = len(vulns)
        if vulns:
            result.max_severity = max(
                (v.info.severity.upper() for v in vulns),
                key=lambda s: SEVERITY_ORDER.get(s, 0),
            )

        return result

    def scan_version(self, version: str, is_internal: bool = False) -> ScanResult:
        """扫描指定版本（已知版本直接匹配）。"""
        result = ScanResult(
            target=f"OpenClaw v{version}",
            fingerprint="OpenClaw",
            detected_version=version,
        )

        vulns = self.db.query("OpenClaw", version, is_internal)
        result.vulns = [self._vuln_to_dict(v) for v in vulns]
        result.vuln_count = len(vulns)
        if vulns:
            result.max_severity = max(
                (v.info.severity.upper() for v in vulns),
                key=lambda s: SEVERITY_ORDER.get(s, 0),
            )

        return result

    def scan_local(self, is_internal: bool = True) -> ScanResult:
        """扫描本地 OpenClaw 实例。

        尝试检测本地版本，如果检测不到则匹配所有版本漏洞。
        """
        version = detect_version_local()

        result = ScanResult(
            target="localhost (本地检测)",
            fingerprint="OpenClaw",
            detected_version=version or "unknown",
        )

        if not version:
            # 无法检测版本时，匹配所有漏洞（最保守）
            all_vulns = self.db.query("OpenClaw", "", is_internal)
            result.error = "无法检测本地版本，显示所有已知漏洞"
            result.vulns = [self._vuln_to_dict(v) for v in all_vulns]
        else:
            vulns = self.db.query("OpenClaw", version, is_internal)
            result.vulns = [self._vuln_to_dict(v) for v in vulns]

        result.vuln_count = len(result.vulns)
        if result.vulns:
            result.max_severity = max(
                (v.get("severity", "LOW").upper() for v in result.vulns),
                key=lambda s: SEVERITY_ORDER.get(s, 0),
            )

        return result

    def _vuln_to_dict(self, v: VulnRule) -> dict:
        sev = VulnDatabase._normalize_severity_raw(v.info.severity)
        return {
            "id": v.id,
            "cve": v.info.cve,
            "summary": v.info.summary,
            "details": v.info.details,
            "severity": sev,
            "cvss": v.info.cvss,
            "rule": v.rule,
            "security_advise": v.info.security_advise,
            "references": v.references[:3],
        }
