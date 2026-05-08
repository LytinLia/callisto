#!/usr/bin/env python3
"""
Skill Code Security Scanner

参考 NSF-ClawGuard src/skill-scanner.ts 实现
扫描技能代码中的风险模式

扫描类别 (8 类):
1. 危险命令调用
2. 敏感文件访问
3. 网络 API 调用
4. eval/Function 使用
5. 加密算法使用
6. 文件系统操作
7. 环境变量访问
8. 技能导入
"""

import os
import re
import json
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional, Set
from dataclasses import dataclass, asdict


@dataclass
class SkillScanResult:
    """技能扫描结果"""
    category: str
    severity: str  # critical | high | medium | low | info
    status: str    # pass | fail
    message: str
    skill_name: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None
    code_snippet: Optional[str] = None


class SkillScanner:
    """技能代码安全扫描器"""

    # ========== 1. 危险命令调用 ==========
    DANGEROUS_COMMAND_PATTERNS = [
        {
            "pattern": r'\bexec\s*\(|exec\s+\(|os\.system\s*\(|subprocess\.(call|run|Popen)\s*\(',
            "severity": "critical",
            "message": "Direct command execution detected"
        },
        {
            "pattern": r'\beval\s*\(|Function\s*\(|new\s+Function\s*\(',
            "severity": "critical",
            "message": "Dynamic code execution detected"
        },
        {
            "pattern": r'\b(__import__|importlib\.import_module)\s*\(',
            "severity": "high",
            "message": "Dynamic module import detected"
        },
        {
            "pattern": r'\bpickle\.loads?\s*\(|marshal\.loads?\s*\(',
            "severity": "high",
            "message": "Unsafe deserialization detected"
        },
        {
            "pattern": r'\byaml\.load\s*\([^)]*\)',  # yaml.load without Loader
            "severity": "high",
            "message": "Unsafe YAML loading (use yaml.safe_load)"
        },
    ]

    # ========== 2. 敏感文件访问 ==========
    SENSITIVE_FILE_PATTERNS = [
        {
            "pattern": r'["\'](/etc/shadow|/etc/passwd|/etc/sudoers)["\']',
            "severity": "critical",
            "message": "Access to sensitive system file"
        },
        {
            "pattern": r'["\'].*\.ssh/.*["\']',
            "severity": "high",
            "message": "SSH configuration access detected"
        },
        {
            "pattern": r'["\'].*\.aws/credentials["\']',
            "severity": "critical",
            "message": "AWS credentials file access"
        },
        {
            "pattern": r'["\'].*\.kube/config["\']',
            "severity": "high",
            "message": "Kubernetes config access"
        },
        {
            "pattern": r'["\'].*\.env["\']',
            "severity": "medium",
            "message": "Environment file access"
        },
        {
            "pattern": r'open\s*\(["\'].*\.(key|pem|p12|pfx)["\']',
            "severity": "high",
            "message": "Private key file access"
        },
    ]

    # ========== 3. 网络 API 调用 ==========
    NETWORK_PATTERNS = [
        {
            "pattern": r'\b(requests|urllib|httpx|aiohttp)\.(get|post|put|delete|request)\s*\(',
            "severity": "medium",
            "message": "HTTP request detected"
        },
        {
            "pattern": r'\bsocket\.connect\s*\(|socket\.socket\s*\(',
            "severity": "medium",
            "message": "Raw socket operation detected"
        },
        {
            "pattern": r'\b(xmlrpc|httplib|urllib\.request)\.',
            "severity": "low",
            "message": "Legacy HTTP library usage"
        },
        {
            "pattern": r'wss?://',
            "severity": "low",
            "message": "WebSocket connection detected"
        },
    ]

    # ========== 4. 加密算法使用 ==========
    CRYPTO_PATTERNS = [
        {
            "pattern": r'\b(hashlib\.md5|hashlib\.sha1)\s*\(',
            "severity": "medium",
            "message": "Weak hashing algorithm (MD5/SHA1)"
        },
        {
            "pattern": r'\bDES\s*\(|DES3\s*\(',
            "severity": "high",
            "message": "Deprecated encryption algorithm (DES/3DES)"
        },
        {
            "pattern": r'["\']RC4["\']|["\']MD5["\']|["\']SHA1["\']',
            "severity": "medium",
            "message": "Weak crypto algorithm reference"
        },
        {
            "pattern": r'\bCrypto\.Cipher\.PKCS1_v1_5',
            "severity": "high",
            "message": "Insecure RSA padding (use OAEP)"
        },
    ]

    # ========== 5. 文件系统操作 ==========
    FS_PATTERNS = [
        {
            "pattern": r'\b(shutil\.rmtree|os\.rmdir|pathlib\.Path\.unlink)\s*\(',
            "severity": "medium",
            "message": "File/directory deletion detected"
        },
        {
            "pattern": r'\b(shutil\.copy|os\.copyfile|pathlib\.Path\.write)\s*\(',
            "severity": "medium",
            "message": "File write/copy operation detected"
        },
        {
            "pattern": r'\bos\.chmod\s*\(|os\.chown\s*\(',
            "severity": "high",
            "message": "File permission change detected"
        },
        {
            "pattern": r'\bos\.mknod\s*\(|pathlib\.Path\.touch\s*\(',
            "severity": "low",
            "message": "File creation detected"
        },
    ]

    # ========== 6. 环境变量访问 ==========
    ENV_PATTERNS = [
        {
            "pattern": r'\bos\.environ\s*\[|os\.getenv\s*\(',
            "severity": "low",
            "message": "Environment variable access"
        },
        {
            "pattern": r'\bos\.putenv\s*\(|os\.setenv\s*\(',
            "severity": "medium",
            "message": "Environment variable modification"
        },
        {
            "pattern": r'["\']PATH["\']|["\']LD_LIBRARY_PATH["\']',
            "severity": "medium",
            "message": "Critical environment variable reference"
        },
    ]

    # ========== 7. 技能导入/加载 ==========
    SKILL_IMPORT_PATTERNS = [
        {
            "pattern": r'\b(import|from)\s+skills?\.',
            "severity": "info",
            "message": "Skill module import"
        },
        {
            "pattern": r'\b(import|from)\s+plugins?\.',
            "severity": "info",
            "message": "Plugin module import"
        },
        {
            "pattern": r'__import__\s*\([^)]*skills?',
            "severity": "medium",
            "message": "Dynamic skill import"
        },
    ]

    # ========== 8. 其他风险模式 ==========
    OTHER_RISKY_PATTERNS = [
        {
            "pattern": r'\btime\.sleep\s*\(',
            "severity": "low",
            "message": "Sleep/delay operation (potential DoS)"
        },
        {
            "pattern": r'\bthreading\.(Thread|Process|Pool)\s*\(',
            "severity": "low",
            "message": "Multi-threading/processing detected"
        },
        {
            "pattern": r'\basyncio\.(create_task|gather|wait)\s*\(',
            "severity": "low",
            "message": "Async task execution detected"
        },
        {
            "pattern": r'ctypes\.|cffi\.',
            "severity": "medium",
            "message": "Native code binding detected"
        },
    ]

    def __init__(self):
        self.all_patterns = {
            "dangerous_commands": self.DANGEROUS_COMMAND_PATTERNS,
            "sensitive_files": self.SENSITIVE_FILE_PATTERNS,
            "network_calls": self.NETWORK_PATTERNS,
            "crypto_usage": self.CRYPTO_PATTERNS,
            "fs_operations": self.FS_PATTERNS,
            "env_access": self.ENV_PATTERNS,
            "skill_imports": self.SKILL_IMPORT_PATTERNS,
            "other_risky": self.OTHER_RISKY_PATTERNS,
        }

    def scan_file(self, file_path: str, skill_name: str = None) -> List[SkillScanResult]:
        """扫描单个技能文件"""
        results = []
        path = Path(file_path)

        if not path.exists() or path.suffix not in ['.py', '.ts', '.js', '.md']:
            return results

        if skill_name is None:
            skill_name = path.stem

        try:
            content = path.read_text(encoding='utf-8')
        except Exception as e:
            return [SkillScanResult(
                category="FILE_READ_ERROR",
                severity="info",
                status="fail",
                message=f"Failed to read file: {e}",
                skill_name=skill_name,
                file_path=str(path)
            )]

        lines = content.split('\n')

        # 扫描所有模式
        for category, patterns in self.all_patterns.items():
            for pattern_info in patterns:
                try:
                    regex = re.compile(pattern_info["pattern"])
                    for line_num, line in enumerate(lines, 1):
                        match = regex.search(line)
                        if match:
                            results.append(SkillScanResult(
                                category=category,
                                severity=pattern_info["severity"],
                                status="fail",
                                message=pattern_info["message"],
                                skill_name=skill_name,
                                file_path=str(path),
                                line_number=line_num,
                                code_snippet=line.strip()[:100]
                            ))
                except re.error:
                    continue

        return results

    def scan_directory(self, dir_path: str, patterns: List[str] = None) -> List[SkillScanResult]:
        """扫描目录中的所有技能文件"""
        if patterns is None:
            patterns = ["skills/*.md", "skills/*.py", "src/skills/**/*.ts", "src/skills/**/*.js"]

        results = []
        dir_path = Path(dir_path)

        for pattern in patterns:
            for file in dir_path.glob(pattern):
                if file.is_file():
                    results.extend(self.scan_file(str(file)))

        return results

    def generate_report(self, results: List[SkillScanResult], output_format: str = "markdown") -> str:
        """生成扫描报告"""
        total = len(results)
        failed = sum(1 for r in results if r.status == "fail")

        by_category = {}
        by_severity = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}

        for r in results:
            if r.status == "fail":
                by_category[r.category] = by_category.get(r.category, 0) + 1
                by_severity[r.severity] = by_severity.get(r.severity, 0) + 1

        if output_format == "json":
            return json.dumps({
                "summary": {
                    "total": total,
                    "failed": failed,
                    "by_category": by_category,
                    "by_severity": by_severity
                },
                "results": [asdict(r) for r in results if r.status == "fail"]
            }, indent=2)

        # Markdown 格式
        report = []
        report.append("# Skill Code Security Scan Report")
        report.append("")
        report.append("## Summary")
        report.append("")
        report.append(f"- **Total Issues**: {failed}")
        report.append("")
        report.append("### Issues by Category")
        report.append("")
        for cat, count in sorted(by_category.items(), key=lambda x: -x[1]):
            report.append(f"- {cat}: {count}")
        report.append("")
        report.append("### Issues by Severity")
        report.append("")
        report.append(f"- 🔴 Critical: {by_severity['critical']}")
        report.append(f"- 🟠 High: {by_severity['high']}")
        report.append(f"- 🟡 Medium: {by_severity['medium']}")
        report.append(f"- 🟢 Low: {by_severity['low']}")
        report.append("")

        # Failed results by severity
        failed_results = sorted(
            [r for r in results if r.status == "fail"],
            key=lambda x: {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(x.severity, 5)
        )

        if failed_results:
            report.append("## Issues Detail")
            report.append("")
            for r in failed_results:
                emoji = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🟢", "info": "⚪"}.get(r.severity, "")
                report.append(f"### {emoji} [{r.severity.upper()}] {r.category}")
                report.append("")
                report.append(f"- **Skill**: {r.skill_name}")
                report.append(f"- **File**: {r.file_path}:{r.line_number}")
                report.append(f"- **Issue**: {r.message}")
                if r.code_snippet:
                    report.append(f"```")
                    report.append(r.code_snippet)
                    report.append(f"```")
                report.append("")

        return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(description="Skill Code Security Scanner")
    parser.add_argument("path", nargs="?", default=".", help="Path to scan (file or directory)")
    parser.add_argument("-o", "--output", default="skill_scan_report.md", help="Output report path")
    parser.add_argument("-f", "--format", choices=["markdown", "json"], default="markdown", help="Output format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    scanner = SkillScanner()
    path = Path(args.path)

    print(f"Scanning skills in: {path}")

    if path.is_file():
        results = scanner.scan_file(str(path))
    elif path.is_dir():
        results = scanner.scan_directory(str(path))
    else:
        print(f"Error: {path} is not a valid file or directory")
        return 1

    report = scanner.generate_report(results, output_format=args.format)

    # 写入报告
    output_path = Path(args.output)
    output_path.write_text(report, encoding='utf-8')

    print(f"Report written to: {output_path}")

    # 统计
    failed = sum(1 for r in results if r.status == "fail")
    critical = sum(1 for r in results if r.status == "fail" and r.severity == "critical")

    if args.verbose:
        print(report)

    if critical > 0:
        print(f"\n⚠️  Found {critical} critical issues!")
        return 2
    elif failed > 0:
        print(f"\n⚠️  Found {failed} issues!")
        return 1
    else:
        print("\n✅ All checks passed!")
        return 0


if __name__ == "__main__":
    exit(main())
