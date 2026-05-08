#!/usr/bin/env python3
"""
Configuration Security Scanner

参考 NSF-ClawGuard src/config-scanner.ts 实现
扫描配置文件中的安全隐患

支持扫描:
- .env 文件 - 敏感变量
- config.yaml / config.json - 配置项
- SOUL.md / skills/*.md - 技能定义
- package.json / requirements.txt - 依赖

扫描规则分类:
- Token 安全 (3 规则)
- 网络安全 (7 规则)
- 会话安全 (3 规则)
- 数据保护 (3 规则)
- 插件安全 (3 规则)
- 执行安全 (6 规则)
"""

import os
import re
import json
import yaml
import argparse
from pathlib import Path
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, asdict


@dataclass
class ScanResult:
    """扫描结果"""
    rule: str
    severity: str  # critical | high | medium | low | info
    status: str    # pass | fail
    message: str
    suggestion: Optional[str] = None
    file_path: Optional[str] = None
    line_number: Optional[int] = None


class ConfigScanner:
    """配置文件安全扫描器"""

    # ========== Token 安全规则 ==========
    TOKEN_RULES = [
        {
            "id": "TOKEN_SAFETY_1",
            "severity": "critical",
            "description": "No hardcoded API tokens",
            "patterns": [
                r'(?i)(api[_-]?key|apikey)\s*[=:]\s*["\'][a-zA-Z0-9\-_]{20,}["\']',
                r'(?i)(secret|token)\s*[=:]\s*["\'][a-zA-Z0-9\-_]{16,}["\']',
            ],
            "suggestion": "Use environment variables instead of hardcoding tokens"
        },
        {
            "id": "TOKEN_SAFETY_2",
            "severity": "critical",
            "description": "No hardcoded AWS credentials",
            "patterns": [
                r'AKIA[A-Z0-9]{16}',
                r'(?i)aws[_-]?secret[_-]?access[_-]?key\s*[=:]\s*["\'][a-zA-Z0-9/+=]{40}["\']',
            ],
            "suggestion": "Use AWS IAM roles or environment variables"
        },
        {
            "id": "TOKEN_SAFETY_3",
            "severity": "high",
            "description": "No hardcoded GitHub tokens",
            "patterns": [
                r'ghp_[A-Za-z0-9]{36}',
                r'gho_[A-Za-z0-9]{36}',
                r'ghu_[A-Za-z0-9]{36}',
                r'ghs_[A-Za-z0-9]{36}',
            ],
            "suggestion": "Use GitHub Actions secrets or environment variables"
        },
    ]

    # ========== 网络安全规则 ==========
    NETWORK_RULES = [
        {
            "id": "NETWORK_SAFETY_1",
            "severity": "high",
            "description": "No localhost/127.0.0.1 allowed in production config",
            "patterns": [
                r'(?i)(host|url|endpoint)\s*[=:]\s*["\']?https?://(127\.0\.0\.1|localhost)',
            ],
            "suggestion": "Use proper service discovery or environment-specific config"
        },
        {
            "id": "NETWORK_SAFETY_2",
            "severity": "high",
            "description": "No private IP ranges in production config",
            "patterns": [
                r'(?i)(host|url|endpoint)\s*[=:]\s*["\']?https?://(10\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.)',
            ],
            "suggestion": "Use service discovery for internal services"
        },
        {
            "id": "NETWORK_SAFETY_3",
            "severity": "critical",
            "description": "No cloud metadata service URLs",
            "patterns": [
                r'169\.254\.169\.254',
                r'metadata\.google\.internal',
            ],
            "suggestion": "Accessing cloud metadata service is a security risk"
        },
        {
            "id": "NETWORK_SAFETY_4",
            "severity": "medium",
            "description": "No insecure HTTP URLs (use HTTPS)",
            "patterns": [
                r'(?i)(url|endpoint|base_url)\s*[=:]\s*["\']?http://(?!localhost|127\.0\.0\.1)',
            ],
            "suggestion": "Use HTTPS for all external communications"
        },
        {
            "id": "NETWORK_SAFETY_5",
            "severity": "high",
            "description": "No open CORS origins",
            "patterns": [
                r'(?i)cors[_-]?origins?\s*[=:]\s*["\']?\*',
            ],
            "suggestion": "Specify explicit allowed origins"
        },
        {
            "id": "NETWORK_SAFETY_6",
            "severity": "medium",
            "description": "No internal domain patterns",
            "patterns": [
                r'(?i)\.(internal|local|lan|corp|private)$',
            ],
            "suggestion": "Ensure internal domains are properly secured"
        },
        {
            "id": "NETWORK_SAFETY_7",
            "severity": "high",
            "description": "No database connection strings with credentials",
            "patterns": [
                r'(?i)(mysql|postgres|mongodb|redis)://[^:]+:[^@]+@',
            ],
            "suggestion": "Use environment variables for database credentials"
        },
    ]

    # ========== 会话安全规则 ==========
    SESSION_RULES = [
        {
            "id": "SESSION_SAFETY_1",
            "severity": "high",
            "description": "Session tokens should expire",
            "patterns": [
                r'(?i)session[_-]?expir(y|ation)\s*[=:]\s*["\']?(0|-1|never|false)',
            ],
            "suggestion": "Set a reasonable session expiration time"
        },
        {
            "id": "SESSION_SAFETY_2",
            "severity": "medium",
            "description": "Secure cookie flag should be enabled",
            "patterns": [
                r'(?i)cookie[_-]?secure\s*[=:]\s*["\']?(false|0|no)',
            ],
            "suggestion": "Enable secure cookie flag"
        },
        {
            "id": "SESSION_SAFETY_3",
            "severity": "high",
            "description": "HttpOnly cookie flag should be enabled",
            "patterns": [
                r'(?i)cookie[_-]?httponly\s*[=:]\s*["\']?(false|0|no)',
            ],
            "suggestion": "Enable HttpOnly cookie flag to prevent XSS"
        },
    ]

    # ========== 数据保护规则 ==========
    DATA_PROTECTION_RULES = [
        {
            "id": "DATA_PROTECTION_1",
            "severity": "critical",
            "description": "No plaintext passwords in config",
            "patterns": [
                r'(?i)(password|passwd|pwd)\s*[=:]\s*["\'][^"\']{8,}["\']',
            ],
            "suggestion": "Use encrypted secrets or environment variables"
        },
        {
            "id": "DATA_PROTECTION_2",
            "severity": "high",
            "description": "Encryption should be enabled",
            "patterns": [
                r'(?i)encrypt(ion|ed)?\s*[=:]\s*["\']?(false|0|no|disabled)',
            ],
            "suggestion": "Enable encryption for sensitive data"
        },
        {
            "id": "DATA_PROTECTION_3",
            "severity": "medium",
            "description": "Debug mode should be disabled",
            "patterns": [
                r'(?i)debug\s*[=:]\s*["\']?(true|1|yes|enabled)',
            ],
            "suggestion": "Disable debug mode in production"
        },
    ]

    # ========== 插件安全规则 ==========
    PLUGIN_SAFETY_RULES = [
        {
            "id": "PLUGIN_SAFETY_1",
            "severity": "high",
            "description": "No untrusted plugin sources",
            "patterns": [
                r'(?i)plugin[_-]?source\s*[=:]\s*["\']?(http://|git@)',
            ],
            "suggestion": "Use HTTPS or verified sources for plugins"
        },
        {
            "id": "PLUGIN_SAFETY_2",
            "severity": "medium",
            "description": "Plugin integrity verification",
            "patterns": [
                r'(?i)plugin[_-]?verify\s*[=:]\s*["\']?(false|0|no)',
            ],
            "suggestion": "Enable plugin integrity verification"
        },
        {
            "id": "PLUGIN_SAFETY_3",
            "severity": "high",
            "description": "No unrestricted plugin permissions",
            "patterns": [
                r'(?i)plugin[_-]?permissions?\s*[=:]\s*["\']?\*',
            ],
            "suggestion": "Specify minimum required permissions"
        },
    ]

    # ========== 执行安全规则 ==========
    EXEC_SAFETY_RULES = [
        {
            "id": "EXEC_SAFETY_1",
            "severity": "critical",
            "description": "No shell execution in config",
            "patterns": [
                r'\$\(|`.*`|\|.*sh|\|.*bash',
            ],
            "suggestion": "Avoid shell execution in configuration"
        },
        {
            "id": "EXEC_SAFETY_2",
            "severity": "high",
            "description": "No dynamic code loading",
            "patterns": [
                r'(?i)eval\s*\(|Function\s*\(|new\s+Function\s*\(',
            ],
            "suggestion": "Avoid dynamic code loading"
        },
        {
            "id": "EXEC_SAFETY_3",
            "severity": "high",
            "description": "No unsafe file operations",
            "patterns": [
                r'(?i)allow[_-]?unsafe[_-]?file\s*[=:]\s*["\']?(true|1|yes)',
            ],
            "suggestion": "Disable unsafe file operations"
        },
        {
            "id": "EXEC_SAFETY_4",
            "severity": "medium",
            "description": "Sandbox mode should be enabled",
            "patterns": [
                r'(?i)sandbox\s*[=:]\s*["\']?(false|0|no|disabled)',
            ],
            "suggestion": "Enable sandbox mode for safety"
        },
        {
            "id": "EXEC_SAFETY_5",
            "severity": "high",
            "description": "No unrestricted command execution",
            "patterns": [
                r'(?i)allow[_-]?exec\s*[=:]\s*["\']?(true|1|yes|enabled)',
            ],
            "suggestion": "Restrict command execution capabilities"
        },
        {
            "id": "EXEC_SAFETY_6",
            "severity": "medium",
            "description": "Rate limiting should be enabled",
            "patterns": [
                r'(?i)rate[_-]?limit\s*[=:]\s*["\']?(false|0|no|disabled)',
            ],
            "suggestion": "Enable rate limiting to prevent abuse"
        },
    ]

    def __init__(self):
        self.all_rules = (
            self.TOKEN_RULES +
            self.NETWORK_RULES +
            self.SESSION_RULES +
            self.DATA_PROTECTION_RULES +
            self.PLUGIN_SAFETY_RULES +
            self.EXEC_SAFETY_RULES
        )

    def scan_file(self, file_path: str) -> List[ScanResult]:
        """扫描单个文件"""
        results = []
        path = Path(file_path)

        if not path.exists():
            return results

        try:
            content = path.read_text(encoding='utf-8')
        except Exception as e:
            return [ScanResult(
                rule="FILE_READ_ERROR",
                severity="info",
                status="fail",
                message=f"Failed to read file: {e}",
                file_path=str(path)
            )]

        lines = content.split('\n')

        # 应用所有规则
        for rule in self.all_rules:
            for pattern in rule["patterns"]:
                try:
                    regex = re.compile(pattern)
                    for line_num, line in enumerate(lines, 1):
                        if regex.search(line):
                            results.append(ScanResult(
                                rule=rule["id"],
                                severity=rule["severity"],
                                status="fail",
                                message=rule["description"],
                                suggestion=rule["suggestion"],
                                file_path=str(path),
                                line_number=line_num
                            ))
                            break  # 每个规则每个文件只报告一次
                except re.error:
                    continue

        # 如果没有失败，添加通过记录
        failed_rules = {r.rule for r in results}
        for rule in self.all_rules:
            if rule["id"] not in failed_rules:
                results.append(ScanResult(
                    rule=rule["id"],
                    severity=rule["severity"],
                    status="pass",
                    message=rule["description"],
                    file_path=str(path)
                ))

        return results

    def scan_directory(self, dir_path: str, patterns: List[str] = None) -> List[ScanResult]:
        """扫描目录中的所有配置文件"""
        if patterns is None:
            patterns = [
                ".env*", "*.env",
                "config.yaml", "config.yml", "config.json",
                "*.config.yaml", "*.config.json",
                "SOUL.md", "skills/*.md",
                "package.json", "requirements.txt", "setup.py",
                "pyproject.toml", "Cargo.toml",
                ".github/workflows/*.yml",
                "docker-compose*.yml", "Dockerfile*",
            ]

        results = []
        dir_path = Path(dir_path)

        for pattern in patterns:
            for file in dir_path.glob(pattern):
                if file.is_file():
                    results.extend(self.scan_file(str(file)))

        return results

    def generate_report(self, results: List[ScanResult], output_format: str = "markdown") -> str:
        """生成扫描报告"""
        total = len(results)
        failed = sum(1 for r in results if r.status == "fail")
        passed = total - failed

        by_severity = {
            "critical": sum(1 for r in results if r.status == "fail" and r.severity == "critical"),
            "high": sum(1 for r in results if r.status == "fail" and r.severity == "high"),
            "medium": sum(1 for r in results if r.status == "fail" and r.severity == "medium"),
            "low": sum(1 for r in results if r.status == "fail" and r.severity == "low"),
            "info": sum(1 for r in results if r.status == "fail" and r.severity == "info"),
        }

        if output_format == "json":
            return json.dumps({
                "summary": {
                    "total": total,
                    "passed": passed,
                    "failed": failed,
                    "by_severity": by_severity
                },
                "results": [asdict(r) for r in results if r.status == "fail"]
            }, indent=2)

        # Markdown 格式
        report = []
        report.append("# Configuration Security Scan Report")
        report.append("")
        report.append("## Summary")
        report.append("")
        report.append(f"- **Total Checks**: {total}")
        report.append(f"- **Passed**: {passed}")
        report.append(f"- **Failed**: {failed}")
        report.append("")
        report.append("### Issues by Severity")
        report.append("")
        report.append(f"- 🔴 Critical: {by_severity['critical']}")
        report.append(f"- 🟠 High: {by_severity['high']}")
        report.append(f"- 🟡 Medium: {by_severity['medium']}")
        report.append(f"- 🟢 Low: {by_severity['low']}")
        report.append("")

        # Failed results
        failed_results = [r for r in results if r.status == "fail"]
        if failed_results:
            report.append("## Failed Checks")
            report.append("")
            report.append("| Rule | Severity | File | Line | Message | Suggestion |")
            report.append("|------|----------|------|------|---------|------------|")
            for r in failed_results:
                file_info = f"{r.file_path}:{r.line_number}" if r.line_number else r.file_path or "N/A"
                report.append(f"| {r.rule} | {r.severity} | {file_info} | {r.message} | {r.suggestion or '-'} |")
            report.append("")

        return "\n".join(report)


def main():
    parser = argparse.ArgumentParser(description="Configuration Security Scanner")
    parser.add_argument("path", nargs="?", default=".", help="Path to scan (file or directory)")
    parser.add_argument("-o", "--output", default="scan_report.md", help="Output report path")
    parser.add_argument("-f", "--format", choices=["markdown", "json"], default="markdown", help="Output format")
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")

    args = parser.parse_args()

    scanner = ConfigScanner()
    path = Path(args.path)

    print(f"Scanning: {path}")

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
