#!/usr/bin/env python3
"""
CALLISTO 自动扫描器

功能：
1. OpenClaw 启动时自动扫描配置和技能
2. 配置文件变更时自动重新扫描
3. 新技能创建时自动扫描
4. 生成安全报告

用法：
    # 手动运行
    python scripts/auto_scanner.py --scan-all

    # 监控模式（自动扫描）
    python scripts/auto_scanner.py --watch

    # OpenClaw 启动时调用
    python scripts/auto_scanner.py --on-startup
"""

import os
import sys
import time
import json
import argparse
import hashlib
from pathlib import Path
from datetime import datetime
from typing import List, Dict, Optional, Set
import threading

# 导入扫描器
from scan_config import ConfigScanner
from scan_skills import SkillScanner


class AutoScanner:
    """自动扫描器"""

    def __init__(self, base_dir: str = None):
        self.base_dir = Path(base_dir) if base_dir else Path.home() / ".openclaw"
        self.config_scanner = ConfigScanner()
        self.skills_scanner = SkillScanner()

        # 缓存
        self.cache_file = Path(__file__).parent.parent / ".callisto_scan_cache.json"
        self.file_hashes: Dict[str, str] = {}
        self.last_scan_time: Optional[datetime] = None

        # 排除路径（本插件目录）
        self.exclude_patterns = [
            "callisto-plugin",
            "plugins/callisto",
            "node_modules",
            ".venv",
            "__pycache__",
            "callisto.egg-info",
            "dist",
            ".DS_Store",
        ]

        # 扫描目标：OpenClaw 默认配置和技能路径
        self.scan_targets = {
            "config": [
                "openclaw.json",
                "openclaw.yaml",
                "openclaw.yml",
                "exec-approvals.json",
                "agents/main/agent/**/*.json",
                "agents/main/agent/**/*.yaml",
                "agents/main/agent/**/*.yml",
            ],
            "skills": [
                "workspace/skills/**/*.md",
                "workspace/skills/**/*.py",
                "workspace/skills/**/*.js",
                "workspace/skills/**/*.ts",
                "workspace/skills/**/*.sh",
            ],
        }

        # 加载缓存
        self._load_cache()

    def _load_cache(self):
        """加载缓存"""
        if self.cache_file.exists():
            try:
                with open(self.cache_file, 'r') as f:
                    cache = json.load(f)
                    self.file_hashes = cache.get('file_hashes', {})
                    if cache.get('last_scan_time'):
                        self.last_scan_time = datetime.fromisoformat(cache['last_scan_time'])
            except Exception:
                pass

    def _save_cache(self):
        """保存缓存"""
        cache = {
            'file_hashes': self.file_hashes,
            'last_scan_time': self.last_scan_time.isoformat() if self.last_scan_time else None,
        }
        with open(self.cache_file, 'w') as f:
            json.dump(cache, f, indent=2)

    def _get_file_hash(self, file_path: Path) -> str:
        """计算文件哈希"""
        try:
            with open(file_path, 'rb') as f:
                return hashlib.md5(f.read()).hexdigest()
        except Exception:
            return ""

    def _find_files(self, patterns: List[str]) -> List[Path]:
        """根据模式查找文件，排除插件目录"""
        files = []
        for pattern in patterns:
            for file in self.base_dir.glob(pattern):
                if not file.is_file():
                    continue
                # 排除本插件目录
                rel = str(file)
                if any(ex in rel for ex in self.exclude_patterns):
                    continue
                files.append(file)
        return files

    def scan_config(self, force: bool = False) -> Dict:
        """
        扫描配置文件

        Args:
            force: 是否强制扫描（忽略缓存）

        Returns:
            扫描结果
        """
        print("\n" + "="*60)
        print("配置文件安全扫描")
        print("="*60)

        files = self._find_files(self.scan_targets["config"])
        print(f"找到 {len(files)} 个配置文件")

        # 检查变化
        changed_files = []
        for file in files:
            current_hash = self._get_file_hash(file)
            if force or self.file_hashes.get(str(file)) != current_hash:
                changed_files.append(str(file))
                self.file_hashes[str(file)] = current_hash

        if not changed_files and not force:
            print("✓ 配置文件无变化，跳过扫描")
            return {"status": "unchanged", "issues": [], "files_scanned_list": [str(f) for f in files], "timestamp": datetime.now().isoformat()}

        print(f"检测到 {len(changed_files)} 个文件变化，开始扫描...")

        # 扫描
        results = []
        for file_str in changed_files:
            results.extend(self.config_scanner.scan_file(file_str))

        # 保存缓存
        self.last_scan_time = datetime.now()
        self._save_cache()

        # 统计
        failed = [r for r in results if r.status == "fail"]

        print(f"\n扫描完成：发现 {len(failed)} 个问题")

        return {
            "status": "completed",
            "timestamp": self.last_scan_time.isoformat(),
            "files_scanned": len(changed_files),
            "files_scanned_list": [str(f) for f in files],
            "issues": [
                {
                    "rule": r.rule,
                    "severity": r.severity,
                    "file": r.file_path,
                    "message": r.message,
                    "suggestion": r.suggestion,
                }
                for r in failed
            ]
        }

    def scan_skills(self, force: bool = False) -> Dict:
        """
        扫描技能代码

        Args:
            force: 是否强制扫描（忽略缓存）

        Returns:
            扫描结果
        """
        print("\n" + "="*60)
        print("技能代码安全扫描")
        print("="*60)

        files = self._find_files(self.scan_targets["skills"])
        print(f"找到 {len(files)} 个技能文件")

        # 检查变化
        changed_files = []
        for file in files:
            current_hash = self._get_file_hash(file)
            if force or self.file_hashes.get(str(file)) != current_hash:
                changed_files.append(str(file))
                self.file_hashes[str(file)] = current_hash

        if not changed_files and not force:
            print("✓ 技能文件无变化，跳过扫描")
            return {"status": "unchanged", "issues": [], "files_scanned_list": [str(f) for f in files], "timestamp": datetime.now().isoformat()}

        print(f"检测到 {len(changed_files)} 个文件变化，开始扫描...")

        # 扫描
        results = []
        for file_str in changed_files:
            results.extend(self.skills_scanner.scan_file(file_str))

        # 保存缓存
        self.last_scan_time = datetime.now()
        self._save_cache()

        # 统计
        failed = [r for r in results if r.status == "fail"]

        print(f"\n扫描完成：发现 {len(failed)} 个问题")

        return {
            "status": "completed",
            "timestamp": self.last_scan_time.isoformat(),
            "files_scanned": len(changed_files),
            "files_scanned_list": [str(f) for f in files],
            "issues": [
                {
                    "category": r.category,
                    "severity": r.severity,
                    "skill": r.skill_name,
                    "file": r.file_path,
                    "message": r.message,
                }
                for r in failed
            ]
        }

    def scan_all(self, force: bool = False) -> Dict:
        """
        扫描所有（配置 + 技能）

        Args:
            force: 是否强制扫描

        Returns:
            合并的扫描结果
        """
        print("\n" + "="*70)
        print("CALLISTO 完整安全扫描")
        print("="*70)
        print(f"扫描目录：{self.base_dir}")
        print(f"扫描时间：{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")

        config_result = self.scan_config(force)
        skills_result = self.scan_skills(force)

        # 合并结果
        total_issues = len(config_result.get('issues', [])) + len(skills_result.get('issues', []))

        print("\n" + "="*70)
        print("扫描汇总")
        print("="*70)
        print(f"配置文件问题：{len(config_result.get('issues', []))}")
        print(f"技能代码问题：{len(skills_result.get('issues', []))}")
        print(f"总问题数：{total_issues}")

        if total_issues > 0:
            print("\n⚠️  发现安全问题，请检查报告")
        else:
            print("\n✅ 未发现安全问题")

        return {
            "status": "completed",
            "timestamp": datetime.now().isoformat(),
            "config_scan": config_result,
            "skills_scan": skills_result,
            "total_issues": total_issues,
        }

    def watch(self, interval: int = 60):
        """
        监控模式：自动检测文件变化并扫描

        Args:
            interval: 检查间隔（秒）
        """
        print("\n" + "="*70)
        print("CALLISTO 自动监控模式")
        print("="*70)
        print(f"监控间隔：{interval}秒")
        print(f"监控目录：{self.base_dir}")
        print("按 Ctrl+C 停止监控\n")

        # 首次扫描
        self.scan_all(force=True)

        print(f"\n开始监控（每{interval}秒检查一次）...")

        try:
            while True:
                time.sleep(interval)

                # 检查是否有文件变化
                all_files = (
                    self._find_files(self.scan_targets["config"]) +
                    self._find_files(self.scan_targets["skills"])
                )

                changed = False
                for file in all_files:
                    current_hash = self._get_file_hash(file)
                    if self.file_hashes.get(str(file)) != current_hash:
                        changed = True
                        break

                if changed:
                    print(f"\n[{datetime.now().strftime('%H:%M:%S')}] 检测到文件变化，重新扫描...")
                    self.scan_all(force=False)
                else:
                    print(f"[{datetime.now().strftime('%H:%M:%S')}] 无变化")

        except KeyboardInterrupt:
            print("\n\n监控已停止")

    def on_startup(self) -> int:
        """
        OpenClaw 启动时调用

        Returns:
            退出码（0=正常，1=发现严重问题）
        """
        print("\n" + "="*70)
        print("CALLISTO 启动安全检查")
        print("="*70)

        result = self.scan_all(force=True)

        # 生成报告
        report_dir = self.base_dir / "test_reports"
        report_dir.mkdir(parents=True, exist_ok=True)
        report_path = report_dir / f"startup_scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}.md"

        self._generate_report(result, report_path)

        print(f"\n报告已保存：{report_path}")

        # 检查是否有严重问题
        critical_issues = [
            i for i in (result.get('config_scan', {}).get('issues', []) +
                       result.get('skills_scan', {}).get('issues', []))
            if i.get('severity') in ['critical', 'high']
        ]

        if critical_issues:
            print(f"\n⚠️  发现 {len(critical_issues)} 个严重/高危问题！")
            print("建议先修复这些问题再运行 OpenClaw")
            return 1

        print("\n✅ 安全检查通过")
        return 0

    def _generate_report(self, result: Dict, output_path: Path):
        """生成 Markdown 报告"""
        lines = [
            "# CALLISTO 安全扫描报告",
            "",
            f"**扫描时间**: {result.get('timestamp', 'N/A')}",
            "",
            "## 汇总",
            "",
            f"- **配置文件问题**: {len(result.get('config_scan', {}).get('issues', []))}",
            f"- **技能代码问题**: {len(result.get('skills_scan', {}).get('issues', []))}",
            f"- **总问题数**: {result.get('total_issues', 0)}",
            "",
        ]

        # 配置问题
        config_issues = result.get('config_scan', {}).get('issues', [])
        if config_issues:
            lines.extend([
                "## 配置文件问题",
                "",
                "| 规则 | 严重性 | 文件 | 问题 |",
                "|------|--------|------|------|",
            ])
            for issue in config_issues:
                lines.append(
                    f"| {issue['rule']} | {issue['severity']} | {issue['file']} | {issue['message']} |"
                )
            lines.append("")

        # 技能问题
        skills_issues = result.get('skills_scan', {}).get('issues', [])
        if skills_issues:
            lines.extend([
                "## 技能代码问题",
                "",
                "| 类别 | 严重性 | 技能 | 问题 |",
                "|------|--------|------|------|",
            ])
            for issue in skills_issues:
                lines.append(
                    f"| {issue['category']} | {issue['severity']} | {issue['skill']} | {issue['message']} |"
                )
            lines.append("")

        lines.append("---")
        lines.append("*报告由 CALLISTO AutoScanner 生成*")

        output_path.write_text("\n".join(lines), encoding='utf-8')


def main():
    parser = argparse.ArgumentParser(description="CALLISTO 自动扫描器")
    parser.add_argument("--scan-all", action="store_true", help="扫描所有（配置 + 技能）")
    parser.add_argument("--scan-config", action="store_true", help="仅扫描配置")
    parser.add_argument("--scan-skills", action="store_true", help="仅扫描技能")
    parser.add_argument("--watch", type=int, default=0, help="监控模式，指定检查间隔（秒）")
    parser.add_argument("--on-startup", action="store_true", help="OpenClaw 启动时扫描")
    parser.add_argument("--force", "-f", action="store_true", help="强制扫描（忽略缓存）")
    parser.add_argument("--dir", type=str, default=str(Path(__file__).parent.parent), help="扫描目录")
    parser.add_argument("--output", type=str, default="", help="报告输出路径")

    args = parser.parse_args()
    scanner = AutoScanner(base_dir=args.dir)

    if args.watch:
        scanner.watch(interval=args.watch)
    elif args.on_startup:
        sys.exit(scanner.on_startup())
    elif args.scan_config:
        result = scanner.scan_config(force=args.force)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.scan_skills:
        result = scanner.scan_skills(force=args.force)
        print(json.dumps(result, indent=2, ensure_ascii=False))
    elif args.scan_all:
        result = scanner.scan_all(force=args.force)
        if args.output:
            scanner._generate_report(result, Path(args.output))
        print(json.dumps(result, indent=2, ensure_ascii=False))
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
