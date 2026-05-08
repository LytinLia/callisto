#!/usr/bin/env python3
"""
CALLISTO - OpenClaw 安全包装器

用法：
    python -m callisto.openclaw [--block] [--report] [openclaw 参数...]

示例：
    python -m callisto.openclaw
    python -m callisto.openclaw --block
    python -m callisto.openclaw --block --report
"""

import subprocess
import sys
import os
import signal
import time
from pathlib import Path

# 配置
OPENCLAW_LOG_DIR = os.path.expanduser("~/.openclaw/agents/main/sessions")
CALLISTO_DIR = Path(__file__).parent.parent
MONITOR_SCRIPT = CALLISTO_DIR / "scripts" / "monitor_openclaw.py"
PYTHON_VENV = CALLISTO_DIR / ".venv"


def main():
    import argparse

    parser = argparse.ArgumentParser(
        description="CALLISTO - OpenClaw 安全包装器",
        add_help=False
    )
    parser.add_argument("--block", action="store_true", help="启用自动熔断")
    parser.add_argument("--report", action="store_true", help="生成检测报告")
    parser.add_argument("-h", "--help", action="store_true", help="显示帮助")

    # 分离已知和未知参数
    known_args, openclaw_args = parser.parse_known_args()

    if known_args.help:
        print("=" * 60)
        print("CALLISTO - OpenClaw 安全包装器")
        print("=" * 60)
        print()
        print("用法:")
        print("  python -m callisto.openclaw [--block] [--report] [openclaw 参数...]")
        print()
        print("选项:")
        print("  --block   启用自动熔断（达到风险阈值自动阻断会话）")
        print("  --report  生成检测报告")
        print("  -h, --help  显示帮助")
        print()
        print("示例:")
        print("  python -m callisto.openclaw")
        print("  python -m callisto.openclaw --block")
        print("  python -m callisto.openclaw --block --report")
        print()
        sys.exit(0)

    # 确定 Python 命令
    if PYTHON_VENV.exists():
        python_cmd = str(PYTHON_VENV / "bin" / "python")
    else:
        python_cmd = "python3"

    # 确保日志目录存在
    os.makedirs(OPENCLAW_LOG_DIR, exist_ok=True)

    # 构建监控命令
    monitor_opts = ["--monitor", "--log-file", f"{OPENCLAW_LOG_DIR}/*.jsonl"]
    if known_args.block:
        monitor_opts.append("--block")
    if known_args.report:
        monitor_opts.append("--report")

    monitor_cmd = [python_cmd, str(MONITOR_SCRIPT)] + monitor_opts

    print("=" * 60)
    print("CALLISTO - OpenClaw 安全监控启动器")
    print("=" * 60)
    print(f"日志目录：{OPENCLAW_LOG_DIR}")
    print(f"自动熔断：{'开启' if known_args.block else '关闭'}")
    print(f"生成报告：{'开启' if known_args.report else '关闭'}")
    print()

    # 启动监控进程
    print("正在启动 CALLISTO 监控...")
    monitor_proc = subprocess.Popen(monitor_cmd)
    time.sleep(2)  # 等待监控启动

    # 检查监控进程
    if monitor_proc.poll() is not None:
        print("错误：监控进程启动失败")
        sys.exit(1)

    print(f"✓ 监控已启动 (PID: {monitor_proc.pid})")
    print()
    print("正在启动 OpenClaw...")
    print("提示：OpenClaw 的所有操作将实时被 CALLISTO 监控")
    print("按 Ctrl+C 可以同时停止监控和 OpenClaw")
    print()

    # 信号处理
    def cleanup(signum=None, frame=None):
        print("\n正在停止监控...")
        monitor_proc.terminate()
        try:
            monitor_proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            monitor_proc.kill()
        print("✓ 监控已停止")
        sys.exit(0)

    signal.signal(signal.SIGINT, cleanup)
    signal.signal(signal.SIGTERM, cleanup)

    # 启动 OpenClaw
    try:
        result = subprocess.run(["openclaw"] + openclaw_args)
        cleanup()
    except Exception as e:
        print(f"OpenClaw 错误：{e}")
        cleanup()


if __name__ == "__main__":
    main()
