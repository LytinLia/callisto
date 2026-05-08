#!/usr/bin/env python3
"""
CALLISTO Web Dashboard 启动脚本

使用方法:
    # 开发模式 (自动重载)
    python -m callisto.web

    # 生产模式
    python -m callisto.web --host 0.0.0.0 --port 8765 --workers 4

    # 后台运行
    nohup python -m callisto.web > /tmp/callisto-web.log 2>&1 &
"""

import sys
import argparse
from pathlib import Path

# 添加项目根目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent))


def main():
    parser = argparse.ArgumentParser(description="CALLISTO Web Dashboard Server")
    parser.add_argument("--host", default="127.0.0.1", help="监听地址")
    parser.add_argument("--port", type=int, default=8765, help="监听端口")
    parser.add_argument("--workers", type=int, default=1, help="工作进程数")
    parser.add_argument("--reload", action="store_true", help="启用自动重载")
    parser.add_argument("--open", action="store_true", help="启动后打开浏览器")

    args = parser.parse_args()

    import uvicorn

    print("="*60)
    print("CALLISTO Web Dashboard")
    print("="*60)
    print(f"监听地址：http://{args.host}:{args.port}")
    print(f"API 文档：http://{args.host}:{args.port}/docs")
    print(f"Redoc:   http://{args.host}:{args.port}/redoc")
    print("="*60)

    if args.open:
        import webbrowser
        webbrowser.open(f"http://{args.host}:{args.port}/")

    uvicorn.run(
        "callisto.web_server:app",
        host=args.host,
        port=args.port,
        workers=args.workers if args.workers > 1 else None,
        reload=args.reload,
    )


if __name__ == "__main__":
    main()
