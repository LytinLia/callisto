#!/bin/bash
#
# CALLISTO Web Dashboard 快速启动脚本
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# 检查虚拟环境
if [ ! -d ".venv" ]; then
    echo -e "${YELLOW}创建虚拟环境...${NC}"
    python3 -m venv .venv
fi

# 激活虚拟环境
source .venv/bin/activate

# 检查依赖
echo -e "${GREEN}检查依赖...${NC}"
pip install -q fastapi uvicorn sse-starlette pyyaml

# 解析参数
HOST="127.0.0.1"
PORT=8765
OPEN_BROWSER=false
RELOAD=false

while [[ $# -gt 0 ]]; do
    case $1 in
        --host)
            HOST="$2"
            shift 2
            ;;
        --port)
            PORT="$2"
            shift 2
            ;;
        --open)
            OPEN_BROWSER=true
            shift
            ;;
        --reload)
            RELOAD=true
            shift
            ;;
        --help)
            echo "用法：$0 [选项]"
            echo ""
            echo "选项:"
            echo "  --host HOST     监听地址 (默认：127.0.0.1)"
            echo "  --port PORT     监听端口 (默认：8765)"
            echo "  --open          启动后打开浏览器"
            echo "  --reload        启用自动重载"
            echo "  --help          显示帮助信息"
            exit 0
            ;;
        *)
            echo "未知选项：$1"
            exit 1
            ;;
    esac
done

# 启动服务器
echo -e "${GREEN}======================================${NC}"
echo -e "${GREEN}CALLISTO Web Dashboard${NC}"
echo -e "${GREEN}======================================${NC}"
echo -e "监听地址：${YELLOW}http://${HOST}:${PORT}${NC}"
echo -e "API 文档：${YELLOW}http://${HOST}:${PORT}/docs${NC}"
echo -e "Redoc:    ${YELLOW}http://${HOST}:${PORT}/redoc${NC}"
echo -e "${GREEN}======================================${NC}"
echo ""

# 打开浏览器
if [ "$OPEN_BROWSER" = true ]; then
    if command -v open &> /dev/null; then
        open "http://${HOST}:${PORT}/"
    elif command -v xdg-open &> /dev/null; then
        xdg-open "http://${HOST}:${PORT}/"
    fi
fi

# 启动 uvicorn
exec python -m uvicorn web_server:app \
    --host "$HOST" \
    --port "$PORT" \
    $(if [ "$RELOAD" = true ]; then echo "--reload"; fi)
