#!/bin/bash
# ============================================================================
# Muduo 网络库的重构与内存池的实现 - 一键启动脚本
# ============================================================================

set -e

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

# 配置
PORT=${1:-8080}
PROJECT_DIR="$(cd "$(dirname "$0")" && pwd)"

echo -e "${CYAN}"
echo "╔═══════════════════════════════════════════════════════════════╗"
echo "║     🚀 Muduo 网络库的重构与内存池的实现 - 一键启动      ║"
echo "╚═══════════════════════════════════════════════════════════════╝"
echo -e "${NC}"

cd "$PROJECT_DIR"

# 检查并创建必要目录
echo -e "${BLUE}📁 检查目录结构...${NC}"
mkdir -p output/data output/logs output/charts

# 编译Web服务器
echo -e "${BLUE}🔨 编译Web服务器...${NC}"
if [ -f "src/webserver.cpp" ]; then
    g++ -std=c++11 -O2 -pthread -Isrc src/webserver.cpp -o webserver 2>/dev/null
    if [ $? -eq 0 ]; then
        echo -e "${GREEN}✅ Web服务器编译成功${NC}"
    else
        echo -e "${RED}❌ 编译失败，请检查代码${NC}"
        exit 1
    fi
else
    echo -e "${RED}❌ 找不到 src/webserver.cpp${NC}"
    exit 1
fi

# 检查端口是否被占用
if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1; then
    echo -e "${YELLOW}⚠️  端口 $PORT 已被占用，尝试关闭...${NC}"
    kill $(lsof -Pi :$PORT -sTCP:LISTEN -t) 2>/dev/null || true
    sleep 1
fi

# 启动服务器
echo -e "${GREEN}🌐 启动Web服务器 (端口: $PORT)...${NC}"
echo ""
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}  访问地址: http://localhost:$PORT${NC}"
echo -e "${CYAN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

./webserver $PORT
