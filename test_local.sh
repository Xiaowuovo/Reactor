#!/bin/bash
# 本地测试脚本 - 用于在本地编译和测试

echo "╔═══════════════════════════════════════════════════╗"
echo "║     Reactor 本地编译测试                          ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

echo -e "${YELLOW}1. 清理旧文件...${NC}"
make clean 2>/dev/null

echo ""
echo -e "${YELLOW}2. 编译webserver...${NC}"
if g++ -std=c++11 -Wall -O2 -pthread -Isrc -c src/webserver.cpp -o src/webserver.o; then
    echo -e "${GREEN}✓ webserver.cpp 编译成功${NC}"
else
    echo -e "${RED}✗ webserver.cpp 编译失败${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}3. 链接可执行文件...${NC}"
if g++ -std=c++11 -Wall -O2 -pthread src/webserver.o -o webserver; then
    echo -e "${GREEN}✓ webserver 链接成功${NC}"
else
    echo -e "${RED}✗ webserver 链接失败${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}4. 检查web目录...${NC}"
if [ -d "web" ]; then
    echo -e "${GREEN}✓ web目录存在${NC}"
    
    if [ -f "web/index.html" ]; then
        echo -e "${GREEN}✓ index.html 存在${NC}"
    else
        echo -e "${RED}✗ index.html 不存在${NC}"
    fi
    
    if [ -f "web/style.css" ]; then
        echo -e "${GREEN}✓ style.css 存在${NC}"
    else
        echo -e "${RED}✗ style.css 不存在${NC}"
    fi
    
    if [ -f "web/app.js" ]; then
        echo -e "${GREEN}✓ app.js 存在${NC}"
    else
        echo -e "${RED}✗ app.js 不存在${NC}"
    fi
else
    echo -e "${RED}✗ web目录不存在${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}5. 创建必要目录...${NC}"
mkdir -p output/data output/logs output/charts
echo -e "${GREEN}✓ 目录创建完成${NC}"

echo ""
echo "╔═══════════════════════════════════════════════════╗"
echo "║            ✅ 编译测试完成！                       ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}可执行文件：${NC}./webserver"
echo -e "${GREEN}启动命令：${NC}./webserver 8080"
echo ""
echo -e "${YELLOW}提示：${NC}"
echo "  1. 确保端口8080未被占用"
echo "  2. 访问 http://localhost:8080"
echo "  3. 按Ctrl+C停止服务器"
echo ""
