#!/bin/bash
# Reactor 网络库监控系统 - 云端部署脚本

echo "╔═══════════════════════════════════════════════════╗"
echo "║     Reactor 监控系统 - 云端部署                    ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""

# 颜色定义
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m'

# 配置
PORT=8080
SERVER_IP="172.27.195.213"  # 内网IP
PUBLIC_PORT=8080            # 公网端口

echo -e "${YELLOW}1. 检查系统环境...${NC}"

# 检查g++
if ! command -v g++ &> /dev/null; then
    echo -e "${RED}✗ 未找到g++，正在安装...${NC}"
    sudo apt-get update
    sudo apt-get install -y build-essential
else
    echo -e "${GREEN}✓ g++ 已安装${NC}"
fi

# 检查make
if ! command -v make &> /dev/null; then
    echo -e "${RED}✗ 未找到make，正在安装...${NC}"
    sudo apt-get install -y make
else
    echo -e "${GREEN}✓ make 已安装${NC}"
fi

echo ""
echo -e "${YELLOW}2. 编译项目...${NC}"
make clean
if make; then
    echo -e "${GREEN}✓ 编译成功${NC}"
else
    echo -e "${RED}✗ 编译失败${NC}"
    exit 1
fi

echo ""
echo -e "${YELLOW}3. 创建必要目录...${NC}"
mkdir -p output/data output/logs output/charts
mkdir -p web
echo -e "${GREEN}✓ 目录创建完成${NC}"

echo ""
echo -e "${YELLOW}4. 配置防火墙...${NC}"
# 检查是否有ufw
if command -v ufw &> /dev/null; then
    echo "检测到ufw防火墙"
    sudo ufw allow $PORT/tcp
    echo -e "${GREEN}✓ ufw规则已添加${NC}"
else
    echo -e "${YELLOW}⚠ 未检测到ufw，请手动配置防火墙${NC}"
fi

# 阿里云安全组提示
echo ""
echo -e "${YELLOW}════════════════════════════════════════${NC}"
echo -e "${YELLOW}重要：阿里云安全组配置${NC}"
echo -e "${YELLOW}════════════════════════════════════════${NC}"
echo "请在阿里云控制台配置安全组规则："
echo "1. 登录阿里云ECS控制台"
echo "2. 找到您的实例 -> 安全组 -> 配置规则"
echo "3. 添加入方向规则："
echo "   - 端口范围: $PUBLIC_PORT/$PUBLIC_PORT"
echo "   - 授权对象: 0.0.0.0/0"
echo "   - 协议类型: TCP"
echo ""

echo -e "${YELLOW}5. 检查端口占用...${NC}"
if netstat -tuln | grep ":$PORT " > /dev/null; then
    echo -e "${RED}✗ 端口 $PORT 已被占用${NC}"
    echo "正在尝试释放端口..."
    PID=$(lsof -ti:$PORT)
    if [ ! -z "$PID" ]; then
        kill -9 $PID
        echo -e "${GREEN}✓ 已释放端口${NC}"
    fi
else
    echo -e "${GREEN}✓ 端口 $PORT 可用${NC}"
fi

echo ""
echo -e "${YELLOW}6. 启动Web服务器...${NC}"

# 停止已存在的服务
pkill -f webserver

# 后台启动服务器
nohup ./webserver $PORT > output/logs/webserver.log 2>&1 &
WEBSERVER_PID=$!

sleep 2

# 检查服务器是否启动成功
if ps -p $WEBSERVER_PID > /dev/null; then
    echo -e "${GREEN}✓ Web服务器启动成功 (PID: $WEBSERVER_PID)${NC}"
else
    echo -e "${RED}✗ Web服务器启动失败${NC}"
    echo "查看日志: tail -f output/logs/webserver.log"
    exit 1
fi

echo ""
echo "╔═══════════════════════════════════════════════════╗"
echo "║            🎉 部署成功！                           ║"
echo "╚═══════════════════════════════════════════════════╝"
echo ""
echo -e "${GREEN}访问地址：${NC}"
echo "  内网: http://$SERVER_IP:$PORT"
echo "  外网: http://您的公网IP:$PORT"
echo ""
echo -e "${GREEN}管理命令：${NC}"
echo "  查看日志: tail -f output/logs/webserver.log"
echo "  停止服务: pkill -f webserver"
echo "  重启服务: ./deploy.sh"
echo ""
echo -e "${YELLOW}提示：${NC}"
echo "  1. 请确保在阿里云安全组开放端口 $PORT"
echo "  2. 使用公网IP访问需要安全组配置"
echo "  3. 服务器已在后台运行"
echo ""

# 保存PID
echo $WEBSERVER_PID > output/webserver.pid

# 显示服务器信息
echo -e "${YELLOW}服务器状态：${NC}"
ps aux | grep webserver | grep -v grep

echo ""
echo -e "${GREEN}部署完成！按Ctrl+C可安全退出，服务器将继续运行。${NC}"
