# Reactor 网络库 - 最终版构建系统
# 适配新的目录结构：src/ tests/ tools/ docs/ output/

CXX = g++
CXXFLAGS = -std=c++11 -Wall -O2 -pthread
INCLUDES = -Isrc
LDFLAGS = -pthread

# 目录定义
SRC_DIR = src
TEST_DIR = tests
TOOL_DIR = tools
DOC_DIR = docs
OUTPUT_DIR = output

# 颜色输出
GREEN = \033[0;32m
YELLOW = \033[1;33m
CYAN = \033[0;36m
NC = \033[0m

# 源文件
CORE_SRCS = $(SRC_DIR)/net.cpp $(SRC_DIR)/MemoryPool.cpp $(SRC_DIR)/BufferPool.cpp
CORE_OBJS = $(CORE_SRCS:.cpp=.o)

# 可执行文件
DEMO = demo
SERVER = server
CLIENT = client
WEBSERVER = webserver
TEST_MEMPOOL = test_mempool
TEST_CORE = test_core
TEST_NETWORK = test_network

TARGETS = $(DEMO) $(SERVER) $(CLIENT) $(WEBSERVER) $(TEST_MEMPOOL) $(TEST_CORE) $(TEST_NETWORK)

# ===== 主目标 =====

all: banner directories $(TARGETS)
	@echo ""
	@echo "$(GREEN)========================================$(NC)"
	@echo "$(GREEN)✅ 编译完成！$(NC)"
	@echo "$(GREEN)========================================$(NC)"
	@echo ""
	@echo "$(CYAN)可执行文件：$(NC)"
	@echo "  ./demo          - 交互式演示系统 $(YELLOW)(推荐)$(NC)"
	@echo "  ./webserver     - Web监控系统 $(YELLOW)(毕设展示)$(NC)"
	@echo "  ./server        - 服务器程序"
	@echo "  ./client        - 客户端程序"
	@echo "  ./test_mempool  - 内存池测试"
	@echo "  ./test_core     - 核心测试"
	@echo "  ./test_network  - 网络测试"
	@echo ""
	@echo "$(CYAN)快速命令：$(NC)"
	@echo "  make run-web    - 启动Web监控系统 $(YELLOW)(毕设演示)$(NC)"
	@echo "  make run-demo   - 运行演示系统"
	@echo "  make test       - 运行所有测试"
	@echo "  make visualize  - 生成图表"
	@echo ""

banner:
	@echo "$(YELLOW)"
	@echo "╔═══════════════════════════════════════════════════╗"
	@echo "║     Reactor 网络库 - 毕业设计项目构建系统         ║"
	@echo "╚═══════════════════════════════════════════════════╝"
	@echo "$(NC)"

directories:
	@mkdir -p $(OUTPUT_DIR)/data $(OUTPUT_DIR)/logs $(OUTPUT_DIR)/charts

# ===== 编译规则 =====

$(DEMO): $(SRC_DIR)/demo.o $(CORE_OBJS)
	@echo "$(YELLOW)链接 demo...$(NC)"
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "$(GREEN)✓ demo 完成$(NC)"

$(SERVER): $(SRC_DIR)/server.o $(CORE_OBJS)
	@echo "$(YELLOW)链接 server...$(NC)"
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "$(GREEN)✓ server 完成$(NC)"

$(CLIENT): $(SRC_DIR)/client.o $(CORE_OBJS)
	@echo "$(YELLOW)链接 client...$(NC)"
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "$(GREEN)✓ client 完成$(NC)"

$(WEBSERVER): $(SRC_DIR)/webserver.o $(CORE_OBJS)
	@echo "$(YELLOW)链接 webserver...$(NC)"
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "$(GREEN)✓ webserver 完成$(NC)"

$(TEST_MEMPOOL): $(TEST_DIR)/test_mempool.o $(CORE_OBJS)
	@echo "$(YELLOW)链接 test_mempool...$(NC)"
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "$(GREEN)✓ test_mempool 完成$(NC)"

$(TEST_CORE): $(TEST_DIR)/test_core.o $(CORE_OBJS)
	@echo "$(YELLOW)链接 test_core...$(NC)"
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "$(GREEN)✓ test_core 完成$(NC)"

$(TEST_NETWORK): $(TEST_DIR)/test_network.o $(CORE_OBJS)
	@echo "$(YELLOW)链接 test_network...$(NC)"
	$(CXX) $(CXXFLAGS) -o $@ $^ $(LDFLAGS)
	@echo "$(GREEN)✓ test_network 完成$(NC)"

%.o: %.cpp
	@echo "$(YELLOW)编译 $<$(NC)"
	$(CXX) $(CXXFLAGS) $(INCLUDES) -c $< -o $@

# ===== 快捷命令 =====

run-web: $(WEBSERVER)
	@echo "$(GREEN)启动Web监控系统...$(NC)"
	@echo "$(CYAN)访问: http://localhost:8080$(NC)"
	@./$(WEBSERVER)

run-demo: $(DEMO)
	@echo "$(GREEN)启动演示系统...$(NC)"
	@./$(DEMO)

test: $(TEST_MEMPOOL) $(TEST_CORE) $(TEST_NETWORK)
	@echo "$(CYAN)========================================$(NC)"
	@echo "$(CYAN)运行测试套件...$(NC)"
	@echo "$(CYAN)========================================$(NC)"
	@echo ""
	@echo "$(YELLOW)[1/3] 核心测试...$(NC)"
	@./$(TEST_CORE) && echo "$(GREEN)✓ 通过$(NC)" || echo "$(RED)✗ 失败$(NC)"
	@echo ""
	@echo "$(YELLOW)[2/3] 内存池测试...$(NC)"
	@./$(TEST_MEMPOOL) && echo "$(GREEN)✓ 通过$(NC)" || echo "$(RED)✗ 失败$(NC)"
	@echo ""
	@echo "$(YELLOW)[3/3] 网络测试...$(NC)"
	@./$(TEST_NETWORK) && echo "$(GREEN)✓ 通过$(NC)" || echo "$(RED)✗ 失败$(NC)"
	@echo ""

visualize: $(TEST_MEMPOOL) $(TEST_NETWORK)
	@echo "$(CYAN)生成性能数据和图表...$(NC)"
	@./$(TEST_MEMPOOL)
	@./$(TEST_NETWORK)
	@python3 $(TOOL_DIR)/visualize_all.py

answer: $(DEMO)
	@echo "$(CYAN)========================================$(NC)"
	@echo "$(CYAN)🎓 答辩演示模式$(NC)"
	@echo "$(CYAN)========================================$(NC)"
	@./$(DEMO)

clean:
	@echo "$(YELLOW)清理编译文件...$(NC)"
	@rm -f $(SRC_DIR)/*.o $(TEST_DIR)/*.o
	@rm -f $(TARGETS)
	@echo "$(GREEN)✓ 清理完成$(NC)"

distclean: clean
	@echo "$(YELLOW)深度清理...$(NC)"
	@rm -rf $(OUTPUT_DIR)
	@echo "$(GREEN)✓ 深度清理完成$(NC)"

help:
	@echo "$(CYAN)Reactor 网络库构建系统$(NC)"
	@echo ""
	@echo "$(GREEN)编译：$(NC)"
	@echo "  make           - 编译所有程序"
	@echo "  make run-web   - 编译并启动Web监控系统 $(YELLOW)(毕设)$(NC)"
	@echo "  make run-demo  - 编译并运行演示系统"
	@echo "  make server    - 仅编译服务器"
	@echo "  make client    - 仅编译客户端"
	@echo ""
	@echo "$(GREEN)测试：$(NC)"
	@echo "  make test      - 运行所有测试"
	@echo "  make visualize - 生成性能图表"
	@echo ""
	@echo "$(GREEN)答辩：$(NC)"
	@echo "  make answer    - 答辩演示模式"
	@echo ""
	@echo "$(GREEN)清理：$(NC)"
	@echo "  make clean     - 清理编译文件"
	@echo "  make distclean - 深度清理"
	@echo ""

.PHONY: all banner directories run-web run-demo test visualize answer clean distclean help

# 依赖关系
$(SRC_DIR)/demo.o: $(SRC_DIR)/demo.cpp $(SRC_DIR)/TerminalUI.h $(SRC_DIR)/MemoryPool.h $(SRC_DIR)/BufferPool.h
$(SRC_DIR)/server.o: $(SRC_DIR)/server.cpp $(SRC_DIR)/net.h
$(SRC_DIR)/client.o: $(SRC_DIR)/client.cpp $(SRC_DIR)/net.h
$(SRC_DIR)/webserver.o: $(SRC_DIR)/webserver.cpp $(SRC_DIR)/HttpServer.h $(SRC_DIR)/net.h
$(TEST_DIR)/test_mempool.o: $(TEST_DIR)/test_mempool.cpp $(SRC_DIR)/MemoryPool.h $(SRC_DIR)/BufferPool.h
$(TEST_DIR)/test_core.o: $(TEST_DIR)/test_core.cpp $(SRC_DIR)/net.h
$(TEST_DIR)/test_network.o: $(TEST_DIR)/test_network.cpp $(SRC_DIR)/TerminalUI.h
$(SRC_DIR)/net.o: $(SRC_DIR)/net.cpp $(SRC_DIR)/net.h
$(SRC_DIR)/MemoryPool.o: $(SRC_DIR)/MemoryPool.cpp $(SRC_DIR)/MemoryPool.h
$(SRC_DIR)/BufferPool.o: $(SRC_DIR)/BufferPool.cpp $(SRC_DIR)/BufferPool.h $(SRC_DIR)/MemoryPool.h
