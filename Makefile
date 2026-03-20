CXX = g++
CXXFLAGS = -std=c++11 -g -Wall -O2
LDFLAGS = -lpthread

# 目标文件
OBJS = net.o MemoryPool.o BufferPool.o

# 主程序
TARGETS = server test_mempool test_core client

.PHONY: all clean test

all: $(TARGETS)

# 服务端程序
server: tmp.cpp $(OBJS)
	$(CXX) $(CXXFLAGS) -o server tmp.cpp $(OBJS) $(LDFLAGS)

# 内存池测试
test_mempool: test_mempool.cpp MemoryPool.o BufferPool.o
	$(CXX) $(CXXFLAGS) -o test_mempool test_mempool.cpp MemoryPool.o BufferPool.o $(LDFLAGS)

# 核心模块测试
test_core: test_core.cpp $(OBJS)
	$(CXX) $(CXXFLAGS) -o test_core test_core.cpp $(OBJS) $(LDFLAGS)

# 客户端测试程序
client: client.cpp
	$(CXX) $(CXXFLAGS) -o client client.cpp $(LDFLAGS)

# 编译对象文件
net.o: net.cpp net.h
	$(CXX) $(CXXFLAGS) -c net.cpp

MemoryPool.o: MemoryPool.cpp MemoryPool.h
	$(CXX) $(CXXFLAGS) -c MemoryPool.cpp

BufferPool.o: BufferPool.cpp BufferPool.h MemoryPool.h
	$(CXX) $(CXXFLAGS) -c BufferPool.cpp

# 运行测试
test: test_mempool test_core
	@echo "========================================"
	@echo "Running Memory Pool Tests..."
	@echo "========================================"
	./test_mempool
	@echo ""
	@echo "========================================"
	@echo "Running Core Module Tests..."
	@echo "========================================"
	./test_core

# 清理
clean:
	rm -f $(TARGETS) $(OBJS) *.o

# 保留兼容性
tmp: server
