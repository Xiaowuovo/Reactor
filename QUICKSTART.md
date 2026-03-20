# 快速开始指南

本文档帮助你快速上手运行和测试本项目。

## 一、快速编译运行（5分钟）

### 1. 编译所有程序
```bash
cd Reactor
make
```

预期输出：
```
g++ -std=c++11 -g -Wall -O2 -c net.cpp
g++ -std=c++11 -g -Wall -O2 -c MemoryPool.cpp
g++ -std=c++11 -g -Wall -O2 -c BufferPool.cpp
g++ -std=c++11 -g -Wall -O2 -o server tmp.cpp net.o MemoryPool.o BufferPool.o -lpthread
g++ -std=c++11 -g -Wall -O2 -o test_mempool test_mempool.cpp MemoryPool.o BufferPool.o -lpthread
g++ -std=c++11 -g -Wall -O2 -o test_core test_core.cpp net.o MemoryPool.o BufferPool.o -lpthread
g++ -std=c++11 -g -Wall -O2 -o client client.cpp -lpthread
```

### 2. 运行单元测试
```bash
make test
```

这会运行：
- 内存池测试（test_mempool）
- 核心模块测试（test_core）

### 3. 启动服务器
```bash
./server
```

**注意**：需要修改 `tmp.cpp` 中的IP地址为你的本机IP：
```cpp
echoserver=new EchoServer("127.0.0.1", 8080, 3, 2);
//                        ^^^^^^^^^^^  ^^^^
//                        改成你的IP    端口
```

### 4. 另开一个终端，运行客户端测试
```bash
./client 127.0.0.1 8080 simple
```

看到类似输出表示成功：
```
========================================
     TCP Client Test Program
========================================
Server: 127.0.0.1:8080

=== Simple Echo Test ===
Connected to 127.0.0.1:8080
Sending: Hello, Server!
Received: reply:Hello, Server!
Simple test PASSED!
```

---

## 二、深入测试（15分钟）

### 2.1 内存池性能测试

查看内存池相比malloc的性能提升：
```bash
./test_mempool
```

关注输出中的 **Speedup** 数值（通常在3-5倍）：
```
=== Benchmark: malloc vs MemoryPool ===
Iterations: 100000
Block Size: 1024 bytes
malloc/free time: 245 ms
MemoryPool time: 52 ms
Speedup: 4.71x  <--- 这里
```

### 2.2 性能测试

测试服务器的QPS（每秒请求数）：
```bash
./client 127.0.0.1 8080 perf
```

预期输出：
```
=== Performance Test ===
Messages to send: 10000
Completed: 10000/10000
Time: 1245 ms
QPS: 8032.13 req/s  <--- 关注这个值
Avg latency: 0.1245 ms
```

### 2.3 并发测试

测试50个客户端同时连接：
```bash
./client 127.0.0.1 8080 concurrent
```

预期输出：
```
=== Concurrent Test ===
Clients: 50
Messages per client: 100
Completed: 5000/5000
Time: 892 ms
Total QPS: 5605.38 req/s
```

### 2.4 压力测试

持续30秒的压力测试：
```bash
./client 127.0.0.1 8080 stress
```

**注意**：这会对服务器施加较大压力，观察服务器是否稳定。

---

## 三、修改服务器参数

### 3.1 修改监听地址和端口

编辑 `tmp.cpp`：
```cpp
int main(int argc,char *argv[]) {
    signal(SIGTERM,Stop);
    signal(SIGINT,Stop);
    
    // 修改这里
    echoserver=new EchoServer("0.0.0.0", 9000, 3, 2);
    //                        IP地址     端口  IO线程 工作线程
    
    echoserver->Start();
    return 0;
}
```

### 3.2 调整线程数

```cpp
EchoServer(const std::string &ip, const uint16_t port, 
           int iothreadnum,    // IO线程数（建议：CPU核心数）
           int workthreadnum)  // 工作线程数（建议：2-4）
```

**建议配置**：
- **4核机器**：`EchoServer("0.0.0.0", 8080, 4, 2)`
- **8核机器**：`EchoServer("0.0.0.0", 8080, 8, 4)`

### 3.3 调整超时参数

编辑 `tmp.cpp` 中的 TcpServer 构造：
```cpp
// 在 net.h 的 EventLoop 构造函数中
EventLoop(bool mainloop, 
          int timetvl = 30,   // 定时器间隔（秒）
          int timeout = 80);  // 连接超时时间（秒）
```

重新编译：
```bash
make clean
make
```

---

## 四、调试技巧

### 4.1 查看详细日志

服务器端会输出一些调试信息，如：
- 新连接建立
- 连接关闭
- 超时清理

### 4.2 使用 gdb 调试

```bash
gdb ./server
(gdb) run
# 出现问题时按 Ctrl+C
(gdb) backtrace  # 查看调用栈
```

### 4.3 使用 valgrind 检测内存泄漏

```bash
valgrind --leak-check=full ./server
```

**注意**：valgrind 会显著降低性能，仅用于调试。

### 4.4 查看网络连接

```bash
# 查看监听端口
netstat -tlnp | grep 8080

# 查看已建立的连接
netstat -antp | grep 8080
```

---

## 五、常见问题

### Q1: 编译出错：找不到头文件

**问题**：`fatal error: sys/epoll.h: No such file or directory`

**解决**：本项目需要 Linux 环境，epoll 是 Linux 特有的。

- Windows 用户：使用 WSL（Windows Subsystem for Linux）
- macOS 用户：可以使用虚拟机或云服务器

### Q2: 服务器启动失败：bind() failed

**问题**：`bind() failed: Address already in use`

**解决**：
```bash
# 查找占用端口的进程
lsof -i :8080

# 杀死进程
kill -9 <PID>
```

或者修改 `tmp.cpp` 使用其他端口。

### Q3: 客户端连接失败

**问题**：`connection failed: Connection refused`

**解决**：
1. 确认服务器已启动
2. 检查防火墙设置
3. 确认IP和端口正确
4. 尝试使用 `127.0.0.1` 本地回环

### Q4: 运行测试时段错误

**问题**：`Segmentation fault (core dumped)`

**解决**：
```bash
# 开启core dump
ulimit -c unlimited

# 重新运行
./test_mempool

# 用gdb分析
gdb ./test_mempool core
(gdb) backtrace
```

### Q5: 性能测试结果差异大

**影响因素**：
- CPU 负载（关闭其他程序）
- 网络延迟（本地测试用 127.0.0.1）
- 系统调度（多运行几次取平均值）
- 编译优化（确保使用 -O2）

---

## 六、性能优化建议

### 6.1 系统参数调优

```bash
# 增加文件描述符限制
ulimit -n 65535

# 调整TCP参数
sudo sysctl -w net.core.somaxconn=1024
sudo sysctl -w net.ipv4.tcp_max_syn_backlog=1024
```

### 6.2 内存池参数调优

编辑 `BufferPool.cpp`：
```cpp
// 根据实际业务调整初始块数
MemoryPool BufferPool::small_pool_(1024, 500);   // 增加到500
MemoryPool BufferPool::medium_pool_(4096, 200);  // 增加到200
MemoryPool BufferPool::large_pool_(16384, 100);  // 增加到100
```

### 6.3 编译优化

```bash
# 修改 Makefile 的 CXXFLAGS
CXXFLAGS = -std=c++11 -O3 -march=native -DNDEBUG
#                      ^^  ^^^^^^^^^^^^^^  ^^^^^^
#                      O3  针对CPU优化     禁用断言
```

---

## 七、下一步学习

### 7.1 理解架构

阅读文档：
1. `README_CN.md` - 项目概述
2. `DESIGN.md` - 详细设计
3. `BENCHMARK.md` - 性能分析

### 7.2 修改业务逻辑

编辑 `net.cpp` 中的 `EchoServer::OnMessage`：
```cpp
void EchoServer::OnMessage(spConnection conn, std::string &message) {
    // 当前是简单的echo
    message = "reply:" + message;
    
    // 可以改成其他业务，例如：
    // - JSON 解析
    // - 数据库查询
    // - 消息转发
    // - ...
    
    conn->send(message.data(), message.size());
}
```

### 7.3 添加新功能

一些扩展方向：
- HTTP 协议支持
- WebSocket 支持
- 数据库连接池
- Redis 集成
- 日志系统

---

## 八、毕设答辩要点

### 8.1 核心成果展示

1. **运行演示**：
   - 启动服务器
   - 运行并发测试
   - 展示内存池性能提升

2. **代码讲解**：
   - EventLoop 事件循环机制
   - 内存池的设计和实现
   - 线程安全的处理

3. **性能数据**：
   - 引用 BENCHMARK.md 中的数据
   - 强调 4.7x 的性能提升
   - 展示内存使用优化

### 8.2 可能的问题

**Q: 为什么选择内存池优化？**
A: 网络服务器中缓冲区分配/释放非常频繁，内存池可以：
- 减少系统调用
- 降低内存碎片
- 提高性能 3-5倍

**Q: Reactor 模式的优势是什么？**
A: 
- 事件驱动，高效利用CPU
- One Loop Per Thread，负载均衡
- 非阻塞IO，支持高并发

**Q: 如何保证线程安全？**
A: 
- 互斥锁保护共享数据
- eventfd 实现线程间通信
- 智能指针管理生命周期

### 8.3 创新点总结

1. **三级内存池**：根据网络包大小智能分配
2. **完整测试体系**：单元测试 + 性能测试 + 压力测试
3. **详细文档**：设计文档 + 性能报告 + 使用指南

---

## 九、清理和重置

### 清理编译文件
```bash
make clean
```

### 完全重置
```bash
make clean
rm -f core.*
```

### 重新开始
```bash
make
./server &
./client 127.0.0.1 8080 all
```

---

## 总结

本快速开始指南涵盖了从编译、测试到调优的完整流程。如有问题，请参考：

- **功能问题** → README_CN.md
- **设计问题** → DESIGN.md  
- **性能问题** → BENCHMARK.md
- **使用问题** → 本文档（QUICKSTART.md）

祝你的毕业设计顺利！🎓
