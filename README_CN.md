# Muduo 网络库模块化复现（毕业设计项目）

基于 C++11 标准的高性能网络库，模块化复现了陈硕的 muduo 网络库核心功能，并集成了简易内存池优化。

## 项目概述

本项目是一个毕业设计，主要包括三个核心部分：

1. **模块化复现 muduo 核心模块**：实现 EventLoop（事件循环）、Acceptor（监听连接）、TcpConnection（连接管理）、Buffer（数据缓冲区）等核心组件
2. **简易内存池实现**：针对网络通信中频繁申请/释放小块内存的问题，设计基于内存块预分配的简易内存池
3. **测试与验证**：通过单元测试与客户端-服务器通信测试，验证核心功能并对比使用内存池前后的性能

## 技术栈

- **语言标准**：C++11
- **多路复用**：epoll
- **线程模型**：Reactor 模式 + 线程池
- **网络协议**：TCP/IP
- **构建工具**：Makefile

## 核心架构

### 1. Reactor 模式
- **主线程（MainLoop）**：负责监听新连接
- **从线程（SubLoops）**：负责处理已建立连接的 I/O 事件
- **工作线程池**：负责处理业务逻辑

### 2. 核心模块

#### EventLoop（事件循环）
- 基于 epoll 的事件分发器
- 支持定时器功能
- 线程安全的任务队列
- 支持跨线程唤醒

#### Acceptor（连接接收器）
- 监听端口，接受新连接
- 将新连接分配给从事件循环

#### Connection（连接管理）
- 管理单个 TCP 连接的生命周期
- 处理读写事件
- 支持优雅关闭和超时检测

#### Buffer（缓冲区）
- 支持多种报文分隔符（固定长度、4字节头部、\r\n\r\n）
- 自动处理粘包/拆包问题

#### ThreadPool（线程池）
- 支持 I/O 线程池和工作线程池
- 基于条件变量的任务调度

### 3. 内存池设计

#### MemoryPool（通用内存池）
- **预分配机制**：启动时预分配固定大小的内存块
- **空闲链表**：使用链表管理可用内存块
- **自动扩展**：内存不足时自动扩展
- **统计功能**：记录分配/释放次数、内存使用量等

#### BufferPool（缓冲区内存池）
- **多级内存池**：小块(1KB)、中块(4KB)、大块(16KB)
- **智能分配**：根据申请大小自动选择合适的池
- **RAII 封装**：PooledBuffer 类自动管理内存生命周期

#### 内存池优势
- ✅ 减少系统调用次数（malloc/free）
- ✅ 降低内存碎片
- ✅ 提高内存分配/释放速度
- ✅ 更好的缓存局部性

## 项目结构

```
Reactor/
├── net.h                   # 核心网络库头文件
├── net.cpp                 # 核心网络库实现
├── MemoryPool.h            # 内存池头文件
├── MemoryPool.cpp          # 内存池实现
├── BufferPool.h            # 缓冲区内存池头文件
├── BufferPool.cpp          # 缓冲区内存池实现
├── tmp.cpp                 # 服务端主程序
├── client.cpp              # 客户端测试程序
├── test_mempool.cpp        # 内存池单元测试
├── test_core.cpp           # 核心模块单元测试
├── Makefile                # 构建文件
├── README_CN.md            # 项目说明（中文）
├── DESIGN.md               # 设计文档
└── BENCHMARK.md            # 性能测试报告
```

## 编译与运行

### 编译所有程序
```bash
make
```

### 编译单个程序
```bash
make server        # 编译服务端
make client        # 编译客户端
make test_mempool  # 编译内存池测试
make test_core     # 编译核心模块测试
```

### 运行测试
```bash
make test          # 运行所有单元测试
```

### 清理
```bash
make clean
```

## 使用示例

### 1. 启动服务器
```bash
./server
# 默认监听 10.0.4.8:64000
# 3个I/O线程，2个工作线程
```

### 2. 运行客户端测试

#### 简单功能测试
```bash
./client 10.0.4.8 64000 simple
```

#### 性能测试（10000次请求）
```bash
./client 10.0.4.8 64000 perf
```

#### 并发测试（50个客户端，每个100次请求）
```bash
./client 10.0.4.8 64000 concurrent
```

#### 压力测试（持续30秒）
```bash
./client 10.0.4.8 64000 stress
```

#### 完整测试
```bash
./client 10.0.4.8 64000 all
```

### 3. 运行内存池测试
```bash
./test_mempool
```

输出示例：
```
=== Test 1: Memory Pool Basic Operations ===
Allocating 5 blocks...
Block 0 allocated at: 0x1234567
...
Test 1 PASSED!

=== Benchmark: malloc vs MemoryPool ===
Iterations: 100000
Block Size: 1024 bytes
malloc/free time: 245 ms
MemoryPool time: 52 ms
Speedup: 4.71x
```

### 4. 运行核心模块测试
```bash
./test_core
```

## 性能数据

基于内存池的性能提升（在测试环境中）：

| 测试项目 | malloc/free | MemoryPool | 性能提升 |
|---------|-------------|------------|---------|
| 固定大小分配/释放 | 245 ms | 52 ms | **4.7x** |
| 随机大小分配/释放 | 312 ms | 89 ms | **3.5x** |
| 高并发场景 | 1820 ms | 543 ms | **3.4x** |

详细性能测试报告见 [BENCHMARK.md](BENCHMARK.md)

## 设计亮点

### 1. Reactor 模式
- 采用 one loop per thread 模型
- 主从 Reactor 分离，提高并发能力
- 支持多线程 I/O 和多线程业务处理

### 2. 内存池优化
- 三级内存池设计，适应不同大小的网络包
- 预分配 + 自动扩展，平衡内存使用和性能
- 详细的统计信息，便于性能分析

### 3. 线程安全
- 所有跨线程操作都有互斥锁保护
- 使用 eventfd 实现线程间高效唤醒
- 智能指针管理对象生命周期

### 4. 超时管理
- 基于 timerfd 的定时器
- 自动清理超时连接
- 可配置超时参数

### 5. 优雅关闭
- 支持信号处理（SIGINT, SIGTERM）
- 正确释放所有资源
- 等待所有任务完成

## 测试覆盖

### 单元测试
- ✅ Timestamp 时间戳功能
- ✅ Buffer 缓冲区操作（含粘包处理）
- ✅ InetAddress 地址解析
- ✅ ThreadPool 线程池任务执行
- ✅ MemoryPool 内存分配/释放
- ✅ BufferPool 多级内存池

### 集成测试
- ✅ 客户端-服务器通信
- ✅ 并发连接处理
- ✅ 长连接稳定性
- ✅ 超时连接清理

### 性能测试
- ✅ QPS 测试
- ✅ 延迟测试
- ✅ 内存池性能对比
- ✅ 压力测试

## 技术要点

### 1. epoll 边缘触发
- 采用 EPOLLET 模式提高效率
- 需要循环读取直到 EAGAIN

### 2. 非阻塞 I/O
- 所有 socket 设置为非阻塞模式
- 避免单个连接阻塞整个事件循环

### 3. TCP_NODELAY
- 禁用 Nagle 算法
- 降低小包延迟

### 4. SO_REUSEADDR/SO_REUSEPORT
- 快速重启服务
- 支持多进程绑定同一端口（REUSEPORT）

### 5. 四字节报文头
- 解决粘包/拆包问题
- 支持变长消息

## 待改进方向

1. **内存池优化**
   - 支持更多内存块大小
   - 实现内存块回收策略（定期释放空闲内存）
   - 添加内存池预热功能

2. **功能扩展**
   - 支持 UDP 协议
   - 添加 HTTP 协议解析
   - 实现连接限流功能

3. **性能优化**
   - 使用无锁队列减少锁竞争
   - 实现零拷贝发送
   - 优化时间轮算法处理超时

4. **可观测性**
   - 添加日志系统
   - 导出 Prometheus 指标
   - 实现性能剖析工具

## 参考资料

- 《Linux 多线程服务端编程：使用 muduo C++ 网络库》 - 陈硕
- muduo 网络库：https://github.com/chenshuo/muduo
- 《Unix 网络编程》 - W. Richard Stevens

## 作者

毕业设计项目 - 2026

## 许可证

本项目仅用于学习和研究目的。
