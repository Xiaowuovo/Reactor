# 设计文档

## 1. 整体架构

### 1.1 Reactor 模式

本项目采用经典的 Reactor 模式，具体实现为 **主从 Reactor + 线程池** 模型：

```
┌─────────────────────────────────────────────────────────┐
│                    Main Reactor                         │
│  (Acceptor + MainLoop)                                  │
│  - 监听端口                                              │
│  - 接受新连接                                            │
└────────────┬────────────────────────────────────────────┘
             │ 轮流分配
             ▼
┌────────────────────────────────────────────────────────┐
│              Sub Reactors (IO Threads)                 │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐             │
│  │ SubLoop1 │  │ SubLoop2 │  │ SubLoop3 │             │
│  │  epoll   │  │  epoll   │  │  epoll   │             │
│  └──────────┘  └──────────┘  └──────────┘             │
│  - 处理已连接的读写事件                                 │
│  - 管理连接生命周期                                     │
└────────────┬───────────────────────────────────────────┘
             │ 投递任务
             ▼
┌────────────────────────────────────────────────────────┐
│              Work Thread Pool                          │
│  - 处理业务逻辑                                         │
│  - 避免阻塞 IO 线程                                     │
└────────────────────────────────────────────────────────┘
```

### 1.2 线程模型

- **主线程（Main Thread）**：运行 MainLoop，只负责 accept 新连接
- **IO 线程（IO Threads）**：运行 SubLoops，每个线程一个 EventLoop，处理连接的 I/O 事件
- **工作线程（Worker Threads）**：处理耗时的业务逻辑，避免阻塞 IO 线程

### 1.3 关键特性

- **One Loop Per Thread**：每个 IO 线程有且仅有一个 EventLoop
- **线程安全**：跨线程操作通过 eventfd + 任务队列实现
- **负载均衡**：新连接按 fd 哈希分配给不同的 SubLoop
- **超时管理**：基于 timerfd 的定时器，自动清理超时连接

---

## 2. 核心模块设计

### 2.1 EventLoop（事件循环）

**职责**：
- 封装 epoll，管理 Channel 的注册/删除
- 运行事件循环，分发事件到各个 Channel
- 支持定时器功能
- 提供跨线程任务投递机制

**核心成员**：
```cpp
class EventLoop {
private:
    std::unique_ptr<Epoll> ep_;              // epoll 封装
    int wakeupfd_;                           // eventfd，用于唤醒
    int timerfd_;                            // 定时器fd
    std::queue<std::function<void()>> taskqueue_;  // 任务队列
    std::map<int, spConnection> conns_;      // 管理的连接
    std::mutex task_mtx_;                    // 任务队列锁
    std::mutex mtx_;                         // 连接容器锁
    bool mainloop_;                          // 是否为主循环
};
```

**关键流程**：
1. **事件循环**：`ep_->loop()` → 获取就绪事件 → `ch->handleevent()` 分发
2. **跨线程唤醒**：其他线程调用 `queueinloop()` → 写 wakeupfd_ → EventLoop 被唤醒 → 执行任务
3. **定时器**：timerfd 触发 → `handletimer()` → 遍历连接检查超时

### 2.2 Channel（通道）

**职责**：
- 封装文件描述符及其感兴趣的事件
- 保存事件回调函数
- 在 EventLoop 中作为事件分发的基本单元

**核心成员**：
```cpp
class Channel {
private:
    int fd_;                              // 文件描述符
    uint32_t events_;                     // 监视的事件
    uint32_t revents_;                    // 已发生的事件
    std::function<void()> readcallback_;  // 读回调
    std::function<void()> writecallback_; // 写回调
    std::function<void()> closecallback_; // 关闭回调
    std::function<void()> errorcallback_; // 错误回调
};
```

**事件处理流程**：
```
epoll_wait 返回 → Channel::setrevents() → Channel::handleevent() →
    → EPOLLRDHUP: closecallback_()
    → EPOLLIN:    readcallback_()
    → EPOLLOUT:   writecallback_()
    → 其他:       errorcallback_()
```

### 2.3 Acceptor（接收器）

**职责**：
- 创建监听 socket
- 在 MainLoop 中监听 EPOLLIN 事件
- 接受新连接并回调 TcpServer

**核心流程**：
```
listen socket 可读 → acceptchannel_ 触发 → Acceptor::newconnection()
    → servsock_.accept() 获取客户端 fd
    → 创建 Socket 对象
    → 回调 TcpServer::newconnection()
```

### 2.4 Connection（连接）

**职责**：
- 管理单个 TCP 连接的生命周期
- 处理读写事件
- 管理接收/发送缓冲区
- 处理连接关闭和错误

**核心成员**：
```cpp
class Connection {
private:
    std::unique_ptr<Socket> clientsock_;     // 客户端 socket
    std::unique_ptr<Channel> clientchannel_; // 对应的 channel
    Buffer inputbuffer_;                     // 接收缓冲区
    Buffer outputbuffer_;                    // 发送缓冲区
    Timestamp lastatime_;                    // 最后活跃时间
    std::atomic_bool disconnect_;            // 是否已断开
};
```

**读事件处理**：
```
EPOLLIN 触发 → Connection::onmessage()
    → 循环 read() 直到 EAGAIN
    → 数据追加到 inputbuffer_
    → inputbuffer_.pickmessage() 拆包
    → 回调 TcpServer::onmessage() 处理业务
```

**写事件处理**：
```
应用层调用 Connection::send()
    → 数据追加到 outputbuffer_
    → enablewriting() 注册写事件
    → EPOLLOUT 触发 → Connection::writecallback()
    → send() 发送 outputbuffer_
    → 发送完成 → disablewriting()
```

### 2.5 TcpServer（服务器）

**职责**：
- 创建主从 EventLoop
- 管理 Acceptor
- 管理所有 Connection
- 提供应用层回调接口

**核心成员**：
```cpp
class TcpServer {
private:
    std::unique_ptr<EventLoop> mainloop_;          // 主事件循环
    std::vector<std::unique_ptr<EventLoop>> subloops_; // 从事件循环
    Acceptor acceptor_;                            // 监听器
    ThreadPool threadpool_;                        // IO线程池
    std::map<int, spConnection> conns_;            // 所有连接
};
```

**新连接处理流程**：
```
Acceptor 接受连接 → TcpServer::newconnection()
    → 选择一个 SubLoop (fd % threadnum_)
    → 创建 Connection 对象
    → 设置各种回调
    → 保存到 conns_ 和 EventLoop::conns_
    → Connection 开始监听读事件
```

### 2.6 Buffer（缓冲区）

**职责**：
- 管理接收/发送缓冲区
- 处理粘包/拆包问题
- 支持多种报文格式

**支持的分隔符**：
- **sep=0**：无分隔符，适用于固定长度协议
- **sep=1**：四字节报头（网络字节序），适用于变长协议
- **sep=2**：`\r\n\r\n` 分隔符，适用于 HTTP

**四字节报头协议**：
```
┌────────────┬────────────────────────┐
│ 4 字节长度 │    消息内容 (len 字节)   │
└────────────┴────────────────────────┘
```

### 2.7 ThreadPool（线程池）

**职责**：
- 管理固定数量的工作线程
- 提供任务队列
- 支持 IO 线程池和工作线程池

**工作原理**：
```
线程启动 → 等待条件变量 → 从任务队列取任务 → 执行 → 继续等待
```

---

## 3. 内存池设计

### 3.1 设计目标

网络服务器中，缓冲区的分配/释放非常频繁：
- 每个连接都有接收/发送缓冲区
- 报文拆包需要临时缓冲区
- 频繁调用 `new`/`delete` 或 `malloc`/`free` 会导致：
  - 系统调用开销大
  - 内存碎片增加
  - 性能下降

**内存池的优势**：
- ✅ 预分配，减少系统调用
- ✅ 固定大小块，减少碎片
- ✅ 快速分配/释放（O(1)）
- ✅ 更好的缓存局部性

### 3.2 MemoryPool（通用内存池）

**核心思想**：
- 预分配一大块内存，切分成固定大小的小块
- 使用空闲链表管理可用块
- 分配时从链表头取，释放时加入链表头

**数据结构**：
```cpp
struct MemoryBlock {
    MemoryBlock* next;  // 空闲链表指针
};

class MemoryPool {
private:
    size_t block_size_;          // 每块大小
    MemoryBlock* free_list_;     // 空闲链表
    std::vector<void*> chunks_;  // 大块内存指针
};
```

**内存布局**：
```
Chunk 1: ┌──────┬──────┬──────┬──────┐
         │Block1│Block2│Block3│Block4│ ...
         └──┬───┴──┬───┴──┬───┴──────┘
            │      │      │
Free List:  ▼      ▼      ▼     NULL
          Block1→Block2→Block3→
```

**分配流程**：
```cpp
void* allocate() {
    if (free_list_ == nullptr) {
        expand(50);  // 扩展50个块
    }
    MemoryBlock* block = free_list_;
    free_list_ = block->next;  // 头部出链
    return block;
}
```

**释放流程**：
```cpp
void deallocate(void* ptr) {
    MemoryBlock* block = static_cast<MemoryBlock*>(ptr);
    block->next = free_list_;
    free_list_ = block;  // 头部入链
}
```

### 3.3 BufferPool（分级内存池）

**设计思路**：
网络包大小差异较大（几十字节到几十KB），单一大小的内存池不够高效。

**三级内存池**：
- **Small Pool**：1KB，适用于小消息（聊天消息、控制命令）
- **Medium Pool**：4KB，适用于中等消息（JSON数据、小文件）
- **Large Pool**：16KB，适用于大消息（大文件、视频流）

**智能分配策略**：
```cpp
void* BufferPool::allocate(size_t size) {
    if (size <= 1024)       return small_pool_.allocate();
    else if (size <= 4096)  return medium_pool_.allocate();
    else if (size <= 16384) return large_pool_.allocate();
    else                    return malloc(size);  // 超大直接malloc
}
```

**优势**：
- 避免内存浪费（小消息不会占用大块）
- 提高命中率（大部分网络包在1-4KB范围）
- 灵活处理超大包（降级到 malloc）

### 3.4 PooledBuffer（RAII 封装）

**设计目的**：
自动管理内存生命周期，避免内存泄漏。

```cpp
class PooledBuffer {
public:
    PooledBuffer(size_t size) {
        data_ = BufferPool::allocate(size);
    }
    
    ~PooledBuffer() {
        BufferPool::deallocate(data_, size_);
    }
    
    // 禁用拷贝，支持移动
    PooledBuffer(const PooledBuffer&) = delete;
    PooledBuffer(PooledBuffer&&) noexcept;
};
```

**使用示例**：
```cpp
{
    PooledBuffer buf(4096);
    // 使用 buf.data()
    // ...
}  // 自动释放回内存池
```

---

## 4. 线程安全设计

### 4.1 跨线程通信

**问题**：工作线程需要给 IO 线程投递发送任务，如何唤醒 IO 线程？

**解决方案**：eventfd + 任务队列

```cpp
// 工作线程调用
void EventLoop::queueinloop(std::function<void()> fn) {
    {
        std::lock_guard<std::mutex> lock(task_mtx_);
        taskqueue_.push(fn);  // 任务入队
    }
    wakeup();  // 唤醒 IO 线程
}

void EventLoop::wakeup() {
    uint64_t val = 1;
    write(wakeupfd_, &val, sizeof(val));  // 写 eventfd
}

// IO 线程被唤醒后
void EventLoop::handlewakeup() {
    uint64_t val;
    read(wakeupfd_, &val, sizeof(val));  // 读掉数据
    
    std::lock_guard<std::mutex> lock(task_mtx_);
    while (!taskqueue_.empty()) {
        auto fn = taskqueue_.front();
        taskqueue_.pop();
        fn();  // 执行任务
    }
}
```

### 4.2 连接管理的线程安全

**问题**：
- TcpServer 的 `conns_` 在主线程访问
- EventLoop 的 `conns_` 在 IO 线程访问
- 超时检查需要遍历删除

**解决方案**：
- TcpServer 的 `conns_` 用 `mutex_` 保护
- EventLoop 的 `conns_` 用 `mtx_` 保护
- 删除操作需要两个锁配合

```cpp
// 超时检查（在 IO 线程）
void EventLoop::handletimer() {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto it = conns_.begin(); it != conns_.end(); ) {
        if (it->second->timeout(now, timeout_)) {
            timercallback_(it->first);  // 回调 TcpServer::removeconn
            it = conns_.erase(it);      // 从 EventLoop 删除
        } else {
            ++it;
        }
    }
}

// TcpServer::removeconn（可能在 IO 线程调用）
void TcpServer::removeconn(int fd) {
    std::lock_guard<std::mutex> lock(mtx_);
    conns_.erase(fd);  // 从 TcpServer 删除
}
```

### 4.3 智能指针管理生命周期

**问题**：Connection 对象被多处引用，如何安全释放？

**解决方案**：`std::shared_ptr` + `enable_shared_from_this`

```cpp
class Connection : public std::enable_shared_from_this<Connection> {
    void onmessage() {
        // 延长生命周期，防止回调中被删除
        onmessagecallback_(shared_from_this(), message);
    }
};
```

---

## 5. 性能优化点

### 5.1 边缘触发（ET）

**优势**：
- 减少 epoll_wait 调用次数
- 只在状态变化时触发

**代价**：
- 必须一次性读完，直到 EAGAIN
- 代码复杂度增加

```cpp
void Channel::useet() {
    events_ |= EPOLLET;
}
```

### 5.2 TCP 优化选项

```cpp
socket.settcpnodelay(true);   // 禁用 Nagle，降低延迟
socket.setkeepalive(true);    // 启用心跳检测
socket.setreuseaddr(true);    // 快速重启
socket.setreuseport(true);    // 多进程监听
```

### 5.3 内存池预分配

**启动时预分配**：
- Small Pool: 200 * 1KB = 200KB
- Medium Pool: 100 * 4KB = 400KB
- Large Pool: 50 * 16KB = 800KB
- 总计约 1.4MB

**优势**：
- 避免运行时扩展的锁竞争
- 提高前期性能稳定性

### 5.4 连接分配策略

```cpp
// 按 fd 哈希分配，保证同一连接总在同一线程
int idx = clientsock->fd() % threadnum_;
spConnection conn(new Connection(subloops_[idx].get(), ...));
```

**优势**：
- 负载均衡
- 避免跨线程访问

---

## 6. 错误处理

### 6.1 EINTR（信号中断）

```cpp
if (nread == -1 && errno == EINTR) {
    continue;  // 重试
}
```

### 6.2 EAGAIN（数据读完）

```cpp
if (nread == -1 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
    break;  // 正常退出读循环
}
```

### 6.3 连接断开

```cpp
if (nread == 0) {
    closecallback();  // 对端关闭
}
```

### 6.4 异常安全

- 使用 RAII 管理资源
- 智能指针自动释放
- 析构函数清理资源

---

## 7. 总结

本设计充分借鉴了 muduo 的设计思想，在保持简洁性的同时，引入了内存池优化，适合作为学习网络编程和毕业设计的参考项目。

**核心优势**：
- 清晰的模块划分
- 线程安全的设计
- 高效的内存管理
- 完善的测试体系
