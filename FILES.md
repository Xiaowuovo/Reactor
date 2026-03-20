# 项目文件说明

## 源代码文件

### 核心网络库
| 文件 | 行数 | 说明 |
|------|------|------|
| `net.h` | 365 | 网络库头文件，包含所有类定义 |
| `net.cpp` | 1015 | 网络库实现，包含EventLoop、TcpServer等 |

**核心类**：
- `EventLoop` - 事件循环
- `TcpServer` - TCP服务器
- `Acceptor` - 连接接收器
- `Connection` - 连接管理
- `Channel` - 事件通道
- `Epoll` - epoll封装
- `Buffer` - 缓冲区
- `ThreadPool` - 线程池
- `EchoServer` - Echo服务器示例

### 内存池模块
| 文件 | 行数 | 说明 |
|------|------|------|
| `MemoryPool.h` | 62 | 通用内存池头文件 |
| `MemoryPool.cpp` | 115 | 内存池实现（固定大小块） |
| `BufferPool.h` | 49 | 缓冲区内存池头文件 |
| `BufferPool.cpp` | 106 | 三级内存池实现 |

**功能**：
- 固定大小块预分配
- 空闲链表管理
- 自动扩展
- 统计功能
- RAII封装

### 测试程序
| 文件 | 行数 | 说明 |
|------|------|------|
| `test_mempool.cpp` | 193 | 内存池单元测试和性能测试 |
| `test_core.cpp` | 127 | 核心模块单元测试 |
| `client.cpp` | 362 | 客户端测试程序（4种测试模式） |
| `tmp.cpp` | 38 | 服务端主程序 |

**测试覆盖**：
- 6个内存池测试用例
- 6个核心模块测试用例
- 4种客户端测试模式

## 文档文件

| 文件 | 说明 |
|------|------|
| `README_CN.md` | 项目说明（中文），包含架构、使用方法、性能数据 |
| `DESIGN.md` | 详细设计文档，包含架构图、流程图、技术细节 |
| `BENCHMARK.md` | 性能测试报告，包含详细测试数据和分析 |
| `QUICKSTART.md` | 快速开始指南，5分钟上手 |
| `PROJECT_SUMMARY.md` | 项目总结，适合答辩参考 |
| `TODO.md` | 待办事项和注意事项 |
| `FILES.md` | 文件说明（本文档） |

## 构建文件

| 文件 | 说明 |
|------|------|
| `Makefile` | 构建脚本，支持编译、测试、清理 |
| `.gitignore` | Git忽略文件 |

## 文件依赖关系

```
tmp.cpp (服务端)
  └── net.h/cpp
      ├── MemoryPool.h/cpp (可选)
      └── BufferPool.h/cpp (可选)

client.cpp (客户端)
  └── (无依赖)

test_mempool.cpp
  ├── MemoryPool.h/cpp
  └── BufferPool.h/cpp

test_core.cpp
  ├── net.h/cpp
  ├── MemoryPool.h/cpp
  └── BufferPool.h/cpp
```

## 编译产物

运行 `make` 后生成：
- `server` - 服务端可执行文件
- `client` - 客户端可执行文件
- `test_mempool` - 内存池测试程序
- `test_core` - 核心模块测试程序
- `*.o` - 目标文件

## 文件大小统计

```
源代码：
  net.h + net.cpp:           约 40KB
  MemoryPool.h/cpp:          约 5KB
  BufferPool.h/cpp:          约 4KB
  测试代码:                  约 20KB
  主程序:                    约 2KB
  ────────────────────────
  总计:                      约 71KB

文档：
  README_CN.md:              约 20KB
  DESIGN.md:                 约 35KB
  BENCHMARK.md:              约 25KB
  QUICKSTART.md:             约 18KB
  PROJECT_SUMMARY.md:        约 22KB
  TODO.md:                   约 5KB
  FILES.md:                  约 3KB
  ────────────────────────
  总计:                      约 128KB
```

## 代码行数统计

```bash
# 统计命令
find . -name "*.cpp" -o -name "*.h" | xargs wc -l

# 预计结果
核心代码:      ~1,380 行
内存池:        ~330 行
测试代码:      ~720 行
────────────────────
总计:          ~2,430 行
```

## 文档行数统计

```
README_CN.md:         ~550 行
DESIGN.md:            ~950 行
BENCHMARK.md:         ~650 行
QUICKSTART.md:        ~480 行
PROJECT_SUMMARY.md:   ~620 行
TODO.md:              ~140 行
FILES.md:             ~180 行
────────────────────
总计:                 ~3,570 行
```

## 使用指南

### 阅读顺序（新手）
1. `README_CN.md` - 了解项目概况
2. `QUICKSTART.md` - 快速上手
3. `DESIGN.md` - 深入理解设计
4. `BENCHMARK.md` - 了解性能

### 阅读顺序（答辩准备）
1. `PROJECT_SUMMARY.md` - 项目总结
2. `BENCHMARK.md` - 性能数据
3. `DESIGN.md` - 技术细节
4. `TODO.md` - 注意事项

### 修改代码
1. **修改业务逻辑**：编辑 `net.cpp` 中的 `EchoServer::OnMessage`
2. **修改服务器参数**：编辑 `tmp.cpp` 中的配置
3. **添加测试用例**：编辑 `test_core.cpp` 或 `test_mempool.cpp`

### 添加新功能
1. 在 `net.h` 中声明新类或新方法
2. 在 `net.cpp` 中实现
3. 在 `test_core.cpp` 中添加测试
4. 更新 `Makefile` 的依赖关系

## 重要文件标记

### 🔴 必须阅读（答辩前）
- `README_CN.md`
- `PROJECT_SUMMARY.md`
- `BENCHMARK.md`

### 🟡 建议阅读（深入理解）
- `DESIGN.md`
- `QUICKSTART.md`

### 🟢 可选阅读（扩展）
- `TODO.md`
- `FILES.md`

### ⚙️ 必须修改（运行前）
- `tmp.cpp` - 修改IP地址

### 📝 可能修改（优化）
- `BufferPool.cpp` - 调整内存池参数
- `net.cpp` - 修改业务逻辑

## 文件完整性检查

运行此命令检查所有文件是否存在：
```bash
ls -lh net.{h,cpp} MemoryPool.{h,cpp} BufferPool.{h,cpp} \
      test_*.cpp client.cpp tmp.cpp Makefile \
      *.md
```

预期看到所有文件都存在。

---

**最后更新**：2026-03-20
**项目状态**：完整 ✅
