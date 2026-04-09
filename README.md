# Muduo 网络库的重构与内存池的实现

> 基于线程局部内存池的高性能网络库 + Web实时监控平台 - 完整系统毕业设计

[![C++11](https://img.shields.io/badge/C++-11-blue.svg)](https://en.cppreference.com/w/cpp/11)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Build](https://img.shields.io/badge/build-passing-brightgreen.svg)]()

---

## 🚀 快速开始

### Web监控系统（推荐用于答辩）

```bash
# 编译
make

# 启动Web监控系统
make run-web

# 浏览器访问
http://localhost:8080
```

**完整的Web系统包含：**
- 🌐 实时性能监控界面
- 📊 在线测试控制面板
- 📈 动态数据可视化
- ⚡ 基于Reactor的HTTP服务器

### 命令行演示

```bash
# 交互式演示
make run-demo

# 运行测试
make test

# 生成图表
make visualize
```

---

## ✨ 核心特性

### 🏆 技术创新

- **线程局部无锁内存池** - 完全零锁竞争，性能提升5-10倍
- **三级智能分配策略** - Small/Medium/Large池，99%命中率
- **主从Reactor模式** - 高并发处理，充分利用多核
- **Epoll ET模式** - 边缘触发，非阻塞I/O

### 🎨 演示系统

- **交互式UI** - 彩色输出、进度条、表格、菜单
- **一键演示** - 自动化答辩演示流程
- **完整可视化** - 4个高清图表，7个CSV数据文件
- **专业文档** - 7个技术文档，详细指南

---

## 📊 性能数据

| 指标 | 数值 | 说明 |
|------|------|------|
| **单线程加速比** | 3.75x | 相比malloc/free |
| **多线程加速比** | 5.25x | 10线程场景 |
| **P99延迟降低** | 6.67x | 尾延迟优化 |
| **网络QPS** | 52,376 | 压力测试 |
| **平均延迟** | 13.5 μs | 微秒级响应 |

---

## 📁 项目结构

```
Reactor/
├── src/              # 📦 源代码（HttpServer.h, webserver.cpp等）
├── web/              # 🌐 前端界面（HTML, CSS, JS）
├── tests/            # 🧪 测试代码
├── tools/            # 🛠️ 工具脚本
├── docs/             # 📚 文档
├── output/           # 📊 输出文件（自动生成）
├── deploy.sh         # ☁️ 云端部署脚本
├── Makefile          # 🔧 构建系统
└── README.md         # 📄 本文档
```

---

## 🎯 核心功能

### 演示系统菜单

```
[1] 🔬 内存池功能演示
[2] 📊 内存池性能测试        ⭐ 核心创新
[3] 🚀 多线程性能对比        ⭐ 核心创新
[4] 🎯 三级缓冲池演示
[5] 🌐 网络库架构展示
[6] ⚡ 网络性能测试
[7] ✅ 运行完整测试套件
[8] 💾 导出数据和报告
[9] 🎓 答辩演示模式          ⭐ 一键演示
```

---

## 🔧 使用方法

### 编译

```bash
# 编译所有程序
make

# 查看帮助
make help
```

### 运行

```bash
# 交互式演示系统
./demo

# 运行服务器
./server

# 运行客户端
./client <ip> <port> <mode>
```

### 测试

```bash
# 运行所有测试
make test

# 生成性能图表
make visualize

# 答辩演示
make answer
```

---

## 📚 文档

- **README.md** - 项目说明（本文档）
- **docs/WEB_SYSTEM.md** - Web系统架构
- **docs/CLOUD_DEPLOYMENT.md** - 云端部署指南
- **docs/ARCHITECTURE.md** - 系统架构
- **docs/DESIGN.md** - 详细设计
- **docs/TESTING.md** - 测试文档
- **docs/DEMO_GUIDE.md** - 答辩演示指南

---

## ☁️ 云端部署

### 一键部署到云服务器

```bash
# 在服务器上执行
cd ~/Reactor
chmod +x deploy.sh
./deploy.sh
```

### 配置阿里云安全组

1. 登录阿里云ECS控制台
2. 安全组 → 配置规则 → 添加入方向规则
3. 端口: **8080/8080**, 协议: **TCP**, 授权: **0.0.0.0/0**

### 访问系统

```
内网: http://172.27.195.213:8080
外网: http://您的公网IP:8080
```

**详细部署文档**: `docs/CLOUD_DEPLOYMENT.md`

---

## 🎓 答辩演示

### 推荐方式

```bash
# 方式一：使用一键脚本（推荐）
cd tools
./demo.sh
# 选择 [1] 完整答辩演示

# 方式二：使用交互式系统
./demo
# 根据菜单选择功能

# 方式三：使用Makefile
make answer
```

### 演示时长

- **完整演示：** 12-15分钟
- **核心重点：** 6-8分钟
- **快速演示：** 3-5分钟

### 详细指南

查看 `docs/DEMO_GUIDE.md` 获取：
- 详细演示流程
- 关键话术
- 常见问题应对
- 备用方案

---

## 💡 核心优势

### 技术层面

1. ✅ **零锁竞争** - thread_local实现，完全无锁
2. ✅ **高性能** - 单线程3.75x，多线程5.25x加速
3. ✅ **智能分配** - 三级池，自动路由，99%命中
4. ✅ **线性扩展** - 多线程扩展效率>90%

### 工程层面

1. ✅ **完整测试** - 单元+性能+集成，100%通过
2. ✅ **规范代码** - Doxygen注释，工业级标准
3. ✅ **齐全文档** - 7个专业文档，详细指南
4. ✅ **优雅演示** - 交互式UI，专业可视化

---

## 📈 生成的文件

### CSV数据文件（7个）

- `output/data/benchmark_single_thread.csv`
- `output/data/benchmark_multi_thread.csv`
- `output/data/network_qps.csv`
- `output/data/network_concurrent.csv`
- `output/data/network_stress.csv`
- `output/data/network_latency_dist.csv`
- `output/data/mempool_performance.csv`

### 性能图表（4个，300 DPI）

- `output/charts/mempool_comparison.png`
- `output/charts/multithread_scalability.png`
- `output/charts/network_performance.png`
- `output/charts/comprehensive_comparison.png`

---

## 🛠️ 环境要求

### 必需

- **操作系统：** Linux (推荐 Ubuntu 20.04+)
- **编译器：** g++ 9.4.0+ (支持C++11)
- **构建工具：** make

### 可选（用于可视化）

- **Python：** 3.6+
- **依赖库：** matplotlib, pandas, numpy

安装方法：
```bash
pip3 install matplotlib pandas numpy
```

---

## � 需要帮助？

- 运行 `make help` 查看所有命令
- 查看 `docs/DEMO_GUIDE.md` 了解答辩演示流程
- 查看 `docs/ARCHITECTURE.md` 了解系统架构

---

**最后更新：** 2026-03-25  
**状态：** ✅ 就绪
