# ☁️ 云端部署指南

> 将Reactor监控系统部署到阿里云ECS

---

## 📋 部署前准备

### 服务器信息
- **IP地址**: 172.27.195.213 (内网)
- **操作系统**: Ubuntu 20.04.6 LTS
- **架构**: x86_64
- **云服务商**: 阿里云ECS

### 需要的端口
- **8080**: Web监控系统HTTP端口

---

## 🚀 快速部署（一键完成）

### 在服务器上执行

```bash
# 1. 进入项目目录
cd ~/Reactor

# 2. 赋予执行权限
chmod +x deploy.sh

# 3. 运行部署脚本
./deploy.sh
```

部署脚本会自动完成：
- ✅ 检查和安装依赖（g++, make）
- ✅ 编译项目
- ✅ 创建必要目录
- ✅ 配置防火墙
- ✅ 后台启动服务器

---

## 🔧 手动部署步骤

### 1. 安装依赖

```bash
sudo apt-get update
sudo apt-get install -y build-essential make
```

### 2. 编译项目

```bash
cd ~/Reactor
make clean
make
```

### 3. 创建目录

```bash
mkdir -p output/data output/logs output/charts
mkdir -p web
```

### 4. 配置防火墙（服务器端）

```bash
# Ubuntu UFW防火墙
sudo ufw allow 8080/tcp
sudo ufw status
```

### 5. 配置阿里云安全组

**重要：必须在阿里云控制台配置！**

1. 登录 [阿里云ECS控制台](https://ecs.console.aliyun.com/)
2. 选择您的实例
3. 点击 **安全组** → **配置规则**
4. 添加入方向规则：
   - **端口范围**: 8080/8080
   - **授权对象**: 0.0.0.0/0
   - **协议类型**: TCP
   - **优先级**: 1

### 6. 启动服务器

```bash
# 后台启动
nohup ./webserver 8080 > output/logs/webserver.log 2>&1 &

# 查看进程
ps aux | grep webserver

# 保存PID
echo $! > output/webserver.pid
```

---

## 🌐 访问系统

### 内网访问
```
http://172.27.195.213:8080
```

### 外网访问
```
http://您的公网IP:8080
```

**获取公网IP：**
```bash
# 在阿里云控制台查看
# 或在服务器执行
curl ifconfig.me
```

---

## 📊 管理命令

### 查看日志
```bash
# 实时查看
tail -f output/logs/webserver.log

# 查看最近100行
tail -n 100 output/logs/webserver.log
```

### 停止服务器
```bash
# 方式1: 使用pkill
pkill -f webserver

# 方式2: 使用PID文件
kill $(cat output/webserver.pid)
```

### 重启服务器
```bash
# 停止
pkill -f webserver

# 启动
nohup ./webserver 8080 > output/logs/webserver.log 2>&1 &
echo $! > output/webserver.pid
```

### 检查运行状态
```bash
# 查看进程
ps aux | grep webserver

# 检查端口
netstat -tuln | grep 8080
lsof -i:8080
```

---

## 🔄 更新部署

### 上传新代码后

```bash
cd ~/Reactor

# 停止服务器
pkill -f webserver

# 重新编译
make clean
make

# 重新部署
./deploy.sh
```

### 仅更新前端文件

```bash
# 无需重启服务器，直接替换web目录文件
# 刷新浏览器即可看到新界面
```

---

## 🛡️ 安全建议

### 1. 限制访问IP（可选）

如果只想允许特定IP访问，修改安全组规则：
```
授权对象: 您的IP地址/32
```

### 2. 启用HTTPS（生产环境）

```bash
# 安装Nginx
sudo apt-get install nginx

# 配置反向代理和SSL
# 使用Let's Encrypt获取免费SSL证书
```

### 3. 设置防火墙规则

```bash
# 只允许必要的端口
sudo ufw default deny incoming
sudo ufw default allow outgoing
sudo ufw allow ssh
sudo ufw allow 8080/tcp
sudo ufw enable
```

---

## 🔍 故障排查

### 问题1: 无法访问Web界面

**检查项：**
```bash
# 1. 服务器是否运行
ps aux | grep webserver

# 2. 端口是否监听
netstat -tuln | grep 8080

# 3. 防火墙是否开放
sudo ufw status

# 4. 查看错误日志
tail -f output/logs/webserver.log
```

**阿里云安全组检查：**
- 确保入方向规则已添加
- 端口号正确（8080）
- 授权对象为 0.0.0.0/0

### 问题2: 编译失败

```bash
# 检查g++版本
g++ --version

# 重新安装
sudo apt-get install --reinstall build-essential

# 清理后重新编译
make clean
rm -f src/*.o tests/*.o
make
```

### 问题3: 端口被占用

```bash
# 查看占用端口的进程
lsof -i:8080

# 杀死进程
kill -9 $(lsof -t -i:8080)
```

### 问题4: 权限问题

```bash
# 赋予执行权限
chmod +x webserver
chmod +x deploy.sh

# 检查文件权限
ls -la
```

---

## 📱 开机自启动

### 创建systemd服务

```bash
# 创建服务文件
sudo nano /etc/systemd/system/reactor-monitor.service
```

**内容：**
```ini
[Unit]
Description=Reactor Monitor Web Service
After=network.target

[Service]
Type=simple
User=root
WorkingDirectory=/root/Reactor
ExecStart=/root/Reactor/webserver 8080
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
```

**启用服务：**
```bash
sudo systemctl daemon-reload
sudo systemctl enable reactor-monitor
sudo systemctl start reactor-monitor
sudo systemctl status reactor-monitor
```

---

## 📈 性能优化

### 1. 调整系统参数

```bash
# 增加文件描述符限制
ulimit -n 65535

# 永久设置
echo "* soft nofile 65535" | sudo tee -a /etc/security/limits.conf
echo "* hard nofile 65535" | sudo tee -a /etc/security/limits.conf
```

### 2. 优化网络参数

```bash
# 编辑sysctl.conf
sudo nano /etc/sysctl.conf

# 添加以下内容
net.core.somaxconn = 1024
net.ipv4.tcp_max_syn_backlog = 2048

# 应用配置
sudo sysctl -p
```

---

## 🎯 答辩演示建议

### 远程演示流程

1. **展示云端部署** (2分钟)
   - 展示阿里云ECS实例
   - SSH连接到服务器
   - 展示运行的进程和日志

2. **访问Web界面** (3分钟)
   - 使用公网IP访问
   - 展示现代化的前端界面
   - 实时运行性能测试

3. **查看实时数据** (2分钟)
   - 展示日志输出
   - 查看测试结果
   - 展示性能指标

4. **技术讲解** (3分钟)
   - 说明基于Reactor的HTTP服务器
   - 展示前后端分离架构
   - 讲解内存池应用

---

## 📞 常用命令速查

```bash
# 部署
./deploy.sh

# 启动
nohup ./webserver 8080 > output/logs/webserver.log 2>&1 &

# 停止
pkill -f webserver

# 查看日志
tail -f output/logs/webserver.log

# 查看状态
ps aux | grep webserver
netstat -tuln | grep 8080

# 编译
make clean && make

# 检查公网IP
curl ifconfig.me
```

---

## ✅ 部署检查清单

- [ ] 服务器已连接（SSH）
- [ ] 依赖已安装（g++, make）
- [ ] 项目已编译成功
- [ ] web目录已创建并包含前端文件
- [ ] 服务器防火墙已配置（UFW）
- [ ] 阿里云安全组已配置
- [ ] Web服务器已启动
- [ ] 可通过内网IP访问
- [ ] 可通过公网IP访问
- [ ] 日志文件正常记录

---

## 🎉 部署成功标志

当您看到以下内容，说明部署成功：

1. **终端输出：**
   ```
   ✓ Web服务器启动成功
   访问地址：http://172.27.195.213:8080
   ```

2. **浏览器访问：**
   - 显示精美的Web界面
   - 系统状态正常显示
   - 可以运行测试

3. **日志文件：**
   ```bash
   tail -f output/logs/webserver.log
   # 显示服务器启动和请求日志
   ```

---

**部署完成！现在您有一个完整的云端Web监控系统！** 🚀
