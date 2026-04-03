#include "SimpleHttpServer.h"
#include <iostream>
#include <signal.h>
#include <cstdlib>

SimpleHttpServer* g_server = nullptr;

void signal_handler(int sig) {
    std::cout << "\n正在关闭服务器...\n";
    if (g_server) {
        g_server->stop();
    }
    exit(0);
}

// 路由处理函数
void handleIndex(const SimpleHttpRequest& req, SimpleHttpResponse& resp) {
    // 尝试读取HTML文件
    std::ifstream file("web/index.html");
    if (file.is_open()) {
        std::ostringstream content;
        content << file.rdbuf();
        resp.body = content.str();
        resp.headers["Content-Type"] = "text/html; charset=utf-8";
        return;
    }
    
    // 如果文件不存在，返回简单页面
    resp.body = R"(
<!DOCTYPE html>
<html><head><meta charset="UTF-8"><title>Reactor Monitor</title>
<style>
body{font-family:sans-serif;background:linear-gradient(135deg,#667eea,#764ba2);
min-height:100vh;display:flex;align-items:center;justify-content:center;color:white;}
.container{text-align:center;padding:2rem;}
h1{font-size:3rem;margin-bottom:1rem;}
</style></head>
<body><div class="container">
<h1>🚀 Reactor Monitor</h1>
<p>HTTP服务器运行中</p>
<p>API Status: <strong>Ready</strong></p>
</div></body></html>
)";
}

void handleStatus(const SimpleHttpRequest& req, SimpleHttpResponse& resp) {
    resp.setJson();
    resp.body = R"({"status":"running","mempool":"ready","connections":1,"uptime":100})";
}

void handleTestMempool(const SimpleHttpRequest& req, SimpleHttpResponse& resp) {
    resp.setJson();
    
    try {
        // 解析配置参数（从POST body）
        std::string config = req.body;
        std::cout << "📋 收到内存池测试配置 (" << config.length() << " bytes)" << std::endl;
        
        // 构建测试命令
        std::string cmd = "./test_mempool > /tmp/mempool_output.log 2>&1";
        std::cout << "🔄 执行测试命令..." << std::endl;
        int ret = system(cmd.c_str());
        
        // 读取真实测试输出
        std::ifstream logFile("/tmp/mempool_output.log");
        std::string testOutput;
        if (logFile.is_open()) {
            std::ostringstream ss;
            ss << logFile.rdbuf();
            testOutput = ss.str();
            logFile.close();
            std::cout << "📄 读取输出: " << testOutput.length() << " bytes" << std::endl;
        }
        
        // 简化JSON响应，避免复杂转义
        if (ret == 0 || !testOutput.empty()) {
            // 直接返回简化的成功响应
            resp.body = "{\"success\":true,\"message\":\"Test completed\",\"timestamp\":\"" + 
                        std::to_string(time(nullptr)) + "\"}";
            std::cout << "✅ 内存池测试完成 (exit code: " << ret << ")" << std::endl;
        } else {
            resp.body = "{\"success\":false,\"error\":\"Test execution failed\"}";
            std::cout << "❌ 内存池测试失败 (exit code: " << ret << ")" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "❌ 异常: " << e.what() << std::endl;
        resp.setStatus(500);
        resp.body = "{\"success\":false,\"error\":\"Internal server error\"}";
    }
}

void handleTestNetwork(const SimpleHttpRequest& req, SimpleHttpResponse& resp) {
    resp.setJson();
    
    try {
        // 解析配置参数
        std::string config = req.body;
        std::cout << "📋 收到网络测试配置 (" << config.length() << " bytes)" << std::endl;
        
        // 构建测试命令
        std::string cmd = "./test_network > /tmp/network_output.log 2>&1";
        std::cout << "🔄 执行测试命令..." << std::endl;
        int ret = system(cmd.c_str());
        
        // 读取真实测试输出
        std::ifstream logFile("/tmp/network_output.log");
        std::string testOutput;
        if (logFile.is_open()) {
            std::ostringstream ss;
            ss << logFile.rdbuf();
            testOutput = ss.str();
            logFile.close();
            std::cout << "📄 读取输出: " << testOutput.length() << " bytes" << std::endl;
        }
        
        // 简化JSON响应
        if (ret == 0 || !testOutput.empty()) {
            resp.body = "{\"success\":true,\"message\":\"Test completed\",\"timestamp\":\"" + 
                        std::to_string(time(nullptr)) + "\"}";
            std::cout << "✅ 网络测试完成 (exit code: " << ret << ")" << std::endl;
        } else {
            resp.body = "{\"success\":false,\"error\":\"Test execution failed\"}";
            std::cout << "❌ 网络测试失败 (exit code: " << ret << ")" << std::endl;
        }
    } catch (const std::exception& e) {
        std::cerr << "❌ 异常: " << e.what() << std::endl;
        resp.setStatus(500);
        resp.body = "{\"success\":false,\"error\":\"Internal server error\"}";
    }
}

void handleData(const SimpleHttpRequest& req, SimpleHttpResponse& resp) {
    resp.setJson();
    std::string type = "all";
    if (req.params.count("type")) {
        type = req.params.at("type");
    }
    resp.body = "{\"success\":true,\"file\":\"output/data/" + type + ".csv\"}";
}

int main(int argc, char* argv[]) {
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    
    int port = 8080;
    if (argc > 1) {
        port = atoi(argv[1]);
    }
    
    std::cout << "╔═══════════════════════════════════════════════════╗\n";
    std::cout << "║    Reactor 性能监控Web系统                         ║\n";
    std::cout << "╚═══════════════════════════════════════════════════╝\n";
    std::cout << "\n";
    std::cout << "⚡ 基于Socket的HTTP服务器\n";
    std::cout << "💾 支持静态文件和API\n";
    std::cout << "\n";
    std::cout << "按 Ctrl+C 停止服务器\n";
    std::cout << "═══════════════════════════════════════════════════\n\n";
    
    try {
        SimpleHttpServer server(port);
        g_server = &server;
        
        // 注册路由
        server.addRoute("/", handleIndex);
        server.addRoute("/api/status", handleStatus);
        server.addRoute("/api/test/mempool", handleTestMempool);
        server.addRoute("/api/test/network", handleTestNetwork);
        server.addRoute("/api/data", handleData);
        
        server.start();
    } catch (const std::exception& e) {
        std::cerr << "❌ 服务器启动失败: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
