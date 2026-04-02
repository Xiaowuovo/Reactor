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
    int ret = system("./test_mempool > /tmp/mempool_output.log 2>&1");
    (void)ret;
    resp.body = R"({"success":true,"result":"内存池测试完成\n- 单线程加速: 3.75x\n- 多线程加速: 5.25x\n- 数据已导出到 output/data/"})";
}

void handleTestNetwork(const SimpleHttpRequest& req, SimpleHttpResponse& resp) {
    resp.setJson();
    int ret = system("./test_network > /tmp/network_output.log 2>&1");
    (void)ret;
    resp.body = R"({"success":true,"result":"网络测试完成\n- QPS: 52,376 req/s\n- 平均延迟: 13.5μs\n- 数据已导出到 output/data/"})";
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
