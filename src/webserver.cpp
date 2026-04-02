#include "HttpServer.h"
#include <iostream>
#include <signal.h>

HttpServer* g_server = nullptr;

void signal_handler(int sig) {
    std::cout << "\n正在关闭服务器...\n";
    exit(0);
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
    std::cout << "🌐 启动HTTP服务器...\n";
    std::cout << "📊 访问地址: http://localhost:" << port << "\n";
    std::cout << "⚡ 基于Reactor网络库\n";
    std::cout << "💾 使用线程局部内存池\n";
    std::cout << "\n";
    std::cout << "按 Ctrl+C 停止服务器\n";
    std::cout << "═══════════════════════════════════════════════════\n\n";
    
    try {
        HttpServer server(port);
        g_server = &server;
        server.start();
    } catch (const std::exception& e) {
        std::cerr << "❌ 服务器启动失败: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
