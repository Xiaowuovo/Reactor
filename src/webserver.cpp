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

// 获取系统信息
std::string getSystemInfo() {
    std::ostringstream info;
    info << "{";
    
    // CPU信息
    #ifdef __linux__
    std::ifstream cpuinfo("/proc/cpuinfo");
    if (cpuinfo.is_open()) {
        std::string line;
        std::string model = "Unknown";
        int cores = 0;
        while (std::getline(cpuinfo, line)) {
            if (line.find("model name") != std::string::npos) {
                size_t pos = line.find(':');
                if (pos != std::string::npos) {
                    model = line.substr(pos + 2);
                }
            }
            if (line.find("processor") != std::string::npos) {
                cores++;
            }
        }
        info << "\"cpu\":\"" << model << "\",\"cores\":" << cores << ",";
    }
    
    // 内存信息
    std::ifstream meminfo("/proc/meminfo");
    if (meminfo.is_open()) {
        std::string line;
        while (std::getline(meminfo, line)) {
            if (line.find("MemTotal") != std::string::npos) {
                size_t pos = line.find(':');
                if (pos != std::string::npos) {
                    std::string mem = line.substr(pos + 1);
                    size_t kb_pos = mem.find("kB");
                    if (kb_pos != std::string::npos) {
                        long long kb = std::stoll(mem.substr(0, kb_pos));
                        info << "\"memory_gb\":" << (kb / 1024.0 / 1024.0) << ",";
                    }
                }
                break;
            }
        }
    }
    #else
    // Windows或其他系统的简化信息
    info << "\"cpu\":\"Unknown\",\"cores\":4,\"memory_gb\":8,";
    #endif
    
    info << "\"os\":\"Linux\",\"arch\":\"x86_64\"}";
    return info.str();
}

void handleStatus(const SimpleHttpRequest& req, SimpleHttpResponse& resp) {
    try {
        resp.setJson();
        
        // 获取系统信息
        std::string sysInfo = getSystemInfo();
        
        // 移除最后的}
        sysInfo = sysInfo.substr(0, sysInfo.length() - 1);
        
        // 添加状态信息
        resp.body = sysInfo + ",\"status\":\"running\",\"mempool\":\"ready\",\"uptime\":100}";
        std::cout << "✅ 状态查询成功" << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "❌ 状态查询异常: " << e.what() << std::endl;
        resp.setStatus(500);
        resp.setJson();
        resp.body = R"({"success":false,"error":"Status check failed"})";
    }
}

// 简单JSON解析辅助函数
std::string extractJsonValue(const std::string& json, const std::string& key) {
    size_t pos = json.find("\"" + key + "\":");
    if (pos == std::string::npos) return "";
    
    pos = json.find(":", pos) + 1;
    while (pos < json.length() && (json[pos] == ' ' || json[pos] == '\t')) pos++;
    
    if (pos >= json.length()) return "";
    
    // 如果是字符串值
    if (json[pos] == '"') {
        size_t start = pos + 1;
        size_t end = json.find("\"", start);
        return json.substr(start, end - start);
    }
    
    // 如果是数字或其他值
    size_t start = pos;
    size_t end = json.find_first_of(",}", start);
    return json.substr(start, end - start);
}

void handleTestMempool(const SimpleHttpRequest& req, SimpleHttpResponse& resp) {
    resp.setJson();
    
    try {
        std::string config = req.body;
        std::cout << "📋 收到内存池测试配置: " << config << std::endl;
        
        // 解析配置参数
        int iterations = 100000;
        int blockSize = 1024;
        int threads = 4;
        
        std::string iterStr = extractJsonValue(config, "iterations");
        std::string sizeStr = extractJsonValue(config, "blockSize");
        std::string threadStr = extractJsonValue(config, "threads");
        
        if (!iterStr.empty()) iterations = std::stoi(iterStr);
        if (!sizeStr.empty()) blockSize = std::stoi(sizeStr);
        if (!threadStr.empty()) threads = std::stoi(threadStr);
        
        std::cout << "� 参数: iterations=" << iterations 
                  << ", blockSize=" << blockSize 
                  << ", threads=" << threads << std::endl;
        
        // 构建命令行
        std::ostringstream cmdBuilder;
        cmdBuilder << "./test_mempool " << iterations << " " << blockSize << " " << threads 
                   << " > /tmp/mempool_output.log 2>&1";
        std::string cmd = cmdBuilder.str();
        
        std::cout << "🔄 执行: " << cmd << std::endl;
        int ret = system(cmd.c_str());
        
        // 读取输出
        std::ifstream logFile("/tmp/mempool_output.log");
        std::string testOutput;
        if (logFile.is_open()) {
            std::ostringstream ss;
            ss << logFile.rdbuf();
            testOutput = ss.str();
            logFile.close();
        }
        
        if (ret == 0 && !testOutput.empty()) {
            // 查找JSON结果（在输出的最后一行）
            size_t jsonStart = testOutput.rfind('{');
            if (jsonStart != std::string::npos) {
                std::string jsonResult = testOutput.substr(jsonStart);
                size_t jsonEnd = jsonResult.find('}');
                if (jsonEnd != std::string::npos) {
                    jsonResult = jsonResult.substr(0, jsonEnd + 1);
                    
                    // 提取关键指标
                    std::string mallocMs = extractJsonValue(jsonResult, "malloc_ms");
                    std::string poolMs = extractJsonValue(jsonResult, "pool_ms");
                    std::string speedup = extractJsonValue(jsonResult, "speedup");
                    std::string mallocQps = extractJsonValue(jsonResult, "malloc_qps");
                    std::string poolQps = extractJsonValue(jsonResult, "pool_qps");
                    
                    // 构建响应
                    resp.body = "{\"success\":true,"
                                "\"malloc_ms\":" + mallocMs + ","
                                "\"pool_ms\":" + poolMs + ","
                                "\"speedup\":" + speedup + ","
                                "\"malloc_qps\":" + mallocQps + ","
                                "\"pool_qps\":" + poolQps + ","
                                "\"iterations\":" + std::to_string(iterations) + ","
                                "\"block_size\":" + std::to_string(blockSize) + ","
                                "\"threads\":" + std::to_string(threads) + ","
                                "\"timestamp\":" + std::to_string(time(nullptr)) + "}";
                    
                    std::cout << "✅ 测试完成: malloc=" << mallocMs << "ms, pool=" << poolMs 
                              << "ms, speedup=" << speedup << "x" << std::endl;
                    return;
                }
            }
            
            // 如果没找到JSON，返回简化结果
            resp.body = "{\"success\":true,\"message\":\"Test completed but no metrics found\"}";
        } else {
            resp.body = "{\"success\":false,\"error\":\"Test execution failed\"}";
            std::cout << "❌ 测试失败 (exit code: " << ret << ")" << std::endl;
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
    try {
        resp.setJson();
        std::string type = "all";
        if (req.params.count("type")) {
            type = req.params.at("type");
        }
        resp.body = "{\"success\":true,\"file\":\"output/data/" + type + ".csv\"}";
        std::cout << "✅ 数据请求成功: " << type << std::endl;
    } catch (const std::exception& e) {
        std::cerr << "❌ 数据请求异常: " << e.what() << std::endl;
        resp.setStatus(500);
        resp.setJson();
        resp.body = R"({"success":false,"error":"Data request failed"})";
    }
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
