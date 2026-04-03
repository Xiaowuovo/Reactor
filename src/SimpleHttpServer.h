#ifndef SIMPLE_HTTP_SERVER_H
#define SIMPLE_HTTP_SERVER_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <string.h>
#include <string>
#include <map>
#include <functional>
#include <sstream>
#include <fstream>
#include <iostream>
#include <thread>

// 简单的HTTP请求解析
class SimpleHttpRequest {
public:
    std::string method;
    std::string path;
    std::map<std::string, std::string> headers;
    std::map<std::string, std::string> params;
    std::string body;
    
    bool parse(const std::string& raw) {
        std::istringstream iss(raw);
        std::string line;
        
        if (!std::getline(iss, line)) return false;
        
        std::istringstream request_line(line);
        std::string version;
        request_line >> method >> path >> version;
        
        // 解析URL参数
        size_t query_pos = path.find('?');
        if (query_pos != std::string::npos) {
            std::string query = path.substr(query_pos + 1);
            path = path.substr(0, query_pos);
            parseQuery(query);
        }
        
        // 解析headers
        while (std::getline(iss, line) && line != "\r") {
            size_t colon = line.find(':');
            if (colon != std::string::npos) {
                std::string key = line.substr(0, colon);
                std::string value = line.substr(colon + 2);
                if (!value.empty() && value.back() == '\r') {
                    value.pop_back();
                }
                headers[key] = value;
            }
        }
        
        // 读取POST body
        if (method == "POST" && headers.count("Content-Length")) {
            int content_length = std::stoi(headers["Content-Length"]);
            if (content_length > 0) {
                std::ostringstream body_stream;
                body_stream << iss.rdbuf();
                body = body_stream.str();
            }
        }
        
        return true;
    }
    
private:
    void parseQuery(const std::string& query) {
        size_t start = 0;
        while (start < query.size()) {
            size_t end = query.find('&', start);
            if (end == std::string::npos) end = query.size();
            
            std::string pair = query.substr(start, end - start);
            size_t eq = pair.find('=');
            if (eq != std::string::npos) {
                params[pair.substr(0, eq)] = pair.substr(eq + 1);
            }
            start = end + 1;
        }
    }
};

// 简单的HTTP响应
class SimpleHttpResponse {
public:
    int status_code;
    std::string status_text;
    std::map<std::string, std::string> headers;
    std::string body;
    
    SimpleHttpResponse(int code = 200) : status_code(code) {
        setStatus(code);
        headers["Server"] = "Reactor-HTTP/1.0";
        headers["Content-Type"] = "text/html; charset=utf-8";
        headers["Connection"] = "close";
        headers["Access-Control-Allow-Origin"] = "*";
        headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS";
    }
    
    void setStatus(int code) {
        status_code = code;
        switch (code) {
            case 200: status_text = "OK"; break;
            case 404: status_text = "Not Found"; break;
            case 500: status_text = "Internal Server Error"; break;
            default: status_text = "Unknown"; break;
        }
    }
    
    void setJson() {
        headers["Content-Type"] = "application/json; charset=utf-8";
    }
    
    std::string toString() const {
        std::ostringstream oss;
        oss << "HTTP/1.1 " << status_code << " " << status_text << "\r\n";
        
        // 设置Content-Length
        std::map<std::string, std::string> temp_headers = headers;
        temp_headers["Content-Length"] = std::to_string(body.size());
        
        for (const auto& h : temp_headers) {
            oss << h.first << ": " << h.second << "\r\n";
        }
        
        oss << "\r\n" << body;
        return oss.str();
    }
};

// 简单的HTTP服务器（基于socket）
class SimpleHttpServer {
public:
    using Handler = std::function<void(const SimpleHttpRequest&, SimpleHttpResponse&)>;
    
    SimpleHttpServer(int port) : port_(port), running_(false) {}
    
    void addRoute(const std::string& path, Handler handler) {
        routes_[path] = handler;
    }
    
    void start() {
        // 创建socket
        int server_fd = socket(AF_INET, SOCK_STREAM, 0);
        if (server_fd < 0) {
            std::cerr << "Failed to create socket" << std::endl;
            return;
        }
        
        // 设置socket选项
        int opt = 1;
        setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        
        // 绑定地址
        struct sockaddr_in address;
        address.sin_family = AF_INET;
        address.sin_addr.s_addr = INADDR_ANY;
        address.sin_port = htons(port_);
        
        if (bind(server_fd, (struct sockaddr*)&address, sizeof(address)) < 0) {
            std::cerr << "Failed to bind" << std::endl;
            close(server_fd);
            return;
        }
        
        // 监听
        if (listen(server_fd, 10) < 0) {
            std::cerr << "Failed to listen" << std::endl;
            close(server_fd);
            return;
        }
        
        std::cout << "🌐 HTTP服务器启动在端口 " << port_ << std::endl;
        std::cout << "📊 访问: http://localhost:" << port_ << std::endl;
        
        running_ = true;
        
        // 主循环
        while (running_) {
            struct sockaddr_in client_addr;
            socklen_t client_len = sizeof(client_addr);
            
            int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
            if (client_fd < 0) {
                continue;
            }
            
            // 在新线程中处理请求
            std::thread([this, client_fd]() {
                handleClient(client_fd);
            }).detach();
        }
        
        close(server_fd);
    }
    
    void stop() {
        running_ = false;
    }
    
private:
    void handleClient(int client_fd) {
        char buffer[8192];
        ssize_t n = read(client_fd, buffer, sizeof(buffer) - 1);
        
        if (n > 0) {
            buffer[n] = '\0';
            std::string request_data(buffer);
            
            SimpleHttpRequest req;
            SimpleHttpResponse resp;
            
            if (!req.parse(request_data)) {
                resp.setStatus(400);
                resp.body = "Bad Request";
                sendResponse(client_fd, resp);
                close(client_fd);
                return;
            }
            
            // OPTIONS请求
            if (req.method == "OPTIONS") {
                resp.setStatus(200);
                sendResponse(client_fd, resp);
                close(client_fd);
                return;
            }
            
            // 路由匹配
            if (routes_.find(req.path) != routes_.end()) {
                routes_[req.path](req, resp);
            } else {
                // 尝试静态文件
                if (!serveStaticFile(req.path, resp)) {
                    resp.setStatus(404);
                    resp.body = "<h1>404 Not Found</h1>";
                }
            }
            
            sendResponse(client_fd, resp);
        }
        
        close(client_fd);
    }
    
    bool serveStaticFile(const std::string& path, SimpleHttpResponse& resp) {
        std::string file_path = "web" + path;
        std::ifstream file(file_path, std::ios::binary);
        
        if (!file.is_open()) {
            file.open(path, std::ios::binary);
        }
        
        if (!file.is_open()) return false;
        
        std::ostringstream content;
        content << file.rdbuf();
        resp.body = content.str();
        
        // 设置MIME类型
        if (path.find(".html") != std::string::npos) {
            resp.headers["Content-Type"] = "text/html; charset=utf-8";
        } else if (path.find(".css") != std::string::npos) {
            resp.headers["Content-Type"] = "text/css; charset=utf-8";
        } else if (path.find(".js") != std::string::npos) {
            resp.headers["Content-Type"] = "application/javascript; charset=utf-8";
        }
        
        return true;
    }
    
    void sendResponse(int client_fd, const SimpleHttpResponse& resp) {
        std::string response = resp.toString();
        write(client_fd, response.c_str(), response.size());
    }
    
    int port_;
    bool running_;
    std::map<std::string, Handler> routes_;
};

#endif
