#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/socket.h>
#include <unistd.h>
#include <cstring>
#include <iostream>
#include <string>
#include <chrono>
#include <thread>
#include <atomic>
#include <vector>

using namespace std;
using namespace std::chrono;

class TcpClient {
private:
    int sockfd_;
    string server_ip_;
    uint16_t server_port_;
    bool connected_;

public:
    TcpClient(const string& ip, uint16_t port) 
        : sockfd_(-1), server_ip_(ip), server_port_(port), connected_(false) {}
    
    ~TcpClient() {
        disconnect();
    }
    
    bool connect() {
        sockfd_ = socket(AF_INET, SOCK_STREAM, 0);
        if (sockfd_ < 0) {
            perror("socket creation failed");
            return false;
        }
        
        sockaddr_in servaddr;
        memset(&servaddr, 0, sizeof(servaddr));
        servaddr.sin_family = AF_INET;
        servaddr.sin_port = htons(server_port_);
        
        if (inet_pton(AF_INET, server_ip_.c_str(), &servaddr.sin_addr) <= 0) {
            perror("invalid address");
            close(sockfd_);
            return false;
        }
        
        if (::connect(sockfd_, (sockaddr*)&servaddr, sizeof(servaddr)) < 0) {
            perror("connection failed");
            close(sockfd_);
            return false;
        }
        
        connected_ = true;
        return true;
    }
    
    void disconnect() {
        if (sockfd_ >= 0) {
            close(sockfd_);
            sockfd_ = -1;
        }
        connected_ = false;
    }
    
    bool send_message(const string& message) {
        if (!connected_) return false;
        
        int len = message.size();
        string packet;
        packet.append((char*)&len, 4);
        packet.append(message);
        
        ssize_t sent = ::send(sockfd_, packet.data(), packet.size(), 0);
        return sent == (ssize_t)packet.size();
    }
    
    bool recv_message(string& message) {
        if (!connected_) return false;
        
        int len;
        ssize_t n = recv(sockfd_, &len, 4, 0);
        if (n != 4) return false;
        
        char buffer[65536];
        n = recv(sockfd_, buffer, len, 0);
        if (n != len) return false;
        
        message.assign(buffer, len);
        return true;
    }
    
    bool is_connected() const { return connected_; }
};

void simple_test(const string& ip, uint16_t port) {
    cout << "\n=== Simple Echo Test ===" << endl;
    
    TcpClient client(ip, port);
    
    if (!client.connect()) {
        cerr << "Failed to connect to server" << endl;
        return;
    }
    
    cout << "Connected to " << ip << ":" << port << endl;
    
    string send_msg = "Hello, Server!";
    cout << "Sending: " << send_msg << endl;
    
    if (!client.send_message(send_msg)) {
        cerr << "Failed to send message" << endl;
        return;
    }
    
    string recv_msg;
    if (!client.recv_message(recv_msg)) {
        cerr << "Failed to receive message" << endl;
        return;
    }
    
    cout << "Received: " << recv_msg << endl;
    
    if (recv_msg == "reply:" + send_msg) {
        cout << "Simple test PASSED!" << endl;
    } else {
        cout << "Simple test FAILED!" << endl;
    }
}

void performance_test(const string& ip, uint16_t port, int message_count) {
    cout << "\n=== Performance Test ===" << endl;
    cout << "Messages to send: " << message_count << endl;
    
    TcpClient client(ip, port);
    
    if (!client.connect()) {
        cerr << "Failed to connect to server" << endl;
        return;
    }
    
    string message = "Performance test message with some data";
    
    auto start = high_resolution_clock::now();
    
    int success_count = 0;
    for (int i = 0; i < message_count; ++i) {
        if (!client.send_message(message)) {
            cerr << "Failed to send message " << i << endl;
            break;
        }
        
        string reply;
        if (!client.recv_message(reply)) {
            cerr << "Failed to receive message " << i << endl;
            break;
        }
        
        success_count++;
    }
    
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start).count();
    
    cout << "Completed: " << success_count << "/" << message_count << endl;
    cout << "Time: " << duration << " ms" << endl;
    cout << "QPS: " << (success_count * 1000.0 / duration) << " req/s" << endl;
    cout << "Avg latency: " << (duration * 1.0 / success_count) << " ms" << endl;
}

void concurrent_test(const string& ip, uint16_t port, int client_count, int msg_per_client) {
    cout << "\n=== Concurrent Test ===" << endl;
    cout << "Clients: " << client_count << endl;
    cout << "Messages per client: " << msg_per_client << endl;
    
    atomic<int> total_success(0);
    vector<thread> threads;
    
    auto start = high_resolution_clock::now();
    
    for (int i = 0; i < client_count; ++i) {
        threads.emplace_back([&, i]() {
            TcpClient client(ip, port);
            
            if (!client.connect()) {
                cerr << "Client " << i << " failed to connect" << endl;
                return;
            }
            
            int success = 0;
            for (int j = 0; j < msg_per_client; ++j) {
                string msg = "Client" + to_string(i) + "_Msg" + to_string(j);
                
                if (client.send_message(msg)) {
                    string reply;
                    if (client.recv_message(reply)) {
                        success++;
                    }
                }
            }
            
            total_success += success;
        });
    }
    
    for (auto& th : threads) {
        th.join();
    }
    
    auto end = high_resolution_clock::now();
    auto duration = duration_cast<milliseconds>(end - start).count();
    
    int expected = client_count * msg_per_client;
    cout << "Completed: " << total_success.load() << "/" << expected << endl;
    cout << "Time: " << duration << " ms" << endl;
    cout << "Total QPS: " << (total_success.load() * 1000.0 / duration) << " req/s" << endl;
}

void stress_test(const string& ip, uint16_t port, int duration_seconds) {
    cout << "\n=== Stress Test ===" << endl;
    cout << "Duration: " << duration_seconds << " seconds" << endl;
    
    atomic<bool> stop_flag(false);
    atomic<int> total_requests(0);
    
    auto worker = [&]() {
        TcpClient client(ip, port);
        
        if (!client.connect()) {
            return;
        }
        
        string message = "Stress test data";
        
        while (!stop_flag) {
            if (client.send_message(message)) {
                string reply;
                if (client.recv_message(reply)) {
                    total_requests++;
                }
            }
        }
    };
    
    const int THREAD_COUNT = 10;
    vector<thread> threads;
    
    auto start = high_resolution_clock::now();
    
    for (int i = 0; i < THREAD_COUNT; ++i) {
        threads.emplace_back(worker);
    }
    
    this_thread::sleep_for(seconds(duration_seconds));
    stop_flag = true;
    
    for (auto& th : threads) {
        th.join();
    }
    
    auto end = high_resolution_clock::now();
    auto actual_duration = duration_cast<milliseconds>(end - start).count();
    
    cout << "Total requests: " << total_requests.load() << endl;
    cout << "Actual duration: " << actual_duration << " ms" << endl;
    cout << "Average QPS: " << (total_requests.load() * 1000.0 / actual_duration) << " req/s" << endl;
}

int main(int argc, char* argv[]) {
    if (argc < 3) {
        cout << "Usage: " << argv[0] << " <server_ip> <server_port> [test_type]" << endl;
        cout << "Test types: simple, perf, concurrent, stress, all" << endl;
        return 1;
    }
    
    string ip = argv[1];
    uint16_t port = atoi(argv[2]);
    string test_type = (argc >= 4) ? argv[3] : "simple";
    
    cout << "========================================" << endl;
    cout << "     TCP Client Test Program" << endl;
    cout << "========================================" << endl;
    cout << "Server: " << ip << ":" << port << endl;
    
    if (test_type == "simple" || test_type == "all") {
        simple_test(ip, port);
    }
    
    if (test_type == "perf" || test_type == "all") {
        performance_test(ip, port, 10000);
    }
    
    if (test_type == "concurrent" || test_type == "all") {
        concurrent_test(ip, port, 50, 100);
    }
    
    if (test_type == "stress") {
        stress_test(ip, port, 30);
    }
    
    cout << "\n========================================" << endl;
    cout << "     Tests Completed" << endl;
    cout << "========================================" << endl;
    
    return 0;
}
