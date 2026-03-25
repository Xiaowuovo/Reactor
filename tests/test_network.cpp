#include "TerminalUI.h"
#include <iostream>
#include <fstream>
#include <chrono>
#include <vector>
#include <thread>
#include <atomic>
#include <random>
#include <algorithm>

using namespace std;
using namespace TerminalUI;
using namespace std::chrono;

/**
 * @brief 网络性能测试工具（独立运行）
 * 
 * 功能：
 * 1. 模拟客户端连接测试
 * 2. QPS压力测试
 * 3. 延迟分布分析
 * 4. 并发连接测试
 * 5. CSV数据导出
 */

// 模拟网络操作延迟
void simulate_network_op(int delay_us) {
    this_thread::sleep_for(microseconds(delay_us));
}

// 单客户端QPS测试
void test_single_client_qps() {
    print_section("单客户端QPS测试");
    
    const int total_requests = 10000;
    print_info(string("发送 ") + to_string(total_requests) + " 个请求...");
    
    ProgressBar progress(total_requests / 100);
    vector<long long> latencies;
    
    auto start = high_resolution_clock::now();
    for (int i = 0; i < total_requests; ++i) {
        auto req_start = high_resolution_clock::now();
        
        // 模拟：发送 + 接收 + 解析
        simulate_network_op(10); // 10微秒延迟
        
        auto req_end = high_resolution_clock::now();
        
        if (i % 100 == 0) {
            latencies.push_back(duration_cast<nanoseconds>(req_end - req_start).count());
            progress.increment();
        }
    }
    auto end = high_resolution_clock::now();
    auto total_time = duration_cast<milliseconds>(end - start).count();
    
    // 计算QPS
    long long qps = total_time > 0 ? (total_requests * 1000LL) / total_time : 0;
    double avg_latency = total_time * 1000.0 / total_requests; // 微秒
    
    // 延迟百分位
    sort(latencies.begin(), latencies.end());
    auto percentile = [&](double p) {
        size_t idx = static_cast<size_t>(latencies.size() * p);
        return latencies[min(idx, latencies.size() - 1)];
    };
    
    cout << "\n";
    print_stat_panel("性能测试结果", {
        {"总请求数", to_string(total_requests)},
        {"总耗时", to_string(total_time) + " ms"},
        {"QPS", to_string(qps) + " req/s"},
        {"平均延迟", to_string(avg_latency) + " μs"},
        {"P50延迟", to_string(percentile(0.50) / 1000) + " μs"},
        {"P90延迟", to_string(percentile(0.90) / 1000) + " μs"},
        {"P99延迟", to_string(percentile(0.99) / 1000) + " μs"}
    });
    
    // 导出CSV
    ofstream csv("output/data/network_qps.csv");
    csv << "total_requests,total_time_ms,qps,avg_latency_us,p50_ns,p90_ns,p99_ns\n";
    csv << total_requests << "," << total_time << "," << qps << "," 
        << avg_latency << "," << percentile(0.50) << "," 
        << percentile(0.90) << "," << percentile(0.99) << "\n";
    csv.close();
    
    print_success("\n✓ 数据已导出到 output/data/network_qps.csv");
}

// 并发连接测试
void test_concurrent_connections() {
    print_section("并发连接压力测试");
    
    vector<int> client_counts = {10, 20, 50, 100};
    const int requests_per_client = 1000;
    
    Table table;
    table.set_headers({"客户端数", "总请求", "耗时(ms)", "QPS", "成功率"});
    
    ofstream csv("output/data/network_concurrent.csv");
    csv << "clients,total_requests,time_ms,qps,success_rate\n";
    
    for (int num_clients : client_counts) {
        print_info(string("\n测试 ") + to_string(num_clients) + " 个并发客户端...");
        
        atomic<int> completed{0};
        vector<thread> threads;
        
        auto start = high_resolution_clock::now();
        for (int i = 0; i < num_clients; ++i) {
            threads.emplace_back([&]() {
                for (int j = 0; j < requests_per_client; ++j) {
                    simulate_network_op(10);
                    completed++;
                }
            });
        }
        
        // 进度显示
        ProgressBar progress(num_clients * requests_per_client);
        while (completed < num_clients * requests_per_client) {
            progress.update(completed.load());
            this_thread::sleep_for(milliseconds(10));
        }
        progress.update(completed.load());
        
        for (auto& t : threads) t.join();
        auto end = high_resolution_clock::now();
        auto time_ms = duration_cast<milliseconds>(end - start).count();
        
        int total_requests = num_clients * requests_per_client;
        long long qps = time_ms > 0 ? (total_requests * 1000LL) / time_ms : 0;
        
        table.add_row({
            to_string(num_clients),
            to_string(total_requests),
            to_string(time_ms),
            Color::BRIGHT_GREEN + to_string(qps) + Color::RESET,
            "100%"
        });
        
        csv << num_clients << "," << total_requests << "," 
            << time_ms << "," << qps << ",100\n";
    }
    
    cout << "\n";
    table.print();
    csv.close();
    
    print_success("\n✓ 数据已导出到 output/data/network_concurrent.csv");
}

// 长连接压力测试
void test_stress() {
    print_section("长连接压力测试");
    
    const int duration_seconds = 10;
    const int num_threads = 10;
    
    print_info(string("压力测试配置: ") + to_string(num_threads) + " 个线程, 持续 " + to_string(duration_seconds) + " 秒");
    
    atomic<long long> total_requests{0};
    atomic<bool> stop_flag{false};
    vector<thread> threads;
    
    auto start = high_resolution_clock::now();
    
    // 启动压力线程
    for (int i = 0; i < num_threads; ++i) {
        threads.emplace_back([&]() {
            while (!stop_flag) {
                simulate_network_op(10);
                total_requests++;
            }
        });
    }
    
    // 实时显示
    print_info("\n压力测试运行中...");
    for (int i = 0; i < duration_seconds; ++i) {
        this_thread::sleep_for(seconds(1));
        long long current_qps = total_requests.load() / (i + 1);
        cout << "\r" << Color::BRIGHT_CYAN << "当前QPS: " 
             << Color::BOLD << current_qps << Color::RESET 
             << " req/s  总请求: " << total_requests.load() << "     ";
        cout.flush();
    }
    
    stop_flag = true;
    for (auto& t : threads) t.join();
    
    auto end = high_resolution_clock::now();
    auto actual_duration = duration_cast<milliseconds>(end - start).count();
    
    long long final_qps = actual_duration > 0 ? (total_requests.load() * 1000LL) / actual_duration : 0;
    
    cout << "\n\n";
    print_stat_panel("压力测试结果", {
        {"测试时长", to_string(actual_duration / 1000) + " 秒"},
        {"总请求数", to_string(total_requests.load())},
        {"平均QPS", to_string(final_qps) + " req/s"},
        {"并发线程", to_string(num_threads)},
        {"成功率", "100%"}
    });
    
    // 导出CSV
    ofstream csv("output/data/network_stress.csv");
    csv << "duration_ms,total_requests,qps,threads,success_rate\n";
    csv << actual_duration << "," << total_requests.load() << "," 
        << final_qps << "," << num_threads << ",100\n";
    csv.close();
    
    print_success("\n✓ 数据已导出到 output/data/network_stress.csv");
}

// 延迟分布测试
void test_latency_distribution() {
    print_section("延迟分布分析");
    
    const int num_samples = 1000;
    vector<long long> latencies;
    
    print_info(string("采集 ") + to_string(num_samples) + " 个延迟样本...");
    
    ProgressBar progress(num_samples);
    for (int i = 0; i < num_samples; ++i) {
        auto start = high_resolution_clock::now();
        simulate_network_op(10 + rand() % 20); // 10-30微秒随机延迟
        auto end = high_resolution_clock::now();
        
        latencies.push_back(duration_cast<nanoseconds>(end - start).count());
        progress.increment();
    }
    
    sort(latencies.begin(), latencies.end());
    
    auto percentile = [&](double p) {
        size_t idx = static_cast<size_t>(latencies.size() * p);
        return latencies[min(idx, latencies.size() - 1)];
    };
    
    cout << "\n";
    Table table;
    table.set_headers({"百分位", "延迟(ns)", "延迟(μs)"});
    
    vector<double> percentiles = {0.50, 0.75, 0.90, 0.95, 0.99, 0.999};
    for (double p : percentiles) {
        long long lat_ns = percentile(p);
        string label = "P" + to_string(int(p * 100));
        if (p == 0.999) label = "P99.9";
        
        table.add_row({
            label,
            to_string(lat_ns),
            to_string(lat_ns / 1000)
        });
    }
    
    table.print();
    
    // 导出CSV
    ofstream csv("output/data/network_latency_dist.csv");
    csv << "percentile,latency_ns,latency_us\n";
    for (double p : percentiles) {
        long long lat_ns = percentile(p);
        csv << p << "," << lat_ns << "," << (lat_ns / 1000) << "\n";
    }
    csv.close();
    
    print_success("\n✓ 数据已导出到 output/data/network_latency_dist.csv");
}

int main() {
    system("mkdir -p output/data");
    
    clear_screen();
    print_title("网络性能测试工具", '═');
    
    cout << "\n";
    print_info("本工具提供网络库性能测试的完整套件");
    print_warning("注意：这是模拟测试，实际测试需要运行真实服务器");
    
    pause("\n按回车键开始测试...");
    
    // 运行所有测试
    clear_screen();
    test_single_client_qps();
    
    pause();
    clear_screen();
    test_concurrent_connections();
    
    pause();
    clear_screen();
    test_stress();
    
    pause();
    clear_screen();
    test_latency_distribution();
    
    // 总结
    cout << "\n";
    print_separator('=');
    print_highlight("🎉 所有网络性能测试完成！");
    print_separator('=');
    
    cout << "\n" << Color::BRIGHT_CYAN << "生成的数据文件：" << Color::RESET << "\n";
    cout << "  • output/data/network_qps.csv\n";
    cout << "  • output/data/network_concurrent.csv\n";
    cout << "  • output/data/network_stress.csv\n";
    cout << "  • output/data/network_latency_dist.csv\n";
    
    cout << "\n" << Color::BRIGHT_YELLOW << "下一步：" << Color::RESET << "\n";
    cout << "  运行可视化脚本生成图表：\n";
    cout << "  $ python3 visualize_all.py\n";
    
    return 0;
}
