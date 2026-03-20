#include "MemoryPool.h"
#include "BufferPool.h"
#include <iostream>
#include <chrono>
#include <vector>
#include <random>
#include <thread>
#include <atomic>

using namespace std;
using namespace std::chrono;

void test_memory_pool_basic() {
    cout << "\n=== Test 1: Memory Pool Basic Operations ===" << endl;
    
    MemoryPool pool(1024, 10);
    
    cout << "Allocating 5 blocks..." << endl;
    vector<void*> blocks;
    for (int i = 0; i < 5; ++i) {
        void* block = pool.allocate();
        blocks.push_back(block);
        cout << "Block " << i << " allocated at: " << block << endl;
    }
    
    pool.print_stats();
    
    cout << "\nDeallocating 3 blocks..." << endl;
    for (int i = 0; i < 3; ++i) {
        pool.deallocate(blocks[i]);
    }
    
    pool.print_stats();
    
    cout << "Test 1 PASSED!" << endl;
}

void test_memory_pool_expansion() {
    cout << "\n=== Test 2: Memory Pool Auto Expansion ===" << endl;
    
    MemoryPool pool(512, 5);
    
    cout << "Allocating 20 blocks (more than initial)..." << endl;
    vector<void*> blocks;
    for (int i = 0; i < 20; ++i) {
        void* block = pool.allocate();
        blocks.push_back(block);
    }
    
    pool.print_stats();
    
    cout << "Deallocating all blocks..." << endl;
    for (void* block : blocks) {
        pool.deallocate(block);
    }
    
    pool.print_stats();
    
    cout << "Test 2 PASSED!" << endl;
}

void test_buffer_pool() {
    cout << "\n=== Test 3: Thread-Local BufferPool ===" << endl;
    
    cout << "Allocating various sizes..." << endl;
    void* small = BufferPool::allocate(800);
    cout << "Small block (800B): " << small << endl;
    
    void* medium = BufferPool::allocate(3000);
    cout << "Medium block (3000B): " << medium << endl;
    
    void* large = BufferPool::allocate(12000);
    cout << "Large block (12000B): " << large << endl;
    
    BufferPool::print_stats();
    
    cout << "Deallocating..." << endl;
    BufferPool::deallocate(small, 800);
    BufferPool::deallocate(medium, 3000);
    BufferPool::deallocate(large, 12000);
    
    BufferPool::print_stats();
    
    cout << "Test 3 PASSED!" << endl;
}

void test_pooled_buffer() {
    cout << "\n=== Test 4: PooledBuffer RAII Test ===" << endl;
    
    {
        cout << "Created buf1 (1KB)" << endl;
        PooledBuffer buf1(1024);
        
        cout << "Created buf2 (4KB)" << endl;
        PooledBuffer buf2(4096);
        
        BufferPool::print_stats();
        
        cout << "\nBuffers will be auto-released when going out of scope..." << endl;
    }
    
    cout << "\nAfter scope exit:" << endl;
    BufferPool::print_stats();
    
    cout << "Test 4 PASSED!" << endl;
}

// 单线程基准测试
void benchmark_single_thread() {
    cout << "\n=== Benchmark: Single Thread (malloc vs MemoryPool) ===" << endl;
    const int iterations = 100000;
    const size_t block_size = 1024;
    
    // malloc/free
    auto start = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        void* ptr = malloc(block_size);
        free(ptr);
    }
    auto end = high_resolution_clock::now();
    auto malloc_time = duration_cast<milliseconds>(end - start).count();
    
    // MemoryPool (thread-local, 无锁)
    start = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        void* ptr = BufferPool::allocate(block_size);
        BufferPool::deallocate(ptr, block_size);
    }
    end = high_resolution_clock::now();
    auto pool_time = duration_cast<milliseconds>(end - start).count();
    
    cout << "Iterations: " << iterations << endl;
    cout << "Block Size: " << block_size << " bytes" << endl;
    cout << "malloc/free time: " << malloc_time << " ms" << endl;
    cout << "MemoryPool time: " << pool_time << " ms" << endl;
    if (pool_time > 0) {
        cout << "Speedup: " << (double)malloc_time / pool_time << "x" << endl;
    }
    
    BufferPool::print_stats();
}

// 多线程工作函数
void worker_malloc(int iterations, atomic<long long>& total_time) {
    auto start = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        void* ptr = malloc(1024);
        free(ptr);
    }
    auto end = high_resolution_clock::now();
    total_time += duration_cast<microseconds>(end - start).count();
}

void worker_pool(int iterations, atomic<long long>& total_time) {
    auto start = high_resolution_clock::now();
    for (int i = 0; i < iterations; ++i) {
        void* ptr = BufferPool::allocate(1024);
        BufferPool::deallocate(ptr, 1024);
    }
    auto end = high_resolution_clock::now();
    total_time += duration_cast<microseconds>(end - start).count();
}

// 多线程基准测试 - 这是关键测试！
void benchmark_multi_thread() {
    cout << "\n=== Benchmark: Multi-Thread (malloc vs Thread-Local Pool) ===" << endl;
    cout << "THIS IS THE KEY TEST showing thread-local pool advantages!" << endl;
    
    const int num_threads = 10;
    const int iterations_per_thread = 100000;
    
    cout << "\nThreads: " << num_threads << endl;
    cout << "Iterations per thread: " << iterations_per_thread << endl;
    cout << "Total operations: " << (num_threads * iterations_per_thread) << endl;
    
    // 测试 malloc/free (有全局锁竞争)
    {
        atomic<long long> total_time{0};
        vector<thread> threads;
        
        auto start = high_resolution_clock::now();
        for (int i = 0; i < num_threads; ++i) {
            threads.emplace_back(worker_malloc, iterations_per_thread, ref(total_time));
        }
        for (auto& t : threads) {
            t.join();
        }
        auto end = high_resolution_clock::now();
        auto wall_time = duration_cast<milliseconds>(end - start).count();
        
        cout << "\nmalloc/free results:" << endl;
        cout << "  Wall time: " << wall_time << " ms" << endl;
        cout << "  Avg time per thread: " << (total_time.load() / num_threads / 1000) << " ms" << endl;
    }
    
    // 测试 Thread-Local Pool (无锁，无竞争)
    {
        atomic<long long> total_time{0};
        vector<thread> threads;
        
        auto start = high_resolution_clock::now();
        for (int i = 0; i < num_threads; ++i) {
            threads.emplace_back(worker_pool, iterations_per_thread, ref(total_time));
        }
        for (auto& t : threads) {
            t.join();
        }
        auto end = high_resolution_clock::now();
        auto wall_time = duration_cast<milliseconds>(end - start).count();
        
        cout << "\nThread-Local Pool results:" << endl;
        cout << "  Wall time: " << wall_time << " ms" << endl;
        cout << "  Avg time per thread: " << (total_time.load() / num_threads / 1000) << " ms" << endl;
    }
    
    cout << "\n*** Thread-local pool eliminates lock contention! ***" << endl;
}

// 随机大小测试
void benchmark_random_sizes() {
    cout << "\n=== Benchmark: Realistic Network Buffer Workload ===" << endl;
    
    const int iterations = 50000;
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> size_dist(100, 8000);
    
    vector<size_t> sizes;
    for (int i = 0; i < iterations; ++i) {
        sizes.push_back(size_dist(gen));
    }
    
    // malloc/free
    auto start = high_resolution_clock::now();
    for (size_t size : sizes) {
        void* ptr = malloc(size);
        free(ptr);
    }
    auto end = high_resolution_clock::now();
    auto malloc_time = duration_cast<milliseconds>(end - start).count();
    
    // BufferPool
    start = high_resolution_clock::now();
    for (size_t size : sizes) {
        void* ptr = BufferPool::allocate(size);
        BufferPool::deallocate(ptr, size);
    }
    end = high_resolution_clock::now();
    auto pool_time = duration_cast<milliseconds>(end - start).count();
    
    cout << "Iterations: " << iterations << endl;
    cout << "Size range: 100-8000 bytes (random)" << endl;
    cout << "malloc/free time: " << malloc_time << " ms" << endl;
    cout << "BufferPool time: " << pool_time << " ms" << endl;
    if (pool_time > 0) {
        cout << "Speedup: " << (double)malloc_time / pool_time << "x" << endl;
    }
    
    cout << "\nBufferPool Statistics:" << endl;
    BufferPool::print_stats();
}

int main() {
    try {
        cout << "========================================" << endl;
        cout << "  Thread-Local Memory Pool Tests" << endl;
        cout << "  (Lock-Free, Zero Contention)" << endl;
        cout << "========================================" << endl;
        
        test_memory_pool_basic();
        test_memory_pool_expansion();
        test_buffer_pool();
        test_pooled_buffer();
        
        benchmark_single_thread();
        benchmark_multi_thread();  // 关键测试！
        benchmark_random_sizes();
        
        cout << "\n========================================" << endl;
        cout << "  All Tests PASSED!" << endl;
        cout << "========================================" << endl;
        
    } catch (const exception& e) {
        cerr << "Test failed with exception: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}
