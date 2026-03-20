#include "MemoryPool.h"
#include "BufferPool.h"
#include <iostream>
#include <chrono>
#include <vector>
#include <random>

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
    cout << "\n=== Test 3: BufferPool Multi-Size Allocation ===" << endl;
    
    cout << "Allocating various sizes..." << endl;
    void* small = BufferPool::allocate(512);    // Should use small pool
    void* medium = BufferPool::allocate(2048);  // Should use medium pool
    void* large = BufferPool::allocate(8192);   // Should use large pool
    
    cout << "Small block: " << small << endl;
    cout << "Medium block: " << medium << endl;
    cout << "Large block: " << large << endl;
    
    BufferPool::print_all_stats();
    
    cout << "Deallocating..." << endl;
    BufferPool::deallocate(small, 512);
    BufferPool::deallocate(medium, 2048);
    BufferPool::deallocate(large, 8192);
    
    BufferPool::print_all_stats();
    
    cout << "Test 3 PASSED!" << endl;
}

void test_pooled_buffer() {
    cout << "\n=== Test 4: PooledBuffer RAII Test ===" << endl;
    
    {
        PooledBuffer buf1(1024);
        cout << "Created buf1 (1KB)" << endl;
        
        PooledBuffer buf2(4096);
        cout << "Created buf2 (4KB)" << endl;
        
        BufferPool::print_all_stats();
        
        cout << "Buffers will be auto-released when going out of scope..." << endl;
    }
    
    cout << "\nAfter scope exit:" << endl;
    BufferPool::print_all_stats();
    
    cout << "Test 4 PASSED!" << endl;
}

void benchmark_malloc_vs_pool() {
    cout << "\n=== Benchmark: malloc vs MemoryPool ===" << endl;
    
    const int ITERATIONS = 100000;
    const size_t BLOCK_SIZE = 1024;
    
    // Benchmark standard malloc/free
    auto start = high_resolution_clock::now();
    for (int i = 0; i < ITERATIONS; ++i) {
        void* ptr = malloc(BLOCK_SIZE);
        free(ptr);
    }
    auto end = high_resolution_clock::now();
    auto malloc_time = duration_cast<milliseconds>(end - start).count();
    
    // Benchmark MemoryPool
    MemoryPool pool(BLOCK_SIZE, 100);
    start = high_resolution_clock::now();
    for (int i = 0; i < ITERATIONS; ++i) {
        void* ptr = pool.allocate();
        pool.deallocate(ptr);
    }
    end = high_resolution_clock::now();
    auto pool_time = duration_cast<milliseconds>(end - start).count();
    
    cout << "Iterations: " << ITERATIONS << endl;
    cout << "Block Size: " << BLOCK_SIZE << " bytes" << endl;
    cout << "malloc/free time: " << malloc_time << " ms" << endl;
    cout << "MemoryPool time: " << pool_time << " ms" << endl;
    cout << "Speedup: " << (double)malloc_time / pool_time << "x" << endl;
    
    pool.print_stats();
}

void benchmark_realistic_workload() {
    cout << "\n=== Benchmark: Realistic Network Buffer Workload ===" << endl;
    
    const int ITERATIONS = 50000;
    random_device rd;
    mt19937 gen(rd());
    uniform_int_distribution<> size_dist(100, 8000);
    
    // Benchmark with BufferPool
    auto start = high_resolution_clock::now();
    for (int i = 0; i < ITERATIONS; ++i) {
        size_t size = size_dist(gen);
        void* ptr = BufferPool::allocate(size);
        BufferPool::deallocate(ptr, size);
    }
    auto end = high_resolution_clock::now();
    auto pool_time = duration_cast<milliseconds>(end - start).count();
    
    // Benchmark with malloc
    start = high_resolution_clock::now();
    for (int i = 0; i < ITERATIONS; ++i) {
        size_t size = size_dist(gen);
        void* ptr = malloc(size);
        free(ptr);
    }
    end = high_resolution_clock::now();
    auto malloc_time = duration_cast<milliseconds>(end - start).count();
    
    cout << "Iterations: " << ITERATIONS << endl;
    cout << "Size range: 100-8000 bytes (random)" << endl;
    cout << "malloc/free time: " << malloc_time << " ms" << endl;
    cout << "BufferPool time: " << pool_time << " ms" << endl;
    cout << "Speedup: " << (double)malloc_time / pool_time << "x" << endl;
    
    cout << "\nBufferPool Statistics:" << endl;
    BufferPool::print_all_stats();
}

int main() {
    cout << "========================================" << endl;
    cout << "  Memory Pool Unit Tests & Benchmarks" << endl;
    cout << "========================================" << endl;
    
    try {
        test_memory_pool_basic();
        test_memory_pool_expansion();
        test_buffer_pool();
        test_pooled_buffer();
        benchmark_malloc_vs_pool();
        benchmark_realistic_workload();
        
        cout << "\n========================================" << endl;
        cout << "  All Tests PASSED!" << endl;
        cout << "========================================" << endl;
        
    } catch (const exception& e) {
        cerr << "Test failed with exception: " << e.what() << endl;
        return 1;
    }
    
    return 0;
}
