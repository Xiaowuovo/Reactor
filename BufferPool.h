#pragma once

#include "MemoryPool.h"
#include <memory>
#include <cstddef>

// BufferPool: 线程局部缓冲区内存池（无锁版本）
// 每个线程拥有独立的内存池实例，完全无竞争
// 管理多个不同大小的内存池，适应不同大小的数据包
class BufferPool {
 private:
  // 线程局部存储的内存池
  // 小块内存池：适用于小消息 (1KB)
  static thread_local MemoryPool* small_pool_;
  // 中块内存池：适用于中等消息 (4KB)
  static thread_local MemoryPool* medium_pool_;
  // 大块内存池：适用于大消息 (16KB)
  static thread_local MemoryPool* large_pool_;

 public:
  // 根据需要的大小，从合适的内存池分配内存（无锁）
  static void* allocate(size_t size);
  
  // 归还内存到对应的内存池（无锁）
  static void deallocate(void* ptr, size_t size);
  
  // 打印当前线程的内存池统计信息
  static void print_stats();
  
  // 获取当前线程的内存池统计信息
  static void get_stats(size_t& small_allocs, size_t& medium_allocs, size_t& large_allocs);
};

// RAII封装的内存块，自动管理内存的分配和释放
class PooledBuffer {
 private:
  void* data_;
  size_t size_;
  
 public:
  PooledBuffer(size_t size);
  ~PooledBuffer();
  
  // 禁用拷贝
  PooledBuffer(const PooledBuffer&) = delete;
  PooledBuffer& operator=(const PooledBuffer&) = delete;
  
  // 支持移动
  PooledBuffer(PooledBuffer&& other) noexcept;
  PooledBuffer& operator=(PooledBuffer&& other) noexcept;
  
  void* data() { return data_; }
  const void* data() const { return data_; }
  size_t size() const { return size_; }
};
