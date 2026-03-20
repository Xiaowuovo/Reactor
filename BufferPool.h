#pragma once

#include "MemoryPool.h"
#include <memory>
#include <cstddef>

// BufferPool: 专门为网络缓冲区设计的内存池
// 管理多个不同大小的内存池，适应不同大小的数据包
class BufferPool {
 private:
  // 小块内存池：适用于小消息 (1KB)
  static MemoryPool small_pool_;
  // 中块内存池：适用于中等消息 (4KB)
  static MemoryPool medium_pool_;
  // 大块内存池：适用于大消息 (16KB)
  static MemoryPool large_pool_;
  
  static bool stats_enabled_;

 public:
  // 根据需要的大小，从合适的内存池分配内存
  static void* allocate(size_t size);
  
  // 归还内存到对应的内存池
  static void deallocate(void* ptr, size_t size);
  
  // 启用/禁用统计
  static void enable_stats(bool enable) { stats_enabled_ = enable; }
  
  // 打印所有内存池的统计信息
  static void print_all_stats();
  
  // 获取各个内存池的统计信息
  static const MemoryPool& get_small_pool() { return small_pool_; }
  static const MemoryPool& get_medium_pool() { return medium_pool_; }
  static const MemoryPool& get_large_pool() { return large_pool_; }
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
