#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <mutex>
#include <vector>

// 简易内存池实现
// 设计思路：
// 1. 预分配固定大小的内存块（例如1KB、4KB）
// 2. 使用空闲链表管理可用内存块
// 3. 申请时从池中获取，释放时放回池中
// 4. 避免频繁调用 new/delete，减少内存碎片
class MemoryPool {
 private:
  struct MemoryBlock {
    MemoryBlock* next;  // 指向下一个空闲块
  };

  size_t block_size_;           // 每个内存块的大小
  size_t block_count_;          // 预分配的内存块数量
  MemoryBlock* free_list_;      // 空闲链表头指针
  std::vector<void*> chunks_;   // 存储所有大块内存的指针，用于最终释放
  std::mutex mutex_;            // 保护内存池的互斥锁
  
  // 统计信息
  size_t total_allocated_;      // 总共分配的块数
  size_t current_used_;         // 当前使用的块数
  size_t max_used_;             // 历史最大使用块数
  size_t allocation_count_;     // 分配次数
  size_t deallocation_count_;   // 释放次数

 public:
  // 构造函数：指定块大小和预分配块数量
  // block_size: 每个内存块的大小（字节）
  // initial_blocks: 初始预分配的块数量
  MemoryPool(size_t block_size = 4096, size_t initial_blocks = 100);
  
  ~MemoryPool();

  // 从内存池中分配一个内存块
  void* allocate();

  // 将内存块归还到内存池
  void deallocate(void* ptr);

  // 获取统计信息
  size_t get_block_size() const { return block_size_; }
  size_t get_total_allocated() const { return total_allocated_; }
  size_t get_current_used() const { return current_used_; }
  size_t get_max_used() const { return max_used_; }
  size_t get_allocation_count() const { return allocation_count_; }
  size_t get_deallocation_count() const { return deallocation_count_; }
  
  // 打印统计信息
  void print_stats() const;

 private:
  // 扩展内存池：分配新的大块内存
  void expand(size_t block_count);
  
  // 禁用拷贝构造和赋值
  MemoryPool(const MemoryPool&) = delete;
  MemoryPool& operator=(const MemoryPool&) = delete;
};
