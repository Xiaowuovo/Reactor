#pragma once

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <vector>

// 线程局部内存池实现（无锁版本）
// 设计思路：
// 1. 每个线程拥有独立的内存池实例（thread_local）
// 2. 无需加锁，完全无竞争
// 3. 预分配固定大小的内存块
// 4. 使用空闲链表管理可用内存块
// 5. 适合 one loop per thread 模型
class MemoryPool {
 private:
  struct MemoryBlock {
    MemoryBlock* next;  // 指向下一个空闲块
  };

  size_t block_size_;           // 每个内存块的大小
  MemoryBlock* free_list_;      // 空闲链表头指针
  std::vector<void*> chunks_;   // 存储所有大块内存的指针，用于最终释放
  
  // 统计信息（无需原子操作，因为是线程局部的）
  size_t total_allocated_;      // 总共分配的块数
  size_t current_used_;         // 当前使用的块数
  size_t max_used_;             // 历史最大使用块数
  size_t allocation_count_;     // 分配次数
  size_t deallocation_count_;   // 释放次数

 public:
  // 构造函数：指定块大小和预分配块数量
  MemoryPool(size_t block_size = 4096, size_t initial_blocks = 50);
  
  ~MemoryPool();

  // 从内存池中分配一个内存块（无锁）
  void* allocate();

  // 将内存块归还到内存池（无锁）
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
