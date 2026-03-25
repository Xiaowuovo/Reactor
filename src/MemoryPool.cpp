#include "MemoryPool.h"
#include <cstring>
#include <iostream>
#include <iomanip>
#include <sstream>

MemoryPool::MemoryPool(size_t block_size, size_t initial_blocks, size_t alignment)
    : block_size_(block_size), 
      alignment_(alignment),
      free_list_(nullptr),
      total_allocated_(0), 
      current_used_(0), 
      max_used_(0),
      allocation_count_(0), 
      deallocation_count_(0),
      expand_count_(0) {
  
  // 确保块大小至少能容纳链表指针
  if (block_size_ < sizeof(MemoryBlock)) {
    block_size_ = sizeof(MemoryBlock);
  }
  
  // 调整块大小为对齐字节数的倍数（提升缓存性能）
  if (block_size_ % alignment_ != 0) {
    block_size_ = ((block_size_ + alignment_ - 1) / alignment_) * alignment_;
  }
  
  // 预分配初始内存块
  expand(initial_blocks);
}

MemoryPool::~MemoryPool() {
  for (void* chunk : chunks_) {
    ::free(chunk);
  }
  chunks_.clear();
  free_list_ = nullptr;
}

void MemoryPool::expand(size_t block_count) {
  // 计算需要分配的总内存大小
  size_t chunk_size = block_size_ * block_count;
  
  // 分配对齐的内存块（使用 aligned_alloc 或 posix_memalign 更好，但为兼容性使用 malloc）
  void* chunk = ::malloc(chunk_size);
  
  if (chunk == nullptr) {
    throw std::bad_alloc();
  }
  
  // 保存大块指针，用于析构时释放
  chunks_.push_back(chunk);
  
  // 将大块内存切分成多个小块，并串成链表
  char* current = static_cast<char*>(chunk);
  for (size_t i = 0; i < block_count; ++i) {
    MemoryBlock* block = reinterpret_cast<MemoryBlock*>(current);
    block->next = free_list_;  // 头插法，O(1)
    free_list_ = block;
    current += block_size_;    // 移动到下一块
  }
  
  // 更新统计信息
  total_allocated_ += block_count;
  ++expand_count_;
}

void* MemoryPool::allocate() {
  // 无锁操作：因为是线程局部的
  if (free_list_ == nullptr) {
    expand(50);
  }
  
  MemoryBlock* block = free_list_;
  free_list_ = block->next;
  
  ++current_used_;
  ++allocation_count_;
  if (current_used_ > max_used_) {
    max_used_ = current_used_;
  }
  
  return block;
}

void MemoryPool::deallocate(void* ptr) {
  if (ptr == nullptr) {
    return;
  }
  
  // 无锁操作：因为是线程局部的
  MemoryBlock* block = static_cast<MemoryBlock*>(ptr);
  block->next = free_list_;
  free_list_ = block;
  
  --current_used_;
  ++deallocation_count_;
}

void MemoryPool::print_stats() const {
  std::cout << "\n========================================" << std::endl;
  std::cout << "   Memory Pool Statistics (Thread-Local)" << std::endl;
  std::cout << "========================================" << std::endl;
  
  // 基本配置信息
  std::cout << "\n[Configuration]" << std::endl;
  std::cout << "  Block Size      : " << block_size_ << " bytes" << std::endl;
  std::cout << "  Alignment       : " << alignment_ << " bytes" << std::endl;
  std::cout << "  Total Blocks    : " << total_allocated_ << std::endl;
  
  // 使用情况
  std::cout << "\n[Usage Statistics]" << std::endl;
  std::cout << "  Current Used    : " << current_used_ << " blocks" << std::endl;
  std::cout << "  Max Used        : " << max_used_ << " blocks" << std::endl;
  std::cout << "  Free Blocks     : " << (total_allocated_ - current_used_) << " blocks" << std::endl;
  std::cout << "  Usage Ratio     : " << std::fixed << std::setprecision(2) 
            << (get_usage_ratio() * 100) << "%" << std::endl;
  std::cout << "  Peak Ratio      : " << std::fixed << std::setprecision(2) 
            << (get_peak_usage_ratio() * 100) << "%" << std::endl;
  
  // 性能指标
  std::cout << "\n[Performance Metrics]" << std::endl;
  std::cout << "  Allocations     : " << allocation_count_ << " times" << std::endl;
  std::cout << "  Deallocations   : " << deallocation_count_ << " times" << std::endl;
  std::cout << "  Expansions      : " << expand_count_ << " times" << std::endl;
  
  // 内存占用
  std::cout << "\n[Memory Footprint]" << std::endl;
  std::cout << "  Total Memory    : " << std::fixed << std::setprecision(2)
            << (total_allocated_ * block_size_ / 1024.0) << " KB" << std::endl;
  std::cout << "  Used Memory     : " << std::fixed << std::setprecision(2)
            << (current_used_ * block_size_ / 1024.0) << " KB" << std::endl;
  std::cout << "  Free Memory     : " << std::fixed << std::setprecision(2)
            << ((total_allocated_ - current_used_) * block_size_ / 1024.0) << " KB" << std::endl;
  
  std::cout << "========================================\n" << std::endl;
}

std::string MemoryPool::export_stats_csv() const {
  std::ostringstream oss;
  oss << block_size_ << ","
      << total_allocated_ << ","
      << current_used_ << ","
      << max_used_ << ","
      << allocation_count_ << ","
      << deallocation_count_ << ","
      << expand_count_ << ","
      << std::fixed << std::setprecision(4) << get_usage_ratio();
  return oss.str();
}

void MemoryPool::reset_counters() {
  allocation_count_ = 0;
  deallocation_count_ = 0;
  max_used_ = current_used_;  // 重置峰值为当前值
  expand_count_ = 0;
}
