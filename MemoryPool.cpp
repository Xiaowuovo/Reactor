#include "MemoryPool.h"
#include <iostream>
#include <cstring>

MemoryPool::MemoryPool(size_t block_size, size_t initial_blocks)
    : block_size_(block_size),
      block_count_(0),
      free_list_(nullptr),
      total_allocated_(0),
      current_used_(0),
      max_used_(0),
      allocation_count_(0),
      deallocation_count_(0) {
  // 确保块大小至少能容纳指针（用于构建空闲链表）
  if (block_size_ < sizeof(MemoryBlock)) {
    block_size_ = sizeof(MemoryBlock);
  }
  
  // 预分配初始内存块
  if (initial_blocks > 0) {
    expand(initial_blocks);
  }
}

MemoryPool::~MemoryPool() {
  // 释放所有大块内存
  for (void* chunk : chunks_) {
    ::free(chunk);
  }
  chunks_.clear();
  free_list_ = nullptr;
}

void MemoryPool::expand(size_t block_count) {
  // 分配一大块连续内存
  size_t chunk_size = block_size_ * block_count;
  void* chunk = ::malloc(chunk_size);
  
  if (chunk == nullptr) {
    throw std::bad_alloc();
  }
  
  // 保存这块内存的指针，用于最后释放
  chunks_.push_back(chunk);
  
  // 将这块内存切分成多个小块，并加入空闲链表
  char* current = static_cast<char*>(chunk);
  for (size_t i = 0; i < block_count; ++i) {
    MemoryBlock* block = reinterpret_cast<MemoryBlock*>(current);
    block->next = free_list_;
    free_list_ = block;
    current += block_size_;
  }
  
  block_count_ += block_count;
  total_allocated_ += block_count;
}

void* MemoryPool::allocate() {
  std::lock_guard<std::mutex> lock(mutex_);
  
  // 如果空闲链表为空，扩展内存池
  if (free_list_ == nullptr) {
    // 每次扩展时增加50个块
    expand(50);
  }
  
  // 从空闲链表头部取出一个块
  MemoryBlock* block = free_list_;
  free_list_ = block->next;
  
  // 更新统计信息
  ++current_used_;
  ++allocation_count_;
  if (current_used_ > max_used_) {
    max_used_ = current_used_;
  }
  
  // 将内存清零（可选，根据需求决定）
  std::memset(block, 0, block_size_);
  
  return block;
}

void MemoryPool::deallocate(void* ptr) {
  if (ptr == nullptr) {
    return;
  }
  
  std::lock_guard<std::mutex> lock(mutex_);
  
  // 将块加入空闲链表头部
  MemoryBlock* block = static_cast<MemoryBlock*>(ptr);
  block->next = free_list_;
  free_list_ = block;
  
  // 更新统计信息
  --current_used_;
  ++deallocation_count_;
}

void MemoryPool::print_stats() const {
  std::cout << "=== Memory Pool Statistics ===" << std::endl;
  std::cout << "Block Size: " << block_size_ << " bytes" << std::endl;
  std::cout << "Total Allocated Blocks: " << total_allocated_ << std::endl;
  std::cout << "Current Used Blocks: " << current_used_ << std::endl;
  std::cout << "Max Used Blocks: " << max_used_ << std::endl;
  std::cout << "Allocation Count: " << allocation_count_ << std::endl;
  std::cout << "Deallocation Count: " << deallocation_count_ << std::endl;
  std::cout << "Total Memory: " << (total_allocated_ * block_size_ / 1024.0) << " KB" << std::endl;
  std::cout << "Used Memory: " << (current_used_ * block_size_ / 1024.0) << " KB" << std::endl;
  std::cout << "=============================" << std::endl;
}
