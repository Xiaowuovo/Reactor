#include "MemoryPool.h"
#include <cstring>
#include <iostream>

MemoryPool::MemoryPool(size_t block_size, size_t initial_blocks)
    : block_size_(block_size), 
      free_list_(nullptr),
      total_allocated_(0), 
      current_used_(0), 
      max_used_(0),
      allocation_count_(0), 
      deallocation_count_(0) {
  if (block_size_ < sizeof(MemoryBlock)) {
    block_size_ = sizeof(MemoryBlock);
  }
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
  size_t chunk_size = block_size_ * block_count;
  void* chunk = ::malloc(chunk_size);
  
  if (chunk == nullptr) {
    throw std::bad_alloc();
  }
  
  chunks_.push_back(chunk);
  
  char* current = static_cast<char*>(chunk);
  for (size_t i = 0; i < block_count; ++i) {
    MemoryBlock* block = reinterpret_cast<MemoryBlock*>(current);
    block->next = free_list_;
    free_list_ = block;
    current += block_size_;
  }
  
  total_allocated_ += block_count;
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
