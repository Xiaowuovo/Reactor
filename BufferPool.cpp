#include "BufferPool.h"
#include <cstring>
#include <iostream>

// 初始化静态成员
// 小块: 1KB，预分配200块
MemoryPool BufferPool::small_pool_(1024, 200);
// 中块: 4KB，预分配100块
MemoryPool BufferPool::medium_pool_(4096, 100);
// 大块: 16KB，预分配50块
MemoryPool BufferPool::large_pool_(16384, 50);

bool BufferPool::stats_enabled_ = false;

void* BufferPool::allocate(size_t size) {
  // 根据大小选择合适的内存池
  if (size <= 1024) {
    return small_pool_.allocate();
  } else if (size <= 4096) {
    return medium_pool_.allocate();
  } else if (size <= 16384) {
    return large_pool_.allocate();
  } else {
    // 如果超过最大池大小，直接使用malloc
    return ::malloc(size);
  }
}

void BufferPool::deallocate(void* ptr, size_t size) {
  if (ptr == nullptr) {
    return;
  }
  
  // 根据大小归还到对应的内存池
  if (size <= 1024) {
    small_pool_.deallocate(ptr);
  } else if (size <= 4096) {
    medium_pool_.deallocate(ptr);
  } else if (size <= 16384) {
    large_pool_.deallocate(ptr);
  } else {
    // 如果是malloc分配的，直接free
    ::free(ptr);
  }
}

void BufferPool::print_all_stats() {
  std::cout << "\n========================================" << std::endl;
  std::cout << "       Buffer Pool Statistics" << std::endl;
  std::cout << "========================================\n" << std::endl;
  
  std::cout << "--- Small Pool (1KB) ---" << std::endl;
  small_pool_.print_stats();
  std::cout << std::endl;
  
  std::cout << "--- Medium Pool (4KB) ---" << std::endl;
  medium_pool_.print_stats();
  std::cout << std::endl;
  
  std::cout << "--- Large Pool (16KB) ---" << std::endl;
  large_pool_.print_stats();
  std::cout << std::endl;
}

// PooledBuffer 实现
PooledBuffer::PooledBuffer(size_t size) : data_(nullptr), size_(size) {
  if (size > 0) {
    data_ = BufferPool::allocate(size);
  }
}

PooledBuffer::~PooledBuffer() {
  if (data_ != nullptr) {
    BufferPool::deallocate(data_, size_);
    data_ = nullptr;
  }
}

PooledBuffer::PooledBuffer(PooledBuffer&& other) noexcept
    : data_(other.data_), size_(other.size_) {
  other.data_ = nullptr;
  other.size_ = 0;
}

PooledBuffer& PooledBuffer::operator=(PooledBuffer&& other) noexcept {
  if (this != &other) {
    // 释放当前资源
    if (data_ != nullptr) {
      BufferPool::deallocate(data_, size_);
    }
    
    // 转移资源
    data_ = other.data_;
    size_ = other.size_;
    
    // 清空源对象
    other.data_ = nullptr;
    other.size_ = 0;
  }
  return *this;
}
