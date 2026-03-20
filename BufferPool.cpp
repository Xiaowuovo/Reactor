#include "BufferPool.h"
#include <cstring>
#include <iostream>

// 初始化线程局部存储的静态成员
thread_local MemoryPool* BufferPool::small_pool_ = nullptr;
thread_local MemoryPool* BufferPool::medium_pool_ = nullptr;
thread_local MemoryPool* BufferPool::large_pool_ = nullptr;

void* BufferPool::allocate(size_t size) {
  if (size <= 1024) {
    // 懒初始化：第一次使用时才创建
    if (!small_pool_) {
      small_pool_ = new MemoryPool(1024, 100);  // 1KB块，预分配100个
    }
    return small_pool_->allocate();
  } else if (size <= 4096) {
    if (!medium_pool_) {
      medium_pool_ = new MemoryPool(4096, 50);  // 4KB块，预分配50个
    }
    return medium_pool_->allocate();
  } else if (size <= 16384) {
    if (!large_pool_) {
      large_pool_ = new MemoryPool(16384, 25);  // 16KB块，预分配25个
    }
    return large_pool_->allocate();
  } else {
    // 超大块直接用malloc
    return ::malloc(size);
  }
}

void BufferPool::deallocate(void* ptr, size_t size) {
  if (ptr == nullptr) return;
  
  if (size <= 1024) {
    if (small_pool_) {
      small_pool_->deallocate(ptr);
    }
  } else if (size <= 4096) {
    if (medium_pool_) {
      medium_pool_->deallocate(ptr);
    }
  } else if (size <= 16384) {
    if (large_pool_) {
      large_pool_->deallocate(ptr);
    }
  } else {
    ::free(ptr);
  }
}

void BufferPool::print_stats() {
  std::cout << "\n========================================" << std::endl;
  std::cout << "  Thread-Local Buffer Pool Statistics" << std::endl;
  std::cout << "========================================" << std::endl;
  
  if (small_pool_) {
    std::cout << "\n--- Small Pool (1KB) ---" << std::endl;
    small_pool_->print_stats();
  }
  
  if (medium_pool_) {
    std::cout << "\n--- Medium Pool (4KB) ---" << std::endl;
    medium_pool_->print_stats();
  }
  
  if (large_pool_) {
    std::cout << "\n--- Large Pool (16KB) ---" << std::endl;
    large_pool_->print_stats();
  }
  
  std::cout << std::endl;
}

void BufferPool::get_stats(size_t& small_allocs, size_t& medium_allocs, size_t& large_allocs) {
  small_allocs = small_pool_ ? small_pool_->get_allocation_count() : 0;
  medium_allocs = medium_pool_ ? medium_pool_->get_allocation_count() : 0;
  large_allocs = large_pool_ ? large_pool_->get_allocation_count() : 0;
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
