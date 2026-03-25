#include "BufferPool.h"
#include <cstring>
#include <iostream>
#include <sstream>
#include <iomanip>

// 初始化线程局部存储的三级内存池指针
thread_local MemoryPool* BufferPool::small_pool_ = nullptr;
thread_local MemoryPool* BufferPool::medium_pool_ = nullptr;
thread_local MemoryPool* BufferPool::large_pool_ = nullptr;

// 初始化可配置的阈值参数（默认值）
thread_local size_t BufferPool::small_threshold_ = 1024;    // 1KB
thread_local size_t BufferPool::medium_threshold_ = 4096;   // 4KB
thread_local size_t BufferPool::large_threshold_ = 16384;   // 16KB

// 预热状态标记
thread_local bool BufferPool::warmed_up_ = false;

void* BufferPool::allocate(size_t size) {
  // 根据动态阈值进行分配决策
  if (size <= small_threshold_) {
    // 懒初始化：第一次使用时才创建
    if (!small_pool_) {
      small_pool_ = new MemoryPool(1024, 100, 64);  // 1KB块，100个，64字节对齐
    }
    return small_pool_->allocate();
  } else if (size <= medium_threshold_) {
    if (!medium_pool_) {
      medium_pool_ = new MemoryPool(4096, 50, 64);  // 4KB块，50个，64字节对齐
    }
    return medium_pool_->allocate();
  } else if (size <= large_threshold_) {
    if (!large_pool_) {
      large_pool_ = new MemoryPool(16384, 25, 64);  // 16KB块，25个，64字节对齐
    }
    return large_pool_->allocate();
  } else {
    // 超大块直接用malloc（降级策略）
    return ::malloc(size);
  }
}

void BufferPool::deallocate(void* ptr, size_t size) {
  if (ptr == nullptr) return;
  
  // 根据动态阈值归还到对应的池
  if (size <= small_threshold_) {
    if (small_pool_) {
      small_pool_->deallocate(ptr);
    }
  } else if (size <= medium_threshold_) {
    if (medium_pool_) {
      medium_pool_->deallocate(ptr);
    }
  } else if (size <= large_threshold_) {
    if (large_pool_) {
      large_pool_->deallocate(ptr);
    }
  } else {
    // 超大块直接free
    ::free(ptr);
  }
}

void BufferPool::warmup(bool warmup_small, bool warmup_medium, bool warmup_large) {
  // 避免重复预热
  if (warmed_up_) {
    return;
  }
  
  std::cout << "\n[BufferPool Warmup] Initializing thread-local pools..." << std::endl;
  
  // 预热小池
  if (warmup_small && !small_pool_) {
    small_pool_ = new MemoryPool(1024, 100, 64);
    std::cout << "  ✓ Small Pool (1KB) initialized with 100 blocks" << std::endl;
  }
  
  // 预热中池
  if (warmup_medium && !medium_pool_) {
    medium_pool_ = new MemoryPool(4096, 50, 64);
    std::cout << "  ✓ Medium Pool (4KB) initialized with 50 blocks" << std::endl;
  }
  
  // 预热大池
  if (warmup_large && !large_pool_) {
    large_pool_ = new MemoryPool(16384, 25, 64);
    std::cout << "  ✓ Large Pool (16KB) initialized with 25 blocks" << std::endl;
  }
  
  warmed_up_ = true;
  std::cout << "[BufferPool Warmup] Complete!" << std::endl;
}

void BufferPool::set_thresholds(size_t small_threshold, 
                                 size_t medium_threshold, 
                                 size_t large_threshold) {
  if (small_threshold > 0) {
    small_threshold_ = small_threshold;
  }
  if (medium_threshold > 0) {
    medium_threshold_ = medium_threshold;
  }
  if (large_threshold > 0) {
    large_threshold_ = large_threshold;
  }
}

void BufferPool::print_stats() {
  std::cout << "\n========================================" << std::endl;
  std::cout << "  Thread-Local Buffer Pool Statistics" << std::endl;
  std::cout << "========================================" << std::endl;
  
  // 显示当前阈值配置
  std::cout << "\n[Threshold Configuration]" << std::endl;
  std::cout << "  Small Threshold  : <= " << small_threshold_ << " bytes" << std::endl;
  std::cout << "  Medium Threshold : <= " << medium_threshold_ << " bytes" << std::endl;
  std::cout << "  Large Threshold  : <= " << large_threshold_ << " bytes" << std::endl;
  std::cout << "  Warmed Up        : " << (warmed_up_ ? "Yes" : "No") << std::endl;
  
  // 显示各级池的统计信息
  if (small_pool_) {
    std::cout << "\n--- Small Pool (1KB) ---" << std::endl;
    small_pool_->print_stats();
  } else {
    std::cout << "\n--- Small Pool (1KB) ---" << std::endl;
    std::cout << "  [Not initialized yet]" << std::endl;
  }
  
  if (medium_pool_) {
    std::cout << "\n--- Medium Pool (4KB) ---" << std::endl;
    medium_pool_->print_stats();
  } else {
    std::cout << "\n--- Medium Pool (4KB) ---" << std::endl;
    std::cout << "  [Not initialized yet]" << std::endl;
  }
  
  if (large_pool_) {
    std::cout << "\n--- Large Pool (16KB) ---" << std::endl;
    large_pool_->print_stats();
  } else {
    std::cout << "\n--- Large Pool (16KB) ---" << std::endl;
    std::cout << "  [Not initialized yet]" << std::endl;
  }
  
  std::cout << "========================================\n" << std::endl;
}

void BufferPool::get_stats(size_t& small_allocs, size_t& medium_allocs, size_t& large_allocs) {
  small_allocs = small_pool_ ? small_pool_->get_allocation_count() : 0;
  medium_allocs = medium_pool_ ? medium_pool_->get_allocation_count() : 0;
  large_allocs = large_pool_ ? large_pool_->get_allocation_count() : 0;
}

std::string BufferPool::export_stats_csv() {
  std::ostringstream oss;
  
  // 导出分配次数
  size_t small_allocs = small_pool_ ? small_pool_->get_allocation_count() : 0;
  size_t medium_allocs = medium_pool_ ? medium_pool_->get_allocation_count() : 0;
  size_t large_allocs = large_pool_ ? large_pool_->get_allocation_count() : 0;
  
  // 导出使用率
  double small_usage = small_pool_ ? small_pool_->get_usage_ratio() : 0.0;
  double medium_usage = medium_pool_ ? medium_pool_->get_usage_ratio() : 0.0;
  double large_usage = large_pool_ ? large_pool_->get_usage_ratio() : 0.0;
  
  oss << small_allocs << ","
      << medium_allocs << ","
      << large_allocs << ","
      << std::fixed << std::setprecision(4) << small_usage << ","
      << std::fixed << std::setprecision(4) << medium_usage << ","
      << std::fixed << std::setprecision(4) << large_usage;
  
  return oss.str();
}

void BufferPool::reset_all_counters() {
  if (small_pool_) {
    small_pool_->reset_counters();
  }
  if (medium_pool_) {
    medium_pool_->reset_counters();
  }
  if (large_pool_) {
    large_pool_->reset_counters();
  }
}

// ===== PooledBuffer RAII 封装实现 =====

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
