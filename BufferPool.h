#pragma once

#include "MemoryPool.h"
#include <memory>
#include <cstddef>
#include <string>

/**
 * @brief 线程局部三级缓冲区内存池（无锁、智能分配版本）
 * 
 * 核心设计：
 * 1. 三级分层策略：根据数据包大小智能选择合适的内存池
 * 2. 线程局部存储：每个线程独立的池实例，零竞争
 * 3. 懒初始化：按需创建，节省资源
 * 4. 预热机制：支持启动时预分配，减少运行时延迟
 * 5. 统计分析：详细的使用统计，用于性能调优
 * 
 * 三级池配置：
 * - Small Pool (1KB)  : 0 < size <= 1024，适用于控制消息、小数据包
 * - Medium Pool (4KB) : 1024 < size <= 4096，适用于常规数据、JSON等
 * - Large Pool (16KB) : 4096 < size <= 16384，适用于大文件块、视频流
 * - Fallback (malloc) : size > 16384，超大包直接使用系统分配器
 * 
 * 性能优势：
 * - 分层设计避免内存浪费（小消息不占用大块）
 * - 命中率高（大部分网络包在1-4KB范围）
 * - 完全无锁，适合高并发场景
 * 
 * @note 设计为静态类，所有成员和方法均为静态/thread_local
 */
class BufferPool {
 private:
  // ===== 线程局部存储的三级内存池 =====
  
  /** @brief 小块内存池：1KB，适用于小消息（控制命令、心跳包等） */
  static thread_local MemoryPool* small_pool_;
  
  /** @brief 中块内存池：4KB，适用于中等消息（JSON数据、普通文件等） */
  static thread_local MemoryPool* medium_pool_;
  
  /** @brief 大块内存池：16KB，适用于大消息（大文件、视频流等） */
  static thread_local MemoryPool* large_pool_;
  
  // ===== 可配置的阈值参数（用于动态调整策略） =====
  
  /** @brief 小池上限阈值（默认1024字节） */
  static thread_local size_t small_threshold_;
  
  /** @brief 中池上限阈值（默认4096字节） */
  static thread_local size_t medium_threshold_;
  
  /** @brief 大池上限阈值（默认16384字节） */
  static thread_local size_t large_threshold_;
  
  /** @brief 是否已预热（避免重复预热） */
  static thread_local bool warmed_up_;

 public:
  /**
   * @brief 根据大小智能分配内存（O(1) 无锁操作）
   * 
   * @param size 需要分配的字节数
   * @return void* 指向已分配内存的指针
   * @throw std::bad_alloc 如果系统内存不足
   * 
   * @note 分配策略：
   *   - size <= 1KB    → Small Pool
   *   - size <= 4KB    → Medium Pool
   *   - size <= 16KB   → Large Pool
   *   - size > 16KB    → malloc (直接系统分配)
   * 
   * @note 懒初始化：第一次使用某级池时才创建
   */
  static void* allocate(size_t size);
  
  /**
   * @brief 归还内存到对应的内存池（O(1) 无锁操作）
   * 
   * @param ptr 要释放的内存指针
   * @param size 内存块的大小（用于判断归还到哪个池）
   * 
   * @note 如果 ptr 为 nullptr，则安全忽略
   * @warning size 必须与 allocate 时的大小一致
   */
  static void deallocate(void* ptr, size_t size);
  
  /**
   * @brief 预热内存池：提前创建并预分配内存（减少运行时延迟）
   * 
   * @param warmup_small 是否预热小池（默认true）
   * @param warmup_medium 是否预热中池（默认true）
   * @param warmup_large 是否预热大池（默认true）
   * 
   * @note 建议在线程启动后、处理请求前调用
   * @note 重复调用是安全的（有状态检查）
   */
  static void warmup(bool warmup_small = true, 
                     bool warmup_medium = true, 
                     bool warmup_large = true);
  
  /**
   * @brief 动态调整阈值策略（用于性能调优）
   * 
   * @param small_threshold 小池上限（字节），0表示不改变
   * @param medium_threshold 中池上限（字节），0表示不改变
   * @param large_threshold 大池上限（字节），0表示不改变
   * 
   * @note 调整后立即生效，影响后续的 allocate 调用
   * @note 已分配的内存不受影响
   */
  static void set_thresholds(size_t small_threshold = 0,
                             size_t medium_threshold = 0,
                             size_t large_threshold = 0);
  
  /**
   * @brief 打印当前线程的三级内存池统计信息
   * 
   * @note 输出包括：每级池的配置、使用情况、性能指标
   */
  static void print_stats();
  
  /**
   * @brief 获取当前线程的内存池统计信息
   * 
   * @param[out] small_allocs 小池累计分配次数
   * @param[out] medium_allocs 中池累计分配次数
   * @param[out] large_allocs 大池累计分配次数
   */
  static void get_stats(size_t& small_allocs, size_t& medium_allocs, size_t& large_allocs);
  
  /**
   * @brief 导出三级池的统计信息为 CSV 格式
   * 
   * @return std::string CSV 格式字符串
   * 
   * @note 格式：small_allocs,medium_allocs,large_allocs,small_usage,medium_usage,large_usage
   */
  static std::string export_stats_csv();
  
  /**
   * @brief 重置所有内存池的统计计数器
   * 
   * @note 保留已分配的内存，仅重置计数器
   */
  static void reset_all_counters();
};

/**
 * @brief RAII 封装的内存块，自动管理生命周期
 * 
 * 设计优势：
 * - 自动分配：构造时从 BufferPool 分配
 * - 自动释放：析构时归还到 BufferPool
 * - 移动语义：支持高效的所有权转移
 * - 禁用拷贝：避免意外的内存拷贝开销
 * 
 * 使用示例：
 * @code
 * {
 *   PooledBuffer buf(4096);  // 自动从池中分配
 *   memcpy(buf.data(), source, 4096);
 *   // ...
 * }  // 自动归还到池
 * @endcode
 */
class PooledBuffer {
 private:
  void* data_;   ///< 指向分配的内存块
  size_t size_;  ///< 内存块大小（字节）
  
 public:
  /**
   * @brief 构造函数：从 BufferPool 分配指定大小的内存
   * 
   * @param size 需要分配的字节数
   * @throw std::bad_alloc 如果分配失败
   */
  explicit PooledBuffer(size_t size);
  
  /**
   * @brief 析构函数：自动归还内存到 BufferPool
   */
  ~PooledBuffer();
  
  // 禁用拷贝构造和拷贝赋值（避免意外的深拷贝）
  PooledBuffer(const PooledBuffer&) = delete;
  PooledBuffer& operator=(const PooledBuffer&) = delete;
  
  /**
   * @brief 移动构造函数：转移所有权
   * 
   * @param other 源对象（移动后将被置空）
   */
  PooledBuffer(PooledBuffer&& other) noexcept;
  
  /**
   * @brief 移动赋值运算符：转移所有权
   * 
   * @param other 源对象（移动后将被置空）
   * @return PooledBuffer& 当前对象的引用
   */
  PooledBuffer& operator=(PooledBuffer&& other) noexcept;
  
  /** @brief 获取内存块指针（可写） */
  void* data() { return data_; }
  
  /** @brief 获取内存块指针（只读） */
  const void* data() const { return data_; }
  
  /** @brief 获取内存块大小 */
  size_t size() const { return size_; }
  
  /** @brief 检查是否有效（是否持有内存） */
  bool valid() const { return data_ != nullptr; }
};
