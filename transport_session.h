#ifndef TRANSPORT_SESSION_H
#define TRANSPORT_SESSION_H

#include <stdint.h>
#include <time.h>
#include <stdbool.h>
#include <stdatomic.h>
#include "flow.h"

// 添加缺失的常量定义
// 会话哈希表大小 - 根据实际会话数量调整
// 实际会话数: 146,588，建议哈希表大小为会话数的4倍
#define SESSION_HASH_SIZE 2097152  // 2M 哈希桶 (2^21)

// 最大会话数 - 基于实际使用情况调整
// 当前实际会话数: 146,588，预留3倍空间
#define MAX_SESSIONS 500000        // 50万会话

// 内存池配置 - 基于实际并发会话数调整
#define MEMORY_POOL_SIZE 200000    // 20万个会话的内存池

// 会话超时配置 (纳秒)
#define SESSION_TIMEOUT_NS 300000000000ULL  // 5分钟超时
#define SESSION_CLEANUP_INTERVAL_NS 60000000000ULL  // 1分钟清理间隔

// 性能调优参数 - 基于实际负载调整
#define HASH_COLLISION_THRESHOLD 5   // 哈希冲突阈值 (降低)
#define LOAD_FACTOR_THRESHOLD 0.70   // 负载因子阈值 (降低)

// 会话类型枚举
typedef enum {
    SESSION_TYPE_TCP = 6,
    SESSION_TYPE_UDP = 17,
    SESSION_TYPE_ICMP = 1,
    SESSION_TYPE_OTHER = 0
} session_type_t;

// TCP会话状态枚举
typedef enum {
    TCP_SESSION_INIT = 0,
    TCP_SESSION_SYN,
    TCP_SESSION_SYN_ACK,
    TCP_SESSION_ESTABLISHED,
    TCP_SESSION_FIN_WAIT,
    TCP_SESSION_CLOSED,
    TCP_SESSION_RESET
} tcp_session_state_t;

// UDP会话状态枚举
typedef enum {
    UDP_SESSION_INIT = 0,
    UDP_SESSION_ACTIVE,
    UDP_SESSION_TIMEOUT
} udp_session_state_t;

// 会话统计结构
typedef struct session_stats {
    // 基本统计
    uint64_t packets_in;                // 接收包数
    uint64_t packets_out;               // 发送包数
    uint64_t bytes_in;                  // 接收字节数
    uint64_t bytes_out;                 // 发送字节数
    uint64_t total_packets;             // 总包数
    uint64_t total_bytes;               // 总字节数
    
    // 包大小统计
    uint32_t max_packet_size;           // 最大包大小
    uint32_t min_packet_size;           // 最小包大小
    uint32_t avg_packet_size;           // 平均包大小
    uint32_t max_packet_size_fwd;       // 正向最大包大小
    uint32_t min_packet_size_fwd;       // 正向最小包大小
    uint32_t max_packet_size_bwd;       // 反向最大包大小
    uint32_t min_packet_size_bwd;       // 反向最小包大小
    
    // 方向统计
    uint64_t total_bytes_fwd;           // 正向总字节数
    uint32_t packet_count_fwd;          // 正向包计数
    uint64_t total_bytes_bwd;           // 反向总字节数
    uint32_t packet_count_bwd;          // 反向包计数
    double fwd_sum_squares;             // 正向包大小平方和
    double bwd_sum_squares;             // 反向包大小平方和
    
    // 时间戳数组
    timestamp_array_t fwd_timestamps;   // 正向时间戳
    timestamp_array_t bwd_timestamps;   // 反向时间戳
    
    // TCP标志统计
    struct tcp_flag_stats tcp_flags;
    
    // TCP相关统计
    uint32_t fwd_header_bytes;         // 正向报文头部字节数
    uint32_t bwd_header_bytes;         // 反向报文头部字节数
    uint32_t fwd_init_win_bytes;       // 前向初始窗口字节数
    uint32_t bwd_init_win_bytes;       // 反向初始窗口字节数
    uint32_t fwd_tcp_payload_bytes;    // 至少有1字节payload的TCP流量
    uint32_t fwd_min_segment;          // 前向观察到的最小segment大小
    
    // 子流相关统计
    uint64_t subflow_fwd_packets;      // 前向子流中的包数量
    uint64_t subflow_fwd_bytes;        // 前向子流中的字节数
    uint64_t subflow_bwd_packets;      // 反向子流中的包数量
    uint64_t subflow_bwd_bytes;        // 反向子流中的字节数
    
    // 时间相关
    uint64_t first_packet;              // 第一个包时间
    uint64_t last_packet;               // 最后包时间
    uint64_t rtt_min;                   // 最小RTT
    
    // 活跃/空闲时间
    uint64_t active_time_ns;            // 活跃时间
    uint64_t idle_time_ns;              // 空闲时间
    uint64_t active_max_ns;             // 最大活跃时间
    uint64_t active_min_ns;             // 最小活跃时间
    uint64_t idle_max_ns;               // 最大空闲时间
    uint64_t idle_min_ns;               // 最小空闲时间
    
    // 流特征
    struct flow_features features;      // 流特征结构
} session_stats_t;

// 会话导出数据结构
typedef struct session_export_data {
    uint32_t session_id;
    char src_ip[16];
    char dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    char state_name[32];
    double duration;
    uint64_t packets_total;
    uint64_t bytes_total;
    char start_time[64];
    double throughput;
    double packet_rate;
} session_export_data_t;

// 内存池块大小
#define MEMORY_POOL_BLOCK_SIZE sizeof(transport_session_t)

// 无锁内存池结构
typedef struct memory_pool {
    void *pool_memory;                  // 内存池基地址
    atomic_bool *used_blocks;           // 原子块使用状态数组
    uint32_t total_blocks;              // 总块数
    atomic_uint used_count;             // 已使用块数（原子）
    atomic_uint next_free_hint;         // 下一个可能空闲的块索引（原子）
    
    // 无锁统计信息
    atomic_ulong allocation_count;      // 分配次数
    atomic_ulong deallocation_count;    // 释放次数
    atomic_uint max_usage;              // 最大使用量
} memory_pool_t;

// 会话唯一标识符（五元组 + 状态）
typedef struct session_identifier {
    struct flow_key flow_key;       // 五元组
    uint8_t session_state_id;       // 会话状态标识
    uint32_t creation_sequence;     // 创建序列号
} session_identifier_t;

// 更新transport_session_t结构
typedef struct transport_session {
    session_identifier_t identifier;    // 会话唯一标识符
    uint32_t session_id;                // 会话ID
    struct flow_key key;                // 流键（五元组）
    session_type_t type;                // 会话类型
    
    // Conversation关联信息
    struct flow_node *flow_node_ptr;    // 指向flow_node的指针
    struct flow_stats *flow_stats_ptr;  // 指向flow_stats的指针
    
    // 会话状态
    union {
        tcp_session_state_t tcp_state;
        udp_session_state_t udp_state;
    } state;
    
    // 时间信息
    struct timespec creation_time;      // 创建时间
    struct timespec last_activity;     // 最后活动时间
    
    // 协议特定信息
    union {
        struct {
            uint32_t initial_seq_client;
            uint32_t initial_seq_server;
            uint16_t window_size_client;
            uint16_t window_size_server;
            uint8_t connection_state;
        } tcp_info;
        
        struct {
            uint32_t total_datagrams;
            uint16_t last_checksum;
        } udp_info;
    } protocol_info;
    
    // 统计信息
    session_stats_t stats;
    
    // 链表指针（使用原子指针）
    atomic_uintptr_t next_atomic;       // 原子下一个指针
    atomic_uintptr_t prev_atomic;       // 原子上一个指针
    struct transport_session *next;     // 普通指针（用于兼容）
    struct transport_session *prev;     // 普通指针（用于兼容）
    
    // 内存池相关
    uint32_t pool_block_index;          // 在内存池中的块索引
    atomic_bool is_from_pool;           // 是否来自内存池（原子）
    atomic_bool is_active;              // 会话是否活跃（原子）
    
} transport_session_t;

// 无锁会话管理器结构
typedef struct session_manager {
    atomic_uintptr_t sessions[SESSION_HASH_SIZE];  // 原子指针数组
    atomic_uint total_sessions;         // 原子总会话数
    atomic_uint active_sessions;        // 原子活跃会话数
    atomic_uint tcp_sessions;           // 原子TCP会话数
    atomic_uint udp_sessions;           // 原子UDP会话数
    atomic_uint next_session_id;        // 原子会话ID计数器
    struct timespec last_cleanup;
    
    // 内存池
    memory_pool_t session_pool;
    
    // 原子统计信息
    atomic_ulong sessions_created;      // 原子创建计数
    atomic_ulong sessions_destroyed;    // 原子销毁计数
    atomic_ulong pool_allocations;      // 原子池分配计数
    atomic_ulong malloc_allocations;    // 原子malloc计数
    
    // 性能统计
    atomic_ulong hash_collisions;       // 哈希冲突计数
    atomic_ulong lookup_operations;     // 查找操作计数
    
    // 动态配置参数
    uint32_t max_sessions_limit;        // 动态最大会话数限制
    uint32_t session_timeout_ns;        // 动态会话超时时间
    uint32_t cleanup_interval_ns;       // 动态清理间隔
    double load_factor_threshold;       // 动态负载因子阈值
    
} session_manager_t;

// 无锁内存池函数声明
int init_lockfree_memory_pool(memory_pool_t *pool, uint32_t block_count, size_t block_size);
void cleanup_lockfree_memory_pool(memory_pool_t *pool);
void *allocate_from_lockfree_pool(memory_pool_t *pool, uint32_t *block_index);
int free_to_lockfree_pool(memory_pool_t *pool, void *ptr, uint32_t block_index);
uint32_t get_lockfree_pool_usage_percent(const memory_pool_t *pool);

// 无锁会话管理函数
transport_session_t *lockfree_find_session(const struct flow_key *key);
int lockfree_insert_session(transport_session_t *session);
int lockfree_remove_session(transport_session_t *session);

// 会话创建函数更新
transport_session_t *create_transport_session_with_state(const struct flow_key *key, 
                                                        uint8_t state_id, 
                                                        uint64_t timestamp);

// CSV导出功能增强
int export_sessions_flow_features_to_csv(const char *filename);
int export_session_detailed_features(transport_session_t *session, FILE *fp);

// 性能监控函数
void print_lockfree_pool_stats(const memory_pool_t *pool);
void print_session_manager_stats(const session_manager_t *manager);

// =================== 基于Session的会话管理函数 ===================

// 基于session创建或获取会话
transport_session_t *get_or_create_session_from_flow(const struct flow_key *key, 
                                                    uint8_t tcp_flags, 
                                                    uint64_t timestamp);

// 处理数据包并更新基于session的会话
transport_session_t *process_packet_with_session(const struct flow_key *key, 
                                                uint32_t packet_size,
                                                uint8_t tcp_flags,
                                                uint64_t timestamp);

// 处理数据包并更新基于conversation的会话
transport_session_t *process_packet_with_conversation(const struct flow_key *key, 
                                                     uint32_t packet_size,
                                                     uint8_t tcp_flags,
                                                     uint64_t timestamp);

// 更新基于session的会话统计
int update_session_from_flow(transport_session_t *session, uint32_t packet_size, 
                            bool is_reverse, uint64_t timestamp);

// 导出基于session的会话统计
int export_session_based_sessions_to_csv(const char *filename);

// 新的CSV导出函数
int export_comprehensive_flow_features_to_csv(const char *filename);
int export_comprehensive_session_features(transport_session_t *session, FILE *fp);

// =================== 日志系统 ===================

// 日志级别枚举
typedef enum {
    LOG_LEVEL_ERROR = 0,
    LOG_LEVEL_WARN,
    LOG_LEVEL_INFO,
    LOG_LEVEL_DEBUG
} log_level_t;

// 日志系统函数声明
extern log_level_t global_log_level;
void set_log_level(log_level_t level);
void log_msg(log_level_t level, const char *fmt, ...);

// 会话管理器初始化和清理
int transport_session_manager_init(void);
void transport_session_manager_cleanup(void);

// 动态配置函数
int set_session_manager_config(uint32_t max_sessions, uint32_t timeout_ns, 
                              uint32_t cleanup_interval, double load_threshold);
int get_session_manager_config(uint32_t *max_sessions, uint32_t *timeout_ns, 
                              uint32_t *cleanup_interval, double *load_threshold);

// 会话管理器状态查询
uint32_t get_total_session_count(void);
uint32_t get_active_session_count(void);
uint32_t get_tcp_session_count(void);
uint32_t get_udp_session_count(void);
double get_session_manager_load_factor(void);
uint32_t get_session_manager_hash_collision_rate(void);

// 基于实际数据的配置建议
void suggest_config_based_on_actual_sessions(uint32_t actual_tcp_sessions, uint32_t actual_udp_sessions);

#endif /* TRANSPORT_SESSION_H */