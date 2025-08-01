#include "transport_session.h"
#include "logger.h"
#include "flow.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <math.h>
#include <float.h>
#include <stddef.h>

// =================== 全局变量 ===================

// 全局会话管理器实例
session_manager_t *global_session_manager = NULL;
static atomic_bool session_manager_initialized = ATOMIC_VAR_INIT(false);

// TCP标志定义
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20



// CAS操作重试次数
#define CAS_RETRY_LIMIT 100

// 原子会话统计计数器
static atomic_ulong session_id_counter = ATOMIC_VAR_INIT(1);
static atomic_uint creation_sequence_counter = ATOMIC_VAR_INIT(1);

// 内部函数声明 - 移除与 flow.h 冲突的声明
static transport_session_t *lockfree_find_session_in_bucket(uintptr_t head_ptr, const struct flow_key *key);
static void normalize_flow_key(const struct flow_key *key, struct flow_key *normalized_key, bool *is_reverse);
static void update_session_statistics(transport_session_t *session, uint32_t packet_size, bool is_reverse, uint64_t timestamp);
static void calculate_session_features_export(const transport_session_t *session, session_export_data_t *export_data);
static tcp_session_state_t get_tcp_state_from_flags(uint8_t tcp_flags, tcp_session_state_t current_state);
static void calculate_iat_features(transport_session_t *session);
static void calculate_iat_stats_simple(const timestamp_array_t *timestamps, 
                                       double *iat_mean, double *iat_std, 
                                       double *iat_max, double *iat_min);
static void calculate_flow_iat_stats(transport_session_t *session);
static int calculate_session_features(transport_session_t *session);

// 无锁内存池函数声明
static transport_session_t *lockfree_allocate_session_from_pool(void);
void lockfree_free_session_to_pool(transport_session_t *session);
static transport_session_t *lockfree_find_session_with_state(const struct flow_key *key, uint8_t state_id);

// 原子操作辅助函数
static inline void atomic_store_session_ptr(atomic_uintptr_t *atomic_ptr, transport_session_t *session) {
    atomic_store(atomic_ptr, (uintptr_t)session);
}

transport_session_t *atomic_load_session_ptr(atomic_uintptr_t *atomic_ptr) {
    return (transport_session_t *)atomic_load(atomic_ptr);
}

static inline bool atomic_cas_session_ptr(atomic_uintptr_t *atomic_ptr, 
                                         transport_session_t *expected, 
                                         transport_session_t *desired) {
    uintptr_t expected_val = (uintptr_t)expected;
    return atomic_compare_exchange_weak(atomic_ptr, &expected_val, (uintptr_t)desired);
}

// ================= 无锁内存池实现 =================

int init_lockfree_memory_pool(memory_pool_t *pool, uint32_t block_count, size_t block_size) {
    if (!pool || block_count == 0 || block_size == 0) {
        return -1;
    }
    
    // 分配内存池
    pool->pool_memory = malloc(block_count * block_size);
    if (!pool->pool_memory) {
        return -1;
    }
    
    // 分配原子使用状态数组
    pool->used_blocks = (atomic_bool*)malloc(block_count * sizeof(atomic_bool));
    if (!pool->used_blocks) {
        free(pool->pool_memory);
        return -1;
    }
    
    // 初始化所有原子变量
    for (uint32_t i = 0; i < block_count; i++) {
        atomic_init(&pool->used_blocks[i], false);
    }
    
    pool->total_blocks = block_count;
    atomic_init(&pool->used_count, 0);
    atomic_init(&pool->next_free_hint, 0);
    atomic_init(&pool->allocation_count, 0);
    atomic_init(&pool->deallocation_count, 0);
    atomic_init(&pool->max_usage, 0);
    
    memset(pool->pool_memory, 0, block_count * block_size);
    
    log_info("Lockfree memory pool initialized: %u blocks of %zu bytes each", block_count, block_size);
    return 0;
}

void cleanup_lockfree_memory_pool(memory_pool_t *pool) {
    if (!pool) return;
    
    if (pool->pool_memory) {
        free(pool->pool_memory);
        pool->pool_memory = NULL;
    }
    
    if (pool->used_blocks) {
        free(pool->used_blocks);
        pool->used_blocks = NULL;
    }
    
    pool->total_blocks = 0;
    atomic_store(&pool->used_count, 0);
    atomic_store(&pool->next_free_hint, 0);
    
    log_info("Lockfree memory pool cleaned up");
    log_info("Final stats - Allocations: %lu, Deallocations: %lu, Max usage: %u",
           atomic_load(&pool->allocation_count),
           atomic_load(&pool->deallocation_count),
           atomic_load(&pool->max_usage));
}

void *allocate_from_lockfree_pool(memory_pool_t *pool, uint32_t *block_index) {
    if (!pool || !pool->pool_memory || !block_index) {
        return NULL;
    }
    
    uint32_t current_used = atomic_load(&pool->used_count);
    if (current_used >= pool->total_blocks) {
        return NULL; // 池已满
    }
    
    // 获取起始搜索位置
    uint32_t start_hint = atomic_load(&pool->next_free_hint);
    uint32_t current_index = start_hint;
    int retry_count = 0;
    
    do {
        // 尝试从当前位置分配
        for (uint32_t i = 0; i < pool->total_blocks; i++) {
            uint32_t index = (current_index + i) % pool->total_blocks;
            
            // 尝试原子地将false改为true
            bool expected = false;
            if (atomic_compare_exchange_weak(&pool->used_blocks[index], &expected, true)) {
                // 成功分配
                *block_index = index;
                
                // 更新统计信息
                uint32_t new_used = atomic_fetch_add(&pool->used_count, 1) + 1;
                atomic_fetch_add(&pool->allocation_count, 1);
                
                // 更新最大使用量
                uint32_t current_max = atomic_load(&pool->max_usage);
                while (new_used > current_max) {
                    if (atomic_compare_exchange_weak(&pool->max_usage, &current_max, new_used)) {
                        break;
                    }
                }
                
                // 更新提示位置
                atomic_store(&pool->next_free_hint, (index + 1) % pool->total_blocks);
                
                void *ptr = (char*)pool->pool_memory + (index * MEMORY_POOL_BLOCK_SIZE);
                memset(ptr, 0, MEMORY_POOL_BLOCK_SIZE);
                
                return ptr;
            }
        }
        
        // 如果一轮搜索没有找到，更新起始位置重试
        current_index = (current_index + 1) % pool->total_blocks;
        retry_count++;
        
    } while (retry_count < CAS_RETRY_LIMIT);
    
    return NULL; // 分配失败
}

int free_to_lockfree_pool(memory_pool_t *pool, void *ptr, uint32_t block_index) {
    if (!pool || !ptr || block_index >= pool->total_blocks) {
        return -1;
    }
    
    // 验证指针是否属于内存池
    void *expected_ptr = (char*)pool->pool_memory + (block_index * MEMORY_POOL_BLOCK_SIZE);
    if (ptr != expected_ptr) {
        return -1;
    }
    
    // 原子地将true改为false
    bool expected = true;
    if (atomic_compare_exchange_strong(&pool->used_blocks[block_index], &expected, false)) {
        // 成功释放
        atomic_fetch_sub(&pool->used_count, 1);
        atomic_fetch_add(&pool->deallocation_count, 1);
        
        // 更新提示位置（如果这个位置更早）
        uint32_t current_hint = atomic_load(&pool->next_free_hint);
        if (block_index < current_hint) {
            atomic_compare_exchange_weak(&pool->next_free_hint, &current_hint, block_index);
        }
        
        // 清零内存
        memset(ptr, 0, MEMORY_POOL_BLOCK_SIZE);
        
        return 0;
    }
    
    return -1; // 块未被使用或释放失败
}

uint32_t get_lockfree_pool_usage_percent(const memory_pool_t *pool) {
    if (!pool || pool->total_blocks == 0) {
        return 0;
    }
    
    uint32_t used = atomic_load(&pool->used_count);
    return (used * 100) / pool->total_blocks;
}

static transport_session_t *lockfree_allocate_session_from_pool(void) {
    if (!global_session_manager) return NULL;
    
    uint32_t block_index;
    transport_session_t *session = (transport_session_t*)allocate_from_lockfree_pool(
        &global_session_manager->session_pool, &block_index);
    
    if (session) {
        session->pool_block_index = block_index;
        atomic_store(&session->is_from_pool, true);
        atomic_store(&session->is_active, true);
        atomic_fetch_add(&global_session_manager->pool_allocations, 1);
        return session;
    }
    
    // 内存池满了，使用malloc
    session = (transport_session_t*)malloc(sizeof(transport_session_t));
    if (session) {
        memset(session, 0, sizeof(transport_session_t));
        atomic_store(&session->is_from_pool, false);
        atomic_store(&session->is_active, true);
        atomic_fetch_add(&global_session_manager->malloc_allocations, 1);
    }
    
    return session;
}

void lockfree_free_session_to_pool(transport_session_t *session) {
    if (!session || !global_session_manager) return;
    
    atomic_store(&session->is_active, false);
    
    if (atomic_load(&session->is_from_pool)) {
        free_to_lockfree_pool(&global_session_manager->session_pool, session, session->pool_block_index);
    } else {
        free(session);
    }
}

// ================= 无锁会话管理实现 =================

transport_session_t *lockfree_find_session(const struct flow_key *key) {
    if (!atomic_load(&session_manager_initialized) || !global_session_manager || !key) {
        return NULL;
    }
    
    struct flow_key normalized_key;
    bool is_reverse;
    normalize_flow_key(key, &normalized_key, &is_reverse);
    
    uint32_t hash = hash_flow_key(&normalized_key);
    uintptr_t head_ptr = atomic_load(&global_session_manager->sessions[hash]);
    
    atomic_fetch_add(&global_session_manager->lookup_operations, 1);
    
    return lockfree_find_session_in_bucket(head_ptr, &normalized_key);
}

static transport_session_t *lockfree_find_session_in_bucket(uintptr_t head_ptr, const struct flow_key *key) {
    transport_session_t *session = (transport_session_t *)head_ptr;
    
    while (session) {   
        // 检查会话是否活跃
        if (!atomic_load(&session->is_active)) {
            session = atomic_load_session_ptr(&session->next_atomic);
            continue;
        }
        
        if (session->key.src_ip == key->src_ip &&
            session->key.dst_ip == key->dst_ip &&
            session->key.src_port == key->src_port &&
            session->key.dst_port == key->dst_port &&
            session->key.protocol == key->protocol) {
            return session;
        }
        
        session = atomic_load_session_ptr(&session->next_atomic);
    }
    
    return NULL;
}

int lockfree_insert_session(transport_session_t *session) {
    if (!session || !atomic_load(&session_manager_initialized) || !global_session_manager) {
        return -1;
    }
    
    uint32_t hash = hash_flow_key(&session->key);
    int retry_count = 0;
    
    while (retry_count < CAS_RETRY_LIMIT) {
        // 获取当前头节点
        transport_session_t *current_head = atomic_load_session_ptr(&global_session_manager->sessions[hash]);
        
        // 设置新节点的next指针
        atomic_store_session_ptr(&session->next_atomic, current_head);
        atomic_store_session_ptr(&session->prev_atomic, NULL);
        session->next = current_head;
        session->prev = NULL;
        
        // 尝试CAS更新头节点
        if (atomic_cas_session_ptr(&global_session_manager->sessions[hash], current_head, session)) {
            // 更新原头节点的prev指针
            if (current_head) {
                atomic_store_session_ptr(&current_head->prev_atomic, session);
                current_head->prev = session;
            }
            
            // 更新统计信息
            atomic_fetch_add(&global_session_manager->total_sessions, 1);
            atomic_fetch_add(&global_session_manager->active_sessions, 1);
            
            if (session->type == SESSION_TYPE_TCP) {
                atomic_fetch_add(&global_session_manager->tcp_sessions, 1);
            } else if (session->type == SESSION_TYPE_UDP) {
                atomic_fetch_add(&global_session_manager->udp_sessions, 1);
            }
            
            return 0; // 插入成功
        }
        
        retry_count++;
        atomic_fetch_add(&global_session_manager->hash_collisions, 1);
    }
    
    return -1; // 插入失败
}

int lockfree_remove_session(transport_session_t *session) {
    if (!session || !atomic_load(&session_manager_initialized) || !global_session_manager) {
        return -1;
    }
    
    // 标记会话为非活跃
    atomic_store(&session->is_active, false);
    
    uint32_t hash = hash_flow_key(&session->key);
    int retry_count = 0;
    
    while (retry_count < CAS_RETRY_LIMIT) {
        transport_session_t *prev = atomic_load_session_ptr(&session->prev_atomic);
        transport_session_t *next = atomic_load_session_ptr(&session->next_atomic);
        
        if (prev) {
            // 不是头节点，更新前节点的next指针
            if (atomic_cas_session_ptr(&prev->next_atomic, session, next)) {
                prev->next = next;
            } else {
                retry_count++;
                continue;
            }
        } else {
            // 是头节点，更新哈希表
            if (!atomic_cas_session_ptr(&global_session_manager->sessions[hash], session, next)) {
                retry_count++;
                continue;
            }
        }
        
        if (next) {
            // 更新后节点的prev指针
            atomic_store_session_ptr(&next->prev_atomic, prev);
            next->prev = prev;
        }
        
        // 更新统计信息
        atomic_fetch_sub(&global_session_manager->active_sessions, 1);
        atomic_fetch_add(&global_session_manager->sessions_destroyed, 1);
        
        if (session->type == SESSION_TYPE_TCP) {
            atomic_fetch_sub(&global_session_manager->tcp_sessions, 1);
        } else if (session->type == SESSION_TYPE_UDP) {
            atomic_fetch_sub(&global_session_manager->udp_sessions, 1);
        }
        
        return 0; // 删除成功
    }
    
    return -1; // 删除失败
}

// =================== 会话创建和查找 ===================

transport_session_t *create_transport_session(const struct flow_key *key, uint64_t timestamp) {
    uint8_t default_state_id = 0;
    
    if (key->protocol == IPPROTO_TCP) {
        default_state_id = (uint8_t)TCP_SESSION_INIT;
    } else if (key->protocol == IPPROTO_UDP) {
        default_state_id = (uint8_t)UDP_SESSION_INIT;
    }
    
    return create_transport_session_with_state(key, default_state_id, timestamp);
}

transport_session_t *find_transport_session(const struct flow_key *key) {
    return lockfree_find_session(key);
}

transport_session_t *get_or_create_session(const struct flow_key *key, uint64_t timestamp) {
    transport_session_t *session = lockfree_find_session(key);
    if (session) {
        struct timespec ts;
        ts.tv_sec = timestamp / 1000000000ULL;
        ts.tv_nsec = timestamp % 1000000000ULL;
        session->last_activity = ts;
        return session;
    }
    
    return create_transport_session(key, timestamp);
}

static transport_session_t *lockfree_find_session_with_state(const struct flow_key *key, uint8_t state_id) {
    if (!atomic_load(&session_manager_initialized) || !global_session_manager || !key) {
        return NULL;
    }
    
    struct flow_key normalized_key;
    bool is_reverse;
    normalize_flow_key(key, &normalized_key, &is_reverse);
    
    uint32_t hash = hash_flow_key(&normalized_key);
    transport_session_t *session = atomic_load_session_ptr(&global_session_manager->sessions[hash]);
    
    while (session) {
        // 检查会话是否活跃
        if (!atomic_load(&session->is_active)) {
            session = atomic_load_session_ptr(&session->next_atomic);
            continue;
        }
        
        if (session->key.src_ip == normalized_key.src_ip &&
            session->key.dst_ip == normalized_key.dst_ip &&
            session->key.src_port == normalized_key.src_port &&
            session->key.dst_port == normalized_key.dst_port &&
            session->key.protocol == normalized_key.protocol &&
            session->identifier.session_state_id == state_id) {
            return session;
        }
        session = atomic_load_session_ptr(&session->next_atomic);
    }
    
    return NULL;
}

// =================== 增强的会话创建 ===================

transport_session_t *create_transport_session_with_state(const struct flow_key *key, 
                                                        uint8_t state_id, 
                                                        uint64_t timestamp) {
    if (!atomic_load(&session_manager_initialized) || !global_session_manager || !key) {
        return NULL;
    }
    
    struct flow_key normalized_key;
    bool is_reverse;
    normalize_flow_key(key, &normalized_key, &is_reverse);
    
    // 检查是否已存在相同状态的会话
    transport_session_t *existing = lockfree_find_session_with_state(&normalized_key, state_id);
    if (existing) {
        struct timespec ts;
        ts.tv_sec = timestamp / 1000000000ULL;
        ts.tv_nsec = timestamp % 1000000000ULL;
        existing->last_activity = ts;
        return existing;
    }
    
    // 检查会话数量限制
    uint32_t current_limit = global_session_manager->max_sessions_limit ? 
                            global_session_manager->max_sessions_limit : MAX_SESSIONS;
    if (atomic_load(&global_session_manager->total_sessions) >= current_limit) {
        log_warn("Warning: Maximum session limit reached (%u)", current_limit);
        return NULL;
    }
    
    // 从内存池分配会话
    transport_session_t *session = lockfree_allocate_session_from_pool();
    if (!session) {
        return NULL;
    }
    
    // 设置会话标识符
    session->identifier.flow_key = normalized_key;
    session->identifier.session_state_id = state_id;
    session->identifier.creation_sequence = atomic_fetch_add(&creation_sequence_counter, 1);
    
    // 设置会话基本信息
    session->key = normalized_key;
    session->session_id = atomic_fetch_add(&session_id_counter, 1);
    session->type = (session_type_t)key->protocol;
    
    struct timespec ts;
    ts.tv_sec = timestamp / 1000000000ULL;
    ts.tv_nsec = timestamp % 1000000000ULL;
    session->creation_time = ts;
    session->last_activity = ts;
    session->stats.last_packet = timestamp;
    
    // 初始化状态
    if (key->protocol == IPPROTO_TCP) {
        session->state.tcp_state = (tcp_session_state_t)state_id;
    } else if (key->protocol == IPPROTO_UDP) {
        session->state.udp_state = (udp_session_state_t)state_id;
    }
    
    // 初始化统计信息
    session->stats.first_packet = timestamp;  // 直接使用 uint64_t
    session->stats.last_packet = timestamp;   // 直接使用 uint64_t
    session->stats.rtt_min = UINT64_MAX;
    session->stats.min_packet_size = UINT32_MAX;
    session->stats.min_packet_size_fwd = UINT32_MAX;
    session->stats.min_packet_size_bwd = UINT32_MAX;
    
    // 使用无锁插入到哈希表
    if (lockfree_insert_session(session) != 0) {
        // 插入失败，释放会话
        lockfree_free_session_to_pool(session);
        return NULL;
    }
    
    atomic_fetch_add(&global_session_manager->sessions_created, 1);
    
    return session;
}

// =================== 会话状态更新 ===================

int update_tcp_session_state(transport_session_t *session, uint8_t tcp_flags, 
                            uint32_t seq, uint32_t ack, uint16_t window, uint64_t timestamp) {
    (void)ack;  // 避免未使用参数警告
    if (!session || session->type != SESSION_TYPE_TCP) {
        return -1;
    }
    
    // 检查会话是否活跃
    if (!atomic_load(&session->is_active)) {
        return -1;
    }
    
    struct timespec ts;
    ts.tv_sec = timestamp / 1000000000ULL;
    ts.tv_nsec = timestamp % 1000000000ULL;
    session->last_activity = ts;
    
    tcp_session_state_t new_state = get_tcp_state_from_flags(tcp_flags, session->state.tcp_state);
    if (new_state != session->state.tcp_state) {
        session->state.tcp_state = new_state;
        
        // 更新TCP特定信息
        if (tcp_flags & TCP_FLAG_SYN) {
            if (session->protocol_info.tcp_info.initial_seq_client == 0) {
                session->protocol_info.tcp_info.initial_seq_client = seq;
            } else if (session->protocol_info.tcp_info.initial_seq_server == 0) {
                session->protocol_info.tcp_info.initial_seq_server = seq;
            }
        }
        
        session->protocol_info.tcp_info.window_size_client = window;
    }
    
    return 0;
}

int update_session_stats(transport_session_t *session, uint32_t packet_size, 
                        int is_outbound, uint64_t timestamp) {
    if (!session) {
        return -1;
    }
    
    // 检查会话是否活跃
    if (!atomic_load(&session->is_active)) {
        return -1;
    }
    
    update_session_statistics(session, packet_size, !is_outbound, timestamp);
    
    struct timespec ts;
    ts.tv_sec = timestamp / 1000000000ULL;
    ts.tv_nsec = timestamp % 1000000000ULL;
    session->last_activity = ts;
    session->stats.last_packet = timestamp;  // 直接使用 uint64_t
    
    return 0;
}

// =================== 统计信息获取 ===================

uint32_t get_total_session_count(void) {
    if (!atomic_load(&session_manager_initialized) || !global_session_manager) {
        return 0;
    }
    return atomic_load(&global_session_manager->total_sessions);
}

uint32_t get_active_session_count(void) {
    if (!atomic_load(&session_manager_initialized) || !global_session_manager) {
        return 0;
    }
    return atomic_load(&global_session_manager->active_sessions);
}

uint32_t get_tcp_session_count(void) {
    if (!atomic_load(&session_manager_initialized) || !global_session_manager) {
        return 0;
    }
    return atomic_load(&global_session_manager->tcp_sessions);
}

uint32_t get_udp_session_count(void) {
    if (!atomic_load(&session_manager_initialized) || !global_session_manager) {
        return 0;
    }
    return atomic_load(&global_session_manager->udp_sessions);
}

uint32_t get_sessions_by_state(tcp_session_state_t state) {
    if (!atomic_load(&session_manager_initialized) || !global_session_manager) {
        return 0;
    }
    
    uint32_t count = 0;
    for (int i = 0; i < SESSION_HASH_SIZE; i++) {
        transport_session_t *session = atomic_load_session_ptr(&global_session_manager->sessions[i]);
        while (session) {
            if (session->type == SESSION_TYPE_TCP && session->state.tcp_state == state) {
                count++;
            }
            session = atomic_load_session_ptr(&session->next_atomic);
        }
    }
    
    return count;
}

// =================== 数据导出 ===================

// CSV头部定义（移除CICFlowMeter特有字段）
static const char* csv_header = 
    "FlowID,SrcIP,SrcPort,DstIP,DstPort,Protocol,"
    "Timestamp,FlowDuration,TotalFwdPackets,TotalBwdPackets,"
    "TotalLengthFwdPackets,TotalLengthBwdPackets,FwdPacketLengthMax,FwdPacketLengthMin,"
    "FwdPacketLengthMean,FwdPacketLengthStd,BwdPacketLengthMax,BwdPacketLengthMin,"
    "BwdPacketLengthMean,BwdPacketLengthStd,FlowBytesPerSec,FlowPacketsPerSec,"
    "FlowIATMean,FlowIATStd,FlowIATMax,FlowIATMin,FwdIATTotal,FwdIATMean,"
    "FwdIATStd,FwdIATMax,FwdIATMin,BwdIATTotal,BwdIATMean,BwdIATStd,"
    "BwdIATMax,BwdIATMin,FwdPSHFlags,BwdPSHFlags,FwdURGFlags,BwdURGFlags,"
    "FwdHeaderLength,BwdHeaderLength,FwdPacketsPerSec,BwdPacketsPerSec,"
    "MinPacketLength,MaxPacketLength,PacketLengthMean,PacketLengthStd,"
    "PacketLengthVariance,FINFlagCount,SYNFlagCount,RSTFlagCount,"
    "PSHFlagCount,ACKFlagCount,URGFlagCount,CWEFlagCount,ECEFlagCount,"
    "DownUpRatio,AvgPacketSize,AvgFwdSegmentSize,AvgBwdSegmentSize,"
    "Label\n";

int export_sessions_flow_features_to_csv(const char *filename) {
    if (!filename || !atomic_load(&session_manager_initialized) || !global_session_manager) {
        return -1;
    }
    
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        return -1;
    }
    
    // 写入CSV头部
    fprintf(fp, "%s", csv_header);

    int exported_count = 0;
    uint32_t total_active_sessions = 0;
    uint32_t tcp_session_count = 0;
    uint32_t udp_session_count = 0;
    
    // 遍历所有会话并统计
    for (int i = 0; i < SESSION_HASH_SIZE; i++) {
        transport_session_t *session = atomic_load_session_ptr(&global_session_manager->sessions[i]);
        while (session) {
            // 统计活跃会话
            if (atomic_load(&session->is_active)) {
                total_active_sessions++;
                
                // 统计协议类型
                if (session->type == SESSION_TYPE_TCP) {
                    tcp_session_count++;
                } else if (session->type == SESSION_TYPE_UDP) {
                    udp_session_count++;
                }
                
                // 计算当前会话的特征
                calculate_session_features(session);
                
                // 导出详细特征
                if (export_session_detailed_features(session, fp) == 0) {
                    exported_count++;
                }
            }
            
            session = atomic_load_session_ptr(&session->next_atomic);
        }
    }
    
    fclose(fp);
    
    // 打印详细统计信息
    log_info("\n=== Session Export Statistics ===\n");
    log_info("Exported %d active sessions with detailed flow features to %s\n", exported_count, filename);
    log_info("Total active sessions: %u\n", total_active_sessions);
    log_info("TCP sessions: %u (%.1f%%)\n", tcp_session_count, 
           total_active_sessions > 0 ? (tcp_session_count * 100.0 / total_active_sessions) : 0.0);
    log_info("UDP sessions: %u (%.1f%%)\n", udp_session_count,
           total_active_sessions > 0 ? (udp_session_count * 100.0 / total_active_sessions) : 0.0);
    log_info("================================\n");
    
    // 打印内存池统计
    print_lockfree_pool_stats(&global_session_manager->session_pool);
    
    return exported_count;
}

int export_session_detailed_features(transport_session_t *session, FILE *fp) {
    if (!session || !fp) {
        return -1;
    }

    struct flow_features *features = &session->stats.features;
    
    // IP地址转换为字符串
    struct in_addr addr;
    char src_ip_str[INET_ADDRSTRLEN];
    char dst_ip_str[INET_ADDRSTRLEN];
    
    addr.s_addr = session->key.src_ip;
    strncpy(src_ip_str, inet_ntoa(addr), sizeof(src_ip_str) - 1);
    src_ip_str[sizeof(src_ip_str) - 1] = '\0';
    
    addr.s_addr = session->key.dst_ip;
    strncpy(dst_ip_str, inet_ntoa(addr), sizeof(dst_ip_str) - 1);
    dst_ip_str[sizeof(dst_ip_str) - 1] = '\0';
    
    // 计算持续时间
    double duration = (session->stats.last_packet - session->stats.first_packet) / 1000000000.0; // 纳秒转秒
    
    // 写入简化的CSV行
    fprintf(fp, "%u,%s,%u,%s,%u,%u,"
               "%.9f,%.6f,%lu,%lu,"
                                                               "%lu,%lu,%u,%u,"
                               "%.2f,%.2f,%u,%u,"
               "%.2f,%.2f,%.2f,%.2f,"
               "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
               "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
               "%.2f,%.2f,%u,%u,%u,%u,"
                                                               "%.2f,%.2f,%.2f,%.2f,"
                               "%u,%u,%.2f,%.2f,"
                               "%.2f,%d,%u,%u,"
               "%u,%u,%u,%u,%u,"
               "%.2f,%.2f,%.2f,%.2f,"
               "Normal\n",
               
               // 基本信息
               session->session_id, src_ip_str, ntohs(session->key.src_port), 
               dst_ip_str, ntohs(session->key.dst_port), session->key.protocol,
               
               // 时间和基本统计
               (double)session->stats.first_packet / 1000000000.0, duration,
               features->tot_fw_pk, features->tot_bw_pk,
               
               // 包长度特征
               features->tot_1_fw_pk, features->tot_1_bw_pk,
               features->fwd_pkt_1_max, features->fwd_pkt_1_min,
               features->fwd_pkt_1_avg, features->fwd_pkt_1_std,
               features->bwd_pkt_1_max, features->bwd_pkt_1_min,
               features->bwd_pkt_1_avg, features->bwd_pkt_1_std,
               
               // 流速率特征
               features->fl_byt_s, features->fl_pkt_s,
               features->fl_iat_avg, features->fl_iat_std,
               features->fl_iat_max, features->fl_iat_min,
               
               // 前向IAT特征
               features->fw_iat_tot, features->fw_iat_avg,
               features->fw_iat_std, features->fw_iat_max, features->fw_iat_min,
               
               // 反向IAT特征
               features->bw_iat_tot, features->bw_iat_avg, features->bw_iat_std,
               features->bw_iat_max, features->bw_iat_min,
               
               // TCP标志特征
               0, 0,  // fwd_psh_count, bwd_psh_count - 在flow_features中不存在
               0, 0,  // fwd_urg_count, bwd_urg_count - 在flow_features中不存在
               (double)features->fw_hdr_len, (double)features->bw_hdr_len,
               
               // 包速率特征
               features->fl_pkt_s, features->fl_pkt_s,
               
               // 包长度统计
               features->pkt_len_min, features->pkt_len_max,
               features->pkt_len_avg, features->pkt_len_std,
                               0.0,  // packet_length_variance - 在flow_features中不存在
               
               // 标志计数
               0, 0, 0,  // fin_flag_count, syn_flag_count, rst_flag_count - 在flow_features中不存在
               0, 0, 0,  // psh_flag_count, ack_flag_count, urg_flag_count - 在flow_features中不存在
               0, 0,  // cwe_flag_count, ece_flag_count - 在flow_features中不存在
               
               // 其他特征
               features->down_up_ratio, features->avg_packet_size,
               features->fw_seg_avg, features->bw_seg_avg);
    
    return 0;
}

// 保留原有的简单导出函数作为备用（无锁版本）
int export_all_sessions_to_csv(const char *filename) {
    if (!filename || !atomic_load(&session_manager_initialized) || !global_session_manager) {
        return -1;
    }
    
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        return -1;
    }
    
    // 写入简单CSV头部
    fprintf(fp, "SessionID,StateID,SrcIP,SrcPort,DstIP,DstPort,Protocol,Type,State,"
                "Duration,PacketsTotal,BytesTotal,StartTime,Throughput,PacketRate,PoolUsage,IsActive\n");
    
    int exported_count = 0;
    
    // 遍历所有会话
    for (int i = 0; i < SESSION_HASH_SIZE; i++) {
        transport_session_t *session = atomic_load_session_ptr(&global_session_manager->sessions[i]);
        while (session) {
            // 只导出活跃会话
            if (atomic_load(&session->is_active)) {
                session_export_data_t export_data;
                calculate_session_features_export(session, &export_data);
                
                // 写入CSV行
                fprintf(fp, "%u,%u,%s,%u,%s,%u,%u,%s,%s,"
                           "%.6f,%lu,%lu,%s,%.2f,%.2f,%u,%s\n",
                           export_data.session_id, session->identifier.session_state_id,
                           export_data.src_ip, export_data.src_port,
                           export_data.dst_ip, export_data.dst_port, export_data.protocol,
                           (session->type == SESSION_TYPE_TCP) ? "TCP" : 
                           (session->type == SESSION_TYPE_UDP) ? "UDP" : "OTHER",
                           export_data.state_name,
                           export_data.duration, export_data.packets_total, export_data.bytes_total,
                           export_data.start_time, export_data.throughput, export_data.packet_rate,
                           get_lockfree_pool_usage_percent(&global_session_manager->session_pool),
                           atomic_load(&session->is_active) ? "YES" : "NO");
                
                exported_count++;
            }
            session = atomic_load_session_ptr(&session->next_atomic);
        }
    }
    
    fclose(fp);
    log_info("Exported %d active sessions (simple format) to %s\n", exported_count, filename);
    return exported_count;
}

// =================== 内部辅助函数声明 ===================

static transport_session_t *find_session_by_flow_key(const struct flow_key *key);
static tcp_session_state_t determine_tcp_state_from_flags(uint8_t tcp_flags);
static void sync_session_stats_from_conversation(transport_session_t *session);

// =================== 内部辅助函数实现 ===================

static void normalize_flow_key(const struct flow_key *key, struct flow_key *normalized, bool *is_reverse) {
    if (!key || !normalized || !is_reverse) return;
    
    *normalized = *key;
    *is_reverse = false;
    
    // 规范化：较小的IP地址作为源地址
    // 如果IP地址相同，则较小的端口作为源端口
    if (key->src_ip > key->dst_ip || 
        (key->src_ip == key->dst_ip && key->src_port > key->dst_port)) {
        
        normalized->src_ip = key->dst_ip;
        normalized->dst_ip = key->src_ip;
        normalized->src_port = key->dst_port;
        normalized->dst_port = key->src_port;
        *is_reverse = true;
    }
}

static tcp_session_state_t get_tcp_state_from_flags(uint8_t flags, tcp_session_state_t current_state) {
    // 简化的TCP状态机
    if (flags & TCP_FLAG_RST) {
        return TCP_SESSION_RESET;
    }
    
    if (flags & TCP_FLAG_FIN) {
        return TCP_SESSION_FIN_WAIT;
    }
    
    if (flags & TCP_FLAG_SYN) {
        if (flags & TCP_FLAG_ACK) {
            return TCP_SESSION_SYN_ACK;
        } else {
            return TCP_SESSION_SYN;
        }
    }
    
    if (flags & TCP_FLAG_ACK) {
        if (current_state == TCP_SESSION_SYN_ACK || current_state == TCP_SESSION_SYN) {
            return TCP_SESSION_ESTABLISHED;
        }
    }
    
    return current_state;
}

static void update_session_statistics(transport_session_t *session, uint32_t packet_size, 
                                     bool is_inbound, uint64_t timestamp) {
    if (!session) return;
    
    // 更新最后包时间戳
    session->stats.last_packet = timestamp;
    
    // 更新基本统计
    if (is_inbound) {
        session->stats.packets_in++;
        session->stats.bytes_in += packet_size;
        
        // 更新时间戳数组
        timestamp_array_add(&session->stats.bwd_timestamps, timestamp);
        
        // 更新包大小统计
        if (packet_size > session->stats.max_packet_size_bwd) {
            session->stats.max_packet_size_bwd = packet_size;
        }
        if (packet_size < session->stats.min_packet_size_bwd) {
            session->stats.min_packet_size_bwd = packet_size;
        }
        session->stats.total_bytes_bwd += packet_size;
        session->stats.packet_count_bwd++;
        
    } else {
        session->stats.packets_out++;
        session->stats.bytes_out += packet_size;
        
        // 更新时间戳数组
        timestamp_array_add(&session->stats.fwd_timestamps, timestamp);
        
        // 更新包大小统计
        if (packet_size > session->stats.max_packet_size_fwd) {
            session->stats.max_packet_size_fwd = packet_size;
        }
        if (packet_size < session->stats.min_packet_size_fwd) {
            session->stats.min_packet_size_fwd = packet_size;
        }
        session->stats.total_bytes_fwd += packet_size;
        session->stats.packet_count_fwd++;
    }
    
    // 更新总体统计
    session->stats.total_packets = session->stats.packets_in + session->stats.packets_out;
    session->stats.total_bytes = session->stats.bytes_in + session->stats.bytes_out;
    
    // 更新包大小统计
    if (packet_size > session->stats.max_packet_size) {
        session->stats.max_packet_size = packet_size;
    }
    if (packet_size < session->stats.min_packet_size) {
        session->stats.min_packet_size = packet_size;
    }
    
    // 计算平均包大小
    if (session->stats.total_packets > 0) {
        session->stats.avg_packet_size = session->stats.total_bytes / session->stats.total_packets;
    }
}

static void calculate_session_features_export(const transport_session_t *session, session_export_data_t *export_data) {
    if (!session || !export_data) return;
    
    // 清零导出数据
    memset(export_data, 0, sizeof(session_export_data_t));
    
    // 五元组信息
    struct in_addr addr;
    addr.s_addr = htonl(session->key.src_ip);
    strncpy(export_data->src_ip, inet_ntoa(addr), sizeof(export_data->src_ip) - 1);
    
    addr.s_addr = htonl(session->key.dst_ip);
    strncpy(export_data->dst_ip, inet_ntoa(addr), sizeof(export_data->dst_ip) - 1);
    
    export_data->src_port = ntohs(session->key.src_port);
    export_data->dst_port = ntohs(session->key.dst_port);
    export_data->protocol = session->key.protocol;
    
    // 会话状态
    if (session->type == SESSION_TYPE_TCP) {
        snprintf(export_data->state_name, sizeof(export_data->state_name), "TCP_%d", session->state.tcp_state);
    } else {
        snprintf(export_data->state_name, sizeof(export_data->state_name), "UDP_%d", session->state.udp_state);
    }
    
    // 统计信息
    export_data->packets_total = session->stats.total_packets;
    export_data->bytes_total = session->stats.total_bytes;
    
    // 计算持续时间 - 修复时间戳访问
    double start_time = session->stats.first_packet / 1e9;  // 纳秒转秒
    double end_time = session->stats.last_packet / 1e9;
    export_data->duration = end_time - start_time;
    
    // 计算吞吐量和包速率
    if (export_data->duration > 0) {
        export_data->throughput = export_data->bytes_total / export_data->duration;
        export_data->packet_rate = export_data->packets_total / export_data->duration;
    }
    
    // 格式化开始时间 - 修复时间戳转换
    time_t start_time_sec = session->stats.first_packet / 1000000000ULL;  // 纳秒转秒
    struct tm *tm_info = localtime(&start_time_sec);
    strftime(export_data->start_time, sizeof(export_data->start_time), "%Y-%m-%d %H:%M:%S", tm_info);
}
// =================== 性能监控函数 ===================

void print_lockfree_pool_stats(const memory_pool_t *pool) {
    if (!pool) return;
    
    log_info("\n=== Lockfree Memory Pool Statistics ===\n");
    log_info("Total blocks: %u\n", pool->total_blocks);
    log_info("Used blocks: %u\n", atomic_load(&pool->used_count));
    log_info("Usage percentage: %u%%\n", get_lockfree_pool_usage_percent(pool));
    log_info("Max usage reached: %u blocks\n", atomic_load(&pool->max_usage));
    log_info("Total allocations: %lu\n", atomic_load(&pool->allocation_count));
    log_info("Total deallocations: %lu\n", atomic_load(&pool->deallocation_count));
    log_info("Current free hint: %u\n", atomic_load(&pool->next_free_hint));
    log_info("==========================================\n\n");
}

void print_session_manager_stats(const session_manager_t *manager) {
    if (!manager) return;
    
    log_info("\n=== Lockfree Session Manager Statistics ===\n");
    log_info("Total sessions: %u\n", atomic_load(&manager->total_sessions));
    log_info("Active sessions: %u\n", atomic_load(&manager->active_sessions));
    log_info("TCP sessions: %u\n", atomic_load(&manager->tcp_sessions));
    log_info("UDP sessions: %u\n", atomic_load(&manager->udp_sessions));
    log_info("Sessions created: %lu\n", atomic_load(&manager->sessions_created));
    log_info("Sessions destroyed: %lu\n", atomic_load(&manager->sessions_destroyed));
    log_info("Pool allocations: %lu\n", atomic_load(&manager->pool_allocations));
    log_info("Malloc allocations: %lu\n", atomic_load(&manager->malloc_allocations));
    log_info("Hash collisions: %lu\n", atomic_load(&manager->hash_collisions));
    log_info("Lookup operations: %lu\n", atomic_load(&manager->lookup_operations));
    log_info("Next session ID: %u\n", atomic_load(&manager->next_session_id));
    log_info("=============================================\n\n");
}

// =================== 特征统计功能实现 =================

int calculate_session_features(transport_session_t *session) {
    if (!session) {
        return -1;
    }
    struct flow_features *features = &session->stats.features;
    
    // 重置特征结构
    memset(features, 0, sizeof(struct flow_features));
    
    // 基本统计 - 使用正确的flow_features字段名
    features->tot_fw_pk = session->stats.packets_out;  // 正向包数
    features->tot_bw_pk = session->stats.packets_in;   // 反向包数
    features->tot_1_fw_pk = session->stats.bytes_out;  // 正向字节数
    features->tot_1_bw_pk = session->stats.bytes_in;   // 反向字节数
    
    // 重新计算流持续时间（fl_dur）
    printf("DEBUG: first_packet=%lu, last_packet=%lu\n", 
           session->stats.first_packet, session->stats.last_packet);
    if (session->stats.last_packet > session->stats.first_packet) {
        features->fl_dur = (double)(session->stats.last_packet - session->stats.first_packet) / 1000000000.0; // 纳秒转秒
        printf("DEBUG: fl_dur calculated = %.6f\n", features->fl_dur);
    } else {
        features->fl_dur = 0.0; // 如果只有一个包，持续时间为0
        printf("DEBUG: fl_dur = 0.0 (no duration)\n");
    }
    
    // 生成开始时间字符串（可读格式）
    time_t start_time_sec = session->stats.first_packet / 1000000000;
    struct tm *tm_info = localtime(&start_time_sec);
    strftime(features->start_time_str, sizeof(features->start_time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // 包大小特征 - 正向
    if (session->stats.packets_out > 0) {
        features->fwd_pkt_1_max = session->stats.max_packet_size_fwd;
        features->fwd_pkt_1_min = session->stats.min_packet_size_fwd;
        features->fwd_pkt_1_avg = (double)session->stats.bytes_out / session->stats.packets_out;
        
        // 计算标准差
        if (session->stats.packets_out > 1) {
            double variance = (session->stats.fwd_sum_squares / session->stats.packets_out) - 
                             (features->fwd_pkt_1_avg * features->fwd_pkt_1_avg);
            features->fwd_pkt_1_std = sqrt(variance > 0 ? variance : 0);
        }
    }
    
    // 包大小特征 - 反向
    if (session->stats.packets_in > 0) {
        features->bwd_pkt_1_max = session->stats.max_packet_size_bwd;
        features->bwd_pkt_1_min = session->stats.min_packet_size_bwd;
        features->bwd_pkt_1_avg = (double)session->stats.bytes_in / session->stats.packets_in;
        
        // 计算标准差
        if (session->stats.packets_in > 1) {
            double variance = (session->stats.bwd_sum_squares / session->stats.packets_in) - 
                             (features->bwd_pkt_1_avg * features->bwd_pkt_1_avg);
            features->bwd_pkt_1_std = sqrt(variance > 0 ? variance : 0);
        }
    }
    
    // 流量率特征
    if (features->fl_dur > 0) {
        features->fl_byt_s = (features->tot_1_fw_pk + features->tot_1_bw_pk) / features->fl_dur;
        features->fl_pkt_s = (features->tot_fw_pk + features->tot_bw_pk) / features->fl_dur;
    }
    
    // 包长度统计
    uint64_t total_packets = features->tot_fw_pk + features->tot_bw_pk;
    if (total_packets > 0) {
        features->pkt_len_min = (session->stats.min_packet_size_fwd < session->stats.min_packet_size_bwd) ? 
                                session->stats.min_packet_size_fwd : session->stats.min_packet_size_bwd;
        features->pkt_len_max = (session->stats.max_packet_size_fwd > session->stats.max_packet_size_bwd) ? 
                                session->stats.max_packet_size_fwd : session->stats.max_packet_size_bwd;
        features->pkt_len_avg = (double)(features->tot_1_fw_pk + features->tot_1_bw_pk) / total_packets;
        features->avg_packet_size = features->pkt_len_avg;
        
        // 计算包长度标准差
        double total_variance = 0.0;
        if (session->stats.packets_out > 0) {
            double fwd_variance = (session->stats.fwd_sum_squares / session->stats.packets_out) - 
                                 (features->fwd_pkt_1_avg * features->fwd_pkt_1_avg);
            total_variance += fwd_variance * session->stats.packets_out;
        }
        if (session->stats.packets_in > 0) {
            double bwd_variance = (session->stats.bwd_sum_squares / session->stats.packets_in) - 
                                 (features->bwd_pkt_1_avg * features->bwd_pkt_1_avg);
            total_variance += bwd_variance * session->stats.packets_in;
        }
        features->pkt_len_std = sqrt(total_variance / total_packets);
        features->pkt_len_va = features->pkt_len_std; // 包长度方差
    }
    
    // 头部长度特征
    features->fw_hdr_len = session->stats.fwd_header_bytes;
    features->bw_hdr_len = session->stats.bwd_header_bytes;
    
    // 窗口和段大小特征
    features->fw_win_byt = session->stats.fwd_init_win_bytes;
    features->bw_win_byt = session->stats.bwd_init_win_bytes;
    features->fw_act_pkt = session->stats.fwd_tcp_payload_bytes;
    features->fw_seg_min = session->stats.fwd_min_segment;
    
    // 段大小平均值
    features->fw_seg_avg = features->fwd_pkt_1_avg;
    features->bw_seg_avg = features->bwd_pkt_1_avg;
    
    // 子流特征 - 使用会话统计
    features->subfl_fw_pk = session->stats.subflow_fwd_packets;
    features->subfl_fw_byt = session->stats.subflow_fwd_bytes;
    features->subfl_bw_pk = session->stats.subflow_bwd_packets;
    features->subfl_bw_byt = session->stats.subflow_bwd_bytes;
    
    // 下行/上行比率
    if (features->tot_1_fw_pk > 0) {
        features->down_up_ratio = (double)features->tot_1_bw_pk / features->tot_1_fw_pk;
    }
    
    // 计算IAT特征
    calculate_iat_features(session);
    
    return 0;
}

static void calculate_iat_features(transport_session_t *session) {
    if (!session) return;
    
    struct flow_features *features = &session->stats.features;
    
    // 计算正向IAT统计
    if (session->stats.fwd_timestamps.count > 1) {
        calculate_iat_stats_simple(&session->stats.fwd_timestamps,
                                                                       &features->fw_iat_avg, &features->fw_iat_std,
                                    &features->fw_iat_max, &features->fw_iat_min);
        
        // 计算总时间
        features->fw_iat_tot = features->fw_iat_avg * (session->stats.fwd_timestamps.count - 1);
    }
    
    // 计算反向IAT统计
    if (session->stats.bwd_timestamps.count > 1) {
        calculate_iat_stats_simple(&session->stats.bwd_timestamps,
                                                                       &features->bw_iat_avg, &features->bw_iat_std,
                                    &features->bw_iat_max, &features->bw_iat_min);
        
        // 计算总时间
        features->bw_iat_tot = features->bw_iat_avg * (session->stats.bwd_timestamps.count - 1);
    }
    
    // 计算流级别的IAT统计
    calculate_flow_iat_stats(session);
}

static void calculate_iat_stats_simple(const timestamp_array_t *timestamps, 
                                       double *iat_mean, double *iat_std, 
                                       double *iat_max, double *iat_min) {
    if (!timestamps || timestamps->count < 2) {
        *iat_mean = *iat_std = *iat_max = *iat_min = 0.0;
        return;
    }

    double total_iat = 0.0;
    double max_iat = 0.0;
    double min_iat = DBL_MAX;
    
    // 计算所有IAT值
    for (size_t i = 1; i < timestamps->count; i++) {
        double iat = (timestamps->times[i] - timestamps->times[i-1]) / 1000000.0; // 转换为毫秒
        total_iat += iat;
        if (iat > max_iat) max_iat = iat;
        if (iat < min_iat) min_iat = iat;
    }
    
    *iat_mean = total_iat / (timestamps->count - 1);
    *iat_max = max_iat;
    *iat_min = min_iat;
    
    // 计算标准差
    double variance = 0.0;
    for (size_t i = 1; i < timestamps->count; i++) {
        double iat = (timestamps->times[i] - timestamps->times[i-1]) / 1000000.0;
        double diff = iat - *iat_mean;
        variance += diff * diff;
    }
    
    *iat_std = sqrt(variance / (timestamps->count - 1));
}

static int compare_timestamps(const void *a, const void *b) {
    uint64_t ts_a = *(const uint64_t*)a;
    uint64_t ts_b = *(const uint64_t*)b;
    if (ts_a < ts_b) return -1;
    if (ts_a > ts_b) return 1;
    return 0;
}

static void calculate_flow_iat_stats(transport_session_t *session) {
    if (!session) return;
    
    struct flow_features *features = &session->stats.features;
    
    // 合并正向和反向时间戳
    uint32_t total_count = session->stats.fwd_timestamps.count + session->stats.bwd_timestamps.count;
    if (total_count < 2) return;
    
    uint64_t *all_timestamps = malloc(total_count * sizeof(uint64_t));
    if (!all_timestamps) return;
    
    uint32_t idx = 0;
    for (uint32_t i = 0; i < session->stats.fwd_timestamps.count; i++) {
        all_timestamps[idx++] = session->stats.fwd_timestamps.times[i];
    }
    for (uint32_t i = 0; i < session->stats.bwd_timestamps.count; i++) {
        all_timestamps[idx++] = session->stats.bwd_timestamps.times[i];
    }
    
    // 排序时间戳
    qsort(all_timestamps, total_count, sizeof(uint64_t), compare_timestamps);
    
    // 计算流级别的IAT统计
    double total_iat = 0.0;
    double max_iat = 0.0;
    double min_iat = DBL_MAX;
    
    for (uint32_t i = 1; i < total_count; i++) {
        double iat = (all_timestamps[i] - all_timestamps[i-1]) / 1000000.0; // 转换为毫秒
        total_iat += iat;
        if (iat > max_iat) max_iat = iat;
        if (iat < min_iat) min_iat = iat;
    }
    
    features->fl_iat_avg = total_iat / (total_count - 1);
    features->fl_iat_max = max_iat;
    features->fl_iat_min = min_iat;
    // min_packet_iat 在flow_features中不存在
    
    // 计算标准差
    double variance = 0.0;
    for (uint32_t i = 1; i < total_count; i++) {
        double iat = (all_timestamps[i] - all_timestamps[i-1]) / 1000000.0;
        double diff = iat - features->fl_iat_avg;
        variance += diff * diff;
    }
    
    features->fl_iat_std = sqrt(variance / (total_count - 1));
    
    free(all_timestamps);
}

// =================== 辅助函数 =================


// =================== 会话管理器初始化和清理 ===================

int transport_session_manager_init(void) {
    bool expected = false;
    if (!atomic_compare_exchange_strong(&session_manager_initialized, &expected, true)) {
        return 0; // Already initialized
    }
    
    global_session_manager = (session_manager_t*)malloc(sizeof(session_manager_t));
    if (!global_session_manager) {
        atomic_store(&session_manager_initialized, false);
        return -1;
    }
    
    memset(global_session_manager, 0, sizeof(session_manager_t));
    
    // 初始化无锁内存池
    if (init_lockfree_memory_pool(&global_session_manager->session_pool, MEMORY_POOL_SIZE, MEMORY_POOL_BLOCK_SIZE) != 0) {
        free(global_session_manager);
        global_session_manager = NULL;
        atomic_store(&session_manager_initialized, false);
        return -1;
    }
    
    // 初始化原子哈希表
    for (int i = 0; i < SESSION_HASH_SIZE; i++) {
        atomic_init(&global_session_manager->sessions[i], (uintptr_t)NULL);
    }
    
    // 初始化原子统计变量
    atomic_init(&global_session_manager->total_sessions, 0);
    atomic_init(&global_session_manager->active_sessions, 0);
    atomic_init(&global_session_manager->tcp_sessions, 0);
    atomic_init(&global_session_manager->udp_sessions, 0);
    atomic_init(&global_session_manager->next_session_id, 1);
    atomic_init(&global_session_manager->sessions_created, 0);
    atomic_init(&global_session_manager->sessions_destroyed, 0);
    atomic_init(&global_session_manager->pool_allocations, 0);
    atomic_init(&global_session_manager->malloc_allocations, 0);
    atomic_init(&global_session_manager->hash_collisions, 0);
    atomic_init(&global_session_manager->lookup_operations, 0);
    
    clock_gettime(CLOCK_REALTIME, &global_session_manager->last_cleanup);
    
    atomic_store(&session_id_counter, 1);
    atomic_store(&creation_sequence_counter, 1);
    
    // 设置默认配置
    global_session_manager->max_sessions_limit = MAX_SESSIONS;
    global_session_manager->session_timeout_ns = (uint32_t)SESSION_TIMEOUT_NS;
    global_session_manager->cleanup_interval_ns = (uint32_t)SESSION_CLEANUP_INTERVAL_NS;
    global_session_manager->load_factor_threshold = LOAD_FACTOR_THRESHOLD;
    
    log_info("Lockfree transport session manager initialized successfully\n");
    log_info("Memory pool: %d blocks, usage: %u%%\n", MEMORY_POOL_SIZE, 
           get_lockfree_pool_usage_percent(&global_session_manager->session_pool));
    log_info("Default config: max_sessions=%u, timeout=%u, cleanup=%u, load_threshold=%.2f\n",
           MAX_SESSIONS, SESSION_TIMEOUT_NS, SESSION_CLEANUP_INTERVAL_NS, LOAD_FACTOR_THRESHOLD);
    return 0;
}

void transport_session_manager_cleanup(void) {
    bool expected = true;
    if (!atomic_compare_exchange_strong(&session_manager_initialized, &expected, false)) {
        return; // Not initialized or already cleaned up
    }
    
    if (!global_session_manager) {
        return;
    }
    
    // 清理所有会话
    for (int i = 0; i < SESSION_HASH_SIZE; i++) {
        transport_session_t *session = atomic_load_session_ptr(&global_session_manager->sessions[i]);
        while (session) {
            transport_session_t *next = atomic_load_session_ptr(&session->next_atomic);
            lockfree_free_session_to_pool(session);
            session = next;
        }
        atomic_store(&global_session_manager->sessions[i], (uintptr_t)NULL);
    }
    
    // 打印统计信息
    print_session_manager_stats(global_session_manager);
    
    // 清理内存池
    cleanup_lockfree_memory_pool(&global_session_manager->session_pool);
    
    free(global_session_manager);
    global_session_manager = NULL;
    
    log_info("Lockfree transport session manager cleaned up\n");
}

// =================== 基于Conversation的会话管理 ===================

/**
 * 基于get_or_create_conversation创建或获取会话
 * 统一conversation和session的概念
 */
transport_session_t *get_or_create_session_from_conversation(const struct flow_key *key, 
                                                           uint8_t tcp_flags, 
                                                           uint64_t timestamp) {
    if (!atomic_load(&session_manager_initialized) || !global_session_manager || !key) {
        return NULL;
    }
    
    // 使用flow.c中的get_or_create_conversation函数
    int is_reverse = 0;
    struct flow_stats *flow_stats = get_or_create_conversation(key, &is_reverse, timestamp, tcp_flags);
    if (!flow_stats) {
        return NULL;
    }
    
    // 从flow_stats获取对应的flow_node
    struct flow_node *flow_node = (struct flow_node *)((char *)flow_stats - offsetof(struct flow_node, stats));
    
    // 检查是否已经有对应的transport_session
    transport_session_t *session = find_session_by_flow_key(key);
    
    if (session) {
        // 更新现有会话的活动时间
        struct timespec ts;
        ts.tv_sec = timestamp / 1000000000ULL;
        ts.tv_nsec = timestamp % 1000000000ULL;
        session->last_activity = ts;
        session->stats.last_packet = timestamp;
        return session;
    }
    
    // 创建新的transport_session
    session = lockfree_allocate_session_from_pool();
    if (!session) {
        return NULL;
    }
    
    // 初始化会话基本信息
    session->key = *key;
    session->session_id = atomic_fetch_add(&session_id_counter, 1);
    session->type = (session_type_t)key->protocol;
    
    // 关联conversation信息
    session->flow_node_ptr = flow_node;
    session->flow_stats_ptr = flow_stats;
    
    // 设置时间信息
    struct timespec ts;
    ts.tv_sec = timestamp / 1000000000ULL;
    ts.tv_nsec = timestamp % 1000000000ULL;
    session->creation_time = ts;
    session->last_activity = ts;
    
    // 初始化统计信息，从conversation继承
    session->stats.first_packet = flow_stats->start_time.tv_sec * 1000000000ULL + flow_stats->start_time.tv_nsec;
    session->stats.last_packet = timestamp;
    session->stats.total_packets = flow_stats->fwd_packets + flow_stats->bwd_packets;
    session->stats.total_bytes = flow_stats->fwd_bytes + flow_stats->bwd_bytes;
    session->stats.packets_in = flow_stats->bwd_packets;
    session->stats.packets_out = flow_stats->fwd_packets;
    session->stats.bytes_in = flow_stats->bwd_bytes;
    session->stats.bytes_out = flow_stats->fwd_bytes;
    
    // 设置会话状态
    if (key->protocol == IPPROTO_TCP) {
        session->state.tcp_state = determine_tcp_state_from_flags(tcp_flags);
    } else if (key->protocol == IPPROTO_UDP) {
        session->state.udp_state = UDP_SESSION_ACTIVE;
    }
    
    // 使用无锁插入到哈希表
    if (lockfree_insert_session(session) != 0) {
        lockfree_free_session_to_pool(session);
        return NULL;
    }
    
    atomic_fetch_add(&global_session_manager->sessions_created, 1);
    
    return session;
}

/**
 * 根据flow key查找会话
 */
static transport_session_t *find_session_by_flow_key(const struct flow_key *key) {
    if (!atomic_load(&session_manager_initialized) || !global_session_manager || !key) {
        return NULL;
    }
    
    // 直接使用现有的lockfree_find_session函数
    return lockfree_find_session(key);
}

/**
 * 从TCP标志确定会话状态
 */
static tcp_session_state_t determine_tcp_state_from_flags(uint8_t tcp_flags) {
    if (tcp_flags & TCP_FLAG_RST) {
        return TCP_SESSION_RESET;
    } else if (tcp_flags & TCP_FLAG_FIN) {
        return TCP_SESSION_FIN_WAIT;
    } else if (tcp_flags & TCP_FLAG_SYN) {
        if (tcp_flags & TCP_FLAG_ACK) {
            return TCP_SESSION_SYN_ACK;
        } else {
            return TCP_SESSION_SYN;
        }
    } else if (tcp_flags & TCP_FLAG_ACK) {
        return TCP_SESSION_ESTABLISHED;
    }
    return TCP_SESSION_INIT;
}

/**
 * 更新基于conversation的会话统计
 */
int update_session_from_conversation(transport_session_t *session, uint32_t packet_size, 
                                   bool is_reverse, uint64_t timestamp) {
    if (!session || !session->flow_stats_ptr) {
        return -1;
    }
    
    // 检查会话是否活跃
    if (!atomic_load(&session->is_active)) {
        return -1;
    }
    
    // 更新flow_stats（通过conversation机制）
    update_flow_stats(session->flow_stats_ptr, packet_size, is_reverse ? 1 : 0, timestamp);
    
    // 同步更新transport_session统计
    sync_session_stats_from_conversation(session);
    
    // 更新活动时间
    struct timespec ts;
    ts.tv_sec = timestamp / 1000000000ULL;
    ts.tv_nsec = timestamp % 1000000000ULL;
    session->last_activity = ts;
    session->stats.last_packet = timestamp;
    
    return 0;
}

/**
 * 从conversation同步统计信息到session
 */
static void sync_session_stats_from_conversation(transport_session_t *session) {
    if (!session || !session->flow_stats_ptr) {
        return;
    }
    
    struct flow_stats *flow_stats = session->flow_stats_ptr;
    
    // 同步基本统计
    session->stats.total_packets = flow_stats->fwd_packets + flow_stats->bwd_packets;
    session->stats.total_bytes = flow_stats->fwd_bytes + flow_stats->bwd_bytes;
    session->stats.packets_out = flow_stats->fwd_packets;
    session->stats.packets_in = flow_stats->bwd_packets;
    session->stats.bytes_out = flow_stats->fwd_bytes;
    session->stats.bytes_in = flow_stats->bwd_bytes;
    
    // 同步包大小统计
    session->stats.max_packet_size_fwd = flow_stats->fwd_max_size;
    session->stats.min_packet_size_fwd = flow_stats->fwd_min_size;
    session->stats.max_packet_size_bwd = flow_stats->bwd_max_size;
    session->stats.min_packet_size_bwd = flow_stats->bwd_min_size;
    
    // 同步时间戳信息
    session->stats.first_packet = flow_stats->start_time.tv_sec * 1000000000ULL + flow_stats->start_time.tv_nsec;
    
    // 计算平均包大小
    if (session->stats.total_packets > 0) {
        session->stats.avg_packet_size = session->stats.total_bytes / session->stats.total_packets;
    }
}

/**
 * 处理数据包并更新基于conversation的会话
 */
transport_session_t *process_packet_with_conversation(const struct flow_key *key, 
                                                    uint32_t packet_size,
                                                    uint8_t tcp_flags,
                                                    uint64_t timestamp) {
    if (!key) {
        return NULL;
    }
    
    // 获取或创建基于conversation的会话
    transport_session_t *session = get_or_create_session_from_conversation(key, tcp_flags, timestamp);
    if (!session) {
        return NULL;
    }
    
    // 确定数据包方向（基于key与session->key的比较）
    bool is_reverse = false;
    if (key->src_ip != session->key.src_ip || 
        key->src_port != session->key.src_port ||
        key->dst_ip != session->key.dst_ip ||
        key->dst_port != session->key.dst_port) {
        is_reverse = true;
    }
    
    // 更新会话统计
    update_session_from_conversation(session, packet_size, is_reverse, timestamp);
    
    // 更新TCP状态（如果是TCP协议）
    if (key->protocol == IPPROTO_TCP) {
        tcp_session_state_t new_state = determine_tcp_state_from_flags(tcp_flags);
        if (new_state != session->state.tcp_state) {
            session->state.tcp_state = new_state;
        }
    }
    
    return session;
}

/**
 * 导出基于conversation的会话统计
 */
int export_conversation_based_sessions_to_csv(const char *filename) {
    if (!filename || !atomic_load(&session_manager_initialized) || !global_session_manager) {
        return -1;
    }
    
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        return -1;
    }
    
    // 写入增强的CSV头部（包含conversation信息）
    fprintf(fp, "SessionID,SrcIP,SrcPort,DstIP,DstPort,Protocol,"
                "Duration,TotalPackets,TotalBytes,FwdPackets,BwdPackets,FwdBytes,BwdBytes,"
                "AvgPacketSize,StartTime,EndTime,State,IsActive\n");
    
    int exported_count = 0;
    
    // 遍历所有会话
    for (int i = 0; i < SESSION_HASH_SIZE; i++) {
        transport_session_t *session = atomic_load_session_ptr(&global_session_manager->sessions[i]);
        while (session) {
            if (atomic_load(&session->is_active) && session->flow_stats_ptr) {
                // 同步最新统计
                sync_session_stats_from_conversation(session);
                
                // 计算持续时间
                double duration = (session->stats.last_packet - session->stats.first_packet) / 1000000000.0;
                
                // IP地址转换
                struct in_addr addr;
                char src_ip_str[INET_ADDRSTRLEN];
                char dst_ip_str[INET_ADDRSTRLEN];
                
                addr.s_addr = session->key.src_ip;
                strncpy(src_ip_str, inet_ntoa(addr), sizeof(src_ip_str) - 1);
                src_ip_str[sizeof(src_ip_str) - 1] = '\0';
                
                addr.s_addr = session->key.dst_ip;
                strncpy(dst_ip_str, inet_ntoa(addr), sizeof(dst_ip_str) - 1);
                dst_ip_str[sizeof(dst_ip_str) - 1] = '\0';
                
                // 格式化时间
                time_t start_time_sec = session->stats.first_packet / 1000000000ULL;
                time_t end_time_sec = session->stats.last_packet / 1000000000ULL;
                struct tm *start_tm = localtime(&start_time_sec);
                struct tm *end_tm = localtime(&end_time_sec);
                
                char start_time_str[32], end_time_str[32];
                strftime(start_time_str, sizeof(start_time_str), "%Y-%m-%d %H:%M:%S", start_tm);
                strftime(end_time_str, sizeof(end_time_str), "%Y-%m-%d %H:%M:%S", end_tm);
                
                // 状态字符串
                const char *state_str = "UNKNOWN";
                if (session->type == SESSION_TYPE_TCP) {
                    switch (session->state.tcp_state) {
                        case TCP_SESSION_INIT: state_str = "TCP_INIT"; break;
                        case TCP_SESSION_SYN: state_str = "TCP_SYN"; break;
                        case TCP_SESSION_SYN_ACK: state_str = "TCP_SYN_ACK"; break;
                        case TCP_SESSION_ESTABLISHED: state_str = "TCP_ESTABLISHED"; break;
                        case TCP_SESSION_FIN_WAIT: state_str = "TCP_FIN_WAIT"; break;
                        case TCP_SESSION_RESET: state_str = "TCP_RESET"; break;
                        default: state_str = "TCP_UNKNOWN"; break;
                    }
                } else if (session->type == SESSION_TYPE_UDP) {
                    state_str = "UDP_ACTIVE";
                }
                
                // 写入CSV行
                fprintf(fp, "%u,%s,%u,%s,%u,%u,"
                           "%.6f,%lu,%lu,%lu,%lu,%lu,%lu,"
                           "%.2f,%s,%s,%s,%s\n",
                           session->session_id,
                           src_ip_str, ntohs(session->key.src_port),
                           dst_ip_str, ntohs(session->key.dst_port), session->key.protocol,
                           duration, session->stats.total_packets, session->stats.total_bytes,
                           session->stats.packets_out, session->stats.packets_in,
                           session->stats.bytes_out, session->stats.bytes_in,
                           (double)session->stats.avg_packet_size, start_time_str, end_time_str,
                           state_str, "YES");
                
                exported_count++;
            }
            session = atomic_load_session_ptr(&session->next_atomic);
        }
    }
    
    fclose(fp);
    
    log_info("Exported %d conversation-based sessions to %s\n", exported_count, filename);
    return exported_count;
}

// =================== 基于Session的会话管理 ===================

// 处理数据包并更新基于session的会话
transport_session_t *process_packet_with_session(const struct flow_key *key, 
                                                uint32_t packet_size,
                                                uint8_t tcp_flags,
                                                uint64_t timestamp) {
    if (!key) return NULL;
    
    // 获取或创建会话
    transport_session_t *session = get_or_create_session_from_flow(key, tcp_flags, timestamp);
    if (!session) return NULL;
    
    // 确定数据包方向
    bool is_reverse = false;
    struct flow_key normalized_key;
    normalize_flow_key(key, &normalized_key, &is_reverse);
    
    // 更新会话统计
    update_session_from_flow(session, packet_size, is_reverse, timestamp);
    
    return session;
}

/**
 * 基于get_or_create_conversation创建或获取会话
 * 统一conversation和session的概念
 */
transport_session_t *get_or_create_session_from_flow(const struct flow_key *key, 
                                                   uint8_t tcp_flags, 
                                                   uint64_t timestamp) {
    if (!atomic_load(&session_manager_initialized) || !global_session_manager || !key) {
        return NULL;
    }
    
    // 使用flow.c中的get_or_create_conversation函数
    int is_reverse = 0;
    struct flow_stats *flow_stats = get_or_create_conversation(key, &is_reverse, timestamp, tcp_flags);
    if (!flow_stats) {
        return NULL;
    }
    
    // 从flow_stats获取对应的flow_node
    struct flow_node *flow_node = (struct flow_node *)((char *)flow_stats - offsetof(struct flow_node, stats));
    
    // 检查是否已经有对应的transport_session
    transport_session_t *session = find_session_by_flow_key(key);
    
    if (session) {
        // 更新现有会话的活动时间
        struct timespec ts;
        ts.tv_sec = timestamp / 1000000000ULL;
        ts.tv_nsec = timestamp % 1000000000ULL;
        session->last_activity = ts;
        session->stats.last_packet = timestamp;
        return session;
    }
    
    // 创建新的transport_session
    session = lockfree_allocate_session_from_pool();
    if (!session) {
        return NULL;
    }
    
    // 初始化会话基本信息
    session->key = *key;
    session->session_id = atomic_fetch_add(&session_id_counter, 1);
    session->type = (session_type_t)key->protocol;
    
    // 关联conversation信息
    session->flow_node_ptr = flow_node;
    session->flow_stats_ptr = flow_stats;
    
    // 设置时间信息
    struct timespec ts;
    ts.tv_sec = timestamp / 1000000000ULL;
    ts.tv_nsec = timestamp % 1000000000ULL;
    session->creation_time = ts;
    session->last_activity = ts;
    
    // 初始化统计信息，从conversation继承
    session->stats.first_packet = flow_stats->start_time.tv_sec * 1000000000ULL + flow_stats->start_time.tv_nsec;
    session->stats.last_packet = timestamp;
    session->stats.total_packets = flow_stats->fwd_packets + flow_stats->bwd_packets;
    session->stats.total_bytes = flow_stats->fwd_bytes + flow_stats->bwd_bytes;
    session->stats.packets_in = flow_stats->bwd_packets;
    session->stats.packets_out = flow_stats->fwd_packets;
    session->stats.bytes_in = flow_stats->bwd_bytes;
    session->stats.bytes_out = flow_stats->fwd_bytes;
    
    // 设置会话状态
    if (key->protocol == IPPROTO_TCP) {
        session->state.tcp_state = determine_tcp_state_from_flags(tcp_flags);
    } else if (key->protocol == IPPROTO_UDP) {
        session->state.udp_state = UDP_SESSION_ACTIVE;
    }
    
    // 使用无锁插入到哈希表
    if (lockfree_insert_session(session) != 0) {
        lockfree_free_session_to_pool(session);
        return NULL;
    }
    
    atomic_fetch_add(&global_session_manager->sessions_created, 1);
    
    return session;
}

// 更新基于flow的会话统计
int update_session_from_flow(transport_session_t *session, uint32_t packet_size, 
                            bool is_reverse, uint64_t timestamp) {
    if (!session) return -1;
    
    // 更新基本统计
    if (is_reverse) {
        session->stats.packets_in++;
        session->stats.bytes_in += packet_size;
        session->stats.total_bytes_bwd += packet_size;
        session->stats.packet_count_bwd++;
        
        // 更新包大小统计
        if (packet_size > session->stats.max_packet_size_bwd) {
            session->stats.max_packet_size_bwd = packet_size;
        }
        if (packet_size < session->stats.min_packet_size_bwd || session->stats.min_packet_size_bwd == 0) {
            session->stats.min_packet_size_bwd = packet_size;
        }
        
        // 更新时间戳数组
        timestamp_array_add(&session->stats.bwd_timestamps, timestamp);
        
    } else {
        session->stats.packets_out++;
        session->stats.bytes_out += packet_size;
        session->stats.total_bytes_fwd += packet_size;
        session->stats.packet_count_fwd++;
        
        // 更新包大小统计
        if (packet_size > session->stats.max_packet_size_fwd) {
            session->stats.max_packet_size_fwd = packet_size;
        }
        if (packet_size < session->stats.min_packet_size_fwd || session->stats.min_packet_size_fwd == 0) {
            session->stats.min_packet_size_fwd = packet_size;
        }
        
        // 更新时间戳数组
        timestamp_array_add(&session->stats.fwd_timestamps, timestamp);
    }
    
    // 更新总体统计
    session->stats.total_packets = session->stats.packets_in + session->stats.packets_out;
    session->stats.total_bytes = session->stats.bytes_in + session->stats.bytes_out;
    
    // 更新包大小统计
    if (packet_size > session->stats.max_packet_size) {
        session->stats.max_packet_size = packet_size;
    }
    if (packet_size < session->stats.min_packet_size || session->stats.min_packet_size == 0) {
        session->stats.min_packet_size = packet_size;
    }
    
    // 计算平均包大小
    if (session->stats.total_packets > 0) {
        session->stats.avg_packet_size = session->stats.total_bytes / session->stats.total_packets;
    }
    
    // 更新时间戳
    session->stats.last_packet = timestamp;
    
    // 更新活动时间
    struct timespec ts;
    ts.tv_sec = timestamp / 1000000000ULL;
    ts.tv_nsec = timestamp % 1000000000ULL;
    session->last_activity = ts;
    
    return 0;
}

// =================== 测试主函数 ===================

#ifdef SESSION_TEST_MAIN

// 模拟包数据
typedef struct {
    struct flow_key key;
    uint32_t packet_size;
    uint8_t tcp_flags;
    uint64_t timestamp;
} test_packet_t;

// 生成测试包数据
static void generate_test_packets(test_packet_t *packets, int count) {
    uint64_t base_time = 1640000000000000000ULL; // 2021年的某个时间戳
    
    for (int i = 0; i < count; i++) {
        // 创建不同的流
        packets[i].key.src_ip = htonl(0xC0A80100 + (i % 10));  // 192.168.1.x
        packets[i].key.dst_ip = htonl(0xC0A80200 + (i % 5));   // 192.168.2.x
        packets[i].key.src_port = htons(1024 + (i % 100));
        packets[i].key.dst_port = htons(80 + (i % 10));
        packets[i].key.protocol = (i % 3 == 0) ? IPPROTO_UDP : IPPROTO_TCP;
        
        packets[i].packet_size = 64 + (i % 1400);
        packets[i].timestamp = base_time + i * 1000000ULL; // 每毫秒一个包
        
        // 设置TCP标志
        if (packets[i].key.protocol == IPPROTO_TCP) {
            if (i % 10 == 0) {
                packets[i].tcp_flags = TCP_FLAG_SYN;
            } else if (i % 10 == 1) {
                packets[i].tcp_flags = TCP_FLAG_SYN | TCP_FLAG_ACK;
            } else if (i % 10 == 2) {
                packets[i].tcp_flags = TCP_FLAG_ACK;
            } else if (i % 10 == 9) {
                packets[i].tcp_flags = TCP_FLAG_FIN | TCP_FLAG_ACK;
            } else {
                packets[i].tcp_flags = TCP_FLAG_ACK | TCP_FLAG_PSH;
            }
        } else {
            packets[i].tcp_flags = 0;
        }
    }
}

int main(void) {
    log_info("=== Transport Session Management Test ===\n");
    
    // 初始化流表（来自flow.c）
    flow_table_init();
    log_info("Flow table initialized\n");
    
    // 初始化会话管理器
    if (transport_session_manager_init() != 0) {
        log_error("Failed to initialize session manager\n");
        return -1;
    }
    log_info("Session manager initialized successfully\n");
    
    // 生成测试包
    const int num_packets = 1000;
    test_packet_t *packets = malloc(num_packets * sizeof(test_packet_t));
    if (!packets) {
        log_error("Failed to allocate memory for test packets\n");
        return -1;
    }
    
    generate_test_packets(packets, num_packets);
    log_info("Generated %d test packets\n", num_packets);
    
    // 处理包并创建基于conversation的会话
    log_info("\n=== Processing Packets with Conversation-based Sessions ===\n");
    int sessions_created = 0;
    int packets_processed = 0;
    
    for (int i = 0; i < num_packets; i++) {
        test_packet_t *pkt = &packets[i];
        
        // 使用新的基于conversation的处理函数
        transport_session_t *session = process_packet_with_conversation(&pkt->key, 
                                                                       pkt->packet_size,
                                                                       pkt->tcp_flags,
                                                                       pkt->timestamp);
        
        if (session) {
            packets_processed++;
            
            // 检查是否是新创建的会话
            if (session->stats.total_packets == 1) {
                sessions_created++;
                
                if (sessions_created <= 5) {
                    log_info("Created session %u: %s:%u -> %s:%u (%s)\n",
                           session->session_id,
                           inet_ntoa((struct in_addr){.s_addr = session->key.src_ip}),
                           ntohs(session->key.src_port),
                           inet_ntoa((struct in_addr){.s_addr = session->key.dst_ip}),
                           ntohs(session->key.dst_port),
                           (session->type == SESSION_TYPE_TCP) ? "TCP" : "UDP");
                }
            }
        }
        
        // 每100个包打印一次进度
        if ((i + 1) % 100 == 0) {
            log_msg(LOG_LEVEL_DEBUG, "Processed %d packets, %d sessions created\n", i + 1, sessions_created);
        }
    }
    
    log_info("\n=== Processing Complete ===\n");
    log_info("Total packets processed: %d\n", packets_processed);
    log_info("Total sessions created: %d\n", sessions_created);
    log_info("Active sessions: %u\n", get_active_session_count());
    log_info("TCP sessions: %u\n", get_tcp_session_count());
    log_info("UDP sessions: %u\n", get_udp_session_count());
    
    // 导出会话统计
    log_info("\n=== Exporting Session Statistics ===\n");
    int exported = export_conversation_based_sessions_to_csv("conversation_sessions.csv");
    log_info("Exported %d sessions to conversation_sessions.csv\n", exported);
    
    // 同时导出传统格式进行对比
    int exported_traditional = export_all_sessions_to_csv("traditional_sessions.csv");
    log_info("Exported %d sessions to traditional_sessions.csv (for comparison)\n", exported_traditional);
    
    // 打印内存池统计
    log_info("\n=== Memory Pool Statistics ===\n");
    if (global_session_manager) {
        print_lockfree_pool_stats(&global_session_manager->session_pool);
        print_session_manager_stats(global_session_manager);
    }
    
    // 打印conversation统计（来自flow.c）
    log_info("\n=== Conversation Statistics ===\n");
    print_wireshark_conversation_stats();
    
    // 清理
    free(packets);
    transport_session_manager_cleanup();
    flow_table_destroy();
    
    log_info("\n=== Test Complete ===\n");
    return 0;
}

#endif /* SESSION_TEST_MAIN */



// =================== 新的CSV导出函数 ===================

// CSV头部定义（修改字段顺序）
static const char* comprehensive_csv_header = 
    "SrcIP,SrcPort,DstIP,DstPort,Protocol,Timestamp,fl_dur,"
    "tot_fw_pk,tot_bw_pk,tot_1_fw_pk,"
    "fwd_pkt_1_min,fwd_pkt_1_max,fwd_pkt_1_avg,fwd_pkt_1_std,"
    "bwd_pkt_1_min,bwd_pkt_1_max,bwd_pkt_1_avg,bwd_pkt_1_std,"
    "fl_byt_s,fl_pkt_s,"
    "fl_iat_avg,fl_iat_std,fl_iat_max,fl_iat_min,"
    "fw_iat_tot,fw_iat_avg,fw_iat_std,fw_iat_max,fw_iat_min,"
    "bw_iat_tot,bw_iat_avg,bw_iat_std,bw_iat_max,bw_iat_min,"
    "fw_hdr_len,bw_hdr_len,fw_pkt_s,bw_pkt_s,"
    "pkt_len_min,pkt_len_max,pkt_len_avg,pkt_len_std,pkt_len_va,"
    "down_up_ratio,pkt_size_avg,fw_seg_avg,bw_seg_avg,"
    "subfl_fw_pk,subfl_fw_byt,subfl_bw_pk,subfl_bw_byt,"
    "fw_win_byt,bw_win_byt,fw_ack_pkt,fw_seg_min\n";

int export_comprehensive_flow_features_to_csv(const char *filename) {
    if (!global_session_manager) {
        log_error("Session manager not initialized\n");
        return -1;
    }
    
    FILE *fp = fopen(filename, "w");
    if (!fp) {
        log_error("Failed to open file: %s\n", filename);
        return -1;
    }
    
    // 写入CSV头部
    fprintf(fp, "%s", comprehensive_csv_header);
    
    int exported_count = 0;
    uint32_t total_active_sessions = 0;
    uint32_t tcp_session_count = 0;
    uint32_t udp_session_count = 0;
    
    // 遍历所有会话
    for (uint32_t i = 0; i < SESSION_HASH_SIZE; i++) {
        transport_session_t *session = atomic_load_session_ptr(&global_session_manager->sessions[i]);
        
        while (session) {
            if (atomic_load(&session->is_active)) {
                total_active_sessions++;
                
                // 计算会话类型统计
                if (session->key.protocol == IPPROTO_TCP) {
                    tcp_session_count++;
                } else if (session->key.protocol == IPPROTO_UDP) {
                    udp_session_count++;
                }
                
                // 计算综合流特征
                calculate_session_features(session);
                
                // 导出会话数据
                if (export_comprehensive_session_features(session, fp) == 0) {
                    exported_count++;
                }
            }
            
            session = session->next;
        }
    }
    
    fclose(fp);
    
    // 打印详细统计信息
    log_info("\n=== Comprehensive Flow Features Export Statistics ===\n");
    log_info("Exported %d active sessions with comprehensive flow features to %s\n", exported_count, filename);
    log_info("Total active sessions: %u\n", total_active_sessions);
    log_info("TCP sessions: %u (%.1f%%)\n", tcp_session_count, 
            total_active_sessions > 0 ? (tcp_session_count * 100.0 / total_active_sessions) : 0.0);
    log_info("UDP sessions: %u (%.1f%%)\n", udp_session_count,
            total_active_sessions > 0 ? (udp_session_count * 100.0 / total_active_sessions) : 0.0);
    log_info("====================================================\n");
    
    return exported_count;
}

int export_comprehensive_session_features(transport_session_t *session, FILE *fp) {
    if (!session || !fp) return -1;
    
    // 添加调试信息
    printf("DEBUG: Session %s:%u -> %s:%u, first_packet=%lu, last_packet=%lu\n",
           inet_ntoa((struct in_addr){.s_addr = session->key.src_ip}),
           ntohs(session->key.src_port),
           inet_ntoa((struct in_addr){.s_addr = session->key.dst_ip}),
           ntohs(session->key.dst_port),
           session->stats.first_packet, session->stats.last_packet);
    
    struct flow_features *features = &session->stats.features;
    
    // 转换IP地址为字符串
    struct in_addr addr;
    addr.s_addr = session->key.src_ip;
    char src_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, src_ip_str, INET_ADDRSTRLEN);
    
    addr.s_addr = session->key.dst_ip;
    char dst_ip_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &addr, dst_ip_str, INET_ADDRSTRLEN);
    
    // 写入CSV行 - 修改字段顺序和格式
    fprintf(fp, "%s,%u,%s,%u,%u,%s,%.6f,",
                src_ip_str, ntohs(session->key.src_port),
                dst_ip_str, ntohs(session->key.dst_port), 
                session->key.protocol,
        features->start_time_str,
        features->fl_dur);
                
                // 基本统计
    fprintf(fp, "%lu,%lu,%lu,",
            features->tot_fw_pk, features->tot_bw_pk, features->tot_1_fw_pk);
                
                // 包大小特征
    fprintf(fp, "%u,%u,%.2f,%.2f,%u,%u,%.2f,%.2f,",
            features->fwd_pkt_1_min, features->fwd_pkt_1_max, features->fwd_pkt_1_avg, features->fwd_pkt_1_std,
            features->bwd_pkt_1_min, features->bwd_pkt_1_max, features->bwd_pkt_1_avg, features->bwd_pkt_1_std);
                
                // 流量率特征
    fprintf(fp, "%.2f,%.2f,",
            features->fl_byt_s, features->fl_pkt_s);
                
                // 流间隔时间特征
    fprintf(fp, "%.2f,%.2f,%.2f,%.2f,",
            features->fl_iat_avg, features->fl_iat_std, features->fl_iat_max, features->fl_iat_min);
                
                // 前向IAT特征
    fprintf(fp, "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,",
            features->fw_iat_tot, features->fw_iat_avg, features->fw_iat_std, features->fw_iat_max, features->fw_iat_min);
                
                // 反向IAT特征
    fprintf(fp, "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,",
            features->bw_iat_tot, features->bw_iat_avg, features->bw_iat_std, features->bw_iat_max, features->bw_iat_min);
                
                // 头部长度和包率
    fprintf(fp, "%.2f,%.2f,%.2f,%.2f,",
            (double)features->fw_hdr_len, (double)features->bw_hdr_len, features->fw_pkt_s, features->bw_pkt_s);
                
                // 包长度统计
    fprintf(fp, "%.2f,%.2f,%.2f,%.2f,%.2f,",
            (double)features->pkt_len_min, (double)features->pkt_len_max, features->pkt_len_avg, features->pkt_len_std, features->pkt_len_va);
                
                // 比率和平均值
    fprintf(fp, "%.2f,%.2f,%.2f,%.2f,%.2f,",
            features->down_up_ratio, features->avg_packet_size, features->fw_seg_avg, features->bw_seg_avg);
                
                // 子流特征
    fprintf(fp, "%.2f,%.2f,%.2f,%.2f,",
                (double)features->subfl_fw_pk, (double)features->subfl_fw_byt,
            (double)features->subfl_bw_pk, (double)features->subfl_bw_byt);
                
                // 窗口和段大小特征
    fprintf(fp, "%.2f,%.2f,%.2f,%.2f,",
                (double)features->fw_win_byt, (double)features->bw_win_byt,
                (double)features->fw_act_pkt, (double)features->fw_seg_min);
    
    fprintf(fp, "\n");
    
    return 0;
}

// =================== 动态配置函数实现 ===================

int set_session_manager_config(uint32_t max_sessions, uint32_t timeout_ns, 
                              uint32_t cleanup_interval, double load_threshold) {
    if (!global_session_manager) {
        log_error("Session manager not initialized\n");
        return -1;
    }
    
    // 验证参数
    if (max_sessions == 0 || max_sessions > 10000000) {  // 最大1000万会话
        log_error("Invalid max_sessions: %u (must be 1-10000000)\n", max_sessions);
        return -1;
    }
    
    if (timeout_ns == 0 || timeout_ns > 3600000000000ULL) {  // 最大1小时
        log_error("Invalid timeout_ns: %u (must be 1-3600000000000)\n", timeout_ns);
        return -1;
    }
    
    if (cleanup_interval == 0 || cleanup_interval > 3600000000000ULL) {
        log_error("Invalid cleanup_interval: %u (must be 1-3600000000000)\n", cleanup_interval);
        return -1;
    }
    
    if (load_threshold <= 0.0 || load_threshold > 1.0) {
        log_error("Invalid load_threshold: %f (must be 0.0-1.0)\n", load_threshold);
        return -1;
    }
    
    // 更新配置
    global_session_manager->max_sessions_limit = max_sessions;
    global_session_manager->session_timeout_ns = timeout_ns;
    global_session_manager->cleanup_interval_ns = cleanup_interval;
    global_session_manager->load_factor_threshold = load_threshold;
    
    log_info("Session manager config updated: max_sessions=%u, timeout=%u, cleanup=%u, load_threshold=%.2f\n",
            max_sessions, timeout_ns, cleanup_interval, load_threshold);
    
    return 0;
}

int get_session_manager_config(uint32_t *max_sessions, uint32_t *timeout_ns, 
                              uint32_t *cleanup_interval, double *load_threshold) {
    if (!global_session_manager) {
        log_error("Session manager not initialized\n");
        return -1;
    }
    
    if (max_sessions) *max_sessions = global_session_manager->max_sessions_limit;
    if (timeout_ns) *timeout_ns = global_session_manager->session_timeout_ns;
    if (cleanup_interval) *cleanup_interval = global_session_manager->cleanup_interval_ns;
    if (load_threshold) *load_threshold = global_session_manager->load_factor_threshold;
    
    return 0;
}

double get_session_manager_load_factor(void) {
    if (!global_session_manager) return 0.0;
    
    uint32_t active_sessions = atomic_load(&global_session_manager->active_sessions);
    return (double)active_sessions / SESSION_HASH_SIZE;
}

uint32_t get_session_manager_hash_collision_rate(void) {
    if (!global_session_manager) return 0;
    
    uint32_t total_lookups = atomic_load(&global_session_manager->lookup_operations);
    uint32_t collisions = atomic_load(&global_session_manager->hash_collisions);
    
    if (total_lookups == 0) return 0;
    return (collisions * 100) / total_lookups;  // 返回百分比
}

// =================== 智能配置建议函数 ===================

void suggest_session_manager_config(uint64_t available_memory_mb, uint32_t expected_sessions) {
    log_info("=== Session Manager Configuration Suggestions ===\n");
    
    // 基于可用内存的建议
    uint64_t memory_bytes = available_memory_mb * 1024 * 1024;
    uint32_t max_sessions_by_memory = memory_bytes / sizeof(transport_session_t);
    
    log_info("Available memory: %lu MB\n", available_memory_mb);
    log_info("Max sessions by memory: %u\n", max_sessions_by_memory);
    
    // 基于预期会话数的哈希表大小建议
    uint32_t suggested_hash_size = expected_sessions * 4;  // 4倍预期会话数
    if (suggested_hash_size < 65536) suggested_hash_size = 65536;  // 最小64K
    if (suggested_hash_size > 16777216) suggested_hash_size = 16777216;  // 最大16M
    
    log_info("Expected sessions: %u\n", expected_sessions);
    log_info("Suggested hash size: %u\n", suggested_hash_size);
    
    // 建议的配置
    uint32_t max_sessions = (max_sessions_by_memory < expected_sessions * 2) ? 
                           max_sessions_by_memory : expected_sessions * 2;
    
    log_info("Recommended configuration:\n");
    log_info("  - Max sessions: %u\n", max_sessions);
    log_info("  - Hash size: %u\n", suggested_hash_size);
    log_info("  - Session timeout: 300 seconds\n");
    log_info("  - Cleanup interval: 60 seconds\n");
    log_info("  - Load factor threshold: 0.75\n");
    
    log_info("==============================================\n");
}

// =================== 基于实际数据的配置建议函数 ===================

void suggest_config_based_on_actual_sessions(uint32_t actual_tcp_sessions, uint32_t actual_udp_sessions) {
    uint32_t total_sessions = actual_tcp_sessions + actual_udp_sessions;
    
    log_info("=== 基于实际会话数的配置建议 ===\n");
    log_info("实际TCP会话数: %u\n", actual_tcp_sessions);
    log_info("实际UDP会话数: %u\n", actual_udp_sessions);
    log_info("总会话数: %u\n", total_sessions);
    
    // 计算建议的哈希表大小 (4倍会话数)
    uint32_t suggested_hash_size = total_sessions * 4;
    if (suggested_hash_size < 65536) suggested_hash_size = 65536;  // 最小64K
    if (suggested_hash_size > 16777216) suggested_hash_size = 16777216;  // 最大16M
    
    // 计算建议的最大会话数 (3倍当前会话数)
    uint32_t suggested_max_sessions = total_sessions * 3;
    if (suggested_max_sessions < 100000) suggested_max_sessions = 100000;  // 最小10万
    if (suggested_max_sessions > 10000000) suggested_max_sessions = 10000000;  // 最大1000万
    
    // 计算建议的内存池大小 (1.5倍当前会话数)
    uint32_t suggested_pool_size = total_sessions * 3 / 2;
    if (suggested_pool_size < 10000) suggested_pool_size = 10000;  // 最小1万
    if (suggested_pool_size > 1000000) suggested_pool_size = 1000000;  // 最大100万
    
    log_info("\n建议配置:\n");
    log_info("  - 哈希表大小: %u (%.1f倍会话数)\n", 
            suggested_hash_size, (double)suggested_hash_size / total_sessions);
    log_info("  - 最大会话数: %u (%.1f倍当前会话数)\n", 
            suggested_max_sessions, (double)suggested_max_sessions / total_sessions);
    log_info("  - 内存池大小: %u (%.1f倍当前会话数)\n", 
            suggested_pool_size, (double)suggested_pool_size / total_sessions);
    
    // 性能预测
    double current_load_factor = (double)total_sessions / SESSION_HASH_SIZE;
    double suggested_load_factor = (double)total_sessions / suggested_hash_size;
    
    log_info("\n性能预测:\n");
    log_info("  - 当前负载因子: %.4f\n", current_load_factor);
    log_info("  - 建议负载因子: %.4f\n", suggested_load_factor);
    log_info("  - 性能提升: %.1f倍\n", current_load_factor / suggested_load_factor);
    
    // 内存使用预测
    uint64_t session_memory = total_sessions * sizeof(transport_session_t);
    uint64_t hash_table_memory = suggested_hash_size * sizeof(void*);
    uint64_t total_memory_mb = (session_memory + hash_table_memory) / (1024 * 1024);
    
    log_info("\n内存使用预测:\n");
    log_info("  - 会话内存: %lu MB\n", session_memory / (1024 * 1024));
    log_info("  - 哈希表内存: %lu MB\n", hash_table_memory / (1024 * 1024));
    log_info("  - 总内存: %lu MB\n", total_memory_mb);
    
    log_info("==============================================\n");
}

