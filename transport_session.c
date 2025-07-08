#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdatomic.h>
#include <pthread.h>
#include <time.h>
#include <math.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <float.h>

#include "transport_session.h"
#include "flow.h"

// TCP标志定义
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

// CAS操作重试次数
#define CAS_RETRY_LIMIT 100

// 全局会话管理器
static session_manager_t *global_session_manager = NULL;
static atomic_bool session_manager_initialized = ATOMIC_VAR_INIT(false);

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
static void lockfree_free_session_to_pool(transport_session_t *session);
static uint32_t generate_session_state_id(const struct flow_key *key, tcp_session_state_t tcp_state, udp_session_state_t udp_state);
static transport_session_t *lockfree_find_session_with_state(const struct flow_key *key, uint8_t state_id);

// 原子操作辅助函数
static inline void atomic_store_session_ptr(atomic_uintptr_t *atomic_ptr, transport_session_t *session) {
    atomic_store(atomic_ptr, (uintptr_t)session);
}

static inline transport_session_t *atomic_load_session_ptr(atomic_uintptr_t *atomic_ptr) {
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
    
    printf("Lockfree memory pool initialized: %u blocks of %zu bytes each\n", block_count, block_size);
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
    
    printf("Lockfree memory pool cleaned up\n");
    printf("Final stats - Allocations: %lu, Deallocations: %lu, Max usage: %u\n",
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

static void lockfree_free_session_to_pool(transport_session_t *session) {
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
    if (atomic_load(&global_session_manager->total_sessions) >= MAX_SESSIONS) {
        printf("Warning: Maximum session limit reached (%d)\n", MAX_SESSIONS);
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
    printf("\n=== Session Export Statistics ===\n");
    printf("Exported %d active sessions with detailed flow features to %s\n", exported_count, filename);
    printf("Total active sessions: %u\n", total_active_sessions);
    printf("TCP sessions: %u (%.1f%%)\n", tcp_session_count, 
           total_active_sessions > 0 ? (tcp_session_count * 100.0 / total_active_sessions) : 0.0);
    printf("UDP sessions: %u (%.1f%%)\n", udp_session_count,
           total_active_sessions > 0 ? (udp_session_count * 100.0 / total_active_sessions) : 0.0);
    printf("================================\n");
    
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
               "%.0f,%.0f,%.0f,%.0f,"
               "%.2f,%.2f,%.0f,%.0f,"
               "%.2f,%.2f,%.2f,%.2f,"
               "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
               "%.2f,%.2f,%.2f,%.2f,%.2f,%.2f,"
               "%.2f,%.2f,%u,%u,%u,%u,"
               "%u,%u,%.2f,%.2f,"
               "%.0f,%.0f,%.2f,%.2f,"
               "%.2f,%u,%u,%u,"
               "%u,%u,%u,%u,%u,"
               "%.2f,%.2f,%.2f,%.2f,"
               "Normal\n",
               
               // 基本信息
               session->session_id, src_ip_str, ntohs(session->key.src_port), 
               dst_ip_str, ntohs(session->key.dst_port), session->key.protocol,
               
               // 时间和基本统计
               (double)session->stats.first_packet / 1000000000.0, duration,
               features->fwd_packets, features->bwd_packets,
               
               // 包长度特征
               (double)features->fwd_bytes, (double)features->bwd_bytes,
               features->fwd_packet_length_max, features->fwd_packet_length_min,
               features->fwd_packet_length_mean, features->fwd_packet_length_std,
               features->bwd_packet_length_max, features->bwd_packet_length_min,
               features->bwd_packet_length_mean, features->bwd_packet_length_std,
               
               // 流速率特征
               features->flow_bytes_per_sec, features->flow_packets_per_sec,
               features->flow_iat_mean, features->flow_iat_std,
               features->flow_iat_max, features->flow_iat_min,
               
               // 前向IAT特征
               features->fwd_iat_total, features->fwd_iat_mean,
               features->fwd_iat_std, features->fwd_iat_max, features->fwd_iat_min,
               
               // 反向IAT特征
               features->bwd_iat_total, features->bwd_iat_mean, features->bwd_iat_std,
               features->bwd_iat_max, features->bwd_iat_min,
               
               // TCP标志特征
               features->fwd_psh_flags, features->bwd_psh_flags,
               features->fwd_urg_flags, features->bwd_urg_flags,
               features->fwd_header_length, features->bwd_header_length,
               
               // 包速率特征
               features->fwd_packets_per_sec, features->bwd_packets_per_sec,
               
               // 包长度统计
               features->min_packet_length, features->max_packet_length,
               features->packet_length_mean, features->packet_length_std,
               features->packet_length_variance,
               
               // 标志计数
               features->fin_flag_count, features->syn_flag_count, features->rst_flag_count,
               features->psh_flag_count, features->ack_flag_count, features->urg_flag_count,
               features->cwe_flag_count, features->ece_flag_count,
               
               // 其他特征
               features->down_up_ratio, features->avg_packet_size,
               features->avg_fwd_segment_size, features->avg_bwd_segment_size);
    
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
    printf("Exported %d active sessions (simple format) to %s\n", exported_count, filename);
    return exported_count;
}

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

static uint32_t generate_session_state_id(const struct flow_key *key, tcp_session_state_t tcp_state, udp_session_state_t udp_state) {
    uint32_t state_id = 0;
    
    if (key->protocol == IPPROTO_TCP) {
        state_id = (uint32_t)tcp_state;
    } else if (key->protocol == IPPROTO_UDP) {
        state_id = (uint32_t)udp_state;
    }
    
    // 组合五元组哈希和状态
    uint32_t flow_hash = key->src_ip ^ key->dst_ip ^ 
                        ((uint32_t)key->src_port << 16) ^ key->dst_port ^ key->protocol;
    
    return (flow_hash & 0xFFFFFF00) | (state_id & 0xFF);
}

// =================== 性能监控函数 ===================

void print_lockfree_pool_stats(const memory_pool_t *pool) {
    if (!pool) return;
    
    printf("\n=== Lockfree Memory Pool Statistics ===\n");
    printf("Total blocks: %u\n", pool->total_blocks);
    printf("Used blocks: %u\n", atomic_load(&pool->used_count));
    printf("Usage percentage: %u%%\n", get_lockfree_pool_usage_percent(pool));
    printf("Max usage reached: %u blocks\n", atomic_load(&pool->max_usage));
    printf("Total allocations: %lu\n", atomic_load(&pool->allocation_count));
    printf("Total deallocations: %lu\n", atomic_load(&pool->deallocation_count));
    printf("Current free hint: %u\n", atomic_load(&pool->next_free_hint));
    printf("==========================================\n\n");
}

void print_session_manager_stats(const session_manager_t *manager) {
    if (!manager) return;
    
    printf("\n=== Lockfree Session Manager Statistics ===\n");
    printf("Total sessions: %u\n", atomic_load(&manager->total_sessions));
    printf("Active sessions: %u\n", atomic_load(&manager->active_sessions));
    printf("TCP sessions: %u\n", atomic_load(&manager->tcp_sessions));
    printf("UDP sessions: %u\n", atomic_load(&manager->udp_sessions));
    printf("Sessions created: %lu\n", atomic_load(&manager->sessions_created));
    printf("Sessions destroyed: %lu\n", atomic_load(&manager->sessions_destroyed));
    printf("Pool allocations: %lu\n", atomic_load(&manager->pool_allocations));
    printf("Malloc allocations: %lu\n", atomic_load(&manager->malloc_allocations));
    printf("Hash collisions: %lu\n", atomic_load(&manager->hash_collisions));
    printf("Lookup operations: %lu\n", atomic_load(&manager->lookup_operations));
    printf("Next session ID: %u\n", atomic_load(&manager->next_session_id));
    printf("=============================================\n\n");
}

// =================== 特征统计功能实现 =================

int calculate_session_features(transport_session_t *session) {
    if (!session) {
        return -1;
    }
    struct flow_features *features = &session->stats.features;
    
    // 重置特征结构
    memset(features, 0, sizeof(struct flow_features));
    
    // 基本统计
    features->fwd_packets = session->stats.fwd_packets;
    features->bwd_packets = session->stats.bwd_packets;
    features->fwd_bytes = session->stats.fwd_bytes;
    features->bwd_bytes = session->stats.bwd_bytes;
    
    // 计算基本特征
    features->total_fwd_packets = features->fwd_packets;
    features->total_bwd_packets = features->bwd_packets;
    features->total_length_fwd_packets = (double)features->fwd_bytes;
    features->total_length_bwd_packets = (double)features->bwd_bytes;
    
    // 包长度特征
    if (features->fwd_packets > 0) {
        features->fwd_packet_length_max = (double)session->stats.fwd_max_size;
        features->fwd_packet_length_min = (double)session->stats.fwd_min_size;
        features->fwd_packet_length_mean = (double)features->fwd_bytes / features->fwd_packets;
        features->fwd_packet_length_std = sqrt(session->stats.fwd_sum_squares / features->fwd_packets - 
                                             features->fwd_packet_length_mean * features->fwd_packet_length_mean);
    }
    
    if (features->bwd_packets > 0) {
        features->bwd_packet_length_max = (double)session->stats.bwd_max_size;
        features->bwd_packet_length_min = (double)session->stats.bwd_min_size;
        features->bwd_packet_length_mean = (double)features->bwd_bytes / features->bwd_packets;
        features->bwd_packet_length_std = sqrt(session->stats.bwd_sum_squares / features->bwd_packets - 
                                             features->bwd_packet_length_mean * features->bwd_packet_length_mean);
    }
    
    // 流速率特征
    double duration = (session->stats.last_packet - session->stats.first_packet) / 1000000000.0;
    if (duration > 0) {
        features->flow_bytes_per_sec = (features->fwd_bytes + features->bwd_bytes) / duration;
        features->flow_packets_per_sec = (features->fwd_packets + features->bwd_packets) / duration;
        features->fwd_packets_per_sec = features->fwd_packets / duration;
        features->bwd_packets_per_sec = features->bwd_packets / duration;
    }
    
    // 包长度统计
    uint64_t total_packets = features->fwd_packets + features->bwd_packets;
    if (total_packets > 0) {
        features->min_packet_length = (session->stats.fwd_min_size < session->stats.bwd_min_size) ? 
                                     session->stats.fwd_min_size : session->stats.bwd_min_size;
        features->max_packet_length = (session->stats.fwd_max_size > session->stats.bwd_max_size) ? 
                                     session->stats.fwd_max_size : session->stats.bwd_max_size;
        features->packet_length_mean = (double)(features->fwd_bytes + features->bwd_bytes) / total_packets;
        features->avg_packet_size = features->packet_length_mean;
    }
    
    // TCP标志特征
    features->fwd_psh_flags = session->stats.tcp_flags.fwd_psh_flags;
    features->bwd_psh_flags = session->stats.tcp_flags.bwd_psh_flags;
    features->fwd_urg_flags = session->stats.tcp_flags.fwd_urg_flags;
    features->bwd_urg_flags = session->stats.tcp_flags.bwd_urg_flags;
    features->fwd_header_length = session->stats.fwd_header_bytes;
    features->bwd_header_length = session->stats.bwd_header_bytes;
    
    // 标志计数
    features->fin_flag_count = session->stats.tcp_flags.fin_flag_count;
    features->syn_flag_count = session->stats.tcp_flags.syn_flag_count;
    features->rst_flag_count = session->stats.tcp_flags.rst_flag_count;
    features->psh_flag_count = session->stats.tcp_flags.psh_flag_count;
    features->ack_flag_count = session->stats.tcp_flags.ack_flag_count;
    features->urg_flag_count = session->stats.tcp_flags.urg_flag_count;
    features->cwe_flag_count = session->stats.tcp_flags.cwe_flag_count;
    features->ece_flag_count = session->stats.tcp_flags.ece_flag_count;
    
    // 下行/上行比率
    if (features->fwd_bytes > 0) {
        features->down_up_ratio = (double)features->bwd_bytes / features->fwd_bytes;
    }
    
    // 段大小特征
    features->avg_fwd_segment_size = features->fwd_packet_length_mean;
    features->avg_bwd_segment_size = features->bwd_packet_length_mean;
    
    // 简化的批量传输特征
    features->fwd_bulk_rate = features->fwd_packets_per_sec;
    features->bwd_bulk_rate = features->bwd_packets_per_sec;
    
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
                                   &features->fwd_iat_mean, &features->fwd_iat_std,
                                   &features->fwd_iat_max, &features->fwd_iat_min);
        
        // 计算总时间
        features->fwd_iat_total = features->fwd_iat_mean * (session->stats.fwd_timestamps.count - 1);
    }
    
    // 计算反向IAT统计
    if (session->stats.bwd_timestamps.count > 1) {
        calculate_iat_stats_simple(&session->stats.bwd_timestamps,
                                   &features->bwd_iat_mean, &features->bwd_iat_std,
                                   &features->bwd_iat_max, &features->bwd_iat_min);
        
        // 计算总时间
        features->bwd_iat_total = features->bwd_iat_mean * (session->stats.bwd_timestamps.count - 1);
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
    
    features->flow_iat_total = total_iat;
    features->flow_iat_mean = total_iat / (total_count - 1);
    features->flow_iat_max = max_iat;
    features->flow_iat_min = min_iat;
    features->min_packet_iat = min_iat;
    
    // 计算标准差
    double variance = 0.0;
    for (uint32_t i = 1; i < total_count; i++) {
        double iat = (all_timestamps[i] - all_timestamps[i-1]) / 1000000.0;
        double diff = iat - features->flow_iat_mean;
        variance += diff * diff;
    }
    
    features->flow_iat_std = sqrt(variance / (total_count - 1));
    
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
    
    printf("Lockfree transport session manager initialized successfully\n");
    printf("Memory pool: %d blocks, usage: %u%%\n", MEMORY_POOL_SIZE, 
           get_lockfree_pool_usage_percent(&global_session_manager->session_pool));
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
    
    printf("Lockfree transport session manager cleaned up\n");
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
                           session->stats.avg_packet_size, start_time_str, end_time_str,
                           state_str, "YES");
                
                exported_count++;
            }
            session = atomic_load_session_ptr(&session->next_atomic);
        }
    }
    
    fclose(fp);
    
    printf("Exported %d conversation-based sessions to %s\n", exported_count, filename);
    return exported_count;
}

// =================== 基于Session的会话管理 ===================

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
    printf("=== Transport Session Management Test ===\n");
    
    // 初始化流表（来自flow.c）
    flow_table_init();
    printf("Flow table initialized\n");
    
    // 初始化会话管理器
    if (transport_session_manager_init() != 0) {
        printf("Failed to initialize session manager\n");
        return -1;
    }
    printf("Session manager initialized successfully\n");
    
    // 生成测试包
    const int num_packets = 1000;
    test_packet_t *packets = malloc(num_packets * sizeof(test_packet_t));
    if (!packets) {
        printf("Failed to allocate memory for test packets\n");
        return -1;
    }
    
    generate_test_packets(packets, num_packets);
    printf("Generated %d test packets\n", num_packets);
    
    // 处理包并创建基于conversation的会话
    printf("\n=== Processing Packets with Conversation-based Sessions ===\n");
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
                    printf("Created session %u: %s:%u -> %s:%u (%s)\n",
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
            printf("Processed %d packets, %d sessions created\n", i + 1, sessions_created);
        }
    }
    
    printf("\n=== Processing Complete ===\n");
    printf("Total packets processed: %d\n", packets_processed);
    printf("Total sessions created: %d\n", sessions_created);
    printf("Active sessions: %u\n", get_active_session_count());
    printf("TCP sessions: %u\n", get_tcp_session_count());
    printf("UDP sessions: %u\n", get_udp_session_count());
    
    // 导出会话统计
    printf("\n=== Exporting Session Statistics ===\n");
    int exported = export_conversation_based_sessions_to_csv("conversation_sessions.csv");
    printf("Exported %d sessions to conversation_sessions.csv\n", exported);
    
    // 同时导出传统格式进行对比
    int exported_traditional = export_all_sessions_to_csv("traditional_sessions.csv");
    printf("Exported %d sessions to traditional_sessions.csv (for comparison)\n", exported_traditional);
    
    // 打印内存池统计
    printf("\n=== Memory Pool Statistics ===\n");
    if (global_session_manager) {
        print_lockfree_pool_stats(&global_session_manager->session_pool);
        print_session_manager_stats(global_session_manager);
    }
    
    // 打印conversation统计（来自flow.c）
    printf("\n=== Conversation Statistics ===\n");
    print_wireshark_conversation_stats();
    
    // 清理
    free(packets);
    transport_session_manager_cleanup();
    flow_table_destroy();
    
    printf("\n=== Test Complete ===\n");
    return 0;
}

#endif /* SESSION_TEST_MAIN */

