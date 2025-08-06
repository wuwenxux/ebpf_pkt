#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
#include <inttypes.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <netinet/igmp.h>
#include <netinet/if_ether.h>
#include <sys/time.h>
#include <math.h>
#include <linux/igmp.h>
#include <stdatomic.h>
#include <pthread.h>
#include <sys/mman.h>
#include <sys/sysinfo.h>

#include "flow.h"
#include "mempool.h"
#include "logger.h"
#include "transport_session.h"

// 前向声明
extern int calculate_session_features(transport_session_t *session);

// =================== 调试级别控制 ===================
static int debug_level = 0;

// 统一的shutdown检查函数
static inline bool is_shutdown_requested() {
    extern volatile int running;
    return !running;
}

void set_debug_level(int level) {
    debug_level = level;
    
    // 同时设置日志级别
    switch (level) {
        case 0:
            set_log_level(LOG_LEVEL_WARN);  // 只显示警告和错误
            break;
        case 1:
            set_log_level(LOG_LEVEL_INFO);  // 显示信息、警告和错误
            break;
        case 2:
            set_log_level(LOG_LEVEL_DEBUG); // 显示所有日志
            break;
        default:
            set_log_level(LOG_LEVEL_WARN);
            break;
    }
}

int get_debug_level() {
    return debug_level;
}

// =================== Wireshark风格的对话统计系统 ===================
// 基于conversation.h中的conv_item_t结构和packet-tcp.c的实现

// 全局变量
struct mempool global_pool;
struct flow_node* flow_table[HASH_TABLE_SIZE] = {0};
int flow_table_initialized = 0;

// 会话创建统计变量
static uint64_t total_sessions_created = 0;
static uint64_t tcp_sessions_created = 0;
static uint64_t udp_sessions_created = 0;
static uint64_t sessions_reused = 0;

// 全局对话计数器 (类似Wireshark的conversation tracking)
static volatile uint32_t tcp_conversation_count = 0;
static volatile uint32_t udp_conversation_count = 0;
static volatile uint32_t total_conversation_count = 0;

// 协议处理函数指针表
typedef void (*protocol_handler_t)(const void *transport_hdr, struct flow_key *key, uint8_t *flags);
static protocol_handler_t protocol_handlers[256];

// =================== 对话计数器管理 (基于Wireshark的conversation机制) ===================

void reset_conversation_counters() {
    atomic_store(&tcp_conversation_count, 0);
    atomic_store(&udp_conversation_count, 0);
    atomic_store(&total_conversation_count, 0);
}

uint32_t get_tcp_conversation_count() {
    return atomic_load(&tcp_conversation_count);
}

uint32_t get_udp_conversation_count() {
    return atomic_load(&udp_conversation_count);
}

uint32_t get_total_conversation_count() {
    return atomic_load(&tcp_conversation_count) + atomic_load(&udp_conversation_count);
}

uint32_t assign_tcp_conversation_id() {
    // 立即增加计数器，不等待会话结束
    return atomic_fetch_add_explicit(&tcp_conversation_count, 1, memory_order_relaxed);
}

uint32_t assign_udp_conversation_id() {
    return atomic_fetch_add_explicit(&udp_conversation_count, 1, memory_order_relaxed);
}

// =================== 协议处理函数 ===================

void handle_tcp(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
    const struct tcphdr *tcp = (const struct tcphdr*)transport_hdr;
    key->src_port = tcp->source;  // 已经是主机字节序
    key->dst_port = tcp->dest;    // 已经是主机字节序
    
    // 提取TCP标志
    *flags = 0;
    if (tcp->fin) *flags |= TCP_FIN;
    if (tcp->syn) *flags |= TCP_SYN;
    if (tcp->rst) *flags |= TCP_RST;
    if (tcp->psh) *flags |= TCP_PSH;
    if (tcp->ack) *flags |= TCP_ACK;
    if (tcp->urg) *flags |= TCP_URG;
}

void handle_udp(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
    const struct udphdr *udp = (const struct udphdr*)transport_hdr;
    key->src_port = udp->source;  // 已经是主机字节序
    key->dst_port = udp->dest;    // 已经是主机字节序
    *flags = 0; // UDP没有标志
}

void handle_icmp(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
    // ICMP没有端口概念，使用type和code作为"端口"
    const struct icmphdr *icmp = (const struct icmphdr*)transport_hdr;
    key->src_port = (icmp->type << 8) | icmp->code;
    key->dst_port = 0; // ICMP响应通常交换type
    *flags = 0;
}

void handle_igmp(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
    (void)transport_hdr;  // 避免未使用参数警告
    // IGMP协议处理
    key->src_port = 0;
    key->dst_port = 0;
    *flags = 0;
}

void handle_gre(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
    (void)transport_hdr;  // 避免未使用参数警告
    // GRE协议处理
    key->src_port = 0;
    key->dst_port = 0;
    *flags = 0;
}

void handle_esp(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
    (void)transport_hdr;  // 避免未使用参数警告
    // ESP协议处理
    key->src_port = 0;
    key->dst_port = 0;
    *flags = 0;
}

void handle_ah(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
    (void)transport_hdr;  // 避免未使用参数警告
    // AH协议处理
    key->src_port = 0;
    key->dst_port = 0;
    *flags = 0;
}

void handle_sctp(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
    (void)transport_hdr;  // 避免未使用参数警告
    // SCTP协议处理 - 简化版本，不解析端口
    key->src_port = 0;
    key->dst_port = 0;
    *flags = 0;
}

void handle_unknown(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
    (void)transport_hdr;  // 避免未使用参数警告
    key->src_port = 0;
    key->dst_port = 0;
    *flags = 0;
}

void init_protocol_handlers() {
    memset(protocol_handlers, 0, sizeof(protocol_handlers));
    protocol_handlers[IPPROTO_TCP] = handle_tcp;
    protocol_handlers[IPPROTO_UDP] = handle_udp;
    protocol_handlers[IPPROTO_ICMP] = handle_icmp;
    protocol_handlers[IPPROTO_IGMP] = handle_igmp;
    protocol_handlers[IPPROTO_GRE] = handle_gre;
    protocol_handlers[IPPROTO_ESP] = handle_esp;
    protocol_handlers[IPPROTO_AH] = handle_ah;
    protocol_handlers[IPPROTO_SCTP] = handle_sctp;
    // 为其他协议设置默认处理器
    for (int i = 0; i < 256; i++) {
        if (!protocol_handlers[i]) {
            protocol_handlers[i] = handle_unknown;
        }
    }
}

// =================== 时间戳数组管理 ===================

void timestamp_array_init(timestamp_array_t *arr) {
    arr->times = NULL;
    arr->count = 0;
    arr->capacity = 0;
}

void timestamp_array_add(timestamp_array_t *arr, uint64_t timestamp) {
    if (arr->count >= arr->capacity) {
        size_t new_capacity = arr->capacity == 0 ? 16 : arr->capacity * 2;
        uint64_t *new_times = realloc(arr->times, new_capacity * sizeof(uint64_t));
        if (!new_times) return;
        
        arr->times = new_times;
        arr->capacity = new_capacity;
    }
    
    arr->times[arr->count++] = timestamp;
}

void timestamp_array_free(timestamp_array_t *arr) {
    if (arr->times) {
        free(arr->times);
        arr->times = NULL;
    }
    arr->count = 0;
    arr->capacity = 0;
}

// =================== 时间处理函数 ===================

uint64_t get_current_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

void ns_to_timespec(uint64_t timestamp_ns, struct timespec *ts) {
    ts->tv_sec = timestamp_ns / 1000000000ULL;
    ts->tv_nsec = timestamp_ns % 1000000000ULL;
}

void set_flow_start_time_from_timestamp(struct flow_stats *stats, uint64_t timestamp_ns) {
    ns_to_timespec(timestamp_ns, &stats->start_time);
}

// =================== 流表管理 ===================

void flow_table_init() {
    if (flow_table_initialized) {
        log_info("Flow table already initialized, skipping re-initialization");
        return;
    }
    
    // 获取系统可用内存
    long pages = sysconf(_SC_AVPHYS_PAGES);
    long page_size = sysconf(_SC_PAGE_SIZE);
    long available_memory = pages * page_size;
    long available_gb = available_memory / (1024 * 1024 * 1024);
    
    // 根据可用内存动态调整内存池大小，更加保守
    size_t pool_blocks;
    if (available_gb >= 32) {
        pool_blocks = 50;   // 32GB+ 系统：50个块
    } else if (available_gb >= 16) {
        pool_blocks = 25;   // 16GB+ 系统：25个块
    } else if (available_gb >= 8) {
        pool_blocks = 15;   // 8GB+ 系统：15个块
    } else if (available_gb >= 4) {
        pool_blocks = 8;    // 4GB+ 系统：8个块
    } else if (available_gb >= 2) {
        pool_blocks = 4;    // 2GB+ 系统：4个块
    } else {
        pool_blocks = 2;    // 小内存系统：2个块
    }
    
    log_info("System available memory: %ld GB, using %zu pool blocks", available_gb, pool_blocks);
    
    // 尝试初始化内存池，如果失败则使用更小的配置
    int retry_count = 0;
    while (retry_count < 3) {
        mempool_init_physical(&global_pool, pool_blocks);
        if (global_pool.physical_memory) {
            break; // 成功分配
        }
        
        // 减少内存池大小重试
        pool_blocks = pool_blocks / 2;
        if (pool_blocks < 1) pool_blocks = 1;
        
        log_warn("Memory allocation failed, retrying with %zu blocks", pool_blocks);
        retry_count++;
    }
    
    if (!global_pool.physical_memory) {
        log_error("Failed to allocate memory pool after %d retries", retry_count);
        return;
    }
    
    memset(flow_table, 0, sizeof(flow_table));
    init_protocol_handlers();
    
    // **重要**: 重置所有对话计数器，包括UDP流计数器
    reset_conversation_counters();
    reset_udp_stream_counter();
    
    flow_table_initialized = 1;
    
    log_info("Flow table initialization completed, all counters reset");
}

uint32_t hash_flow_key(const struct flow_key *key) {
    uint32_t hash = 0;
    hash ^= key->src_ip;
    hash ^= key->dst_ip;
    hash ^= ((uint32_t)key->src_port << 16) | key->dst_port;
    hash ^= key->protocol;
    
    // 简单的哈希函数
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = ((hash >> 16) ^ hash) * 0x45d9f3b;
    hash = (hash >> 16) ^ hash;
    
    return hash % HASH_TABLE_SIZE;
}

// **新增函数**: 为指定协议分配对话ID
void assign_conversation_id_for_protocol(struct flow_stats *stats, uint8_t protocol) {
    if (!stats) return;
    
    // 重置所有对话ID
    stats->tcp_conversation_id = 0;
    stats->udp_conversation_id = 0;
    
    // 只为相应协议分配对话ID
    if (protocol == IPPROTO_TCP) {
        stats->tcp_conversation_id = assign_tcp_conversation_id();
    } else if (protocol == IPPROTO_UDP) {
        stats->udp_conversation_id = assign_udp_conversation_id();
    }
    // 其他协议不分配对话ID，保持为0
}

struct flow_node *flow_table_insert_with_timestamp(const struct flow_key *key, uint64_t packet_timestamp) {
    struct flow_node *node = mempool_alloc(&global_pool);
    if (!node) return NULL;
    
    // 使用传入的已标准化的key (确保双向conversation一致性)
    node->key = *key;
    
    // 初始化原始端口号和IP地址（默认为标准化后的值）
    node->original_src_port = key->src_port;
    node->original_dst_port = key->dst_port;
    node->original_src_ip = key->src_ip;
    node->original_dst_ip = key->dst_ip;
    
    // 初始化统计结构
    memset(&node->stats, 0, sizeof(struct flow_stats));
    
    // 初始化Wireshark风格的对话字段
    node->tcp_state = TCP_CONV_UNKNOWN;
    node->completeness = 0;
    node->conversation_id = 0;
    node->first_packet_time = packet_timestamp;
    node->last_packet_time = packet_timestamp;
    
    // 设置flow_stats中的时间戳字段
    node->stats.first_seen = packet_timestamp;
    node->stats.last_seen = packet_timestamp;
    
    node->packet_num = 0;
    node->create_flags = 0;
    
    node->in_use = 1;
    
    // 初始化时间戳数组
    timestamp_array_init(&node->stats.fwd_timestamps);
    timestamp_array_init(&node->stats.bwd_timestamps);
    timestamp_array_init(&node->stats.udp.fwd_timestamps);
    timestamp_array_init(&node->stats.udp.bwd_timestamps);

    set_flow_start_time_from_timestamp(&node->stats, packet_timestamp);
    
    // 初始化流统计的最小值
    node->stats.fwd_min_size = UINT32_MAX;
    node->stats.bwd_min_size = UINT32_MAX;
    node->stats.udp.fwd_min_size = UINT32_MAX;
    node->stats.udp.bwd_min_size = UINT32_MAX;
    
    node->stats.active_min_ns = UINT64_MAX;
    node->stats.idle_min_ns = UINT64_MAX;
    
    // **使用新函数**: 为相应协议分配对话ID
    assign_conversation_id_for_protocol(&node->stats, key->protocol);
    
    // **关键修复**: 将新节点插入到哈希表中
    uint32_t idx = hash_flow_key(key);
    node->next = flow_table[idx];  // 链接到现有链表头部
    flow_table[idx] = node;        // 设置为新的链表头部
    
    return node;
}

// =================== Wireshark风格的对话创建和管理 ===================

// TCP标志位宏定义
#define TCP_FLAG_FIN 0x01
#define TCP_FLAG_SYN 0x02
#define TCP_FLAG_RST 0x04
#define TCP_FLAG_PSH 0x08
#define TCP_FLAG_ACK 0x10
#define TCP_FLAG_URG 0x20

/**
 * 更新对话完整性标志 (基于packet-tcp.c中的TCP分析)
 */
void update_conversation_completeness(struct flow_node *node, uint8_t tcp_flags) {
    if (!node) return;
    
    if (tcp_flags & TCP_FLAG_SYN) {
        node->completeness |= TCP_COMPLETENESS_SYNSENT;
        if (tcp_flags & TCP_FLAG_ACK) {
            node->completeness |= TCP_COMPLETENESS_SYNACK;
            node->tcp_state = TCP_CONV_ESTABLISHED;
        } else {
            node->tcp_state = TCP_CONV_INIT;
        }
    }
    
    if (tcp_flags & TCP_FLAG_ACK) {
        node->completeness |= TCP_COMPLETENESS_ACK;
        if (node->tcp_state == TCP_CONV_UNKNOWN) {
            node->tcp_state = TCP_CONV_ESTABLISHED;
        }
    }
    
    if (tcp_flags & TCP_FLAG_FIN) {
        node->completeness |= TCP_COMPLETENESS_FIN;
        node->tcp_state = TCP_CONV_CLOSING;
        // 标记会话已完成 - 类似Wireshark的逻辑
        node->stats.session_completed = 1;
    }
    
    if (tcp_flags & TCP_FLAG_RST) {
        node->completeness |= TCP_COMPLETENESS_RST;
        node->tcp_state = TCP_CONV_RESET;
        // 标记会话已完成 - 类似Wireshark的逻辑
        node->stats.session_completed = 1;
    }
    
    // 检查数据载荷 - 简化逻辑
    if ((tcp_flags & TCP_FLAG_PSH) || 
        (!(tcp_flags & (TCP_FLAG_SYN | TCP_FLAG_FIN | TCP_FLAG_RST)) && (tcp_flags & TCP_FLAG_ACK))) {
        node->completeness |= TCP_COMPLETENESS_DATA;
    }
}

struct flow_stats* get_or_create_conversation(const struct flow_key *key, int *is_reverse_ptr, uint64_t packet_timestamp, uint8_t tcp_flags) {
    // 检查程序是否正在关闭
    if (is_shutdown_requested()) {
        log_debug("Skipping conversation creation during shutdown");
        return NULL;
    }
    
    // **重要**: 根据协议类型使用不同的处理逻辑
    if (key->protocol == IPPROTO_UDP) {
        // UDP使用Wireshark风格的稳定对话管理
        struct flow_stats* udp_stats = get_or_create_udp_conversation(key, is_reverse_ptr, packet_timestamp);
        log_debug("get_or_create_conversation(UDP) returns: %p", (void*)udp_stats);
        return udp_stats;
    }
    
    // 保存原始端口号和IP地址（用于CSV输出）
    uint16_t original_src_port = key->src_port;
    uint16_t original_dst_port = key->dst_port;
    uint32_t original_src_ip = key->src_ip;
    uint32_t original_dst_ip = key->dst_ip;
    
    // TCP继续使用原有的复杂逻辑（已优化）
    // 标准化流键 - 确保较小的IP地址作为源地址
    struct flow_key normalized_key;
    bool is_reverse = false;
    
    // 修复IP地址字节序比较问题 - 转换为主机字节序进行比较
    uint32_t src_ip_host = ntohl(key->src_ip);
    uint32_t dst_ip_host = ntohl(key->dst_ip);
    
    // 端口号已经是主机字节序（通过ntohs转换），直接比较
    if (src_ip_host < dst_ip_host || 
        (src_ip_host == dst_ip_host && key->src_port < key->dst_port)) {
        normalized_key = *key;
        is_reverse = false;
    } else {
        normalized_key.src_ip = key->dst_ip;
        normalized_key.dst_ip = key->src_ip;
        normalized_key.src_port = key->dst_port;
        normalized_key.dst_port = key->src_port;
        normalized_key.protocol = key->protocol;
        is_reverse = true;
    }
    
    if (is_reverse_ptr) {
        *is_reverse_ptr = is_reverse;
    }
    
    // 查找现有会话
    uint32_t idx = hash_flow_key(&normalized_key);
    struct flow_node *node = flow_table[idx];
    
    while (node) {
        // 移除 is_shutdown_requested() 检查，允许遍历所有节点
        // if (is_shutdown_requested()) {
        //     log_debug("Skipping flow lookup during shutdown");
        //     return NULL;
        // }
        // 验证节点指针的有效性
        if (!node || (uintptr_t)node < 0x1000) {
            log_debug("Invalid node pointer detected, skipping");
            node = node->next;
            continue;
        }
        
        if (memcmp(&node->key, &normalized_key, sizeof(struct flow_key)) == 0) {
            // 找到现有会话 - **修改**: 使用更宽松的tshark风格逻辑
            bool should_create_new_session = false;
            
            if (key->protocol == IPPROTO_TCP) {
                // **更保守的会话创建策略**: 只在真正需要时才创建新会话
                if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
                    // 新的SYN包 - 使用更严格的条件判断是否创建新会话
                    if (node->stats.session_completed ||  // 会话已明确结束
                        node->tcp_state == TCP_CONV_RESET ||  // 会话被重置
                        (packet_timestamp - node->last_packet_time > 600000000000ULL)) {  // 超过10分钟无活动
                        should_create_new_session = true;
                        log_debug("Creating new TCP session: session completed or long timeout");
                    } else {
                        // **更严格**: 只有在会话明确结束或长时间无活动时才创建新会话
                        // 移除双向通信检查，避免过度创建会话
                        log_debug("Continuing with existing session, not creating new one");
                    }
                }
                
                // **处理连接重置**
                if ((tcp_flags & TCP_FLAG_RST) && node->tcp_state != TCP_CONV_RESET) {
                    node->tcp_state = TCP_CONV_RESET;
                    node->stats.session_completed = 1;
                }
            }
            
            if (should_create_new_session) {
                // **更保守的新会话创建策略**: 只在真正需要时才创建新会话
                if (node->stats.session_completed || 
                    (packet_timestamp - node->last_packet_time > 600000000000ULL)) { // 10分钟无活动
                    
                    struct flow_node *new_session_node = flow_table_insert_with_timestamp(&normalized_key, packet_timestamp);
                    if (new_session_node) {
                        // 设置原始端口号和IP地址 - 根据标准化结果调整
                        if (is_reverse) {
                            // 如果标准化时交换了IP地址，原始端口号也要相应交换
                            new_session_node->original_src_port = original_dst_port;
                            new_session_node->original_dst_port = original_src_port;
                            new_session_node->original_src_ip = original_dst_ip;
                            new_session_node->original_dst_ip = original_src_ip;
                        } else {
                            // 没有交换，使用原始值
                            new_session_node->original_src_port = original_src_port;
                            new_session_node->original_dst_port = original_dst_port;
                            new_session_node->original_src_ip = original_src_ip;
                            new_session_node->original_dst_ip = original_dst_ip;
                        }
                        
                        // 初始化TCP相关字段
                        if ((tcp_flags & TCP_FLAG_SYN)) {
                            new_session_node->stats.tcp_base_seq_set = true;
                        }
                        
                        // 更新对话完整性
                        update_conversation_completeness(new_session_node, tcp_flags);
                        
                        return &new_session_node->stats;
                    }
                } else {
                    // 即使有SYN包，也继续使用现有会话
                    log_debug("Continue using existing session, not creating new session");
                }
            }
            
            // 更新现有会话的时间戳和完整性
            node->stats.last_seen = packet_timestamp;
            node->last_packet_time = packet_timestamp;
            
            sessions_reused++; // 统计会话重用次数
            
            if (key->protocol == IPPROTO_TCP) {
                if (!node->stats.tcp_base_seq_set && (tcp_flags & TCP_FLAG_SYN)) {
                    // 设置TCP基础序列号（从TCP头部获取）
                    node->stats.tcp_base_seq_set = true;
                }
            }
            
            // 更新对话完整性
            update_conversation_completeness(node, tcp_flags);
            
            log_debug("hit existing node: %p, returns stats: %p", (void*)node, (void*)&node->stats);
            return &node->stats;
        }
        node = node->next;
    }
    
    // 创建新会话
    struct flow_node *new_node = flow_table_insert_with_timestamp(&normalized_key, packet_timestamp);
    if (!new_node) {
        log_debug("Failed to create new flow node");
        return NULL;
    }
    log_debug("new new_node: %p, returns stats: %p", (void*)new_node, (void*)&new_node->stats);
    
    // 设置原始端口号和IP地址 - 根据标准化结果调整
    if (is_reverse) {
        // 如果标准化时交换了IP地址，原始端口号也要相应交换
        new_node->original_src_port = original_dst_port;
        new_node->original_dst_port = original_src_port;
        new_node->original_src_ip = original_dst_ip;
        new_node->original_dst_ip = original_src_ip;
    } else {
        // 没有交换，使用原始值
        new_node->original_src_port = original_src_port;
        new_node->original_dst_port = original_dst_port;
        new_node->original_src_ip = original_src_ip;
        new_node->original_dst_ip = original_dst_ip;
    }
    
    // 初始化TCP相关字段
    if (key->protocol == IPPROTO_TCP && (tcp_flags & TCP_FLAG_SYN)) {
        new_node->stats.tcp_base_seq_set = true;
    }
    
    // 更新对话完整性
    update_conversation_completeness(new_node, tcp_flags);
    
    // 更新会话创建统计
    total_sessions_created++;
    if (key->protocol == IPPROTO_TCP) {
        tcp_sessions_created++;
    } else if (key->protocol == IPPROTO_UDP) {
        udp_sessions_created++;
    }
    
    return &new_node->stats;
}

// =================== 流统计更新函数 ===================

void update_flow_stats(struct flow_stats *stats, uint32_t pkt_size, int is_reverse, uint64_t packet_timestamp) {
    if (!stats) return;
    
    // 检查程序是否正在关闭
    if (is_shutdown_requested()) {
        log_debug("Skipping flow stats update during shutdown");
        return;
    }
    
    // 如果是第一次更新，设置first_seen
    if (stats->first_seen == 0) {
        stats->first_seen = packet_timestamp;
    }
    
    // 更新最后看到的时间戳
    stats->last_seen = packet_timestamp;
    
    // 更新结束时间
    ns_to_timespec(packet_timestamp, &stats->end_time);
    
    if (is_reverse) {
        // 反向流统计
        stats->bwd_packets++;
        stats->bwd_bytes += pkt_size;
        
        if (pkt_size > stats->bwd_max_size) stats->bwd_max_size = pkt_size;
        if (pkt_size < stats->bwd_min_size) stats->bwd_min_size = pkt_size;
        
        // 更新平方和用于标准差计算
        stats->bwd_sum_squares += (double)pkt_size * pkt_size;
        
        timestamp_array_add(&stats->bwd_timestamps, packet_timestamp);
    } else {
        // 正向流统计
        stats->fwd_packets++;
        stats->fwd_bytes += pkt_size;
        
        if (pkt_size > stats->fwd_max_size) stats->fwd_max_size = pkt_size;
        if (pkt_size < stats->fwd_min_size) stats->fwd_min_size = pkt_size;
        
        // 更新平方和用于标准差计算
        stats->fwd_sum_squares += (double)pkt_size * pkt_size;
        
        timestamp_array_add(&stats->fwd_timestamps, packet_timestamp);
    }
}

void update_udp_stats(struct flow_stats *stats, uint32_t pkt_size, int is_reverse, uint64_t packet_timestamp) {
    if (!stats) return;
    
    // 检查程序是否正在关闭
    if (is_shutdown_requested()) {
        log_debug("Skipping UDP stats update during shutdown");
        return;
    }
    
    if (is_reverse) {
        stats->udp.bwd_packets++;
        stats->udp.bwd_bytes += pkt_size;
        
        if (pkt_size > stats->udp.bwd_max_size) stats->udp.bwd_max_size = pkt_size;
        if (pkt_size < stats->udp.bwd_min_size) stats->udp.bwd_min_size = pkt_size;
        
        // 更新平方和
        stats->udp.bwd_sum_squares += (double)pkt_size * pkt_size;
        
        timestamp_array_add(&stats->udp.bwd_timestamps, packet_timestamp);
        } else {
        stats->udp.fwd_packets++;
        stats->udp.fwd_bytes += pkt_size;
        
        if (pkt_size > stats->udp.fwd_max_size) stats->udp.fwd_max_size = pkt_size;
        if (pkt_size < stats->udp.fwd_min_size) stats->udp.fwd_min_size = pkt_size;
        
        // 更新平方和
        stats->udp.fwd_sum_squares += (double)pkt_size * pkt_size;
        
        timestamp_array_add(&stats->udp.fwd_timestamps, packet_timestamp);
    }
}

// =================== 包处理函数 ===================

void process_packet(const struct iphdr *ip, const void *transport_hdr, uint64_t packet_timestamp) {
    if (!ip || !transport_hdr) return;
    
    // 检查程序是否正在关闭
    if (is_shutdown_requested()) {
        log_debug("Skipping packet processing during shutdown");
        return;
    }
    
    struct flow_key key = {0};
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;
    
    uint8_t flags = 0;
    
    // 使用协议处理函数
    if (protocol_handlers[ip->protocol]) {
        protocol_handlers[ip->protocol](transport_hdr, &key, &flags);
    } else {
        handle_unknown(transport_hdr, &key, &flags);
    }
    
    int is_reverse;
    struct flow_stats *stats = get_or_create_conversation(&key, &is_reverse, packet_timestamp, flags);
    
    if (stats) {
        uint32_t pkt_size = ntohs(ip->tot_len);
        
        // 更新流统计
        update_flow_stats(stats, pkt_size, is_reverse, packet_timestamp);
        
        // 更新TCP标志统计
        if (key.protocol == IPPROTO_TCP) {
            update_tcp_flags(stats, flags, is_reverse);
        }
        
        // 更新活跃/空闲状态
        update_active_idle(stats, packet_timestamp);
        
        // 如果是UDP，也更新UDP特定统计
        if (key.protocol == IPPROTO_UDP) {
            update_udp_stats(stats, pkt_size, is_reverse, packet_timestamp);
        }
        
        // 优化：只在会话不存在时才创建会话，避免重复创建
        static uint64_t last_session_check_time = 0;
        uint64_t current_time = get_current_time();
        
        // 每100ms检查一次会话，而不是每个包都检查
        if (current_time - last_session_check_time > 100000000ULL) { // 100ms in nanoseconds
            transport_session_t *session = process_packet_with_conversation(&key, pkt_size, flags, packet_timestamp);
            if (session) {
                // 计算会话特征
                calculate_session_features(session);
            }
            last_session_check_time = current_time;
        }
    }
}

// =================== Wireshark风格的统计函数 ===================







void print_wireshark_conversation_stats() {
    printf("\n================== Wireshark风格对话统计 ==================\n");
    
    // 使用优化后的计数器
    uint32_t tcp_conv = get_tcp_conversation_count();
    uint32_t udp_conv = count_wireshark_udp_conversations();  // **使用新的UDP统计函数**
    uint32_t total_conv = tcp_conv + udp_conv;  // **修正**: 分别计算总数
    
    printf("对话统计摘要:\n");
    printf("  TCP对话: %u\n", tcp_conv);
    printf("  UDP对话: %u (基于Wireshark stream机制)\n", udp_conv);
    printf("  总对话数: %u\n", total_conv);
    printf("  说明: 基于Wireshark的conversation table机制\n");
    printf("        - TCP: 基于会话状态和完整性\n");
    printf("        - UDP: 基于稳定的stream ID分配\n");
    printf("\n");
    
    // UDP对话计数验证
    int udp_manual_count = verify_udp_conversation_count();
    if ((uint32_t)udp_manual_count != udp_conv) {
        printf("⚠️  UDP对话计数不一致: 计数器=%u, 实际=%d\n", udp_conv, udp_manual_count);
    } else {
        printf("✅ UDP对话计数一致性验证通过\n");
    }
    printf("\n");

    // **替换**: 使用新的Wireshark风格会话打印函数
    //print_all_wireshark_sessions();
    count_sessions_by_five_tuple();
    printf("\n注意: 此统计基于Wireshark的conversation table机制\n");
    printf("TCP: 每个唯一的5-tuple + 会话状态创建一个对话\n");
    printf("UDP: 每个唯一的5-tuple创建一个稳定的stream ID\n");
    printf("================== 统计结束 ==================\n");
    
    // **新增**: tshark风格验证
    verify_tshark_style_counting();
}



int count_all_flows() {
    if (!flow_table_initialized) return 0;
    
    int total_count = 0;
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
    while (node) {
            total_count++;
            node = node->next;
        }
    }
    
    return total_count;
}
// =================== 清理函数 ===================

void flow_table_destroy() {
    if (!flow_table_initialized) return;
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            struct flow_node *next = node->next;
            
            // 清理时间戳数组
            timestamp_array_free(&node->stats.fwd_timestamps);
            timestamp_array_free(&node->stats.bwd_timestamps);
            timestamp_array_free(&node->stats.udp.fwd_timestamps);
            timestamp_array_free(&node->stats.udp.bwd_timestamps);
            // 新增：释放active和idle数组
            if (node->stats.active) {
                free(node->stats.active);
                node->stats.active = NULL;
                node->stats.active_count = 0;
            }
            if (node->stats.idle) {
                free(node->stats.idle);
                node->stats.idle = NULL;
                node->stats.idle_count = 0;
            }
            mempool_free(&global_pool, node);
            node = next;
        }
        flow_table[i] = NULL;
    }
    
    mempool_destroy(&global_pool);
    
    // **重要**: 重置对话计数器，确保下次统计从0开始
    reset_conversation_counters();
    reset_udp_stream_counter();
    
    flow_table_initialized = 0;
    
    log_info("Flow table destroyed, all counters reset");
}

void cleanup_flows() {
    if (!flow_table_initialized) return;
    
    uint64_t current_time = get_current_time();
    
    // 检查内存池使用情况，动态调整清理策略
    size_t total_nodes, free_nodes, used_nodes;
    mempool_get_stats(&global_pool, &total_nodes, &free_nodes, &used_nodes);
    double usage_ratio = (double)used_nodes / total_nodes;
    
    // 根据内存使用情况调整超时时间 - 更激进的清理
    uint64_t timeout;
    if (usage_ratio > 0.8) {
        timeout = ACTIVE_TIMEOUT_NS / 16; // 极其激进：使用1/16的超时时间
    } else if (usage_ratio > 0.6) {
        timeout = ACTIVE_TIMEOUT_NS / 8; // 非常激进：使用1/8的超时时间
    } else if (usage_ratio > 0.4) {
        timeout = ACTIVE_TIMEOUT_NS / 4; // 激进：使用1/4的超时时间
    } else {
        timeout = ACTIVE_TIMEOUT_NS / 2; // 标准：使用一半的超时时间
    }
    
    int cleaned_count = 0;
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        struct flow_node *prev = NULL;
        
        while (node) {
            struct flow_node *next = node->next;
            
            // 检查流是否超时 - 更激进的清理条件
            bool should_cleanup = false;
            
            // 条件1：超过超时时间
            if (current_time - node->last_packet_time > timeout) {
                should_cleanup = true;
            }
            
            // 条件2：内存使用率很高时，清理更多流
            if (usage_ratio > 0.5 && current_time - node->last_packet_time > ACTIVE_TIMEOUT_NS / 8) {
                should_cleanup = true;
            }
            
            // 条件3：会话已完成的流
            if (node->stats.session_completed && current_time - node->last_packet_time > 30000000000ULL) {
                should_cleanup = true;
            }
            
            // 条件4：内存使用率极高时，清理所有不活跃的流
            if (usage_ratio > 0.9 && current_time - node->last_packet_time > 10000000000ULL) {
                should_cleanup = true;
            }
            
            if (should_cleanup) {
                // 从链表中移除节点
                if (prev) {
                    prev->next = next;
                } else {
                    flow_table[i] = next;
                }
                
                // 释放时间戳数组内存
                timestamp_array_free(&node->stats.fwd_timestamps);
                timestamp_array_free(&node->stats.bwd_timestamps);
                timestamp_array_free(&node->stats.udp.fwd_timestamps);
                timestamp_array_free(&node->stats.udp.bwd_timestamps);
                
                // 释放active和idle数组内存
                if (node->stats.active) {
                    free(node->stats.active);
                    node->stats.active = NULL;
                    node->stats.active_count = 0;
                }
                if (node->stats.idle) {
                    free(node->stats.idle);
                    node->stats.idle = NULL;
                    node->stats.idle_count = 0;
                }
                
                // 返回到内存池
                mempool_free(&global_pool, node);
                cleaned_count++;
            } else {
                prev = node;
            }
            
            node = next;
        }
    }
    
    if (cleaned_count > 0) {
        log_info("Cleaned up %d inactive flows (memory usage: %.1f%%)", cleaned_count, usage_ratio * 100.0);
    }
}

// =================== 简单统计函数 ===================





// =================== 缺失的函数实现 ===================

int count_active_flows() {
    if (!flow_table_initialized) return 0;
    
    int active_count = 0;
    uint64_t current_time = get_current_time();
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            // 使用ACTIVE_TIMEOUT_NS作为活跃流的判断标准
            uint64_t timeout = ACTIVE_TIMEOUT_NS;
            
            // 检查流是否在活跃超时时间内
            if (current_time - node->last_packet_time <= timeout) {
                active_count++;
            }
            node = node->next;
        }
    }
    
    return active_count;
}





double time_diff(const struct timespec *end, const struct timespec *start) {
    if (!end || !start) return 0.0;
    
    double diff = (end->tv_sec - start->tv_sec) + 
                  (end->tv_nsec - start->tv_nsec) / 1000000000.0;
    return diff > 0.0 ? diff : 0.0;
}

// 计算平均值
static double calculate_mean(const uint64_t *values, size_t count) {
    if (count == 0) return 0.0;
    
    double sum = 0.0;
    for (size_t i = 0; i < count; i++) {
        sum += values[i];
    }
    return sum / count;
}

// 计算标准差
static double calculate_std(const uint64_t *values, size_t count, double mean) {
    if (count <= 1) return 0.0;
    
    double sum_sq_diff = 0.0;
    for (size_t i = 0; i < count; i++) {
        double diff = values[i] - mean;
        sum_sq_diff += diff * diff;
    }
    return sqrt(sum_sq_diff / (count - 1));
}

// 计算包间隔时间统计
static void calculate_iat_stats(const timestamp_array_t *timestamps, 
                               double *total, double *mean, double *std, 
                               double *max_val, double *min_val) {
    *total = 0.0;
    *mean = 0.0;
    *std = 0.0;
    *max_val = 0.0;
    *min_val = 0.0;
    
    if (!timestamps || timestamps->count < 2) return;
    
    // 计算包间隔时间
    uint64_t *iats = malloc((timestamps->count - 1) * sizeof(uint64_t));
    if (!iats) return;
    
    for (size_t i = 1; i < timestamps->count; i++) {
        iats[i-1] = timestamps->times[i] - timestamps->times[i-1];
        *total += iats[i-1] / 1000000000.0; // 转换为秒
    }
    
    if (timestamps->count > 1) {
        *mean = calculate_mean(iats, timestamps->count - 1) / 1000000000.0;
        *std = calculate_std(iats, timestamps->count - 1, *mean * 1000000000.0) / 1000000000.0;
        
        // 找最大最小值
        uint64_t max_iat = 0, min_iat = UINT64_MAX;
        for (size_t i = 0; i < timestamps->count - 1; i++) {
            if (iats[i] > max_iat) max_iat = iats[i];
            if (iats[i] < min_iat) min_iat = iats[i];
        }
        *max_val = max_iat / 1000000000.0;
        *min_val = min_iat / 1000000000.0;
    }
    
    free(iats);
}

void calculate_flow_features(const struct flow_stats *stats, struct flow_features *features) {
    if (!stats || !features) return;
    
    memset(features, 0, sizeof(struct flow_features));
    
    // 基本统计 - 使用flow_features结构体中定义的字段名称
    features->tot_fw_pk = stats->fwd_packets;
    features->tot_bw_pk = stats->bwd_packets;
    features->tot_1_fw_pk = stats->fwd_bytes;
    features->tot_1_bw_pk = stats->bwd_bytes;
    
    // 包大小统计
    features->fwd_pkt_1_max = stats->fwd_max_size;
    features->fwd_pkt_1_min = (stats->fwd_min_size == UINT32_MAX) ? 0 : stats->fwd_min_size;
    features->bwd_pkt_1_max = stats->bwd_max_size;
    features->bwd_pkt_1_min = (stats->bwd_min_size == UINT32_MAX) ? 0 : stats->bwd_min_size;
    
    // 计算平均包大小
    if (stats->fwd_packets > 0) {
        features->fwd_pkt_1_avg = (double)stats->fwd_bytes / stats->fwd_packets;
        features->fwd_pkt_1_std = sqrt(stats->fwd_sum_squares / stats->fwd_packets - 
                                     features->fwd_pkt_1_avg * features->fwd_pkt_1_avg);
    }
    
    if (stats->bwd_packets > 0) {
        features->bwd_pkt_1_avg = (double)stats->bwd_bytes / stats->bwd_packets;
        features->bwd_pkt_1_std = sqrt(stats->bwd_sum_squares / stats->bwd_packets - 
                                     features->bwd_pkt_1_avg * features->bwd_pkt_1_avg);
    }
    
    uint64_t total_packets = stats->fwd_packets + stats->bwd_packets;
    uint64_t total_bytes = stats->fwd_bytes + stats->bwd_bytes;
    
    if (total_packets > 0) {
        features->avg_packet_size = (double)total_bytes / total_packets;
    }
    
    // 计算基于会话的持续时间 - 借鉴print_session_timing_info的逻辑（单位：毫秒）
    // 直接使用first_seen和last_seen，这是最准确的时间记录方式
    // 优势：
    // 1. first_seen记录会话的第一个包时间戳
    // 2. last_seen记录会话的最后一个包时间戳
    // 3. 对于TCP会话，last_seen会在收到FIN/RST时更新
    // 4. 对于UDP会话，last_seen会在最后一个包时更新
    // 5. 这种计算方式与Wireshark的会话时间记录逻辑一致
    if (stats->last_seen > stats->first_seen) {
        features->fl_dur = (double)(stats->last_seen - stats->first_seen) / 1000000.0; // 纳秒转毫秒
    } else {
        features->fl_dur = 0.0; // 如果只有一个包或时间无效，持续时间为0
    }
    
    // 计算流量率
    if (features->fl_dur > 0) {
        features->fl_byt_s = total_bytes / features->fl_dur;
        features->fl_pkt_s = total_packets / features->fl_dur;
    }
    
    // 计算包间隔时间统计
    calculate_iat_stats(&stats->fwd_timestamps, 
                       &features->fw_iat_tot, &features->fw_iat_avg, 
                       &features->fw_iat_std, &features->fw_iat_max, &features->fw_iat_min);
    
    calculate_iat_stats(&stats->bwd_timestamps, 
                       &features->bw_iat_tot, &features->bw_iat_avg, 
                       &features->bw_iat_std, &features->bw_iat_max, &features->bw_iat_min);
    
    // 计算流间隔时间统计（合并正向和反向的时间戳）
    timestamp_array_t combined_timestamps;
    timestamp_array_init(&combined_timestamps);
    
    // 添加所有时间戳
    for (size_t i = 0; i < stats->fwd_timestamps.count; i++) {
        timestamp_array_add(&combined_timestamps, stats->fwd_timestamps.times[i]);
    }
    for (size_t i = 0; i < stats->bwd_timestamps.count; i++) {
        timestamp_array_add(&combined_timestamps, stats->bwd_timestamps.times[i]);
    }
    
    // 计算流间隔时间统计
    calculate_iat_stats(&combined_timestamps, 
                       NULL, &features->fl_iat_avg, 
                       &features->fl_iat_std, &features->fl_iat_max, &features->fl_iat_min);
    
    timestamp_array_free(&combined_timestamps);
    
    // TCP标志统计 - 使用flow_features结构体中定义的字段
    features->fw_hdr_len = stats->fwd_header_bytes;
    features->bw_hdr_len = stats->bwd_header_bytes;
    
    // 计算新增字段的值
    
    // 包率计算
    if (features->fl_dur > 0) {
        features->fw_pkt_s = stats->fwd_packets / features->fl_dur;
        features->bw_pkt_s = stats->bwd_packets / features->fl_dur;
    } else {
        features->fw_pkt_s = 0.0;
        features->bw_pkt_s = 0.0;
    }
    
    // 流长度特征
    features->pkt_len_min = (features->fwd_pkt_1_min < features->bwd_pkt_1_min) ? features->fwd_pkt_1_min : features->bwd_pkt_1_min;
    features->pkt_len_max = (features->fwd_pkt_1_max > features->bwd_pkt_1_max) ? features->fwd_pkt_1_max : features->bwd_pkt_1_max;
    features->pkt_len_avg = (features->fwd_pkt_1_avg + features->bwd_pkt_1_avg) / 2.0;
    features->pkt_len_std = (features->fwd_pkt_1_std + features->bwd_pkt_1_std) / 2.0;
    features->pkt_len_va = 0; // 数据包到达的最小间隔时间，暂时设为0
    
    // 上传下载比例
    if (stats->bwd_bytes > 0) {
        features->down_up_ratio = (double)stats->fwd_bytes / stats->bwd_bytes;
    } else {
        features->down_up_ratio = 0.0;
    }
    
    // 数据包平均长度 - 使用已存在的变量
    if (total_packets > 0) {
        features->pkt_size_avg = (double)total_bytes / total_packets;
    } else {
        features->pkt_size_avg = 0.0;
    }
    
    // 前向和反向平均长度
    if (stats->fwd_packets > 0) {
        features->fw_seg_avg = (double)stats->fwd_bytes / stats->fwd_packets;
    } else {
        features->fw_seg_avg = 0.0;
    }
    
    if (stats->bwd_packets > 0) {
        features->bw_seg_avg = (double)stats->bwd_bytes / stats->bwd_packets;
    } else {
        features->bw_seg_avg = 0.0;
    }
    
    // 子流特征 - 简化计算
    features->subfl_fw_pk = (double)stats->fwd_packets; // 前向子流中的数据包数
    features->subfl_fw_byt = (double)stats->fwd_bytes;  // 前向子流的平均字节数
    features->subfl_bw_pk = (double)stats->bwd_packets; // 反向子流中的数据包数
    features->subfl_bw_byt = (double)stats->bwd_bytes;  // 反向子流的平均字节数
    
    // TCP相关特征
    features->fw_win_byt = stats->fwd_init_win_bytes;
    features->fw_act_pkt = stats->fwd_tcp_payload_bytes; // 前向具有至少1字节TCP数据有效载荷的数据包数量
    features->fw_seg_min = stats->fwd_min_segment; // 前向观察到的最小段大小
    

    

    
    // 注意：active_mean, active_min, active_max, active_std, idle_mean, idle_min, idle_max, idle_std
    // 这些字段在flow_features结构体中不存在，所以移除了相关计算
    
    // 格式化开始时间字符串
    struct tm *start_tm = localtime(&stats->start_time.tv_sec);
    if (start_tm) {
        strftime(features->start_time_str, sizeof(features->start_time_str), 
                "%Y-%m-%d %H:%M:%S", start_tm);
    }
    
    // ====== 补全并计算所有flow_features字段 ======
    // 平均包大小
    uint64_t total_pkts = features->tot_fw_pk + features->tot_bw_pk;
    uint64_t total_bytes_feat = features->tot_1_fw_pk + features->tot_1_bw_pk;
    if (total_pkts > 0) {
        features->avg_packet_size = (double)total_bytes_feat / total_pkts;
    } else {
        features->avg_packet_size = 0;
    }
    // 流长度特征
    features->pkt_len_min = (features->fwd_pkt_1_min < features->bwd_pkt_1_min) ? features->fwd_pkt_1_min : features->bwd_pkt_1_min;
    features->pkt_len_max = (features->fwd_pkt_1_max > features->bwd_pkt_1_max) ? features->fwd_pkt_1_max : features->bwd_pkt_1_max;
    features->pkt_len_avg = (features->fwd_pkt_1_avg + features->bwd_pkt_1_avg) / 2.0;
    features->pkt_len_std = (features->fwd_pkt_1_std + features->bwd_pkt_1_std) / 2.0;
    features->pkt_len_va = 0; // 如有包到达间隔可计算，否则置0
}





// =================== Wireshark风格的UDP对话管理 ===================

/**
 * 基于Wireshark packet-udp.c的UDP对话创建逻辑
 * 参考: init_udp_conversation_data() 和 get_udp_conversation_data()
 */
struct udp_conversation_data {
    uint32_t stream_id;
    uint64_t first_frame_time;
    uint64_t last_frame_time;
    uint32_t packet_count;
    bool conversation_established;
};

// UDP流计数器 - 类似Wireshark的udp_stream_count
static uint32_t udp_stream_counter = 0;

/**
 * 重置UDP流计数器
 */
void reset_udp_stream_counter() {
    udp_stream_counter = 0;
}

/**
 * 获取下一个UDP流ID - 类似Wireshark的实现
 */
uint32_t get_next_udp_stream_id() {
    return ++udp_stream_counter;
}

/**
 * Wireshark风格的UDP对话查找和创建
 * 基于find_or_create_conversation_strat()的逻辑
 */
struct flow_stats* get_or_create_udp_conversation(const struct flow_key *key, int *is_reverse_ptr, uint64_t packet_timestamp) {
    // 检查程序是否正在关闭
    if (is_shutdown_requested()) {
        log_debug("Skipping UDP conversation creation during shutdown");
        return NULL;
    }
    
    // 标准化流键 - 确保较小的IP地址作为源地址
    struct flow_key normalized_key;
    bool is_reverse = false;
    
    // 修复IP地址字节序比较问题 - 转换为主机字节序进行比较
    uint32_t src_ip_host = ntohl(key->src_ip);
    uint32_t dst_ip_host = ntohl(key->dst_ip);
    
    // 端口号已经是主机字节序（通过ntohs转换），直接比较
    if (src_ip_host < dst_ip_host || 
        (src_ip_host == dst_ip_host && key->src_port < key->dst_port)) {
        normalized_key = *key;
        is_reverse = false;
    } else {
        normalized_key.src_ip = key->dst_ip;
        normalized_key.dst_ip = key->src_ip;
        normalized_key.src_port = key->dst_port;
        normalized_key.dst_port = key->src_port;
        normalized_key.protocol = key->protocol;
        is_reverse = true;
    }
    
    if (is_reverse_ptr) {
        *is_reverse_ptr = is_reverse;
    }
    
    // 查找现有会话
    uint32_t idx = hash_flow_key(&normalized_key);
    struct flow_node *node = flow_table[idx];
    
    while (node) {
        // 移除 is_shutdown_requested() 检查，允许遍历所有节点
        // if (is_shutdown_requested()) {
        //     log_debug("Skipping UDP flow lookup during shutdown");
        //     return NULL;
        // }
        // 验证节点指针的有效性
        if (!node || (uintptr_t)node < 0x1000) {
            log_debug("Invalid UDP node pointer detected, skipping");
            node = node->next;
            continue;
        }
        
        if (memcmp(&node->key, &normalized_key, sizeof(struct flow_key)) == 0) {
            // 找到现有UDP会话
            // **Wireshark风格**: UDP会话一旦创建就保持稳定，不轻易重置
            
            // 更新时间戳
            node->stats.last_seen = packet_timestamp;
            node->last_packet_time = packet_timestamp;
            
            log_debug("Reusing UDP session: stream_id=%u", node->stats.udp_conversation_id);
            return &node->stats;
        }
        node = node->next;
    }
    
    // 创建新的UDP会话 - 类似Wireshark的init_udp_conversation_data()
    struct flow_node *new_node = flow_table_insert_with_timestamp(&normalized_key, packet_timestamp);
    if (!new_node) {
        return NULL;
    }
    
    // 设置原始端口号和IP地址 - 根据标准化结果调整
    if (is_reverse) {
        // 如果标准化时交换了IP地址，原始端口号也要相应交换
        new_node->original_src_port = key->dst_port;
        new_node->original_dst_port = key->src_port;
        new_node->original_src_ip = key->dst_ip;
        new_node->original_dst_ip = key->src_ip;
    } else {
        // 没有交换，使用原始值
        new_node->original_src_port = key->src_port;
        new_node->original_dst_port = key->dst_port;
        new_node->original_src_ip = key->src_ip;
        new_node->original_dst_ip = key->dst_ip;
    }
    
    // **关键**: 为UDP分配唯一的流ID，类似Wireshark的udp_stream_count++
    new_node->stats.udp_conversation_id = get_next_udp_stream_id();
    
    // 初始化UDP会话数据
    new_node->stats.session_completed = 0;  // UDP没有明确的会话结束
    new_node->first_packet_time = packet_timestamp;
    new_node->last_packet_time = packet_timestamp;
    
    // 更新会话创建统计
    total_sessions_created++;
    udp_sessions_created++;
    
    return &new_node->stats;
}

// =================== Wireshark风格的UDP统计函数 ===================

/**
 * 获取UDP对话数量 - 基于Wireshark的udp_stream_count逻辑
 */
int count_wireshark_udp_conversations() {
    // **关键**: 直接返回UDP流计数器，类似Wireshark的get_udp_stream_count()
    return udp_stream_counter;
}

/**
 * 验证UDP对话计数的一致性
 */
int verify_udp_conversation_count() {
    int manual_count = 0;
    
    // 手动统计UDP流节点数量，用于验证
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            if (node->key.protocol == IPPROTO_UDP && node->stats.udp_conversation_id > 0) {
                manual_count++;
            }
            node = node->next;
        }
    }
    
    log_debug("UDP conversation count verification: counter=%u, manual count=%d", 
               udp_stream_counter, manual_count);
    
    return manual_count;
}

/**
 * 打印UDP对话详细信息 - 类似Wireshark的conversation table
 */


// =================== 五元组会话统计函数 ===================

/**
 * 五元组会话统计结构
 */
struct five_tuple_session_stats {
    struct flow_key key;           // 五元组
    uint32_t session_count;        // 该五元组的会话数
    uint32_t tcp_sessions;         // TCP会话数
    uint32_t udp_sessions;         // UDP会话数
    uint64_t total_packets;        // 总包数
    uint64_t total_bytes;          // 总字节数
    uint64_t first_seen;           // 首次出现时间
    uint64_t last_seen;            // 最后出现时间
    char protocol_name[16];        // 协议名称
};

/**
 * 按五元组统计会话数量 - 区分方向
 * 对于同一个五元组，不同方向统计为不同的会话
 * 例如: A->B 和 B->A 被视为两个不同的会话
 */
void count_sessions_by_five_tuple() {
    if (!flow_table_initialized) {
        printf("流表未初始化\n");
        return;
    }
    
    printf("\n=================== 五元组会话统计 (区分方向) ===================\n");
    
    // 动态数组存储五元组统计信息
    struct five_tuple_session_stats *stats_array = NULL;
    int stats_count = 0;
    int stats_capacity = 100;
    
    stats_array = malloc(stats_capacity * sizeof(struct five_tuple_session_stats));
    if (!stats_array) {
        printf("内存分配失败\n");
        return;
    }
    
    // 遍历流表，统计每个五元组（保持原始方向）
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            // **关键**: 不对五元组进行标准化，保持原始方向
            struct flow_key original_key = node->key;
            
            // 查找是否已存在相同的五元组（相同方向）
            int found_index = -1;
            for (int j = 0; j < stats_count; j++) {
                if (memcmp(&stats_array[j].key, &original_key, sizeof(struct flow_key)) == 0) {
                    found_index = j;
                    break;
                }
            }
            
            if (found_index >= 0) {
                // 更新现有五元组统计
                stats_array[found_index].session_count++;
                stats_array[found_index].total_packets += (node->stats.fwd_packets + node->stats.bwd_packets);
                stats_array[found_index].total_bytes += (node->stats.fwd_bytes + node->stats.bwd_bytes);
                
                // 更新时间范围
                if (node->first_packet_time < stats_array[found_index].first_seen) {
                    stats_array[found_index].first_seen = node->first_packet_time;
                }
                if (node->last_packet_time > stats_array[found_index].last_seen) {
                    stats_array[found_index].last_seen = node->last_packet_time;
                }
                
                // 按协议分类统计
                if (original_key.protocol == IPPROTO_TCP) {
                    stats_array[found_index].tcp_sessions++;
                } else if (original_key.protocol == IPPROTO_UDP) {
                    stats_array[found_index].udp_sessions++;
                }
            } else {
                // 添加新的五元组统计
                if (stats_count >= stats_capacity) {
                    stats_capacity *= 2;
                    stats_array = realloc(stats_array, stats_capacity * sizeof(struct five_tuple_session_stats));
                    if (!stats_array) {
                        printf("内存重分配失败\n");
                        return;
                    }
                }
                
                // 初始化新的五元组统计
                memset(&stats_array[stats_count], 0, sizeof(struct five_tuple_session_stats));
                stats_array[stats_count].key = original_key;
                stats_array[stats_count].session_count = 1;
                stats_array[stats_count].total_packets = (node->stats.fwd_packets + node->stats.bwd_packets);
                stats_array[stats_count].total_bytes = (node->stats.fwd_bytes + node->stats.bwd_bytes);
                stats_array[stats_count].first_seen = node->first_packet_time;
                stats_array[stats_count].last_seen = node->last_packet_time;
                
                // 设置协议名称和统计
                if (original_key.protocol == IPPROTO_TCP) {
                    strncpy(stats_array[stats_count].protocol_name, "TCP", sizeof(stats_array[stats_count].protocol_name) - 1);
                    stats_array[stats_count].tcp_sessions = 1;
                } else if (original_key.protocol == IPPROTO_UDP) {
                    strncpy(stats_array[stats_count].protocol_name, "UDP", sizeof(stats_array[stats_count].protocol_name) - 1);
                    stats_array[stats_count].udp_sessions = 1;
                } else {
                    snprintf(stats_array[stats_count].protocol_name, sizeof(stats_array[stats_count].protocol_name), "PROTO_%d", original_key.protocol);
                }
                
                stats_count++;
            }
            node = node->next;
        }
    }
    
    // 计算总体统计
    int total_sessions = 0;
    int total_tcp_sessions = 0;
    int total_udp_sessions = 0;
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    
    for (int i = 0; i < stats_count; i++) {
        total_sessions += stats_array[i].session_count;
        total_tcp_sessions += stats_array[i].tcp_sessions;
        total_udp_sessions += stats_array[i].udp_sessions;
        total_packets += stats_array[i].total_packets;
        total_bytes += stats_array[i].total_bytes;
    }
    
    printf("总体统计:\n");
    printf("  总会话数: %d\n", total_sessions);
    printf("  唯一五元组数（区分方向）: %d\n", stats_count);
    printf("  平均每个五元组的会话数: %.2f\n", stats_count > 0 ? (double)total_sessions / stats_count : 0.0);
    printf("  TCP会话: %d (%.1f%%)\n", total_tcp_sessions, total_sessions > 0 ? (total_tcp_sessions * 100.0 / total_sessions) : 0.0);
    printf("  UDP会话: %d (%.1f%%)\n", total_udp_sessions, total_sessions > 0 ? (total_udp_sessions * 100.0 / total_sessions) : 0.0);
    printf("  其他协议会话: %d (%.1f%%)\n", total_sessions - total_tcp_sessions - total_udp_sessions, 
           total_sessions > 0 ? ((total_sessions - total_tcp_sessions - total_udp_sessions) * 100.0 / total_sessions) : 0.0);
    printf("  总包数: %lu\n", total_packets);
    printf("  总字节数: %lu\n", total_bytes);
    printf("\n");
    
    // 按会话数排序（降序）
    for (int i = 0; i < stats_count - 1; i++) {
        for (int j = i + 1; j < stats_count; j++) {
            if (stats_array[i].session_count < stats_array[j].session_count) {
                struct five_tuple_session_stats temp = stats_array[i];
                stats_array[i] = stats_array[j];
                stats_array[j] = temp;
            }
        }
    }
    
    // 打印前20个最活跃的五元组（区分方向）
    printf("前20个最活跃的五元组（区分方向）:\n");
    printf("%-4s %-15s %-6s %-15s %-6s %-8s %-8s %-10s %-10s %-12s %-12s %-15s\n",
           "排名", "源IP", "源端口", "目标IP", "目标端口", "协议", "会话数", "TCP会话", "UDP会话", "总包数", "总字节数", "持续时间(ms)");
    printf("----------------------------------------------------------------------------------------------------------------------------\n");
    
    int display_count = (stats_count < 20) ? stats_count : 20;
    for (int i = 0; i < display_count; i++) {
        char src_ip_str[INET_ADDRSTRLEN];
        char dst_ip_str[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &stats_array[i].key.src_ip, src_ip_str, sizeof(src_ip_str));
        inet_ntop(AF_INET, &stats_array[i].key.dst_ip, dst_ip_str, sizeof(dst_ip_str));
        double duration_ms = 0.0;
        if (stats_array[i].last_seen > stats_array[i].first_seen) {
            duration_ms = (double)(stats_array[i].last_seen - stats_array[i].first_seen) / 1000000.0;
        }
        // 查找对应的flow_node以获取原始端口号
        uint16_t original_src_port = stats_array[i].key.src_port;
        uint16_t original_dst_port = stats_array[i].key.dst_port;
        
        // 在flow_table中查找对应的节点以获取原始端口号
        for (int j = 0; j < HASH_TABLE_SIZE; j++) {
            struct flow_node *node = flow_table[j];
            while (node) {
                if (memcmp(&node->key, &stats_array[i].key, sizeof(struct flow_key)) == 0) {
                    original_src_port = node->original_src_port;
                    original_dst_port = node->original_dst_port;
                    break;
                }
                node = node->next;
            }
        }
        
        printf("%-4d %-15s %-6u %-15s %-6u %-8s %-8u %-10u %-10u %-12lu %-12lu %-15.2f\n",
               i + 1,
               src_ip_str, original_src_port,
               dst_ip_str, original_dst_port,
               stats_array[i].protocol_name,
               stats_array[i].session_count,
               stats_array[i].tcp_sessions,
               stats_array[i].udp_sessions,
               stats_array[i].total_packets,
               stats_array[i].total_bytes,
               duration_ms);
    }
    
    printf("\n");
    
    // 分析会话分布
    int single_session_tuples = 0;
    int multi_session_tuples = 0;
    int high_session_tuples = 0;
    
    for (int i = 0; i < stats_count; i++) {
        if (stats_array[i].session_count == 1) {
            single_session_tuples++;
        } else if (stats_array[i].session_count <= 5) {
            multi_session_tuples++;
        } else {
            high_session_tuples++;
        }
    }
    
    printf("会话分布分析（区分方向）:\n");
    printf("  单会话五元组: %d (%.1f%%)\n", single_session_tuples, 
           stats_count > 0 ? (single_session_tuples * 100.0 / stats_count) : 0.0);
    printf("  多会话五元组(2-5个): %d (%.1f%%)\n", multi_session_tuples, 
           stats_count > 0 ? (multi_session_tuples * 100.0 / stats_count) : 0.0);
    printf("  高会话五元组(>5个): %d (%.1f%%)\n", high_session_tuples, 
           stats_count > 0 ? (high_session_tuples * 100.0 / stats_count) : 0.0);
    
    // 协议分布统计
    int tcp_tuples = 0, udp_tuples = 0, other_tuples = 0;
    for (int i = 0; i < stats_count; i++) {
        if (stats_array[i].key.protocol == IPPROTO_TCP) {
            tcp_tuples++;
        } else if (stats_array[i].key.protocol == IPPROTO_UDP) {
            udp_tuples++;
        } else {
            other_tuples++;
        }
    }
    
    printf("协议分布（按五元组）:\n");
    printf("  TCP五元组: %d (%.1f%%)\n", tcp_tuples, 
           stats_count > 0 ? (tcp_tuples * 100.0 / stats_count) : 0.0);
    printf("  UDP五元组: %d (%.1f%%)\n", udp_tuples, 
           stats_count > 0 ? (udp_tuples * 100.0 / stats_count) : 0.0);
    printf("  其他协议五元组: %d (%.1f%%)\n", other_tuples, 
           stats_count > 0 ? (other_tuples * 100.0 / stats_count) : 0.0);
    printf("\n");
    
    printf("注意: 此统计区分五元组方向\n");
    printf("• A->B 和 B->A 被视为不同的五元组\n");
    printf("• 每个方向的会话数单独统计\n");
    printf("• 这提供了更细粒度的流量分析\n");
    printf("================== 五元组统计结束 ==================\n");
    
    // 释放内存
    if (stats_array) {
        free(stats_array);
        stats_array = NULL;
    }
}





// **新增**: 专门的tshark风格会话计数函数
int count_tshark_style_tcp_sessions() {
    int session_count = 0;
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            if (node->key.protocol == IPPROTO_TCP && node->in_use) {
                session_count++;
                log_debug("tshark count: TCP session %s:%d -> %s:%d (ID: %u)",
                            inet_ntoa((struct in_addr){.s_addr = node->key.src_ip}),
                            node->key.src_port,
                            inet_ntoa((struct in_addr){.s_addr = node->key.dst_ip}),
                            node->key.dst_port,
                            node->stats.tcp_conversation_id);
            }
            node = node->next;
        }
    }
    
    return session_count;
}

// **新增**: 验证tshark风格计数的一致性
void verify_tshark_style_counting() {
    int actual_tcp_sessions = count_tshark_style_tcp_sessions();
    int counter_tcp_sessions = get_tcp_conversation_count();
    
    printf("\n==================== tshark风格计数验证 ====================\n");
    printf("实际TCP会话数 (遍历流表): %d\n", actual_tcp_sessions);
    printf("计数器TCP会话数: %d\n", counter_tcp_sessions);
    
    if (actual_tcp_sessions == counter_tcp_sessions) {
        printf("✅ tshark风格计数一致\n");
    } else {
        printf("❌ tshark风格计数不一致，差异: %d\n", abs(actual_tcp_sessions - counter_tcp_sessions));
    }
    
    printf("========================================================\n\n");
}

void update_tcp_flags(struct flow_stats *stats, uint8_t tcp_flags, int is_reverse) {
    if (!stats) return;
    
    // 检查程序是否正在关闭
    if (is_shutdown_requested()) {
        log_debug("Skipping TCP flags update during shutdown");
        return;
    }
    
    if (is_reverse) {
        // 反向流标志统计
        if (tcp_flags & TCP_FIN) stats->tcp_flags.bwd_fin_count++;
        if (tcp_flags & TCP_SYN) stats->tcp_flags.bwd_syn_count++;
        if (tcp_flags & TCP_RST) stats->tcp_flags.bwd_rst_count++;
        if (tcp_flags & TCP_PSH) stats->tcp_flags.bwd_psh_count++;
        if (tcp_flags & TCP_ACK) stats->tcp_flags.bwd_ack_count++;
        if (tcp_flags & TCP_URG) stats->tcp_flags.bwd_urg_count++;
        if (tcp_flags & TCP_CWR) stats->tcp_flags.bwd_cwr_count++;
        if (tcp_flags & TCP_ECE) stats->tcp_flags.bwd_ece_count++;
    } else {
        // 正向流标志统计
        if (tcp_flags & TCP_FIN) stats->tcp_flags.fwd_fin_count++;
        if (tcp_flags & TCP_SYN) stats->tcp_flags.fwd_syn_count++;
        if (tcp_flags & TCP_RST) stats->tcp_flags.fwd_rst_count++;
        if (tcp_flags & TCP_PSH) stats->tcp_flags.fwd_psh_count++;
        if (tcp_flags & TCP_ACK) stats->tcp_flags.fwd_ack_count++;
        if (tcp_flags & TCP_URG) stats->tcp_flags.fwd_urg_count++;
        if (tcp_flags & TCP_CWR) stats->tcp_flags.fwd_cwr_count++;
        if (tcp_flags & TCP_ECE) stats->tcp_flags.fwd_ece_count++;
    }
}

void update_active_idle(struct flow_stats *stats, uint64_t current_time) {
    if (!stats) return;
    
    // 检查程序是否正在关闭
    if (is_shutdown_requested()) {
        log_debug("Skipping active/idle update during shutdown");
        return;
    }
    
    // 初始化活跃/空闲时间数组（只在第一次调用时分配）
    if (!stats->active) {
        stats->active = malloc(MAX_TIMESTAMPS * sizeof(uint64_t));
        if (stats->active) {
            stats->active_count = 0;
        }
    }
    if (!stats->idle) {
        stats->idle = malloc(MAX_TIMESTAMPS * sizeof(uint64_t));
        if (stats->idle) {
            stats->idle_count = 0;
        }
    }
    
    // 计算与上一个包的时间间隔
    if (stats->last_seen > 0) {
        uint64_t time_diff = current_time - stats->last_seen;
        
        if (time_diff <= ACTIVE_TIMEOUT_NS) {
            // 活跃状态
            if (stats->active && stats->active_count < MAX_TIMESTAMPS) {
                stats->active[stats->active_count++] = time_diff;
            }
        } else {
            // 空闲状态
            if (stats->idle && stats->idle_count < MAX_TIMESTAMPS) {
                stats->idle[stats->idle_count++] = time_diff;
            }
        }
    }
    
    // 更新最后看到的时间
    stats->last_seen = current_time;
}

// =================== 会话时间记录函数 ===================



// 获取会话创建统计
void get_session_creation_stats(uint64_t *total_created, uint64_t *tcp_created, uint64_t *udp_created, uint64_t *reused) {
    *total_created = total_sessions_created;
    *tcp_created = tcp_sessions_created;
    *udp_created = udp_sessions_created;
    *reused = sessions_reused;
}