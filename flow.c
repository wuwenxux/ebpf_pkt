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
#include <sys/time.h>
#include <math.h>
#include <linux/igmp.h>

#include "flow.h"
#include "mempool.h"

// =================== 调试级别控制 ===================
static int debug_level = 0;

void set_debug_level(int level) {
    debug_level = level;
}

int get_debug_level() {
    return debug_level;
}

#define DEBUG_PRINT(level, ...) \
    do { \
        if (debug_level >= level) { \
            printf(__VA_ARGS__); \
        } \
    } while(0)

// =================== Wireshark风格的对话统计系统 ===================
// 基于conversation.h中的conv_item_t结构和packet-tcp.c的实现

// 全局变量
struct mempool global_pool;
struct flow_node* flow_table[HASH_TABLE_SIZE] = {0};
int flow_table_initialized = 0;

// 全局对话计数器 (类似Wireshark的conversation tracking)
static uint32_t tcp_conversation_count = 0;
static uint32_t udp_conversation_count = 0;
static uint32_t total_conversation_count = 0;

// 协议处理函数指针表
typedef void (*protocol_handler_t)(const void *transport_hdr, struct flow_key *key, uint8_t *flags);
static protocol_handler_t protocol_handlers[256];

// =================== 对话计数器管理 (基于Wireshark的conversation机制) ===================

void reset_conversation_counters() {
    tcp_conversation_count = 0;
    udp_conversation_count = 0;
    total_conversation_count = 0;
}

uint32_t get_tcp_conversation_count() {
    return tcp_conversation_count;
}

uint32_t get_udp_conversation_count() {
    return udp_conversation_count;
}

uint32_t get_total_conversation_count() {
    return total_conversation_count;
}

uint32_t assign_tcp_conversation_id() {
    // 立即增加计数器，不等待会话结束
    tcp_conversation_count++;
    total_conversation_count++;
    return tcp_conversation_count;
}

uint32_t assign_udp_conversation_id() {
    udp_conversation_count++;
    total_conversation_count++;
    return udp_conversation_count;
}

// =================== 协议处理函数 ===================

void handle_tcp(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
    const struct tcphdr *tcp = (const struct tcphdr*)transport_hdr;
    key->src_port = ntohs(tcp->source);
    key->dst_port = ntohs(tcp->dest);
    
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
    key->src_port = ntohs(udp->source);
    key->dst_port = ntohs(udp->dest);
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
    // IGMP协议处理
    key->src_port = 0;
    key->dst_port = 0;
    *flags = 0;
}

void handle_gre(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
    // GRE协议处理
    key->src_port = 0;
    key->dst_port = 0;
    *flags = 0;
}

void handle_esp(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
    // ESP协议处理
    key->src_port = 0;
    key->dst_port = 0;
    *flags = 0;
}

void handle_ah(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
    // AH协议处理
    key->src_port = 0;
    key->dst_port = 0;
    *flags = 0;
}

void handle_sctp(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
    // SCTP协议处理 - 简化版本，不解析端口
    key->src_port = 0;
    key->dst_port = 0;
    *flags = 0;
}

void handle_unknown(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
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
        DEBUG_PRINT(1, "流表已初始化，跳过重新初始化\n");
        return;
    }
    // 强制重新初始化，确保每次都是干净的状态
    mempool_init(&global_pool);
    memset(flow_table, 0, sizeof(flow_table));
    init_protocol_handlers();
    reset_conversation_counters();
    
    flow_table_initialized = 1;
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
    
    // 初始化统计结构
    memset(&node->stats, 0, sizeof(struct flow_stats));
    
    // 初始化Wireshark风格的对话字段
    node->tcp_state = TCP_CONV_UNKNOWN;
    node->completeness = 0;
    node->conversation_id = 0;
    node->first_packet_time = packet_timestamp;
    node->last_packet_time = packet_timestamp;
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
    // 标准化流键 - 确保较小的IP地址作为源地址
    struct flow_key normalized_key;
    bool is_reverse = false;
    
    if (key->src_ip < key->dst_ip || 
        (key->src_ip == key->dst_ip && key->src_port < key->dst_port)) {
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
        if (memcmp(&node->key, &normalized_key, sizeof(struct flow_key)) == 0) {
            // 找到现有会话 - 简化的重用检测逻辑，类似Wireshark
            bool should_create_new_session = false;
            
            if (key->protocol == IPPROTO_TCP) {
                // **简化**: 只在明确的会话结束后才创建新会话
                if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
                    // 新的SYN包 - 只有在会话已明确结束时才创建新会话
                    if (node->stats.session_completed) {
                        should_create_new_session = true;
                        DEBUG_PRINT(2, "检测到TCP会话结束后的新SYN，创建新会话\n");
                    }
                }
            } else {
                // UDP: 使用更长的超时时间，减少会话重置
                uint64_t time_diff = packet_timestamp - node->stats.last_seen;
                if (time_diff > (300 * 1000000000ULL)) { // 5分钟超时
                    should_create_new_session = true;
                    DEBUG_PRINT(2, "UDP会话超时，创建新会话\n");
                }
            }
            
            if (should_create_new_session) {
                // 重置会话统计，但保留会话ID分配逻辑
                memset(&node->stats, 0, sizeof(struct flow_stats));
                
                // **使用新函数**: 为相应协议分配对话ID
                assign_conversation_id_for_protocol(&node->stats, key->protocol);
                
                DEBUG_PRINT(2, "重置会话统计: TCP ID %u, UDP ID %u\n",
                           node->stats.tcp_conversation_id, node->stats.udp_conversation_id);
            }
            
            // 更新时间戳和会话完整性
            node->stats.last_seen = packet_timestamp;
            if (key->protocol == IPPROTO_TCP) {
                if (!node->stats.tcp_base_seq_set && (tcp_flags & TCP_FLAG_SYN)) {
                    // 设置TCP基础序列号（从TCP头部获取）
                    node->stats.tcp_base_seq_set = true;
                }
            }
            
            // 更新对话完整性
            update_conversation_completeness(node, tcp_flags);
            
            return &node->stats;
        }
        node = node->next;
    }
    
    // 创建新会话
    struct flow_node *new_node = flow_table_insert_with_timestamp(&normalized_key, packet_timestamp);
    if (!new_node) {
        return NULL;
    }
    
    // 初始化TCP相关字段
    if (key->protocol == IPPROTO_TCP && (tcp_flags & TCP_FLAG_SYN)) {
        new_node->stats.tcp_base_seq_set = true;
    }
    
    // 更新对话完整性
    update_conversation_completeness(new_node, tcp_flags);
    
    DEBUG_PRINT(2, "创建新会话: TCP ID %u, UDP ID %u\n", 
               new_node->stats.tcp_conversation_id, new_node->stats.udp_conversation_id);
    
    return &new_node->stats;
}

// =================== 流统计更新函数 ===================

void update_flow_stats(struct flow_stats *stats, uint32_t pkt_size, int is_reverse, uint64_t packet_timestamp) {
    if (!stats) return;
    
    // 添加调试信息
    static int update_debug_count = 0;
    if (update_debug_count < 5) {
        DEBUG_PRINT(2, "DEBUG: update_flow_stats: pkt_size=%u, is_reverse=%d\n", pkt_size, is_reverse);
        update_debug_count++;
    }
    
    // 更新最后看到的时间戳
    stats->last_seen = packet_timestamp;
    
    // 更新结束时间
    ns_to_timespec(packet_timestamp, &stats->end_time);
    
    if (is_reverse) {
        // 反向流统计
        stats->bwd_packets++;
        stats->bwd_bytes += pkt_size;
        
        if (update_debug_count <= 5) {
            DEBUG_PRINT(2, "DEBUG: Updated bwd stats: packets=%" PRIu64 ", bytes=%" PRIu64 "\n", 
                   stats->bwd_packets, stats->bwd_bytes);
        }
        
        if (pkt_size > stats->bwd_max_size) stats->bwd_max_size = pkt_size;
        if (pkt_size < stats->bwd_min_size) stats->bwd_min_size = pkt_size;
        
        // 更新平方和用于标准差计算
        stats->bwd_sum_squares += (double)pkt_size * pkt_size;
        
        timestamp_array_add(&stats->bwd_timestamps, packet_timestamp);
    } else {
        // 正向流统计
        stats->fwd_packets++;
        stats->fwd_bytes += pkt_size;
        
        if (update_debug_count <= 5) {
            DEBUG_PRINT(2, "DEBUG: Updated fwd stats: packets=%" PRIu64 ", bytes=%" PRIu64 "\n", 
                   stats->fwd_packets, stats->fwd_bytes);
        }
        
        if (pkt_size > stats->fwd_max_size) stats->fwd_max_size = pkt_size;
        if (pkt_size < stats->fwd_min_size) stats->fwd_min_size = pkt_size;
        
        // 更新平方和用于标准差计算
        stats->fwd_sum_squares += (double)pkt_size * pkt_size;
        
        timestamp_array_add(&stats->fwd_timestamps, packet_timestamp);
    }
}

void update_udp_stats(struct flow_stats *stats, uint32_t pkt_size, int is_reverse, uint64_t packet_timestamp) {
    if (!stats) return;
    
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
        
        // 如果是UDP，也更新UDP特定统计
        if (key.protocol == IPPROTO_UDP) {
            update_udp_stats(stats, pkt_size, is_reverse, packet_timestamp);
        }
    }
}

// =================== Wireshark风格的统计函数 ===================

int count_wireshark_tcp_conversations() {
    return get_tcp_conversation_count();
}

int count_wireshark_udp_conversations() {
    return get_udp_conversation_count();
}

int count_wireshark_all_conversations() {
    return get_total_conversation_count();
}

void count_tcp_conversations_by_completeness(int *complete, int *incomplete, int *partial) {
    if (!complete || !incomplete || !partial) return;
    
    *complete = 0;
    *incomplete = 0; 
    *partial = 0;
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            if (node->key.protocol == IPPROTO_TCP) {
                uint8_t completeness = node->completeness;
                
                // 完整对话：有完整的三次握手（SYN -> SYN+ACK -> ACK）
                if ((completeness & TCP_COMPLETENESS_SYNSENT) &&
                    (completeness & TCP_COMPLETENESS_SYNACK) &&
                    (completeness & TCP_COMPLETENESS_ACK)) {
                    (*complete)++;
                } 
                // 部分对话：有一些TCP活动但不是完整的三次握手
                else if (completeness != 0) {
                    (*partial)++;
                }
                // 不完整对话：没有任何TCP完整性标志
                else {
                    (*incomplete)++;
                }
            }
            node = node->next;
        }
    }
}

void print_wireshark_conversation_stats() {
    printf("\n================== Wireshark风格对话统计 ==================\n");
    
    // 直接使用已统计好的计数器
    uint32_t tcp_conv = get_tcp_conversation_count();
    uint32_t udp_conv = get_udp_conversation_count();
    uint32_t total_conv = get_total_conversation_count();
    
    printf("对话统计摘要:\n");
    printf("  TCP对话: %u\n", tcp_conv);
    printf("  UDP对话: %u\n", udp_conv);
    printf("  总对话数: %u\n", total_conv);
    printf("  说明: 基于Wireshark的conversation table机制\n");
    printf("        - 超时分割阈值: %" PRIu64 "秒\n", (uint64_t)(FLOW_TIMEOUT_NS / 1000000000ULL));
    printf("\n");
    
    // TCP对话完整性分析
    int complete, incomplete, partial;
    count_tcp_conversations_by_completeness(&complete, &incomplete, &partial);
    
    printf("TCP对话完整性分析:\n");
    printf("  完整对话: %d\n", complete);
    printf("  部分对话: %d\n", partial);
    printf("  不完整对话: %d\n", incomplete);
    printf("\n");
    
    // 详细对话列表 (类似tshark -z conv,tcp) - 修复列对齐问题
    printf("TCP对话详情 (前15个):\n");
    printf("%-15s %-6s %-15s %-6s %-8s %-8s %-8s %-8s %-12s %-12s\n",
           "地址A", "端口A", "地址B", "端口B", "包数A→B", "字节A→B", "包数B→A", "字节B→A", "流持续时间", "状态");
    printf("=============== ====== =============== ====== ======== ======== ======== ======== ============ ============\n");
    
    int tcp_conv_printed = 0;
    
    for (int i = 0; i < HASH_TABLE_SIZE && tcp_conv_printed < 15; i++) {
        struct flow_node *node = flow_table[i];
        while (node && tcp_conv_printed < 15) {
            if (node->key.protocol == IPPROTO_TCP) {
                struct in_addr src_addr = {.s_addr = node->key.src_ip};
                struct in_addr dst_addr = {.s_addr = node->key.dst_ip};
                
                const char *state_str = "UNKNOWN";
                switch (node->tcp_state) {
                    case TCP_CONV_INIT: state_str = "INIT"; break;
                    case TCP_CONV_ESTABLISHED: state_str = "ESTAB"; break;
                    case TCP_CONV_CLOSING: state_str = "CLOSING"; break;
                    case TCP_CONV_CLOSED: state_str = "CLOSED"; break;
                    case TCP_CONV_RESET: state_str = "RESET"; break;
                    default: state_str = "UNKNOWN"; break;
                }
                
                double flow_duration_ms = 0.0;
                if (node->last_packet_time > node->first_packet_time) {
                    flow_duration_ms = (node->last_packet_time - node->first_packet_time) / 1000000.0;
                }
                
                printf("%-15s %-6u %-15s %-6u %-8lu %-8lu %-8lu %-8lu %-12.2f %-12s\n",
                       inet_ntoa(src_addr), ntohs(node->key.src_port),
                       inet_ntoa(dst_addr), ntohs(node->key.dst_port),
                       node->stats.fwd_packets, node->stats.fwd_bytes,
                       node->stats.bwd_packets, node->stats.bwd_bytes,
                       flow_duration_ms, state_str);
                
                tcp_conv_printed++;
            }
            node = node->next;
        }
    }
    
    if (tcp_conv_printed == 15 && tcp_conv > 15) {
        printf("... (显示前15个TCP对话，总共%u个)\n", tcp_conv);
    }
    
    printf("\n注意: 此统计基于Wireshark的conversation table机制\n");
    printf("每个唯一的5-tuple创建一个对话\n");
    printf("================== 统计结束 ==================\n");
}

// =================== 向后兼容函数 ===================

int count_tshark_tcp_conversations() {
    return count_wireshark_tcp_conversations();
}

int count_tshark_udp_conversations() {
    return count_wireshark_udp_conversations();
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
            
            mempool_free(&global_pool, node);
            node = next;
        }
        flow_table[i] = NULL;
    }
    
    mempool_destroy(&global_pool);
    
    // 重置对话计数器，确保下次统计从0开始
    reset_conversation_counters();
    
    flow_table_initialized = 0;
}

void cleanup_flows() {
    // 在这个简化版本中，我们不进行超时清理
    // 如果需要，可以在这里添加基于时间的清理逻辑
}

// =================== 简单统计函数 ===================

void print_simple_stats() {
    printf("流统计: TCP对话=%u, UDP对话=%u, 总对话=%u\n", 
           get_tcp_conversation_count(), 
           get_udp_conversation_count(), 
           get_total_conversation_count());
}

void print_flow_stats() {
    // 移除重复的Wireshark统计调用，只在print_final_stats中调用一次
    // print_wireshark_conversation_stats();
}

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

void count_flow_directions(int *forward_flows, int *reverse_flows) {
    if (!forward_flows || !reverse_flows) return;
    
    *forward_flows = 0;
    *reverse_flows = 0;
    
    if (!flow_table_initialized) return;
    
    uint64_t current_time = get_current_time();
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            // 使用ACTIVE_TIMEOUT_NS作为活跃流的判断标准
            uint64_t timeout = ACTIVE_TIMEOUT_NS;
            
            // 只统计活跃流
            if (current_time - node->last_packet_time <= timeout) {
                // 简单的方向判断：如果正向包数更多，认为是正向流
                if (node->stats.fwd_packets >= node->stats.bwd_packets) {
                    (*forward_flows)++;
                } else {
                    (*reverse_flows)++;
                }
            }
            node = node->next;
        }
    }
}

void count_all_flow_directions(int *forward_flows, int *reverse_flows) {
    if (!forward_flows || !reverse_flows) return;
    
    *forward_flows = 0;
    *reverse_flows = 0;
    
    if (!flow_table_initialized) return;
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            // 统计所有流，不考虑是否活跃
            if (node->stats.fwd_packets >= node->stats.bwd_packets) {
                (*forward_flows)++;
            } else {
                (*reverse_flows)++;
            }
            node = node->next;
        }
    }
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
    
    // 基本统计
    features->fwd_packets = stats->fwd_packets;
    features->bwd_packets = stats->bwd_packets;
    features->fwd_bytes = stats->fwd_bytes;
    features->bwd_bytes = stats->bwd_bytes;
    
    // 包大小统计
    features->fwd_max_size = stats->fwd_max_size;
    features->fwd_min_size = (stats->fwd_min_size == UINT32_MAX) ? 0 : stats->fwd_min_size;
    features->bwd_max_size = stats->bwd_max_size;
    features->bwd_min_size = (stats->bwd_min_size == UINT32_MAX) ? 0 : stats->bwd_min_size;
    
    // 计算平均包大小
    if (stats->fwd_packets > 0) {
        features->fwd_avg_size = (double)stats->fwd_bytes / stats->fwd_packets;
        features->fwd_std_size = sqrt(stats->fwd_sum_squares / stats->fwd_packets - 
                                     features->fwd_avg_size * features->fwd_avg_size);
    }
    
    if (stats->bwd_packets > 0) {
        features->bwd_avg_size = (double)stats->bwd_bytes / stats->bwd_packets;
        features->bwd_std_size = sqrt(stats->bwd_sum_squares / stats->bwd_packets - 
                                     features->bwd_avg_size * features->bwd_avg_size);
    }
    
    uint64_t total_packets = stats->fwd_packets + stats->bwd_packets;
    uint64_t total_bytes = stats->fwd_bytes + stats->bwd_bytes;
    
    if (total_packets > 0) {
        features->avg_packet_size = (double)total_bytes / total_packets;
    }
    
    // 计算持续时间（使用时间戳数组）
    uint64_t start_time = 0, end_time = 0;
    
    if (stats->fwd_timestamps.count > 0) {
        start_time = stats->fwd_timestamps.times[0];
        end_time = stats->fwd_timestamps.times[stats->fwd_timestamps.count - 1];
    }
    
    if (stats->bwd_timestamps.count > 0) {
        if (start_time == 0 || stats->bwd_timestamps.times[0] < start_time) {
            start_time = stats->bwd_timestamps.times[0];
        }
        if (stats->bwd_timestamps.times[stats->bwd_timestamps.count - 1] > end_time) {
            end_time = stats->bwd_timestamps.times[stats->bwd_timestamps.count - 1];
        }
    }
    
    if (end_time > start_time) {
        features->duration = (end_time - start_time) / 1000000000.0; // 转换为秒
    }
    
    // 计算流量率
    if (features->duration > 0) {
        features->byte_rate = total_bytes / features->duration;
        features->packet_rate = total_packets / features->duration;
        features->fwd_packet_rate = stats->fwd_packets / features->duration;
        features->bwd_packet_rate = stats->bwd_packets / features->duration;
    }
    
    // 计算包间隔时间统计
    calculate_iat_stats(&stats->fwd_timestamps, 
                       &features->fwd_iat_total, &features->fwd_iat_mean, 
                       &features->fwd_iat_std, &features->fwd_iat_max, &features->fwd_iat_min);
    
    calculate_iat_stats(&stats->bwd_timestamps, 
                       &features->bwd_iat_total, &features->bwd_iat_mean, 
                       &features->bwd_iat_std, &features->bwd_iat_max, &features->bwd_iat_min);
    
    // TCP标志统计
    features->tcp_flags.fwd_fin_count = stats->tcp_flags.fwd_fin_count;
    features->tcp_flags.fwd_syn_count = stats->tcp_flags.fwd_syn_count;
    features->tcp_flags.fwd_rst_count = stats->tcp_flags.fwd_rst_count;
    features->tcp_flags.fwd_psh_count = stats->tcp_flags.fwd_psh_count;
    features->tcp_flags.fwd_ack_count = stats->tcp_flags.fwd_ack_count;
    features->tcp_flags.fwd_urg_count = stats->tcp_flags.fwd_urg_count;
    
    features->tcp_flags.bwd_fin_count = stats->tcp_flags.bwd_fin_count;
    features->tcp_flags.bwd_syn_count = stats->tcp_flags.bwd_syn_count;
    features->tcp_flags.bwd_rst_count = stats->tcp_flags.bwd_rst_count;
    features->tcp_flags.bwd_psh_count = stats->tcp_flags.bwd_psh_count;
    features->tcp_flags.bwd_ack_count = stats->tcp_flags.bwd_ack_count;
    features->tcp_flags.bwd_urg_count = stats->tcp_flags.bwd_urg_count;
    
    // 总标志计数
    features->fin_flag_cnt = features->tcp_flags.fwd_fin_count + features->tcp_flags.bwd_fin_count;
    features->syn_flag_cnt = features->tcp_flags.fwd_syn_count + features->tcp_flags.bwd_syn_count;
    features->rst_flag_cnt = features->tcp_flags.fwd_rst_count + features->tcp_flags.bwd_rst_count;
    features->psh_flag_cnt = features->tcp_flags.fwd_psh_count + features->tcp_flags.bwd_psh_count;
    features->ack_flag_cnt = features->tcp_flags.fwd_ack_count + features->tcp_flags.bwd_ack_count;
    features->urg_flag_cnt = features->tcp_flags.fwd_urg_count + features->tcp_flags.bwd_urg_count;
    
    // 头部字节数
    features->fwd_header_bytes = stats->fwd_header_bytes;
    features->bwd_header_bytes = stats->bwd_header_bytes;
    
    // 初始窗口字节数
    features->fwd_init_win_bytes = stats->fwd_init_win_bytes;
    features->bwd_init_win_bytes = stats->bwd_init_win_bytes;
    
    // 格式化开始时间字符串
    struct tm *start_tm = localtime(&stats->start_time.tv_sec);
    if (start_tm) {
        strftime(features->start_time_str, sizeof(features->start_time_str), 
                "%Y-%m-%d %H:%M:%S", start_tm);
    }
}

// 添加新的TCP会话统计函数，基于会话完成度
int count_tcp_sessions_by_lifecycle() {
    if (!flow_table_initialized) return 0;
    
    int session_count = 0;
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            if (node->key.protocol == IPPROTO_TCP) {
                // 每个TCP流节点代表一个会话实例
                // 不管完整性如何，只要有TCP活动就算一个会话
                session_count++;
            }
            node = node->next;
        }
    }
    
    return session_count;
}

// 按照TCP会话状态分类统计
void count_tcp_sessions_by_state(int *init_sessions, int *established_sessions, 
                                 int *closing_sessions, int *reset_sessions, int *unknown_sessions) {
    if (!init_sessions || !established_sessions || !closing_sessions || 
        !reset_sessions || !unknown_sessions) return;
    
    *init_sessions = 0;
    *established_sessions = 0;
    *closing_sessions = 0;
    *reset_sessions = 0;
    *unknown_sessions = 0;
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            if (node->key.protocol == IPPROTO_TCP) {
                switch (node->tcp_state) {
                    case TCP_CONV_INIT:
                        (*init_sessions)++;
                        break;
                    case TCP_CONV_ESTABLISHED:
                        (*established_sessions)++;
                        break;
                    case TCP_CONV_CLOSING:
                        (*closing_sessions)++;
                        break;
                    case TCP_CONV_RESET:
                        (*reset_sessions)++;
                        break;
                    case TCP_CONV_CLOSED:
                        (*closing_sessions)++;
                        break;
                    default:
                        (*unknown_sessions)++;
                    break;
                }
            }
            node = node->next;
        }
    }
}