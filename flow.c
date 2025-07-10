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
#include <stdatomic.h>

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
    return atomic_load(&total_conversation_count);
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
    
    // **重要**: 重置所有对话计数器，包括UDP流计数器
    reset_conversation_counters();
    reset_udp_stream_counter();
    
    flow_table_initialized = 1;
    
    DEBUG_PRINT(1, "流表初始化完成，所有计数器已重置\n");
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
    // **重要**: 根据协议类型使用不同的处理逻辑
    if (key->protocol == IPPROTO_UDP) {
        // UDP使用Wireshark风格的稳定对话管理
        return get_or_create_udp_conversation(key, is_reverse_ptr, packet_timestamp);
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
        if (memcmp(&node->key, &normalized_key, sizeof(struct flow_key)) == 0) {
            // 找到现有会话 - **修改**: 使用更宽松的tshark风格逻辑
            bool should_create_new_session = false;
            
            if (key->protocol == IPPROTO_TCP) {
                // **tshark风格**: 更宽松的新会话创建条件
                if ((tcp_flags & TCP_FLAG_SYN) && !(tcp_flags & TCP_FLAG_ACK)) {
                    // 新的SYN包 - 使用多种条件判断是否创建新会话
                    if (node->stats.session_completed ||  // 会话已明确结束
                        node->tcp_state == TCP_CONV_RESET ||  // 会话被重置
                        node->tcp_state == TCP_CONV_CLOSING ||  // 会话正在关闭
                        (packet_timestamp - node->last_packet_time > 60000000000ULL)) {  // 超过60秒无活动
                        should_create_new_session = true;
                        DEBUG_PRINT(2, "tshark风格: 检测到新SYN，创建新TCP会话 (状态: %d)\n", node->tcp_state);
                    } else {
                        // **新增**: 即使会话未结束，如果是明显的新连接尝试也创建新会话
                        // 这更符合tshark的行为
                        if (node->stats.fwd_packets > 0 && node->stats.bwd_packets > 0) {
                            // 如果已有双向通信，新的SYN可能是新连接
                            should_create_new_session = true;
                            DEBUG_PRINT(2, "tshark风格: 双向通信后的新SYN，创建新会话\n");
                        }
                    }
                }
                
                // **新增**: 处理连接重置后的新连接
                if ((tcp_flags & TCP_FLAG_RST) && node->tcp_state != TCP_CONV_RESET) {
                    node->tcp_state = TCP_CONV_RESET;
                    node->stats.session_completed = 1;
                }
            }
            
            if (should_create_new_session) {
                // **修改**: 创建全新的节点而不是重置现有节点
                // 这样可以保持历史会话记录，更符合tshark行为
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
            }
            
            // 更新现有会话的时间戳和完整性
            node->stats.last_seen = packet_timestamp;
            node->last_packet_time = packet_timestamp;
            
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
    
    return &new_node->stats;
}

// =================== 流统计更新函数 ===================

void update_flow_stats(struct flow_stats *stats, uint32_t pkt_size, int is_reverse, uint64_t packet_timestamp) {
    if (!stats) return;
    
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
    
    // 添加详细调试信息，检查IP地址原始字节和主机序
    // static int debug_count = 0;
    // if (debug_count < 10) {
    //     char src_ip_str[INET_ADDRSTRLEN];
    //     char dst_ip_str[INET_ADDRSTRLEN];
    //     inet_ntop(AF_INET, &ip->saddr, src_ip_str, sizeof(src_ip_str));
    //     inet_ntop(AF_INET, &ip->daddr, dst_ip_str, sizeof(dst_ip_str));
    //     printf("DEBUG: Packet %d - src raw: %08x, dst raw: %08x | src host: %08x, dst host: %08x | %s -> %s\n",
    //         debug_count + 1,
    //         ip->saddr, ip->daddr,
    //         ntohl(ip->saddr), ntohl(ip->daddr),
    //         src_ip_str, dst_ip_str);
    //     debug_count++;
    // }
    
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
    }
}

// =================== Wireshark风格的统计函数 ===================

int count_wireshark_tcp_conversations() {
    return get_tcp_conversation_count();
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
    if (udp_manual_count != udp_conv) {
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
    
    // **新增**: 打印五元组会话统计
    count_sessions_by_five_tuple();
    
    // **新增**: tshark风格验证
    verify_tshark_style_counting();
}

// =================== 向后兼容函数 ===================

int count_tshark_tcp_conversations() {
    return get_tcp_conversation_count();
}

int count_tshark_udp_conversations() {
    return get_udp_conversation_count();
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
    
    // **重要**: 重置对话计数器，确保下次统计从0开始
    reset_conversation_counters();
    reset_udp_stream_counter();
    
    flow_table_initialized = 0;
    
    DEBUG_PRINT(1, "流表销毁完成，所有计数器已重置\n");
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
    
    // 计算活跃状态特征
    if (stats->active_count > 0) {
        double active_total = 0, active_min = UINT64_MAX, active_max = 0, active_sum_sq = 0;
        
        for (size_t i = 0; i < stats->active_count; i++) {
            double val = stats->active[i] / 1000000.0; // 纳秒转毫秒
            active_total += val;
            if (val < active_min) active_min = val;
            if (val > active_max) active_max = val;
        }
        
        features->active_mean = active_total / stats->active_count;
        features->active_min = active_min;
        features->active_max = active_max;
        
        // 计算标准差
        for (size_t i = 0; i < stats->active_count; i++) {
            double val = stats->active[i] / 1000000.0;
            active_sum_sq += pow(val - features->active_mean, 2);
        }
        features->active_std = sqrt(active_sum_sq / stats->active_count);
    }
    
    // 计算空闲状态特征
    if (stats->idle_count > 0) {
        double idle_total = 0, idle_min = UINT64_MAX, idle_max = 0, idle_sum_sq = 0;
        
        for (size_t i = 0; i < stats->idle_count; i++) {
            double val = stats->idle[i] / 1000000.0; // 纳秒转毫秒
            idle_total += val;
            if (val < idle_min) idle_min = val;
            if (val > idle_max) idle_max = val;
        }
        
        features->idle_mean = idle_total / stats->idle_count;
        features->idle_min = idle_min;
        features->idle_max = idle_max;
        
        // 计算标准差
        for (size_t i = 0; i < stats->idle_count; i++) {
            double val = stats->idle[i] / 1000000.0;
            idle_sum_sq += pow(val - features->idle_mean, 2);
        }
        features->idle_std = sqrt(idle_sum_sq / stats->idle_count);
    }
    
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
        if (memcmp(&node->key, &normalized_key, sizeof(struct flow_key)) == 0) {
            // 找到现有UDP会话
            // **Wireshark风格**: UDP会话一旦创建就保持稳定，不轻易重置
            
            // 更新时间戳
            node->stats.last_seen = packet_timestamp;
            node->last_packet_time = packet_timestamp;
            
            DEBUG_PRINT(3, "重用UDP会话: stream_id=%u\n", node->stats.udp_conversation_id);
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
    
    DEBUG_PRINT(2, "UDP对话计数验证: 计数器=%u, 手动统计=%d\n", 
               udp_stream_counter, manual_count);
    
    return manual_count;
}

/**
 * 打印UDP对话详细信息 - 类似Wireshark的conversation table
 */
void print_udp_conversation_details() {
    printf("\nUDP对话详情 (类似Wireshark conversation table):\n");
    printf("%-15s %-6s %-15s %-6s %-8s %-8s %-8s %-8s %-10s\n",
           "地址A", "端口A", "地址B", "端口B", "包数A→B", "字节A→B", "包数B→A", "字节B→A", "流ID");
    printf("=============== ====== =============== ====== ======== ======== ======== ======== ==========\n");
    
    int udp_conv_printed = 0;
    
    for (int i = 0; i < HASH_TABLE_SIZE && udp_conv_printed < 15; i++) {
        struct flow_node *node = flow_table[i];
        while (node && udp_conv_printed < 15) {
            if (node->key.protocol == IPPROTO_UDP && node->stats.udp_conversation_id > 0) {
                struct in_addr src_addr = {.s_addr = node->key.src_ip};
                struct in_addr dst_addr = {.s_addr = node->key.dst_ip};
                
                printf("%-15s %-6u %-15s %-6u %-8lu %-8lu %-8lu %-8lu %-10u\n",
                       inet_ntoa(src_addr), node->original_src_port,
                       inet_ntoa(dst_addr), node->original_dst_port,
                       node->stats.fwd_packets, node->stats.fwd_bytes,
                       node->stats.bwd_packets, node->stats.bwd_bytes,
                       node->stats.udp_conversation_id);
                
                udp_conv_printed++;
            }
            node = node->next;
        }
    }
    
    if (udp_conv_printed == 15 && udp_stream_counter > 15) {
        printf("... (显示前15个UDP对话，总共%u个)\n", udp_stream_counter);
    }
    
    printf("\n注意: 此统计基于Wireshark的UDP stream机制\n");
    printf("每个唯一的UDP 5-tuple创建一个稳定的stream ID\n");
}

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
            duration_ms = (stats_array[i].last_seen - stats_array[i].first_seen) / 1000000.0;
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
    printf("\n");
    
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
    
    // 清理内存
    free(stats_array);
}

// =================== Wireshark风格的会话打印函数 ===================

/**
 * 按照Wireshark的会话生成方式打印所有会话
 * 基于Wireshark的conversation table机制
 */
void print_all_wireshark_sessions() {
    printf("\n================== Wireshark风格会话表 ==================\n");
    printf("基于Wireshark conversation table机制的完整会话列表\n\n");
    
    // 统计各类会话数量
    uint32_t tcp_sessions = 0, udp_sessions = 0, other_sessions = 0;
    uint32_t total_sessions = 0;
    
    // 首先统计各协议的会话数量
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            total_sessions++;
            switch (node->key.protocol) {
                case IPPROTO_TCP:
                    tcp_sessions++;
                    break;
                case IPPROTO_UDP:
                    udp_sessions++;
                    break;
                default:
                    other_sessions++;
                    break;
            }
            node = node->next;
        }
    }
    
    printf("会话统计概览:\n");
    printf("  TCP会话: %u (基于连接状态和完整性)\n", tcp_sessions);
    printf("  UDP会话: %u (基于稳定的stream ID)\n", udp_sessions);
    printf("  其他协议会话: %u\n", other_sessions);
    printf("  总会话数: %u\n", total_sessions);
    printf("\n");
    
    if (total_sessions == 0) {
        printf("未检测到任何会话\n");
        printf("================== 会话表结束 ==================\n");
        return;
    }
    
    // 打印详细的会话表头
    printf("详细会话表 (按照Wireshark conversation table格式):\n");
    printf("%-4s %-15s %-6s %-15s %-6s %-8s %-10s %-10s %-10s %-10s %-12s %-12s %-10s %-15s\n",
           "ID", "地址A", "端口A", "地址B", "端口B", "协议", "包数A→B", "字节A→B", "包数B→A", "字节B→A", 
           "总包数", "总字节数", "持续时间", "会话状态");
    printf("==== =============== ====== =============== ====== ======== ========== ========== ========== ========== ============ ============ ========== ===============\n");
    
    uint32_t session_id = 1;
    
    // TCP会话详情 (按照Wireshark的TCP conversation逻辑)
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            if (node->key.protocol == IPPROTO_TCP) {
                struct in_addr src_addr = {.s_addr = node->key.src_ip};
                struct in_addr dst_addr = {.s_addr = node->key.dst_ip};
                
                // 计算会话持续时间 (毫秒)
                double duration_ms = 0.0;
                if (node->last_packet_time > node->first_packet_time) {
                    duration_ms = (node->last_packet_time - node->first_packet_time) / 1000000.0;
                }
                
                // 总流量统计
                uint64_t total_packets = node->stats.fwd_packets + node->stats.bwd_packets;
                uint64_t total_bytes = node->stats.fwd_bytes + node->stats.bwd_bytes;
                
                // TCP会话状态 (基于Wireshark的TCP分析)
                const char *session_state;
                if (node->stats.session_completed) {
                    if (node->tcp_state == TCP_CONV_RESET) {
                        session_state = "RESET";
                    } else if (node->tcp_state == TCP_CONV_CLOSING) {
                        session_state = "CLOSED";
                    } else {
                        session_state = "COMPLETED";
                    }
                } else {
                    switch (node->tcp_state) {
                        case TCP_CONV_INIT:
                            session_state = "INIT";
                            break;
                        case TCP_CONV_ESTABLISHED:
                            session_state = "ESTABLISHED";
                            break;
                        case TCP_CONV_CLOSING:
                            session_state = "CLOSING";
                            break;
                        default:
                            session_state = "UNKNOWN";
                            break;
                    }
                }
                
                char src_ip_str[INET_ADDRSTRLEN];
                char dst_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &node->key.src_ip, src_ip_str, sizeof(src_ip_str));
                inet_ntop(AF_INET, &node->key.dst_ip, dst_ip_str, sizeof(dst_ip_str));
                
                printf("%-4u %-15s %-6u %-15s %-6u %-8s %-10lu %-10lu %-10lu %-10lu %-12lu %-12lu %-10.2f %-15s\n",
                       session_id,
                       src_ip_str, node->original_src_port,
                       dst_ip_str, node->original_dst_port,
                       "TCP",
                       node->stats.fwd_packets, node->stats.fwd_bytes,
                       node->stats.bwd_packets, node->stats.bwd_bytes,
                       total_packets, total_bytes,
                       duration_ms, session_state);
                
                session_id++;
            }
            node = node->next;
        }
    }
    
    // UDP会话详情 (按照Wireshark的UDP stream逻辑)
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            if (node->key.protocol == IPPROTO_UDP) {
                struct in_addr src_addr = {.s_addr = node->key.src_ip};
                struct in_addr dst_addr = {.s_addr = node->key.dst_ip};
                
                char src_ip_str[INET_ADDRSTRLEN];
                char dst_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &node->key.src_ip, src_ip_str, sizeof(src_ip_str));
                inet_ntop(AF_INET, &node->key.dst_ip, dst_ip_str, sizeof(dst_ip_str));
                
                // 计算会话持续时间 (毫秒)
                double duration_ms = 0.0;
                if (node->last_packet_time > node->first_packet_time) {
                    duration_ms = (node->last_packet_time - node->first_packet_time) / 1000000.0;
                }
                
                // 总流量统计
                uint64_t total_packets = node->stats.fwd_packets + node->stats.bwd_packets;
                uint64_t total_bytes = node->stats.fwd_bytes + node->stats.bwd_bytes;
                
                // UDP会话状态 (基于Wireshark的UDP stream机制)
                char session_state[32];
                if (node->stats.udp_conversation_id > 0) {
                    snprintf(session_state, sizeof(session_state), "STREAM_%u", node->stats.udp_conversation_id);
                } else {
                    strcpy(session_state, "NO_STREAM");
                }
                
                printf("%-4u %-15s %-6u %-15s %-6u %-8s %-10lu %-10lu %-10lu %-10lu %-12lu %-12lu %-10.2f %-15s\n",
                       session_id,
                       src_ip_str, node->original_src_port,
                       dst_ip_str, node->original_dst_port,
                       "UDP",
                       node->stats.fwd_packets, node->stats.fwd_bytes,
                       node->stats.bwd_packets, node->stats.bwd_bytes,
                       total_packets, total_bytes,
                       duration_ms, session_state);
                
                session_id++;
            }
            node = node->next;
        }
    }
    
    // 其他协议会话详情
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            if (node->key.protocol != IPPROTO_TCP && node->key.protocol != IPPROTO_UDP) {
                struct in_addr src_addr = {.s_addr = node->key.src_ip};
                struct in_addr dst_addr = {.s_addr = node->key.dst_ip};
                
                char src_ip_str[INET_ADDRSTRLEN];
                char dst_ip_str[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &node->key.src_ip, src_ip_str, sizeof(src_ip_str));
                inet_ntop(AF_INET, &node->key.dst_ip, dst_ip_str, sizeof(dst_ip_str));
                
                // 计算会话持续时间 (毫秒)
                double duration_ms = 0.0;
                if (node->last_packet_time > node->first_packet_time) {
                    duration_ms = (node->last_packet_time - node->first_packet_time) / 1000000.0;
                }
                
                // 总流量统计
                uint64_t total_packets = node->stats.fwd_packets + node->stats.bwd_packets;
                uint64_t total_bytes = node->stats.fwd_bytes + node->stats.bwd_bytes;
                
                // 协议名称
                const char *protocol_name;
                switch (node->key.protocol) {
                    case IPPROTO_ICMP:
                        protocol_name = "ICMP";
                        break;
                    case IPPROTO_IGMP:
                        protocol_name = "IGMP";
                        break;
                    case IPPROTO_GRE:
                        protocol_name = "GRE";
                        break;
                    case IPPROTO_ESP:
                        protocol_name = "ESP";
                        break;
                    case IPPROTO_AH:
                        protocol_name = "AH";
                        break;
                    case IPPROTO_SCTP:
                        protocol_name = "SCTP";
                        break;
                    default:
                        protocol_name = "OTHER";
                        break;
                }
                
                printf("%-4u %-15s %-6u %-15s %-6u %-8s %-10lu %-10lu %-10lu %-10lu %-12lu %-12lu %-10.2f %-15s\n",
                       session_id,
                       src_ip_str, node->original_src_port,
                       dst_ip_str, node->original_dst_port,
                       protocol_name,
                       node->stats.fwd_packets, node->stats.fwd_bytes,
                       node->stats.bwd_packets, node->stats.bwd_bytes,
                       total_packets, total_bytes,
                       duration_ms, "ACTIVE");
                
                session_id++;
            }
            node = node->next;
        }
    }
    
    printf("\n");
    printf("会话生成规则说明 (基于Wireshark机制):\n");
    printf("• TCP会话: 基于5-tuple + 连接状态，支持会话重用和状态跟踪\n");
    printf("• UDP会话: 基于5-tuple + 稳定的stream ID，每个唯一5-tuple一个stream\n");
    printf("• 其他协议: 基于5-tuple，简单的双向流统计\n");
    printf("• 会话ID分配: TCP和UDP分别使用独立的计数器\n");
    printf("• 状态跟踪: TCP支持完整的连接生命周期，UDP使用stream机制\n");
    printf("\n");
    
    // 打印会话完整性分析 (仅适用于TCP)
    if (tcp_sessions > 0) {
        int complete_tcp = 0, incomplete_tcp = 0, partial_tcp = 0;
        count_tcp_conversations_by_completeness(&complete_tcp, &incomplete_tcp, &partial_tcp);
        
        printf("TCP会话完整性分析:\n");
        printf("  完整会话 (完整三次握手): %d (%.1f%%)\n", 
               complete_tcp, tcp_sessions > 0 ? (complete_tcp * 100.0 / tcp_sessions) : 0.0);
        printf("  部分会话 (部分TCP活动): %d (%.1f%%)\n", 
               partial_tcp, tcp_sessions > 0 ? (partial_tcp * 100.0 / tcp_sessions) : 0.0);
        printf("  不完整会话 (仅基本连接): %d (%.1f%%)\n", 
               incomplete_tcp, tcp_sessions > 0 ? (incomplete_tcp * 100.0 / tcp_sessions) : 0.0);
        printf("\n");
    }
    
    // 打印UDP stream验证信息
    if (udp_sessions > 0) {
        int udp_manual_count = verify_udp_conversation_count();
        printf("UDP Stream验证:\n");
        printf("  计数器显示: %u streams\n", get_udp_conversation_count());
        printf("  实际统计: %d streams\n", udp_manual_count);
        if (udp_manual_count == get_udp_conversation_count()) {
            printf("  ✅ UDP stream计数一致性验证通过\n");
        } else {
            printf("  ⚠️  UDP stream计数不一致\n");
        }
        printf("\n");
    }
    
    printf("================== 会话表结束 ==================\n");
}


// **新增**: 专门的tshark风格会话计数函数
int count_tshark_style_tcp_sessions() {
    int session_count = 0;
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            if (node->key.protocol == IPPROTO_TCP && node->in_use) {
                session_count++;
                DEBUG_PRINT(3, "tshark计数: TCP会话 %s:%d -> %s:%d (ID: %u)\n",
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
    
    // 初始化活跃/空闲时间数组
    if (!stats->active) {
        stats->active = malloc(MAX_TIMESTAMPS * sizeof(uint64_t));
        stats->active_count = 0;
    }
    if (!stats->idle) {
        stats->idle = malloc(MAX_TIMESTAMPS * sizeof(uint64_t));
        stats->idle_count = 0;
    }
    
    // 计算与上一个包的时间间隔
    if (stats->last_seen > 0) {
        uint64_t time_diff = current_time - stats->last_seen;
        
        if (time_diff <= ACTIVE_TIMEOUT_NS) {
            // 活跃状态
            if (stats->active_count < MAX_TIMESTAMPS) {
                stats->active[stats->active_count++] = time_diff;
            }
        } else {
            // 空闲状态
            if (stats->idle_count < MAX_TIMESTAMPS) {
                stats->idle[stats->idle_count++] = time_diff;
            }
        }
    }
    
    // 更新最后看到的时间
    stats->last_seen = current_time;
}