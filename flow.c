#define _GNU_SOURCE
#include "flow.h"
#include "mempool.h"
#include <string.h>
#include <stdio.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdlib.h>

// 增加预取相关宏定义
#define PREFETCH(addr) __builtin_prefetch(addr)
#define PREFETCH_RW(addr) __builtin_prefetch(addr, 1, 1)
#define PREFETCH_LOCALITY_HIGH 3
#define PREFETCH_LOCALITY_MED 2
#define PREFETCH_LOCALITY_LOW 1
#define PREFETCH_LOCALITY_NONE 0

// Initial timestamp array size
#define TIMESTAMP_INITIAL_SIZE 32

// Global variables
struct mempool global_pool;
struct flow_node* flow_table[HASH_TABLE_SIZE] = {0}; // Initialize hash table
int flow_table_initialized = 0; // 移除static关键字，使其对外部可见

// 外部声明，这些在loader.c中定义
extern int in_place_updates;
extern int first_stats_print;
extern const char *ANSI_CLEAR_SCREEN;
extern const char *ANSI_CLEAR_LINE;
extern const char *ANSI_CURSOR_UP;
extern const char *ANSI_SAVE_CURSOR;
extern const char *ANSI_RESTORE_CURSOR;
extern const char *ANSI_HIDE_CURSOR;
extern const char *ANSI_SHOW_CURSOR;
extern volatile int running; // 运行状态变量
extern int quiet_mode;       // 安静模式变量

// 协议处理函数原型定义
typedef void (*protocol_handler_t)(const void *transport_hdr, struct flow_key *key, uint8_t *flags);

// 处理函数以供跳转表使用
void handle_tcp(const void *transport_hdr, struct flow_key *key, uint8_t *flags);
void handle_udp(const void *transport_hdr, struct flow_key *key, uint8_t *flags);
void handle_unknown(const void *transport_hdr, struct flow_key *key, uint8_t *flags);

// 协议处理函数跳转表
static protocol_handler_t protocol_handlers[256] = {0}; // 初始化为全零

// 初始化协议处理函数表
void init_protocol_handlers() {
    // 默认所有协议都指向handle_unknown
    for (int i = 0; i < 256; i++) {
        protocol_handlers[i] = handle_unknown;
    }
    
    // 为已知协议设置处理函数
    protocol_handlers[IPPROTO_TCP] = handle_tcp;
    protocol_handlers[IPPROTO_UDP] = handle_udp;
}

// 时间戳数组操作函数
void timestamp_array_init(timestamp_array_t *arr) {
    if (!arr) return;
    
    arr->times = malloc(TIMESTAMP_INITIAL_SIZE * sizeof(uint64_t));
    if (arr->times) {
        arr->capacity = TIMESTAMP_INITIAL_SIZE;
        arr->count = 0;
    } else {
        fprintf(stderr, "Failed to allocate memory for timestamp array\n");
        arr->capacity = 0;
        arr->count = 0;
    }
}

void timestamp_array_add(timestamp_array_t *arr, uint64_t timestamp) {
    if (!arr || !arr->times) return;
    
    // 检查是否需要扩容
    if (arr->count >= arr->capacity) {
        size_t new_capacity = arr->capacity * 2;
        uint64_t *new_times = realloc(arr->times, new_capacity * sizeof(uint64_t));
        
        if (new_times) {
            arr->times = new_times;
            arr->capacity = new_capacity;
        } else {
            fprintf(stderr, "Failed to resize timestamp array\n");
            return;
        }
    }
    
    // 添加新时间戳
    arr->times[arr->count++] = timestamp;
}

void timestamp_array_free(timestamp_array_t *arr) {
    if (!arr) return;
    
    if (arr->times) {
        free(arr->times);
        arr->times = NULL;
    }
    
    arr->count = 0;
    arr->capacity = 0;
}

// 计算时间戳数组的统计特征
void calculate_timestamp_stats(const timestamp_array_t *arr, 
                               double *total, double *mean, 
                               double *std, double *max, double *min) {
    if (!arr || arr->count < 2 || !arr->times || 
        !total || !mean || !std || !max || !min) {
        if (total) *total = 0;
        if (mean) *mean = 0;
        if (std) *std = 0;
        if (max) *max = 0;
        if (min) *min = 0;
        return;
    }
    
    *total = 0;
    *max = 0;
    *min = UINT64_MAX;
    double sum_squares = 0;
    
    // 计算相邻时间戳的间隔
    for (size_t i = 1; i < arr->count; i++) {
        // 假设时间戳是升序的，计算差值
        uint64_t diff = arr->times[i] - arr->times[i-1];
        double diff_sec = diff / 1000000000.0; // 转换为秒
        
        *total += diff_sec;
        
        if (diff_sec > *max) *max = diff_sec;
        if (diff_sec < *min) *min = diff_sec;
    }
    
    // 计算平均值
    *mean = *total / (arr->count - 1);
    
    // 计算标准差
    for (size_t i = 1; i < arr->count; i++) {
        uint64_t diff = arr->times[i] - arr->times[i-1];
        double diff_sec = diff / 1000000000.0;
        sum_squares += pow(diff_sec - *mean, 2);
    }
    
    *std = sqrt(sum_squares / (arr->count - 1));
}

// Get current time in nanoseconds
uint64_t get_current_time() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000 + ts.tv_nsec;
}

void flow_table_init() {
    if (flow_table_initialized) {
        fprintf(stderr, "Warning: flow_table_init called more than once\n");
        return;
    }
    
    mempool_init(&global_pool);
    // Initialize flow table
    memset(flow_table, 0, sizeof(flow_table));
    flow_table_initialized = 1;
    
    // 初始化协议处理函数表
    init_protocol_handlers();
    
    printf("Flow table initialized\n");
}

struct flow_node *flow_table_insert(const struct flow_key *key) {
    if (!key || !flow_table_initialized) return NULL;
    
    struct flow_node *node = mempool_alloc(&global_pool);
    if (!node) return NULL;
    
    // 创建新的key，如果设置了忽略端口，确保端口为0
#if IGNORE_PORTS
    struct flow_key normalized_key = *key;
    normalized_key.src_port = 0;
    normalized_key.dst_port = 0;
    memcpy(&node->key, &normalized_key, sizeof(normalized_key));
#else
    memcpy(&node->key, key, sizeof(*key));
#endif
    
    // 初始化统计信息...
    memset(&node->stats, 0, sizeof(node->stats));
    node->stats.fwd_min_size = UINT32_MAX;
    node->stats.bwd_min_size = UINT32_MAX;
    node->stats.flow_min_length = UINT32_MAX;
    clock_gettime(CLOCK_REALTIME, &node->stats.start_time);
    node->stats.last_seen = get_current_time();
    
    // 初始化时间戳数组
    timestamp_array_init(&node->stats.fwd_timestamps);
    timestamp_array_init(&node->stats.bwd_timestamps);
    
    return node;
}

void flow_table_remove(struct flow_node *node) {
    if (!node) return;
    
    // 释放时间戳数组
    timestamp_array_free(&node->stats.fwd_timestamps);
    timestamp_array_free(&node->stats.bwd_timestamps);
    
    mempool_free(&global_pool, node);
}

double time_diff(const struct timespec *end, const struct timespec *start) {
    return (end->tv_sec - start->tv_sec) + 
          (end->tv_nsec - start->tv_nsec) / 1e9;
}

// 更新TCP标志计数 - 使用更精确的位检查
void update_tcp_flags(struct flow_stats *stats, uint8_t tcp_flags, int is_reverse) {
    if (!stats) return;
    
    struct tcp_flag_stats *flag_stats = &stats->tcp_flags;
    
    // 使用显式位检查而不是非零检查
    if (is_reverse) {
        // 反向流标志统计 - 明确检查每个位
        flag_stats->bwd_fin_count += ((tcp_flags & TCP_FIN) == TCP_FIN) ? 1 : 0;
        flag_stats->bwd_syn_count += ((tcp_flags & TCP_SYN) == TCP_SYN) ? 1 : 0;
        flag_stats->bwd_rst_count += ((tcp_flags & TCP_RST) == TCP_RST) ? 1 : 0;
        flag_stats->bwd_psh_count += ((tcp_flags & TCP_PSH) == TCP_PSH) ? 1 : 0;
        flag_stats->bwd_ack_count += ((tcp_flags & TCP_ACK) == TCP_ACK) ? 1 : 0;
        flag_stats->bwd_urg_count += ((tcp_flags & TCP_URG) == TCP_URG) ? 1 : 0;
        flag_stats->bwd_cwr_count += ((tcp_flags & TCP_CWR) == TCP_CWR) ? 1 : 0;
        flag_stats->bwd_ece_count += ((tcp_flags & TCP_ECE) == TCP_ECE) ? 1 : 0;
    } else {
        // 正向流标志统计 - 明确检查每个位
        flag_stats->fwd_fin_count += ((tcp_flags & TCP_FIN) == TCP_FIN) ? 1 : 0;
        flag_stats->fwd_syn_count += ((tcp_flags & TCP_SYN) == TCP_SYN) ? 1 : 0;
        flag_stats->fwd_rst_count += ((tcp_flags & TCP_RST) == TCP_RST) ? 1 : 0;
        flag_stats->fwd_psh_count += ((tcp_flags & TCP_PSH) == TCP_PSH) ? 1 : 0;
        flag_stats->fwd_ack_count += ((tcp_flags & TCP_ACK) == TCP_ACK) ? 1 : 0;
        flag_stats->fwd_urg_count += ((tcp_flags & TCP_URG) == TCP_URG) ? 1 : 0;
        flag_stats->fwd_cwr_count += ((tcp_flags & TCP_CWR) == TCP_CWR) ? 1 : 0;
        flag_stats->fwd_ece_count += ((tcp_flags & TCP_ECE) == TCP_ECE) ? 1 : 0;
    }
}

void calculate_flow_features(const struct flow_stats *stats, struct flow_features *features) {
    if (!stats || !features) return;
    
    memset(features, 0, sizeof(struct flow_features));
    
    // 基本数据
    features->duration = time_diff(&stats->end_time, &stats->start_time);
    features->fwd_packets = stats->fwd_packets;
    features->bwd_packets = stats->bwd_packets;
    features->fwd_bytes = stats->fwd_bytes;
    features->bwd_bytes = stats->bwd_bytes;
    
    // 包大小特征
    features->fwd_max_size = stats->fwd_max_size;
    features->fwd_min_size = stats->fwd_min_size == UINT32_MAX ? 0 : stats->fwd_min_size;
    
    if (stats->fwd_packets > 0) {
        features->fwd_avg_size = (double)stats->fwd_bytes / stats->fwd_packets;
        features->fwd_std_size = sqrt(stats->fwd_sum_squares / stats->fwd_packets - 
                            pow(features->fwd_avg_size, 2));
    }
    
    features->bwd_max_size = stats->bwd_max_size;
    features->bwd_min_size = stats->bwd_min_size == UINT32_MAX ? 0 : stats->bwd_min_size;
    
    if (stats->bwd_packets > 0) {
        features->bwd_avg_size = (double)stats->bwd_bytes / stats->bwd_packets;
        features->bwd_std_size = sqrt(stats->bwd_sum_squares / stats->bwd_packets - 
                            pow(features->bwd_avg_size, 2));
    }
    
    uint64_t total_packets = stats->fwd_packets + stats->bwd_packets;
    uint64_t total_bytes = stats->fwd_bytes + stats->bwd_bytes;
    
    if (total_packets > 0) {
        features->avg_packet_size = (double)total_bytes / total_packets;
    }
    
    // 流量率特征
    if (features->duration > 0) {
        features->byte_rate = total_bytes / features->duration;
        features->packet_rate = total_packets / features->duration;
        features->fwd_packet_rate = stats->fwd_packets / features->duration;
        features->bwd_packet_rate = stats->bwd_packets / features->duration;
    }
    
    if (stats->fwd_bytes > 0 && stats->bwd_bytes > 0) {
        features->download_upload_ratio = (double)stats->bwd_bytes / stats->fwd_bytes;
    }
    
    // 包间隔时间特征 - 正向
    calculate_timestamp_stats(&stats->fwd_timestamps, 
                             &features->fwd_iat_total, 
                             &features->fwd_iat_mean, 
                             &features->fwd_iat_std, 
                             &features->fwd_iat_max,
                             &features->fwd_iat_min);
    
    // 包间隔时间特征 - 反向
    calculate_timestamp_stats(&stats->bwd_timestamps, 
                             &features->bwd_iat_total, 
                             &features->bwd_iat_mean, 
                             &features->bwd_iat_std, 
                             &features->bwd_iat_max,
                             &features->bwd_iat_min);
    
    // 流间隔时间特征 - 这需要合并两个方向的时间戳
    if (features->fwd_iat_min > 0 && features->bwd_iat_min > 0) {
        // 使用两者中的较小值作为最小数据包间隔时间
        features->min_packet_iat = features->fwd_iat_min < features->bwd_iat_min ?
                                  features->fwd_iat_min : features->bwd_iat_min;
    } else if (features->fwd_iat_min > 0) {
        features->min_packet_iat = features->fwd_iat_min;
    } else if (features->bwd_iat_min > 0) {
        features->min_packet_iat = features->bwd_iat_min;
    }
    
    // 合并估计流的整体IAT统计
    if (features->fwd_iat_total > 0 || features->bwd_iat_total > 0) {
        features->flow_iat_total = features->fwd_iat_total + features->bwd_iat_total;
        if (stats->fwd_packets + stats->bwd_packets > 2) {
            features->flow_iat_mean = features->flow_iat_total / 
                                    ((stats->fwd_packets - 1) + (stats->bwd_packets - 1));
        }
        // 流的最大和最小间隔时间
        features->flow_iat_max = features->fwd_iat_max > features->bwd_iat_max ?
                                features->fwd_iat_max : features->bwd_iat_max;
        if (features->fwd_iat_min > 0 && features->bwd_iat_min > 0) {
            features->flow_iat_min = features->fwd_iat_min < features->bwd_iat_min ?
                                    features->fwd_iat_min : features->bwd_iat_min;
        } else if (features->fwd_iat_min > 0) {
            features->flow_iat_min = features->fwd_iat_min;
        } else if (features->bwd_iat_min > 0) {
            features->flow_iat_min = features->bwd_iat_min;
        }
    }
    
    // 流长度特征
    features->flow_min_length = stats->flow_min_length == UINT32_MAX ? 0 : stats->flow_min_length;
    features->flow_max_length = stats->flow_max_length;
    
    if (total_packets > 0) {
        features->flow_mean_length = stats->flow_length_sum / total_packets;
        features->flow_std_length = sqrt(stats->flow_length_sum_squares / total_packets - 
                                       pow(features->flow_mean_length, 2));
    }
    
    // TCP标志特征 - 复制到嵌套结构
    features->tcp_flags.fwd_fin_count = stats->tcp_flags.fwd_fin_count;
    features->tcp_flags.fwd_syn_count = stats->tcp_flags.fwd_syn_count;
    features->tcp_flags.fwd_rst_count = stats->tcp_flags.fwd_rst_count;
    features->tcp_flags.fwd_psh_count = stats->tcp_flags.fwd_psh_count;
    features->tcp_flags.fwd_ack_count = stats->tcp_flags.fwd_ack_count;
    features->tcp_flags.fwd_urg_count = stats->tcp_flags.fwd_urg_count;
    features->tcp_flags.fwd_cwr_count = stats->tcp_flags.fwd_cwr_count;
    features->tcp_flags.fwd_ece_count = stats->tcp_flags.fwd_ece_count;
    
    features->tcp_flags.bwd_fin_count = stats->tcp_flags.bwd_fin_count;
    features->tcp_flags.bwd_syn_count = stats->tcp_flags.bwd_syn_count;
    features->tcp_flags.bwd_rst_count = stats->tcp_flags.bwd_rst_count;
    features->tcp_flags.bwd_psh_count = stats->tcp_flags.bwd_psh_count;
    features->tcp_flags.bwd_ack_count = stats->tcp_flags.bwd_ack_count;
    features->tcp_flags.bwd_urg_count = stats->tcp_flags.bwd_urg_count;
    features->tcp_flags.bwd_cwr_count = stats->tcp_flags.bwd_cwr_count;
    features->tcp_flags.bwd_ece_count = stats->tcp_flags.bwd_ece_count;
    
    // TCP相关特征
    features->fwd_header_bytes = stats->fwd_header_bytes;
    features->bwd_header_bytes = stats->bwd_header_bytes;
    
    if (stats->fwd_packets > 0) {
        features->fwd_segment_avg_size = (double)stats->fwd_bytes / stats->fwd_packets;
    }
    
    if (stats->bwd_packets > 0) {
        features->bwd_segment_avg_size = (double)stats->bwd_bytes / stats->bwd_packets;
    }
    
    // 子流统计
    if (stats->subflow_fwd_packets > 0) {
        features->fwd_subflow_avg_pkts = (double)stats->subflow_fwd_packets / 
                                      (stats->fwd_packets > 0 ? 1 : 0);
        features->fwd_subflow_avg_bytes = (double)stats->subflow_fwd_bytes / 
                                       (stats->fwd_packets > 0 ? 1 : 0);
    }
    
    if (stats->subflow_bwd_packets > 0) {
        features->bwd_subflow_avg_pkts = (double)stats->subflow_bwd_packets / 
                                      (stats->bwd_packets > 0 ? 1 : 0);
        features->bwd_subflow_avg_bytes = (double)stats->subflow_bwd_bytes / 
                                       (stats->bwd_packets > 0 ? 1 : 0);
    }
    
    // 初始窗口大小
    features->fwd_init_win_bytes = stats->fwd_init_win_bytes;
    features->bwd_init_win_bytes = stats->bwd_init_win_bytes;
    features->fwd_tcp_payload_bytes = stats->fwd_tcp_payload_bytes;
    features->fwd_min_segment = stats->fwd_min_segment;
}

// 改进的哈希函数，减少冲突
uint32_t hash_flow_key(const struct flow_key *key) {
    if (!key) return 0;
    
    // 使用FNV-1a哈希算法，它具有很好的分布性能
    uint32_t hash = 2166136261u; // FNV偏移基数
    
    // 哈希源IP
    hash ^= (key->src_ip & 0xFF);
    hash *= 16777619; // FNV素数
    hash ^= ((key->src_ip >> 8) & 0xFF);
    hash *= 16777619;
    hash ^= ((key->src_ip >> 16) & 0xFF);
    hash *= 16777619;
    hash ^= ((key->src_ip >> 24) & 0xFF);
    hash *= 16777619;
    
    // 哈希目的IP
    hash ^= (key->dst_ip & 0xFF);
    hash *= 16777619;
    hash ^= ((key->dst_ip >> 8) & 0xFF);
    hash *= 16777619;
    hash ^= ((key->dst_ip >> 16) & 0xFF);
    hash *= 16777619;
    hash ^= ((key->dst_ip >> 24) & 0xFF);
    hash *= 16777619;
    
#if !IGNORE_PORTS
    // 哈希源端口
    hash ^= (key->src_port & 0xFF);
    hash *= 16777619;
    hash ^= ((key->src_port >> 8) & 0xFF);
    hash *= 16777619;
    
    // 哈希目的端口
    hash ^= (key->dst_port & 0xFF);
    hash *= 16777619;
    hash ^= ((key->dst_port >> 8) & 0xFF);
    hash *= 16777619;
#endif
    
    // 哈希协议
    hash ^= key->protocol;
    hash *= 16777619;
    
    return hash % HASH_TABLE_SIZE;
}

// 检查TCP流是否应该分段成新流
static int should_segment_tcp_flow(struct flow_stats *stats, uint8_t new_flags) {
    // 如果禁用了所有分段功能，直接返回0
#if !TCP_SEGMENT_ON_IDLE && !TCP_SEGMENT_ON_FLAGS
    return 0;
#else
    // 检查基于空闲时间的分段
#if TCP_SEGMENT_ON_IDLE
    uint64_t now = get_current_time();
    // 检查空闲超时
    if (now - stats->last_seen > TCP_IDLE_TIMEOUT_NS) {
        return 1; // 流空闲超时，应该创建新流
    }
#endif

    // 检查基于标志位的分段
#if TCP_SEGMENT_ON_FLAGS
    // 根据TCP标志变化判断是否需要创建新流
    struct tcp_flag_stats *flags = &stats->tcp_flags;
    int total_flags = flags->fwd_syn_count + flags->fwd_fin_count + 
                      flags->fwd_rst_count + flags->fwd_psh_count +
                      flags->bwd_syn_count + flags->bwd_fin_count +
                      flags->bwd_rst_count + flags->bwd_psh_count;
    
    // 检查是否超过标志位阈值
    if (total_flags > TCP_FLAGS_THRESH) {
        return 1; // 标志位变化过多，应该创建新流
    }
    
    // 检查关键标志位
    if (new_flags & TCP_SYN) {
        // 如果已经有其他SYN, 或流中已有数据包，可能是新连接
        if (flags->fwd_syn_count + flags->bwd_syn_count > 0 || 
            stats->fwd_packets + stats->bwd_packets > 2) {
            return 1;
        }
    }
    
    // FIN或RST通常标志着流的结束
    if ((new_flags & TCP_FIN) || (new_flags & TCP_RST)) {
        if (stats->fwd_packets + stats->bwd_packets > 2) {
            return 1;
        }
    }
#endif
    
    return 0; // 默认不分段
#endif
}

// 修改get_flow_stats函数，加入TCP流分段逻辑
struct flow_stats* get_flow_stats(const struct flow_key *key, int *is_reverse_ptr) {
    if (!key || !flow_table_initialized) return NULL;
    
    // 创建临时key用于查找
    struct flow_key search_key = *key;
    
    // 如果配置为忽略端口，将端口设置为0
#if IGNORE_PORTS
    search_key.src_port = 0;
    search_key.dst_port = 0;
#endif
    
    uint32_t idx = hash_flow_key(&search_key);
    struct flow_node *node = flow_table[idx];
    
    // 处理TCP流的特殊情况
    int is_tcp = (key->protocol == IPPROTO_TCP);
    uint8_t tcp_flags = 0;
    
    // 获取当前TCP标志，供分段逻辑使用
    if (is_tcp && is_reverse_ptr) {
        tcp_flags = *((uint8_t*)is_reverse_ptr); // 临时使用is_reverse_ptr传递标志位
        *is_reverse_ptr = 0;                    // 重置标志
    }
    
    // 查找流
    while (node) {
#if IGNORE_PORTS
        // 如果忽略端口，只比较IP和协议
        if (node->key.src_ip == search_key.src_ip &&
            node->key.dst_ip == search_key.dst_ip &&
            node->key.protocol == search_key.protocol) {
#else
        // 完整比较
        if (memcmp(&node->key, &search_key, sizeof(struct flow_key)) == 0) {
#endif
            // 检查TCP流是否应该分段
#if TCP_SEGMENT_ON_IDLE || TCP_SEGMENT_ON_FLAGS
            if (is_tcp && should_segment_tcp_flow(&node->stats, tcp_flags)) {
                // 跳过现有流，创建新流
                break;
            }
#endif
            
            if (is_reverse_ptr) *is_reverse_ptr = 0;
            return &node->stats;
        }
        node = node->next;
    }
    
    // 创建新流
    struct flow_node *new_node = flow_table_insert(&search_key);
    if (!new_node) return NULL;
    
    new_node->next = flow_table[idx];
    flow_table[idx] = new_node;
    
    if (is_reverse_ptr) *is_reverse_ptr = 0;
    return &new_node->stats;
}

// 流统计函数 - 只统计当前活跃（未超时）的流
int count_active_flows() {
    int count = 0;
    uint64_t now = get_current_time();
    
    // 直接统计流表中的活跃节点
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            // 检查流是否超时
            uint64_t timeout = FLOW_TIMEOUT_NS;
            if (node->key.protocol == IPPROTO_TCP) {
                timeout = TCP_FLOW_TIMEOUT_NS;
            }
            
            // 只统计未超时的流
            if (now - node->stats.last_seen <= timeout) {
                // 每个活跃流节点计数
                count++;
            }
            
            node = node->next;
        }
    }
    
    return count;
}

// 简单统计信息输出函数 - 仅显示活跃流的包数量
void print_simple_stats() {
    static uint64_t last_total_packets = 0;
    static uint64_t last_total_bytes = 0;
    int flow_count = count_active_flows();
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    
    uint64_t now = get_current_time();
    
    // 计算活跃流的总数据包和字节数
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            // 检查流是否超时
            uint64_t timeout = FLOW_TIMEOUT_NS;
            if (node->key.protocol == IPPROTO_TCP) {
                timeout = TCP_FLOW_TIMEOUT_NS;
            }
            
            // 只统计未超时的流
            if (now - node->stats.last_seen <= timeout) {
                total_packets += node->stats.fwd_packets + node->stats.bwd_packets;
                total_bytes += node->stats.fwd_bytes + node->stats.bwd_bytes;
            }
            
            node = node->next;
        }
    }
    
    // 计算自上次统计以来的增量
    uint64_t packet_diff = total_packets - last_total_packets;
    uint64_t bytes_diff = total_bytes - last_total_bytes;
    
    // 更新上次统计值
    last_total_packets = total_packets;
    last_total_bytes = total_bytes;
    
    // 控制台输出
    if (in_place_updates) {
        // 使用ANSI序列清理行并显示简单统计
        printf("%s[STATS] Active Flows: %d | Total Packets: %lu (+%lu) | Total Traffic: %.2f MB (+%.2f KB)",
               ANSI_CLEAR_LINE,
               flow_count,
               (unsigned long)total_packets,
               (unsigned long)packet_diff,
               total_bytes / (1024.0 * 1024.0),
               bytes_diff / 1024.0);
        
        // 将光标返回到行首，不换行
        fflush(stdout);
    } else {
        // 标准输出模式
        printf("[STATS] Active Flows: %d | Total Packets: %lu (+%lu) | Total Traffic: %.2f MB (+%.2f KB)\n",
               flow_count,
               (unsigned long)total_packets, 
               (unsigned long)packet_diff,
               total_bytes / (1024.0 * 1024.0),
               bytes_diff / 1024.0);
    }
}

// 定期输出流统计（示例）
void print_flow_stats() {
    // 安静模式下不输出任何信息
    if (quiet_mode) {
        return;
    }
    
    // 否则显示简单统计，详细统计由print_final_stats在程序退出时调用
    print_simple_stats();
}

void cleanup_flows() {
#if ENABLE_FLOW_CLEANUP
    if (!flow_table_initialized) return;
    
    uint64_t now = get_current_time();
    int flows_cleaned = 0;
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node **ptr = &flow_table[i];
        while (*ptr) {
            struct flow_node *curr = *ptr;
            
            // 对TCP流应用特殊的超时
            uint64_t timeout = FLOW_TIMEOUT_NS;
            if (curr->key.protocol == IPPROTO_TCP) {
                timeout = TCP_FLOW_TIMEOUT_NS;
            }
            
            // 清理超时流
            if (now - curr->stats.last_seen > timeout) {
                *ptr = curr->next;
                flow_table_remove(curr);  // 使用内存池释放
                flows_cleaned++;
            } else {
                ptr = &curr->next;
            }
        }
    }
    
    if (flows_cleaned > 0) {
        printf("Cleaned up %d expired flows\n", flows_cleaned);
    }
#endif
}

// 更新流量统计
void update_flow_stats(struct flow_stats *stats, uint32_t pkt_size, int is_reverse) {
    if (!stats) return;
    
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    
    // 更新时间戳
    stats->end_time = now;
    uint64_t current_time = get_current_time();
    stats->last_seen = current_time;
    
    // 更新流长度统计
    if (pkt_size < stats->flow_min_length) stats->flow_min_length = pkt_size;
    if (pkt_size > stats->flow_max_length) stats->flow_max_length = pkt_size;
    stats->flow_length_sum += pkt_size;
    stats->flow_length_sum_squares += (double)pkt_size * pkt_size;
    
    // 计算IP头部大小，假设为标准大小20字节
    uint32_t ip_header_size = 20;   // 标准IP头部
    uint32_t transport_header_size = 0;
    
    // 假设TCP头部20字节，UDP头部8字节
    if (stats->fwd_packets + stats->bwd_packets == 0) {
        // 第一个包
        if (is_reverse) {
            stats->bwd_init_win_bytes = pkt_size;
        } else {
            stats->fwd_init_win_bytes = pkt_size;
        }
    }
    
    // 更新方向统计
    if (is_reverse) {
        stats->bwd_packets++;
        stats->bwd_bytes += pkt_size;
        stats->bwd_sum_squares += (double)pkt_size * pkt_size;
        if (pkt_size > stats->bwd_max_size) stats->bwd_max_size = pkt_size;
        if (pkt_size < stats->bwd_min_size) stats->bwd_min_size = pkt_size;
        
        // 更新头部字节统计
        if (stats->fwd_packets > 0) {  // 如果已经有前向包
            transport_header_size = 8;  // 假设UDP，TCP会在流处理中根据协议更新
            stats->bwd_header_bytes += (ip_header_size + transport_header_size);
        }
        
        // 更新子流统计
        stats->subflow_bwd_packets++;
        stats->subflow_bwd_bytes += pkt_size;
        
        // 添加时间戳用于计算包间隔
        timestamp_array_add(&stats->bwd_timestamps, current_time);
    } else {
        stats->fwd_packets++;
        stats->fwd_bytes += pkt_size;
        stats->fwd_sum_squares += (double)pkt_size * pkt_size;
        if (pkt_size > stats->fwd_max_size) stats->fwd_max_size = pkt_size;
        if (pkt_size < stats->fwd_min_size) stats->fwd_min_size = pkt_size;
        
        // 更新TCP特定统计
        if (stats->fwd_min_segment == 0 || pkt_size < stats->fwd_min_segment) {
            stats->fwd_min_segment = pkt_size;
        }
        
        // 更新有效TCP载荷统计（简化：假设所有包都有TCP载荷）
        stats->fwd_tcp_payload_bytes += pkt_size;
        
        // 更新头部字节统计
        transport_header_size = 20;  // 假设TCP
        stats->fwd_header_bytes += (ip_header_size + transport_header_size);
        
        // 更新子流统计
        stats->subflow_fwd_packets++;
        stats->subflow_fwd_bytes += pkt_size;
        
        // 添加时间戳用于计算包间隔
        timestamp_array_add(&stats->fwd_timestamps, current_time);
    }
}

// 处理TCP协议的专用函数 - 改进标志位提取
void handle_tcp(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
    const struct tcphdr *tcp = (const struct tcphdr*)transport_hdr;
    key->src_port = ntohs(tcp->source);
    key->dst_port = ntohs(tcp->dest);
    
    // 更可靠的标志位提取方法（适应不同系统）
    uint8_t *tcp_bytes = (uint8_t*)tcp;
    
    // 尝试多种常见的标志位偏移
    *flags = 0;
    
    // 主要的TCP标志字节通常在偏移13处（第14个字节）
    if (tcp_bytes[13] != 0) {
        *flags = tcp_bytes[13];
    } 
    // 备选位置检查
    else if (tcp_bytes[12] != 0) {
        *flags = tcp_bytes[12];
    }
    // 使用位偏移检查，更通用的方法
    else {
        // 假设标准TCP头中的标志位位置
        int offset = (tcp->doff * 4) - 8; // 标志位距离TCP头尾部通常为8字节
        if (offset >= 0 && offset < 20) { // 安全检查
            *flags = tcp_bytes[offset];
        }
    }
    
#ifdef DEBUG
    printf("TCP: %d->%d flags:%02x\n", key->src_port, key->dst_port, *flags);
#endif
}

// 处理UDP协议的专用函数
void handle_udp(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
    const struct udphdr *udp = (const struct udphdr*)transport_hdr;
    key->src_port = ntohs(udp->source);
    key->dst_port = ntohs(udp->dest);
    *flags = 0; // UDP没有标志位
}

// 处理未知协议的默认函数
void handle_unknown(const void *transport_hdr, struct flow_key *key, uint8_t *flags) {
    // 对于未知协议，设置默认值
    key->src_port = 0;
    key->dst_port = 0;
    *flags = 0;
}

// 新添加的函数实现，用于处理Bulk特征、子流和活跃空闲状态计算

/**
 * 更新流统计中的Bulk分析相关数据
 * @param stats 流统计指针
 * @param payload_size 有效载荷大小
 * @param is_reverse 是否为反向流量
 * @param timestamp 数据包时间戳
 */
void update_flow_bulk(struct flow_stats *stats, uint32_t payload_size, int is_reverse, uint64_t timestamp) {
    if (!stats || payload_size == 0) {
        return;
    }

    if (!is_reverse) {  // 前向流量
        if (stats->backward_bulk_last_timestamp > stats->forward_bulk_start_tmp) {
            stats->forward_bulk_start_tmp = 0;
        }
        
        if (stats->forward_bulk_start_tmp == 0) {
            stats->forward_bulk_start_tmp = timestamp;
            stats->forward_bulk_last_timestamp = timestamp;
            stats->forward_bulk_count_tmp = 1;
            stats->forward_bulk_size_tmp = payload_size;
        } else {
            // 检查是否超时（将nanoseconds转换为秒比较）
            if ((timestamp - stats->forward_bulk_last_timestamp) / 1000000000.0 > CLUMP_TIMEOUT) {
                stats->forward_bulk_start_tmp = timestamp;
                stats->forward_bulk_last_timestamp = timestamp;
                stats->forward_bulk_count_tmp = 1;
                stats->forward_bulk_size_tmp = payload_size;
            } else {  // 添加到现有Bulk
                stats->forward_bulk_count_tmp += 1;
                stats->forward_bulk_size_tmp += payload_size;
                
                // 检查是否达到Bulk边界
                if (stats->forward_bulk_count_tmp == BULK_BOUND) {
                    stats->forward_bulk_count += 1;
                    stats->forward_bulk_packet_count += stats->forward_bulk_count_tmp;
                    stats->forward_bulk_size += stats->forward_bulk_size_tmp;
                    stats->forward_bulk_duration += (timestamp - stats->forward_bulk_start_tmp);
                } else if (stats->forward_bulk_count_tmp > BULK_BOUND) {
                    stats->forward_bulk_packet_count += 1;
                    stats->forward_bulk_size += payload_size;
                    stats->forward_bulk_duration += (timestamp - stats->forward_bulk_last_timestamp);
                }
                
                stats->forward_bulk_last_timestamp = timestamp;
            }
        }
    } else {  // 反向流量
        if (stats->forward_bulk_last_timestamp > stats->backward_bulk_start_tmp) {
            stats->backward_bulk_start_tmp = 0;
        }
        
        if (stats->backward_bulk_start_tmp == 0) {
            stats->backward_bulk_start_tmp = timestamp;
            stats->backward_bulk_last_timestamp = timestamp;
            stats->backward_bulk_count_tmp = 1;
            stats->backward_bulk_size_tmp = payload_size;
        } else {
            // 检查是否超时（将nanoseconds转换为秒比较）
            if ((timestamp - stats->backward_bulk_last_timestamp) / 1000000000.0 > CLUMP_TIMEOUT) {
                stats->backward_bulk_start_tmp = timestamp;
                stats->backward_bulk_last_timestamp = timestamp;
                stats->backward_bulk_count_tmp = 1;
                stats->backward_bulk_size_tmp = payload_size;
            } else {  // 添加到现有Bulk
                stats->backward_bulk_count_tmp += 1;
                stats->backward_bulk_size_tmp += payload_size;
                
                // 检查是否达到Bulk边界
                if (stats->backward_bulk_count_tmp == BULK_BOUND) {
                    stats->backward_bulk_count += 1;
                    stats->backward_bulk_packet_count += stats->backward_bulk_count_tmp;
                    stats->backward_bulk_size += stats->backward_bulk_size_tmp;
                    stats->backward_bulk_duration += (timestamp - stats->backward_bulk_start_tmp);
                } else if (stats->backward_bulk_count_tmp > BULK_BOUND) {
                    stats->backward_bulk_packet_count += 1;
                    stats->backward_bulk_size += payload_size;
                    stats->backward_bulk_duration += (timestamp - stats->backward_bulk_last_timestamp);
                }
                
                stats->backward_bulk_last_timestamp = timestamp;
            }
        }
    }
}

/**
 * 更新子流统计信息
 * @param stats 流统计指针
 * @param current_time 当前时间戳
 */
void update_subflow(struct flow_stats *stats, uint64_t current_time) {
    if (!stats) {
        return;
    }
    
    uint64_t last_timestamp = (stats->last_seen != 0) ? stats->last_seen : current_time;
    
    // 如果两个包之间的时间差超过分组超时，则更新活跃/空闲状态
    if ((current_time - last_timestamp) / 1000000000.0 > CLUMP_TIMEOUT) {
        update_active_idle(stats, current_time);
    }
}

/**
 * 更新活跃和空闲状态统计
 * @param stats 流统计指针
 * @param current_time 当前时间（纳秒）
 */
void update_active_idle(struct flow_stats *stats, uint64_t current_time) {
    if (!stats) {
        return;
    }
    
    // 计算时间差（秒）
    double time_diff = (current_time - stats->last_seen) / 1000000000.0;
    
    // 如果流空闲时间超过活跃超时，将当前活跃周期添加到活跃数组，并开始新的活跃周期
    if (time_diff > ACTIVE_TIMEOUT) {
        double duration = fabs((double)(stats->last_seen - stats->start_time.tv_sec) - 
                                stats->start_time.tv_nsec / 1000000000.0);
        
        // 分配活跃状态数组（如果需要）
        if (!stats->active) {
            stats->active = malloc(TIMESTAMP_INITIAL_SIZE * sizeof(uint64_t));
            if (stats->active) {
                stats->active_count = 0;
            } else {
                fprintf(stderr, "Failed to allocate memory for active array\n");
                return;
            }
        }
        
        // 分配空闲状态数组（如果需要）
        if (!stats->idle) {
            stats->idle = malloc(TIMESTAMP_INITIAL_SIZE * sizeof(uint64_t));
            if (stats->idle) {
                stats->idle_count = 0;
            } else {
                fprintf(stderr, "Failed to allocate memory for idle array\n");
                return;
            }
        }
        
        // 如果有有效的活跃持续时间，添加到活跃数组
        if (duration > 0 && stats->active && stats->active_count < TIMESTAMP_INITIAL_SIZE) {
            stats->active[stats->active_count++] = (uint64_t)(duration * 1000000); // 转换为微秒
        }
        
        // 添加空闲时间到空闲数组
        if (stats->idle && stats->idle_count < TIMESTAMP_INITIAL_SIZE) {
            stats->idle[stats->idle_count++] = (uint64_t)(time_diff * 1000000); // 转换为微秒
        }
    }
}

// 更新处理数据包的函数，加入对新增功能的处理
void process_packet(const struct iphdr *ip, const void *transport_hdr) {
    if (!ip || !transport_hdr) return;
    
    struct flow_key key = {0};
    uint8_t flags = 0;
    uint64_t current_time_ns = get_current_time();
    
    // 调用协议处理函数填充key和flags
    protocol_handlers[ip->protocol](transport_hdr, &key, &flags);
    
    // 补全key中的IP信息
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;
    
    // 如果配置为忽略端口，清空端口信息
    if (IGNORE_PORTS) {
        key.src_port = 0;
        key.dst_port = 0;
    }
    
    int is_reverse = 0;
    struct flow_stats *stats = get_flow_stats(&key, &is_reverse);
    
    if (!stats) {
        fprintf(stderr, "Failed to get flow stats\n");
        return;
    }
    
    // 计算数据包大小和头部大小
    uint32_t total_size = ntohs(ip->tot_len);
    uint32_t header_size = ip->ihl * 4;
    uint32_t transport_header_size = 0;
    uint32_t payload_size = 0;
    
    if (key.protocol == IPPROTO_TCP) {
        const struct tcphdr *tcp = (const struct tcphdr *)transport_hdr;
        transport_header_size = tcp->doff * 4;
        payload_size = total_size - header_size - transport_header_size;
        
        // 更新TCP标志
        update_tcp_flags(stats, flags, is_reverse);
    } else if (key.protocol == IPPROTO_UDP) {
        transport_header_size = 8; // UDP header is always 8 bytes
        payload_size = total_size - header_size - transport_header_size;
        
        // 更新UDP统计
        update_udp_stats(stats, total_size, is_reverse);
    }
    
    // 更新流统计
    update_flow_stats(stats, total_size, is_reverse);
    
    // 更新子流统计
    update_subflow(stats, current_time_ns);
    
    // 更新Bulk分析
    if (payload_size > 0) {
        update_flow_bulk(stats, payload_size, is_reverse, current_time_ns);
    }
    
    // 更新最后访问时间
    stats->last_seen = current_time_ns;
}

// 程序退出时清理
void flow_table_destroy() {
    printf("Destroying flow table...\n");
    
    if (!flow_table_initialized) {
        return;
    }
    
    // Set the flag to prevent double cleanup and future use
    flow_table_initialized = 0;
    
    // Free all flow nodes
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            struct flow_node *next = node->next;
            flow_table_remove(node);
            node = next;
        }
        flow_table[i] = NULL;
    }
    
    // Clean up memory pool
    mempool_destroy(&global_pool);
    
    printf("Flow table destroyed\n");
}

// 流方向统计函数 - 只统计当前活跃（未超时）的流
void count_flow_directions(int *forward_flows, int *reverse_flows) {
    if (!forward_flows || !reverse_flows) return;
    
    *forward_flows = 0;
    *reverse_flows = 0;
    
    uint64_t now = get_current_time();
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            // 检查流是否超时
            uint64_t timeout = FLOW_TIMEOUT_NS;
            if (node->key.protocol == IPPROTO_TCP) {
                timeout = TCP_FLOW_TIMEOUT_NS;
            }
            
            // 只统计未超时的流
            if (now - node->stats.last_seen <= timeout) {
                // 通过比较源目IP判断流方向
                // 当忽略端口时，只使用IP比较
#if IGNORE_PORTS
                if (node->key.src_ip < node->key.dst_ip) {
                    (*forward_flows)++;
                } else {
                    (*reverse_flows)++;
                }
#else
                // 通过比较源目IP和端口判断流方向
                if (node->key.src_ip < node->key.dst_ip || 
                   (node->key.src_ip == node->key.dst_ip && 
                    node->key.src_port < node->key.dst_port)) {
                    (*forward_flows)++;
                } else {
                    (*reverse_flows)++;
                }
#endif
            }
            
            node = node->next;
        }
    }
}

// 统计所有流，包括已超时的流
int count_all_flows() {
    int count = 0;
    
    // 直接统计流表中的所有节点
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            count++;
            node = node->next;
        }
    }
    
    return count;
}

// 统计所有流的方向，包括已超时的流
void count_all_flow_directions(int *forward_flows, int *reverse_flows) {
    if (!forward_flows || !reverse_flows) return;
    
    *forward_flows = 0;
    *reverse_flows = 0;
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            // 通过比较源目IP判断流方向
            // 当忽略端口时，只使用IP比较
#if IGNORE_PORTS
            if (node->key.src_ip < node->key.dst_ip) {
                (*forward_flows)++;
            } else {
                (*reverse_flows)++;
            }
#else
            // 通过比较源目IP和端口判断流方向
            if (node->key.src_ip < node->key.dst_ip || 
               (node->key.src_ip == node->key.dst_ip && 
                node->key.src_port < node->key.dst_port)) {
                (*forward_flows)++;
            } else {
                (*reverse_flows)++;
            }
#endif
            
            node = node->next;
        }
    }
}

/**
 * 更新UDP特定统计信息
 * @param stats 流统计指针
 * @param pkt_size 数据包大小
 * @param is_reverse 是否为反向流
 */
void update_udp_stats(struct flow_stats *stats, uint32_t pkt_size, int is_reverse) {
    if (!stats) return;
    
    if (is_reverse) {
        // 更新反向UDP统计
        stats->udp.bwd_packets++;
        stats->udp.bwd_bytes += pkt_size;
        stats->udp.bwd_sum_squares += (double)pkt_size * pkt_size;
        
        // 更新最大/最小包大小
        if (pkt_size > stats->udp.bwd_max_size) {
            stats->udp.bwd_max_size = pkt_size;
        }
        if (stats->udp.bwd_min_size == 0 || pkt_size < stats->udp.bwd_min_size) {
            stats->udp.bwd_min_size = pkt_size;
        }
        
        // 更新UDP头部字节统计
        stats->udp.bwd_header_bytes += 8; // UDP头部固定为8字节
    } else {
        // 更新正向UDP统计
        stats->udp.fwd_packets++;
        stats->udp.fwd_bytes += pkt_size;
        stats->udp.fwd_sum_squares += (double)pkt_size * pkt_size;
        
        // 更新最大/最小包大小
        if (pkt_size > stats->udp.fwd_max_size) {
            stats->udp.fwd_max_size = pkt_size;
        }
        if (stats->udp.fwd_min_size == 0 || pkt_size < stats->udp.fwd_min_size) {
            stats->udp.fwd_min_size = pkt_size;
        }
        
        // 更新UDP头部字节统计
        stats->udp.fwd_header_bytes += 8; // UDP头部固定为8字节
    }
}