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

// Initial timestamp array size
#define TIMESTAMP_INITIAL_SIZE 32

// Global variables
struct mempool global_pool;
struct flow_node* flow_table[HASH_TABLE_SIZE] = {0}; // Initialize hash table
static int flow_table_initialized = 0;

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
    printf("Flow table initialized\n");
}

struct flow_node *flow_table_insert(const struct flow_key *key) {
    if (!key || !flow_table_initialized) return NULL;
    
    struct flow_node *node = mempool_alloc(&global_pool);
    if (!node) return NULL;
    
    memcpy(&node->key, key, sizeof(*key));
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

// 更新TCP标志计数
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

// 计算活跃流的数量
static int count_active_flows() {
    int count = 0;
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            count++;
            node = node->next;
        }
    }
    return count;
}

// 定期输出流统计（示例）
void print_flow_stats() {
    time_t current_time = time(NULL);
    printf("\n============= Flow Statistics %s =============\n", ctime(&current_time));
    printf("Current Active Flows: %d\n", count_active_flows());
    
    int flow_count = 0;
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            flow_count++;
            struct flow_features features;
            calculate_flow_features(&node->stats, &features);
            
            // Print flow identifier and basic info
            printf("\n[Flow #%d] %u.%u.%u.%u:%d -> %u.%u.%u.%u:%d Protocol=%s\n",
                   flow_count,
                   NIPQUAD(node->key.src_ip), node->key.src_port,
                   NIPQUAD(node->key.dst_ip), node->key.dst_port,
                   node->key.protocol == IPPROTO_TCP ? "TCP" : 
                   (node->key.protocol == IPPROTO_UDP ? "UDP" : "Unknown"));
            
            // Print time information
            char start_time_str[64], end_time_str[64];
            struct tm *start_tm = localtime(&node->stats.start_time.tv_sec);
            struct tm *end_tm = localtime(&node->stats.end_time.tv_sec);
            strftime(start_time_str, sizeof(start_time_str), "%Y-%m-%d %H:%M:%S", start_tm);
            strftime(end_time_str, sizeof(end_time_str), "%Y-%m-%d %H:%M:%S", end_tm);
            
            printf("Start Time: %s.%09ld\n", start_time_str, node->stats.start_time.tv_nsec);
            printf("Last Time: %s.%09ld\n", end_time_str, node->stats.end_time.tv_nsec);
            printf("Duration: %.3f seconds\n", features.duration);
            
            // Active status
            uint64_t now = get_current_time();
            uint64_t idle_time = now - node->stats.last_seen;
            printf("Idle Time: %.3f seconds\n", idle_time / 1000000000.0);
            printf("Status: %s\n", idle_time > FLOW_TIMEOUT_NS ? "Expiring Soon" : "Active");
            
            // Print forward flow stats
            printf("\n[Forward Flow Stats (Source->Destination)]\n");
            printf("Packet Count: %lu\n", (unsigned long)node->stats.fwd_packets);
            printf("Total Bytes: %lu (%.2f KB)\n", 
                   (unsigned long)node->stats.fwd_bytes, 
                   node->stats.fwd_bytes / 1024.0);
            if (node->stats.fwd_packets > 0) {
                printf("Max Packet Size: %u bytes\n", node->stats.fwd_max_size);
                printf("Min Packet Size: %u bytes\n", 
                       node->stats.fwd_min_size == UINT32_MAX ? 0 : node->stats.fwd_min_size);
                printf("Avg Packet Size: %.2f bytes\n", features.fwd_avg_size);
                printf("Packet Size StdDev: %.2f\n", features.fwd_std_size);
                printf("Packets/sec: %.2f\n", features.fwd_packet_rate);
                printf("Header Bytes: %u\n", features.fwd_header_bytes);
                
                // 包间隔时间
                if (node->stats.fwd_packets > 1) {
                    printf("IAT Total: %.6f sec\n", features.fwd_iat_total);
                    printf("IAT Mean: %.6f sec\n", features.fwd_iat_mean);
                    printf("IAT StdDev: %.6f sec\n", features.fwd_iat_std);
                    printf("IAT Max: %.6f sec\n", features.fwd_iat_max);
                    printf("IAT Min: %.6f sec\n", features.fwd_iat_min);
                }
                
                // TCP特定信息
                if (node->key.protocol == IPPROTO_TCP) {
                    printf("TCP Segment Avg Size: %.2f bytes\n", features.fwd_segment_avg_size);
                    printf("Initial Window Bytes: %u\n", features.fwd_init_win_bytes);
                    printf("Min Segment Size: %u\n", features.fwd_min_segment);
                    printf("TCP Payload Bytes: %u\n", features.fwd_tcp_payload_bytes);
                    
                    // TCP标志计数
                    printf("\n[Forward TCP Flags]\n");
                    printf("FIN: %u  SYN: %u  RST: %u  PSH: %u\n", 
                           features.tcp_flags.fwd_fin_count, features.tcp_flags.fwd_syn_count, 
                           features.tcp_flags.fwd_rst_count, features.tcp_flags.fwd_psh_count);
                    printf("ACK: %u  URG: %u  CWR: %u  ECE: %u\n", 
                           features.tcp_flags.fwd_ack_count, features.tcp_flags.fwd_urg_count, 
                           features.tcp_flags.fwd_cwr_count, features.tcp_flags.fwd_ece_count);
                }
            }
            
            // Print backward flow stats
            printf("\n[Backward Flow Stats (Destination->Source)]\n");
            printf("Packet Count: %lu\n", (unsigned long)node->stats.bwd_packets);
            printf("Total Bytes: %lu (%.2f KB)\n", 
                   (unsigned long)node->stats.bwd_bytes, 
                   node->stats.bwd_bytes / 1024.0);
            if (node->stats.bwd_packets > 0) {
                printf("Max Packet Size: %u bytes\n", node->stats.bwd_max_size);
                printf("Min Packet Size: %u bytes\n", 
                       node->stats.bwd_min_size == UINT32_MAX ? 0 : node->stats.bwd_min_size);
                printf("Avg Packet Size: %.2f bytes\n", features.bwd_avg_size);
                printf("Packet Size StdDev: %.2f\n", features.bwd_std_size);
                printf("Packets/sec: %.2f\n", features.bwd_packet_rate);
                printf("Header Bytes: %u\n", features.bwd_header_bytes);
                
                // 包间隔时间
                if (node->stats.bwd_packets > 1) {
                    printf("IAT Total: %.6f sec\n", features.bwd_iat_total);
                    printf("IAT Mean: %.6f sec\n", features.bwd_iat_mean);
                    printf("IAT StdDev: %.6f sec\n", features.bwd_iat_std);
                    printf("IAT Max: %.6f sec\n", features.bwd_iat_max);
                    printf("IAT Min: %.6f sec\n", features.bwd_iat_min);
                }
                
                // TCP特定信息
                if (node->key.protocol == IPPROTO_TCP) {
                    printf("TCP Segment Avg Size: %.2f bytes\n", features.bwd_segment_avg_size);
                    printf("Initial Window Bytes: %u\n", features.bwd_init_win_bytes);
                    
                    // TCP标志计数
                    printf("\n[Backward TCP Flags]\n");
                    printf("FIN: %u  SYN: %u  RST: %u  PSH: %u\n", 
                           features.tcp_flags.bwd_fin_count, features.tcp_flags.bwd_syn_count, 
                           features.tcp_flags.bwd_rst_count, features.tcp_flags.bwd_psh_count);
                    printf("ACK: %u  URG: %u  CWR: %u  ECE: %u\n", 
                           features.tcp_flags.bwd_ack_count, features.tcp_flags.bwd_urg_count, 
                           features.tcp_flags.bwd_cwr_count, features.tcp_flags.bwd_ece_count);
                }
            }
            
            // Print overall flow stats
            printf("\n[Overall Flow Statistics]\n");
            printf("Total Packets: %lu\n", 
                   (unsigned long)(node->stats.fwd_packets + node->stats.bwd_packets));
            printf("Total Bytes: %lu (%.2f KB)\n", 
                   (unsigned long)(node->stats.fwd_bytes + node->stats.bwd_bytes),
                   (node->stats.fwd_bytes + node->stats.bwd_bytes) / 1024.0);
            printf("Byte Rate: %.2f KB/s\n", features.byte_rate / 1024.0);
            printf("Packet Rate: %.2f pps\n", features.packet_rate);
            printf("Download/Upload Ratio: %.2f\n", features.download_upload_ratio);
            
            // 流长度统计
            printf("Flow Min Length: %u bytes\n", features.flow_min_length);
            printf("Flow Max Length: %u bytes\n", features.flow_max_length);
            printf("Flow Mean Length: %.2f bytes\n", features.flow_mean_length);
            printf("Flow Length StdDev: %.2f\n", features.flow_std_length);
            
            // 整体流间隔时间
            if (features.flow_iat_total > 0) {
                printf("Flow IAT Total: %.6f sec\n", features.flow_iat_total);
                printf("Flow IAT Mean: %.6f sec\n", features.flow_iat_mean);
                printf("Flow IAT Max: %.6f sec\n", features.flow_iat_max);
                printf("Flow IAT Min: %.6f sec\n", features.flow_iat_min);
                printf("Min Packet IAT: %.6f sec\n", features.min_packet_iat);
            }
            
            printf("------------------------------------------------\n");
            node = node->next;
        }
    }
    
    if (flow_count == 0) {
        printf("No active flows currently\n");
    } else {
        printf("\nTotal: %d flows\n", flow_count);
    }
    printf("==================================================\n\n");
}

// 哈希函数（Jenkins one-at-a-time）
uint32_t hash_flow_key(const struct flow_key *key) {
    uint32_t hash = 0;
    hash = (hash + key->src_ip) * 0x1f3d5b79;
    hash = (hash + key->dst_ip) * 0x9e3779b9;
    hash = (hash + key->src_port) * 0x85ebca6b;
    hash = (hash + key->dst_port) * 0xc2b2ae35;
    hash = (hash + key->protocol) * 0x165667b1;
    return hash % HASH_TABLE_SIZE;
}

// 获取或创建会话记录
struct flow_stats* get_flow_stats(const struct flow_key *key, int is_reverse) {
    if (!key || !flow_table_initialized) return NULL;
    
    uint32_t idx = hash_flow_key(key);
    struct flow_node *node = flow_table[idx];
    
    // 查找现有会话
    while (node) {
        if (memcmp(&node->key, key, sizeof(struct flow_key)) == 0) {
            return &node->stats;
        }
        node = node->next;
    }
    
    // 创建新会话
    struct flow_node *new_node = flow_table_insert(key);
    if(!new_node) return NULL;
    
    new_node->next = flow_table[idx];
    flow_table[idx] = new_node;

    return &new_node->stats;
}

void cleanup_flows() {
    if (!flow_table_initialized) return;
    
    uint64_t now = get_current_time();
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node **ptr = &flow_table[i];
        while (*ptr) {
            struct flow_node *curr = *ptr;
            if (now - curr->stats.last_seen > FLOW_TIMEOUT_NS) {
                *ptr = curr->next;
                flow_table_remove(curr);  // 使用内存池释放
            } else {
                ptr = &curr->next;
            }
        }
    }
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

// 主处理函数
void process_packet(const struct iphdr *ip, const void *transport_hdr) {
    if (!ip || !transport_hdr || !flow_table_initialized) return;
    
    struct flow_key key;
    int is_reverse = 0;
    uint8_t tcp_flags = 0;
    
    // 生成会话Key
    key.src_ip = ip->saddr;
    key.dst_ip = ip->daddr;
    key.protocol = ip->protocol;
    
    // 处理传输层
    switch (ip->protocol) {
    case IPPROTO_TCP: {
        const struct tcphdr *tcp = (const struct tcphdr*)transport_hdr;
        key.src_port = ntohs(tcp->source);
        key.dst_port = ntohs(tcp->dest);
        
        // 获取TCP标志 - 使用通用的方式获取 TCP 标志位
        // 不同的系统有不同的 tcphdr 定义，所以我们直接使用位操作
        tcp_flags = *((uint8_t*)tcp + 13); // TCP标志位通常在TCP头部的第13个字节
        
        break;
    }
    case IPPROTO_UDP: {
        const struct udphdr *udp = (const struct udphdr*)transport_hdr;
        key.src_port = ntohs(udp->source);
        key.dst_port = ntohs(udp->dest);
        break;
    }
    default:
        return; // 不统计其他协议
    }
    
    // 判断流向（假设初始方向为src->dst）
    struct flow_key reverse_key = {
        .src_ip = key.dst_ip,
        .dst_ip = key.src_ip,
        .src_port = key.dst_port,
        .dst_port = key.src_port,
        .protocol = key.protocol
    };
    
    struct flow_stats *stats = get_flow_stats(&key, 0);
    if (!stats) {
        // 尝试反向查找
        stats = get_flow_stats(&reverse_key, 1);
        is_reverse = 1;
    }
    
    // 更新统计 (if stats is NULL, we just skip this)
    if (stats) {
        uint32_t pkt_size = ntohs(ip->tot_len);
        update_flow_stats(stats, pkt_size, is_reverse);
        
        // 如果是TCP，更新TCP标志计数
        if (key.protocol == IPPROTO_TCP) {
            update_tcp_flags(stats, tcp_flags, is_reverse);
        }
    }
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