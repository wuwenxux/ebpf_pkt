#include "flow_pb.h"
#include "flow.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <math.h>
#include <time.h>

// 引入自动生成的Protocol Buffer代码
#include "flow.pb-c.h"

// 全局发送器配置
static flow_sender_config_t thread_config;
static pthread_t sender_thread;
static int sender_running = 0;
static pthread_mutex_t sender_mutex = PTHREAD_MUTEX_INITIALIZER;

// 将IP地址整数转换为字符串
static void ip_to_str(uint32_t ip, char *buffer, size_t buffer_size) {
    struct in_addr addr;
    addr.s_addr = ip;
    snprintf(buffer, buffer_size, "%s", inet_ntoa(addr));
}

// 获取当前时间戳（毫秒）
static uint64_t get_timestamp_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

// 计算Inter-Arrival Time统计信息
static void calculate_iat_stats(const timestamp_array_t *arr, 
                               double *mean, double *std, 
                               double *max, double *min) {
    if (!arr || arr->count < 2 || !arr->times) {
        if (mean) *mean = 0;
        if (std) *std = 0;
        if (max) *max = 0;
        if (min) *min = 0;
        return;
    }
    
    double total = 0;
    *max = 0;
    *min = UINT64_MAX;
    
    // 计算相邻时间戳的间隔
    for (size_t i = 1; i < arr->count; i++) {
        uint64_t diff = arr->times[i] - arr->times[i-1];
        double diff_sec = diff / 1000000000.0; // 转换为秒
        
        total += diff_sec;
        
        if (diff_sec > *max) *max = diff_sec;
        if (diff_sec < *min) *min = diff_sec;
    }
    
    // 计算平均值
    *mean = total / (arr->count - 1);
    
    // 计算标准差
    double sum_squares = 0;
    for (size_t i = 1; i < arr->count; i++) {
        uint64_t diff = arr->times[i] - arr->times[i-1];
        double diff_sec = diff / 1000000000.0;
        sum_squares += pow(diff_sec - *mean, 2);
    }
    
    *std = sqrt(sum_squares / (arr->count - 1));
}

// 将流统计转换为Protocol Buffer消息
static Flow__FlowData* convert_flow_to_pb(struct flow_stats *stats, uint64_t current_time, bool is_active) {
    if (!stats) return NULL;
    
    // 分配Protocol Buffer结构
    Flow__FlowData *flow_data = (Flow__FlowData*)malloc(sizeof(Flow__FlowData));
    if (!flow_data) return NULL;
    
    flow__flow_data__init(flow_data);
    
    // 生成唯一流ID
    char flow_id[64];
    char src_ip_str[16], dst_ip_str[16];
    
    // 获取流的key信息（在flow_node中，所以需要计算偏移）
    // 通过计算flow_stats在flow_node中的偏移，反推flow_node地址，然后访问key
    struct flow_node *node = (struct flow_node *)((char *)stats - offsetof(struct flow_node, stats));
    
    ip_to_str(node->key.src_ip, src_ip_str, sizeof(src_ip_str));
    ip_to_str(node->key.dst_ip, dst_ip_str, sizeof(dst_ip_str));
    
    // 格式: src_ip:port-dst_ip:port-proto
    snprintf(flow_id, sizeof(flow_id), "%s:%d-%s:%d-%d", 
              src_ip_str, node->key.src_port,
              dst_ip_str, node->key.dst_port,
              node->key.protocol);
    
    // 设置基本流信息
    flow_data->flow_id = strdup(flow_id);
    flow_data->src_ip = strdup(src_ip_str);
    flow_data->dst_ip = strdup(dst_ip_str);
    flow_data->src_port = node->key.src_port;
    flow_data->dst_port = node->key.dst_port;
    flow_data->protocol = node->key.protocol;
    
    // 设置时间信息
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    flow_data->duration = time_diff(&now, &stats->start_time);
    
    // 将开始时间格式化为字符串
    char start_time_str[32];
    struct tm *timeinfo = localtime(&stats->start_time.tv_sec);
    strftime(start_time_str, sizeof(start_time_str), "%Y-%m-%d %H:%M:%S", timeinfo);
    flow_data->start_time = strdup(start_time_str);
    
    // 设置活跃状态
    flow_data->is_active = is_active;
    
    // 设置基本统计信息
    flow_data->fwd_packets = stats->fwd_packets;
    flow_data->fwd_bytes = stats->fwd_bytes;
    flow_data->bwd_packets = stats->bwd_packets;
    flow_data->bwd_bytes = stats->bwd_bytes;
    
    // 包大小信息
    flow_data->fwd_min_size = (stats->fwd_min_size == UINT32_MAX) ? 0 : stats->fwd_min_size;
    flow_data->fwd_max_size = stats->fwd_max_size;
    flow_data->bwd_min_size = (stats->bwd_min_size == UINT32_MAX) ? 0 : stats->bwd_min_size;
    flow_data->bwd_max_size = stats->bwd_max_size;
    
    // 计算平均和标准差
    if (stats->fwd_packets > 0) {
        flow_data->fwd_avg_size = (double)stats->fwd_bytes / stats->fwd_packets;
        flow_data->fwd_std_size = sqrt(stats->fwd_sum_squares / stats->fwd_packets - 
                                 pow(flow_data->fwd_avg_size, 2));
    }
    
    if (stats->bwd_packets > 0) {
        flow_data->bwd_avg_size = (double)stats->bwd_bytes / stats->bwd_packets;
        flow_data->bwd_std_size = sqrt(stats->bwd_sum_squares / stats->bwd_packets - 
                                 pow(flow_data->bwd_avg_size, 2));
    }
    
    // 计算流量率
    if (flow_data->duration > 0) {
        uint64_t total_bytes = stats->fwd_bytes + stats->bwd_bytes;
        uint64_t total_packets = stats->fwd_packets + stats->bwd_packets;
        
        flow_data->byte_rate = total_bytes / flow_data->duration;
        flow_data->packet_rate = total_packets / flow_data->duration;
        flow_data->fwd_packet_rate = stats->fwd_packets / flow_data->duration;
        flow_data->bwd_packet_rate = stats->bwd_packets / flow_data->duration;
    }
    
    // 计算IAT统计
    double mean, std, max, min;
    
    // 前向IAT
    calculate_iat_stats(&stats->fwd_timestamps, &mean, &std, &max, &min);
    flow_data->fwd_iat_mean = mean;
    flow_data->fwd_iat_std = std;
    flow_data->fwd_iat_max = max;
    flow_data->fwd_iat_min = min;
    
    // 后向IAT
    calculate_iat_stats(&stats->bwd_timestamps, &mean, &std, &max, &min);
    flow_data->bwd_iat_mean = mean;
    flow_data->bwd_iat_std = std;
    flow_data->bwd_iat_max = max;
    flow_data->bwd_iat_min = min;
    
    // Flow IAT (前后向合并计算)
    // TODO: 实现合并IAT计算
    flow_data->flow_iat_mean = 0;
    flow_data->flow_iat_std = 0;
    flow_data->flow_iat_max = 0;
    flow_data->flow_iat_min = 0;
    
    // TCP标志
    if (node->key.protocol == IPPROTO_TCP) {
        struct tcp_flag_stats *flag_stats = &stats->tcp_flags;
        flow_data->fin_count = flag_stats->fwd_fin_count + flag_stats->bwd_fin_count;
        flow_data->syn_count = flag_stats->fwd_syn_count + flag_stats->bwd_syn_count;
        flow_data->rst_count = flag_stats->fwd_rst_count + flag_stats->bwd_rst_count;
        flow_data->psh_count = flag_stats->fwd_psh_count + flag_stats->bwd_psh_count;
        flow_data->ack_count = flag_stats->fwd_ack_count + flag_stats->bwd_ack_count;
        flow_data->urg_count = flag_stats->fwd_urg_count + flag_stats->bwd_urg_count;
        flow_data->cwr_count = flag_stats->fwd_cwr_count + flag_stats->bwd_cwr_count;
        flow_data->ece_count = flag_stats->fwd_ece_count + flag_stats->bwd_ece_count;
    }
    
    // TCP窗口信息
    flow_data->fwd_init_win_bytes = stats->fwd_init_win_bytes;
    flow_data->bwd_init_win_bytes = stats->bwd_init_win_bytes;
    
    // Bulk分析
    flow_data->fwd_bulk_count = stats->forward_bulk_count;
    flow_data->fwd_bulk_bytes = stats->forward_bulk_size;
    flow_data->fwd_bulk_duration = stats->forward_bulk_duration / 1000000000; // 纳秒转秒
    flow_data->bwd_bulk_count = stats->backward_bulk_count;
    flow_data->bwd_bulk_bytes = stats->backward_bulk_size;
    flow_data->bwd_bulk_duration = stats->backward_bulk_duration / 1000000000; // 纳秒转秒
    
    // 活跃/空闲时间特征
    flow_data->active_count = stats->active_count;
    flow_data->idle_count = stats->idle_count;
    
    // 设置活跃时间统计
    if (stats->active_count > 0 && stats->active) {
        double active_total = 0, active_min = UINT64_MAX, active_max = 0, active_sum_sq = 0;
        
        for (size_t i = 0; i < stats->active_count; i++) {
            double val = stats->active[i] / 1000000.0; // 微秒转秒
            active_total += val;
            if (val < active_min) active_min = val;
            if (val > active_max) active_max = val;
        }
        
        double active_mean = active_total / stats->active_count;
        
        for (size_t i = 0; i < stats->active_count; i++) {
            double val = stats->active[i] / 1000000.0;
            active_sum_sq += pow(val - active_mean, 2);
        }
        
        flow_data->active_mean = active_mean;
        flow_data->active_std = sqrt(active_sum_sq / stats->active_count);
        flow_data->active_max = active_max;
        flow_data->active_min = active_min;
    }
    
    // 设置空闲时间统计
    if (stats->idle_count > 0 && stats->idle) {
        double idle_total = 0, idle_min = UINT64_MAX, idle_max = 0, idle_sum_sq = 0;
        
        for (size_t i = 0; i < stats->idle_count; i++) {
            double val = stats->idle[i] / 1000000.0; // 微秒转秒
            idle_total += val;
            if (val < idle_min) idle_min = val;
            if (val > idle_max) idle_max = val;
        }
        
        double idle_mean = idle_total / stats->idle_count;
        
        for (size_t i = 0; i < stats->idle_count; i++) {
            double val = stats->idle[i] / 1000000.0;
            idle_sum_sq += pow(val - idle_mean, 2);
        }
        
        flow_data->idle_mean = idle_mean;
        flow_data->idle_std = sqrt(idle_sum_sq / stats->idle_count);
        flow_data->idle_max = idle_max;
        flow_data->idle_min = idle_min;
    }
    
    return flow_data;
}

// 释放Protocol Buffer消息资源
static void free_flow_pb(Flow__FlowData *flow_data) {
    if (!flow_data) return;
    
    // 释放所有分配的字符串
    free(flow_data->flow_id);
    free(flow_data->src_ip);
    free(flow_data->dst_ip);
    free(flow_data->start_time);
    
    // 释放消息结构
    free(flow_data);
}

// 发送单个流数据
int send_flow(struct flow_stats *flow, const char *server_addr, int port) {
    if (!flow || !server_addr || port <= 0) return -1;
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, server_addr, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return -1;
    }
    
    // 创建流批次消息
    Flow__FlowBatch flow_batch = FLOW__FLOW_BATCH__INIT;
    
    // 获取当前时间
    uint64_t current_time = get_timestamp_ms();
    
    // 转换流为Protocol Buffer格式
    bool is_active = (current_time - flow->last_seen) < TCP_FLOW_TIMEOUT_NS;
    Flow__FlowData *pb_flow = convert_flow_to_pb(flow, current_time, is_active);
    if (!pb_flow) {
        close(sock);
        return -1;
    }
    
    // 设置批次数据
    flow_batch.flows = &pb_flow;
    flow_batch.n_flows = 1;
    flow_batch.timestamp = current_time;
    flow_batch.flow_count = 1;
    
    // 获取主机名作为发送者ID
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        flow_batch.sender_id = hostname;
    } else {
        flow_batch.sender_id = "unknown";
    }
    
    // 序列化消息
    size_t len = flow__flow_batch__get_packed_size(&flow_batch);
    uint8_t *buffer = (uint8_t*)malloc(len);
    if (!buffer) {
        free_flow_pb(pb_flow);
        close(sock);
        return -1;
    }
    
    flow__flow_batch__pack(&flow_batch, buffer);
    
    // 发送长度前缀
    uint32_t len_n = htonl(len);
    send(sock, &len_n, sizeof(len_n), 0);
    
    // 发送序列化数据
    ssize_t sent = send(sock, buffer, len, 0);
    
    // 释放资源
    free(buffer);
    free_flow_pb(pb_flow);
    close(sock);
    
    return (sent == len) ? 0 : -1;
}

// 发送多个流数据
int send_flow_batch(struct flow_stats **flows, int flow_count, const char *server_addr, int port) {
    if (!flows || flow_count <= 0 || !server_addr || port <= 0) return -1;
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, server_addr, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return -1;
    }
    
    // 创建流批次消息
    Flow__FlowBatch flow_batch = FLOW__FLOW_BATCH__INIT;
    
    // 获取当前时间
    uint64_t current_time = get_timestamp_ms();
    
    // 转换所有流为Protocol Buffer格式
    Flow__FlowData **pb_flows = (Flow__FlowData**)malloc(flow_count * sizeof(Flow__FlowData*));
    if (!pb_flows) {
        close(sock);
        return -1;
    }
    
    int actual_count = 0;
    for (int i = 0; i < flow_count; i++) {
        if (!flows[i]) continue;
        
        bool is_active = (current_time - flows[i]->last_seen) < TCP_FLOW_TIMEOUT_NS;
        Flow__FlowData *pb_flow = convert_flow_to_pb(flows[i], current_time, is_active);
        if (pb_flow) {
            pb_flows[actual_count++] = pb_flow;
        }
    }
    
    if (actual_count == 0) {
        free(pb_flows);
        close(sock);
        return 0; // 没有有效流，但不视为错误
    }
    
    // 设置批次数据
    flow_batch.flows = pb_flows;
    flow_batch.n_flows = actual_count;
    flow_batch.timestamp = current_time;
    flow_batch.flow_count = actual_count;
    
    // 获取主机名作为发送者ID
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        flow_batch.sender_id = hostname;
    } else {
        flow_batch.sender_id = "unknown";
    }
    
    // 序列化消息
    size_t len = flow__flow_batch__get_packed_size(&flow_batch);
    uint8_t *buffer = (uint8_t*)malloc(len);
    if (!buffer) {
        for (int i = 0; i < actual_count; i++) {
            free_flow_pb(pb_flows[i]);
        }
        free(pb_flows);
        close(sock);
        return -1;
    }
    
    flow__flow_batch__pack(&flow_batch, buffer);
    
    // 发送长度前缀
    uint32_t len_n = htonl(len);
    send(sock, &len_n, sizeof(len_n), 0);
    
    // 发送序列化数据
    ssize_t sent = send(sock, buffer, len, 0);
    
    // 释放资源
    free(buffer);
    for (int i = 0; i < actual_count; i++) {
        free_flow_pb(pb_flows[i]);
    }
    free(pb_flows);
    close(sock);
    
    return (sent == len) ? 0 : -1;
}

// 发送当前所有流数据
int send_flow_data(const char *server_addr, int port, bool include_inactive) {
    if (!server_addr || port <= 0) return -1;
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        return -1;
    }
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, server_addr, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        return -1;
    }
    
    // 创建流批次消息
    Flow__FlowBatch flow_batch = FLOW__FLOW_BATCH__INIT;
    
    // 获取当前时间
    uint64_t current_time = get_timestamp_ms();
    Flow__FlowData **pb_flows = NULL;
    int pb_flow_capacity = 0;
    int pb_flow_count = 0;
    
    // 初始分配空间 (预估)
    pb_flow_capacity = 1000;
    pb_flows = (Flow__FlowData**)malloc(pb_flow_capacity * sizeof(Flow__FlowData*));
    if (!pb_flows) {
        close(sock);
        return -1;
    }
    
    // 遍历流表，收集需要发送的流
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            // 检查流是否超时
            bool is_timeout = false;
            if (node->key.protocol == IPPROTO_TCP) {
                is_timeout = (current_time - node->stats.last_seen) > TCP_FLOW_TIMEOUT_NS;
            } else {
                is_timeout = (current_time - node->stats.last_seen) > FLOW_TIMEOUT_NS;
            }
            
            bool is_active = !is_timeout;
            
            // 如果不包括非活跃流，则跳过超时的流
            if (!include_inactive && !is_active) {
                node = node->next;
            continue;
            }
            
            // 检查是否需要扩展数组
            if (pb_flow_count >= pb_flow_capacity) {
                pb_flow_capacity *= 2;
                Flow__FlowData **new_flows = (Flow__FlowData**)realloc(pb_flows, 
                                                              pb_flow_capacity * sizeof(Flow__FlowData*));
                if (!new_flows) {
                    for (int j = 0; j < pb_flow_count; j++) {
                        free_flow_pb(pb_flows[j]);
                    }
                    free(pb_flows);
                    close(sock);
                    return -1;
                }
                pb_flows = new_flows;
            }
            
            // 转换流为Protocol Buffer格式
            Flow__FlowData *pb_flow = convert_flow_to_pb(&node->stats, current_time, is_active);
            if (pb_flow) {
                pb_flows[pb_flow_count++] = pb_flow;
            }
            
            node = node->next;
        }
    }
    
    if (pb_flow_count == 0) {
        free(pb_flows);
        close(sock);
        return 0; // 没有流，但不视为错误
    }
    
    // 设置批次数据
    flow_batch.flows = pb_flows;
    flow_batch.n_flows = pb_flow_count;
    flow_batch.timestamp = current_time;
    flow_batch.flow_count = pb_flow_count;
    
    // 获取主机名作为发送者ID
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        flow_batch.sender_id = hostname;
            } else {
        flow_batch.sender_id = "unknown";
    }
    
    // 序列化消息
    size_t len = flow__flow_batch__get_packed_size(&flow_batch);
    uint8_t *buffer = (uint8_t*)malloc(len);
    if (!buffer) {
        for (int i = 0; i < pb_flow_count; i++) {
            free_flow_pb(pb_flows[i]);
        }
        free(pb_flows);
        close(sock);
        return -1;
    }
    
    flow__flow_batch__pack(&flow_batch, buffer);
    
    // 发送长度前缀
    uint32_t len_n = htonl(len);
    send(sock, &len_n, sizeof(len_n), 0);
    
    // 发送序列化数据
    ssize_t sent = send(sock, buffer, len, 0);
    
    // 释放资源
    free(buffer);
    for (int i = 0; i < pb_flow_count; i++) {
        free_flow_pb(pb_flows[i]);
    }
    free(pb_flows);
    close(sock);
    
    return (sent == len) ? 0 : -1;
}

// CSV文件发送相关代码
// CSV字段分隔符
#define CSV_SEPARATOR ','

// 从CSV文件创建一个流数据结构
static Flow__FlowData* create_flow_from_csv(const char *csv_line) {
    if (!csv_line) return NULL;
    
    // 分配Protocol Buffer结构
    Flow__FlowData *flow_data = (Flow__FlowData*)malloc(sizeof(Flow__FlowData));
    if (!flow_data) return NULL;
    
    flow__flow_data__init(flow_data);
    
    // 复制一行进行解析（因为strtok会修改字符串）
    char *line_copy = strdup(csv_line);
    if (!line_copy) {
        free(flow_data);
        return NULL;
    }
    
    // 预处理 - 统计字段数
    int field_count = 1;  // 至少有一个字段
    for (const char *p = csv_line; *p; p++) {
        if (*p == CSV_SEPARATOR) field_count++;
    }
    
    // 分配字段数组
    char **fields = (char**)calloc(field_count, sizeof(char*));
    if (!fields) {
        free(flow_data);
        free(line_copy);
        return NULL;
    }
    
    // 拆分CSV行
    int idx = 0;
    char *token = strtok(line_copy, ",");
    while (token && idx < field_count) {
        fields[idx++] = token;
        token = strtok(NULL, ",");
    }
    
    // 如果行数据不完整
    idx = (idx < field_count) ? idx : field_count; // 确保不越界
    
    // 假设CSV格式如下：
    // flow_id,src_ip,src_port,dst_ip,dst_port,protocol,duration,...
    int field_idx = 0;
    
    if (field_idx < idx && fields[field_idx]) flow_data->flow_id = strdup(fields[field_idx]);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->src_ip = strdup(fields[field_idx]);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->src_port = atoi(fields[field_idx]);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->dst_ip = strdup(fields[field_idx]);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->dst_port = atoi(fields[field_idx]);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->protocol = atoi(fields[field_idx]);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->duration = atof(fields[field_idx]);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->start_time = strdup(fields[field_idx]);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->is_active = (strcmp(fields[field_idx], "1") == 0);
    field_idx++;
    
    // 设置基本统计信息
    if (field_idx < idx && fields[field_idx]) flow_data->fwd_packets = strtoull(fields[field_idx], NULL, 10);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->fwd_bytes = strtoull(fields[field_idx], NULL, 10);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->bwd_packets = strtoull(fields[field_idx], NULL, 10);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->bwd_bytes = strtoull(fields[field_idx], NULL, 10);
    field_idx++;
    
    // 包大小信息
    if (field_idx < idx && fields[field_idx]) flow_data->fwd_min_size = atoi(fields[field_idx]);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->fwd_max_size = atoi(fields[field_idx]);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->fwd_avg_size = atof(fields[field_idx]);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->fwd_std_size = atof(fields[field_idx]);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->bwd_min_size = atoi(fields[field_idx]);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->bwd_max_size = atoi(fields[field_idx]);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->bwd_avg_size = atof(fields[field_idx]);
    field_idx++;
    
    if (field_idx < idx && fields[field_idx]) flow_data->bwd_std_size = atof(fields[field_idx]);
    field_idx++;
    
    // 继续设置其他字段...
    // 为简化代码，这里只列出部分字段
    
    // 释放临时内存
    free(fields);
    free(line_copy);
    
    return flow_data;
}

// 从CSV文件发送流数据
int send_flow_data_from_csv(const char *csv_file, const char *server_addr, int port) {
    if (!csv_file || !server_addr || port <= 0) return -1;
    
    FILE *file = fopen(csv_file, "r");
    if (!file) {
        perror("Failed to open CSV file");
        return -1;
    }
    
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) {
        perror("Socket creation failed");
        fclose(file);
        return -1;
    }
    
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;
    serv_addr.sin_port = htons(port);
    
    if (inet_pton(AF_INET, server_addr, &serv_addr.sin_addr) <= 0) {
        perror("Invalid address");
        close(sock);
        fclose(file);
        return -1;
    }
    
    if (connect(sock, (struct sockaddr *)&serv_addr, sizeof(serv_addr)) < 0) {
        perror("Connection failed");
        close(sock);
        fclose(file);
        return -1;
    }
    
    // 创建流批次消息
    Flow__FlowBatch flow_batch = FLOW__FLOW_BATCH__INIT;
    
    // 获取当前时间
    uint64_t current_time = get_timestamp_ms();
    
    // 初始分配空间 (预估)
    int pb_flow_capacity = 1000;
    int pb_flow_count = 0;
    Flow__FlowData **pb_flows = (Flow__FlowData**)malloc(pb_flow_capacity * sizeof(Flow__FlowData*));
    if (!pb_flows) {
        close(sock);
        fclose(file);
        return -1;
    }
    
    char line[4096];
    bool first_line = true;
    
    while (fgets(line, sizeof(line), file)) {
        // 跳过第一行（标题）
        if (first_line) {
            first_line = false;
            continue;
        }
        
        // 去除换行符
        line[strcspn(line, "\r\n")] = 0;
        
        // 解析CSV行
        Flow__FlowData *pb_flow = create_flow_from_csv(line);
        if (!pb_flow) continue;
        
        // 检查是否需要扩展数组
        if (pb_flow_count >= pb_flow_capacity) {
            pb_flow_capacity *= 2;
            Flow__FlowData **new_flows = (Flow__FlowData**)realloc(pb_flows, 
                                                          pb_flow_capacity * sizeof(Flow__FlowData*));
            if (!new_flows) {
                for (int j = 0; j < pb_flow_count; j++) {
                    free_flow_pb(pb_flows[j]);
                }
                free(pb_flows);
        close(sock);
                fclose(file);
        return -1;
            }
            pb_flows = new_flows;
        }
        
        pb_flows[pb_flow_count++] = pb_flow;
    }
    
    fclose(file);
    
    if (pb_flow_count == 0) {
        free(pb_flows);
        close(sock);
        return 0; // 没有流，但不视为错误
    }
    
    // 设置批次数据
    flow_batch.flows = pb_flows;
    flow_batch.n_flows = pb_flow_count;
    flow_batch.timestamp = current_time;
    flow_batch.flow_count = pb_flow_count;
    
    // 获取主机名作为发送者ID
    char hostname[256];
    if (gethostname(hostname, sizeof(hostname)) == 0) {
        flow_batch.sender_id = hostname;
    } else {
        flow_batch.sender_id = "unknown";
    }
    
    // 序列化消息
    size_t len = flow__flow_batch__get_packed_size(&flow_batch);
    uint8_t *buffer = (uint8_t*)malloc(len);
    if (!buffer) {
        for (int i = 0; i < pb_flow_count; i++) {
            free_flow_pb(pb_flows[i]);
        }
        free(pb_flows);
        close(sock);
        return -1;
    }
    
    flow__flow_batch__pack(&flow_batch, buffer);
    
    // 发送长度前缀
    uint32_t len_n = htonl(len);
    send(sock, &len_n, sizeof(len_n), 0);
    
    // 发送序列化数据
    ssize_t sent = send(sock, buffer, len, 0);
    
    // 释放资源
    free(buffer);
    for (int i = 0; i < pb_flow_count; i++) {
        free_flow_pb(pb_flows[i]);
    }
    free(pb_flows);
    close(sock);
    
    return (sent == len) ? 0 : -1;
}

// 发送线程函数
static void *sender_thread_func(void *arg) {
    flow_sender_config_t *config = (flow_sender_config_t*)arg;
    
    while (sender_running) {
        // 发送所有流数据
        int result = send_flow_data(config->server_addr, config->port, config->include_inactive);
        if (result < 0) {
            fprintf(stderr, "Failed to send flow data\n");
        }
        
        // 等待下一轮发送
        sleep(config->interval);
    }
    
    return NULL;
}

// CSV发送线程函数
static void *csv_sender_thread_func(void *arg) {
    flow_sender_config_t *config = (flow_sender_config_t*)arg;
    
    while (sender_running) {
        // 如果提供了CSV文件
        if (config->csv_file[0] != '\0') {
            int result = send_flow_data_from_csv(config->csv_file, config->server_addr, config->port);
            if (result < 0) {
                fprintf(stderr, "Failed to send flow data from CSV\n");
            }
        }
        
        // 等待下一轮发送
        sleep(config->interval);
    }
    
    return NULL;
}

// 启动流数据发送线程
int start_flow_sender(flow_sender_config_t *config) {
    if (!config || config->server_addr[0] == '\0' || config->port <= 0) {
        fprintf(stderr, "Invalid sender configuration\n");
        return -1;
    }
    
    pthread_mutex_lock(&sender_mutex);
    
    // 如果已经在运行则返回错误
    if (sender_running) {
        pthread_mutex_unlock(&sender_mutex);
        fprintf(stderr, "Flow sender already running\n");
        return -1;
    }
    
    // 复制配置
    memcpy(&thread_config, config, sizeof(flow_sender_config_t));
    
    // 标记为运行状态
    sender_running = 1;
    
    // 创建发送线程
    if (pthread_create(&sender_thread, NULL, sender_thread_func, &thread_config) != 0) {
        sender_running = 0;
        pthread_mutex_unlock(&sender_mutex);
        fprintf(stderr, "Failed to create sender thread\n");
        return -1;
    }
    
    pthread_mutex_unlock(&sender_mutex);
    return 0;
}

// 启动CSV流数据发送线程
int start_csv_flow_sender(flow_sender_config_t *config) {
    if (!config || config->server_addr[0] == '\0' || config->port <= 0 || config->csv_file[0] == '\0') {
        fprintf(stderr, "Invalid CSV sender configuration\n");
        return -1;
    }
    
    pthread_mutex_lock(&sender_mutex);
    
    // 如果已经在运行则返回错误
    if (sender_running) {
        pthread_mutex_unlock(&sender_mutex);
        fprintf(stderr, "Flow sender already running\n");
        return -1;
    }
    
    // 复制配置
    memcpy(&thread_config, config, sizeof(flow_sender_config_t));
    
    // 标记为运行状态
    sender_running = 1;
    
    // 创建发送线程
    if (pthread_create(&sender_thread, NULL, csv_sender_thread_func, &thread_config) != 0) {
        sender_running = 0;
        pthread_mutex_unlock(&sender_mutex);
        fprintf(stderr, "Failed to create CSV sender thread\n");
        return -1;
    }
    
    pthread_mutex_unlock(&sender_mutex);
    return 0;
}

// 停止流数据发送线程
void stop_flow_sender() {
    pthread_mutex_lock(&sender_mutex);
    
    if (sender_running) {
    sender_running = 0;
        pthread_mutex_unlock(&sender_mutex);
    
        // 等待线程结束
    pthread_join(sender_thread, NULL);
        return;
    }
    
    pthread_mutex_unlock(&sender_mutex);
} 