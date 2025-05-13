#ifndef FLOW_PB_H
#define FLOW_PB_H

#include <stdbool.h>
#include <stdint.h>
#include "flow.h"  // 包含流定义

// 发送器配置结构
typedef struct {
    char server_addr[256];  // 服务器地址
    int port;               // 服务器端口
    int interval;           // 发送间隔(秒)
    char csv_file[256];     // CSV文件路径（如果从CSV读取）
    bool include_inactive;  // 是否包含非活跃流
    uint32_t batch_size;    // 每批次最大流数量，0表示不限制
} flow_sender_config_t;

// 发送单个流数据
int send_flow(struct flow_stats *flow, const char *server_addr, int port);

// 发送多个流数据
int send_flow_batch(struct flow_stats **flows, int flow_count, const char *server_addr, int port);

// 发送当前所有流数据
int send_flow_data(const char *server_addr, int port, bool include_inactive);

// 从CSV文件发送流数据
int send_flow_data_from_csv(const char *csv_file, const char *server_addr, int port);

// 启动流数据发送线程
int start_flow_sender(flow_sender_config_t *config);

// 启动CSV流数据发送线程
int start_csv_flow_sender(flow_sender_config_t *config);

// 停止流数据发送线程
void stop_flow_sender();

#endif /* FLOW_PB_H */ 