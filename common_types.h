#ifndef COMMON_TYPES_H
#define COMMON_TYPES_H

#include <stdint.h>
#include <stdbool.h>
#include <time.h>

// 流键结构 - 用于标识网络流
struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    uint8_t tos;
    uint8_t ttl;
    uint16_t tcp_window;
    uint32_t tcp_options;
};

// 时间戳数组结构 - 用于存储包时间戳
typedef struct {
    uint64_t *times;
    size_t capacity;
    size_t count;
    size_t head;
    size_t tail;
    bool is_circular;
} timestamp_array_t;

// 流特征结构在flow.h中定义，这里只声明
struct flow_features;

#endif // COMMON_TYPES_H 