#ifndef COMMON_TYPES_H
#define COMMON_TYPES_H

#include <stdint.h>
#include <stddef.h>

// 用于存储包间隔时间的数组
typedef struct {
    uint64_t *times;       // 时间戳数组 (纳秒)
    size_t count;          // 当前数组大小
    size_t capacity;       // 数组容量
} timestamp_array_t;

// 流键结构（五元组）
struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
    // Padding to ensure cache line alignment
    uint8_t  padding[3];
};

// 流特征结构（前向声明）
struct flow_features;

// 流统计结构（前向声明）
struct flow_stats;

// 流节点结构（前向声明）
struct flow_node;

#endif /* COMMON_TYPES_H */ 