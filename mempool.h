// include/mempool.h
#ifndef MEMPOOL_H
#define MEMPOOL_H

#include <stddef.h>
#include <stdint.h>
#include <sys/mman.h>
#include <sys/resource.h>
#include "flow.h"

// 大幅增加内存块大小，以支持更多流
#define MEMPOOL_BLOCK_SIZE 65536  // 每次扩展分配的节点数增加到128K

// Memory pool structure - Cache line aligned for performance
struct mempool {
    // 高频访问字段 - 第一个cache line
    void* physical_memory;        // 连续物理内存基地址
    size_t total_size;            // 总大小
    size_t block_size;            // 单个节点大小
    size_t block_count;           // 当前内存块数
    size_t total_nodes;           // 总节点数
    struct flow_node *free_list;  // 空闲节点链表
    int is_physical;              // 是否使用物理内存
    
    // Padding to ensure cache line alignment
    uint8_t padding[4];
};

// 初始化内存池（使用连续物理内存）
void mempool_init_physical(struct mempool *pool, size_t initial_blocks);

// 从池中分配节点
struct flow_node *mempool_alloc(struct mempool *pool);

// 释放节点回池
void mempool_free(struct mempool *pool, struct flow_node *node);

// 销毁内存池
void mempool_destroy(struct mempool *pool);

// 获取内存池统计信息
void mempool_get_stats(struct mempool *pool, size_t *total_nodes, size_t *free_nodes, size_t *used_nodes);

// 清空内存池
void mempool_clear(struct mempool *pool);

// 分配连续物理内存的辅助函数
void* allocate_physical_memory(size_t size);

#endif /* MEMPOOL_H */