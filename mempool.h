// include/mempool.h
#ifndef MEMPOOL_H
#define MEMPOOL_H

#include <stddef.h>
#include <stdint.h>
#include "flow.h"

// 大幅增加内存块大小，以支持更多流
#define MEMPOOL_BLOCK_SIZE 65536  // 每次扩展分配的节点数增加到64K

// Memory pool structure
struct mempool {
    struct flow_node *blocks;     // 内存块链表
    struct flow_node *free_list;  // 空闲节点链表
    size_t block_count;           // 当前内存块数
};

// 初始化内存池
void mempool_init(struct mempool *pool);

// 从池中分配节点
struct flow_node *mempool_alloc(struct mempool *pool);

// 释放节点回池
void mempool_free(struct mempool *pool, struct flow_node *node);

// 销毁内存池
void mempool_destroy(struct mempool *pool);

#endif /* MEMPOOL_H */