// src/mempool.c
#include "mempool.h"
#include "logger.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

// 设置内存锁定限制
static void set_memory_lock_limit() {
    struct rlimit rlim;
    rlim.rlim_cur = RLIM_INFINITY;
    rlim.rlim_max = RLIM_INFINITY;
    setrlimit(RLIMIT_MEMLOCK, &rlim);
}

// 分配连续物理内存
void* allocate_physical_memory(size_t size) {
    // 设置内存锁定限制
    set_memory_lock_limit();
    
    // 分配内存并锁定到物理内存
    void* ptr = mmap(NULL, size, 
                     PROT_READ | PROT_WRITE,
                     MAP_PRIVATE | MAP_ANONYMOUS | MAP_LOCKED,
                     -1, 0);
    
    if (ptr == MAP_FAILED) {
        perror("mmap failed");
        return NULL;
    }
    
    // 预填充内存以确保物理页面被分配
    memset(ptr, 0, size);
    
    return ptr;
}

// 初始化使用连续物理内存的mempool
void mempool_init_physical(struct mempool *pool, size_t initial_blocks) {
    if (!pool) return;
    
    memset(pool, 0, sizeof(struct mempool));
    
    pool->block_size = sizeof(struct flow_node);
    pool->block_count = initial_blocks;
    pool->total_nodes = initial_blocks * MEMPOOL_BLOCK_SIZE;
    pool->total_size = pool->total_nodes * pool->block_size;
    pool->is_physical = 1;
    
    // 分配连续物理内存
    pool->physical_memory = allocate_physical_memory(pool->total_size);
    if (!pool->physical_memory) {
        log_error("Failed to allocate physical memory for mempool");
        return;
    }
    
    // 初始化空闲链表
    pool->free_list = NULL;
    
    // 将所有节点加入空闲链表
    struct flow_node* nodes = (struct flow_node*)pool->physical_memory;
    for (size_t i = 0; i < pool->total_nodes; i++) {
        nodes[i].next = pool->free_list;
        pool->free_list = &nodes[i];
    }
    
    log_info("Initialized physical mempool: %zu blocks, %zu nodes, %.2f MB total",
             initial_blocks, pool->total_nodes, 
             pool->total_size / (1024.0 * 1024.0));
}

struct flow_node *mempool_alloc(struct mempool *pool) {
    if (!pool) return NULL;
    
    // 如果没有空闲节点，返回NULL（物理内存池不支持动态扩展）
    if (!pool->free_list) {
        log_warn("No free nodes available in mempool");
        return NULL;
    }
    
    // 从空闲链表获取节点
    struct flow_node *node = pool->free_list;
    pool->free_list = node->next;
    
    // 清除节点并标记为使用中
    memset(node, 0, sizeof(struct flow_node));
    node->in_use = 1;
    
    return node;
}

void mempool_free(struct mempool *pool, struct flow_node *node) {
    if (!pool || !node) return;
    
    // 将节点返回到空闲链表
    node->in_use = 0;
    node->next = pool->free_list;
    pool->free_list = node;
}

void mempool_destroy(struct mempool *pool) {
    if (!pool) return;
    
    if (pool->physical_memory) {
        munmap(pool->physical_memory, pool->total_size);
        pool->physical_memory = NULL;
    }
    
    // 清除池
    memset(pool, 0, sizeof(struct mempool));
    
    log_info("Physical mempool destroyed");
}

void mempool_get_stats(struct mempool *pool, size_t *total_nodes, size_t *free_nodes, size_t *used_nodes) {
    if (!pool) return;
    
    *total_nodes = pool->total_nodes;
    
    // 计算空闲节点数量
    size_t free_count = 0;
    struct flow_node* current = pool->free_list;
    while (current) {
        free_count++;
        current = current->next;
    }
    *free_nodes = free_count;
    *used_nodes = pool->total_nodes - free_count;
}