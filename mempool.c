// src/mempool.c
#include "mempool.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

// Simplified memory block structure
struct mem_block {
    struct flow_node nodes[MEMPOOL_BLOCK_SIZE];
    struct mem_block *next;
};

static void mempool_expand(struct mempool *pool);

void mempool_init(struct mempool *pool) {
    if (!pool) return;
    
    memset(pool, 0, sizeof(struct mempool));
    // Allocate initial block
    mempool_expand(pool); 
}

static void mempool_expand(struct mempool *pool) {
    if (!pool) return;
    
    // Allocate a new block
    struct mem_block *block = (struct mem_block*)malloc(sizeof(struct mem_block));
    if (!block) {
        fprintf(stderr, "Failed to allocate memory block\n");
        return;
    }
    
    // Clear the memory
    memset(block, 0, sizeof(struct mem_block));
    
    // Link the nodes in this block to the free list
    for (int i = 0; i < MEMPOOL_BLOCK_SIZE; i++) {
        block->nodes[i].next = pool->free_list;
        pool->free_list = &block->nodes[i];
    }
    
    // Add the block to the block list - using proper casting
    block->next = (struct mem_block*)pool->blocks;
    pool->blocks = (struct flow_node*)block;
    
    pool->block_count++;
}

struct flow_node *mempool_alloc(struct mempool *pool) {
    if (!pool) return NULL;
    
    // If no free nodes, expand the pool
    if (!pool->free_list) {
        mempool_expand(pool);
        if (!pool->free_list) {
            return NULL; // Expansion failed
        }
    }
    
    // Get a node from the free list
    struct flow_node *node = pool->free_list;
    pool->free_list = node->next;
    
    // Clear the node and mark as in-use
    memset(node, 0, sizeof(struct flow_node));
    node->in_use = 1;
    
    return node;
}

void mempool_free(struct mempool *pool, struct flow_node *node) {
    if (!pool || !node) return;
    
    // Return the node to the free list
    node->in_use = 0;
    node->next = pool->free_list;
    pool->free_list = node;
}

void mempool_destroy(struct mempool *pool) {
    if (!pool) return;
    
    // Free all allocated blocks
    struct mem_block *block = (struct mem_block*)pool->blocks;
    while (block) {
        struct mem_block *next = block->next;
        free(block);
        block = next;
    }
    
    // Clear the pool
    memset(pool, 0, sizeof(struct mempool));
}