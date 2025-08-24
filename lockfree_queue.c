#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include "loader.h"
#include "logger.h"

// 确保队列容量是2的幂次
uint64_t next_power_of_2(uint64_t n) {
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n |= n >> 32;
    return n + 1;
}

// 初始化无锁队列
void lockfree_queue_init(lockfree_queue_t *queue, int initial_capacity) {
    uint64_t capacity = next_power_of_2(initial_capacity);
    
    queue->packets = (struct packet_info *)aligned_alloc(64, capacity * sizeof(struct packet_info));
    if (!queue->packets) {
        log_error("Failed to allocate lockfree packet queue");
        exit(EXIT_FAILURE);
    }
    
    queue->head = 0;
    queue->tail = 0;
    queue->capacity = capacity;
    queue->mask = capacity - 1;
    
    memset(queue->packets, 0, capacity * sizeof(struct packet_info));
    log_info("Initialized lockfree queue with capacity %lu", capacity);
}

// 销毁无锁队列
void lockfree_queue_destroy(lockfree_queue_t *queue) {
    if (queue->packets) {
        free(queue->packets);
        queue->packets = NULL;
    }
}

// 无锁入队操作
int lockfree_queue_enqueue(lockfree_queue_t *queue, const struct packet_info *packet) {
    if (!running) return -1;
    
    uint64_t tail, head, next_tail;
    int retry_count = 0;
    const int max_retries = 1000;
    
    while (retry_count < max_retries && running) {
        tail = queue->tail;
        head = queue->head;
        next_tail = tail + 1;
        
        if (next_tail - head >= queue->capacity - 1) {
            __asm__ __volatile__("pause" ::: "memory");
            retry_count++;
            continue;
        }
        
        if (__sync_bool_compare_and_swap(&queue->tail, tail, next_tail)) {
            uint64_t idx = tail & queue->mask;
            memcpy(&queue->packets[idx], packet, sizeof(struct packet_info));
            __sync_synchronize();
            return 0;
        }
        
        __asm__ __volatile__("pause" ::: "memory");
        retry_count++;
    }
    
    if (running) {
        static int drop_warning_count = 0;
        if (drop_warning_count < 10) {
            log_warn("Lockfree queue full, dropping packet (warning %d/10)", ++drop_warning_count);
        }
        return -1;
    }
    
    return -1;
}

// 无锁出队操作
int lockfree_queue_dequeue(lockfree_queue_t *queue, struct packet_info *packet) {
    uint64_t head, tail, next_head;
    int retry_count = 0;
    const int max_retries = 100;
    
    while (retry_count < max_retries && running) {
        head = queue->head;
        tail = queue->tail;
        next_head = head + 1;
        
        if (head == tail) {
            __asm__ __volatile__("pause" ::: "memory");
            retry_count++;
            continue;
        }
        
        if (__sync_bool_compare_and_swap(&queue->head, head, next_head)) {
            uint64_t idx = head & queue->mask;
            memcpy(packet, &queue->packets[idx], sizeof(struct packet_info));
            __sync_synchronize();
            return 0;
        }
        
        __asm__ __volatile__("pause" ::: "memory");
        retry_count++;
    }
    
    return running ? 0 : -1;
}

// 获取无锁队列大小
uint64_t lockfree_queue_size(lockfree_queue_t *queue) {
    uint64_t tail = queue->tail;
    uint64_t head = queue->head;
    return tail - head;
} 