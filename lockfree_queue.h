#ifndef LOCKFREE_QUEUE_H
#define LOCKFREE_QUEUE_H

#include <stdint.h>
#include "loader.h"

// 无锁队列函数声明
uint64_t next_power_of_2(uint64_t n);
void lockfree_queue_init(lockfree_queue_t *queue, int initial_capacity);
void lockfree_queue_destroy(lockfree_queue_t *queue);
int lockfree_queue_enqueue(lockfree_queue_t *queue, const struct packet_info *packet);
int lockfree_queue_dequeue(lockfree_queue_t *queue, struct packet_info *packet);
uint64_t lockfree_queue_size(lockfree_queue_t *queue);

#endif // LOCKFREE_QUEUE_H 