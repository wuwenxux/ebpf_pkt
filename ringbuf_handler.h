#ifndef RINGBUF_HANDLER_H
#define RINGBUF_HANDLER_H

#include <stddef.h>
#include "loader.h"

// RINGBUF处理函数声明
int handle_ringbuf_event(void *ctx, void *data, size_t size);
int handle_ringbuf_event_optimized(void *ctx, void *data, size_t size);
int handle_ringbuf_event_optimized_improved(void *ctx, void *data, size_t size);
void process_lockfree_packet_queue(void);

#endif // RINGBUF_HANDLER_H 