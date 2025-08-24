#ifndef WORKER_THREADS_H
#define WORKER_THREADS_H

#include <stdint.h>
#include <pthread.h>
#include "loader.h"

// 工作线程配置
#define MAX_WORKER_THREADS 16
#define WORKER_QUEUE_SIZE 10000

// 本地会话表结构
typedef struct local_session_table {
    struct transport_session *sessions;
    size_t capacity;
    size_t size;
    pthread_mutex_t mutex;
    uint32_t thread_id;
} local_session_table_t;

// 工作线程结构
typedef struct worker_thread {
    pthread_t thread;
    int thread_id;
    int cpu_id;
    local_session_table_t local_sessions;
    packet_queue_t packet_queue;
    volatile int running;
    uint64_t packets_processed;
    uint64_t bytes_processed;
} worker_thread_t;

// 全局变量声明
extern worker_thread_t worker_threads[];
extern int worker_thread_count;

// 工作线程函数声明
int init_worker_threads(void);
void stop_worker_threads(void);
int get_worker_thread_count(void);
void get_worker_thread_stats(int thread_id, uint64_t *packets, uint64_t *bytes);

#endif // WORKER_THREADS_H 