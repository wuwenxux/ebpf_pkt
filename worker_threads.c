#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <stdatomic.h>
#include "loader.h"
#include "logger.h"
#include "transport_session.h"
#include "flow.h"
#include "worker_threads.h"

// 全局工作线程数组
worker_thread_t worker_threads[MAX_WORKER_THREADS];
int worker_thread_count = 0;

// 线程亲和性设置函数
static int set_thread_affinity(pthread_t thread, int cpu_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);
    
    int ret = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);
    if (ret != 0) {
        log_error("Failed to set thread affinity for CPU %d: %s", cpu_id, strerror(ret));
        return -1;
    }
    
    log_info("Successfully set thread affinity to CPU %d", cpu_id);
    return 0;
}

// 初始化本地会话表
static int init_local_session_table(local_session_table_t *table, size_t capacity, int thread_id) {
    table->sessions = calloc(capacity, sizeof(struct transport_session));
    if (!table->sessions) {
        log_error("Failed to allocate local session table for thread %d", thread_id);
        return -1;
    }
    
    table->capacity = capacity;
    table->size = 0;
    table->thread_id = thread_id;
    
    if (pthread_mutex_init(&table->mutex, NULL) != 0) {
        log_error("Failed to initialize mutex for local session table %d", thread_id);
        free(table->sessions);
        return -1;
    }
    
    log_info("Initialized local session table for thread %d with capacity %zu", thread_id, capacity);
    return 0;
}

// 清理本地会话表
static void cleanup_local_session_table(local_session_table_t *table) {
    if (table->sessions) {
        pthread_mutex_lock(&table->mutex);
        
        // 清理会话
        for (size_t i = 0; i < table->size; i++) {
            if (atomic_load_explicit(&table->sessions[i].is_active, memory_order_acquire)) {
                // 清理会话资源
                atomic_store_explicit(&table->sessions[i].is_active, false, memory_order_release);
                
                // 释放时间戳数组内存
                timestamp_array_free(&table->sessions[i].stats.fwd_timestamps);
                timestamp_array_free(&table->sessions[i].stats.bwd_timestamps);
                
                // 释放特征数据内存
                if (table->sessions[i].stats.features) {
                    free(table->sessions[i].stats.features);
                    table->sessions[i].stats.features = NULL;
                }
            }
        }
        
        pthread_mutex_unlock(&table->mutex);
        pthread_mutex_destroy(&table->mutex);
        free(table->sessions);
        table->sessions = NULL;
    }
}

// 工作线程函数
static void *worker_thread_func(void *arg) {
    worker_thread_t *worker = (worker_thread_t *)arg;
    int thread_id = worker->thread_id;
    int cpu_id = worker->cpu_id;
    
    log_info("Worker thread %d started on CPU %d", thread_id, cpu_id);
    
    // 设置线程亲和性
    if (set_thread_affinity(pthread_self(), cpu_id) != 0) {
        log_warn("Failed to set affinity for worker thread %d", thread_id);
    }
    
    // 初始化本地会话表
    if (init_local_session_table(&worker->local_sessions, 10000, thread_id) != 0) {
        log_error("Failed to initialize local session table for worker thread %d", thread_id);
        return NULL;
    }
    
    // 初始化本地数据包队列
    packet_queue_init(&worker->packet_queue, WORKER_QUEUE_SIZE);
    
    while (worker->running) {
        // 处理本地队列中的数据包
        packet_data_t packet;
        if (packet_queue_dequeue(&worker->packet_queue, &packet) == 0) {
            worker->packets_processed++;
            worker->bytes_processed += packet.ip_header.tot_len;
            
            // 使用本地会话表处理数据包
            pthread_mutex_lock(&worker->local_sessions.mutex);
            
            // 查找或创建会话
            struct transport_session *session = NULL;
            for (size_t i = 0; i < worker->local_sessions.size; i++) {
                if (atomic_load_explicit(&worker->local_sessions.sessions[i].is_active, memory_order_acquire) &&
                    worker->local_sessions.sessions[i].key.src_ip == packet.ip_header.saddr &&
                    worker->local_sessions.sessions[i].key.dst_ip == packet.ip_header.daddr &&
                    worker->local_sessions.sessions[i].key.src_port == packet.transport_header.tcp.th_sport &&
                    worker->local_sessions.sessions[i].key.dst_port == packet.transport_header.tcp.th_dport &&
                    worker->local_sessions.sessions[i].key.protocol == packet.ip_header.protocol) {
                    session = &worker->local_sessions.sessions[i];
                    break;
                }
            }
            
            if (!session) {
                // 创建新会话
                if (worker->local_sessions.size < worker->local_sessions.capacity) {
                    session = &worker->local_sessions.sessions[worker->local_sessions.size];
                    
                    // 初始化flow_key
                    session->key.src_ip = packet.ip_header.saddr;
                    session->key.dst_ip = packet.ip_header.daddr;
                    session->key.src_port = packet.transport_header.tcp.th_sport;
                    session->key.dst_port = packet.transport_header.tcp.th_dport;
                    session->key.protocol = packet.ip_header.protocol;
                    
                    // 设置会话状态
                    atomic_store_explicit(&session->is_active, true, memory_order_release);
                    session->session_id = worker->local_sessions.size;
                    session->type = (packet.ip_header.protocol == IPPROTO_TCP) ? SESSION_TYPE_TCP : SESSION_TYPE_UDP;
                    
                    // 初始化时间戳
                    clock_gettime(CLOCK_MONOTONIC, &session->creation_time);
                    session->last_activity = session->creation_time;
                    
                    worker->local_sessions.size++;
                }
            }
            
            if (session) {
                // 更新会话时间戳
                clock_gettime(CLOCK_MONOTONIC, &session->last_activity);
                
                // 更新统计信息
                session->stats.packets_in++;
                session->stats.bytes_in += packet.ip_header.tot_len;
                session->stats.total_packets++;
                session->stats.total_bytes += packet.ip_header.tot_len;
            }
            
            // 调用全局处理函数来更新流和会话统计
            if (packet.ip_header.protocol == IPPROTO_TCP) {
                process_packet_direct(&packet.ip_header, 
                                    packet.transport_header.tcp.th_sport,
                                    packet.transport_header.tcp.th_dport,
                                    0, packet.transport_header.tcp.th_flags, 
                                    packet.timestamp);
            } else if (packet.ip_header.protocol == IPPROTO_UDP) {
                process_packet_direct(&packet.ip_header,
                                    packet.transport_header.udp.source,
                                    packet.transport_header.udp.dest,
                                    0, 0, packet.timestamp);
            }
            
            pthread_mutex_unlock(&worker->local_sessions.mutex);
        } else {
            // 队列为空，短暂休眠
            usleep(1000); // 1ms
        }
    }
    
    // 清理资源
    cleanup_local_session_table(&worker->local_sessions);
    packet_queue_cleanup(&worker->packet_queue);
    
    log_info("Worker thread %d stopped", thread_id);
    return NULL;
}

// 初始化工作线程池
int init_worker_threads(void) {
    int cpu_count = get_nprocs();
    worker_thread_count = (cpu_count > MAX_WORKER_THREADS) ? MAX_WORKER_THREADS : cpu_count;
    
    log_info("Initializing %d worker threads on %d CPUs", worker_thread_count, cpu_count);
    
    for (int i = 0; i < worker_thread_count; i++) {
        worker_threads[i].thread_id = i;
        worker_threads[i].cpu_id = i % cpu_count; // 循环分配CPU
        worker_threads[i].running = 1;
        worker_threads[i].packets_processed = 0;
        worker_threads[i].bytes_processed = 0;
        
        if (pthread_create(&worker_threads[i].thread, NULL, worker_thread_func, &worker_threads[i]) != 0) {
            log_error("Failed to create worker thread %d", i);
            return -1;
        }
        
        log_info("Created worker thread %d on CPU %d", i, worker_threads[i].cpu_id);
    }
    
    return 0;
}

// 停止工作线程池
void stop_worker_threads(void) {
    log_info("Stopping %d worker threads", worker_thread_count);
    
    for (int i = 0; i < worker_thread_count; i++) {
        worker_threads[i].running = 0;
    }
    
    for (int i = 0; i < worker_thread_count; i++) {
        pthread_join(worker_threads[i].thread, NULL);
    }
    
    log_info("All worker threads stopped");
}

// 获取工作线程数量
int get_worker_thread_count(void) {
    return worker_thread_count;
}

// 获取工作线程统计信息
void get_worker_thread_stats(int thread_id, uint64_t *packets, uint64_t *bytes) {
    if (thread_id >= 0 && thread_id < worker_thread_count) {
        *packets = worker_threads[thread_id].packets_processed;
        *bytes = worker_threads[thread_id].bytes_processed;
    } else {
        *packets = 0;
        *bytes = 0;
    }
} 