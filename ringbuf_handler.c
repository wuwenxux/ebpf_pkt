#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include "loader.h"
#include "logger.h"
#include "flow.h"
#include "lockfree_queue.h"
#include "worker_threads.h"

// 外部变量声明
extern worker_thread_t worker_threads[];
extern int worker_thread_count;
extern packet_queue_t packet_queue;

// 优化的RINGBUF事件处理函数
int handle_ringbuf_event_optimized(void *ctx, void *data, size_t size) {
    const struct packet_info *pkts = (const struct packet_info *)data;
    int count = size / sizeof(struct packet_info);
    
    // 预取数据
    for (int i = 0; i < count && i < 4; i++) {
        PREFETCH(&pkts[i]);
    }
    
    // 检查退出条件
    time_t current_time = time(NULL);
    int should_exit = (duration > 0) && (current_time - start_time >= duration);
    running &= !should_exit;
    
    if (should_exit) {
        log_info("Reached specified duration of %d seconds. Exiting...", duration);
        return 0;
    }
    
    // 批量处理数据包
    for (int i = 0; i < count; i++) {
        // 预取下一个数据包
        if (i + 4 < count) {
            PREFETCH(&pkts[i + 4]);
        }
        
        const struct packet_info *pkt = &pkts[i];
        
        // 有效性检查
        int is_valid = (pkt->src_ip != 0) && (pkt->dst_ip != 0) && (pkt->pkt_len != 0);
        if (!is_valid) {
            __sync_fetch_and_add(&total_packets_invalid, 1);
            continue;
        }
        
        // 更新全局统计
        __sync_fetch_and_add(&global_packet_count, 1);
        __sync_fetch_and_add(&total_packets_captured, 1);
        __sync_fetch_and_add(&total_bytes_captured, pkt->pkt_len);
        
        // 准备数据包结构
        packet_data_t packet_data;
        packet_data.ip_header.saddr = pkt->src_ip;
        packet_data.ip_header.daddr = pkt->dst_ip;
        packet_data.ip_header.protocol = pkt->protocol;
        packet_data.ip_header.tot_len = htons(pkt->pkt_len);
        packet_data.transport_header.tcp.th_sport = pkt->src_port;
        packet_data.transport_header.tcp.th_dport = pkt->dst_port;
        packet_data.transport_header.tcp.th_flags = pkt->tcp_flags;
        packet_data.timestamp = pkt->timestamp;
        
        // 使用哈希值选择工作线程
        int worker_id = pkt->hash % get_worker_thread_count();
        if (worker_id >= 0 && worker_id < get_worker_thread_count()) {
            // 添加到对应工作线程的队列
            if (packet_queue_enqueue(&worker_threads[worker_id].packet_queue, &packet_data) != 0) {
                __sync_fetch_and_add(&total_packets_dropped, 1);
            } else {
                __sync_fetch_and_add(&total_packets_queued, 1);
            }
        } else {
            // 回退到全局队列
            if (packet_queue_enqueue(&packet_queue, &packet_data) != 0) {
                __sync_fetch_and_add(&total_packets_dropped, 1);
            } else {
                __sync_fetch_and_add(&total_packets_queued, 1);
            }
        }
    }
    
    return 0;
}

// 优化的RINGBUF事件处理函数（改进版）
int handle_ringbuf_event_optimized_improved(void *ctx, void *data, size_t size) {
    const struct packet_info *pkts = (const struct packet_info *)data;
    int count = size / sizeof(struct packet_info);
    
    // 预取数据
    for (int i = 0; i < count && i < 4; i++) {
        PREFETCH(&pkts[i]);
    }
    
    // 检查退出条件
    time_t current_time = time(NULL);
    int should_exit = (duration > 0) && (current_time - start_time >= duration);
    running &= !should_exit;
    
    if (should_exit) {
        log_info("Reached specified duration of %d seconds. Exiting...", duration);
        return 0;
    }
    
    // 批量处理数据包
    for (int i = 0; i < count; i++) {
        // 预取下一个数据包
        if (i + 4 < count) {
            PREFETCH(&pkts[i + 4]);
        }
        
        const struct packet_info *pkt = &pkts[i];
        
        // 验证数据包
        if (pkt->src_ip == 0 || pkt->dst_ip == 0 || pkt->pkt_len == 0) {
            __sync_fetch_and_add(&total_packets_invalid, 1);
            continue;
        }
        
        // 更新全局统计
        __sync_fetch_and_add(&global_packet_count, 1);
        __sync_fetch_and_add(&total_packets_captured, 1);
        __sync_fetch_and_add(&total_bytes_captured, pkt->pkt_len);
        
        // 使用无锁队列入队
        if (lockfree_queue_enqueue(&global_lockfree_queue, pkt) != 0) {
            __sync_fetch_and_add(&total_packets_dropped, 1);
        } else {
            __sync_fetch_and_add(&total_packets_queued, 1);
        }
    }
    
    return 0;
}

// 优化的数据包处理函数
void process_lockfree_packet_queue(void) {
    while (lockfree_queue_size(&global_lockfree_queue) > 0 && running) {
        struct packet_info packet;
        if (lockfree_queue_dequeue(&global_lockfree_queue, &packet) == 0) {
            __sync_fetch_and_add(&total_packets_dequeued, 1);
            
            // 准备数据包结构
            packet_data_t packet_data;
            packet_data.ip_header.saddr = packet.src_ip;
            packet_data.ip_header.daddr = packet.dst_ip;
            packet_data.ip_header.protocol = packet.protocol;
            packet_data.ip_header.tot_len = htons(packet.pkt_len);
            packet_data.transport_header.tcp.th_sport = packet.src_port;
            packet_data.transport_header.tcp.th_dport = packet.dst_port;
            packet_data.transport_header.tcp.th_flags = packet.tcp_flags;
            packet_data.timestamp = packet.timestamp;
            
            // 使用哈希值选择工作线程（如果启用了工作线程池）
            if (get_worker_thread_count() > 0) {
                int worker_id = packet.hash % get_worker_thread_count();
                if (worker_id >= 0 && worker_id < get_worker_thread_count()) {
                    if (packet_queue_enqueue(&worker_threads[worker_id].packet_queue, &packet_data) != 0) {
                        __sync_fetch_and_add(&total_packets_dropped, 1);
                    }
                } else {
                    // 回退到全局队列
                    if (packet_queue_enqueue(&packet_queue, &packet_data) != 0) {
                        __sync_fetch_and_add(&total_packets_dropped, 1);
                    }
                }
            } else {
                // 直接处理数据包
                if (packet.protocol == IPPROTO_TCP) {
                    process_packet_direct(&packet_data.ip_header, 
                                        packet_data.transport_header.tcp.th_sport,
                                        packet_data.transport_header.tcp.th_dport,
                                        0, packet_data.transport_header.tcp.th_flags, 
                                        packet_data.timestamp);
                } else if (packet.protocol == IPPROTO_UDP) {
                    process_packet_direct(&packet_data.ip_header,
                                        packet_data.transport_header.udp.source,
                                        packet_data.transport_header.udp.dest,
                                        0, 0, packet_data.timestamp);
                }
            }
        }
    }
}

// 标准RINGBUF事件处理函数
int handle_ringbuf_event(void *ctx, void *data, size_t size) {
    const struct packet_info *pkts = (const struct packet_info *)data;
    int count = size / sizeof(struct packet_info);
    
    // 预取数据，避免首次访问时的缓存缺失
    for (int i = 0; i < count && i < 4; i++) {
        PREFETCH(&pkts[i]);
    }
    
    // 使用位操作进行条件判断
    time_t current_time = time(NULL);
    int should_exit = (duration > 0) & (current_time - start_time >= duration);
    running &= !should_exit;
    
    if (should_exit) {
        log_info("Reached specified duration of %d seconds. Exiting...", duration);
        return 0;
    }
    
    for (int i = 0; i < count; i++) {
        // 提前预取下一个数据包
        if (i + 4 < count) {
            PREFETCH(&pkts[i + 4]);
        }
        
        const struct packet_info *pkt = &pkts[i];
        
        // 使用位操作进行有效性判断
        int is_valid = (pkt->src_ip != 0) & (pkt->dst_ip != 0) & (pkt->pkt_len != 0);
        if (!is_valid) {
            __sync_fetch_and_add(&total_packets_invalid, 1);
            continue;
        }
        
        // 更新全局包计数器
        __sync_fetch_and_add(&global_packet_count, 1);
        
        // **恢复**: 在BPF捕获点统计包数，这是从eBPF程序实际接收到的包
        __sync_fetch_and_add(&total_packets_captured, 1);
        __sync_fetch_and_add(&total_bytes_captured, pkt->pkt_len);
        
        // 调试输出（前10个包）- 仅在debug模式下显示
        static int debug_count = 0;
        if (debug_count < 10) {
            struct in_addr src_addr = {.s_addr = pkt->src_ip};
            struct in_addr dst_addr = {.s_addr = pkt->dst_ip};
            log_debug("Packet %d - IP: %s -> %s, Protocol: %d, Ports: %u -> %u, TCP flags: 0x%02x, Length: %u bytes", 
                   debug_count + 1, inet_ntoa(src_addr), inet_ntoa(dst_addr), 
                   pkt->protocol, pkt->src_port, pkt->dst_port, pkt->tcp_flags, pkt->pkt_len);
            debug_count++;
        }
        
        // 准备数据包结构
        packet_data_t packet_data;
        
        // 手动创建IP头
        packet_data.ip_header.saddr = pkt->src_ip;
        packet_data.ip_header.daddr = pkt->dst_ip;
        packet_data.ip_header.protocol = pkt->protocol;
        packet_data.ip_header.tot_len = htons(pkt->pkt_len);
        
        // 使用预编译的位掩码和协议比较 - 使用位操作
        uint8_t is_tcp = (pkt->protocol == IPPROTO_TCP);
        
        // 设置传输层信息
        packet_data.transport_header.tcp.th_sport = pkt->src_port;
        packet_data.transport_header.tcp.th_dport = pkt->dst_port;
        
        // 仅当协议为TCP时设置标志位
        packet_data.transport_header.tcp.th_flags = pkt->tcp_flags & is_tcp;
        
        // 提取并转换时间戳为纳秒
        packet_data.timestamp = (uint64_t)pkt->timestamp;
        
        // 将数据包添加到队列
        if (packet_queue_enqueue(&packet_queue, &packet_data) != 0) {
            // 入队失败，统计丢包
            __sync_fetch_and_add(&total_packets_dropped, 1);
            if (!running) break;
        } else {
            __sync_fetch_and_add(&total_packets_queued, 1);
        }
    }
    
    return 0; // 成功处理
} 