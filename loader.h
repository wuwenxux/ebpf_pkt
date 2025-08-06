#ifndef LOADER_H
#define LOADER_H

#include <stdint.h>
#include <time.h>

extern struct timespec program_start_time;
extern volatile uint64_t total_packets_processed;
extern volatile int running;

// eBPF统计函数声明
uint64_t get_ebpf_captured_packets(void);
uint64_t get_ebpf_captured_bytes(void);
uint64_t get_ebpf_processed_packets(void);
uint64_t get_ebpf_processed_bytes(void);
void get_ebpf_stats(uint64_t *captured_packets, uint64_t *captured_bytes, 
                   uint64_t *processed_packets, uint64_t *processed_bytes);
void print_ebpf_stats(void);


#endif // LOADER_H 