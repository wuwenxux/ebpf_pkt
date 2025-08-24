#include <stdio.h>
#include <sys/resource.h>
#include <sys/times.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>  // For sysconf and _SC_CLK_TCK
// External variables from loader.c
extern struct timespec program_start_time;
extern volatile uint64_t total_packets_processed;

// System statistics structure已在loader_core.c中定义
// 使用外部声明
extern struct {
    double cpu_usage;
    double memory_usage;
    uint64_t packets_processed;
    double processing_time;
    uint64_t packets_per_second;
} system_stats;

// Get CPU usage for all CPUs
static double get_cpu_usage(void) {
    static uint64_t prev_total = 0;
    static uint64_t prev_idle = 0;
    
    FILE *fp = fopen("/proc/stat", "r");
    if (!fp) {
        return 0.0;
    }
    
    uint64_t user, nice, system, idle, iowait, irq, softirq, steal, guest, guest_nice;
    if (fscanf(fp, "cpu %lu %lu %lu %lu %lu %lu %lu %lu %lu %lu",
               &user, &nice, &system, &idle, &iowait, &irq, &softirq, &steal, &guest, &guest_nice) != 10) {
        fclose(fp);
        return 0.0;
    }
    fclose(fp);
    
    // Calculate total CPU time
    uint64_t total = user + nice + system + idle + iowait + irq + softirq + steal;
    uint64_t non_idle = total - idle;
    
    double cpu_usage = 0.0;
    
    if (prev_total > 0) {
        uint64_t total_diff = total - prev_total;
        uint64_t non_idle_diff = non_idle - (prev_total - prev_idle);
        
        if (total_diff > 0) {
            cpu_usage = (double)non_idle_diff / total_diff * 100.0;
        }
    }
    
    // Store current values for next calculation
    prev_total = total;
    prev_idle = idle;
    
    return cpu_usage;
}

// Get memory usage
double get_memory_usage(void) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        return 0.0;
    }
    long memory_kb = usage.ru_maxrss;
    struct sysinfo si;
    if (sysinfo(&si) != 0) {
        return 0.0;
    }
    double memory_mb = memory_kb / 1024.0;
    double total_memory_mb = si.totalram / (1024.0 * 1024.0);
    if (total_memory_mb > 0) {
        return (memory_mb / total_memory_mb) * 100.0;
    }
    return 0.0;
}

// Update system statistics
void update_system_stats(void) {
    system_stats.cpu_usage = get_cpu_usage();
    system_stats.memory_usage = get_memory_usage();
    system_stats.packets_processed = total_packets_processed;
    struct timespec current_time;
    clock_gettime(CLOCK_REALTIME, &current_time);
    system_stats.processing_time = (current_time.tv_sec - program_start_time.tv_sec) + 
                                  (current_time.tv_nsec - program_start_time.tv_nsec) / 1000000000.0;
    if (system_stats.processing_time > 0) {
        system_stats.packets_per_second = (uint64_t)(system_stats.packets_processed / system_stats.processing_time);
    }
} 