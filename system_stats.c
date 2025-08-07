#include <sys/resource.h>
#include <sys/times.h>
#include <sys/sysinfo.h>
#include <time.h>
#include <stdint.h>
#include <unistd.h>  // For sysconf and _SC_CLK_TCK
// External variables from loader.c
extern struct timespec program_start_time;
extern volatile uint64_t total_packets_processed;

// System statistics structure
typedef struct {
    double cpu_usage;
    double memory_usage;
    uint64_t packets_processed;
    double processing_time;
    uint64_t packets_per_second;
} system_stats_t;

// Global system statistics
system_stats_t system_stats = {0};

// Get CPU usage
static double get_cpu_usage(void) {
    // Implementation from loader.c
    struct tms time_sample;
    clock_t now = times(&time_sample);
    if (now == (clock_t)-1) {
        return 0.0;
    }
    double total_cpu_time = (double) (time_sample.tms_utime + time_sample.tms_stime) / sysconf(_SC_CLK_TCK);
    struct timespec current_time;
    clock_gettime(CLOCK_REALTIME, &current_time);
    double elapsed_time = (current_time.tv_sec - program_start_time.tv_sec) + 
                         (current_time.tv_nsec - program_start_time.tv_nsec) / 1000000000.0;
    if (elapsed_time > 0) {
        return (total_cpu_time / elapsed_time) * 100.0;
    }
    return 0.0;
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