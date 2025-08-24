#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "loader.h"
#include "flow.h"
#include "logger.h"

// 优化的接口信息结构已在loader.h中定义

// 优化的接口数组
static optimized_interface_info_t optimized_interfaces[MAX_INTERFACES];
static int optimized_interface_count = 0;
static pthread_mutex_t optimized_interface_mutex = PTHREAD_MUTEX_INITIALIZER;

// 传统接口数组（用于兼容性）
static interface_info_t interfaces[MAX_INTERFACES];
static int interface_count = 0;

// 获取可用接口列表
int get_available_interfaces(char interfaces[][IF_NAMESIZE], int max_count) {
    return get_available_interfaces_ex(interfaces, max_count, true);
}

// 获取可用接口列表（扩展版本，支持排除特定接口）
int get_available_interfaces_ex(char interfaces[][IF_NAMESIZE], int max_count, bool exclude_enp1s0) {
    struct if_nameindex *if_ni, *i;
    int count = 0;
    
    if_ni = if_nameindex();
    if (if_ni == NULL) {
        perror("if_nameindex");
        return 0;
    }
    
    for (i = if_ni; i->if_index != 0 || i->if_name != NULL; i++) {
        if (count >= max_count) break;
        
        // 跳过回环接口
        if (strcmp(i->if_name, "lo") == 0) continue;
        
        // 根据参数决定是否排除enp1s0
        if (exclude_enp1s0 && strcmp(i->if_name, "enp1s0") == 0) {
            log_info("Skipping enp1s0 interface in all-interfaces mode");
            continue;
        }
        
        strncpy(interfaces[count], i->if_name, IF_NAMESIZE - 1);
        interfaces[count][IF_NAMESIZE - 1] = '\0';
        count++;
    }
    
    if_freenameindex(if_ni);
    return count;
}

// 初始化单个接口
int init_interface(const char *ifname, int thread_id) {
    if (interface_count >= MAX_INTERFACES) {
        log_error("Maximum number of interfaces reached");
        return -1;
    }
    
    interface_info_t *iface = &interfaces[interface_count];
    
    memset(iface, 0, sizeof(interface_info_t));
    strncpy(iface->name, ifname, IF_NAMESIZE - 1);
    iface->name[IF_NAMESIZE - 1] = '\0';
    iface->is_active = 0;
    iface->thread_ret = 0;
    
    // 获取接口索引
    iface->ifindex = if_nametoindex(ifname);
    if (!iface->ifindex) {
        log_error("Failed to get interface index for %s: %s", ifname, strerror(errno));
        return -1;
    }
    
    log_info("Initializing interface %s (index: %d) for thread %d", ifname, iface->ifindex, thread_id);
    
    interface_count++;
    return 0;
}

// 初始化优化接口信息
int init_optimized_interface(const char *ifname, int cpu_id) {
    if (optimized_interface_count >= MAX_INTERFACES) {
        log_error("Maximum number of optimized interfaces reached");
        return -1;
    }
    
    optimized_interface_info_t *iface = &optimized_interfaces[optimized_interface_count];
    
    memset(iface, 0, sizeof(optimized_interface_info_t));
    strncpy(iface->name, ifname, IF_NAMESIZE - 1);
    iface->name[IF_NAMESIZE - 1] = '\0';
    iface->is_active = 0;
    iface->thread_ret = 0;
    iface->cpu_id = cpu_id;
    
    // 获取接口索引
    iface->ifindex = if_nametoindex(ifname);
    if (!iface->ifindex) {
        log_error("Failed to get interface index for %s: %s", ifname, strerror(errno));
        return -1;
    }
    
    log_info("Initializing optimized interface %s (index: %d, CPU: %d)", 
             ifname, iface->ifindex, cpu_id);
    
    optimized_interface_count++;
    return 0;
}

// 获取优化接口数量
int get_optimized_interface_count(void) {
    return optimized_interface_count;
}

// 获取优化接口信息
optimized_interface_info_t *get_optimized_interface(int index) {
    if (index >= 0 && index < optimized_interface_count) {
        return &optimized_interfaces[index];
    }
    return NULL;
}

// 更新接口统计信息
void update_interface_stats(int ifindex, uint64_t packets, uint64_t bytes) {
    pthread_mutex_lock(&optimized_interface_mutex);
    for (int i = 0; i < optimized_interface_count; i++) {
        if (optimized_interfaces[i].ifindex == ifindex) {
            optimized_interfaces[i].packets_captured += packets;
            optimized_interfaces[i].bytes_captured += bytes;
            break;
        }
    }
    pthread_mutex_unlock(&optimized_interface_mutex);
}

// 获取接口统计信息
void get_interface_stats(int ifindex, uint64_t *packets, uint64_t *bytes, uint64_t *dropped, uint64_t *errors) {
    pthread_mutex_lock(&optimized_interface_mutex);
    for (int i = 0; i < optimized_interface_count; i++) {
        if (optimized_interfaces[i].ifindex == ifindex) {
            *packets = optimized_interfaces[i].packets_captured;
            *bytes = optimized_interfaces[i].bytes_captured;
            *dropped = optimized_interfaces[i].packets_dropped;
            *errors = optimized_interfaces[i].packets_error;
            pthread_mutex_unlock(&optimized_interface_mutex);
            return;
        }
    }
    pthread_mutex_unlock(&optimized_interface_mutex);
    
    // 接口未找到
    *packets = 0;
    *bytes = 0;
    *dropped = 0;
    *errors = 0;
}

// 打印所有接口统计信息
void print_all_interface_stats(void) {
    pthread_mutex_lock(&optimized_interface_mutex);
    
    log_info("=== Interface Statistics ===");
    for (int i = 0; i < optimized_interface_count; i++) {
        optimized_interface_info_t *iface = &optimized_interfaces[i];
        log_info("Interface %s (index: %d, CPU: %d):", 
                iface->name, iface->ifindex, iface->cpu_id);
        log_info("  Packets captured: %lu", iface->packets_captured);
        log_info("  Bytes captured: %lu", iface->bytes_captured);
        log_info("  Packets dropped: %lu", iface->packets_dropped);
        log_info("  Packets error: %lu", iface->packets_error);
        log_info("  Status: %s", iface->is_active ? "Active" : "Inactive");
    }
    
    pthread_mutex_unlock(&optimized_interface_mutex);
}

// 清理接口资源
void cleanup_interface_resources(void) {
    pthread_mutex_lock(&optimized_interface_mutex);
    
    for (int i = 0; i < optimized_interface_count; i++) {
        optimized_interface_info_t *iface = &optimized_interfaces[i];
        
        if (iface->rb) {
            ring_buffer__free(iface->rb);
            iface->rb = NULL;
        }
        
        if (iface->link) {
            bpf_link__destroy(iface->link);
            iface->link = NULL;
        }
        
        if (iface->obj) {
            bpf_object__close(iface->obj);
            iface->obj = NULL;
        }
        
        iface->is_active = 0;
    }
    
    optimized_interface_count = 0;
    
    pthread_mutex_unlock(&optimized_interface_mutex);
    
    log_info("Cleaned up all interface resources");
}

// 检查接口是否有效
int is_valid_interface(const char *ifname) {
    int ifindex = if_nametoindex(ifname);
    return ifindex != 0;
}

// 获取接口的CPU亲和性
int get_interface_cpu_affinity(const char *ifname) {
    pthread_mutex_lock(&optimized_interface_mutex);
    
    for (int i = 0; i < optimized_interface_count; i++) {
        if (strcmp(optimized_interfaces[i].name, ifname) == 0) {
            int cpu_id = optimized_interfaces[i].cpu_id;
            pthread_mutex_unlock(&optimized_interface_mutex);
            return cpu_id;
        }
    }
    
    pthread_mutex_unlock(&optimized_interface_mutex);
    return -1; // 接口未找到
}

// 设置接口的CPU亲和性
int set_interface_cpu_affinity(const char *ifname, int cpu_id) {
    pthread_mutex_lock(&optimized_interface_mutex);
    
    for (int i = 0; i < optimized_interface_count; i++) {
        if (strcmp(optimized_interfaces[i].name, ifname) == 0) {
            optimized_interfaces[i].cpu_id = cpu_id;
            log_info("Set CPU affinity for interface %s to CPU %d", ifname, cpu_id);
            pthread_mutex_unlock(&optimized_interface_mutex);
            return 0;
        }
    }
    
    pthread_mutex_unlock(&optimized_interface_mutex);
    return -1; // 接口未找到
} 