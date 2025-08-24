#ifndef INTERFACE_MANAGER_H
#define INTERFACE_MANAGER_H

#include <stdint.h>
#include "loader.h"

// 接口管理函数声明
int get_available_interfaces(char interfaces[][IF_NAMESIZE], int max_count);
int get_available_interfaces_ex(char interfaces[][IF_NAMESIZE], int max_count, bool exclude_enp1s0);
int init_interface(const char *ifname, int thread_id);
int init_optimized_interface(const char *ifname, int cpu_id);
int get_optimized_interface_count(void);
optimized_interface_info_t *get_optimized_interface(int index);
void update_interface_stats(int ifindex, uint64_t packets, uint64_t bytes);
void get_interface_stats(int ifindex, uint64_t *packets, uint64_t *bytes, uint64_t *dropped, uint64_t *errors);
void print_all_interface_stats(void);
void cleanup_interface_resources(void);
int is_valid_interface(const char *ifname);
int get_interface_cpu_affinity(const char *ifname);
int set_interface_cpu_affinity(const char *ifname, int cpu_id);

#endif // INTERFACE_MANAGER_H 