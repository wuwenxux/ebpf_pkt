#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define MAX_FILTER_RULES 1024
#define FILTER_TYPE_IP      1
#define FILTER_TYPE_PORT    2
#define FILTER_TYPE_PROTO   3
#define FILTER_TYPE_SUBNET  4

#define FILTER_ACTION_ALLOW 1
#define FILTER_ACTION_DENY  2

// 过滤规则结构 (与eBPF程序中的结构保持一致)
struct filter_rule {
    __u8 type;
    __u8 action;
    __u8 protocol;
    __u8 reserved;
    __u32 src_ip;
    __u32 dst_ip;
    __u32 src_mask;
    __u32 dst_mask;
    __u16 src_port_min;
    __u16 src_port_max;
    __u16 dst_port_min;
    __u16 dst_port_max;
    __u32 priority;
} __attribute__((packed));

// 过滤配置结构
struct filter_config {
    __u8 enabled;
    __u8 default_action;
    __u16 rule_count;
} __attribute__((packed));

// 全局变量
static int filter_rules_map_fd = -1;
static int filter_config_map_fd = -1;
static int filter_stats_map_fd = -1;

// 将IP地址字符串转换为网络字节序
static __u32 ip_str_to_addr(const char *ip_str) {
    struct in_addr addr;
    if (inet_aton(ip_str, &addr) == 0) {
        return 0;
    }
    return addr.s_addr;
}

// 将网络字节序IP地址转换为字符串
static void ip_addr_to_str(__u32 ip_addr, char *ip_str, size_t len) {
    struct in_addr addr;
    addr.s_addr = ip_addr;
    strncpy(ip_str, inet_ntoa(addr), len - 1);
    ip_str[len - 1] = '\0';
}

// 计算子网掩码
static __u32 cidr_to_mask(int cidr) {
    if (cidr == 0) return 0;
    if (cidr >= 32) return 0xFFFFFFFF;
    return htonl(~((1ULL << (32 - cidr)) - 1));
}

// 初始化过滤器管理器
int filter_manager_init(const char *bpf_obj_path) {
    struct bpf_object *obj;
    struct bpf_map *map;
    int err;

    // 加载BPF对象
    obj = bpf_object__open(bpf_obj_path);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object: %s\n", strerror(errno));
        return -1;
    }

    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "Failed to load BPF object: %s\n", strerror(-err));
        bpf_object__close(obj);
        return -1;
    }

    // 获取map文件描述符
    map = bpf_object__find_map_by_name(obj, "filter_rules_map");
    if (!map) {
        fprintf(stderr, "Failed to find filter_rules_map\n");
        bpf_object__close(obj);
        return -1;
    }
    filter_rules_map_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(obj, "filter_config_map");
    if (!map) {
        fprintf(stderr, "Failed to find filter_config_map\n");
        bpf_object__close(obj);
        return -1;
    }
    filter_config_map_fd = bpf_map__fd(map);

    map = bpf_object__find_map_by_name(obj, "filter_stats_map");
    if (!map) {
        fprintf(stderr, "Failed to find filter_stats_map\n");
        bpf_object__close(obj);
        return -1;
    }
    filter_stats_map_fd = bpf_map__fd(map);

    printf("Filter manager initialized successfully\n");
    return 0;
}

// 启用/禁用过滤器
int filter_set_enabled(int enabled) {
    __u32 key = 0;
    struct filter_config config = {0};
    
    // 先读取当前配置
    if (bpf_map_lookup_elem(filter_config_map_fd, &key, &config) != 0) {
        // 如果没有配置，使用默认值
        config.enabled = 0;
        config.default_action = FILTER_ACTION_ALLOW;
        config.rule_count = 0;
    }
    
    config.enabled = enabled ? 1 : 0;
    
    if (bpf_map_update_elem(filter_config_map_fd, &key, &config, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update filter config: %s\n", strerror(errno));
        return -1;
    }
    
    printf("Filter %s\n", enabled ? "enabled" : "disabled");
    return 0;
}

// 设置默认动作
int filter_set_default_action(int action) {
    __u32 key = 0;
    struct filter_config config = {0};
    
    // 先读取当前配置
    if (bpf_map_lookup_elem(filter_config_map_fd, &key, &config) != 0) {
        config.enabled = 0;
        config.default_action = FILTER_ACTION_ALLOW;
        config.rule_count = 0;
    }
    
    config.default_action = action;
    
    if (bpf_map_update_elem(filter_config_map_fd, &key, &config, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update filter config: %s\n", strerror(errno));
        return -1;
    }
    
    printf("Default action set to %s\n", action == FILTER_ACTION_ALLOW ? "ALLOW" : "DENY");
    return 0;
}

// 添加IP过滤规则
int filter_add_ip_rule(const char *src_ip, const char *dst_ip, int action, int priority) {
    __u32 key = 0;
    struct filter_config config = {0};
    struct filter_rule rule = {0};
    
    // 读取当前配置
    if (bpf_map_lookup_elem(filter_config_map_fd, &key, &config) != 0) {
        config.enabled = 0;
        config.default_action = FILTER_ACTION_ALLOW;
        config.rule_count = 0;
    }
    
    if (config.rule_count >= MAX_FILTER_RULES) {
        fprintf(stderr, "Maximum number of rules reached\n");
        return -1;
    }
    
    // 设置规则
    rule.type = FILTER_TYPE_IP;
    rule.action = action;
    rule.protocol = 0; // 所有协议
    rule.priority = priority;
    
    if (src_ip && strlen(src_ip) > 0) {
        rule.src_ip = ip_str_to_addr(src_ip);
        rule.src_mask = 0xFFFFFFFF; // 精确匹配
    }
    
    if (dst_ip && strlen(dst_ip) > 0) {
        rule.dst_ip = ip_str_to_addr(dst_ip);
        rule.dst_mask = 0xFFFFFFFF; // 精确匹配
    }
    
    // 添加规则到map
    __u32 rule_key = config.rule_count;
    if (bpf_map_update_elem(filter_rules_map_fd, &rule_key, &rule, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to add rule: %s\n", strerror(errno));
        return -1;
    }
    
    // 更新规则计数
    config.rule_count++;
    if (bpf_map_update_elem(filter_config_map_fd, &key, &config, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update rule count: %s\n", strerror(errno));
        return -1;
    }
    
    printf("Added IP rule: src=%s dst=%s action=%s priority=%d\n",
           src_ip ? src_ip : "any", dst_ip ? dst_ip : "any",
           action == FILTER_ACTION_ALLOW ? "ALLOW" : "DENY", priority);
    return 0;
}

// 添加端口过滤规则
int filter_add_port_rule(int src_port_min, int src_port_max, 
                        int dst_port_min, int dst_port_max, 
                        int protocol, int action, int priority) {
    __u32 key = 0;
    struct filter_config config = {0};
    struct filter_rule rule = {0};
    
    // 读取当前配置
    if (bpf_map_lookup_elem(filter_config_map_fd, &key, &config) != 0) {
        config.enabled = 0;
        config.default_action = FILTER_ACTION_ALLOW;
        config.rule_count = 0;
    }
    
    if (config.rule_count >= MAX_FILTER_RULES) {
        fprintf(stderr, "Maximum number of rules reached\n");
        return -1;
    }
    
    // 设置规则
    rule.type = FILTER_TYPE_PORT;
    rule.action = action;
    rule.protocol = protocol;
    rule.priority = priority;
    rule.src_port_min = src_port_min;
    rule.src_port_max = src_port_max ? src_port_max : src_port_min;
    rule.dst_port_min = dst_port_min;
    rule.dst_port_max = dst_port_max ? dst_port_max : dst_port_min;
    
    // 添加规则到map
    __u32 rule_key = config.rule_count;
    if (bpf_map_update_elem(filter_rules_map_fd, &rule_key, &rule, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to add rule: %s\n", strerror(errno));
        return -1;
    }
    
    // 更新规则计数
    config.rule_count++;
    if (bpf_map_update_elem(filter_config_map_fd, &key, &config, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update rule count: %s\n", strerror(errno));
        return -1;
    }
    
    printf("Added port rule: src_port=%d-%d dst_port=%d-%d protocol=%d action=%s priority=%d\n",
           src_port_min, rule.src_port_max, dst_port_min, rule.dst_port_max,
           protocol, action == FILTER_ACTION_ALLOW ? "ALLOW" : "DENY", priority);
    return 0;
}

// 添加子网过滤规则
int filter_add_subnet_rule(const char *src_subnet, const char *dst_subnet, 
                          int action, int priority) {
    __u32 key = 0;
    struct filter_config config = {0};
    struct filter_rule rule = {0};
    char ip_str[32], *slash_pos;
    int cidr;
    
    // 读取当前配置
    if (bpf_map_lookup_elem(filter_config_map_fd, &key, &config) != 0) {
        config.enabled = 0;
        config.default_action = FILTER_ACTION_ALLOW;
        config.rule_count = 0;
    }
    
    if (config.rule_count >= MAX_FILTER_RULES) {
        fprintf(stderr, "Maximum number of rules reached\n");
        return -1;
    }
    
    // 设置规则
    rule.type = FILTER_TYPE_SUBNET;
    rule.action = action;
    rule.protocol = 0; // 所有协议
    rule.priority = priority;
    
    // 解析源子网
    if (src_subnet && strlen(src_subnet) > 0) {
        strncpy(ip_str, src_subnet, sizeof(ip_str) - 1);
        ip_str[sizeof(ip_str) - 1] = '\0';
        
        slash_pos = strchr(ip_str, '/');
        if (slash_pos) {
            *slash_pos = '\0';
            cidr = atoi(slash_pos + 1);
            rule.src_mask = cidr_to_mask(cidr);
        } else {
            rule.src_mask = 0xFFFFFFFF; // 默认/32
        }
        rule.src_ip = ip_str_to_addr(ip_str);
    }
    
    // 解析目的子网
    if (dst_subnet && strlen(dst_subnet) > 0) {
        strncpy(ip_str, dst_subnet, sizeof(ip_str) - 1);
        ip_str[sizeof(ip_str) - 1] = '\0';
        
        slash_pos = strchr(ip_str, '/');
        if (slash_pos) {
            *slash_pos = '\0';
            cidr = atoi(slash_pos + 1);
            rule.dst_mask = cidr_to_mask(cidr);
        } else {
            rule.dst_mask = 0xFFFFFFFF; // 默认/32
        }
        rule.dst_ip = ip_str_to_addr(ip_str);
    }
    
    // 添加规则到map
    __u32 rule_key = config.rule_count;
    if (bpf_map_update_elem(filter_rules_map_fd, &rule_key, &rule, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to add rule: %s\n", strerror(errno));
        return -1;
    }
    
    // 更新规则计数
    config.rule_count++;
    if (bpf_map_update_elem(filter_config_map_fd, &key, &config, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to update rule count: %s\n", strerror(errno));
        return -1;
    }
    
    printf("Added subnet rule: src=%s dst=%s action=%s priority=%d\n",
           src_subnet ? src_subnet : "any", dst_subnet ? dst_subnet : "any",
           action == FILTER_ACTION_ALLOW ? "ALLOW" : "DENY", priority);
    return 0;
}

// 清除所有规则
int filter_clear_rules() {
    __u32 key = 0;
    struct filter_config config = {0};
    
    // 读取当前配置
    if (bpf_map_lookup_elem(filter_config_map_fd, &key, &config) != 0) {
        config.enabled = 0;
        config.default_action = FILTER_ACTION_ALLOW;
    }
    
    config.rule_count = 0;
    
    if (bpf_map_update_elem(filter_config_map_fd, &key, &config, BPF_ANY) != 0) {
        fprintf(stderr, "Failed to clear rules: %s\n", strerror(errno));
        return -1;
    }
    
    printf("All rules cleared\n");
    return 0;
}

// 显示当前配置
int filter_show_config() {
    __u32 key = 0;
    struct filter_config config = {0};
    
    if (bpf_map_lookup_elem(filter_config_map_fd, &key, &config) != 0) {
        printf("No filter configuration found\n");
        return 0;
    }
    
    printf("Filter Configuration:\n");
    printf("  Enabled: %s\n", config.enabled ? "Yes" : "No");
    printf("  Default Action: %s\n", config.default_action == FILTER_ACTION_ALLOW ? "ALLOW" : "DENY");
    printf("  Rule Count: %d\n", config.rule_count);
    
    return 0;
}

// 显示所有规则
int filter_show_rules() {
    __u32 key = 0;
    struct filter_config config = {0};
    struct filter_rule rule;
    char src_ip[32], dst_ip[32];
    
    if (bpf_map_lookup_elem(filter_config_map_fd, &key, &config) != 0) {
        printf("No filter configuration found\n");
        return 0;
    }
    
    printf("Filter Rules (%d total):\n", config.rule_count);
    printf("%-4s %-8s %-8s %-15s %-15s %-10s %-10s %-8s %-8s\n",
           "ID", "Type", "Action", "Src IP", "Dst IP", "Src Port", "Dst Port", "Protocol", "Priority");
    printf("%-4s %-8s %-8s %-15s %-15s %-10s %-10s %-8s %-8s\n",
           "----", "--------", "--------", "---------------", "---------------", 
           "----------", "----------", "--------", "--------");
    
    for (__u32 i = 0; i < config.rule_count; i++) {
        if (bpf_map_lookup_elem(filter_rules_map_fd, &i, &rule) == 0) {
            // 转换IP地址
            if (rule.src_ip) {
                ip_addr_to_str(rule.src_ip, src_ip, sizeof(src_ip));
            } else {
                strcpy(src_ip, "any");
            }
            
            if (rule.dst_ip) {
                ip_addr_to_str(rule.dst_ip, dst_ip, sizeof(dst_ip));
            } else {
                strcpy(dst_ip, "any");
            }
            
            printf("%-4d %-8s %-8s %-15s %-15s %-10s %-10s %-8d %-8d\n",
                   i,
                   rule.type == FILTER_TYPE_IP ? "IP" :
                   rule.type == FILTER_TYPE_PORT ? "PORT" :
                   rule.type == FILTER_TYPE_SUBNET ? "SUBNET" : "UNKNOWN",
                   rule.action == FILTER_ACTION_ALLOW ? "ALLOW" : "DENY",
                   src_ip, dst_ip,
                   rule.src_port_min ? (rule.src_port_max ? 
                       (snprintf(src_ip, sizeof(src_ip), "%d-%d", rule.src_port_min, rule.src_port_max), src_ip) :
                       (snprintf(src_ip, sizeof(src_ip), "%d", rule.src_port_min), src_ip)) : "any",
                   rule.dst_port_min ? (rule.dst_port_max ? 
                       (snprintf(dst_ip, sizeof(dst_ip), "%d-%d", rule.dst_port_min, rule.dst_port_max), dst_ip) :
                       (snprintf(dst_ip, sizeof(dst_ip), "%d", rule.dst_port_min), dst_ip)) : "any",
                   rule.protocol,
                   rule.priority);
        }
    }
    
    return 0;
}

// 显示过滤统计
int filter_show_stats() {
    __u64 stats[4] = {0};
    
    for (int i = 0; i < 4; i++) {
        __u32 key = i;
        bpf_map_lookup_elem(filter_stats_map_fd, &key, &stats[i]);
    }
    
    printf("Filter Statistics:\n");
    printf("  Allowed packets: %llu\n", stats[0]);
    printf("  Denied packets: %llu\n", stats[1]);
    printf("  Total packets: %llu\n", stats[2]);
    printf("  Rule hits: %llu\n", stats[3]);
    
    if (stats[2] > 0) {
        printf("  Allow rate: %.2f%%\n", (double)stats[0] / stats[2] * 100);
        printf("  Deny rate: %.2f%%\n", (double)stats[1] / stats[2] * 100);
        printf("  Hit rate: %.2f%%\n", (double)stats[3] / stats[2] * 100);
    }
    
    return 0;
}

// 打印使用帮助
void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Options:\n");
    printf("  -i <bpf_obj>     Initialize with BPF object file\n");
    printf("  -e <0|1>         Enable/disable filter (0=disable, 1=enable)\n");
    printf("  -d <allow|deny>  Set default action\n");
    printf("  -a ip <src_ip> <dst_ip> <allow|deny> <priority>\n");
    printf("                   Add IP filter rule\n");
    printf("  -a port <src_min> <src_max> <dst_min> <dst_max> <proto> <allow|deny> <priority>\n");
    printf("                   Add port filter rule\n");
    printf("  -a subnet <src_subnet> <dst_subnet> <allow|deny> <priority>\n");
    printf("                   Add subnet filter rule\n");
    printf("  -c               Clear all rules\n");
    printf("  -s               Show configuration\n");
    printf("  -r               Show rules\n");
    printf("  -t               Show statistics\n");
    printf("  -h               Show this help\n");
    printf("\nExamples:\n");
    printf("  %s -i bpf_program.o -e 1\n", prog_name);
    printf("  %s -a ip 192.168.1.100 \"\" deny 10\n", prog_name);
    printf("  %s -a port 0 0 80 80 6 allow 20\n", prog_name);
    printf("  %s -a subnet 192.168.1.0/24 \"\" allow 30\n", prog_name);
}

int main(int argc, char **argv) {
    int opt;
    char *bpf_obj_path = NULL;
    
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    while ((opt = getopt(argc, argv, "i:e:d:a:csrth")) != -1) {
        switch (opt) {
            case 'i':
                bpf_obj_path = optarg;
                if (filter_manager_init(bpf_obj_path) != 0) {
                    return 1;
                }
                break;
                
            case 'e':
                if (filter_rules_map_fd == -1) {
                    fprintf(stderr, "Please initialize first with -i option\n");
                    return 1;
                }
                filter_set_enabled(atoi(optarg));
                break;
                
            case 'd':
                if (filter_rules_map_fd == -1) {
                    fprintf(stderr, "Please initialize first with -i option\n");
                    return 1;
                }
                if (strcmp(optarg, "allow") == 0) {
                    filter_set_default_action(FILTER_ACTION_ALLOW);
                } else if (strcmp(optarg, "deny") == 0) {
                    filter_set_default_action(FILTER_ACTION_DENY);
                } else {
                    fprintf(stderr, "Invalid default action: %s\n", optarg);
                    return 1;
                }
                break;
                
            case 'c':
                if (filter_rules_map_fd == -1) {
                    fprintf(stderr, "Please initialize first with -i option\n");
                    return 1;
                }
                filter_clear_rules();
                break;
                
            case 's':
                if (filter_rules_map_fd == -1) {
                    fprintf(stderr, "Please initialize first with -i option\n");
                    return 1;
                }
                filter_show_config();
                break;
                
            case 'r':
                if (filter_rules_map_fd == -1) {
                    fprintf(stderr, "Please initialize first with -i option\n");
                    return 1;
                }
                filter_show_rules();
                break;
                
            case 't':
                if (filter_rules_map_fd == -1) {
                    fprintf(stderr, "Please initialize first with -i option\n");
                    return 1;
                }
                filter_show_stats();
                break;
                
            case 'h':
                print_usage(argv[0]);
                return 0;
                
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    return 0;
} 