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
#include <cjson/cJSON.h>

#define MAX_FILTER_RULES 1024
#define FILTER_TYPE_IP      1
#define FILTER_TYPE_PORT    2
#define FILTER_TYPE_PROTO   3
#define FILTER_TYPE_SUBNET  4

#define FILTER_ACTION_ALLOW 1
#define FILTER_ACTION_DENY  2

// 源地址范围配置结构
struct src_range_config {
    __u32 range_start;    // 允许的源地址范围开始
    __u32 range_end;      // 允许的源地址范围结束
    __u8 enabled;         // 是否启用范围检查
    __u8 reserved[3];     // 保留字段
} __attribute__((packed));

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

// JSON规则结构
struct json_rule {
    int id;
    char name[256];
    char type[32];
    char action[32];
    int priority;
    int enabled;
    char src_ip[64];
    char dst_ip[64];
    char src_subnet[64];
    char dst_subnet[64];
    int src_port_min;
    int src_port_max;
    int dst_port_min;
    int dst_port_max;
    int protocol;
    char description[512];
};

// 全局变量
static int filter_rules_map_fd = -1;
static int filter_config_map_fd = -1;
static int filter_stats_map_fd = -1;
static int src_range_map_fd = -1;

// 将IP地址字符串转换为网络字节序
static __u32 ip_str_to_addr(const char *ip_str) {
    struct in_addr addr;
    if (!ip_str || strlen(ip_str) == 0) return 0;
    if (inet_aton(ip_str, &addr) == 0) {
        return 0;
    }
    return addr.s_addr;
}

// 计算子网掩码
static __u32 cidr_to_mask(int cidr) {
    if (cidr == 0) return 0;
    if (cidr >= 32) return 0xFFFFFFFF;
    return htonl(~((1ULL << (32 - cidr)) - 1));
}

// 解析子网字符串
static int parse_subnet(const char *subnet_str, __u32 *ip, __u32 *mask) {
    if (!subnet_str || strlen(subnet_str) == 0) {
        *ip = 0;
        *mask = 0;
        return 0;
    }
    
    char subnet_copy[64];
    strncpy(subnet_copy, subnet_str, sizeof(subnet_copy) - 1);
    subnet_copy[sizeof(subnet_copy) - 1] = '\0';
    
    char *slash_pos = strchr(subnet_copy, '/');
    if (slash_pos) {
        *slash_pos = '\0';
        int cidr = atoi(slash_pos + 1);
        *mask = cidr_to_mask(cidr);
    } else {
        *mask = 0xFFFFFFFF; // 默认/32
    }
    
    *ip = ip_str_to_addr(subnet_copy);
    return 0;
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

    map = bpf_object__find_map_by_name(obj, "src_range_map");
    if (!map) {
        fprintf(stderr, "Failed to find src_range_map\n");
        bpf_object__close(obj);
        return -1;
    }
    src_range_map_fd = bpf_map__fd(map);

    printf("Filter manager initialized successfully\n");
    return 0;
}

// 解析JSON字符串获取字符串值
static const char* get_json_string(cJSON *obj, const char *key, const char *default_val) {
    cJSON *val_obj = cJSON_GetObjectItem(obj, key);
    if (val_obj && cJSON_IsString(val_obj)) {
        const char *str = cJSON_GetStringValue(val_obj);
        return str ? str : default_val;
    }
    return default_val;
}

// 解析JSON字符串获取整数值
static int get_json_int(cJSON *obj, const char *key, int default_val) {
    cJSON *val_obj = cJSON_GetObjectItem(obj, key);
    if (val_obj && cJSON_IsNumber(val_obj)) {
        return cJSON_GetNumberValue(val_obj);
    }
    return default_val;
}

// 解析JSON字符串获取布尔值
static int get_json_bool(cJSON *obj, const char *key, int default_val) {
    cJSON *val_obj = cJSON_GetObjectItem(obj, key);
    if (val_obj && cJSON_IsBool(val_obj)) {
        return cJSON_IsTrue(val_obj) ? 1 : 0;
    }
    return default_val;
}

// 将JSON规则转换为eBPF规则
static int json_rule_to_bpf_rule(struct json_rule *json_rule, struct filter_rule *bpf_rule) {
    memset(bpf_rule, 0, sizeof(*bpf_rule));
    
    // 设置规则类型
    if (strcmp(json_rule->type, "ip") == 0) {
        bpf_rule->type = FILTER_TYPE_IP;
    } else if (strcmp(json_rule->type, "port") == 0) {
        bpf_rule->type = FILTER_TYPE_PORT;
    } else if (strcmp(json_rule->type, "subnet") == 0) {
        bpf_rule->type = FILTER_TYPE_SUBNET;
    } else {
        fprintf(stderr, "Unknown rule type: %s\n", json_rule->type);
        return -1;
    }
    
    // 设置动作
    if (strcmp(json_rule->action, "allow") == 0) {
        bpf_rule->action = FILTER_ACTION_ALLOW;
    } else if (strcmp(json_rule->action, "deny") == 0) {
        bpf_rule->action = FILTER_ACTION_DENY;
    } else {
        fprintf(stderr, "Unknown action: %s\n", json_rule->action);
        return -1;
    }
    
    bpf_rule->priority = json_rule->priority;
    bpf_rule->protocol = json_rule->protocol;
    
    // 根据规则类型设置相应字段
    switch (bpf_rule->type) {
        case FILTER_TYPE_IP:
            bpf_rule->src_ip = ip_str_to_addr(json_rule->src_ip);
            bpf_rule->dst_ip = ip_str_to_addr(json_rule->dst_ip);
            bpf_rule->src_mask = bpf_rule->src_ip ? 0xFFFFFFFF : 0;
            bpf_rule->dst_mask = bpf_rule->dst_ip ? 0xFFFFFFFF : 0;
            break;
            
        case FILTER_TYPE_PORT:
            bpf_rule->src_port_min = json_rule->src_port_min;
            bpf_rule->src_port_max = json_rule->src_port_max ? json_rule->src_port_max : json_rule->src_port_min;
            bpf_rule->dst_port_min = json_rule->dst_port_min;
            bpf_rule->dst_port_max = json_rule->dst_port_max ? json_rule->dst_port_max : json_rule->dst_port_min;
            break;
            
        case FILTER_TYPE_SUBNET:
            parse_subnet(json_rule->src_subnet, &bpf_rule->src_ip, &bpf_rule->src_mask);
            parse_subnet(json_rule->dst_subnet, &bpf_rule->dst_ip, &bpf_rule->dst_mask);
            break;
    }
    
    return 0;
}

// 从JSON文件加载配置
int load_config_from_json(const char *json_file) {
    FILE *fp = fopen(json_file, "r");
    if (!fp) {
        fprintf(stderr, "Failed to open JSON file: %s\n", strerror(errno));
        return -1;
    }
    
    // 读取文件内容
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    
    char *json_string = malloc(file_size + 1);
    if (!json_string) {
        fprintf(stderr, "Failed to allocate memory\n");
        fclose(fp);
        return -1;
    }
    
    size_t read_size = fread(json_string, 1, file_size, fp);
    json_string[read_size] = '\0';
    fclose(fp);
    
    // 解析JSON
    cJSON *root = cJSON_Parse(json_string);
    free(json_string);
    
    if (!root) {
        const char *error_ptr = cJSON_GetErrorPtr();
        if (error_ptr != NULL) {
            fprintf(stderr, "JSON parse error before: %s\n", error_ptr);
        } else {
            fprintf(stderr, "Failed to parse JSON\n");
        }
        return -1;
    }
    
    // 解析过滤器配置
    cJSON *filter_config_obj = cJSON_GetObjectItem(root, "filter_config");
    if (filter_config_obj) {
        int enabled = get_json_bool(filter_config_obj, "enabled", 1);
        const char *default_action = get_json_string(filter_config_obj, "default_action", "allow");
        
        // 设置过滤器配置
        __u32 key = 0;
        struct filter_config config = {0};
        config.enabled = enabled ? 1 : 0;
        config.default_action = (strcmp(default_action, "allow") == 0) ? FILTER_ACTION_ALLOW : FILTER_ACTION_DENY;
        config.rule_count = 0;
        
        if (bpf_map_update_elem(filter_config_map_fd, &key, &config, BPF_ANY) != 0) {
            fprintf(stderr, "Failed to update filter config: %s\n", strerror(errno));
            cJSON_Delete(root);
            return -1;
        }
        
        printf("Filter configuration loaded: enabled=%s, default_action=%s\n",
               enabled ? "true" : "false", default_action);
    }
    
    // 解析源地址范围配置
    cJSON *src_range_obj = cJSON_GetObjectItem(root, "src_range");
    if (src_range_obj) {
        int range_enabled = get_json_bool(src_range_obj, "enabled", 0);
        const char *start_ip = get_json_string(src_range_obj, "start_ip", "");
        const char *end_ip = get_json_string(src_range_obj, "end_ip", "");
        
        struct src_range_config range_config = {0};
        range_config.enabled = range_enabled ? 1 : 0;
        range_config.range_start = ip_str_to_addr(start_ip);
        range_config.range_end = ip_str_to_addr(end_ip);
        
        __u32 range_key = 0;
        if (bpf_map_update_elem(src_range_map_fd, &range_key, &range_config, BPF_ANY) != 0) {
            fprintf(stderr, "Failed to update src range config: %s\n", strerror(errno));
            cJSON_Delete(root);
            return -1;
        }
        
        printf("Source range configuration loaded: enabled=%s, range=%s-%s\n",
               range_enabled ? "true" : "false", start_ip, end_ip);
    }
    
    // 解析规则
    cJSON *rules_array = cJSON_GetObjectItem(root, "rules");
    if (rules_array && cJSON_IsArray(rules_array)) {
        int rules_count = cJSON_GetArraySize(rules_array);
        int active_rules = 0;
        
        printf("Loading %d rules from JSON...\n", rules_count);
        
        for (int i = 0; i < rules_count && active_rules < MAX_FILTER_RULES; i++) {
            cJSON *rule_obj = cJSON_GetArrayItem(rules_array, i);
            if (!rule_obj) continue;
            
            // 解析JSON规则
            struct json_rule json_rule = {0};
            json_rule.id = get_json_int(rule_obj, "id", 0);
            strncpy(json_rule.name, get_json_string(rule_obj, "name", ""), sizeof(json_rule.name) - 1);
            strncpy(json_rule.type, get_json_string(rule_obj, "type", ""), sizeof(json_rule.type) - 1);
            strncpy(json_rule.action, get_json_string(rule_obj, "action", "allow"), sizeof(json_rule.action) - 1);
            json_rule.priority = get_json_int(rule_obj, "priority", 100);
            json_rule.enabled = get_json_bool(rule_obj, "enabled", 1);
            
            // 如果规则被禁用，跳过
            if (!json_rule.enabled) {
                printf("Skipping disabled rule %d: %s\n", json_rule.id, json_rule.name);
                continue;
            }
            
            strncpy(json_rule.src_ip, get_json_string(rule_obj, "src_ip", ""), sizeof(json_rule.src_ip) - 1);
            strncpy(json_rule.dst_ip, get_json_string(rule_obj, "dst_ip", ""), sizeof(json_rule.dst_ip) - 1);
            strncpy(json_rule.src_subnet, get_json_string(rule_obj, "src_subnet", ""), sizeof(json_rule.src_subnet) - 1);
            strncpy(json_rule.dst_subnet, get_json_string(rule_obj, "dst_subnet", ""), sizeof(json_rule.dst_subnet) - 1);
            json_rule.src_port_min = get_json_int(rule_obj, "src_port_min", 0);
            json_rule.src_port_max = get_json_int(rule_obj, "src_port_max", 0);
            json_rule.dst_port_min = get_json_int(rule_obj, "dst_port_min", 0);
            json_rule.dst_port_max = get_json_int(rule_obj, "dst_port_max", 0);
            json_rule.protocol = get_json_int(rule_obj, "protocol", 0);
            strncpy(json_rule.description, get_json_string(rule_obj, "description", ""), sizeof(json_rule.description) - 1);
            
            // 转换为eBPF规则
            struct filter_rule bpf_rule;
            if (json_rule_to_bpf_rule(&json_rule, &bpf_rule) != 0) {
                fprintf(stderr, "Failed to convert rule %d\n", json_rule.id);
                continue;
            }
            
            // 添加规则到eBPF map
            __u32 rule_key = active_rules;
            if (bpf_map_update_elem(filter_rules_map_fd, &rule_key, &bpf_rule, BPF_ANY) != 0) {
                fprintf(stderr, "Failed to add rule %d: %s\n", json_rule.id, strerror(errno));
                continue;
            }
            
            printf("Added rule %d: %s (type=%s, action=%s, priority=%d)\n",
                   json_rule.id, json_rule.name, json_rule.type, json_rule.action, json_rule.priority);
            
            active_rules++;
        }
        
        // 更新规则计数
        __u32 key = 0;
        struct filter_config config = {0};
        if (bpf_map_lookup_elem(filter_config_map_fd, &key, &config) == 0) {
            config.rule_count = active_rules;
            if (bpf_map_update_elem(filter_config_map_fd, &key, &config, BPF_ANY) != 0) {
                fprintf(stderr, "Failed to update rule count: %s\n", strerror(errno));
            }
        }
        
        printf("Successfully loaded %d active rules\n", active_rules);
    }
    
    cJSON_Delete(root);
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

// 显示过滤统计
int filter_show_stats() {
    __u64 stats[6] = {0};
    
    for (int i = 0; i < 6; i++) {
        __u32 key = i;
        bpf_map_lookup_elem(filter_stats_map_fd, &key, &stats[i]);
    }
    
    printf("Filter Statistics:\n");
    printf("  Allowed packets: %llu\n", stats[0]);
    printf("  Denied packets: %llu\n", stats[1]);
    printf("  Total packets: %llu\n", stats[2]);
    printf("  Rule hits: %llu\n", stats[3]);
    printf("  Out-of-range source IPs: %llu\n", stats[4]);
    printf("  In-range source IPs: %llu\n", stats[5]);
    
    if (stats[2] > 0) {
        printf("  Allow rate: %.2f%%\n", (double)stats[0] / stats[2] * 100);
        printf("  Deny rate: %.2f%%\n", (double)stats[1] / stats[2] * 100);
        printf("  Hit rate: %.2f%%\n", (double)stats[3] / stats[2] * 100);
        if (stats[4] + stats[5] > 0) {
            printf("  In-range rate: %.2f%%\n", (double)stats[5] / (stats[4] + stats[5]) * 100);
            printf("  Out-of-range rate: %.2f%%\n", (double)stats[4] / (stats[4] + stats[5]) * 100);
        }
    }
    
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

// 打印使用帮助
void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("Options:\n");
    printf("  -i <bpf_obj>     Initialize with BPF object file\n");
    printf("  -f <json_file>   Load configuration from JSON file\n");
    printf("  -s               Show configuration\n");
    printf("  -t               Show statistics\n");
    printf("  -c               Clear all rules\n");
    printf("  -h               Show this help\n");
    printf("\nExamples:\n");
    printf("  %s -i bpf_program.o -f filter_config.json\n", prog_name);
    printf("  %s -i bpf_program.o -s\n", prog_name);
    printf("  %s -i bpf_program.o -t\n", prog_name);
}

int main(int argc, char **argv) {
    int opt;
    char *bpf_obj_path = NULL;
    char *json_file = NULL;
    
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    while ((opt = getopt(argc, argv, "i:f:scth")) != -1) {
        switch (opt) {
            case 'i':
                bpf_obj_path = optarg;
                if (filter_manager_init(bpf_obj_path) != 0) {
                    return 1;
                }
                break;
                
            case 'f':
                if (filter_rules_map_fd == -1) {
                    fprintf(stderr, "Please initialize first with -i option\n");
                    return 1;
                }
                json_file = optarg;
                if (load_config_from_json(json_file) != 0) {
                    return 1;
                }
                break;
                
            case 's':
                if (filter_rules_map_fd == -1) {
                    fprintf(stderr, "Please initialize first with -i option\n");
                    return 1;
                }
                filter_show_config();
                break;
                
            case 't':
                if (filter_rules_map_fd == -1) {
                    fprintf(stderr, "Please initialize first with -i option\n");
                    return 1;
                }
                filter_show_stats();
                break;
                
            case 'c':
                if (filter_rules_map_fd == -1) {
                    fprintf(stderr, "Please initialize first with -i option\n");
                    return 1;
                }
                filter_clear_rules();
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