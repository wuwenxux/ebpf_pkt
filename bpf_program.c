#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/stddef.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#define BATCH_SIZE 32
#define FLUSH_TIMEOUT_NS 1000000 // 1毫秒
#define MAX_FILTER_RULES 1024    // 最大过滤规则数量

// TCP标志位常量定义
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80

// 过滤规则类型
#define FILTER_TYPE_IP      1    // IP地址过滤
#define FILTER_TYPE_PORT    2    // 端口过滤
#define FILTER_TYPE_PROTO   3    // 协议过滤
#define FILTER_TYPE_SUBNET  4    // 子网过滤

// 过滤动作
#define FILTER_ACTION_ALLOW 1    // 允许
#define FILTER_ACTION_DENY  2    // 拒绝

// 过滤规则结构
struct filter_rule {
    __u8 type;          // 过滤类型
    __u8 action;        // 过滤动作 (ALLOW/DENY)
    __u8 protocol;      // 协议 (0表示所有协议)
    __u8 reserved;      // 保留字段
    __u32 src_ip;       // 源IP (网络字节序)
    __u32 dst_ip;       // 目的IP (网络字节序)
    __u32 src_mask;     // 源IP掩码
    __u32 dst_mask;     // 目的IP掩码
    __u16 src_port_min; // 源端口范围最小值
    __u16 src_port_max; // 源端口范围最大值
    __u16 dst_port_min; // 目的端口范围最小值
    __u16 dst_port_max; // 目的端口范围最大值
    __u32 priority;     // 优先级 (数值越小优先级越高)
} __attribute__((packed));

// 过滤配置结构
struct filter_config {
    __u8 enabled;       // 是否启用过滤
    __u8 default_action; // 默认动作 (ALLOW/DENY)
    __u16 rule_count;   // 规则数量
} __attribute__((packed));

// 源地址范围配置
struct src_range_config {
    __u32 range_start;    // 允许的源地址范围开始
    __u32 range_end;      // 允许的源地址范围结束
    __u8 enabled;         // 是否启用范围检查
    __u8 reserved[3];     // 保留字段
} __attribute__((packed));

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

// 过滤规则map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct filter_rule));
    __uint(max_entries, MAX_FILTER_RULES);
} filter_rules_map SEC(".maps");

// 过滤配置map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct filter_config));
    __uint(max_entries, 1);
} filter_config_map SEC(".maps");

// 过滤统计map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 6); // 0:允许包数, 1:拒绝包数, 2:总包数, 3:过滤规则命中数, 4:范围外源地址数, 5:范围内源地址数
} filter_stats_map SEC(".maps");

// 源地址范围配置map
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct src_range_config));
    __uint(max_entries, 1);
} src_range_map SEC(".maps");

struct packet_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u32 pkt_len;
    __u64 timestamp;
     __u8 tcp_flags;
} __attribute__((packed));


struct batch_data {
    struct packet_info pkts[BATCH_SIZE];
    __u32 count;
    __u64 last_flush;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(struct batch_data)); // 400 bytes
    __uint(max_entries, 1);
} batch_map SEC(".maps");

// 更新过滤统计
static __always_inline void update_filter_stats(__u32 index) {
    __u64 *count = bpf_map_lookup_elem(&filter_stats_map, &index);
    if (count) {
        __sync_fetch_and_add(count, 1);
    }
}

// 检查IP是否匹配规则
static __always_inline int match_ip(__u32 ip, __u32 rule_ip, __u32 mask) {
    if (mask == 0) return 1; // 0掩码表示匹配所有
    return (ip & mask) == (rule_ip & mask);
}

// 检查端口是否在范围内
static __always_inline int match_port(__u16 port, __u16 min_port, __u16 max_port) {
    if (min_port == 0 && max_port == 0) return 1; // 0表示匹配所有端口
    if (max_port == 0) max_port = min_port; // 如果只设置了最小值，则表示精确匹配
    return port >= min_port && port <= max_port;
}

// 检查数据包是否匹配过滤规则
static __always_inline int check_filter_rule(struct filter_rule *rule, 
                                            __u32 src_ip, __u32 dst_ip,
                                            __u16 src_port, __u16 dst_port,
                                            __u8 protocol) {
    // 检查协议
    if (rule->protocol != 0 && rule->protocol != protocol) {
        return 0;
    }
    
    // 检查源IP
    if (!match_ip(src_ip, rule->src_ip, rule->src_mask)) {
        return 0;
    }
    
    // 检查目的IP
    if (!match_ip(dst_ip, rule->dst_ip, rule->dst_mask)) {
        return 0;
    }
    
    // 检查源端口
    if (!match_port(src_port, rule->src_port_min, rule->src_port_max)) {
        return 0;
    }
    
    // 检查目的端口
    if (!match_port(dst_port, rule->dst_port_min, rule->dst_port_max)) {
        return 0;
    }
    
    return 1; // 匹配
}

// 检查源地址是否在允许范围内
static __always_inline int check_src_range(__u32 src_ip) {
    __u32 range_key = 0;
    struct src_range_config *range_config = bpf_map_lookup_elem(&src_range_map, &range_key);
    
    if (!range_config || !range_config->enabled) {
        return 1; // 如果未配置范围检查，默认允许
    }
    
    // 转换为主机字节序进行比较
    __u32 src_host = bpf_ntohl(src_ip);
    __u32 start_host = bpf_ntohl(range_config->range_start);
    __u32 end_host = bpf_ntohl(range_config->range_end);
    
    if (src_host >= start_host && src_host <= end_host) {
        // 范围内地址统计
        __u32 in_range_key = 5;
        update_filter_stats(in_range_key);
        return 1;
    } else {
        // 范围外地址统计
        __u32 out_range_key = 4;
        update_filter_stats(out_range_key);
        return 0;
    }
}

// 应用过滤规则
static __always_inline int apply_packet_filter(__u32 src_ip, __u32 dst_ip,
                                              __u16 src_port, __u16 dst_port,
                                              __u8 protocol) {
    __u32 config_key = 0;
    struct filter_config *config = bpf_map_lookup_elem(&filter_config_map, &config_key);
    
    // 如果过滤未启用，默认允许
    if (!config || !config->enabled) {
        return FILTER_ACTION_ALLOW;
    }
    
    // 更新总包数统计
    __u32 total_key = 2;
    update_filter_stats(total_key);
    
    // 检查源地址范围
    if (!check_src_range(src_ip)) {
        // 源地址不在允许范围内，拒绝
        __u32 deny_key = 1;
        update_filter_stats(deny_key);
        return FILTER_ACTION_DENY;
    }
    
    // 简化规则检查 - 只检查第一个规则
    __u32 rule_key = 0;
    struct filter_rule *rule = bpf_map_lookup_elem(&filter_rules_map, &rule_key);
    if (rule && check_filter_rule(rule, src_ip, dst_ip, src_port, dst_port, protocol)) {
        // 规则匹配，更新统计
        __u32 hit_key = 3;
        update_filter_stats(hit_key);
        
        // 更新允许/拒绝统计
        if (rule->action == FILTER_ACTION_ALLOW) {
            __u32 allow_key = 0;
            update_filter_stats(allow_key);
        } else {
            __u32 deny_key = 1;
            update_filter_stats(deny_key);
        }
        
        return rule->action;
    }
    
    // 没有匹配的规则，使用默认动作
    if (config->default_action == FILTER_ACTION_ALLOW) {
        __u32 allow_key = 0;
        update_filter_stats(allow_key);
    } else {
        __u32 deny_key = 1;
        update_filter_stats(deny_key);
    }
    
    return config->default_action;
}

static __always_inline int is_valid_packet(struct iphdr *ip) {
    // 检查IP地址是否有效（排除0.0.0.0和广播地址）
    if (ip->saddr == 0 || ip->daddr == 0 || 
        ip->saddr == 0xFFFFFFFF || ip->daddr == 0xFFFFFFFF)
        return 0;
    
    // 检查是否为多播地址（224.0.0.0/4）
    if ((bpf_ntohl(ip->daddr) & 0xF0000000) == 0xE0000000)
        return 0;
    
    // 检查是否为链路本地地址（169.254.0.0/16）
    if ((bpf_ntohl(ip->saddr) & 0xFFFF0000) == 0xA9FE0000 ||
        (bpf_ntohl(ip->daddr) & 0xFFFF0000) == 0xA9FE0000)
        return 0;
    
    // 检查协议类型
    switch (ip->protocol) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_ICMP:
            break;
        default:
            return 0;
    }
    
    // 检查包长度
    __u16 len = bpf_ntohs(ip->tot_len);
    if (len < sizeof(struct iphdr) || len > 1500)
        return 0;
    
    // 检查IP头部长度
    if (ip->ihl < 5)
        return 0;
    
    return 1;
}

static __always_inline int is_loopback(__u32 saddr, __u32 daddr) {
    return (saddr & 0xFF000000) == 0x7F000000 || 
           (daddr & 0xFF000000) == 0x7F000000;
}

static __always_inline void submit_batch(struct xdp_md *ctx, struct batch_data *batch) {
    if (batch->count > 0) {
        // 显式限制 count 不超过 BATCH_SIZE
        __u32 count = batch->count;
        if (count > BATCH_SIZE)
            count = BATCH_SIZE;
        
        __u32 max_size = sizeof(struct batch_data);
        __u32 data_size = offsetof(struct batch_data, pkts);
        
        // 使用安全的方式计算数据大小，避免整数溢出
        data_size += count * sizeof(struct packet_info);
        
        // 显式边界检查，使验证器满意
        if (data_size > max_size)
            data_size = max_size;
        
        // 使用 & 操作符来限制范围，这是验证器最喜欢的方式
        data_size &= (max_size - 1) | max_size;
        
        bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, 
                             batch, data_size);
        batch->count = 0;
        batch->last_flush = bpf_ktime_get_ns();
    }
}

SEC("xdp") 
int xdp_packet_capture(struct xdp_md *ctx) {
    __u32 batch_key = 0;
    struct batch_data *batch = bpf_map_lookup_elem(&batch_map, &batch_key);
    if (!batch) return XDP_PASS;

    // 初始化时间戳
    if (batch->last_flush == 0) {
        batch->last_flush = bpf_ktime_get_ns();
    }

    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end)
        return XDP_PASS;
    
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;
    
    struct iphdr *ip = data + sizeof(*eth);
    if (data + sizeof(*eth) + sizeof(*ip) > data_end)
        return XDP_PASS;

    if (!is_valid_packet(ip) || is_loopback(ip->saddr, ip->daddr))
        return XDP_DROP;

    struct packet_info pkt = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .protocol = ip->protocol,
        .pkt_len = bpf_ntohs(ip->tot_len),
        .timestamp = bpf_ktime_get_ns(),
        .src_port = 0,
        .dst_port = 0
    };

    /* 修正传输层处理 */
    if (ip->protocol == IPPROTO_TCP || ip->protocol == IPPROTO_UDP) {
        void *trans_start = (void *)ip + sizeof(*ip);
        if (trans_start + 4 <= data_end) {  // 确保能读取端口
            pkt.src_port = bpf_ntohs(*(__be16 *)trans_start);
            pkt.dst_port = bpf_ntohs(*(__be16 *)(trans_start + 2));
            
            // 验证端口号是否有效（排除端口0）
            if (pkt.src_port == 0 && pkt.dst_port == 0) {
                return XDP_DROP;  // 丢弃无效端口的包
            }
            
            // 特殊处理TCP头和标志位
            if (ip->protocol == IPPROTO_TCP) {
                struct tcphdr *tcp = (struct tcphdr *)trans_start;
                
                // 安全检查，确保可以访问完整的TCP头部
                if ((void *)(tcp + 1) <= data_end) {
                    // 标准的TCP标志位提取 - Linux内核中的定义
                    // 这将处理不同架构上的字节序问题
                    __u8 flags = 0;
                    
                    // 注意：这些可能因字节序影响而需要调整
                    if (tcp->fin) flags |= TCP_FIN;
                    if (tcp->syn) flags |= TCP_SYN;
                    if (tcp->rst) flags |= TCP_RST;
                    if (tcp->psh) flags |= TCP_PSH;
                    if (tcp->ack) flags |= TCP_ACK;
                    if (tcp->urg) flags |= TCP_URG;
                    
                    // 另一种方法：直接获取第13字节并使用位操作
                    void *flags_ptr = (void *)tcp + 13;
                    if (flags_ptr < data_end) {
                        __u8 raw_flags = *(__u8 *)flags_ptr;
                        
                        // 保存两种方式提取的标志，以便调试比较
                        pkt.tcp_flags = flags ? flags : raw_flags;
                        
                        // 调试输出
                        bpf_printk("TCP struct flags: 0x%x, raw flags: 0x%x", 
                                  flags, raw_flags);
                    }
                }
            }
        } else {
            // 无法读取端口信息，丢弃包
            return XDP_DROP;
        }
    }

    // 应用过滤规则
    int filter_result = apply_packet_filter(pkt.src_ip, pkt.dst_ip, 
                                          pkt.src_port, pkt.dst_port, 
                                          pkt.protocol);
    
    if (filter_result == FILTER_ACTION_DENY) {
        return XDP_DROP;  // 拒绝数据包
    }

    /* 安全写入批次 */
    if (batch->count >= BATCH_SIZE) {
        submit_batch(ctx, batch);
    }

    // 使用显式边界检查
    if (batch->count < BATCH_SIZE) {
        // 确保数组访问安全
        __u32 index = batch->count & (BATCH_SIZE - 1);
        batch->pkts[index] = pkt;
        batch->count++;
    } else {
        // 防御性处理：提交后重置
        submit_batch(ctx, batch);
        batch->pkts[0] = pkt;
        batch->count = 1;
    }

    /* 超时提交 */
    if (bpf_ktime_get_ns() - batch->last_flush > FLUSH_TIMEOUT_NS) {
        submit_batch(ctx, batch);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";