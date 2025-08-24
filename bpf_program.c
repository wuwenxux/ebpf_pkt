#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/stddef.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// 优化配置
#define BATCH_SIZE 64           // 增加批处理大小
#define FLUSH_TIMEOUT_NS 500000 // 减少到0.5毫秒，提高实时性
#define MAX_FILTER_RULES 1024
#define MAX_INTERFACES 32       // 支持最多32个接口

// TCP标志位常量定义
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80

// 过滤动作
#define FILTER_ACTION_ALLOW 1    // 允许
#define FILTER_ACTION_DENY  2    // 拒绝

// 优化的数据包信息结构
struct packet_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u32 pkt_len;
    __u64 timestamp;
    __u8 tcp_flags;
    __u32 ifindex;      // 接口索引
    __u32 cpu_id;       // CPU ID
    __u32 hash;         // 预计算的五元组哈希
    __u8 priority;      // 优先级（用于QoS）
} __attribute__((packed));





// 优化的RINGBUF映射
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 512 * 1024); // 增加到512KB
} ringbuf_events SEC(".maps");





// 统计映射
struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(key_size, sizeof(__u32));
    __uint(value_size, sizeof(__u64));
    __uint(max_entries, 8); // 0:总包数, 1:过滤包数, 2:批处理包数, 3:直接发送包数, 4:丢弃包数, 5:允许包数, 6:拒绝包数, 7:哈希冲突数
} stats_map SEC(".maps");

// 优化的Jenkins哈希函数（用于五元组哈希）
static __always_inline __u32 jenkins_hash(__u32 a, __u32 b, __u32 c) {
    a -= b; a -= c; a ^= (c >> 13);
    b -= c; b -= a; b ^= (a << 8);
    c -= a; c -= b; c ^= (b >> 13);
    a -= b; a -= c; a ^= (c >> 12);
    b -= c; b -= a; b ^= (a << 16);
    c -= a; c -= b; c ^= (b >> 5);
    a -= b; a -= c; a ^= (c >> 3);
    b -= c; b -= a; b ^= (a << 10);
    c -= a; c -= b; c ^= (b >> 15);
    return c;
}

// 计算五元组哈希
static __always_inline __u32 calculate_flow_hash(__u32 src_ip, __u32 dst_ip, 
                                                __u16 src_port, __u16 dst_port, 
                                                __u8 protocol) {
    __u32 hash = jenkins_hash(src_ip, dst_ip, (__u32)src_port << 16 | dst_port);
    return jenkins_hash(hash, protocol, 0);
}

// 简化的过滤检查函数
static __always_inline int check_filter(struct packet_info *pkt) {
    // 暂时禁用过滤，直接允许所有包
    return FILTER_ACTION_ALLOW;
}



// 简化的XDP主函数
SEC("xdp")
int xdp_packet_capture(struct xdp_md *ctx) {
    // 获取接口索引和CPU ID
    __u32 ifindex = ctx->ingress_ifindex;
    __u32 cpu_id = bpf_get_smp_processor_id();
    
    // 更新统计
    __u64 *total_pkts = bpf_map_lookup_elem(&stats_map, &(int){0});
    if (total_pkts) {
        __sync_fetch_and_add(total_pkts, 1);
    }
    
    // 解析以太网头
    void *data_end = (void *)(long)ctx->data_end;
    void *data = (void *)(long)ctx->data;
    
    struct ethhdr *eth = data;
    if (data + sizeof(*eth) > data_end) {
        return XDP_PASS;
    }
    
    // 只处理IPv4包
    if (eth->h_proto != bpf_htons(ETH_P_IP)) {
        return XDP_PASS;
    }
    
    // 解析IP头
    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) {
        return XDP_PASS;
    }
    
    // 只处理TCP和UDP
    if (ip->protocol != IPPROTO_TCP && ip->protocol != IPPROTO_UDP) {
        return XDP_PASS;
    }
    
    // 创建数据包信息
    struct packet_info pkt = {
        .src_ip = ip->saddr,
        .dst_ip = ip->daddr,
        .protocol = ip->protocol,
        .pkt_len = bpf_ntohs(ip->tot_len),
        .timestamp = bpf_ktime_get_ns(),
        .ifindex = ifindex,
        .cpu_id = cpu_id,
        .priority = 0
    };
    
    // 解析传输层头
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (void *)(ip + 1);
        if ((void *)(tcp + 1) > data_end) {
            return XDP_PASS;
        }
        pkt.src_port = bpf_ntohs(tcp->source);
        pkt.dst_port = bpf_ntohs(tcp->dest);
        pkt.tcp_flags = *((__u8*)tcp + 13);
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (void *)(ip + 1);
        if ((void *)(udp + 1) > data_end) {
            return XDP_PASS;
        }
        pkt.src_port = bpf_ntohs(udp->source);
        pkt.dst_port = bpf_ntohs(udp->dest);
        pkt.tcp_flags = 0;
    }
    
    // 计算五元组哈希
    pkt.hash = calculate_flow_hash(pkt.src_ip, pkt.dst_ip, pkt.src_port, pkt.dst_port, pkt.protocol);
    
    // 应用过滤规则
    int filter_result = check_filter(&pkt);
    if (filter_result == FILTER_ACTION_DENY) {
        __u64 *filtered_pkts = bpf_map_lookup_elem(&stats_map, &(int){1});
        if (filtered_pkts) {
            __sync_fetch_and_add(filtered_pkts, 1);
        }
        return XDP_DROP;
    }
    
    // 直接发送到RINGBUF
    struct packet_info *event = bpf_ringbuf_reserve(&ringbuf_events, sizeof(pkt), 0);
    if (event) {
        *event = pkt;
        bpf_ringbuf_submit(event, 0);
    }
    
    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";