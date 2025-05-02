#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/stddef.h>
#include <linux/in.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#define BATCH_SIZE 16
#define FLUSH_TIMEOUT_NS 1000000 // 1毫秒

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(int));
    __uint(value_size, sizeof(__u32));
    __uint(max_entries, 1024);
} events SEC(".maps");

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



static __always_inline int is_valid_packet(struct iphdr *ip) {
    if (ip->saddr == 0 || ip->daddr == 0 || 
        ip->saddr == 0xFFFFFFFF || ip->daddr == 0xFFFFFFFF)
        return 0;
    
    switch (ip->protocol) {
        case IPPROTO_TCP:
        case IPPROTO_UDP:
        case IPPROTO_ICMP:
            break;
        default:
            return 0;
    }
    
    __u16 len = bpf_ntohs(ip->tot_len);
    if (len < sizeof(struct iphdr) || len > 1500)
        return 0;
    
    return 1;
}

static __always_inline int is_loopback(__u32 saddr, __u32 daddr) {
    return (saddr & 0xFF000000) == 0x7F000000 || 
           (daddr & 0xFF000000) == 0x7F000000;
}

static __always_inline void submit_batch(struct xdp_md *ctx, struct batch_data *batch) {
    if (batch->count > 0) {
        __u32 max_size = sizeof(struct batch_data);
        __u32 data_size = offsetof(struct batch_data, pkts) + 
                         batch->count * sizeof(struct packet_info);
        data_size = data_size > max_size ? max_size : data_size; // 截断
        
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
        }
    }

    /* 安全写入批次 */
    if (batch->count >= BATCH_SIZE) {
        submit_batch(ctx, batch);
    }

    if (batch->count < BATCH_SIZE) {
        batch->pkts[batch->count] = pkt;
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