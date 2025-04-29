#ifndef __PACKET_H
#define __PACKET_H

// 定义我们收集的数据包信息结构
struct packet_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;     // IPPROTO_TCP, IPPROTO_UDP 等
    __u16 pkt_len;
    __u64 timestamp;   // 纳秒级时间戳
};

// 定义 perf buffer 的事件结构
struct event {
    __u32 pid;
    char comm[16];     // 进程名
    struct packet_info pkt_info;
};

#endif // __PACKET_H
