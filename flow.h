#ifndef FLOW_H
#define FLOW_H

#include <stdint.h>
#include <math.h>
#include <time.h>
// Add the netinet/ip.h header to get struct iphdr definition
#include <netinet/ip.h>
// Remove Linux kernel headers causing conflicts
// #include <linux/ip.h>
// #include <linux/tcp.h>
// #include <linux/udp.h>
#include <arpa/inet.h>
// Add system network headers
#include <netinet/in.h>

// Flow timeout in nanoseconds
#define FLOW_TIMEOUT_NS 30000000000 // 30 seconds

// Initial window size for TCP (number of packets to consider)
#define INITIAL_WINDOW_SIZE 10

// TCP标志定义
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20
#define TCP_ECE  0x40
#define TCP_CWR  0x80

// NIPQUAD macro for printing IP addresses
#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

// 会话唯一标识（五元组）
struct flow_key {
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t  protocol;
};

// 用于存储包间隔时间的数组
typedef struct {
    uint64_t *times;       // 时间戳数组 (纳秒)
    size_t count;          // 当前数组大小
    size_t capacity;       // 数组容量
} timestamp_array_t;

// 流量统计指标
struct flow_stats {
    // 时间相关
    struct timespec start_time;   // 会话开始时间
    struct timespec end_time;     // 最后报文时间
    uint64_t last_seen;          // 上次看到的时间戳(ns)
    
    // 正向流（src->dst）
    uint64_t fwd_packets;        // 正向包数量
    uint64_t fwd_bytes;          // 正向总字节
    uint32_t fwd_max_size;       // 正向最大包大小
    uint32_t fwd_min_size;       // 正向最小包大小
    double   fwd_sum_squares;    // 平方和（用于标准差）
    
    // 反向流（dst->src）
    uint64_t bwd_packets;
    uint64_t bwd_bytes;
    uint32_t bwd_max_size;
    uint32_t bwd_min_size;
    double   bwd_sum_squares;

    // 包间隔时间统计
    timestamp_array_t fwd_timestamps;  // 正向包时间戳 
    timestamp_array_t bwd_timestamps;  // 反向包时间戳

    // TCP相关统计
    uint32_t fwd_header_bytes;      // 正向报文头部字节数
    uint32_t bwd_header_bytes;      // 反向报文头部字节数
    uint32_t fwd_init_win_bytes;    // 前向初始窗口字节数
    uint32_t bwd_init_win_bytes;    // 反向初始窗口字节数
    uint32_t fwd_tcp_payload_bytes; // 至少有1字节payload的TCP流量
    uint32_t fwd_min_segment;       // 前向观察到的最小segment大小

    // TCP标志统计 - 正向
    uint32_t fwd_fin_count;         // FIN标志计数
    uint32_t fwd_syn_count;         // SYN标志计数
    uint32_t fwd_rst_count;         // RST标志计数
    uint32_t fwd_psh_count;         // PSH标志计数
    uint32_t fwd_ack_count;         // ACK标志计数
    uint32_t fwd_urg_count;         // URG标志计数
    uint32_t fwd_cwr_count;         // CWR标志计数
    uint32_t fwd_ece_count;         // ECE标志计数

    // TCP标志统计 - 反向
    uint32_t bwd_fin_count;         // FIN标志计数
    uint32_t bwd_syn_count;         // SYN标志计数
    uint32_t bwd_rst_count;         // RST标志计数
    uint32_t bwd_psh_count;         // PSH标志计数
    uint32_t bwd_ack_count;         // ACK标志计数
    uint32_t bwd_urg_count;         // URG标志计数
    uint32_t bwd_cwr_count;         // CWR标志计数
    uint32_t bwd_ece_count;         // ECE标志计数

    // 子流相关统计
    uint64_t subflow_fwd_packets;   // 前向子流中的包数量
    uint64_t subflow_fwd_bytes;     // 前向子流中的字节数
    uint64_t subflow_bwd_packets;   // 反向子流中的包数量
    uint64_t subflow_bwd_bytes;     // 反向子流中的字节数

    // 流长度相关
    uint32_t flow_min_length;       // 流的最小长度
    uint32_t flow_max_length;       // 流的最大长度
    double   flow_length_sum;       // 流长度总和
    double   flow_length_sum_squares; // 流长度平方和
};

// 扩展的特征集
struct flow_features {
    // 基本特征
    double duration;                // 持续时间
    uint64_t fwd_packets;           // 正向包数
    uint64_t bwd_packets;           // 反向包数 
    uint64_t fwd_bytes;             // 正向字节数
    uint64_t bwd_bytes;             // 反向字节数
    
    // 包大小特征
    uint32_t fwd_max_size;          // 正向最大包大小
    uint32_t fwd_min_size;          // 正向最小包大小
    double fwd_avg_size;            // 正向包平均大小
    double fwd_std_size;            // 正向包大小标准差
    uint32_t bwd_max_size;          // 反向最大包大小
    uint32_t bwd_min_size;          // 反向最小包大小
    double bwd_avg_size;            // 反向包平均大小
    double bwd_std_size;            // 反向包大小标准差
    double avg_packet_size;         // 所有包的平均大小

    // 流量率特征
    double byte_rate;               // 字节率
    double packet_rate;             // 包率
    double fwd_packet_rate;         // 每秒前向包数
    double bwd_packet_rate;         // 每秒反向包数
    double download_upload_ratio;   // 下载上传比例

    // 包间隔时间特征 - 正向
    double fwd_iat_total;           // 前向包间隔时间总和
    double fwd_iat_mean;            // 前向包间隔时间平均值
    double fwd_iat_std;             // 前向包间隔时间标准差
    double fwd_iat_max;             // 前向包间隔时间最大值
    double fwd_iat_min;             // 前向包间隔时间最小值

    // 包间隔时间特征 - 反向
    double bwd_iat_total;           // 反向包间隔时间总和
    double bwd_iat_mean;            // 反向包间隔时间平均值
    double bwd_iat_std;             // 反向包间隔时间标准差
    double bwd_iat_max;             // 反向包间隔时间最大值
    double bwd_iat_min;             // 反向包间隔时间最小值

    // 包间隔时间特征 - 所有
    double flow_iat_total;          // 流间隔时间总和
    double flow_iat_mean;           // 流间隔时间平均值
    double flow_iat_std;            // 流间隔时间标准差
    double flow_iat_max;            // 流间隔时间最大值
    double flow_iat_min;            // 流间隔时间最小值
    double min_packet_iat;          // 数据包最小到达间隔时间

    // 流长度特征
    uint32_t flow_min_length;       // 流的最小长度
    uint32_t flow_max_length;       // 流的最大长度
    double flow_mean_length;        // 流的平均长度
    double flow_std_length;         // 流的标准差长度

    // TCP标志特征 - 正向
    uint32_t fwd_fin_count;         // FIN标志计数
    uint32_t fwd_syn_count;         // SYN标志计数
    uint32_t fwd_rst_count;         // RST标志计数
    uint32_t fwd_psh_count;         // PSH标志计数
    uint32_t fwd_ack_count;         // ACK标志计数
    uint32_t fwd_urg_count;         // URG标志计数
    uint32_t fwd_cwr_count;         // CWR标志计数
    uint32_t fwd_ece_count;         // ECE标志计数

    // TCP标志特征 - 反向
    uint32_t bwd_fin_count;         // FIN标志计数
    uint32_t bwd_syn_count;         // SYN标志计数
    uint32_t bwd_rst_count;         // RST标志计数
    uint32_t bwd_psh_count;         // PSH标志计数
    uint32_t bwd_ack_count;         // ACK标志计数
    uint32_t bwd_urg_count;         // URG标志计数
    uint32_t bwd_cwr_count;         // CWR标志计数
    uint32_t bwd_ece_count;         // ECE标志计数

    // TCP相关特征
    uint32_t fwd_header_bytes;      // 用于前向数据包头部的总字节数
    uint32_t bwd_header_bytes;      // 用于反向数据包头部的总字节数
    double fwd_segment_avg_size;    // 前向数据segment平均尺寸
    double bwd_segment_avg_size;    // 反向数据segment平均尺寸
    double fwd_subflow_avg_pkts;    // 前向子流中的平均数据包数
    double fwd_subflow_avg_bytes;   // 前向子流的平均字节数
    double bwd_subflow_avg_pkts;    // 反向子流中的平均数据包数
    double bwd_subflow_avg_bytes;   // 反向子流中的平均字节数
    uint32_t fwd_init_win_bytes;    // 前向初始窗口中发送的字节数
    uint32_t bwd_init_win_bytes;    // 反向初始窗口中发送的字节数
    uint32_t fwd_tcp_payload_bytes; // 前向有效TCP载荷字节数
    uint32_t fwd_min_segment;       // 前向观察到的最小segment大小
};

// 会话记录哈希表节点
struct flow_node {
    struct flow_key key;
    struct flow_stats stats;
    struct flow_node *next;
    uint8_t in_use;  // 标记是否使用中
};

#define HASH_TABLE_SIZE 4096
extern struct flow_node* flow_table[HASH_TABLE_SIZE]; // 哈希表

void flow_table_init();
void flow_table_destroy();
void cleanup_flows();

struct flow_stats* get_flow_stats(const struct flow_key *key, int is_reverse);
void update_flow_stats(struct flow_stats *stats, uint32_t pkt_size, int is_reverse);
void update_tcp_flags(struct flow_stats *stats, uint8_t tcp_flags, int is_reverse);
void calculate_flow_features(const struct flow_stats *stats, struct flow_features *features);
void print_flow_stats();
void process_packet(const struct iphdr *ip, const void *transport_hdr);

uint32_t hash_flow_key(const struct flow_key *key);
uint64_t get_current_time();

// 时间戳数组操作函数
void timestamp_array_init(timestamp_array_t *arr);
void timestamp_array_add(timestamp_array_t *arr, uint64_t timestamp);
void timestamp_array_free(timestamp_array_t *arr);

#endif /* FLOW_H */
