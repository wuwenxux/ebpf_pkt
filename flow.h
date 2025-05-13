#ifndef FLOW_H
#define FLOW_H

#include <stdint.h>
#include <math.h>
#include <time.h>
// Add the netinet/ip.h header to get struct iphdr definition
#include <netinet/ip.h>
#include <arpa/inet.h>
// Add system network headers
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/time.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// 增加流超时时间，确保短期流不会过快删除
#define FLOW_TIMEOUT_NS 9999999999999 // 普通流不超时

// TCP流使用特殊的超时时间，显著短于一般超时
#define TCP_FLOW_TIMEOUT_NS 1500000000 // 1.5sTCP流超时

// TCP流分段设置
#define TCP_SEGMENT_ON_IDLE 1      // 空闲超时时分段（已关闭）
#define TCP_IDLE_TIMEOUT_NS 500000000 // 0.5秒无活动视为空闲

// TCP标志位分段设置
#define TCP_SEGMENT_ON_FLAGS 0     // 根据TCP标志位分段（已关闭）
#define TCP_FLAGS_THRESH 10        // 10个标志位变化视为新的子流

// 启用流清理，但只对TCP流应用更短的超时
#define ENABLE_FLOW_CLEANUP 1

// Initial window size for TCP (number of packets to consider)
#define INITIAL_WINDOW_SIZE 10

// 以下是流识别配置选项，关闭过度细分的特征
#define CAPTURE_TOS 0          // 关闭TOS/DSCP字段区分
#define CAPTURE_TTL 0          // 关闭TTL字段区分
#define CAPTURE_TCP_WIN 0      // 关闭TCP窗口大小区分
#define CAPTURE_TCP_OPTIONS 0  // 关闭TCP选项区分
#define FINE_GRAINED_FLOWS 0   // 关闭细粒度流识别

// 定义更宽松的流识别，忽略端口信息
#define IGNORE_PORTS 0         // 设置为1将忽略端口号，只用IP和协议识别流

// 流活跃性检查，确保将所有活跃流计入统计
#define FLOW_ACTIVE_THRESHOLD 0  // 任何数据包都认为流是活跃的

// 从cicflowmeter项目复制的TCP相关参数
#define EXPIRED_UPDATE 240           // 流过期更新时间（秒）
#define CLUMP_TIMEOUT 1              // 数据包分组超时（秒）
#define ACTIVE_TIMEOUT 0.005         // 活跃超时（秒）
#define BULK_BOUND 4                 // 批量传输边界条件

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

// 流键结构增强版
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

// UDP流量统计结构
struct udp_stats {
    // 正向流统计
    uint64_t fwd_packets;        // 正向UDP包数量
    uint64_t fwd_bytes;          // 正向UDP字节总数
    uint32_t fwd_max_size;       // 正向UDP包最大大小
    uint32_t fwd_min_size;       // 正向UDP包最小大小
    double   fwd_sum_squares;    // 正向UDP包大小平方和
    uint64_t fwd_header_bytes;   // 正向UDP头部字节数
    
    // 反向流统计
    uint64_t bwd_packets;        // 反向UDP包数量
    uint64_t bwd_bytes;          // 反向UDP字节总数
    uint32_t bwd_max_size;       // 反向UDP包最大大小
    uint32_t bwd_min_size;       // 反向UDP包最小大小
    double   bwd_sum_squares;    // 反向UDP包大小平方和
    uint64_t bwd_header_bytes;   // 反向UDP头部字节数
    
    // 时间相关统计
    timestamp_array_t fwd_timestamps;  // 正向UDP包时间戳
    timestamp_array_t bwd_timestamps;  // 反向UDP包时间戳
};

// TCP标志统计结构
struct tcp_flag_stats {
    // 正向流标志统计
    uint32_t fwd_fin_count;      // FIN标志计数
    uint32_t fwd_syn_count;      // SYN标志计数
    uint32_t fwd_rst_count;      // RST标志计数
    uint32_t fwd_psh_count;      // PSH标志计数
    uint32_t fwd_ack_count;      // ACK标志计数
    uint32_t fwd_urg_count;      // URG标志计数
    uint32_t fwd_cwr_count;      // CWR标志计数
    uint32_t fwd_ece_count;      // ECE标志计数
    
    // 反向流标志统计
    uint32_t bwd_fin_count;      // FIN标志计数
    uint32_t bwd_syn_count;      // SYN标志计数
    uint32_t bwd_rst_count;      // RST标志计数
    uint32_t bwd_psh_count;      // PSH标志计数
    uint32_t bwd_ack_count;      // ACK标志计数
    uint32_t bwd_urg_count;      // URG标志计数
    uint32_t bwd_cwr_count;      // CWR标志计数
    uint32_t bwd_ece_count;      // ECE标志计数
};

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

    // 从cicflowmeter添加的TCP流数据结构
    uint32_t flow_interarrival_time_count;    // 流包间隔时间计数
    uint64_t *flow_interarrival_time;         // 流包间隔时间数组
    uint32_t active_count;                    // 活跃状态计数
    uint64_t *active;                         // 活跃状态数组
    uint32_t idle_count;                      // 空闲状态计数
    uint64_t *idle;                           // 空闲状态数组

    // 添加Bulk分析相关字段
    uint64_t forward_bulk_last_timestamp;     // 前向bulk最后时间戳
    uint64_t forward_bulk_start_tmp;          // 前向bulk开始时间
    uint32_t forward_bulk_count;              // 前向bulk计数
    uint32_t forward_bulk_count_tmp;          // 前向bulk临时计数
    uint64_t forward_bulk_duration;           // 前向bulk持续时间
    uint32_t forward_bulk_packet_count;       // 前向bulk包计数
    uint32_t forward_bulk_size;               // 前向bulk大小
    uint32_t forward_bulk_size_tmp;           // 前向bulk临时大小
    uint64_t backward_bulk_last_timestamp;    // 反向bulk最后时间戳
    uint64_t backward_bulk_start_tmp;         // 反向bulk开始时间
    uint32_t backward_bulk_count;             // 反向bulk计数
    uint32_t backward_bulk_count_tmp;         // 反向bulk临时计数
    uint64_t backward_bulk_duration;          // 反向bulk持续时间
    uint32_t backward_bulk_packet_count;      // 反向bulk包计数
    uint32_t backward_bulk_size;              // 反向bulk大小
    uint32_t backward_bulk_size_tmp;          // 反向bulk临时大小

    // TCP标志统计
    struct tcp_flag_stats tcp_flags;

    // UDP特定统计
    struct udp_stats udp;

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

// UDP特征统计结构
struct udp_features {
    // 正向流特征
    uint64_t fwd_packets;         // 正向UDP包数量
    uint64_t fwd_bytes;           // 正向UDP字节总数
    uint32_t fwd_max_size;        // 正向UDP包最大大小
    uint32_t fwd_min_size;        // 正向UDP包最小大小
    double   fwd_avg_size;        // 正向UDP包平均大小
    double   fwd_std_size;        // 正向UDP包大小标准差
    uint64_t fwd_header_bytes;    // 正向UDP头部字节数
    
    // 反向流特征
    uint64_t bwd_packets;         // 反向UDP包数量
    uint64_t bwd_bytes;           // 反向UDP字节总数
    uint32_t bwd_max_size;        // 反向UDP包最大大小
    uint32_t bwd_min_size;        // 反向UDP包最小大小
    double   bwd_avg_size;        // 反向UDP包平均大小
    double   bwd_std_size;        // 反向UDP包大小标准差
    uint64_t bwd_header_bytes;    // 反向UDP头部字节数
    
    // 时间特征
    double fwd_iat_total;         // 正向包间隔时间总和
    double fwd_iat_mean;          // 正向包间隔时间平均值
    double fwd_iat_std;           // 正向包间隔时间标准差
    double fwd_iat_max;           // 正向包间隔时间最大值
    double fwd_iat_min;           // 正向包间隔时间最小值
    
    double bwd_iat_total;         // 反向包间隔时间总和
    double bwd_iat_mean;          // 反向包间隔时间平均值
    double bwd_iat_std;           // 反向包间隔时间标准差
    double bwd_iat_max;           // 反向包间隔时间最大值
    double bwd_iat_min;           // 反向包间隔时间最小值
};

// TCP标志特征结构
struct tcp_flag_features {
    // 正向流标志特征
    uint32_t fwd_fin_count;       // FIN标志计数
    uint32_t fwd_syn_count;       // SYN标志计数
    uint32_t fwd_rst_count;       // RST标志计数
    uint32_t fwd_psh_count;       // PSH标志计数
    uint32_t fwd_ack_count;       // ACK标志计数
    uint32_t fwd_urg_count;       // URG标志计数
    uint32_t fwd_cwr_count;       // CWR标志计数
    uint32_t fwd_ece_count;       // ECE标志计数
    
    // 反向流标志特征
    uint32_t bwd_fin_count;       // FIN标志计数
    uint32_t bwd_syn_count;       // SYN标志计数
    uint32_t bwd_rst_count;       // RST标志计数
    uint32_t bwd_psh_count;       // PSH标志计数
    uint32_t bwd_ack_count;       // ACK标志计数
    uint32_t bwd_urg_count;       // URG标志计数
    uint32_t bwd_cwr_count;       // CWR标志计数
    uint32_t bwd_ece_count;       // ECE标志计数
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

    // TCP标志特征
    struct tcp_flag_features tcp_flags;

    // UDP特定特征
    struct udp_features udp;

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

    // 添加cicflowmeter项目特有的TCP特征
    uint32_t fin_flag_cnt;          // FIN标志计数
    uint32_t syn_flag_cnt;          // SYN标志计数
    uint32_t rst_flag_cnt;          // RST标志计数
    uint32_t psh_flag_cnt;          // PSH标志计数
    uint32_t ack_flag_cnt;          // ACK标志计数
    uint32_t urg_flag_cnt;          // URG标志计数
    uint32_t ece_flag_cnt;          // ECE标志计数
    uint32_t cwe_flag_count;        // CWE标志计数

    // Active与Idle状态特征
    double active_max;              // 活跃状态最大值
    double active_min;              // 活跃状态最小值
    double active_mean;             // 活跃状态平均值
    double active_std;              // 活跃状态标准差
    double idle_max;                // 空闲状态最大值
    double idle_min;                // 空闲状态最小值
    double idle_mean;               // 空闲状态平均值
    double idle_std;                // 空闲状态标准差

    // Bulk特征
    double fwd_byts_b_avg;          // 前向bulk平均字节数
    double fwd_pkts_b_avg;          // 前向bulk平均包数
    double bwd_byts_b_avg;          // 反向bulk平均字节数
    double bwd_pkts_b_avg;          // 反向bulk平均包数
    double fwd_blk_rate_avg;        // 前向bulk平均速率
    double bwd_blk_rate_avg;        // 反向bulk平均速率
};

// TCP 连接状态定义
#define TCP_STATE_NEW     0  // 新连接
#define TCP_STATE_SYN     1  // 收到SYN
#define TCP_STATE_SYN_ACK 2  // 收到SYN-ACK
#define TCP_STATE_EST     3  // 连接已建立
#define TCP_STATE_FIN     4  // 开始关闭
#define TCP_STATE_RST     5  // 连接被重置
#define TCP_STATE_CLOSED  6  // 连接已关闭

// 会话记录哈希表节点
struct flow_node {
    struct flow_key key;
    struct flow_stats stats;
    struct flow_node *next;
    uint8_t in_use;         // 标记是否使用中
    uint8_t tcp_state;      // TCP连接状态
};

// 大幅增加哈希表大小以减少冲突
#define HASH_TABLE_SIZE 262144  // 增加到256K
extern struct flow_node* flow_table[HASH_TABLE_SIZE]; // 哈希表

void flow_table_init();
void flow_table_destroy();
void cleanup_flows();

// Time utility function
double time_diff(const struct timespec *end, const struct timespec *start);

struct flow_stats* get_flow_stats(const struct flow_key *key, int *is_reverse_ptr) ;
void update_flow_stats(struct flow_stats *stats, uint32_t pkt_size, int is_reverse);
void update_tcp_flags(struct flow_stats *stats, uint8_t tcp_flags, int is_reverse);
void update_udp_stats(struct flow_stats *stats, uint32_t pkt_size, int is_reverse);
void calculate_flow_features(const struct flow_stats *stats, struct flow_features *features);
void print_flow_stats();
void process_packet(const struct iphdr *ip, const void *transport_hdr);
int count_active_flows();
void count_flow_directions(int *forward_flows, int *reverse_flows);
int count_all_flows();
void count_all_flow_directions(int *forward_flows, int *reverse_flows);

uint32_t hash_flow_key(const struct flow_key *key);
uint64_t get_current_time();

// 时间戳数组操作函数
void timestamp_array_init(timestamp_array_t *arr);
void timestamp_array_add(timestamp_array_t *arr, uint64_t timestamp);
void timestamp_array_free(timestamp_array_t *arr);

// 添加新函数声明用于处理Bulk特征
void update_flow_bulk(struct flow_stats *stats, uint32_t payload_size, int is_reverse, uint64_t timestamp);
void update_subflow(struct flow_stats *stats, uint64_t current_time);
void update_active_idle(struct flow_stats *stats, uint64_t current_time);

#endif /* FLOW_H */
