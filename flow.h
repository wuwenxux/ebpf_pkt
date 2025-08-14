#ifndef FLOW_H
#define FLOW_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <time.h>
// 使用用户空间的网络头文件，避免与内核头文件冲突
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdatomic.h>
#include "common_types.h"  // 添加共享类型支持

// Cache line alignment for performance optimization
#define CACHE_LINE_SIZE 64
#define CACHE_LINE_ALIGN __attribute__((aligned(CACHE_LINE_SIZE)))

// 最大时间戳数组大小
#define MAX_TIMESTAMPS 1000

// 流表大小
#define HASH_TABLE_SIZE 1048576  // 1M 哈希桶

// 活跃超时时间（纳秒）
#define ACTIVE_TIMEOUT_NS 60000000000ULL  // 60秒

// TCP标志位定义
#define TCP_FIN 0x01
#define TCP_SYN 0x02
#define TCP_RST 0x04
#define TCP_PSH 0x08
#define TCP_ACK 0x10
#define TCP_URG 0x20
#define TCP_CWR 0x40
#define TCP_ECE 0x80

// =================== 调试级别控制 ===================
void set_debug_level(int level);
int get_debug_level();

// =================== 流管理参数 ===================

// 流超时配置 - 调整为更接近Wireshark的默认设置
#define FLOW_TIMEOUT_NS (120 * 1000000000ULL)    // 流过期时间 (120秒，类似Wireshark)
#define TCP_FLOW_TIMEOUT_NS (120 * 1000000000ULL) // TCP流120秒超时，与Wireshark一致

// cicflowmeter 活跃超时配置
#define CLUMP_TIMEOUT_NS (1 * 1000000000ULL)     // 集群超时时间 (1秒)，用于子流和批量传输分割
#define BULK_BOUND 4                             // 批量传输阈值 (4个数据包)

// TCP流分段设置 - 更保守的设置
#define TCP_SEGMENT_ON_IDLE 0               // 禁用空闲超时分段，减少过度分割
#define TCP_IDLE_TIMEOUT_NS (30 * 1000000000ULL) // TCP空闲超时 (30秒)

// TCP标志位分段设置 - 更保守
#define TCP_SEGMENT_ON_FLAGS 0              // 禁用TCP标志位分段
#define TCP_FLAGS_THRESH 20                 // 20个标志位变化视为新的子流（更保守）

// 启用流清理
#define ENABLE_FLOW_CLEANUP 1

// Initial window size for TCP (number of packets to consider)
#define INITIAL_WINDOW_SIZE 10

// 流识别配置选项
#define CAPTURE_TOS 0          // 关闭TOS/DSCP字段区分
#define CAPTURE_TTL 0          // 关闭TTL字段区分
#define CAPTURE_TCP_WIN 0      // 关闭TCP窗口大小区分
#define CAPTURE_TCP_OPTIONS 0  // 关闭TCP选项区分
#define FINE_GRAINED_FLOWS 0   // 关闭细粒度流识别

// 流识别参数
#define IGNORE_PORTS 0         // 设置为1将忽略端口号，只用IP和协议识别流

// 流活跃性检查
#define FLOW_ACTIVE_THRESHOLD 0  // 任何数据包都认为流是活跃的

// =================== cicflowmeter 流键生成宏 ===================

/**
 * 检查时间间隔是否超过阈值
 */
#define CIC_TIME_DIFF_EXCEEDS(current, last, threshold_ns) \
    ((current) - (last) > (threshold_ns))

/**
 * 获取两个时间戳的差值 (纳秒)
 */
#define CIC_TIME_DIFF_NS(current, last) \
    ((current) - (last))

/**
 * 检查TCP标志是否包含特定位
 */
#define CIC_HAS_TCP_FLAG(flags, flag) \
    (((flags) & (flag)) != 0)

/**
 * 检查是否为TCP FIN包
 */
#define CIC_IS_TCP_FIN(flags) \
    CIC_HAS_TCP_FLAG(flags, TCP_FIN)

/**
 * 检查是否为TCP RST包
 */
#define CIC_IS_TCP_RST(flags) \
    CIC_HAS_TCP_FLAG(flags, TCP_RST)

// =================== 原有定义保持不变 ===================

// TCP标志定义
#define TCP_FIN  0x01
#define TCP_SYN  0x02
#define TCP_RST  0x04
#define TCP_PSH  0x08
#define TCP_ACK  0x10
#define TCP_URG  0x20


// =================== Wireshark风格TCP对话完整性标志 ===================
// 基于Wireshark的conversation.h中的对话完整性追踪
#define TCP_COMPLETENESS_SYNSENT        0x01    // SYN发送
#define TCP_COMPLETENESS_SYNACK         0x02    // SYN-ACK发送 
#define TCP_COMPLETENESS_ACK            0x04    // ACK发送
#define TCP_COMPLETENESS_DATA           0x08    // 数据传输
#define TCP_COMPLETENESS_FIN            0x10    // FIN发送
#define TCP_COMPLETENESS_RST            0x20    // RST发送

// TCP对话完整性类型
#define TCP_CONV_COMPLETE               0x3F    // 完整对话 (所有标志)
#define TCP_CONV_INCOMPLETE             0x00    // 不完整对话
#define TCP_CONV_PARTIAL_HANDSHAKE      0x07    // 部分握手 (SYN+SYNACK+ACK)
#define TCP_CONV_DATA_ONLY              0x08    // 仅数据传输

// =================== Wireshark风格对话状态 ===================
// 类似packet-tcp.h中的TCP分析状态
typedef enum {
    TCP_CONV_UNKNOWN = 0,       // 未知状态
    TCP_CONV_INIT,              // 初始状态
    TCP_CONV_ESTABLISHED,       // 已建立连接
    TCP_CONV_CLOSING,           // 正在关闭
    TCP_CONV_CLOSED,            // 已关闭
    TCP_CONV_RESET              // 被重置
} tcp_conversation_state_t;

// =================== 简化的会话状态管理 ===================

// 会话状态枚举
typedef enum {
    SESSION_STATE_INIT = 0,      // 初始状态
    SESSION_STATE_ESTABLISHED,   // 已建立
    SESSION_STATE_CLOSING,       // 正在关闭
    SESSION_STATE_CLOSED,        // 已关闭
    SESSION_STATE_RESET          // 被重置
} session_state_t;

// 会话完成度标志
#define SESSION_FLAG_SYN_SENT    0x01    // SYN已发送
#define SESSION_FLAG_SYN_ACK     0x02    // SYN-ACK已发送
#define SESSION_FLAG_ACK_SENT    0x04    // ACK已发送
#define SESSION_FLAG_DATA_SENT   0x08    // 数据已发送
#define SESSION_FLAG_FIN_SENT    0x10    // FIN已发送
#define SESSION_FLAG_RST_SENT    0x20    // RST已发送

// NIPQUAD macro for printing IP addresses
#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

// 流键结构和timestamp_array_t现在在common_types.h中定义

// UDP流量统计结构


// TCP标志统计结构


// 流量统计指标 - 简化版本，只保留flow_features实际使用的参数
struct flow_stats {
    // 高频访问字段 - 放在第一个cache line
    uint64_t first_seen;         // 第一个包的时间戳(ns)
    uint64_t last_seen;          // 上次看到的时间戳(ns)
    uint64_t fwd_packets;        // 正向包数量
    uint64_t fwd_bytes;          // 正向总字节
    uint64_t bwd_packets;        // 反向包数量
    uint64_t bwd_bytes;          // 反向总字节
    uint32_t fwd_max_size;       // 正向最大包大小
    uint32_t fwd_min_size;       // 正向最小包大小
    uint32_t bwd_max_size;       // 反向最大包大小
    uint32_t bwd_min_size;       // 反向最小包大小
    double   fwd_sum_squares;    // 平方和（用于标准差）
    double   bwd_sum_squares;    // 反向平方和
    
    // 时间相关 - 第二个cache line
    struct timespec start_time;   // 会话开始时间
    
    // 包间隔时间统计
    timestamp_array_t fwd_timestamps;  // 正向包时间戳 
    timestamp_array_t bwd_timestamps;  // 反向包时间戳

    // TCP相关统计 - 第三个cache line
    uint32_t fwd_header_bytes;      // 正向报文头部字节数
    uint32_t bwd_header_bytes;      // 反向报文头部字节数
    uint32_t fwd_init_win_bytes;    // 前向初始窗口字节数
    uint32_t bwd_init_win_bytes;    // 反向初始窗口字节数
    uint32_t fwd_tcp_payload_bytes; // 至少有1字节payload的TCP流量
    uint32_t fwd_min_segment;       // 前向观察到的最小segment大小
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
    double fl_dur;                // 持续时间
    char start_time_str[64];        // 开始时间字符串(年月日时分秒)
    uint64_t tot_fw_pk;           // 正向包数
    uint64_t tot_bw_pk;           // 反向包数 
    uint64_t tot_1_fw_pk;             // 正向字节数
    uint64_t tot_1_bw_pk;             // 反向字节数
    
    // 包大小特征
    uint32_t fwd_pkt_1_max;          // 正向最大包大小
    uint32_t fwd_pkt_1_min;          // 正向最小包大小
    double fwd_pkt_1_avg;            // 正向包平均大小
    double fwd_pkt_1_std;            // 正向包大小标准差
    uint32_t bwd_pkt_1_max;          // 反向最大包大小
    uint32_t bwd_pkt_1_min;          // 反向最小包大小
    double bwd_pkt_1_avg;            // 反向包平均大小
    double bwd_pkt_1_std;            // 反向包大小标准差
    
    double avg_packet_size;         // 所有包的平均大小

    // 流量率特征
    double fl_byt_s;               // 字节率
    double fl_pkt_s;             // 包率
    double fw_pkt_s;             // 前向包率
    double bw_pkt_s;             // 反向包率
    // 包间隔时间特征 - 所有
    double fl_iat_avg;           // 流间隔时间平均值
    double fl_iat_std;            // 流间隔时间标准差
    double fl_iat_max;            // 流间隔时间最大值
    double fl_iat_min;            // 流间隔时间最小值
  
    // 包间隔时间特征 - 正向
    double fw_iat_tot;           // 前向包间隔时间总和
    double fw_iat_avg;            // 前向包间隔时间平均值
    double fw_iat_std;             // 前向包间隔时间标准差
    double fw_iat_max;             // 前向包间隔时间最大值
    double fw_iat_min;             // 前向包间隔时间最小值

    // 包间隔时间特征 - 反向
    double bw_iat_tot;           // 反向包间隔时间总和
    double bw_iat_avg;            // 反向包间隔时间平均值
    double bw_iat_std;             // 反向包间隔时间标准差
    double bw_iat_max;             // 反向包间隔时间最大值
    double bw_iat_min;             // 反向包间隔时间最小值

  
    uint64_t fw_hdr_len; //前向数据包头部总字节数
    uint64_t bw_hdr_len; //反向数据包头部总字节数

    // 流长度特征
    uint32_t pkt_len_min;       // 流的最小长度
    uint32_t pkt_len_max;       // 流的最大长度
    double  pkt_len_avg;        // 流的平均长度
    double  pkt_len_std;         // 流的标准差长度
    double pkt_len_va;          //数据包最小到达间隔时间 
    
    double down_up_ratio; //下载上传比例
    double pkt_size_avg; //数据包大小平均值
    double fw_seg_avg; //前向分段平均大小
    double bw_seg_avg;  //反向分段平均大小
    uint32_t subfl_fw_pk; //前向子流中的平均数据包数
    uint32_t subfl_fw_byt; //前向子流中的的平均数据包数
    uint32_t subfl_bw_pk; //反向子流中的平均数据包数
    uint32_t subfl_bw_byt; //反向子流中的的平均数据包数
    
    uint32_t fw_win_byt; //前向初始窗口中发送到字节数
    uint32_t bw_win_byt; //反向初始窗口中发送到字节数
    uint32_t fw_act_pkt; //前向具有至少1字节TCP数据有效载荷的数据包的数量
    uint32_t fw_ack_pkt; //前向具有至少1字节TCP数据有效载荷的数据包数量
    uint32_t fw_seg_min; //前向观察到的最小段大小
};

// TCP 连接状态定义
#define TCP_STATE_NEW     0  // 新连接
#define TCP_STATE_SYN     1  // 收到SYN
#define TCP_STATE_SYN_ACK 2  // 收到SYN-ACK
#define TCP_STATE_EST     3  // 连接已建立
#define TCP_STATE_FIN     4  // 开始关闭
#define TCP_STATE_RST     5  // 连接被重置
#define TCP_STATE_CLOSED  6  // 连接已关闭

// 流节点结构 - Cache line aligned for performance
struct flow_node {
    struct flow_key key;
    struct flow_stats stats;
    struct flow_node *next;
    uint8_t in_use;         // 标记是否使用中
    uint8_t tcp_state;      // TCP连接状态
    atomic_int ref_count;   // 引用计数
    
    // =================== 原始端口号字段（用于CSV输出）===================
    uint16_t original_src_port;     // 原始源端口号（数据包中的实际端口）
    uint16_t original_dst_port;     // 原始目标端口号（数据包中的实际端口）
    uint32_t original_src_ip;       // 原始源IP地址
    uint32_t original_dst_ip;       // 原始目标IP地址
    
    // =================== Wireshark风格的对话字段 ===================
    uint32_t conversation_id;       // 对话ID (类似Wireshark的stream)
    uint64_t first_packet_time;     // 第一个包的时间戳
    uint64_t last_packet_time;      // 最后一个包的时间戳
    uint32_t packet_num;            // 流内包序号
    uint8_t  create_flags;          // 创建时的标志 (SYN/UDP等)
    
    // =================== 简化的会话状态管理 ===================
    uint8_t session_state;          // 会话状态
    uint8_t session_flags;          // 会话完成度标志
    uint8_t last_tcp_flags;         // 上次TCP标志（用于检测标志变化）
    
    // Padding to ensure cache line alignment
    uint8_t padding[1];
};

// 大幅增加哈希表大小以减少冲突

extern struct flow_node* flow_table[HASH_TABLE_SIZE]; // 哈希表

void flow_table_init();
struct flow_node *flow_table_insert(const struct flow_key *key);
struct flow_node *flow_table_insert_with_timestamp(const struct flow_key *key, uint64_t packet_timestamp);
void set_flow_start_time_from_timestamp(struct flow_stats *stats, uint64_t timestamp_ns);
void ns_to_timespec(uint64_t timestamp_ns, struct timespec *ts);
void flow_table_destroy();
void cleanup_flows();

// 引用计数管理函数
void flow_ref_inc(struct flow_node *node);  // 增加引用计数
void flow_ref_dec(struct flow_node *node);  // 减少引用计数，当计数为0时自动释放
int flow_get_ref_count(struct flow_node *node);  // 获取引用计数
void print_flow_ref_counts();  // 打印所有flow的引用计数（调试用）

// Flow清理函数
int cleanup_flow_and_sessions(struct flow_node *node);  // 释放flow及其所有session

// Time utility function
double time_diff(const struct timespec *end, const struct timespec *start);

struct flow_stats* get_flow_stats(const struct flow_key *key, int *is_reverse_ptr, uint64_t packet_timestamp) ;
void update_flow_stats(struct flow_stats *stats, uint32_t pkt_size, int is_reverse, uint64_t packet_timestamp);
void reset_flow_stats_for_new_session(struct flow_stats *stats, uint64_t packet_timestamp);
void calculate_flow_features(const struct flow_stats *stats, struct flow_features *features);

void process_packet(const struct iphdr *ip, const void *transport_hdr, uint64_t packet_timestamp);
int count_active_flows();
int count_all_flows();  // 统计唯一的五元组数量

// UDP流管理 - Wireshark风格
void reset_udp_stream_counter(void);
uint32_t get_next_udp_stream_id(void);
int verify_udp_conversation_count(void);


// 活跃/空闲时间管理




uint32_t get_total_conversation_count();

uint32_t hash_flow_key(const struct flow_key *key);
uint64_t get_current_time();

// 时间戳数组操作函数
void timestamp_array_init(timestamp_array_t *arr);
void timestamp_array_add(timestamp_array_t *arr, uint64_t timestamp);
void timestamp_array_free(timestamp_array_t *arr);



// cicflowmeter Integration - Bulk Transfer Threshold
#define CIC_BULK_BYTE_THRESHOLD   512      // 批量传输阈值 (字节)

// cicflowmeter Integration - Subflow Timeout
#define CIC_SUBFLOW_TIMEOUT_NS    1000000000ULL   // 子流超时时间 (1秒)



// =================== Wireshark 风格的对话统计函数 ===================

// 对话计数器重置函数 (类似Wireshark的tcp_init())
void reset_conversation_counters();


// 分配对话ID函数 (类似Wireshark的tcpd->stream = tcp_stream_count++)
uint32_t assign_tcp_conversation_id();
uint32_t assign_udp_conversation_id();

// **新增函数**: 为指定协议分配对话ID
void assign_conversation_id_for_protocol(struct flow_stats *stats, uint8_t protocol);

// Wireshark风格的流创建函数 (类似find_or_create_conversation)
struct flow_stats* get_or_create_conversation(const struct flow_key *key, int *is_reverse_ptr, uint64_t packet_timestamp, uint8_t tcp_flags);

// 简化的会话状态管理函数
void update_session_state(struct flow_node *node, uint8_t tcp_flags);
bool is_session_complete(struct flow_node *node);
bool should_create_new_session(struct flow_node *node, uint8_t tcp_flags, uint64_t packet_timestamp);

// Wireshark风格的统计打印函数
void print_wireshark_conversation_stats();
int count_wireshark_udp_conversations();

// =================== Tshark风格兼容函数声明 ===================




extern int quiet_mode;       // 安静模式变量
extern int tshark_stats_mode; // tshark兼容统计模式变量

// =================== 函数声明 ===================

// 流表管理
void flow_table_init(void);
void flow_table_destroy(void);
uint32_t hash_flow_key(const struct flow_key *key);
struct flow_node *flow_table_insert_with_timestamp(const struct flow_key *key, uint64_t packet_timestamp);

// 对话管理
struct flow_stats* get_or_create_conversation(const struct flow_key *key, int *is_reverse_ptr, uint64_t packet_timestamp, uint8_t tcp_flags);
struct flow_stats* get_or_create_udp_conversation(const struct flow_key *key, int *is_reverse_ptr, uint64_t packet_timestamp);

// 会话创建函数
struct flow_stats* create_and_init_session_node(const struct flow_key *normalized_key, 
                                               uint64_t packet_timestamp, uint8_t tcp_flags,
                                               bool is_reverse, uint16_t original_src_port, 
                                               uint16_t original_dst_port, uint32_t original_src_ip,
                                               uint32_t original_dst_ip, uint8_t protocol);

// 包处理
void process_packet(const struct iphdr *ip, const void *transport_hdr, uint64_t packet_timestamp);

// 统计函数
void update_flow_stats(struct flow_stats *stats, uint32_t pkt_size, int is_reverse, uint64_t packet_timestamp);


// 对话计数器管理
void reset_conversation_counters(void);
uint32_t get_tcp_conversation_count(void);
uint32_t get_udp_conversation_count(void);
uint32_t get_total_conversation_count(void);
uint32_t assign_tcp_conversation_id(void);
uint32_t assign_udp_conversation_id(void);

// Wireshark风格统计
int count_wireshark_tcp_conversations(void);
int count_wireshark_udp_conversations(void);
int count_wireshark_all_conversations(void);
void count_tcp_conversations_by_completeness(int *complete, int *incomplete, int *partial);
void print_wireshark_conversation_stats(void);





// 流特征计算
void calculate_flow_features(const struct flow_stats *stats, struct flow_features *features);


void print_flow_stats(void);

// 清理函数
void cleanup_flows(void);

// 时间处理
uint64_t get_current_time(void);
void ns_to_timespec(uint64_t timestamp_ns, struct timespec *ts);
void set_flow_start_time_from_timestamp(struct flow_stats *stats, uint64_t timestamp_ns);
double time_diff(const struct timespec *end, const struct timespec *start);

// 调试控制
void set_debug_level(int level);
int get_debug_level(void);

// 时间戳数组管理
void timestamp_array_init(timestamp_array_t *arr);
void timestamp_array_add(timestamp_array_t *arr, uint64_t timestamp);
void timestamp_array_free(timestamp_array_t *arr);

// 五元组会话统计函数
void count_sessions_by_five_tuple();



// **新增**: tshark风格会话计数和验证函数
int count_tshark_style_tcp_sessions();
void verify_tshark_style_counting();

// 会话创建统计
void get_session_creation_stats(uint64_t *total_created, uint64_t *tcp_created, uint64_t *udp_created, uint64_t *reused);

// tshark风格会话验证
void verify_tshark_style_session_creation();


void format_ebpf_packet_time(uint64_t ktime_ns, char *buf, size_t buflen);

#endif /* FLOW_H */

