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

// 添加缺失的宏定义
#define MAX_TIMESTAMPS 1000

// =================== 调试级别控制 ===================
void set_debug_level(int level);
int get_debug_level();

// =================== 流管理参数 ===================

// 流超时配置 - 调整为更接近Wireshark的默认设置
#define FLOW_TIMEOUT_NS (120 * 1000000000ULL)    // 流过期时间 (120秒，类似Wireshark)
#define TCP_FLOW_TIMEOUT_NS (120 * 1000000000ULL) // TCP流120秒超时，与Wireshark一致

// cicflowmeter 活跃超时配置
#define ACTIVE_TIMEOUT_NS (5 * 1000000ULL)       // 活跃超时时间 (5毫秒 = 0.005秒)
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
#define TCP_ECE  0x40
#define TCP_CWR  0x80

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
    
    // =================== cicflowmeter 状态管理字段 ===================
    
    // 流状态管理 (cicflowmeter 兼容)
    uint64_t last_activity_time;            // 最后活跃时间 (纳秒)
    uint32_t packet_count;                  // 总包数计数器
    uint32_t subflow_count;                 // 子流计数
    
    // 批量传输特性字段 (新的 cicflowmeter 实现)
    uint64_t fwd_bulk_bytes;                // 前向批量传输字节数
    uint32_t fwd_bulk_packets;              // 前向批量传输包数
    uint32_t fwd_bulk_state_count;          // 前向批量传输状态计数
    uint64_t fwd_bulk_duration_ns;          // 前向批量传输持续时间
    uint64_t fwd_bulk_start;                // 前向批量传输开始时间
    double   fwd_bulk_rate;                 // 前向批量传输速率
    
    uint64_t bwd_bulk_bytes;                // 反向批量传输字节数
    uint32_t bwd_bulk_packets;              // 反向批量传输包数
    uint32_t bwd_bulk_state_count;          // 反向批量传输状态计数
    uint64_t bwd_bulk_duration_ns;          // 反向批量传输持续时间
    uint64_t bwd_bulk_start;                // 反向批量传输开始时间
    double   bwd_bulk_rate;                 // 反向批量传输速率
    
    // 子流管理字段
    uint64_t last_subflow_time;             // 最后子流时间
    uint32_t subflow_packets;               // 当前子流包数
    uint64_t subflow_bytes;                 // 当前子流字节数
    uint64_t subflow_start;                 // 当前子流开始时间
    uint64_t subflow_duration_ns;           // 当前子流持续时间
    
    // 活跃/空闲时间管理字段
    uint64_t active_time_ns;                // 累积活跃时间
    uint64_t idle_time_ns;                  // 累积空闲时间
    uint64_t active_max_ns;                 // 最大活跃时间
    uint64_t active_min_ns;                 // 最小活跃时间
    uint64_t active_mean_ns;                // 平均活跃时间
    uint64_t idle_max_ns;                   // 最大空闲时间
    uint64_t idle_min_ns;                   // 最小空闲时间
    uint64_t idle_mean_ns;                  // 平均空闲时间
    uint64_t idle_std_ns;                   // 空闲状态标准差
    
    // 流分割控制 (cicflowmeter 逻辑)
    uint64_t last_fin_time;                 // 最后FIN包时间
    uint8_t  fin_seen;                      // 是否看到FIN包
    uint8_t  rst_seen;                      // 是否看到RST包
    
    // 第一个包的方向 (用于确定正向/反向)
    uint8_t  first_packet_direction;
    
    // 垃圾回收和流管理
    uint8_t  should_expire;                 // 标记是否应该过期
    uint8_t  in_garbage_collect;            // 标记是否在垃圾回收中
    uint8_t  session_completed;             // 标记TCP会话是否已完成（FIN或RST）

    // TCP端口重用检测字段
    uint32_t tcp_base_seq;          // TCP基础序列号，用于检测端口重用
    bool tcp_base_seq_set;       // 是否已设置TCP基础序列号
    bool tcp_session_ended;      // TCP会话是否已结束（收到RST或FIN）

    uint64_t forward_packets;
    uint64_t reverse_packets;
    uint64_t total_packets;
    uint64_t total_bytes;
    uint64_t first_packet_time;
    uint64_t last_packet_time;
    uint64_t timestamps[MAX_TIMESTAMPS];
    uint32_t timestamp_index;
    uint32_t tcp_conversation_id;
    uint32_t udp_conversation_id;
    uint8_t conversation_completeness;
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
    char start_time_str[64];        // 开始时间字符串(年月日时分秒)
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
    
    // =================== 原始端口号字段（用于CSV输出）===================
    uint16_t original_src_port;     // 原始源端口号（数据包中的实际端口）
    uint16_t original_dst_port;     // 原始目标端口号（数据包中的实际端口）
    uint32_t original_src_ip;       // 原始源IP地址
    uint32_t original_dst_ip;       // 原始目标IP地址
    
    // =================== Wireshark风格的对话字段 ===================
    uint32_t conversation_id;       // 对话ID (类似Wireshark的stream)
    uint8_t  completeness;          // 对话完整性标志
    uint64_t first_packet_time;     // 第一个包的时间戳
    uint64_t last_packet_time;      // 最后一个包的时间戳
    uint32_t packet_num;            // 流内包序号
    uint8_t  create_flags;          // 创建时的标志 (SYN/UDP等)
};

// 大幅增加哈希表大小以减少冲突
#define HASH_TABLE_SIZE 262144  // 增加到256K
extern struct flow_node* flow_table[HASH_TABLE_SIZE]; // 哈希表

void flow_table_init();
struct flow_node *flow_table_insert(const struct flow_key *key);
struct flow_node *flow_table_insert_with_timestamp(const struct flow_key *key, uint64_t packet_timestamp);
void set_flow_start_time_from_timestamp(struct flow_stats *stats, uint64_t timestamp_ns);
void ns_to_timespec(uint64_t timestamp_ns, struct timespec *ts);
void flow_table_destroy();
void cleanup_flows();

// Time utility function
double time_diff(const struct timespec *end, const struct timespec *start);

struct flow_stats* get_flow_stats(const struct flow_key *key, int *is_reverse_ptr, uint64_t packet_timestamp) ;
void update_flow_stats(struct flow_stats *stats, uint32_t pkt_size, int is_reverse, uint64_t packet_timestamp);
void reset_flow_stats_for_new_session(struct flow_stats *stats, uint64_t packet_timestamp);
void update_tcp_flags(struct flow_stats *stats, uint8_t tcp_flags, int is_reverse);
void update_udp_stats(struct flow_stats *stats, uint32_t pkt_size, int is_reverse, uint64_t packet_timestamp);
void calculate_flow_features(const struct flow_stats *stats, struct flow_features *features);
void print_flow_stats();
void process_packet(const struct iphdr *ip, const void *transport_hdr, uint64_t packet_timestamp);
int count_active_flows();
void count_flow_directions(int *forward_flows, int *reverse_flows);
int count_all_flows();
void count_all_flow_directions(int *forward_flows, int *reverse_flows);
uint32_t get_total_conversation_count();

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

// cicflowmeter Integration - Bulk Transfer Threshold
#define CIC_BULK_BYTE_THRESHOLD   512      // 批量传输阈值 (字节)

// cicflowmeter Integration - Subflow Timeout
#define CIC_SUBFLOW_TIMEOUT_NS    1000000000ULL   // 子流超时时间 (1秒)

// =================== cicflowmeter 风格的流处理函数 ===================
void update_subflow_cic(struct flow_stats *stats, uint64_t packet_timestamp);
void update_active_idle_cic(struct flow_stats *stats, uint64_t current_time_diff);
void update_flow_bulk_cic(struct flow_stats *stats, uint32_t payload_size, int is_reverse, uint64_t packet_timestamp);

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

// 更新对话完整性函数 (类似Wireshark的completeness tracking)
void update_conversation_completeness(struct flow_node *node, uint8_t tcp_flags);

// Wireshark风格的统计打印函数
void print_wireshark_conversation_stats();
int count_wireshark_tcp_conversations();
int count_wireshark_udp_conversations();
int count_wireshark_all_conversations();
void count_tcp_conversations_by_completeness(int *complete, int *incomplete, int *partial);

// =================== Tshark风格兼容函数声明 ===================

// 统计函数 - 与tshark完全兼容
int count_tshark_tcp_conversations();       // 统计TCP对话数（与tshark -z conv,tcp一致）
int count_tshark_udp_conversations();       // 统计UDP对话数（与tshark -z conv,udp一致）
int count_tshark_ip_conversations();        // 统计IP对话数（与tshark -z conv,ip一致）
void print_tshark_style_stats();            // 打印tshark风格的统计信息

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

// UDP流管理 - Wireshark风格
void reset_udp_stream_counter(void);
uint32_t get_next_udp_stream_id(void);
int verify_udp_conversation_count(void);
void print_udp_conversation_details(void);

// 包处理
void process_packet(const struct iphdr *ip, const void *transport_hdr, uint64_t packet_timestamp);

// 统计函数
void update_flow_stats(struct flow_stats *stats, uint32_t pkt_size, int is_reverse, uint64_t packet_timestamp);
void update_udp_stats(struct flow_stats *stats, uint32_t pkt_size, int is_reverse, uint64_t packet_timestamp);

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



// TCP会话统计
int count_tcp_sessions_by_lifecycle(void);
void count_tcp_sessions_by_state(int *init_sessions, int *established_sessions, 
                                 int *closing_sessions, int *reset_sessions, int *unknown_sessions);

// 流特征计算
void calculate_flow_features(const struct flow_stats *stats, struct flow_features *features);

// 打印函数
void print_simple_stats(void);
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

// Wireshark风格会话打印函数
void print_all_wireshark_sessions();

// **新增**: tshark风格会话计数和验证函数
int count_tshark_style_tcp_sessions();
void verify_tshark_style_counting();

#endif /* FLOW_H */
