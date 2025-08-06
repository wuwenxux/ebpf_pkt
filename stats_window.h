#ifndef STATS_WINDOW_H
#define STATS_WINDOW_H

#include <ncurses.h>
#include <stdatomic.h>
#include <stdint.h>

// 实时统计结构
typedef struct {
    atomic_ulong packet_count;
    atomic_uint tcp_session_count;
    atomic_uint udp_session_count;
    double memory_usage_percent;
    uint64_t last_update_time;
} realtime_stats_t;

// 会话信息结构（用于显示）
typedef struct {
    uint32_t session_id;
    char src_ip[16];
    char dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint8_t protocol;
    char start_time_str[32];
    double duration;
    uint64_t packets_total;
    uint64_t bytes_total;
    // features前20个属性
    double fl_dur;
    char features_start_time[32];
    uint64_t tot_fw_pk;
    uint64_t tot_bw_pk;
    uint64_t tot_1_fw_pk;
    uint64_t tot_1_bw_pk;
    uint32_t fwd_pkt_1_max;
    uint32_t fwd_pkt_1_min;
    double fwd_pkt_1_avg;
    double fwd_pkt_1_std;
    uint32_t bwd_pkt_1_max;
    uint32_t bwd_pkt_1_min;
    double bwd_pkt_1_avg;
    double bwd_pkt_1_std;
    double fl_byt_s;
    double fl_pkt_s;
    double fl_iat_avg;
    double fl_iat_std;
    double fl_iat_max;
    double fl_iat_min;
} session_display_info_t;

// 全局实时统计
extern realtime_stats_t g_realtime_stats;

// 函数声明
WINDOW *init_stats_window();
void update_stats_window(WINDOW *win);
void cleanup_stats_window(WINDOW *win);
void init_realtime_stats();
void update_realtime_stats();
void get_latest_sessions(session_display_info_t *sessions, int max_count, int *actual_count);
void draw_session_table(WINDOW *win, int start_y);
void draw_stats_header(WINDOW *win);
void draw_ebpf_stats_window(WINDOW *win);
void run_realtime_monitor();

#endif // STATS_WINDOW_H 