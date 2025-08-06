#include <ncurses.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <stdint.h>
#include <stdbool.h>
#include <math.h>
#include <stdatomic.h>

#include "flow.h"
#include "loader.h"
#include "logger.h"
#include "transport_session.h"

// 前向声明
typedef struct lockfree_queue lockfree_queue_t;
extern uint64_t packet_queue_size(lockfree_queue_t *queue);
extern lockfree_queue_t packet_queue;

// 会话管理器类型定义
typedef struct session_manager session_manager_t;

// 实时统计结构定义
typedef struct {
    atomic_uint packet_count;
    atomic_uint tcp_session_count;
    atomic_uint udp_session_count;
    double memory_usage_percent;
    time_t last_update_time;
} realtime_stats_t;

// 会话显示信息结构
typedef struct {
    uint8_t protocol;
    char src_ip[16];
    char dst_ip[16];
    uint16_t src_port;
    uint16_t dst_port;
    uint32_t session_id;
    double duration;
    uint64_t packets_total;
    uint64_t bytes_total;
    double fl_dur;
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
    char start_time_str[64];
    char features_start_time[64];
    double fl_pkt_s;
    double fl_iat_avg;
    double fl_iat_std;
    double fl_iat_max;
    double fl_iat_min;
} session_display_info_t;

// 系统统计结构定义（与system_stats.c保持一致）
typedef struct {
    double cpu_usage;
    double memory_usage;
    uint64_t packets_processed;
    double processing_time;
    uint64_t packets_per_second;
} system_stats_t;

// 全局实时统计
extern realtime_stats_t g_realtime_stats;

// 使用system_stats.c中定义的system_stats_t
extern system_stats_t system_stats;
extern volatile int running;
extern void update_system_stats(void);
extern double get_memory_usage(void);
extern session_manager_t *global_session_manager;
extern void sig_handler(int sig);

// 外部变量声明（从loader.c导入）
extern volatile uint64_t total_packets_captured;
extern volatile uint64_t total_bytes_captured;
extern volatile uint64_t total_packets_processed;
extern volatile uint64_t total_bytes_processed;

// 初始化实时统计
void init_realtime_stats() {
    atomic_init(&g_realtime_stats.packet_count, 0);
    atomic_init(&g_realtime_stats.tcp_session_count, 0);
    atomic_init(&g_realtime_stats.udp_session_count, 0);
    g_realtime_stats.memory_usage_percent = 0.0;
    g_realtime_stats.last_update_time = 0;
}

// 更新实时统计
void update_realtime_stats() {
    // 更新系统统计
    update_system_stats();
    
    // 更新内存使用率
    g_realtime_stats.memory_usage_percent = get_memory_usage();
    
    // 更新会话统计（从全局会话管理器获取）
    if (global_session_manager) {
        uint32_t tcp_count = atomic_load(&global_session_manager->tcp_sessions);
        uint32_t udp_count = atomic_load(&global_session_manager->udp_sessions);
        
        atomic_store(&g_realtime_stats.tcp_session_count, tcp_count);
        atomic_store(&g_realtime_stats.udp_session_count, udp_count);
        
        // 调试输出（每5秒输出一次）
        static time_t last_debug_time = 0;
        time_t current_time = time(NULL);
        if (current_time - last_debug_time >= 5) {
            log_debug("TCP sessions: %u, UDP sessions: %u", tcp_count, udp_count);
            last_debug_time = current_time;
        }
    }
    
    g_realtime_stats.last_update_time = time(NULL);
}

// 获取最新会话列表
void get_latest_sessions(session_display_info_t *sessions, int max_count, int *actual_count) {
    if (!global_session_manager || !sessions) {
        *actual_count = 0;
        return;
    }
    
    session_display_info_t *temp_sessions = malloc(SESSION_HASH_SIZE * sizeof(session_display_info_t));
    if (!temp_sessions) {
        *actual_count = 0;
        return;
    }
    
    int session_count = 0;
    
    // 遍历所有会话
    int total_sessions_found = 0;
    int active_sessions_found = 0;
    
    for (int i = 0; i < SESSION_HASH_SIZE; i++) {
        transport_session_t *session = atomic_load_session_ptr(&global_session_manager->sessions[i]);
        while (session && session_count < SESSION_HASH_SIZE) {
            total_sessions_found++;
            // 暂时显示所有会话，不仅仅是活跃的
            if (1) { // atomic_load(&session->is_active)) {
                active_sessions_found++;
                session_display_info_t *info = &temp_sessions[session_count];
                
                // 基本信息
                info->session_id = session->session_id;
                info->protocol = session->key.protocol;
                info->src_port = ntohs(session->key.src_port);
                info->dst_port = ntohs(session->key.dst_port);
                
                // IP地址转换 - 使用线程安全的inet_ntop
                struct in_addr src_addr = {.s_addr = session->key.src_ip};
                struct in_addr dst_addr = {.s_addr = session->key.dst_ip};
                inet_ntop(AF_INET, &src_addr, info->src_ip, sizeof(info->src_ip));
                inet_ntop(AF_INET, &dst_addr, info->dst_ip, sizeof(info->dst_ip));
                
                // 时间信息
                time_t start_time_sec = session->stats.first_packet / 1000000000ULL;
                struct tm *tm_info = localtime(&start_time_sec);
                strftime(info->start_time_str, sizeof(info->start_time_str), "%H:%M:%S", tm_info);
                
                // 持续时间
                info->duration = (session->stats.last_packet - session->stats.first_packet) / 1000000000.0;
                
                // 统计信息
                info->packets_total = session->stats.total_packets;
                info->bytes_total = session->stats.total_bytes;
                
                // features前20个属性
                struct flow_features *features = &session->stats.features;
                info->fl_dur = features->fl_dur;
                strncpy(info->features_start_time, features->start_time_str, sizeof(info->features_start_time) - 1);
                info->tot_fw_pk = features->tot_fw_pk;
                info->tot_bw_pk = features->tot_bw_pk;
                info->tot_1_fw_pk = features->tot_1_fw_pk;
                info->tot_1_bw_pk = features->tot_1_bw_pk;
                info->fwd_pkt_1_max = features->fwd_pkt_1_max;
                info->fwd_pkt_1_min = features->fwd_pkt_1_min;
                info->fwd_pkt_1_avg = features->fwd_pkt_1_avg;
                info->fwd_pkt_1_std = features->fwd_pkt_1_std;
                info->bwd_pkt_1_max = features->bwd_pkt_1_max;
                info->bwd_pkt_1_min = features->bwd_pkt_1_min;
                info->bwd_pkt_1_avg = features->bwd_pkt_1_avg;
                info->bwd_pkt_1_std = features->bwd_pkt_1_std;
                info->fl_byt_s = features->fl_byt_s;
                info->fl_pkt_s = features->fl_pkt_s;
                info->fl_iat_avg = features->fl_iat_avg;
                info->fl_iat_std = features->fl_iat_std;
                info->fl_iat_max = features->fl_iat_max;
                info->fl_iat_min = features->fl_iat_min;
                
                session_count++;
            }
            session = atomic_load_session_ptr(&session->next_atomic);
        }
    }
    
    // 按时间排序（最新的在前）
    for (int i = 0; i < session_count - 1; i++) {
        for (int j = i + 1; j < session_count; j++) {
            if (temp_sessions[i].duration < temp_sessions[j].duration) {
                session_display_info_t temp = temp_sessions[i];
                temp_sessions[i] = temp_sessions[j];
                temp_sessions[j] = temp;
            }
        }
    }
    
    // 复制前max_count个会话
    *actual_count = (session_count < max_count) ? session_count : max_count;
    memcpy(sessions, temp_sessions, *actual_count * sizeof(session_display_info_t));
    
    // 调试输出（每3秒输出一次）
    /*
    static time_t last_session_debug_time = 0;
    time_t current_time = time(NULL);
    if (current_time - last_session_debug_time >= 3) {
        log_debug("Found %d total sessions, %d active sessions, displaying %d sessions", 
               total_sessions_found, active_sessions_found, *actual_count);
        last_session_debug_time = current_time;
    }
    */
    
    free(temp_sessions);
}

// 绘制统计头部
void draw_stats_header(WINDOW *win) {
    wclear(win);
    box(win, 0, 0);
    
    // 标题
    mvwprintw(win, 0, 2, " eBPF Packet Monitor ");
    
    // 获取当前时间（东八区 UTC+8）
    time_t now = time(NULL);
    now += 8 * 3600; // 转换为东八区时间
    struct tm *tm_info = gmtime(&now);
    char time_str[30];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // 获取eBPF统计信息
    // extern volatile uint64_t total_packets_captured; // This line is removed as per the new_code
    // extern volatile uint64_t total_bytes_captured; // This line is removed as per the new_code
    // extern volatile uint64_t total_packets_processed; // This line is removed as per the new_code
    
    // 计算处理效率
    double processing_ratio = 0.0;
    if (total_packets_captured > 0) {
        processing_ratio = (double)total_packets_processed / total_packets_captured * 100.0;
    }
    
    // 计算速率（基于最近的数据）
    static uint64_t last_packet_count = 0;
    static uint64_t last_byte_count = 0;
    static uint64_t last_time = 0;
    
    uint64_t current_time = get_current_time();
    double pps = 0.0, bps = 0.0;
    
    if (last_time > 0 && current_time > last_time) {
        uint64_t time_diff = current_time - last_time;
        uint64_t packet_diff = total_packets_captured - last_packet_count;
        uint64_t byte_diff = total_bytes_captured - last_byte_count;
        
        if (time_diff > 0) {
            // 转换为秒并计算速率
            double time_diff_sec = (double)time_diff / 1000000000.0;
            pps = (double)packet_diff / time_diff_sec;
            bps = (double)byte_diff / time_diff_sec;
        }
    }
    
    last_packet_count = total_packets_captured;
    last_byte_count = total_bytes_captured;
    last_time = current_time;
    
    // 显示eBPF统计信息
    mvwprintw(win, 1, 2, "Time: %s", time_str);
    mvwprintw(win, 2, 2, "eBPF Captured: %lu pkts (%.1f pkt/s) | %.2f MB (%.1f KB/s) | Processing: %.1f%%", 
               total_packets_captured, pps,
               total_bytes_captured / (1024.0 * 1024.0), bps / 1024.0,
               processing_ratio);
    
    // 分隔线
    for (int i = 1; i < COLS - 1; i++) {
        mvwaddch(win, 3, i, '-');
    }
    
    // 状态栏 - 显示当前模式和按键帮助
    mvwprintw(win, 4, 2, "Mode: Normal Stats | Keys: E-Switch eBPF Stats Q-Quit H-Help");
    
    wrefresh(win);
}

// 绘制会话表格
void draw_session_table(WINDOW *win, int start_y) {
    session_display_info_t sessions[30];
    int actual_count;
    
    get_latest_sessions(sessions, 30, &actual_count);
    
    // 表头 - 显示前20个特征，增加列宽和间距，居中显示
    mvwprintw(win, start_y, 1, "%4s  %5s  %20s  %20s  %8s  %6s  %8s  %8s  %8s  %8s  %8s  %8s  %8s  %8s  %8s  %8s  %8s  %8s  %8s  %8s  %8s",
              "ID", "Proto", "SrcIP:Port", "DstIP:Port", "Dur", "Pkts", "Bytes", "fl_dur", "fw_pk", "bw_pk", "fw_byt", "bw_byt", "fw_max", "fw_min", "fw_avg", "fw_std", "bw_max", "bw_min", "bw_avg", "bw_std", "fl_byt_s");
    
    // 会话数据
    for (int i = 0; i < actual_count && i < 30; i++) {
        session_display_info_t *s = &sessions[i];
        const char *proto_str = (s->protocol == 6) ? "TCP" : (s->protocol == 17) ? "UDP" : "OTH";
        
        // 格式化IP:Port字符串
        char src_addr[32], dst_addr[32];
        snprintf(src_addr, sizeof(src_addr), "%s:%u", s->src_ip, s->src_port);
        snprintf(dst_addr, sizeof(dst_addr), "%s:%u", s->dst_ip, s->dst_port);
        
        mvwprintw(win, start_y + 1 + i, 1, 
                  "%4u  %5s  %20s  %20s  %8.1f  %6lu  %8lu  %8.2f  %8lu  %8lu  %8lu  %8lu  %8u  %8u  %8.1f  %8.1f  %8u  %8u  %8.1f  %8.1f  %8.1f",
                  s->session_id,
                  proto_str,
                  src_addr,
                  dst_addr,
                  s->duration,
                  s->packets_total,
                  s->bytes_total,
                  s->fl_dur,
                  s->tot_fw_pk,
                  s->tot_bw_pk,
                  s->tot_1_fw_pk,
                  s->tot_1_bw_pk,
                  s->fwd_pkt_1_max,
                  s->fwd_pkt_1_min,
                  s->fwd_pkt_1_avg,
                  s->fwd_pkt_1_std,
                  s->bwd_pkt_1_max,
                  s->bwd_pkt_1_min,
                  s->bwd_pkt_1_avg,
                  s->bwd_pkt_1_std,
                  s->fl_byt_s);
    }
    
    // 清空剩余行
    for (int i = actual_count; i < 30; i++) {
        mvwprintw(win, start_y + 1 + i, 1, " ");
        wclrtoeol(win);
    }
    
    wrefresh(win);
}

// 绘制eBPF统计窗口
void draw_ebpf_stats_window(WINDOW *win) {
    wclear(win);
    box(win, 0, 0);
    
    // 标题
    mvwprintw(win, 0, 2, " eBPF Statistics ");
    
    // 获取eBPF统计信息
    // extern volatile uint64_t total_packets_captured; // This line is removed as per the new_code
    // extern volatile uint64_t total_bytes_captured; // This line is removed as per the new_code
    // extern volatile uint64_t total_packets_processed; // This line is removed as per the new_code
    // extern volatile uint64_t total_bytes_processed; // This line is removed as per the new_code
    
    // 计算处理效率
    double packet_processing_ratio = 0.0;
    double byte_processing_ratio = 0.0;
    if (total_packets_captured > 0) {
        packet_processing_ratio = (double)total_packets_processed / total_packets_captured * 100.0;
    }
    if (total_bytes_captured > 0) {
        byte_processing_ratio = (double)total_bytes_processed / total_bytes_captured * 100.0;
    }
    
    // 获取队列状态
    uint64_t queue_size = packet_queue_size(&packet_queue);
    
    // 获取当前时间
    time_t now = time(NULL);
    now += 8 * 3600; // 转换为东八区时间
    struct tm *tm_info = gmtime(&now);
    char time_str[30];
    strftime(time_str, sizeof(time_str), "%Y-%m-%d %H:%M:%S", tm_info);
    
    // 显示eBPF捕获统计
    mvwprintw(win, 1, 2, "Time: %s", time_str);
    mvwprintw(win, 2, 2, "eBPF Capture Statistics:");
    mvwprintw(win, 3, 4, "Captured Packets: %lu", total_packets_captured);
    mvwprintw(win, 4, 4, "Captured Bytes: %lu (%.2f MB)", total_bytes_captured, 
               total_bytes_captured / (1024.0 * 1024.0));
    
    // 显示处理统计
    mvwprintw(win, 5, 2, "Processing Statistics:");
    mvwprintw(win, 6, 4, "Processed Packets: %lu", total_packets_processed);
    mvwprintw(win, 7, 4, "Processed Bytes: %lu (%.2f MB)", total_bytes_processed, 
               total_bytes_processed / (1024.0 * 1024.0));
    
    // 显示处理效率
    mvwprintw(win, 8, 2, "Processing Efficiency:");
    mvwprintw(win, 9, 4, "Packet Processing Rate: %.1f%%", packet_processing_ratio);
    mvwprintw(win, 10, 4, "Byte Processing Rate: %.1f%%", byte_processing_ratio);
    
    // 显示队列状态
    mvwprintw(win, 11, 2, "Queue Status: %lu packets pending", queue_size);
    
    // 状态指示
    const char *status_msg = "";
    if (packet_processing_ratio < 95.0) {
        status_msg = "Warning: Low processing efficiency";
    } else if (queue_size > 1000) {
        status_msg = "Warning: Severe queue backlog";
    } else if (queue_size > 100) {
        status_msg = "Notice: Queue has backlog";
    } else {
        status_msg = "Status: Normal";
    }
    mvwprintw(win, 12, 4, "%s", status_msg);
    
    // 状态栏 - 显示当前模式和按键帮助
    mvwprintw(win, 13, 2, "Mode: eBPF Statistics | Keys: E-Switch Normal Stats Q-Quit H-Help");
    
    wrefresh(win);
}

// 初始化统计窗口
WINDOW *init_stats_window() {
    initscr();
    cbreak();
    noecho();
    curs_set(0);
    nodelay(stdscr, TRUE);
    
    // 创建主窗口
    WINDOW *win = newwin(LINES, COLS, 0, 0);
    box(win, 0, 0);
    wrefresh(win);
    
    // 初始化实时统计
    init_realtime_stats();
    
    return win;
}

// 更新统计窗口
void update_stats_window(WINDOW *win) {
    update_realtime_stats();
    
    // 绘制统计头部
    draw_stats_header(win);
    
    // 绘制会话表格
    draw_session_table(win, 4);
    
    // 底部提示
    mvwprintw(win, LINES - 2, 1, "Press 'q' to quit, 'r' to refresh");
    wrefresh(win);
}

// 清理统计窗口
void cleanup_stats_window(WINDOW *win) {
    delwin(win);
    endwin();
    
    // 确保光标回到正常位置并恢复终端状态
    printf("\n");
    fflush(stdout);
    
    // 恢复终端到正常状态
    printf("\033[?25h");  // 显示光标
    printf("\033[0m");     // 重置所有属性
    fflush(stdout);
}

// 删除未使用的run_realtime_monitor函数 