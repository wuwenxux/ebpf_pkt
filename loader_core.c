#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <getopt.h>
#include <time.h>
#include <fcntl.h>
#include <sys/file.h>
#include <pthread.h>
#include <sys/resource.h>
#include <sys/times.h>
#include <sys/sysinfo.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// 处理BPF和PCAP的冲突 - 先包含PCAP，再包含BPF
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap.h>

// BPF相关头文件
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <linux/if_link.h>

// 项目头文件
#include "loader.h"
#include "flow.h"
#include "stats_window.h"
#include "transport_session.h"
#include "worker_threads.h"
#include "ringbuf_handler.h"
#include "interface_manager.h"

// 全局变量定义
volatile int running = 1;
int quiet_mode = 0;
int loop_count = 1;
int loop_delay = 0;
int duration = 0;
int single_thread_mode = 1;  // 默认单线程模式
static volatile sig_atomic_t cleanup_done = 0;
static volatile int monitor_running = 1;  // 监控模式运行状态

// 全局配置变量
int stats_interval = DEFAULT_STATS_INTERVAL;
int stats_packet_count = DEFAULT_STATS_PACKETS;
int cleanup_interval = DEFAULT_CLEANUP_INTERVAL;
char *csv_file = NULL;

// 全局统计变量
volatile uint64_t total_packets_captured = 0;
volatile uint64_t total_bytes_captured = 0;
volatile uint64_t total_packets_processed = 0;
volatile uint64_t total_bytes_processed = 0;
volatile uint64_t total_packets_dropped = 0;
volatile uint64_t total_packets_invalid = 0;
volatile uint64_t total_packets_queued = 0;
volatile uint64_t total_packets_dequeued = 0;
volatile uint64_t global_packet_count = 0;

// 全局时间基准
struct timespec boot_realtime;
uint64_t boot_monotonic_ns = 0;
time_t start_time;

// 全局RINGBUF处理器
struct ring_buffer *global_ringbuf = NULL;
struct bpf_object *global_bpf_obj = NULL;
struct bpf_link **global_links = NULL;
int global_link_count = 0;

// 全局无锁队列
lockfree_queue_t global_lockfree_queue;

// 数据包队列
packet_queue_t packet_queue;

// 系统统计
struct {
    double cpu_usage;
    double memory_usage;
    uint64_t packets_processed;
    double processing_time;
    uint64_t packets_per_second;
} system_stats;

// 锁文件路径
#define LOCK_FILE "/var/run/ebpf_pkt.lock"
static int lock_fd = -1;

// 信号处理函数
void sig_handler(int sig) {
    if (sig == SIGINT || sig == SIGTERM) {
        printf("\nReceived signal %d, shutting down...\n", sig);
        running = 0;
        monitor_running = 0;
    }
}

// 清理函数
void cleanup(void) {
    if (cleanup_done) return;
    cleanup_done = 1;
    
    log_info("Starting cleanup...");
    
    // 清理接口资源
    cleanup_interface_resources();
    
    // 清理全局RINGBUF
    if (global_ringbuf) {
        ring_buffer__free(global_ringbuf);
        global_ringbuf = NULL;
    }
    
    if (global_links) {
        for (int i = 0; i < global_link_count; i++) {
            if (global_links[i]) {
                // 检查是否是真正的bpf_link对象还是我们存储的ifindex
                uintptr_t ptr_value = (uintptr_t)global_links[i];
                if (ptr_value < 65536) { // 假设ifindex不会超过65535
                    // 这是一个ifindex，表示SKB模式，需要手动分离XDP程序
                    int ifindex = (int)ptr_value;
                    bpf_xdp_detach(ifindex, XDP_FLAGS_SKB_MODE, NULL);
                    log_info("Detached XDP program from interface (ifindex: %d) in SKB mode", ifindex);
                } else {
                    // 这是一个真正的bpf_link对象
                    bpf_link__destroy(global_links[i]);
                }
            }
        }
        free(global_links);
        global_links = NULL;
        global_link_count = 0;
    }
    
    if (global_bpf_obj) {
        bpf_object__close(global_bpf_obj);
        global_bpf_obj = NULL;
    }
    
    // 清理流表（这将同时清理相关的会话）
    flow_table_destroy();
    
    // 清理会话管理器
    transport_session_manager_cleanup();
    
    // 清理无锁队列
    lockfree_queue_destroy(&global_lockfree_queue);
    
    // 清理数据包队列
    packet_queue_cleanup(&packet_queue);
    
    // 清理锁文件
    if (lock_fd >= 0) {
        close(lock_fd);
        unlink(LOCK_FILE);
        lock_fd = -1;
    }
    
    log_info("Cleanup completed");
}

// 单实例检查
int check_single_instance(void) {
    lock_fd = open(LOCK_FILE, O_CREAT | O_RDWR, 0644);
    if (lock_fd < 0) {
        perror("Failed to open lock file");
        return -1;
    }
    
    if (flock(lock_fd, LOCK_EX | LOCK_NB) < 0) {
        if (errno == EWOULDBLOCK) {
            return 1; // 已有实例运行
        } else {
            perror("Failed to acquire lock");
            return -1;
        }
    }
    
    return 0; // 成功获取锁
}

// 启动时初始化时间基准
void init_time_base(void) {
    struct timespec realtime, monotonic;
    clock_gettime(CLOCK_REALTIME, &realtime);
    clock_gettime(CLOCK_MONOTONIC, &monotonic);
    boot_realtime = realtime;
    boot_monotonic_ns = (uint64_t)monotonic.tv_sec * 1000000000ULL + monotonic.tv_nsec;
}

// 将bpf_ktime_get_ns()时间戳转为wall time字符串（东八区时间）
void format_ebpf_packet_time(uint64_t ktime_ns, char *buf, size_t buflen) {
    uint64_t base_ns = (uint64_t)boot_realtime.tv_sec * 1000000000ULL + boot_realtime.tv_nsec;
    uint64_t abs_ns = base_ns + (ktime_ns - boot_monotonic_ns);
    time_t sec = abs_ns / 1000000000ULL;
    
    // 转换为东八区时间
    sec += 8 * 3600; // 添加8小时转换为东八区
    
    struct tm tm;
    gmtime_r(&sec, &tm); // 使用gmtime_r而不是localtime_r
    strftime(buf, buflen, "%Y-%m-%d %H:%M:%S", &tm);
}

// 格式化东八区时间的辅助函数
void format_beijing_time(time_t timestamp, char *buf, size_t buflen) {
    time_t beijing_time = timestamp + 8 * 3600; // 转换为东八区时间
    struct tm tm;
    gmtime_r(&beijing_time, &tm);
    strftime(buf, buflen, "%Y-%m-%d %H:%M:%S", &tm);
}

// 获取当前时间（纳秒）
uint64_t get_current_time(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + ts.tv_nsec;
}

// 打印使用帮助
void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("  -i, --interface <ifname>    Network interface to monitor (default: all)\n");
    printf("                               Use 'all' to monitor all available interfaces\n");
    printf("  -r, --read <pcap-file>      Read packets from pcap file instead of network\n");
    printf("  -d, --duration <seconds>    Run for specified duration in seconds (default: indefinite)\n");
    printf("  -s, --stats-interval <sec>  Interval between statistics printing (default: 1 second)\n");
    printf("  -p, --packets <count>       Print stats every N packets (default: 1000)\n");
    printf("  -c, --cleanup <seconds>     Flow cleanup interval (default: 60 seconds)\n");
    printf("  -o, --output <csv-file>     Export features to CSV file\n");
    printf("  -l, --loop <count>          Loop pcap file N times (0 = infinite, default: 1)\n");
    printf("  -w, --wait <seconds>        Wait N seconds between loops (default: 0)\n");
    printf("  -v, --verbose <level>       Debug level: 0=none, 1=basic, 2=detailed (default: 0)\n");
    printf("  -q, --quiet                 Quiet mode, don't print statistics to screen\n");
    printf("  -m, --monitor               Realtime monitor mode with ncurses interface\n");
    printf("  -h, --help                  Show this help message\n");
}

// 主函数
int main(int argc, char **argv) {
    init_time_base();
    const char *ifname = "all";  // Default to monitor all interfaces
    const char *pcap_file = NULL;
    int c;
    int ret = 0;
    int monitor_mode = 0;  // 监控模式标志
    
    // 输出编译模式和日志级别信息
    log_info("Build Mode: %s", get_build_mode_log_level());
    log_info("Default Log Level: %s", 
           (get_log_level() == 0) ? "ERROR" :
           (get_log_level() == 1) ? "WARN" :
           (get_log_level() == 2) ? "INFO" : "DEBUG");
    log_info("==========================================");

    // Setup signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Initialize system monitoring
    init_system_monitoring();
    
    // Register cleanup function for normal exit
    atexit(cleanup);
    
    // 检查是否已经有实例在运行
    ret = check_single_instance();
    if (ret > 0) {
        // 已有实例运行
        fprintf(stderr, "Another instance is already running\n");
        return 1;
    } else if (ret < 0) {
        // 错误
        fprintf(stderr, "Failed to check single instance, continuing...\n");
        // 继续运行，因为这不是致命错误
    }

    static struct option long_options[] = {
        {"interface",     required_argument, 0, 'i'},
        {"read",          required_argument, 0, 'r'},
        {"duration",      required_argument, 0, 'd'},
        {"stats-interval", required_argument, 0, 's'},
        {"packets",       required_argument, 0, 'p'},
        {"cleanup",       required_argument, 0, 'c'},
        {"output",        required_argument, 0, 'o'},
        {"loop",          required_argument, 0, 'l'},
        {"wait",          required_argument, 0, 'w'},
        {"verbose",       required_argument, 0, 'v'},
        {"quiet",         no_argument,       0, 'q'},
        {"monitor",       no_argument,       0, 'm'},
        {"help",          no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((c = getopt_long(argc, argv, "i:r:d:s:p:c:o:l:w:v:qm", long_options, NULL)) != -1) {
        switch (c) {
            case 'i':
                ifname = optarg;
                break;
            case 'r':
                pcap_file = optarg;
                break;
            case 'd':
                duration = atoi(optarg);
                if (duration < 0) {
                    fprintf(stderr, "Duration must be a positive number\n");
                    return 1;
                }
                printf("Setting duration to %d seconds\n", duration);
                break;
            case 's':
                stats_interval = atoi(optarg);
                if (stats_interval <= 0) {
                    fprintf(stderr, "Stats interval must be a positive number\n");
                    return 1;
                }
                printf("Setting stats interval to %d seconds\n", stats_interval);
                break;
            case 'p':
                stats_packet_count = atoi(optarg);
                if (stats_packet_count <= 0) {
                    fprintf(stderr, "Packet count must be a positive number\n");
                    return 1;
                }
                printf("Setting stats packet count to %d packets\n", stats_packet_count);
                break;
            case 'c':
                cleanup_interval = atoi(optarg);
                if (cleanup_interval <= 0) {
                    fprintf(stderr, "Cleanup interval must be a positive number\n");
                    return 1;
                }
                printf("Setting cleanup interval to %d seconds\n", cleanup_interval);
                break;
            case 'o':
                csv_file = optarg;
                printf("Will export flow features to CSV file: %s\n", csv_file);
                break;
            case 'l':
                loop_count = atoi(optarg);
                if (loop_count < 0) {
                    fprintf(stderr, "Loop count must be a non-negative number\n");
                    return 1;
                }
                printf("Setting loop count to %d\n", loop_count);
                break;
            case 'w':
                loop_delay = atoi(optarg);
                if (loop_delay < 0) {
                    fprintf(stderr, "Loop delay must be a non-negative number\n");
                    return 1;
                }
                printf("Setting loop delay to %d seconds\n", loop_delay);
                break;
            case 'v':
                {
                    int debug_level = atoi(optarg);
                    if (debug_level < 0 || debug_level > 2) {
                        fprintf(stderr, "Debug level must be 0, 1, or 2\n");
                        return 1;
                    }
                    set_debug_level(debug_level);
                    printf("Setting debug level to %d\n", debug_level);
                }
                break;
            case 'q':
                quiet_mode = 1;
                printf("Quiet mode enabled, statistics will not be printed to screen\n");
                break;
            case 'm':
                monitor_mode = 1;
                printf("Monitor mode enabled, will start realtime monitor interface\n");
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (monitor_mode) {
        // 实时监控模式
        printf("Starting realtime monitor mode...\n");
        set_log_level(LOG_LEVEL_INFO);
        ret = run_monitor_mode(ifname);
    } else if (pcap_file) {
        // PCAP文件处理模式
        printf("Processing pcap file: %s\n", pcap_file);
        ret = process_pcap_file(pcap_file);
    } else {
        // 实时网络捕获模式
        printf("Starting live capture mode...\n");
        ret = run_live_capture(ifname);
    }
    
    printf("Program finished with return code: %d\n", ret);
    return ret;
}

// ===== 缺失的函数定义 =====

// 数据包队列管理函数
void packet_queue_init(packet_queue_t *queue, int size) {
    queue->packets = malloc(size * sizeof(packet_data_t));
    if (!queue->packets) {
        log_error("Failed to allocate packet queue");
        exit(EXIT_FAILURE);
    }
    queue->head = 0;
    queue->tail = 0;
    queue->capacity = size;
    pthread_mutex_init(&queue->mutex, NULL);
}

void packet_queue_cleanup(packet_queue_t *queue) {
    if (queue->packets) {
        free(queue->packets);
        queue->packets = NULL;
    }
    pthread_mutex_destroy(&queue->mutex);
}

int packet_queue_enqueue(packet_queue_t *queue, const packet_data_t *packet) {
    pthread_mutex_lock(&queue->mutex);
    
    // 检查队列是否已满
    uint64_t next_tail = (queue->tail + 1) % queue->capacity;
    if (next_tail == queue->head) {
        pthread_mutex_unlock(&queue->mutex);
        return -1; // 队列已满
    }
    
    queue->packets[queue->tail] = *packet;
    queue->tail = next_tail;
    
    pthread_mutex_unlock(&queue->mutex);
    return 0;
}

int packet_queue_dequeue(packet_queue_t *queue, packet_data_t *packet) {
    pthread_mutex_lock(&queue->mutex);
    
    // 检查队列是否为空
    if (queue->head == queue->tail) {
        pthread_mutex_unlock(&queue->mutex);
        return -1; // 队列为空
    }
    
    *packet = queue->packets[queue->head];
    queue->head = (queue->head + 1) % queue->capacity;
    
    pthread_mutex_unlock(&queue->mutex);
    return 0;
}

int packet_queue_size(packet_queue_t *queue) {
    pthread_mutex_lock(&queue->mutex);
    uint64_t size = (queue->tail - queue->head + queue->capacity) % queue->capacity;
    pthread_mutex_unlock(&queue->mutex);
    return (int)size;
}

// 全局变量定义
struct timespec program_start_time;

// 直接处理数据包函数（单线程版本）
void process_packet_direct(const struct iphdr *ip, uint16_t src_port, uint16_t dst_port, 
                          uint32_t tcp_seq, uint8_t tcp_flags, uint64_t timestamp) {
    // 添加调试信息
    static int debug_packet_count = 0;
    if (debug_packet_count < 5) {
        struct in_addr src_addr = {.s_addr = ip->saddr};
        struct in_addr dst_addr = {.s_addr = ip->daddr};
        log_debug("Processing packet %d: %s:%u -> %s:%u, protocol: %d", 
                   debug_packet_count + 1, 
                   inet_ntoa(src_addr), src_port,
                   inet_ntoa(dst_addr), dst_port,
                   ip->protocol);
        debug_packet_count++;
    }
    
    // 创建传输层头部信息用于传递给process_packet
    if (ip->protocol == IPPROTO_TCP) {
        // 对于TCP，我们需要传递序列号和标志位
        struct tcphdr tcp_info = {0};
        tcp_info.source = ntohs(src_port);  // 转换为主机字节序
        tcp_info.dest = ntohs(dst_port);    // 转换为主机字节序
        tcp_info.seq = htonl(tcp_seq);
        *((uint8_t*)&tcp_info + 13) = tcp_flags;  // 设置TCP标志位
        
        process_packet(ip, &tcp_info, timestamp);
    } else if (ip->protocol == IPPROTO_UDP) {
        // 对于UDP，只需要端口信息
        struct udphdr udp_info = {0};
        udp_info.source = ntohs(src_port);  // 转换为主机字节序
        udp_info.dest = ntohs(dst_port);    // 转换为主机字节序
        
        process_packet(ip, &udp_info, timestamp);
    }
    
    // 更新实时统计
    total_packets_processed++;
}

// 系统监控函数
void init_system_monitoring(void) {
    // 初始化程序启动时间
    clock_gettime(CLOCK_REALTIME, &program_start_time);
    
    // 初始化系统统计
    system_stats.cpu_usage = 0.0;
    system_stats.memory_usage = 0.0;
    system_stats.packets_processed = 0;
    system_stats.processing_time = 0.0;
    system_stats.packets_per_second = 0;
}

// 临时占位函数（需要从loader.c中复制完整实现）
int process_pcap_file(const char *pcap_file) {
    log_error("process_pcap_file not implemented in modularized version");
    return -1;
}

int run_live_capture(const char *ifname) {
    // 直接使用单线程多接口捕获模式
    log_info("Using single-thread multi-interface capture mode");
    return run_single_interface_capture(ifname);
}

int run_single_interface_capture(const char *ifname) {
    log_info("Starting optimized single-thread multi-interface capture");
    
    // 获取可用接口列表
    char interfaces[MAX_INTERFACES][IF_NAMESIZE];
    int available_count;
    
    // 如果指定了特定接口，允许包含enp1s0；否则排除enp1s0
    if (ifname && strcmp(ifname, "all") != 0) {
        // 单独监听指定接口，允许enp1s0
        available_count = get_available_interfaces_ex(interfaces, MAX_INTERFACES, false);
        log_info("Single interface mode: allowing enp1s0");
    } else {
        // 监听所有接口，排除enp1s0
        available_count = get_available_interfaces_ex(interfaces, MAX_INTERFACES, true);
        log_info("All interfaces mode: excluding enp1s0");
    }
    
    if (available_count == 0) {
        log_error("No available network interfaces found");
        return 1;
    }
    
    log_info("Found %d available interfaces:", available_count);
    for (int i = 0; i < available_count; i++) {
        log_info("  %d: %s", i + 1, interfaces[i]);
    }
    
    // 初始化全局资源
    start_time = time(NULL);
    packet_queue_init(&packet_queue, PACKET_QUEUE_SIZE);
    lockfree_queue_init(&global_lockfree_queue, PACKET_QUEUE_SIZE);
    flow_table_init();
    
    // 初始化会话管理器
    if (transport_session_manager_init() != 0) {
        log_error("Failed to initialize session manager");
        return 1;
    }
    
    // 初始化工作线程池
    if (init_worker_threads() != 0) {
        log_error("Failed to initialize worker threads");
        return 1;
    }
    
    log_info("Flow tracking, session manager, and worker threads initialized");
    
    if (duration > 0) {
        log_info("Will capture traffic for %d seconds", duration);
    }
    
    // 加载BPF程序
    log_info("Loading BPF program from bpf_program.o...");
    global_bpf_obj = bpf_object__open_file("bpf_program.o", NULL);
    if (libbpf_get_error(global_bpf_obj)) {
        log_error("Failed to open BPF object file: %s", strerror(-libbpf_get_error(global_bpf_obj)));
        return 1;
    }
    log_info("BPF object loaded successfully");
    
    // 加载到内核
    log_info("Loading BPF program into kernel...");
    int err = bpf_object__load(global_bpf_obj);
    if (err) {
        log_error("BPF loading failed: %s", strerror(-err));
        return 1;
    }
    log_info("BPF program loaded into kernel successfully");
    
    // 获取RINGBUF映射
    int ringbuf_map_fd = bpf_object__find_map_fd_by_name(global_bpf_obj, "ringbuf_events");
    if (ringbuf_map_fd < 0) {
        log_error("Failed to find ringbuf_events map");
        return 1;
    }
    
    // 创建全局RINGBUF
    global_ringbuf = ring_buffer__new(ringbuf_map_fd, handle_ringbuf_event_optimized_improved, NULL, NULL);
    if (!global_ringbuf) {
        log_error("Failed to create ring buffer");
        return 1;
    }
    
    // 为每个接口附加XDP程序
    global_links = malloc(available_count * sizeof(struct bpf_link *));
    if (!global_links) {
        log_error("Failed to allocate link array");
        return 1;
    }
    
    struct bpf_program *prog = bpf_object__find_program_by_name(global_bpf_obj, "xdp_packet_capture");
    if (!prog) {
        log_error("BPF program 'xdp_packet_capture' not found");
        return 1;
    }
    
    for (int i = 0; i < available_count; i++) {
        log_info("Attaching XDP program to interface %s...", interfaces[i]);
        
        int ifindex = if_nametoindex(interfaces[i]);
        if (ifindex == 0) {
            log_error("Failed to get interface index for %s: %s", interfaces[i], strerror(errno));
            global_links[i] = NULL;
            continue;
        }
        
        // 首先尝试原生模式
        global_links[i] = bpf_program__attach_xdp(prog, ifindex);
        if (libbpf_get_error(global_links[i])) {
            log_warn("Failed to attach XDP program in native mode to %s, trying SKB mode...", interfaces[i]);
            
            // 如果原生模式失败，尝试SKB模式
            int ret = bpf_xdp_attach(ifindex, bpf_program__fd(prog), XDP_FLAGS_SKB_MODE, NULL);
            if (ret < 0) {
                log_error("Failed to attach XDP program to %s in both native and SKB mode: %s", 
                         interfaces[i], strerror(-ret));
                global_links[i] = NULL;
            } else {
                // 对于SKB模式，我们不能使用bpf_link，但标记为成功
                global_links[i] = (struct bpf_link*)((uintptr_t)ifindex); // 存储ifindex作为清理标记
                global_link_count++;
                log_info("Successfully attached XDP program to %s in SKB mode", interfaces[i]);
            }
        } else {
            global_link_count++;
            log_info("Successfully attached XDP program to %s in native mode", interfaces[i]);
        }
    }
    
    if (global_link_count == 0) {
        log_error("Failed to attach XDP program to any interface");
        return 1;
    }
    
    log_info("Successfully attached XDP program to %d interfaces", global_link_count);
    
    // 主循环：轮询RINGBUF并处理数据包
    uint64_t last_stats_time = 0;
    const uint64_t STATS_INTERVAL_MS = 1000;  // 每1秒输出一次统计
    
    while (running) {
        uint64_t current_time = get_current_time();
        
        // 轮询RINGBUF
        int poll_result = ring_buffer__poll(global_ringbuf, 100); // 100ms超时
        if (poll_result < 0) {
            log_error("Error polling ring buffer: %d", poll_result);
            break;
        }
        
        // 处理无锁队列中的数据包
        process_lockfree_packet_queue();
        
        // 定期输出统计信息
        if (current_time - last_stats_time >= STATS_INTERVAL_MS) {
            // 清除当前行并回到行首
            printf("\r\033[2K");
            
            // 计算处理速率
            static uint64_t last_packets = 0;
            static uint64_t last_bytes = 0;
            static uint64_t last_time = 0;
            
            uint64_t packets_diff = total_packets_captured - last_packets;
            uint64_t bytes_diff = total_bytes_captured - last_bytes;
            uint64_t time_diff = current_time - last_time;
            
            double pps = 0.0, bps = 0.0;
            if (time_diff > 0) {
                double time_diff_sec = (double)time_diff / 1000000000.0;
                pps = (double)packets_diff / time_diff_sec;
                bps = (double)bytes_diff / time_diff_sec;
            }
            
            // 动态进度指示器
            static int progress_phase = 0;
            const char *progress_chars[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
            const char *progress = progress_chars[progress_phase % 10];
            progress_phase++;
            
            // 获取会话统计
            uint64_t total_created, tcp_created, udp_created, reused;
            get_session_creation_stats(&total_created, &tcp_created, &udp_created, &reused);
            
            // 更新系统统计
            update_system_stats();
            
            // 获取当前时间戳（东八区）
            time_t now = time(NULL);
            time_t beijing_time = now + 8 * 3600;
            struct tm tm;
            gmtime_r(&beijing_time, &tm);
            char time_only[9];
            strftime(time_only, sizeof(time_only), "%H:%M:%S", &tm);
            
            printf("\r⏰ %s | 🔄 %s | 📦 %lu (%.1f pkt/s) | 💾 %.2f MB (%.1f kb/s) | 🔗 TCP:%u UDP:%u Total:%u | 🗄️ %d/%d | 📊 Created:%lu Reused:%lu | 🖥️  CPU:%.1f%% MEM:%.1f%% | 🧵 Workers:%d",
                   time_only, progress,
                   total_packets_captured, pps,
                   total_bytes_captured / (1024.0 * 1024.0), bps * 8 / 1000.0,
                   get_tcp_conversation_count(),
                   get_udp_conversation_count(),
                   get_total_conversation_count(),
                   count_active_flows(),
                   count_all_flows(),
                   total_created,
                   reused,
                   system_stats.cpu_usage,
                   system_stats.memory_usage,
                   get_worker_thread_count());
            
            // 更新上次统计值
            last_packets = total_packets_captured;
            last_bytes = total_bytes_captured;
            last_time = current_time;
            
            fflush(stdout);
            last_stats_time = current_time;
            
            // 定期清理
            static uint64_t last_cleanup_time = 0;
            if (current_time - last_cleanup_time >= 1000) {
                if (running) {
                    cleanup_flows();
                    cleanup_expired_sessions();
                    schedule_batch_cleanup();  // 调度批量清理
                    monitor_memory_usage();    // 监控内存使用
                    last_cleanup_time = current_time;
                }
            }
        }
        
        // 短暂休眠
        usleep(1000); // 1ms
    }
    
    // 清理资源
    log_info("Main loop ended, performing cleanup...");
    
    // 首先停止工作线程（这会清理本地会话表）
    stop_worker_threads();
    
    // 然后执行全局清理
    cleanup();
    
    log_info("Cleanup completed");
    
    return 0;
}

int run_monitor_mode(const char *ifname) {
    log_error("run_monitor_mode not implemented in modularized version");
    return -1;
} 