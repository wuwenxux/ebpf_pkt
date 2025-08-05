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

// System monitoring headers
#include <sys/resource.h>
#include <sys/times.h>
#include <sys/sysinfo.h>

// System and network headers
#include <arpa/inet.h>
#include <net/if.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// If u_char is not defined
typedef unsigned char u_char;

// Handle the BPF conflict
// Make sure to use system's bpf.h, not pcap's
#define PCAP_DONT_INCLUDE_PCAP_BPF_H
#include <pcap.h>

// Because we've defined PCAP_DONT_INCLUDE_PCAP_BPF_H, 
// we need to include these explicitly
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// Our headers
#include "flow.h"
#include "stats_window.h"
#include "loader.h"
#include "transport_session.h"

// 增加预取相关宏定义
#define PREFETCH(addr) __builtin_prefetch(addr)
#define PREFETCH_RW(addr) __builtin_prefetch(addr, 1, 1)
#define PREFETCH_LOCALITY_HIGH 3
#define PREFETCH_LOCALITY_MED 2
#define PREFETCH_LOCALITY_LOW 1
#define PREFETCH_LOCALITY_NONE 0

// 多线程相关配置
#define PACKET_QUEUE_SIZE 10000  // 数据包队列大小
#define MAX_INTERFACES 32        // 最大支持的接口数量

// ANSI转义序列用于终端控制
const char *ANSI_CLEAR_SCREEN = "\033[2J\033[H";  // 清屏并将光标移到开头
const char *ANSI_CLEAR_LINE = "\033[2K\r";      // 清除当前行并回到行首
const char *ANSI_CURSOR_UP = "\033[1A";        // 光标上移一行
const char *ANSI_SAVE_CURSOR = "\033[s";         // 保存光标位置
const char *ANSI_RESTORE_CURSOR = "\033[u";         // 恢复光标位置
const char *ANSI_HIDE_CURSOR = "\033[?25l";      // 隐藏光标
const char *ANSI_SHOW_CURSOR = "\033[?25h";      // 显示光标

// 系统统计结构定义（与system_stats.c保持一致）
typedef struct {
    double cpu_usage;
    double memory_usage;
    uint64_t packets_processed;
    double processing_time;
    uint64_t packets_per_second;
} system_stats_t;

// 使用system_stats.c中定义的system_stats_t
extern system_stats_t system_stats;
clock_t start_cpu_time;
clock_t start_wall_time;
struct timespec program_start_time;

// 全局时间基准
struct timespec boot_realtime;
uint64_t boot_monotonic_ns = 0;

// 全局变量

// 运行状态，设为extern以便其他文件可访问
volatile int running = 1;
static volatile int monitor_running = 1;  // 监控模式运行状态

// 函数前向声明
void print_final_stats(void);
int run_single_interface_capture(const char *ifname);
// 删除未使用的函数声明
static int run_monitor_mode(const char *ifname);
static void *capture_thread_func(void *arg);
// flow_table_initialized是flow.c中的变量，我们在这里声明为外部变量
extern int flow_table_initialized;
extern int count_active_flows(); // 从flow.c导入流计数函数
extern int transport_session_manager_init(void);
extern void transport_session_manager_cleanup(void);
extern session_manager_t *global_session_manager;
extern transport_session_t *process_packet_with_conversation(const struct flow_key *key, 
                                                           uint32_t packet_size,
                                                           uint8_t tcp_flags,
                                                           uint64_t timestamp);

// 多接口监听相关结构
typedef struct {
    char name[IF_NAMESIZE];     // 接口名称
    int ifindex;                // 接口索引
    pthread_t thread;           // 监听线程
    struct bpf_object *obj;     // BPF对象
    struct bpf_link *link;      // BPF链接
    struct perf_buffer *pb;     // 性能缓冲区
    int is_active;              // 是否活跃
    int thread_ret;             // 线程返回值
} interface_thread_t;

// 全局接口线程数组
static interface_thread_t interface_threads[MAX_INTERFACES];
static int interface_count = 0;
static pthread_mutex_t interface_mutex = PTHREAD_MUTEX_INITIALIZER;

// 线程参数结构
typedef struct {
    char interface_name[IF_NAMESIZE];
    int thread_id;
} thread_arg_t;

#define TCPHDR_FIN  0x01
#define TCPHDR_SYN  0x02
#define TCPHDR_RST  0x04
#define TCPHDR_PSH  0x08
#define TCPHDR_ACK  0x10
#define TCPHDR_URG  0x20
#define TCPHDR_ECE  0x40
#define TCPHDR_CWR  0x80
#define PERF_BUFFER_PAGES 16

// NIPQUAD macro for printing IP addresses
#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

// Default settings
#define DEFAULT_STATS_INTERVAL 2   // 5 seconds between stats prints
#define DEFAULT_STATS_PACKETS 1000 // Print stats every 1000 packets
#define DEFAULT_CLEANUP_INTERVAL 10 // 10 seconds between flow cleanups
#define DEFAULT_DURATION 0         // 0 means run indefinitely
#define DEFAULT_CSV_FILE NULL      // Default CSV file (none)
#define DEFAULT_LOOP_COUNT 1       // Default loop count (1 = no loop)

// 锁文件路径
#define LOCK_FILE "/var/run/ebpf_pkt.lock"

// Global settings
static int stats_interval = DEFAULT_STATS_INTERVAL;
static int stats_packet_count = DEFAULT_STATS_PACKETS;
static int cleanup_interval = DEFAULT_CLEANUP_INTERVAL;  // 使用从cicflowmeter复制的参数
static int duration = DEFAULT_DURATION;  // in seconds, 0 means run indefinitely
static time_t start_time;                // program start time
static int lock_fd = -1;                // 文件锁描述符
static const char *csv_file = DEFAULT_CSV_FILE; // CSV输出文件路径
static int loop_count = DEFAULT_LOOP_COUNT;     // pcap循环播放次数，0表示无限循环
static int loop_delay = 0;                      // 每次循环之间的延迟（秒）
int quiet_mode = 0;              // 安静模式，不输出统计信息，声明为全局可访问

// 多线程处理相关数据结构
typedef struct {
    struct iphdr ip_header;
    union {
        struct {
            uint16_t source;
            uint16_t dest;
            uint32_t seq;           // 添加TCP序列号
            uint8_t flags_byte[14]; // 足够存储TCP标志位(在字节13)
        } tcp;
        struct {
            uint16_t source;
            uint16_t dest;
        } udp;
    } transport_header;
    uint64_t timestamp; // 添加时间戳字段
} packet_data_t;

// 无锁队列结构 - 使用原子操作确保线程安全
typedef struct {
    packet_data_t *packets;          // 数据包缓冲区
    volatile uint64_t head;          // 队列头部索引（读位置）
    volatile uint64_t tail;          // 队列尾部索引（写位置）
    volatile uint64_t capacity;      // 队列容量
    volatile uint64_t mask;          // 容量掩码（用于快速取模）
    volatile int expanding;          // 扩容标志
    packet_data_t *new_packets;     // 新缓冲区（扩容时使用）
    volatile uint64_t new_capacity;  // 新容量
} lockfree_queue_t;

// 全局数据包队列
static lockfree_queue_t packet_queue;

// 全局包计数器
static volatile uint64_t global_packet_count = 0;

// 实时统计计数器
static volatile uint64_t total_packets_captured = 0;
static volatile uint64_t total_bytes_captured = 0;

// 获取当前时间（纳秒）- 使用flow.h中已声明的函数

// 确保队列容量是2的幂次，便于位运算优化
static uint64_t next_power_of_2(uint64_t n) {
    n--;
    n |= n >> 1;
    n |= n >> 2;
    n |= n >> 4;
    n |= n >> 8;
    n |= n >> 16;
    n |= n >> 32;
    return n + 1;
}

// 初始化无锁队列
static void packet_queue_init(lockfree_queue_t *queue, int initial_capacity) {
    uint64_t capacity = next_power_of_2(initial_capacity);
    
    queue->packets = (packet_data_t *)aligned_alloc(64, capacity * sizeof(packet_data_t));
    if (!queue->packets) {
        log_error("Failed to allocate packet queue");
        exit(EXIT_FAILURE);
    }
    
    queue->head = 0;
    queue->tail = 0;
    queue->capacity = capacity;
    queue->mask = capacity - 1;
    queue->expanding = 0;
    queue->new_packets = NULL;
    queue->new_capacity = 0;
    
    // 预热缓存
    memset(queue->packets, 0, capacity * sizeof(packet_data_t));
}

// 销毁无锁队列
static void packet_queue_destroy(lockfree_queue_t *queue) {
    if (queue->packets) {
        free(queue->packets);
        queue->packets = NULL;
    }
    if (queue->new_packets) {
        free(queue->new_packets);
        queue->new_packets = NULL;
    }
}

// 扩容队列 - 当队列接近满时触发
static int expand_queue(lockfree_queue_t *queue) {
    // 检查队列是否已初始化
    if (!queue || !queue->packets) {
        return -1;
    }
    
    // 使用CAS操作确保只有一个线程进行扩容
    if (!__sync_bool_compare_and_swap(&queue->expanding, 0, 1)) {
        return 0; // 其他线程正在扩容
    }
    
    uint64_t new_capacity = queue->capacity * 2;
    packet_data_t *new_packets = (packet_data_t *)aligned_alloc(64, new_capacity * sizeof(packet_data_t));
    
    if (!new_packets) {
        queue->expanding = 0;
        return -1; // 扩容失败
    }
    
    // 复制现有数据到新缓冲区
    uint64_t head = queue->head;
    uint64_t tail = queue->tail;
    uint64_t old_mask = queue->mask;
    
    for (uint64_t i = head; i != tail; i++) {
        uint64_t old_idx = i & old_mask;
        uint64_t new_idx = i & (new_capacity - 1);
        memcpy(&new_packets[new_idx], &queue->packets[old_idx], sizeof(packet_data_t));
    }
    
    // 原子更新队列参数
    queue->new_packets = new_packets;
    queue->new_capacity = new_capacity;
    
    // 内存屏障确保所有写操作完成
    __sync_synchronize();
    
    // 切换到新缓冲区
    packet_data_t *old_packets = queue->packets;
    queue->packets = new_packets;
    queue->capacity = new_capacity;
    queue->mask = new_capacity - 1;
    queue->new_packets = NULL;
    queue->new_capacity = 0;
    
    // 清理旧缓冲区
    free(old_packets);
    
    queue->expanding = 0;
    return 0;
}

// 无锁入队操作
static int packet_queue_enqueue(lockfree_queue_t *queue, const packet_data_t *packet) {
    if (!running) return -1;
    
    // 检查队列是否已初始化
    if (!queue || !queue->packets) {
        return -1;
    }
    
    uint64_t tail, head, next_tail;
    int retry_count = 0;
    const int max_retries = 1000;
    
    while (retry_count < max_retries && running) {
        tail = queue->tail;
        head = queue->head;
        next_tail = tail + 1;
        
        // 检查队列是否接近满（留一些缓冲空间）
        if (next_tail - head >= queue->capacity - 1) {
            // 尝试扩容
            if (queue->expanding == 0) {
                expand_queue(queue);
            }
            // 短暂等待后重试
            usleep(1);
            retry_count++;
            continue;
        }
        
        // 尝试原子更新tail
        if (__sync_bool_compare_and_swap(&queue->tail, tail, next_tail)) {
            // 成功获得写入位置，复制数据
            uint64_t idx = tail & queue->mask;
            PREFETCH_RW(&queue->packets[idx]);
            memcpy(&queue->packets[idx], packet, sizeof(packet_data_t));
            
            // 内存屏障确保数据写入完成
            __sync_synchronize();
            return 0;
        }
        
        // CAS失败，CPU yield后重试
        __asm__ __volatile__("pause" ::: "memory");
        retry_count++;
    }
    
    // 达到最大重试次数，直接返回失败，避免无限递归
    if (running) {
        // 队列可能已满，丢弃这个包以避免卡死
        static int drop_warning_count = 0;
        if (drop_warning_count < 10) {
            log_warn("Packet queue full, dropping packet (warning %d/10)", ++drop_warning_count);
        }
        return -1;
    }
    
    return -1;
}

// 无锁出队操作
static int packet_queue_dequeue(lockfree_queue_t *queue, packet_data_t *packet) {
    // 检查队列是否已初始化
    if (!queue || !queue->packets) {
        return -1;
    }
    
    uint64_t head, tail, next_head;
    int retry_count = 0;
    const int max_retries = 100;
    
    while (retry_count < max_retries && running) {
        head = queue->head;
        tail = queue->tail;
        next_head = head + 1;
        
        // 检查队列是否为空
        if (head == tail) {
            // 队列为空，短暂等待
            usleep(1);
            retry_count++;
            continue;
        }
        
        // 尝试原子更新head
        if (__sync_bool_compare_and_swap(&queue->head, head, next_head)) {
            // 成功获得读取位置，复制数据
            uint64_t idx = head & queue->mask;
            PREFETCH(&queue->packets[idx]);
            memcpy(packet, &queue->packets[idx], sizeof(packet_data_t));
            
            // 内存屏障确保数据读取完成
            __sync_synchronize();
            return 0;
        }
        
        // CAS失败，CPU yield后重试
        __asm__ __volatile__("pause" ::: "memory");
        retry_count++;
    }
    
    return running ? 0 : -1; // 如果仍在运行，返回0表示可以继续尝试
}

// 获取队列当前大小（近似值，用于监控）
static uint64_t packet_queue_size(lockfree_queue_t *queue) {
    // 检查队列是否已初始化
    if (!queue || !queue->packets) {
        return 0;
    }
    
    uint64_t tail = queue->tail;
    uint64_t head = queue->head;
    return tail - head;
}

// 包处理计数器
volatile uint64_t total_packets_processed = 0;
static volatile uint64_t total_bytes_processed = 0;

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

struct perf_buffer_opts opts = {
    .sz = sizeof(opts),
};

// Add a global flag to track if cleanup has been done
static int cleanup_done = 0;

// 直接处理数据包函数（单线程版本）
static void process_packet_direct(const struct iphdr *ip, uint16_t src_port, uint16_t dst_port, 
                                uint32_t tcp_seq, uint8_t tcp_flags, uint64_t timestamp) {
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
    
    // 同时处理会话管理器（如果已初始化）
    if (global_session_manager) {
        struct flow_key key = {0};
        key.src_ip = ip->saddr;
        key.dst_ip = ip->daddr;
        key.protocol = ip->protocol;
        
        if (ip->protocol == IPPROTO_TCP) {
            key.src_port = src_port;
            key.dst_port = dst_port;
        } else if (ip->protocol == IPPROTO_UDP) {
            key.src_port = src_port;
            key.dst_port = dst_port;
        }
        
        // 使用会话管理器处理数据包
        (void)process_packet_with_conversation(&key, 
                                              ntohs(ip->tot_len),
                                              tcp_flags,
                                              timestamp);
    }
    
    // 更新统计信息
    __sync_fetch_and_add(&total_packets_processed, 1);
    __sync_fetch_and_add(&total_bytes_processed, ntohs(ip->tot_len));
    
    // 更新实时统计
    atomic_fetch_add(&g_realtime_stats.packet_count, 1);
}

static void cleanup(void) {
    static pthread_mutex_t cleanup_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&cleanup_mutex);
    if (cleanup_done) {
        pthread_mutex_unlock(&cleanup_mutex);
        return;
    }
    cleanup_done = 1;

    // 销毁数据包队列
    packet_queue_destroy(&packet_queue);

    // Cleanup flow table
    if (flow_table_initialized) {
        // print_final_stats();  // 注释掉统计结果输出
        flow_table_destroy();
    }

    // Close lock file
    if (lock_fd != -1) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        unlink(LOCK_FILE);
        lock_fd = -1;
    }
    pthread_mutex_unlock(&cleanup_mutex);
}

// Initialize system monitoring
static void init_system_monitoring(void) {
    start_cpu_time = clock();
    start_wall_time = clock();
    clock_gettime(CLOCK_REALTIME, &program_start_time);
    system_stats.packets_processed = 0;
    system_stats.cpu_usage = 0.0;
    system_stats.memory_usage = 0.0;
    system_stats.processing_time = 0.0;
    system_stats.packets_per_second = 0;
}

// CPU usage function is defined in system_stats.c

// Update system statistics - 使用system_stats.c中的实现
extern void update_system_stats(void);

void sig_handler(int sig) {
    static int signal_count = 0;
    signal_count++;
    
    if (signal_count == 1) {
        log_info("Received signal %d, initiating graceful shutdown...", sig);
        // 使用原子操作设置退出标志
        __sync_fetch_and_and(&running, 0);
        __sync_fetch_and_and(&monitor_running, 0);
        
        // 设置较短的超时时间
        alarm(3); // 3秒超时
    } else {
        log_info("Forcing immediate exit...");
        
        // 恢复终端到正常状态
        printf("\033[?25h");  // 显示光标
        printf("\033[0m");     // 重置所有属性
        fflush(stdout);
        
        exit(1);
    }
}

// 检查是否已经有实例在运行
static int check_single_instance(void) {
    // 打开锁文件
    lock_fd = open(LOCK_FILE, O_RDWR | O_CREAT, 0644);
    if (lock_fd == -1) {
        // 检查是否有权限创建锁文件
        if (errno == EACCES || errno == EPERM) {
            log_warn("No permission to create lock file %s, trying to use /tmp directory", LOCK_FILE);
            // 尝试在/tmp目录下创建
            const char *tmp_lock = "/tmp/ebpf_pkt.lock";
            lock_fd = open(tmp_lock, O_RDWR | O_CREAT, 0644);
            if (lock_fd == -1) {
                log_error("Cannot create lock file: %s", strerror(errno));
                return -1;
            }
        } else {
            log_error("Cannot create lock file: %s", strerror(errno));
            return -1;
        }
    }
    
    // 尝试对文件加锁
    if (flock(lock_fd, LOCK_EX | LOCK_NB) == -1) {
        if (errno == EWOULDBLOCK) {
            // 已有另一个实例在运行
            log_error("Another instance is already running");
            close(lock_fd);
            lock_fd = -1;
            return 1;
        } else {
            log_error("Unable to lock file: %s", strerror(errno));
            close(lock_fd);
            lock_fd = -1;
            return -1;
        }
    }
    
    // 成功获取锁，写入PID
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    if (ftruncate(lock_fd, 0) == -1 || 
        lseek(lock_fd, 0, SEEK_SET) == -1 ||
        write(lock_fd, pid_str, strlen(pid_str)) == -1) {
        log_warn("Unable to write PID to lock file: %s", strerror(errno));
        // 继续运行，这只是额外的信息
    }
    
    // 注册退出时的清理函数
    atexit(cleanup);
    
    return 0;
}

// 修改后的BPF数据处理函数，将数据包添加到队列
static void handle_batch(void *ctx, int cpu, void *data, __u32 size) {
    (void)ctx;  // 避免未使用参数警告
    (void)cpu;  // 避免未使用参数警告
    // 新增：断言 size 必须是 struct packet_info 的整数倍
    /* 
    if (size % sizeof(struct packet_info) != 0) {
        fprintf(stderr, "[ASAN-DEBUG] handle_batch: perf event size %u is not a multiple of struct packet_info (%zu)!\n", size, sizeof(struct packet_info));
        fflush(stderr);
        abort();
    }
    */
    const struct packet_info *pkts = data;
    int count = size / sizeof(struct packet_info);
    
    // 预取数据，避免首次访问时的缓存缺失
    for (int i = 0; i < count && i < 4; i++) {
        PREFETCH(&pkts[i]);
    }
    
    // 使用位操作进行条件判断
    time_t current_time = time(NULL);
    int should_exit = (duration > 0) & (current_time - start_time >= duration);
    running &= !should_exit;
    
    if (should_exit) {
        log_info("Reached specified duration of %d seconds. Exiting...", duration);
        return;
    }
    
    for (int i = 0; i < count; i++) {
        // 提前预取下一个数据包
        if (i + 4 < count) {
            PREFETCH(&pkts[i + 4]);
        }
        
        const struct packet_info *pkt = &pkts[i];
        
        // 使用位操作进行有效性判断
        int is_valid = (pkt->src_ip != 0) & (pkt->dst_ip != 0) & (pkt->pkt_len != 0);
        if (!is_valid) continue;
        
        // 更新全局包计数器
        __sync_fetch_and_add(&global_packet_count, 1);
        
        // 更新统计信息（在实时捕获模式下）
        __sync_fetch_and_add(&total_packets_captured, 1);
        __sync_fetch_and_add(&total_bytes_captured, pkt->pkt_len);
        
        // 调试输出（前10个包）- 仅在debug模式下显示/
        /*
        static int debug_count = 0;
        if (debug_count < 10) {
            struct in_addr src_addr = {.s_addr = pkt->src_ip};
            struct in_addr dst_addr = {.s_addr = pkt->dst_ip};
            log_debug("Packet %d - IP: %s -> %s, Protocol: %d, Ports: %u -> %u, TCP flags: 0x%02x", 
                   debug_count + 1, inet_ntoa(src_addr), inet_ntoa(dst_addr), 
                   pkt->protocol, pkt->src_port, pkt->dst_port, pkt->tcp_flags);
            debug_count++;
        }*/
        
        // 准备数据包结构
        packet_data_t packet_data;
        
        // 手动创建IP头
        packet_data.ip_header.saddr = pkt->src_ip;
        packet_data.ip_header.daddr = pkt->dst_ip;
        packet_data.ip_header.protocol = pkt->protocol;
        packet_data.ip_header.tot_len = htons(pkt->pkt_len);
        
        // 使用预编译的位掩码和协议比较 - 使用位操作
        uint8_t is_tcp = (pkt->protocol == IPPROTO_TCP);
        
        // 设置传输层信息
        packet_data.transport_header.tcp.source = pkt->src_port;
        packet_data.transport_header.tcp.dest = pkt->dst_port;
        
        // 仅当协议为TCP时设置标志位
        packet_data.transport_header.tcp.flags_byte[13] = pkt->tcp_flags & is_tcp;
        
        // 提取并转换时间戳为纳秒
        packet_data.timestamp = (uint64_t)pkt->timestamp;
        
        // 将数据包添加到队列
        if (packet_queue_enqueue(&packet_queue, &packet_data) != 0) {
            // 入队失败，检查是否应该退出
            if (!running) break;
        }
    }
}

// 重新实现的pcap包处理函数 - 安全对齐处理
void process_pcap_packet(const u_char *packet, const struct pcap_pkthdr *header) {
    // 跳过以太网头（14字节）
    const u_char *ip_data = packet + 14;
    
    // 安全拷贝IP头到对齐的内存
    struct iphdr ip_header;
    memcpy(&ip_header, ip_data, sizeof(ip_header));
    
    // 检查IP版本
    if (ip_header.version != 4) {
        return;  // Skip non-IPv4 packets
    }
    
    // 计算时间戳
    uint64_t timestamp = (uint64_t)header->ts.tv_sec * 1000000000ULL + (uint64_t)header->ts.tv_usec * 1000ULL;
    
    // 根据协议类型处理
    if (ip_header.protocol == IPPROTO_TCP) {
        // 计算TCP头位置
        const u_char *tcp_data = ip_data + (ip_header.ihl * 4);
        
        // 安全拷贝TCP头到对齐的内存
        struct tcphdr tcp_header;
        memcpy(&tcp_header, tcp_data, sizeof(tcp_header));
        
        // 直接处理TCP包
        process_packet_direct(&ip_header, 
                            ntohs(tcp_header.source),
                            ntohs(tcp_header.dest),
                            ntohl(tcp_header.seq),
                            *((uint8_t*)&tcp_header + 13), // TCP标志位
                            timestamp);
    } else if (ip_header.protocol == IPPROTO_UDP) {
        // 计算UDP头位置
        const u_char *udp_data = ip_data + (ip_header.ihl * 4);
        
        // 安全拷贝UDP头到对齐的内存
        struct udphdr udp_header;
        memcpy(&udp_header, udp_data, sizeof(udp_header));
        
        // 直接处理UDP包
        process_packet_direct(&ip_header,
                            ntohs(udp_header.source),
                            ntohs(udp_header.dest),
                            0, 0, // UDP没有序列号和标志位
                            timestamp);
    }
}



// 重新实现的pcap文件处理函数 - 高效直接处理
int process_pcap_file(const char *pcap_file) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    int ret = 0;
    
    // 记录开始时间
    start_time = time(NULL);
    
    // 初始化流跟踪
    flow_table_init();
    
    log_info("Processing pcap file: %s", pcap_file);
    
    if (loop_count == 0) {
        log_info("Loop mode: infinite loops");
    } else if (loop_count > 1) {
        log_info("Loop mode: %d loops", loop_count);
    }
    
    if (loop_delay > 0 && loop_count != 1) {
        log_info("Loop delay: %d seconds between loops", loop_delay);
    }
    
    if (duration > 0) {
        log_info("Will analyze traffic for %d seconds", duration);
    }
    
    int total_packet_count = 0;
    int current_loop = 0;
    
    // 循环播放pcap文件
    while (running && (loop_count == 0 || current_loop < loop_count)) {
        current_loop++;
        
        // 打开pcap文件
        handle = pcap_open_offline(pcap_file, errbuf);
        if (handle == NULL) {
            log_error("Couldn't open pcap file %s: %s", pcap_file, errbuf);
            ret = -1;
            break;
        }
        
        if (current_loop > 1 && !quiet_mode) {
            log_info("Starting loop %d/%s...", current_loop, 
                   loop_count == 0 ? "∞" : (char[]){loop_count + '0', '\0'});
        }
        
        // 处理pcap文件中的数据包
        struct pcap_pkthdr header;
        const u_char *packet;
        int loop_packet_count = 0;
        
        while (running && (packet = pcap_next(handle, &header)) != NULL) {
            // 直接处理数据包
            process_pcap_packet(packet, &header);
            loop_packet_count++;
            total_packet_count++;
            
            // 每500个包检查一次时间限制（更频繁的检查）
            if (loop_packet_count % 500 == 0) {
                if (duration > 0 && time(NULL) - start_time >= duration) {
                    log_info("Reached specified duration of %d seconds. Exiting...", duration);
                    running = 0;
                    break;
                }
            }
        }
        
        // 关闭当前句柄
        if (handle) {
            pcap_close(handle);
            handle = NULL;
        }
        
        if (!quiet_mode) {
            log_info("Loop %d completed: processed %d packets", current_loop, loop_packet_count);
        }
        
        // 检查是否需要继续循环
        if (!running) {
            break;
        }
        
        // 如果不是最后一次循环且设置了延迟，则等待
        if ((loop_count == 0 || current_loop < loop_count) && loop_delay > 0) {
            if (!quiet_mode) {
                log_info("Waiting %d seconds before next loop...", loop_delay);
            }
            
            // 分段睡眠以便能响应中断信号
            for (int i = 0; i < loop_delay && running; i++) {
                sleep(1);
            }
        }
        
        // 检查时间限制
        if (duration > 0 && time(NULL) - start_time >= duration) {
            log_info("Reached specified duration of %d seconds. Exiting...", duration);
            break;
        }
    }
    
    log_info("Total packets processed: %d (across %d loop%s)", 
           total_packet_count, current_loop, current_loop > 1 ? "s" : "");
    
    // 打印最终统计信息（包括CSV文件生成）
    print_final_stats();
    
    // 调用统一清理函数
    cleanup();
    
    return ret;
}

// 获取系统所有网络接口
static int get_available_interfaces(char interfaces[][IF_NAMESIZE], int max_count) {
    struct if_nameindex *if_ni, *i;
    int count = 0;
    
    if_ni = if_nameindex();
    if (if_ni == NULL) {
        perror("if_nameindex");
        return 0;
    }
    
    for (i = if_ni; i->if_index != 0 || i->if_name != NULL; i++) {
        if (count >= max_count) break;
        
        // 跳过回环接口
        if (strcmp(i->if_name, "lo") == 0) continue;
        
        strncpy(interfaces[count], i->if_name, IF_NAMESIZE - 1);
        interfaces[count][IF_NAMESIZE - 1] = '\0';
        count++;
    }
    
    if_freenameindex(if_ni);
    return count;
}

// 初始化单个接口的监听线程
static int init_interface_thread(const char *ifname, int thread_id) {
    if (interface_count >= MAX_INTERFACES) {
        log_error("Maximum number of interfaces reached");
        return -1;
    }
    
    interface_thread_t *it = &interface_threads[interface_count];
    
    // 初始化接口线程结构
    memset(it, 0, sizeof(interface_thread_t));
    strncpy(it->name, ifname, IF_NAMESIZE - 1);
    it->name[IF_NAMESIZE - 1] = '\0';
    it->is_active = 0;
    it->thread_ret = 0;
    
    // 获取接口索引
    it->ifindex = if_nametoindex(ifname);
    if (!it->ifindex) {
        log_error("Failed to get interface index for %s: %s", 
                ifname, strerror(errno));
        return -1;
    }
    
    log_info("Initializing interface %s (index: %d) for thread %d", 
           ifname, it->ifindex, thread_id);
    
    interface_count++;
    return 0;
}

// 单个接口的监听线程函数
static void *interface_listener_thread(void *arg) {
    thread_arg_t *thread_arg = (thread_arg_t *)arg;
    char *ifname = thread_arg->interface_name;
    int thread_id = thread_arg->thread_id;
    
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct perf_buffer *pb = NULL;
    int map_fd, err;
    int ret = 0;
    
    log_info("Thread %d: Starting listener for interface %s", thread_id, ifname);
    
    // 加载BPF程序
    obj = bpf_object__open_file("bpf_program.o", NULL);
    if (libbpf_get_error(obj)) {
        log_error("Thread %d: Failed to open BPF object file for %s", 
                thread_id, ifname);
        ret = 1;
        goto cleanup;
    }
    
    // 加载到内核
    err = bpf_object__load(obj);
    if (err) {
        log_error("Thread %d: BPF loading failed for %s: %s", 
                thread_id, ifname, strerror(-err));
        ret = 1;
        goto cleanup;
    }
    
    // 附加到接口
    prog = bpf_object__find_program_by_name(obj, "xdp_packet_capture");
    if (!prog) {
        log_error("Thread %d: BPF program not found for %s", 
                thread_id, ifname);
        ret = 1;
        goto cleanup;
    }
    
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        log_error("Thread %d: Failed to get interface index for %s: %s", 
                thread_id, ifname, strerror(errno));
        ret = 1;
        goto cleanup;
    }
    
    link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link)) {
        log_error("Thread %d: XDP attachment failed for %s: %s", 
                thread_id, ifname, strerror(-errno));
        ret = 1;
        goto cleanup;
    }
    
    // 设置性能缓冲区
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        log_error("Thread %d: Perf event map not found for %s", 
                thread_id, ifname);
        ret = 1;
        goto cleanup;
    }
    
    struct perf_buffer_opts pb_opts = {
        .sz = sizeof(pb_opts),
    };
    
    pb = perf_buffer__new(map_fd, PERF_BUFFER_PAGES, 
                          handle_batch, 
                          NULL, 
                          NULL, 
                          &pb_opts);
    
    if (libbpf_get_error(pb)) {
        log_error("Thread %d: Failed to create perf buffer for %s", 
                thread_id, ifname);
        ret = 1;
        goto cleanup;
    }
    
    // 更新接口线程状态
    pthread_mutex_lock(&interface_mutex);
    for (int i = 0; i < interface_count; i++) {
        if (strcmp(interface_threads[i].name, ifname) == 0) {
            interface_threads[i].obj = obj;
            interface_threads[i].link = link;
            interface_threads[i].pb = pb;
            interface_threads[i].is_active = 1;
            break;
        }
    }
    pthread_mutex_unlock(&interface_mutex);
    
    log_info("Thread %d: Successfully started capturing on %s", thread_id, ifname);
    
    // 事件循环
    while (running) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            log_error("Thread %d: Error polling %s: %d", thread_id, ifname, err);
            break;
        }
    }
    
    log_info("Thread %d: Exiting listener for %s", thread_id, ifname);
    
cleanup:
    // 清理资源
    if (pb) {
        perf_buffer__free(pb);
    }
    
    if (link) {
        bpf_link__destroy(link);
    }
    
    if (obj) {
        bpf_object__close(obj);
    }
    
    // 更新接口线程状态
    pthread_mutex_lock(&interface_mutex);
    for (int i = 0; i < interface_count; i++) {
        if (strcmp(interface_threads[i].name, ifname) == 0) {
            interface_threads[i].is_active = 0;
            interface_threads[i].thread_ret = ret;
            break;
        }
    }
    pthread_mutex_unlock(&interface_mutex);
    
    free(thread_arg);
    return NULL;
}

// 启动多接口监听
static int start_multi_interface_capture(char *interfaces[], int interface_count) {
    pthread_t *threads = malloc(interface_count * sizeof(pthread_t));
    if (!threads) {
        log_error("Failed to allocate thread array");
        return -1;
    }
    
    log_info("Starting %d interface listener threads...", interface_count);
    
    // 为每个接口创建监听线程
    for (int i = 0; i < interface_count; i++) {
        thread_arg_t *arg = malloc(sizeof(thread_arg_t));
        if (!arg) {
            log_error("Failed to allocate thread argument for %s", interfaces[i]);
            continue;
        }
        
        strncpy(arg->interface_name, interfaces[i], IF_NAMESIZE - 1);
        arg->interface_name[IF_NAMESIZE - 1] = '\0';
        arg->thread_id = i;
        
        // 初始化接口线程
        if (init_interface_thread(interfaces[i], i) != 0) {
            log_error("Failed to initialize interface %s", interfaces[i]);
            free(arg);
            continue;
        }
        
        // 创建线程
        if (pthread_create(&threads[i], NULL, interface_listener_thread, arg) != 0) {
            log_error("Failed to create thread for interface %s", interfaces[i]);
            free(arg);
            continue;
        }
        
        log_info("Created listener thread %d for interface %s", i, interfaces[i]);
    }
    
    // 等待所有线程完成
    log_info("Waiting for interface threads to complete...");
    for (int i = 0; i < interface_count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    free(threads);
    return 0;
}

// 修改后的run_live_capture函数 - 支持多接口监听
int run_live_capture(const char *ifname) {
    // 如果指定了特定接口，使用单接口模式
    if (ifname && strcmp(ifname, "all") != 0) {
        return run_single_interface_capture(ifname);
    }
    
    // 多接口模式
    char interfaces[MAX_INTERFACES][IF_NAMESIZE];
    int available_count = get_available_interfaces(interfaces, MAX_INTERFACES);
    
    if (available_count == 0) {
        log_error( "No available network interfaces found\n");
        return 1;
    }
    
    log_info("Found %d available interfaces:\n", available_count);
    for (int i = 0; i < available_count; i++) {
        log_info("  %d: %s\n", i + 1, interfaces[i]);
    }
    
    // 初始化全局资源
    start_time = time(NULL);
    packet_queue_init(&packet_queue, PACKET_QUEUE_SIZE);
    flow_table_init();
    log_info("Flow tracking initialized");
    
    if (duration > 0) {
        log_info("Will capture traffic for %d seconds\n", duration);
    }
    
    // 转换为指针数组
    char *interface_ptrs[MAX_INTERFACES];
    for (int i = 0; i < available_count; i++) {
        interface_ptrs[i] = interfaces[i];
    }
    
    // 启动多接口监听
    int ret = start_multi_interface_capture(interface_ptrs, available_count);
    
    // 等待队列处理完所有数据包
    while (packet_queue_size(&packet_queue) > 0 && running) {
        packet_data_t packet;
        if (packet_queue_dequeue(&packet_queue, &packet) == 0) {
            // 直接处理数据包
            if (packet.ip_header.protocol == IPPROTO_TCP) {
                // 从存储的TCP头部数据中提取标志位
                struct tcphdr *tcp_header = (struct tcphdr *)packet.transport_header.tcp.flags_byte;
                uint8_t tcp_flags = *((uint8_t*)tcp_header + 13);  // TCP标志位在第13字节
                uint32_t tcp_seq = packet.transport_header.tcp.seq;
                
                process_packet_direct(&packet.ip_header, 
                                    packet.transport_header.tcp.source,
                                    packet.transport_header.tcp.dest,
                                    tcp_seq, tcp_flags, packet.timestamp);
            } else if (packet.ip_header.protocol == IPPROTO_UDP) {
                process_packet_direct(&packet.ip_header,
                                    packet.transport_header.udp.source,
                                    packet.transport_header.udp.dest,
                                    0, 0, packet.timestamp);  // UDP没有序列号和标志位
            }
        }
    }
    
    // 调用统一清理函数
    cleanup();
    
    return ret;
}

// 单接口监听函数（保持原有逻辑）
int run_single_interface_capture(const char *ifname) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct perf_buffer *pb = NULL;
    int map_fd, err;
    int ret = 0;

    // Record start time
    start_time = time(NULL);
    
    // 初始化数据包队列
    packet_queue_init(&packet_queue, PACKET_QUEUE_SIZE);

    // Initialize flow tracking
    flow_table_init();
    log_info("Flow tracking initialized");
    if (duration > 0) {
        log_info("Will capture traffic for %d seconds", duration);
    }
    
    log_info("Processing interface: %s", ifname);

    /* 1. Load BPF program */
    log_info("Loading BPF program from bpf_program.o...");
    obj = bpf_object__open_file("bpf_program.o", NULL);
    if (libbpf_get_error(obj)) {
        log_error("Failed to open BPF object file: %s", strerror(-libbpf_get_error(obj)));
        ret = 1;
        goto cleanup;
    }
    log_info("BPF object loaded successfully");

    /* 2. Load into kernel */
    log_info("Loading BPF program into kernel...");
    err = bpf_object__load(obj);
    if (err) {
        log_error("BPF loading failed: %s", strerror(-err));
        ret = 1;
        goto cleanup;
    }
    log_info("BPF program loaded into kernel successfully");

    /* 3. Attach to interface */
    log_info("Finding XDP program...");
    prog = bpf_object__find_program_by_name(obj, "xdp_packet_capture");
    if (!prog) {
        log_error("BPF program 'xdp_packet_capture' not found");
        ret = 1;
        goto cleanup;
    }
    log_info("XDP program found");

    log_info("Getting interface index for %s...", ifname);
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        log_error("Failed to get interface index for %s: %s", ifname, strerror(errno));
        ret = 1;
        goto cleanup;
    }
    log_info("Interface index: %d", ifindex);

    // 预取相关内存以提高性能
    PREFETCH(prog);
    log_info("Attaching XDP program to interface...");
    link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link)) {
        log_error("XDP attachment failed: %s", strerror(-libbpf_get_error(link)));
        ret = 1;
        goto cleanup;
    }
    log_info("XDP program attached successfully");

    /* 4. Setup perf buffer */
    log_info("Setting up perf buffer...");
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        log_error("Perf event map 'events' not found");
        ret = 1;
        goto cleanup;
    }
    log_info("Perf event map found, fd: %d", map_fd);
    
    struct perf_buffer_opts pb_opts = {
        .sz = sizeof(pb_opts),
    };

    /* 新版libbpf API */
    pb = perf_buffer__new(map_fd, PERF_BUFFER_PAGES, 
                        handle_batch, 
                        NULL, 
                        NULL, 
                        &pb_opts);

    if (libbpf_get_error(pb)) {
        log_error("Failed to create perf buffer: %s", strerror(-libbpf_get_error(pb)));
        ret = 1;
        goto cleanup;
    }
    log_info("Perf buffer created successfully");

    log_info("Successfully started capturing on %s", ifname);

    /* 5. Event loop */
    if (!quiet_mode) {
        log_info("Entering event loop...");
    }
    
    // 添加定期处理变量
    uint64_t packet_count = 0;
    uint64_t last_process_time = 0;
    uint64_t current_time = 0;
    const uint64_t PROCESS_INTERVAL_MS = 300;  // 300ms处理间隔
    const uint64_t PROCESS_PACKET_COUNT = 1000;  // 每1000个包处理一次
    const int MAX_BATCH_SIZE = 500;  // 每次最多处理500个包，避免长时间占用CPU
    
    // 添加统计输出变量
    uint64_t last_stats_time = 0;
    const uint64_t STATS_INTERVAL_MS = 1000;  // 每1秒输出一次统计，提高更新频率
    
    while (running) {
        err = perf_buffer__poll(pb, 100);
        // 使用位操作代替条件判断 - 仅当err < 0且err != -EINTR时退出
        int should_break = (err < 0) & (err != -EINTR);
        if (should_break) {
            log_error("Error polling: %d", err);
            break;
        }
        
        // 获取当前时间（毫秒）
        current_time = get_current_time() / 1000000;  // 转换为毫秒
        
        // 处理队列中的数据包 - 每1000个包或每300ms处理一次
        if (packet_count >= PROCESS_PACKET_COUNT || 
            (current_time - last_process_time) >= PROCESS_INTERVAL_MS) {
            
            int processed_count = 0;
            
            while (packet_queue_size(&packet_queue) > 0 && running && processed_count < MAX_BATCH_SIZE) {
                packet_data_t packet;
                if (packet_queue_dequeue(&packet_queue, &packet) == 0) {
                    // 直接处理数据包
                    if (packet.ip_header.protocol == IPPROTO_TCP) {
                        // 从存储的TCP头部数据中提取标志位
                        struct tcphdr *tcp_header = (struct tcphdr *)packet.transport_header.tcp.flags_byte;
                        uint8_t tcp_flags = *((uint8_t*)tcp_header + 13);  // TCP标志位在第13字节
                        uint32_t tcp_seq = packet.transport_header.tcp.seq;
                        
                        process_packet_direct(&packet.ip_header, 
                                            packet.transport_header.tcp.source,
                                            packet.transport_header.tcp.dest,
                                            tcp_seq, tcp_flags, packet.timestamp);
                    } else if (packet.ip_header.protocol == IPPROTO_UDP) {
                        process_packet_direct(&packet.ip_header,
                                            packet.transport_header.udp.source,
                                            packet.transport_header.udp.dest,
                                            0, 0, packet.timestamp);  // UDP没有序列号和标志位
                    }
                    processed_count++;
                }
            }
            
            // 重置计数器和时间
            packet_count = 0;
            last_process_time = current_time;
            
            // 调试输出（仅在debug模式下）
            if (get_debug_level() >= 2 && processed_count > 0) {
                log_debug("Processed %d packets from queue (queue size: %lu)\n", 
                       processed_count, packet_queue_size(&packet_queue));
            }
            
            // 如果队列仍然很大，给其他进程一些CPU时间
            if (packet_queue_size(&packet_queue) > 1000) {
                usleep(1000);  // 休眠1ms，让出CPU时间片
            }
        }
        
        // 更新包计数器 - 使用全局计数器
        packet_count = global_packet_count;
        
        // 定期输出统计信息（固定位置更新）
        if (current_time - last_stats_time >= STATS_INTERVAL_MS) {
            // 清除当前行并回到行首，确保固定位置更新
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
                pps = (double)packets_diff * 1000.0 / time_diff;  // 包/秒
                bps = (double)bytes_diff * 1000.0 / time_diff;    // 字节/秒
            }
            
            // 动态进度指示器
            static int progress_phase = 0;
            const char *progress_chars[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
            const char *progress = progress_chars[progress_phase % 10];
            progress_phase++;
            
            // 获取当前时间戳
            time_t now = time(NULL);
            struct tm *tm_info = localtime(&now);
            char time_str[9];
            strftime(time_str, sizeof(time_str), "%H:%M:%S", tm_info);
            
            // 输出增强的统计信息（固定位置，不换行）
            printf("⏰ %s | 🔄 %s | 📦 %lu (%.1f pkt/s) | 💾 %.2f MB (%.1f KB/s) | 🔗 TCP:%u UDP:%u Total:%u | 🗄️ %d/%d",
                   time_str, progress,
                   total_packets_captured, pps,
                   total_bytes_captured / (1024.0 * 1024.0), bps / 1024.0,
                   get_tcp_conversation_count(),
                   get_udp_conversation_count(),
                   get_total_conversation_count(),
                   count_active_flows(),
                   count_all_flows());
            
            // 更新上次统计值
            last_packets = total_packets_captured;
            last_bytes = total_bytes_captured;
            last_time = current_time;
            
            fflush(stdout);
            last_stats_time = current_time;
        }
    }

    log_info("Exiting program...");
    
    // 在退出时添加换行，确保统计信息行完整显示
    printf("\n");
    
    // 等待队列处理完所有数据包
    while (packet_queue_size(&packet_queue) > 0 && running) {
        packet_data_t packet;
        if (packet_queue_dequeue(&packet_queue, &packet) == 0) {
            // 直接处理数据包
            if (packet.ip_header.protocol == IPPROTO_TCP) {
                // 从存储的TCP头部数据中提取标志位
                struct tcphdr *tcp_header = (struct tcphdr *)packet.transport_header.tcp.flags_byte;
                uint8_t tcp_flags = *((uint8_t*)tcp_header + 13);  // TCP标志位在第13字节
                uint32_t tcp_seq = packet.transport_header.tcp.seq;
                
                process_packet_direct(&packet.ip_header, 
                                    packet.transport_header.tcp.source,
                                    packet.transport_header.tcp.dest,
                                    tcp_seq, tcp_flags, packet.timestamp);
            } else if (packet.ip_header.protocol == IPPROTO_UDP) {
                process_packet_direct(&packet.ip_header,
                                    packet.transport_header.udp.source,
                                    packet.transport_header.udp.dest,
                                    0, 0, packet.timestamp);  // UDP没有序列号和标志位
            }
        }
    }
    
cleanup:
    // Cleanup resources in reverse order of creation
    if (pb) {
        log_info("Cleaning up perf buffer...");
        perf_buffer__free(pb);
    }
    
    if (link) {
        log_info("Cleaning up XDP link...");
        bpf_link__destroy(link);
    }
    
    if (obj) {
        log_info("Cleaning up BPF object...");
        bpf_object__close(obj);
    }
    
    return ret;
}

// 流信息结构体，用于排序
struct flow_info {
    struct flow_node *node;
    int flow_id;
    int is_active;
    double duration;
    char start_time_str[64];
    char src_ip[16];
    char dst_ip[16];
    uint8_t protocol;
    uint64_t flow_packets;
    uint64_t flow_bytes;
    struct flow_features features;
};

// 比较函数，按开始时间排序
static int compare_flows_by_time(const void *a, const void *b) {
    const struct flow_info *flow_a = (const struct flow_info *)a;
    const struct flow_info *flow_b = (const struct flow_info *)b;
    
    // 比较开始时间
    if (flow_a->node->stats.start_time.tv_sec < flow_b->node->stats.start_time.tv_sec) {
        return -1;
    } else if (flow_a->node->stats.start_time.tv_sec > flow_b->node->stats.start_time.tv_sec) {
        return 1;
    } else {
        // 秒数相同，比较纳秒
        if (flow_a->node->stats.start_time.tv_nsec < flow_b->node->stats.start_time.tv_nsec) {
            return -1;
        } else if (flow_a->node->stats.start_time.tv_nsec > flow_b->node->stats.start_time.tv_nsec) {
            return 1;
        } else {
            return 0;
        }
    }
}

// 实现print_final_stats函数 - 在程序结束时打印最终统计（按时间顺序）
void print_final_stats(void) {
    int all_flow_count = count_all_flows();
    if (all_flow_count == 0) {
        log_info("No flows found");
        return;
    }
    
    // 分配内存
    struct flow_info *flows = malloc(all_flow_count * sizeof(struct flow_info));
    if (!flows) {
        log_error("Memory allocation failed");
        return;
    }
    
    int flow_count = 0;
    
    // 收集流信息
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node && flow_count < all_flow_count) {
            struct flow_info *flow = &flows[flow_count];
            flow->node = node;
            
            // 基本信息
            snprintf(flow->src_ip, sizeof(flow->src_ip), "%u.%u.%u.%u", NIPQUAD(node->key.src_ip));
            snprintf(flow->dst_ip, sizeof(flow->dst_ip), "%u.%u.%u.%u", NIPQUAD(node->key.dst_ip));
            flow->protocol = node->key.protocol;
            flow->flow_packets = node->stats.fwd_packets + node->stats.bwd_packets;
            flow->flow_bytes = node->stats.fwd_bytes + node->stats.bwd_bytes;
            
            // 计算特征
            memset(&flow->features, 0, sizeof(struct flow_features));
            if (node->stats.last_seen > node->stats.first_seen) {
                flow->features.fl_dur = (double)(node->stats.last_seen - node->stats.first_seen) / 1000000.0;
            }
            
            // 基本统计
            flow->features.tot_fw_pk = node->stats.fwd_packets;
            flow->features.tot_bw_pk = node->stats.bwd_packets;
            flow->features.tot_1_fw_pk = node->stats.fwd_bytes;
            flow->features.fwd_pkt_1_min = node->stats.fwd_min_size;
            flow->features.fwd_pkt_1_max = node->stats.fwd_max_size;
            flow->features.bwd_pkt_1_min = node->stats.bwd_min_size;
            flow->features.bwd_pkt_1_max = node->stats.bwd_max_size;
            flow->features.fw_hdr_len = node->stats.fwd_header_bytes;
            flow->features.bw_hdr_len = node->stats.bwd_header_bytes;
            flow->features.fw_win_byt = node->stats.fwd_init_win_bytes;
            flow->features.bw_win_byt = node->stats.bwd_init_win_bytes;
            flow->features.fw_act_pkt = node->stats.fwd_tcp_payload_bytes;
            flow->features.fw_seg_min = node->stats.fwd_min_segment;
            
            // 平均值
            if (node->stats.fwd_packets > 0) {
                flow->features.fwd_pkt_1_avg = (double)node->stats.fwd_bytes / node->stats.fwd_packets;
            }
            if (node->stats.bwd_packets > 0) {
                flow->features.bwd_pkt_1_avg = (double)node->stats.bwd_bytes / node->stats.bwd_packets;
            }
            
            // 流量率
            if (flow->features.fl_dur > 0) {
                flow->features.fl_byt_s = (double)flow->flow_bytes / flow->features.fl_dur;
                flow->features.fl_pkt_s = (double)flow->flow_packets / flow->features.fl_dur;
            }
            
            // 比例
            if (node->stats.bwd_bytes > 0) {
                flow->features.down_up_ratio = (double)node->stats.fwd_bytes / node->stats.bwd_bytes;
            }
            if (flow->flow_packets > 0) {
                flow->features.pkt_size_avg = (double)flow->flow_bytes / flow->flow_packets;
            }
            
            flow_count++;
            node = node->next;
        }
    }
    
    // 排序
    qsort(flows, flow_count, sizeof(struct flow_info), compare_flows_by_time);
    
    // 生成CSV
    FILE *csv_fp = NULL;
    if (csv_file) {
        csv_fp = fopen(csv_file, "w");
        if (csv_fp) {
            // 标题
            fprintf(csv_fp, "SrcIP,SrcPort,DstIP,DstPort,Protocol,Timestamp,fl_dur,tot_fw_pk,tot_bw_pk,tot_1_fw_pk,fwd_pkt_1_min,fwd_pkt_1_max,fwd_pkt_1_avg,fwd_pkt_1_std,bwd_pkt_1_min,bwd_pkt_1_max,bwd_pkt_1_avg,bwd_pkt_1_std,fl_byt_s,fl_pkt_s,fl_iat_avg,fl_iat_std,fl_iat_max,fl_iat_min,fw_iat_tot,fw_iat_avg,fw_iat_std,fw_iat_max,fw_iat_min,bw_iat_tot,bw_iat_avg,bw_iat_std,bw_iat_max,bw_iat_min,fw_hdr_len,bw_hdr_len,fw_pkt_s,bw_pkt_s,pkt_len_min,pkt_len_max,pkt_len_avg,pkt_len_std,pkt_len_va,down_up_ratio,pkt_size_avg,fw_seg_avg,bw_seg_avg,subfl_fw_pk,subfl_fw_byt,subfl_bw_pk,subfl_bw_byt,fw_win_byt,bw_win_byt,fw_ack_pkt,fw_seg_min\n");
            
            // 数据
            for (int i = 0; i < flow_count; i++) {
                struct flow_info *flow = &flows[i];
                struct flow_node *node = flow->node;
                
                char timebuf[32];
                format_ebpf_packet_time(node->stats.first_seen, timebuf, sizeof(timebuf));
                
                fprintf(csv_fp, "%s,%d,%s,%d,%d,%s,%.6f,%lu,%lu,%lu,%u,%u,%.6f,%.6f,%u,%u,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%lu,%lu,%.6f,%.6f,%u,%u,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%.6f,%u,%u,%u,%u\n",
                       flow->src_ip, node->original_src_port, flow->dst_ip, node->original_dst_port,
                       flow->protocol, timebuf, flow->features.fl_dur,
                       (unsigned long)flow->features.tot_fw_pk, (unsigned long)flow->features.tot_bw_pk,
                       (unsigned long)flow->features.tot_1_fw_pk, flow->features.fwd_pkt_1_min,
                       flow->features.fwd_pkt_1_max, flow->features.fwd_pkt_1_avg, flow->features.fwd_pkt_1_std,
                       flow->features.bwd_pkt_1_min, flow->features.bwd_pkt_1_max, flow->features.bwd_pkt_1_avg,
                       flow->features.bwd_pkt_1_std, flow->features.fl_byt_s, flow->features.fl_pkt_s,
                       flow->features.fl_iat_avg, flow->features.fl_iat_std, flow->features.fl_iat_max,
                       flow->features.fl_iat_min, flow->features.fw_iat_tot, flow->features.fw_iat_avg,
                       flow->features.fw_iat_std, flow->features.fw_iat_max, flow->features.fw_iat_min,
                       flow->features.bw_iat_tot, flow->features.bw_iat_avg, flow->features.bw_iat_std,
                       flow->features.bw_iat_max, flow->features.bw_iat_min, flow->features.fw_hdr_len,
                       flow->features.bw_hdr_len, flow->features.fw_pkt_s, flow->features.bw_pkt_s,
                       flow->features.pkt_len_min, flow->features.pkt_len_max, flow->features.pkt_len_avg,
                       flow->features.pkt_len_std, flow->features.pkt_len_va, flow->features.down_up_ratio,
                       flow->features.pkt_size_avg, flow->features.fw_seg_avg, flow->features.bw_seg_avg,
                       (double)flow->features.subfl_fw_pk, (double)flow->features.subfl_fw_byt,
                       (double)flow->features.subfl_bw_pk, (double)flow->features.subfl_bw_byt,
                       (unsigned int)flow->features.fw_win_byt, (unsigned int)flow->features.bw_win_byt, 
                       (unsigned int)flow->features.fw_act_pkt, (unsigned int)flow->features.fw_seg_min);
            }
            fclose(csv_fp);
            log_info("CSV exported: %s (%d flows)", csv_file, flow_count);
        }
    }
    
    free(flows);
}

// 打印使用帮助
void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("  -i, --interface <ifname>    Network interface to monitor (default: enp1s0)\n");
    printf("                               Use 'all' to monitor all available interfaces\n");
    printf("  -r, --read <pcap-file>      Read packets from pcap file instead of network\n");
    printf("  -d, --duration <seconds>    Run for specified duration in seconds (default: indefinite)\n");
    printf("  -s, --stats-interval <sec>  Interval between statistics printing (default: %d seconds)\n", 
           DEFAULT_STATS_INTERVAL);
    printf("  -p, --packets <count>       Print stats every N packets (default: %d)\n", 
           DEFAULT_STATS_PACKETS);
    printf("  -c, --cleanup <seconds>     Flow cleanup interval (default: %d seconds)\n", 
           DEFAULT_CLEANUP_INTERVAL);
    printf("  -o, --output <csv-file>     Export features to CSV file\n");
    printf("  -l, --loop <count>          Loop pcap file N times (0 = infinite, default: 1)\n");
    printf("  -w, --wait <seconds>        Wait N seconds between loops (default: 0)\n");
    printf("  -v, --verbose <level>       Debug level: 0=none, 1=basic, 2=detailed (default: 0)\n");
    printf("  -q, --quiet                 Quiet mode, don't print statistics to screen\n");
    printf("  -m, --monitor               Realtime monitor mode with ncurses interface\n");
    printf("  -h, --help                  Show this help message\n");
    printf("\nExamples:\n");
    printf("  %s -i enp1s0              # Monitor single interface\n", prog_name);
    printf("  %s -i all                 # Monitor all available interfaces\n", prog_name);
    printf("  %s -r capture.pcap        # Read from pcap file\n", prog_name);
    printf("  %s --monitor              # Start realtime monitor mode\n", prog_name);
}

// 启动时初始化时间基准
void init_time_base() {
    struct timespec realtime, monotonic;
    clock_gettime(CLOCK_REALTIME, &realtime);
    clock_gettime(CLOCK_MONOTONIC, &monotonic);
    boot_realtime = realtime;
    boot_monotonic_ns = (uint64_t)monotonic.tv_sec * 1000000000ULL + monotonic.tv_nsec;
}

// 将bpf_ktime_get_ns()时间戳转为wall time字符串
void format_ebpf_packet_time(uint64_t ktime_ns, char *buf, size_t buflen) {
    uint64_t base_ns = (uint64_t)boot_realtime.tv_sec * 1000000000ULL + boot_realtime.tv_nsec;
    uint64_t abs_ns = base_ns + (ktime_ns - boot_monotonic_ns);
    time_t sec = abs_ns / 1000000000ULL;
    struct tm tm;
    localtime_r(&sec, &tm);
    strftime(buf, buflen, "%Y-%m-%d %H:%M:%S", &tm);
}
// 删除未使用的cleanup_expired_sessions函数

// 删除未使用的print_realtime_stats函数

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

    while ((c = getopt_long(argc, argv, "i:r:d:s:p:c:o:l:w:v:qmh", long_options, NULL)) != -1) {
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

    // 检查是否有实时监控模式参数（通过命令行参数）
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--monitor") == 0 || strcmp(argv[i], "-m") == 0) {
            monitor_mode = 1;
            break;
        }
    }

    if (monitor_mode) {
        // 实时监控模式
        printf("Starting realtime monitor mode...\n");
        
        // 在monitor模式下显示信息、警告和错误日志，但不显示调试信息
        set_log_level(LOG_LEVEL_INFO);
        
        // 初始化会话管理器
        if (transport_session_manager_init() != 0) {
            fprintf(stderr, "Failed to initialize session manager\n");
            return 1;
        }
        
        // 运行单线程监控模式
        int ret = run_monitor_mode(ifname);
        
        // 清理
        transport_session_manager_cleanup();
        
        printf("\nMonitor mode finished\n");
        
        return ret;
    }

    if (pcap_file) {
        // Process pcap file
        ret = process_pcap_file(pcap_file);
    } else {
        // Live capture mode
        ret = run_live_capture(ifname);
    }

    // 打印最终消息
    printf("\n程序结束\n");

    return ret;
}



// 捕获线程函数
static void *capture_thread_func(void *arg) {
    struct perf_buffer *pb = (struct perf_buffer *)arg;
    int err;
    
    log_info("Capture thread started");
    
    while (monitor_running) {
        // 处理perf buffer事件（非阻塞）
        err = perf_buffer__poll(pb, 100); // 100ms超时
        if (err < 0 && err != -EINTR) {
            log_error("Error polling perf buffer: %s", strerror(-err));
            break;
        }
        
        // 处理队列中的数据包
        while (packet_queue_size(&packet_queue) > 0 && monitor_running) {
            packet_data_t packet;
            if (packet_queue_dequeue(&packet_queue, &packet) == 0) {
                // 直接处理数据包
                if (packet.ip_header.protocol == IPPROTO_TCP) {
                    // 从存储的TCP头部数据中提取标志位
                    struct tcphdr *tcp_header = (struct tcphdr *)packet.transport_header.tcp.flags_byte;
                    uint8_t tcp_flags = *((uint8_t*)tcp_header + 13);  // TCP标志位在第13字节
                    uint32_t tcp_seq = packet.transport_header.tcp.seq;
                    
                    process_packet_direct(&packet.ip_header, 
                                        packet.transport_header.tcp.source,
                                        packet.transport_header.tcp.dest,
                                        tcp_seq, tcp_flags, packet.timestamp);
                } else if (packet.ip_header.protocol == IPPROTO_UDP) {
                    process_packet_direct(&packet.ip_header,
                                        packet.transport_header.udp.source,
                                        packet.transport_header.udp.dest,
                                        0, 0, packet.timestamp);  // UDP没有序列号和标志位
                }
            }
        }
        
        // 短暂休眠以避免过度占用CPU
        usleep(10000); // 10ms
    }
    
    log_info("Capture thread finished");
    return NULL;
}

// 新增：运行监控模式的函数（捕获线程 + 主线程UI）
static int run_monitor_mode(const char *ifname) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct perf_buffer *pb = NULL;
    int map_fd, err;
    int ret = 0;
    WINDOW *win = NULL;
    pthread_t capture_thread;

    // 初始化时间基准
    init_time_base();
    
    // 初始化系统监控
    init_system_monitoring();

    // 初始化数据包队列
    packet_queue_init(&packet_queue, PACKET_QUEUE_SIZE);

    // 初始化流表
    flow_table_init();
    log_info("Flow tracking initialized");
    log_info("Processing interface: %s", ifname);

    /* 1. Load BPF program */
    log_info("Loading BPF program from bpf_program.o...");
    obj = bpf_object__open_file("bpf_program.o", NULL);
    if (libbpf_get_error(obj)) {
        log_error("Failed to open BPF object file: %s", strerror(-libbpf_get_error(obj)));
        ret = 1;
        goto cleanup;
    }
    log_info("BPF object loaded successfully");

    /* 2. Load into kernel */
    log_info("Loading BPF program into kernel...");
    err = bpf_object__load(obj);
    if (err) {
        log_error("BPF loading failed: %s", strerror(-err));
        ret = 1;
        goto cleanup;
    }
    log_info("BPF program loaded into kernel successfully");

    /* 3. Attach to interface */
    log_info("Finding XDP program...");
    prog = bpf_object__find_program_by_name(obj, "xdp_packet_capture");
    if (!prog) {
        log_error("BPF program 'xdp_packet_capture' not found");
        ret = 1;
        goto cleanup;
    }
    log_info("XDP program found");

    log_info("Getting interface index for %s...", ifname);
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        log_error("Failed to get interface index for %s: %s", ifname, strerror(errno));
        ret = 1;
        goto cleanup;
    }
    log_info("Interface index: %d", ifindex);

    // 预取相关内存以提高性能
    PREFETCH(prog);
    log_info("Attaching XDP program to interface...");
    link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link)) {
        log_error("XDP attachment failed: %s", strerror(-libbpf_get_error(link)));
        ret = 1;
        goto cleanup;
    }
    log_info("XDP program attached successfully");

    /* 4. Setup perf buffer */
    log_info("Setting up perf buffer...");
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        log_error("Perf event map 'events' not found");
        ret = 1;
        goto cleanup;
    }
    log_info("Perf event map found, fd: %d", map_fd);
    
    struct perf_buffer_opts pb_opts = {
        .sz = sizeof(pb_opts),
    };

    /* 新版libbpf API */
    pb = perf_buffer__new(map_fd, PERF_BUFFER_PAGES, 
                        handle_batch, 
                        NULL, 
                        NULL, 
                        &pb_opts);

    if (libbpf_get_error(pb)) {
        log_error("Failed to create perf buffer: %s", strerror(-libbpf_get_error(pb)));
        ret = 1;
        goto cleanup;
    }
    log_info("Perf buffer created successfully");
    log_info("Successfully started capturing on %s", ifname);

    /* 5. Start capture thread */
    log_info("Starting capture thread...");
    if (pthread_create(&capture_thread, NULL, capture_thread_func, pb) != 0) {
        log_error("Failed to create capture thread");
        ret = 1;
        goto cleanup;
    }

    /* 6. Initialize ncurses */
    win = init_stats_window();
    if (!win) {
        log_error("Failed to initialize stats window");
        ret = 1;
        goto cleanup;
    }

    /* 7. Main UI loop */
    log_info("Entering main UI loop...");
    
    while (monitor_running) {
        // 更新系统统计
        update_system_stats();
        
        // 更新UI
        update_stats_window(win);
        
        // 检查按键
        int ch = wgetch(win);
        if (ch == 'q' || ch == 'Q') {
            log_info("User requested exit from monitor");
            monitor_running = 0;
            break;
        }
        
        // 短暂休眠
        usleep(500000); // 0.5秒
    }

    /* 8. Wait for capture thread to complete */
    log_info("Waiting for capture thread to complete...");
    pthread_join(capture_thread, NULL);

cleanup:
    if (win) {
        cleanup_stats_window(win);
    }
    if (pb) {
        perf_buffer__free(pb);
    }
    if (link) {
        bpf_link__destroy(link);
    }
    if (obj) {
        bpf_object__close(obj);
    }
    
    // 清理数据包队列
    packet_queue_destroy(&packet_queue);
    
    // 清理流表
    flow_table_destroy();
    
    return ret;
}
