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

// SIMD优化宏定义
// 多线程相关配置
#define PACKET_QUEUE_SIZE 500000  // 数据包队列大小（优化：预分配更大容量避免扩容）
#define MAX_INTERFACES 32        // 最大支持的接口数量
#define MAX_WORKER_THREADS 4     // 最大工作线程数（减少到4）
#define DEFAULT_WORKER_THREADS 2 // 默认工作线程数（等于CPU核心数）
#define WORKER_THREAD_STACK_SIZE (64 * 1024) // 工作线程栈大小64KB

// 线程池相关结构体
typedef struct {
    pthread_t thread;           // 线程ID
    int thread_id;             // 线程编号
    volatile int running;      // 线程运行状态
    volatile int busy;         // 线程忙碌状态
    uint64_t packets_processed; // 该线程处理的包数
    uint64_t bytes_processed;   // 该线程处理的字节数
    struct timespec last_activity; // 最后活动时间
} worker_thread_t;

// 线程池管理器
typedef struct {
    worker_thread_t workers[MAX_WORKER_THREADS]; // 工作线程数组
    int thread_count;          // 实际线程数
    volatile int shutdown;     // 关闭标志
    pthread_mutex_t stats_mutex; // 统计信息互斥锁
    pthread_cond_t work_cond;  // 工作条件变量
    pthread_mutex_t work_mutex; // 工作互斥锁
} thread_pool_t;

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
volatile int running = 1;
int quiet_mode = 0;
int loop_count = 1;
int loop_delay = 0;
int duration = 0;
static volatile sig_atomic_t cleanup_done = 0;
static volatile int monitor_running = 1;  // 监控模式运行状态

// 全局统计变量
volatile uint64_t total_packets_captured = 0;
volatile uint64_t total_bytes_captured = 0;
volatile uint64_t total_packets_processed = 0;

// 哈希算法测试相关变量
static int hash_test_mode = 0;
static int hash_test_iterations = 1000000;
volatile uint64_t total_bytes_processed = 0;

// 线程池相关全局变量
static thread_pool_t g_thread_pool = {0};
static int worker_thread_count = DEFAULT_WORKER_THREADS; // 可配置的工作线程数

// 线程池最终统计保存
static uint64_t final_thread_pool_packets = 0;
static uint64_t final_thread_pool_bytes = 0;
static int final_thread_pool_busy = 0;
static int final_thread_pool_total = 0;
static int thread_pool_initialized = 0;  // 线程池初始化标志

// 函数声明
static void print_stats_line(const char *time_str, const char *progress, 
                            uint64_t packets, double pps, double mb_processed, double kbps,
                            uint32_t tcp_count, uint32_t udp_count, uint32_t total_count,
                            int active_flows, int total_flows, uint64_t created, uint64_t reused,
                            double cpu_usage, double memory_usage, const char *suffix);

static void print_pcap_stats_line(int current_loop, uint64_t processed, uint64_t total, 
                                 double progress_percent, double pps, double mb_processed, double kbps,
                                 uint32_t tcp_count, uint32_t udp_count, uint32_t total_count,
                                 int active_flows, int total_flows, uint64_t created, uint64_t reused,
                                 double cpu_usage, double memory_usage);

// 详细统计计数器
volatile uint64_t total_packets_filtered = 0;      // 被过滤的包数
volatile uint64_t total_packets_invalid = 0;       // 无效包数
volatile uint64_t total_packets_dropped = 0;       // 队列满丢弃的包数
volatile uint64_t total_packets_queued = 0;        // 成功入队的包数
volatile uint64_t total_packets_dequeued = 0;      // 成功出队的包数


// 全局实时统计
realtime_stats_t g_realtime_stats = {0};

// 函数前向声明
void print_final_stats(void);
void analyze_packet_count_mismatch(void);
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
extern struct mempool global_pool; // 从flow.c导入全局内存池
extern void mempool_get_stats(struct mempool *pool, size_t *total_nodes, size_t *free_nodes, size_t *used_nodes);
extern void cleanup_flows(void); // 从flow.c导入流清理函数
extern void mempool_clear(struct mempool *pool); // 从mempool.c导入内存池清理函数
extern void get_session_creation_stats(uint64_t *total_created, uint64_t *tcp_created, uint64_t *udp_created, uint64_t *reused);
extern transport_session_t *process_packet_with_conversation(const struct flow_key *key, 
                                                           uint32_t packet_size,
                                                           uint8_t tcp_flags,
                                                           uint64_t timestamp);
extern int calculate_session_features(transport_session_t *session);
extern int export_comprehensive_flow_features_to_csv(const char *filename);
extern int export_conversation_based_sessions_to_csv(const char *filename);

// 哈希算法测试函数声明
static void test_hash_algorithms(void);
static void generate_random_flow_key(struct flow_key *key);

// 线程池相关函数声明
static int thread_pool_init(int thread_count);
static void thread_pool_destroy(void);
static void *worker_thread_func(void *arg);
static void process_packet_queue_mt(void);
static void update_thread_pool_stats(void);
void get_thread_pool_stats(uint64_t *total_packets, uint64_t *total_bytes, 
                          int *busy_threads, int *total_threads);

// 内存监控函数声明


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
#define PERF_BUFFER_PAGES 128  // 优化：从32增加到128页(512KB)以减少内核态丢包

// NIPQUAD macro for printing IP addresses
#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

// Default settings
#define DEFAULT_STATS_INTERVAL 2   // 5 seconds between stats prints
#define DEFAULT_STATS_PACKETS 1000 // Print stats every 1000 packets
#define DEFAULT_CLEANUP_INTERVAL 5  // 4GB优化：5秒清理间隔，更频繁清理
#define DEFAULT_DURATION 0         // 0 means run indefinitely
#define DEFAULT_CSV_FILE NULL      // Default CSV file (none)
#define DEFAULT_LOOP_COUNT 1       // Default loop count (1 = no loop)

// 锁文件路径
#define LOCK_FILE "/var/run/ebpf_pkt.lock"

// Global settings
static int stats_interval = DEFAULT_STATS_INTERVAL;
static int stats_packet_count = DEFAULT_STATS_PACKETS;
static int cleanup_interval = DEFAULT_CLEANUP_INTERVAL;  // 使用从cicflowmeter复制的参数
static time_t start_time;                // program start time
static int lock_fd = -1;                // 文件锁描述符
static const char *csv_file = DEFAULT_CSV_FILE; // CSV输出文件路径

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
lockfree_queue_t packet_queue;

// 全局包计数器
static volatile uint64_t global_packet_count = 0;

// 实时统计计数器（已移到全局变量声明中）

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
            // 短暂让出CPU，减少延迟（优化：从usleep(1)改为CPU yield）
            __asm__ __volatile__("pause" ::: "memory");
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
            // 队列为空，短暂让出CPU（优化：减少延迟）
            __asm__ __volatile__("pause" ::: "memory");
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
uint64_t packet_queue_size(lockfree_queue_t *queue) {
    // 检查队列是否已初始化
    if (!queue || !queue->packets) {
        return 0;
    }
    
    uint64_t tail = queue->tail;
    uint64_t head = queue->head;
    return tail - head;
}

// 包处理计数器（已移到全局变量声明中）

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

// 直接处理数据包函数（单线程版本）
static void process_packet_direct(const struct iphdr *ip, uint16_t src_port, uint16_t dst_port, 
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
    
    // **与pcap保持一致**: 只调用process_packet()，不进行额外的会话处理
    // 这样可以避免重复创建会话，减少内存消耗
    
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

    log_info("Starting cleanup process...");

    // 保存线程池统计信息
    log_info("Saving thread pool stats before destruction...");
    get_thread_pool_stats(&final_thread_pool_packets, &final_thread_pool_bytes, 
                         &final_thread_pool_busy, &final_thread_pool_total);
    log_info("Thread pool stats saved: threads=%d, packets=%lu, bytes=%lu", 
             final_thread_pool_total, final_thread_pool_packets, final_thread_pool_bytes);

    // 销毁线程池
    thread_pool_destroy();

    // 销毁数据包队列
    packet_queue_destroy(&packet_queue);

    // Cleanup flow table
    if (flow_table_initialized) {
        print_final_stats();  // 注释掉统计结果输出
        flow_table_destroy();
    }

    // 清理会话管理器
    log_info("Cleaning up session manager...");
    transport_session_manager_cleanup();
    log_info("Session manager cleaned up");

    // 清空内存池
    log_info("Clearing memory pool...");
    mempool_clear(&global_pool);
    log_info("Memory pool cleared successfully");

    // Close lock file
    if (lock_fd != -1) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        unlink(LOCK_FILE);
        lock_fd = -1;
    }
    
    log_info("Cleanup completed");
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
        
        // 只设置退出标志，让主线程处理清理
        log_info("Setting shutdown flag, main thread will handle cleanup...");
        __sync_fetch_and_and(&running, 0);
        __sync_fetch_and_and(&monitor_running, 0);
        
        // 设置较短的超时时间
        alarm(5); // 5秒超时
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
    // atexit(cleanup);  // 注释掉，改为手动调用
    
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
        if (!is_valid) {
            __sync_fetch_and_add(&total_packets_invalid, 1);
            continue;
        }
        
        // 更新全局包计数器
        __sync_fetch_and_add(&global_packet_count, 1);
        
        // **恢复**: 在BPF捕获点统计包数，这是从eBPF程序实际接收到的包
        __sync_fetch_and_add(&total_packets_captured, 1);
        __sync_fetch_and_add(&total_bytes_captured, pkt->pkt_len);
        
        // 调试输出（前10个包）- 仅在debug模式下显示
        static int debug_count = 0;
        if (debug_count < 10) {
            struct in_addr src_addr = {.s_addr = pkt->src_ip};
            struct in_addr dst_addr = {.s_addr = pkt->dst_ip};
            log_debug("Packet %d - IP: %s -> %s, Protocol: %d, Ports: %u -> %u, TCP flags: 0x%02x, Length: %u bytes", 
                   debug_count + 1, inet_ntoa(src_addr), inet_ntoa(dst_addr), 
                   pkt->protocol, pkt->src_port, pkt->dst_port, pkt->tcp_flags, pkt->pkt_len);
            debug_count++;
        }
        
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
            // 入队失败，统计丢包
            __sync_fetch_and_add(&total_packets_dropped, 1);
            if (!running) break;
        } else {
            __sync_fetch_and_add(&total_packets_queued, 1);
            
            // 每入队1000个包输出一次调试信息
            static uint64_t enqueue_debug_count = 0;
            if (++enqueue_debug_count % 1000 == 0) {
                log_info("Enqueued %lu packets, queue size: %lu", enqueue_debug_count, packet_queue_size(&packet_queue));
            }
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
    
    // 更新字节统计 - 使用pcap头部的实际长度
    __sync_fetch_and_add(&total_bytes_captured, header->len);
    __sync_fetch_and_add(&total_packets_captured, 1);
    
    // 调试输出（前5个包）- 显示字节统计更新
    static int debug_count = 0;
    if (debug_count < 5) {
        log_debug("PCAP Packet %d - Length: %u bytes, Total bytes: %lu", 
                   debug_count + 1, header->len, total_bytes_captured);
        debug_count++;
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
    
    // 初始化线程池
    log_info("About to initialize thread pool with %d threads (PCAP mode)", worker_thread_count);
    if (thread_pool_init(worker_thread_count) != 0) {
        log_error("Failed to initialize thread pool\n");
        return 1;
    }
    log_info("Thread pool initialization successful (PCAP mode)");
    
    // 初始化会话管理器
    if (transport_session_manager_init() != 0) {
        log_error("Failed to initialize session manager\n");
        return 1;
    }
    
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
        
        // 首先统计pcap文件的总包数
        uint64_t pcap_total_packets = 0;
        uint64_t pcap_total_bytes = 0;
        pcap_t *count_handle = pcap_open_offline(pcap_file, errbuf);
        if (count_handle != NULL) {
            struct pcap_pkthdr header;
            const u_char *packet;
            while ((packet = pcap_next(count_handle, &header)) != NULL) {
                pcap_total_packets++;
                pcap_total_bytes += header.len;
            }
            pcap_close(count_handle);
            log_info("PCAP file contains %lu packets (%.2f MB)", 
                    pcap_total_packets, pcap_total_bytes / (1024.0 * 1024.0));
        }
        
        // 处理pcap文件中的数据包
        struct pcap_pkthdr header;
        const u_char *packet;
        int loop_packet_count = 0;
        
        // 实时统计变量
        uint64_t last_stats_time = 0;
        uint64_t last_packets = 0;
        uint64_t last_bytes = 0;
        uint64_t total_packets_processed = 0;
        // 使用全局变量而不是局部变量
        total_bytes_processed = 0;
        
        while (running && (packet = pcap_next(handle, &header)) != NULL) {
            // 直接处理数据包
            process_pcap_packet(packet, &header);
            loop_packet_count++;
            total_packet_count++;
            total_packets_processed++;
            total_bytes_processed += header.len;
            
            // 实时统计显示（每100ms更新一次）
            uint64_t current_time = get_current_time() / 1000000; // 转换为毫秒
            if (current_time - last_stats_time >= 100) { // 每100ms更新一次
                // 计算速率
                double time_diff = (current_time - last_stats_time) / 1000.0; // 转换为秒
                double pps = time_diff > 0 ? (total_packets_processed - last_packets) / time_diff : 0;
                double bps = time_diff > 0 ? (total_bytes_processed - last_bytes) / time_diff : 0;
                
                // 计算进度百分比
                double progress_percent = pcap_total_packets > 0 ? 
                    (total_packets_processed * 100.0) / pcap_total_packets : 0.0;
                
                // 获取会话统计
                uint64_t total_created, tcp_created, udp_created, reused;
                get_session_creation_stats(&total_created, &tcp_created, &udp_created, &reused);
                
                // 获取系统统计
                update_system_stats();
                
                // 显示实时统计（包含总包数和进度）
                print_pcap_stats_line(current_loop,
                                     total_packets_processed, pcap_total_packets, progress_percent, pps,
                                     total_bytes_processed / (1024.0 * 1024.0), bps * 8 / 1000.0,
                                     get_tcp_conversation_count(),
                                     get_udp_conversation_count(),
                                     get_total_conversation_count(),
                                     count_active_flows(),
                                     count_all_flows(),
                                     total_created,
                                     reused,
                                     system_stats.cpu_usage,
                                     system_stats.memory_usage);
                
                // 更新上次统计值
                last_packets = total_packets_processed;
                last_bytes = total_bytes_processed;
                last_stats_time = current_time;
            }
        }
        
        // 处理完一个循环后，显示完成统计
        if (!quiet_mode) {
            printf("\n✅ Loop %d completed: %d packets processed\n", current_loop, loop_packet_count);
        }
        
        pcap_close(handle);
        
        // 如果不是最后一个循环，等待指定时间
        if (running && (loop_count == 0 || current_loop < loop_count) && loop_delay > 0) {
            if (!quiet_mode) {
                printf("⏳ Waiting %d seconds before next loop...\n", loop_delay);
            }
            sleep(loop_delay);
        }
    }
    
    // 处理完成后，等待所有统计更新完成
    if (!quiet_mode) {
        printf("\n🔄 Finalizing statistics...\n");
    }
    
    // 等待一小段时间确保所有统计都已更新
    usleep(100000); // 100ms
    
    // 显示最终统计
    printf("\n📊 PCAP Processing Complete!\n");
    printf("📦 Total packets processed: %d\n", total_packet_count);
    printf("💾 Total bytes processed: %.2f MB\n", total_bytes_processed / (1024.0 * 1024.0));
    printf("🔗 TCP sessions: %u\n", get_tcp_conversation_count());
    printf("🔗 UDP sessions: %u\n", get_udp_conversation_count());
    printf("🔗 Total sessions: %u\n", get_total_conversation_count());
    printf("🗄️  Active flows: %d\n", count_active_flows());
    printf("🗄️  Total flows: %d\n", count_all_flows());
    
    return ret;
}

// 显示统计信息的统一函数
static void print_stats_line(const char *time_str, const char *progress, 
                            uint64_t packets, double pps, double mb_processed, double kbps,
                            uint32_t tcp_count, uint32_t udp_count, uint32_t total_count,
                            int active_flows, int total_flows, uint64_t created, uint64_t reused,
                            double cpu_usage, double memory_usage, const char *suffix) {
    printf("\r⏰ %s | 🔄 %s | 📦 %lu (%.1f pkt/s) | 💾 %.2f MB (%.1f kb/s) | 🔗 TCP:%u UDP:%u Total:%u | 🗄️ %d/%d | 📊 Created:%lu Reused:%lu | 🖥️  CPU:%.1f%% MEM:%.1f%%%s",
           time_str, progress, packets, pps, mb_processed, kbps,
           tcp_count, udp_count, total_count, active_flows, total_flows,
           created, reused, cpu_usage, memory_usage, suffix);
    fflush(stdout);
}

// 显示PCAP处理统计信息的函数
static void print_pcap_stats_line(int current_loop, uint64_t processed, uint64_t total, 
                                 double progress_percent, double pps, double mb_processed, double kbps,
                                 uint32_t tcp_count, uint32_t udp_count, uint32_t total_count,
                                 int active_flows, int total_flows, uint64_t created, uint64_t reused,
                                 double cpu_usage, double memory_usage) {
    printf("\r⏰ PCAP | 🔄 Loop:%d | 📦 %lu/%lu (%.1f%%) (%.1f pkt/s) | 💾 %.2f MB (%.1f kb/s) | 🔗 TCP:%u UDP:%u Total:%u | 🗄️ %d/%d | 📊 Created:%lu Reused:%lu | 🖥️  CPU:%.1f%% MEM:%.1f%%",
           current_loop, processed, total, progress_percent, pps, mb_processed, kbps,
           tcp_count, udp_count, total_count, active_flows, total_flows,
           created, reused, cpu_usage, memory_usage);
    fflush(stdout);
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
        
        // 跳过回环接口和enp1s0
        if (strcmp(i->if_name, "lo") == 0 || strcmp(i->if_name, "enp1s0") == 0) continue;
        
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
    
    // 不等待线程完成，让线程在后台运行
    log_info("All interface threads started, running in background...");
    
    // 释放线程数组，因为线程已经在后台运行，不需要等待
    free(threads);
    
    return 0;
}

// 统一的队列处理函数
static void process_packet_queue(void) {
    while (packet_queue_size(&packet_queue) > 0 && running) {
        packet_data_t packet;
        if (packet_queue_dequeue(&packet_queue, &packet) == 0) {
            __sync_fetch_and_add(&total_packets_dequeued, 1);
            
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
        log_info("  %d: %s", i + 1, interfaces[i]);
    }
    
    // 初始化全局资源
    start_time = time(NULL);
    packet_queue_init(&packet_queue, PACKET_QUEUE_SIZE);
    flow_table_init();
    
    // 初始化线程池
    log_info("About to initialize thread pool with %d threads", worker_thread_count);
    if (thread_pool_init(worker_thread_count) != 0) {
        log_error("Failed to initialize thread pool\n");
        return 1;
    }
    log_info("Thread pool initialization successful");
    
    // 初始化会话管理器
    if (transport_session_manager_init() != 0) {
        log_error("Failed to initialize session manager\n");
        return 1;
    }
    
    log_info("Flow tracking and session manager initialized");
    
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
    
    // 添加实时统计显示循环（复用单接口模式的代码）
    uint64_t last_stats_time = 0;
    const uint64_t STATS_INTERVAL_MS = 1000;  // 每1秒输出一次统计
    
    while (running) {
        uint64_t current_time = get_current_time();
        
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
                // 转换为秒并计算速率
                double time_diff_sec = (double)time_diff / 1000000000.0;
                pps = (double)packets_diff / time_diff_sec;
                bps = (double)bytes_diff / time_diff_sec;
            }
            
            // 动态进度指示器
            static int progress_phase = 0;
            const char *progress_chars[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
            const char *progress = progress_chars[progress_phase % 10];
            progress_phase++;
            

            
            // 输出增强的统计信息（固定位置，不换行）
            uint64_t total_created, tcp_created, udp_created, reused;
            get_session_creation_stats(&total_created, &tcp_created, &udp_created, &reused);
            
            // 更新系统统计
            update_system_stats();
            
            // 获取当前时间戳（东八区）
            time_t now = time(NULL);
            time_t beijing_time = now + 8 * 3600; // 转换为东八区时间
            struct tm tm;
            gmtime_r(&beijing_time, &tm);
            char time_only[9];
            strftime(time_only, sizeof(time_only), "%H:%M:%S", &tm);
            
            print_stats_line(time_only, progress,
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
                            system_stats.memory_usage, "");
            
            // 更新上次统计值
            last_packets = total_packets_captured;
            last_bytes = total_bytes_captured;
            last_time = current_time;
            last_stats_time = current_time;
            
            // 定期清理不活跃的流（每1秒清理一次）
            static uint64_t last_cleanup_time = 0;
            if (current_time - last_cleanup_time >= 1000) { // 1秒（毫秒）
                if (running) {  // 只在程序运行时进行清理
                    cleanup_flows();
                    last_cleanup_time = current_time;
                }
            }
            
            // 紧急清理：当内存池使用率过高时立即清理
            static uint64_t last_emergency_cleanup = 0;
            if (current_time - last_emergency_cleanup >= 250) { // 每0.25秒检查一次（毫秒）
                if (running) {  // 只在程序运行时进行紧急清理
                    size_t total_nodes, free_nodes, used_nodes;
                    mempool_get_stats(&global_pool, &total_nodes, &free_nodes, &used_nodes);
                    
                    if (used_nodes > total_nodes * 0.2) { // 使用率超过20%就触发紧急清理
                        log_debug("Emergency cleanup triggered - memory usage: %.1f%%", 
                                 (double)used_nodes * 100.0 / total_nodes);
                        cleanup_flows();
                        last_emergency_cleanup = current_time;
                    }
                }
            }
            
            // 显示线程池状态（每10秒显示一次）
            static int thread_pool_display_count = 0;
            if (thread_pool_display_count % 10 == 0) {
                uint64_t tp_packets, tp_bytes;
                int tp_busy, tp_total;
                get_thread_pool_stats(&tp_packets, &tp_bytes, &tp_busy, &tp_total);
                printf("\n🔧 Thread Pool Status: %d/%d threads busy, processed %lu packets (%.2f MB)", 
                       tp_busy, tp_total, tp_packets, tp_bytes / (1024.0 * 1024.0));
            }
            thread_pool_display_count++;
        }
        
        // 短暂休眠，避免CPU占用过高
        usleep(10000); // 10ms
        
        // 多线程处理队列中的数据包
        process_packet_queue_mt();
    }
    
    // 主循环结束后的清理逻辑
    log_info("Main loop ended, performing cleanup...");
    
    // 等待工作线程处理完所有数据包
    log_info("Waiting for worker threads to process remaining packets...");
    uint64_t remaining_packets = packet_queue_size(&packet_queue);
    if (remaining_packets > 0) {
        log_info("Remaining packets in queue: %lu", remaining_packets);
        
        // 等待一段时间让工作线程处理剩余数据包
        int wait_count = 0;
        while (packet_queue_size(&packet_queue) > 0 && wait_count < 100) { // 最多等待10秒
            usleep(100000); // 100ms
            wait_count++;
            
            if (wait_count % 10 == 0) { // 每1秒输出一次状态
                uint64_t current_remaining = packet_queue_size(&packet_queue);
                log_info("Still waiting... remaining packets: %lu", current_remaining);
            }
        }
        
        uint64_t final_remaining = packet_queue_size(&packet_queue);
        if (final_remaining > 0) {
            log_warn("Worker threads could not process all packets, %lu packets remaining", final_remaining);
        } else {
            log_info("All packets processed by worker threads");
        }
    }
    
    // 执行完整的清理操作
    log_info("Performing complete cleanup...");
    cleanup();
    log_info("Cleanup completed");
    
    // 打印最终统计信息（包括CSV文件生成）
    
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
    
    // 初始化线程池
    log_info("About to initialize thread pool with %d threads (single interface mode)", worker_thread_count);
    if (thread_pool_init(worker_thread_count) != 0) {
        log_error("Failed to initialize thread pool\n");
        return 1;
    }
    log_info("Thread pool initialization successful (single interface mode)");
    
    // 初始化会话管理器
    if (transport_session_manager_init() != 0) {
        log_error("Failed to initialize session manager\n");
        return 1;
    }
    
    log_info("Flow tracking and session manager initialized");
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
    uint64_t last_process_time = 0;
    uint64_t current_time = 0;
    const uint64_t PROCESS_INTERVAL_MS = 50;  // 50ms处理间隔（优化：从300ms减少到50ms以减少丢包）
    const int MAX_BATCH_SIZE = 2000;  // 每次最多处理2000个包（优化：从500增加到2000以提高吞吐量）
    
    // 添加统计输出变量
    uint64_t last_stats_time = 0;
    const uint64_t STATS_INTERVAL_MS = 1000;  // 每1秒输出一次统计（毫秒）
    
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
        
        // 处理队列中的数据包 - 简化版本，只处理包不统计
        if ((current_time - last_process_time) >= PROCESS_INTERVAL_MS) {
            
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
            
            // 重置时间
            last_process_time = current_time;
            
            // 如果队列仍然很大，短暂让出CPU（优化：减少延迟）
            if (packet_queue_size(&packet_queue) > 5000) {
                usleep(100);  // 休眠0.1ms，让出CPU时间片（优化：从1ms减少到0.1ms）
            }
        }
        
        // 定期输出统计信息（固定位置更新）
        if (current_time - last_stats_time >= STATS_INTERVAL_MS) {
            // 清除当前行并回到行首，确保固定位置更新
            printf("\r\033[2K");
            
            // 获取eBPF捕获的包数
            uint64_t captured_packets = get_ebpf_captured_packets();
            uint64_t captured_bytes = get_ebpf_captured_bytes();
            
            // 调试输出（每10次更新显示一次）
            static int debug_count = 0;
            if (debug_count % 10 == 0) {
                log_debug("Stats Update - Packets: %lu, Bytes: %lu (%.2f MB)", 
                         captured_packets, captured_bytes, captured_bytes / (1024.0 * 1024.0));
            }
            debug_count++;
            
            // 计算捕获速率
            static uint64_t last_captured_packets = 0;
            static uint64_t last_captured_bytes = 0;
            static uint64_t last_time = 0;
            
            // 如果是第一次更新，初始化last_time
            if (last_time == 0) {
                last_time = current_time;
                last_captured_packets = captured_packets;
                last_captured_bytes = captured_bytes;
            }
            
            uint64_t packets_diff = captured_packets - last_captured_packets;
            uint64_t bytes_diff = captured_bytes - last_captured_bytes;
            uint64_t time_diff = current_time - last_time;
            
            double pps = 0.0, bps = 0.0;
            if (time_diff > 0) {
                // 转换为秒并计算速率（current_time已经是毫秒）
                double time_diff_sec = (double)time_diff / 1000.0;
                pps = (double)packets_diff / time_diff_sec;
                bps = (double)bytes_diff / time_diff_sec;
            }
            
            // 动态进度指示器
            static int progress_phase = 0;
            const char *progress_chars[] = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
            const char *progress = progress_chars[progress_phase % 10];
            progress_phase++;
            
            // 输出增强的统计信息（固定位置，不换行）
            uint64_t total_created, tcp_created, udp_created, reused;
            get_session_creation_stats(&total_created, &tcp_created, &udp_created, &reused);
            
            // 更新系统统计
            update_system_stats();
            
            // 获取当前时间戳（东八区）
            time_t now = time(NULL);
            time_t beijing_time = now + 8 * 3600; // 转换为东八区时间
            struct tm tm;
            gmtime_r(&beijing_time, &tm);
            char time_only[9];
            strftime(time_only, sizeof(time_only), "%H:%M:%S", &tm);
            
            print_stats_line(time_only, progress,
                            captured_packets, pps,
                            captured_bytes / (1024.0 * 1024.0), bps * 8 / 1000.0,
                            get_tcp_conversation_count(),
                            get_udp_conversation_count(),
                            get_total_conversation_count(),
                            count_active_flows(),
                            count_all_flows(),
                            total_created,
                            reused,
                            system_stats.cpu_usage,
                            system_stats.memory_usage, "                    ");
            
            // 显示线程池状态（每10秒显示一次）
            static int thread_pool_display_count = 0;
            if (thread_pool_display_count % 10 == 0) {
                uint64_t tp_packets, tp_bytes;
                int tp_busy, tp_total;
                get_thread_pool_stats(&tp_packets, &tp_bytes, &tp_busy, &tp_total);
                printf("\n🔧 Thread Pool Status: %d/%d threads busy, processed %lu packets (%.2f MB)", 
                       tp_busy, tp_total, tp_packets, tp_bytes / (1024.0 * 1024.0));
            }
            thread_pool_display_count++;
            
            // 更新上次统计值
            last_captured_packets = captured_packets;
            last_captured_bytes = captured_bytes;
            last_time = current_time;
            last_stats_time = current_time;
            
            // 定期清理不活跃的流（每1秒清理一次）
            static uint64_t last_cleanup_time = 0;
            if (current_time - last_cleanup_time >= 1000) { // 1秒（毫秒）
                if (running) {  // 只在程序运行时进行清理
                    cleanup_flows();
                    last_cleanup_time = current_time;
                }
            }
            
            // 紧急清理：当内存池使用率过高时立即清理
            static uint64_t last_emergency_cleanup = 0;
            if (current_time - last_emergency_cleanup >= 250) { // 每0.25秒检查一次（毫秒）
                if (running) {  // 只在程序运行时进行紧急清理
                    size_t total_nodes, free_nodes, used_nodes;
                    mempool_get_stats(&global_pool, &total_nodes, &free_nodes, &used_nodes);
                    
                    if (used_nodes > total_nodes * 0.2) { // 使用率超过20%就触发紧急清理
                        log_debug("Emergency cleanup triggered - memory usage: %.1f%%", 
                                 (double)used_nodes * 100.0 / total_nodes);
                        cleanup_flows();
                        last_emergency_cleanup = current_time;
                    }
                }
            }
        }
    }

    log_info("Exiting program...");
    
    // 在退出时添加换行，确保统计信息行完整显示
    printf("\n");
    
    // 等待工作线程处理完所有数据包
    log_info("Waiting for worker threads to process remaining packets...");
    uint64_t remaining_packets = packet_queue_size(&packet_queue);
    if (remaining_packets > 0) {
        log_info("Remaining packets in queue: %lu", remaining_packets);
        
        // 等待一段时间让工作线程处理剩余数据包
        int wait_count = 0;
        while (packet_queue_size(&packet_queue) > 0 && wait_count < 100) { // 最多等待10秒
            usleep(100000); // 100ms
            wait_count++;
            
            if (wait_count % 10 == 0) { // 每1秒输出一次状态
                uint64_t current_remaining = packet_queue_size(&packet_queue);
                log_info("Still waiting... remaining packets: %lu", current_remaining);
            }
        }
        
        uint64_t final_remaining = packet_queue_size(&packet_queue);
        if (final_remaining > 0) {
            log_warn("Worker threads could not process all packets, %lu packets remaining", final_remaining);
        } else {
            log_info("All packets processed by worker threads");
        }
    }
    
cleanup:
    // 打印最终统计信息（包括CSV文件生成）
    
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



// 实现print_final_stats函数 - 精简版本
void print_final_stats(void) {
    printf("\n================== Final Statistics ==================\n");
    
    // 获取会话创建统计
    uint64_t total_created, tcp_created, udp_created, reused;
    get_session_creation_stats(&total_created, &tcp_created, &udp_created, &reused);
    
    printf("Session Statistics:\n");
    printf("  Created Sessions: %lu\n", total_created);
    printf("  TCP Sessions: %lu\n", tcp_created);
    printf("  UDP Sessions: %lu\n", udp_created);
    printf("  Reused Sessions: %lu\n", reused);
    
    // 显示流统计信息
    int all_flow_count = count_all_flows();
    int active_flow_count = count_active_flows();
    
    printf("\nFlow Statistics:\n");
    printf("  Total Flows: %d\n", all_flow_count);
    printf("  Active Flows: %d\n", active_flow_count);
    printf("  TCP Conversations: %u\n", get_tcp_conversation_count());
    printf("  UDP Conversations: %u\n", get_udp_conversation_count());
    
    // 显示哈希性能统计
    uint64_t hash_collisions, hash_operations;
    get_hash_stats(&hash_collisions, &hash_operations);
    if (hash_operations > 0) {
        double collision_rate = (double)hash_collisions * 100.0 / hash_operations;
        double load_factor = (double)hash_operations / 1048576.0; // HASH_TABLE_SIZE
        printf("\nHash Performance:\n");
        printf("  Total Operations: %lu\n", hash_operations);
        printf("  Collisions: %lu\n", hash_collisions);
        printf("  Collision Rate: %.2f%%\n", collision_rate);
        printf("  Load Factor: %.2f%%\n", load_factor * 100.0);
        printf("  Hash Table Size: 1M buckets\n");
        printf("  Hash Algorithm: %s\n", get_hash_algorithm_name());
        
        // 调用详细分析
        analyze_hash_distribution();
    }
    
    // ================== CSV导出功能 ==================
    if (csv_file) {
        printf("\n================== CSV Export ==================\n");
        
        // 在导出前进行内存清理
        printf("Cleaning up memory...\n");
        printf("TCP sessions before cleanup: %u\n", get_tcp_conversation_count());
        cleanup_flows();
        printf("TCP sessions after cleanup: %u\n", get_tcp_conversation_count());
        
        // 导出综合流特征到CSV
        int exported_count = export_comprehensive_flow_features_to_csv(csv_file);
        if (exported_count >= 0) {
            printf("✅ Successfully exported %d session flow features to: %s\n", exported_count, csv_file);
        } else {
            printf("❌ Failed to export comprehensive flow features\n");
        }
        
        printf("TCP sessions after export: %u\n", get_tcp_conversation_count());
        printf("\n================== Export Complete ==================\n");
    }
    
    printf("================================================\n\n");
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
    printf("  -t, --hash-test             Test hash algorithm performance and distribution\n");
    printf("  -a, --hash-algo <0-4>       Set hash algorithm: 0=Original, 1=xxHash, 2=Simple XOR, 3=XOR Combine, 4=XOR Aggressive\n");
    printf("  -T, --threads <count>       Set number of worker threads (default: %d)\n", DEFAULT_WORKER_THREADS);
    printf("  -h, --help                  Show this help message\n");
}

// 启动时初始化时间基准
void init_time_base() {
    struct timespec realtime, monotonic;
    clock_gettime(CLOCK_REALTIME, &realtime);
    clock_gettime(CLOCK_MONOTONIC, &monotonic);
    boot_realtime = realtime;
    boot_monotonic_ns = (uint64_t)monotonic.tv_sec * 1000000000ULL + monotonic.tv_nsec;
}

/**
 * 检测CPU核心数并设置合适的线程数
 */
static int detect_optimal_thread_count(void) {
    int cpu_count = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu_count <= 0) {
        log_warn("Failed to detect CPU count, using default: %d", DEFAULT_WORKER_THREADS);
        return DEFAULT_WORKER_THREADS;
    }
    
    log_info("Detected %d CPU cores", cpu_count);
    
    // 对于2核设备，使用1个工作线程（避免过度竞争）
    if (cpu_count <= 2) {
        int optimal_threads = 1; // 2核设备使用1个线程
        log_info("Low core count detected, using %d worker thread (optimal for %d cores)", optimal_threads, cpu_count);
        return optimal_threads;
    }
    
    // 对于多核设备，使用核心数-1个线程（留一个给主线程）
    int optimal_threads = cpu_count - 1;
    if (optimal_threads > MAX_WORKER_THREADS) {
        optimal_threads = MAX_WORKER_THREADS;
    }
    
    log_info("Using %d worker threads (optimal for %d cores)", optimal_threads, cpu_count);
    return optimal_threads;
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

// 删除未使用的cleanup_expired_sessions函数

// 删除未使用的print_realtime_stats函数

int main(int argc, char **argv) {
    init_time_base();
    
    const char *ifname = "all";  // Default to monitor all interfaces
    const char *pcap_file = NULL;
    int c;
    int ret = 0;
    int monitor_mode = 0;  // 监控模式标志
    
    // 自动检测CPU核心数并设置默认线程数
    worker_thread_count = detect_optimal_thread_count();
    log_info("Worker thread count set to: %d", worker_thread_count);
    
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
    // atexit(cleanup);  // 注释掉，改为手动调用
    
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
        {"hash-test",     no_argument,       0, 't'},
        {"hash-algo",     required_argument, 0, 'a'},
        {"threads",       required_argument, 0, 'T'},
        {"help",          no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((c = getopt_long(argc, argv, "i:r:d:s:p:c:o:l:w:v:qmt:a:T:h", long_options, NULL)) != -1) {
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
            case 't':
                hash_test_mode = 1;
                printf("Hash test mode enabled\n");
                break;
            case 'a':
                {
                    int algo = atoi(optarg);
                    if (algo < 0 || algo > 4) {
                        fprintf(stderr, "Hash algorithm must be 0-4 (0:Original, 1:xxHash, 2:Simple XOR, 3:XOR Combine, 4:XOR Aggressive)\n");
                        return 1;
                    }
                    set_hash_algorithm((hash_algorithm_t)algo);
                    set_hash_algorithm((hash_algorithm_t)algo);
                    printf("Hash algorithm set to %d (%s)\n", algo, get_hash_algorithm_name());
                }
                break;
            case 'T':
                worker_thread_count = atoi(optarg);
                if (worker_thread_count <= 0 || worker_thread_count > MAX_WORKER_THREADS) {
                    log_error("Invalid thread count: %d (must be 1-%d)", worker_thread_count, MAX_WORKER_THREADS);
                    return 1;
                }
                printf("Setting worker thread count to %d\n", worker_thread_count);
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

    if (hash_test_mode) {
        // 哈希算法测试模式
        printf("Starting hash algorithm test mode...\n");
        srand(time(NULL));
        test_hash_algorithms();
        return 0;
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
        log_info("Starting PCAP file processing mode");
        ret = process_pcap_file(pcap_file);
    } else {
        // Live capture mode
        log_info("Starting live capture mode");
        ret = run_live_capture(ifname);
    }

    log_info("Main processing completed, getting thread pool stats...");
    
    // 检查线程池状态
    log_info("Thread pool status check:");
    log_info("  - thread_pool_initialized: %d", thread_pool_initialized);
    log_info("  - g_thread_pool.thread_count: %d", g_thread_pool.thread_count);
    log_info("  - g_thread_pool.shutdown: %d", g_thread_pool.shutdown);
    log_info("  - packet_queue_size: %lu", packet_queue_size(&packet_queue));
    
    // 手动调用cleanup，而不是依赖atexit
    log_info("Manually calling cleanup...");
    cleanup();

    // 打印最终消息
    //printf("\n程序结束\n");

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
    
    // 创建eBPF统计窗口
    WINDOW *ebpf_win = NULL;
    int show_ebpf_stats = 0;  // 控制是否显示eBPF统计窗口
    
    while (monitor_running) {
        // 更新系统统计
        update_system_stats();
        
        // 更新UI
        if (show_ebpf_stats) {
            // 显示eBPF统计窗口
            if (!ebpf_win) {
                ebpf_win = newwin(LINES - 2, COLS, 1, 0);
                box(ebpf_win, 0, 0);
            }
            draw_ebpf_stats_window(ebpf_win);
        } else {
            // 显示正常的统计窗口
            update_stats_window(win);
        }
        
        // 检查按键
        int ch = wgetch(show_ebpf_stats ? ebpf_win : win);
        if (ch == 'q' || ch == 'Q') {
            log_info("User requested exit from monitor");
            monitor_running = 0;
            break;
        } else if (ch == 'e' || ch == 'E') {
            // 切换eBPF统计显示
            show_ebpf_stats = !show_ebpf_stats;
            if (show_ebpf_stats) {
                log_info("Switching to eBPF statistics view");
            } else {
                log_info("Switching to normal statistics view");
            }
        } else if (ch == 'h' || ch == 'H') {
            // 显示帮助信息
            printf("\n按键帮助:\n");
            printf("  Q/q - 退出程序\n");
            printf("  E/e - 切换eBPF统计显示\n");
            printf("  H/h - 显示此帮助信息\n");
        }
        
        // 短暂休眠
        usleep(500000); // 0.5秒
        
        // 多线程处理队列中的数据包
        process_packet_queue_mt();
    }

    /* 8. Wait for capture thread to complete */
    log_info("Waiting for capture thread to complete...");
    pthread_join(capture_thread, NULL);

cleanup:
    if (ebpf_win) {
        delwin(ebpf_win);
        ebpf_win = NULL;
    }
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

// =================== eBPF统计函数 ===================

/**
 * 获取eBPF捕获的包数统计
 */
uint64_t get_ebpf_captured_packets() {
    return total_packets_captured;
}

/**
 * 获取eBPF捕获的字节数统计
 */
uint64_t get_ebpf_captured_bytes() {
    return total_bytes_captured;
}

/**
 * 获取eBPF处理的包数统计
 */
uint64_t get_ebpf_processed_packets() {
    return total_packets_processed;
}

/**
 * 获取eBPF处理的字节数统计
 */
uint64_t get_ebpf_processed_bytes() {
    return total_bytes_processed;
}

/**
 * 获取eBPF统计信息
 */
void get_ebpf_stats(uint64_t *captured_packets, uint64_t *captured_bytes, 
                   uint64_t *processed_packets, uint64_t *processed_bytes) {
    if (captured_packets) *captured_packets = total_packets_captured;
    if (captured_bytes) *captured_bytes = total_bytes_captured;
    if (processed_packets) *processed_packets = total_packets_processed;
    if (processed_bytes) *processed_bytes = total_bytes_processed;
}

/**
 * 打印eBPF统计信息
 */
void print_ebpf_stats(void) {
    printf("\n================== eBPF Statistics ==================\n");
    
    // 获取eBPF统计信息
    uint64_t captured_packets = get_ebpf_captured_packets();
    uint64_t captured_bytes = get_ebpf_captured_bytes();
    uint64_t processed_packets = get_ebpf_processed_packets();
    uint64_t processed_bytes = get_ebpf_processed_bytes();
    
    printf("eBPF Capture Statistics:\n");
    printf("  Captured Packets: %lu\n", captured_packets);
    printf("  Captured Bytes: %lu (%.2f MB)\n", captured_bytes, 
           captured_bytes / (1024.0 * 1024.0));
    
    printf("\nProcessing Statistics:\n");
    printf("  Processed Packets: %lu\n", processed_packets);
    printf("  Processed Bytes: %lu (%.2f MB)\n", processed_bytes, 
           processed_bytes / (1024.0 * 1024.0));
    
    // 计算处理效率
    double packet_processing_ratio = 0.0;
    double byte_processing_ratio = 0.0;
    
    if (captured_packets > 0) {
        packet_processing_ratio = (double)processed_packets / captured_packets * 100.0;
    }
    if (captured_bytes > 0) {
        byte_processing_ratio = (double)processed_bytes / captured_bytes * 100.0;
    }
    
    printf("\nProcessing Efficiency:\n");
    printf("  Packet Processing Rate: %.2f%%\n", packet_processing_ratio);
    printf("  Byte Processing Rate: %.2f%%\n", byte_processing_ratio);
    
    // 状态评估
    printf("\nStatus Assessment:\n");
    if (packet_processing_ratio < 95.0) {
        printf("  ⚠️  Warning: Low packet processing efficiency\n");
    } else {
        printf("  ✅ Good: Packet processing efficiency is normal\n");
    }
    
    if (byte_processing_ratio < 95.0) {
        printf("  ⚠️  Warning: Low byte processing efficiency\n");
    } else {
        printf("  ✅ Good: Byte processing efficiency is normal\n");
    }
    
    printf("\nNote: These statistics show the data captured by eBPF program\n");
    printf("and the actual processing efficiency in the user space.\n");
    printf("================== eBPF Statistics End ==================\n\n");
}



// 分析包数不匹配的原因
void analyze_packet_count_mismatch(void) {
    printf("\n================== 包数不匹配分析 ==================\n");
    
    // 获取各种统计
    uint64_t captured_packets = get_ebpf_captured_packets();
    uint64_t processed_packets = get_ebpf_processed_packets();
    uint64_t queue_size = packet_queue_size(&packet_queue);
    
    // 获取会话统计
    uint64_t total_created, tcp_created, udp_created, reused;
    get_session_creation_stats(&total_created, &tcp_created, &udp_created, &reused);
    
    // 获取流统计
    int active_flows = count_active_flows();
    int total_flows = count_all_flows();
    
    printf("包数统计对比:\n");
    printf("  eBPF捕获包数: %lu\n", captured_packets);
    printf("  实际处理包数: %lu\n", processed_packets);
    printf("  当前队列大小: %lu\n", queue_size);
    
    // 详细统计
    printf("\n详细统计:\n");
    printf("  成功入队包数: %lu\n", total_packets_queued);
    printf("  成功出队包数: %lu\n", total_packets_dequeued);
    printf("  队列满丢弃包数: %lu\n", total_packets_dropped);
    printf("  无效包数: %lu\n", total_packets_invalid);
    
    if (captured_packets > processed_packets) {
        uint64_t diff = captured_packets - processed_packets;
        double loss_rate = (double)diff / captured_packets * 100.0;
        printf("  ⚠️  包数差异: %lu (%.2f%%)\n", diff, loss_rate);
        
        printf("\n可能的原因分析:\n");
        
        // 检查队列是否满
        if (queue_size > 0) {
            printf("  1. 队列中还有 %lu 个包未处理\n", queue_size);
        }
        
        // 检查处理效率
        if (loss_rate > 5.0) {
            printf("  2. 处理效率较低 (%.2f%% 丢包率)\n", loss_rate);
        }
        
        // 检查会话创建
        printf("  3. 会话统计:\n");
        printf("     - 总会话创建数: %lu\n", total_created);
        printf("     - TCP会话数: %lu\n", tcp_created);
        printf("     - UDP会话数: %lu\n", udp_created);
        printf("     - 会话重用数: %lu\n", reused);
        
        // 检查流统计
        printf("  4. 流统计:\n");
        printf("     - 活跃流数: %d\n", active_flows);
        printf("     - 总流数: %d\n", total_flows);
        
    } else if (captured_packets < processed_packets) {
        uint64_t diff = processed_packets - captured_packets;
        printf("  ⚠️  处理包数多于捕获包数: %lu\n", diff);
        printf("  可能原因: 重复处理或统计错误\n");
    } else {
        printf("  ✅ 包数匹配\n");
    }
    
    printf("\n建议:\n");
    printf("  1. 检查网络接口统计: ethtool -S <interface>\n");
    printf("  2. 检查内核网络统计: cat /proc/net/softnet_stat\n");
    printf("  3. 检查XDP程序统计: bpftool prog show name xdp_packet_capture\n");
    printf("  4. 调整队列大小和处理间隔以减少丢包\n");
    
    printf("================== 分析结束 ==================\n\n");
}

// 生成随机五元组
static void generate_random_flow_key(struct flow_key *key) {
    key->src_ip = rand() % 0xFFFFFFFF;
    key->dst_ip = rand() % 0xFFFFFFFF;
    key->src_port = rand() % 65536;
    key->dst_port = rand() % 65536;
    key->protocol = rand() % 256;
}

// 测试哈希算法性能
static void test_hash_algorithms(void) {
    struct flow_key key;
    clock_t start, end;
    double time_used;
    
    printf("\n=== 哈希算法性能测试 (%d 次) ===\n", hash_test_iterations);
    printf("测试算法: Original, xxHash, Simple XOR, XOR Combine, XOR Aggressive\n\n");
    
    // 测试原始哈希
    set_hash_algorithm(HASH_ALGO_ORIGINAL);
    start = clock();
    for (int i = 0; i < hash_test_iterations; i++) {
        generate_random_flow_key(&key);
        hash_flow_key(&key);
    }
    end = clock();
    time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Original: %.6f 秒 (%.0f ops/s)\n", time_used, hash_test_iterations / time_used);
    
    // 测试xxHash
    set_hash_algorithm(HASH_ALGO_XXHASH);
    start = clock();
    for (int i = 0; i < hash_test_iterations; i++) {
        generate_random_flow_key(&key);
        hash_flow_key(&key);
    }
    end = clock();
    time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("xxHash: %.6f 秒 (%.0f ops/s)\n", time_used, hash_test_iterations / time_used);
    
    // 测试简单异或
    set_hash_algorithm(HASH_ALGO_SIMPLE);
    start = clock();
    for (int i = 0; i < hash_test_iterations; i++) {
        generate_random_flow_key(&key);
        hash_flow_key(&key);
    }
    end = clock();
    time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("Simple XOR: %.6f 秒 (%.0f ops/s)\n", time_used, hash_test_iterations / time_used);
    
    // 测试异或组合
    set_hash_algorithm(HASH_ALGO_XOR_COMBINE);
    start = clock();
    for (int i = 0; i < hash_test_iterations; i++) {
        generate_random_flow_key(&key);
        hash_flow_key(&key);
    }
    end = clock();
    time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("XOR Combine: %.6f 秒 (%.0f ops/s)\n", time_used, hash_test_iterations / time_used);
    
    // 测试激进异或
    set_hash_algorithm(HASH_ALGO_XOR_AGGRESSIVE);
    start = clock();
    for (int i = 0; i < hash_test_iterations; i++) {
        generate_random_flow_key(&key);
        hash_flow_key(&key);
    }
    end = clock();
    time_used = ((double)(end - start)) / CLOCKS_PER_SEC;
    printf("XOR Aggressive: %.6f 秒 (%.0f ops/s)\n", time_used, hash_test_iterations / time_used);
    
    // 测试哈希分布
    printf("\n=== 哈希分布测试 (100,000 次) ===\n");
    int buckets[1000] = {0};
    int num_dist_tests = 100000;
    
    // 测试原始哈希分布
    set_hash_algorithm(HASH_ALGO_ORIGINAL);
    memset(buckets, 0, sizeof(buckets));
    for (int i = 0; i < num_dist_tests; i++) {
        generate_random_flow_key(&key);
        uint32_t hash = hash_flow_key(&key);
        buckets[hash % 1000]++;
    }
    
    int min_bucket = buckets[0], max_bucket = buckets[0];
    for (int i = 1; i < 1000; i++) {
        if (buckets[i] < min_bucket) min_bucket = buckets[i];
        if (buckets[i] > max_bucket) max_bucket = buckets[i];
    }
    printf("Original: 最小桶=%d, 最大桶=%d, 分布比=%.2f\n", 
           min_bucket, max_bucket, (double)max_bucket / min_bucket);
    
    // 测试xxHash分布
    set_hash_algorithm(HASH_ALGO_XXHASH);
    memset(buckets, 0, sizeof(buckets));
    for (int i = 0; i < num_dist_tests; i++) {
        generate_random_flow_key(&key);
        uint32_t hash = hash_flow_key(&key);
        buckets[hash % 1000]++;
    }
    
    min_bucket = max_bucket = buckets[0];
    for (int i = 1; i < 1000; i++) {
        if (buckets[i] < min_bucket) min_bucket = buckets[i];
        if (buckets[i] > max_bucket) max_bucket = buckets[i];
    }
    printf("xxHash: 最小桶=%d, 最大桶=%d, 分布比=%.2f\n", 
           min_bucket, max_bucket, (double)max_bucket / min_bucket);
    
    // 测试异或组合分布
    set_hash_algorithm(HASH_ALGO_XOR_COMBINE);
    memset(buckets, 0, sizeof(buckets));
    for (int i = 0; i < num_dist_tests; i++) {
        generate_random_flow_key(&key);
        uint32_t hash = hash_flow_key(&key);
        buckets[hash % 1000]++;
    }
    
    min_bucket = max_bucket = buckets[0];
    for (int i = 1; i < 1000; i++) {
        if (buckets[i] < min_bucket) min_bucket = buckets[i];
        if (buckets[i] > max_bucket) max_bucket = buckets[i];
    }
    printf("XOR Combine: 最小桶=%d, 最大桶=%d, 分布比=%.2f\n", 
           min_bucket, max_bucket, (double)max_bucket / min_bucket);
    
    printf("\n=== 哈希测试完成 ===\n");
    printf("提示: 使用 --hash-test 参数运行此测试\n");
    printf("使用 --hash-algo <0-4> 设置哈希算法:\n");
    printf("  0: Original, 1: xxHash, 2: Simple XOR, 3: XOR Combine, 4: XOR Aggressive\n\n");
}

// =================== 线程池实现 ===================

/**
 * 初始化线程池
 */
static int thread_pool_init(int thread_count) {
    log_info("Initializing thread pool with %d threads...", thread_count);
    
    if (thread_count <= 0 || thread_count > MAX_WORKER_THREADS) {
        log_error("Invalid thread count: %d (must be 1-%d)", thread_count, MAX_WORKER_THREADS);
        return -1;
    }
    
    // 初始化线程池结构
    memset(&g_thread_pool, 0, sizeof(g_thread_pool));
    g_thread_pool.thread_count = thread_count;
    g_thread_pool.shutdown = 0;
    
    log_info("Thread pool structure initialized");
    
    // 初始化互斥锁和条件变量
    if (pthread_mutex_init(&g_thread_pool.stats_mutex, NULL) != 0) {
        log_error("Failed to initialize stats mutex");
        return -1;
    }
    
    if (pthread_mutex_init(&g_thread_pool.work_mutex, NULL) != 0) {
        log_error("Failed to initialize work mutex");
        pthread_mutex_destroy(&g_thread_pool.stats_mutex);
        return -1;
    }
    
    if (pthread_cond_init(&g_thread_pool.work_cond, NULL) != 0) {
        log_error("Failed to initialize work condition variable");
        pthread_mutex_destroy(&g_thread_pool.stats_mutex);
        pthread_mutex_destroy(&g_thread_pool.work_mutex);
        return -1;
    }
    
    log_info("Mutexes and condition variables initialized");
    
    // 创建工作线程
    for (int i = 0; i < thread_count; i++) {
        worker_thread_t *worker = &g_thread_pool.workers[i];
        worker->thread_id = i;
        worker->running = 1;
        worker->busy = 0;
        worker->packets_processed = 0;
        worker->bytes_processed = 0;
        clock_gettime(CLOCK_MONOTONIC, &worker->last_activity);
        
        // 设置线程属性
        pthread_attr_t attr;
        pthread_attr_init(&attr);
        pthread_attr_setstacksize(&attr, WORKER_THREAD_STACK_SIZE);
        pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_JOINABLE);
        
        // 创建线程
        if (pthread_create(&worker->thread, &attr, worker_thread_func, worker) != 0) {
            log_error("Failed to create worker thread %d", i);
            pthread_attr_destroy(&attr);
            thread_pool_destroy();
            return -1;
        }
        
        pthread_attr_destroy(&attr);
        log_info("Created worker thread %d", i);
    }
    
    log_info("Thread pool initialized with %d worker threads", thread_count);
    thread_pool_initialized = 1;  // 设置初始化标志
    return 0;
}

/**
 * 销毁线程池
 */
static void thread_pool_destroy(void) {
    if (g_thread_pool.thread_count == 0) {
        return; // 已经销毁
    }
    
    log_info("Shutting down thread pool...");
    
    // 设置关闭标志
    g_thread_pool.shutdown = 1;
    
    // 唤醒所有等待的线程
    pthread_cond_broadcast(&g_thread_pool.work_cond);
    
    // 等待所有线程结束
    for (int i = 0; i < g_thread_pool.thread_count; i++) {
        worker_thread_t *worker = &g_thread_pool.workers[i];
        if (worker->running) {
            pthread_join(worker->thread, NULL);
            log_info("Worker thread %d joined", i);
        }
    }
    
    // 清理资源
    pthread_mutex_destroy(&g_thread_pool.stats_mutex);
    pthread_mutex_destroy(&g_thread_pool.work_mutex);
    pthread_cond_destroy(&g_thread_pool.work_cond);
    
    memset(&g_thread_pool, 0, sizeof(g_thread_pool));
    log_info("Thread pool destroyed");
}

/**
 * 工作线程函数
 */
static void *worker_thread_func(void *arg) {
    worker_thread_t *worker = (worker_thread_t *)arg;
    int thread_id = worker->thread_id;
    
    log_info("Worker thread %d started", thread_id);
    
    // 设置线程名称（如果支持）
    char thread_name[16];
    snprintf(thread_name, sizeof(thread_name), "worker_%d", thread_id);
    pthread_setname_np(worker->thread, thread_name);
    
    while (worker->running && !g_thread_pool.shutdown) {
        packet_data_t packet;
        int processed = 0;
        
        // 处理队列中的数据包
        uint64_t queue_size = packet_queue_size(&packet_queue);
        if (queue_size > 0) {
            log_debug("Worker %d: queue size = %lu", thread_id, queue_size);
        }
        
        while (packet_queue_size(&packet_queue) > 0 && worker->running && !g_thread_pool.shutdown) {
            if (packet_queue_dequeue(&packet_queue, &packet) == 0) {
                worker->busy = 1;
                clock_gettime(CLOCK_MONOTONIC, &worker->last_activity);
                
                // 处理数据包
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
                
                // 更新统计信息
                worker->packets_processed++;
                worker->bytes_processed += packet.ip_header.tot_len;
                processed++;
                
                // 原子更新全局统计
                __sync_fetch_and_add(&total_packets_processed, 1);
                __sync_fetch_and_add(&total_packets_dequeued, 1);
                __sync_fetch_and_add(&total_bytes_processed, packet.ip_header.tot_len);
            }
        }
        
        // 如果没有处理任何包，短暂休眠避免空转
        if (processed == 0) {
            worker->busy = 0;
            usleep(1000); // 1ms
        }
    }
    
    log_info("Worker thread %d finished (processed %lu packets)", 
             thread_id, worker->packets_processed);
    
    return NULL;
}

/**
 * 多线程处理数据包队列
 */
static void process_packet_queue_mt(void) {
    // 线程池会自动处理队列中的数据包
    // 这里只需要检查线程池状态
    if (g_thread_pool.shutdown) {
        return;
    }
    
    // 可以在这里添加一些监控逻辑
    static uint64_t last_check_time = 0;
    uint64_t current_time = get_current_time();
    
    // 每100ms检查一次线程池状态
    if (current_time - last_check_time >= 100000000) { // 100ms in nanoseconds
        update_thread_pool_stats();
        last_check_time = current_time;
    }
}

/**
 * 更新线程池统计信息
 */
static void update_thread_pool_stats(void) {
    pthread_mutex_lock(&g_thread_pool.stats_mutex);
    
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    int busy_threads = 0;
    
    for (int i = 0; i < g_thread_pool.thread_count; i++) {
        worker_thread_t *worker = &g_thread_pool.workers[i];
        total_packets += worker->packets_processed;
        total_bytes += worker->bytes_processed;
        if (worker->busy) {
            busy_threads++;
        }
    }
    
    // 输出线程池状态（仅在调试模式下）
    static int debug_count = 0;
    if (debug_count % 100 == 0) { // 每10秒输出一次
        log_debug("Thread pool status: %d/%d threads busy, total packets: %lu, total bytes: %lu MB", 
                 busy_threads, g_thread_pool.thread_count, total_packets, 
                 total_bytes / (1024 * 1024));
    }
    debug_count++;
    
    pthread_mutex_unlock(&g_thread_pool.stats_mutex);
}

/**
 * 获取线程池统计信息
 */
void get_thread_pool_stats(uint64_t *total_packets, uint64_t *total_bytes, 
                          int *busy_threads, int *total_threads) {
    log_info("Getting thread pool stats, thread_count: %d, initialized: %d, shutdown: %d", 
              g_thread_pool.thread_count, thread_pool_initialized, g_thread_pool.shutdown);
    
    if (!thread_pool_initialized) {
        log_warn("Thread pool not initialized!");
        if (total_packets) *total_packets = 0;
        if (total_bytes) *total_bytes = 0;
        if (busy_threads) *busy_threads = 0;
        if (total_threads) *total_threads = 0;
        return;
    }
    
    pthread_mutex_lock(&g_thread_pool.stats_mutex);
    
    uint64_t packets = 0;
    uint64_t bytes = 0;
    int busy = 0;
    
    for (int i = 0; i < g_thread_pool.thread_count; i++) {
        worker_thread_t *worker = &g_thread_pool.workers[i];
        packets += worker->packets_processed;
        bytes += worker->bytes_processed;
        if (worker->busy) {
            busy++;
        }
        log_info("Worker %d: packets=%lu, bytes=%lu, busy=%d, running=%d", 
                 i, worker->packets_processed, worker->bytes_processed, worker->busy, worker->running);
    }
    
    if (total_packets) *total_packets = packets;
    if (total_bytes) *total_bytes = bytes;
    if (busy_threads) *busy_threads = busy;
    if (total_threads) *total_threads = g_thread_pool.thread_count;
    
    log_info("Thread pool stats: packets=%lu, bytes=%lu, busy=%d, total=%d", 
              packets, bytes, busy, g_thread_pool.thread_count);
    
    pthread_mutex_unlock(&g_thread_pool.stats_mutex);
}

