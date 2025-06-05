#define _GNU_SOURCE /* For CLOCK_MONOTONIC */
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
#include <pthread.h>  // 添加pthread库支持

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

// 增加预取相关宏定义
#define PREFETCH(addr) __builtin_prefetch(addr)
#define PREFETCH_RW(addr) __builtin_prefetch(addr, 1, 1)
#define PREFETCH_LOCALITY_HIGH 3
#define PREFETCH_LOCALITY_MED 2
#define PREFETCH_LOCALITY_LOW 1
#define PREFETCH_LOCALITY_NONE 0

// 多线程相关配置
#define DEFAULT_NUM_THREADS 4    // 默认工作线程数
#define MAX_NUM_THREADS 32       // 最大工作线程数
#define PACKET_QUEUE_SIZE 10000  // 数据包队列大小

// ANSI转义序列用于终端控制
const char *ANSI_CLEAR_SCREEN = "\033[2J\033[H";  // 清屏并将光标移到开头
const char *ANSI_CLEAR_LINE = "\033[2K\r";      // 清除当前行并回到行首
const char *ANSI_CURSOR_UP = "\033[1A";        // 光标上移一行
const char *ANSI_SAVE_CURSOR = "\033[s";         // 保存光标位置
const char *ANSI_RESTORE_CURSOR = "\033[u";         // 恢复光标位置
const char *ANSI_HIDE_CURSOR = "\033[?25l";      // 隐藏光标
const char *ANSI_SHOW_CURSOR = "\033[?25h";      // 显示光标

// System statistics structure
typedef struct {
    double cpu_usage;           // CPU使用率 (%)
    double memory_usage;        // 内存使用率 (%)
    uint64_t packets_processed; // 已处理的数据包数量
    double processing_time;     // 处理时间 (秒)
    uint64_t packets_per_second; // 每秒处理的数据包数
} system_stats_t;

// Global system statistics
static system_stats_t system_stats = {0};
static clock_t start_cpu_time;
static clock_t start_wall_time;
static struct timespec program_start_time;

// 全局变量以跟踪终端模式
int in_place_updates = 1;  // 默认启用原位更新
int first_stats_print = 1; // 第一次打印标志

// 运行状态，设为extern以便其他文件可访问
volatile int running = 1;

// 函数前向声明
void print_final_stats(void);
static void stop_worker_threads(void);

// flow_table_initialized是flow.c中的变量，我们在这里声明为外部变量
extern int flow_table_initialized;
extern int count_active_flows(); // 从flow.c导入流计数函数

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
static int num_threads = DEFAULT_NUM_THREADS; // 工作线程数量
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
        fprintf(stderr, "Failed to allocate packet queue\n");
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
            fprintf(stderr, "Warning: Packet queue full, dropping packet (warning %d/10)\n", ++drop_warning_count);
        }
        return -1;
    }
    
    return -1;
}

// 无锁出队操作
static int packet_queue_dequeue(lockfree_queue_t *queue, packet_data_t *packet) {
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
    uint64_t tail = queue->tail;
    uint64_t head = queue->head;
    return tail - head;
}

// 线程相关
static pthread_t *worker_threads = NULL;
static pthread_t stats_thread;       // 统计线程
static pthread_mutex_t stats_mutex = PTHREAD_MUTEX_INITIALIZER; // 统计互斥锁
static pthread_mutex_t flow_table_mutex = PTHREAD_MUTEX_INITIALIZER; // 流表互斥锁

// 包处理计数器
static volatile uint64_t total_packets_processed = 0;
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

// 线程安全版本的流表访问函数
static void thread_safe_process_packet(const struct iphdr *ip, uint16_t src_port, uint16_t dst_port, 
                                     uint32_t tcp_seq, uint8_t tcp_flags, uint64_t timestamp) {
    pthread_mutex_lock(&flow_table_mutex);
    
    // 创建传输层头部信息用于传递给process_packet
    if (ip->protocol == IPPROTO_TCP) {
        // 对于TCP，我们需要传递序列号和标志位
        struct tcphdr tcp_info = {0};
        tcp_info.source = htons(src_port);
        tcp_info.dest = htons(dst_port);
        tcp_info.seq = htonl(tcp_seq);
        *((uint8_t*)&tcp_info + 13) = tcp_flags;  // 设置TCP标志位
        
        process_packet(ip, &tcp_info, timestamp);
    } else if (ip->protocol == IPPROTO_UDP) {
        // 对于UDP，只需要端口信息
        struct udphdr udp_info = {0};
        udp_info.source = htons(src_port);
        udp_info.dest = htons(dst_port);
        
        process_packet(ip, &udp_info, timestamp);
    }
    
    pthread_mutex_unlock(&flow_table_mutex);
    
    // 更新统计信息
    __sync_fetch_and_add(&total_packets_processed, 1);
    __sync_fetch_and_add(&total_bytes_processed, ntohs(ip->tot_len));
}

// 工作线程函数，从队列中获取数据包并处理
static void *worker_thread_func(void *arg) {
    packet_data_t packet;
    int idle_count = 0;
    const int max_idle = 1000; // 最大空闲次数
    
    while (running) {
        // 从队列中获取数据包
        int result = packet_queue_dequeue(&packet_queue, &packet);
        
        if (result == 0) {
            // 成功获取数据包，重置空闲计数
            idle_count = 0;
            
            // 预取数据包内容以提高性能
            PREFETCH(&packet.ip_header);
            PREFETCH(&packet.transport_header);
            
            // 处理数据包
            if (packet.ip_header.protocol == IPPROTO_TCP) {
                // 从存储的TCP头部数据中提取标志位
                struct tcphdr *tcp_header = (struct tcphdr *)packet.transport_header.tcp.flags_byte;
                uint8_t tcp_flags = *((uint8_t*)tcp_header + 13);  // TCP标志位在第13字节
                uint32_t tcp_seq = packet.transport_header.tcp.seq;
                
                thread_safe_process_packet(&packet.ip_header, 
                                         packet.transport_header.tcp.source,
                                         packet.transport_header.tcp.dest,
                                         tcp_seq, tcp_flags, packet.timestamp);
            } else if (packet.ip_header.protocol == IPPROTO_UDP) {
                thread_safe_process_packet(&packet.ip_header,
                                         packet.transport_header.udp.source,
                                         packet.transport_header.udp.dest,
                                         0, 0, packet.timestamp);  // UDP没有序列号和标志位
            }
        } else {
            // 队列为空或出错，增加空闲计数
            idle_count++;
            
            // 如果空闲时间过长，让出CPU
            if (idle_count > max_idle) {
                usleep(100); // 100微秒
                idle_count = 0;
            } else {
                // 短暂yield
                __asm__ __volatile__("pause" ::: "memory");
            }
            
            // 检查是否应该退出
            if (!running) break;
        }
    }
    
    return NULL;
}

// 统计线程函数，定期打印流统计信息
static void *stats_thread_func(void *arg) {
    time_t last_stats_time = 0;
    time_t last_cleanup_time = 0;
    
    while (running) {
        // 睡眠一小段时间检查是否需要打印统计信息
        usleep(250000); // 250ms
        
        time_t current_time = time(NULL);
        
        // 检查是否需要打印统计信息
        if (current_time - last_stats_time >= stats_interval) {
            pthread_mutex_lock(&stats_mutex);
            print_flow_stats();
            last_stats_time = current_time;
            pthread_mutex_unlock(&stats_mutex);
        }
        
        // 检查是否需要清理过期流
        if (current_time - last_cleanup_time >= cleanup_interval) {
            pthread_mutex_lock(&flow_table_mutex);
            cleanup_flows();
            last_cleanup_time = current_time;
            pthread_mutex_unlock(&flow_table_mutex);
        }
        
        // 检查是否超过指定运行时间
        if (duration > 0 && current_time - start_time >= duration) {
            printf("Reached specified duration of %d seconds. Exiting...\n", duration);
            running = 0;
            break;
        }
    }
    
    return NULL;
}

static void cleanup(void) {
    if (cleanup_done) {
        return;
    }
    cleanup_done = 1;
    
    // 停止worker线程
    if (worker_threads != NULL) {
        stop_worker_threads();
        free(worker_threads);
        worker_threads = NULL;
    }
    
    // 销毁数据包队列
    packet_queue_destroy(&packet_queue);
    
    // Cleanup flow table
    if (flow_table_initialized) {
        print_final_stats();
        flow_table_destroy();
    }
    
    // Close lock file
    if (lock_fd != -1) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        unlink(LOCK_FILE);
        lock_fd = -1;
    }
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

// Get current CPU usage
static double get_cpu_usage(void) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        return 0.0;
    }
    
    // 计算用户态和内核态CPU时间
    double user_time = usage.ru_utime.tv_sec + usage.ru_utime.tv_usec / 1000000.0;
    double sys_time = usage.ru_stime.tv_sec + usage.ru_stime.tv_usec / 1000000.0;
    double total_cpu_time = user_time + sys_time;
    
    // 计算程序运行的总时间
    struct timespec current_time;
    clock_gettime(CLOCK_REALTIME, &current_time);
    double elapsed_time = (current_time.tv_sec - program_start_time.tv_sec) + 
                         (current_time.tv_nsec - program_start_time.tv_nsec) / 1000000000.0;
    
    if (elapsed_time > 0) {
        return (total_cpu_time / elapsed_time) * 100.0;
    }
    return 0.0;
}

// Get current memory usage
static double get_memory_usage(void) {
    struct rusage usage;
    if (getrusage(RUSAGE_SELF, &usage) != 0) {
        return 0.0;
    }
    
    // ru_maxrss在Linux上以KB为单位
    long memory_kb = usage.ru_maxrss;
    
    // 获取系统总内存
    struct sysinfo si;
    if (sysinfo(&si) != 0) {
        return 0.0;
    }
    
    // 转换为MB并计算百分比
    double memory_mb = memory_kb / 1024.0;
    double total_memory_mb = si.totalram / (1024.0 * 1024.0);
    
    if (total_memory_mb > 0) {
        return (memory_mb / total_memory_mb) * 100.0;
    }
    return 0.0;
}

// Update system statistics
static void update_system_stats(void) {
    system_stats.cpu_usage = get_cpu_usage();
    system_stats.memory_usage = get_memory_usage();
    system_stats.packets_processed = total_packets_processed;
    
    // 计算处理时间
    struct timespec current_time;
    clock_gettime(CLOCK_REALTIME, &current_time);
    system_stats.processing_time = (current_time.tv_sec - program_start_time.tv_sec) + 
                                  (current_time.tv_nsec - program_start_time.tv_nsec) / 1000000000.0;
    
    // 计算每秒处理的数据包数
    if (system_stats.processing_time > 0) {
        system_stats.packets_per_second = (uint64_t)(system_stats.packets_processed / system_stats.processing_time);
    }
}

void sig_handler(int sig) {
    static int signal_count = 0;
    signal_count++;
    
    if (signal_count == 1) {
        printf("\nReceived signal %d, initiating graceful shutdown...\n", sig);
        running = 0;
        
        // 移除这里的print_final_stats()调用，避免与cleanup()中的重复
        // if (flow_table_initialized) {
        //     print_final_stats();
        // }
        
        // Give some time for threads to finish
        sleep(1);
        alarm(5); // Set a 5-second timeout
    } else {
        printf("\nForcing immediate exit...\n");
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
            fprintf(stderr, "No permission to create lock file %s, trying to use /tmp directory\n", LOCK_FILE);
            // 尝试在/tmp目录下创建
            const char *tmp_lock = "/tmp/ebpf_pkt.lock";
            lock_fd = open(tmp_lock, O_RDWR | O_CREAT, 0644);
            if (lock_fd == -1) {
                fprintf(stderr, "Cannot create lock file: %s\n", strerror(errno));
                return -1;
            }
        } else {
            fprintf(stderr, "Cannot create lock file: %s\n", strerror(errno));
            return -1;
        }
    }
    
    // 尝试对文件加锁
    if (flock(lock_fd, LOCK_EX | LOCK_NB) == -1) {
        if (errno == EWOULDBLOCK) {
            // 已有另一个实例在运行
            fprintf(stderr, "Another instance is already running\n");
            close(lock_fd);
            lock_fd = -1;
            return 1;
        } else {
            fprintf(stderr, "Unable to lock file: %s\n", strerror(errno));
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
        fprintf(stderr, "Unable to write PID to lock file: %s\n", strerror(errno));
        // 继续运行，这只是额外的信息
    }
    
    // 注册退出时的清理函数
    atexit(cleanup);
    
    return 0;
}

// 创建并启动工作线程
static int start_worker_threads() {
    worker_threads = (pthread_t *)malloc(num_threads * sizeof(pthread_t));
    if (!worker_threads) {
        fprintf(stderr, "Failed to allocate memory for worker threads\n");
        return -1;
    }
    
    // 创建工作线程
    for (int i = 0; i < num_threads; i++) {
        if (pthread_create(&worker_threads[i], NULL, worker_thread_func, NULL) != 0) {
            fprintf(stderr, "Failed to create worker thread %d\n", i);
            return -1;
        }
        
        // 设置线程亲和性，将线程分配到不同的CPU核心
        cpu_set_t cpuset;
        CPU_ZERO(&cpuset);
        CPU_SET(i % sysconf(_SC_NPROCESSORS_ONLN), &cpuset);
        pthread_setaffinity_np(worker_threads[i], sizeof(cpu_set_t), &cpuset);
    }
    
    // 创建统计线程
    if (pthread_create(&stats_thread, NULL, stats_thread_func, NULL) != 0) {
        fprintf(stderr, "Failed to create stats thread\n");
        return -1;
    }
    
    return 0;
}

// 停止所有工作线程
static void stop_worker_threads() {
    if (!worker_threads) {
        return;
    }
    
    // 设置运行标志为停止
    running = 0;
    
    // 等待所有工作线程退出
    for (int i = 0; i < num_threads; i++) {
        pthread_join(worker_threads[i], NULL);
    }
    
    // 等待统计线程退出
    pthread_join(stats_thread, NULL);
    
    // 释放线程资源
    free(worker_threads);
    worker_threads = NULL;
}

// 修改后的BPF数据处理函数，将数据包添加到队列
static void handle_batch(void *ctx, int cpu, void *data, __u32 size) {
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
        printf("Reached specified duration of %d seconds. Exiting...\n", duration);
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
        packet_data.transport_header.tcp.source = htons(pkt->src_port);
        packet_data.transport_header.tcp.dest = htons(pkt->dst_port);
        
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

// 修改后的pcap包处理函数，将数据包添加到队列
void process_pcap_packet(const u_char *packet, const struct pcap_pkthdr *header) {
    // 预取以太网头和IP头
    PREFETCH((void *)packet);
    PREFETCH((void *)(packet + sizeof(struct ethhdr)));
    
    struct ethhdr *eth = (struct ethhdr *)packet;
    
    // 使用位操作替代条件判断
    if ((ntohs(eth->h_proto) ^ ETH_P_IP) != 0) {
        return;  // Skip non-IP packets
    }
    
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    
    // 使用位操作替代条件判断
    if ((ip->version ^ 4) != 0) {
        return;  // Skip non-IPv4 packets
    }
    
    // 预取传输层头
    void *transport_header = (void *)ip + (ip->ihl * 4);
    PREFETCH(transport_header);
    
    // 准备数据包结构
    packet_data_t packet_data;
    
    // 复制IP头
    memcpy(&packet_data.ip_header, ip, sizeof(struct iphdr));
    
    // 提取并转换时间戳为纳秒
    packet_data.timestamp = (uint64_t)header->ts.tv_sec * 1000000000ULL + (uint64_t)header->ts.tv_usec * 1000ULL;
    
    // 根据协议类型处理传输层
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)transport_header;
        packet_data.transport_header.tcp.source = tcp->source;
        packet_data.transport_header.tcp.dest = tcp->dest;
        packet_data.transport_header.tcp.seq = ntohl(tcp->seq);
        memcpy(packet_data.transport_header.tcp.flags_byte, tcp, sizeof(struct tcphdr));
    } else if (ip->protocol == IPPROTO_UDP) {
        struct udphdr *udp = (struct udphdr *)transport_header;
        packet_data.transport_header.udp.source = udp->source;
        packet_data.transport_header.udp.dest = udp->dest;
    }
    
    // 将数据包添加到队列
    if (packet_queue_enqueue(&packet_queue, &packet_data) != 0) {
        // 入队失败，检查是否应该退出
        if (!running) return;
    }
    
    // 使用位操作进行条件判断
    time_t current_time = time(NULL);
    int should_exit = (duration > 0) & (current_time - start_time >= duration);
    running &= !should_exit;
    
    if (should_exit) {
        printf("Reached specified duration of %d seconds. Exiting...\n", duration);
        return;
    }
}

// Process a pcap file
int process_pcap_file(const char *pcap_file) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    int ret = 0;
    
    // Record start time
    start_time = time(NULL);
    
    // 初始化数据包队列
    packet_queue_init(&packet_queue, PACKET_QUEUE_SIZE);
    
    // Initialize flow tracking
    flow_table_init();
    
    // 启动工作线程
    if (start_worker_threads() != 0) {
        fprintf(stderr, "Failed to start worker threads\n");
        return -1;
    }
    
    printf("Started %d worker threads for packet processing\n", num_threads);
    printf("Processing pcap file: %s\n", pcap_file);
    
    if (loop_count == 0) {
        printf("Loop mode: infinite loops\n");
    } else if (loop_count > 1) {
        printf("Loop mode: %d loops\n", loop_count);
    }
    
    if (loop_delay > 0 && loop_count != 1) {
        printf("Loop delay: %d seconds between loops\n", loop_delay);
    }
    
    if (duration > 0) {
        printf("Will analyze traffic for %d seconds\n", duration);
    }
    
    int total_packet_count = 0;
    int current_loop = 0;
    
    // 循环播放pcap文件
    while (running && (loop_count == 0 || current_loop < loop_count)) {
        current_loop++;
        
        // Open the pcap file
        handle = pcap_open_offline(pcap_file, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open pcap file %s: %s\n", pcap_file, errbuf);
            ret = -1;
            break;
        }
        
        if (current_loop > 1 && !quiet_mode) {
            printf("Starting loop %d/%s...\n", current_loop, 
                   loop_count == 0 ? "∞" : (char[]){loop_count + '0', '\0'});
        }
        
        // Process packets from the pcap file
        struct pcap_pkthdr header;
        const u_char *packet;
        int loop_packet_count = 0;
        
        while (running && (packet = pcap_next(handle, &header)) != NULL) {
            // 预取数据包内容以提高性能
            PREFETCH(packet);
            PREFETCH(packet + 64); // 预取第二个缓存行
            
            process_pcap_packet(packet, &header);
            loop_packet_count++;
            total_packet_count++;
            
            // 每10000个包检查一次时间限制
            if (loop_packet_count % 10000 == 0) {
                if (duration > 0 && time(NULL) - start_time >= duration) {
                    printf("Reached specified duration of %d seconds. Exiting...\n", duration);
                    running = 0;
                    break;
                }
            }
        }
        
        // Close current handle
        if (handle) {
            pcap_close(handle);
            handle = NULL;
        }
        
        if (!quiet_mode) {
            printf("Loop %d completed: processed %d packets\n", current_loop, loop_packet_count);
        }
        
        // 检查是否需要继续循环
        if (!running) {
            break;
        }
        
        // 如果不是最后一次循环且设置了延迟，则等待
        if ((loop_count == 0 || current_loop < loop_count) && loop_delay > 0) {
            if (!quiet_mode) {
                printf("Waiting %d seconds before next loop...\n", loop_delay);
            }
            
            // 分段睡眠以便能响应中断信号
            for (int i = 0; i < loop_delay && running; i++) {
                sleep(1);
            }
        }
        
        // 检查时间限制
        if (duration > 0 && time(NULL) - start_time >= duration) {
            printf("Reached specified duration of %d seconds. Exiting...\n", duration);
            break;
        }
    }
    
    printf("Total packets processed: %d (across %d loop%s)\n", 
           total_packet_count, current_loop, current_loop > 1 ? "s" : "");
    
    // 等待队列处理完所有数据包
    if (!quiet_mode) {
        printf("Waiting for packet processing to complete...\n");
    }
    
    while (packet_queue_size(&packet_queue) > 0 && running) {
        usleep(10000); // 10ms
    }
    
    // 停止工作线程
    stop_worker_threads();

    // 输出流统计信息 - 已注释掉
    /*
    printf("====== Conversation & Flow Statistics ======\n");
    
    // 使用get_total_conversation_count统计对话总数
    uint32_t total_conversations = get_total_conversation_count();
    uint32_t tcp_conversations = get_tcp_conversation_count();
    uint32_t udp_conversations = get_udp_conversation_count();
    
    // 统计活跃流和所有流的数量
    int active_flows = count_active_flows();
    int all_flows = count_all_flows();
    
    printf("Conversations: Total=%u (TCP=%u, UDP=%u)\n", 
           total_conversations, tcp_conversations, udp_conversations);
    printf("Flows: Active=%d, Total=%d, Inactive=%d\n", 
           active_flows, all_flows, all_flows - active_flows);
    
    // 计算活跃流和所有流的方向统计
    int forward_active_flows = 0, reverse_active_flows = 0;
    count_flow_directions(&forward_active_flows, &reverse_active_flows);
    
    int forward_all_flows = 0, reverse_all_flows = 0;
    count_all_flow_directions(&forward_all_flows, &reverse_all_flows);
    
    printf("Flow Directions - Active: Forward=%d, Reverse=%d\n", 
           forward_active_flows, reverse_active_flows);
    printf("Flow Directions - Total: Forward=%d, Reverse=%d\n", 
           forward_all_flows, reverse_all_flows);
    printf("============================================\n");
    */
    
    // Clean up
    if (handle) {
        pcap_close(handle);
        handle = NULL;
    }
    
    // 调用统一清理函数
    cleanup();
    
    return ret;
}

// 修改后的run_live_capture函数
int run_live_capture(const char *ifname) {
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
    printf("Flow tracking initialized\n");
    if (duration > 0) {
        printf("Will capture traffic for %d seconds\n", duration);
    }
    
    // 启动工作线程
    if (start_worker_threads() != 0) {
        fprintf(stderr, "Failed to start worker threads\n");
        return -1;
    }
    
    printf("Started %d worker threads for packet processing\n", num_threads);

    /* 1. Load BPF program */
    obj = bpf_object__open_file("bpf_program.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file\n");
        ret = 1;
        goto cleanup;
    }

    /* 2. Load into kernel */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "BPF loading failed: %s\n", strerror(-err));
        ret = 1;
        goto cleanup;
    }

    /* 3. Attach to interface */
    prog = bpf_object__find_program_by_name(obj, "xdp_packet_capture");
    if (!prog) {
        fprintf(stderr, "BPF program not found\n");
        ret = 1;
        goto cleanup;
    }

    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "Failed to get interface index: %s\n", strerror(errno));
        ret = 1;
        goto cleanup;
    }

    // 预取相关内存以提高性能
    PREFETCH(prog);
    link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "XDP attachment failed: %s\n", strerror(-errno));
        ret = 1;
        goto cleanup;
    }

    /* 4. Setup perf buffer */
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "Perf event map not found\n");
        ret = 1;
        goto cleanup;
    }
    struct perf_buffer_opts pb_opts = {
        .sz = sizeof(opts),
    };

    /* 新版libbpf API */
    pb = perf_buffer__new(map_fd, PERF_BUFFER_PAGES, 
                        handle_batch, 
                        NULL, 
                        NULL, 
                        &pb_opts);

    if (libbpf_get_error(pb)) {
        fprintf(stderr, "Failed to create perf buffer\n");
        ret = 1;
        goto cleanup;
    }

    printf("Successfully started capturing on %s, press Ctrl+C to stop...\n", ifname);

    /* 5. Event loop */
    while (running) {
        err = perf_buffer__poll(pb, 100);
        // 使用位操作代替条件判断 - 仅当err < 0且err != -EINTR时退出
        int should_break = (err < 0) & (err != -EINTR);
        if (should_break) {
            fprintf(stderr, "Error polling: %d\n", err);
            break;
        }
    }

    printf("Exiting program...\n");
    
    // 等待队列处理完所有数据包
    while (packet_queue_size(&packet_queue) > 0 && running) {
        usleep(10000); // 10ms
    }
    
    // 停止工作线程
    stop_worker_threads();

    // 输出流统计信息 - 已注释掉
    /*
    printf("====== Flow Statistics ======\n");
    
    // 使用get_total_conversation_count统计对话总数
    uint32_t total_conversations = get_total_conversation_count();
    uint32_t tcp_conversations = get_tcp_conversation_count();
    uint32_t udp_conversations = get_udp_conversation_count();
    
    // 统计活跃流和所有流的数量
    int active_flows = count_active_flows();
    int all_flows = count_all_flows();
    
    printf("Conversations: Total=%u (TCP=%u, UDP=%u)\n", 
           total_conversations, tcp_conversations, udp_conversations);
    printf("Flows: Active=%d, Total=%d, Inactive=%d\n", 
           active_flows, all_flows, all_flows - active_flows);
    
    // 计算活跃流和所有流的方向统计
    int forward_active_flows = 0, reverse_active_flows = 0;
    count_flow_directions(&forward_active_flows, &reverse_active_flows);
    
    int forward_all_flows = 0, reverse_all_flows = 0;
    count_all_flow_directions(&forward_all_flows, &reverse_all_flows);
    
    printf("Flow Directions - Active: Forward=%d, Reverse=%d\n", 
           forward_active_flows, reverse_active_flows);
    printf("Flow Directions - Total: Forward=%d, Reverse=%d\n", 
           forward_all_flows, reverse_all_flows);
    printf("============================================\n");
    */

cleanup:
    // Cleanup resources in reverse order of creation
    if (pb) {
        perf_buffer__free(pb);
        pb = NULL;
    }
    
    if (link) {
        bpf_link__destroy(link);
        link = NULL;
    }
    
    if (obj) {
        bpf_object__close(obj);
        obj = NULL;
    }
    
    // 调用统一清理函数
    cleanup();
    
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
    time_t current_time = time(NULL);
    
    // Update and print system statistics first
    update_system_stats();
    
    printf("\n=== System Performance Statistics ===\n");
    printf("CPU Usage:              %.2f%%\n", system_stats.cpu_usage);
    printf("Memory Usage:           %.2f%%\n", system_stats.memory_usage);
    printf("Packets Processed:      %lu\n", system_stats.packets_processed);
    printf("Processing Time:        %.2f seconds\n", system_stats.processing_time);
    printf("Packets per Second:     %lu\n", system_stats.packets_per_second);
    printf("======================================\n");
    
    // 使用get_total_conversation_count统计对话总数
    uint32_t total_conversations = get_total_conversation_count();
    uint32_t tcp_conversations = get_tcp_conversation_count();
    uint32_t udp_conversations = get_udp_conversation_count();
    
    // 获取活跃流和所有流的数量
    int active_flow_count = count_active_flows();
    int all_flow_count = count_all_flows();
    
    // 在非安静模式下打印对话统计
    if (!quiet_mode) {
        printf("\n============= Conversation Statistics =============\n");
        printf("Total Conversations:    %u\n", total_conversations);
        printf("  TCP Conversations:    %u\n", tcp_conversations);
        printf("  UDP Conversations:    %u\n", udp_conversations);
        printf("Active Flows:           %d\n", active_flow_count);
        printf("Total Flows:            %d\n", all_flow_count);
        printf("Inactive Flows:         %d\n", all_flow_count - active_flow_count);
        printf("==================================================\n");
    }
    
    // 统计流方向
    int forward_all_flows = 0, reverse_all_flows = 0;
    count_all_flow_directions(&forward_all_flows, &reverse_all_flows);
    
    if (!quiet_mode) {
        printf("\n============= Flow Direction Statistics =============\n");
        printf("Total Flow Directions: Forward: %d, Reverse: %d\n", 
               forward_all_flows, reverse_all_flows);
        
        // 打印活跃流方向统计
        int forward_active_flows = 0, reverse_active_flows = 0;
        count_flow_directions(&forward_active_flows, &reverse_active_flows);
        printf("Active Flow Directions: Forward: %d, Reverse: %d\n", 
               forward_active_flows, reverse_active_flows);
        printf("====================================================\n");
    }
    
    // 添加Wireshark风格的对话统计
    print_wireshark_conversation_stats();
    
    // 收集总数据包和字节统计
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    uint64_t total_tcp_flows = 0;
    uint64_t total_udp_flows = 0;
    uint64_t total_tcp_packets = 0;
    uint64_t total_udp_packets = 0;
    uint64_t total_tcp_bytes = 0;
    uint64_t total_udp_bytes = 0;
    
    if (!quiet_mode) {
        printf("\n============= Final Flow Statistics (Time Ordered) at %s =============\n", ctime(&current_time));
    }
    
    // 分配内存来存储所有流信息
    struct flow_info *flows = malloc(all_flow_count * sizeof(struct flow_info));
    if (!flows) {
        fprintf(stderr, "Error: Cannot allocate memory for flow sorting\n");
        return;
    }
    
    uint64_t now = get_current_time();
    int flow_count = 0;
    
    // 收集所有流信息
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            if (flow_count >= all_flow_count) {
                fprintf(stderr, "Warning: Flow count exceeded expected count\n");
                break;
            }
            
            struct flow_info *flow = &flows[flow_count];
            flow->node = node;
            flow->flow_id = flow_count + 1;
            
            // 检查流是否超时
            uint64_t timeout = FLOW_TIMEOUT_NS;
            if (node->key.protocol == IPPROTO_TCP) {
                timeout = TCP_FLOW_TIMEOUT_NS;
            }
            
            // 判断流是否活跃
            flow->is_active = (now - node->stats.last_seen <= timeout) ? 1 : 0;
            
            // 计算流持续时间
            flow->duration = time_diff(&node->stats.end_time, &node->stats.start_time);
            
            // 格式化开始时间
            struct tm *start_tm = localtime(&node->stats.start_time.tv_sec);
            strftime(flow->start_time_str, sizeof(flow->start_time_str), "%H:%M:%S", start_tm);
            
            // 准备IP地址字符串
            snprintf(flow->src_ip, sizeof(flow->src_ip), "%u.%u.%u.%u", NIPQUAD(node->key.src_ip));
            snprintf(flow->dst_ip, sizeof(flow->dst_ip), "%u.%u.%u.%u", NIPQUAD(node->key.dst_ip));
            
            // 计算总包数和字节数
            flow->flow_packets = node->stats.fwd_packets + node->stats.bwd_packets;
            flow->flow_bytes = node->stats.fwd_bytes + node->stats.bwd_bytes;
            
            // 计算流特征
            calculate_flow_features(&node->stats, &flow->features);
            
            flow_count++;
            node = node->next;
        }
    }
    
    // 按开始时间排序
    qsort(flows, flow_count, sizeof(struct flow_info), compare_flows_by_time);
    
    // 如果指定了CSV文件，打开它
    FILE *csv_fp = NULL;
    if (csv_file) {
        csv_fp = fopen(csv_file, "w");
        if (!csv_fp) {
            fprintf(stderr, "Error: Could not open CSV file %s for writing: %s\n", 
                    csv_file, strerror(errno));
        }
        
        // 写入CSV标题
        if (csv_fp) {
            fprintf(csv_fp, "流ID,源IP,源端口,目的IP,目的端口,协议,持续时间,开始时间,");
            fprintf(csv_fp, "正向包数,正向字节数,反向包数,反向字节数,");
            fprintf(csv_fp, "正向最小包大小,正向最大包大小,正向平均包大小,正向包大小标准差,");
            fprintf(csv_fp, "反向最小包大小,反向最大包大小,反向平均包大小,反向包大小标准差,");
            fprintf(csv_fp, "字节率,包率,正向包率,反向包率,");
            fprintf(csv_fp, "正向包间隔平均值,正向包间隔标准差,正向包间隔最大值,正向包间隔最小值,");
            fprintf(csv_fp, "反向包间隔平均值,反向包间隔标准差,反向包间隔最大值,反向包间隔最小值,");
            fprintf(csv_fp, "流间隔平均值,流间隔标准差,流间隔最大值,流间隔最小值,");
            fprintf(csv_fp, "FIN标志数,SYN标志数,RST标志数,PSH标志数,ACK标志数,");
            fprintf(csv_fp, "正向初始窗口字节数,反向初始窗口字节数,活跃状态\n");
        }
    }
    
    // 按时间顺序打印流信息
    if (!quiet_mode) {
        printf("\n%-5s %-25s %-25s %-10s %-15s %-15s %-10s %-10s %-10s\n", 
               "ID", "Source", "Destination", "Protocol", "Duration(s)", "Start Time", "Status", "Packets", "Bytes");
        printf("%-5s %-25s %-25s %-10s %-15s %-15s %-10s %-10s %-10s\n", 
               "----", "-----------------", "-----------------", "--------", "-----------", "-----------", "------", "-------", "-----");
    }
    
    // 输出排序后的流信息
    for (int i = 0; i < flow_count; i++) {
        struct flow_info *flow = &flows[i];
        struct flow_node *node = flow->node;
        
        // 计算总计数
        total_packets += flow->flow_packets;
        total_bytes += flow->flow_bytes;
        
        // 统计按协议
        if (node->key.protocol == IPPROTO_TCP) {
            total_tcp_flows++;
            total_tcp_packets += flow->flow_packets;
            total_tcp_bytes += flow->flow_bytes;
        } else if (node->key.protocol == IPPROTO_UDP) {
            total_udp_flows++;
            total_udp_packets += flow->flow_packets;
            total_udp_bytes += flow->flow_bytes;
        }
        
        // 非安静模式下打印流信息
        if (!quiet_mode) {
            char src[30], dst[30];
            snprintf(src, sizeof(src), "%s:%d", flow->src_ip, node->key.src_port);
            snprintf(dst, sizeof(dst), "%s:%d", flow->dst_ip, node->key.dst_port);
            
            printf("%-5d %-25s %-25s %-10s %-15.2f %-15s %-10s %-10lu %-10lu\n", 
                   flow->flow_id, src, dst, 
                   node->key.protocol == IPPROTO_TCP ? "TCP" : 
                   (node->key.protocol == IPPROTO_UDP ? "UDP" : "Other"),
                   flow->duration, 
                   flow->start_time_str,
                   flow->is_active ? "ACTIVE" : "INACTIVE",
                   (unsigned long)flow->flow_packets,
                   (unsigned long)flow->flow_bytes);
            
            // 打印方向统计信息
            printf("     Forward: %-10lu pkts, %-10lu bytes | Reverse: %-10lu pkts, %-10lu bytes\n",
                   (unsigned long)node->stats.fwd_packets,
                   (unsigned long)node->stats.fwd_bytes,
                   (unsigned long)node->stats.bwd_packets,
                   (unsigned long)node->stats.bwd_bytes);
            
            // 打印包特征信息
            printf("     Packet Size (bytes) - Fwd: min=%-5u max=%-5u avg=%-7.1f | Bwd: min=%-5u max=%-5u avg=%-7.1f\n",
                   flow->features.fwd_min_size,
                   flow->features.fwd_max_size,
                   flow->features.fwd_avg_size,
                   flow->features.bwd_min_size,
                   flow->features.bwd_max_size,
                   flow->features.bwd_avg_size);
                   
            // 打印流量率特征
            printf("     Flow Rates - Bytes: %-7.2f KB/s | Packets: %-7.2f pkts/s\n",
                   flow->features.byte_rate / 1024.0,
                   flow->features.packet_rate);
            
            // 打印时间间隔特征
            printf("     Packet IAT (s) - Fwd: avg=%-7.6f std=%-7.6f | Bwd: avg=%-7.6f std=%-7.6f\n",
                   flow->features.fwd_iat_mean,
                   flow->features.fwd_iat_std,
                   flow->features.bwd_iat_mean,
                   flow->features.bwd_iat_std);
            
            // 打印TCP标志信息 (如果是TCP流)
            if (node->key.protocol == IPPROTO_TCP) {
                printf("     TCP Flags - FIN: %-4u SYN: %-4u RST: %-4u PSH: %-4u ACK: %-4u URG: %-4u CWR: %-4u ECE: %-4u\n",
                       node->stats.tcp_flags.fwd_fin_count + node->stats.tcp_flags.bwd_fin_count,
                       node->stats.tcp_flags.fwd_syn_count + node->stats.tcp_flags.bwd_syn_count,
                       node->stats.tcp_flags.fwd_rst_count + node->stats.tcp_flags.bwd_rst_count,
                       node->stats.tcp_flags.fwd_psh_count + node->stats.tcp_flags.bwd_psh_count,
                       node->stats.tcp_flags.fwd_ack_count + node->stats.tcp_flags.bwd_ack_count,
                       node->stats.tcp_flags.fwd_urg_count + node->stats.tcp_flags.bwd_urg_count,
                       node->stats.tcp_flags.fwd_cwr_count + node->stats.tcp_flags.bwd_cwr_count,
                       node->stats.tcp_flags.fwd_ece_count + node->stats.tcp_flags.bwd_ece_count);
                
                // 打印TCP初始窗口大小
                printf("     TCP Init Windows - Fwd: %-6u bytes | Bwd: %-6u bytes\n",
                       node->stats.fwd_init_win_bytes,
                       node->stats.bwd_init_win_bytes);
            }
            
            // 打印空行分隔不同流的信息
            printf("\n");
        }
        
        if (csv_fp) {
            // 基本流信息
            fprintf(csv_fp, "%d,%s,%d,%s,%d,%d,%.6f,%s,%d,",
                   flow->flow_id, flow->src_ip, node->key.src_port, 
                   flow->dst_ip, node->key.dst_port,
                   node->key.protocol, flow->duration, flow->start_time_str, flow->is_active);
            
            // 方向统计
            fprintf(csv_fp, "%lu,%lu,%lu,%lu,",
                   (unsigned long)flow->features.fwd_packets,
                   (unsigned long)flow->features.fwd_bytes,
                   (unsigned long)flow->features.bwd_packets,
                   (unsigned long)flow->features.bwd_bytes);
            
            // 包大小特征
            fprintf(csv_fp, "%u,%u,%.6f,%.6f,",
                   flow->features.fwd_min_size, flow->features.fwd_max_size,
                   flow->features.fwd_avg_size, flow->features.fwd_std_size);
            fprintf(csv_fp, "%u,%u,%.6f,%.6f,",
                   flow->features.bwd_min_size, flow->features.bwd_max_size,
                   flow->features.bwd_avg_size, flow->features.bwd_std_size);
            
            // 流量率特征
            fprintf(csv_fp, "%.6f,%.6f,%.6f,%.6f,",
                   flow->features.byte_rate, flow->features.packet_rate,
                   flow->features.fwd_packet_rate, flow->features.bwd_packet_rate);
            
            // 时间间隔特征 - 正向
            fprintf(csv_fp, "%.6f,%.6f,%.6f,%.6f,",
                   flow->features.fwd_iat_mean, flow->features.fwd_iat_std,
                   flow->features.fwd_iat_max, flow->features.fwd_iat_min);
            
            // 时间间隔特征 - 反向
            fprintf(csv_fp, "%.6f,%.6f,%.6f,%.6f,",
                   flow->features.bwd_iat_mean, flow->features.bwd_iat_std,
                   flow->features.bwd_iat_max, flow->features.bwd_iat_min);
            
            // 流间隔时间特征
            fprintf(csv_fp, "%.6f,%.6f,%.6f,%.6f,",
                   flow->features.flow_iat_mean, flow->features.flow_iat_std,
                   flow->features.flow_iat_max, flow->features.flow_iat_min);
            
            // TCP标志统计 (所有流)
            int total_fin = node->stats.tcp_flags.fwd_fin_count + node->stats.tcp_flags.bwd_fin_count;
            int total_syn = node->stats.tcp_flags.fwd_syn_count + node->stats.tcp_flags.bwd_syn_count;
            int total_rst = node->stats.tcp_flags.fwd_rst_count + node->stats.tcp_flags.bwd_rst_count;
            int total_psh = node->stats.tcp_flags.fwd_psh_count + node->stats.tcp_flags.bwd_psh_count;
            int total_ack = node->stats.tcp_flags.fwd_ack_count + node->stats.tcp_flags.bwd_ack_count;
            
            fprintf(csv_fp, "%d,%d,%d,%d,%d,",
                   total_fin, total_syn, total_rst, total_psh, total_ack);
            
            // TCP窗口信息
            fprintf(csv_fp, "%u,%u,%d\n",
                   node->stats.fwd_init_win_bytes,
                   node->stats.bwd_init_win_bytes,
                   flow->is_active);
        }
    }
    
    // 释放分配的内存
    free(flows);
    
    if (!quiet_mode) {
        printf("\n============= Final Summary Statistics =============\n");
        printf("Conversation Summary:\n");
        printf("  Total Conversations:  %u\n", total_conversations);
        printf("    TCP Conversations:  %u\n", tcp_conversations);
        printf("    UDP Conversations:  %u\n", udp_conversations);
        printf("\nFlow Summary:\n");
        printf("  Total Flows:          %lu\n", (unsigned long)flow_count);
        printf("    TCP Flows:          %lu\n", (unsigned long)total_tcp_flows);
        printf("    UDP Flows:          %lu\n", (unsigned long)total_udp_flows);
        printf("    Active Flows:       %d\n", active_flow_count);
        printf("    Inactive Flows:     %d\n", all_flow_count - active_flow_count);
        printf("\nPacket Summary:\n");
        printf("  Total Packets:        %lu\n", (unsigned long)total_packets);
        printf("    TCP Packets:        %lu\n", (unsigned long)total_tcp_packets);
        printf("    UDP Packets:        %lu\n", (unsigned long)total_udp_packets);
        printf("\nByte Summary:\n");
        printf("  Total Bytes:          %lu (%.2f MB)\n", 
               (unsigned long)total_bytes, total_bytes / (1024.0 * 1024.0));
        printf("    TCP Bytes:          %lu (%.2f MB)\n", 
               (unsigned long)total_tcp_bytes, total_tcp_bytes / (1024.0 * 1024.0));
        printf("    UDP Bytes:          %lu (%.2f MB)\n", 
               (unsigned long)total_udp_bytes, total_udp_bytes / (1024.0 * 1024.0));
        printf("===================================================\n");
    }
    
    if (csv_fp) {
        fclose(csv_fp);
        if (!quiet_mode) {
            printf("\nFeatures exported to CSV file: %s\n", csv_file);
        } else {
            printf("Features exported to CSV file: %s\n", csv_file);
        }
    }
    
    if (!quiet_mode) {
        printf("\n=============================================================\n\n");
    }
    

}

// 打印使用帮助
void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("  -i, --interface <ifname>    Network interface to monitor (default: eth0)\n");
    printf("  -r, --read <pcap-file>      Read packets from pcap file instead of network\n");
    printf("  -d, --duration <seconds>    Run for specified duration in seconds (default: indefinite)\n");
    printf("  -s, --stats-interval <sec>  Interval between statistics printing (default: %d seconds)\n", 
           DEFAULT_STATS_INTERVAL);
    printf("  -p, --packets <count>       Print stats every N packets (default: %d)\n", 
           DEFAULT_STATS_PACKETS);
    printf("  -c, --cleanup <seconds>     Flow cleanup interval (default: %d seconds)\n", 
           DEFAULT_CLEANUP_INTERVAL);
    printf("  -t, --threads <count>       Number of worker threads (default: %d)\n",
           DEFAULT_NUM_THREADS);
    printf("  -o, --output <csv-file>     Export features to CSV file\n");
    printf("  -l, --loop <count>          Loop pcap file N times (0 = infinite, default: 1)\n");
    printf("  -w, --wait <seconds>        Wait N seconds between loops (default: 0)\n");
    printf("  -v, --verbose <level>       Debug level: 0=none, 1=basic, 2=detailed (default: 0)\n");
    printf("  -q, --quiet                 Quiet mode, don't print statistics to screen\n");
    printf("  -h, --help                  Show this help message\n");
}

int main(int argc, char **argv) {
    const char *ifname = "enp1s0";  // Default interface
    const char *pcap_file = NULL;
    int c;
    int ret = 0;

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
        {"threads",       required_argument, 0, 't'},
        {"output",        required_argument, 0, 'o'},
        {"loop",          required_argument, 0, 'l'},
        {"wait",          required_argument, 0, 'w'},
        {"verbose",       required_argument, 0, 'v'},
        {"quiet",         no_argument,       0, 'q'},
        {"help",          no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((c = getopt_long(argc, argv, "i:r:d:s:p:c:t:o:l:w:v:qh", long_options, NULL)) != -1) {
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
            case 't':
                num_threads = atoi(optarg);
                if (num_threads <= 0) {
                    fprintf(stderr, "Thread count must be a positive number\n");
                    return 1;
                }
                if (num_threads > MAX_NUM_THREADS) {
                    fprintf(stderr, "Thread count cannot exceed %d, setting to %d\n", 
                            MAX_NUM_THREADS, MAX_NUM_THREADS);
                    num_threads = MAX_NUM_THREADS;
                }
                printf("Setting worker thread count to %d\n", num_threads);
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
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }

    if (pcap_file) {
        // Process pcap file
        ret = process_pcap_file(pcap_file);
    } else {
        // Live capture mode
        ret = run_live_capture(ifname);
    }
    
    return ret;
}