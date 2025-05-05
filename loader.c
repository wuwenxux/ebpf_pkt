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

// 全局变量以跟踪终端模式
int in_place_updates = 1;  // 默认启用原位更新
int first_stats_print = 1; // 第一次打印标志

// 运行状态，设为extern以便其他文件可访问
volatile int running = 1;

// 函数前向声明
void print_final_stats(void);

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
#define DEFAULT_STATS_INTERVAL 5   // 5 seconds between stats prints
#define DEFAULT_STATS_PACKETS 1000 // Print stats every 1000 packets
#define DEFAULT_CLEANUP_INTERVAL 10 // 10 seconds between flow cleanups
#define DEFAULT_DURATION 0         // 0 means run indefinitely

// 锁文件路径
#define LOCK_FILE "/var/run/ebpf_pkt.lock"

// Global settings
static int stats_interval = DEFAULT_STATS_INTERVAL;
static int stats_packet_count = DEFAULT_STATS_PACKETS;
static int cleanup_interval = DEFAULT_CLEANUP_INTERVAL;
static int duration = DEFAULT_DURATION;  // in seconds, 0 means run indefinitely
static time_t start_time;                // program start time
static int lock_fd = -1;                // 文件锁描述符
static int num_threads = DEFAULT_NUM_THREADS; // 工作线程数量

// 多线程处理相关数据结构
typedef struct {
    struct iphdr ip_header;
    union {
        struct {
            uint16_t source;
            uint16_t dest;
            uint8_t flags_byte[14]; // 足够存储TCP标志位(在字节13)
        } tcp;
        struct {
            uint16_t source;
            uint16_t dest;
        } udp;
    } transport_header;
} packet_data_t;

// 数据包队列
typedef struct {
    packet_data_t *packets;          // 数据包缓冲区
    int front;                        // 队列前端
    int rear;                         // 队列尾部
    int size;                         // 队列大小
    int capacity;                     // 队列容量 
    pthread_mutex_t mutex;            // 保护队列的互斥锁
    pthread_cond_t not_empty;         // 队列非空条件变量
    pthread_cond_t not_full;          // 队列非满条件变量
} packet_queue_t;

// 全局数据包队列
static packet_queue_t packet_queue;

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

// 初始化数据包队列
static void packet_queue_init(packet_queue_t *queue, int capacity) {
    queue->packets = (packet_data_t *)malloc(capacity * sizeof(packet_data_t));
    if (!queue->packets) {
        fprintf(stderr, "Failed to allocate packet queue\n");
        exit(EXIT_FAILURE);
    }
    
    queue->front = 0;
    queue->rear = -1;
    queue->size = 0;
    queue->capacity = capacity;
    
    pthread_mutex_init(&queue->mutex, NULL);
    pthread_cond_init(&queue->not_empty, NULL);
    pthread_cond_init(&queue->not_full, NULL);
}

// 销毁数据包队列
static void packet_queue_destroy(packet_queue_t *queue) {
    if (queue->packets) {
        free(queue->packets);
        queue->packets = NULL;
    }
    
    pthread_mutex_destroy(&queue->mutex);
    pthread_cond_destroy(&queue->not_empty);
    pthread_cond_destroy(&queue->not_full);
}

// 将数据包添加到队列
static int packet_queue_enqueue(packet_queue_t *queue, const packet_data_t *packet) {
    pthread_mutex_lock(&queue->mutex);
    
    // 队列已满，等待队列有空间
    while (queue->size == queue->capacity && running) {
        pthread_cond_wait(&queue->not_full, &queue->mutex);
    }
    
    // 如果程序不再运行，退出
    if (!running) {
        pthread_mutex_unlock(&queue->mutex);
        return -1;
    }
    
    // 添加数据包到队列
    queue->rear = (queue->rear + 1) % queue->capacity;
    PREFETCH_RW(&queue->packets[queue->rear]);
    memcpy(&queue->packets[queue->rear], packet, sizeof(packet_data_t));
    queue->size++;
    
    // 通知等待的消费者
    pthread_cond_signal(&queue->not_empty);
    pthread_mutex_unlock(&queue->mutex);
    
    return 0;
}

// 从队列中获取数据包
static int packet_queue_dequeue(packet_queue_t *queue, packet_data_t *packet) {
    pthread_mutex_lock(&queue->mutex);
    
    // 队列为空，等待队列有数据
    while (queue->size == 0 && running) {
        pthread_cond_wait(&queue->not_empty, &queue->mutex);
    }
    
    // 如果程序不再运行且队列为空，退出
    if (!running && queue->size == 0) {
        pthread_mutex_unlock(&queue->mutex);
        return -1;
    }
    
    // 从队列中获取数据包
    PREFETCH(&queue->packets[queue->front]);
    memcpy(packet, &queue->packets[queue->front], sizeof(packet_data_t));
    queue->front = (queue->front + 1) % queue->capacity;
    queue->size--;
    
    // 通知等待的生产者
    pthread_cond_signal(&queue->not_full);
    pthread_mutex_unlock(&queue->mutex);
    
    return 0;
}

// 线程安全版本的流表访问函数
static void thread_safe_process_packet(const struct iphdr *ip, const void *transport_hdr) {
    pthread_mutex_lock(&flow_table_mutex);
    process_packet(ip, transport_hdr);
    pthread_mutex_unlock(&flow_table_mutex);
    
    // 更新统计信息
    __sync_fetch_and_add(&total_packets_processed, 1);
    __sync_fetch_and_add(&total_bytes_processed, ntohs(ip->tot_len));
}

// 工作线程函数，从队列中获取数据包并处理
static void *worker_thread_func(void *arg) {
    packet_data_t packet;
    
    while (running) {
        // 从队列中获取数据包
        if (packet_queue_dequeue(&packet_queue, &packet) != 0) {
            // 队列获取失败，检查是否应该退出
            if (!running) break;
            continue;
        }
        
        // 预取数据包内容以提高性能
        PREFETCH(&packet.ip_header);
        PREFETCH(&packet.transport_header);
        
        // 处理数据包
        thread_safe_process_packet(&packet.ip_header, &packet.transport_header);
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
    // 确保终端光标可见
    if (in_place_updates) {
        printf("%s", ANSI_SHOW_CURSOR);
    }
    
    // 如果流表已初始化，打印最终统计信息
    if (!cleanup_done && flow_table_initialized) {
        print_final_stats();
    }
    
    // 清理流表
    if (!cleanup_done) {
        cleanup_done = 1;
        flow_table_destroy();
    }
    
    // 释放文件锁
    if (lock_fd != -1) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        lock_fd = -1;
    }
    
    // 销毁数据包队列
    packet_queue_destroy(&packet_queue);
    
    // 释放线程资源
    if (worker_threads) {
        free(worker_threads);
        worker_threads = NULL;
    }
}

void sig_handler(int sig) {
    printf("\nReceived signal %d. Cleaning up and exiting...\n", sig);
    running = 0;
    
    // 唤醒所有等待队列的线程
    pthread_cond_broadcast(&packet_queue.not_empty);
    pthread_cond_broadcast(&packet_queue.not_full);
}

// 检查是否已经有实例在运行
static int check_single_instance(void) {
    // 打开锁文件
    lock_fd = open(LOCK_FILE, O_RDWR | O_CREAT, 0644);
    if (lock_fd == -1) {
        // 检查是否有权限创建锁文件
        if (errno == EACCES || errno == EPERM) {
            fprintf(stderr, "无权限创建锁文件 %s，尝试使用 /tmp 目录\n", LOCK_FILE);
            // 尝试在/tmp目录下创建
            const char *tmp_lock = "/tmp/ebpf_pkt.lock";
            lock_fd = open(tmp_lock, O_RDWR | O_CREAT, 0644);
            if (lock_fd == -1) {
                fprintf(stderr, "无法创建锁文件: %s\n", strerror(errno));
                return -1;
            }
        } else {
            fprintf(stderr, "无法创建锁文件: %s\n", strerror(errno));
            return -1;
        }
    }
    
    // 尝试对文件加锁
    if (flock(lock_fd, LOCK_EX | LOCK_NB) == -1) {
        if (errno == EWOULDBLOCK) {
            // 已有另一个实例在运行
            fprintf(stderr, "另一个实例已经在运行\n");
            close(lock_fd);
            lock_fd = -1;
            return 1;
        } else {
            fprintf(stderr, "无法锁定文件: %s\n", strerror(errno));
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
        fprintf(stderr, "无法写入PID到锁文件: %s\n", strerror(errno));
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
    
    // 唤醒所有等待队列的线程
    pthread_cond_broadcast(&packet_queue.not_empty);
    pthread_cond_broadcast(&packet_queue.not_full);
    
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
    
    // 根据协议类型处理传输层
    if (ip->protocol == IPPROTO_TCP) {
        struct tcphdr *tcp = (struct tcphdr *)transport_header;
        packet_data.transport_header.tcp.source = tcp->source;
        packet_data.transport_header.tcp.dest = tcp->dest;
        packet_data.transport_header.tcp.flags_byte[13] = *((uint8_t*)tcp + 13);
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
    
    // Open the pcap file
    handle = pcap_open_offline(pcap_file, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "Couldn't open pcap file %s: %s\n", pcap_file, errbuf);
        return -1;
    }
    
    printf("Processing pcap file: %s\n", pcap_file);
    if (duration > 0) {
        printf("Will analyze traffic for %d seconds\n", duration);
    }
    
    // Initialize flow tracking
    flow_table_init();
    
    // 启动工作线程
    if (start_worker_threads() != 0) {
        fprintf(stderr, "Failed to start worker threads\n");
        pcap_close(handle);
        return -1;
    }
    
    printf("Started %d worker threads for packet processing\n", num_threads);
    
    // Process packets from the pcap file
    struct pcap_pkthdr header;
    const u_char *packet;
    int packet_count = 0;
    
    while (running && (packet = pcap_next(handle, &header)) != NULL) {
        // 预取数据包内容以提高性能
        PREFETCH(packet);
        PREFETCH(packet + 64); // 预取第二个缓存行
        
        process_pcap_packet(packet, &header);
        packet_count++;
        
        // Print progress every 10000 packets
        if (packet_count % 10000 == 0) {
            printf("Processed %d packets...\n", packet_count);
        }
    }
    
    printf("Read %d packets from pcap file\n", packet_count);
    
    // 等待队列处理完所有数据包
    while (packet_queue.size > 0 && running) {
        usleep(10000); // 10ms
    }
    
    // 停止工作线程
    stop_worker_threads();
    
    printf("Processed %lu packets total\n", (unsigned long)total_packets_processed);
    
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

    /* 1. 加载BPF程序 */
    obj = bpf_object__open_file("bpf_program.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "Failed to open BPF object file\n");
        ret = 1;
        goto cleanup;
    }

    /* 2. 加载到内核 */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "BPF loading failed: %s\n", strerror(-err));
        ret = 1;
        goto cleanup;
    }

    /* 3. 附加到接口 */
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

    /* 4. 设置perf buffer */
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

    /* 5. 事件循环 */
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
    while (packet_queue.size > 0 && running) {
        usleep(10000); // 10ms
    }
    
    // 停止工作线程
    stop_worker_threads();

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

// 实现print_final_stats函数 - 在程序结束时打印最终统计
void print_final_stats(void) {
    time_t current_time = time(NULL);
    printf("\n============= Final Flow Statistics at %s =============\n", ctime(&current_time));
    printf("Total Active Flows: %d\n", count_active_flows());
    
    // 收集总数据包和字节统计
    uint64_t total_packets = 0;
    uint64_t total_bytes = 0;
    uint64_t total_tcp_flows = 0;
    uint64_t total_udp_flows = 0;
    uint64_t total_tcp_packets = 0;
    uint64_t total_udp_packets = 0;
    uint64_t total_tcp_bytes = 0;
    uint64_t total_udp_bytes = 0;
    
    // 打印流量详细信息
    int flow_count = 0;
    printf("\nFlow Details:\n");
    printf("------------------------------------------------------\n");
    printf("%-5s %-25s %-25s %-10s\n", "ID", "Source", "Destination", "Protocol");
    printf("------------------------------------------------------\n");
    
    for (int i = 0; i < HASH_TABLE_SIZE; i++) {
        struct flow_node *node = flow_table[i];
        while (node) {
            flow_count++;
            
            // 计算总计数
            uint64_t flow_packets = node->stats.fwd_packets + node->stats.bwd_packets;
            uint64_t flow_bytes = node->stats.fwd_bytes + node->stats.bwd_bytes;
            total_packets += flow_packets;
            total_bytes += flow_bytes;
            
            // 统计按协议
            if (node->key.protocol == IPPROTO_TCP) {
                total_tcp_flows++;
                total_tcp_packets += flow_packets;
                total_tcp_bytes += flow_bytes;
            } else if (node->key.protocol == IPPROTO_UDP) {
                total_udp_flows++;
                total_udp_packets += flow_packets;
                total_udp_bytes += flow_bytes;
            }
            
            // 打印流信息
            char src[30], dst[30];
            snprintf(src, sizeof(src), "%u.%u.%u.%u:%d", 
                    NIPQUAD(node->key.src_ip), node->key.src_port);
            snprintf(dst, sizeof(dst), "%u.%u.%u.%u:%d", 
                    NIPQUAD(node->key.dst_ip), node->key.dst_port);
            
            printf("%-5d %-25s %-25s %-10s\n", 
                   flow_count, src, dst, 
                   node->key.protocol == IPPROTO_TCP ? "TCP" : 
                   (node->key.protocol == IPPROTO_UDP ? "UDP" : "Other"));
            
            node = node->next;
        }
    }
    
    // 打印摘要统计
    printf("\nSummary Statistics:\n");
    printf("Total Flows:      %lu\n", (unsigned long)flow_count);
    printf("  TCP Flows:      %lu\n", (unsigned long)total_tcp_flows);
    printf("  UDP Flows:      %lu\n", (unsigned long)total_udp_flows);
    printf("Total Packets:    %lu\n", (unsigned long)total_packets);
    printf("  TCP Packets:    %lu\n", (unsigned long)total_tcp_packets);
    printf("  UDP Packets:    %lu\n", (unsigned long)total_udp_packets);
    printf("Total Bytes:      %lu (%.2f MB)\n", 
           (unsigned long)total_bytes, total_bytes / (1024.0 * 1024.0));
    printf("  TCP Bytes:      %lu (%.2f MB)\n", 
           (unsigned long)total_tcp_bytes, total_tcp_bytes / (1024.0 * 1024.0));
    printf("  UDP Bytes:      %lu (%.2f MB)\n", 
           (unsigned long)total_udp_bytes, total_udp_bytes / (1024.0 * 1024.0));
    
    printf("\n=============================================================\n\n");
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
    printf("  -h, --help                  Show this help message\n");
}

int main(int argc, char **argv) {
    const char *ifname = "eth0";  // Default interface
    const char *pcap_file = NULL;
    int c;
    int ret = 0;

    // Setup signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // 检查是否已经有实例在运行
    ret = check_single_instance();
    if (ret > 0) {
        // 已有实例运行
        fprintf(stderr, "程序已有一个实例在运行，退出...\n");
        return 1;
    } else if (ret < 0) {
        // 错误
        fprintf(stderr, "检查单实例失败，继续运行...\n");
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
        {"help",          no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((c = getopt_long(argc, argv, "i:r:d:s:p:c:t:h", long_options, NULL)) != -1) {
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