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

// BPF相关头文件
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/ringbuf.h>

// 项目头文件
#include "flow.h"
#include "stats_window.h"
#include "loader.h"
#include "transport_session.h"

// 多网口RINGBUF配置
#define MAX_INTERFACES 32
#define PACKET_QUEUE_SIZE 100000
#define MAX_INTERFACE_NAME_LEN 32

// 数据包信息结构（与BPF程序保持一致）
struct packet_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u32 pkt_len;
    __u64 timestamp;
    __u8 tcp_flags;
    __u32 ifindex;
    __u32 cpu_id;
} __attribute__((packed));

// 接口配置结构
struct interface_config {
    __u8 enabled;
    __u8 capture_mode;
    __u16 sampling_rate;
    __u32 max_packets_per_sec;
    __u32 max_bytes_per_sec;
} __attribute__((packed));

// 接口信息结构
typedef struct {
    char name[MAX_INTERFACE_NAME_LEN];
    int ifindex;
    struct bpf_object *obj;
    struct bpf_link *link;
    struct ring_buffer *rb;
    pthread_t thread;
    int is_active;
    int thread_ret;
    uint64_t packets_captured;
    uint64_t bytes_captured;
    uint64_t packets_dropped;
    uint64_t packets_error;
} interface_info_t;

// 全局变量
volatile int running = 1;
int quiet_mode = 0;
int duration = 0;
static volatile sig_atomic_t cleanup_done = 0;

// 全局统计
volatile uint64_t total_packets_captured = 0;
volatile uint64_t total_bytes_captured = 0;
volatile uint64_t total_packets_processed = 0;
volatile uint64_t total_bytes_processed = 0;
volatile uint64_t total_packets_dropped = 0;
volatile uint64_t total_packets_error = 0;

// 接口管理
static interface_info_t interfaces[MAX_INTERFACES];
static int interface_count = 0;
static pthread_mutex_t interface_mutex = PTHREAD_MUTEX_INITIALIZER;

// 数据包队列（用于处理线程）
typedef struct {
    struct packet_info *packets;
    volatile uint64_t head;
    volatile uint64_t tail;
    volatile uint64_t capacity;
    volatile uint64_t mask;
} lockfree_queue_t;

static lockfree_queue_t packet_queue;

// 函数声明
static void cleanup(void);
static void sig_handler(int sig);
static int check_single_instance(void);
static int get_available_interfaces(char interfaces[][IF_NAMESIZE], int max_count);
static int init_interface(const char *ifname, int thread_id);
static void *interface_capture_thread(void *arg);
static int start_multi_interface_capture(char *interface_names[], int count);
static void process_packet_queue(void);
static void handle_ringbuf_event(void *ctx, void *data, size_t size);
static void print_final_stats(void);
static void print_usage(const char *prog_name);

// 锁文件路径
#define LOCK_FILE "/var/run/ebpf_pkt_ringbuf_improved.lock"
static int lock_fd = -1;

// 确保队列容量是2的幂次
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
    
    queue->packets = (struct packet_info *)aligned_alloc(64, capacity * sizeof(struct packet_info));
    if (!queue->packets) {
        fprintf(stderr, "Failed to allocate packet queue\n");
        exit(EXIT_FAILURE);
    }
    
    queue->head = 0;
    queue->tail = 0;
    queue->capacity = capacity;
    queue->mask = capacity - 1;
    
    memset(queue->packets, 0, capacity * sizeof(struct packet_info));
}

// 销毁无锁队列
static void packet_queue_destroy(lockfree_queue_t *queue) {
    if (queue->packets) {
        free(queue->packets);
        queue->packets = NULL;
    }
}

// 无锁入队操作
static int packet_queue_enqueue(lockfree_queue_t *queue, const struct packet_info *packet) {
    if (!running) return -1;
    
    uint64_t tail, head, next_tail;
    int retry_count = 0;
    const int max_retries = 1000;
    
    while (retry_count < max_retries && running) {
        tail = queue->tail;
        head = queue->head;
        next_tail = tail + 1;
        
        if (next_tail - head >= queue->capacity - 1) {
            __asm__ __volatile__("pause" ::: "memory");
            retry_count++;
            continue;
        }
        
        if (__sync_bool_compare_and_swap(&queue->tail, tail, next_tail)) {
            uint64_t idx = tail & queue->mask;
            memcpy(&queue->packets[idx], packet, sizeof(struct packet_info));
            __sync_synchronize();
            return 0;
        }
        
        __asm__ __volatile__("pause" ::: "memory");
        retry_count++;
    }
    
    if (running) {
        static int drop_warning_count = 0;
        if (drop_warning_count < 10) {
            fprintf(stderr, "Packet queue full, dropping packet (warning %d/10)\n", ++drop_warning_count);
        }
        return -1;
    }
    
    return -1;
}

// 无锁出队操作
static int packet_queue_dequeue(lockfree_queue_t *queue, struct packet_info *packet) {
    uint64_t head, tail, next_head;
    int retry_count = 0;
    const int max_retries = 100;
    
    while (retry_count < max_retries && running) {
        head = queue->head;
        tail = queue->tail;
        next_head = head + 1;
        
        if (head == tail) {
            __asm__ __volatile__("pause" ::: "memory");
            retry_count++;
            continue;
        }
        
        if (__sync_bool_compare_and_swap(&queue->head, head, next_head)) {
            uint64_t idx = head & queue->mask;
            memcpy(packet, &queue->packets[idx], sizeof(struct packet_info));
            __sync_synchronize();
            return 0;
        }
        
        __asm__ __volatile__("pause" ::: "memory");
        retry_count++;
    }
    
    return running ? 0 : -1;
}

// 获取队列大小
static uint64_t packet_queue_size(lockfree_queue_t *queue) {
    uint64_t tail = queue->tail;
    uint64_t head = queue->head;
    return tail - head;
}

// RINGBUF事件处理函数
static void handle_ringbuf_event(void *ctx, void *data, size_t size) {
    struct packet_info *packets = (struct packet_info *)data;
    int count = size / sizeof(struct packet_info);
    
    for (int i = 0; i < count; i++) {
        const struct packet_info *pkt = &packets[i];
        
        // 验证数据包
        if (pkt->src_ip == 0 || pkt->dst_ip == 0 || pkt->pkt_len == 0) {
            __sync_fetch_and_add(&total_packets_error, 1);
            continue;
        }
        
        // 更新统计
        __sync_fetch_and_add(&total_packets_captured, 1);
        __sync_fetch_and_add(&total_bytes_captured, pkt->pkt_len);
        
        // 更新接口统计
        pthread_mutex_lock(&interface_mutex);
        for (int j = 0; j < interface_count; j++) {
            if (interfaces[j].ifindex == pkt->ifindex) {
                interfaces[j].packets_captured++;
                interfaces[j].bytes_captured += pkt->pkt_len;
                break;
            }
        }
        pthread_mutex_unlock(&interface_mutex);
        
        // 添加到处理队列
        if (packet_queue_enqueue(&packet_queue, pkt) != 0) {
            __sync_fetch_and_add(&total_packets_dropped, 1);
        }
    }
}

// 处理数据包队列
static void process_packet_queue(void) {
    while (packet_queue_size(&packet_queue) > 0 && running) {
        struct packet_info packet;
        if (packet_queue_dequeue(&packet_queue, &packet) == 0) {
            __sync_fetch_and_add(&total_packets_processed, 1);
            __sync_fetch_and_add(&total_bytes_processed, packet.pkt_len);
            
            // 创建IP头结构
            struct iphdr ip_header;
            ip_header.saddr = packet.src_ip;
            ip_header.daddr = packet.dst_ip;
            ip_header.protocol = packet.protocol;
            ip_header.tot_len = htons(packet.pkt_len);
            
            // 处理数据包
            if (packet.protocol == IPPROTO_TCP) {
                struct tcphdr tcp_header;
                tcp_header.source = htons(packet.src_port);
                tcp_header.dest = htons(packet.dst_port);
                *((uint8_t*)&tcp_header + 13) = packet.tcp_flags;
                
                process_packet(&ip_header, &tcp_header, packet.timestamp);
            } else if (packet.protocol == IPPROTO_UDP) {
                struct udphdr udp_header;
                udp_header.source = htons(packet.src_port);
                udp_header.dest = htons(packet.dst_port);
                
                process_packet(&ip_header, &udp_header, packet.timestamp);
            }
        }
    }
}

// 获取可用接口列表
static int get_available_interfaces(char interfaces[][IF_NAMESIZE], int max_count) {
    return get_available_interfaces_ex(interfaces, max_count, true);
}

// 获取可用接口列表（扩展版本）
static int get_available_interfaces_ex(char interfaces[][IF_NAMESIZE], int max_count, bool exclude_enp1s0) {
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
        
        // 根据参数决定是否排除enp1s0
        if (exclude_enp1s0 && strcmp(i->if_name, "enp1s0") == 0) {
            printf("Skipping enp1s0 interface in all-interfaces mode\n");
            continue;
        }
        
        strncpy(interfaces[count], i->if_name, IF_NAMESIZE - 1);
        interfaces[count][IF_NAMESIZE - 1] = '\0';
        count++;
    }
    
    if_freenameindex(if_ni);
    return count;
}

// 初始化单个接口
static int init_interface(const char *ifname, int thread_id) {
    if (interface_count >= MAX_INTERFACES) {
        fprintf(stderr, "Maximum number of interfaces reached\n");
        return -1;
    }
    
    interface_info_t *iface = &interfaces[interface_count];
    
    memset(iface, 0, sizeof(interface_info_t));
    strncpy(iface->name, ifname, MAX_INTERFACE_NAME_LEN - 1);
    iface->name[MAX_INTERFACE_NAME_LEN - 1] = '\0';
    iface->is_active = 0;
    iface->thread_ret = 0;
    
    // 获取接口索引
    iface->ifindex = if_nametoindex(ifname);
    if (!iface->ifindex) {
        fprintf(stderr, "Failed to get interface index for %s: %s\n", 
                ifname, strerror(errno));
        return -1;
    }
    
    printf("Initializing interface %s (index: %d) for thread %d\n", 
           ifname, iface->ifindex, thread_id);
    
    interface_count++;
    return 0;
}

// 接口捕获线程函数
static void *interface_capture_thread(void *arg) {
    interface_info_t *iface = (interface_info_t *)arg;
    int ret = 0;
    
    printf("Thread: Starting capture on interface %s (index: %d)\n", 
           iface->name, iface->ifindex);
    
    // 加载BPF程序
    iface->obj = bpf_object__open_file("bpf_program_ringbuf_improved.o", NULL);
    if (libbpf_get_error(iface->obj)) {
        fprintf(stderr, "Failed to open BPF object file for %s: %s\n", 
                iface->name, strerror(-libbpf_get_error(iface->obj)));
        ret = 1;
        goto cleanup;
    }
    
    // 加载到内核
    int err = bpf_object__load(iface->obj);
    if (err) {
        fprintf(stderr, "BPF loading failed for %s: %s\n", 
                iface->name, strerror(-err));
        ret = 1;
        goto cleanup;
    }
    
    // 附加到接口
    struct bpf_program *prog = bpf_object__find_program_by_name(iface->obj, "xdp_packet_capture");
    if (!prog) {
        fprintf(stderr, "BPF program not found for %s\n", iface->name);
        ret = 1;
        goto cleanup;
    }
    
    iface->link = bpf_program__attach_xdp(prog, iface->ifindex);
    if (libbpf_get_error(iface->link)) {
        fprintf(stderr, "XDP attachment failed for %s: %s\n", 
                iface->name, strerror(-libbpf_get_error(iface->link)));
        ret = 1;
        goto cleanup;
    }
    
    // 设置RINGBUF
    int map_fd = bpf_object__find_map_fd_by_name(iface->obj, "ringbuf_events");
    if (map_fd < 0) {
        fprintf(stderr, "Ring buffer map not found for %s\n", iface->name);
        ret = 1;
        goto cleanup;
    }
    
    struct ring_buffer *rb = ring_buffer__new(map_fd, handle_ringbuf_event, NULL, NULL);
    if (libbpf_get_error(rb)) {
        fprintf(stderr, "Failed to create ring buffer for %s: %s\n", 
                iface->name, strerror(-libbpf_get_error(rb)));
        ret = 1;
        goto cleanup;
    }
    
    iface->rb = rb;
    iface->is_active = 1;
    
    printf("Successfully started capturing on %s\n", iface->name);
    
    // 事件循环
    while (running) {
        err = ring_buffer__poll(rb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer for %s: %d\n", iface->name, err);
            break;
        }
    }
    
    printf("Exiting capture thread for %s\n", iface->name);
    
cleanup:
    if (iface->rb) {
        ring_buffer__free(iface->rb);
        iface->rb = NULL;
    }
    
    if (iface->link) {
        bpf_link__destroy(iface->link);
        iface->link = NULL;
    }
    
    if (iface->obj) {
        bpf_object__close(iface->obj);
        iface->obj = NULL;
    }
    
    iface->is_active = 0;
    iface->thread_ret = ret;
    
    return NULL;
}

// 启动多接口捕获
static int start_multi_interface_capture(char *interface_names[], int count) {
    pthread_t *threads = malloc(count * sizeof(pthread_t));
    if (!threads) {
        fprintf(stderr, "Failed to allocate thread array\n");
        return -1;
    }
    
    printf("Starting %d interface capture threads...\n", count);
    
    // 为每个接口创建捕获线程
    for (int i = 0; i < count; i++) {
        // 初始化接口
        if (init_interface(interface_names[i], i) != 0) {
            fprintf(stderr, "Failed to initialize interface %s\n", interface_names[i]);
            continue;
        }
        
        // 创建线程
        if (pthread_create(&threads[i], NULL, interface_capture_thread, &interfaces[i]) != 0) {
            fprintf(stderr, "Failed to create thread for interface %s\n", interface_names[i]);
            continue;
        }
        
        printf("Created capture thread %d for interface %s\n", i, interface_names[i]);
    }
    
    // 等待所有线程完成
    for (int i = 0; i < count; i++) {
        pthread_join(threads[i], NULL);
    }
    
    free(threads);
    return 0;
}

// 信号处理函数
static void sig_handler(int sig) {
    static int signal_count = 0;
    signal_count++;
    
    if (signal_count == 1) {
        printf("Received signal %d, initiating graceful shutdown...\n", sig);
        running = 0;
        alarm(5);
    } else {
        printf("Forcing immediate exit...\n");
        exit(1);
    }
}

// 检查单实例运行
static int check_single_instance(void) {
    lock_fd = open(LOCK_FILE, O_RDWR | O_CREAT, 0644);
    if (lock_fd == -1) {
        if (errno == EACCES || errno == EPERM) {
            fprintf(stderr, "No permission to create lock file %s, trying /tmp\n", LOCK_FILE);
            const char *tmp_lock = "/tmp/ebpf_pkt_ringbuf_improved.lock";
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
    
    if (flock(lock_fd, LOCK_EX | LOCK_NB) == -1) {
        if (errno == EWOULDBLOCK) {
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
    
    char pid_str[32];
    snprintf(pid_str, sizeof(pid_str), "%d\n", getpid());
    if (ftruncate(lock_fd, 0) == -1 || 
        lseek(lock_fd, 0, SEEK_SET) == -1 ||
        write(lock_fd, pid_str, strlen(pid_str)) == -1) {
        fprintf(stderr, "Unable to write PID to lock file: %s\n", strerror(errno));
    }
    
    atexit(cleanup);
    return 0;
}

// 清理函数
static void cleanup(void) {
    static pthread_mutex_t cleanup_mutex = PTHREAD_MUTEX_INITIALIZER;
    pthread_mutex_lock(&cleanup_mutex);
    if (cleanup_done) {
        pthread_mutex_unlock(&cleanup_mutex);
        return;
    }
    cleanup_done = 1;
    
    printf("Starting cleanup process...\n");
    
    // 销毁数据包队列
    packet_queue_destroy(&packet_queue);
    
    // 清理流表
    if (flow_table_initialized) {
        print_final_stats();
        flow_table_destroy();
    }
    
    // 清理会话管理器
    printf("Cleaning up session manager...\n");
    transport_session_manager_cleanup();
    
    // 关闭锁文件
    if (lock_fd != -1) {
        flock(lock_fd, LOCK_UN);
        close(lock_fd);
        unlink(LOCK_FILE);
        lock_fd = -1;
    }
    
    printf("Cleanup completed\n");
    pthread_mutex_unlock(&cleanup_mutex);
}

// 打印最终统计
static void print_final_stats(void) {
    printf("\n================== Final Statistics ==================\n");
    
    printf("Global Statistics:\n");
    printf("  Total Packets Captured: %lu\n", total_packets_captured);
    printf("  Total Bytes Captured: %lu (%.2f MB)\n", total_bytes_captured, 
           total_bytes_captured / (1024.0 * 1024.0));
    printf("  Total Packets Processed: %lu\n", total_packets_processed);
    printf("  Total Bytes Processed: %lu (%.2f MB)\n", total_bytes_processed, 
           total_bytes_processed / (1024.0 * 1024.0));
    printf("  Total Packets Dropped: %lu\n", total_packets_dropped);
    printf("  Total Packets Error: %lu\n", total_packets_error);
    
    printf("\nInterface Statistics:\n");
    for (int i = 0; i < interface_count; i++) {
        if (interfaces[i].is_active) {
            printf("  %s (index: %d):\n", interfaces[i].name, interfaces[i].ifindex);
            printf("    Packets Captured: %lu\n", interfaces[i].packets_captured);
            printf("    Bytes Captured: %lu (%.2f MB)\n", interfaces[i].bytes_captured, 
                   interfaces[i].bytes_captured / (1024.0 * 1024.0));
            printf("    Packets Dropped: %lu\n", interfaces[i].packets_dropped);
            printf("    Packets Error: %lu\n", interfaces[i].packets_error);
        }
    }
    
    printf("================================================\n\n");
}

// 打印使用帮助
static void print_usage(const char *prog_name) {
    printf("Usage: %s [OPTIONS]\n", prog_name);
    printf("  -i, --interface <ifname>    Network interface to monitor (default: all)\n");
    printf("  -d, --duration <seconds>    Run for specified duration in seconds (default: indefinite)\n");
    printf("  -v, --verbose <level>       Debug level: 0=none, 1=basic, 2=detailed (default: 0)\n");
    printf("  -q, --quiet                 Quiet mode, don't print statistics to screen\n");
    printf("  -h, --help                  Show this help message\n");
}

int main(int argc, char **argv) {
    const char *ifname = "all";
    int c;
    int ret = 0;
    
    // 设置信号处理
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // 检查单实例运行
    ret = check_single_instance();
    if (ret > 0) {
        fprintf(stderr, "Another instance is already running\n");
        return 1;
    } else if (ret < 0) {
        fprintf(stderr, "Failed to check single instance, continuing...\n");
    }
    
    // 解析命令行参数
    static struct option long_options[] = {
        {"interface", required_argument, 0, 'i'},
        {"duration", required_argument, 0, 'd'},
        {"verbose", required_argument, 0, 'v'},
        {"quiet", no_argument, 0, 'q'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    while ((c = getopt_long(argc, argv, "i:d:v:qh", long_options, NULL)) != -1) {
        switch (c) {
            case 'i':
                ifname = optarg;
                break;
            case 'd':
                duration = atoi(optarg);
                if (duration < 0) {
                    fprintf(stderr, "Duration must be a positive number\n");
                    return 1;
                }
                printf("Setting duration to %d seconds\n", duration);
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
                printf("Quiet mode enabled\n");
                break;
            case 'h':
                print_usage(argv[0]);
                return 0;
            default:
                print_usage(argv[0]);
                return 1;
        }
    }
    
    // 初始化系统
    packet_queue_init(&packet_queue, PACKET_QUEUE_SIZE);
    flow_table_init();
    
    if (transport_session_manager_init() != 0) {
        fprintf(stderr, "Failed to initialize session manager\n");
        return 1;
    }
    
    printf("Flow tracking and session manager initialized\n");
    
    if (duration > 0) {
        printf("Will capture traffic for %d seconds\n", duration);
    }
    
    // 获取可用接口
    char available_interfaces[MAX_INTERFACES][IF_NAMESIZE];
    int available_count;
    
    // 如果指定了特定接口，允许包含enp1s0；否则排除enp1s0
    if (strcmp(ifname, "all") != 0) {
        // 单独监听指定接口，允许enp1s0
        available_count = get_available_interfaces_ex(available_interfaces, MAX_INTERFACES, false);
        printf("Single interface mode: allowing enp1s0\n");
    } else {
        // 监听所有接口，排除enp1s0
        available_count = get_available_interfaces_ex(available_interfaces, MAX_INTERFACES, true);
        printf("All interfaces mode: excluding enp1s0\n");
    }
    
    if (available_count == 0) {
        fprintf(stderr, "No available network interfaces found\n");
        return 1;
    }
    
    printf("Found %d available interfaces:\n", available_count);
    for (int i = 0; i < available_count; i++) {
        printf("  %d: %s\n", i + 1, available_interfaces[i]);
    }
    
    // 确定要监控的接口
    char *interface_names[MAX_INTERFACES];
    int interface_count_to_monitor = 0;
    
    if (strcmp(ifname, "all") == 0) {
        // 监控所有接口
        for (int i = 0; i < available_count; i++) {
            interface_names[interface_count_to_monitor] = available_interfaces[i];
            interface_count_to_monitor++;
        }
    } else {
        // 监控指定接口
        interface_names[0] = (char *)ifname;
        interface_count_to_monitor = 1;
    }
    
    // 启动多接口捕获
    ret = start_multi_interface_capture(interface_names, interface_count_to_monitor);
    
    // 主循环：处理数据包队列和显示统计
    time_t start_time = time(NULL);
    uint64_t last_stats_time = 0;
    
    while (running) {
        // 检查持续时间
        if (duration > 0 && (time(NULL) - start_time) >= duration) {
            printf("Reached specified duration of %d seconds. Exiting...\n", duration);
            break;
        }
        
        // 处理数据包队列
        process_packet_queue();
        
        // 显示统计信息
        uint64_t current_time = get_current_time() / 1000000; // 转换为毫秒
        if (current_time - last_stats_time >= 1000) { // 每秒更新一次
            if (!quiet_mode) {
                printf("\r⏰ %s | 📦 %lu (%.1f pkt/s) | 💾 %.2f MB | 🔗 TCP:%u UDP:%u Total:%u | 🗄️ %d/%d",
                       "RINGBUF_IMPROVED",
                       total_packets_captured,
                       (double)total_packets_captured / ((time(NULL) - start_time) + 1),
                       total_bytes_captured / (1024.0 * 1024.0),
                       get_tcp_conversation_count(),
                       get_udp_conversation_count(),
                       get_total_conversation_count(),
                       count_active_flows(),
                       count_all_flows());
                fflush(stdout);
            }
            last_stats_time = current_time;
        }
        
        usleep(10000); // 10ms
    }
    
    printf("\n");
    cleanup();
    
    return ret;
} 