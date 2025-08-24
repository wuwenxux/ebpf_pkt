#ifndef LOADER_H
#define LOADER_H

#include <stdint.h>
#include <pthread.h>
#include <bpf/libbpf.h>
#include <time.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>

// 常量定义
#define MAX_INTERFACES 32
#define PACKET_QUEUE_SIZE 100000

// 避免IF_NAMESIZE重定义
#ifndef IF_NAMESIZE
#define IF_NAMESIZE 32
#endif

#define DEFAULT_STATS_INTERVAL 1
#define DEFAULT_STATS_PACKETS 1000
#define DEFAULT_CLEANUP_INTERVAL 60

// 全局变量声明
extern int stats_interval;
extern int stats_packet_count;
extern int cleanup_interval;
extern char *csv_file;

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
    __u32 ifindex;      // 接口索引
    __u32 cpu_id;       // CPU ID
    __u32 hash;         // 预计算的五元组哈希
    __u8 priority;      // 优先级（用于QoS）
} __attribute__((packed));

// 数据包队列结构
typedef struct {
    struct packet_info *packets;
    volatile uint64_t head;
    volatile uint64_t tail;
    volatile uint64_t capacity;
    volatile uint64_t mask;
} lockfree_queue_t;

// 数据包数据结构
typedef struct {
    struct iphdr ip_header;
    union {
        struct tcphdr tcp;
        struct udphdr udp;
    } transport_header;
    uint64_t timestamp;
} packet_data_t;

// 数据包队列（传统）
typedef struct {
    packet_data_t *packets;
    volatile uint64_t head;
    volatile uint64_t tail;
    volatile uint64_t capacity;
    pthread_mutex_t mutex;
} packet_queue_t;

// 接口信息结构
typedef struct {
    char name[32];
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

// 优化的接口信息结构
typedef struct {
    char name[32];
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
    int cpu_id;  // 绑定的CPU ID
} optimized_interface_info_t;

// 全局变量声明
extern volatile int running;
extern int quiet_mode;
extern int loop_count;
extern int loop_delay;
extern int duration;
extern int single_thread_mode;
extern volatile uint64_t total_packets_captured;
extern volatile uint64_t total_bytes_captured;
extern volatile uint64_t total_packets_processed;
extern volatile uint64_t total_bytes_processed;
extern volatile uint64_t total_packets_dropped;
extern volatile uint64_t total_packets_invalid;
extern volatile uint64_t total_packets_queued;
extern volatile uint64_t total_packets_dequeued;
extern volatile uint64_t global_packet_count;
extern time_t start_time;

// 全局无锁队列
extern lockfree_queue_t global_lockfree_queue;

// 全局变量声明
extern struct timespec program_start_time;

// 预取宏定义
#define PREFETCH(addr) __builtin_prefetch(addr)
#define PREFETCH_RW(addr) __builtin_prefetch(addr, 1, 1)

// ===== 无锁队列模块 (lockfree_queue.c) =====
uint64_t next_power_of_2(uint64_t n);
void lockfree_queue_init(lockfree_queue_t *queue, int initial_capacity);
void lockfree_queue_destroy(lockfree_queue_t *queue);
int lockfree_queue_enqueue(lockfree_queue_t *queue, const struct packet_info *packet);
int lockfree_queue_dequeue(lockfree_queue_t *queue, struct packet_info *packet);
uint64_t lockfree_queue_size(lockfree_queue_t *queue);

// ===== 工作线程模块 (worker_threads.c) =====
int init_worker_threads(void);
void stop_worker_threads(void);
int get_worker_thread_count(void);
void get_worker_thread_stats(int thread_id, uint64_t *packets, uint64_t *bytes);

// ===== RINGBUF处理模块 (ringbuf_handler.c) =====
int handle_ringbuf_event(void *ctx, void *data, size_t size);
int handle_ringbuf_event_optimized(void *ctx, void *data, size_t size);
int handle_ringbuf_event_optimized_improved(void *ctx, void *data, size_t size);
void process_lockfree_packet_queue(void);

// ===== 接口管理模块 (interface_manager.c) =====
int get_available_interfaces(char interfaces[][IF_NAMESIZE], int max_count);
int get_available_interfaces_ex(char interfaces[][IF_NAMESIZE], int max_count, bool exclude_enp1s0);
int init_interface(const char *ifname, int thread_id);
int init_optimized_interface(const char *ifname, int cpu_id);
int get_optimized_interface_count(void);
optimized_interface_info_t *get_optimized_interface(int index);
void update_interface_stats(int ifindex, uint64_t packets, uint64_t bytes);
void get_interface_stats(int ifindex, uint64_t *packets, uint64_t *bytes, uint64_t *dropped, uint64_t *errors);
void print_all_interface_stats(void);
void cleanup_interface_resources(void);
int is_valid_interface(const char *ifname);
int get_interface_cpu_affinity(const char *ifname);
int set_interface_cpu_affinity(const char *ifname, int cpu_id);

// ===== 核心功能函数 =====
void process_packet_direct(const struct iphdr *ip_header, uint16_t src_port, uint16_t dst_port, 
                          uint32_t tcp_seq, uint8_t tcp_flags, uint64_t timestamp);
void process_packet(const struct iphdr *ip_header, const void *transport_header, uint64_t timestamp);
void process_packet_queue(void);
// 这些函数在loader_core.c中定义，其他模块通过extern访问
void print_usage(const char *prog_name);
void init_time_base(void);
void format_ebpf_packet_time(uint64_t ktime_ns, char *buf, size_t buflen);
void format_beijing_time(time_t timestamp, char *buf, size_t buflen);
uint64_t get_current_time(void);

// ===== 捕获模式函数 =====
int run_single_interface_capture(const char *ifname);
int run_single_thread_multi_interface_capture(const char *ifname);
int run_optimized_single_thread_multi_interface_capture(const char *ifname);
int run_live_capture(const char *ifname);
int run_monitor_mode(const char *ifname);
int process_pcap_file(const char *pcap_file);


// ===== 日志函数 =====
// 注意：日志函数在logger.h中定义，这里不重复声明

// ===== 流和会话管理 =====
void flow_table_init(void);
void cleanup_flows(void);
int count_active_flows(void);
int count_all_flows(void);
uint32_t get_tcp_conversation_count(void);
uint32_t get_udp_conversation_count(void);
uint32_t get_total_conversation_count(void);
void get_session_creation_stats(uint64_t *total_created, uint64_t *tcp_created, 
                               uint64_t *udp_created, uint64_t *reused);
int cleanup_expired_sessions(void);

// ===== 系统统计 =====
void init_system_monitoring(void);
void update_system_stats(void);
// system_stats结构体在loader_core.c中定义

// ===== 数据包队列管理 =====
void packet_queue_init(packet_queue_t *queue, int size);
void packet_queue_cleanup(packet_queue_t *queue);
int packet_queue_enqueue(packet_queue_t *queue, const packet_data_t *packet);
int packet_queue_dequeue(packet_queue_t *queue, packet_data_t *packet);
int packet_queue_size(packet_queue_t *queue);

// ===== 多线程接口管理 =====
int start_multi_interface_capture(char *interface_names[], int count);
void *interface_listener_thread(void *arg);
void *capture_thread_func(void *arg);

// ===== 全局RINGBUF管理 =====
// 这些变量在loader_core.c中定义，其他模块通过extern访问

#endif // LOADER_H 