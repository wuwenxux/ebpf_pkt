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

static volatile bool running = true;

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

static void cleanup(void) {
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
}

void sig_handler(int sig) {
    printf("\nReceived signal %d. Cleaning up and exiting...\n", sig);
    running = false;
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

static void handle_batch(void *ctx, int cpu, void *data, __u32 size) {
    const struct packet_info *pkts = data;
    int count = size / sizeof(struct packet_info);
    static unsigned long packet_count = 0;
    static time_t last_stats_time = 0;
    time_t current_time;
    
    // Check if we've exceeded the specified duration
    if (duration > 0) {
        current_time = time(NULL);
        if (current_time - start_time >= duration) {
            printf("Reached specified duration of %d seconds. Exiting...\n", duration);
            running = false;
            return;
        }
    }
    
    for (int i = 0; i < count; i++) {
        const struct packet_info *pkt = &pkts[i];
        
        // 过滤无效数据包
        if (pkt->src_ip == 0 || pkt->dst_ip == 0 || pkt->pkt_len == 0) {
            continue;
        }
        
        // 手动创建IP头和传输层头用于处理
        struct iphdr ip_header = {
            .saddr = pkt->src_ip,
            .daddr = pkt->dst_ip,
            .protocol = pkt->protocol,
            .tot_len = htons(pkt->pkt_len)
        };
        
        // 创建临时传输层头
        struct {
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
            } h;
        } trans_header;

        // 设置传输层信息
        if (pkt->protocol == IPPROTO_TCP) {
            trans_header.h.tcp.source = htons(pkt->src_port);
            trans_header.h.tcp.dest = htons(pkt->dst_port);
            // 设置TCP标志位到正确位置
            trans_header.h.tcp.flags_byte[13] = pkt->tcp_flags;
            
            // 调试输出TCP标志位已移除，TCP标志会在每个流的统计中显示
        } else if (pkt->protocol == IPPROTO_UDP) {
            trans_header.h.udp.source = htons(pkt->src_port);
            trans_header.h.udp.dest = htons(pkt->dst_port);
        }

        // 调用统一的流处理函数
        process_packet(&ip_header, &trans_header);

        // Count packets
        packet_count++;
    }
    
    // Print flow statistics periodically
    current_time = time(NULL);
    if (current_time - last_stats_time >= stats_interval || 
        packet_count % stats_packet_count == 0) {
        print_flow_stats();
        last_stats_time = current_time;
    }
}

// Process a single packet from pcap
void process_pcap_packet(const u_char *packet, const struct pcap_pkthdr *header) {
    struct ethhdr *eth = (struct ethhdr *)packet;
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return;  // Skip non-IP packets
    }
    
    struct iphdr *ip = (struct iphdr *)(packet + sizeof(struct ethhdr));
    if (ip->version != 4) {
        return;  // Skip non-IPv4 packets
    }
    
    // Get transport layer header
    void *transport_header = (void *)ip + (ip->ihl * 4);
    
    // Process packet using our flow tracking functions
    process_packet(ip, transport_header);
    
    // Update packet count
    static unsigned long packet_count = 0;
    static time_t last_stats_time = 0;
    time_t current_time;
    
    packet_count++;
    
    // Check if we've exceeded the specified duration
    if (duration > 0) {
        current_time = time(NULL);
        if (current_time - start_time >= duration) {
            printf("Reached specified duration of %d seconds. Exiting...\n", duration);
            running = false;
            return;
        }
    }
    
    // Print flow statistics periodically - use time() instead of clock_gettime
    current_time = time(NULL);
    if (current_time - last_stats_time >= stats_interval || 
        packet_count % stats_packet_count == 0) {
        print_flow_stats();
        last_stats_time = current_time;
    }
}

// Process a pcap file
int process_pcap_file(const char *pcap_file) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *handle = NULL;
    int ret = 0;
    
    // Record start time
    start_time = time(NULL);
    
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
    
    // Process packets from the pcap file
    struct pcap_pkthdr header;
    const u_char *packet;
    int packet_count = 0;
    
    while (running && (packet = pcap_next(handle, &header)) != NULL) {
        process_pcap_packet(packet, &header);
        packet_count++;
        
        // Print progress every 10000 packets
        if (packet_count % 10000 == 0) {
            printf("Processed %d packets...\n", packet_count);
        }
    }
    
    printf("Processed %d packets total\n", packet_count);
    print_flow_stats();
    
    // Clean up
    if (handle) {
        pcap_close(handle);
        handle = NULL;
    }
    
    // 调用统一清理函数
    cleanup();
    
    return ret;
}

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
    printf("  -h, --help                  Show this help message\n");
}

int run_live_capture(const char *ifname) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct perf_buffer *pb = NULL;
    int map_fd, err;
    int ret = 0;

    // Record start time
    start_time = time(NULL);

    // Initialize flow tracking
    flow_table_init();
    printf("Flow tracking initialized\n");
    if (duration > 0) {
        printf("Will capture traffic for %d seconds\n", duration);
    }

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

    printf("Successfully started, press Ctrl+C to stop...\n");

    /* 5. 事件循环 */
    while (running) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling: %d\n", err);
            break;
        }
        
        // Check if we've exceeded the specified duration
        if (duration > 0) {
            time_t current_time = time(NULL);
            if (current_time - start_time >= duration) {
                printf("Reached specified duration of %d seconds. Exiting...\n", duration);
                break;
            }
        }
        
        // Periodically clean up old flows
        static time_t last_cleanup = 0;
        time_t now = time(NULL);
        if (now - last_cleanup > cleanup_interval) {  // Clean up every N seconds
            cleanup_flows();
            last_cleanup = now;
        }
    }

    printf("Exiting program...\n");

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
        {"help",          no_argument,       0, 'h'},
        {0, 0, 0, 0}
    };

    while ((c = getopt_long(argc, argv, "i:r:d:s:p:c:h", long_options, NULL)) != -1) {
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