#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

#define PERF_BUFFER_PAGES 16

static volatile bool running = true;

struct packet_info {
    __u32 src_ip;
    __u32 dst_ip;
    __u16 src_port;
    __u16 dst_port;
    __u8 protocol;
    __u32 pkt_len;
    // Add other necessary fields
};
struct perf_buffer_opts opts = {
    .sz = sizeof(opts),
};

void sig_handler(int sig) {
    running = false;
}

/* 定义回调函数（必须在被使用前声明）*/
static void handle_batch(void *ctx, int cpu, void *data, __u32 size) {
    const struct packet_info *pkts = data;
    int count = size / sizeof(struct packet_info);
    
    for (int i = 0; i < count; i++) {
        const struct packet_info *pkt = &pkts[i];
        
        if (pkt->src_ip == 0 || pkt->dst_ip == 0 || pkt->pkt_len == 0) {
            continue;
        }

        char src_ip[INET_ADDRSTRLEN], dst_ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &pkt->src_ip, src_ip, sizeof(src_ip));
        inet_ntop(AF_INET, &pkt->dst_ip, dst_ip, sizeof(dst_ip));
        
        printf("CPU%d: %s:%d -> %s:%d Proto:%d Len:%d\n",
               cpu, src_ip, pkt->src_port, dst_ip, pkt->dst_port,
               pkt->protocol, pkt->pkt_len);
    }
}

int main(int argc, char **argv) {
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    struct bpf_link *link = NULL;
    struct perf_buffer *pb = NULL;
    int map_fd, err;

    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* 1. 加载BPF程序 */
    obj = bpf_object__open_file("bpf_program.o", NULL);
    if (libbpf_get_error(obj)) {
        fprintf(stderr, "无法打开BPF对象文件\n");
        return 1;
    }

    /* 2. 加载到内核 */
    err = bpf_object__load(obj);
    if (err) {
        fprintf(stderr, "BPF加载失败: %s\n", strerror(-err));
        goto cleanup;
    }

    /* 3. 附加到接口 */
    prog = bpf_object__find_program_by_name(obj, "xdp_packet_capture");
    if (!prog) {
        fprintf(stderr, "找不到BPF程序\n");
        goto cleanup;
    }

    const char *ifname = argc > 1 ? argv[1] : "eth0";
    int ifindex = if_nametoindex(ifname);
    if (!ifindex) {
        fprintf(stderr, "获取接口索引失败: %s\n", strerror(errno));
        goto cleanup;
    }

    link = bpf_program__attach_xdp(prog, ifindex);
    if (libbpf_get_error(link)) {
        fprintf(stderr, "XDP附加失败: %s\n", strerror(-errno));
        goto cleanup;
    }

    /* 4. 设置perf buffer */
    map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) {
        fprintf(stderr, "找不到perf event map\n");
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
        fprintf(stderr, "创建perf buffer失败\n");
        goto cleanup;
    }

    printf("成功启动，按Ctrl+C停止...\n");

    /* 5. 事件循环 */
    while (running) {
        err = perf_buffer__poll(pb, 100);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "poll错误: %d\n", err);
            break;
        }
    }

cleanup:
    if (pb) perf_buffer__free(pb);
    if (link) bpf_link__destroy(link);
    if (obj) bpf_object__close(obj);
    
    return 0;
}