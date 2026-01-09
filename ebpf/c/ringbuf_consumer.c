// SPDX-License-Identifier: GPL-2.0
// Ring buffer consumer for policy events
//
// Compiles with: clang -o ringbuf_consumer ringbuf_consumer.c -lbpf
// Usage: sudo ./ringbuf_consumer /sys/fs/bpf/policy_events

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <signal.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>

// Must match the struct in BPF code
struct data_t {
    __u32 src_ip;
    __u32 src_port;
    __u32 dest_ip;
    __u32 dest_port;
    __u32 protocol;
    __u32 verdict;
    __u32 packet_sz;
    __u32 runtime_ns;  // Time taken by BPF program in nanoseconds
    __u8 is_egress;
    __u8 tier;
};

static volatile bool running = true;

static void sig_handler(int sig)
{
    running = false;
}

static const char *tier_name(__u8 tier)
{
    switch (tier) {
        case 0: return "ERROR";
        case 1: return "ADMIN";
        case 2: return "NETWORK_POLICY";
        case 3: return "BASELINE";
        case 4: return "DEFAULT";
        default: return "UNKNOWN";
    }
}

static const char *proto_name(__u32 proto)
{
    switch (proto) {
        case 6: return "TCP";
        case 17: return "UDP";
        case 132: return "SCTP";
        case 1: return "ICMP";
        default: return "???";
    }
}

static int handle_event(void *ctx, void *data, size_t data_sz)
{
    struct data_t *evt = data;
    char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];
    
    // Convert IPs (stored in little-endian)
    inet_ntop(AF_INET, &evt->src_ip, src_ip, sizeof(src_ip));
    inet_ntop(AF_INET, &evt->dest_ip, dest_ip, sizeof(dest_ip));
    
    // Output as JSON for easy Python parsing
    printf("{\"src_ip\":\"%s\",\"src_port\":%u,\"dest_ip\":\"%s\",\"dest_port\":%u,"
           "\"protocol\":\"%s\",\"verdict\":\"%s\",\"size\":%u,\"direction\":\"%s\","
           "\"tier\":\"%s\",\"runtime_ns\":%u}\n",
           src_ip, evt->src_port,
           dest_ip, evt->dest_port,
           proto_name(evt->protocol),
           evt->verdict ? "ALLOW" : "DENY",
           evt->packet_sz,
           evt->is_egress ? "EGRESS" : "INGRESS",
           tier_name(evt->tier),
           evt->runtime_ns);
    
    fflush(stdout);
    return 0;
}

int main(int argc, char **argv)
{
    const char *map_path = "/sys/fs/bpf/policy_events";
    struct ring_buffer *rb = NULL;
    int map_fd;
    int err;
    
    if (argc > 1) {
        map_path = argv[1];
    }
    
    // Open the pinned map
    map_fd = bpf_obj_get(map_path);
    if (map_fd < 0) {
        fprintf(stderr, "Error: Failed to open map %s: %s\n", 
                map_path, strerror(errno));
        return 1;
    }
    
    // Set up signal handlers
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    // Create ring buffer manager
    rb = ring_buffer__new(map_fd, handle_event, NULL, NULL);
    if (!rb) {
        fprintf(stderr, "Error: Failed to create ring buffer: %s\n", 
                strerror(errno));
        close(map_fd);
        return 1;
    }
    
    fprintf(stderr, "Listening for policy events on %s...\n", map_path);
    
    // Poll for events
    while (running) {
        err = ring_buffer__poll(rb, 100 /* timeout ms */);
        if (err < 0 && err != -EINTR) {
            fprintf(stderr, "Error polling ring buffer: %d\n", err);
            break;
        }
    }
    
    fprintf(stderr, "Shutting down...\n");
    ring_buffer__free(rb);
    close(map_fd);
    
    return 0;
}
