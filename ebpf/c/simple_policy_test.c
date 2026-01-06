// test_policy.c
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/ip.h>
#include <bpf/bpf_helpers.h>
#include <linux/if_ether.h>

// 1. DEFINE THE MAP (The "Database")
// We will store allowed IPs here. 
// Key = IP Address (u32), Value = Any integer (u32)
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u32);
} allowed_ips SEC(".maps");

// 2. THE HOOK (The Logic)
SEC("tc_cls")
int handle_ingress(struct __sk_buff *skb) {
    
    // Parse the packet manually (simplified for demo)
    void *data_end = (void *)(long)skb->data_end;
    void *data = (void *)(long)skb->data;
    struct ethhdr *eth = data;
    struct iphdr *ip = data + sizeof(*eth);

    // Bounds check to satisfy the verifier
    if (data + sizeof(*eth) + sizeof(*ip) > data_end) {
        return TC_ACT_OK; // Malformed packet
    }

    // Only look at IPv4 (skip ARP, IPv6, etc.)
    if (eth->h_proto != __constant_htons(ETH_P_IP)) {
        return TC_ACT_OK; // Allow non-IPv4
    }

    // Now we know it's IPv4 - log it
    bpf_printk("IPv4 packet received");

    // 3. THE LOOKUP
    __u32 src_ip = ip->saddr;
    
    // Look for the Source IP in our map
    __u32 *rule = bpf_map_lookup_elem(&allowed_ips, &src_ip);

    if (rule) {
        bpf_printk("IP allowed: %x (found in map)", src_ip);
        return TC_ACT_OK; // ALLOW
    }

    bpf_printk("IP dropped: %x (not in map)", src_ip);
    return TC_ACT_SHOT; // DROP
}

char _license[] SEC("license") = "GPL";